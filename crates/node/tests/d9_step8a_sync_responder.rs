//! D9 Step 8A — Production Sync Responder + G1 restart re-registration（真实 production 路径）。
//!
//! 覆盖两条本轮实现路径：
//! - **Feature A**：`Established peer → SyncBlockRequest →（既有 envelope/auth）→ node wiring 有界队列
//!   → NodeRuntime 有界 serve → BlockStore 只读查找 → 既有 `SyncBlockResponse` codec（单块；
//!   `request_id` 原样回带）→ 既有 `NetworkSigner` → 既有 `NetworkService::enqueue_outbound` → 真实 TCP`。
//! - **Feature B（G1）**：`已落盘但不在 DAG` 的块（crash 于 finality/commit 之前 / restart 后 DAG 仅由
//!   canonical head 祖先链重建）在**重新投递**时不再被 `AlreadyKnown` 短路 ⇒ 走完 ⑥/⑦ 全验证 ⇒
//!   幂等补登记（仍**不** commit / **不**推进 head / **不**产生 finality）。
//!
//! 诚实边界（本文件断言）：`SyncBlockResponse` **不是** finality evidence；sync **不**推进 head；
//! 本轮**不**实现 historical catch-up / peer-height discovery / range sync / QC import。
//!
//! 真实 TCP：T1 为**两个真实 NodeRuntime**（production requester ↔ production responder）；
//! T2/T3/T4 为真实 TCP wire fixture 作为**请求方**、真实 NodeRuntime 作为**响应方**；
//! T5 为真实 TCP fixture 供块 + 真实 NodeRuntime 重启回归。

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{
    AlgorithmId, DomainId, SigningMessageHash, build_signed_bytes, hash_signing_message,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash, validator_id,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, SigningKey, VerifyingKey, sign_message_hash};
use nova_network::message::{MessageEnvelope, MessageType, decode, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{HandshakeKind, PeerAuthConfig, handshake_payload_encode};
use nova_network::sync::{SyncBlockRequest, SyncBlockResponse};
use nova_network::transport::{ConnectionTarget, MemoryTransport, TcpTransport, Transport};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block_header,
};

use nova_node::block_adapter::NoAccountsKeyResolver;
use nova_node::block_inbound::InboundBlockVerdict;
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, KeyProviderError};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::sync_responder::{MAX_SYNC_BLOCKS_PER_RESPONSE, MAX_SYNC_WALK};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
const MAX_FRAME: usize = 1024 * 1024;
const MAX_ITER: usize = 4000;

// ---------------------------------------------------------------------------
// Test-only 确定性 validator key（seed 重建 ⇒ restart / 多实例同 key；非生产密钥）
// ---------------------------------------------------------------------------

struct SeedSigner {
    key: SigningKey,
}

impl SigningCapability for SeedSigner {
    fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(&self.key, message_hash))
    }
}

/// 每次 `load_signer` 从固定 seed **重新构造** SigningKey（不同实例 ⇒ 同一私钥）。
#[derive(Clone, Copy)]
struct SeedKeyProvider {
    seed: [u8; 32],
}

impl SeedKeyProvider {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl KeyProvider for SeedKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        Ok(Box::new(SeedSigner {
            key: SigningKey::from_seed(self.seed),
        }))
    }
}

fn pubkey_from_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
}

fn validator_id_from_seed(seed: [u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(&pubkey_from_seed(seed))
}

// ---------------------------------------------------------------------------
// genesis / env / runtime harness
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// N 验证者 genesis（canonical ordering：validator 按 validator_id 升序；account 按 address 升序；
/// `total_supply == Σ liquid`）。
fn genesis_with(keys: &[[u8; 32]]) -> GenesisV1 {
    let accounts: Vec<AccountInit> = (0..keys.len())
        .map(|i| AccountInit {
            address: addr([0x10 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut validators: Vec<([u8; 32], [u8; 32], YazimaoAddress)> = keys
        .iter()
        .enumerate()
        .map(|(i, pk)| (validator_id(pk), *pk, accounts[i].address))
        .collect();
    validators.sort_by_key(|v| v.0);
    let initial_validator_set = validators
        .into_iter()
        .map(|(_, pk, account_address)| ValidatorInit {
            account_address,
            consensus_public_key: pk,
            bonded_stake: STAKE,
            commission_bps: 0,
        })
        .collect();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set,
        initial_accounts: accounts,
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: 1_000_000,
            max_contract_code_bytes: 1024,
            max_contract_storage_bytes: 1024,
            epoch_length_blocks: 1_000,
            snapshot_interval_blocks: 10_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: 1_000_000 * keys.len() as u128,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    base: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d9s8a_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        Self {
            genesis_path,
            genesis_hash,
            base: dir.clone(),
            _dir: dir,
        }
    }

    /// 每节点独立 chain/safety 目录（`node` 唯一）；同一 genesis。
    /// **同一 `node` 标签重复调用 ⇒ 同一目录**（供 restart 复用）。
    fn config(
        &self,
        node: &str,
        listen_addr: Option<SocketAddr>,
        peers: Vec<ConnectionTarget>,
    ) -> NodeConfig {
        let root = self.base.join(node);
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: root.join("chain"),
            validator_enabled: true,
            safety_dir: root.join("safety"),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr,
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn start_node(config: &NodeConfig, validator_seed: [u8; 32], net_kp: KeyPair) -> NodeRuntime {
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_other) = MemoryTransport::pair(net_id, NodeId::from_bytes([0x99; 32]));
    let provider = SeedKeyProvider::new(validator_seed);
    NodeRuntime::start_with_network(
        config,
        Some(&provider),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("runtime 启动（validator + network）")
}

fn wait_until<F: FnMut() -> bool>(mut f: F) -> bool {
    for _ in 0..MAX_ITER {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
    }
    false
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production().expect("adapter").head().height
}

fn head_hash(rt: &NodeRuntime) -> [u8; 32] {
    rt.block_production().expect("adapter").head().block_hash
}

fn head_finality(rt: &NodeRuntime) -> Option<[u8; 32]> {
    rt.consensus().state().finality.finalized_reference
}

fn store_get(rt: &NodeRuntime, hash: &[u8; 32]) -> Option<Block> {
    rt.block_production()
        .and_then(|a| a.block_store().and_then(|bs| bs.get(hash).ok().flatten()))
}

// ---------------------------------------------------------------------------
// wire fixture helpers（真实 TCP；既有 codec / 既有签名）
// ---------------------------------------------------------------------------

fn peer_auth(genesis_hash: [u8; 32]) -> PeerAuthConfig {
    PeerAuthConfig {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_hash,
        protocol_version: 1,
        capabilities: b"",
        per_peer_handshake_limit: 8,
        global_handshake_limit: 128,
        replay_cache_capacity: 256,
    }
}

fn sign_envelope(kp: &KeyPair, message_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: node_id_of(kp),
        signature: [0u8; 64],
    };
    sign_message(kp.signing_key(), &mut envelope).expect("sign envelope");
    envelope
}

fn init_envelope(kp: &KeyPair, auth: &PeerAuthConfig, nonce_tag: u8) -> MessageEnvelope {
    let id = node_id_of(kp);
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        auth.network_id,
        auth.chain_id,
        auth.genesis_hash,
        auth.protocol_version,
        &id,
        &SessionNonce::from_bytes([nonce_tag; 16]),
        auth.capabilities,
    )
    .expect("handshake encode");
    sign_envelope(kp, MessageType::Handshake, payload)
}

/// 读到满足条件的信封（bounded）。
fn recv_matching<F: Fn(&MessageEnvelope) -> bool>(
    t: &mut TcpTransport,
    pred: F,
    iters: usize,
) -> Option<MessageEnvelope> {
    for _ in 0..iters {
        if let Ok(Some((_from, bytes))) = t.try_recv()
            && let Ok(env) = decode(&bytes)
            && pred(&env)
        {
            return Some(env);
        }
        thread::sleep(Duration::from_millis(1));
    }
    None
}

/// wire fixture 作为 **client**：dial runtime（listener）→ 读对端 Init → 回带本端 Init。
///
/// 注意：runtime 只在 `step()` 中 accept/发送 Init ⇒ 本函数在等待期间**推进 runtime**。
fn client_handshake(
    a_addr: SocketAddr,
    a_id: NodeId,
    kp: &KeyPair,
    auth: &PeerAuthConfig,
    a: &mut NodeRuntime,
) -> Option<TcpTransport> {
    let self_id = node_id_of(kp);
    let mut t = TcpTransport::dial(a_addr, self_id, a_id, MAX_FRAME, None).ok()?;
    let peer_init = {
        let mut got = None;
        for _ in 0..MAX_ITER {
            let _ = a.step();
            if let Ok(Some((_from, bytes))) = t.try_recv()
                && let Ok(env) = decode(&bytes)
                && env.message_type == MessageType::Handshake
            {
                got = Some(env);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        got
    }?;
    assert_eq!(peer_init.sender, a_id, "对端 Init sender == runtime NodeId");
    let own = init_envelope(kp, auth, 0x11);
    t.send(&a_id, encode(&own)).ok()?;
    Some(t)
}

/// wire fixture 作为 **server**：accept runtime（dialer）→ 读其 Init → 回带本端 Init →
/// 依次发送给定 payload 信封（每帧间 sleep）。线程在发送完成后进入 bounded idle。
fn spawn_server_fixture(
    listener: TcpListener,
    kp: KeyPair,
    auth: PeerAuthConfig,
    frames: Vec<(MessageType, Vec<u8>)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let self_id = node_id_of(&kp);
        let Ok(mut t) =
            TcpTransport::accept(&listener, self_id, MAX_FRAME, Some(Duration::from_secs(10)))
        else {
            return;
        };
        let runtime_id = t.peer_id();
        // 读 runtime 的 Init（dial 后立即发出）。
        let Some(_) = recv_matching(
            &mut t,
            |e| e.message_type == MessageType::Handshake,
            MAX_ITER,
        ) else {
            return;
        };
        let own = init_envelope(&kp, &auth, 0x22);
        if t.send(&runtime_id, encode(&own)).is_err() {
            return;
        }
        for (mt, payload) in frames {
            let env = sign_envelope(&kp, mt, payload);
            if t.send(&runtime_id, encode(&env)).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(30));
        }
        for _ in 0..600 {
            let _ = t.try_recv();
            thread::sleep(Duration::from_millis(1));
        }
    })
}

/// 远端 canonical block（height / parent 显式；真实 proposer 签名）。
fn remote_block(
    sk: &SigningKey,
    genesis_hash: [u8; 32],
    state_root: [u8; 32],
    height: u64,
    parent_hash: [u8; 32],
    timestamp: u64,
) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height,
        parent_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: genesis_hash,
        timestamp,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

/// 在给定 runtime 的 genesis bootstrap 上（同 config）取 genesis state root。
fn genesis_state_root(config: &NodeConfig) -> [u8; 32] {
    let adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, config).expect("bootstrap");
    *adapter.store().state_root().as_bytes()
}

// ---------------------------------------------------------------------------
// T1 — REAL TCP E2E：production requester ↔ production responder（两个真实 NodeRuntime）
// ---------------------------------------------------------------------------

#[test]
fn d9s8a_t1_real_tcp_two_runtime_sync_roundtrip() {
    const SEED_A: [u8; 32] = [0xA1; 32];
    const SEED_B: [u8; 32] = [0xB1; 32];
    let genesis = genesis_with(&[pubkey_from_seed(SEED_A), pubkey_from_seed(SEED_B)]);
    let env = Env::new(&genesis);
    let set = ValidatorSet::from_genesis(&genesis);
    // height-1 块（父高轮 0）的 proposer 由既有 `select_proposer` 决定；把「proposer」作为 listener
    //（A），“另一验证者”作为 dialer（B）。角色按 seed 交换（两 seed 均为 genesis 成员）。
    let proposer = select_proposer(CHAIN_ID, 0, 0, &env.genesis_hash, &set).unwrap();
    let (a_seed, a_pub, b_seed) = if proposer == validator_id_from_seed(SEED_A) {
        (SEED_A, pubkey_from_seed(SEED_A), SEED_B)
    } else {
        (SEED_B, pubkey_from_seed(SEED_B), SEED_A)
    };

    // A（listener，validator）+ B（dialer，validator）→ 共同推进到 head 1 → head 2（真实 quorum）。
    let a_net = KeyPair::generate().unwrap();
    let a_id = node_id_of(&a_net);
    let b_net = KeyPair::generate().unwrap();
    let b_id = node_id_of(&b_net);

    let a_config = env.config("a", Some("127.0.0.1:0".parse().unwrap()), Vec::new());
    let mut a = start_node(&a_config, a_seed, a_net);
    let a_addr = a.network_listen_addr().expect("A listener bound");
    let b_config = env.config(
        "b",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut b = start_node(&b_config, b_seed, b_net);

    let established = wait_until(|| {
        let _ = b.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        a.network_peer_established(b_id) && b.network_peer_established(a_id)
    });
    assert!(established, "A/B 双向 Established（真实 TCP 握手）");

    let committed1 = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        head_height(&a) >= 1
    });
    assert!(committed1, "A 未 commit height 1（需 B 的真实 vote）");
    let block1_hash = head_hash(&a);
    let block1 = store_get(&a, &block1_hash).expect("A 已 durable 落盘 block 1");

    let committed2 = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        head_height(&a) >= 2
    });
    assert!(committed2, "A 未 commit height 2");

    // B2：**新节点**（fresh chain/safety 目录 ⇒ head 0），validator key = B 的 key，仅以 A 为目标。
    let b2_net = KeyPair::generate().unwrap();
    let b2_id = node_id_of(&b2_net);
    let b2_config = env.config(
        "b2",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut b2 = start_node(&b2_config, b_seed, b2_net);
    assert_eq!(head_height(&b2), 0, "B2 从 genesis 起步");

    let b2_established = wait_until(|| {
        let _ = b2.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        let _ = b2.step();
        a.network_peer_established(b2_id) && b2.network_peer_established(a_id)
    });
    assert!(b2_established, "A/B2 双向 Established");

    // A 的 height-2 块 gossip 到 B2（head 0）⇒ FutureMissingAncestor ⇒ B2 发起 SyncBlockRequest
    //（target = head+1 = height 1，hash=None）⇒ **A 的 production responder** 回带 block 1。
    let registered = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        let _ = b2.step();
        b2.consensus().dag().contains(&block1_hash)
    });
    let a_diag = a.sync_respond_diagnostics();
    assert!(
        registered,
        "B2 未通过 production sync responder 获得并登记 block 1（A serve={} / B2 resolved={}）",
        a_diag.served,
        b2.sync_resolved_responses(),
    );

    // A 侧：production responder 真实服务过请求。
    assert!(
        a_diag.served >= 1,
        "A responder served >= 1（实测 {}）",
        a_diag.served
    );
    assert_eq!(a_diag.missing, 0, "A 未把请求判为 missing");
    // B2 侧：真实 correlation resolve + DAG ancestry + durable 落盘。
    assert!(
        b2.sync_resolved_responses() >= 1,
        "B2 request lifecycle resolved"
    );
    assert_eq!(
        b2.consensus().dag().parents_of(&block1_hash),
        Some(&[env.genesis_hash][..]),
        "真实 ancestry（parent = genesis）"
    );
    let served_block = store_get(&b2, &block1_hash).expect("B2 durable 落盘 sync 来源块");
    assert_eq!(served_block.header.height, 1);
    assert_eq!(served_block.header.parent_hash, env.genesis_hash);
    assert_eq!(
        nova_runtime::block_hash(&served_block).unwrap(),
        block1_hash,
        "请求块 hash 关联一致（hash == A 侧同一块）"
    );
    nova_runtime::validate_block_signature(
        &served_block,
        &VerifyingKey::from_bytes(&a_pub).unwrap(),
        CHAIN_ID,
    )
    .expect("proposer 签名有效（sync 不绕过验证）");

    // §17 不变式（P1-A.7 / ADR-0064 精确定义）：
    // **block sync 本身不授予 finality** —— `SyncBlockResponse` 只提供 block；若无独立验证通过的
    // 历史 PrecommitQC，则 head 不推进、finality 不产生（见本文件后续 fixture-only 测试）。
    //
    // A7：production responder 在 block 响应之后**附发同一高度的已持久化 PrecommitQC**
    //（既有 `MessageType::ConsensusQc`；零 wire 变更）⇒ 本节点经 **Verified External Finality
    // Adoption** 采纳该外部 finality，并由**既有** durable commit bridge 提交 ⇒ head = 1。
    // 关键区别：推进 head 的不是 block，而是**独立验证通过**的外部 QC。
    let advanced = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        let _ = b2.step();
        head_height(&b2) >= 1
    });
    assert!(
        advanced,
        "A7：已验证外部 QC 未推进 head（adopted={} deferred={} served={}）",
        b2.external_finality_adopted(),
        b2.inbound_qc_deferred(),
        a.sync_respond_diagnostics().qc_served
    );
    assert_eq!(
        head_height(&b2),
        1,
        "A7：外部 QC 经既有 bridge 推进 head 至 1"
    );
    assert_eq!(head_hash(&b2), block1_hash, "A7：head == 外部 QC 所指块");
    assert_eq!(
        head_finality(&b2),
        Some(block1_hash),
        "A7：finalized_reference == 已验证外部 QC 的 target"
    );
    assert!(
        b2.external_finality_adopted() >= 1,
        "A7：采纳计数（实测 {}）",
        b2.external_finality_adopted()
    );

    let _ = block1; // A 侧同一块（已用于断言 hash 关联）
    drop(b2);
    drop(b);
    drop(a);
}

// ---------------------------------------------------------------------------
// T2 — hash 查找路径（wire fixture requester → 真实 NodeRuntime responder）
// ---------------------------------------------------------------------------

#[test]
fn d9s8a_t2_responder_serves_requested_hash() {
    const SEED: [u8; 32] = [0x51; 32];
    let genesis = genesis_with(&[pubkey_from_seed(SEED)]);
    let env = Env::new(&genesis);
    let a_net = KeyPair::generate().unwrap();
    let a_id = node_id_of(&a_net);
    let config = env.config("a", Some("127.0.0.1:0".parse().unwrap()), Vec::new());
    let mut a = start_node(&config, SEED, a_net);
    let a_addr = a.network_listen_addr().unwrap();

    // 单验证者 ⇒ 自行 commit block 1（唯一 block 数据源）。
    let committed = wait_until(|| {
        let _ = a.step();
        head_height(&a) >= 1
    });
    assert!(committed, "单验证者 A 未 commit height 1");
    let h1 = head_hash(&a);

    let f_kp = KeyPair::generate().unwrap();
    let auth = peer_auth(env.genesis_hash);
    let Some(mut t) = client_handshake(a_addr, a_id, &f_kp, &auth, &mut a) else {
        panic!("fixture 握手失败");
    };
    // 等待 A 侧完成认证（fixture 已回带 Init）。
    let authed = wait_until(|| {
        let _ = a.step();
        a.sync_respond_diagnostics().attempts > 0 || a.network_peer_established(node_id_of(&f_kp))
    });
    assert!(authed, "A 未认证 fixture");

    let request_id = nova_network::security::random_request_id().unwrap();
    let request = SyncBlockRequest {
        request_id,
        height: 1,
        block_hash: Some(h1),
    };
    let env_msg = sign_envelope(&f_kp, MessageType::SyncBlockRequest, request.encode());
    t.send(&a_id, encode(&env_msg)).expect("send request");

    let mut responded = None;
    for _ in 0..MAX_ITER {
        let _ = a.step();
        if let Some(env) = recv_matching(
            &mut t,
            |e| e.message_type == MessageType::SyncBlockResponse,
            2,
        ) {
            responded = Some(env);
            break;
        }
    }
    let env = responded.expect("A production responder 未回带 SyncBlockResponse");
    let response = SyncBlockResponse::decode(&env.payload).expect("response decode");
    assert_eq!(
        response.request_id, request_id,
        "request_id 原样回带（不生成新 id）"
    );
    assert_eq!(
        response.blocks.len(),
        MAX_SYNC_BLOCKS_PER_RESPONSE,
        "单块响应（MAX_SYNC_BLOCKS_PER_RESPONSE）"
    );
    let block = nova_runtime::decode_block(&response.blocks[0].0).expect("block decode");
    assert_eq!(
        nova_runtime::block_hash(&block).unwrap(),
        h1,
        "requested hash == returned block hash"
    );
    assert_eq!(block.header.height, 1);
    let diag = a.sync_respond_diagnostics();
    assert!(diag.served >= 1, "responder served >= 1（{}）", diag.served);
    drop(t);
    drop(a);
}

// ---------------------------------------------------------------------------
// T3 — missing / walk-exceeded（不伪造 / 不返回其它块 / 不 panic）
// ---------------------------------------------------------------------------

#[test]
fn d9s8a_t3_missing_and_walk_bounds_do_not_fabricate() {
    const SEED: [u8; 32] = [0x52; 32];
    let genesis = genesis_with(&[pubkey_from_seed(SEED)]);
    let env = Env::new(&genesis);
    let a_net = KeyPair::generate().unwrap();
    let a_id = node_id_of(&a_net);
    let config = env.config("a", Some("127.0.0.1:0".parse().unwrap()), Vec::new());
    let mut a = start_node(&config, SEED, a_net);
    let a_addr = a.network_listen_addr().unwrap();

    // 推进到 head > MAX_SYNC_WALK（单验证者逐步 commit）⇒ 使 height=1 的请求**超过**回走上限。
    let deep = MAX_SYNC_WALK + 2;
    let reached = wait_until(|| {
        let _ = a.step();
        head_height(&a) >= deep
    });
    assert!(
        reached,
        "A 未推进到 head >= {deep}（实测 {}）",
        head_height(&a)
    );

    let f_kp = KeyPair::generate().unwrap();
    let auth = peer_auth(env.genesis_hash);
    let Some(mut t) = client_handshake(a_addr, a_id, &f_kp, &auth, &mut a) else {
        panic!("fixture 握手失败");
    };
    let authed = wait_until(|| {
        let _ = a.step();
        a.network_peer_established(node_id_of(&f_kp))
    });
    assert!(authed, "A 未认证 fixture");

    // ① unknown hash ⇒ Missing（不响应）。
    let rid1 = nova_network::security::random_request_id().unwrap();
    let req1 = SyncBlockRequest {
        request_id: rid1,
        height: 1,
        block_hash: Some([0xAB; 32]),
    };
    t.send(
        &a_id,
        encode(&sign_envelope(
            &f_kp,
            MessageType::SyncBlockRequest,
            req1.encode(),
        )),
    )
    .expect("send req1");
    // ② height=1（无 hash），head 远高于 1 ⇒ 回走超过 MAX_SYNC_WALK ⇒ WalkExceeded（不响应）。
    let rid2 = nova_network::security::random_request_id().unwrap();
    let req2 = SyncBlockRequest {
        request_id: rid2,
        height: 1,
        block_hash: None,
    };
    t.send(
        &a_id,
        encode(&sign_envelope(
            &f_kp,
            MessageType::SyncBlockRequest,
            req2.encode(),
        )),
    )
    .expect("send req2");
    // ③ height 超过 head ⇒ Missing（不响应）。
    let rid3 = nova_network::security::random_request_id().unwrap();
    let req3 = SyncBlockRequest {
        request_id: rid3,
        height: head_height(&a) + 5,
        block_hash: None,
    };
    t.send(
        &a_id,
        encode(&sign_envelope(
            &f_kp,
            MessageType::SyncBlockRequest,
            req3.encode(),
        )),
    )
    .expect("send req3");

    // 有界推进 + 断言**没有**任何响应（不伪造 / 不用 head 冒充 / 不回其它高度）。
    let mut unexpected = None;
    for _ in 0..400 {
        let _ = a.step();
        if let Ok(Some((_f, bytes))) = t.try_recv()
            && let Ok(env) = decode(&bytes)
            && env.message_type == MessageType::SyncBlockResponse
        {
            unexpected = Some(env);
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        unexpected.is_none(),
        "缺失/超限请求不得产生响应（实测收到 {:?}）",
        unexpected.map(|e| e.message_type)
    );
    let diag = a.sync_respond_diagnostics();
    assert!(diag.missing >= 2, "missing 计数（实测 {}）", diag.missing);
    assert!(
        diag.walk_exceeded >= 1,
        "walk_exceeded 计数（实测 {}）",
        diag.walk_exceeded
    );
    assert_eq!(diag.served, 0, "无任何成功响应");
    drop(t);
    drop(a);
}

// ---------------------------------------------------------------------------
// T4 — Established-only（未认证请求不进入 responder；由既有 NetworkService gate 丢弃）
// ---------------------------------------------------------------------------

#[test]
fn d9s8a_t4_non_established_request_never_reaches_responder() {
    const SEED: [u8; 32] = [0x53; 32];
    let genesis = genesis_with(&[pubkey_from_seed(SEED)]);
    let env = Env::new(&genesis);
    let a_net = KeyPair::generate().unwrap();
    let a_id = node_id_of(&a_net);
    let config = env.config("a", Some("127.0.0.1:0".parse().unwrap()), Vec::new());
    let mut a = start_node(&config, SEED, a_net);
    let a_addr = a.network_listen_addr().unwrap();

    // 只发 32B 身份首包 + 一个**签名有效**的 SyncBlockRequest（**不握手**）。
    let f_kp = KeyPair::generate().unwrap();
    let f_id = node_id_of(&f_kp);
    let mut t = TcpTransport::dial(a_addr, f_id, a_id, MAX_FRAME, None).expect("dial A");
    let rid = nova_network::security::random_request_id().unwrap();
    let request = SyncBlockRequest {
        request_id: rid,
        height: 1,
        block_hash: None,
    };
    t.send(
        &a_id,
        encode(&sign_envelope(
            &f_kp,
            MessageType::SyncBlockRequest,
            request.encode(),
        )),
    )
    .expect("send unauthenticated request");

    for _ in 0..200 {
        a.step().expect("step ok");
        thread::sleep(Duration::from_millis(1));
    }
    // 未认证 ⇒ 既有 NS 门 fail-closed drop：既不进 wiring 队列，也不产生响应。
    assert_eq!(
        a.sync_respond_diagnostics().attempts,
        0,
        "未认证请求不得到达 responder"
    );
    assert_eq!(a.sync_respond_diagnostics().served, 0);
    assert!(
        !a.network_peer_established(f_id),
        "未认证 peer 不 Established"
    );
    let mut got_response = false;
    for _ in 0..50 {
        if let Ok(Some((_f, bytes))) = t.try_recv()
            && let Ok(env) = decode(&bytes)
            && env.message_type == MessageType::SyncBlockResponse
        {
            got_response = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(!got_response, "未认证请求不得获得响应");
    drop(t);
    drop(a);
}

// ---------------------------------------------------------------------------
// T5 — G1：restart 后 stored-but-unregistered 块的幂等补登记
// ---------------------------------------------------------------------------

#[test]
fn d9s8a_t5_restart_reregisters_stored_but_unregistered_block() {
    const SEED_P: [u8; 32] = [0x61; 32];
    const SEED_F: [u8; 32] = [0x62; 32];
    let genesis = genesis_with(&[pubkey_from_seed(SEED_P), pubkey_from_seed(SEED_F)]);
    let env = Env::new(&genesis);
    let set = ValidatorSet::from_genesis(&genesis);
    let proposer = select_proposer(CHAIN_ID, 0, 0, &env.genesis_hash, &set).unwrap();
    // 「块生产者」= height-1 proposer；「被测节点 F」= 另一验证者（非 proposer ⇒ 不会自行出块）。
    let (producer_seed, follower_seed) = if proposer == validator_id_from_seed(SEED_P) {
        (SEED_P, SEED_F)
    } else {
        (SEED_F, SEED_P)
    };

    // 被测节点 config（同一 `node` 标签 ⇒ restart 复用同一 chain/safety 目录）。
    let f_net = KeyPair::generate().unwrap();
    let genesis_state_root = genesis_state_root(&env.config("f", None, Vec::new()));
    // 远端 canonical block X（height 1 / parent genesis；由 proposer key 真实签名）。
    let x = remote_block(
        &SigningKey::from_seed(producer_seed),
        env.genesis_hash,
        genesis_state_root,
        1,
        env.genesis_hash,
        0,
    );
    let x_hash = nova_runtime::block_hash(&x).unwrap();
    let x_wire = nova_runtime::encode_block(&x).unwrap();

    // -------- phase 1：F 收到 X（gossip）⇒ 登记 + 落盘，但不 commit --------
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr1 = l1.local_addr().unwrap();
    let fx_kp = KeyPair::generate().unwrap();
    let fx_id = node_id_of(&fx_kp);
    let cfg1 = env.config(
        "f",
        None,
        vec![ConnectionTarget {
            peer_id: fx_id,
            address: addr1,
        }],
    );
    let mut f1 = start_node(&cfg1, follower_seed, f_net);
    let h1 = spawn_server_fixture(
        l1,
        fx_kp,
        peer_auth(env.genesis_hash),
        vec![(MessageType::GossipBlock, x_wire.clone())],
    );
    let established = wait_until(|| {
        let _ = f1.establish_configured_peers();
        let _ = f1.step();
        f1.network_peer_established(fx_id)
    });
    assert!(established, "F 未与 fixture Established");
    let registered1 = wait_until(|| {
        let _ = f1.step();
        f1.consensus().dag().contains(&x_hash)
    });
    assert!(registered1, "phase 1：X 未登记进 DAG");
    assert!(
        store_get(&f1, &x_hash).is_some(),
        "phase 1：X 未 durable 落盘"
    );
    assert_eq!(head_height(&f1), 0, "phase 1：head 不推进");
    assert_eq!(head_finality(&f1), None, "phase 1：无 finality");
    drop(f1);
    let _ = h1.join();

    // -------- restart：同 chain/safety 目录；新 fixture 地址 --------
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = l2.local_addr().unwrap();
    let fx2_kp = KeyPair::generate().unwrap();
    let fx2_id = node_id_of(&fx2_kp);
    let cfg2 = env.config(
        "f",
        None,
        vec![ConnectionTarget {
            peer_id: fx2_id,
            address: addr2,
        }],
    );
    let mut f2 = start_node(&cfg2, follower_seed, KeyPair::generate().unwrap());
    assert_eq!(head_height(&f2), 0, "restart 后 head 仍为旧高度（0）");
    assert!(
        !f2.consensus().dag().contains(&x_hash),
        "G1 前提：restart 后 DAG 不含 X（DAG 不持久化，仅按 head 祖先链重建）"
    );
    assert!(
        store_get(&f2, &x_hash).is_some(),
        "restart 后 X 仍在 BlockStore"
    );

    // 重新投递同一 X（两次）⇒ 第一次补登记；第二次为真 AlreadyKnown（幂等）。
    let h2 = spawn_server_fixture(
        l2,
        fx2_kp,
        peer_auth(env.genesis_hash),
        vec![
            (MessageType::GossipBlock, x_wire.clone()),
            (MessageType::GossipBlock, x_wire.clone()),
        ],
    );
    let established2 = wait_until(|| {
        let _ = f2.establish_configured_peers();
        let _ = f2.step();
        f2.network_peer_established(fx2_id)
    });
    assert!(established2, "restart 后 F 未与新 fixture Established");
    let reregistered = wait_until(|| {
        let _ = f2.step();
        f2.consensus().dag().contains(&x_hash)
    });
    assert!(
        reregistered,
        "G1 未修复：restart 后重新投递的 X 未补登记进 DAG"
    );
    assert_eq!(
        f2.consensus().dag().parents_of(&x_hash),
        Some(&[env.genesis_hash][..]),
        "补登记使用真实 ancestry（parent = genesis）"
    );
    // 全验证仍然执行（②③④⑤⑥⑦）：若被 AlreadyKnown 短路则不会出现 CanonicalNextCandidate。
    let first_batch = f2.take_block_inbound_outcomes();
    assert!(
        first_batch.iter().any(|o| matches!(
            o,
            Ok(InboundBlockVerdict::CanonicalNextCandidate { block_hash, height })
                if *block_hash == x_hash && *height == 1
        )),
        "补登记前必须走完 ⑥/⑦ 全验证（实测 {first_batch:?}）"
    );
    // 幂等：第二次投递为真 AlreadyKnown（DAG 已含 ⇒ 终态短路）；可能已落在同一批 outcomes。
    let mut idempotent = first_batch.iter().any(
        |o| matches!(o, Ok(InboundBlockVerdict::AlreadyKnown { block_hash, .. }) if *block_hash == x_hash),
    );
    if !idempotent {
        idempotent = wait_until(|| {
            let _ = f2.step();
            f2.take_block_inbound_outcomes()
                .iter()
                .any(|o| matches!(o, Ok(InboundBlockVerdict::AlreadyKnown { block_hash, .. }) if *block_hash == x_hash))
        });
    }
    assert!(
        idempotent,
        "重复投递应命中真 AlreadyKnown（DAG 已含 ⇒ 幂等 no-op）"
    );
    // §17 不变式（**保留并强化**）：**只有 block、没有 QC** ⇒ **不产生 finality**。
    // 本测试的 fixture 只发 `GossipBlock`（从不发 `ConsensusQc`）⇒ 无论 DAG 登记多少次，
    // 都不能推进 head 或产生 finality（ADR-0064：外部 finality 必须来自独立验证的 PrecommitQC）。
    assert_eq!(head_height(&f2), 0, "仅 block（无 QC）⇒ head 不推进");
    assert_eq!(head_hash(&f2), env.genesis_hash, "head 仍为 genesis");
    assert_eq!(
        head_finality(&f2),
        None,
        "仅 block（无 QC）⇒ 不产生 finality"
    );
    assert!(
        f2.sync_respond_diagnostics().served == 0,
        "本测试不涉及 responder"
    );
    drop(f2);
    let _ = h2.join();
}
