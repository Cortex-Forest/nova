//! D9 — Proposal / Canonical Block Egress（真实 production runtime + 真实 TCP 对端）。
//!
//! 证明 production 数据流已闭环：
//! ```text
//! runtime_propose（build → sign → BlockStore.put → submit_proposal → register_block）
//!     → record_local_proposal（ProposalRef + block wire）
//!     → driver.pending_outbound
//!     → step() egress（egress::envelope_for：NetworkSigner 签名）
//!     → NetworkService.broadcast（connected ∧ established only）→ flush
//!     → peer 收到 ConsensusProposal + GossipBlock（同一 canonical block）
//! ```
//! 断言：payload 可被现有 decoder 还原；`ProposalRef.block_hash == block_hash(block)`；
//! 每个本地生产的块恰好一次 Proposal + 一次 Block（不重复广播）；established-only。
//!
//! 无 mock head / 无手设 consensus state；对端为程序化 TCP fixture（测试专用，非生产）。

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nova_consensus::round::{ProposalRef, decode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::VerifyingKey;
use nova_network::message::{MessageEnvelope, MessageType, decode, encode};
use nova_network::node_id::NodeId;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_encode, random_session_nonce,
};
use nova_network::transport::{ConnectionTarget, MemoryTransport, TcpTransport, Transport};

use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::{NodeRuntime, PeerStatus};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
const MAX_ITER: usize = 3000;

/// 对端捕获（peer 线程写入）：`(message_type, payload)` 原样。
type Captured = Arc<Mutex<Vec<(MessageType, Vec<u8>)>>>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// 单验证者 genesis（validators = runtime 的 validator key ⇒ 本节点即当选 proposer）。
fn single_validator_genesis(pk: [u8; 32]) -> GenesisV1 {
    let account = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: account.address,
            consensus_public_key: pk,
            bonded_stake: STAKE,
            commission_bps: 0,
        }],
        initial_accounts: vec![account],
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
            total_supply: 1_000_000,
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
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d9eg_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        Self {
            _dir: dir,
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self, peers: Vec<ConnectionTarget>) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

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

fn envelope(
    signer: &dyn NetworkSigner,
    message_type: MessageType,
    payload: Vec<u8>,
) -> MessageEnvelope {
    MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: signer.node_id(),
        signature: [0u8; 64],
    }
}

fn init_envelope(signer: &dyn NetworkSigner, auth: &PeerAuthConfig) -> MessageEnvelope {
    let nonce = random_session_nonce().unwrap();
    let local = signer.node_id();
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        auth.network_id,
        auth.chain_id,
        auth.genesis_hash,
        auth.protocol_version,
        &local,
        &nonce,
        auth.capabilities,
    )
    .unwrap();
    let mut env = envelope(signer, MessageType::Handshake, payload);
    signer.sign_envelope(&mut env).unwrap();
    env
}

/// 程序化 TCP 对端：accept → 回 Init → 持续记录收到的 envelope payload（不做其他语义）。
fn run_peer_capture(
    listener: TcpListener,
    peer_kp: KeyPair,
    auth: PeerAuthConfig,
    captured: Captured,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let peer_id = NodeId::from_verifying_key(peer_kp.verifying_key());
        let signer = SoftwareNetworkIdentity::new(peer_kp);
        let mut tcp = match TcpTransport::accept(
            &listener,
            peer_id,
            1024 * 1024,
            Some(Duration::from_secs(10)),
        ) {
            Ok(t) => t,
            Err(_) => return,
        };
        let runtime_id = tcp.peer_id();
        // 读 runtime Init（dial 后立即发出）→ 回对端 Init（runtime 侧完成握手）。
        let mut got_init = false;
        for _ in 0..MAX_ITER {
            if let Ok(Some(_)) = tcp.try_recv() {
                got_init = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if !got_init {
            return;
        }
        let _ = tcp.send(&runtime_id, encode(&init_envelope(&signer, &auth)));
        for _ in 0..MAX_ITER {
            if tcp.is_closed() {
                return;
            }
            if let Ok(Some((_from, bytes))) = tcp.try_recv()
                && let Ok(env) = decode(&bytes)
            {
                captured
                    .lock()
                    .unwrap()
                    .push((env.message_type, env.payload));
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

/// 启动 validator runtime（network 装配 + configured peer target），返回 (runtime, captured, vk)。
fn start_validator(config: &NodeConfig, validator_kp: KeyPair) -> (NodeRuntime, Captured) {
    let net_kp = KeyPair::generate().unwrap();
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_dummy) = MemoryTransport::pair(net_id, NodeId::from_bytes([0x99; 32]));
    let runtime = NodeRuntime::start_with_network(
        config,
        Some(&SoftwareKeyProvider::from_keypair(validator_kp)),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("validator + network 启动");
    (runtime, Arc::new(Mutex::new(Vec::new())))
}

fn establish(runtime: &mut NodeRuntime, peer_id: NodeId) {
    let mut established = false;
    for _ in 0..MAX_ITER {
        let res = runtime.establish_configured_peers().expect("establish ok");
        if matches!(res[0].status, PeerStatus::Established) {
            established = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(established, "runtime Established peer（真实 TCP 握手）");
    assert!(runtime.network_peer_established(peer_id));
}

fn step_until_head(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..MAX_ITER {
        runtime.step().expect("step ok");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("head 未推进到 {want_height}");
}

fn wait_until<F: Fn() -> bool>(f: F) -> bool {
    for _ in 0..MAX_ITER {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
    }
    false
}

fn payloads_of(captured: &Captured, want: MessageType) -> Vec<Vec<u8>> {
    captured
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| *t == want)
        .map(|(_, p)| p.clone())
        .collect()
}

fn proposals_of(captured: &Captured) -> Vec<ProposalRef> {
    payloads_of(captured, MessageType::ConsensusProposal)
        .iter()
        .map(|p| decode_proposal_ref(p).expect("ProposalRef decode"))
        .collect()
}

fn blocks_of(captured: &Captured) -> Vec<nova_runtime::Block> {
    payloads_of(captured, MessageType::GossipBlock)
        .iter()
        .map(|p| nova_runtime::decode_block(p).expect("block decode"))
        .collect()
}

// ---------------------------------------------------------------------------
// Test A/B/C + E — Proposal + Block 真实出站至 established peer（可解码、hash 关联、真实签名）
// ---------------------------------------------------------------------------

#[test]
fn d9_eg1_proposal_and_block_egress_to_established_peer() {
    let validator_kp = KeyPair::generate().unwrap();
    let pk = validator_kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let env = Env::new(&genesis);
    let genesis_hash = env.genesis_hash;
    let validator_id = ValidatorId::from_consensus_public_key(&pk);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let peer_id = node_id_of(&peer_kp);
    let config = env.config(vec![ConnectionTarget {
        peer_id,
        address: laddr,
    }]);

    let (mut runtime, captured) = start_validator(&config, validator_kp);
    assert!(runtime.network_peer_auth_enabled(), "peer-auth 已装配");
    let handle = run_peer_capture(listener, peer_kp, peer_auth(genesis_hash), captured.clone());
    establish(&mut runtime, peer_id);

    // production path：propose → register → outbound（第一个块的 commit 前即已广播）。
    step_until_head(&mut runtime, 1);
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let got_both = wait_until(|| {
        !payloads_of(&captured, MessageType::ConsensusProposal).is_empty()
            && !payloads_of(&captured, MessageType::GossipBlock).is_empty()
    });
    assert!(got_both, "peer 收到 ConsensusProposal + GossipBlock");

    // Test D（单块）：恰好 1 次 Proposal + 1 次 Block（无重复广播）。
    let proposals = proposals_of(&captured);
    let blocks = blocks_of(&captured);
    assert_eq!(
        proposals.len(),
        1,
        "一个本地 proposal ⇒ 恰好一次 Proposal outbound"
    );
    assert_eq!(
        blocks.len(),
        1,
        "同一 canonical block ⇒ 恰好一次 Block outbound"
    );

    // Test A：ProposalRef 结构正确（proposer = 本地 validator）。
    let pr = &proposals[0];
    assert_eq!(
        pr.proposer, validator_id,
        "proposal.proposer == 本地 validator"
    );

    // Test B：block wire 可被现有 decoder 还原。
    let block = &blocks[0];
    assert_eq!(block.header.height, 1);
    assert_eq!(
        block.header.parent_hash, genesis_hash,
        "canonical-next parent"
    );
    assert_eq!(block.header.chain_id, CHAIN_ID);
    // 真实 proposer 签名（本 actor 签名；可被 validator vk 验证 ⇒ 非伪造块）。
    nova_runtime::validate_block_signature(block, &vk, CHAIN_ID).expect("proposer 签名有效");

    // Test C：Proposal ↔ Block 同一 canonical block。
    let decoded_hash = nova_runtime::block_hash(block).unwrap();
    assert_eq!(
        pr.block_hash, decoded_hash,
        "ProposalRef.block_hash == 广播 block 的 hash（同一 canonical block）"
    );

    // 既有 pipeline 未受影响：votes（本地 Prevote/Precommit）+ 已验证 QC 仍照常出站
    //（有界等待真实到达；QC 在达成 precommit quorum 的 tick 才产生）。
    let legacy_ok = wait_until(|| {
        !payloads_of(&captured, MessageType::ConsensusVote).is_empty()
            && !payloads_of(&captured, MessageType::ConsensusQc).is_empty()
    });
    assert!(legacy_ok, "既有 vote / verified-QC egress 未回归");

    drop(runtime);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Test D（多高度）— 每个本地生产的块恰好一次 Proposal + 一次 Block（跨高度不重复）
// ---------------------------------------------------------------------------

#[test]
fn d9_eg2_no_duplicate_broadcast_across_produced_blocks() {
    let validator_kp = KeyPair::generate().unwrap();
    let pk = validator_kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let env = Env::new(&genesis);
    let genesis_hash = env.genesis_hash;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let peer_id = node_id_of(&peer_kp);
    let config = env.config(vec![ConnectionTarget {
        peer_id,
        address: laddr,
    }]);

    let (mut runtime, captured) = start_validator(&config, validator_kp);
    let handle = run_peer_capture(listener, peer_kp, peer_auth(genesis_hash), captured.clone());
    establish(&mut runtime, peer_id);

    // 连续生产 3 个高度（同进程；Step 7-B 高度推进）。
    step_until_head(&mut runtime, 3);
    let enough = wait_until(|| blocks_of(&captured).len() >= 3);
    assert!(enough, "peer 收到 3 个 block");

    let blocks = blocks_of(&captured);
    let proposals = proposals_of(&captured);

    // 每个 distinct block hash 恰好出现一次（同块不重复广播；无 retransmission 需求）。
    let mut hashes: Vec<[u8; 32]> = blocks
        .iter()
        .map(|b| nova_runtime::block_hash(b).unwrap())
        .collect();
    let total = hashes.len();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(total, hashes.len(), "每个 block 只广播一次（无重复）");

    // Proposal ↔ Block 一一对应（1:1；无多余 proposal / 无孤立 block）。
    assert_eq!(
        proposals.len(),
        hashes.len(),
        "proposal 数 == distinct block 数（1:1）"
    );
    for pr in &proposals {
        assert!(
            hashes.contains(&pr.block_hash),
            "每个 ProposalRef 都对应一个已广播 block（hash 一致）"
        );
    }
    // 高度线性（canonical-next 链）。
    let mut heights: Vec<u64> = blocks.iter().map(|b| b.header.height).collect();
    heights.sort_unstable();
    assert_eq!(heights, vec![1, 2, 3], "广播块高度 = 1/2/3（生产顺序一致）");

    drop(runtime);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Test E — established-only：未建立会话前不投递；建立后仅投递新块
// ---------------------------------------------------------------------------

#[test]
fn d9_eg3_established_only_egress() {
    let validator_kp = KeyPair::generate().unwrap();
    let pk = validator_kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let env = Env::new(&genesis);
    let genesis_hash = env.genesis_hash;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let peer_id = node_id_of(&peer_kp);
    let config = env.config(vec![ConnectionTarget {
        peer_id,
        address: laddr,
    }]);

    let (mut runtime, captured) = start_validator(&config, validator_kp);
    let handle = run_peer_capture(listener, peer_kp, peer_auth(genesis_hash), captured.clone());

    // 未建立会话：本地照常生产并 commit 第一个块（head=1），但**不投递**任何消息。
    step_until_head(&mut runtime, 1);
    assert!(
        captured.lock().unwrap().is_empty(),
        "无 established peer ⇒ 不发送（bounded drop；不 panic）"
    );

    // 建立会话（真实 TCP dial + 握手）后，只有**之后生产**的块被投递。
    establish(&mut runtime, peer_id);
    step_until_head(&mut runtime, 2);
    let got = wait_until(|| !blocks_of(&captured).is_empty());
    assert!(got, "建立后 peer 收到新块");

    let heights: Vec<u64> = blocks_of(&captured)
        .iter()
        .map(|b| b.header.height)
        .collect();
    assert_eq!(
        heights,
        vec![2],
        "仅投递 established 之后生产的块（高度 1 从未投递；established-only 生效）"
    );
    let proposals = proposals_of(&captured);
    assert_eq!(proposals.len(), 1, "仅一次 Proposal outbound（高度 2）");
    let block2 = blocks_of(&captured)[0].clone();
    assert_eq!(
        proposals[0].block_hash,
        nova_runtime::block_hash(&block2).unwrap(),
        "Proposal ↔ Block hash 一致"
    );

    drop(runtime);
    let _ = handle.join();
}

/// 环境自检：单验证者集合 quorum 可由单票达成（本文件的生产前置）。
#[test]
fn d9_eg0_single_validator_precondition() {
    let kp = KeyPair::generate().unwrap();
    let genesis = single_validator_genesis(kp.verifying_key().to_bytes());
    let set = ValidatorSet::from_genesis(&genesis);
    assert!(set.quorum() <= STAKE, "单验证者自身可达 quorum");
}
