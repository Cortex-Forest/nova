//! D9 Step 7 — Inbound Listener（真实 `TcpListener` / 真实 `TcpStream` / 两个真实 `NodeRuntime`）。
//!
//! 证明 production 入站路径闭环：
//! ```text
//! NodeConfig.listen_addr = Some(addr)
//!     → NodeRuntime::start（bind nonblocking listener）
//!     → step：有界 accept（≤ MAX_ACCEPT_PER_STEP）→ TcpTransport::from_accepted（32B 首包）
//!     → 确定性 multiplex（BTreeMap + cursor）→ 注入 NetworkService::poll_transport
//!     → 既有 decode / verify / process_handshake（**无第二套认证**）
//!     → KEEP-FIRST / connect_peer（connected ≠ authenticated）/ 本端 Init / EOF 清理
//! ```
//! 断言全部经 `NodeRuntime` **公开 API**（不触碰 listener / multiplex 内部；不用 `MemoryTransport`
//! 模拟 inbound listener）。除 D9-IN0（默认 `None` ⇒ 无 listener）外，其余测试均为真实 TCP 双节点。

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash, validator_id,
};
use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, MessageType, encode};
use nova_network::node_id::NodeId;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_encode, random_session_nonce,
};
use nova_network::transport::{
    ConnectionTarget, MemoryTransport, TcpTransport, Transport, frame_encode,
};
use nova_node::block_inbound::InboundBlockVerdict;
use nova_node::bootstrap::NodeConfig;
use nova_node::inbound::{MAX_ACCEPT_PER_STEP, MAX_INBOUND_CONNECTIONS};
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::NodeRuntime;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
const MAX_FRAME: usize = 1024 * 1024;
/// 有界等待循环上限（每次 1ms；测试确定性退出，不用无限等待）。
const MAX_ITER: usize = 600;

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

/// 双验证者 genesis（A/B 共用；用于「A 出块 → B 收块 → B 投票 → A finality/commit」闭环）。
///
/// canonical 约束（crypto `validate_genesis_with_expected`）：
/// - `initial_validator_set` 必须按 `validator_id` **严格升序** ⇒ 按 id 排序（不自动排序）；
/// - `initial_accounts` 按 address bytes 升序；
/// - `total_supply == Σ liquid_balance`。
fn two_validator_genesis(pk1: [u8; 32], pk2: [u8; 32]) -> GenesisV1 {
    let acc1 = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    let acc2 = AccountInit {
        address: addr([0x22; 32]),
        liquid_balance: 1_000_000,
    };
    let mut validators = vec![
        (validator_id(&pk1), pk1, acc1.address),
        (validator_id(&pk2), pk2, acc2.address),
    ];
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
        initial_accounts: vec![acc1, acc2],
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
            total_supply: 2_000_000,
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
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d9in_{}_{}", std::process::id(), n));
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

    fn config(
        &self,
        listen_addr: Option<SocketAddr>,
        peers: Vec<ConnectionTarget>,
        validator_enabled: bool,
    ) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr,
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn validator_id_of(kp: &KeyPair) -> ValidatorId {
    ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
}

/// 启动真实 runtime（网络装配 + 显式网络身份；`listen_addr` 由 config 决定）。
fn start_node(config: &NodeConfig, validator_kp: Option<KeyPair>, net_kp: KeyPair) -> NodeRuntime {
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_other) = MemoryTransport::pair(net_id, NodeId::from_bytes([0x99; 32]));
    let provider = validator_kp.map(SoftwareKeyProvider::from_keypair);
    NodeRuntime::start_with_network(
        config,
        provider
            .as_ref()
            .map(|p| p as &dyn nova_node::key_provider::KeyProvider),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("runtime 启动（真实网络装配）")
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

/// A/B 双节点装配：**listener = height-1 proposer**（使「A 出块」确定）。
struct Ab {
    genesis: GenesisV1,
    a_kp: KeyPair,
    b_kp: KeyPair,
}

fn setup_ab() -> Ab {
    let kp1 = KeyPair::generate().unwrap();
    let kp2 = KeyPair::generate().unwrap();
    let genesis = two_validator_genesis(
        kp1.verifying_key().to_bytes(),
        kp2.verifying_key().to_bytes(),
    );
    let set = ValidatorSet::from_genesis(&genesis);
    let genesis_hash = compute_genesis_hash(&genesis).unwrap();
    // canonical-next（height 1）的 proposer —— 与 node 内部 `select_proposer(chain_id, head.height=0, 0, …)`
    // 同源（`build_proposal` / `block_dispatch` / commit bridge 一致）。
    let proposer = select_proposer(CHAIN_ID, 0, 0, &genesis_hash, &set).unwrap();
    let (a_kp, b_kp) = if proposer == validator_id_of(&kp1) {
        (kp1, kp2)
    } else {
        (kp2, kp1)
    };
    Ab {
        genesis,
        a_kp,
        b_kp,
    }
}

/// 启动 A（listener）+ B（dial A）并推进双向 Established。
struct Pair {
    a: NodeRuntime,
    b: NodeRuntime,
    a_id: NodeId,
    b_id: NodeId,
    a_addr: SocketAddr,
    a_vk: nova_crypto::signature::VerifyingKey,
}

fn start_established_pair(ab: Ab) -> Pair {
    let Ab {
        genesis,
        a_kp,
        b_kp,
    } = ab;
    let a_vk = *a_kp.verifying_key();
    // 每个节点**独立** chain storage + safety journal（同一 genesis ⇒ 同一链身份）。
    let env_a = Env::new(&genesis);
    let env_b = Env::new(&genesis);
    let a_net = KeyPair::generate().unwrap();
    let b_net = KeyPair::generate().unwrap();
    let a_id = node_id_of(&a_net);
    let b_id = node_id_of(&b_net);

    let a_config = env_a.config(Some("127.0.0.1:0".parse().unwrap()), Vec::new(), true);
    let mut a = start_node(&a_config, Some(a_kp), a_net);
    let a_addr = a
        .network_listen_addr()
        .expect("listener 已绑定（port 0 → 真实端口）");

    let b_config = env_b.config(
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
        true,
    );
    let mut b = start_node(&b_config, Some(b_kp), b_net);

    let ok = wait_until(|| {
        let _ = b.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        a.network_peer_established(b_id) && b.network_peer_established(a_id)
    });
    assert!(ok, "双向握手未完成（A listen / B dial）");
    Pair {
        a,
        b,
        a_id,
        b_id,
        a_addr,
        a_vk,
    }
}

// ---------------------------------------------------------------------------
// D9-IN0 — listen_addr = None ⇒ 现行为完全不变
// ---------------------------------------------------------------------------

#[test]
fn d9_in0_listen_addr_none_keeps_existing_behavior() {
    let kp1 = KeyPair::generate().unwrap();
    let genesis = two_validator_genesis(
        kp1.verifying_key().to_bytes(),
        KeyPair::generate().unwrap().verifying_key().to_bytes(),
    );
    let env = Env::new(&genesis);

    // 出站 dial fixture（既有行为：configured target 真实 TCP）。
    let fixture = TcpListener::bind("127.0.0.1:0").unwrap();
    let faddr = fixture.local_addr().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let peer_id = node_id_of(&peer_kp);
    let handle = thread::spawn(move || {
        if let Ok(mut t) =
            TcpTransport::accept(&fixture, peer_id, MAX_FRAME, Some(Duration::from_secs(5)))
        {
            for _ in 0..200 {
                let _ = t.try_recv();
                thread::sleep(Duration::from_millis(1));
            }
        }
    });

    let config = env.config(
        None,
        vec![ConnectionTarget {
            peer_id,
            address: faddr,
        }],
        true,
    );
    let mut a = start_node(&config, Some(kp1), KeyPair::generate().unwrap());

    // 无 listener 的三重可观测断言。
    assert!(
        a.network_listen_addr().is_none(),
        "listen_addr=None ⇒ 无 listener"
    );
    assert!(
        a.network_inbound_diagnostics().is_none(),
        "listen_addr=None ⇒ 无 inbound 状态"
    );
    assert_eq!(a.network_inbound_connection_count(), 0);

    // 既有出站路径不变（真实 dial + connected）。
    assert_eq!(a.connect_configured_peer().expect("dial ok"), Some(peer_id));
    assert!(
        a.network_peer_connected(peer_id),
        "既有 outbound dial 未回归"
    );
    for _ in 0..20 {
        a.step().expect("step ok（无 listener 分支）");
    }
    drop(a);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// D9-IN1 — 真实双向 Establishment（A listen / B dial）
// ---------------------------------------------------------------------------

#[test]
fn d9_in1_bidirectional_establishment_over_real_tcp() {
    let ab = setup_ab();
    let Pair {
        a,
        b,
        a_id,
        b_id,
        a_addr,
        a_vk: _,
    } = start_established_pair(ab);

    assert_ne!(a_addr.port(), 0, "真实监听端口");
    assert!(
        a.network_peer_established(b_id),
        "A established B（入站握手）"
    );
    assert!(
        b.network_peer_established(a_id),
        "B established A（对称 Init）"
    );
    assert!(a.network_peer_connected(b_id), "A connected B");
    assert!(b.network_peer_connected(a_id), "B connected A");
    assert!(a.network_peer_auth_enabled());
    assert_eq!(a.network_inbound_connection_count(), 1, "1 条入站连接");
    assert!(a.network_inbound_diagnostics().unwrap().accepted >= 1);

    drop(a);
    drop(b);
}

// ---------------------------------------------------------------------------
// D9-IN2 — A 出块 ⇒ B 收到 Proposal + Block（B 的投票指向同一 block hash）
// ---------------------------------------------------------------------------

#[test]
fn d9_in2_proposal_and_block_reach_inbound_peer() {
    let ab = setup_ab();
    let Pair {
        mut a,
        mut b,
        a_id,
        a_vk,
        ..
    } = start_established_pair(ab);

    // 推进到 B 收到 canonical-next 块（只读 verdict；不 commit）。
    let got = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        b.block_inbound_outcome_len() > 0
    });
    assert!(
        got,
        "B 未收到 A 的 GossipBlock（A head={:?} / B outcomes={} / B established A={}）",
        a.block_production().map(|ad| ad.head().height),
        b.block_inbound_outcome_len(),
        b.network_peer_established(a_id),
    );

    let verdicts = b.take_block_inbound_outcomes();
    let first = verdicts.first().expect("至少一个 verdict");
    let (block_hash, height) = match first {
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash, height, ..
        }) => (*block_hash, *height),
        other => panic!("期望 CanonicalNextCandidate，实得 {other:?}"),
    };
    assert_eq!(height, 1, "canonical-next 高度");

    // A 侧同一 block（本地 produced ⇒ BlockStore durable）+ proposer 签名有效 ⇒ 两端同一 canonical block。
    let a_block = {
        let adapter = a.block_production().expect("A validator adapter");
        adapter
            .block_store()
            .expect("A BlockStore")
            .get(&block_hash)
            .expect("BlockStore get")
            .expect("A 本地 produced block 已 durable")
    };
    assert_eq!(a_block.header.height, 1);
    assert_eq!(
        nova_runtime::block_hash(&a_block).unwrap(),
        block_hash,
        "B 解码块 hash == A produced block hash"
    );
    nova_runtime::validate_block_signature(&a_block, &a_vk, CHAIN_ID).expect("proposer 签名有效");

    // B 收到 **Proposal** 的证据（与 proposal/block 相对到达时序**无关**，避免 race）：
    // B 只有在成功 decode `ProposalRef` + 通过 proposer authority gate 后才会为**该 proposal 的**
    // block_hash 投票；而 B 的 finality reference == block_hash ⇒ B 已接受 proposal(hash) + 收到
    // 该 block + 收到 A 的 QC。同时该断言证明 A→B 与 B→A 双向数据流均已贯通。
    let finalized = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        matches!(
            b.consensus().state().finality.finalized_reference,
            Some(h) if h == block_hash
        )
    });
    assert!(
        finalized,
        "B 未 finalize 该 block（⇒ 未接受/未投票/未收到 QC；B head={:?}）",
        b.block_production().map(|ad| ad.head().height),
    );

    drop(a);
    drop(b);
}

// ---------------------------------------------------------------------------
// D9-IN3 — B 的 Vote → A 真实收到（A 达成 finality + commit ⇒ head 前进）
// ---------------------------------------------------------------------------

#[test]
fn d9_in3_peer_votes_reach_listener_node() {
    let ab = setup_ab();
    let Pair {
        mut a, mut b, b_id, ..
    } = start_established_pair(ab);

    // A 出块 → B 收到并投票 → A 收到 B 的票 → precommit quorum → QC → finality → commit（head=1）。
    let committed = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        a.block_production()
            .map(|adapter| adapter.head().height >= 1)
            .unwrap_or(false)
    });
    assert!(
        committed,
        "A 未 commit height 1（⇒ 未真实收到 B 的 vote / QC）"
    );
    assert!(a.network_peer_established(b_id), "A 仍 established B");
    drop(a);
    drop(b);
}

// ---------------------------------------------------------------------------
// D9-IN4 — 重复 peer：KEEP-FIRST（不替换 / 不迁移 session）
// ---------------------------------------------------------------------------

#[test]
fn d9_in4_duplicate_peer_keeps_first_connection() {
    let ab = setup_ab();
    let Pair {
        mut a,
        b,
        a_id,
        b_id,
        a_addr,
        a_vk: _,
    } = start_established_pair(ab);
    let before = a.network_inbound_connection_count();
    assert_eq!(before, 1);

    // 第二条入站连接：transport 级身份首包声明为 b_id（同一已连接 peer）。
    let dup = TcpTransport::dial(a_addr, b_id, a_id, MAX_FRAME, None);
    assert!(dup.is_ok(), "原始重复连接已建立（wire fixture）");

    let rejected = wait_until(|| {
        let _ = a.step();
        a.network_inbound_diagnostics()
            .map(|d| d.duplicate_drops >= 1)
            .unwrap_or(false)
    });
    assert!(rejected, "重复 peer 入站连接未被拒（KEEP-FIRST）");
    let diag = a.network_inbound_diagnostics().unwrap();
    assert_eq!(diag.connections, before, "既有连接未被替换");
    assert!(a.network_peer_established(b_id), "既有 session 不受影响");
    assert!(b.network_peer_established(a_id), "对端 session 不受影响");
    drop(dup);
    drop(a);
    drop(b);
}

// ---------------------------------------------------------------------------
// D9-IN5 — 非法握手：不 Established / 不 connected / 连接回收
// ---------------------------------------------------------------------------

#[test]
fn d9_in5_invalid_handshake_is_rejected_and_cleaned_up() {
    let kp1 = KeyPair::generate().unwrap();
    let genesis = two_validator_genesis(
        kp1.verifying_key().to_bytes(),
        KeyPair::generate().unwrap().verifying_key().to_bytes(),
    );
    let env = Env::new(&genesis);
    let mut a = start_node(
        &env.config(Some("127.0.0.1:0".parse().unwrap()), Vec::new(), true),
        Some(kp1),
        KeyPair::generate().unwrap(),
    );
    let a_addr = a.network_listen_addr().unwrap();

    // wire fixture：真实 TCP + 32B 身份首包 + 正确签名的 Handshake **错误 chain**。
    let bad_kp = KeyPair::generate().unwrap();
    let bad_id = node_id_of(&bad_kp);
    let bad_signer = SoftwareNetworkIdentity::new(bad_kp);
    let mut sock = TcpStream::connect(a_addr).expect("connect A");
    sock.write_all(bad_id.as_bytes()).unwrap();
    // 错误链（chain_id + 1）⇒ frozen `validate_handshake_context` 拒绝。
    let auth = PeerAuthConfig {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID + 1,
        genesis_hash: env.genesis_hash,
        protocol_version: 1,
        capabilities: b"",
        per_peer_handshake_limit: 8,
        global_handshake_limit: 128,
        replay_cache_capacity: 256,
    };
    let nonce = random_session_nonce().unwrap();
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        auth.network_id,
        auth.chain_id,
        auth.genesis_hash,
        auth.protocol_version,
        &bad_id,
        &nonce,
        auth.capabilities,
    )
    .unwrap();
    let mut env_msg = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: bad_id,
        signature: [0u8; 64],
    };
    bad_signer.sign_envelope(&mut env_msg).unwrap();
    sock.write_all(&frame_encode(&encode(&env_msg), MAX_FRAME).unwrap())
        .unwrap();
    sock.flush().unwrap();

    let cleaned = wait_until(|| {
        let _ = a.step();
        !a.network_peer_connected(bad_id) && a.network_inbound_connection_count() == 0
    });
    assert!(cleaned, "非法握手后连接未回收");
    assert!(
        !a.network_peer_established(bad_id),
        "非法握手 ⇒ 不 Established"
    );
    assert!(
        !a.network_peer_connected(bad_id),
        "非法握手 ⇒ frozen close_peer 断开"
    );
    assert!(
        a.network_inbound_diagnostics().unwrap().closed_drops >= 1,
        "连接回收计数"
    );
    drop(sock);
    drop(a);
}

// ---------------------------------------------------------------------------
// D9-IN6 — 对端 shutdown ⇒ 无 stale established / connected / transport
// ---------------------------------------------------------------------------

#[test]
fn d9_in6_disconnect_cleans_up_inbound_state() {
    let ab = setup_ab();
    let Pair { mut a, b, b_id, .. } = start_established_pair(ab);
    assert!(a.network_peer_established(b_id));

    // B 关闭（真实 TCP close ⇒ A 侧 EOF）。
    b.shutdown().expect("B shutdown");

    let cleaned = wait_until(|| {
        let _ = a.step();
        !a.network_peer_established(b_id) && a.network_inbound_connection_count() == 0
    });
    assert!(cleaned, "B 关闭后 A 未清理入站状态");
    assert!(!a.network_peer_established(b_id), "无 stale established");
    assert!(!a.network_peer_connected(b_id), "无 stale connected");
    assert_eq!(
        a.network_inbound_connection_count(),
        0,
        "无 stale transport"
    );
    drop(a);
}

// ---------------------------------------------------------------------------
// D9-IN7 — 资源上限：bounded accept / bounded connections / no panic
// ---------------------------------------------------------------------------

#[test]
fn d9_in7_resource_bounds_are_enforced() {
    let kp1 = KeyPair::generate().unwrap();
    let genesis = two_validator_genesis(
        kp1.verifying_key().to_bytes(),
        KeyPair::generate().unwrap().verifying_key().to_bytes(),
    );
    let env = Env::new(&genesis);
    // full-node（无 validator）：只验证 listener 资源边界。
    let mut a = start_node(
        &env.config(Some("127.0.0.1:0".parse().unwrap()), Vec::new(), false),
        None,
        KeyPair::generate().unwrap(),
    );
    let a_addr = a.network_listen_addr().unwrap();

    // 70 条真实 TCP 连接（各带唯一 32B 身份首包；保持打开）。
    let over = MAX_INBOUND_CONNECTIONS + 6;
    let mut held = Vec::new();
    for i in 0..over {
        let mut s = TcpStream::connect(a_addr).expect("connect A");
        let mut id = [0u8; 32];
        id[0] = (i as u8).wrapping_add(1);
        id[31] = 0x5a;
        s.write_all(&id).unwrap();
        s.flush().unwrap();
        held.push(s);
    }

    // 单 step ⇒ accept 有界（≤ MAX_ACCEPT_PER_STEP）。
    a.step().expect("step ok");
    let after_one = a.network_inbound_connection_count();
    assert!(
        after_one <= MAX_ACCEPT_PER_STEP,
        "每 step accept 有界：{after_one} ≤ {MAX_ACCEPT_PER_STEP}"
    );

    // 推进：注册到上限为止（不 panic / 不无界）。
    for _ in 0..32 {
        a.step().expect("step ok（超限不 panic）");
    }
    let diag = a.network_inbound_diagnostics().unwrap();
    assert_eq!(
        diag.connections, MAX_INBOUND_CONNECTIONS,
        "并存入站连接上限 {MAX_INBOUND_CONNECTIONS}"
    );
    assert!(
        diag.overflow_drops >= (over - MAX_INBOUND_CONNECTIONS) as u64,
        "超限连接被拒（{over} 条中 ≥ {} 条 overflow）",
        over - MAX_INBOUND_CONNECTIONS
    );

    // 释放 wire 连接 ⇒ 全部回收（无 stale）。
    drop(held);
    let drained = wait_until(|| {
        let _ = a.step();
        a.network_inbound_connection_count() == 0
    });
    assert!(drained, "连接关闭后入站表未清空（stale transport）");
    drop(a);
}
