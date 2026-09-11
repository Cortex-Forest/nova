//! D10-P0 — 真实 TCP **双节点双高度（H2）闭环**测试（test-only，无生产代码修改）。
//!
//! # 证明目标（Owner P0）
//! ```text
//! A produces H1
//!   → A → B over REAL TCP
//!   → B validates H1 / DAG-registers / durable-stores / votes
//!   → B vote → A over REAL TCP
//!   → A reaches finality and commits H1   (A.head.height == 1)
//!   → B also reaches finality + commits H1 (B.head.height == 1, round.height == 1)
//!   → **B** is the designated proposer for H2 ⇒ B produces H2 (parent == H1)
//!   → B → A over REAL TCP
//!   → A validates H2 / DAG-registers / durable-stores / votes
//!   → A vote → B over REAL TCP
//!   → H2 finality on both sides → canonical commit on both sides
//! ```
//! 最终断言：`A.head.height == 2 && B.head.height == 2`、`H2.parent_hash == H1.block_hash`、
//! `A canonical H2 == B canonical H2`（height / hash / parent 全等），且 **H2 由 B 产生**
//! （B 是 ADR-0050 选定 proposer；H2 的 proposer 签名对 B 的 key 验证通过、对 A 的 key 验证失败）。
//!
//! # 真实 TCP 证明（不使用 MemoryTransport 承载 A↔B）
//! - A：`NodeConfig.listen_addr = Some("127.0.0.1:0")` ⇒ 真实 `std::net::TcpListener`；
//! - B：`configured peer = A 的真实监听地址` ⇒ 真实 `TcpDialer` 出站拨号；
//! - 注入的 `MemoryTransport` 仅满足 `NodeRuntime::start_with_network` 的 transport 参数，
//!   且其 pair 对端是 **陌生 NodeId（0x99..）**——既不是 A 也不是 B ⇒ 结构上无法承载 A↔B 帧；
//! - 断言 A 侧真实入站连接数 ≥ 1（`network_inbound_connection_count()`）与 `accepted ≥ 1`
//!   （只能来自真实 TCP accept），以及双向 `network_peer_established`。
//!
//! # 关键性（为什么 2 验证者构成强证明）
//! 双验证者等 stake（各 200_000 / total 400_000）⇒ `quorum (= 2/3+1 权重) > 单验证者权重`，
//! 即 **quorum 必须两票齐全**。因此：
//! - A 对 H1 达到 finality ⇒ 必然收到 **B 的 vote（经 TCP）**；
//! - B 对 H1 达到 finality ⇒ 必然收到 **A 的 vote（经 TCP）**；
//! - H2 同理。⇒ 双向网络闭环不是假设，而是 finality 的前置条件。
//!
//! # 纪律
//! - 仅新增测试文件；生产代码（runtime / proposer / finality / DAG / validation / transport /
//!   commit bridge / height advance）**零修改**；
//! - 无 `git add` / commit / push；无 `unsafe`；无新依赖；
//! - 等待全部为**有界状态轮询**（状态驱动，1ms 粒度，`MAX_ITER` 上限，超时携带诊断信息失败）。

use std::net::SocketAddr;
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
use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::block_inbound::InboundBlockVerdict;
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;
use nova_storage::block_store::BlockStore;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// 注入 transport 的「陌生对端」NodeId：既非 A 亦非 B ⇒ MemoryTransport 不承载 A↔B 闭环。
const STRANGER_NODE_ID: [u8; 32] = [0x99; 32];
/// 有界等待循环上限（每次 1ms；确定性退出）。
const MAX_ITER: usize = 4000;

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

/// 双验证者 genesis（A/B 各 stake 200_000；total 400_000 ⇒ quorum 必须两票）。
///
/// canonical 约束：validator 按 `validator_id` 严格升序、accounts 按地址升序、
/// `total_supply == Σ liquid_balance`。
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

/// 每节点独立 chain/safety 目录（同一 genesis ⇒ 同一链身份）。
struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1, tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nova_p0_h2_{}_{}_{}", std::process::id(), n, tag));
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

    fn config(&self, listen_addr: Option<SocketAddr>, peers: Vec<ConnectionTarget>) -> NodeConfig {
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

/// 启动真实 runtime（网络装配 + 真实网络身份；`listen_addr` 由 config 决定）。
///
/// 注入的 `MemoryTransport` 与**陌生 NodeId** 配对（非 A 非 B）⇒ 不可能承载 A↔B 帧。
fn start_node(config: &NodeConfig, validator_kp: KeyPair, net_kp: KeyPair) -> NodeRuntime {
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_stranger) =
        MemoryTransport::pair(net_id, NodeId::from_bytes(STRANGER_NODE_ID));
    let provider = SoftwareKeyProvider::from_keypair(validator_kp);
    NodeRuntime::start_with_network(
        config,
        Some(&provider as &dyn nova_node::key_provider::KeyProvider),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("runtime 启动（真实网络装配）")
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production()
        .map(|ad| ad.head().height)
        .unwrap_or(0)
}

/// 32B hash → hex（仅测试输出用）。
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn head_hash(rt: &NodeRuntime) -> [u8; 32] {
    rt.block_production()
        .map(|ad| ad.head().block_hash)
        .unwrap_or([0u8; 32])
}

/// 角色分配：使 **A = H1 proposer（`select_proposer(height=0)`）**、
/// **B = H2 proposer（`select_proposer(height=1)`）**。
///
/// 用真实 ADR-0050 选定函数在测试侧判定（与生产 `build_proposal` / `block_dispatch` /
/// commit bridge 同源）；若两高度选中同一验证者，则重新生成 keypair（真实 genesis 约束下
/// 无法让同一验证者连续出两块 ⇒ 必须找到 p0 != p1 的组合）。
fn roles_for_two_heights() -> (KeyPair, KeyPair, GenesisV1, [u8; 32], ValidatorSet) {
    for _ in 0..64 {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let genesis = two_validator_genesis(
            kp1.verifying_key().to_bytes(),
            kp2.verifying_key().to_bytes(),
        );
        let genesis_hash = compute_genesis_hash(&genesis).unwrap();
        let set = ValidatorSet::from_genesis(&genesis);
        let p0 = select_proposer(CHAIN_ID, 0, 0, &genesis_hash, &set).unwrap();
        let p1 = select_proposer(CHAIN_ID, 1, 0, &genesis_hash, &set).unwrap();
        if p0 != p1 {
            let (a_kp, b_kp) = if validator_id_of(&kp1) == p0 {
                (kp1, kp2)
            } else {
                (kp2, kp1)
            };
            debug_assert_eq!(validator_id_of(&a_kp), p0, "A 必须是 H1 proposer");
            debug_assert_eq!(validator_id_of(&b_kp), p1, "B 必须是 H2 proposer");
            return (a_kp, b_kp, genesis, genesis_hash, set);
        }
    }
    panic!("未能找到 p0 != p1 的双验证者角色组合（ADR-0050 选择退化？）");
}

/// 有界状态轮询：交替推进两节点直到 `done` 为真；返回 `(达成?, 最后错误, 记录)`。
struct DriveOutcome {
    reached: bool,
    last_error: Option<String>,
    iterations: usize,
}

fn drive_until(
    a: &mut NodeRuntime,
    b: &mut NodeRuntime,
    a_id: NodeId,
    b_id: NodeId,
    mut done: impl FnMut(&mut NodeRuntime, &mut NodeRuntime) -> bool,
) -> DriveOutcome {
    let mut last_error: Option<String> = None;
    for i in 0..MAX_ITER {
        if let Err(e) = a.step() {
            last_error = Some(format!("A.step error: {e:?}"));
        }
        if let Err(e) = b.step() {
            last_error = Some(format!("B.step error: {e:?}"));
        }
        // 已断连（非预期）⇒ 提前结束并诊断。
        let link_ok = a.network_peer_established(b_id) && b.network_peer_established(a_id);
        if done(&mut *a, &mut *b) {
            return DriveOutcome {
                reached: true,
                last_error,
                iterations: i + 1,
            };
        }
        if !link_ok && i > 20 {
            return DriveOutcome {
                reached: false,
                last_error: Some(format!(
                    "A/B established link lost (A est B={} / B est A={})",
                    a.network_peer_established(b_id),
                    b.network_peer_established(a_id)
                )),
                iterations: i + 1,
            };
        }
        thread::sleep(Duration::from_millis(1));
    }
    DriveOutcome {
        reached: false,
        last_error,
        iterations: MAX_ITER,
    }
}

// ---------------------------------------------------------------------------
// P0 — 真实 TCP 双节点 H2 闭环
// ---------------------------------------------------------------------------

#[test]
fn d10_p0_dual_node_tcp_height2_closure() {
    // -------- 角色 / genesis：A = H1 proposer，B = H2 proposer --------
    let (a_kp, b_kp, genesis, genesis_hash, set) = roles_for_two_heights();
    let a_id_expected = validator_id_of(&a_kp);
    let b_id_expected = validator_id_of(&b_kp);
    assert_ne!(a_id_expected, b_id_expected, "A/B 必须是不同 validator");
    assert!(
        STAKE < set.quorum(),
        "quorum={} 必须 > 单验证者权重 {STAKE}（否则「对方 vote 经网络到达」不被 finality 前提保证）",
        set.quorum()
    );

    // -------- 两个真实 NodeRuntime（A listen / B real-TCP dial）--------
    let env_a = Env::new(&genesis, "a");
    let env_b = Env::new(&genesis, "b");
    let a_net = KeyPair::generate().unwrap();
    let b_net = KeyPair::generate().unwrap();
    let a_net_id = node_id_of(&a_net);
    let b_net_id = node_id_of(&b_net);
    assert_ne!(a_net_id, NodeId::from_bytes(STRANGER_NODE_ID));
    assert_ne!(b_net_id, NodeId::from_bytes(STRANGER_NODE_ID));
    // KeyPair 非 Clone ⇒ 先取出验证公钥（后续签名断言用），再移交所有权给 runtime。
    let a_vk = *a_kp.verifying_key();
    let b_vk = *b_kp.verifying_key();

    let a_config = env_a.config(Some("127.0.0.1:0".parse().unwrap()), Vec::new());
    let mut a = start_node(&a_config, a_kp, a_net);
    let a_addr = a
        .network_listen_addr()
        .expect("A 真实监听地址（listener 已绑定）");
    assert_ne!(a_addr.port(), 0, "真实监听端口（port 0 已解析为实际端口）");

    let b_config = env_b.config(
        None,
        vec![ConnectionTarget {
            peer_id: a_net_id,
            address: a_addr,
        }],
    );
    let mut b = start_node(&b_config, b_kp, b_net);

    // -------- 建立双向 authenticated/established（真实握手）--------
    let mut established = false;
    for _ in 0..MAX_ITER {
        let _ = b.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        if a.network_peer_established(b_net_id) && b.network_peer_established(a_net_id) {
            established = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        established,
        "A/B 双向 established 失败（B dial A 的 real TCP 或握手未完成）"
    );

    // 真实 TCP 结构性证据（MemoryTransport 的陌生对端不参与）。
    assert!(a.network_peer_auth_enabled(), "peer-auth 已启用");
    assert!(b.network_peer_auth_enabled(), "peer-auth 已启用");
    assert!(a.network_peer_connected(b_net_id), "A connected B");
    assert!(b.network_peer_connected(a_net_id), "B connected A");
    assert!(
        a.network_inbound_connection_count() == 1,
        "A 恰好一条真实入站 TCP 连接（经 TcpListener accept；KEEP-FIRST）"
    );
    let a_inbound = a.network_inbound_diagnostics().expect("A inbound 状态");
    assert!(
        a_inbound.accepted >= 1,
        "A accepted >= 1（真实 TcpListener::accept）"
    );
    assert_eq!(
        a_inbound.header_drops, 0,
        "无 32B 首包身份解析失败（干净握手）"
    );
    assert_eq!(a_inbound.overflow_drops, 0, "无连接上限溢出");
    assert_eq!(a_inbound.duplicate_drops, 0, "无重复 peer 丢弃");

    // -------- H1：A 出块 → B 收块/验证/登记/落盘/投票 → A finality + commit --------
    let mut b_saw_h1 = false;
    let h1 = drive_until(&mut a, &mut b, b_net_id, a_net_id, |aa, bb| {
        for v in bb.take_block_inbound_outcomes() {
            if let Ok(InboundBlockVerdict::CanonicalNextCandidate { height, .. }) = v
                && height == 1
            {
                b_saw_h1 = true;
            }
        }
        head_height(aa) >= 1 && head_height(bb) >= 1
    });
    assert!(
        h1.reached,
        "H1 未在 A/B 双侧 commit（A.head={} / B.head={} / iters={} / err={:?} / B_est_A={} / A_est_B={}）",
        head_height(&a),
        head_height(&b),
        h1.iterations,
        h1.last_error,
        b.network_peer_established(a_net_id),
        a.network_peer_established(b_net_id),
    );
    assert!(
        b_saw_h1,
        "B 必须经真实 TCP 收到并验证 H1（CanonicalNextCandidate）"
    );

    let h1_hash = head_hash(&a);
    assert_eq!(head_height(&a), 1, "H1 精确断言：A canonical head == 1");
    assert_eq!(head_height(&b), 1, "H1 精确断言：B canonical head == 1");
    assert_eq!(head_hash(&b), h1_hash, "A/B H1 canonical hash 必须一致");

    // H1 durable（两侧 BlockStore）+ DAG 登记（B 侧为远端登记）。
    let a_bs = BlockStore::open(&a_config.storage_dir.join("blocks")).unwrap();
    let b_bs = BlockStore::open(&b_config.storage_dir.join("blocks")).unwrap();
    let h1_a = a_bs.get(&h1_hash).unwrap().expect("A durable H1");
    let h1_b = b_bs.get(&h1_hash).unwrap().expect("B durable H1");
    assert_eq!(h1_a.header.height, 1);
    assert_eq!(
        h1_a.header.parent_hash, genesis_hash,
        "H1.parent == genesis"
    );
    assert_eq!(h1_b.header.height, 1);
    assert_eq!(
        h1_b.header.parent_hash, genesis_hash,
        "B 的 H1.parent == genesis"
    );
    assert!(
        b.consensus().dag().contains(&h1_hash),
        "B 已将 H1 登记进 DAG"
    );
    assert!(
        a.consensus().dag().contains(&h1_hash),
        "A 已将 H1 登记进 DAG"
    );
    // A 的 H1 由 A 产生（A = H1 proposer）。
    assert!(
        nova_runtime::validate_block_signature(&h1_a, &a_vk, CHAIN_ID).is_ok(),
        "H1 proposer 签名必须对 A 的 key 验证通过（A = H1 proposer）"
    );

    // H1 finality（两侧）⇒ 双向 vote 均已跨真实 TCP 到达（quorum 需两票）。
    assert_eq!(
        a.consensus().state().finality.finalized_reference,
        Some(h1_hash),
        "A 对 H1 达到 finality（⇒ 收到 B 的 vote）"
    );
    assert_eq!(
        b.consensus().state().finality.finalized_reference,
        Some(h1_hash),
        "B 对 H1 达到 finality（⇒ 收到 A 的 vote）"
    );

    // -------- H2：必须由 B 产生（B = H2 proposer），经真实 TCP 回到 A --------
    let p1 = select_proposer(CHAIN_ID, 1, 0, &genesis_hash, &set).unwrap();
    assert_eq!(
        p1, b_id_expected,
        "B 必须是 ADR-0050 选定的 H2 proposer（生产 select_proposer 同源判定）"
    );

    let mut a_saw_h2 = false;
    let h2 = drive_until(&mut a, &mut b, b_net_id, a_net_id, |aa, bb| {
        // A 侧直接观察：H2 必须作为 canonical-next 从网络到达（⇒ B → A 经真实 TCP）。
        // B 侧不需要（且不应）经 inbound 看到 H2 —— H2 由 B 本地产出（runtime_propose 路径，
        // 不经 block inbound）；此处仅清空队列以保持观测有界。
        for v in aa.take_block_inbound_outcomes() {
            if let Ok(InboundBlockVerdict::CanonicalNextCandidate { height, .. }) = v
                && height == 2
            {
                a_saw_h2 = true;
            }
        }
        let _ = bb.take_block_inbound_outcomes();
        head_height(aa) >= 2 && head_height(bb) >= 2
    });
    assert!(
        h2.reached,
        "H2 未在 A/B 双侧 commit（A.head={} / B.head={} / iters={} / err={:?} / B_round_h={} / A_round_h={}）",
        head_height(&a),
        head_height(&b),
        h2.iterations,
        h2.last_error,
        b.consensus().state().round.height,
        a.consensus().state().round.height,
    );

    // -------- 最终状态：双侧 head == 2 且 canonical H2 完全一致 --------
    assert!(
        a_saw_h2,
        "A 必须经真实 TCP 收到并验证 H2（CanonicalNextCandidate height=2）"
    );
    assert_eq!(head_height(&a), 2, "最终断言：A.head.height == 2");
    assert_eq!(head_height(&b), 2, "最终断言：B.head.height == 2");

    let a_h2_hash = head_hash(&a);
    let b_h2_hash = head_hash(&b);
    assert_eq!(a_h2_hash, b_h2_hash, "A/B canonical H2 hash 必须一致");
    assert_ne!(a_h2_hash, h1_hash, "H2 != H1");

    let a_h2 = a_bs.get(&a_h2_hash).unwrap().expect("A durable H2");
    let b_h2 = b_bs.get(&b_h2_hash).unwrap().expect("B durable H2");
    assert_eq!(a_h2.header.height, 2, "A canonical H2 height == 2");
    assert_eq!(b_h2.header.height, 2, "B canonical H2 height == 2");
    assert_eq!(a_h2.header.parent_hash, h1_hash, "A H2.parent == H1.hash");
    assert_eq!(
        b_h2.header.parent_hash, h1_hash,
        "B H2.parent == H1.hash（同一链）"
    );
    assert_eq!(
        a_h2.header.parent_hash, b_h2.header.parent_hash,
        "A/B H2 parent 必须一致"
    );
    assert_eq!(
        nova_runtime::block_hash(&a_h2).unwrap(),
        nova_runtime::block_hash(&b_h2).unwrap(),
        "A/B H2 canonical block hash（重算）一致"
    );
    // 区块内容一致（同 height / parent / tx 集 ⇒ 同 hash；此处比较可读字段）。
    assert_eq!(a_h2.header.height, b_h2.header.height, "H2 height 一致");
    assert_eq!(
        a_h2.header.parent_hash, b_h2.header.parent_hash,
        "H2 parent 一致"
    );
    assert_eq!(
        a_h2.proposer_signature, b_h2.proposer_signature,
        "H2 proposer 签名一致（同一区块）"
    );

    // H2 由 **B** 产生（B 是 H2 proposer）；A 的 key 无法验证 ⇒ 证明不是 A 出块。
    assert!(
        nova_runtime::validate_block_signature(&a_h2, &b_vk, CHAIN_ID).is_ok(),
        "H2 proposer 签名必须对 B 的 key 验证通过（B 产生 H2）"
    );
    assert!(
        nova_runtime::validate_block_signature(&a_h2, &a_vk, CHAIN_ID).is_err(),
        "H2 不得由 A 产生（对 A 的 key 验证必须失败）"
    );

    // H2 DAG 登记（双方）+ finality（双方）。
    assert!(a.consensus().dag().contains(&a_h2_hash), "A DAG 含 H2");
    assert!(b.consensus().dag().contains(&b_h2_hash), "B DAG 含 H2");
    assert!(
        b.consensus().dag().is_ancestor(&h1_hash, &b_h2_hash),
        "B DAG：H1 是 H2 的祖先"
    );
    assert_eq!(
        a.consensus().state().finality.finalized_reference,
        Some(a_h2_hash),
        "A 对 H2 达到 finality（⇒ 收到 B 的 vote）"
    );
    assert_eq!(
        b.consensus().state().finality.finalized_reference,
        Some(b_h2_hash),
        "B 对 H2 达到 finality（⇒ 收到 A 的 vote）"
    );
    // consensus round 高度已跟进 durable head（Step 7-B）。
    assert_eq!(a.consensus().state().round.height, 2, "A round.height == 2");
    assert_eq!(b.consensus().state().round.height, 2, "B round.height == 2");

    // 连接在整段闭环后仍保持 established（无中途重连/降级）。
    assert!(a.network_peer_established(b_net_id), "闭环后 A 仍 est B");
    assert!(b.network_peer_established(a_net_id), "闭环后 B 仍 est A");

    // ——— Owner Review 证据输出（`--nocapture` 可见；不影响任何断言）———
    println!(
        "[P0-H2] H1.hash={} H1.parent={} | H2.hash={} H2.parent={} | \
         A.head={} B.head={} | A.round={} B.round={} | A.finality={:?} B.finality={:?} | \
         H1.iters={} H2.iters={} | A.inbound_conns={} accepted={} | H1proposer=A H2proposer=B",
        hex(&h1_hash),
        hex(&genesis_hash),
        hex(&a_h2_hash),
        hex(&a_h2.header.parent_hash),
        head_height(&a),
        head_height(&b),
        a.consensus().state().round.height,
        b.consensus().state().round.height,
        a.consensus()
            .state()
            .finality
            .finalized_reference
            .map(|h| hex(&h)),
        b.consensus()
            .state()
            .finality
            .finalized_reference
            .map(|h| hex(&h)),
        h1.iterations,
        h2.iterations,
        a.network_inbound_connection_count(),
        a_inbound.accepted,
    );

    a.shutdown().unwrap();
    b.shutdown().unwrap();
}
