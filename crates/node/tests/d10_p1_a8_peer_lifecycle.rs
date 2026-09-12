//! P1-A.8 — Configured peer lifecycle hardening（dead peer 退避 / 不阻塞健康 peer）。
//!
//! 验证目标（Owner 冻结决策）：
//! - 不可达 configured peer **不得**每个 runtime round 都重新 dial（逻辑 tick 指数退避：
//!   `2,4,8,…,2048,4096,4096,…`，`failure_count ≤ 12`）；
//! - 每轮最多 `MAX_DIAL_ATTEMPTS_PER_CALL = 1` 次 dial（bounded work）；
//! - 死 peer **不阻塞**健康 peer（健康 peer 仍能 Establishment）；
//! - 对端恢复 ⇒ 能重新 Establishment（`dial` 成功清除失败历史）；
//! - state 有界：条目数 ≤ configured peers，`failure_count ≤ 12`，退避 ≤ 4096 逻辑 tick。
//!
//! 手段：**逻辑 tick**（无墙钟 / 无 RNG / 无 sleep）；失败路径使用**拒绝端口**
//! （`127.0.0.1:1` 或"先 bind 再 drop"释放的端口）⇒ 立即 `ECONNREFUSED`，绝不触发 2s
//! `connect_timeout` ⇒ 测试无长墙钟等待。

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, MessageType, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_encode, random_session_nonce,
};
use nova_network::transport::{
    BoxTransport, ConnectionTarget, MemoryTransport, TcpTransport, Transport,
};

use nova_node::bootstrap::NodeConfig;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::{NodeRuntime, PeerStatus};

const CHAIN_ID: u64 = 3003;

// ---------------------------------------------------------------------------
// fixtures（与 configured_handshake_tests.rs 同构；必要时重载）
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn genesis() -> GenesisV1 {
    let validator_vk = KeyPair::generate().unwrap().verifying_key().to_bytes();
    let mut accounts = vec![
        AccountInit {
            address: addr([0x11; 32]),
            liquid_balance: 1_000_000,
        },
        AccountInit {
            address: addr([0x22; 32]),
            liquid_balance: 500_000,
        },
    ];
    accounts.sort_by_key(|a| a.address.payload().to_bytes());
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: accounts[0].address,
            consensus_public_key: validator_vk,
            bonded_stake: 200_000,
            commission_bps: 0,
        }],
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
            total_supply,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

struct Env {
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let g = genesis();
        let dir = std::env::temp_dir().join(format!("nova_a8_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(&g).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(&g).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        std::fs::create_dir_all(&chain_dir).unwrap();
        std::fs::create_dir_all(&safety_dir).unwrap();
        Self {
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
            validator_enabled: false,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr: None,
        }
    }

    fn auth(&self) -> PeerAuthConfig {
        PeerAuthConfig {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_hash: self.genesis_hash,
            protocol_version: 1,
            capabilities: b"",
            per_peer_handshake_limit: 8,
            global_handshake_limit: 128,
            replay_cache_capacity: 256,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.genesis_path.parent().unwrap());
    }
}

fn start_a(env: &Env, peers: Vec<ConnectionTarget>) -> NodeRuntime {
    let cfg = env.config(peers);
    let kp = KeyPair::generate().unwrap();
    let self_id = NodeId::from_verifying_key(kp.verifying_key());
    let other = NodeId::from_bytes([0x99; 32]);
    let transport: Box<dyn Transport> = Box::new(MemoryTransport::pair(self_id, other).0);
    let signer: Box<dyn NetworkSigner> = Box::new(SoftwareNetworkIdentity::new(kp));
    NodeRuntime::start_with_network(&cfg, None, transport, signer).expect("start A")
}

fn node_id(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// 由 B 的 key 签名的握手 Init envelope（claimed = B 的 NodeId）。
fn b_init(b_kp: &KeyPair, auth: &PeerAuthConfig) -> MessageEnvelope {
    let local = node_id(b_kp);
    let nonce = random_session_nonce().unwrap();
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
    let mut env = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: local,
        signature: [0u8; 64],
    };
    sign_message(b_kp.signing_key(), &mut env).unwrap();
    env
}

/// 必然被拒绝（无监听）的地址：`ECONNREFUSED` 立即返回（非 2s 黑洞超时）。
fn bad_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1))
}

/// 申请一个"当前空闲"的固定端口（bind 成功后立刻释放）。
fn free_port() -> u16 {
    let l = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn target(peer_id: NodeId, address: SocketAddr) -> ConnectionTarget {
    ConnectionTarget { peer_id, address }
}

/// 对端 B（listener 侧，**只服务一条连接**）：accept → 完成 B 侧握手（若 context 匹配则
/// Established A）→ 回 B 的 Init → keep-alive 直到 A 关闭（EOF）或 `linger` 到期 ⇒ 线程退出
/// ⇒ listener 被 drop（端口随之释放 ⇒ 后续 dial 被拒）。
///
/// `b_kp` 用 `Arc` 共享（`KeyPair` 刻意**不**实现 `Clone`；同一身份需跨多次 spawn 复用）。
fn spawn_peer_once(
    listener: TcpListener,
    auth: PeerAuthConfig,
    b_kp: Arc<KeyPair>,
    linger: Duration,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let b_id = node_id(&b_kp);
        let Ok(tcp) = TcpTransport::accept(&listener, b_id, 4096, Some(Duration::from_secs(5)))
        else {
            return;
        };
        let a_id = tcp.peer_id();
        let mut bns = NetworkService::<BoxTransport>::new(
            NetworkServiceConfig {
                peer_auth: Some(auth),
                ..Default::default()
            },
            b_id,
            BoxTransport::new(Box::new(tcp)),
        );
        let _ = bns.connect_peer(a_id);
        for _ in 0..200 {
            let _ = bns.poll_transport();
            if bns.is_peer_established(a_id) {
                break;
            }
            thread::yield_now();
        }
        if bns.is_peer_established(a_id) {
            let _ = bns.enqueue_outbound(a_id, b_init(&b_kp, &auth));
            let _ = bns.flush_outbound();
        }
        // keep-alive：保持连接（模拟稳定对端），直到 A 关闭或 linger 到期。
        let deadline = Instant::now() + linger;
        while Instant::now() < deadline {
            let _ = bns.poll_transport();
            if bns.transport().is_closed() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

/// 有界推进：反复 `establish_configured_peers()`，直到**首个** target 为 `Established`。
/// 返回 `true` = 达成；`false` = 预算内未达成（或返回 Err）。
fn drive_until_established(rt: &mut NodeRuntime, budget: usize) -> bool {
    for _ in 0..budget {
        let Ok(res) = rt.establish_configured_peers() else {
            return false;
        };
        if res
            .first()
            .is_some_and(|e| matches!(e.status, PeerStatus::Established))
        {
            return true;
        }
        thread::yield_now();
    }
    false
}

// ---------------------------------------------------------------------------
// T1 — 失败 peer 不每轮重 dial（退避门控 + 每轮 dial 预算）
// ---------------------------------------------------------------------------

#[test]
fn t1_failed_peer_is_not_redialed_every_call() {
    let env = Env::new();
    let dead = node_id(&KeyPair::generate().unwrap());
    let mut rt = start_a(&env, vec![target(dead, bad_addr())]);

    // 第 1 轮（peer_tick = 1）：无状态 ⇒ 立即尝试（首次不等退避）⇒ 真失败 ⇒ Backoff{1, 2}。
    let res = rt.establish_configured_peers().unwrap();
    assert_eq!(res.len(), 1);
    assert!(
        matches!(
            res[0].status,
            PeerStatus::Backoff {
                failure_count: 1,
                remaining_ticks: 2
            }
        ),
        "首次 dial 失败 ⇒ Backoff{{1, 2}}，实际 {:?}",
        res[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 1, "第 1 轮恰好 1 次 dial");
    assert_eq!(rt.peer_lifecycle_len(), 1, "失败 state 恰好 1 条");

    // 第 2 轮（peer_tick = 2 < 3）：退避内 ⇒ **不得** dial（attempts 不增），remaining 递减到 1。
    let res = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            res[0].status,
            PeerStatus::Backoff {
                failure_count: 1,
                remaining_ticks: 1
            }
        ),
        "退避内 ⇒ Backoff{{1, 1}}，实际 {:?}",
        res[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 1, "退避内不得重复 dial");

    // 第 3 轮（peer_tick = 3 == next_allowed）：重新尝试 ⇒ 第 2 次 dial ⇒ failure_count = 2，delay = 4。
    let res = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            res[0].status,
            PeerStatus::Backoff {
                failure_count: 2,
                remaining_ticks: 4
            }
        ),
        "退避到期 ⇒ 重试并升级到 Backoff{{2, 4}}，实际 {:?}",
        res[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 2, "恰好第 2 次 dial");
    assert_eq!(rt.peer_dial_failures_total(), 2);
    let st = rt.peer_lifecycle(dead).expect("失败历史存在");
    assert_eq!(st.failure_count, 2);
    assert_eq!(st.next_allowed_attempt_tick, 3 + 4);
    assert_eq!(rt.peer_tick(), 3, "每次调用 peer_tick +1");
}

// ---------------------------------------------------------------------------
// T2 — 退避指数增长 + 无 dial 骚扰（完整表 / 饱和由公式层单元测试覆盖）
//
// 注：真实失败 dial 在 Windows 上约占满 `DEFAULT_CONNECT_TIMEOUT`（≈ 2s），故集成层只观测
// 前几项（2,4,8,16）；完整冻结序列 2,4,8,…,2048,4096,4096,… 与 u32::MAX 饱和由
// `runtime.rs` 单元测试 `p1a8_backoff_delay_table_is_frozen_and_bounded` 覆盖。
// ---------------------------------------------------------------------------

#[test]
fn t2_backoff_grows_exponentially_and_suppresses_redials() {
    let env = Env::new();
    let dead = node_id(&KeyPair::generate().unwrap());
    let mut rt = start_a(&env, vec![target(dead, bad_addr())]);

    // 4 次真实失败发生在 peer_tick = 1, 3, 7, 15（延迟 2,4,8,16）⇒ 其后 next_allowed = 31。
    const ROUNDS: u64 = 30;
    let expected = [2u64, 4, 8, 16];
    let mut observed: Vec<u64> = Vec::new();
    let mut seen_attempts = 0u64;
    for _ in 0..ROUNDS {
        let res = rt.establish_configured_peers().unwrap();
        let attempts = rt.peer_dial_attempts_total();
        assert!(
            attempts - seen_attempts <= 1,
            "每轮 dial 预算 = 1（本轮 {} 次）",
            attempts - seen_attempts
        );
        if attempts > seen_attempts {
            seen_attempts = attempts;
            match res[0].status {
                PeerStatus::Backoff {
                    failure_count,
                    remaining_ticks,
                } => {
                    assert_eq!(
                        failure_count,
                        observed.len() as u32 + 1,
                        "failure_count 单调 +1（本轮远未达上限）"
                    );
                    observed.push(remaining_ticks);
                }
                ref other => panic!("dial 失败应报 Backoff，实际 {other:?}"),
            }
        }
        // 无论哪一轮：状态都必须有界。
        if let PeerStatus::Backoff {
            failure_count,
            remaining_ticks,
        } = res[0].status
        {
            assert!(failure_count <= 12, "failure_count 饱和 ≤ 12");
            assert!(remaining_ticks <= 4096, "退避 ≤ 4096 逻辑 tick");
        }
    }
    assert_eq!(observed, expected, "退避按 2,4,8,16 指数增长");
    // 关键：30 轮只有 4 次 dial（修复前 = 30 次 ⇒ 30 次 2s 阻塞）。
    assert_eq!(
        rt.peer_dial_attempts_total(),
        4,
        "退避内不得重复 dial（30 轮仅 4 次尝试）"
    );
    assert_eq!(rt.peer_dial_failures_total(), 4);
    assert_eq!(rt.peer_tick(), ROUNDS, "peer_tick = 调用次数");
    let st = rt.peer_lifecycle(dead).expect("失败历史存在");
    assert_eq!(st.failure_count, 4);
    assert_eq!(st.next_allowed_attempt_tick, 31, "15 + 16 = 31");
}

// ---------------------------------------------------------------------------
// T3 — 死 peer 不阻塞健康 peer（错误隔离 + 预算轮转）
// ---------------------------------------------------------------------------

#[test]
fn t3_dead_peer_does_not_block_healthy_peer() {
    let env = Env::new();
    let b_kp = Arc::new(KeyPair::generate().unwrap());
    let b_id = node_id(&b_kp);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let b_addr = listener.local_addr().unwrap();
    let handle = spawn_peer_once(
        listener,
        env.auth(),
        Arc::clone(&b_kp),
        Duration::from_secs(10),
    );
    let dead = node_id(&KeyPair::generate().unwrap());

    // 死 peer 排在**前**（配置顺序）：它仍不得饿死健康 peer。
    let mut rt = start_a(&env, vec![target(dead, bad_addr()), target(b_id, b_addr)]);

    // 第 1 轮：死 peer 用掉预算 ⇒ 健康 peer 本轮 Deferred（Pending），但**不会**被永久阻塞。
    let res = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(res[0].status, PeerStatus::Backoff { .. }),
        "死 peer ⇒ Backoff，实际 {:?}",
        res[0].status
    );
    assert!(
        matches!(res[1].status, PeerStatus::Pending),
        "预算被占用 ⇒ 健康 peer 本轮 Pending，实际 {:?}",
        res[1].status
    );

    // 后续轮：健康 peer 得到预算 ⇒ 完成握手 ⇒ Established（死 peer 仍在退避）。
    let mut established = false;
    for _ in 0..500 {
        let res = rt.establish_configured_peers().unwrap();
        assert!(
            matches!(res[0].status, PeerStatus::Backoff { .. }),
            "死 peer 始终退避（不阻塞其它 peer），实际 {:?}",
            res[0].status
        );
        if matches!(res[1].status, PeerStatus::Established) {
            established = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        established,
        "健康 peer 必须在死 peer 存在时仍能 Established"
    );
    assert_eq!(rt.peer_lifecycle_len(), 1, "只有死 peer 留下退避 state");
    assert!(rt.peer_lifecycle(b_id).is_none(), "健康 peer 无失败历史");
    drop(handle);
}

// ---------------------------------------------------------------------------
// T4 — 对端恢复：退避中仍能在下次允许的 tick 成功重连
// ---------------------------------------------------------------------------

#[test]
fn t4_peer_recovery_after_transient_outage() {
    let env = Env::new();
    let b_kp = Arc::new(KeyPair::generate().unwrap());
    let b_id = node_id(&b_kp);
    let port = free_port();
    let b_addr = SocketAddr::from(([127, 0, 0, 1], port));

    let mut rt = start_a(&env, vec![target(b_id, b_addr)]);

    // 阶段 1：端口空闲 ⇒ 连接被拒 ⇒ 至少 2 次失败（failure_count ≥ 2）。
    while rt.peer_dial_failures_total() < 2 {
        let _ = rt.establish_configured_peers().unwrap();
    }
    let st = rt.peer_lifecycle(b_id).expect("失败历史存在");
    assert!(st.failure_count >= 2, "连续失败已累积");
    assert!(
        st.next_allowed_attempt_tick > rt.peer_tick(),
        "处于退避区间内"
    );

    // 阶段 2：对端在同一端口上线 ⇒ 后续允许的尝试必须成功。
    let listener = TcpListener::bind(b_addr).expect("同端口重新 bind");
    let handle = spawn_peer_once(
        listener,
        env.auth(),
        Arc::clone(&b_kp),
        Duration::from_secs(10),
    );

    let mut established = false;
    for _ in 0..2_000 {
        let res = rt.establish_configured_peers().unwrap();
        if matches!(res[0].status, PeerStatus::Established) {
            established = true;
            break;
        }
        thread::yield_now();
    }
    assert!(established, "对端恢复后必须能重新 Established");
    // dial 成功 ⇒ 失败历史**清除**（下一失败序列从 0 起）。
    assert!(rt.peer_lifecycle(b_id).is_none(), "成功后清除退避 state");
    assert_eq!(rt.peer_lifecycle_len(), 0);
    assert!(
        rt.peer_dial_failures_total() >= 2,
        "历史失败计数保留（观测）"
    );
    drop(handle);
}

// ---------------------------------------------------------------------------
// T5 — 断开 / 重连：失败历史**不继承**（每轮从 0 起）
// ---------------------------------------------------------------------------

#[test]
fn t5_reconnect_after_disconnect_starts_from_zero_failures() {
    let env = Env::new();
    let b_kp = Arc::new(KeyPair::generate().unwrap());
    let b_id = node_id(&b_kp);
    let port = free_port();
    let b_addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = TcpListener::bind(b_addr).expect("bind port");
    let handle = spawn_peer_once(
        listener,
        env.auth(),
        Arc::clone(&b_kp),
        Duration::from_secs(10),
    );
    let mut rt = start_a(&env, vec![target(b_id, b_addr)]);

    // 阶段 1：健康 Establishment。
    assert!(drive_until_established(&mut rt, 500), "初次 Establishment");
    assert!(rt.peer_lifecycle(b_id).is_none(), "成功 ⇒ 无失败历史");

    // 阶段 2：断开（runtime 侧）⇒ 对端 fixture 观察到 EOF ⇒ 退出 ⇒ 端口释放 ⇒ 后续 dial 被拒。
    rt.disconnect_configured_peer_for(b_id).unwrap();
    let _ = handle.join();
    let attempts_before = rt.peer_dial_attempts_total();
    let mut redialed = false;
    for _ in 0..500 {
        let res = rt.establish_configured_peers().unwrap();
        if rt.peer_dial_attempts_total() > attempts_before {
            // 第一次重连尝试（失败）⇒ 计数**从 0 起**（不继承历史）。
            match res[0].status {
                PeerStatus::Backoff {
                    failure_count,
                    remaining_ticks,
                } => {
                    assert_eq!(failure_count, 1, "失败历史不继承（第一次失败 = 1）");
                    assert_eq!(remaining_ticks, 2, "首次失败 ⇒ delay 2");
                }
                ref other => panic!("重连失败应报 Backoff，实际 {other:?}"),
            }
            redialed = true;
            break;
        }
        thread::yield_now();
    }
    assert!(redialed, "断开后必须发生重连尝试");
    assert_eq!(
        rt.peer_lifecycle(b_id).map(|s| s.failure_count),
        Some(1),
        "当前失败历史恰为 1（非继承）"
    );

    // 阶段 3：对端重新上线 ⇒ 恢复 Establishment。
    let listener2 = TcpListener::bind(b_addr).expect("重新 bind 同一端口");
    let handle2 = spawn_peer_once(
        listener2,
        env.auth(),
        Arc::clone(&b_kp),
        Duration::from_secs(10),
    );
    assert!(
        drive_until_established(&mut rt, 2_000),
        "重连后必须再次 Established"
    );
    assert!(rt.peer_lifecycle(b_id).is_none(), "成功 ⇒ 清除失败历史");
    drop(handle2);
}

// ---------------------------------------------------------------------------
// T6 — state 有界（条目数 ≤ configured peers；计数 / 退避均有上限；每轮预算 1）
//
// 注：每个 state 都要一次真实失败（≈ 2s）才能建立，故集成层只推进少量轮次以控制墙钟；
// 关键断言（不得出现无界增长）不依赖轮数：条目 ≤ configured peers、计数 ≤ 12、退避 ≤ 4096。
// ---------------------------------------------------------------------------

#[test]
fn t6_lifecycle_state_is_bounded() {
    let env = Env::new();
    const N: u8 = 8;
    // 每个 peer 一个**各自空闲**（bind 后立刻释放 ⇒ 连接被拒）且**互不相同**的地址：
    // 传输层拒绝重复 target 地址，故不能共用一个地址。
    let peers: Vec<ConnectionTarget> = (0..N)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i + 1;
            let dead_addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
            target(NodeId::from_bytes(seed), dead_addr)
        })
        .collect();
    let ids: Vec<NodeId> = peers.iter().map(|t| t.peer_id).collect();
    let mut rt = start_a(&env, peers);

    // 预算 = 1/轮 ⇒ 4 轮最多 4 次 dial（仅被 dial 的 peer 才留下 state；其余 Deferred）。
    const ROUNDS: u64 = 4;
    for round in 1..=ROUNDS {
        let res = rt.establish_configured_peers().unwrap();
        assert_eq!(res.len(), N as usize, "每 target 恰好一个状态（基数恒定）");
        for e in &res {
            if let PeerStatus::Backoff {
                failure_count,
                remaining_ticks,
            } = e.status
            {
                assert!(failure_count <= 12, "failure_count ≤ 12");
                assert!(remaining_ticks <= 4096, "退避 ≤ 4096 逻辑 tick");
            }
        }
        assert!(
            rt.peer_lifecycle_len() <= N as usize,
            "state 条目 ≤ configured peers（第 {round} 轮）"
        );
        assert!(
            rt.peer_dial_attempts_total() <= rt.peer_tick(),
            "每轮 dial 预算 = 1（尝试数 ≤ 轮数）"
        );
        assert_eq!(
            rt.peer_dial_attempts_total(),
            round,
            "预算 1/轮 ⇒ 每轮恰好一次尝试（其余 Deferred，不入 state）"
        );
    }
    assert_eq!(rt.peer_tick(), ROUNDS, "peer_tick = 调用次数");
    assert!(rt.peer_dial_failures_total() >= 1, "至少一次失败被记录");
    assert!(
        rt.peer_lifecycle_len() <= ROUNDS as usize,
        "state 条目 ≤ 尝试次数（只有真正失败者入 state）"
    );
    assert!(
        rt.peer_lifecycle(*ids.last().unwrap()).is_none(),
        "从未被 dial 的 peer 不得留下 state"
    );
    for id in &ids {
        if let Some(st) = rt.peer_lifecycle(*id) {
            assert!(st.failure_count <= 12);
            assert!(
                st.next_allowed_attempt_tick <= rt.peer_tick() + 4096,
                "退避窗口有界"
            );
        }
    }

    // 空配置：state 必须保持为空（prune / 无 peer 无 state；零 dial）。
    let mut empty = start_a(&Env::new(), Vec::new());
    for _ in 0..5 {
        assert!(empty.establish_configured_peers().unwrap().is_empty());
    }
    assert_eq!(empty.peer_lifecycle_len(), 0);
    assert_eq!(empty.peer_dial_attempts_total(), 0);
}
