//! P1-A.9 Round 1 —— Reconnect（P1-2）+ 最低限度运行时可观测性（P1-3）—— 集成测试。
//!
//! # 覆盖的故障（P1-2）
//!
//! 修复前：`configured peer` 曾 Established ⇒ runtime 的 `handshake_init_sent_for` 永久保留该 peer；
//! TCP/session EOF（对端重启 / 链路抖动）后 NetworkService 已把 peer 清为 **非 connected /
//! 非 established**，但 runtime 因 stale 标记**不再发送** Handshake Init ⇒ dial 成功却永不重新认证
//! ⇒ **单向失联**（仅进程重启才自愈）。
//!
//! 修复：每个 lifecycle 轮次与 NetworkService **实际会话状态**对账 —— 仅当
//! `!connected && !established` 时清该 peer 的 Init 标记 ⇒ 下一次 dial 重新发 Init。
//!
//! # 为什么这些测试能证明"Init 被重发"（而不是只测一个 HashSet）
//!
//! 对端 fixture 复用真实 `NetworkService`：它**只有在自己已认证 A（即收到并验证 A 的 Init）之后**
//! 才回送自己的 Init。因此"A 在 EOF 之后**再次** Established"蕴含"A 重新发送了 Init 并被对端验证"。
//! fixture 返回每条 accept 连接上"A 是否被对端认证"，测试直接断言 `[true, true]`
//! ⇒ 真实 TCP/session 行为，非内存结构断言。
//!
//! # T4（P1-3）
//!
//! 用**真实二进制**（`CARGO_BIN_EXE_yazimao-node`）跑有界预算，断言 stdout 的 periodic status 行
//! 按固定 step interval 出现（250 steps ⇒ 恰好 2 行，steps=100/200）、且退出摘要保留既有契约字段
//! 并新增 P1-A.9 观测字段。

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
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
use nova_crypto::signature::SigningKey;
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

/// 与 bin 集成测试（P1-A.3）一致的 devnet 参数。
const CHAIN_ID: u64 = 1001;
/// T4 的 step 预算与 pacing（`STATUS_INTERVAL_STEPS = 100` ⇒ 恰好 2 行 status）。
const T4_RUN_STEPS: &str = "250";
const T4_IDLE_MS: &str = "1";
const T4_STATUS_INTERVAL: u64 = 100;
const T4_HARD_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Devnet,
        key_hash: kh,
    })
}

fn genesis() -> GenesisV1 {
    let validator_vk = SigningKey::from_seed([0x22; 32]).verifying_key().to_bytes();
    let mut accounts = vec![
        AccountInit {
            address: addr([0x11; 32]),
            liquid_balance: 1_000_000,
        },
        AccountInit {
            address: addr([0x22; 32]),
            liquid_balance: 1_000_000,
        },
    ];
    accounts.sort_by_key(|a| a.address.payload().to_bytes());
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Devnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: accounts[0].address,
            consensus_public_key: validator_vk,
            bonded_stake: 100,
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
        let dir = std::env::temp_dir().join(format!("nova_a9_{}_{}", std::process::id(), n));
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
            expected_network_id: NetworkId::Devnet,
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
            network_id: NetworkId::Devnet,
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

/// 必然被拒绝（无监听）的地址：`ECONNREFUSED`（Windows 上约占满 2s connect timeout）。
fn bad_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1))
}

fn target(peer_id: NodeId, address: SocketAddr) -> ConnectionTarget {
    ConnectionTarget { peer_id, address }
}

/// 对端 B（**纯 listener**：从不主动 dial —— hub-spoke 的 spoke 侧）：
///
/// 在同一 listener 上按 `hold` 顺序逐条 accept；每条连接：
/// 1. `connect_peer` + poll 直到**认证 A**（= 收到并验证 A 的 Handshake Init）；
/// 2. 若已认证 ⇒ 回送 B 的 Init（A 侧据此 Established B）；
/// 3. 保持（持续 poll 驱动真实收发）`hold[i]` 时长，到期 ⇒ 返回 ⇒ drop（**关闭连接 ⇒ A 看到 EOF**）。
///
/// 返回每条连接上"B 是否认证了 A"（`true` ⇒ 该连接上存在**有效的 A Init**）。
fn spawn_peer_serving(
    listener: TcpListener,
    auth: PeerAuthConfig,
    b_kp: Arc<KeyPair>,
    hold: Vec<Duration>,
) -> JoinHandle<Vec<bool>> {
    thread::spawn(move || {
        let b_id = node_id(&b_kp);
        let mut served: Vec<bool> = Vec::new();
        for stay in hold {
            let Ok(tcp) =
                TcpTransport::accept(&listener, b_id, 4096, Some(Duration::from_secs(10)))
            else {
                break;
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
            for _ in 0..5_000 {
                let _ = bns.poll_transport();
                if bns.is_peer_established(a_id) {
                    break;
                }
                thread::yield_now();
            }
            let established = bns.is_peer_established(a_id);
            if established {
                let _ = bns.enqueue_outbound(a_id, b_init(&b_kp, &auth));
                let _ = bns.flush_outbound();
            }
            served.push(established);
            let deadline = Instant::now() + stay;
            while Instant::now() < deadline {
                let _ = bns.poll_transport();
                if bns.transport().is_closed() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        served
    })
}

/// 有界推进直到该 peer 被认证（Established）。
fn drive_until_established(rt: &mut NodeRuntime, peer: NodeId, budget: usize) -> bool {
    for _ in 0..budget {
        let _ = rt.establish_configured_peers();
        if rt.network_peer_established(peer) {
            return true;
        }
        thread::yield_now();
    }
    false
}

/// 有界推进直到 runtime **观察到**该 peer 已断（NetworkService 已清 session ⇒ 不再 Established）。
fn drive_until_disconnected(rt: &mut NodeRuntime, peer: NodeId, budget: usize) -> bool {
    for _ in 0..budget {
        let _ = rt.establish_configured_peers();
        if !rt.network_peer_established(peer) {
            return true;
        }
        thread::yield_now();
    }
    false
}

// ---------------------------------------------------------------------------
// T1 — EOF reconnect（真实 TCP/session）
// ---------------------------------------------------------------------------

#[test]
fn t1_reconnect_after_eof_resends_handshake_init() {
    let env = Env::new();
    let b_kp = Arc::new(KeyPair::generate().unwrap());
    let b_id = node_id(&b_kp);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let b_addr = listener.local_addr().unwrap();
    // 第 1 条连接：握手成功后 ~250ms 主动关闭（制造 EOF）；第 2 条：保持。
    let handle = spawn_peer_serving(
        listener,
        env.auth(),
        Arc::clone(&b_kp),
        vec![Duration::from_millis(250), Duration::from_secs(6)],
    );

    let mut rt = start_a(&env, vec![target(b_id, b_addr)]);

    // 阶段 1：首次 Establishment（真实握手）。
    assert!(
        drive_until_established(&mut rt, b_id, 20_000),
        "首次必须 Established"
    );
    assert!(rt.peer_lifecycle(b_id).is_none(), "成功 ⇒ 无失败历史");

    // 阶段 2：对端关闭 ⇒ runtime 必须观察到 disconnected（NetworkService 清 session）。
    assert!(
        drive_until_disconnected(&mut rt, b_id, 200_000),
        "runtime 必须观察到 EOF/disconnect"
    );

    // 阶段 3：重连 —— 必须重新 dial + **重新发送 Init** + 重新 Establishment。
    assert!(
        drive_until_established(&mut rt, b_id, 200_000),
        "EOF 之后必须能重新 Established（P1-2）"
    );
    assert!(rt.peer_lifecycle(b_id).is_none(), "重连成功 ⇒ 无失败历史");

    let served = handle.join().expect("fixture");
    assert_eq!(
        served,
        vec![true, true],
        "第 2 条连接亦被对端认证 ⇒ A 确实**重新发送**了 Handshake Init（P1-2 核心证据）"
    );
}

// ---------------------------------------------------------------------------
// T2 — Hub-spoke（单侧 dial）连续两次 EOF 均能自愈
// ---------------------------------------------------------------------------

#[test]
fn t2_hub_spoke_single_sided_dial_recovers_across_repeated_eof() {
    let env = Env::new();
    let b_kp = Arc::new(KeyPair::generate().unwrap());
    let b_id = node_id(&b_kp);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let b_addr = listener.local_addr().unwrap();
    // 三次连接：两次制造 EOF，最后一次保持（spoke 从不主动 dial ⇒ 只可能由 A 重发 Init 自愈）。
    let handle = spawn_peer_serving(
        listener,
        env.auth(),
        Arc::clone(&b_kp),
        vec![
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_secs(6),
        ],
    );

    let mut rt = start_a(&env, vec![target(b_id, b_addr)]);

    assert!(
        drive_until_established(&mut rt, b_id, 20_000),
        "回合 1 Established"
    );
    assert!(
        drive_until_disconnected(&mut rt, b_id, 200_000),
        "回合 1 观察到 EOF"
    );
    assert!(
        drive_until_established(&mut rt, b_id, 200_000),
        "回合 2 必须自愈"
    );
    assert!(
        drive_until_disconnected(&mut rt, b_id, 200_000),
        "回合 2 观察到 EOF"
    );
    assert!(
        drive_until_established(&mut rt, b_id, 200_000),
        "回合 3 必须再次自愈"
    );

    // 全程没有把"干净 EOF"误记成 dial 失败（重连 dial 均成功）。
    assert_eq!(
        rt.peer_dial_failures_total(),
        0,
        "EOF 重连不得产生 dial 失败"
    );

    let served = handle.join().expect("fixture");
    assert_eq!(
        served,
        vec![true, true, true],
        "三条连接均被对端认证 ⇒ 每次 EOF 后 A 都重新发送了 Init"
    );
}

// ---------------------------------------------------------------------------
// T3 — A.8 backoff 语义必须保持（对账不得重置失败历史）
// ---------------------------------------------------------------------------

#[test]
fn t3_backoff_semantics_preserved_after_reconcile() {
    let env = Env::new();
    let dead = node_id(&KeyPair::generate().unwrap());
    let mut rt = start_a(&env, vec![target(dead, bad_addr())]);

    // 第 1 轮：无 state ⇒ 立即尝试 ⇒ 真失败 ⇒ Backoff{1, 2}（A.8 冻结语义）。
    let r1 = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            r1[0].status,
            PeerStatus::Backoff {
                failure_count: 1,
                remaining_ticks: 2
            }
        ),
        "A.8：首次失败 ⇒ Backoff{{1,2}}，实际 {:?}",
        r1[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 1);

    // 退避内（peer_tick = 2 < next_allowed = 3）：不得重 dial、不得重置 failure_count。
    let r2 = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            r2[0].status,
            PeerStatus::Backoff {
                failure_count: 1,
                remaining_ticks: 1
            }
        ),
        "退避内必须为 Backoff{{1,1}}，实际 {:?}",
        r2[0].status
    );
    assert_eq!(
        rt.peer_dial_attempts_total(),
        1,
        "MAX_DIAL_ATTEMPTS_PER_CALL = 1 + 退避门控必须保持"
    );
    let st = rt.peer_lifecycle(dead).expect("失败历史存在");
    assert_eq!(st.failure_count, 1, "对账不得重置 failure_count");
    assert_eq!(
        st.next_allowed_attempt_tick, 3,
        "next_allowed = 1 + delay(1) = 3"
    );

    // peer_tick = 3 == next_allowed ⇒ 允许重试：序列保持 2 → 4，failure_count → 2。
    let r3 = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            r3[0].status,
            PeerStatus::Backoff {
                failure_count: 2,
                remaining_ticks: 4
            }
        ),
        "A.8：第 2 次失败 ⇒ Backoff{{2,4}}，实际 {:?}",
        r3[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 2);
    assert_eq!(rt.peer_dial_failures_total(), 2);

    // 再次进入退避（peer_tick = 4 < 7）：状态保持、不重 dial、不重置。
    let r4 = rt.establish_configured_peers().unwrap();
    assert!(
        matches!(
            r4[0].status,
            PeerStatus::Backoff {
                failure_count: 2,
                remaining_ticks: 3
            }
        ),
        "退避内必须为 Backoff{{2,3}}，实际 {:?}",
        r4[0].status
    );
    assert_eq!(rt.peer_dial_attempts_total(), 2);
    let st2 = rt.peer_lifecycle(dead).expect("失败历史仍在");
    assert_eq!(st2.failure_count, 2, "对账不得重置 failure_count");
    assert_eq!(st2.next_allowed_attempt_tick, 3 + 4);
}

// ---------------------------------------------------------------------------
// T4 — Periodic status（真实二进制；固定 step interval + 摘要契约）
// ---------------------------------------------------------------------------

/// 测试用临时目录（系统 temp；Drop 清理；不触碰仓库 / 用户文件）。
struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("yazimao_p1a9_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).expect("write temp file");
        p
    }

    fn write_seed(&self, name: &str, seed: [u8; 32]) -> PathBuf {
        self.write(name, hex32(&seed).as_bytes())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 有界等待进程退出（超时 ⇒ kill + 明确失败；绝不无限等待）。
fn wait_bounded(child: &mut Child, what: &str, deadline: Instant) -> ExitStatus {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {}
            Err(e) => panic!("{what}: try_wait 失败: {e}"),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: 未在有界等待上限内退出");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// 从 `key=<n>` 取十进制值（无正则；仅数字前缀）。
fn extract_number(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

#[test]
fn t4_periodic_status_and_enriched_summary() {
    let env = TempDir::new("status");
    let g = genesis();
    let genesis_hash = compute_genesis_hash(&g).expect("genesis hash");
    let genesis_path = env.write("genesis.bin", &canonical_genesis_bytes(&g).unwrap());
    let net_seed = env.write_seed("net.seed", [0x44; 32]);
    let storage = env.path("chain");

    let args: Vec<String> = vec![
        "--genesis".into(),
        genesis_path.to_string_lossy().into(),
        "--genesis-hash".into(),
        hex32(&genesis_hash),
        "--chain-id".into(),
        CHAIN_ID.to_string(),
        "--network-id".into(),
        "devnet".into(),
        "--storage-dir".into(),
        storage.to_string_lossy().into(),
        "--network-seed-file".into(),
        net_seed.to_string_lossy().into(),
        "--run-steps".into(),
        T4_RUN_STEPS.into(),
        "--idle-ms".into(),
        T4_IDLE_MS.into(),
    ];

    let exe = env!("CARGO_BIN_EXE_yazimao-node");
    let mut child = Command::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn yazimao-node");

    let status = wait_bounded(&mut child, "node", Instant::now() + T4_HARD_TIMEOUT);
    let mut stdout = String::new();
    {
        use std::io::Read;
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut stdout);
        }
    }
    let mut stderr = String::new();
    {
        use std::io::Read;
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut stderr);
        }
    }
    assert!(
        status.success(),
        "节点必须 exit 0；stdout={stdout}\nstderr={stderr}"
    );

    // 启动行契约（既有）+ status 行按固定 interval 出现。
    assert!(
        stdout.contains("entering bounded run loop"),
        "启动行缺失；stdout={stdout}"
    );
    let status_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("yazimao-node: status "))
        .collect();
    let expected = T4_RUN_STEPS.parse::<u64>().expect("run_steps 是十进制") / T4_STATUS_INTERVAL;
    assert_eq!(
        status_lines.len() as u64,
        expected,
        "status 行数必须 = run_steps / STATUS_INTERVAL_STEPS（非每 step）；stdout={stdout}"
    );
    let steps_seen: Vec<u64> = status_lines
        .iter()
        .filter_map(|l| extract_number(l, "steps="))
        .collect();
    assert_eq!(
        steps_seen,
        vec![T4_STATUS_INTERVAL, T4_STATUS_INTERVAL * 2],
        "status 必须在固定 step 边界输出；stdout={stdout}"
    );
    for key in [
        "head_height=",
        "finalized_height=",
        "consensus_height=",
        "round=",
        "configured_peers=",
        "established_peers=",
        "inbound_connections=",
        "sync_pending=",
        "validator_enabled=",
    ] {
        assert!(
            status_lines.iter().all(|l| l.contains(key)),
            "status 行缺少字段 {key}；stdout={stdout}"
        );
    }

    // 退出摘要：既有契约字段 + P1-A.9 新增观测字段。
    let summary = stdout
        .lines()
        .find(|l| l.contains("stopped after "))
        .unwrap_or_else(|| panic!("缺少退出摘要行；stdout={stdout}"));
    assert!(
        summary.contains(&format!(
            "stopped after {T4_RUN_STEPS}/{T4_RUN_STEPS} steps"
        )),
        "摘要预算字段异常: {summary}"
    );
    for key in [
        "head_height=",
        "finalized_height=",
        "consensus_height=",
        "round=",
        "configured_peers=",
        "inbound_connections=",
        "inbound_accepted=",
        "sync_pending=",
        "peer_dial_attempts=",
        "peer_dial_failures=",
        "validator_enabled=",
    ] {
        assert!(summary.contains(key), "摘要缺少字段 {key}: {summary}");
    }
    assert!(summary.contains("runtime shut down"), "摘要契约: {summary}");

    // 顺序：status 行必须早于退出摘要（观测发生在运行中）。
    let last_status_pos = stdout
        .rfind("yazimao-node: status ")
        .expect("status 行存在");
    let summary_pos = stdout.find("stopped after ").expect("摘要行存在");
    assert!(
        last_status_pos < summary_pos,
        "status 必须在运行中输出、且早于退出摘要"
    );
}
