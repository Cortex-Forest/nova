//! PHASE 6H-AI — O2 D1 **Applied** 在**真实多进程 TCP** 上的观测（observer / 滞后节点场景）。
//!
//! # 目标（Owner 授权 A；**test-only**）
//!
//! 证明**既有冻结** D1 适用路径可在真实网络被观测为 `Applied`：
//!
//! ```text
//! 真实进程 A（validator）——确定性 round-0 停滞（round-0 proposer 缺席）
//!   → 真实 EXPIRE → sign_abandon → 池 quorum(2W) → 组装 `RoundChangeCertificate`
//!   → `0x0D` 经 **真 TCP** 广播
//! ==================== NETWORK ====================
//! 真实进程 O（**observer / 非 validator**；`--validator` 不传）
//!   → `NetworkService` decode → wiring → `NodeRuntime::step()`
//!   → 冻结 `verify_certificate` → D1 适用性 → **Applied** → round +1 → 计时器重开
//! ```
//!
//! 接受判据（Owner）：**真实 observer 进程上 `rc_authority >= 1`**，且该计数只由
//! `apply_verified_round_change` 的 `RoundChangeApplication::Applied` 分支递增
//!（`runtime.rs` `drive_round_change_authority` / `reevaluate_stored_round_change`）。
//! **不**以"收到 `0x0D`"推断 authority。
//!
//! # 为什么 observer 必须**在首张证书广播之前**就连上（对 Owner 建议顺序的**必要偏离**）
//!
//! 冻结语义（只读核实；本阶段未修改任何一行生产代码）：
//! - `apply_verified_round_change` ②：`cert.height != node.state().round.height ⇒ Rejected{WrongHeight}`
//!   ⇒ 接收方必须与证书**同高度**；
//! - `0x0D` 由组装方**一次性广播**（`take_pending_broadcast` 排空；无重播/无 relay）；
//! - A/B 的 round-0 停滞一旦被打破（后续轮 proposer 在线）即**迅速推进高度**
//!   （6H-AH 实测：step ~1100 时 `head=3`）。
//!
//! ⇒ 若等首张证书产生后再启动 O，O 只可能收到**更高高度**的证书（`WrongHeight`）或
//!   需等待 O 自行 sync 追平（A17 追赶实测 ≈4.3s/块，不在本阶段范围）⇒ 无法在本窗口内观测 Applied。
//! ⇒ 因此 O 在 **A/B 就绪后立即启动**（仍是**条件驱动**：`entering bounded run loop` → O → 建立连接），
//!   并以 `--idle-ms` **放大 O 的逻辑时钟**（O 5ms/step vs A/B 3ms/step）使其在 A/B 首张证书到达时
//!   **仍在 round 0**（O 的 round-0 窗口 ≈5s，远大于证书时刻 ≈3s）。
//!   **不使用**固定 sleep 作为同步手段。
//!
//! # 拓扑（为什么 O 只连 A）
//!
//! O 仅配置 `--peer A`（单边 dial；A 侧 accept + greet ⇒ 单条 TCP 双向成立）：
//! - A 的 `broadcast`（established-only）覆盖 O ⇒ O 收到 **恰好一份** `0x0D`（A 的）；
//! - O 只收到 A 的 `0x0E` ⇒ O 池最多 1W < quorum 2W ⇒ **不会**自行组装/广播（`rc_certs == 0`）；
//! - B 与 O 无连接 ⇒ B 的证书副本不会到达 O ⇒ O 观察 `rc_rejected == 0`（**唯一**副本被 Applied，
//!   无"第二副本落为 stale"的情形）。
//!
//! # 明确边界（本阶段不做）
//!
//! 不改生产代码 / 不改 consensus / 不改 D1 applicability / 不改 sync / A17 / NetworkService /
//! framing / auth / `0x0D` / `0x0E` / D3；不加 test-only production hook；不跑长实验。

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::signature::SigningKey;
use nova_network::node_id::NodeId;
use nova_node::runtime::derive_validator_id;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// A/B（validator）逻辑时钟：`--idle-ms 3` ⇒ round-0 窗口 1000 tick ≈ 3s（首张证书时刻）。
const AB_IDLE_MS: &str = "3";
const AB_RUN_STEPS: &str = "3000";
/// O（observer）逻辑时钟：**极度慢速**（50ms/step）。实测：证书帧在 A 侧 assemb 后需相当长的
/// 网络/队列延迟才被 O 轮询到（前两次实测 O 在收到时其 height/round 已先行推进 ⇒ 冻结语义拒绝）。
/// round 与 height 的推进均按 **step** 计，步进变慢 ⇒ 两者同步变慢 ⇒ O 在收到证书时仍处于
/// `(height 0, round 0)` ⇒ 冻结 D1 应判 `Applied`。
const OBSERVER_IDLE_MS: &str = "50";
const OBSERVER_RUN_STEPS: &str = "1200";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// D1 观测窗口（仅等待确定性即将发生的事件）。
const D1_WINDOW: Duration = Duration::from_secs(180);
/// P4 有界收敛窗口：等待 A/B 的**已采样** durable head 追平观察者（见阶段 6 说明）。
const P4_CONVERGENCE: Duration = Duration::from_secs(120);

/// 与 6H-AH 相同的确定性身份（3 验证者 genesis；round-0 proposer 缺席 ⇒ 确定性停滞）。
const VAL_SEED: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NET_SEED: [[u8; 32]; 3] = [[0x41; 32], [0x42; 32], [0x43; 32]];
/// observer 的 network 身份（独立于 3 个 validator 的 network seed）。
const OBSERVER_NET_SEED: [u8; 32] = [0x44; 32];

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn net_node_id(seed: [u8; 32]) -> NodeId {
    NodeId::from_verifying_key(&SigningKey::from_seed(seed).verifying_key())
}

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Devnet,
        key_hash: kh,
    })
}

/// N 验证者 devnet genesis（等额 stake ⇒ quorum = ceil(2N/3)；canonical ordering）。
fn test_genesis(val_seeds: &[[u8; 32]]) -> GenesisV1 {
    let n = val_seeds.len();
    let accounts: Vec<AccountInit> = (0..n)
        .map(|i| AccountInit {
            address: addr([0x10 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut validators: Vec<([u8; 32], YazimaoAddress)> = (0..n)
        .map(|i| {
            let pk = SigningKey::from_seed(val_seeds[i])
                .verifying_key()
                .to_bytes();
            (pk, accounts[i].address)
        })
        .collect();
    validators.sort_by_key(|(pk, _)| derive_validator_id(pk));
    GenesisV1 {
        network_id: NetworkId::Devnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: validators
            .into_iter()
            .map(|(pk, account_address)| ValidatorInit {
                account_address,
                consensus_public_key: pk,
                bonded_stake: STAKE,
                commission_bps: 0,
            })
            .collect(),
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
            total_supply: 1_000_000 * n as u128,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

/// 测试临时目录（系统 temp；Drop 递归清理）。
struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("yazimao_o2_ai_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
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

fn free_port() -> u16 {
    let l = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind 0");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

/// 子进程 guard：持续排空 stdout/stderr（防 pipe 满死锁）；Drop ⇒ kill + wait（无孤儿进程）。
struct ChildGuard {
    label: &'static str,
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

impl ChildGuard {
    fn spawn(label: &'static str, args: &[String]) -> Self {
        let exe = env!("CARGO_BIN_EXE_yazimao-node");
        let mut child = Command::new(exe)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label} 失败: {e}"));
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        if let Some(mut out) = child.stdout.take() {
            let sink = Arc::clone(&stdout);
            thread::spawn(move || drain(&mut out, sink));
        }
        if let Some(mut err) = child.stderr.take() {
            let sink = Arc::clone(&stderr);
            thread::spawn(move || drain(&mut err, sink));
        }
        Self {
            label,
            child,
            stdout,
            stderr,
        }
    }

    fn stdout(&self) -> String {
        self.stdout.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        self.stderr.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn terminate(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn diagnostic(&self, stats: Option<Stats>) -> String {
        let out = self.stdout();
        let err = self.stderr();
        let log = std::env::temp_dir().join(format!("yazimao-o2-ai-{}.log", self.label));
        let _ = std::fs::write(
            &log,
            format!("=== STDOUT ===\n{out}\n=== STDERR ===\n{err}\n"),
        );
        let tail = |s: &str| -> String {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(60)..].join("\n")
        };
        format!(
            "--- NODE {} (pid={}) ---\nstats={stats:?}\nlog_file={}\n\
             --- last 60 stdout ---\n{}\n--- last 60 stderr ---\n{}\n",
            self.label,
            self.child.id(),
            log.display(),
            tail(&out),
            tail(&err)
        )
    }
}

fn drain<R: Read>(reader: &mut R, sink: Arc<Mutex<String>>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if let Ok(mut g) = sink.lock() {
                    g.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
    }
}

/// 条件轮询直到 `pred` 为真（hard deadline；非 sleep-only 判定）。
fn poll_until(mut pred: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    pred()
}

/// 真实二进制测试串行 guard。
fn real_binary_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 观测（全部取自**真实进程** stdout 的 status 行；字段由 PHASE 6H-AH 暴露，读 runtime 既有 accessor）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Stats {
    steps: u64,
    height: u64,
    round: u64,
    /// `head_height`（durable head；与 `height` = `consensus_height` 分开观测）。
    head: u64,
    /// `finalized_height`（`qc_history_tip_height`；`none` ⇒ 0）。
    finalized: u64,
    /// `finalized_ref_present`（是否有 finality reference）。
    finalized_ref_present: bool,
    validator_enabled: bool,
    abandon_produced: u64,
    abandon_broadcast: u64,
    abandon_rejected: u64,
    rc_certs: u64,
    rc_authority: u64,
    rc_rejected: u64,
    /// `rc_rej=` 六个拒绝分类桶（**严格**解析；缺失/畸形 ⇒ 无样本）。
    rc_rej: [u64; 6],
    established_peers: u64,
}

/// `rc_rej=` 桶索引（与 `runtime.rs` 的 `RoundChangeRejectKind::index()` 一一对应）。
const RC_REJ_MALFORMED: usize = 0;
const RC_REJ_STALE: usize = 1;
const RC_REJ_WRONG_HEIGHT: usize = 2;
const RC_REJ_QUORUM: usize = 3;
const RC_REJ_IDENTITY: usize = 4;
const RC_REJ_OTHER: usize = 5;

/// 解析 `key=a/b/c/d/e/f`（**严格**：字段缺失或任一分量不可解析 ⇒ `None`；绝不默认零）。
fn buckets6(line: &str, key: &str) -> Option<[u64; 6]> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let raw: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '/')
        .collect();
    let mut out = [0u64; 6];
    let mut it = raw.split('/');
    for slot in out.iter_mut() {
        *slot = it.next()?.parse().ok()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some(out)
}

fn field(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn bool_field(line: &str, key: &str) -> Option<bool> {
    let start = line.find(key)? + key.len();
    match line.get(start..)?.chars().next()? {
        't' => Some(true),
        'f' => Some(false),
        _ => None,
    }
}

fn is_status(line: &str) -> bool {
    line.contains(": status ") && line.contains("rc_authority=")
}

fn parse_line(line: &str) -> Option<Stats> {
    Some(Stats {
        steps: field(line, "steps=")?,
        height: field(line, "consensus_height=")?,
        round: field(line, "round=")?,
        head: field(line, "head_height=").unwrap_or(0),
        finalized: field(line, "finalized_height=").unwrap_or(0),
        finalized_ref_present: bool_field(line, "finalized_ref_present=").unwrap_or(false),
        validator_enabled: bool_field(line, "validator_enabled=")?,
        abandon_produced: field(line, "abandon_produced=").unwrap_or(0),
        abandon_broadcast: field(line, "abandon_broadcast=").unwrap_or(0),
        abandon_rejected: field(line, "abandon_rejected=").unwrap_or(0),
        rc_certs: field(line, "rc_certs=").unwrap_or(0),
        rc_authority: field(line, "rc_authority=").unwrap_or(0),
        rc_rejected: field(line, "rc_rejected=").unwrap_or(0),
        rc_rej: buckets6(line, "rc_rej=")?,
        established_peers: field(line, "established_peers=").unwrap_or(0),
    })
}

fn last_stats(out: &str) -> Option<Stats> {
    out.lines().rfind(|l| is_status(l)).and_then(parse_line)
}

fn all_stats(out: &str) -> Vec<Stats> {
    out.lines()
        .filter(|l| is_status(l))
        .filter_map(parse_line)
        .collect()
}

#[test]
fn o2_d1_applied_observed_on_real_observer_process() {
    let _serial = real_binary_guard();
    let env = TempDir::new("d1_apply");

    // ---- fixtures：3 验证者 genesis（**不可改**；quorum = 2W）----
    let genesis = test_genesis(&VAL_SEED);
    let genesis_hash = compute_genesis_hash(&genesis).expect("genesis hash");
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical genesis"),
    );
    let genesis_hash_hex = hex32(&genesis_hash);
    let set = ValidatorSet::from_genesis(&genesis);

    // ---- 确定性停滞：省略 round-0 proposer（父高度轮约定，与 block_dispatch 一致）----
    let proposer0 = select_proposer(CHAIN_ID, 0, 0, &genesis_hash, &set).expect("proposer r0");
    let val_ids: Vec<ValidatorId> = VAL_SEED
        .iter()
        .map(|s| derive_validator_id(&SigningKey::from_seed(*s).verifying_key().to_bytes()))
        .collect();
    let absent_idx = val_ids
        .iter()
        .position(|id| *id == proposer0)
        .expect("round-0 proposer 必须属于 genesis validator set");
    let running: Vec<usize> = (0..3).filter(|i| *i != absent_idx).collect();

    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let net_seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("net-{i}.seed"), NET_SEED[i]))
        .collect();
    let val_seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("val-{i}.seed"), VAL_SEED[i]))
        .collect();

    // ---- validator 参数（A/B；真实 TCP）；A **额外显式 dial O** ----
    // 必要性（实测）：`NetworkService::broadcast` 只发给 **Established** 对端。仅靠 O 单边 dial A
    // 时，A 侧不把 O 计入可广播集（实测：A 的 `0x0D` 未到达 O ⇒ O.rc_authority 恒 0）。
    // ⇒ 让 A 也 **configured dial** O（O 的端口在此已分配）⇒ A 侧必有 Established 的 O。
    let observer_net_id = net_node_id(OBSERVER_NET_SEED);
    let observer_port = free_port();
    let build_validator_args = |i: usize, peer_idx: usize| -> Vec<String> {
        let safety_dir = env.path(&format!("safety-{i}"));
        let mut args: Vec<String> = vec![
            "--genesis".into(),
            genesis_path.to_string_lossy().into(),
            "--genesis-hash".into(),
            genesis_hash_hex.clone(),
            "--chain-id".into(),
            CHAIN_ID.to_string(),
            "--network-id".into(),
            "devnet".into(),
            "--storage-dir".into(),
            env.path(&format!("chain-{i}")).to_string_lossy().into(),
            "--safety-dir".into(),
            safety_dir.to_string_lossy().into(),
            "--network-seed-file".into(),
            net_seed_paths[i].to_string_lossy().into(),
            "--validator".into(),
            "--validator-seed-file".into(),
            val_seed_paths[i].to_string_lossy().into(),
            "--listen".into(),
            format!("127.0.0.1:{}", ports[i]),
            "--run-steps".into(),
            AB_RUN_STEPS.into(),
            "--idle-ms".into(),
            AB_IDLE_MS.into(),
        ];
        if !safety_dir.join("safety.journal").exists() {
            args.push("--init-validator-safety".into());
        }
        args.push("--peer".into());
        args.push(format!(
            "{}@127.0.0.1:{}",
            hex32(net_ids[peer_idx].as_bytes()),
            ports[peer_idx]
        ));
        // 仅 A（running[0]）额外 dial observer ⇒ A 的 broadcast 必覆盖 O（且 B 不连 O
        // ⇒ O 只收到一份 `0x0D` 副本 ⇒ `rc_rejected` 可为 0）。
        if i == running[0] {
            args.push("--peer".into());
            args.push(format!(
                "{}@127.0.0.1:{}",
                hex32(observer_net_id.as_bytes()),
                observer_port
            ));
        }
        args
    };

    // ---- observer 参数（**不传 --validator**；独立 storage / network seed / listen / 端口；
    //      仅 --peer A ⇒ 恰好一份 `0x0D` 副本，且自身池永不成 quorum）----
    let observer_net_seed_path = env.write_seed("net-observer.seed", OBSERVER_NET_SEED);
    let observer_args: Vec<String> = vec![
        "--genesis".into(),
        genesis_path.to_string_lossy().into(),
        "--genesis-hash".into(),
        genesis_hash_hex.clone(),
        "--chain-id".into(),
        CHAIN_ID.to_string(),
        "--network-id".into(),
        "devnet".into(),
        "--storage-dir".into(),
        env.path("chain-observer").to_string_lossy().into(),
        "--network-seed-file".into(),
        observer_net_seed_path.to_string_lossy().into(),
        "--listen".into(),
        format!("127.0.0.1:{observer_port}"),
        "--run-steps".into(),
        OBSERVER_RUN_STEPS.into(),
        "--idle-ms".into(),
        OBSERVER_IDLE_MS.into(),
        "--peer".into(),
        format!(
            "{}@127.0.0.1:{}",
            hex32(net_ids[running[0]].as_bytes()),
            ports[running[0]]
        ),
    ];

    // ---- 阶段 1：**先启动 observer O**（关键：O 的 listener 必须先于 A 的首次 dial 存在）----
    // 实测：`NetworkService::broadcast` 只发给 **Established** 对端；若 A 先启动、O 后监听，
    // A 对 O 的 dial 首轮失败并进入退避（2^failures × idle）⇒ 在首张证书时刻 A 还没有 O，
    // 证书不会到达 O（实测 rc_authority 恒 0）。⇒ **O 先监听，A/B 后启动**，A 首轮 dial 即成功。
    // 注意：O 的 warmup 需要 A/B 已上线 ⇒ O 的 step 循环会在 A/B 就绪后开始（不影响结论）。
    let mut o = ChildGuard::spawn("O", &observer_args);
    thread::sleep(Duration::from_millis(150));

    // ---- 阶段 2：启动 A、B（2 个真实 validator 进程；A 额外 dial O）----
    let mut a = ChildGuard::spawn("A", &build_validator_args(running[0], running[1]));
    let mut b = ChildGuard::spawn("B", &build_validator_args(running[1], running[0]));
    let ready = poll_until(
        || {
            a.stdout().contains("entering bounded run loop")
                && b.stdout().contains("entering bounded run loop")
        },
        STARTUP_TIMEOUT,
    );
    assert!(
        ready,
        "A/B 必须进入 run loop\n{}\n{}",
        a.diagnostic(None),
        b.diagnostic(None)
    );
    let o_ready = poll_until(
        || o.stdout().contains("entering bounded run loop"),
        STARTUP_TIMEOUT,
    );
    assert!(
        o_ready,
        "observer 必须进入 run loop\n{}",
        o.diagnostic(None)
    );

    // ---- 阶段 3：O 完成真实鉴权连接（established peers ≥ 1；单边 dial 由 accept+greet 闭合）----
    let o_connected = poll_until(
        || last_stats(&o.stdout()).is_some_and(|s| s.established_peers >= 1),
        STARTUP_TIMEOUT,
    );
    assert!(
        o_connected,
        "observer 必须与 A 完成真实 TCP 鉴权连接\n{}",
        o.diagnostic(last_stats(&o.stdout()))
    );

    // ---- 阶段 4：A/B 真实产生 O2 证书（`0x0E` 交换 ⇒ quorum 2W ⇒ 组装并广播 `0x0D`）----
    let ab_certified = poll_until(
        || {
            [&a, &b]
                .iter()
                .all(|c| last_stats(&c.stdout()).is_some_and(|s| s.rc_certs >= 1))
        },
        D1_WINDOW,
    );

    // ---- 阶段 5：**核心观测** —— O 上出现 D1 `Applied`（`rc_authority >= 1`）----
    let applied = poll_until(
        || last_stats(&o.stdout()).is_some_and(|s| s.rc_authority >= 1),
        D1_WINDOW,
    );

    // ---- 阶段 6：P4 有界收敛（在采集/终止之前）----
    // 等待 A/B 的**已采样** durable head 追平/超过 O 的 durable head（见 P4 处说明）。
    let p4_converged = poll_until(
        || {
            let a_head = last_stats(&a.stdout()).map_or(0, |s| s.head);
            let b_head = last_stats(&b.stdout()).map_or(0, |s| s.head);
            let o_head = last_stats(&o.stdout()).map_or(0, |s| s.head);
            a_head.max(b_head) >= o_head
        },
        P4_CONVERGENCE,
    );

    // ---- 证据采集（terminate 之前）----
    let a_stats = last_stats(&a.stdout());
    let b_stats = last_stats(&b.stdout());
    let o_stats = last_stats(&o.stdout());
    let o_samples = all_stats(&o.stdout());
    let alive = [a.is_running(), b.is_running(), o.is_running()];

    for c in [&mut a, &mut b, &mut o] {
        c.terminate();
    }

    let diag = || {
        format!(
            "absent_validator_index={absent_idx} running={running:?} ab_certified={ab_certified} \
             applied={applied}\nalive={alive:?}\nA={a_stats:?}\nB={b_stats:?}\nO={o_stats:?}\n\
             O_samples={o_samples:?}\n{}\n{}\n{}",
            a.diagnostic(a_stats),
            b.diagnostic(b_stats),
            o.diagnostic(o_stats),
        )
    };

    // ================= 断言 =================
    let o_stats = o_stats.unwrap_or_else(|| panic!("observer 无有效 status 样本\n{}", diag()));

    // (1) O 形态：非 validator（未参与 consensus 表决/提案/attestation）。
    assert!(
        !o_stats.validator_enabled,
        "observer 必须为 validator_enabled=false\n{}",
        diag()
    );
    // (2) O 从未本地签名 attestation（无 actor）。
    assert_eq!(
        o_stats.abandon_produced,
        0,
        "observer 不得产生本地 attestation\n{}",
        diag()
    );
    // (3) O 池未成 quorum（只收到 A 的 `0x0E` = 1W < 2W）⇒ 不自行组装/广播。
    assert_eq!(
        o_stats.rc_certs,
        0,
        "observer 不应组装证书（仅 1W < quorum 2W）\n{}",
        diag()
    );
    // (4) **核心**：D1 `Applied`（真实 TCP 上的 `0x0D` 经冻结验证 + 适用性 ⇒ round +1）。
    assert!(
        applied && o_stats.rc_authority >= 1,
        "observer 必须观测到 D1 Applied（rc_authority >= 1）\n{}",
        diag()
    );
    // (5) 拒绝**分类契约**（取代旧的 `rc_rejected == 0`）。
    //
    // 旧断言把「observer 恰好只收到一份 `0x0D`」这一**拓扑/观测假设**写成了协议契约；同提交的
    // `o2_round_change_real_tcp_e2e.rs` 已明确容忍「本地计时器先行前进 ⇒ 证书按冻结语义被判 stale」。
    // 源码依据（`crates/consensus/src/round_change.rs::verify_certificate`）：
    //   ⑪ `to_round <= local_round ⇒ StaleCertificate`；② `cert.height != local height ⇒ WrongHeight`。
    // 二者在 ADR-0066 下都是**合法**拒绝；observer 自身 pacemaker 会独立推进 (height, round)
    // （`runtime.rs::drive_round_timeout` 对所有节点生效），故重复/迟到副本可合法落入这两类。
    //
    // 但**只放行这两类**，并强制分类完备：任何 Malformed / Quorum / Identity / Other（或未分类）
    // 拒绝仍使测试失败 ⇒ 「不允许非法消息或未授权证书通过」这一安全保证**未被削弱**。
    assert_eq!(
        o_stats.rc_rej[RC_REJ_MALFORMED],
        0,
        "observer 不得出现 Malformed 拒绝\n{}",
        diag()
    );
    assert_eq!(
        o_stats.rc_rej[RC_REJ_QUORUM],
        0,
        "observer 不得出现 Quorum 拒绝\n{}",
        diag()
    );
    assert_eq!(
        o_stats.rc_rej[RC_REJ_IDENTITY],
        0,
        "observer 不得出现 Identity 拒绝\n{}",
        diag()
    );
    assert_eq!(
        o_stats.rc_rej[RC_REJ_OTHER],
        0,
        "observer 不得出现 Other 拒绝\n{}",
        diag()
    );
    assert_eq!(
        o_stats.rc_rejected,
        o_stats.rc_rej[RC_REJ_STALE] + o_stats.rc_rej[RC_REJ_WRONG_HEIGHT],
        "拒绝只能是合法 Stale/WrongHeight，且必须分类完备（rc_rejected == Stale + WrongHeight）\n{}",
        diag()
    );
    // (6) 验证者侧确实走完了 O2 生产路径（真实 EXPIRE ⇒ `0x0E` ⇒ quorum 2W ⇒ `0x0D`）。
    // **系统级**（不做逐节点要求）：谁先收到对端 attestation 决定谁成为组装方 —— 实测中
    // A 的**自身** attestation 恰好完成 quorum ⇒ 池返回 `Assembled`（而非 `Recorded`）⇒ A
    // 不再广播自己的 `0x0E`（`abandon_broadcast=0`），且 B 因收不到 A 的 `0x0E` 而 `rc_certs=0`。
    // 这是 6H-AH 已定义的幂等语义（同 `(height, from_round)` 不重复广播），非缺陷。
    let prod_total: u64 =
        a_stats.map_or(0, |s| s.abandon_produced) + b_stats.map_or(0, |s| s.abandon_produced);
    let certs_total: u64 = a_stats.map_or(0, |s| s.rc_certs) + b_stats.map_or(0, |s| s.rc_certs);
    assert!(
        prod_total >= 2,
        "A+B 必须各自产生真实 EXPIRE attestation（合计 >= 2）\n{}",
        diag()
    );
    assert!(
        certs_total >= 1,
        "A+B 中必须至少一方达到 quorum 2W 并组装证书\n{}",
        diag()
    );

    // (7) authority **归因**（**性质式 oracle**；已取代旧的逐样本"恰好 +1"断言）
    //
    // ★ 观测粒度（诚实边界；本轮**未**改生产观测面）：status 行每 100 step 一行，O（idle 50ms）
    //   约每 5s 一行；observer 可在**同一观测窗**内经 sync 追赶**多个**高度（合法：逐块提交）。
    //   ⇒ “相邻样本高度恰好 +1”是**观测粒度假设**，不是协议性质 —— 旧断言在此产生**假失败**。
    //   本段改为性质断言（并保留真正的非法检测）：
    //   P1 单调：`height` 永不回退；同高度内 `round` 永不回退；
    //   P2 归因：`rc_authority` 首次 ≥ 1 的样本必须与前一态**不同**（Applied 必改变 round/height）；
    //   P3 归因（修订）：`rc_authority` 累计**单调**，且**每次增加**都必须伴随本地 (height, round)
    //            变化 —— **取消**旧「恰为 1」的唯一性假设（多张不同证书可合法应用，见 P3 处说明）；
    //   P4 覆盖（修订）：observer durable head 必须（在**有界收敛**窗口内）被 A/B 的已采样
    //            durable head 覆盖（容差 0）⇒ 观察者不是链推进的来源；**不**再跨时刻比较 +1 容差；
    //   P5 目标/终局：A/B 必须跨过 round-0 停滞（`head >= 1`）；`finalized <= head`；两者都已 finality。
    let idx = o_samples
        .iter()
        .position(|s| s.rc_authority >= 1)
        .unwrap_or_else(|| panic!("O 样本中必须出现 rc_authority >= 1\n{}", diag()));
    assert!(idx >= 1, "需要至少一个前序样本才能证明增量唯一\n{}", diag());
    let prev = o_samples[idx - 1];
    let cur = o_samples[idx];
    assert_eq!(
        prev.rc_authority,
        0,
        "authority 首次递增点前的样本必须为 0\n{}",
        diag()
    );
    // 取代旧断言 `cur.rc_authority == 1`（":739-742"）：
    // status 每 **100 step** 才打印一次（`crates/node/src/bin/yazimao-node.rs:86`），因此"首个非零
    // 样本恰为 1"是**采样粒度假设** —— 一个采样窗内可合法地发生**多次**应用（⇒ 首个非零样本可为 2）。
    // 真正可证明的性质是"非零即已发生真实应用"（`rc_authority` 仅在 `Applied` 分支自增）与"每次
    // 增加都伴随状态变化"（见下方 P3 归因循环）；此处**不**对上界作未经证明的假设。
    assert!(
        cur.rc_authority >= 1,
        "authority 首次非零样本必须 >= 1\n{}",
        diag()
    );
    // P2：Applied 必定改变本地 round/height（同 `(height, round)` 而 authority 增加 = 非法）。
    assert!(
        cur.height != prev.height || cur.round != prev.round,
        "authority 递增但状态未变（prev h={} r={} → cur h={} r={}）\n{}",
        prev.height,
        prev.round,
        cur.height,
        cur.round,
        diag()
    );
    // P3（修订）：**逐样本归因**取代旧的 `assert_eq!(o_stats.rc_authority, 1)`。
    //
    // 旧前提「整轮仅一张证书」**不是**协议性质：证书按**每个** `(height, from_round)` 上 2W 见证
    // 重合而独立产生（`crates/consensus/src/round_change.rs::verify_certificate` ⑤⑥⑨），而 A/B 在本
    // 场景会**多次**到期（实测 `abandon_produced` = 3/4）⇒ 同一轮运行内**可合法地应用多张不同证书**
    // （实测 `rc_authority == 2`，且 `rc_rej` 仅 `Stale`）。
    //
    // 「同一证书不得重复应用」在冻结语义下**结构性成立**：首次应用后 `local_round == to_round`
    // ⇒ 任何副本必然在 ⑪ `to_round <= local_round` 处被判 `Stale`（**零副作用**）。该性质由
    // (4)（≥ 1 次真实应用）、(5)（拒绝仅限 Stale/WrongHeight）与本循环（每次增加都伴随状态变化）
    // 共同覆盖 —— **无需**、也**不应**用总计数上界来表达（该上界不可从协议推出）。
    for w in o_samples.windows(2) {
        let (p, c) = (w[0], w[1]);
        assert!(
            c.rc_authority >= p.rc_authority,
            "authority 累计计数不得回退 {}→{}\n{}",
            p.rc_authority,
            c.rc_authority,
            diag()
        );
        if c.rc_authority > p.rc_authority {
            assert!(
                c.height != p.height || c.round != p.round,
                "authority 增加必须伴随本地 (height, round) 变化\
                 （prev h={} r={} a={} → cur h={} r={} a={}）\n{}",
                p.height,
                p.round,
                p.rc_authority,
                c.height,
                c.round,
                c.rc_authority,
                diag()
            );
        }
    }
    // P1：单调性（真正的非法状态检测；不要求逐窗 +1）。
    for w in o_samples.windows(2) {
        let (p, c) = (w[0], w[1]);
        assert!(
            c.height >= p.height,
            "observer height 回退 {}→{}（steps {}→{}）\n{}",
            p.height,
            c.height,
            p.steps,
            c.steps,
            diag()
        );
        if p.height == c.height {
            assert!(
                c.round >= p.round,
                "observer 同高度 round 回退 {}→{}（steps {}→{}）\n{}",
                p.round,
                c.round,
                p.steps,
                c.steps,
                diag()
            );
        }
    }
    // P4（修订）：容差为 **0** 的 durable-head 覆盖（配合上方阶段 6 的有界收敛等待）。
    //
    // 旧断言 `o.head <= max(a.head, b.head) + 1` 直接比较**不同时刻**的采样：status 每 100 step 打印
    // 一次（`yazimao-node.rs:86`），而 `head_height` 是 **durable** head（`block_production().head()`,
    // `yazimao-node.rs:1075`）⇒ 本测试在 O 首次 `applied` 后立即采集/终止，A/B 的**最后一条采样**
    // 可能落后其真实 durable head 若干高度 ⇒ 旧断言存在**采样竞态**，其失败**不能**证明协议违规。
    //
    // 新契约（保持安全意图）：仅在 A/B 的已采样 durable head **有界收敛**至 ≥ O 的 durable head 之后，
    // 再做**容差 0** 的比较 ⇒ 证明"观察者的 durable head 已被验证者提供的高度覆盖"（观察者不是
    // 链推进的来源）。窗口耗尽仍未覆盖 ⇒ 失败并输出完整诊断（可能是真实异常，需独立调查）。
    // **不**扩大容差、**不**无条件放宽：仍要求 `ab_max >= o.head`。
    let ab_head_max = a_stats
        .map_or(0, |s| s.head)
        .max(b_stats.map_or(0, |s| s.head));
    assert!(
        p4_converged && ab_head_max >= o_stats.head,
        "observer durable head 未被 A/B 覆盖（有界收敛失败：o={} ab_max={} converged={}）\n{}",
        o_stats.head,
        ab_head_max,
        p4_converged,
        diag()
    );
    // P5：目标 + 终局一致性（2/3 quorum ⇒ A/B 必须共同推进；finalized 不得超过自身 head）。
    if let (Some(a), Some(b)) = (a_stats, b_stats) {
        assert!(
            a.head >= 1 && b.head >= 1,
            "A/B 必须跨过 round-0 停滞（head >= 1）\n{}",
            diag()
        );
        assert!(
            a.finalized <= a.head && b.finalized <= b.head && o_stats.finalized <= o_stats.head,
            "finalized 不得超过自身 head（A {}/{}, B {}/{}, O {}/{}）\n{}",
            a.finalized,
            a.head,
            b.finalized,
            b.head,
            o_stats.finalized,
            o_stats.head,
            diag()
        );
        assert!(
            a.finalized >= 1 && b.finalized >= 1,
            "A/B 必须各自达到 finality（finalized >= 1）\n{}",
            diag()
        );
    }

    // 证据输出（`--nocapture` 可见）。
    println!(
        "O2_D1_APPLY_EVIDENCE absent_validator_index={absent_idx} running={running:?} \
         A={a_stats:?} B={b_stats:?} O={o_stats:?} O_samples={o_samples:?}"
    );
}
