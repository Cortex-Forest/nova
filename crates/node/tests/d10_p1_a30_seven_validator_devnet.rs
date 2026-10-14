//! B3 — **Tier-2：7 个真实 `yazimao-node` 进程**（真实 TCP、生产二进制路径）。
//!
//! 目的（Testnet readiness 证据；**tests-only**）：以 **7 个独立 validator 进程**验证
//! frozen consensus 的 **2/3 quorum 边界**，不改变任何生产语义：
//! - quorum（权重制）= `ceil(total_weight × 2 / 3)`；7 × 等额 stake（`7×STAKE = 1_400_000`）
//!   ⇒ quorum = **933_334**；
//!   · 7/7 online（1_400_000）≥ quorum ⇒ finality **EXPECTED**；
//!   · 6/7 online（1_200_000）≥ quorum ⇒ finality **EXPECTED**；
//!   · 5/7 online（1_000_000）≥ quorum ⇒ finality **EXPECTED**（BFT 门限恰好可达）；
//!   · 4/7 online（  800_000）<  quorum ⇒ finality **NOT EXPECTED**。
//! - 每节点独立：validator 身份（seed）／network 身份（seed）／storage 目录／safety 目录／监听端口／
//!   **独立 OS 进程生命周期**（不使用 `replica:N`，不共享 seed / storage / safety journal）。
//! - 真实 loopback TCP + 真实认证握手（生产 `NetworkService` + `PeerAuthConfig` 路径）。
//!
//! # ★ METRIC DISCIPLINE（PHASE 3 修正）
//!
//! CLI status 行字段语义（**必须严格区分**）：
//! ```text
//! head_height        = production head（validator 模式下只在「finality commit」后前进）
//! consensus_height   = round.height（consensus context 高度）
//! finalized_height   = runtime.qc_history_tip_height()（durable QC-history tip，**服务能力指标**）
//! round              = 当前 BFT round（> 0 ⇒ pacemaker timeout 已发生）
//! qc_served          = 对他节点 served QC 数（服务能力）
//! ```
//! ⇒ **`finalized_height` 不是 consensus finality**；PHASE 2 曾误用它作全节点判据（已修正）。
//!
//! ## FINALITY OBSERVATION GAP（binary 层已知缺口，只读记录，不修改生产代码）
//!
//! CLI status 行**不暴露** `state().finality.finalized_reference`（真实 consensus finality）。
//! in-process rig（`d10_p1_a10_common`）有 `finalized_ref(rt)` / `precommit_weight(rt)` 可直读，
//! 但**不适用于真实 OS 进程**。
//! ⇒ 本文件以 **`head_height` 前进（finality-commit 代理）+ 跨节点 head 一致 + `consensus_height`
//!   前进** 作为 7/6/5-of-7 的 finality 判据，并**显式标注为代理指标**；
//!   4/7 以「无 head 前进 ∧ 无 durable QC tip ∧ 无 QC 服务」三条同时成立作为 no-finality 判据。
//!
//! # PACEMAKER WINDOW（PHASE 3 修正）
//!
//! 生产默认 `RoundTimeoutConfig = (initial 1000 tick, max 60_000, ×2)`；offline proposer ⇒
//! round 0→1 需 ~1000 tick、1→2 再 ~2000 tick。旧窗口（300s）**不足**。
//! 本文件在 T7-1 的 **S0 阶段先实测 step rate**，再据此设定窗口（覆盖 ≥2 个 timeout cycle）。
//!
//! 说明：
//! - 本文件**自包含**（复制必要 helper）；**不修改**既有 A12 / A21 / rig 文件。
//! - 全部等待均为**有界**（`poll_until` + 硬超时），失败时输出各进程 stdout 尾部 + 显式失败。
//! - genesis 使用 `NetworkId::Devnet`（bin 在 `--validator` 下拒绝 mainnet，属既有 fail-closed 契约）。
//! - **本文件不生成任何正式 Testnet Genesis**；`test_genesis(n=7)` 仅为 disposable test fixture
//!   （chain_id 1001 / devnet），**不得**被当作正式 Testnet Genesis（正式 Testnet 参数仍 TBD）。
//!
//! 与已冻结/未冻结协议的关系：本文件**不**修改 quorum / consensus / finality / validator-set /
//! QC verification / block validation 规则；仅作为**证据采集**的集成测试。

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::signature::SigningKey;
use nova_network::node_id::NodeId;
use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_node::runtime::derive_validator_id;

/// disposable test fixture 的 chain_id（**不是**正式 Testnet chain_id）。
const CHAIN_ID: u64 = 1001;
/// 每 validator 的 bonded stake（7 个等额 ⇒ `T = 7 × STAKE`）。
const STAKE: u128 = 200_000;
/// 有限步数上界（进程会自动退出）。
const RUN_STEPS: &str = "20000";
const IDLE_MS: &str = "1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

/// **S0 — step rate 实测窗口**（用于推导后续窗口；不得再用未经验证的固定窗口）。
const RATE_PROBE: Duration = Duration::from_secs(60);
/// **PHASE R — 节点可观测性窗口**：等待**全部 N 个节点**各自输出至少一行完整 `status`。
///
/// 该窗口只覆盖「节点是否可观测」这一**独立**命题（step-loop 吞吐 / 启动差异），
/// **不**与 consensus finality 判据混同（实测：7 节点中首个节点 300s 内未达 step 100）。
const WINDOW_REPORT: Duration = Duration::from_secs(420);
/// 7/7 路径（全在线 ⇒ 无 offline proposer）观察窗口。
const WINDOW_7: Duration = Duration::from_secs(240);
/// **逐节点前进性（活性）**独立窗口。
///
/// 注意（PHASE 4 第 2 次重跑实测）：**不得**用「跨节点 head 差值上界」作为判据 ——
/// status 每 100 step 才输出一行，而各节点 step 吞吐相差近 2×，采样时刻不同会让
/// 同一条单一链上的两个节点看起来相差 ~21 个高度。lag 仅作证据记录。
const WINDOW_CONVERGE: Duration = Duration::from_secs(600);
/// **PHASE 5 E1 — 受控实验窗口**：覆盖 round 0..3（1000+2000+4000+8000 = 15000 ticks）。
/// 可用环境变量 `A30_WINDOW_E1`（秒）覆盖；默认 3000。
const WINDOW_E1_DEFAULT_SECS: u64 = 3000;

/// 读取 E1 窗口（env 覆盖；**test-only 窗口配置**，不改任何实现）。
fn window_e1() -> Duration {
    Duration::from_secs(
        std::env::var("A30_WINDOW_E1")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(WINDOW_E1_DEFAULT_SECS),
    )
}
/// 6/7 · 5/7（含 offline proposer ⇒ 需 pacemaker timeout）观察窗口。
/// 覆盖 ≥2 个 timeout cycle（1000 + 2000 tick）。
const WINDOW_QUORUM: Duration = Duration::from_secs(900);
/// 4/7 no-finality 观察窗口（须足以覆盖若干轮 pacemaker 超时后仍无 quorum）。
const WINDOW_NOFINAL: Duration = Duration::from_secs(300);
/// restart / catch-up 各阶段窗口。
const WINDOW_RESTART: Duration = Duration::from_secs(600);

const VAL: [[u8; 32]; 7] = [
    [0x31; 32],
    [0x32; 32],
    [0x33; 32],
    [0x34; 32],
    [0x35; 32],
    [0x36; 32],
    [0x37; 32],
];
const NET: [[u8; 32]; 7] = [
    [0x41; 32],
    [0x42; 32],
    [0x43; 32],
    [0x44; 32],
    [0x45; 32],
    [0x46; 32],
    [0x47; 32],
];
const LABELS: [&str; 7] = ["V0", "V1", "V2", "V3", "V4", "V5", "V6"];
const N: usize = 7;

/// 期望 quorum（`ceil(T*2/3)`；与 `ValidatorSet::quorum` 同口径，仅用于证据打印/断言推导）。
fn expected_quorum() -> u128 {
    let total = STAKE * N as u128;
    (total * 2).div_ceil(3)
}

// ---------------------------------------------------------------------------
// 基础工具（自包含；与 A21 同语义但不共享文件）
// ---------------------------------------------------------------------------

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

/// 7 验证者 disposable devnet genesis（等额 stake ⇒ canonical ordering）。
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

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "yazimao_p1a30_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
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

fn drain(mut r: impl Read, sink: Arc<Mutex<String>>) {
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Ok(mut g) = sink.lock() {
                    g.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
    }
}

struct ChildGuard {
    label: &'static str,
    child: Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
    /// Task-2：子进程**回收记录**（被 `kill + wait` 回收的 PID）。
    /// 仅由孤儿回归测试注入；所有节点用例恒为 `None` ⇒ 零行为差异。
    reap_record: Option<Arc<Mutex<Vec<u32>>>>,
}

impl Drop for ChildGuard {
    /// **Task-2 RAII 保证**：无论测试是**正常结束**、**断言失败（panic / 栈展开）**还是**提前 return**，
    /// 本 guard 持有的子进程都会被 `kill + wait`。
    ///
    /// 安全边界：**只**针对本 guard 自己 `spawn` 的 PID（不扫描进程表 / **不**按名字批量杀
    /// `yazimao-node`）⇒ 不会误杀其他测试或用户启动的进程。Drop 不 panic（kill/wait 错误忽略）。
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

impl ChildGuard {
    fn spawn(label: &'static str, args: &[String]) -> Self {
        let exe = env!("CARGO_BIN_EXE_yazimao-node");
        let mut cmd = Command::new(exe);
        cmd.args(args);
        Self::spawn_command(label, cmd, None)
    }

    /// Task-2：**唯一**启动路径（节点用例与孤儿回归测试共用）⇒ 被回归测试覆盖的正是生产用法。
    fn spawn_command(
        label: &'static str,
        mut cmd: Command,
        reap_record: Option<Arc<Mutex<Vec<u32>>>>,
    ) -> Self {
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label} 失败: {e}"));
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        if let Some(o) = child.stdout.take() {
            let sink = Arc::clone(&out);
            thread::spawn(move || drain(o, sink));
        }
        if let Some(e) = child.stderr.take() {
            let sink = Arc::clone(&err);
            thread::spawn(move || drain(e, sink));
        }
        Self {
            label,
            child,
            out,
            err,
            reap_record,
        }
    }

    fn stdout(&self) -> String {
        self.out.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        self.err.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn terminate(&mut self) -> Option<ExitStatus> {
        if self.is_running() {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // Task-2：记录**本 guard 回收的** PID（`wait()` 已返回 ⇒ OS 已回收 ⇒ 无孤儿）。
            if let Some(rec) = self.reap_record.as_ref()
                && let Ok(mut g) = rec.lock()
            {
                g.push(self.child.id());
            }
        }
        self.child.try_wait().ok().flatten()
    }

    fn tail(&self) -> String {
        let out = self.stdout();
        let lines: Vec<&str> = out.lines().collect();
        lines[lines.len().saturating_sub(12)..].join("\n")
    }
}

/// Task-2 回归辅助：平台无关的"长跑"命令（**与节点无关**；只用来验证放手路径确实回收子进程）。
#[cfg(windows)]
fn sleeper_command() -> Command {
    let mut c = Command::new("cmd");
    c.args(["/C", "ping", "-n", "60", "127.0.0.1"]);
    c
}

#[cfg(unix)]
fn sleeper_command() -> Command {
    let mut c = Command::new("sleep");
    c.arg("60");
    c
}

/// **Task-2 回归（可复现、平台无关，不依赖"事后看有无孤儿"）**：
///
/// 证明链（不需外部工具）：
/// ① 用与节点用例**完全相同**的 `ChildGuard::spawn_command` 启动两个本测试自己构造的长跑子进程；
/// ② 分别在 **panic（栈展开）** 与 **作用域提前结束** 两条路径上让 guard 被 Drop；
/// ③ 断言 Drop 真的执行了 `kill + wait` —— 注入的回收记录中恰好出现**这两个 PID**
///（`wait()` 返回 ⟺ OS 已回收 ⇒ 不存在孤儿）；且两次 Drop 都只影响各自持有的 PID。
#[test]
fn t7_orphan_guard_reaps_own_children_on_panic_and_early_return() {
    let record: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    // ① panic（模拟断言失败）路径。
    let rec = Arc::clone(&record);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard =
            ChildGuard::spawn_command("orphan-regression-panic", sleeper_command(), Some(rec));
        panic!("simulated assertion failure (Task-2 regression)");
    }));
    assert!(outcome.is_err(), "本用例必须走 panic 路径");
    assert_eq!(
        record.lock().map(|g| g.len()).unwrap_or(0),
        1,
        "panic 路径必须恰好回收 1 个子进程（栈展开 ⇒ Drop）"
    );

    // ② 作用域提前结束（非 panic 的提前返回）路径。
    let rec = Arc::clone(&record);
    {
        let _guard =
            ChildGuard::spawn_command("orphan-regression-scope", sleeper_command(), Some(rec));
    }
    let pids = record.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(pids.len(), 2, "两条路径各回收 1 个 ⇒ 累计 2");
    assert!(pids.iter().all(|p| *p > 0), "PID 必须有效");
    assert_ne!(pids[0], pids[1], "两次回收的是各自持有的不同 PID");
}

/// 完整 status 观测（**严格区分**各指标）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stats {
    steps: u64,
    /// production head（finality-commit 代理）。
    head: u64,
    /// **durable QC-history tip**（服务能力指标；**≠ consensus finality**）。
    qc_tip: Option<u64>,
    /// consensus context 高度（round.height）。
    consensus: u64,
    /// BFT round（> 0 ⇒ pacemaker timeout 已发生）。
    round: u64,
    /// QC 服务能力（对其他节点 served QC 数）。
    qc_served: u64,
    established: usize,
}

/// 解析最后一行**完整** `status …`（要求尾部字段完整，避免撕裂行）。
fn last_status(out: &str) -> Option<Stats> {
    let line = out
        .lines()
        .rev()
        .find(|l| l.contains("status steps=") && l.contains("validator_enabled="))?;
    let field =
        |k: &str| -> Option<&str> { line.split_whitespace().find_map(|tok| tok.strip_prefix(k)) };
    let num = |k: &str| -> Option<u64> { field(k)?.parse().ok() };
    let qc_tip = match field("finalized_height=") {
        Some("none") => None,
        Some(v) => Some(v.parse().ok()?),
        None => return None,
    };
    Some(Stats {
        steps: num("steps=")?,
        head: num("head_height=")?,
        qc_tip,
        consensus: num("consensus_height=")?,
        round: num("round=")?,
        qc_served: num("qc_served=")?,
        established: num("established_peers=")? as usize,
    })
}

/// **PHASE 6H-A30 OD-X8 观测** — 解析节点 stdout 中**最后一行** `liveness …` 的
/// `egress_prop_refreshed=<n>`。
///
/// 数据源 = 现有 [`ChildGuard`] 已捕获的**真实子进程 stdout**（无新增进程 / 无新增网络 / 无新文件）。
/// 字段缺失 ⇒ `None`（**绝不**静默补 0）。
fn last_liveness_refreshed(out: &str) -> Option<u64> {
    let line = out
        .lines()
        .rev()
        .find(|l| l.contains("liveness steps=") && l.contains("egress_prop_refreshed="))?;
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix("egress_prop_refreshed="))?
        .parse()
        .ok()
}

/// OD-X8 — 逐节点计数（**纯函数**）：`(节点数, 解析成功数, 缺失数)`。
fn observability_counts(items: &[(Option<Stats>, Option<u64>)]) -> (usize, usize, usize) {
    let parsed = items
        .iter()
        .filter(|(s, r)| s.is_some() && r.is_some())
        .count();
    (items.len(), parsed, items.len() - parsed)
}

/// OD-X8 — 输出**真实运行时**逐节点诊断摘要（只读；不改判定 / 断言 / 计时 / 共识语义）。
///
/// 节点标签沿用 harness 既有 `V{i}` 约定；`head/qc_tip/consensus` 取自既有 [`last_status`]，
/// `egress_prop_refreshed` 取自 [`last_liveness_refreshed`]。缺失字段明确标为 `MISSING`。
fn observability_dump(kids: &[ChildGuard]) {
    let items: Vec<(Option<Stats>, Option<u64>)> = kids
        .iter()
        .map(|c| {
            let out = c.stdout();
            (last_status(&out), last_liveness_refreshed(&out))
        })
        .collect();
    for (i, (stats, refreshed)) in items.iter().enumerate() {
        let (head, qc_tip, consensus) = match stats {
            Some(s) => (
                s.head.to_string(),
                s.qc_tip.map_or_else(|| "none".to_string(), |v| v.to_string()),
                s.consensus.to_string(),
            ),
            None => (
                "MISSING".to_string(),
                "MISSING".to_string(),
                "MISSING".to_string(),
            ),
        };
        let verdict = if stats.is_some() && refreshed.is_some() {
            "PASS"
        } else {
            "FAIL"
        };
        eprintln!(
            "A30_OBSERVABILITY node=V{i} egress_prop_refreshed={} head={head} qc_tip={qc_tip} consensus={consensus} parsed={verdict}",
            refreshed.map_or_else(|| "MISSING".to_string(), |v| v.to_string())
        );
    }
    let (nodes, parsed, missing) = observability_counts(&items);
    eprintln!("A30_OBSERVABILITY_SUMMARY nodes={nodes} parsed={parsed} missing={missing}");
}

fn poll_until<F: FnMut() -> bool>(mut f: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// 构造单个节点的 CLI 参数。
///
/// `active` = 本轮**实际启动**的节点数（下标 `0..active`）；`--peer` 仅指向这些节点
/// （避免向未启动端口 dial 造成无关噪声）。genesis 仍始终为完整的 7-validator 集合。
#[allow(clippy::too_many_arguments)]
fn node_args(
    env: &TempDir,
    active: usize,
    i: usize,
    ids: &[NodeId],
    ports: &[u16],
    genesis_path: &Path,
    hash_hex: &str,
) -> Vec<String> {
    // 仅 fresh safety dir（journal 不存在）声明显式初始化。
    let safety_dir = env.path(&format!("a30-safety-{i}"));
    let mut args: Vec<String> = vec![
        "--genesis".into(),
        genesis_path.to_string_lossy().into(),
        "--genesis-hash".into(),
        hash_hex.into(),
        "--chain-id".into(),
        CHAIN_ID.to_string(),
        "--network-id".into(),
        "devnet".into(),
        "--storage-dir".into(),
        env.path(&format!("a30-chain-{i}")).to_string_lossy().into(),
        "--safety-dir".into(),
        safety_dir.to_string_lossy().into(),
        "--network-seed-file".into(),
        env.path(&format!("a30-net-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--validator".into(),
        "--validator-seed-file".into(),
        env.path(&format!("a30-val-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--listen".into(),
        format!("127.0.0.1:{}", ports[i]),
        "--run-steps".into(),
        RUN_STEPS.into(),
        "--idle-ms".into(),
        IDLE_MS.into(),
    ];
    if !safety_dir.join("safety.journal").exists() {
        args.push("--init-validator-safety".into());
    }
    for j in 0..active {
        if j != i {
            args.push("--peer".into());
            args.push(format!(
                "{}@127.0.0.1:{}",
                hex32(ids[j].as_bytes()),
                ports[j]
            ));
        }
    }
    args
}

/// fatal 标记（fail-closed/崩溃；**不**匹配正常 status 行）。
fn fatal_marker(out: &str, err: &str) -> Option<String> {
    for k in [
        "CorruptedState",
        "Startup(",
        "Runtime(",
        "panicked",
        "Error:",
    ] {
        if out.contains(k) || err.contains(k) {
            return Some(k.to_string());
        }
    }
    None
}

fn forensic(tag: &str, nodes: &[&ChildGuard]) -> String {
    let mut s = format!("=== {tag} FORENSICS ===\n");
    for n in nodes {
        s.push_str(&format!(
            "--- {}: stats={:?} running={}\nstdout_tail:\n{}\nstderr_tail:\n{}\n",
            n.label,
            last_status(&n.stdout()),
            n.stdout().lines().count(),
            n.tail(),
            n.stderr()
                .lines()
                .rev()
                .take(6)
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    s
}

/// 准备 fixture（genesis + seed 文件 + id/port 表）。
struct Fixture {
    env: TempDir,
    ids: Vec<NodeId>,
    ports: Vec<u16>,
    genesis_path: PathBuf,
    hash_hex: String,
    /// PHASE 5：保留 genesis 本体 + hash ⇒ 供 [`Tracer`] **离线**复算 proposer identity。
    genesis: GenesisV1,
    gh: [u8; 32],
}

fn setup(tag: &str) -> Fixture {
    let env = TempDir::new(tag);
    let genesis = test_genesis(&VAL);
    let gh = compute_genesis_hash(&genesis).expect("hash");
    let hash_hex = hex32(&gh);
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET.iter().enumerate() {
        env.write_seed(&format!("a30-net-{i}.seed"), *s);
    }
    for (i, s) in VAL.iter().enumerate() {
        env.write_seed(&format!("a30-val-{i}.seed"), *s);
    }
    let ids: Vec<NodeId> = NET.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..N).map(|_| free_port()).collect();
    Fixture {
        env,
        ids,
        ports,
        genesis_path,
        hash_hex,
        genesis,
        gh,
    }
}

fn spawn_first(fx: &Fixture, k: usize) -> Vec<ChildGuard> {
    (0..k)
        .map(|i| {
            ChildGuard::spawn(
                LABELS[i],
                &node_args(
                    &fx.env,
                    k,
                    i,
                    &fx.ids,
                    &fx.ports,
                    &fx.genesis_path,
                    &fx.hash_hex,
                ),
            )
        })
        .collect()
}

fn wait_ready(kids: &[ChildGuard], timeout: Duration) -> bool {
    poll_until(
        || {
            kids.iter()
                .all(|c| c.stdout().contains("entering bounded run loop"))
        },
        timeout,
    )
}

fn stats_of(kids: &[ChildGuard]) -> Vec<Option<Stats>> {
    kids.iter().map(|c| last_status(&c.stdout())).collect()
}

/// **finality 判据（PHASE 3 修正）**：`head` 与 `consensus_height` 均前进到 `h`。
///
/// validator 模式 head 只在 finality commit 后前进 ⇒ 这是 finality 的**代理**指标
/// （CLI status 行不暴露 `finalized_reference`；见文件头 FINALITY OBSERVATION GAP）。
fn advanced_to(s: &Stats, h: u64) -> bool {
    s.head >= h && s.consensus >= h
}

/// 跨节点 head 一致（允许 ≤2 块采样偏差）——"多个 validator 观察到同一 finalized reference"。
fn head_agreement(stats: &[Option<Stats>]) -> Option<(u64, u64)> {
    let hs: Vec<u64> = stats
        .iter()
        .filter_map(|s| s.as_ref().map(|x| x.head))
        .collect();
    if hs.is_empty() {
        return None;
    }
    Some((*hs.iter().min().unwrap(), *hs.iter().max().unwrap()))
}

/// 全部节点中**已报告**的最大 `steps`（避免把「未输出 status 的节点」误当作 0 速率源）。
fn max_steps(kids: &[ChildGuard]) -> u64 {
    kids.iter()
        .filter_map(|c| last_status(&c.stdout()))
        .map(|s| s.steps)
        .max()
        .unwrap_or(0)
}

/// 已输出**完整** status 的节点数（可观测节点数）。
fn reporting_count(kids: &[ChildGuard]) -> usize {
    kids.iter()
        .filter(|c| last_status(&c.stdout()).is_some())
        .count()
}

/// 单行 ASCII 快照：**逐节点** steps / head / qc_tip / consensus / round / qc_served / established。
///
/// 用于 poll 期间**记录 head progression 与 QC 证据**（证据记录；不参与判据）。
fn snapshot_line(stats: &[Option<Stats>]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(stats.len());
    for (i, s) in stats.iter().enumerate() {
        match s {
            Some(s) => parts.push(format!(
                "[V{i} steps={} head={} qc_tip={:?} consensus={} round={} qc_served={} est={}]",
                s.steps, s.head, s.qc_tip, s.consensus, s.round, s.qc_served, s.established
            )),
            None => parts.push(format!("[V{i} NO_STATUS]")),
        }
    }
    parts.join(" ")
}

/// 带周期性 ASCII 快照的 polling（**仅**用于证据记录；判据与 [`poll_until`] 完全一致）。
fn poll_traced<F, S>(label: &str, mut f: F, mut snap: S, window: Duration) -> bool
where
    F: FnMut() -> bool,
    S: FnMut() -> String,
{
    let t0 = Instant::now();
    let deadline = t0 + window;
    let mut next_snap = t0;
    loop {
        if f() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        if now >= next_snap {
            eprintln!("TRACE {label} t={:?} {}", t0.elapsed(), snap());
            next_snap = now + Duration::from_secs(30);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// PHASE 5 — E1…E5 观测器（**test-only**；不触碰任何 production 语义）
// ---------------------------------------------------------------------------

/// 每节点 round 索引上限（timeout 归属表大小；防越界）。
const TRACER_MAX_ROUND: usize = 16;

/// 配置的 round 窗口（**A3：毫秒**）：`min(10_000 × 2^round, 120_000)`。
///
/// **只读镜像**生产默认 `RoundTimeoutConfig`（`crates/consensus/src/round.rs`，A3 基线
/// 10s / ×2 / 120s）；不修改实现。
fn configured_window_ms(round: u64) -> u64 {
    let mut t: u64 = 10_000;
    for _ in 0..round.min(64) {
        t = t.saturating_mul(2).min(120_000);
        if t == 120_000 {
            break;
        }
    }
    t
}

/// PHASE 5 观测器：把 CLI status 采样**离线**派生成 E1–E5 所需指标。
///
/// 派生规则（全部只读，不与生产进程交互）：
/// - **timeout 计数**：同一 `consensus_height` 下观测到 `round: r → r'`（`r' > r`）⇒ 对 `r..r'`
///   各记一次。`RoundTimeout` 是 round 前进的**唯一**原因（新高度会把 round 重置为 0）。
///   受 status cadence（每 100 step 一行）限制 ⇒ 该计数是**下界**（可能连跳）。
/// - **round 墙钟窗口**：记录进入每个 `(height, round)` 的时刻，离开时得出观测墙钟时长；
///   与 [`configured_window_ms`] 对照 ⇒ E5 的 `implied_ms_rate`（1 计时单位的墙钟厚度）。
/// - **round 发散**：同一采样中，处于同一 `consensus_height` 的节点出现 >1 种 `round`。
/// - **proposer identity**：调用**既有只读纯函数** `select_proposer`（ADR-0050 冻结算法）离线复算
///   `(height, round) → proposer`；不修改该函数，也不要求生产进程输出该信息。
struct Tracer {
    t0: Instant,
    active: usize,
    labels: Vec<&'static str>,
    set: ValidatorSet,
    gh: [u8; 32],
    vids: Vec<ValidatorId>,
    prev: Vec<Option<Stats>>,
    prev_at: Option<Instant>,
    prev_max_steps: u64,
    timeouts_by_round: Vec<u64>,
    timeouts_by_node: Vec<Vec<u64>>,
    entering: Vec<Option<(u64, u64, Instant)>>,
    window_obs: Vec<Vec<f64>>,
    divergence_samples: u64,
    samples: u64,
    max_divergence: usize,
    last_min_head: u64,
    last_progress_at: Option<Instant>,
    max_stall_secs: f64,
    /// 高度推进（正常 finality）导致的 `(height, round)` 变更次数（非 timeout）。
    height_advance_events: u64,
}

impl Tracer {
    fn new(genesis: &GenesisV1, gh: [u8; 32], active: usize) -> Self {
        let set = ValidatorSet::from_genesis(genesis);
        let vids: Vec<ValidatorId> = VAL
            .iter()
            .map(|s| {
                ValidatorId::from_consensus_public_key(
                    &SigningKey::from_seed(*s).verifying_key().to_bytes(),
                )
            })
            .collect();
        Self {
            t0: Instant::now(),
            active,
            labels: LABELS.to_vec(),
            set,
            gh,
            vids,
            prev: vec![None; LABELS.len()],
            prev_at: None,
            prev_max_steps: 0,
            timeouts_by_round: vec![0; TRACER_MAX_ROUND],
            timeouts_by_node: vec![vec![0; TRACER_MAX_ROUND]; LABELS.len()],
            entering: vec![None; LABELS.len()],
            window_obs: vec![Vec::new(); TRACER_MAX_ROUND],
            divergence_samples: 0,
            samples: 0,
            max_divergence: 1,
            last_min_head: 0,
            last_progress_at: None,
            max_stall_secs: 0.0,
            height_advance_events: 0,
        }
    }

    /// `(height, round)` 的预期 proposer（离线复算）；`(OFF)` = 该节点本轮未启动。
    fn proposer_label(&self, height: u64, round: u64) -> String {
        match select_proposer(CHAIN_ID, height, round, &self.gh, &self.set) {
            Ok(vid) => match self.vids.iter().position(|v| *v == vid) {
                Some(i) if i < self.active => self.labels[i].to_string(),
                Some(i) => format!("{}(OFF)", self.labels[i]),
                None => "??".to_string(),
            },
            Err(_) => "err".to_string(),
        }
    }

    /// 记录一次采样，返回覆盖 E1 全部要求字段的证据行。
    fn observe(&mut self, stats: &[Option<Stats>], now: Instant) -> String {
        self.samples += 1;
        let dt = self
            .prev_at
            .map_or(0.0, |p| now.duration_since(p).as_secs_f64());
        self.prev_at = Some(now);
        let max_steps = stats.iter().flatten().map(|s| s.steps).max().unwrap_or(0);
        let rate = if dt > 0.0 {
            max_steps.saturating_sub(self.prev_max_steps) as f64 / dt
        } else {
            0.0
        };
        self.prev_max_steps = max_steps;

        for (i, s) in stats.iter().enumerate() {
            let Some(s) = s else { continue };
            // clippy::collapsible_if 最小修复：let-chain 保持**同一**短路顺序与语义
            //（`Option` 先取、后比较；`s` 为 `Copy` ⇒ `self.prev` 借用不延长）。
            if let Some(p) = self.prev[i]
                && s.consensus == p.consensus
                && s.round > p.round
            {
                let hi = (p.round + TRACER_MAX_ROUND as u64).min(s.round);
                for r in p.round..hi {
                    let ri = r as usize;
                    self.timeouts_by_round[ri] += 1;
                    self.timeouts_by_node[i][ri] += 1;
                }
            }
            let same = self
                .entering[i]
                .is_some_and(|(h, r, _)| h == s.consensus && r == s.round);
            if !same {
                if let Some((h0, r, at)) = self.entering[i] {
                    let secs = now.duration_since(at).as_secs_f64();
                    let ri = r as usize;
                    if ri < TRACER_MAX_ROUND && secs > 0.0 {
                        // E5 严谨性：**仅当高度未变**时，round 变化才意味着 timeout 到期；
                        // 高度推进（正常 finality）导致的 round 归零不属于 timeout 窗口，单独计数。
                        if h0 == s.consensus {
                            self.window_obs[ri].push(secs);
                        } else {
                            self.height_advance_events += 1;
                        }
                    }
                }
                self.entering[i] = Some((s.consensus, s.round, now));
            }
            self.prev[i] = Some(*s);
        }

        // round 发散（同一 consensus_height 下 >1 种 round）
        let mut distinct: Vec<(u64, u64)> = Vec::new();
        for s in stats.iter().flatten() {
            if !distinct.contains(&(s.consensus, s.round)) {
                distinct.push((s.consensus, s.round));
            }
        }
        let mut div = 1usize;
        for (h, _) in &distinct {
            div = div.max(distinct.iter().filter(|(hh, _)| hh == h).count());
        }
        self.max_divergence = self.max_divergence.max(div);
        if div > 1 {
            self.divergence_samples += 1;
        }

        // 停滞时长（min head 未增长的最大墙钟时长）
        let min_head = stats.iter().flatten().map(|s| s.head).min().unwrap_or(0);
        if self.last_progress_at.is_none() || min_head > self.last_min_head {
            self.last_min_head = min_head;
            self.last_progress_at = Some(now);
        } else if let Some(p) = self.last_progress_at {
            self.max_stall_secs = self.max_stall_secs.max(now.duration_since(p).as_secs_f64());
        }

        let mut parts: Vec<String> = Vec::with_capacity(stats.len());
        for (i, s) in stats.iter().enumerate() {
            match s {
                Some(s) => parts.push(format!(
                    "[{} steps={} head={} qc_tip={:?} consensus={} round={} qc_served={} est={} prop@({},{})={}]",
                    self.labels[i],
                    s.steps,
                    s.head,
                    s.qc_tip,
                    s.consensus,
                    s.round,
                    s.qc_served,
                    s.established,
                    s.consensus,
                    s.round,
                    self.proposer_label(s.consensus, s.round)
                )),
                None => parts.push(format!("[{} NO_STATUS]", self.labels[i])),
            }
        }
        format!(
            "t={:.1}s rate={rate:.2}step/s stall={:.0}s div={div}/{} to={:?} | {}",
            self.t0.elapsed().as_secs_f64(),
            self.max_stall_secs,
            self.samples,
            self.timeouts_by_round,
            parts.join(" ")
        )
    }

    /// E1–E5 汇总（timeout 归属、round 窗口实测与推算 tick 速率、发散统计、停滞时长）。
    fn summary(&self) -> String {
        let mut out = Vec::new();
        out.push(format!(
            "samples={} divergence_samples={} max_distinct_rounds_same_height={} max_stall_secs={:.1} height_advance_events={}",
            self.samples,
            self.divergence_samples,
            self.max_divergence,
            self.max_stall_secs,
            self.height_advance_events
        ));
        out.push(format!("timeouts_by_round={:?}", self.timeouts_by_round));
        out.push(format!("timeouts_by_node={:?}", self.timeouts_by_node));
        for (r, w) in self.window_obs.iter().enumerate() {
            if w.is_empty() {
                continue;
            }
            let n = w.len() as f64;
            let mean = w.iter().sum::<f64>() / n;
            let mn = w.iter().cloned().fold(f64::INFINITY, f64::min);
            let mx = w.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let window_ms = configured_window_ms(r as u64);
            let implied = if mean > 0.0 {
                window_ms as f64 / mean
            } else {
                0.0
            };
            out.push(format!(
                "round{r}_window_obs_secs n={} min={mn:.1} mean={mean:.1} max={mx:.1} configured_window_ms={window_ms} implied_ms_rate={implied:.2}/s",
                w.len()
            ));
        }
        out.join("\n")
    }
}

/// **S0 — step rate 实测**（PHASE 3 §3：先计算实际 tick/step rate）。
///
/// PHASE 4 修正：取**最大**已报告 steps（而非 `kids[0]`）—— 首个节点可能长期未输出 status，
/// 会把「未观测」伪造成 `0.00 steps/s`。
fn measure_step_rate(kids: &[ChildGuard]) -> (f64, u64) {
    let t0 = Instant::now();
    let s0 = max_steps(kids);
    let _ = poll_until(|| false, RATE_PROBE);
    let t1 = Instant::now();
    let s1 = max_steps(kids);
    let dt = t1.duration_since(t0).as_secs_f64().max(1e-6);
    let delta = s1.saturating_sub(s0);
    (delta as f64 / dt, delta)
}

// ---------------------------------------------------------------------------
// T7-0 — 诊断（PHASE 5 E4）：离线复算 (height, round) → proposer 表（**不启动任何进程**）
// ---------------------------------------------------------------------------
/// 用途：区分「**proposer availability**」与「**round 同步 / 投票传播**」对停滞的影响。
///
/// 该表由**既有只读纯函数** `select_proposer`（ADR-0050 冻结算法）在**本测试进程内**复算得到，
/// 不修改该函数、不与任何生产进程交互、不新增任何 production instrumentation。
#[test]
fn t7_0_expected_proposer_table() {
    let genesis = test_genesis(&VAL);
    let gh = compute_genesis_hash(&genesis).expect("hash");
    let set = ValidatorSet::from_genesis(&genesis);
    let vids: Vec<ValidatorId> = VAL
        .iter()
        .map(|s| {
            ValidatorId::from_consensus_public_key(
                &SigningKey::from_seed(*s).verifying_key().to_bytes(),
            )
        })
        .collect();
    let label = |vid: ValidatorId| -> String {
        vids.iter()
            .position(|v| *v == vid)
            .map_or_else(|| "??".to_string(), |i| LABELS[i].to_string())
    };

    eprintln!(
        "T7-0 proposer table (chain_id={CHAIN_ID}, genesis_hash={}, quorum={}, T={}):",
        hex32(&gh),
        set.quorum(),
        set.total_weight()
    );
    for h in 0..8u64 {
        let mut row: Vec<String> = Vec::new();
        for r in 0..4u64 {
            // clippy::redundant_closure 最小修复：`label` 捕获为不可变借用 ⇒ `&label` 同型同语义。
            let p = select_proposer(CHAIN_ID, h, r, &gh, &set)
                .map(&label)
                .unwrap_or_else(|_| "err".to_string());
            row.push(format!("r{r}={p}"));
        }
        eprintln!("  h={h}: {}", row.join(" "));
    }

    // 各在线集合下「proposer 恰好离线」的 (height, round) 集合（E4 判定依据）。
    for (active, name) in [(7usize, "7/7"), (6, "6/7"), (5, "5/7")] {
        let mut hits: Vec<String> = Vec::new();
        for h in 0..8u64 {
            for r in 0..4u64 {
                // clippy::collapsible_if 最小修复（两层合并）：let-chain 保持**同一**短路顺序
                //（先 `select_proposer`、再 `position`、再 `i >= active`）⇒ 输出集合完全一致。
                if let Ok(vid) = select_proposer(CHAIN_ID, h, r, &gh, &set)
                    && let Some(i) = vids.iter().position(|v| *v == vid)
                    && i >= active
                {
                    hits.push(format!("(h={h},r={r})->{}", LABELS[i]));
                }
            }
        }
        eprintln!(
            "T7-0 {name} offline-proposer rounds (h=0..7, r=0..3): {}",
            if hits.is_empty() {
                "none".to_string()
            } else {
                hits.join(", ")
            }
        );
    }
}

// ---------------------------------------------------------------------------
// T7-1 — 7/7 online ⇒ finality EXPECTED
// ---------------------------------------------------------------------------
#[test]
fn t7_1_seven_of_seven_finality() {
    eprintln!(
        "T7-1: quorum={} (T={}, 7/7 weight={})",
        expected_quorum(),
        STAKE * N as u128,
        STAKE * N as u128
    );
    let fx = setup("t71");
    let mut kids = spawn_first(&fx, N);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-1：7 进程未在 {STARTUP_TIMEOUT:?} 内进入 run loop\n{}",
        forensic("T7-1-startup", &kids.iter().collect::<Vec<_>>())
    );
    // S0：实测 step rate（须先于窗口判定）。
    let (rate, delta) = measure_step_rate(&kids);
    eprintln!("T7-1 S0 STEP RATE: {rate:.2} steps/s (delta_steps={delta} in {RATE_PROBE:?})");

    let initial = stats_of(&kids);
    eprintln!("T7-1 INITIAL: {}", snapshot_line(&initial));

    // PHASE R — **节点可观测性**（独立命题；**不**与 finality 混同）。
    //   7/7 验证要求 7 个进程均可观测；单个节点的 step-loop 吞吐问题会被单独归因，
    //   而不是伪装成 consensus 失败。
    let reported = poll_traced(
        "T7-1-R",
        || reporting_count(&kids) == N,
        || snapshot_line(&stats_of(&kids)),
        WINDOW_REPORT,
    );
    let report_stats = stats_of(&kids);
    assert!(
        reported,
        "T7-1 PHASE R：仅 {}/{} 节点在 {WINDOW_REPORT:?} 内输出完整 status（**节点可观测性 / step-loop 吞吐问题，非 consensus finality 失败**）\n{}\n{}",
        reporting_count(&kids),
        N,
        snapshot_line(&report_stats),
        forensic("T7-1-report", &kids.iter().collect::<Vec<_>>())
    );
    eprintln!(
        "T7-1 PHASE R (observability): reporting={}/{} {}",
        reporting_count(&kids),
        N,
        snapshot_line(&report_stats)
    );

    // PHASE A — **finality 推进**：全部节点 `head ≥ 5 ∧ consensus ≥ 5`（finality-commit 代理）。
    //   PHASE 4 修正：**不再**把 `established_peers >= N-1` 并入门限 —— 该指标属**网络连通性**，
    //   不是 finality observation（实测 7/7 时部分节点 established=5 而 finality 已到 height 26）。
    //   连通性仅作**证据记录**（见 TRACE 的 `est=`）。
    // PHASE 5：接入 [`Tracer`] ⇒ E4 需要 7/7 的 round-0/1/2 timeout 计数。
    let mut tr71 = Tracer::new(&fx.genesis, fx.gh, N);
    let ok = poll_traced(
        "T7-1-A",
        || {
            kids.iter()
                .all(|c| last_status(&c.stdout()).is_some_and(|s| advanced_to(&s, 5)))
        },
        || tr71.observe(&stats_of(&kids), Instant::now()),
        WINDOW_7,
    );
    let advance_stats = stats_of(&kids);
    assert!(
        ok,
        "T7-1 PHASE A：7/7 未在 {WINDOW_7:?} 内达成 head≥5 ∧ consensus≥5（initial={initial:?} final={advance_stats:?}）\n{}\n{}",
        snapshot_line(&advance_stats),
        forensic("T7-1-advance", &kids.iter().collect::<Vec<_>>())
    );
    eprintln!(
        "T7-1 PHASE A (finality advance): {}",
        snapshot_line(&advance_stats)
    );

    // PHASE B — **逐节点前进性 / 活性**（独立窗口）。
    //
    // PHASE 4 第 2 次重跑实测（682.16s，7/7，est=6，round 全 0）：
    //   agreement = Some((299, 320)) —— 跨节点 head 差在 600s 内稳定 ~21，**从未** ≤ 2。
    //   但 head/consensus 在**全部**节点上持续增长，且所有节点 `round = 0`（**无** pacemaker 超时）。
    //   ⇒ 该差值来自 **status 采样时刻不同**（status 每 100 step 才输出一行，而各节点 step
    //     吞吐相差近 2×：V1=800 vs V4/V5/V6=1500），**不是** 共识分歧 / 单链分叉。
    //   ⇒ 因此**不得**把「跨节点 head 差值上界」当作 finality 判据（会伪失败）。
    //   本阶段断言的是**每个节点都在持续前进**（真正的活性命题）；lag 仅作证据记录。
    let window_start = stats_of(&kids);
    let progressed = poll_traced(
        "T7-1-B",
        || {
            kids.iter()
                .enumerate()
                .all(|(i, c)| match (last_status(&c.stdout()), window_start[i]) {
                    (Some(now), Some(before)) => {
                        now.head > before.head && now.consensus > before.consensus
                    }
                    _ => false,
                })
        },
        || tr71.observe(&stats_of(&kids), Instant::now()),
        WINDOW_CONVERGE,
    );
    let final_stats = stats_of(&kids);
    let agree = head_agreement(&final_stats);
    eprintln!("T7-1 E4 (7/7) SUMMARY:\n{}", tr71.summary());
    assert!(
        progressed,
        "T7-1 PHASE B：并非全部 {} 个节点都在 {WINDOW_CONVERGE:?} 内输出**前进后**的状态（head 与 consensus 均严格增加）—— 这是节点停摆（活性失败），**不是** head 差值问题\n{}\n{}",
        N,
        snapshot_line(&final_stats),
        forensic("T7-1-converge", &kids.iter().collect::<Vec<_>>())
    );
    eprintln!(
        "T7-1 PHASE B (per-node progress): OK; lag_record={agree:?} start={}",
        snapshot_line(&window_start)
    );
    for c in &kids {
        assert!(
            fatal_marker(&c.stdout(), &c.stderr()).is_none(),
            "T7-1：{} 出现 fatal 标记 {:?}\n{}",
            c.label,
            fatal_marker(&c.stdout(), &c.stderr()),
            forensic("T7-1-fatal", &kids.iter().collect::<Vec<_>>())
        );
    }
    eprintln!(
        "T7-1 PASS: rate={rate:.2} steps/s (delta={delta}) convergence={agree:?} advance={} final={}",
        snapshot_line(&advance_stats),
        snapshot_line(&final_stats)
    );
    // PHASE 6H-A30 OD-X8 — **真实七节点**运行时可观测性摘要。
    // 只读：不改断言 / 不改计时 / 不改进程管理 / 不在生产侧新增日志或网络消息。
    // 复用既有 `observability_dump`（`last_status` + `last_liveness_refreshed`）；无新增解析器。
    observability_dump(&kids);

    let statuses: Vec<Option<ExitStatus>> = kids.iter_mut().map(ChildGuard::terminate).collect();
    eprintln!("T7-1 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// T7-2 — 6/7 online ⇒ finality EXPECTED
// ---------------------------------------------------------------------------
#[test]
fn t7_2_six_of_seven_finality() {
    eprintln!(
        "T7-2: quorum={} ; 6/7 weight={}",
        expected_quorum(),
        STAKE * 6
    );
    let fx = setup("t72");
    let mut kids = spawn_first(&fx, 6);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-2：6 进程未进入 run loop\n{}",
        forensic("T7-2-startup", &kids.iter().collect::<Vec<_>>())
    );

    // PHASE 5 E1/E2 — 6/7：接入 [`Tracer`]（与 T7-3 等价）+ E1 窗口（默认 3000s）。
    let mut tr2 = Tracer::new(&fx.genesis, fx.gh, 6);
    let ok = poll_traced(
        "T7-2-A",
        || {
            kids.iter().all(|c| {
                last_status(&c.stdout())
                    .is_some_and(|s| advanced_to(&s, 5) && s.established >= 5)
            })
        },
        || tr2.observe(&stats_of(&kids), Instant::now()),
        window_e1(),
    );
    let final_stats = stats_of(&kids);
    eprintln!(
        "T7-2 E1/E4 SUMMARY (recovered={ok}):\n{}",
        tr2.summary()
    );
    eprintln!("T7-2 final={final_stats:?}");
    assert!(
        ok,
        "T7-2：6/7 未在 {:?} 内达成 finality 代理判据（head≥5 ∧ consensus≥5）（final={final_stats:?}）\n{}",
        window_e1(),
        forensic("T7-2-advance", &kids.iter().collect::<Vec<_>>())
    );
    let rounds: Vec<u64> = final_stats
        .iter()
        .map(|s| s.map_or(0, |x| x.round))
        .collect();
    let qctips: Vec<Option<u64>> = final_stats
        .iter()
        .map(|s| s.and_then(|x| x.qc_tip))
        .collect();
    eprintln!("T7-2 PASS: rounds={rounds:?} qc_tips={qctips:?} final={final_stats:?}");
    let statuses: Vec<Option<ExitStatus>> = kids.iter_mut().map(ChildGuard::terminate).collect();
    eprintln!("T7-2 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// T7-3 — 5/7 online ⇒ finality EXPECTED（BFT 门限恰好可达）
// ---------------------------------------------------------------------------
#[test]
fn t7_3_five_of_seven_finality() {
    eprintln!(
        "T7-3: quorum={} ; 5/7 weight={} (>= quorum: {})",
        expected_quorum(),
        STAKE * 5,
        STAKE * 5 >= expected_quorum()
    );
    let fx = setup("t73");
    let mut kids = spawn_first(&fx, 5);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-3：5 进程未进入 run loop\n{}",
        forensic("T7-3-startup", &kids.iter().collect::<Vec<_>>())
    );

    // PHASE 5 E1 — 5/7：接入 [`Tracer`] + E1 窗口（默认 3000s，覆盖 round 0..3 = 15000 ticks）。
    // 判据**不变**（仅 `poll_until` → 等价判据的 `poll_traced` + 证据增强）。
    let mut tr3 = Tracer::new(&fx.genesis, fx.gh, 5);
    let ok = poll_traced(
        "T7-3-A",
        || {
            kids.iter().all(|c| {
                last_status(&c.stdout())
                    .is_some_and(|s| advanced_to(&s, 5) && s.established >= 4)
            })
        },
        || tr3.observe(&stats_of(&kids), Instant::now()),
        window_e1(),
    );
    let final_stats = stats_of(&kids);
    eprintln!("T7-3 E1/E4 SUMMARY (recovered={ok}):\n{}", tr3.summary());
    eprintln!("T7-3 final={final_stats:?}");
    assert!(
        ok,
        "T7-3：5/7 未在 {:?} 内达成 finality 代理判据（head≥5 ∧ consensus≥5）（final={final_stats:?}）\n{}",
        window_e1(),
        forensic("T7-3-advance", &kids.iter().collect::<Vec<_>>())
    );
    let rounds: Vec<u64> = final_stats
        .iter()
        .map(|s| s.map_or(0, |x| x.round))
        .collect();
    let qctips: Vec<Option<u64>> = final_stats
        .iter()
        .map(|s| s.and_then(|x| x.qc_tip))
        .collect();
    eprintln!("T7-3 PASS: rounds={rounds:?} qc_tips={qctips:?} final={final_stats:?}");
    // PHASE 6H-A30 OD-X8 — **真实**运行时可观测性摘要（只读；不改断言 / 计时 / 进程管理）。
    observability_dump(&kids);
    let statuses: Vec<Option<ExitStatus>> = kids.iter_mut().map(ChildGuard::terminate).collect();
    eprintln!("T7-3 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// T7-4 — 4/7 online ⇒ finality NOT EXPECTED（无 quorum）
// ---------------------------------------------------------------------------
#[test]
fn t7_4_four_of_seven_no_finality() {
    eprintln!(
        "T7-4: quorum={} ; 4/7 weight={} (< quorum: {})",
        expected_quorum(),
        STAKE * 4,
        STAKE * 4 < expected_quorum()
    );
    let fx = setup("t74");
    let mut kids = spawn_first(&fx, 4);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-4：4 进程未进入 run loop\n{}",
        forensic("T7-4-startup", &kids.iter().collect::<Vec<_>>())
    );
    // 确保 4 个节点彼此已完成认证握手（否则"无 finality"可能只因未连通）。
    let connected = poll_until(
        || {
            kids.iter()
                .all(|c| last_status(&c.stdout()).is_some_and(|s| s.established >= 3))
        },
        STARTUP_TIMEOUT,
    );
    assert!(
        connected,
        "T7-4：4/7 未能全部建立 3 个 established peer（无法据此判定 quorum 边界）\n{}",
        forensic("T7-4-connect", &kids.iter().collect::<Vec<_>>())
    );

    // 观察窗口（覆盖若干轮 pacemaker 超时）；判据不变，仅额外采集逐节点时间序列。
    let _ = poll_traced(
        "T7-4-A",
        || false,
        || snapshot_line(&stats_of(&kids)),
        WINDOW_NOFINAL,
    );
    let final_stats = stats_of(&kids);
    for (i, c) in kids.iter().enumerate() {
        let s = final_stats[i].unwrap_or(Stats {
            steps: 0,
            head: 0,
            qc_tip: None,
            consensus: 0,
            round: 0,
            qc_served: 0,
            established: 0,
        });
        // no-finality 判据（三条件同时成立；不得仅凭 head=0）：
        //   ① 无 head 前进（finality-commit 代理从未触发）
        //   ② 无 consensus finality 证据（durable QC tip 从未 ≥1）
        //   ③ 无 QC 服务能力（qc_served == 0）
        assert!(
            s.head == 0 && s.qc_tip.is_none() && s.qc_served == 0,
            "T7-4：4/7 竟然产生了 finality 迹象（{} head={} qc_tip={:?} qc_served={} consensus={} round={}）——违反 2/3 quorum 门限\n{}",
            c.label,
            s.head,
            s.qc_tip,
            s.qc_served,
            s.consensus,
            s.round,
            forensic("T7-4-violation", &kids.iter().collect::<Vec<_>>())
        );
        assert!(
            fatal_marker(&c.stdout(), &c.stderr()).is_none(),
            "T7-4：{} 出现 fatal 标记 {:?}\n{}",
            c.label,
            fatal_marker(&c.stdout(), &c.stderr()),
            forensic("T7-4-fatal", &kids.iter().collect::<Vec<_>>())
        );
    }
    eprintln!("T7-4 PASS (no finality as expected): final={final_stats:?}");
    let statuses: Vec<Option<ExitStatus>> = kids.iter_mut().map(ChildGuard::terminate).collect();
    eprintln!("T7-4 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// T7-5 — 7/7 ⇒ 停 V6 ⇒ 6/7 继续 ⇒ 重启 V6（同身份/同目录）⇒ 重连 + catch-up
// ---------------------------------------------------------------------------
#[test]
fn t7_5_seven_validator_restart_catchup() {
    let fx = setup("t75");
    let mut kids = spawn_first(&fx, N);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-5：7 进程未进入 run loop\n{}",
        forensic("T7-5-startup", &kids.iter().collect::<Vec<_>>())
    );
    // 判据不变（仅 `poll_until` → 等价判据的 `poll_traced`，额外采集逐节点快照）。
    let stable = poll_traced(
        "T7-5-A",
        || {
            kids.iter().all(|c| {
                last_status(&c.stdout())
                    .is_some_and(|s| advanced_to(&s, 5) && s.established >= N - 1)
            })
        },
        || snapshot_line(&stats_of(&kids)),
        WINDOW_7,
    );
    assert!(
        stable,
        "T7-5：未达稳定基线\n{}",
        forensic("T7-5-baseline", &kids.iter().collect::<Vec<_>>())
    );

    let before = last_status(&kids[6].stdout()).expect("V6 基线");
    let _ = kids[6].terminate();

    // CONSENSUS CONTINUED：6/7（1_200_000 ≥ quorum）继续推进。
    let continued = poll_until(
        || {
            kids[..6]
                .iter()
                .all(|c| last_status(&c.stdout()).is_some_and(|s| s.head >= before.head + 2))
        },
        WINDOW_QUORUM,
    );
    let after_stop = stats_of(&kids[..6]);
    assert!(
        continued,
        "T7-5：CONSENSUS DID NOT CONTINUE（停 V6 后 6/7 未推进 head ≥ {}）（after={after_stop:?}）\n{}",
        before.head + 2,
        forensic("T7-5-continue", &kids.iter().collect::<Vec<_>>())
    );
    eprintln!("T7-5 CONSENSUS CONTINUED: after_stop={after_stop:?}");

    // 重启 V6（同身份 / 同 storage / 同 safety ⇒ 复用同一 args）
    let v6_args = node_args(
        &fx.env,
        N,
        6,
        &fx.ids,
        &fx.ports,
        &fx.genesis_path,
        &fx.hash_hex,
    );
    assert!(
        v6_args.iter().all(|a| a != "--init-validator-safety"),
        "T7-5：重启 V6 **不得**携带 --init-validator-safety（既有 journal ⇒ 恢复路径）"
    );
    let mut v6 = ChildGuard::spawn("V6r", &v6_args);

    let reconnected = poll_until(
        || last_status(&v6.stdout()).is_some_and(|s| s.established >= 1),
        WINDOW_RESTART,
    );
    let v6_status = last_status(&v6.stdout());
    assert!(
        reconnected,
        "T7-5：RESTART FAILED（重连失败；v6={v6_status:?}）\n{}",
        forensic(
            "T7-5-reconnect",
            &[&kids[0], &kids[1], &kids[2], &kids[3], &kids[4], &kids[5], &v6]
        )
    );
    let restart_fatal = fatal_marker(&v6.stdout(), &v6.stderr());
    assert!(
        restart_fatal.is_none(),
        "T7-5：RESTART FAILED（V6 出现 {:?}；含 SafetyJournalMissing/AlreadyExists 类 fail-closed）\n{}",
        restart_fatal,
        forensic(
            "T7-5-restart-fatal",
            &[&kids[0], &kids[1], &kids[2], &kids[3], &kids[4], &kids[5], &v6]
        )
    );
    eprintln!("T7-5 RESTART SUCCESS: v6={v6_status:?}");

    let caught = poll_until(
        || {
            let others_min = kids[..6]
                .iter()
                .filter_map(|c| last_status(&c.stdout()))
                .map(|s| s.head)
                .min()
                .unwrap_or(u64::MAX);
            last_status(&v6.stdout()).is_some_and(|s| s.head >= 5 && s.head + 1 >= others_min)
        },
        WINDOW_RESTART,
    );
    let final_stats: Vec<Option<Stats>> = kids[..6]
        .iter()
        .map(|c| last_status(&c.stdout()))
        .chain(std::iter::once(last_status(&v6.stdout())))
        .collect();
    assert!(
        caught,
        "T7-5：CATCH-UP FAILED（V6 未在 {WINDOW_RESTART:?} 内追平；before={before:?} final={final_stats:?}）\n{}",
        forensic(
            "T7-5-catchup",
            &[&kids[0], &kids[1], &kids[2], &kids[3], &kids[4], &kids[5], &v6]
        )
    );
    for c in kids[..6].iter().chain(std::iter::once(&v6)) {
        assert!(
            fatal_marker(&c.stdout(), &c.stderr()).is_none(),
            "T7-5：{} 出现 fatal 标记 {:?}",
            c.label,
            fatal_marker(&c.stdout(), &c.stderr())
        );
    }
    eprintln!("T7-5 CATCH-UP SUCCESS: before={before:?} final={final_stats:?}");

    let mut statuses: Vec<Option<ExitStatus>> =
        kids.iter_mut().map(ChildGuard::terminate).collect();
    statuses.push(v6.terminate());
    eprintln!("T7-5 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// PHASE 6H-A30 OD-X8 — 观测解析器单元测试
//
// 边界：这里的合成行**只**用于解析器单元测试；正式摘要必须来自真实子进程输出。
// ---------------------------------------------------------------------------
const ODX8_STATUS_SAMPLE: &str = "yazimao-node: status steps=300 head_height=7 \
     finalized_height=7 consensus_height=7 round=0 configured_peers=6 established_peers=4 \
     sync_pending=0 block_inbound_skipped=0 pending_external_qc=0 qc_served=0 \
     validator_enabled=true";

#[test]
fn odx8_parser_accepts_zero_and_nonzero_refresh_counts() {
    // ① 合法行（计数 = 0）与 ② 合法行（计数非零）均须正确解析。
    assert_eq!(
        last_liveness_refreshed("v: liveness steps=10 prop_calls=10 egress_prop_refreshed=0"),
        Some(0)
    );
    assert_eq!(
        last_liveness_refreshed("v: liveness steps=10 prop_calls=10 egress_prop_refreshed=3"),
        Some(3)
    );
}

#[test]
fn odx8_parser_never_defaults_missing_field_to_zero() {
    // ③ 缺 `egress_prop_refreshed` ⇒ None（不静默补 0）；⑤ 空/垃圾输出 ⇒ None（不产生虚假成功）。
    assert_eq!(
        last_liveness_refreshed("v: liveness steps=10 egress_prop_enqueued=7"),
        None
    );
    assert_eq!(last_liveness_refreshed(""), None);
    assert_eq!(last_liveness_refreshed("not a status line"), None);
}

#[test]
fn odx8_parser_uses_last_liveness_line() {
    let out = "v: liveness steps=1 egress_prop_refreshed=0\nv: liveness steps=2 egress_prop_refreshed=2\n";
    assert_eq!(last_liveness_refreshed(out), Some(2));
}

#[test]
fn odx8_status_parser_still_parses_other_fields_and_fails_loudly_when_incomplete() {
    // ⑦ 原有 status 行其余字段仍可正确解析。
    let s = last_status(ODX8_STATUS_SAMPLE).expect("完整 status 行应可解析");
    assert_eq!(s.steps, 300);
    assert_eq!(s.head, 7);
    assert_eq!(s.qc_tip, Some(7));
    assert_eq!(s.consensus, 7);
    assert_eq!(s.round, 0);
    assert_eq!(s.established, 4);
    // ④ 缺关键字段（`finalized_height=` / qc_tip）⇒ None：明确失败，不伪造成成功。
    let incomplete = "yazimao-node: status steps=300 head_height=7 consensus_height=7 \
         round=0 established_peers=4 validator_enabled=true";
    assert!(last_status(incomplete).is_none());
    assert!(last_status("").is_none());
    assert!(last_status("garbage").is_none());
}

#[test]
fn odx8_summary_counts_nodes_parsed_and_missing() {
    // ⑥ 七节点摘要的节点数 / 解析成功数 / 缺失数必须正确。
    let s = last_status(ODX8_STATUS_SAMPLE).expect("样本行应可解析");
    let items: Vec<(Option<Stats>, Option<u64>)> = vec![
        (Some(s), Some(0)),
        (Some(s), Some(1)),
        (Some(s), Some(2)),
        (Some(s), Some(3)),
        (Some(s), Some(0)),
        (None, None),
        (Some(s), None),
    ];
    assert_eq!(observability_counts(&items), (7, 5, 2));
    // 空集 ⇒ (0,0,0)（不产生虚假成功摘要）。
    assert_eq!(observability_counts(&[]), (0, 0, 0));
}
