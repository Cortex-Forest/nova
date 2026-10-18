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
//! # PACEMAKER WINDOW（PHASE 3 修正；PHASE 6H-A3 后**单位已变更**）
//!
//! **A3 之后的当前生产默认** = `RoundTimeoutConfig::default()` = `(initial 10_000 ms,
//! max 120_000 ms, ×2)`（毫秒；`crates/consensus/src/round.rs` L245–L252；唯一构造点
//! `runtime.rs` L3664）。round 0 窗口 **10 s**、cap **120 s**。
//!
//! **历史（A3 之前）**：单位为「逻辑 step tick」，默认 `(1000 / 60_000 / ×2)`；本文件早期
//! 版本的注释与窗口推导均基于该 tick 语义。两条历史记录**不得**再用于当前墙钟推算：
//! 「round 0..3 = 1000+2000+4000+8000 = 15000 ticks」与「cap 60_000 ticks ≈ 2.5–3.3 h」在
//! 当前实现下分别对应 **10+20+40+80 = 150 s** 与 **cap = 120 s**。
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
/// **PHASE 5 E1 — 受控实验窗口**（秒）。
///
/// A3 之后 round 窗口为**墙钟毫秒**：round 0..3 = `10_000+20_000+40_000+80_000` =
/// **150_000 ms = 150 s**，cap = **120 s**（`configured_window_ms`）。默认 3000 s 覆盖 ≥2 个
/// 完整 timeout cycle 且留足收敛余量；可用环境变量 `A30_WINDOW_E1`（秒）覆盖。
///
/// **实验纪律**：本参数**必须**在每个产物中被显式记录（含取默认值的情形），否则该次运行
/// 的窗口预算不可知（历史上多次运行缺失该记录）。
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
    ///
    /// 字段来源（`bin/yazimao-node.rs` L1111）：`finalized_height = runtime.qc_history_tip_height()`。
    /// ⇒ CLI 的 `finalized_height` **不是** consensus finality（见文件头「METRIC DISCIPLINE」）。
    qc_tip: Option<u64>,
    /// **权威**：`state().finality.finalized_reference.is_some()`（consensus finality 是否成立）。
    ///
    /// 数据源 = CLI status 行的 `finalized_ref_present=`；该字段由 `bin` 直接读
    /// `driver().consensus().state().finality.finalized_reference`（`FinalityState`，
    /// 仅在 `verify_qc` 通过的 PrecommitQC 触发 `Advance` 时置位）。
    ///
    /// **与 `qc_tip` 严格区分**：`qc_tip` 是 durable QC-history tip（只在该 finality 引用的
    /// QC 被持久化时才前进 ⇒ 可能滞后 / 缺失）；`finalized_ref_present` 是 finality 状态本身。
    finalized_ref_present: bool,
    /// **权威** finalization 引用本身（`finalized_ref=<64hex|none>`，P3 授权诊断）。
    ///
    /// `Some(h)` = finality 已在区块 `h` 成立（值 = PrecommitQC 的 `qc.target`，32B 区块哈希）；
    /// `None` = **显式** `none`（finality 尚未成立）。
    ///
    /// fail-closed 纪律：字段**缺失** / 重复 / 非 64 位 hex / 与 `finalized_ref_present`
    /// 自相矛盾 ⇒ **整行** `None`。因此本结构存在即证明该值是**观测值**，而非「未观测」被当作 `none`。
    finalized_ref: Option<[u8; 32]>,
    /// consensus context 高度（round.height）。
    consensus: u64,
    /// BFT round（> 0 ⇒ pacemaker timeout 已发生）。
    round: u64,
    /// QC 服务能力（对其他节点 served QC 数）。
    qc_served: u64,
    established: usize,
    /// **权威**：节点自报的本地 round-timeout **事件**计数（累计；含 Applied/Ignored/Rejected 三类）。
    ///
    /// 语义区分（不得混淆）：`round_timeouts` 计**尝试**；仅 `round_adv_local` 计**真实推进**。
    round_timeouts: u64,
    /// 当前已 ARM 计时器的窗口（**毫秒**）；`None` = 未 arm / 已被 finality disarm。
    timer_window: Option<u64>,
}

/// PHASE 6H-ONEPASS — **liveness 行**（`OUTPUT_MODE=B`）的节点自报权威计数。
///
/// 数据源 = 真实子进程 stdout 中的 `yazimao-node: liveness …`（字段顺序固定；见
/// `bin/yazimao-node.rs` L1216 起的 [`liveness_line`]）。
///
/// 本结构存在的**唯一原因**：把原先只能由 harness **推断**的量（round 推进来源、
/// timeout 是否真的发生、proposer 跳过原因）替换为**节点自报**的量 ⇒ 使
/// 「round 推进是否由本地 timeout 驱动」「当选 proposer 是否在线」可由证据直接判定，
/// 而不再依赖采样推断。**只读观测**：不改变任何共识语义，也不改变任何判据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Liveness {
    steps: u64,
    prop_calls: u64,
    prop_build_ok: u64,
    prop_skip_not_elected: u64,
    prop_skip_step_guard: u64,
    prop_skip_fail: u64,
    inbound_prop_ok: u64,
    egress_prop_enqueued: u64,
    /// 本地 pacemaker timeout **真实推进** round 的次数（`Applied`）。
    round_adv_local: u64,
    /// 高度前进次数（**非** timeout；round 重置为 0 的那类推进）。
    round_adv_height: u64,
    /// **RC（round change）驱动**的 round 推进次数。
    round_adv_rc: u64,
    elected_is_self: bool,
    prop_absent_steps: u64,
    proposal_admitted: u64,
    proposal_pending: u64,
    proposal_rejected: u64,
    proposal_expired: u64,
    recovery_runs: u64,
    net_frames_received: u64,
    net_sent: u64,
}

/// 解析节点 stdout 中**最后一行** `liveness …`（要求尾部关键字段完整，避免撕裂行）。
///
/// 缺失**任何**必需字段 ⇒ `None`（**绝不**静默补 0；与 [`last_liveness_refreshed`] 同纪律）。
fn last_liveness(out: &str) -> Option<Liveness> {
    let line = out
        .lines()
        .rev()
        .find(|l| l.contains("liveness steps=") && l.contains("round_adv_rc="))?;
    let field = |k: &str| -> Option<&str> {
        line.split_whitespace()
            .find_map(|tok| tok.strip_prefix(k))
    };
    let num = |k: &str| -> Option<u64> { field(k)?.parse().ok() };
    let boolean = |k: &str| -> Option<bool> { field(k)?.parse().ok() };
    Some(Liveness {
        steps: num("steps=")?,
        prop_calls: num("prop_calls=")?,
        prop_build_ok: num("prop_build_ok=")?,
        prop_skip_not_elected: num("prop_skip_not_elected=")?,
        prop_skip_step_guard: num("prop_skip_step_guard=")?,
        prop_skip_fail: num("prop_skip_fail=")?,
        inbound_prop_ok: num("inbound_prop_ok=")?,
        egress_prop_enqueued: num("egress_prop_enqueued=")?,
        round_adv_local: num("round_adv_local=")?,
        round_adv_height: num("round_adv_height=")?,
        round_adv_rc: num("round_adv_rc=")?,
        elected_is_self: boolean("elected_is_self=")?,
        prop_absent_steps: num("prop_absent_steps=")?,
        proposal_admitted: num("proposal_admitted=")?,
        proposal_pending: num("proposal_pending=")?,
        proposal_rejected: num("proposal_rejected=")?,
        proposal_expired: num("proposal_expired=")?,
        recovery_runs: num("recovery_runs=")?,
        net_frames_received: num("net_frames_received=")?,
        net_sent: num("net_sent=")?,
    })
}

/// **纯函数**：权威计数的逐节点聚合（便于穷举单测；无进程 / 无 I/O）。
///
/// 返回 `(nodes, liveness_parsed, round_timeouts, round_adv_local, round_adv_height,
/// round_adv_rc, prop_build_ok, prop_absent_steps)`。
///
/// 纪律：`round_timeouts` 仅在对应节点的 `liveness`/`status` **均解析成功**时计入 ——
/// 缺失一律 **不**补 0（避免把「未观测」伪装成「0 次超时」）。
#[allow(clippy::type_complexity)]
fn auth_totals(
    stats: &[Option<Stats>],
    live: &[Option<Liveness>],
) -> (usize, usize, u64, u64, u64, u64, u64, u64) {
    let mut parsed = 0usize;
    let (mut to, mut al, mut ah, mut ar, mut bok, mut abs) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for (i, l) in live.iter().enumerate() {
        let (Some(l), Some(st)) = (l, stats.get(i).copied().flatten()) else {
            continue;
        };
        parsed += 1;
        to += st.round_timeouts;
        al += l.round_adv_local;
        ah += l.round_adv_height;
        ar += l.round_adv_rc;
        bok += l.prop_build_ok;
        abs += l.prop_absent_steps;
    }
    (live.len(), parsed, to, al, ah, ar, bok, abs)
}

/// PHASE 6H-ONEPASS — **权威**逐节点计数摘要 + 推进来源守恒关系。
///
/// 输出每节点的自报计数（缺失 ⇒ `MISSING`），并给出**推进来源守恒**关系：
/// ```text
/// Σ round_adv_local + Σ round_adv_rc + Σ round_adv_height  ≟  观测到的 round/height 迁移总数
/// ```
/// 该关系是区分 **H4（RC 传播/应用）** 与 **H1（timeout 预算）** 的关键：若推进几乎全部
/// 来自 `round_adv_rc`，则停滞与本地 timeout 预算无关；若 `round_adv_local` 远大于实际
/// round 变化，则存在「timeout 触发但不推进」的路径（`Ignored`/`Rejected`）。
fn authoritative_summary(kids: &[ChildGuard]) -> String {
    let outs: Vec<String> = kids.iter().map(|c| c.stdout()).collect();
    let stats: Vec<Option<Stats>> = outs.iter().map(|o| last_status(o)).collect();
    let live: Vec<Option<Liveness>> = outs.iter().map(|o| last_liveness(o)).collect();
    let mut out = Vec::new();
    for (i, c) in kids.iter().enumerate() {
        let st = stats.get(i).copied().flatten();
        let lv = live.get(i).copied().flatten();
        let g = |f: fn(&Liveness) -> String| -> String {
            lv.map_or("MISSING".to_string(), |l| f(&l))
        };
        out.push(format!(
            "{} status[round_timeouts={} timer_window={:?} finality={} ref={}] liveness[round_adv_local={} \
             round_adv_height={} round_adv_rc={} elected_is_self={} prop_build_ok={} \
             prop_skip_not_elected={} prop_skip_step_guard={} prop_skip_fail={} \
             prop_absent_steps={} proposal(admitted={} pending={} rejected={} expired={}) \
             recovery_runs={} net(sent={} recv={})]",
            c.label,
            st.map_or("MISSING".to_string(), |s| s.round_timeouts.to_string()),
            st.and_then(|s| s.timer_window),
            st.map_or("MISSING".to_string(), |s| s.finalized_ref_present.to_string()),
            st.map_or("MISSING".to_string(), |s| {
                s.finalized_ref
                    .map_or_else(|| "none".to_string(), |h| hex32_hex(&h))
            }),
            g(|l| l.round_adv_local.to_string()),
            g(|l| l.round_adv_height.to_string()),
            g(|l| l.round_adv_rc.to_string()),
            g(|l| l.elected_is_self.to_string()),
            g(|l| l.prop_build_ok.to_string()),
            g(|l| l.prop_skip_not_elected.to_string()),
            g(|l| l.prop_skip_step_guard.to_string()),
            g(|l| l.prop_skip_fail.to_string()),
            g(|l| l.prop_absent_steps.to_string()),
            g(|l| l.proposal_admitted.to_string()),
            g(|l| l.proposal_pending.to_string()),
            g(|l| l.proposal_rejected.to_string()),
            g(|l| l.proposal_expired.to_string()),
            g(|l| l.recovery_runs.to_string()),
            g(|l| l.net_sent.to_string()),
            g(|l| l.net_frames_received.to_string()),
        ));
    }
    let (nodes, parsed, to, al, ah, ar, bok, abs) = auth_totals(&stats, &live);
    out.push(format!(
        "AUTH_TOTALS nodes={nodes} liveness_parsed={parsed} round_timeouts={to} \
         round_adv_local={al} round_adv_height={ah} round_adv_rc={ar} \
         prop_build_ok={bok} prop_absent_steps={abs}"
    ));
    out.join("\n")
}

/// 32B → 小写 hex（与 `bin` 的 `hex32` **同编码**；仅用于证据打印，**不**参与判据）。
fn hex32_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// **纯函数** — 解析 `finalized_ref=` 的单个取值。
///
/// - `Some(None)` = 显式 `none`（finality 尚未成立）
/// - `Some(Some(h))` = 64 位 hex，逐字节解出
/// - `None` = 非法（长度 ≠ 64 / 非十六进制 / 空串）—— **绝不**猜测
///
/// 大小写均接受（消费端宽容），但**生产端**恒输出小写（见 `bin` 的 `opt_hash32`）。
/// 全零哈希是合法值，**不**得被误判为缺失。
fn parse_finalized_ref_token(v: &str) -> Option<Option<[u8; 32]>> {
    if v == "none" {
        return Some(None);
    }
    let raw = v.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (raw[2 * i] as char).to_digit(16)?;
        let lo = (raw[2 * i + 1] as char).to_digit(16)?;
        *slot = ((hi as u8) << 4) | (lo as u8);
    }
    Some(Some(out))
}

/// 从整行中**严格**提取 `finalized_ref=`：必须**恰好出现一次**。
///
/// 重复 / 冲突（≥ 2 次）⇒ `None`（fail-closed；**不**取首个、**不**取末个）。
/// 注：`strip_prefix` 是**精确前缀**匹配 ⇒ `finalized_ref_present=true` 不会被误命中。
fn extract_finalized_ref(line: &str) -> Option<Option<[u8; 32]>> {
    let mut vals = line
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix("finalized_ref="));
    let first = vals.next()?;
    if vals.next().is_some() {
        return None;
    }
    parse_finalized_ref_token(first)
}

/// **纯函数** — 按 finality 高度（`head`，finality-commit 代理）分组，**仅组内**比较
/// finalization 引用。返回 `(group_count, mismatched_heads)`。
///
/// **为何必须分组**（P4 实测 `P4-BASE-01`）：`status` 每 100 step 才输出一行，各节点
/// step 吞吐不同 ⇒ 同一时刻各节点的 `last_status` 可能停在**不同的 finality 高度**。
/// 此时「不同节点报告不同引用」是**正常**的（各自 finalize 了各自高度的区块），
/// **不是** 对象分歧。P3 的跳 head 直接比较会产生**伪失败**（已在 P4 复现）。
///
/// **仍然非空洞**：若**同一 head** 下的两个节点报告不同引用 ⇒ 真正的 finality 对象分歧。
///
/// 边界：`head` 或 `ref` 缺失的条目**不参与**比较（由调用方先行做完整性断言）。
fn finality_identity_check(heads: &[Option<u64>], refs: &[Option<[u8; 32]>]) -> (usize, Vec<u64>) {
    let mut groups: std::collections::BTreeMap<u64, Vec<Option<[u8; 32]>>> =
        std::collections::BTreeMap::new();
    for (i, h) in heads.iter().enumerate() {
        let (Some(h), Some(r)) = (h, refs.get(i).copied().flatten()) else {
            continue;
        };
        groups.entry(*h).or_default().push(Some(r));
    }
    let mut mismatched: Vec<u64> = Vec::new();
    for (h, rs) in &groups {
        let first = rs[0];
        if rs.iter().any(|r| *r != first) {
            mismatched.push(*h);
        }
    }
    (groups.len(), mismatched)
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
    // CLI 的 `finalized_height` 实际为 `runtime.qc_history_tip_height()`（bin L1111）⇒ 映射到
    // `qc_tip`（durable QC-history tip），**不**是 consensus finality。该映射为**有意**行为，
    // 由 `t7_7_status_and_liveness_field_domains` 回归测试固定，防止未来被误读为真实 finality。
    let qc_tip = match field("finalized_height=") {
        Some("none") => None,
        Some(v) => Some(v.parse().ok()?),
        None => return None,
    };
    // `timer_window` 在未 arm 时打印为 `-` / `none` ⇒ 必须区分「未 arm」与「0」，不得静默补 0。
    let timer_window = match field("timer_window=") {
        Some("-") | Some("none") => None,
        Some(v) => Some(v.parse().ok()?),
        None => return None,
    };
    // `finalized_ref_present` 是**权威** finality 布尔值（不是代理）⇒ 缺失或非法一律 fail-closed：
    // 绝不把「未观测」默认为 `false`（否则会把 finality 观测失败伪装成「无 finality」）。
    let finalized_ref_present = match field("finalized_ref_present=") {
        Some("true") => true,
        Some("false") => false,
        _ => return None,
    };
    // P3 — `finalized_ref` 是**权威** finalization 引用本身。
    // 缺失 / 重复 / 非法 ⇒ 整行 `None`（**绝不**把「未观测」伪装成 `none`）；
    // 且必须与 `finalized_ref_present` **一致**（生产端同一次读取，理论不可能矛盾）。
    let finalized_ref = extract_finalized_ref(line)?;
    if finalized_ref.is_some() != finalized_ref_present {
        return None;
    }
    Some(Stats {
        steps: num("steps=")?,
        head: num("head_height=")?,
        qc_tip,
        finalized_ref_present,
        finalized_ref,
        consensus: num("consensus_height=")?,
        round: num("round=")?,
        qc_served: num("qc_served=")?,
        established: num("established_peers=")? as usize,
        round_timeouts: num("round_timeouts=")?,
        timer_window,
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

/// **P4-A2** — 带**进程存活**与 **fatal 标记**检测的 polling 结果。
///
/// 只有 `reached == true` **且** `dead`/`fatal` 均为空，才表示「判据在存活前提下达成」。
#[derive(Debug, Default)]
struct LivePoll {
    /// 判据是否在窗口内达成（**不含**存活/fatal 结论）。
    reached: bool,
    /// 判据达成前意外退出的验证者标签。
    dead: Vec<&'static str>,
    /// 检测到的 fatal 标记（标签 + 命中的模式）。
    fatal: Vec<(&'static str, String)>,
}

/// **P4-A2** — 与 [`poll_traced`] **判据等价**，但每轮额外检查子进程存活、并周期扫描 fatal 标记。
///
/// 设计目的（OD-P4-1 A2 授权）：关闭「节点达成目标后崩溃，测试仍 PASS」的假阴性通道。
/// `t7_3` 场景中**没有**任何测试侧主动停机，因此任何子进程退出都是**意外退出**，一律失败。
///
/// 代价控制：`try_wait` 每轮（20 ms）执行，开销极低；`fatal_marker` 是全量字符串扫描，
/// 因此按 **1 s** 节流，而不是每轮执行。
fn poll_traced_live<F, S>(
    label: &str,
    kids: &mut [ChildGuard],
    mut f: F,
    mut snap: S,
    window: Duration,
) -> LivePoll
where
    F: FnMut(&[ChildGuard]) -> bool,
    S: FnMut(&[ChildGuard]) -> String,
{
    let t0 = Instant::now();
    let deadline = t0 + window;
    let mut next_snap = t0;
    let mut next_fatal = t0;
    loop {
        // ① 存活检查（每轮）：任一子进程已退出 ⇒ 立即失败，不得再用其陈旧 status 判 PASS。
        let mut dead: Vec<&'static str> = Vec::new();
        for k in kids.iter_mut() {
            if !k.is_running() {
                dead.push(k.label);
            }
        }
        if !dead.is_empty() {
            return LivePoll {
                reached: false,
                dead,
                fatal: Vec::new(),
            };
        }
        // ② fatal 标记（1 s 节流）。
        let now = Instant::now();
        if now >= next_fatal {
            let mut hit: Vec<(&'static str, String)> = Vec::new();
            for k in kids.iter() {
                if let Some(m) = fatal_marker(&k.stdout(), &k.stderr()) {
                    hit.push((k.label, m));
                }
            }
            if !hit.is_empty() {
                return LivePoll {
                    reached: false,
                    dead: Vec::new(),
                    fatal: hit,
                };
            }
            next_fatal = now + Duration::from_secs(1);
        }
        // ③ 判据（与 [`poll_traced`] 完全一致）。
        if f(kids) {
            return LivePoll {
                reached: true,
                dead: Vec::new(),
                fatal: Vec::new(),
            };
        }
        let now = Instant::now();
        if now >= deadline {
            return LivePoll::default();
        }
        if now >= next_snap {
            eprintln!("TRACE {label} t={:?} {}", t0.elapsed(), snap(kids));
            next_snap = now + Duration::from_secs(30);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// **P4-A2** — 停机并**验证停机确实生效**（故障注入的激活证据）。
///
/// 返回 `Err` 表示注入**未生效**。调用方必须据此 FAIL，而**不是**继续观察 ——
/// 否则「注入失败」会被误读成「注入后无活性变化」，二者语义完全不同。
fn stop_validator_and_verify(kid: &mut ChildGuard) -> Result<ExitStatus, String> {
    let label = kid.label;
    let status = kid.terminate();
    if kid.is_running() {
        return Err(format!("{label}: terminate 后仍在运行"));
    }
    status.ok_or_else(|| format!("{label}: terminate 未返回退出状态"))
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
/// - **timeout 计数（推断；非权威）**：同一 `consensus_height` 下观测到 `round: r → r'`（`r' > r`）
///   ⇒ 对 `r..r'` 各记一次。
///
///   ⚠️ **两条已知局限（PHASE 6H-ONEPASS 更正）**，引用本字段时**必须**同时引用它们：
///   1. **前提不成立**：round 前进的原因**不唯一** —— 除本地 pacemaker timeout 外，
///      **RC（round change）** 亦可推进 round（节点自报 `round_adv_rc`）。早期版本声称
///      「`RoundTimeout` 是 round 前进的**唯一**原因」是**错误**的。
///   2. **首次推进系统性丢失**：首个采样点常为 `NO_STATUS`（进程尚未输出 status），
///      而 round 0→1 通常发生在此之前 ⇒ 该迁移**不可观测** ⇒ 恒少计（历史上出现
///      `timeouts_by_round[0] = 0` 而节点已在 round ≥1 的情形，即为本局限所致）。
///
///   ⇒ 本计数是**下界**且**混淆来源**。判定「timeout 是否真的发生、是否真的推进」
///   **必须**使用 [`authoritative_summary`] 的节点自报 `round_timeouts` /
///   `round_adv_local` / `round_adv_height` / `round_adv_rc`。
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
    // P4-A2 加固：判据**不变**，但每轮检查进程存活 + 周期扫描 fatal 标记。
    // 本场景**无**测试侧主动停机 ⇒ 任何子进程退出都是意外退出，一律不得判 PASS。
    let poll = poll_traced_live(
        "T7-3-A",
        &mut kids,
        |ks| {
            ks.iter().all(|c| {
                last_status(&c.stdout())
                    .is_some_and(|s| advanced_to(&s, 5) && s.established >= 4)
            })
        },
        |ks| tr3.observe(&stats_of(ks), Instant::now()),
        window_e1(),
    );
    let ok = poll.reached;
    let final_stats = stats_of(&kids);
    eprintln!("T7-3 E1/E4 SUMMARY (recovered={ok}):\n{}", tr3.summary());
    // PHASE 6H-ONEPASS：**断言之前**输出节点自报的权威计数 ⇒ PASS 与 FAIL 两条路径下的
    // 证据等价（FAIL 路径此前只能依赖 `forensic()` 的 stdout 尾部，且会被截断）。
    // 只读观测：不改变判据、不改变计时、不改变任何共识语义。
    eprintln!("T7-3 AUTH SUMMARY (recovered={ok}):\n{}", authoritative_summary(&kids));
    eprintln!("T7-3 final={final_stats:?}");
    // P4-A2 ① — 进程存活：判据达成**之前**有验证者退出 ⇒ 立即失败（不得用陈旧 status 判 PASS）。
    assert!(
        poll.dead.is_empty(),
        "T7-3：PROCESS_LIVENESS — 验证者在判据达成前意外退出 dead={:?}（final={final_stats:?}）\n{}",
        poll.dead,
        forensic("T7-3-process-dead", &kids.iter().collect::<Vec<_>>())
    );
    // P4-A2 ② — fatal 标记：轮询期间出现即失败（优先于进展判据）。
    assert!(
        poll.fatal.is_empty(),
        "T7-3：FATAL_MARKER — 轮询期间出现 fatal {:?}（final={final_stats:?}）\n{}",
        poll.fatal,
        forensic("T7-3-fatal-poll", &kids.iter().collect::<Vec<_>>())
    );
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
    // ── P3 — **最终化对象标识**跨节点比较（本轮新增观测；不改既有判据 / 计时 / 进程管理）──
    //
    // 判据强度：仅「5/5 finalized_ref_present=true」**不足以**证明 finality 一致性
    //（不同节点可能对不同区块 finality）。必须比较 32B 引用本身。
    let refs: Vec<Option<[u8; 32]>> = final_stats
        .iter()
        .map(|s| s.and_then(|x| x.finalized_ref))
        .collect();
    let refs_hex: Vec<String> = refs
        .iter()
        .map(|r| r.map_or_else(|| "MISSING".to_string(), |h| hex32_hex(&h)))
        .collect();
    // （P4）对象标识的分组打印见下方 ② 之后。
    // ① 每个节点都必须有**可解析**的引用 ⇒ 否则观测不完整（不得当作 PASS）。
    let incomplete: Vec<usize> = (0..refs.len()).filter(|i| refs[*i].is_none()).collect();
    assert!(
        incomplete.is_empty(),
        "T7-3：FINALITY_OBJECT_IDENTITY_INCOMPLETE — 节点索引 {incomplete:?} 无可解析 finalized_ref \
         （refs={refs_hex:?}）\n{}",
        forensic("T7-3-object-incomplete", &kids.iter().collect::<Vec<_>>())
    );
    // ② **按 head 分组**后组内比较 ⇒ 跨 head 的不同引用是正常的异步推进，不是分歧。
    //    （P4 修正：P3 的跨 head 直接比较在 `P4-BASE-01` 中产生了伪失败。）
    let heads: Vec<Option<u64>> = final_stats
        .iter()
        .map(|s| s.as_ref().map(|x| x.head))
        .collect();
    let (groups, mismatched_heads) = finality_identity_check(&heads, &refs);
    let group_desc: Vec<String> = {
        let mut m: std::collections::BTreeMap<u64, Vec<usize>> = std::collections::BTreeMap::new();
        for (i, h) in heads.iter().enumerate() {
            if let Some(h) = h {
                m.entry(*h).or_default().push(i);
            }
        }
        m.iter().map(|(h, v)| format!("head={h}:{v:?}")).collect()
    };
    eprintln!(
        "T7-3 FINALITY_OBJECT groups=[{}] refs={refs_hex:?}",
        group_desc.join(" ")
    );
    assert!(
        mismatched_heads.is_empty(),
        "T7-3：FINALITY_OBJECT_IDENTITY_MISMATCH — 同一 head 下引用分歧 heads={mismatched_heads:?} \
         （refs={refs_hex:?}）\n{}",
        forensic("T7-3-object-mismatch", &kids.iter().collect::<Vec<_>>())
    );
    eprintln!(
        "T7-3 FINALITY_OBJECT_IDENTITY_CONSISTENT groups={groups} nodes={} heads={heads:?}",
        refs.len()
    );
    // P4-A2 ③ — **最终接受点复核**：不依赖轮询期间的结论，重新检查存活与 fatal。
    // 目的：节点在达成目标后、宣布 PASS 前退出，也必须失败（见 OD-P4-1 A2 §A/§B）。
    let mut dead_at_accept: Vec<&'static str> = Vec::new();
    for c in kids.iter_mut() {
        if !c.is_running() {
            dead_at_accept.push(c.label);
        }
    }
    assert!(
        dead_at_accept.is_empty(),
        "T7-3：PROCESS_LIVENESS — 节点 {:?} 在最终接受点已退出（判据虽已达成，但不得 PASS）\n{}",
        dead_at_accept,
        forensic("T7-3-dead-at-acceptance", &kids.iter().collect::<Vec<_>>())
    );
    let fatal_at_accept: Vec<(&'static str, String)> = kids
        .iter()
        .filter_map(|c| fatal_marker(&c.stdout(), &c.stderr()).map(|m| (c.label, m)))
        .collect();
    assert!(
        fatal_at_accept.is_empty(),
        "T7-3：FATAL_MARKER — 节点 {:?} 在最终接受点出现 fatal\n{}",
        fatal_at_accept,
        forensic("T7-3-fatal-acceptance", &kids.iter().collect::<Vec<_>>())
    );
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
    // PHASE 6H-ONEPASS：**断言之前**输出权威计数（4/7 是「无 finality 属预期」的路径，
    // 其价值在于记录真实 round 推进来源；只读观测，不改判据）。
    eprintln!("T7-4 AUTH SUMMARY:\n{}", authoritative_summary(&kids));
    for (i, c) in kids.iter().enumerate() {
        // fail-closed：节点状态缺失**不得**退化为全零默认值（否则 no-finality 判据会「空过」）。
        // 该分支必须与本循环其它断言一样携带取证输出，便于事后复核「为何读不到状态」。
        let s = final_stats[i].unwrap_or_else(|| {
            panic!(
                "T7-4：{} 状态缺失（status 行不可解析或从未产出），不能把「未观测」当作 \
                 no-finality 证据；需显式失败\n{}",
                c.label,
                forensic("T7-4-unparsed", &kids.iter().collect::<Vec<_>>()),
            )
        });
        // no-finality 判据（五条件同时成立；不得仅凭 head=0）：
        //   ① 无 head 前进（finality-commit 代理从未触发）
        //   ② 无 consensus finality 证据（durable QC tip 从未 ≥1）
        //   ③ 无 QC 服务能力（qc_served == 0）
        //   ④ **权威** finality 状态未置位（`state().finality.finalized_reference` 为 None）
        //   ⑤ **P3** 权威 finalization 引用本身为**显式** none（不是「未观测」）
        // ④ 是本轮新增：使用节点自报的**权威**布尔值，而非仅依赖 QC-tip 代理。只增不减。
        // ⑤ 是 P3 新增：布尔为 false 时引用必须同时为 none（解析端已强制自洽）。
        assert!(
            s.head == 0
                && s.qc_tip.is_none()
                && s.qc_served == 0
                && !s.finalized_ref_present
                && s.finalized_ref.is_none(),
            "T7-4：4/7 竟然产生了 finality 迹象（{} head={} qc_tip={:?} qc_served={} \
             finalized_ref_present={} finalized_ref={:?} consensus={} round={}）——违反 2/3 quorum 门限\n{}",
            c.label,
            s.head,
            s.qc_tip,
            s.qc_served,
            s.finalized_ref_present,
            s.finalized_ref,
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
// T7-8 — 7/7 ⇒ **停 V5 + V6** ⇒ 5/7（恰达 quorum）继续 ⇒ 重启两者 ⇒ 重连 + catch-up
//
// P4-A2 授权（OD-P4-1 A2）：确定性 test-only 故障注入 + 恢复。
// 复用 `t7_5` 的机制（里程碑触发 / `ChildGuard` 进程管理 / `node_args` 同身份重启），
// **不修改** `t7_5` 的语义；额外要求「注入确实生效」与「最终接受点存活」被**显式证明**。
// ---------------------------------------------------------------------------
#[test]
fn t7_8_seven_to_five_fault_injection_and_recovery() {
    // quorum 口径：5/7 = 5 × 200_000 = 1_000_000 ≥ 933_334 ⇒ 停滞即缺陷；
    // 4/7 = 800_000 < quorum ⇒ 停滞属正确行为（本用例不进入 4/7）。
    eprintln!(
        "T7-8: quorum={} ; 5/7 weight={} (>= quorum: {})",
        expected_quorum(),
        STAKE * 5,
        STAKE * 5 >= expected_quorum()
    );
    assert!(
        STAKE * 5 >= expected_quorum(),
        "T7-8：前提不成立 —— 5/7 必须仍达 quorum，否则本用例「应当推进」的期望无效"
    );

    let fx = setup("t78");
    let mut kids = spawn_first(&fx, N);

    assert!(
        wait_ready(&kids, STARTUP_TIMEOUT),
        "T7-8：7 进程未进入 run loop\n{}",
        forensic("T7-8-startup", &kids.iter().collect::<Vec<_>>())
    );

    // ── 阶段 A：健康基线（全部 7 节点推进且彼此已连接）──
    let base = poll_traced_live(
        "T7-8-A",
        &mut kids,
        |ks| {
            ks.iter().all(|c| {
                last_status(&c.stdout())
                    .is_some_and(|s| advanced_to(&s, 5) && s.established >= N - 1)
            })
        },
        |ks| snapshot_line(&stats_of(ks)),
        WINDOW_7,
    );
    assert!(
        base.dead.is_empty(),
        "T7-8：基线阶段有进程退出 {:?}\n{}",
        base.dead,
        forensic("T7-8-base-dead", &kids.iter().collect::<Vec<_>>())
    );
    assert!(
        base.fatal.is_empty(),
        "T7-8：基线阶段出现 fatal {:?}\n{}",
        base.fatal,
        forensic("T7-8-base-fatal", &kids.iter().collect::<Vec<_>>())
    );
    assert!(
        base.reached,
        "T7-8：基线未在 {WINDOW_7:?} 内达成（7/7 未全部 advanced_to(5) ∧ established≥{}）\n{}",
        N - 1,
        forensic("T7-8-baseline", &kids.iter().collect::<Vec<_>>())
    );

    let before = stats_of(&kids);
    let base_heads: Vec<u64> = before
        .iter()
        .take(5)
        .map(|s| s.map_or(0, |x| x.head))
        .collect();
    eprintln!("T7-8 BASELINE: {before:?}");

    // ── 阶段 B：注入 —— 停 V5 + V6（7 → 5 在线）──
    let st5 = stop_validator_and_verify(&mut kids[5]);
    if let Err(e) = &st5 {
        panic!(
            "T7-8：INJECTION FAILED (V5) — {e}\n{}",
            forensic("T7-8-inject-fail", &kids.iter().collect::<Vec<_>>())
        );
    }
    let st6 = stop_validator_and_verify(&mut kids[6]);
    if let Err(e) = &st6 {
        panic!(
            "T7-8：INJECTION FAILED (V6) — {e}\n{}",
            forensic("T7-8-inject-fail", &kids.iter().collect::<Vec<_>>())
        );
    }

    // 注入后的**独立**观测：两个被停的必须已退出，其余 5 个必须仍存活。
    let mut alive_after_stop: Vec<&'static str> = Vec::new();
    for c in kids[..5].iter_mut() {
        if c.is_running() {
            alive_after_stop.push(c.label);
        }
    }
    let mut still_running: Vec<&'static str> = Vec::new();
    for c in kids[5..].iter_mut() {
        if c.is_running() {
            still_running.push(c.label);
        }
    }
    assert!(
        still_running.is_empty(),
        "T7-8：INJECTION NOT EFFECTIVE — 被停节点仍在运行 {:?}",
        still_running
    );
    assert_eq!(
        alive_after_stop.len(),
        5,
        "T7-8：INJECTION — 期望恰好 5 个节点存活，实际 {:?}",
        alive_after_stop
    );
    eprintln!(
        "T7-8 INJECTION ACTIVATED: alive={alive_after_stop:?} stopped=[V5={:?} V6={:?}]",
        st5.as_ref().ok(),
        st6.as_ref().ok()
    );

    // ── 阶段 C：5/7（仍 ≥ quorum）必须继续推进 —— 本用例的**正向**期望 ──
    let progressed = poll_traced_live(
        "T7-8-B",
        &mut kids[..5],
        |ks| {
            ks.iter()
                .enumerate()
                .all(|(i, c)| last_status(&c.stdout()).is_some_and(|s| s.head >= base_heads[i] + 2))
        },
        |ks| snapshot_line(&stats_of(ks)),
        WINDOW_QUORUM,
    );
    let after_stop = stats_of(&kids[..5]);
    assert!(
        progressed.dead.is_empty(),
        "T7-8：5/7 阶段有节点退出 {:?}\n{}",
        progressed.dead,
        forensic("T7-8-five-dead", &kids[..5].iter().collect::<Vec<_>>())
    );
    assert!(
        progressed.fatal.is_empty(),
        "T7-8：5/7 阶段出现 fatal {:?}\n{}",
        progressed.fatal,
        forensic("T7-8-five-fatal", &kids[..5].iter().collect::<Vec<_>>())
    );
    assert!(
        progressed.reached,
        "T7-8：QUORUM-SUFFICIENT STALL — 停 V5/V6 后 5/7（1_000_000 ≥ quorum {}）未在 {WINDOW_QUORUM:?} 内继续推进（base={base_heads:?} after={after_stop:?}）\n{}",
        expected_quorum(),
        forensic("T7-8-stall", &kids[..5].iter().collect::<Vec<_>>())
    );
    eprintln!("T7-8 5/7 PROGRESSED: after_stop={after_stop:?}");

    // ── 阶段 D：恢复 —— 同身份/同目录重启 V5/V6（既有 `node_args`）──
    let v5_args = node_args(
        &fx.env,
        N,
        5,
        &fx.ids,
        &fx.ports,
        &fx.genesis_path,
        &fx.hash_hex,
    );
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
        v5_args.iter().all(|a| a != "--init-validator-safety"),
        "T7-8：重启 V5 **不得**携带 --init-validator-safety（既有 journal ⇒ 恢复路径）"
    );
    assert!(
        v6_args.iter().all(|a| a != "--init-validator-safety"),
        "T7-8：重启 V6 **不得**携带 --init-validator-safety（既有 journal ⇒ 恢复路径）"
    );
    let mut restarted: Vec<ChildGuard> = vec![
        ChildGuard::spawn("V5r", &v5_args),
        ChildGuard::spawn("V6r", &v6_args),
    ];

    // ── 阶段 E：重连（两个重启进程各自至少 established ≥ 1）──
    let reconnected = poll_traced_live(
        "T7-8-C",
        &mut restarted,
        |ks| {
            ks.iter()
                .all(|c| last_status(&c.stdout()).is_some_and(|s| s.established >= 1))
        },
        |ks| snapshot_line(&stats_of(ks)),
        WINDOW_RESTART,
    );
    let restart_stats = stats_of(&restarted);
    assert!(
        reconnected.dead.is_empty(),
        "T7-8：RECOVERY FAILED — 重启进程退出 {:?}\n{}",
        reconnected.dead,
        forensic("T7-8-recover-dead", &restarted.iter().collect::<Vec<_>>())
    );
    assert!(
        reconnected.fatal.is_empty(),
        "T7-8：RECOVERY FAILED — 重启进程出现 fatal {:?}\n{}",
        reconnected.fatal,
        forensic("T7-8-recover-fatal", &restarted.iter().collect::<Vec<_>>())
    );
    assert!(
        reconnected.reached,
        "T7-8：RECOVERY FAILED — V5/V6 未在 {WINDOW_RESTART:?} 内重连（{restart_stats:?}）\n{}",
        forensic("T7-8-reconnect", &restarted.iter().collect::<Vec<_>>())
    );
    eprintln!("T7-8 RECOVERY RECONNECTED: {restart_stats:?}");

    // ── 阶段 F：catch-up（与 `t7_5` 同口径：head ≥ 5 且不落后其他节点超过 1）──
    let caught = poll_traced_live(
        "T7-8-D",
        &mut restarted,
        |ks| {
            let others_min = kids[..5]
                .iter()
                .filter_map(|c| last_status(&c.stdout()))
                .map(|s| s.head)
                .min()
                .unwrap_or(u64::MAX);
            ks.iter().all(|c| {
                last_status(&c.stdout()).is_some_and(|s| s.head >= 5 && s.head + 1 >= others_min)
            })
        },
        |ks| snapshot_line(&stats_of(ks)),
        WINDOW_RESTART,
    );
    let final_restarted = stats_of(&restarted);
    assert!(
        caught.dead.is_empty(),
        "T7-8：CATCH-UP FAILED — 重启进程退出 {:?}\n{}",
        caught.dead,
        forensic("T7-8-catchup-dead", &restarted.iter().collect::<Vec<_>>())
    );
    assert!(
        caught.fatal.is_empty(),
        "T7-8：CATCH-UP FAILED — 重启进程出现 fatal {:?}\n{}",
        caught.fatal,
        forensic("T7-8-catchup-fatal", &restarted.iter().collect::<Vec<_>>())
    );
    assert!(
        caught.reached,
        "T7-8：CATCH-UP FAILED — V5/V6 未在 {WINDOW_RESTART:?} 内追平（restarted={final_restarted:?}）\n{}",
        forensic(
            "T7-8-catchup",
            &kids[..5].iter().chain(restarted.iter()).collect::<Vec<_>>()
        )
    );
    eprintln!("T7-8 CATCH-UP SUCCESS: restarted={final_restarted:?}");

    // ── 阶段 G：最终接受点 —— 存活 + fatal（不依赖前面任一步的结论）──
    let mut dead_final: Vec<&'static str> = Vec::new();
    for c in kids[..5].iter_mut() {
        if !c.is_running() {
            dead_final.push(c.label);
        }
    }
    for c in restarted.iter_mut() {
        if !c.is_running() {
            dead_final.push(c.label);
        }
    }
    assert!(
        dead_final.is_empty(),
        "T7-8：PROCESS_LIVENESS — 最终接受点有节点已退出 {:?}\n{}",
        dead_final,
        forensic(
            "T7-8-dead-at-acceptance",
            &kids[..5].iter().chain(restarted.iter()).collect::<Vec<_>>()
        )
    );
    let fatal_final: Vec<(&'static str, String)> = kids[..5]
        .iter()
        .chain(restarted.iter())
        .filter_map(|c| fatal_marker(&c.stdout(), &c.stderr()).map(|m| (c.label, m)))
        .collect();
    assert!(
        fatal_final.is_empty(),
        "T7-8：FATAL_MARKER — 最终接受点出现 fatal {:?}",
        fatal_final
    );
    eprintln!(
        "T7-8 PASS: before={before:?} after_stop={after_stop:?} restarted={final_restarted:?}"
    );

    let mut statuses: Vec<Option<ExitStatus>> =
        kids[..5].iter_mut().map(ChildGuard::terminate).collect();
    statuses.extend(restarted.iter_mut().map(ChildGuard::terminate));
    eprintln!("T7-8 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// PHASE 6H-A30 OD-X8 — 观测解析器单元测试
//
// 边界：这里的合成行**只**用于解析器单元测试；正式摘要必须来自真实子进程输出。
// ---------------------------------------------------------------------------
/// 样本行中 `finalized_ref=` 的取值（32 字节互不相同 ⇒ 可检出截断 / 错位 / 字节序错误）。
const ODX8_STATUS_SAMPLE_REF: &str =
    "finalized_ref=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

const ODX8_STATUS_SAMPLE: &str = "yazimao-node: status steps=300 head_height=7 \
     finalized_height=7 consensus_height=7 round=0 configured_peers=6 established_peers=4 \
     sync_pending=0 block_inbound_skipped=0 pending_external_qc=0 qc_served=0 \
     validator_enabled=true rc_certs=0 rc_authority=0 rc_rejected=0 rc_rej=0/0/0/0/0/0 \
     abandon_bcast_nopeer=0 rc_reeval=0/0 timeout_split=3/0/0 guard_rej=0/0/0/0/0/0/0/0 \
     wire_drops=0/0/0/0 round_timeouts=3 timer_elapsed=41144 timer_window=120000 \
     round_step=Prevote proposal_present=true finalized_ref_present=true \
     finalized_ref=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
     inbound=1/2/3/4/5/6/7 inbound_drops=0/0/0/0 peer_state=[] peer_fail=[]";

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

// ---------------------------------------------------------------------------
// PHASE 6H-ONEPASS — 权威观测解析器与字段域的回归测试
//
// 目的：把「哪些字段是**节点自报**、哪些量在**什么单位域**」固定为可执行断言，
// 防止本研究线历史上反复出现的两类错误：
//   ① 把界面的**别名**当成语义（如把 durable QC-history tip 读成 consensus finality）；
//   ② 把**单位域**搞错（把毫秒值当成 step tick 用）。
// 边界：这些断言**只**检查解析与单位域，**不**触碰任何共识判据。
// ---------------------------------------------------------------------------

/// 真实的 `liveness` 行样本（字段顺序与 `bin/yazimao-node.rs` L1216 起的
/// `liveness_line` 一致；用于确认解析器读的是**节点自报**值）。
const ONEPASS_LIVENESS_SAMPLE: &str = "yazimao-node: liveness steps=2400 prop_calls=2400 \
     prop_build_ok=1 prop_skip_not_elected=2068 prop_skip_height_desync=0 \
     prop_skip_step_guard=331 prop_skip_conflict_target=0 prop_skip_fail=0 \
     inbound_prop_ok=1 egress_prop_enqueued=1 egress_prop_no_peer=0 egress_prop_refreshed=0 \
     round_adv_local=4 round_adv_height=0 round_adv_rc=7 elected_is_self=false \
     prop_absent_steps=1113 proposal_admitted=1 proposal_pending=1 proposal_rejected=0 \
     proposal_expired=0 net_frames_received=653 net_events_enqueued=653 net_sent=1062 \
     net_dropped_invalid=0 net_dropped_overflow=0 net_unauthenticated_drops=0 \
     el_handler_errors=0 el_events_dropped_overflow=0 recovery_runs=1 recovery_candidates=1 \
     recovery_kept_missing_block=0 recovery_admitted=1 recovery_rejected=0";

#[test]
fn onepass_liveness_parser_reads_authoritative_advance_sources() {
    // round 推进的**来源三分**必须逐项可读：本地 timeout / 高度前进 / RC。
    let l = last_liveness(ONEPASS_LIVENESS_SAMPLE).expect("完整 liveness 行应可解析");
    assert_eq!(l.steps, 2400);
    assert_eq!(l.prop_calls, 2400);
    assert_eq!(l.prop_build_ok, 1);
    assert_eq!(l.prop_skip_not_elected, 2068);
    assert_eq!(l.prop_skip_step_guard, 331);
    assert_eq!(l.round_adv_local, 4);
    assert_eq!(l.round_adv_height, 0);
    assert_eq!(l.round_adv_rc, 7);
    assert!(!l.elected_is_self);
    assert_eq!(l.prop_absent_steps, 1113);
    assert_eq!(l.proposal_admitted, 1);
    assert_eq!(l.proposal_pending, 1);
    assert_eq!(l.recovery_runs, 1);
    assert_eq!(l.net_frames_received, 653);
    assert_eq!(l.net_sent, 1062);
}

#[test]
fn onepass_liveness_parser_never_invents_missing_fields() {
    // 缺任一必需字段 ⇒ None（绝不以 0 冒充「未观测」）。
    let without_rc = "yazimao-node: liveness steps=1 prop_calls=1 prop_build_ok=0";
    assert!(last_liveness(without_rc).is_none());
    // 缺 `round_adv_rc` 之外的字段也同样必须失败（抽样两个）。
    let missing_local = ONEPASS_LIVENESS_SAMPLE.replace("round_adv_local=4 ", "");
    assert!(last_liveness(&missing_local).is_none());
    let missing_elected = ONEPASS_LIVENESS_SAMPLE.replace("elected_is_self=false ", "");
    assert!(last_liveness(&missing_elected).is_none());
    assert!(last_liveness("").is_none());
    assert!(last_liveness("garbage").is_none());
}

#[test]
fn onepass_liveness_parser_uses_last_line() {
    let out = format!(
        "{}\n{}\n",
        ONEPASS_LIVENESS_SAMPLE,
        ONEPASS_LIVENESS_SAMPLE.replace("round_adv_rc=7", "round_adv_rc=9")
    );
    assert_eq!(last_liveness(&out).map(|l| l.round_adv_rc), Some(9));
}

#[test]
fn onepass_status_domains_are_pinned() {
    // ① `finalized_height` → `qc_tip` 是**有意**映射（durable QC-history tip），非 consensus finality。
    let s = last_status(ODX8_STATUS_SAMPLE).expect("完整 status 行应可解析");
    assert_eq!(s.qc_tip, Some(7));
    // ② 权威 timeout 事件计数必须来自节点自报字段。
    assert_eq!(s.round_timeouts, 3);
    // ③ `timer_window` 为**毫秒**域；`-`（未 arm）⇒ None（不得补 0）。
    assert_eq!(s.timer_window, Some(120_000));
    let unarmed = ODX8_STATUS_SAMPLE.replace("timer_window=120000", "timer_window=-");
    assert_eq!(last_status(&unarmed).and_then(|s| s.timer_window), None);
    assert!(last_status(&unarmed).is_some(), "未 arm 行仍应整体可解析");
    let none_armed = ODX8_STATUS_SAMPLE.replace("timer_window=120000", "timer_window=none");
    assert_eq!(last_status(&none_armed).and_then(|s| s.timer_window), None);
    assert!(
        last_status(&none_armed).is_some(),
        "timer_window=none 仍应整体可解析"
    );
    // ④ 缺 `round_timeouts` ⇒ 解析失败（避免把「未观测」读成「0 次超时」）。
    let no_timeouts = ODX8_STATUS_SAMPLE.replace("round_timeouts=3 ", "");
    assert!(last_status(&no_timeouts).is_none());
}

/// **权威 finality 观测**：`finalized_ref_present` 的解析必须 fail-closed，且**不得**与
/// `qc_tip`（durable QC-history tip 代理）混淆。
///
/// 回归目标（防止「观测失败 → 默认 false」这一假阴性路径）：
/// - `true` / `false` 都是有效值；
/// - **缺失**或**非法**值 ⇒ 整行不可解析（而不是默认 `false`）；
/// - `qc_tip == None` **不**覆盖权威 finality 状态（两者语义独立）。
#[test]
fn onepass_finality_presence_is_authoritative_and_fail_closed() {
    // ① 样本行：权威字段为 true。
    let s = last_status(ODX8_STATUS_SAMPLE).expect("完整 status 行应可解析");
    assert!(s.finalized_ref_present);

    // ② `false` 是**有效值**，不得被当作「缺失」。
    // P3：必须**同时**把引用置为 `none`，否则同一行内布尔与哈希自相矛盾（解析端 fail-closed）。
    let absent = ODX8_STATUS_SAMPLE
        .replace("finalized_ref_present=true", "finalized_ref_present=false")
        .replace(ODX8_STATUS_SAMPLE_REF, "finalized_ref=none");
    let s2 = last_status(&absent).expect("finalized_ref_present=false 仍应整体可解析");
    assert!(!s2.finalized_ref_present);
    assert_eq!(s2.finalized_ref, None, "显式 none 必须解析为 None");

    // ③ 缺失 ⇒ 整行不可解析（绝不默认为 false）。
    let missing = ODX8_STATUS_SAMPLE.replace("finalized_ref_present=true ", "");
    assert!(
        last_status(&missing).is_none(),
        "缺失 finality 权威字段必须 fail-closed（不得默认为 false）"
    );

    // ④ 非法值（非 true/false）⇒ 整行不可解析（不得猜测）。
    let bogus =
        ODX8_STATUS_SAMPLE.replace("finalized_ref_present=true", "finalized_ref_present=yes");
    assert!(
        last_status(&bogus).is_none(),
        "非法 finality 布尔值必须 fail-closed"
    );

    // ⑤ 与 qc_tip 语义分离：QC tip 缺失 **不** 意味着 finality 未成立。
    let tip_none = ODX8_STATUS_SAMPLE.replace("finalized_height=7", "finalized_height=none");
    let s3 = last_status(&tip_none).expect("qc tip 为 none 时整行仍应可解析");
    assert_eq!(
        s3.qc_tip, None,
        "qc_tip 应反映 durable QC-history tip 的缺失"
    );
    assert!(
        s3.finalized_ref_present,
        "QC tip 缺失不得覆盖权威 finality 状态（两者语义独立）"
    );
}

/// **P3-E3** — `finalized_ref` 解析端的完整裁决表（纯函数；无进程 / 无 I/O）。
///
/// 覆盖：合法 64 hex / 显式 none / 长度错误 / 非 hex / 空值 / 大小写 / 全零。
/// 纪律：任何非法输入一律 `None`（**不**猜测、**不**截断补全）。
#[test]
fn p3_finalized_ref_token_accepts_exactly_valid_forms() {
    // ① 显式 none。
    assert_eq!(parse_finalized_ref_token("none"), Some(None));

    // ② 合法 64 hex ⇒ 逐字节解出。
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(1);
    }
    let hex = hex32_hex(&bytes);
    assert_eq!(hex.len(), 64, "编码必为定长 64");
    assert_eq!(parse_finalized_ref_token(&hex), Some(Some(bytes)));

    // ③ 大小写不敏感（消费端宽容；生产端恒输出小写）。
    assert_eq!(
        parse_finalized_ref_token(&hex.to_uppercase()),
        Some(Some(bytes))
    );

    // ④ 全零哈希是**合法值**（不得被误判为缺失）。
    assert_eq!(
        parse_finalized_ref_token(&"0".repeat(64)),
        Some(Some([0u8; 32]))
    );

    // ⑤ 长度错误（63 / 65 / 32）一律拒绝。
    assert_eq!(parse_finalized_ref_token(&hex[..63]), None);
    assert_eq!(parse_finalized_ref_token(&format!("{hex}0")), None);
    assert_eq!(parse_finalized_ref_token(&hex[..32]), None);

    // ⑥ 非 hex 一律拒绝（含 `0x` 前缀 / 非 hex 字符 / 空串）。
    assert_eq!(parse_finalized_ref_token(&format!("0x{}", &hex[2..])), None);
    assert_eq!(
        parse_finalized_ref_token(&format!("{}zz", &hex[..62])),
        None
    );
    assert_eq!(parse_finalized_ref_token(""), None);

    // ⑦ 与 `none` 相近但非法的值不得被接受（大小写 / 占位符）。
    assert_eq!(parse_finalized_ref_token("None"), None);
    assert_eq!(parse_finalized_ref_token("-"), None);
}

/// **P3-E3** — 整行提取：缺失 / 重复 / 冲突 / 矛盾一律 fail-closed（整行不可解析）。
#[test]
fn p3_finalized_ref_line_extraction_is_fail_closed_and_duplicate_safe() {
    // 基线：样本行可解析，且哈希与样本 fixture 逐字节一致。
    assert!(
        ODX8_STATUS_SAMPLE.contains(ODX8_STATUS_SAMPLE_REF),
        "样本行必须内联同一 fixture（防止常量漂移）"
    );
    let s = last_status(ODX8_STATUS_SAMPLE).expect("样本行应可解析");
    let mut want = [0u8; 32];
    for (i, b) in want.iter_mut().enumerate() {
        *b = (i as u8) + 1;
    }
    assert_eq!(s.finalized_ref, Some(want), "必须逐字节解出 fixture");

    // ① 缺失 ⇒ 整行不可解析（**绠不**默认为 none）。
    assert!(
        last_status(&ODX8_STATUS_SAMPLE.replace(ODX8_STATUS_SAMPLE_REF, "")).is_none(),
        "缺失 finalized_ref 必须 fail-closed"
    );
    // ② 重复（同值）⇒ 整行不可解析（歧义即失败，不取首个 / 末个）。
    let dup = format!("{ODX8_STATUS_SAMPLE} {ODX8_STATUS_SAMPLE_REF}");
    assert!(last_status(&dup).is_none(), "重复 token 必须 fail-closed");
    // ③ 冲突（异值）⇒ 整行不可解析。
    let conflict = format!("{ODX8_STATUS_SAMPLE} finalized_ref={}", "f".repeat(64));
    assert!(
        last_status(&conflict).is_none(),
        "冲突 token 必须 fail-closed"
    );
    // ④ 非法 hex ⇒ 整行不可解析。
    let bogus = ODX8_STATUS_SAMPLE.replace(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        &"g".repeat(64),
    );
    assert!(last_status(&bogus).is_none(), "非 hex 必须 fail-closed");
    // ⑤ 布尔与哈希矛盾（true + none）⇒ 整行不可解析。
    let contradiction = ODX8_STATUS_SAMPLE.replace(ODX8_STATUS_SAMPLE_REF, "finalized_ref=none");
    assert!(
        last_status(&contradiction).is_none(),
        "布尔与哈希矛盾必须 fail-closed"
    );
    // ⑥ 既有字段不受影响（保持独立可读）。
    assert!(s.finalized_ref_present);
    assert_eq!(s.qc_tip, Some(7));
    assert_eq!(s.steps, 300);
    assert_eq!(s.consensus, 7);
}

#[test]
fn p4_finality_identity_check_groups_by_head_and_still_detects_same_head_divergence() {
    let a = [0xAAu8; 32];
    let b = [0xBBu8; 32];

    // ① 全同 head + 全同 ref ⇒ 单组，无分歧。
    let heads = vec![Some(7u64); 5];
    let refs = vec![Some(a); 5];
    assert_eq!(finality_identity_check(&heads, &refs), (1, vec![]));

    // ② **P4-BASE-01 的真实形状**：4 个节点 head=7 同一 ref，1 个节点 head=6 另一 ref。
    //    跳 head ⇒ 不同 ref **不是**分歧（组内仍一致），因此不得判为 MISMATCH。
    let heads = vec![Some(7u64), Some(7), Some(6), Some(7), Some(7)];
    let refs = vec![Some(a), Some(a), Some(b), Some(a), Some(a)];
    assert_eq!(
        finality_identity_check(&heads, &refs),
        (2, vec![]),
        "跳 head 的不同引用不得被判为对象分歧"
    );

    // ③ **真分歧必须仍被检出**：同一 head 下两个不同 ref。
    let heads = vec![Some(7u64), Some(7), Some(7)];
    let refs = vec![Some(a), Some(b), Some(a)];
    assert_eq!(
        finality_identity_check(&heads, &refs),
        (1, vec![7]),
        "同一 head 下的不同引用必须被判为分歧"
    );

    // ④ 多个 head 同时出现真分歧 ⇒ 只报告出问题的 head。
    let heads = vec![Some(7u64), Some(7), Some(6), Some(6)];
    let refs = vec![Some(a), Some(a), Some(a), Some(b)];
    assert_eq!(finality_identity_check(&heads, &refs), (2, vec![6]));

    // ⑤ 缺失观测不参与比较（完整性由调用方断言），不得伪造一致。
    let heads = vec![Some(7u64), None, Some(7)];
    let refs = vec![Some(a), Some(b), Some(a)];
    assert_eq!(finality_identity_check(&heads, &refs), (1, vec![]));
    let heads = vec![Some(7u64), Some(7)];
    let refs = vec![Some(a), None];
    assert_eq!(finality_identity_check(&heads, &refs), (1, vec![]));
    // 全部缺失 ⇒ 0 组（调用方必须据此判为观测不完整，而非「一致」）。
    assert_eq!(
        finality_identity_check(&[None, None], &[None, None]),
        (0, vec![])
    );
}

/// **P4-A2** — [`poll_traced_live`] 的回归：**存活检测不得被进展判据旁路**。
///
/// 这是关闭「节点达成目标后崩溃仍 PASS」假阴性通道的核心单元验证：
/// 即便判据恒为 `true`，子进程已退出也必须返回 `reached=false` 且报出该标签。
#[test]
fn p4_poll_traced_live_detects_dead_child_and_never_reports_reached() {
    let mut kids = vec![ChildGuard::spawn_command(
        "sleeper",
        sleeper_command(),
        None,
    )];

    // ① 子进程存活 + 判据不成立 ⇒ 窗口耗尽返回，不得虚报 reached，也不得误报 dead。
    let out = poll_traced_live(
        "LIVEPOLL-alive",
        &mut kids,
        |_| false,
        |_| String::new(),
        Duration::from_millis(60),
    );
    assert!(!out.reached, "判据未成立时不得报 reached");
    assert!(
        out.dead.is_empty(),
        "存活子进程不得被报为 dead: {:?}",
        out.dead
    );
    assert!(out.fatal.is_empty(), "无 fatal 输出时不得报 fatal");

    // ② 子进程退出后：**即使判据为真**，也必须 reached=false 且报出该标签。
    let _ = kids[0].terminate();
    let out2 = poll_traced_live(
        "LIVEPOLL-dead",
        &mut kids,
        |_| true,
        |_| String::new(),
        Duration::from_secs(2),
    );
    assert!(!out2.reached, "子进程已退出时不得报 reached");
    assert_eq!(out2.dead, vec!["sleeper"], "必须报出退出的子进程标签");
}

#[test]
fn onepass_configured_window_is_millisecond_domain() {
    // 生产默认（A3）为**毫秒**域：10_000 / 20_000 / 40_000 / 80_000 / cap 120_000。
    assert_eq!(configured_window_ms(0), 10_000);
    assert_eq!(configured_window_ms(1), 20_000);
    assert_eq!(configured_window_ms(2), 40_000);
    assert_eq!(configured_window_ms(3), 80_000);
    assert_eq!(configured_window_ms(4), 120_000);
    assert_eq!(configured_window_ms(64), 120_000);
    assert_eq!(configured_window_ms(u64::MAX), 120_000);
    // 与 A3 **之前**的 tick 域（1000 / 60_000）必须不同 —— 若此断言失败，说明域被改回 tick，
    // 而 `implied_ms_rate` / 窗口预算的墙钟解释将随之失效。
    assert_ne!(configured_window_ms(0), 1_000);
    assert_ne!(configured_window_ms(64), 60_000);
}

#[test]
fn onepass_auth_totals_require_parsed_status_and_liveness() {
    // 只有 status 与 liveness **都**解析成功的节点才计入总量；缺失不得补 0。
    let s = last_status(ODX8_STATUS_SAMPLE).expect("样本行应可解析");
    let l = last_liveness(ONEPASS_LIVENESS_SAMPLE).expect("样本行应可解析");
    let st = vec![Some(s), Some(s), None];
    let lv = vec![Some(l), None, Some(l)];
    // 仅 idx0 同时具备 ⇒ (nodes, parsed, timeout=3, local=4, height=0, rc=7, build_ok=1, absent=1113)
    assert_eq!(auth_totals(&st, &lv), (3, 1, 3, 4, 0, 7, 1, 1113));
    assert_eq!(auth_totals(&[], &[]), (0, 0, 0, 0, 0, 0, 0, 0));
    // 两节点均解析 ⇒ 总量相加。
    let st2 = vec![Some(s), Some(s)];
    let lv2 = vec![Some(l), Some(l)];
    assert_eq!(auth_totals(&st2, &lv2), (2, 2, 6, 8, 0, 14, 2, 2226));
}
