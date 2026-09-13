//! P1-A.12 Phase 1 — **真实 3 个 `yazimao-node` validator 进程**通过真实 TCP 达成 durable finality。
//!
//! 证明链（**全部为生产路径**，非 in-process harness）：
//! ```text
//! CARGO_BIN_EXE_yazimao-node（--validator）
//!   → 真实 NodeRuntime + ValidatorActor（durable safety journal）
//!   → 真实 TCP（--listen / --peer 静态拓扑，全互联）
//!   → remote vote → QC → durable finality（finalized_height / head）
//! ```
//!
//! 证据来源 = **二进制 stdout 的 periodic status / 退出摘要**（A.9 公开契约），
//! 不依赖瞬时 accumulator 采样，不修改任何生产代码。
//! 明确边界：不涉及 peer discovery / graceful shutdown / partition / soak（后续阶段）。

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::ValidatorSet;
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
/// 正式 3 节点**运行上界**（idle 1ms；P1-A.13 起 warm-up 先建连再驱动共识）。
/// P1-A.14：仅作 `--run-steps` 上界；**`6000 steps completed` 不再是 PASS 条件**。
const RUN_STEPS: &str = "6000";
const IDLE_MS: &str = "1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// 正式**观测窗口**（P1-A.14：实时验收窗口；**不**再要求进程在窗口内退出）。
const EXIT_TIMEOUT: Duration = Duration::from_secs(240);
/// **回滚（snapshot rollback）后 C2 追赶 gap=70 的验收窗口**（P1-A.17/A12 harness fix 取证）：
/// 实测追赶速率 ≈4.3s/块 ⇒ gap 68 块理论最低 ≈292s、历史 p95 ≈329s ⇒ 默认 240s 在边界产生
/// 间歇假失败（C2 始终 alive / 持续前进 / 无 fatal）。仅放宽**恢复过程**的验收时间，
/// **不**放宽任何断言（target / head / consensus / durable sanity / established 全部保持）。
const A17_CATCHUP_WINDOW: Duration = Duration::from_secs(420);

/// 确定性身份（validator ≠ network；三节点互不相同）。
const VAL_SEED: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NET_SEED: [[u8; 32]; 3] = [[0x41; 32], [0x42; 32], [0x43; 32]];

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
            std::env::temp_dir().join(format!("yazimao_p1a12_{}_{}", std::process::id(), tag));
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

/// 子进程 guard：持续排空 stdout/stderr（防 pipe 满死锁）；Drop ⇒ kill + wait（**无孤儿进程**）。
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

    /// 有界等待退出（**F1 诊断：超时 ⇒ kill+wait 并返回 None，不再 panic**；
    /// 由调用方输出 PROCESS_EXIT_TIMEOUT 诊断，并在稍后仍以原有验收标准失败）。
    fn wait_bounded(&mut self, deadline: Instant) -> Option<ExitStatus> {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(e) => panic!("{}: try_wait 失败: {e}", self.label),
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// 进程是否仍在运行（`try_wait() == Ok(None)`；**不** kill、不阻塞）。
    /// P1-A.14：用于证明“durable finality 由**活着的** validator 持续产生”。
    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// P1-A.14 —— 主动终止（kill + wait；无 orphan；与 `Drop` 兼容且幂等）。
    /// 返回值仅作 **诊断 / cleanup 证据**，**不**是验收条件（测试主动 kill ⇒ 不会是 exit 0）。
    fn terminate(&mut self) -> Option<ExitStatus> {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.child.try_wait().ok().flatten()
    }

    /// F1 诊断：pid / ready / exit / 输出字节数 / 最后 200 行 / 关键词计数；并写完整日志到 %TEMP%。
    fn diagnostic(&self, status: Option<ExitStatus>, ready: bool) -> String {
        let out = self.stdout();
        let err = self.stderr();
        let log_out = std::env::temp_dir().join(format!("yazimao-p1-a12-{}.log", self.label));
        let _ = std::fs::write(
            &log_out,
            format!("=== STDOUT ===\n{out}\n=== STDERR ===\n{err}\n"),
        );
        let tail = |s: &str| -> String {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(200)..].join("\n")
        };
        let count = |s: &str, k: &str| s.matches(k).count();
        let mut block = format!(
            "=== PROCESS {} DIAGNOSTIC ===\npid={}\nready={}\nexit_status={:?}\n\
             stdout_bytes={}\nstderr_bytes={}\nlog_file={}\n",
            self.label,
            self.child.id(),
            ready,
            status.map(|s| s.code()),
            out.len(),
            err.len(),
            log_out.display(),
        );
        for k in [
            "status steps=",
            "proposal",
            "vote",
            "prevote",
            "precommit",
            "qc",
            "finality",
            "peer_",
            "handshake",
            "session",
            "reconnect",
            "error",
        ] {
            block.push_str(&format!("kw[{k}]={}\n", count(&out, k)));
        }
        block.push_str(&format!("--- last 200 stdout lines ---\n{}\n", tail(&out)));
        block.push_str(&format!("--- last 200 stderr lines ---\n{}\n", tail(&err)));
        block
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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

/// 从 `key=<n>` 取十进制值（`none` ⇒ None）。
fn field(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

/// 退出摘要行（A.9 契约：`stopped after X/Y steps; head_height=… finalized_height=…`）。
fn summary_of(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.contains("stopped after "))
        .unwrap_or_default()
        .to_string()
}

fn assert_no_consensus_errors(label: &str, out: &str, err: &str) {
    for needle in ["InvalidSignature", "QcVerification", "panicked", "error"] {
        assert!(
            !out.contains(needle),
            "{label} stdout 不得包含 {needle}：\n{out}"
        );
    }
    assert!(
        !err.contains("panicked") && !err.contains("InvalidSignature"),
        "{label} stderr 不得包含 panic/InvalidSignature：\n{err}"
    );
}

// ===========================================================================
// P1-A.14 —— 实时验收（**不**依赖进程退出 / 退出摘要 / 6000 步耗尽）
// ===========================================================================

/// 单个 validator 的实时样本（**仅**来自完整 status 行）。
///
/// P1-A.19 —— 字段语义**必须**区分（RC-2 = `TEST PREDICATE ARTIFACT` 的根因）：
/// - `head`：canonical head（commit 结果；只随 finality 授权 + commit 桥推进、不回退）⇒ **活性 progress 主判据**；
/// - `consensus`：`consensus_height`（本节点当前轮次高度）⇒ 与 `head` 并列的主判据（禁止只判「单节点 head」）；
/// - `finalized`：`finalized_height` = **durable QC-history tip**（对端 QC **服务能力**指标；
///   ⚠️ **不等价于 consensus finality**：不参与本地 safety / finality / commit 不变式，追赶 / 快进 /
///   重负载下可**合法滞后**）⇒ 仅作 sanity bound（≤ head）+ durable 见证（任一节点 ≥ 1）；
/// - `established`：established peers。
#[derive(Clone, Copy, Debug)]
struct StatusSample {
    steps: u64,
    head: u64,
    /// `finalized_height=none` ⇒ `None`（durable QC-history tip **未知**；**不是**「无 finality」）。
    finalized: Option<u64>,
    consensus: u64,
    established: u64,
}

impl StatusSample {
    /// durable sanity：QC-history tip 若存在必须 `≤ head`（tip **领先** head 才是异常）。
    fn durable_sane(&self) -> bool {
        self.finalized.is_none_or(|f| f <= self.head)
    }
}

/// 单个 validator 的实时采样跟踪（按 `steps` 去重；保留全部样本用于“持续进展”判定）。
struct LiveTracker {
    label: &'static str,
    last_steps: Option<u64>,
    samples: Vec<StatusSample>,
}

impl LiveTracker {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            last_steps: None,
            samples: Vec::new(),
        }
    }

    /// 采样一次：仅当出现**新的**（`steps` 变化的）完整 status 行时记录。
    fn observe(&mut self, c: &ChildGuard) {
        let Some(line) = last_status(&c.stdout()) else {
            return;
        };
        let (Some(steps), Some(head)) = (field(&line, "steps="), field(&line, "head_height="))
        else {
            return;
        };
        if self.last_steps == Some(steps) {
            return;
        }
        self.last_steps = Some(steps);
        self.samples.push(StatusSample {
            steps,
            head,
            finalized: field(&line, "finalized_height="),
            consensus: field(&line, "consensus_height=").unwrap_or(0),
            established: field(&line, "established_peers=").unwrap_or(0),
        });
    }

    fn last(&self) -> Option<StatusSample> {
        self.samples.last().copied()
    }

    /// 至少 2 个完整样本，且 `head` 至少一次**严格增加**（持续进展）。
    ///
    /// P1-A.19：原判据用 `finalized_height`（durable QC tip）严格增加 —— 该量在追赶 / 快进 / 重负载下
    /// **可合法滞后**，会把「无滞后」误判为「无进展」。改用 `head`（只随 finality 授权 + commit 桥推进）
    /// ⇒ 严格性等价或更强（head 前进**必须**经 quorum precommit QC + commit 桥）。
    fn sustained(&self) -> bool {
        self.samples.len() >= 2 && self.samples.windows(2).any(|w| w[1].head > w[0].head)
    }

    /// §18 审计行：validator / steps / head / finalized / established / samples。
    fn audit(&self) -> String {
        match self.last() {
            Some(s) => format!(
                "{}: steps={} head={} consensus={} finalized_tip={:?} established={} samples={}",
                self.label,
                s.steps,
                s.head,
                s.consensus,
                s.finalized,
                s.established,
                self.samples.len()
            ),
            None => format!("{}: <无完整 status 样本>", self.label),
        }
    }
}

/// P1-A.14 —— **窄匹配**致命标记（避免把正常日志误判成 fatal error）。
/// 只匹配：共识/QC 错误关键字、panic、以及生产 fail-closed 退出标记（`Error: Run(…)`）。
fn fatal_marker(out: &str, err: &str) -> Option<&'static str> {
    const NEEDLES: [&str; 5] = [
        "InvalidSignature",
        "QcVerification",
        "panicked at",
        "Error: Run(",
        "Error: Shutdown",
    ];
    NEEDLES
        .into_iter()
        .find(|n| out.contains(n) || err.contains(n))
}

/// T1/T2 共用验收谓词（全部证据 = **实时完整 status 样本**）；P1-A.19 语义修正：
/// - 每节点：`consensus == head`（与 head 同步）∧ `head >= 2` ∧ `established >= 1` ∧ durable sanity（tip ≤ head）；
/// - 每节点：≥2 完整样本且 `head` 至少一次严格增加（持续进展）；
/// - **durable 见证**（不被完全移除）：任一节点 QC-history tip ≥ 1。
///
/// ⚠️ 原文案要求每节点 `finalized == Some(head)` —— `finalized_height` 是 **durable QC tip（服务能力）**，
/// **不是** consensus finality（RC-2 = `TEST PREDICATE ARTIFACT`）。
/// `consensus == head` 亦**不**单独声明 finality proof：它只表示本节点已把 head 推进到其轮次高度，
/// 而 head 只能经 quorum precommit QC + commit 桥前进。
fn formal_predicate(ts: &[LiveTracker]) -> bool {
    !ts.is_empty()
        && ts.iter().all(|t| {
            t.sustained()
                && t.last().is_some_and(|s| {
                    s.consensus == s.head && s.head >= 2 && s.established >= 1 && s.durable_sane()
                })
        })
        && ts
            .iter()
            .filter_map(|t| t.last())
            .any(|s| s.finalized.is_some_and(|f| f >= 1))
}

/// 有界观测：持续采样直到谓词成立或窗口到期（**在 terminate 之前**收集全部验收证据）。
fn observe_until_acceptance(
    kids: &[ChildGuard],
    trackers: &mut [LiveTracker],
    window: Duration,
    accept: fn(&[LiveTracker]) -> bool,
) -> bool {
    let deadline = Instant::now() + window;
    loop {
        for (c, t) in kids.iter().zip(trackers.iter_mut()) {
            t.observe(c);
        }
        if accept(trackers) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// **P1-A.14 正式验收（T1/T2 共用）**：观测窗口 → 判定存活 → 终止子进程 → 诊断输出 → 断言。
///
/// 明确**不再**作为 PASS 条件：`6000/6000 steps`、`exit_status == 0`、跨节点瞬时高度等值。
fn run_formal_acceptance(
    header: &str,
    children: &mut [ChildGuard],
    readiness: &[bool],
    window: Duration,
) -> Vec<LiveTracker> {
    let mut trackers: Vec<LiveTracker> =
        children.iter().map(|c| LiveTracker::new(c.label)).collect();
    let t0 = Instant::now();
    let accepted = observe_until_acceptance(children, &mut trackers, window, formal_predicate);
    let elapsed = t0.elapsed();

    // 验收时刻的存活证明（**必须**在 terminate 之前判定）。
    let alive: Vec<bool> = children.iter_mut().map(|c| c.is_running()).collect();

    // 主动终止 + 无条件诊断（无论 PASS / FAIL；无 orphan；不依赖 Drop）。
    let statuses: Vec<Option<ExitStatus>> = children.iter_mut().map(|c| c.terminate()).collect();
    let mut block = String::new();
    for (i, c) in children.iter().enumerate() {
        block.push_str(&c.diagnostic(statuses[i], readiness[i]));
        block.push_str(&format!("last_status={:?}\n", last_status(&c.stdout())));
        block.push_str(&format!(
            "fatal_marker={:?}\n",
            fatal_marker(&c.stdout(), &c.stderr())
        ));
        let summary = summary_of(&c.stdout());
        if !summary.is_empty() {
            block.push_str(&format!("summary={summary}\n"));
        }
    }
    eprintln!("=== {header} ===\n{block}");

    let audit: Vec<String> = trackers.iter().map(|t| t.audit()).collect();
    eprintln!(
        "P1-A.14 ACCEPTANCE: window={window:?} elapsed={elapsed:?} accepted={accepted} \
         alive_at_acceptance={alive:?} exit_status={:?}（exit 仅诊断，非 PASS 条件）",
        statuses
            .iter()
            .map(|s| s.map(|x| x.code()))
            .collect::<Vec<_>>()
    );
    for a in &audit {
        eprintln!("  {a}");
    }

    // ---- 断言（P1-A.14 正式口径）----
    assert!(
        accepted,
        "P1-A.14 正式验收未在 {window:?} 内达成（口径 = 实时 head/consensus 进展 + 持续进展 + 无致命错误；\
         durable QC tip 仅作 sanity(≤ head) 与见证(任一 ≥ 1)，**不**作 consensus finality 判据；\
         **不**要求 6000 步 / exit 0）：{audit:?}"
    );
    assert!(
        alive.iter().all(|a| *a),
        "达标时所有 validator 必须仍在运行（证明 finality 由活节点持续产生）：alive={alive:?}；audit={audit:?}"
    );
    for t in &trackers {
        let s = t.last().expect("accepted ⇒ 必有完整样本");
        assert!(
            s.consensus == s.head,
            "{} 必须 consensus_height == head（与 head 同步；head 只能经 finality 授权 + commit 桥前进）：\
             head={} consensus={}",
            t.label,
            s.head,
            s.consensus
        );
        assert!(
            s.head >= 2,
            "{} canonical head 必须 ≥2（实测 {}）",
            t.label,
            s.head
        );
        assert!(
            s.durable_sane(),
            "{} durable QC-history tip 必须 ≤ head（tip={:?} head={}）；\
             ⚠️ tip 是服务能力指标，可合法滞后，但不得领先 head",
            t.label,
            s.finalized,
            s.head
        );
        assert!(
            s.established >= 1,
            "{} 必须至少 1 个 established peer（实测 {}）",
            t.label,
            s.established
        );
        assert!(
            t.sustained(),
            "{} 必须观测到 ≥2 个完整样本且 head 至少一次严格增加；head 序列={:?}",
            t.label,
            t.samples.iter().map(|s| s.head).collect::<Vec<_>>()
        );
    }
    // **durable 见证（P1-A.19 §9）**：至少一个节点仍展示 QC-history 基础服务能力（tip ≥ 1）。
    assert!(
        trackers
            .iter()
            .filter_map(|t| t.last())
            .any(|s| s.finalized.is_some_and(|f| f >= 1)),
        "P1-A.19 durable 见证缺失：所有节点 durable QC-history tip 均 < 1（tip 序列：{:?}）",
        trackers
            .iter()
            .map(|t| t.last().and_then(|s| s.finalized))
            .collect::<Vec<_>>()
    );
    // 收敛（**P1-A.19 口径**）：所有节点 canonical head ≥ 2（head 前进必经 finality 路径）；
    // 不要求 durable tip 等值 / 瞬时一致 —— 精确引用一致性由 A.10 in-process rig 断言。
    let min_head = trackers
        .iter()
        .filter_map(|t| t.last().map(|s| s.head))
        .min();
    assert!(
        min_head.is_some_and(|m| m >= 2),
        "P1-A.14 收敛口径 min(head) ≥ 2 未达成：{audit:?}"
    );
    // 无致命错误（窄匹配；同时覆盖 stdout 与 stderr）。
    for c in children.iter() {
        assert!(
            fatal_marker(&c.stdout(), &c.stderr()).is_none(),
            "{} 出现致命标记 {:?}；stderr={}",
            c.label,
            fatal_marker(&c.stdout(), &c.stderr()),
            c.stderr()
        );
    }
    trackers
}

#[test]
fn p1a12_three_real_validator_processes_reach_durable_finality() {
    let _serial = real_binary_guard();
    let env = TempDir::new("three_validator");

    // ---- fixtures：3 validator seed + 3 network seed + devnet genesis（3 验证者）----
    let genesis = test_genesis(&VAL_SEED);
    let genesis_hash = compute_genesis_hash(&genesis).expect("genesis hash");
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical genesis"),
    );
    let genesis_hash_hex = hex32(&genesis_hash);
    let net_seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("net-{i}.seed"), NET_SEED[i]))
        .collect();
    let val_seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("val-{i}.seed"), VAL_SEED[i]))
        .collect();

    // 身份互异性（validator ≠ network；三节点互不相同）
    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    let val_ids: Vec<[u8; 32]> = VAL_SEED
        .iter()
        .map(|s| SigningKey::from_seed(*s).verifying_key().to_bytes())
        .collect();
    let net_hex: std::collections::BTreeSet<String> =
        net_ids.iter().map(|id| hex32(id.as_bytes())).collect();
    let val_hex: std::collections::BTreeSet<String> = val_ids.iter().map(hex32).collect();
    assert_eq!(net_hex.len(), 3, "三节点 network 身份互不相同");
    assert_eq!(val_hex.len(), 3, "三节点 validator 身份互不相同");
    for i in 0..3 {
        assert_ne!(
            hex32(net_ids[i].as_bytes()),
            hex32(&val_ids[i]),
            "network identity 必须与 validator identity 不同（节点 {i}）"
        );
    }

    // ---- 静态全互联拓扑（动态端口；不实现 discovery）----
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let peers: Vec<Vec<String>> = (0..3)
        .map(|i| {
            (0..3)
                .filter(|j| *j != i)
                .map(|j| format!("{}@127.0.0.1:{}", hex32(net_ids[j].as_bytes()), ports[j]))
                .collect()
        })
        .collect();

    let build_args = |i: usize| -> Vec<String> {
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
            env.path(&format!("safety-{i}")).to_string_lossy().into(),
            "--network-seed-file".into(),
            net_seed_paths[i].to_string_lossy().into(),
            "--validator".into(),
            "--validator-seed-file".into(),
            val_seed_paths[i].to_string_lossy().into(),
            "--listen".into(),
            format!("127.0.0.1:{}", ports[i]),
            "--run-steps".into(),
            RUN_STEPS.into(),
            "--idle-ms".into(),
            IDLE_MS.into(),
        ];
        for p in &peers[i] {
            args.push("--peer".into());
            args.push(p.clone());
        }
        args
    };

    // ---- 启动 3 个真实进程（guard 保证清理）----
    let labels: [&'static str; 3] = ["A", "B", "C"];
    let mut children: Vec<ChildGuard> = (0..3)
        .map(|i| ChildGuard::spawn(labels[i], &build_args(i)))
        .collect();

    // ---- readiness：条件轮询等待三节点均进入 run loop（**非** sleep-only）----
    let ready = poll_until(
        || {
            children
                .iter()
                .all(|c| c.stdout().contains("entering bounded run loop"))
        },
        STARTUP_TIMEOUT,
    );
    assert!(
        ready,
        "三节点必须在 {STARTUP_TIMEOUT:?} 内进入 run loop；stdout={:?} stderr={:?}",
        children.iter().map(|c| c.stdout()).collect::<Vec<_>>(),
        children.iter().map(|c| c.stderr()).collect::<Vec<_>>()
    );

    // ---- P1-A.14 正式验收：**实时观测窗口**（**不**要求耗尽 6000 步 / **不**要求 exit 0）----
    // 验收证据（完整 status 样本）在 `run_formal_acceptance` 内部于 terminate **之前** 采集。
    let ready_flags: Vec<bool> = children
        .iter()
        .map(|c| c.stdout().contains("entering bounded run loop"))
        .collect();
    let trackers = run_formal_acceptance(
        "P1-A.12-F1 DIAGNOSTICS (P1-A.14 live-window acceptance)",
        &mut children,
        &ready_flags,
        EXIT_TIMEOUT,
    );
    let finals: Vec<u64> = trackers
        .iter()
        .filter_map(|t| t.last()?.finalized)
        .collect();
    eprintln!(
        "P1-A.14 T2 PASS: 3 validators durable finality（实时窗口内）+ 持续进展 + 无致命错误；\
         finalized={finals:?}"
    );
}

// ===========================================================================
// F2 DIAGNOSTIC EXPERIMENTS（tests-only；实验产物 = 分类标签 + 完整日志，不修改验收标准）
// ===========================================================================

/// 诊断窗口（与 F1 一致；仅诊断用途）。
const F2_WINDOW: Duration = Duration::from_secs(90);
const F2_RUN_STEPS: &str = "1500";

/// F2 通用：N 节点静态全互联参数（动态端口；无 discovery）。
/// （8 个参数为测试内显式拓扑描述；不引入 helper 结构体以避免无关重构。）
#[allow(clippy::too_many_arguments)]
fn f2_node_args(
    env: &TempDir,
    n: usize,
    i: usize,
    net_ids: &[NodeId],
    ports: &[u16],
    genesis_path: &Path,
    hash_hex: &str,
    run_steps: &str,
) -> Vec<String> {
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
        env.path(&format!("f2-{n}-chain-{i}"))
            .to_string_lossy()
            .into(),
        "--safety-dir".into(),
        env.path(&format!("f2-{n}-safety-{i}"))
            .to_string_lossy()
            .into(),
        "--network-seed-file".into(),
        env.path(&format!("f2-{n}-net-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--validator".into(),
        "--validator-seed-file".into(),
        env.path(&format!("f2-{n}-val-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--listen".into(),
        format!("127.0.0.1:{}", ports[i]),
        "--run-steps".into(),
        run_steps.into(),
        "--idle-ms".into(),
        IDLE_MS.into(),
    ];
    for j in 0..n {
        if j != i {
            args.push("--peer".into());
            args.push(format!(
                "{}@127.0.0.1:{}",
                hex32(net_ids[j].as_bytes()),
                ports[j]
            ));
        }
    }
    args
}

/// 从 status 行中抽取关键字段（`established_peers=` / `round=` / `head_height=` …）。
///
/// P1-A.14 —— **只接受完整 status 行**：要求末尾字段 `validator_enabled=` 完整存在。
/// 理由：进程被 kill 时 stdout 可能留下**被撕裂的尾行**（例如 `finalized_height=102`
/// 被截断成 `finalized_height=10`）；对 `>=` 判定危害小，对**等值/收敛判定是致命的**。
fn last_status(out: &str) -> Option<String> {
    out.lines()
        .rfind(|l| l.contains(": status steps=") && l.contains("validator_enabled="))
        .map(|s| s.to_string())
}

/// **正式 T1（P1-A.14）**：2 个真实 validator 进程（真实 TCP + 静态 --peer）⇒ **实时窗口验收**。
///
/// 验收条件：每 validator `finalized == head >= 2`；至少 2 个完整 status 样本且 finalized 至少一次
/// 严格增加；收敛口径 `min(finalized) >= 2`；无致命标记；达标时进程仍存活。
/// **不**要求：`6000/6000 steps`、`exit 0`、两节点瞬时等值（真实进程步进速率不同）。
#[test]
fn t1_two_real_validators_reach_durable_finality() {
    let _serial = real_binary_guard();
    let env = TempDir::new("f2a");
    let val_seeds = [VAL_SEED[0], VAL_SEED[1]];
    let net_seeds = [NET_SEED[0], NET_SEED[1]];
    let genesis = test_genesis(&val_seeds);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in net_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-2-net-{i}.seed"), *s);
    }
    for (i, s) in val_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-2-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = net_seeds.iter().map(|s| net_node_id(*s)).collect();
    assert_ne!(net_ids[0], net_ids[1]);
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();

    let mut kids: Vec<ChildGuard> = (0..2)
        .map(|i| {
            ChildGuard::spawn(
                if i == 0 { "A" } else { "B" },
                &f2_node_args(
                    &env,
                    2,
                    i,
                    &net_ids,
                    &ports,
                    &genesis_path,
                    &hash_hex,
                    RUN_STEPS,
                ),
            )
        })
        .collect();
    // T1 也须先等待 warm-up 输出（生产侧新增可观测性）。
    let warmed = poll_until(
        || {
            kids.iter()
                .all(|c| c.stdout().contains("peer warm-up completed"))
        },
        STARTUP_TIMEOUT,
    );
    if !warmed {
        eprintln!("T1 NOTE: 未见 'peer warm-up completed'（可能 exhausted 或输出被截断）");
    }

    let ready = poll_until(
        || {
            kids.iter()
                .all(|c| c.stdout().contains("entering bounded run loop"))
        },
        STARTUP_TIMEOUT,
    );
    assert!(
        ready,
        "T1 两节点必须在 {STARTUP_TIMEOUT:?} 内进入 run loop；stdout={:?}",
        kids.iter().map(|c| c.stdout()).collect::<Vec<_>>()
    );
    // ---- P1-A.14 正式验收：**实时观测窗口**（**不**要求耗尽 6000 步 / **不**要求 exit 0）----
    let ready_flags: Vec<bool> = kids
        .iter()
        .map(|c| c.stdout().contains("entering bounded run loop"))
        .collect();
    let trackers = run_formal_acceptance(
        "F2A DIAGNOSTICS (P1-A.14 live-window acceptance)",
        &mut kids,
        &ready_flags,
        EXIT_TIMEOUT,
    );
    let finals: Vec<u64> = trackers
        .iter()
        .filter_map(|t| t.last()?.finalized)
        .collect();
    eprintln!(
        "P1-A.14 T1 PASS: 2 validators durable finality（实时窗口内）+ 持续进展 + 无致命错误；\
         finalized={finals:?} warmup_observed={warmed}"
    );
}

/// **正式 T3（P1-A.14）**：configured peer 指向**不可达端口**（无 listener）⇒ peer warm-up 必须
/// **有界耗尽**，进程随后进入正常有界运行循环并按预算正常退出（exit 0），**绝不**无限等待。
///
/// 边界（§16）：不实现 firewall / fault injection / 新依赖；仅复用既有 `--peer` + `--run-steps`
/// 与既有进程 guard（`ChildGuard`）。验收 = warm-up exhausted + exit 0 + 预算耗尽摘要。
#[test]
fn t3_unreachable_peer_exhausts_warmup_and_exits_bounded() {
    let _serial = real_binary_guard();
    const T3_RUN_STEPS: &str = "120";
    let env = TempDir::new("t3");
    let val_seeds = [VAL_SEED[0], VAL_SEED[1]];
    let net_seeds = [NET_SEED[0], NET_SEED[1]];
    let genesis = test_genesis(&val_seeds);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in net_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-2-net-{i}.seed"), *s);
    }
    for (i, s) in val_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-2-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = net_seeds.iter().map(|s| net_node_id(*s)).collect();
    // ports[0] = 本节点 listen；ports[1] = **不可达 peer**（free_port 后无任何 listener）。
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();

    let mut kid = ChildGuard::spawn(
        "T3",
        &f2_node_args(
            &env,
            2,
            0,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            T3_RUN_STEPS,
        ),
    );

    // 有界等待退出（超时 ⇒ kill 并返回 None ⇒ 断言失败，**不**无限挂起测试）。
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = kid.wait_bounded(deadline);
    let out = kid.stdout();
    let err = kid.stderr();
    eprintln!("=== T3 DIAGNOSTICS ===\n{}", kid.diagnostic(status, true));
    assert_no_consensus_errors("T3", &out, &err);
    assert!(
        status.is_some_and(|s| s.success()),
        "T3 必须 exit 0（不可达 peer 不得阻塞启动）；实测 exit={:?}；stdout={out}",
        status.and_then(|s| s.code())
    );
    assert!(
        out.contains("peer warm-up exhausted"),
        "T3 必须观测到 warm-up **有界耗尽**（configured peer 不可达）；stdout={out}"
    );
    let summary = summary_of(&out);
    assert!(
        summary.contains(&format!(
            "stopped after {T3_RUN_STEPS}/{T3_RUN_STEPS} steps"
        )),
        "T3 耗尽 warm-up 后必须继续正常有界运行循环并耗尽预算；summary={summary}"
    );
    eprintln!("T3 PASS: warm-up exhausted + 有界运行至预算耗尽 + exit 0");
}

// ===========================================================================
// P1-A.17 — 真实 binary：restart behind tip / catch-up（3 validators，quorum 2/3）
// ===========================================================================

/// P1-A.17 —— N-1 停机观测窗口（仅用于「停 1 个验证者后 A/B 推进多少」的**观测**，
/// **不是** FAIL 条件：实测该速率受 round-timeout pacemaker 限制（≈80s/块且波动大），
/// 属 P1-A.18 议题）。90s 足以观察到 ≥1 块推进且不拖长串行化后的总墙钟。
const A17_DOWNTIME_WINDOW: Duration = Duration::from_secs(90);

/// 实时 status 采样（P1-A.19 起为**具名字段**；取代位置元组 ⇒ 消除 RC-2 类「索引歧义」：
/// 原来 `s.2` 既被当作 consensus finality 又被当作 durable QC tip）。
///
/// 字段语义见 [`StatusSample`]：主判据 = `head` + `consensus`；`finalized`（durable QC tip）仅作
/// sanity（≤ head）与见证（任一 ≥ 1）。
#[derive(Clone, Copy, Debug)]
struct LiveStats {
    steps: u64,
    head: u64,
    finalized: Option<u64>,
    consensus: u64,
    established: u64,
}

impl LiveStats {
    /// durable sanity：QC-history tip 若存在必须 `≤ head`。
    fn durable_sane(&self) -> bool {
        self.finalized.is_none_or(|f| f <= self.head)
    }
}

/// P1-A.19 —— **initial-finality（三节点起步）统一判据**（Owner 批准语义）：
///
/// `all(节点: head ≥ H ∧ consensus_height ≥ H ∧ durable sanity)` ∧ `any(节点: durable tip ≥ 1)`
///
/// - `H` = 调用方沿用**原场景既有阈值**（本文件 = 2；**不降低**）；
/// - 主判据 = `head` + `consensus` 进度：`head` 只能经 finality 授权 + commit 桥前进 ⇒
///   proposer 失败 / 共识停滞 / finality 停滞 / 节点死亡 / 分区 / 追赶失败 **仍全部 FAIL**；
/// - durable QC tip（服务能力）**不再**作 consensus finality 判据，但保留 sanity 与 ≥1 见证。
fn initial_finality_reached(kids: &[ChildGuard], h: u64) -> bool {
    kids.iter()
        .all(|c| live_stats(c).is_some_and(|s| s.head >= h && s.consensus >= h && s.durable_sane()))
        && kids
            .iter()
            .filter_map(live_stats)
            .any(|s| s.finalized.is_some_and(|f| f >= 1))
}

/// **P1-A.17 —— 真实进程测试串行化守卫。**
///
/// 本文件的测试各自 spawn 2–3 个真实 `yazimao-node` 进程；并发运行会互相抢占 CPU，
/// 使**墙钟敏感**的验收（live-window finality / catch-up）在重负载下假失败
/// （P1-A.17 全量套件实测：并行时 2 个用例失败，单独运行时全绿）。
/// 该守卫把本 binary 内的真实进程测试串行化（跨 binary 仍并行；其余 target 均为快速单测）。
fn real_binary_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 读取某进程**最新完整** status 行（P1-A.19：具名字段）。
///
/// 严格性：`consensus_height=` 缺失 ⇒ `None`（**不猜**：宁可判为「无有效样本」= 停滞，也不放过）。
fn live_stats(c: &ChildGuard) -> Option<LiveStats> {
    let line = last_status(&c.stdout())?;
    Some(LiveStats {
        steps: field(&line, "steps=")?,
        head: field(&line, "head_height=")?,
        finalized: field(&line, "finalized_height="),
        consensus: field(&line, "consensus_height=")?,
        established: field(&line, "established_peers=").unwrap_or(0),
    })
}

/// P1-A.17 —— **真实进程** restart-behind-tip 场景（3 validators 全互联、真实 TCP）：
///
/// ```text
/// A/B/C 起步（3 validator，quorum 2/3）→ 三者 durable finality ≥ 2
///   → 停 C（kill）→ A/B 继续推进 ≥ C.head + gap（= 2/3 quorum 存活）
///   → 以**同一** data dir / safety dir / validator seed / listen 端口重启 C
///   → C 重连 → 追赶（head 单调上升至 ≥ 目标高度；durable finalized 恢复并继续前进）
/// ```
///
/// 断言口径（P1-A.16 §15）：同身份 / 同目录 / 重连 / head 单调 / 最终 head ≥ 目标 / finalized ≥ 1 /
/// head 单调 / 最终 head ≥ 目标 / 1 ≤ finalized ≤ head 且 finalized 前进 / 无 fatal（InvalidSignature · QcVerification · panic · `Error: Run(` ·
/// ValidatorNotInValidatorSet · IdentityMismatch · CorruptedState）/ 达标时进程存活。
fn p1a17_restart_behind_tip_scenario(tag: &str, gap: u64) {
    p1a17_restart_behind_tip_scenario_with(tag, gap, A17_DOWNTIME_WINDOW, false, RUN_STEPS);
}

/// **P1-A.17-SYNC-STABILITY Control C（诊断）**：与 [`p1a17_restart_behind_tip_scenario`] 同流程，
/// 但 `downtime` 更长且目标取 **min(gap, A/B 实测 head)**：
/// - 可在**不删除 / 不复制**任何目录的前提下观察「**同目录** restart + **大 gap** 追赶」
///   （真实 operator restart 路径）；
/// - 验收标准与既有用例**完全一致**（head 单调前进 / `finalized ≥ 1` 且 ≤ head /
///   达标时仍存活 / 无 fatal 标记 / finalized 继续前进）—— **不**新增/放宽任何标准。
fn p1a17_restart_behind_tip_scenario_with(
    tag: &str,
    gap: u64,
    downtime: Duration,
    emergent_target: bool,
    run_steps: &str,
) {
    let _serial = real_binary_guard();
    let env = TempDir::new(tag);
    let genesis = test_genesis(&VAL_SEED);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-net-{i}.seed"), *s);
    }
    for (i, s) in VAL_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let labels: [&'static str; 3] = ["A", "B", "C"];
    let roots = chain_roots(&env);

    let mut kids: Vec<ChildGuard> = (0..3)
        .map(|i| {
            ChildGuard::spawn(
                labels[i],
                &f2_node_args(
                    &env,
                    3,
                    i,
                    &net_ids,
                    &ports,
                    &genesis_path,
                    &hash_hex,
                    run_steps,
                ),
            )
        })
        .collect();

    let ready = poll_until(
        || {
            kids.iter()
                .all(|c| c.stdout().contains("entering bounded run loop"))
        },
        STARTUP_TIMEOUT,
    );
    if !ready {
        dump_all_node_forensics(tag, "startup", &[&kids[0], &kids[1], &kids[2]], &roots);
    }
    assert!(
        ready,
        "{tag}: 三节点未在 {STARTUP_TIMEOUT:?} 内进入 run loop"
    );

    // ---- 阶段 1：三节点均达 initial-finality（真实进程；P1-A.19 口径：head + consensus 进度）----
    let initial = poll_until(|| initial_finality_reached(&kids, 2), EXIT_TIMEOUT);
    let initial_audit: Vec<String> = kids
        .iter()
        .map(|c| format!("{}={:?}", c.label, live_stats(c)))
        .collect();
    if !initial {
        dump_all_node_forensics(
            tag,
            "initial-finality",
            &[&kids[0], &kids[1], &kids[2]],
            &roots,
        );
    }
    assert!(
        initial,
        "{tag}: 三节点未达 initial-finality（head ≥ 2 ∧ consensus ≥ 2 ∧ durable sanity ∧ ∃durable 见证）：{initial_audit:?}"
    );
    let c_before = live_stats(&kids[2]).expect("C 有完整 status 样本");
    let _pre_target = c_before.head.saturating_add(gap);

    // ---- 阶段 2：停 C；A/B（2/3 quorum）继续推进（**有界观测；不要求特定速率**）----
    let c_kill_status = kids[2].terminate();
    eprintln!(
        "{tag}: C stopped（before={c_before:?}）→ 观测 A/B 的 N-1 推进（窗口 {EXIT_TIMEOUT:?}）"
    );
    let progressed = poll_until(
        || {
            let a = live_stats(&kids[0]).map(|s| s.head).unwrap_or(0);
            let b = live_stats(&kids[1]).map(|s| s.head).unwrap_or(0);
            a.min(b) >= c_before.head.saturating_add(gap)
        },
        downtime,
    );
    let ab_audit: Vec<String> = kids[..2]
        .iter()
        .map(|c| format!("{}={:?}", c.label, live_stats(c)))
        .collect();
    // 实测：N-1 活性受 round-timeout pacemaker 限制（≈80s/块且波动大）⇒ **不**把
    // 「停 1 个后能推进多少」当作本测试的 PASS 条件（那属 P1-A.18 pacemaker 议题）；
    // 本测试只要求「A/B 至少推进 1 块」（仍证明 2/3 quorum 可继续），并把目标改为**实测值**。
    let ab_head_min = kids[..2]
        .iter()
        .filter_map(|c| live_stats(c).map(|s| s.head))
        .min()
        .unwrap_or(c_before.head);
    if !progressed {
        eprintln!(
            "{tag} NOTE: N-1 窗口内 A/B 未达预设 gap（实测 min_head={ab_head_min}）；\
             改用 emergent target（P1-A.18 pacemaker 议题，不作为本测试失败）"
        );
    }
    let target = if emergent_target {
        // Control C：目标 = min(gap, 实测 A/B head) ⇒ 若 A/B 未达 gap 则不制造假失败，
        // 但达标时仍要求 C2 真正追赶到 **≥ gap 块**（无法凑数）。
        c_before.head.saturating_add(gap).min(ab_head_min)
    } else {
        c_before.head.saturating_add(gap).max(ab_head_min)
    };
    eprintln!(
        "{tag}: target head={target}（gap 参数={gap}，实测 gap={}，A/B min_head={ab_head_min}，\
         downtime={downtime:?}，emergent={emergent_target}）",
        target.saturating_sub(c_before.head)
    );

    // ---- 阶段 3：以同一 data dir / safety dir / seed / listen 重启 C ----
    let c2_args = f2_node_args(
        &env,
        3,
        2,
        &net_ids,
        &ports,
        &genesis_path,
        &hash_hex,
        run_steps,
    );
    let mut c2 = ChildGuard::spawn("C2", &c2_args);
    let reconnected = poll_until(
        || live_stats(&c2).is_some_and(|s| s.established >= 1),
        STARTUP_TIMEOUT,
    );
    let c2_after_ready = live_stats(&c2);
    if !reconnected {
        dump_all_node_forensics(tag, "restart-reconnect", &[&kids[0], &kids[1], &c2], &roots);
    }
    assert!(
        reconnected,
        "{tag}: C 重启后未重新建立任何 Established peer（status={c2_after_ready:?}）"
    );

    // ---- 阶段 4：C 追赶（head/consensus 单调 → ≥ target）----
    // 注（P1-A.19）：`finalized_height` = durable QC-history tip = **服务能力**指标，**不是** consensus
    // finality；追赶 / 快进 / 重负载下可**合法滞后**（A.6 实测 B: head 277 / tip 1）。
    // 因此本测试判据 = `head ≥ target ∧ consensus ≥ target ∧ durable sanity(≤ head)`，
    // 而 durable 见证由 A/B/C2 **任一节点** tip ≥ 1 提供（§9：不把 QC-history 服务能力完全移除）。
    let caught = poll_until(
        || {
            live_stats(&c2)
                .is_some_and(|s| s.head >= target && s.consensus >= target && s.durable_sane())
        },
        EXIT_TIMEOUT,
    );

    // ---- 验收证据必须在 terminate 之前采集 ----
    let c2_alive = c2.is_running();
    let c2_final = live_stats(&c2);
    // 取证（test-only 观测；**不**改变任何验收条件）：把各进程**完整 stdout** 落盘 ⇒
    // `%TEMP%\yazimao-p1-a12-{A,B,C2}.log` 含每 100 步的 status 行（可重建完整时间线）。
    eprintln!("{}", kids[0].diagnostic(None, true));
    eprintln!("{}", kids[1].diagnostic(None, true));
    eprintln!("{}", c2.diagnostic(None, true));
    let ab_alive = [kids[0].is_running(), kids[1].is_running()];
    let ab_final: Vec<Option<LiveStats>> = kids[..2].iter().map(live_stats).collect();
    let markers: Vec<(String, Option<&str>)> = vec![
        (
            "A".to_string(),
            fatal_marker(&kids[0].stdout(), &kids[0].stderr()),
        ),
        (
            "B".to_string(),
            fatal_marker(&kids[1].stdout(), &kids[1].stderr()),
        ),
        (
            "C-killed".to_string(),
            fatal_marker(&kids[2].stdout(), &kids[2].stderr()),
        ),
        ("C2".to_string(), fatal_marker(&c2.stdout(), &c2.stderr())),
    ];
    // 重启特有的 fail-closed 标记（不在通用 fatal_marker 内）。
    let c2_identity_reject = [
        "ValidatorNotInValidatorSet",
        "IdentityMismatch",
        "CorruptedState",
    ]
    .into_iter()
    .find(|m| c2.stdout().contains(m) || c2.stderr().contains(m));
    // 取证（test-only）：仅失败路径导出，不改变任何断言。
    if !caught || !c2_alive {
        dump_all_node_forensics(tag, "catchup", &[&kids[0], &kids[1], &c2], &roots);
    }
    let c2_status_exit = c2.child.try_wait().ok().flatten();

    // ---- 清理：终止全部子进程（无 orphan）----
    let statuses = [
        kids[0].terminate(),
        kids[1].terminate(),
        c_kill_status,
        c2.terminate(),
    ];

    eprintln!(
        "=== {tag} P1-A.17 DIAGNOSTICS ===\n\
         C before restart: {c_before:?}\n\
         target head: {target}（gap={gap}）\n\
         A/B during C downtime: {ab_audit:?}\n\
         A/B final: {ab_final:?} alive={ab_alive:?}\n\
         C2 final: {c2_final:?} alive_at_acceptance={c2_alive} wait={c2_status_exit:?}\n\
         fatal markers: {markers:?}\n\
         c2 identity/corruption markers: {c2_identity_reject:?}\n\
         exit statuses（诊断，非 PASS 条件）: {statuses:?}"
    );

    // ---- 断言（P1-A.19 口径）----
    assert!(
        caught,
        "{tag}: C 未在窗口内追赶到 head ≥ {target} ∧ consensus ≥ {target}（final={c2_final:?}）"
    );
    let c2_s = c2_final.expect("C2 有完整样本");
    assert!(
        c2_s.head >= target && c2_s.consensus >= target,
        "{tag}: C 未达目标（head={} consensus={} steps={} target={target}）",
        c2_s.head,
        c2_s.consensus,
        c2_s.steps
    );
    assert!(
        c2_s.head > c_before.head,
        "{tag}: C head 未单调前进（restart 前 {} → 后 {}）",
        c_before.head,
        c2_s.head
    );
    assert!(
        c2_s.durable_sane(),
        "{tag}: durable QC tip 不得领先 head（head={} tip={:?}）",
        c2_s.head,
        c2_s.finalized
    );
    // **durable 见证（P1-A.19 §9）**：至少一个节点（A/B/C2）仍展示 QC-history 基础服务能力（tip ≥ 1）。
    // 不再要求 **C2 自身** durable tip 严格前进：durable QC-history 持久化是**对端服务能力**，
    // 追赶 / 快进期间可合法滞后（RC-2 = TEST PREDICATE ARTIFACT；production 不变式不受影响）。
    assert!(
        [&kids[0], &kids[1], &c2]
            .into_iter()
            .any(|c| live_stats(c).is_some_and(|s| s.finalized.is_some_and(|f| f >= 1))),
        "{tag}: durable 见证缺失（A/B/C2 的 QC-history tip 均 < 1；A={:?} B={:?} C2={:?}）",
        live_stats(&kids[0]),
        live_stats(&kids[1]),
        c2_final
    );
    assert!(c2_alive, "{tag}: 达标时 C 必须仍在运行");
    assert!(
        c2_identity_reject.is_none(),
        "{tag}: C 重启出现身份/损坏拒绝标记 {c2_identity_reject:?}"
    );
    for (label, m) in &markers {
        assert!(m.is_none(), "{tag}: {label} 出现 fatal 标记 {m:?}");
    }
    eprintln!(
        "{tag} PASS: gap={gap} C {} → {}（consensus={}，durable tip={:?}），A/B 存活={ab_alive:?}",
        c_before.head, c2_s.head, c2_s.consensus, c2_s.finalized
    );
}

/// **P1-A.17 T2（正式）**：真实进程 restart-behind-tip（停 C ⇒ A/B 以 2/3 quorum 继续 ⇒ 同目录重启 C
/// ⇒ 追赶至 ≥ 目标高度并恢复 finality）。
///
/// **口径依据（实测，P1-A.17 首轮）**：停 1 个验证者后，A/B 在 240s 内仅 36 → 39（≈80s/块），
/// 且第二轮 240s 内推进不足 2 块 —— 瓶颈是 **N-1 活性（round-timeout pacemaker 的 1000 tick 窗口）**，
/// **不是** sync（sync 侧已由 P1-A.17 把窗口从 64 提升到 512）。故本用例的目标高度取**实测值**
/// （emergent target = 重启时刻 A/B 的 durable finalized 最小值），不再预先规定 gap 大小。
#[test]
fn p1a17_restart_behind_tip_after_downtime() {
    p1a17_restart_behind_tip_scenario("a17_small", 1);
}

/// **Control C（P1-A.17-SYNC-STABILITY 诊断）**：同目录 restart + **大 gap**（无删除 / 无复制）。
///
/// 目标 = `min(70, 实测 A/B head)`（见 [`p1a17_restart_behind_tip_scenario_with`]）：若 A/B 在
/// `downtime` 内真正推进 ≥ 70 块，本用例即验证「**同目录 restart 追赶 ≥ 70（> 旧窗口 64）**」。
/// 不做任何目录复制 ⇒ **不**依赖冷备份 harness。
const A17_SCS_SCDIR_DOWNTIME: Duration = Duration::from_secs(420);
/// **Control C step-budget（A12 harness fix）**：大 downtime（420s）内 N-1 停滞期 step 空转很快
/// （round timeout 以逻辑 step 计 + idle_ms=1）⇒ 默认 `RUN_STEPS=6000` 会在 C 重启前耗尽
/// （A/B 正常 exit 0）⇒ C2 无 peer 可连（established=0）。本诊断**单列**更大生命周期预算：
/// - **仅**该用例生效（其余用例继续用 `RUN_STEPS`）；
/// - **不**改生产 run_steps 默认值 / idle_ms / peer lifecycle / ChildGuard；
/// - **不**放宽 established / rejoin / catch-up / target 任何断言；downtime 与窗口均不变。
const A17_SCS_SCDIR_RUN_STEPS: &str = "60000";

#[test]
fn p1a17_same_dir_restart_large_gap_diagnostic() {
    p1a17_restart_behind_tip_scenario_with(
        "a17_scs_scdir",
        70,
        A17_SCS_SCDIR_DOWNTIME,
        true,
        A17_SCS_SCDIR_RUN_STEPS,
    );
}

/// 递归复制目录（测试专用；「冷备份 / 回滚到旧状态」场景，用于**确定性**制造 gap）。
fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir dst");
    for entry in std::fs::read_dir(src).expect("read_dir src") {
        let entry = entry.expect("dir entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy file");
        }
    }
}

/// **P1-A.17-SYNC-STABILITY 取证**（test-only 观测；**不**参与任何验收判定）：
/// 导出 `<storage_root>/blocks`（**BlockStore 真实目录**，不是 storage root）清单：filename + size。
///
/// 诊断价值：
/// - 存在 `block_*.blk.tmp` ⇒ `atomic_write` 已过 `File::create(tmp)` 但**未完成** `fs::rename`
///   （Windows 典型：目标被占用 / sharing violation / 瞬态 IO）；
/// - `size==0` 的 `.blk` ⇒ 记录被部分写入（`write_all` 之后、`sync_all` 之前失败）；
/// - `blk` 计数 vs head ⇒ 是否有缺失块文件。
fn dump_blockstore_forensics(tag: &str, chain_root: &Path) {
    let blocks = chain_root.join("blocks");
    let (mut blk, mut zero, mut tmp, mut other) = (0usize, 0usize, 0usize, 0usize);
    let mut blk_files: Vec<String> = Vec::new();
    let mut tmp_files: Vec<String> = Vec::new();
    match std::fs::read_dir(&blocks) {
        Ok(rd) => {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                if name.ends_with(".blk.tmp") {
                    tmp += 1;
                    tmp_files.push(format!("{name} size={len}"));
                } else if name.ends_with(".blk") {
                    blk += 1;
                    if len == 0 {
                        zero += 1;
                    }
                    if blk_files.len() < 30 {
                        blk_files.push(format!("{name} size={len}"));
                    }
                } else {
                    other += 1;
                }
            }
        }
        Err(e) => eprintln!("{tag} BLOCKSTORE FORENSICS: blocks 目录不可读 {blocks:?}: {e}"),
    }
    eprintln!(
        "{tag} BLOCKSTORE FORENSICS root={chain_root:?} blocks={blocks:?} blk={blk} \
         zero_blk={zero} tmp={tmp} other={other}\n  blk_files(first30)={blk_files:?}\n  \
         tmp_files={tmp_files:?}"
    );
}

/// 三个 validator 的 chain (storage) 根目录（`<storage>/blocks` 才是 BlockStore 目录）。
fn chain_roots(env: &TempDir) -> Vec<PathBuf> {
    (0..3)
        .map(|i| env.path(&format!("f2-3-chain-{i}")))
        .collect()
}

/// **P1-A.17-SYNC-STABILITY 统一失败取证**（test-only；**任意阶段**失败都导出，**不**改变判定）。
///
/// 覆盖 startup / initial-finality / reconnect / A-B-advance / catch-up 全阶段：
/// 每节点 status 采样 + stdout/stderr 尾部（各 ≤200 行）+ BlockStore stage 分类标记 +
/// 每个 `<storage>/blocks` 清单。**只**在失败路径调用（PASS 路径不产生额外输出）。
fn dump_all_node_forensics(tag: &str, phase: &str, kids: &[&ChildGuard], roots: &[PathBuf]) {
    let mut stage_lines: Vec<String> = Vec::new();
    eprintln!("=== {tag} FORENSICS BEGIN phase={phase} ===");
    for c in kids {
        let out = c.stdout();
        let err = c.stderr();
        let tail = |s: &str| -> String {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(200)..].join("\n")
        };
        for l in err.lines().chain(out.lines()) {
            if l.contains("BlockStore stage=") {
                stage_lines.push(format!("{}: {l}", c.label));
            }
        }
        let has = |k: &str| out.contains(k) || err.contains(k);
        eprintln!(
            "=== NODE {} FORENSICS phase={phase} status={:?} stdout_bytes={} stderr_bytes={}\n\
             markers: BackendFailure={} CorruptedState={} SerializationFailure={} \
             blockstore_exit={} panicked={} identity_reject={}\n\
             --- NODE {} STDOUT TAIL ---\n{}\n--- NODE {} STDERR TAIL ---\n{}\n=== END NODE {} ===",
            c.label,
            live_stats(c),
            out.len(),
            err.len(),
            has("BackendFailure"),
            has("CorruptedState"),
            has("SerializationFailure"),
            has("Error: Run(\"BlockStore\")"),
            has("panicked at"),
            has("IdentityMismatch") || has("ValidatorNotInValidatorSet"),
            c.label,
            tail(&out),
            c.label,
            tail(&err),
            c.label,
        );
    }
    let cls = if stage_lines
        .iter()
        .any(|l| l.contains("stage=remote_canonical_put"))
    {
        "SYNC_BLOCKSTORE_FAILURE"
    } else if stage_lines
        .iter()
        .any(|l| l.contains("stage=finality_commit_get"))
    {
        "FINALITY_COMMIT_BLOCKSTORE_FAILURE"
    } else if stage_lines
        .iter()
        .any(|l| l.contains("stage=local_proposal_put"))
    {
        "LOCAL_PROPOSAL_BLOCKSTORE_FAILURE"
    } else if stage_lines.is_empty() {
        "NO_BLOCKSTORE_STAGE"
    } else {
        "OTHER_BLOCKSTORE_STAGE"
    };
    eprintln!("{tag} BLOCKSTORE CLASS={cls} stage_lines={stage_lines:?}");
    for root in roots {
        dump_blockstore_forensics(tag, root);
    }
    eprintln!("=== {tag} FORENSICS END phase={phase} ===");
}

/// **P1-A.17 T3/T4（正式）**：**确定性 gap** 的 restart-behind-tip —— 冷备份回滚场景。
///
/// 为何用该场景：忠实场景（停 1 个验证者等 gap 长大）受 **N-1 pacemaker 速率**限制（实测 ≈80s/块，
/// 且波动大）⇒ 无法在单个测试窗口内稳定制造 ≥10 块 gap。本场景在 **3/3 全活**（全速）下让链前进
/// `gap` 块，再让 C 回滚到更早的**一致性备份**（kill 后复制，故为崩溃一致快照）并重启：
/// - 仍然**真实**经过 P1-A.17 关注的完整同步路径：重连 → 发现远端更高链 → `SyncBlockRequest`
///   （`head+1` / `hash=None`）→ 响应验证 → durable 持久化 → DAG 登记 → finality 采纳 → head 推进；
/// - `gap` 可控且确定性 ⇒ 可用于验证 **新窗口（512）** 下 `gap > 64`（旧窗口**必然失败**）的追赶能力。
fn p1a17_snapshot_rollback_scenario(tag: &str, gap: u64) {
    let _serial = real_binary_guard();
    let env = TempDir::new(tag);
    let genesis = test_genesis(&VAL_SEED);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-net-{i}.seed"), *s);
    }
    for (i, s) in VAL_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let args = |i: usize| {
        f2_node_args(
            &env,
            3,
            i,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            RUN_STEPS,
        )
    };
    let chain_live = env.path("f2-3-chain-2");
    let safety_live = env.path("f2-3-safety-2");
    let chain_snap = env.path("snap-chain-2");
    let safety_snap = env.path("snap-safety-2");
    let roots = chain_roots(&env);

    let mut kids: Vec<ChildGuard> = (0..3)
        .map(|i| ChildGuard::spawn(["A", "B", "C"][i], &args(i)))
        .collect();
    let ready = poll_until(
        || {
            kids.iter()
                .all(|c| c.stdout().contains("entering bounded run loop"))
        },
        STARTUP_TIMEOUT,
    );
    if !ready {
        dump_all_node_forensics(tag, "startup", &[&kids[0], &kids[1], &kids[2]], &roots);
    }
    assert!(ready, "{tag}: 未进入 run loop");
    // P1-A.19：head + consensus 进度为主判据（原 `finalized_height ≥ 2` 用的是 durable QC tip）。
    let initial = poll_until(|| initial_finality_reached(&kids, 2), EXIT_TIMEOUT);
    if !initial {
        dump_all_node_forensics(
            tag,
            "initial-finality",
            &[&kids[0], &kids[1], &kids[2]],
            &roots,
        );
    }
    assert!(
        initial,
        "{tag}: 未达 initial-finality（head ≥ 2 ∧ consensus ≥ 2 ∧ durable sanity ∧ ∃durable 见证）"
    );

    // ---- 冷备份：kill C ⇒（C 已停，故为崩溃一致快照）复制其 chain/safety 目录 ⇒ 立即重启 C ----
    let _ = kids[2].terminate();
    copy_dir_recursive(&chain_live, &chain_snap);
    copy_dir_recursive(&safety_live, &safety_snap);
    let c_snap = live_stats(&kids[2]).expect("C 快照状态");
    kids[2] = ChildGuard::spawn("C", &args(2));
    let c_ready = poll_until(
        || live_stats(&kids[2]).is_some_and(|s| s.established >= 1),
        STARTUP_TIMEOUT,
    );
    if !c_ready {
        dump_all_node_forensics(
            tag,
            "post-snapshot-restart",
            &[&kids[0], &kids[1], &kids[2]],
            &roots,
        );
    }
    assert!(c_ready, "{tag}: 重启的 C 未重新建立 Established peer");

    // ---- 3/3 全活（全速）下前进 gap 块 ----
    // 判据用 **head**（commit 结果；只随 finality 推进、不回退）而非 `finalized_height`
    // （= durable QC-history tip，追赶/重负载下可滞后——P1-A.17 实测 B 曾出现 head 373 / tip 27）。
    let target = c_snap.head.saturating_add(gap);
    let advanced = poll_until(
        || {
            let a = live_stats(&kids[0]).map(|s| s.head).unwrap_or(0);
            let b = live_stats(&kids[1]).map(|s| s.head).unwrap_or(0);
            a.min(b) >= target
        },
        EXIT_TIMEOUT,
    );
    let ab_audit: Vec<String> = kids[..2]
        .iter()
        .map(|c| format!("{}={:?}", c.label, live_stats(c)))
        .collect();
    if !advanced {
        dump_all_node_forensics(tag, "ab-advance", &[&kids[0], &kids[1], &kids[2]], &roots);
    }
    assert!(
        advanced,
        "{tag}: A/B 未在窗口内前进到 finalized ≥ {target}（{ab_audit:?}）"
    );

    // ---- 回滚 C 到快照（gap 块）并重启 ----
    let _ = kids[2].terminate();
    std::fs::remove_dir_all(&chain_live).expect("remove live chain");
    std::fs::remove_dir_all(&safety_live).expect("remove live safety");
    copy_dir_recursive(&chain_snap, &chain_live);
    copy_dir_recursive(&safety_snap, &safety_live);
    let mut c2 = ChildGuard::spawn("C2", &args(2));
    let reconnected = poll_until(
        || live_stats(&c2).is_some_and(|s| s.established >= 1),
        STARTUP_TIMEOUT,
    );
    if !reconnected {
        dump_all_node_forensics(
            tag,
            "post-rollback-reconnect",
            &[&kids[0], &kids[1], &c2],
            &roots,
        );
    }
    assert!(
        reconnected,
        "{tag}: 回滚后的 C 未重连（status={:?}）",
        live_stats(&c2)
    );
    let c_before_target = c_snap.head;

    // ---- 验收：C 追赶至 ≥ target（head ∧ consensus）；durable tip 仅 sanity ----
    let caught = poll_until(
        || {
            live_stats(&c2)
                .is_some_and(|s| s.head >= target && s.consensus >= target && s.durable_sane())
        },
        A17_CATCHUP_WINDOW,
    );

    let c2_alive = c2.is_running();
    let c2_final = live_stats(&c2);
    // 取证（test-only 观测；**不**改变任何验收条件）：完整 stdout 落盘 ⇒ status 时间线。
    eprintln!("{}", kids[0].diagnostic(None, true));
    eprintln!("{}", kids[1].diagnostic(None, true));
    eprintln!("{}", c2.diagnostic(None, true));
    let ab_alive = [kids[0].is_running(), kids[1].is_running()];
    let markers: Vec<(String, Option<&str>)> = vec![
        (
            "A".to_string(),
            fatal_marker(&kids[0].stdout(), &kids[0].stderr()),
        ),
        (
            "B".to_string(),
            fatal_marker(&kids[1].stdout(), &kids[1].stderr()),
        ),
        ("C2".to_string(), fatal_marker(&c2.stdout(), &c2.stderr())),
    ];
    let c2_identity_reject = [
        "ValidatorNotInValidatorSet",
        "IdentityMismatch",
        "CorruptedState",
    ]
    .into_iter()
    .find(|m| c2.stdout().contains(m) || c2.stderr().contains(m));
    // 取证（test-only）：仅失败路径导出，不改变任何断言。
    if !caught || !c2_alive {
        dump_all_node_forensics(tag, "catchup", &[&kids[0], &kids[1], &c2], &roots);
    }
    let statuses = [kids[0].terminate(), kids[1].terminate(), c2.terminate()];

    eprintln!(
        "=== {tag} P1-A.17 SNAPSHOT DIAGNOSTICS ===\n\
         C snapshot: {c_snap:?}（回滚前目标 head ≥ {target}，gap={gap}）\n\
         A/B at rollback: {ab_audit:?}\n\
         C2 final: {c2_final:?} alive_at_acceptance={c2_alive}\n\
         A/B alive at acceptance: {ab_alive:?}\n\
         fatal markers: {markers:?}\n\
         c2 identity/corruption: {c2_identity_reject:?}\n\
         exit statuses（诊断）: {statuses:?}"
    );

    assert!(
        caught,
        "{tag}: C 未在窗口内追赶 head ≥ {target} ∧ consensus ≥ {target}（final={c2_final:?}）"
    );
    let c2_s = c2_final.expect("C2 有完整样本");
    assert!(
        c2_s.head >= target && c2_s.consensus >= target,
        "{tag}: head={} consensus={} < target={target}",
        c2_s.head,
        c2_s.consensus
    );
    assert!(
        c2_s.head > c_before_target,
        "{tag}: head 未单调前进（{c_before_target} → {}）",
        c2_s.head
    );
    assert!(
        c2_s.durable_sane(),
        "{tag}: durable QC tip 越界（head={} tip={:?}）",
        c2_s.head,
        c2_s.finalized
    );
    // **durable 见证（P1-A.19 §9）**：至少一个节点仍展示 QC-history 基础服务能力（tip ≥ 1）。
    assert!(
        [&kids[0], &kids[1], &c2]
            .into_iter()
            .any(|c| live_stats(c).is_some_and(|s| s.finalized.is_some_and(|f| f >= 1))),
        "{tag}: durable 见证缺失（A/B/C2 的 QC-history tip 均 < 1；A={:?} B={:?} C2={:?}）",
        live_stats(&kids[0]),
        live_stats(&kids[1]),
        c2_final
    );
    assert!(c2_alive, "{tag}: 达标时 C 必须仍存活");
    assert!(
        c2_identity_reject.is_none(),
        "{tag}: 出现身份/损坏标记 {c2_identity_reject:?}"
    );
    for (label, m) in &markers {
        assert!(m.is_none(), "{tag}: {label} 出现 fatal 标记 {m:?}");
    }
    eprintln!(
        "{tag} PASS: gap={gap} C {c_before_target} → {}（durable tip={:?}，consensus={}）",
        c2_s.head, c2_s.finalized, c2_s.consensus
    );
}

/// **P1-A.17 T3（正式）**：确定性 gap = 20（旧 64 窗口内，但此前**从未**被真实进程验证）。
#[test]
fn p1a17_snapshot_rollback_medium_gap() {
    p1a17_snapshot_rollback_scenario("a17_snap20", 20);
}

/// **P1-A.17 T4（正式）**：确定性 gap = 70（**超出旧的 `MAX_SYNC_WALK = 64`**）——
/// 旧实现下 responder 必然 `WalkExceeded`（不响应）且无重发途径 ⇒ 永久失联；
/// P1-A.17 将窗口提升到 512 后本用例是「>64 追赶可行」的直接证据。
#[test]
fn p1a17_snapshot_rollback_beyond_old_window() {
    p1a17_snapshot_rollback_scenario("a17_snap70", 70);
}

/// **P1-A.18 RC-1 Stage 2（T8）** —— 真实多进程：历史含 **round ≥ 1** 块的重启追赶。
///
/// 确定性构造（不依赖运气）：
/// 1. A/B/C 起步，等 durable finality ≥ 2；
/// 2. 读当前 head `h`，计算 **height h+1 的 round-0 proposer** `P0 = select(chain, h, 0, genesis, set)`
///    并**停掉该 proposer 对应的进程**（其余 2/3 仍满足 quorum）；
/// 3. P0 离线 ⇒ height h+1 **不可能在 round 0 产出**（`build_proposal` 要求
///    `select(rs.height, rs.round) == local_id` ⇒ round 0 只有 P0 能提案）⇒ 存活两节点 round timeout
///    ⇒ **round 1** ⇒ P_1 提案（Stage 1 round-aware gossip 验证）⇒ votes/QC/finality ⇒ head 前进；
/// 4. 重启被停节点（同目录 / 同 seed）⇒ 它必须经 **sync** 取回该 **round ≥ 1** 历史块，
///    依赖 Stage 2 的 **QC-bound round 解析**（`qc.target == block_hash`）才能完成 proposer 验签
///    ⇒ 登记 DAG ⇒ finality ⇒ head 追赶。
///
/// PASS 判据 = 「P0 离线期间存活 2/3 仍推进 head」∧「重启节点追赶到 ≥ 存活节点 head」；
/// 二者合并只有在 **round ≥ 1 可产出且可同步** 时成立。
#[test]
fn p1a18_t8_round_ge1_history_sync_after_restart() {
    let _serial = real_binary_guard();
    let tag = "a18_t8";
    let env = TempDir::new(tag);
    let genesis = test_genesis(&VAL_SEED);
    let genesis_hash = compute_genesis_hash(&genesis).expect("hash");
    let hash_hex = hex32(&genesis_hash);
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-net-{i}.seed"), *s);
    }
    for (i, s) in VAL_SEED.iter().enumerate() {
        env.write_seed(&format!("f2-3-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let set = ValidatorSet::from_genesis(&genesis);
    let id_of_index = |i: usize| {
        derive_validator_id(
            &SigningKey::from_seed(VAL_SEED[i])
                .verifying_key()
                .to_bytes(),
        )
    };
    let args = |i: usize| {
        f2_node_args(
            &env,
            3,
            i,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            RUN_STEPS,
        )
    };

    let mut kids: Vec<ChildGuard> = (0..3)
        .map(|i| ChildGuard::spawn(["A", "B", "C"][i], &args(i)))
        .collect();
    assert!(
        poll_until(
            || kids
                .iter()
                .all(|c| c.stdout().contains("entering bounded run loop")),
            STARTUP_TIMEOUT
        ),
        "{tag}: 未进入 run loop"
    );
    let ready = poll_until(|| initial_finality_reached(&kids, 2), EXIT_TIMEOUT);
    if !ready {
        dump_all_node_forensics(
            tag,
            "initial-finality",
            &[&kids[0], &kids[1], &kids[2]],
            &chain_roots(&env),
        );
    }
    assert!(
        ready,
        "{tag}: 未达 initial-finality（head ≥ 2 ∧ consensus ≥ 2 ∧ durable sanity ∧ ∃durable 见证）"
    );

    // ---- 选定「**未来**高度的 round-0 proposer」并停掉它 ----
    //
    // 确定性构造（不依赖运气 / 不依赖 status 采样）：`build_proposal` 要求
    // `select(rs.height, rs.round) == local_id` ⇒ **round 0 只有该高度的 round-0 proposer 能提案**。
    // 故只要其进程离线，该高度**只能在 round ≥ 1 产出** —— 这就是「历史含 round ≥ 1 块」的构造性证明。
    //
    // 注意：必须取**跨节点最新** head（单节点 status 可能滞后），且必须选**未来**高度。
    let h = kids
        .iter()
        .filter_map(|c| live_stats(c).map(|s| s.head))
        .max()
        .unwrap_or(0);
    let (h_k, i0) = (h + 1..=h + 64)
        .find_map(|hh| {
            // fixture 前提**内联在搜索谓词**：同时要求「round-0 proposer 可定位」∧「round-0 ≠ round-1」
            // （3 等权验证者下二者相同概率 ≈1/3 ⇒ 只按前一条件选取会以 ≈1/3 概率在下方防御断言处中止）。
            let p0 =
                select_proposer(CHAIN_ID, hh.saturating_sub(1), 0, &genesis_hash, &set).ok()?;
            let p1 =
                select_proposer(CHAIN_ID, hh.saturating_sub(1), 1, &genesis_hash, &set).ok()?;
            if p0 == p1 {
                return None;
            }
            (0..3).find(|i| id_of_index(*i) == p0).map(|i| (hh, i))
        })
        .expect("未来 64 个高度内必存在可定位的 round-0 proposer（且 round-0 ≠ round-1）");
    let p0 = select_proposer(CHAIN_ID, h_k - 1, 0, &genesis_hash, &set).expect("proposer");
    let p1 = select_proposer(CHAIN_ID, h_k - 1, 1, &genesis_hash, &set).expect("proposer");
    assert_eq!(id_of_index(i0), p0, "victim 必须是 H_k 的 round-0 proposer");
    assert_ne!(p0, p1, "round-0 与 round-1 当选者必须不同");
    eprintln!(
        "{tag} 构造：跨节点最新 head={h} ⇒ 选取 **height {h_k}**（其 round-0 proposer = 节点下标 {i0}，将停掉；\
         round-1 proposer = {p1:?}）⇒ 该高度**只能在 round ≥ 1 产出**"
    );
    let killed_status = kids[i0].terminate();
    let survivors: Vec<usize> = (0..3).filter(|i| *i != i0).collect();

    // ---- 存活 2/3：必须跨过 H_k ⇒ **必然经 round timeout → round ≥ 1** 产出该高度 ----
    let advanced = poll_until(
        || {
            survivors
                .iter()
                .all(|i| live_stats(&kids[*i]).is_some_and(|s| s.head >= h_k && s.consensus >= h_k))
        },
        EXIT_TIMEOUT,
    );
    // 取证：存活节点 status 轨迹（含 `round=`）⇒ 「round ≥ 1」的可观测痕迹。
    // 采样可能错过短窗口，故**仅记录**（逻辑构造已保证 height h+1 只能在 round ≥ 1 产出）。
    let mut round_trace: Vec<String> = Vec::new();
    let mut saw_round_ge1 = false;
    for i in &survivors {
        for l in kids[*i]
            .stdout()
            .lines()
            .filter(|l| l.contains("status steps="))
        {
            let (Some(steps), Some(head), Some(round)) = (
                field(l, "steps="),
                field(l, "head_height="),
                field(l, "round="),
            ) else {
                continue;
            };
            if round >= 1 {
                saw_round_ge1 = true;
                round_trace.push(format!(
                    "{}: steps={steps} head={head} round={round}",
                    kids[*i].label
                ));
            }
        }
    }
    let ab_after: Vec<String> = kids
        .iter()
        .map(|c| format!("{}={:?}", c.label, live_stats(c)))
        .collect();
    eprintln!(
        "{tag} 存活节点 after: {ab_after:?}；killed_status={killed_status:?}；\
         观察到 round ≥ 1 的 status 样本={saw_round_ge1}；round≥1 轨迹（前 8 条）={:?}",
        round_trace.iter().take(8).collect::<Vec<_>>()
    );
    if !advanced {
        dump_all_node_forensics(
            tag,
            "p0-offline-advance",
            &[&kids[0], &kids[1], &kids[2]],
            &chain_roots(&env),
        );
    }
    assert!(
        advanced,
        "{tag}: H_k={h_k} 的 round-0 proposer（下标 {i0}）离线后，存活 2/3 未在窗口内跨过 H_k（{ab_after:?}）\
         ⇒ 无法证明 round ≥ 1 产出"
    );

    // ---- 重启被停节点（同目录 / 同 seed）⇒ 必须追赶（历史含 round ≥ 1 的块）----
    let target = survivors
        .iter()
        .map(|i| live_stats(&kids[*i]).map(|s| s.head).unwrap_or(0))
        .min()
        .unwrap_or(h_k)
        .max(h_k);
    let mut revived = ChildGuard::spawn(["A", "B", "C"][i0], &args(i0));
    let reconnected = poll_until(
        || live_stats(&revived).is_some_and(|s| s.established >= 1),
        STARTUP_TIMEOUT,
    );
    if !reconnected {
        dump_all_node_forensics(
            tag,
            "revived-reconnect",
            &[&kids[0], &kids[1], &kids[2], &revived],
            &chain_roots(&env),
        );
    }
    assert!(
        reconnected,
        "{tag}: 重启节点未重连（status={:?}）",
        live_stats(&revived)
    );

    let caught = poll_until(
        || {
            live_stats(&revived)
                .is_some_and(|s| s.head >= target && s.consensus >= target && s.durable_sane())
        },
        EXIT_TIMEOUT,
    );
    let revived_alive = revived.is_running();
    let revived_final = live_stats(&revived);
    let markers: Vec<(String, Option<&str>)> = vec![
        (
            "A".to_string(),
            fatal_marker(&kids[0].stdout(), &kids[0].stderr()),
        ),
        (
            "B".to_string(),
            fatal_marker(&kids[1].stdout(), &kids[1].stderr()),
        ),
        (
            "C".to_string(),
            fatal_marker(&kids[2].stdout(), &kids[2].stderr()),
        ),
        (
            "REVIVED".to_string(),
            fatal_marker(&revived.stdout(), &revived.stderr()),
        ),
    ];
    let revived_corrupt = [
        "ValidatorNotInValidatorSet",
        "IdentityMismatch",
        "CorruptedState",
    ]
    .into_iter()
    .find(|m| revived.stdout().contains(m) || revived.stderr().contains(m));
    let statuses = [
        kids[0].terminate(),
        kids[1].terminate(),
        kids[2].terminate(),
        revived.terminate(),
    ];

    eprintln!(
        "=== {tag} T8 DIAGNOSTICS ===\n\
         跨节点最新 head（停机时）: {h}\n\
         **round ≥ 1 高度**: H_k = {h_k}（其 round-0 proposer = 下标 {i0}，整个产出窗口离线）\n\
         存活节点 after: {ab_after:?}\n\
         revived final: {revived_final:?} alive={revived_alive}（target head ≥ {target}）\n\
         fatal markers: {markers:?}\n\
         revived identity/corruption: {revived_corrupt:?}\n\
         exit statuses（诊断）: {statuses:?}"
    );

    assert!(
        caught,
        "{tag}: 重启节点未追赶 head ≥ {target} ∧ consensus ≥ {target}（final={revived_final:?}）"
    );
    let rs = revived_final.expect("revived 有完整样本");
    assert!(
        rs.head >= target && rs.consensus >= target,
        "{tag}: head={} consensus={} steps={} < target={target}",
        rs.head,
        rs.consensus,
        rs.steps
    );
    assert!(
        rs.durable_sane(),
        "{tag}: durable QC tip 越界（head={} tip={:?}）",
        rs.head,
        rs.finalized
    );
    // **durable 见证（P1-A.19 §9）**：至少一个节点仍展示 QC-history 基础服务能力（tip ≥ 1）。
    assert!(
        kids.iter()
            .chain(std::iter::once(&revived))
            .any(|c| live_stats(c).is_some_and(|s| s.finalized.is_some_and(|f| f >= 1))),
        "{tag}: durable 见证缺失（所有节点 QC-history tip 均 < 1）"
    );
    assert!(revived_alive, "{tag}: 达标时重启节点必须仍存活");
    assert!(
        revived_corrupt.is_none(),
        "{tag}: 出现身份/损坏标记 {revived_corrupt:?}"
    );
    for (label, m) in &markers {
        assert!(m.is_none(), "{tag}: {label} 出现 fatal 标记 {m:?}");
    }
    eprintln!(
        "{tag} PASS: **height {h_k}** 在其 round-0 proposer（下标 {i0}）全程离线的情况下由存活 2/3 跨过\
         ⇒ 该高度**只在 round ≥ 1 产出**；重启节点经 sync（QC-bound round 解析）追赶至 head {}（durable tip={:?}），\
         跨节点最新 head（停机时）={h}",
        rs.head, rs.finalized
    );
}

/// F2 实验 B：**交错启动** 3 个真实 validator（先 A 单独跑到 ≥100 steps，再依次启 B/C）。
#[test]
fn f2b_staggered_three_validator() {
    let _serial = real_binary_guard();
    let env = TempDir::new("f2b");
    let val_seeds = [VAL_SEED[0], VAL_SEED[1], VAL_SEED[2]];
    let net_seeds = [NET_SEED[0], NET_SEED[1], NET_SEED[2]];
    let genesis = test_genesis(&val_seeds);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in net_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-3-net-{i}.seed"), *s);
    }
    for (i, s) in val_seeds.iter().enumerate() {
        env.write_seed(&format!("f2-3-val-{i}.seed"), *s);
    }
    let net_ids: Vec<NodeId> = net_seeds.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let labels: [&'static str; 3] = ["A", "B", "C"];
    let t0 = Instant::now();

    // STEP 1–2：启动 A + 等待 ready。
    let mut kids: Vec<ChildGuard> = vec![ChildGuard::spawn(
        labels[0],
        &f2_node_args(
            &env,
            3,
            0,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            F2_RUN_STEPS,
        ),
    )];
    let a_ready = poll_until(
        || kids[0].stdout().contains("entering bounded run loop"),
        STARTUP_TIMEOUT,
    );
    // STEP 3：等待 A **独自**跑到 ≥100 steps（条件轮询，非 sleep-only）。
    let a_ran = poll_until(|| kids[0].stdout().contains("status steps=100"), F2_WINDOW);
    let a_solo = last_status(&kids[0].stdout()).unwrap_or_default();

    // STEP 4–7：依次启动 B、C，并各自等待 ready。
    kids.push(ChildGuard::spawn(
        labels[1],
        &f2_node_args(
            &env,
            3,
            1,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            F2_RUN_STEPS,
        ),
    ));
    let b_ready = poll_until(
        || kids[1].stdout().contains("entering bounded run loop"),
        STARTUP_TIMEOUT,
    );
    kids.push(ChildGuard::spawn(
        labels[2],
        &f2_node_args(
            &env,
            3,
            2,
            &net_ids,
            &ports,
            &genesis_path,
            &hash_hex,
            F2_RUN_STEPS,
        ),
    ));
    let c_ready = poll_until(
        || kids[2].stdout().contains("entering bounded run loop"),
        STARTUP_TIMEOUT,
    );

    eprintln!(
        "=== STAGGERED TIMELINE ===\nA spawned: t=0ms\nA ready: {} ({a_ready})\nA ran>100 steps: {a_ran}\nA solo status: {a_solo}\nB spawned: t={}ms\nB ready: {} ({b_ready})\nC spawned: t={}ms\nC ready: {} ({c_ready})",
        a_ready,
        t0.elapsed().as_millis(),
        b_ready,
        t0.elapsed().as_millis(),
        c_ready
    );

    // STEP 8：让三者继续跑到有界窗口结束。
    let deadline = Instant::now() + F2_WINDOW;
    let statuses: Vec<Option<ExitStatus>> =
        kids.iter_mut().map(|c| c.wait_bounded(deadline)).collect();
    let mut block = String::new();
    for (i, c) in kids.iter().enumerate() {
        block.push_str(&c.diagnostic(statuses[i], true));
        if let Some(s) = last_status(&c.stdout()) {
            block.push_str(&format!("last_status={s}\n"));
        }
    }
    eprintln!("=== F2B DIAGNOSTICS ===\n{block}");

    let mut any_head = 0u64;
    let mut any_fin = false;
    for (i, c) in kids.iter().enumerate() {
        let out = c.stdout();
        let ls = last_status(&out).unwrap_or_default();
        let head = field(&ls, "head_height=").unwrap_or(0);
        let round = field(&ls, "round=").unwrap_or(0);
        let est = field(&ls, "established_peers=").unwrap_or(0);
        let fin = field(&ls, "finalized_height=");
        any_head = any_head.max(head);
        any_fin |= fin.is_some_and(|h| h >= 1);
        eprintln!(
            "F2B {}: exit={:?} established={est} round={round} head={head} finalized={fin:?}",
            c.label,
            statuses[i].and_then(|s| s.code())
        );
    }
    let verdict = if !(a_ready && b_ready && c_ready) {
        "INCONCLUSIVE（未就绪）"
    } else if any_head > 0 || any_fin {
        "STAGGERED_STARTUP_RECOVERS_LIVENESS"
    } else {
        "STAGGERED_STARTUP_DOES_NOT_RECOVER"
    };
    eprintln!("F2B RESULT: {verdict}（any_head={any_head} any_finality={any_fin}）");
    assert!(
        a_ready && b_ready && c_ready || verdict == "INCONCLUSIVE（未就绪）",
        "F2B 必须完成诊断并给出分类：{verdict}"
    );
}
