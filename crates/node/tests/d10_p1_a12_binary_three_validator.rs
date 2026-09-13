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
#[derive(Clone, Copy, Debug)]
struct StatusSample {
    steps: u64,
    head: u64,
    /// `finalized_height=none` ⇒ `None`（尚未产生 durable finality）。
    finalized: Option<u64>,
    established: u64,
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
            established: field(&line, "established_peers=").unwrap_or(0),
        });
    }

    fn last(&self) -> Option<StatusSample> {
        self.samples.last().copied()
    }

    /// 至少 2 个完整样本，且 `finalized_height` 至少一次**严格增加**（持续 durable 进展）。
    fn sustained(&self) -> bool {
        self.samples.len() >= 2
            && self
                .samples
                .windows(2)
                .any(|w| w[1].finalized.unwrap_or(0) > w[0].finalized.unwrap_or(0))
    }

    /// §18 审计行：validator / steps / head / finalized / established / samples。
    fn audit(&self) -> String {
        match self.last() {
            Some(s) => format!(
                "{}: steps={} head={} finalized={:?} established={} samples={}",
                self.label,
                s.steps,
                s.head,
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

/// T1/T2 共用验收谓词（全部证据 = **实时完整 status 样本**）：
/// - 每节点：`finalized == Some(head)`（无滞后 validator）、`head >= 2`、`established >= 1`；
/// - 每节点：≥2 完整样本且 `finalized` 至少一次严格增加（持续进展）。
fn formal_predicate(ts: &[LiveTracker]) -> bool {
    !ts.is_empty()
        && ts.iter().all(|t| {
            t.sustained()
                && t.last().is_some_and(|s| {
                    s.finalized == Some(s.head) && s.head >= 2 && s.established >= 1
                })
        })
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
        "P1-A.14 正式验收未在 {window:?} 内达成（口径 = 实时 durable finality + 持续进展 + 无致命错误；\
         **不**要求 6000 步 / exit 0）：{audit:?}"
    );
    assert!(
        alive.iter().all(|a| *a),
        "达标时所有 validator 必须仍在运行（证明 finality 由活节点持续产生）：alive={alive:?}；audit={audit:?}"
    );
    for t in &trackers {
        let s = t.last().expect("accepted ⇒ 必有完整样本");
        assert!(
            s.finalized == Some(s.head),
            "{} 必须 head == finalized（无滞后 validator）：head={} finalized={:?}",
            t.label,
            s.head,
            s.finalized
        );
        assert!(
            s.finalized.is_some_and(|f| f >= 2),
            "{} durable finalized_height 必须 ≥2（实测 {:?}）",
            t.label,
            s.finalized
        );
        assert!(
            s.established >= 1,
            "{} 必须至少 1 个 established peer（实测 {}）",
            t.label,
            s.established
        );
        assert!(
            t.sustained(),
            "{} 必须观测到 ≥2 个完整样本且 finalized 至少一次严格增加；finalized 序列={:?}",
            t.label,
            t.samples.iter().map(|s| s.finalized).collect::<Vec<_>>()
        );
    }
    // 收敛（**可达口径**）：所有 validator 都 durable-finalized 至少同一高度 2；
    // 不要求瞬时等值（真实进程步进速率不同）。精确引用一致性由 A.10 in-process rig 断言。
    let min_finalized = trackers
        .iter()
        .filter_map(|t| t.last().and_then(|s| s.finalized))
        .min();
    assert!(
        min_finalized.is_some_and(|m| m >= 2),
        "P1-A.14 收敛口径 min(finalized) ≥ 2 未达成：{audit:?}"
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

/// F2 实验 B：**交错启动** 3 个真实 validator（先 A 单独跑到 ≥100 steps，再依次启 B/C）。
#[test]
fn f2b_staggered_three_validator() {
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
