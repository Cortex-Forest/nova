//! B2 — **Tier-2：5 个真实 `yazimao-node` 进程**（真实 TCP、生产二进制路径）。
//!
//! 覆盖（Testnet readiness 证据；**tests-only**，不改动 A12/A10 文件）：
//! - **T2-1**：5 进程静态全互联 ⇒ `head` 前进 ∧ `finalized_height` 前进（非"仅启动成功"）。
//! - **T2-2**：停 V4 ⇒ 存活 V0–V3（4/5 = quorum 666_667 可达）继续出块 + finality ⇒ 重启 V4（同
//!   身份/同数据目录）⇒ 重连 ⇒ catch-up 追平 ⇒ 无 `CorruptedState`。
//!
//! 说明：
//! - 本文件**复制**必要的 helper（A12 文件禁止修改）；两文件各自独立编译，互不影响。
//! - 全部等待均为**有界**（`poll_until` + 硬超时），失败时输出各进程 stdout 尾部 + 显式失败。
//! - `run_steps` 保持**有限**（`20000`）；连续运行模式属 B1（已单独验证），此处不依赖。
//!   （为何由 `6000` 提到 `20000`：真实二进制走**生产默认** pacemaker 窗口（`initial 1000 tick`、`×2` 退避）
//!   且无法使用 test-only seam（无 CLI flag，属既有冻结契约）——停掉 V4 后若该高度 round-0 proposer 恰是 V4，
//!   幸存进程必须靠 pacemaker 超时跳 round，累计 1000+2000(+4000) tick。A12 的同类测试亦采用大 run_steps
//!   （`A17_SCS_SCDIR_RUN_STEPS=60000`）；步数仍有限、等待仍由 `poll_until` 硬超时界定。）
//! - genesis 使用 `NetworkId::Devnet`（bin 在 `--validator` 下拒绝 mainnet，属既有 fail-closed 契约）。

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
/// 有限步数上界（进程会自动退出，因此必须大于「离线 proposer 跳 round」所需的累计 tick 数）。
const RUN_STEPS: &str = "20000";
const IDLE_MS: &str = "1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

const VAL: [[u8; 32]; 5] = [[0x31; 32], [0x32; 32], [0x33; 32], [0x34; 32], [0x35; 32]];
const NET: [[u8; 32]; 5] = [[0x41; 32], [0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
const LABELS: [&str; 5] = ["V0", "V1", "V2", "V3", "V4"];
/// 单 node 观察窗口上限（进程级；由 `poll_until` 强制）。
const STEP_WINDOW: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// 基础工具（自包含；与 A12 同语义但不共享文件）
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

/// 5 验证者 devnet genesis（等额 stake ⇒ quorum = ceil(2T/3) = 666_667；canonical ordering）。
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
            "yazimao_p1a21_{}_{}_{}",
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

    /// 主动终止（kill + wait ⇒ 无 orphan；不是验收条件，仅供清理/重启前使用）。
    fn terminate(&mut self) -> Option<ExitStatus> {
        if self.is_running() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.child.try_wait().ok().flatten()
    }

    fn tail(&self) -> String {
        let out = self.stdout();
        let lines: Vec<&str> = out.lines().collect();
        lines[lines.len().saturating_sub(12)..].join("\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stats {
    steps: u64,
    head: u64,
    finalized: Option<u64>,
    consensus: u64,
    established: usize,
}

/// 解析最后一行 `status …`（stdout 契约；A.9）。
fn last_status(out: &str) -> Option<Stats> {
    let line = out.lines().rev().find(|l| l.contains("status steps="))?;
    let field =
        |k: &str| -> Option<&str> { line.split_whitespace().find_map(|tok| tok.strip_prefix(k)) };
    let num = |k: &str| -> Option<u64> { field(k)?.parse().ok() };
    let finalized = match field("finalized_height=") {
        Some("none") => None,
        Some(v) => Some(v.parse().ok()?),
        None => return None,
    };
    Some(Stats {
        steps: num("steps=")?,
        head: num("head_height=")?,
        finalized,
        consensus: num("consensus_height=")?,
        established: num("established_peers=")? as usize,
    })
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

fn node_args(
    env: &TempDir,
    n: usize,
    i: usize,
    ids: &[NodeId],
    ports: &[u16],
    genesis_path: &Path,
    hash_hex: &str,
) -> Vec<String> {
    // G5-D.7.2：仅 fresh safety dir（journal 不存在）声明显式初始化。
    let safety_dir = env.path(&format!("a21-{n}-safety-{i}"));
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
        env.path(&format!("a21-{n}-chain-{i}"))
            .to_string_lossy()
            .into(),
        "--safety-dir".into(),
        safety_dir.to_string_lossy().into(),
        "--network-seed-file".into(),
        env.path(&format!("a21-{n}-net-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--validator".into(),
        "--validator-seed-file".into(),
        env.path(&format!("a21-{n}-val-{i}.seed"))
            .to_string_lossy()
            .into(),
        "--listen".into(),
        format!("127.0.0.1:{}", ports[i]),
        "--run-steps".into(),
        RUN_STEPS.into(),
        "--idle-ms".into(),
        IDLE_MS.into(),
    ];
    // G5-D.7.2：仅 fresh safety dir（journal 不存在）声明显式初始化。
    if !safety_dir.join("safety.journal").exists() {
        args.push("--init-validator-safety".into());
    }
    for j in 0..n {
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

/// 失败路径取证：每节点 stats + stdout 尾部 + stderr 尾部。
fn forensic(tag: &str, nodes: &[&ChildGuard]) -> String {
    let mut s = format!("=== {tag} FORENSICS ===\n");
    for n in nodes {
        s.push_str(&format!(
            "--- {}: stats={:?}\nstdout_tail:\n{}\nstderr_tail:\n{}\n",
            n.label,
            last_status(&n.stdout()),
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

// ---------------------------------------------------------------------------
// T2-1 — 5 进程 baseline：真实 TCP ⇒ height + finality 前进
// ---------------------------------------------------------------------------
#[test]
fn t2_1_five_process_baseline_finality() {
    let env = TempDir::new("t21");
    let genesis = test_genesis(&VAL);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET.iter().enumerate() {
        env.write_seed(&format!("a21-5-net-{i}.seed"), *s);
    }
    for (i, s) in VAL.iter().enumerate() {
        env.write_seed(&format!("a21-5-val-{i}.seed"), *s);
    }
    let ids: Vec<NodeId> = NET.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..5).map(|_| free_port()).collect();

    let mut kids: Vec<ChildGuard> = (0..5)
        .map(|i| {
            ChildGuard::spawn(
                LABELS[i],
                &node_args(&env, 5, i, &ids, &ports, &genesis_path, &hash_hex),
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
    assert!(
        ready,
        "T2-1：5 进程未在 {STARTUP_TIMEOUT:?} 内进入 run loop\n{}",
        forensic("T2-1-startup", &kids.iter().collect::<Vec<_>>())
    );

    // 记录进入循环后的初始高度（证明"持续推进"而非"仅启动"）。
    let initial: Vec<Option<Stats>> = kids.iter().map(|c| last_status(&c.stdout())).collect();

    let ok = poll_until(
        || {
            kids.iter().all(|c| {
                last_status(&c.stdout()).is_some_and(|s| {
                    s.head >= 3 && s.finalized.is_some_and(|f| f >= 2) && s.established >= 4
                })
            })
        },
        STEP_WINDOW,
    );
    let final_stats: Vec<Option<Stats>> = kids.iter().map(|c| last_status(&c.stdout())).collect();
    assert!(
        ok,
        "T2-1：5 进程未在 {STEP_WINDOW:?} 内达成 head≥3 ∧ finalized≥2 ∧ established≥4（initial={initial:?} final={final_stats:?}）\n{}",
        forensic("T2-1-advance", &kids.iter().collect::<Vec<_>>())
    );

    for c in &kids {
        assert!(
            fatal_marker(&c.stdout(), &c.stderr()).is_none(),
            "T2-1：{} 出现 fatal 标记 {:?}\n{}",
            c.label,
            fatal_marker(&c.stdout(), &c.stderr()),
            forensic("T2-1-fatal", &kids.iter().collect::<Vec<_>>())
        );
    }
    for (i, c) in kids.iter().enumerate() {
        let s = last_status(&c.stdout()).expect("status 样本");
        assert!(
            s.steps > 0 && s.head >= 3,
            "T2-1：{} head={}（initial={:?}）",
            c.label,
            s.head,
            initial[i]
        );
    }
    eprintln!("T2-1 PASS: initial={initial:?} final={final_stats:?}");

    let statuses: Vec<Option<ExitStatus>> = kids.iter_mut().map(ChildGuard::terminate).collect();
    eprintln!("T2-1 cleanup statuses={statuses:?}");
}

// ---------------------------------------------------------------------------
// T2-2 — 停 V4 ⇒ 4/5 继续 ⇒ 重启 V4 ⇒ 重连 + catch-up 收敛
// ---------------------------------------------------------------------------
#[test]
fn t2_2_five_process_stop_restart_converge() {
    let env = TempDir::new("t22");
    let genesis = test_genesis(&VAL);
    let hash_hex = hex32(&compute_genesis_hash(&genesis).expect("hash"));
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical"),
    );
    for (i, s) in NET.iter().enumerate() {
        env.write_seed(&format!("a21-5-net-{i}.seed"), *s);
    }
    for (i, s) in VAL.iter().enumerate() {
        env.write_seed(&format!("a21-5-val-{i}.seed"), *s);
    }
    let ids: Vec<NodeId> = NET.iter().map(|s| net_node_id(*s)).collect();
    let ports: Vec<u16> = (0..5).map(|_| free_port()).collect();

    let mut kids: Vec<ChildGuard> = (0..5)
        .map(|i| {
            ChildGuard::spawn(
                LABELS[i],
                &node_args(&env, 5, i, &ids, &ports, &genesis_path, &hash_hex),
            )
        })
        .collect();

    assert!(
        poll_until(
            || kids
                .iter()
                .all(|c| c.stdout().contains("entering bounded run loop")),
            STARTUP_TIMEOUT
        ),
        "T2-2：5 进程未进入 run loop\n{}",
        forensic("T2-2-startup", &kids.iter().collect::<Vec<_>>())
    );

    // 稳定基线
    let stable = poll_until(
        || {
            kids.iter().all(|c| {
                last_status(&c.stdout()).is_some_and(|s| {
                    s.head >= 3 && s.finalized.is_some_and(|f| f >= 2) && s.established >= 4
                })
            })
        },
        STEP_WINDOW,
    );
    assert!(
        stable,
        "T2-2：未达稳定基线\n{}",
        forensic("T2-2-baseline", &kids.iter().collect::<Vec<_>>())
    );

    // 停 V4（index 4）
    let before = last_status(&kids[4].stdout()).expect("V4 基线");
    let _ = kids[4].terminate();

    // 4/5 继续：head ≥ before.head + 2 ∧ finalized 前进
    let continued = poll_until(
        || {
            kids[..4].iter().all(|c| {
                last_status(&c.stdout()).is_some_and(|s| {
                    s.finalized.is_some_and(|f| f >= 2) && s.consensus >= before.consensus
                })
            }) && kids[..4]
                .iter()
                .filter_map(|c| last_status(&c.stdout()))
                .map(|s| s.finalized.unwrap_or(0))
                .max()
                .unwrap_or(0)
                > before.finalized.unwrap_or(0)
        },
        STEP_WINDOW,
    );
    let after_stop: Vec<Option<Stats>> =
        kids[..4].iter().map(|c| last_status(&c.stdout())).collect();
    assert!(
        continued,
        "T2-2：停 V4 后 4/5 未继续（before={before:?} after={after_stop:?}）\n{}",
        forensic("T2-2-continue", &kids.iter().collect::<Vec<_>>())
    );

    // 重启 V4（同身份 / 同数据目录 ⇒ 复用同一 args）
    let v4_args = node_args(&env, 5, 4, &ids, &ports, &genesis_path, &hash_hex);
    let mut v4 = ChildGuard::spawn("V4r", &v4_args);

    // 重连
    let reconnected = poll_until(
        || last_status(&v4.stdout()).is_some_and(|s| s.established >= 1),
        STARTUP_TIMEOUT,
    );
    assert!(
        reconnected,
        "T2-2：V4 重启后未重连\n{}",
        forensic(
            "T2-2-reconnect",
            &[&kids[0], &kids[1], &kids[2], &kids[3], &v4]
        )
    );

    // catch-up：V4 head ≥ 幸存者最小 head（且 ≥3）∧ finalized 前进
    let caught = poll_until(
        || {
            let others_min = kids[..4]
                .iter()
                .filter_map(|c| last_status(&c.stdout()))
                .map(|s| s.head)
                .min()
                .unwrap_or(u64::MAX);
            last_status(&v4.stdout()).is_some_and(|s| {
                // 重连后 V4 必须追到「距幸存者最小 head ≤1 块」且自身 finalized 前进
                // （允许 1 块采样滞后；不使用 reset 伪造状态）。
                s.head >= 3 && s.finalized.is_some_and(|f| f >= 2) && s.head + 1 >= others_min
            })
        },
        STEP_WINDOW,
    );
    let final_stats: Vec<Option<Stats>> = kids[..4]
        .iter()
        .map(|c| last_status(&c.stdout()))
        .chain(std::iter::once(last_status(&v4.stdout())))
        .collect();
    assert!(
        caught,
        "T2-2：V4 未在 {STEP_WINDOW:?} 内完成 catch-up（before={before:?} final={final_stats:?}）\n{}",
        forensic(
            "T2-2-catchup",
            &[&kids[0], &kids[1], &kids[2], &kids[3], &v4]
        )
    );

    // 无 fatal（含 CorruptedState；V4 重启路径）
    for c in [&kids[0], &kids[1], &kids[2], &kids[3], &v4] {
        let m = fatal_marker(&c.stdout(), &c.stderr());
        assert!(
            m.is_none(),
            "T2-2：{} 出现 fatal 标记 {m:?}\n{}",
            c.label,
            forensic("T2-2-fatal", &[&kids[0], &kids[1], &kids[2], &kids[3], &v4])
        );
    }
    let v4_final = last_status(&v4.stdout()).expect("V4 最终样本");
    assert!(
        v4_final.head > before.head,
        "T2-2：V4 重启后 head 必须前进（{} → {}）",
        before.head,
        v4_final.head
    );
    eprintln!("T2-2 PASS: before={before:?} final={final_stats:?}");

    let statuses: Vec<Option<ExitStatus>> = kids
        .iter_mut()
        .map(ChildGuard::terminate)
        .chain(std::iter::once(v4.terminate()))
        .collect();
    eprintln!("T2-2 cleanup statuses={statuses:?}");
}
