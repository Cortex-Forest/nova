//! PHASE 6H-AH — O2 **真实多进程 TCP** E2E：个人 `0x0E` Abandon Attestation → `0x0D` RoundChangeCertificate。
//!
//! # 本测试要证明的唯一新增边（6H-AG 确认的唯一 Level-3 blocker）
//!
//! ```text
//! Process A（真实 EXPIRE）
//!   → ValidatorActor::sign_abandon（S1：Ed25519 0x01 / DomainId::RoundChangeCertificate 0x10）
//!   → RoundChangeAttestationPool::admit（首次收录 = Recorded）
//!   → OutboundConsensusMessage::AbandonAttestation（ADR-0074，精确 112B）
//!   → egress::envelope_for（NetworkSigner 签名）
//!   → NetworkService::broadcast → flush_outbound → **真 TCP**
//!   ====================== NETWORK ======================
//!   → Process B：NetworkService::poll_transport → decode/validate/classify
//!   → NetworkEvent::ConsensusAbandonAttestation → wiring（bounded）→ NodeRuntime::step
//!   → ADR-0074 decode（112B）→ 冻结 verify_evidence → 第二个 pool
//!   ⇒ 两个 pool 各自达到 quorum（3 验证者等权 ⇒ quorum = 2W > 自身 1W）
//!   ⇒ 组装 `RoundChangeCertificate` → **既有** `0x0D` 出站 → 对端收到 → 处理
//! ```
//!
//! # 为什么必须**两个**进程、并且宁可少启动一个 validator（§9/§10）
//!
//! - 本测试的 genesis 声明 **3** 个等权 validator（genesis 不可改；stake 相等 ⇒ quorum = 2W）。
//! - 只启动 **2** 个进程（**故意省略 round-0 的 proposer**）⇒ 该 round **必然停滞**（无人出块）。
//! - 关键不变量：**单节点自己的 attestation 只有 1W < quorum 2W** ⇒
//!   `rc_certs >= 1`（池内组装出证书）**只能**由**远端** `0x0E` 经真实 TCP 到达并验签入池产生。
//!   这正是 §11/§12 要求的「实际网络字节」证据 —— 而不是同进程内 3 个 actor 的模拟。
//! - round-0 proposer = `select_proposer(chain_id, head_height = 0, round = 0, genesis_hash, set)`
//!   （与 `block_dispatch::resolve_expected_proposer_vk_at_round` 同一约定：canonical-next 块由
//!   **父高度轮** 的 proposer 产出）⇒ 在本测试内**离线可确定**，因此停滞是**确定性**的，不是概率事件。
//!
//! # 观测面（§12：不直接调用 `pool.admit()` / `apply_verified_round_change()`）
//!
//! 全部证据来自**真实二进制 stdout 的 periodic status 行**（PHASE 6H-AH 新增 O2 计数字段，读写
//! 的均为 runtime **既有**只读 accessor），不依赖瞬时内存采样、不修改任何生产语义。
//!
//! # 边界（明确不做）
//!
//! 不做：D3 限流 / peer discovery / 分区注入 / 长时间 liveness（5-7、6-7）/ A17 压力 / Akash。

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
/// `idle 1ms` ⇒ 1 step ≈ 1 逻辑 tick。默认 round-0 窗口 = 1000 tick（`RoundTimeoutConfig::default`）
/// ⇒ 4000 step 覆盖 round 0 与 round 1 两轮窗口（1000 / 2000 tick），**非**长时间实验。
const RUN_STEPS: &str = "4000";
const IDLE_MS: &str = "1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// O2 观测窗口（仅等待**确定性**即将发生的事件；不做 soak）。
const O2_WINDOW: Duration = Duration::from_secs(150);

/// 3 个 validator 身份（genesis 固定 3 验证者；运行时**只**启动其中 2 个 —— 见模块头）。
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
            std::env::temp_dir().join(format!("yazimao_o2_ah_{}_{}", std::process::id(), tag));
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

    /// 主动终止（kill + wait；无 orphan；幂等）。
    fn terminate(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// 失败诊断：完整 stdout/stderr 尾部 + O2 观测；并写完整日志到 %TEMP%。
    fn diagnostic(&self, stats: Option<O2Stats>) -> String {
        let out = self.stdout();
        let err = self.stderr();
        let log = std::env::temp_dir().join(format!("yazimao-o2-ah-{}.log", self.label));
        let _ = std::fs::write(
            &log,
            format!("=== STDOUT ===\n{out}\n=== STDERR ===\n{err}\n"),
        );
        let tail = |s: &str| -> String {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(60)..].join("\n")
        };
        format!(
            "--- NODE {} (pid={}) ---\no2_stats={stats:?}\nlog_file={}\n\
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

/// 真实二进制测试串行 guard（避免与既有 binary 测试争抢端口/CPU）。
fn real_binary_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// O2 观测（全部取自**真实进程** stdout 的 status 行；字段由 PHASE 6H-AH 暴露，读 runtime 既有 accessor）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct O2Stats {
    steps: u64,
    head: u64,
    consensus: u64,
    round: u64,
    abandon_produced: u64,
    abandon_broadcast: u64,
    abandon_rejected: u64,
    rc_certs: u64,
    rc_authority: u64,
    rc_rejected: u64,
    /// `timeout_split=` = [Applied, Ignored, Rejected]（**单调累计**；严格解析）。
    timeout_split: [u64; 3],
}

/// 解析 `key=a/b/c`（**严格**：字段缺失或任一分量不可解析 ⇒ `None`；绝不默认零）。
fn buckets3(line: &str, key: &str) -> Option<[u64; 3]> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let raw: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '/')
        .collect();
    let mut out = [0u64; 3];
    let mut it = raw.split('/');
    for slot in out.iter_mut() {
        *slot = it.next()?.parse().ok()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some(out)
}

/// 从 `key=` 取十进制值（缺失 ⇒ 0；仅供**观测**，严格性由调用方按需判 None）。
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

/// 最后一条 status 行（缺失 ⇒ None：宁可判「无样本」也不猜）。
fn last_status(out: &str) -> Option<String> {
    out.lines()
        .rfind(|l| l.contains(": status ") && l.contains("rc_certs="))
        .map(|l| l.to_string())
}

/// 解析某时刻的 O2 观测。
fn parse_stats(out: &str) -> Option<O2Stats> {
    let line = last_status(out)?;
    Some(O2Stats {
        steps: field(&line, "steps=")?,
        head: field(&line, "head_height=")?,
        consensus: field(&line, "consensus_height=")?,
        round: field(&line, "round=")?,
        abandon_produced: field(&line, "abandon_produced=").unwrap_or(0),
        abandon_broadcast: field(&line, "abandon_broadcast=").unwrap_or(0),
        abandon_rejected: field(&line, "abandon_rejected=").unwrap_or(0),
        rc_certs: field(&line, "rc_certs=").unwrap_or(0),
        rc_authority: field(&line, "rc_authority=").unwrap_or(0),
        rc_rejected: field(&line, "rc_rejected=").unwrap_or(0),
        timeout_split: buckets3(&line, "timeout_split=")?,
    })
}

#[test]
fn o2_abandon_attestation_reaches_peer_over_real_tcp() {
    let _serial = real_binary_guard();
    let env = TempDir::new("o2_e2e");

    // ---- fixtures：3 validator genesis（**不可改**：声明 3 个等权验证者 ⇒ quorum = 2W）----
    let genesis = test_genesis(&VAL_SEED);
    let genesis_hash = compute_genesis_hash(&genesis).expect("genesis hash");
    let genesis_path = env.write(
        "genesis.bin",
        &canonical_genesis_bytes(&genesis).expect("canonical genesis"),
    );
    let genesis_hash_hex = hex32(&genesis_hash);
    let set = ValidatorSet::from_genesis(&genesis);

    // ---- 确定性停滞：省略 round-0 的 proposer（`select_proposer(chain, head=0, round=0, vsid, set)`）----
    // 约定与 `block_dispatch::resolve_expected_proposer_vk_at_round` 一致（canonical-next 由**父高度轮**的
    // proposer 产出；启动时 head = 0 ⇒ 轮高 = 0）。
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
    assert_eq!(
        running.len(),
        2,
        "只启动 2 个真实进程（省略 round-0 proposer）"
    );

    // ---- 身份互异性（validator ≠ network；两进程互不相同）----
    let net_ids: Vec<NodeId> = NET_SEED.iter().map(|s| net_node_id(*s)).collect();
    for i in &running {
        assert_ne!(
            hex32(net_ids[*i].as_bytes()),
            hex32(val_ids[*i].as_bytes()),
            "network identity 必须与 validator identity 不同（节点 {i}）"
        );
    }

    // ---- 静态拓扑：两个在线 validator 互连（真实 TCP；不实现 discovery）----
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("net-{i}.seed"), NET_SEED[i]))
        .collect();
    let val_seed_paths: Vec<PathBuf> = (0..3)
        .map(|i| env.write_seed(&format!("val-{i}.seed"), VAL_SEED[i]))
        .collect();

    let build_args = |i: usize, peer_idx: usize| -> Vec<String> {
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
            seed_paths[i].to_string_lossy().into(),
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
        // 仅 fresh safety dir（journal 不存在）声明显式初始化（既有契约）。
        if !safety_dir.join("safety.journal").exists() {
            args.push("--init-validator-safety".into());
        }
        args.push("--peer".into());
        args.push(format!(
            "{}@127.0.0.1:{}",
            hex32(net_ids[peer_idx].as_bytes()),
            ports[peer_idx]
        ));
        args
    };

    // ---- 启动 2 个**独立进程**（独立 storage / safety / network endpoint / validator signer）----
    let mut children = [
        ChildGuard::spawn("A", &build_args(running[0], running[1])),
        ChildGuard::spawn("B", &build_args(running[1], running[0])),
    ];

    // ---- readiness：两进程均进入 bounded run loop（条件轮询，非 sleep-only）----
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
        "两进程必须在 {STARTUP_TIMEOUT:?} 内进入 run loop\n{}\n{}",
        children[0].diagnostic(None),
        children[1].diagnostic(None)
    );

    // ---- 观测窗口：等待**确定性** O2 事件（round-0 停滞 ⇒ 双端 EXPIRE ⇒ `0x0E` 交换 ⇒ quorum ⇒ `0x0D`）----
    //
    // ⚠️ 等待条件**必须**包含「对端 `0x0D` 已被处理」（`rc_authority + rc_rejected >= 1`）：
    // 断言 (5) 要求对端 `0x0D` 到达并处理，而等待条件原先只覆盖
    // `rc_certs / abandon_broadcast / abandon_produced` ⇒ **断言 (5) 与其先决条件之间存在竞态**
    // （实测 run2：三条件已全部成立，但 `rc_authority == 0 && rc_rejected == 0` ⇒ 断言 (5) 在
    // 事件到达前即被判定为失败）。补入该条件**只**把被断言的先决条件纳入等待，仍受 `O2_WINDOW`
    // 有界约束 —— **不**新增重试、**不**延长时间窗、**不**削弱断言 (5) 本身。
    let converged = poll_until(
        || {
            children.iter_mut().all(|c| {
                parse_stats(&c.stdout()).is_some_and(|s| {
                    s.rc_certs >= 1
                        && s.abandon_broadcast >= 1
                        && s.abandon_produced >= 1
                        && s.rc_authority + s.rc_rejected >= 1
                })
            })
        },
        O2_WINDOW,
    );

    // ---- 采集证据（terminate 之前）----
    let stats: Vec<Option<O2Stats>> = children.iter().map(|c| parse_stats(&c.stdout())).collect();
    // 逐节点采样历史（用于「不跳轮」不变量）。
    let samples: Vec<Vec<O2Stats>> = children
        .iter()
        .map(|c| {
            c.stdout()
                .lines()
                .filter(|l| l.contains(": status ") && l.contains("rc_certs="))
                .filter_map(|l| {
                    // 复用同一解析器（最后一行即当前行的解析已覆盖格式；此处按行解析）
                    Some(O2Stats {
                        steps: field(l, "steps=")?,
                        head: field(l, "head_height=")?,
                        consensus: field(l, "consensus_height=")?,
                        round: field(l, "round=")?,
                        abandon_produced: field(l, "abandon_produced=").unwrap_or(0),
                        abandon_broadcast: field(l, "abandon_broadcast=").unwrap_or(0),
                        abandon_rejected: field(l, "abandon_rejected=").unwrap_or(0),
                        rc_certs: field(l, "rc_certs=").unwrap_or(0),
                        rc_authority: field(l, "rc_authority=").unwrap_or(0),
                        rc_rejected: field(l, "rc_rejected=").unwrap_or(0),
                        timeout_split: buckets3(l, "timeout_split=")?,
                    })
                })
                .collect()
        })
        .collect();
    let alive: Vec<bool> = children.iter_mut().map(|c| c.is_running()).collect();

    // ---- 清理（无 orphan）----
    for c in children.iter_mut() {
        c.terminate();
    }

    let diag = || {
        format!(
            "{}\n{}\nconverged={converged}\nalive={alive:?}\nabsent_validator_index={absent_idx} \
             running={running:?}",
            children[0].diagnostic(stats[0]),
            children[1].diagnostic(stats[1]),
        )
    };

    // ================= 断言 =================

    // (1) 收敛：两进程均出现真实的 `0x0E` 生产 + 出站 + 远端证书组装。
    assert!(converged, "O2 事件未在 {O2_WINDOW:?} 内出现\n{}", diag());

    for (idx, s) in stats.iter().enumerate() {
        let s = s.unwrap_or_else(|| panic!("节点 {idx} 无有效 status 样本\n{}", diag()));
        // (2) 真实 EXPIRE（本进程自己的计时器真的到期）。
        assert!(
            s.abandon_produced >= 1,
            "节点 {idx}: 必须出现真实 EXPIRE 产生的本地 attestation；stats={s:?}\n{}",
            diag()
        );
        // (3) `0x0E` **已出站**（进入 NetworkService 出站队列并 flush 到真 TCP）。
        assert!(
            s.abandon_broadcast >= 1,
            "节点 {idx}: 必须发出 `0x0E`（abandon_broadcast >= 1）；stats={s:?}\n{}",
            diag()
        );
        // (4) **关键证据**：池内组装出证书 ⇒ quorum(2W) > 自身权重(1W) ⇒ 必有远端 `0x0E`
        //     经真实 TCP 到达、decode、冻结验签并入池。
        assert!(
            s.rc_certs >= 1,
            "节点 {idx}: 必须从**远端** attestation 组装出证书（rc_certs >= 1）；stats={s:?}\n{}",
            diag()
        );
        // (5) `0x0D` 证书经真实 TCP 到达并被处理（应用 ⇒ rc_authority；本地计时器已先行前进 ⇒
        //     证书按冻结语义被判 stale ⇒ rc_rejected）。两种结果都是「收到并处理」。
        assert!(
            s.rc_authority + s.rc_rejected >= 1,
            "节点 {idx}: 必须收到并处理对端 `0x0D` 证书（rc_authority|rc_rejected >= 1）；stats={s:?}\n{}",
            diag()
        );
        // (6) 入站 attestation 无拒绝（无畸形 / 无验签失败 / 无身份不符 / 无跨高度重放）。
        assert_eq!(
            s.abandon_rejected,
            0,
            "节点 {idx}: 合法双端 `0x0E` 不应被拒（abandon_rejected == 0）；stats={s:?}\n{}",
            diag()
        );
        // (7) 停滞解除（round 曾前进）—— 以**单调累计**计数取代旧的瞬时采样断言 `max_round >= 1`。
        //
        // 旧断言对每 100 step 的 status 采样取 `round` 最大值；而 status 的 `round` 是**当前**值，
        // 且**高度推进即归零** ⇒ 采样会系统性漏掉瞬态（实测：`timeout_split=1/0/0` 已发生 Applied，
        // 而全部采样 `round` 仍为 0）⇒ 旧断言属**观测粒度假失败**。
        //
        // `timeout_split` = 本节点 round-timeout 结果 [Applied, Ignored, Rejected]，为**单调累计**，
        // 仅由 `drive_round_timeout`（`crates/node/src/runtime.rs`）在**真实到期且冻结转移 Applied**
        // 时递增 ⇒ `timeout_split[0] >= 1` 证明**该节点自己的 round 真实前进过**。
        //
        // **诚实边界**：本断言**只**证明本地 pacemaker 的 round 前进；**不代表**对端 attestation 到达、
        // 证书组装或状态应用 —— 那些性质由 (2)(3)(4)(5)(6) 独立承担，未被本改动触及。
        // `samples`（含逐样本 `round`）保留在失败诊断信息中。
        assert!(
            s.timeout_split[0] >= 1,
            "节点 {idx}: 本地 round 必须真实前进过（timeout_split[0] >= 1）；stats={s:?} samples={:?}\n{}",
            samples[idx],
            diag()
        );
    }

    // 证据输出（`--nocapture` 可见）：真实进程观测到的 O2 计数（本阶段验收证据）。
    println!(
        "O2_E2E_EVIDENCE absent_validator_index={absent_idx} running={running:?} \
         A={:?} B={:?}",
        stats[0], stats[1]
    );

    // (8) 「不跳轮」：同高度内相邻样本的 round 增量 ≤ 1（冻结 `checked_successor` 单步后继）。
    for (idx, node_samples) in samples.iter().enumerate() {
        for w in node_samples.windows(2) {
            let (a, b) = (w[0], w[1]);
            if a.consensus == b.consensus {
                assert!(
                    b.round <= a.round + 1,
                    "节点 {idx}: 同高度 round 跳变 {}→{}（采样 steps {}→{}）⇒ 违反单步后继\n{}",
                    a.round,
                    b.round,
                    a.steps,
                    b.steps,
                    diag()
                );
            }
        }
    }
}
