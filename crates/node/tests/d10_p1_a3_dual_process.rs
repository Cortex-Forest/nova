//! D10 / P1-A.3 — **二进制级双进程 E2E**（`std::process::Command`；无任何新依赖）。
//!
//! 目标：证明**真实 `yazimao-node` 可执行文件**能够长运行并被对端驱动（而非仅进程内 runtime）。
//!
//! 拓扑（最小；双方均为 **full-node**）：
//! - **A**：full-node + 真实入站 listener（`--listen 127.0.0.1:0`，端口由内核分配 ⇒ 从 A 的启动行
//!   读取真实绑定地址）+ 有界预算（`--run-steps` / `--idle-ms`）。
//! - **B**：full-node + configured peer `A_node_id@A_addr`（`--peer`）+ 较小的有界预算。
//!
//! 为何两边都用 full-node（实测证据，非设计偏好）：
//! - validator 节点**每步推进共识并提交区块**（实测：60 步 ≈ 3s，且高度持续递增），预算放大时会使
//!   E2E 时长不可控。
//! - 更关键：**full-node 对端收到 validator 的共识流量时，既有 `NodeRuntime::step()` 会以
//!   `RuntimeError::Driver` fail-closed 退出**（实测：A stderr = `Error: Run("Driver")`）。这是
//!   **既有 runtime 行为**（`runtime.rs` 本轮不可修改）⇒ P1-A.3 的二进制级 E2E 不以此拓扑取证；
//!   validator 形态的双节点真实 TCP 闭环已由既有 in-process 测试
//!   `crates/node/tests/d10_p0_dual_node_tcp_height2.rs` 与 bin 内 T38/T46 覆盖。
//! - 因此本测试聚焦 P1-A.3 自身的可验证面：真实二进制 / 启动链 / listener 绑定 / 真实拨号 /
//!   握手 + peer-auth Established / 有界长运行跑满预算 / 既有 shutdown / 无泄露 / 可释放。
//!
//! 断言（P1-A.3 §16）：两进程启动、A 真实绑定、B 真实拨号 + 认证 established、双方跑满各自预算、
//! 双方 exit 0、stdout 不含 seed、stdout 含 shutdown indication、无 panic、无 unexpected stderr、
//! 临时 storage 可正常释放。
//!
//! 纪律：
//! - **有界等待**：所有等待均有 deadline（`try_wait` 轮询 + 上限），绝无无限等待。
//! - fixture（genesis + seed）只写**系统临时目录**；不触碰仓库 / 不新增依赖 / 不修改 network 代码。
//! - A 的步数预算**大于** B 的（wall-clock 上 A 必定晚于 B 退出）⇒ B 退出时的
//!   `configured_peers=1/1` 不依赖两者同时退出的巧合。

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash, validator_id,
};
use nova_crypto::signature::SigningKey;
use nova_network::node_id::NodeId;

/// A 的 network identity seed（仅测试用；不写入仓库）。
const SEED_NET_A: [u8; 32] = [0x44; 32];
/// B 的 network identity seed。
const SEED_NET_B: [u8; 32] = [0x55; 32];
/// genesis 中唯一 validator 的公钥来源（**不交给任何节点** ⇒ 其 hex 亦不得出现于输出）。
const SEED_VAL_B: [u8; 32] = [0x22; 32];
/// A 的有界运行预算（较大 ⇒ A 晚于 B 退出，使 B 的 established 断言确定性成立）。
const RUN_STEPS_A: &str = "200";
/// B 的有界运行预算。
const RUN_STEPS_B: &str = "40";
/// 有界空闲间隔（ms；`1..=50`）。
const IDLE_MS: &str = "20";
/// 整个 E2E 的硬上限（避免测试挂死）。
const HARD_TIMEOUT: Duration = Duration::from_secs(90);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vk_bytes(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
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

/// 与 P1-A.2 bin 测试同构的最小合法 genesis（单验证者；canonical 约束）。
fn test_genesis(validator_pk: [u8; 32]) -> GenesisV1 {
    let acc_v = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    let acc_a = AccountInit {
        address: addr([0x22; 32]),
        liquid_balance: 1_000_000,
    };
    let mut vals = vec![(validator_id(&validator_pk), validator_pk, acc_v.address)];
    vals.sort_by_key(|v| v.0);
    GenesisV1 {
        network_id: NetworkId::Devnet,
        chain_id: 1001,
        genesis_timestamp: 1,
        initial_validator_set: vals
            .into_iter()
            .map(|(_, pk, a)| ValidatorInit {
                account_address: a,
                consensus_public_key: pk,
                bonded_stake: 100,
                commission_bps: 0,
            })
            .collect(),
        initial_accounts: vec![acc_v, acc_a],
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

/// 测试用临时目录（系统 temp；Drop 清理；不触碰仓库 / 用户文件）。
struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("yazimao_p1a3_{}_{}", std::process::id(), tag));
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

/// 从 CLI 契约行中取出 `key=<n>` 的十进制值（无正则；仅数字前缀）。
fn extract_number(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// 从启动行取出真实监听地址（`listen=Some(<addr>)`）。
fn extract_listen_addr(line: &str) -> Option<SocketAddr> {
    let start = line.find("listen=Some(")? + "listen=Some(".len();
    let rest = line.get(start..)?;
    let end = rest.find(')')?;
    rest.get(..end)?.parse::<SocketAddr>().ok()
}

/// 有界等待进程退出（`try_wait` 轮询；超时 ⇒ kill + 明确失败，绝不无限等待）。
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
            panic!("{what}: 未在有界等待上限内退出（E2E 挂起保护）");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_to_string<R: Read>(mut r: R) -> String {
    let mut s = String::new();
    let _ = r.read_to_string(&mut s);
    s
}

// ---------------------------------------------------------------------------
// E2E：A（listener，full-node）+ B（validator，dial A）双进程
// ---------------------------------------------------------------------------

#[test]
fn p1a3_dual_process_bounded_long_run() {
    let env = TempDir::new("e2e");

    // ---------- fixtures ----------
    let genesis = test_genesis(vk_bytes(SEED_VAL_B));
    let genesis_bytes = canonical_genesis_bytes(&genesis).expect("canonical genesis bytes");
    let genesis_hash = compute_genesis_hash(&genesis).expect("genesis hash");
    let genesis_path = env.write("genesis.bin", &genesis_bytes);
    let genesis_hash_hex = hex32(&genesis_hash);

    let net_seed_a = env.write_seed("net-a.seed", SEED_NET_A);
    let net_seed_b = env.write_seed("net-b.seed", SEED_NET_B);

    let storage_a = env.path("chain-a");
    let storage_b = env.path("chain-b");

    let a_id_hex = hex32(net_node_id(SEED_NET_A).as_bytes());

    let base = |storage: &PathBuf, seed: &PathBuf, run_steps: &str| -> Vec<String> {
        vec![
            "--genesis".into(),
            genesis_path.to_string_lossy().into(),
            "--genesis-hash".into(),
            genesis_hash_hex.clone(),
            "--chain-id".into(),
            "1001".into(),
            "--network-id".into(),
            "devnet".into(),
            "--storage-dir".into(),
            storage.to_string_lossy().into(),
            "--network-seed-file".into(),
            seed.to_string_lossy().into(),
            "--run-steps".into(),
            run_steps.into(),
            "--idle-ms".into(),
            IDLE_MS.into(),
        ]
    };

    let mut args_a = base(&storage_a, &net_seed_a, RUN_STEPS_A);
    args_a.extend(["--listen".into(), "127.0.0.1:0".into()]);

    let deadline = Instant::now() + HARD_TIMEOUT;

    // ---------- 启动 A（listener；full-node）----------
    let exe = env!("CARGO_BIN_EXE_yazimao-node");
    let mut child_a = Command::new(exe)
        .args(&args_a)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn A (yazimao-node)");

    // A 的 stdout 有界读取：首行（含真实绑定地址）经 channel 返回，其余累计供断言。
    let a_stdout_pipe = child_a.stdout.take().expect("A stdout piped");
    let (tx, rx) = mpsc::channel::<String>();
    let reader_a = std::thread::spawn(move || {
        let mut lines = BufReader::new(a_stdout_pipe);
        let mut all = String::new();
        let mut buf = String::new();
        let mut sent = false;
        loop {
            buf.clear();
            match lines.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            all.push_str(&buf);
            if !sent {
                let _ = tx.send(buf.clone());
                sent = true;
            }
        }
        all
    });

    let a_first_line = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("A 未在期限内输出启动行");
    assert!(
        a_first_line.contains("runtime assembled")
            && a_first_line.contains("entering bounded run loop"),
        "A 启动行不符合 CLI 契约: {a_first_line}"
    );
    let a_addr = extract_listen_addr(&a_first_line).expect("A 启动行必须报告真实监听地址");
    assert_ne!(a_addr.port(), 0, "A 的 port 0 必须被内核分配为真实端口");

    // ---------- 启动 B（full-node；dial A）----------
    let mut args_b = base(&storage_b, &net_seed_b, RUN_STEPS_B);
    args_b.extend(["--peer".into(), format!("{a_id_hex}@{a_addr}")]);

    let mut child_b = Command::new(exe)
        .args(&args_b)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn B (yazimao-node)");

    // ---------- 有界等待两个进程自行跑满预算退出 ----------
    let status_b = wait_bounded(&mut child_b, "B", deadline);
    let status_a = wait_bounded(&mut child_a, "A", deadline);

    let b_stdout = read_to_string(child_b.stdout.take().expect("B stdout piped"));
    let b_stderr = read_to_string(child_b.stderr.take().expect("B stderr piped"));
    let a_stderr = read_to_string(child_a.stderr.take().expect("A stderr piped"));
    let a_stdout = reader_a.join().expect("A stdout reader thread");

    let diag = format!(
        "--- A stdout ---\n{a_stdout}\n--- A stderr ---\n{a_stderr}\n\
         --- B stdout ---\n{b_stdout}\n--- B stderr ---\n{b_stderr}"
    );

    // ---------- 1/2. 两个进程都启动并正常退出（exit 0）----------
    assert!(status_a.success(), "A 必须 exit 0；{diag}");
    assert!(status_b.success(), "B 必须 exit 0；{diag}");

    // ---------- 3. A 真实绑定 listener ----------
    assert!(
        a_stdout.contains(&format!("listen=Some({a_addr})")),
        "A 启动行必须报告已绑定地址 {a_addr}；{diag}"
    );

    // ---------- 4/5. B 真实拨号 + 认证路径成功（established）----------
    assert!(
        b_stdout.contains("configured_peers=1/1"),
        "B 必须完成对 A 的 dial + 握手 + 认证（established 1/1）；{diag}"
    );
    // A 侧：真实 accept 计数（单调）证明入站连接确实建立。
    let a_accepted = extract_number(&a_stdout, "inbound_accepted=")
        .unwrap_or_else(|| panic!("A 摘要行缺少 inbound_accepted；{diag}"));
    assert!(a_accepted >= 1, "A 必须至少 accept 一条入站连接；{diag}");

    // ---------- 6. 两个进程都持续运行到各自 budget（无 N+1 / 无提前退出）----------
    let expected_a = format!("stopped after {RUN_STEPS_A}/{RUN_STEPS_A} steps");
    let expected_b = format!("stopped after {RUN_STEPS_B}/{RUN_STEPS_B} steps");
    assert!(
        a_stdout.contains(&expected_a),
        "A 必须跑满预算 {expected_a}；{diag}"
    );
    assert!(
        b_stdout.contains(&expected_b),
        "B 必须跑满预算 {expected_b}；{diag}"
    );

    // ---------- 8. stdout 不含 seed（三重：两个 network seed + validator seed）----------
    for (label, seed) in [
        ("A network seed", SEED_NET_A),
        ("B network seed", SEED_NET_B),
        ("B validator seed", SEED_VAL_B),
    ] {
        let h = hex32(&seed);
        assert!(!a_stdout.contains(&h), "A stdout 泄露 {label}；{diag}");
        assert!(!b_stdout.contains(&h), "B stdout 泄露 {label}；{diag}");
        assert!(!a_stderr.contains(&h), "A stderr 泄露 {label}；{diag}");
        assert!(!b_stderr.contains(&h), "B stderr 泄露 {label}；{diag}");
    }

    // ---------- 9. stdout 含正常 shutdown indication ----------
    assert!(
        a_stdout.contains("runtime shut down") && b_stdout.contains("runtime shut down"),
        "两进程都必须报告既有 shutdown 已执行；{diag}"
    );

    // ---------- 10/11. 无 panic / 无 unexpected stderr ----------
    for (name, out) in [
        ("A stdout", &a_stdout),
        ("B stdout", &b_stdout),
        ("A stderr", &a_stderr),
        ("B stderr", &b_stderr),
    ] {
        assert!(!out.contains("panicked"), "{name} 出现 panic；{diag}");
    }
    assert!(
        a_stderr.trim().is_empty(),
        "A stderr 必须为空（无日志 / 无错误）；{diag}"
    );
    assert!(
        b_stderr.trim().is_empty(),
        "B stderr 必须为空（无日志 / 无错误）；{diag}"
    );

    // ---------- 12. 临时 storage 可正常释放（无遗留句柄 / 锁）----------
    std::fs::remove_dir_all(&storage_a).expect("A storage 必须可释放（无遗留句柄）");
    std::fs::remove_dir_all(&storage_b).expect("B storage 必须可释放（无遗留句柄）");
}
