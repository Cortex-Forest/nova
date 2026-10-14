//! YAZIMAO Node — long-running production node executable（**P1-A.3**）。
//!
//! # 本轮边界（P1-A.3 = 有界长运行驱动循环）
//! ```text
//! process start
//!   → main()
//!   → 最小 CLI 解析（std::env::args；零新依赖；严格 fail-closed）
//!   → genesis pre-flight（read → decode → compute hash → 比对锚 → validate → ValidatorSet）
//!   → seed 装载（严格 hex64；只读；不回显；hex 读缓冲与临时 seed buffer 均经正式 `zeroize` 清零）
//!   → 身份装配（network identity；validator 模式：身份分离 + 成员预检 + KeyProvider）
//!   → 基座 transport（IdleTransport）+ NodeRuntime 装配（既有 `start_with_network`）
//!   → 装配断言（NodeId / peer-auth / listener / 入站连接数）
//!   → 有界运行循环：每轮 [configured peers 建立（幂等）→ 既有 `NodeRuntime::step()` → pacing]
//!   → 预算耗尽 ⇒ 既有 `shutdown()`（**恰好一次**）→ 摘要行 → exit 0
//!   → `step()` 失败 ⇒ fail-closed：停止循环 → 仍执行 `shutdown()` → 非 0 退出
//! ```
//!
//! **驱动点唯一**：循环只调用既有 `NodeRuntime::step()`（不新增共识 / 网络 / 存储逻辑）。
//!
//! # 明确未实现（诚实声明）
//! - **无 Ctrl-C / SIGTERM 优雅停机**（不引入 signal 依赖；`unsafe_code = forbid`）⇒ 运维终止
//!   依赖 OS 默认终止；持久状态由既有 crash-consistency 保证（WAL 每事务 fsync / safety journal
//!   durable / finality durable-before-bridge / commit durable-before-advance）。
//! - 无 peer discovery / 无自动重连策略 / 无日志与遥测 / 无 `--run-ms`（仅 `--run-steps` 预算）。
//!
//! # 诚实声明（help 文案同步）
//! - `bootstrap / devnet / testnet oriented`；**NOT MAINNET READY**。
//! - 网络模型 = **configured peers only**；**automatic peer discovery is not implemented**；
//!   因此 **不做** "Zero-Operator complete" 声明。
//! - 不声称 quantum-safe / quantum-resistant / production validator。
//!
//! # 输出与日志
//! - 本文件**不使用**标准输出/错误“打印宏”（`docs/operations/logging.md` §1 禁止生产代码使用）。
//!   `--help` / `--version` 属 CLI 契约输出，仅经 `std::io::stdout().write_all` 写出。
//! - 启动错误经 `main() -> Result<(), StartupError>` 传播：由标准库以非 0 退出码终止
//!   （`Error: <Debug>`），**不引入任何日志 / 遥测依赖**（P1-A.1 不实现日志）。
//!
//! # 治理边界
//! - 只读使用既有公开 API：`nova_crypto::{identity,address}` / `nova_consensus::validator` /
//!   `nova_network::{node_id,transport}` / `nova_node::{bootstrap,key_provider}`。
//! - **未修改**：`crates/{consensus,core,crypto,storage,network}`、D8 frozen node 文件、
//!   `docs/**`、`README.md`、任何既有 node 模块。
//! - **依赖变化仅 1 项（P1-A.2b，Owner 批准 Option B）**：`crates/node/Cargo.toml` 增
//!   `zeroize.workspace = true`；`Cargo.lock` 预期且唯一变化 = `nova-node` 依赖列表 +1 行
//!   `+ "zeroize",`（`zeroize 1.9.0` 已由 `nova-crypto` 引入并已在 lockfile，无版本 / feature 漂移）。
//!   用途仅限 secret 内存清零；**不引入** CLI 解析库 / 信号处理库 / 日志框架。

use std::cell::RefCell;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use nova_consensus::round::RoundStep;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::NetworkId;
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{
    ChainIdentity, compute_genesis_hash, decode_genesis_bytes, validate_genesis_with_expected,
};
use nova_crypto::signature::{Signature, SigningKey, VerifyingKey, sign_message_hash};
use nova_network::message::{MessageEnvelope, NetworkError, sign_message};
use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, Transport};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, KeyProviderConfig, KeyProviderError};
use nova_node::network_identity::{NetworkSigner, NetworkSigningError};
use nova_node::runtime::{
    NodeRuntime, NodeRuntimeError, RoundChangeRejectKind, RoundTimeoutOutcome, RuntimeError,
};
use nova_node::signer::{SigningCapability, SigningError};
use zeroize::{Zeroize, Zeroizing};

/// 程序名（help / version 输出）。
const PROGRAM: &str = "yazimao-node";
/// 软件版本（workspace 统一版本）。
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 有界空闲间隔默认值（ms）。
/// `IDLE_MS_MAX`（`= 50`）上限（`--idle-ms 0` 已被 CLI 拒绝 ⇒ 无 busy loop）。
const IDLE_MS_DEFAULT: u64 = 1;
/// 有界空闲间隔上限（ms；越界 ⇒ fail-closed）。
const IDLE_MS_MAX: u64 = 50;
/// 有界运行步数默认值（`--run-steps`；smoke / test 友好且必有限）。
const RUN_STEPS_DEFAULT: u64 = 5_000;

/// P1-A.9（P1-3）—— periodic status 的固定 **step interval**（逻辑条件：`steps % 100 == 0`）。
///
/// 选择理由：
/// - **不使用墙钟**（无 `Instant` / `SystemTime` / sleep 耦合）⇒ 完全确定性、可单测、不改变
///   step timing / 不引入时间依赖；
/// - 小整数（100）：默认预算 `RUN_STEPS_DEFAULT = 5_000` ⇒ 最多约 50 行 status（**无日志洪水**），
///   且默认 1ms pacing 下约每 0.1s 一行 ⇒ "可观测但不过量"；
/// - 输出路径复用既有 `write_stdout`（stdout only）⇒ **零新依赖** / 无日志框架 / 无 metrics crate。
const STATUS_INTERVAL_STEPS: u64 = 100;

/// P1-A.9（P1-3）—— 是否在本 step 输出 status（确定性；固定 interval）。
///
/// `steps` 从 1 起 ⇒ 首个 status 在 `STATUS_INTERVAL_STEPS`（**不**在 step 0 / 不每 step）。
fn should_emit_status(steps: u64) -> bool {
    steps > 0 && steps.is_multiple_of(STATUS_INTERVAL_STEPS)
}

/// CLI 契约文本（非日志；不含任何完成度宣称）。
const HELP: &str = "\
YAZIMAO node
bootstrap/devnet/testnet oriented executable skeleton

NOT MAINNET READY

P1-A.3 scope: CLI parsing + genesis pre-flight validation + NodeConfig assembly +
seed-based network/validator identities + runtime assembly verification + a bounded
long-running drive loop over the existing NodeRuntime::step().
Signal handling (Ctrl-C / SIGTERM) and a graceful-shutdown policy are NOT implemented:
this build drives the runtime for a bounded number of steps (--run-steps) and then
performs the existing runtime shutdown and exits; external termination relies on OS
default termination (durable storage/safety state is crash-consistent).

Networking model (current architecture):
  configured peers only
  automatic peer discovery is not implemented
  zero-operator / permissionless bootstrap is NOT complete

Usage:
  yazimao-node --genesis <path> --genesis-hash <hex64> --chain-id <u64> \\
               --network-id <devnet|testnet|mainnet> --storage-dir <path> \\
               --network-seed-file <path> [options]

Required:
  --genesis <path>              canonical genesis bytes
  --genesis-hash <hex64>        external trust anchor (never derived from the file)
  --chain-id <u64>              expected chain id (== genesis chain_id)
  --network-id <devnet|testnet|mainnet>
  --storage-dir <path>          canonical chain storage directory
  --network-seed-file <path>    32-byte network identity seed (hex64)

Options:
  --listen <ip:port>            enable inbound TCP listener (omitted = disabled)
  --peer <nodeid_hex@ip:port>   configured peer target (repeatable)
  --validator                   validator mode (requires --safety-dir and
                                --validator-seed-file; refused with --network-id mainnet)
  --safety-dir <path>           validator safety journal directory
  --validator-seed-file <path>  32-byte validator identity seed (hex64)
  --init-validator-safety       declare a NEW validator safety store initialization
                                (requires --validator; refused with --network-id mainnet;
                                 rejected if a safety journal already exists; NOT a recovery)
  --idle-ms <n>                 bounded idle interval in ms (default 1, maximum 50)
  --run-steps <n>               run for n steps and exit (default 5000)
  --run-steps 0                 run continuously without a step limit
  --help                        print this help and exit 0
  --version                     print version and exit 0
";

/// CLI 解析 / 交叉校验错误（binary-local；**不混入** `NodeRuntimeError`）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CliError {
    /// 未知 `--flag`（不静默忽略）。
    UnknownArgument(String),
    /// 位置参数（本 CLI 不接受）。
    UnexpectedPositional(String),
    /// `--flag` 缺少值。
    MissingValue(&'static str),
    /// 单值参数重复出现。
    DuplicateArgument(&'static str),
    /// 必填参数缺失。
    MissingRequired(&'static str),
    /// `--genesis-hash` 非 64 位十六进制。
    InvalidGenesisHash,
    /// `--chain-id` 非 u64。
    InvalidChainId,
    /// `--network-id` 非 devnet / testnet / mainnet。
    InvalidNetworkId(String),
    /// `--listen` 非合法 `ip:port`。
    InvalidListenAddr(String),
    /// `--peer` 非 `nodeid_hex@ip:port`。
    InvalidPeerFormat(String),
    /// `--idle-ms` 为 0 或 > 50（或非数字）。
    InvalidIdleMs,
    /// `--run-steps` 非数字或为 0（必须 > 0）。
    InvalidRunSteps,
    /// `--validator` 未提供 `--safety-dir`。
    ValidatorRequiresSafetyDir,
    /// `--validator` 未提供 `--validator-seed-file`。
    ValidatorRequiresSeedFile,
    /// `--validator` + `--network-id mainnet`（Mainnet 级密钥管理未实现）。
    MainnetValidatorUnsupported,
    /// `--init-validator-safety` 未同时提供 `--validator`（不静默忽略）。
    InitValidatorSafetyRequiresValidator,
    /// `--init-validator-safety` + `--network-id mainnet`（禁止以 flag 初始化安全状态）。
    InitValidatorSafetyUnsupportedOnMainnet,
}

/// genesis pre-flight 错误（fail-closed；非零退出）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreflightError {
    /// genesis 文件不可读。
    GenesisRead,
    /// genesis canonical bytes 解码失败。
    GenesisDecode,
    /// genesis hash 计算失败。
    GenesisHashCompute,
    /// 计算出的 genesis hash ≠ `--genesis-hash`（外部信任锚）。
    GenesisHashMismatch,
    /// `validate_genesis_with_expected` 拒绝（identity / 内部不变量）。
    GenesisValidation,
    /// genesis `chain_id` ≠ `--chain-id`。
    ChainIdMismatch { expected: u64, found: u64 },
    /// genesis `network_id` ≠ `--network-id`。
    NetworkIdMismatch {
        expected: NetworkId,
        found: NetworkId,
    },
    /// 构造出的 ValidatorSet 为空（无 proposer / 无 quorum ⇒ fail-closed）。
    EmptyValidatorSet,
}

/// seed 文件错误（binary-local；fail-closed；**绝不携带 seed 内容**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedError {
    /// 文件不可读（不存在 / 权限）。
    Read,
    /// 文件内容非 UTF-8。
    NotUtf8,
    /// 文件以 UTF-8 BOM 开头（禁止）。
    Bom,
    /// 非 64 位十六进制（长度错误 / 非 hex / 多余非空白内容 / 空内容）。
    Malformed,
}

/// 身份装配错误（binary-local；fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityError {
    /// 网络身份与验证者身份派生公钥相同（禁止同一 key 兼任两种身份）。
    NetworkAndValidatorIdentityMustDiffer,
    /// validator 身份不在 genesis ValidatorSet 中。
    ValidatorNotInValidatorSet,
    /// runtime 未装配网络层（逻辑错误；应为 `Some`）。
    NetworkStackMissing,
    /// runtime 报告的 NodeId ≠ 由 network seed 派生的 NodeId。
    NetworkNodeIdMismatch,
    /// peer-auth 未启用（应为 `true`）。
    PeerAuthDisabled,
    /// `--listen` 指定但 runtime 未报告真实监听地址。
    ListenNotBound,
    /// 未指定 `--listen` 但 runtime 报告了监听地址。
    UnexpectedListener,
    /// 未拨号 / 未 accept 前出现入站连接（应为 0）。
    UnexpectedInboundConnections,
}

/// 入口层错误（CLI / pre-flight / seed / 身份 / runtime 装配 / 输出）。
///
/// 注：`Shutdown` 不携带 `ShutdownError` 细节（该类型未实现 `PartialEq`）；仅以非零退出码揭示失败。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupError {
    /// CLI 解析 / 交叉校验失败。
    Cli(CliError),
    /// genesis pre-flight 失败。
    Preflight(PreflightError),
    /// seed 文件读取 / 解析失败。
    Seed(SeedError),
    /// 身份装配 / 运行时断言失败。
    Identity(IdentityError),
    /// `NodeRuntime` 装配失败（既有 typed 错误透传）。
    Runtime(NodeRuntimeError),
    /// 运行循环中 `NodeRuntime::step()` 失败（fail-closed）。
    ///
    /// 载荷 = **稳定类别名**（绝大多数变体）或「类别名 + `BlockCommit` 的真实 inner error」：
    /// - 既有 `RuntimeError` 仅实现 `Debug`（`crates/node/src/runtime.rs`，本轮**冻结不可改**）
    ///   ⇒ 无法整体搬入 `StartupError` 的 `Clone/PartialEq/Eq` 派生；
    /// - 其 `Debug` 文本可能包含 session/nonce 类运行期材料 ⇒ 入口层不复制底层载荷文本；
    /// - 而 `RuntimeError::BlockCommit` 的 payload 是 **typed 且确定性**的
    ///   `NodeBlockApplicationError`（`Display` 沿四域分类链展开 decode / validation /
    ///   execution / storage），不含运行期材料 ⇒ 允许以 `String` 保留其 `Display`
    ///   （**P1-A.17 F-1 诊断**，Owner 授权；否则失败闸门不可判定）。
    ///
    /// 错误事实仍 fail-closed 传播（非 0 退出，未吞错）。
    Run(String),
    /// 既有 `NodeRuntime::shutdown` 失败（D-A2-1 ② 资源释放）。
    Shutdown,
    /// CLI 契约输出写失败（stdout）。
    OutputWrite,
}

/// 解析结果三态：帮助 / 版本 / 运行（配置门）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// `--help`
    Help,
    /// `--version`
    Version,
    /// 配置门（P1-A.1 的终点）。
    Run(Box<Cli>),
}

/// 已校验的 CLI 配置（NodeConfig 的唯一来源；字段与 CLI 一一对应）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    genesis: PathBuf,
    genesis_hash: [u8; 32],
    chain_id: u64,
    network_id: NetworkId,
    storage_dir: PathBuf,
    listen_addr: Option<SocketAddr>,
    peers: Vec<ConnectionTarget>,
    validator: bool,
    safety_dir: Option<PathBuf>,
    validator_seed_file: Option<PathBuf>,
    /// G5-D.7.2：显式声明“本次启动是一次**新的** validator safety store 初始化”（非恢复）。
    init_validator_safety: bool,
    network_seed_file: PathBuf,
    idle_ms: u64,
    /// 本进程最多执行的 `NodeRuntime::step()` 次数（`--run-steps`；必 > 0）。
    run_steps: u64,
}

// ---------------------------------------------------------------------------
// 解析原语（纯函数；无 I/O）
// ---------------------------------------------------------------------------

/// 单十六进制字符 → 半字节。
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 严格 64 位十六进制 → 32B（长度 / 字符任一非法 ⇒ `None`）。
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// `devnet` / `testnet` / `mainnet` → 既有 crypto `NetworkId`（不新增枚举）。
fn parse_network_id(s: &str) -> Result<NetworkId, CliError> {
    match s {
        "devnet" => Ok(NetworkId::Devnet),
        "testnet" => Ok(NetworkId::Testnet),
        "mainnet" => Ok(NetworkId::Mainnet),
        other => Err(CliError::InvalidNetworkId(other.to_string())),
    }
}

/// `<nodeid_hex@ip:port>` → `ConnectionTarget`（复用既有 network 类型）。
fn parse_peer(s: &str) -> Result<ConnectionTarget, CliError> {
    let (id_hex, addr_str) = s
        .split_once('@')
        .ok_or_else(|| CliError::InvalidPeerFormat(s.to_string()))?;
    let id = parse_hex32(id_hex).ok_or_else(|| CliError::InvalidPeerFormat(s.to_string()))?;
    let address =
        SocketAddr::from_str(addr_str).map_err(|_| CliError::InvalidPeerFormat(s.to_string()))?;
    Ok(ConnectionTarget {
        peer_id: NodeId::from_bytes(id),
        address,
    })
}

/// 取 `--flag` 的值；缺失 / 下一个 token 仍是 `--flag` ⇒ `MissingValue`。
///
/// 严格语义：值不得以 `--` 开头（路径若需以 `--` 开头，本 CLI 不支持；fail-closed）。
fn take_value<'a>(
    args: &'a [String],
    idx: &mut usize,
    flag: &'static str,
) -> Result<&'a str, CliError> {
    let Some(next) = args.get(*idx + 1) else {
        return Err(CliError::MissingValue(flag));
    };
    if next.starts_with("--") {
        return Err(CliError::MissingValue(flag));
    }
    *idx += 2;
    Ok(next.as_str())
}

// ---------------------------------------------------------------------------
// CLI 解析（严格 fail-closed）
// ---------------------------------------------------------------------------

/// 先判定 `--help` / `--version`（CLI 契约；优先于其它校验），否则完整解析。
fn classify(args: &[String]) -> Result<Action, CliError> {
    if args.iter().any(|a| a == "--help") {
        return Ok(Action::Help);
    }
    if args.iter().any(|a| a == "--version") {
        return Ok(Action::Version);
    }
    Ok(Action::Run(Box::new(parse_args(args)?)))
}

/// 严格解析 CLI 参数；任何未知 / 重复 / 缺失 / 非法值 ⇒ `Err`（不静默忽略）。
fn parse_args(args: &[String]) -> Result<Cli, CliError> {
    let mut genesis: Option<PathBuf> = None;
    let mut genesis_hash: Option<[u8; 32]> = None;
    let mut chain_id: Option<u64> = None;
    let mut network_id: Option<NetworkId> = None;
    let mut storage_dir: Option<PathBuf> = None;
    let mut listen_addr: Option<SocketAddr> = None;
    let mut listen_set = false;
    let mut peers: Vec<ConnectionTarget> = Vec::new();
    let mut validator = false;
    let mut safety_dir: Option<PathBuf> = None;
    let mut validator_seed_file: Option<PathBuf> = None;
    let mut init_validator_safety = false;
    let mut network_seed_file: Option<PathBuf> = None;
    let mut idle_ms: Option<u64> = None;
    let mut run_steps: Option<u64> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--genesis" => {
                if genesis.is_some() {
                    return Err(CliError::DuplicateArgument("--genesis"));
                }
                genesis = Some(PathBuf::from(take_value(args, &mut i, "--genesis")?));
            }
            "--genesis-hash" => {
                if genesis_hash.is_some() {
                    return Err(CliError::DuplicateArgument("--genesis-hash"));
                }
                let raw = take_value(args, &mut i, "--genesis-hash")?;
                genesis_hash = Some(parse_hex32(raw).ok_or(CliError::InvalidGenesisHash)?);
            }
            "--chain-id" => {
                if chain_id.is_some() {
                    return Err(CliError::DuplicateArgument("--chain-id"));
                }
                let raw = take_value(args, &mut i, "--chain-id")?;
                chain_id = Some(raw.parse::<u64>().map_err(|_| CliError::InvalidChainId)?);
            }
            "--network-id" => {
                if network_id.is_some() {
                    return Err(CliError::DuplicateArgument("--network-id"));
                }
                let raw = take_value(args, &mut i, "--network-id")?;
                network_id = Some(parse_network_id(raw)?);
            }
            "--storage-dir" => {
                if storage_dir.is_some() {
                    return Err(CliError::DuplicateArgument("--storage-dir"));
                }
                storage_dir = Some(PathBuf::from(take_value(args, &mut i, "--storage-dir")?));
            }
            "--listen" => {
                if listen_set {
                    return Err(CliError::DuplicateArgument("--listen"));
                }
                let raw = take_value(args, &mut i, "--listen")?;
                listen_addr = Some(
                    SocketAddr::from_str(raw)
                        .map_err(|_| CliError::InvalidListenAddr(raw.to_string()))?,
                );
                listen_set = true;
            }
            "--peer" => {
                let raw = take_value(args, &mut i, "--peer")?;
                peers.push(parse_peer(raw)?);
            }
            "--validator" => {
                if validator {
                    return Err(CliError::DuplicateArgument("--validator"));
                }
                validator = true;
                i += 1;
            }
            "--init-validator-safety" => {
                if init_validator_safety {
                    return Err(CliError::DuplicateArgument("--init-validator-safety"));
                }
                init_validator_safety = true;
                i += 1;
            }
            "--safety-dir" => {
                if safety_dir.is_some() {
                    return Err(CliError::DuplicateArgument("--safety-dir"));
                }
                safety_dir = Some(PathBuf::from(take_value(args, &mut i, "--safety-dir")?));
            }
            "--validator-seed-file" => {
                if validator_seed_file.is_some() {
                    return Err(CliError::DuplicateArgument("--validator-seed-file"));
                }
                validator_seed_file = Some(PathBuf::from(take_value(
                    args,
                    &mut i,
                    "--validator-seed-file",
                )?));
            }
            "--network-seed-file" => {
                if network_seed_file.is_some() {
                    return Err(CliError::DuplicateArgument("--network-seed-file"));
                }
                network_seed_file = Some(PathBuf::from(take_value(
                    args,
                    &mut i,
                    "--network-seed-file",
                )?));
            }
            "--idle-ms" => {
                if idle_ms.is_some() {
                    return Err(CliError::DuplicateArgument("--idle-ms"));
                }
                let raw = take_value(args, &mut i, "--idle-ms")?;
                let v = raw.parse::<u64>().map_err(|_| CliError::InvalidIdleMs)?;
                // 0 = 忙循环（CPU 火焰），> IDLE_MS_MAX = 不可接受的响应/停机延迟 ⇒ 双双拒绝。
                if v == 0 || v > IDLE_MS_MAX {
                    return Err(CliError::InvalidIdleMs);
                }
                idle_ms = Some(v);
            }
            "--run-steps" => {
                if run_steps.is_some() {
                    return Err(CliError::DuplicateArgument("--run-steps"));
                }
                let raw = take_value(args, &mut i, "--run-steps")?;
                let v = raw.parse::<u64>().map_err(|_| CliError::InvalidRunSteps)?;
                // B1（Testnet）—— `0` = **continuous / unlimited**（不因 step 预算自然退出）；
                // `N > 0` = 有限预算（既有语义**完全不变**；全部测试继续依赖有限值）。
                run_steps = Some(v);
            }
            other if other.starts_with("--") => {
                return Err(CliError::UnknownArgument(other.to_string()));
            }
            other => {
                return Err(CliError::UnexpectedPositional(other.to_string()));
            }
        }
    }

    let genesis = genesis.ok_or(CliError::MissingRequired("--genesis"))?;
    let genesis_hash = genesis_hash.ok_or(CliError::MissingRequired("--genesis-hash"))?;
    let chain_id = chain_id.ok_or(CliError::MissingRequired("--chain-id"))?;
    let network_id = network_id.ok_or(CliError::MissingRequired("--network-id"))?;
    let storage_dir = storage_dir.ok_or(CliError::MissingRequired("--storage-dir"))?;
    let network_seed_file =
        network_seed_file.ok_or(CliError::MissingRequired("--network-seed-file"))?;

    // 交叉校验（validator 模式 + Mainnet 安全门 + 显式初始化安全门）。
    // Guard A（G5-D.7.2）：`--init-validator-safety` 必须与 `--validator` 同时提供（不静默忽略）。
    if init_validator_safety && !validator {
        return Err(CliError::InitValidatorSafetyRequiresValidator);
    }
    // Guard B（G5-D.7.2）：mainnet 下禁止以 flag 初始化安全状态
    //（mainnet 丢失安全状态必须经备份恢复 / 单独授权，不能由启动 flag 自修复）。
    if init_validator_safety && network_id == NetworkId::Mainnet {
        return Err(CliError::InitValidatorSafetyUnsupportedOnMainnet);
    }
    if validator {
        if safety_dir.is_none() {
            return Err(CliError::ValidatorRequiresSafetyDir);
        }
        if validator_seed_file.is_none() {
            return Err(CliError::ValidatorRequiresSeedFile);
        }
        if network_id == NetworkId::Mainnet {
            return Err(CliError::MainnetValidatorUnsupported);
        }
    }

    Ok(Cli {
        genesis,
        genesis_hash,
        chain_id,
        network_id,
        storage_dir,
        listen_addr,
        peers,
        validator,
        safety_dir,
        validator_seed_file,
        init_validator_safety,
        network_seed_file,
        idle_ms: idle_ms.unwrap_or(IDLE_MS_DEFAULT),
        run_steps: run_steps.unwrap_or(RUN_STEPS_DEFAULT),
    })
}

// ---------------------------------------------------------------------------
// genesis pre-flight（只读；fail-closed）
// ---------------------------------------------------------------------------

/// 启动前 genesis 校验：read → decode → hash → 锚比对 → 全量校验 → chain/network → ValidatorSet。
///
/// `--genesis-hash` 是**外部信任锚**：绝不从文件推导、绝不自动生成。
fn preflight(cli: &Cli) -> Result<(ChainIdentity, ValidatorSet), PreflightError> {
    let bytes = std::fs::read(&cli.genesis).map_err(|_| PreflightError::GenesisRead)?;
    let genesis = decode_genesis_bytes(&bytes).map_err(|_| PreflightError::GenesisDecode)?;
    let computed =
        compute_genesis_hash(&genesis).map_err(|_| PreflightError::GenesisHashCompute)?;
    if computed != cli.genesis_hash {
        return Err(PreflightError::GenesisHashMismatch);
    }
    let identity = validate_genesis_with_expected(&genesis, &cli.genesis_hash)
        .map_err(|_| PreflightError::GenesisValidation)?;
    if identity.chain_id != cli.chain_id {
        return Err(PreflightError::ChainIdMismatch {
            expected: cli.chain_id,
            found: identity.chain_id,
        });
    }
    if identity.network_id != cli.network_id {
        return Err(PreflightError::NetworkIdMismatch {
            expected: cli.network_id,
            found: identity.network_id,
        });
    }
    // ValidatorSet 必须可构造且非空（空集 ⇒ 无 proposer / 无 quorum ⇒ fail-closed）。
    let set = ValidatorSet::from_genesis(&genesis);
    if set.is_empty() {
        return Err(PreflightError::EmptyValidatorSet);
    }
    Ok((identity, set))
}

// ---------------------------------------------------------------------------
// NodeConfig 组装（G5-D.7.2：新增且仅新增 `validator_safety_init`）
// ---------------------------------------------------------------------------

/// 由已校验 CLI 组装既有 `NodeConfig`（字段一一映射；G5-D.7.2 新增 `validator_safety_init`）。
fn build_node_config(cli: &Cli) -> NodeConfig {
    NodeConfig {
        genesis_path: cli.genesis.clone(),
        expected_genesis_hash: cli.genesis_hash,
        expected_chain_id: cli.chain_id,
        expected_network_id: cli.network_id,
        storage_dir: cli.storage_dir.clone(),
        validator_enabled: cli.validator,
        // G5-D.7.2：显式初始化信号（runtime 只在 journal 缺失且该值为 true 时 create）。
        validator_safety_init: cli.init_validator_safety,
        // full-node 形态下 runtime 不触碰 safety 路径（仅 validator 模式经 build_validator 使用）；
        // 未显式提供时取 storage_dir 下的确定性占位路径（不创建、不读取）。
        safety_dir: cli
            .safety_dir
            .clone()
            .unwrap_or_else(|| cli.storage_dir.join("safety")),
        // 语义 = “由调用方注入 provider 实例”：本骨架**不构造** provider（P1-A.2 注入 seed 适配器）。
        key_provider_config: KeyProviderConfig::None,
        peers: cli.peers.clone(),
        listen_addr: cli.listen_addr,
    }
}

// ---------------------------------------------------------------------------
// P1-A.2：seed 装载 / 身份 / 基座 transport / NodeRuntime 装配（**不含事件循环**）
// ---------------------------------------------------------------------------

/// 读取 seed 文件：严格 64 位十六进制（允许尾部空白；禁止 BOM / 空 / 非 hex / 多余内容）。
///
/// 只读；**不**自动生成 / 不写回 / 不回显（错误类型不携带任何 seed 内容）。
/// hex 读缓冲为 `zeroize::Zeroizing<Vec<u8>>` ⇒ **全部**返回路径（含所有 early return /
/// BOM / 非 UTF-8 / 长度 / 非 hex 错误）都在 Drop 时正式清零（volatile 语义）。
fn read_seed_file(path: &Path) -> Result<[u8; 32], SeedError> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| SeedError::Read)?);
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SeedError::Bom);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| SeedError::NotUtf8)?;
    parse_hex32(text.trim_end()).ok_or(SeedError::Malformed)
}

/// 32B → 小写 hex（仅用于**非敏感**输出，如 NodeId）。
fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 网络身份（binary-local）：仅持有 network seed 派生的 `SigningKey`。
///
/// `node_id()` = `NodeId::from_verifying_key(...)`（与生产同源）；`sign_envelope` 直接调用
/// `nova_network::message::sign_message`（**不重新实现**信封签名算法）。
struct SeedNetworkIdentity {
    signing: SigningKey,
}

impl NetworkSigner for SeedNetworkIdentity {
    fn node_id(&self) -> NodeId {
        NodeId::from_verifying_key(&self.signing.verifying_key())
    }

    fn sign_envelope(&self, envelope: &mut MessageEnvelope) -> Result<(), NetworkSigningError> {
        sign_message(&self.signing, envelope).map_err(NetworkSigningError::Sign)
    }
}

/// validator 签名器（binary-local）：语义与 `SoftwareSigner` **逐字节同源**
///（同一 `sign_message_hash` 原语；不复制签名算法 / 不暴露私钥）。
struct SeedSigner {
    signing: SigningKey,
}

impl SigningCapability for SeedSigner {
    fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(&self.signing, message_hash))
    }
}

/// validator KeyProvider（binary-local）：take-once（与 `SoftwareKeyProvider` 同语义；
/// 第二次 `load_signer` ⇒ `AlreadyProvisioned`）。
struct SeedKeyProvider {
    signing: RefCell<Option<SigningKey>>,
}

impl SeedKeyProvider {
    fn from_signing_key(signing: SigningKey) -> Self {
        Self {
            signing: RefCell::new(Some(signing)),
        }
    }
}

impl KeyProvider for SeedKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        let signing = self
            .signing
            .borrow_mut()
            .take()
            .ok_or(KeyProviderError::AlreadyProvisioned)?;
        Ok(Box::new(SeedSigner { signing }))
    }
}

/// production 基座 transport（binary-local）：**诚实失败**的空实现。
///
/// 真实流量路径：(a) 入站 TCP 由 runtime 的 `InboundListenerState` + multiplex 承载；
/// (b) configured peer 出站由 `NetworkService` 的 `TcpDialer` 连接承载。
/// 本基座仅满足注入参数；**不静默成功**（`TransportIo`）——**不使用**测试语义的 `MemoryTransport`。
struct IdleTransport;

impl Transport for IdleTransport {
    fn send(&mut self, _peer: &NodeId, _message: Vec<u8>) -> Result<(), NetworkError> {
        Err(NetworkError::TransportIo)
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        Ok(None)
    }

    fn is_closed(&self) -> bool {
        false
    }
}

/// 装配结果（仅**非敏感**可观测值；用于 CLI 契约输出与测试断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeReport {
    node_id: NodeId,
    listen_addr: Option<SocketAddr>,
    peer_auth_enabled: bool,
    inbound_connections: usize,
}

/// seed 装载 → 身份 → 基座 transport → `NodeRuntime` 装配 → 装配断言 ⇒ 返回**已装配且未 shutdown**
/// 的 runtime（P1-A.2 为装配后立即 shutdown；P1-A.3 起 shutdown 归 `main`，**恰好一次**）。
///
/// 边界：**不**驱动循环（归 [`run_node_loop`]）；**不**拨号（归 [`run_node_loop`] 的幂等
/// `establish_configured_peers`）；**不**修改 runtime / provider / identity 既有实现。
fn assemble_and_verify_runtime(
    cli: &Cli,
    set: &ValidatorSet,
) -> Result<(NodeRuntime, RuntimeReport), StartupError> {
    // 1. 网络身份（必填 seed；只读；派生后立即清零临时 buffer）。
    //    `Zeroizing` 同时覆盖所有 early return（`?`）路径 —— 不留栈残留。
    let mut net_seed =
        Zeroizing::new(read_seed_file(&cli.network_seed_file).map_err(StartupError::Seed)?);
    let net_signing = SigningKey::from_seed(*net_seed);
    net_seed.zeroize();
    let net_vk_bytes = net_signing.verifying_key().to_bytes();
    let network_identity = SeedNetworkIdentity {
        signing: net_signing,
    };
    let expected_node_id = network_identity.node_id();

    // 2. validator 身份（仅 validator 模式）：身份分离 + 成员预检 + KeyProvider。
    let provider = if cli.validator {
        let path = cli
            .validator_seed_file
            .as_ref()
            .ok_or(StartupError::Cli(CliError::ValidatorRequiresSeedFile))?;
        let mut val_seed = Zeroizing::new(read_seed_file(path).map_err(StartupError::Seed)?);
        let val_signing = SigningKey::from_seed(*val_seed);
        val_seed.zeroize();
        let val_vk_bytes = val_signing.verifying_key().to_bytes();
        if val_vk_bytes == net_vk_bytes {
            return Err(StartupError::Identity(
                IdentityError::NetworkAndValidatorIdentityMustDiffer,
            ));
        }
        let validator_id = ValidatorId::from_consensus_public_key(&val_vk_bytes);
        if !set.contains(&validator_id) {
            return Err(StartupError::Identity(
                IdentityError::ValidatorNotInValidatorSet,
            ));
        }
        Some(SeedKeyProvider::from_signing_key(val_signing))
    } else {
        None
    };

    // 3. 既有 NodeConfig 组装（无新字段）+ 既有 `start_with_network`（**不改 runtime**）。
    let config = build_node_config(cli);
    let runtime = NodeRuntime::start_with_network(
        &config,
        provider.as_ref().map(|p| p as &dyn KeyProvider),
        Box::new(IdleTransport),
        Box::new(network_identity),
    )
    .map_err(StartupError::Runtime)?;

    // 4. 装配断言（全部经公开只读访问器；未进入事件循环 ⇒ 无 `step()`）。
    let node_id = runtime
        .network_node_id()
        .ok_or(StartupError::Identity(IdentityError::NetworkStackMissing))?;
    if node_id != expected_node_id {
        return Err(StartupError::Identity(IdentityError::NetworkNodeIdMismatch));
    }
    if !runtime.network_peer_auth_enabled() {
        return Err(StartupError::Identity(IdentityError::PeerAuthDisabled));
    }
    let listen_addr = runtime.network_listen_addr();
    match (cli.listen_addr, listen_addr) {
        (Some(_), None) => return Err(StartupError::Identity(IdentityError::ListenNotBound)),
        (None, Some(_)) => return Err(StartupError::Identity(IdentityError::UnexpectedListener)),
        _ => {}
    }
    let inbound_connections = runtime.network_inbound_connection_count();
    if inbound_connections != 0 {
        return Err(StartupError::Identity(
            IdentityError::UnexpectedInboundConnections,
        ));
    }
    let report = RuntimeReport {
        node_id,
        listen_addr,
        peer_auth_enabled: true,
        inbound_connections,
    };

    // 5. 装配完成 ⇒ **不在此处** shutdown（P1-A.3：循环结束后由 `main` 在所有路径上恰调用一次）。
    Ok((runtime, report))
}

// ---------------------------------------------------------------------------
// P1-A.3：有界长运行驱动循环（唯一驱动点 = 既有 `NodeRuntime::step()`）
// ---------------------------------------------------------------------------

/// 有界运行摘要（仅**非敏感**观测值）；不含 seed / 私钥 / 任何秘密材料。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunSummary {
    /// 实际执行的 `NodeRuntime::step()` 调用次数（含返回 `Err` 的那一次；`<= run_steps`）。
    steps: u64,
    /// 本进程的 step 预算（`--run-steps`）。
    run_steps: u64,
    /// canonical head 高度（无对端 / 未收到块时为 genesis head；P1-A.24 起 full-node 同样具备
    /// canonical adapter，可随链推进）。
    head_height: u64,
    /// configured peers 中已认证 `Established` 的数量。
    established_peers: usize,
    /// configured peers 总数。
    configured_peers: usize,
    /// 退出时并存入站连接数。
    inbound_connections: usize,
    /// 累计成功注册的入站连接数（单调；确定性观测）。
    inbound_accepted: u64,
    /// P1-A.9（P1-3）—— 已 finalize 高度（= durable per-height PrecommitQC 最高高度；
    /// `None` = 尚未产生/持久化任何 finality）。**既有只读 accessor**，不扩张 runtime API。
    finalized_height: Option<u64>,
    /// P1-A.9（P1-3）—— 共识当前高度（`consensus.round.height`）。
    consensus_height: u64,
    /// P1-A.9（P1-3）—— 共识当前轮次（`consensus.round.round`）。
    round: u64,
    /// P1-A.9（P1-3）—— 有界 sync pending intent 数。
    sync_pending: usize,
    /// P1-A.12-DIAG（**仅观测**）—— `block_inbound_skipped` 累计数（既有只读 accessor；
    /// 用于区分「未收到响应」与「收到但 A3 轮次证据不一致而 skip」）。
    block_inbound_skipped: u64,
    /// P1-A.12-DIAG（**仅观测**）—— 当前 pending external QC 条数（≤ `PENDING_EXTERNAL_QC_CAP`；
    /// A3 sync 分支轮次证据的唯一来源）。
    pending_external_qc: usize,
    /// P1-A.12-DIAG（**仅观测**）—— 已附发历史 QC 数（sync responder 服务能力）。
    qc_served: u64,
    /// P1-A.9（P1-3）—— 本进程是否 validator 形态（proposal/vote/finality 推进）。
    validator_enabled: bool,
    /// P1-A.9（P1-3）—— A.8 dial 尝试总数（saturating；恒定观测）。
    peer_dial_attempts_total: u64,
    /// P1-A.9（P1-3）—— A.8 dial 失败总数（saturating；恒定观测）。
    peer_dial_failures_total: u64,
    /// PHASE 6H-AH — O2 观测（全部为 runtime **既有**只读 accessor；不新增语义）。
    /// 本地真实 EXPIRE 产生的 Abandon attestation 数。
    abandon_produced: u64,
    /// 已**发出**（`broadcast` 已入队）的本地 `0x0E` attestation 数。
    abandon_broadcast: u64,
    /// 入站 `0x0E` attestation 被拒数。
    abandon_rejected: u64,
    /// 池内组装完成并经**既有 `0x0D`** 广播的证书数。
    rc_certs: u64,
    /// 经**证书**（D1 authority）应用的 round change 数。
    rc_authority: u64,
    /// 入站 `0x0D` 证书被拒数。
    rc_rejected: u64,
    /// P1-A.30 **D0** — RC 拒绝原因分类 `[malformed, stale, wrong_height, quorum, identity, other]`
    /// （既有 `rc_rejected` 总数**不变**；本字段仅**拆分**同一批事件）。
    rc_reject_buckets: [u64; 6],
    /// P1-A.30 **D0** — RC 证书广播 `Ok(0)`（零 Established 对端）次数。
    rc_bcast_no_peer: u64,
    /// P1-A.30 **D0** — Abandon attestation 广播 `Ok(0)`（零 Established 对端）次数。
    abandon_bcast_no_peer: u64,
    /// P1-A.30 **D0** — 暂存证书重评尝试次数（每 step ≤ 1）。
    rc_reeval_attempts: u64,
    /// P1-A.30 **D0** — 暂存证书重评**成功应用**次数（恒 ≤ `rc_reeval_attempts`）。
    rc_reeval_applied: u64,
    /// P1-A.30 **D0** — 本地 timeout 结果分类 `[applied, ignored, rejected]`
    /// （总数见 `round_timeouts`；本字段仅**拆分**同一批事件）。
    timeout_outcomes: [u64; 3],
    /// P1-A.30 **D0** — Guard C 拒绝分类计数（8 类固定序；数据源 = 既有 PendingProposalStore）。
    guard_rej: [u64; 8],
    /// P1-A.30 **D0′** — 入站队列溢出丢弃
    /// `[block_inbound, sync_requests, round_changes, abandon_attestations]`（既有 handler 计数）。
    wire_drops: [u64; 4],
    /// ── PHASE 6H-AQ — pacemaker / round **只读观测**（纯诊断；零语义 / 零状态机影响）──
    /// 本地 round timeout **已触发次数**（含被冻结 `checked_successor` 拒绝的尝试）。
    /// `0` = 从未到达 `Expired`（既有只读 accessor；不新增语义）。
    round_timeouts: u64,
    /// 当前计时器已历 step 数（`None` = 尚未 arm / **已被 finality DISARM**）。
    timer_elapsed: Option<u64>,
    /// 当前计时器窗口（tick；`None` = 未 arm）。
    timer_window: Option<u64>,
    /// `consensus.round.step` 名称（Propose / Prevote / Precommit / Finalized）。
    round_step: &'static str,
    /// `consensus.round.proposal.is_some()`（DISARM 谓词输入之一）。
    proposal_present: bool,
    /// `consensus.finality.finalized_reference.is_some()`（DISARM 谓词输入之一）。
    finalized_ref_present: bool,
    /// ── PHASE 6H-A30 OD-X7 — liveness **只读**观测（OUTPUT_MODE=B：**独立** `liveness` 行）──
    /// 提案构造调用总数 / 成功提交数（既有 `status` 行**逐字不变**）。
    prop_calls: u64,
    /// 成功构造**并提交**提案次数。
    prop_build_ok: u64,
    /// 因"非当选者"跳过次数（只读复算）。
    prop_skip_not_elected: u64,
    /// 因 `rs.height != head.height` 跳过次数（只读复算）。
    prop_skip_height_desync: u64,
    /// 因阶段 / 幂等守卫跳过次数（只读复算）。
    prop_skip_step_guard: u64,
    /// SAFETY-REJECT-SKIP — 出块签名被 `block_safety` 冲突门正确拒绝而放弃的提案数（非 fatal）。
    prop_skip_conflict_target: u64,
    /// **残差**跳过次数（`calls − ok − known_skips`；**不**推断未知原因）。
    prop_skip_fail: u64,
    /// 入站提案消费数 / 本地产出入站登记数 / "零 Established 对端"丢弃数。
    inbound_prop_ok: u64,
    /// 本地提案被登记出站（`record_local_proposal`）次数。
    egress_prop_enqueued: u64,
    /// 单发广播**提案**时 `Established 对端 = 0`（静默丢弃）次数。
    egress_prop_no_peer: u64,
    /// PHASE 6H-A30 OD-X8 — 本地提案**有界重播**实际入队次数（直读 snapshot；**仅观测**，
    /// 不参与任何判定；`<= MAX_PROPOSAL_REFRESH x 本地提案数`）。
    egress_prop_refreshed: u64,
    /// round 前进来源分解：本地 pacemaker / 高度推进 / RC 权威（后者=既有 accessor）。
    round_adv_local: u64,
    /// 因高度推进（`advance_to_height`）导致 round 归零的次数。
    round_adv_height: u64,
    /// 经 RC 权威推进 round 的次数（= 既有 `round_changes_by_authority`，**仅暴露**）。
    round_adv_rc: u64,
    /// 瞬态：当前 `(height, round)` 当选者是否本节点（只读派生；无法判定 ⇒ `false`）。
    elected_is_self: bool,
    /// 瞬态：当前 `(height, round)` 内无提案的**连续 step** 数。
    prop_absent_steps: u64,
    /// ── PHASE 6H-A30 OD-X7b — 入站 proposal admission 生命周期（只读；既有真实计数）──
    /// Guard A2+C 通过（`note_admitted()`）累计。
    proposal_admitted: u64,
    /// 首次入 pending（`note_pended()`）累计（决策结果，非队列长度）。
    proposal_pending: u64,
    /// 准入拒绝累计（直拒 + recovery 拒）。
    proposal_rejected: u64,
    /// 到期淘汰（`sweep_expired()`）累计。
    proposal_expired: u64,
    /// ── PHASE 6H-A30 OD-X7d — 网络/事件环 **只读**诊断（直读既有 `diagnostics()`）──
    /// 已从 transport 读取的帧数 / 已入队 inbound 的有效事件数。
    net_frames_received: u64,
    net_events_enqueued: u64,
    /// 已成功发出的出站消息数。
    net_sent: u64,
    /// 因 invalid envelope/sender/超限丢帧数（注：**含**出站 send 失败，语义混合）。
    net_dropped_invalid: u64,
    /// NS inbound 队列满丢事件数。
    net_dropped_overflow: u64,
    /// 非 Established session 丢弃数。
    net_unauthenticated_drops: u64,
    /// handler 返回 Err 次数（wire decode 失败等）。
    el_handler_errors: u64,
    /// EventLoop 队列满丢事件数。
    el_events_dropped_overflow: u64,
    /// ── PHASE 6H-A30 OD-X7e — recovery / block readiness（直读既有 `A11Diag`）──
    /// pending recovery checkpoint 被调用次数 / 候选数 / 因区块未就绪保留数 / 接纳数 / 拒绝数。
    recovery_runs: u64,
    recovery_candidates: u64,
    recovery_kept_missing_block: u64,
    recovery_admitted: u64,
    recovery_rejected: u64,
    /// block inbound 处理数 / canonical-next 候选数 / 登记成功数。
    block_inbound_processed: u64,
    block_canonical_next: u64,
    block_register_ok: u64,
    /// ── PHASE 6H-A30 OD-X7f — `InboundBlockVerdict` 窗口内分类（只读；非累计）──
    /// 六项之和 == 既有 outcomes 窗口长度（bounded ≤128）。
    block_verdict_future_missing_ancestor: u64,
    block_verdict_already_known: u64,
    /// 真实变体 `Stale`（无 `Duplicate`）。
    block_verdict_stale: u64,
    /// 真实变体 `ConflictingParent`（无 `UnknownTarget`）。
    block_verdict_conflicting_parent: u64,
    block_verdict_malformed: u64,
    /// 残差（含 `CanonicalNextCandidate` 与其余 `InboundBlockError`）。
    /// PHASE 6H-A30 OD-X7g 起：`block_err_*` 已单独列出 ⇒ 本项 == 窗口内 CanonicalNextCandidate 数。
    block_verdict_other: u64,
    /// ── PHASE 6H-A30 OD-X7g — `Err(InboundBlockError)` 细分类（窗口内；真实变体 1:1）──
    /// 不变量：5 个 Ok 类 + malformed + 下列 10 类 + other == 既有 outcomes 窗口长度。
    block_err_oversized: u64,
    block_err_wrong_version: u64,
    block_err_wrong_chain: u64,
    block_err_hash_mismatch: u64,
    block_err_invalid_proposer_signature: u64,
    block_err_transaction_root_mismatch: u64,
    block_err_noncanonical_transaction_ordering: u64,
    block_err_state_root_mismatch: u64,
    block_err_unsupported_validation: u64,
    block_err_storage: u64,
    /// ── PHASE 6H-A30-OD-X7h — 入站 block **来源类别**归属（累计；非窗口）──
    /// 数据源 = `step()` 内既有 dispatch `source`（既有 match 分支）+ 该块既有 verdict。
    /// 一致性：gossip/sync 两项之和 == 累计 `InvalidProposerSignature` 数（≤128 判定时
    /// == 窗口内 `block_err_invalid_proposer_signature`）。
    block_src_gossip_total: u64,
    block_src_gossip_invalid_proposer_signature: u64,
    block_src_sync_total: u64,
    block_src_sync_invalid_proposer_signature: u64,
    /// ── PHASE 6H-A30-OD-X7i — Gossip IPS 来源分类（累计；A 证据冲突 / B 验签失败）──
    /// 不变量：A + B == 累计 gossip 路径 `InvalidProposerSignature` 数
    /// （wire hash 可解析时精确；归 A = dispatcher 在验签之前返回的 IPS）。
    block_gossip_invalid_proposer_signature_evidence_conflict: u64,
    block_gossip_invalid_proposer_signature_signature_failure: u64,
}

/// PHASE 6H-AQ — `RoundStep` 名称（只读观测；无状态机影响）。
fn round_step_name(step: RoundStep) -> &'static str {
    match step {
        RoundStep::Propose => "Propose",
        RoundStep::Prevote => "Prevote",
        RoundStep::Precommit => "Precommit",
        RoundStep::Finalized => "Finalized",
    }
}

/// PHASE 6H-AQ — `Option<u64>` 渲染（与既有 `finalized_height=none` 约定一致）。
fn opt_u64(v: Option<u64>) -> String {
    v.map_or_else(|| "none".to_string(), |x| x.to_string())
}

/// 采样当前 runtime 只读观测（不触碰秘密材料；全部用**既有** public accessor）。
fn summarize(runtime: &NodeRuntime, cli: &Cli, steps: u64) -> RunSummary {
    let head_height = runtime.block_production().map_or(0, |a| a.head().height);
    let established_peers = cli
        .peers
        .iter()
        .filter(|t| runtime.network_peer_established(t.peer_id))
        .count();
    let inbound_accepted = runtime
        .network_inbound_diagnostics()
        .map_or(0, |d| d.accepted);
    let consensus_height = runtime.driver().consensus().state().round.height;
    let round = runtime.driver().consensus().state().round.round;
    // PHASE 6H-AQ — 只读观测（既有 accessor + 既有 `pub` consensus 字段；不改状态机）。
    let state = runtime.driver().consensus().state();
    let round_step = round_step_name(state.round.step);
    let proposal_present = state.round.proposal.is_some();
    let finalized_ref_present = state.finality.finalized_reference.is_some();
    // PHASE 6H-A30 OD-X7 — 只读 liveness 快照（既有 accessor；不改状态机）。
    let live = runtime.liveness_snapshot();
    // P1-A.30 D0 — 只读诊断（拒绝原因分类 / 广播无对端 / 暂存重评 / 超时结果分类）。
    let rc_reeval = runtime.round_change_reeval();
    let rc_reject_buckets = [
        runtime.round_change_reject_count(RoundChangeRejectKind::Malformed),
        runtime.round_change_reject_count(RoundChangeRejectKind::Stale),
        runtime.round_change_reject_count(RoundChangeRejectKind::WrongHeight),
        runtime.round_change_reject_count(RoundChangeRejectKind::Quorum),
        runtime.round_change_reject_count(RoundChangeRejectKind::Identity),
        runtime.round_change_reject_count(RoundChangeRejectKind::Other),
    ];
    RunSummary {
        steps,
        run_steps: cli.run_steps,
        head_height,
        established_peers,
        configured_peers: cli.peers.len(),
        inbound_connections: runtime.network_inbound_connection_count(),
        inbound_accepted,
        finalized_height: runtime.qc_history_tip_height(),
        consensus_height,
        round,
        sync_pending: runtime.sync_pending_requests(),
        block_inbound_skipped: runtime.block_inbound_skipped(),
        pending_external_qc: runtime.pending_external_qc_len(),
        qc_served: runtime.qc_served(),
        validator_enabled: runtime.validator_enabled(),
        peer_dial_attempts_total: runtime.peer_dial_attempts_total(),
        peer_dial_failures_total: runtime.peer_dial_failures_total(),
        abandon_produced: runtime.abandon_attestations_produced(),
        abandon_broadcast: runtime.abandon_attestations_broadcast(),
        abandon_rejected: runtime.abandon_attestations_rejected(),
        rc_certs: runtime.round_change_certificates_assembled(),
        rc_authority: runtime.round_changes_by_authority(),
        rc_rejected: runtime.round_changes_rejected(),
        rc_reject_buckets,
        rc_bcast_no_peer: runtime.round_change_broadcast_no_peer(),
        abandon_bcast_no_peer: runtime.abandon_broadcast_no_peer(),
        rc_reeval_attempts: rc_reeval.0,
        rc_reeval_applied: rc_reeval.1,
        timeout_outcomes: [
            runtime.round_timeout_outcome(RoundTimeoutOutcome::Applied),
            runtime.round_timeout_outcome(RoundTimeoutOutcome::Ignored),
            runtime.round_timeout_outcome(RoundTimeoutOutcome::Rejected),
        ],
        guard_rej: runtime.guard_reject_counts(),
        wire_drops: runtime.inbound_queue_drops(),
        round_timeouts: runtime.round_timeouts(),
        timer_elapsed: runtime.round_timeout_elapsed_ms(),
        timer_window: runtime.round_timeout_window_ms(),
        round_step,
        proposal_present,
        finalized_ref_present,
        prop_calls: live.prop_calls,
        prop_build_ok: live.prop_build_ok,
        prop_skip_not_elected: live.prop_skip_not_elected,
        prop_skip_height_desync: live.prop_skip_height_desync,
        prop_skip_step_guard: live.prop_skip_step_guard,
        prop_skip_conflict_target: live.prop_skip_conflict_target,
        prop_skip_fail: live.prop_skip_fail,
        inbound_prop_ok: live.inbound_prop_ok,
        egress_prop_enqueued: live.egress_prop_enqueued,
        egress_prop_no_peer: live.egress_prop_no_peer,
        // PHASE 6H-A30 OD-X8 — 直读 snapshot 计数（无新增增量点 / 无行为变更）。
        egress_prop_refreshed: live.egress_prop_refreshed,
        round_adv_local: live.round_adv_local,
        round_adv_height: live.round_adv_height,
        round_adv_rc: live.round_adv_rc,
        elected_is_self: live.elected_is_self,
        prop_absent_steps: live.prop_absent_steps,
        // PHASE 6H-A30 OD-X7b — 真实计数直读（无增量点 / 无结果猜测）。
        proposal_admitted: live.proposal_admitted,
        proposal_pending: live.proposal_pending,
        proposal_rejected: live.proposal_rejected,
        proposal_expired: live.proposal_expired,
        // PHASE 6H-A30 OD-X7d — 只读网络/事件环诊断直读（无推算）。
        net_frames_received: live.net_frames_received,
        net_events_enqueued: live.net_events_enqueued,
        net_sent: live.net_sent,
        net_dropped_invalid: live.net_dropped_invalid,
        net_dropped_overflow: live.net_dropped_overflow,
        net_unauthenticated_drops: live.net_unauthenticated_drops,
        el_handler_errors: live.el_handler_errors,
        el_events_dropped_overflow: live.el_events_dropped_overflow,
        // PHASE 6H-A30 OD-X7e — 只读 recovery/block 直读（无推算）。
        recovery_runs: live.recovery_runs,
        recovery_candidates: live.recovery_candidates,
        recovery_kept_missing_block: live.recovery_kept_missing_block,
        recovery_admitted: live.recovery_admitted,
        recovery_rejected: live.recovery_rejected,
        block_inbound_processed: live.block_inbound_processed,
        block_canonical_next: live.block_canonical_next,
        block_register_ok: live.block_register_ok,
        // PHASE 6H-A30 OD-X7f — 既有 outcomes 窗口分类（无推算）。
        block_verdict_future_missing_ancestor: live.block_verdict_future_missing_ancestor,
        block_verdict_already_known: live.block_verdict_already_known,
        block_verdict_stale: live.block_verdict_stale,
        block_verdict_conflicting_parent: live.block_verdict_conflicting_parent,
        block_verdict_malformed: live.block_verdict_malformed,
        block_verdict_other: live.block_verdict_other,
        // PHASE 6H-A30 OD-X7g — Err 细分直读（窗口内；无推算）。
        block_err_oversized: live.block_err_oversized,
        block_err_wrong_version: live.block_err_wrong_version,
        block_err_wrong_chain: live.block_err_wrong_chain,
        block_err_hash_mismatch: live.block_err_hash_mismatch,
        block_err_invalid_proposer_signature: live.block_err_invalid_proposer_signature,
        block_err_transaction_root_mismatch: live.block_err_transaction_root_mismatch,
        block_err_noncanonical_transaction_ordering: live
            .block_err_noncanonical_transaction_ordering,
        block_err_state_root_mismatch: live.block_err_state_root_mismatch,
        block_err_unsupported_validation: live.block_err_unsupported_validation,
        block_err_storage: live.block_err_storage,
        // PHASE 6H-A30-OD-X7h — 来源类别累计直读（无推算）。
        block_src_gossip_total: live.block_src_gossip_total,
        block_src_gossip_invalid_proposer_signature: live
            .block_src_gossip_invalid_proposer_signature,
        block_src_sync_total: live.block_src_sync_total,
        block_src_sync_invalid_proposer_signature: live.block_src_sync_invalid_proposer_signature,
        // PHASE 6H-A30-OD-X7i — gossip IPS 来源分类直读（无推算）。
        block_gossip_invalid_proposer_signature_evidence_conflict: live
            .block_gossip_invalid_proposer_signature_evidence_conflict,
        block_gossip_invalid_proposer_signature_signature_failure: live
            .block_gossip_invalid_proposer_signature_signature_failure,
    }
}

/// PHASE 6H-A30 OD-X7 — **独立** `liveness` 行（OUTPUT_MODE=B）。
///
/// - 既有 `status` 行**逐字不变**（本行纯 append；不影响 `status_write_failed`）。
/// - 只读观测；字段顺序固定、无时间戳、无随机值、不读取外部服务。
fn liveness_line(runtime: &NodeRuntime, cli: &Cli, steps: u64) -> String {
    let s = summarize(runtime, cli, steps);
    format!(
        "{PROGRAM}: liveness steps={} prop_calls={} prop_build_ok={} \
         prop_skip_not_elected={} prop_skip_height_desync={} prop_skip_step_guard={} \
         prop_skip_conflict_target={} \
         prop_skip_fail={} inbound_prop_ok={} egress_prop_enqueued={} egress_prop_no_peer={} \
         egress_prop_refreshed={} \
         round_adv_local={} round_adv_height={} round_adv_rc={} elected_is_self={} \
         prop_absent_steps={} proposal_admitted={} proposal_pending={} \
         proposal_rejected={} proposal_expired={} net_frames_received={} \
         net_events_enqueued={} net_sent={} net_dropped_invalid={} net_dropped_overflow={} \
         net_unauthenticated_drops={} el_handler_errors={} el_events_dropped_overflow={} \
         recovery_runs={} recovery_candidates={} recovery_kept_missing_block={} \
         recovery_admitted={} recovery_rejected={} block_inbound_processed={} \
         block_canonical_next={} block_register_ok={} \
         block_verdict_future_missing_ancestor={} block_verdict_already_known={} \
         block_verdict_stale={} block_verdict_conflicting_parent={} \
         block_verdict_malformed={} block_verdict_other={} block_err_oversized={} \
         block_err_wrong_version={} block_err_wrong_chain={} block_err_hash_mismatch={} \
         block_err_invalid_proposer_signature={} block_err_transaction_root_mismatch={} \
         block_err_noncanonical_transaction_ordering={} block_err_state_root_mismatch={} \
         block_err_unsupported_validation={} block_err_storage={} \
         block_src_gossip_total={} block_src_gossip_invalid_proposer_signature={} \
         block_src_sync_total={} block_src_sync_invalid_proposer_signature={} \
         block_gossip_invalid_proposer_signature_evidence_conflict={} \
         block_gossip_invalid_proposer_signature_signature_failure={}\n",
        s.steps,
        s.prop_calls,
        s.prop_build_ok,
        s.prop_skip_not_elected,
        s.prop_skip_height_desync,
        s.prop_skip_step_guard,
        s.prop_skip_conflict_target,
        s.prop_skip_fail,
        s.inbound_prop_ok,
        s.egress_prop_enqueued,
        s.egress_prop_no_peer,
        s.egress_prop_refreshed,
        s.round_adv_local,
        s.round_adv_height,
        s.round_adv_rc,
        s.elected_is_self,
        s.prop_absent_steps,
        s.proposal_admitted,
        s.proposal_pending,
        s.proposal_rejected,
        s.proposal_expired,
        s.net_frames_received,
        s.net_events_enqueued,
        s.net_sent,
        s.net_dropped_invalid,
        s.net_dropped_overflow,
        s.net_unauthenticated_drops,
        s.el_handler_errors,
        s.el_events_dropped_overflow,
        s.recovery_runs,
        s.recovery_candidates,
        s.recovery_kept_missing_block,
        s.recovery_admitted,
        s.recovery_rejected,
        s.block_inbound_processed,
        s.block_canonical_next,
        s.block_register_ok,
        s.block_verdict_future_missing_ancestor,
        s.block_verdict_already_known,
        s.block_verdict_stale,
        s.block_verdict_conflicting_parent,
        s.block_verdict_malformed,
        s.block_verdict_other,
        s.block_err_oversized,
        s.block_err_wrong_version,
        s.block_err_wrong_chain,
        s.block_err_hash_mismatch,
        s.block_err_invalid_proposer_signature,
        s.block_err_transaction_root_mismatch,
        s.block_err_noncanonical_transaction_ordering,
        s.block_err_state_root_mismatch,
        s.block_err_unsupported_validation,
        s.block_err_storage,
        s.block_src_gossip_total,
        s.block_src_gossip_invalid_proposer_signature,
        s.block_src_sync_total,
        s.block_src_sync_invalid_proposer_signature,
        s.block_gossip_invalid_proposer_signature_evidence_conflict,
        s.block_gossip_invalid_proposer_signature_signature_failure,
    )
}

/// P1-A.9（P1-3）—— 单行 periodic status（确定性；仅非敏感观测值）。
///
/// 字段顺序固定、无时间戳、无随机值、不读取外部服务。
/// P1-A.30 **D0** — 紧凑诊断串（`a/b/c`；确定性、零外部输入、无时间戳 / 无随机 / 无分配副作用）。
///
/// 仅用于把**固定长度**的诊断分类数组打成单字段，避免字符型描述扩充状态行长度。
fn slash_join(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<String>>()
        .join("/")
}

fn status_line(runtime: &NodeRuntime, cli: &Cli, steps: u64) -> String {
    let s = summarize(runtime, cli, steps);
    let finalized = s
        .finalized_height
        .map_or_else(|| "none".to_string(), |h| h.to_string());
    // ---- NETDIAG（**仅诊断**；Owner 授权；零行为变更 / 不改连接选择与重试策略）----
    // 入站诊断（既有 `InboundDiagnostics`；此前仅退出摘要行输出部分字段）。
    let inbound = runtime.network_inbound_diagnostics();
    let ib = inbound.map_or([0u64; 7], |d| {
        [
            d.accepted,
            d.duplicate_drops,
            d.overflow_drops,
            d.header_drops,
            d.accept_error_drops,
            d.closed_drops,
            d.connections as u64,
        ]
    });
    let idr = inbound.map_or([0u64; 4], |d| {
        [
            d.greet_keepfirst_drops,
            d.greet_connect_failed_drops,
            d.handshake_failed_drops,
            d.pending_timeout_drops,
        ]
    });
    // per-peer 状态（配置顺序；确定性）：`E`=established / `C`=connected / `-`=均无；`i`=持有入站连接。
    let peer_state = cli
        .peers
        .iter()
        .map(|t| {
            let sess = if runtime.network_peer_established(t.peer_id) {
                'E'
            } else if runtime.network_peer_connected(t.peer_id) {
                'C'
            } else {
                '-'
            };
            let inb = if runtime.network_inbound_contains(t.peer_id) {
                'i'
            } else {
                '.'
            };
            format!("{sess}{inb}")
        })
        .collect::<Vec<_>>()
        .join(",");
    let peer_fail = cli
        .peers
        .iter()
        .map(|t| {
            runtime
                .peer_lifecycle(t.peer_id)
                .map_or(0, |s| s.failure_count)
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{PROGRAM}: status steps={} head_height={} finalized_height={} consensus_height={} \
         round={} configured_peers={} established_peers={} inbound_connections={} \
         sync_pending={} block_inbound_skipped={} pending_external_qc={} qc_served={} \
         validator_enabled={} abandon_produced={} abandon_broadcast={} abandon_rejected={} \
         rc_certs={} rc_authority={} rc_rejected={} \
         rc_rej={} rc_bcast_nopeer={} abandon_bcast_nopeer={} rc_reeval={}/{} timeout_split={} \
         guard_rej={} wire_drops={} \
         round_timeouts={} timer_elapsed={} timer_window={} round_step={} \
         proposal_present={} finalized_ref_present={} \
         inbound={}/{}/{}/{}/{}/{}/{} inbound_drops={}/{}/{}/{} \
         peer_state=[{}] peer_fail=[{}]\n",
        s.steps,
        s.head_height,
        finalized,
        s.consensus_height,
        s.round,
        s.configured_peers,
        s.established_peers,
        s.inbound_connections,
        s.sync_pending,
        s.block_inbound_skipped,
        s.pending_external_qc,
        s.qc_served,
        s.validator_enabled,
        s.abandon_produced,
        s.abandon_broadcast,
        s.abandon_rejected,
        s.rc_certs,
        s.rc_authority,
        s.rc_rejected,
        slash_join(&s.rc_reject_buckets),
        s.rc_bcast_no_peer,
        s.abandon_bcast_no_peer,
        s.rc_reeval_attempts,
        s.rc_reeval_applied,
        slash_join(&s.timeout_outcomes),
        slash_join(&s.guard_rej),
        slash_join(&s.wire_drops),
        s.round_timeouts,
        opt_u64(s.timer_elapsed),
        opt_u64(s.timer_window),
        s.round_step,
        s.proposal_present,
        s.finalized_ref_present,
        // NETDIAG（仅诊断）
        ib[0],
        ib[1],
        ib[2],
        ib[3],
        ib[4],
        ib[5],
        ib[6],
        idr[0],
        idr[1],
        idr[2],
        idr[3],
        peer_state,
        peer_fail,
    )
}

/// P1-A.9（P1-3）—— 退出摘要行（保留 P1-A.3 既有契约字段，另增 P1-A.9 观测字段）。
fn summary_line(s: &RunSummary) -> String {
    let finalized = s
        .finalized_height
        .map_or_else(|| "none".to_string(), |h| h.to_string());
    format!(
        "{PROGRAM}: stopped after {}/{} steps; head_height={} finalized_height={} \
         consensus_height={} round={} configured_peers={}/{} inbound_connections={} \
         inbound_accepted={} sync_pending={} peer_dial_attempts={} peer_dial_failures={} \
         validator_enabled={} abandon_produced={} abandon_broadcast={} abandon_rejected={} \
         rc_certs={} rc_authority={} rc_rejected={} \
         rc_rej={} rc_bcast_nopeer={} abandon_bcast_nopeer={} rc_reeval={}/{} timeout_split={} \
         guard_rej={} wire_drops={} \
         round_timeouts={} timer_elapsed={} timer_window={} round_step={} \
         proposal_present={} finalized_ref_present={}; runtime shut down\n",
        s.steps,
        if s.run_steps == 0 {
            "unlimited".to_string()
        } else {
            s.run_steps.to_string()
        },
        s.head_height,
        finalized,
        s.consensus_height,
        s.round,
        s.established_peers,
        s.configured_peers,
        s.inbound_connections,
        s.inbound_accepted,
        s.sync_pending,
        s.peer_dial_attempts_total,
        s.peer_dial_failures_total,
        s.validator_enabled,
        s.abandon_produced,
        s.abandon_broadcast,
        s.abandon_rejected,
        s.rc_certs,
        s.rc_authority,
        s.rc_rejected,
        slash_join(&s.rc_reject_buckets),
        s.rc_bcast_no_peer,
        s.abandon_bcast_no_peer,
        s.rc_reeval_attempts,
        s.rc_reeval_applied,
        slash_join(&s.timeout_outcomes),
        slash_join(&s.guard_rej),
        slash_join(&s.wire_drops),
        s.round_timeouts,
        opt_u64(s.timer_elapsed),
        opt_u64(s.timer_window),
        s.round_step,
        s.proposal_present,
        s.finalized_ref_present,
    )
}

/// 循环结果：正常耗完预算或 fail-closed 停止（**两者均携带摘要**，便于退出观测）。
struct RunLoopOutcome {
    summary: RunSummary,
    /// `Some` ⇒ 某次 `runtime.step()` 返回 `Err`（fail-closed：不继续下一轮、不吞错）。
    error: Option<StartupError>,
    /// P1-A.9（P1-3）—— periodic status 写失败（best-effort 观测）。
    /// **不**改变 step 语义 / **不**跳过 `shutdown` / **不**覆盖 step 错误（优先级最低）。
    status_write_failed: bool,
}

/// `RuntimeError` → 稳定类别标签（穷尽匹配；新增变体 ⇒ 编译期强制在本层显式处理）。
fn run_fault_kind(e: &RuntimeError) -> &'static str {
    match e {
        RuntimeError::EventLoop(_) => "EventLoop",
        RuntimeError::Driver(_) => "Driver",
        RuntimeError::Egress(_) => "Egress",
        RuntimeError::Proposer(_) => "Proposer",
        RuntimeError::Validator(_) => "Validator",
        RuntimeError::NetworkDial(_) => "NetworkDial",
        RuntimeError::Session(_) => "Session",
        RuntimeError::NetworkSigning(_) => "NetworkSigning",
        RuntimeError::PeerAuthMissing => "PeerAuthMissing",
        RuntimeError::IdentityMismatch { .. } => "IdentityMismatch",
        RuntimeError::NetworkSecurity(_) => "NetworkSecurity",
        RuntimeError::DagRegister(_) => "DagRegister",
        RuntimeError::BlockCommit(_) => "BlockCommit",
        RuntimeError::BlockCodec(_) => "BlockCodec",
        RuntimeError::BlockStore(_) => "BlockStore",
        RuntimeError::BlockDecode(_) => "BlockDecode",
        RuntimeError::FinalityFact(_) => "FinalityFact",
    }
}

/// 入口层错误载荷：`BlockCommit` 保留 **inner error 的真实 `Display`**（其余变体沿用类别名）。
///
/// **P1-A.17 F-1 诊断（Owner 授权；仅错误格式化）** —— 语义逐项不变：
/// - 控制流不变（`runtime.step()` 返回 `Err` ⇒ 仍 fail-closed 立即停止，不继续下一轮）；
/// - 退出码不变（仍为非 0）；
/// - 除 `BlockCommit` / `Validator` 外，**所有**变体载荷文本逐字不变（仍取 `run_fault_kind` 的稳定类别名）；
/// - 只多出 inner error 的 typed 文本（`NodeBlockApplicationError` →
///   `block application pipeline: <decode|validation|execution|storage>: …`；
///   `ValidatorActorError` → 具体变体 + 对应 target hash / 高度轮次 / safety 类别），
///   不引入 `RuntimeError` 的 `Debug` 文本 / 不含 session/nonce 类运行期材料；
///   **不**包含任何私钥 / 密钥材料 / 凭证（target 为公开 block hash；safety 错误为枚举类别）。
fn run_fault_message(e: &RuntimeError) -> String {
    match e {
        RuntimeError::BlockCommit(inner) => format!("BlockCommit: {inner}"),
        // SAFETY-REJECT-SKIP 配套诊断（仅文本）：保留**具体**的 validator 错误变体，
        // 使「合法安全拒绝」与「journal 损坏 / identity 失配 / 签名失败」在日志上可区分。
        RuntimeError::Validator(inner) => format!("Validator: {inner:?}"),
        other => run_fault_kind(other).to_string(),
    }
}

/// **P1-A.3 主体**：有界长运行驱动循环（每轮顺序固定）。
///
/// 1. 存在 configured peers ⇒ 调用**幂等** `establish_configured_peers()`（per-peer 错误隔离：
///    单个 peer dial/握手失败只记入其 `PeerStatus`，**不**终止本节点）。
/// 2. 调用**唯一驱动点** `runtime.step()`；`Err` ⇒ fail-closed 立即停止（`shutdown` 仍由 `main`
///    在所有路径上调用，未经修改的 runtime 错误原样向上传播）。
/// 3. 预算：`run_steps > 0` 时 `steps == cli.run_steps` ⇒ 正常结束（**不**多执行一轮，不存在
///    N+1）；`run_steps == 0` ⇒ **continuous**（无 step 上限；仅 `runtime.step()` 返回 `Err`
///    时 fail-closed 停止）。两种模式均 `std::thread::sleep(cli.idle_ms)` pacing
///    （Owner D1 批准的唯一生产 sleep；`1..=50ms` 已由 CLI 拒绝 0 ⇒ **无 busy loop**）。
/// 4. **P1-A.9（P1-3）**：每 `STATUS_INTERVAL_STEPS` 步输出一行 status（stdout；固定 interval；
///    无墙钟 / 无随机 / 不影响 step timing）。status 写失败只记录（`status_write_failed`），
///    **不**改变 step 语义、**不**跳过 `shutdown`、**不**覆盖 step 错误。
///
/// P1-A.13 —— peer warm-up 最大轮数（每轮 = 一次 `establish_configured_peers()` + `idle_ms` pacing）。
///
/// 有界性保证：configured peer 永久不可达时**不会**卡死启动 —— 到期（rounds 耗尽）即带
/// `warmup_exhausted` 继续进入正常有界运行循环；也不会引入新协议/新消息（仅复用既有幂等接口）。
const WARMUP_MAX_ROUNDS: u64 = 300;

fn run_node_loop(runtime: &mut NodeRuntime, cli: &Cli) -> RunLoopOutcome {
    let mut steps: u64 = 0;
    let mut error: Option<StartupError> = None;
    let mut status_write_failed = false;

    // ===== P1-A.13 — 有界 peer warm-up（先建连/握手，再驱动共识）=====
    // 动机：若在 configured peer 尚未 Established 时就 `step()`，首轮（height=0/round=0）proposer
    // 的提案 egress 无接收者 ⇒ **提案丢失**，只能依赖 round-timeout 恢复（默认窗口 1000 逻辑 tick，
    // 在慢 step 下可达分钟级）⇒ 启动期看似无进展。
    // 与已通过的 in-process rig（A.10：先建连后共识）在“共识起始条件”上对齐。
    // **不**修改 pacemaker 默认值、**不**改 runtime / consensus。
    if !cli.peers.is_empty() {
        let mut rounds: u64 = 0;
        loop {
            let _ = runtime.establish_configured_peers();
            // P1-A.14 — 网络生命周期**窄口**：只驱动网络（inbound_tick / begin_step /
            // accept+greet / poll_once / reconcile），**不**进入共识 ⇒ 零 proposal / vote / QC /
            // finality / commit / head advance / round mutation。
            // 必要性（P1-A.13 实测证据）：`establish_configured_peers()` 只驱动**本端 dial 侧**，
            // listener 侧的 accept/greet 仅存在于 `step()` 的网络段 ⇒ 仅靠前者 warm-up 永不完成
            // （`established_peers=0~1` 耗尽 300 轮）。
            // 错误处理与上一行同策略（best-effort；warm-up 不 fail-closed）：紧随其后的正常循环
            // 第一步 `step()` 会**先**执行同一网络生命周期并以既有 fail-closed 语义传播错误
            // ⇒ 不吞错 / 不改 step 语义 / 不改网络协议。
            let _ = runtime.poll_network_only();
            let established = cli
                .peers
                .iter()
                .filter(|t| runtime.network_peer_established(t.peer_id))
                .count();
            let done = established == cli.peers.len();
            if done || rounds >= WARMUP_MAX_ROUNDS {
                let _ = write_stdout(&format!(
                    "{PROGRAM}: peer warm-up {}; configured_peers={} established_peers={} \
                     warmup_rounds={} warmup_max_rounds={}\n",
                    if done { "completed" } else { "exhausted" },
                    cli.peers.len(),
                    established,
                    rounds,
                    WARMUP_MAX_ROUNDS,
                ));
                break;
            }
            rounds += 1;
            std::thread::sleep(std::time::Duration::from_millis(cli.idle_ms));
        }
    }

    // B1（Testnet）—— `run_steps == 0` = continuous（无 step 上限）；`> 0` = 既有有限预算。
    while cli.run_steps == 0 || steps < cli.run_steps {
        if !cli.peers.is_empty() {
            // 幂等；不因单个 configured peer 失败而终止节点（错误在 status 中，无状态机副作用）。
            let _ = runtime.establish_configured_peers();
        }
        steps += 1;
        if let Err(e) = runtime.step() {
            error = Some(StartupError::Run(run_fault_message(&e)));
            break;
        }
        // P1-A.9（P1-3）：固定 interval 观测行（best-effort；写失败不中断 / 不吞错）。
        if should_emit_status(steps) && write_stdout(&status_line(runtime, cli, steps)).is_err() {
            status_write_failed = true;
        }
        // PHASE 6H-A30 OD-X7（OUTPUT_MODE=B）：**独立** liveness 行（best-effort）。
        // 写失败**不**影响既有 `status_write_failed` 语义 / 不中断运行（append-only 观测量）。
        if should_emit_status(steps) {
            let _ = write_stdout(&liveness_line(runtime, cli, steps));
        }
        // B1：仅**有限预算**在 steps 达到 N 时退出；`0`（continuous）不因预算退出。
        if cli.run_steps != 0 && steps >= cli.run_steps {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(cli.idle_ms));
    }
    RunLoopOutcome {
        summary: summarize(runtime, cli, steps),
        error,
        status_write_failed,
    }
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// CLI 契约输出（stdout；**非** logging）。
fn write_stdout(text: &str) -> Result<(), StartupError> {
    let mut out = std::io::stdout();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|_| StartupError::OutputWrite)
}

/// 进程入口：解析 → （help/version 短路）→ pre-flight → NodeConfig 组装 → 停止。
fn main() -> Result<(), StartupError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match classify(&args).map_err(StartupError::Cli)? {
        Action::Help => write_stdout(HELP),
        Action::Version => {
            let line = format!("{PROGRAM} {VERSION}\n");
            write_stdout(&line)
        }
        Action::Run(cli) => {
            // P-6 mount guard（Owner 授权）：在**任何**状态创建之前，拒绝把容器可写层普通目录
            // 当作持久化 `--storage-dir` / `--safety-dir`（判据 = 内核挂载表；容器内不可判定 ⇒ fail-closed）。
            // 非容器化开发/CI 环境无法判定挂载 ⇒ 只打印一行提示并继续（生产 = 容器 ⇒ 强制执行）。
            // 错误载荷复用既有 `Run(String)`（typed/确定性、不含秘密），避免改动 `StartupError` 派生与 Display。
            // 只要 CLI 提供了 `--safety-dir`（validator 模式的必需项）就**必须**同样受保护：
            // 未挂载的 safety 目录会让 journal 落在易失层（重启即丢失 ⇒ double-vote 风险面）。
            let safety_target = cli.safety_dir.as_deref();
            let guard_outcome = nova_node::mount_guard::enforce_persistent_dirs_with(
                &cli.storage_dir,
                safety_target,
                &nova_node::mount_guard::ProcSelfMountinfoInspector,
                nova_node::mount_guard::in_container_default(),
            )
            .map_err(|e| StartupError::Run(format!("MountGuard: {e}")))?;
            if guard_outcome == nova_node::mount_guard::GuardOutcome::SkippedNotContainer {
                eprintln!(
                    "{PROGRAM}: mount guard skipped (not running in a container); \
                     persistent-volume persistence is NOT verified in this environment"
                );
            }
            let (_identity, set) = preflight(&cli).map_err(StartupError::Preflight)?;
            let (mut runtime, report) = assemble_and_verify_runtime(&cli, &set)?;
            // 启动行（CLI 契约输出；非日志）—— 进入循环前写出 ⇒ 绑定地址 / 预算立即可观测。
            // B1：有限预算 ⇒ 既有无改动契约行 `entering bounded run loop`（既有测试依赖该字符串）；
            // continuous（run_steps=0）⇒ `entering continuous run loop`。
            write_stdout(&format!(
                "{PROGRAM}: runtime assembled (P1-A.3); node_id={} listen={:?} peer_auth={}; \
                 entering {} run loop (run_steps={} idle_ms={})\n",
                hex32(report.node_id.as_bytes()),
                report.listen_addr,
                report.peer_auth_enabled,
                if cli.run_steps == 0 {
                    "continuous"
                } else {
                    "bounded"
                },
                if cli.run_steps == 0 {
                    "unlimited".to_string()
                } else {
                    cli.run_steps.to_string()
                },
                cli.idle_ms,
            ))?;
            let outcome = run_node_loop(&mut runtime, &cli);
            let summary = outcome.summary;
            // 既有 `shutdown`：**所有路径恰好一次**（含 step 失败路径；consuming self）。
            let shutdown_result = runtime.shutdown().map_err(|_| StartupError::Shutdown);
            // 退出摘要行（仅非敏感观测值；P1-A.9 扩充字段，保留 P1-A.3 既有契约字段）。
            write_stdout(&summary_line(&summary))?;
            // 优先级：runtime step 错误 > periodic status 写失败 > shutdown 错误；均**不**吞掉。
            if let Some(e) = outcome.error {
                return Err(e);
            }
            if outcome.status_write_failed {
                return Err(StartupError::OutputWrite);
            }
            shutdown_result
        }
    }
}

// ---------------------------------------------------------------------------
// Tests（解析 / pre-flight / 组装；**不主动拨号**；仅 T39 在 127.0.0.1:0 真实绑定监听，
//        无任何入站连接；T24–T39 的 fixture 写入系统临时目录并在 Drop 时清理）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认预算必须 > 0（否则默认 CLI 会产生 0 步空转）；编译期常量断言，无运行期开销。
    const _: () = assert!(RUN_STEPS_DEFAULT > 0);
    /// 默认空闲间隔必须落在 CLI 允许区间 `1..=50`。
    const _: () = assert!(IDLE_MS_DEFAULT > 0 && IDLE_MS_DEFAULT <= IDLE_MS_MAX);

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// 最小必填集合（T14 基线，可叠加单个非法/缺失项）。
    fn valid_base() -> Vec<&'static str> {
        vec![
            "--genesis",
            "/tmp/genesis.bin",
            "--genesis-hash",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--chain-id",
            "1001",
            "--network-id",
            "devnet",
            "--storage-dir",
            "/tmp/chain",
            "--network-seed-file",
            "/tmp/net.seed",
        ]
    }

    fn parse(items: &[&str]) -> Result<Cli, CliError> {
        parse_args(&argv(items))
    }

    /// 从基线集合中删除某个 `--flag` 及其值。
    fn without(flag: &str) -> Vec<String> {
        let base = valid_base();
        let mut out: Vec<String> = Vec::new();
        let mut skip_next = false;
        for item in base {
            if skip_next {
                skip_next = false;
                continue;
            }
            if item == flag {
                skip_next = true;
                continue;
            }
            out.push(item.to_string());
        }
        out
    }

    // T1 — 缺少 --genesis ⇒ reject
    #[test]
    fn t1_missing_genesis_rejected() {
        let args = without("--genesis");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--genesis"))
        );
    }

    // T2 — 缺少 --genesis-hash ⇒ reject
    #[test]
    fn t2_missing_genesis_hash_rejected() {
        let args = without("--genesis-hash");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--genesis-hash"))
        );
    }

    // T3 — 缺少 --chain-id ⇒ reject
    #[test]
    fn t3_missing_chain_id_rejected() {
        let args = without("--chain-id");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--chain-id"))
        );
    }

    // T4 — 缺少 --network-id ⇒ reject
    #[test]
    fn t4_missing_network_id_rejected() {
        let args = without("--network-id");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--network-id"))
        );
    }

    // T5 — 缺少 --storage-dir ⇒ reject
    #[test]
    fn t5_missing_storage_dir_rejected() {
        let args = without("--storage-dir");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--storage-dir"))
        );
    }

    // T6 — 未知参数 ⇒ reject（不静默忽略）
    #[test]
    fn t6_unknown_argument_rejected() {
        let mut items = valid_base();
        items.push("--bogus");
        assert_eq!(
            parse(&items),
            Err(CliError::UnknownArgument("--bogus".to_string()))
        );
    }

    // T7 — 非法 genesis hash ⇒ reject
    #[test]
    fn t7_invalid_genesis_hash_rejected() {
        assert_eq!(
            parse(&[
                "--genesis",
                "g.bin",
                "--genesis-hash",
                "deadbeef",
                "--chain-id",
                "1",
                "--network-id",
                "devnet",
                "--storage-dir",
                "s",
                "--network-seed-file",
                "n.seed",
            ]),
            Err(CliError::InvalidGenesisHash)
        );
        // 64 字符但含非十六进制字符 ⇒ 同样 reject
        assert_eq!(
            parse(&[
                "--genesis",
                "g.bin",
                "--genesis-hash",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "--chain-id",
                "1",
                "--network-id",
                "devnet",
                "--storage-dir",
                "s",
                "--network-seed-file",
                "n.seed",
            ]),
            Err(CliError::InvalidGenesisHash)
        );
    }

    // T8 — 非法 chain-id ⇒ reject
    #[test]
    fn t8_invalid_chain_id_rejected() {
        let mut items = valid_base();
        let idx = items.iter().position(|s| *s == "--chain-id").unwrap();
        items[idx + 1] = "not-a-number";
        assert_eq!(parse(&items), Err(CliError::InvalidChainId));
    }

    // T9 — 非法 network-id ⇒ reject
    #[test]
    fn t9_invalid_network_id_rejected() {
        let mut items = valid_base();
        let idx = items.iter().position(|s| *s == "--network-id").unwrap();
        items[idx + 1] = "main";
        assert_eq!(
            parse(&items),
            Err(CliError::InvalidNetworkId("main".to_string()))
        );
        // 大小写不匹配亦拒绝（严格）
        let mut items2 = valid_base();
        let idx2 = items2.iter().position(|s| *s == "--network-id").unwrap();
        items2[idx2 + 1] = "Devnet";
        assert_eq!(
            parse(&items2),
            Err(CliError::InvalidNetworkId("Devnet".to_string()))
        );
    }

    // T10 — idle-ms > 50 ⇒ reject（0 亦 reject）
    #[test]
    fn t10_idle_ms_bounds_rejected() {
        let mut over = valid_base();
        over.push("--idle-ms");
        over.push("51");
        assert_eq!(parse(&over), Err(CliError::InvalidIdleMs));

        let mut zero = valid_base();
        zero.push("--idle-ms");
        zero.push("0");
        assert_eq!(parse(&zero), Err(CliError::InvalidIdleMs));

        let mut nonnum = valid_base();
        nonnum.push("--idle-ms");
        nonnum.push("fast");
        assert_eq!(parse(&nonnum), Err(CliError::InvalidIdleMs));

        // 边界值 50 合法
        let mut max = valid_base();
        max.push("--idle-ms");
        max.push("50");
        assert_eq!(parse(&max).map(|c| c.idle_ms), Ok(50));
    }

    // T11 — --validator 缺少 validator seed ⇒ reject
    #[test]
    fn t11_validator_without_seed_file_rejected() {
        let mut items = valid_base();
        items.push("--validator");
        items.push("--safety-dir");
        items.push("/tmp/safety");
        assert_eq!(parse(&items), Err(CliError::ValidatorRequiresSeedFile));
    }

    // T12 — --validator 缺少 safety-dir ⇒ reject
    #[test]
    fn t12_validator_without_safety_dir_rejected() {
        let mut items = valid_base();
        items.push("--validator");
        items.push("--validator-seed-file");
        items.push("/tmp/val.seed");
        assert_eq!(parse(&items), Err(CliError::ValidatorRequiresSafetyDir));
    }

    // T13 — --validator + mainnet ⇒ reject（Mainnet 级密钥管理未实现）
    #[test]
    fn t13_validator_on_mainnet_rejected() {
        let mut items = valid_base();
        let idx = items.iter().position(|s| *s == "devnet").unwrap();
        items[idx] = "mainnet";
        items.push("--validator");
        items.push("--safety-dir");
        items.push("/tmp/safety");
        items.push("--validator-seed-file");
        items.push("/tmp/val.seed");
        assert_eq!(parse(&items), Err(CliError::MainnetValidatorUnsupported));
    }

    // T14 — 合法 devnet 配置 ⇒ accept（+ NodeConfig 映射校验）
    #[test]
    fn t14_valid_devnet_config_accepted() {
        let cli = parse(&valid_base()).expect("valid devnet configuration must be accepted");
        assert!(!cli.validator);
        assert!(cli.listen_addr.is_none());
        assert!(cli.peers.is_empty());
        assert_eq!(cli.idle_ms, IDLE_MS_DEFAULT);
        assert_eq!(cli.chain_id, 1001);
        assert_eq!(cli.network_id, NetworkId::Devnet);
        assert_eq!(cli.genesis, PathBuf::from("/tmp/genesis.bin"));

        let config = build_node_config(&cli);
        assert_eq!(config.genesis_path, PathBuf::from("/tmp/genesis.bin"));
        assert_eq!(config.expected_chain_id, 1001);
        assert_eq!(config.expected_network_id, NetworkId::Devnet);
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/chain"));
        assert!(!config.validator_enabled);
        assert_eq!(config.listen_addr, None);
        assert!(config.peers.is_empty());
        assert_eq!(config.key_provider_config, KeyProviderConfig::None);
        // 未提供 safety-dir ⇒ 确定性占位（storage_dir/safety），不创建 / 不读取
        assert_eq!(config.safety_dir, PathBuf::from("/tmp/chain/safety"));
        assert_eq!(config.expected_genesis_hash, [0xaa; 32]);
    }

    // T15 — 缺少 --network-seed-file ⇒ reject（必填）
    #[test]
    fn t15_missing_network_seed_file_rejected() {
        let args = without("--network-seed-file");
        assert_eq!(
            parse_args(&args),
            Err(CliError::MissingRequired("--network-seed-file"))
        );
    }

    // T16 — 单值参数重复 ⇒ reject
    #[test]
    fn t16_duplicate_argument_rejected() {
        let mut items = valid_base();
        items.push("--chain-id");
        items.push("2");
        assert_eq!(
            parse(&items),
            Err(CliError::DuplicateArgument("--chain-id"))
        );

        let mut items2 = valid_base();
        items2.push("--validator");
        items2.push("--validator");
        assert_eq!(
            parse(&items2),
            Err(CliError::DuplicateArgument("--validator"))
        );
    }

    // T17 — --flag 缺少值（结尾 / 后接另一个 --flag）⇒ reject
    #[test]
    fn t17_missing_value_rejected() {
        let mut trailing = valid_base();
        trailing.push("--listen");
        assert_eq!(parse(&trailing), Err(CliError::MissingValue("--listen")));

        let mut followed = valid_base();
        followed.push("--listen");
        followed.push("--validator");
        assert_eq!(parse(&followed), Err(CliError::MissingValue("--listen")));
    }

    // T18 — 非法 peer 格式 ⇒ reject（可重复参数：合法项可解析）
    #[test]
    fn t18_invalid_peer_rejected() {
        let bad_id = "aa@127.0.0.1:1"; // 非 64 hex
        let mut items = valid_base();
        items.push("--peer");
        items.push(bad_id);
        assert_eq!(
            parse(&items),
            Err(CliError::InvalidPeerFormat(bad_id.to_string()))
        );

        let no_at = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa127.0.0.1:1";
        let mut items2 = valid_base();
        items2.push("--peer");
        items2.push(no_at);
        assert_eq!(
            parse(&items2),
            Err(CliError::InvalidPeerFormat(no_at.to_string()))
        );

        let good =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@127.0.0.1:9000";
        let mut items3 = valid_base();
        items3.push("--peer");
        items3.push(good);
        items3.push("--peer");
        items3.push(good);
        let cli = parse(&items3).expect("peers are repeatable");
        assert_eq!(cli.peers.len(), 2);
        assert_eq!(cli.peers[0].address, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(
            cli.peers[0].peer_id,
            NodeId::from_bytes([0xbb; 32]),
            "peer id 解析"
        );
    }

    // T19 — 非法 listen 地址 ⇒ reject
    #[test]
    fn t19_invalid_listen_rejected() {
        let mut items = valid_base();
        items.push("--listen");
        items.push("127.0.0.1");
        assert_eq!(
            parse(&items),
            Err(CliError::InvalidListenAddr("127.0.0.1".to_string()))
        );

        let mut ok_items = valid_base();
        ok_items.push("--listen");
        ok_items.push("127.0.0.1:0");
        assert_eq!(
            parse(&ok_items).map(|c| c.listen_addr),
            Ok(Some("127.0.0.1:0".parse().unwrap()))
        );
    }

    // T20 — 位置参数 ⇒ reject
    #[test]
    fn t20_positional_argument_rejected() {
        let mut items = valid_base();
        items.push("run");
        assert_eq!(
            parse(&items),
            Err(CliError::UnexpectedPositional("run".to_string()))
        );
    }

    // T21 — help / version 优先短路（不要求配置完整）
    #[test]
    fn t21_help_and_version_short_circuit() {
        assert_eq!(classify(&argv(&["--help"])), Ok(Action::Help));
        assert_eq!(classify(&argv(&["--version"])), Ok(Action::Version));
        assert_eq!(
            classify(&argv(&["--help", "--bogus"])),
            Ok(Action::Help),
            "help 优先于未知参数"
        );
        // 无参数 ⇒ 走 Run 路径 ⇒ 必填缺失
        assert_eq!(
            classify(&argv(&[])),
            Err(CliError::MissingRequired("--genesis"))
        );
    }

    // T22 — validator 模式合法配置 ⇒ accept（非 mainnet）
    #[test]
    fn t22_valid_validator_config_accepted() {
        let mut items = valid_base();
        items.push("--validator");
        items.push("--safety-dir");
        items.push("/tmp/safety");
        items.push("--validator-seed-file");
        items.push("/tmp/val.seed");
        items.push("--listen");
        items.push("0.0.0.0:7000");
        let cli = parse(&items).expect("valid validator devnet config");
        assert!(cli.validator);
        assert_eq!(cli.safety_dir, Some(PathBuf::from("/tmp/safety")));
        assert_eq!(
            cli.validator_seed_file,
            Some(PathBuf::from("/tmp/val.seed"))
        );

        let config = build_node_config(&cli);
        assert!(config.validator_enabled);
        assert_eq!(config.safety_dir, PathBuf::from("/tmp/safety"));
        assert_eq!(config.listen_addr, Some("0.0.0.0:7000".parse().unwrap()));
    }

    // T23 — genesis pre-flight 错误面（文件；不依赖 fixture 内容）
    #[test]
    fn t23_preflight_missing_file_fails_closed() {
        let cli = parse(&valid_base()).expect("parse ok");
        let missing = PathBuf::from("/definitely/not/a/genesis/file.bin");
        let cli = Cli {
            genesis: missing,
            ..cli
        };
        assert!(matches!(preflight(&cli), Err(PreflightError::GenesisRead)));
    }

    // -----------------------------------------------------------------------
    // G5-D.7.2 tests：`--init-validator-safety` 契约（Guard A / Guard B / 重复 / HELP）
    // -----------------------------------------------------------------------

    /// 构造“合法 validator 模式”参数（含 safety-dir 与 validator seed）。
    fn valid_validator_items() -> Vec<&'static str> {
        let mut items = valid_base();
        items.push("--validator");
        items.push("--safety-dir");
        items.push("/tmp/safety");
        items.push("--validator-seed-file");
        items.push("/tmp/val.seed");
        items
    }

    // G1 — 显式初始化 + --validator ⇒ accept；且默认（无 flag）为 false。
    #[test]
    fn g1_init_validator_safety_accepted_with_validator() {
        let mut items = valid_validator_items();
        items.push("--init-validator-safety");
        let cli = parse(&items).expect("validator + init flag ⇒ accept");
        assert!(cli.validator);
        assert!(
            cli.init_validator_safety,
            "显式声明的初始化信号必须保留到 NodeConfig"
        );

        let plain = valid_validator_items();
        assert!(
            !parse(&plain)
                .expect("validator 模式无 flag ⇒ accept")
                .init_validator_safety,
            "默认必须为 false（不得隐式初始化）"
        );
    }

    // G2 — Guard A：--init-validator-safety 无 --validator ⇒ reject（不静默忽略）。
    #[test]
    fn g2_init_validator_safety_without_validator_rejected() {
        let mut items = valid_base();
        items.push("--init-validator-safety");
        assert_eq!(
            parse(&items),
            Err(CliError::InitValidatorSafetyRequiresValidator)
        );
    }

    // G3 — Guard B：--init-validator-safety + mainnet ⇒ reject。
    #[test]
    fn g3_init_validator_safety_on_mainnet_rejected() {
        let mut items = valid_validator_items();
        let idx = items.iter().position(|s| *s == "devnet").unwrap();
        items[idx] = "mainnet";
        items.push("--init-validator-safety");
        assert_eq!(
            parse(&items),
            Err(CliError::InitValidatorSafetyUnsupportedOnMainnet)
        );
    }

    // G4 — 重复 --init-validator-safety ⇒ reject。
    #[test]
    fn g4_init_validator_safety_duplicate_rejected() {
        let mut items = valid_validator_items();
        items.push("--init-validator-safety");
        items.push("--init-validator-safety");
        assert_eq!(
            parse(&items),
            Err(CliError::DuplicateArgument("--init-validator-safety"))
        );
    }

    // G5 — HELP 必须含该 flag（CLI 契约可见性）。
    #[test]
    fn g5_help_lists_init_validator_safety() {
        assert!(
            HELP.contains("--init-validator-safety"),
            "HELP 必须列出 --init-validator-safety"
        );
    }

    // -----------------------------------------------------------------------
    // P1-A.2 tests（T24–T39）：seed / 身份 / transport / 装配（无事件循环、无拨号、无 sleep）
    // -----------------------------------------------------------------------

    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::identity::{
        AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
        canonical_genesis_bytes, validator_id,
    };

    /// 确定性测试 seed（仅测试用；不写入仓库 / 不外显）。
    const TEST_SEED_NET: [u8; 32] = [0x11; 32];
    const TEST_SEED_VAL: [u8; 32] = [0x22; 32];
    /// 与 genesis 不匹配的第三个 seed（T30 用）。
    const TEST_SEED_OTHER: [u8; 32] = [0x33; 32];

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Devnet,
            key_hash: kh,
        })
    }

    /// 最小合法 genesis（单验证者；canonical 约束：validator 升序 / 账户升序 /
    /// total_supply == Σ liquid）。
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

    fn vk_bytes(seed: [u8; 32]) -> [u8; 32] {
        SigningKey::from_seed(seed).verifying_key().to_bytes()
    }

    /// 测试用临时目录（仅测试进程私有；Drop 时清理；不触碰仓库 / 用户文件）。
    struct TempEnv {
        dir: PathBuf,
    }

    impl TempEnv {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("yazimao_p1a2_{}_{}", std::process::id(), tag));
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

    impl Drop for TempEnv {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// 构造装配用合法 CLI（genesis/hash/storage/network seed 已就位）。
    fn assembly_cli(env: &TempEnv, genesis_hash: [u8; 32], extra: &[String]) -> Cli {
        let mut items = vec![
            "--genesis".to_string(),
            env.path("genesis.bin").to_string_lossy().to_string(),
            "--genesis-hash".to_string(),
            hex32(&genesis_hash),
            "--chain-id".to_string(),
            "1001".to_string(),
            "--network-id".to_string(),
            "devnet".to_string(),
            "--storage-dir".to_string(),
            env.path("chain").to_string_lossy().to_string(),
            "--network-seed-file".to_string(),
            env.path("net.seed").to_string_lossy().to_string(),
        ];
        items.extend_from_slice(extra);
        parse_args(&items).expect("valid assembly CLI")
    }

    fn write_valid_genesis(env: &TempEnv, validator_pk: [u8; 32]) -> [u8; 32] {
        let genesis = test_genesis(validator_pk);
        let bytes = canonical_genesis_bytes(&genesis).expect("canonical genesis bytes");
        env.write("genesis.bin", &bytes);
        compute_genesis_hash(&genesis).expect("genesis hash")
    }

    // T24 — network seed 文件不存在 ⇒ fail-closed
    #[test]
    fn t24_network_seed_missing() {
        let env = TempEnv::new("t24");
        assert_eq!(read_seed_file(&env.path("nope.seed")), Err(SeedError::Read));
    }

    // T25 — network seed 长度错误 ⇒ fail-closed
    #[test]
    fn t25_network_seed_wrong_length() {
        let env = TempEnv::new("t25");
        let p = env.write("short.seed", b"abcd");
        assert_eq!(read_seed_file(&p), Err(SeedError::Malformed));
    }

    // T26 — network seed 非 hex ⇒ fail-closed
    #[test]
    fn t26_network_seed_invalid_hex() {
        let env = TempEnv::new("t26");
        let mut bad = [b'z'; 64];
        bad[0] = b'a';
        let p = env.write("bad.seed", &bad);
        assert_eq!(read_seed_file(&p), Err(SeedError::Malformed));
    }

    // T27 — network seed 带 BOM ⇒ fail-closed
    #[test]
    fn t27_network_seed_bom() {
        let env = TempEnv::new("t27");
        let mut content = vec![0xEF, 0xBB, 0xBF];
        content.extend_from_slice(hex32(&TEST_SEED_NET).as_bytes());
        let p = env.write("bom.seed", &content);
        assert_eq!(read_seed_file(&p), Err(SeedError::Bom));
    }

    // T28 — validator seed 文件不存在（validator 模式）⇒ fail-closed
    #[test]
    fn t28_validator_seed_missing() {
        let env = TempEnv::new("t28");
        env.write_seed("net.seed", TEST_SEED_NET);
        let genesis = test_genesis(vk_bytes(TEST_SEED_VAL));
        let set = ValidatorSet::from_genesis(&genesis);
        let cli = assembly_cli(
            &env,
            [0u8; 32],
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                env.path("missing-val.seed").to_string_lossy().to_string(),
            ],
        );
        // NodeRuntime 未实现 Debug（既有类型，本轮不可改）⇒ 不使用 expect_err。
        let err = assemble_and_verify_runtime(&cli, &set)
            .err()
            .expect("must fail-closed");
        assert!(
            matches!(err, StartupError::Seed(SeedError::Read)),
            "{err:?}"
        );
    }

    // T29 — validator seed 格式非法 ⇒ fail-closed
    #[test]
    fn t29_validator_seed_malformed() {
        let env = TempEnv::new("t29");
        env.write_seed("net.seed", TEST_SEED_NET);
        let val_path = env.write("val.seed", b"not-hex-not-64");
        let genesis = test_genesis(vk_bytes(TEST_SEED_VAL));
        let set = ValidatorSet::from_genesis(&genesis);
        let cli = assembly_cli(
            &env,
            [0u8; 32],
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                val_path.to_string_lossy().to_string(),
            ],
        );
        let err = assemble_and_verify_runtime(&cli, &set)
            .err()
            .expect("must fail-closed");
        assert!(
            matches!(err, StartupError::Seed(SeedError::Malformed)),
            "{err:?}"
        );
    }

    // T30 — validator 身份不在 genesis ValidatorSet ⇒ fail-closed
    #[test]
    fn t30_validator_not_in_validator_set() {
        let env = TempEnv::new("t30");
        env.write_seed("net.seed", TEST_SEED_NET);
        // genesis 登记的 validator = TEST_SEED_VAL；实际提供 TEST_SEED_OTHER
        let val_path = env.write_seed("val.seed", TEST_SEED_OTHER);
        let genesis = test_genesis(vk_bytes(TEST_SEED_VAL));
        let set = ValidatorSet::from_genesis(&genesis);
        let cli = assembly_cli(
            &env,
            [0u8; 32],
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                val_path.to_string_lossy().to_string(),
            ],
        );
        let err = assemble_and_verify_runtime(&cli, &set)
            .err()
            .expect("must fail-closed");
        assert!(
            matches!(
                err,
                StartupError::Identity(IdentityError::ValidatorNotInValidatorSet)
            ),
            "{err:?}"
        );
    }

    // T31 — network seed == validator seed ⇒ fail-closed（身份分离）
    #[test]
    fn t31_network_and_validator_identity_must_differ() {
        let env = TempEnv::new("t31");
        env.write_seed("net.seed", TEST_SEED_NET);
        let val_path = env.write_seed("val.seed", TEST_SEED_NET);
        let genesis = test_genesis(vk_bytes(TEST_SEED_NET));
        let set = ValidatorSet::from_genesis(&genesis);
        let cli = assembly_cli(
            &env,
            [0u8; 32],
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                val_path.to_string_lossy().to_string(),
            ],
        );
        let err = assemble_and_verify_runtime(&cli, &set)
            .err()
            .expect("must fail-closed");
        assert!(
            matches!(
                err,
                StartupError::Identity(IdentityError::NetworkAndValidatorIdentityMustDiffer)
            ),
            "{err:?}"
        );
    }

    // T32/T33 — SeedKeyProvider：首次 load PASS；第二次 ⇒ AlreadyProvisioned
    #[test]
    fn t32_t33_seed_key_provider_take_once() {
        let provider = SeedKeyProvider::from_signing_key(SigningKey::from_seed(TEST_SEED_VAL));
        let signer = provider.load_signer().expect("first load ok");
        assert_eq!(
            signer.public_key().to_bytes(),
            vk_bytes(TEST_SEED_VAL),
            "provider 公钥 == seed 派生公钥"
        );
        assert_eq!(
            provider.load_signer().err(),
            Some(KeyProviderError::AlreadyProvisioned),
            "第二次 load ⇒ AlreadyProvisioned"
        );
    }

    // T34 — 同一 network seed ⇒ 稳定 NodeId；不同 seed ⇒ 不同 NodeId
    #[test]
    fn t34_network_node_id_deterministic() {
        let a = SeedNetworkIdentity {
            signing: SigningKey::from_seed(TEST_SEED_NET),
        };
        let b = SeedNetworkIdentity {
            signing: SigningKey::from_seed(TEST_SEED_NET),
        };
        let c = SeedNetworkIdentity {
            signing: SigningKey::from_seed(TEST_SEED_VAL),
        };
        assert_eq!(a.node_id(), b.node_id(), "同 seed ⇒ 同 NodeId");
        assert_ne!(a.node_id(), c.node_id(), "不同 seed ⇒ 不同 NodeId");
        assert_eq!(
            a.node_id(),
            NodeId::from_verifying_key(&SigningKey::from_seed(TEST_SEED_NET).verifying_key()),
            "NodeId == from_verifying_key(seed 派生 VK)"
        );
    }

    // T35/T36 — IdleTransport：send ⇒ TransportIo；try_recv ⇒ None；非 closed
    #[test]
    fn t35_t36_idle_transport_semantics() {
        let mut t = IdleTransport;
        assert_eq!(
            t.send(&NodeId::from_bytes([0x99; 32]), vec![1, 2, 3]),
            Err(NetworkError::TransportIo)
        );
        assert_eq!(t.try_recv(), Ok(None));
        assert!(!t.is_closed());
    }

    // T37 — 合法 full-node 装配（真实 genesis/seed 临时文件；无拨号 / 无事件循环）
    #[test]
    fn t37_valid_full_node_assembly() {
        let env = TempEnv::new("t37");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(&env, genesis_hash, &[]);
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        assert_eq!(
            report.node_id,
            NodeId::from_verifying_key(&SigningKey::from_seed(TEST_SEED_NET).verifying_key())
        );
        assert!(report.peer_auth_enabled, "peer-auth 已启用");
        assert_eq!(report.listen_addr, None, "未指定 --listen ⇒ 无 listener");
        assert_eq!(report.inbound_connections, 0, "未拨号 ⇒ 无入站连接");
        // P1-A.3：装配不再内部 shutdown ⇒ 本测试显式释放（资源不泄漏）。
        runtime.shutdown().expect("shutdown ok");
    }

    // T38 — 合法 validator 装配（成员命中；safety dir 自动创建）
    #[test]
    fn t38_valid_validator_assembly() {
        let env = TempEnv::new("t38");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let val_path = env.write_seed("val.seed", TEST_SEED_VAL);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                val_path.to_string_lossy().to_string(),
                // G5-D.7.2：fresh safety dir（journal 不存在）⇒ 显式声明初始化。
                "--init-validator-safety".to_string(),
            ],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (runtime, report) =
            assemble_and_verify_runtime(&cli, &set).expect("validator assembly ok");
        assert!(report.peer_auth_enabled);
        assert_eq!(report.inbound_connections, 0);
        runtime.shutdown().expect("shutdown ok");
    }

    // T39 — --listen ⇒ runtime 报告真实监听地址
    #[test]
    fn t39_listen_address_bound() {
        let env = TempEnv::new("t39");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &["--listen".to_string(), "127.0.0.1:0".to_string()],
        );
        assert_eq!(cli.listen_addr, Some("127.0.0.1:0".parse().unwrap()));
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        let bound = report.listen_addr.expect("runtime 必须报告真实监听地址");
        assert_ne!(bound.port(), 0, "port 0 已解析为实际端口");
        runtime.shutdown().expect("shutdown ok");
    }

    // -----------------------------------------------------------------------
    // P1-A.3：`--run-steps` 解析 + 有界长运行驱动循环
    // -----------------------------------------------------------------------

    // T40 — --run-steps 缺值 / 后接另一个 flag ⇒ MissingValue（fail-closed）
    #[test]
    fn t40_run_steps_missing_value_rejected() {
        let mut items = valid_base();
        items.push("--run-steps");
        assert_eq!(parse(&items), Err(CliError::MissingValue("--run-steps")));

        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "--idle-ms", "1"]);
        assert_eq!(parse(&items), Err(CliError::MissingValue("--run-steps")));
    }

    // T41 — --run-steps 非法值（非数字 / 负数 / 空白 / 溢出）⇒ InvalidRunSteps
    //      （**B1 语义变更**：`0` 现在合法 = continuous / unlimited ⇒ 不再属于非法值）
    #[test]
    fn t41_run_steps_invalid_values_rejected() {
        for bad in [
            "abc",
            "-1",
            " 1",
            "1 ",
            "0x10",
            "1.5",
            "99999999999999999999999",
        ] {
            let mut items = valid_base();
            items.extend_from_slice(&["--run-steps", bad]);
            assert_eq!(
                parse(&items),
                Err(CliError::InvalidRunSteps),
                "value={bad:?} 必须 fail-closed"
            );
        }
    }

    // T42 — --run-steps 合法值接受（含 B1 的 `0` = continuous）；缺省 = RUN_STEPS_DEFAULT（有限预算）
    #[test]
    fn t42_run_steps_accepted_and_default() {
        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "7"]);
        assert_eq!(parse(&items).map(|c| c.run_steps), Ok(7));

        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "1"]);
        assert_eq!(parse(&items).map(|c| c.run_steps), Ok(1));

        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "18446744073709551615"]);
        assert_eq!(parse(&items).map(|c| c.run_steps), Ok(u64::MAX));

        // B1（Testnet）—— `0` = **continuous / unlimited**（不再被拒绝）；CLI 必须接受并原样传入。
        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "0"]);
        assert_eq!(
            parse(&items).map(|c| c.run_steps),
            Ok(0),
            "run_steps=0 ⇒ continuous / unlimited"
        );

        assert_eq!(
            parse(&valid_base()).map(|c| c.run_steps),
            Ok(RUN_STEPS_DEFAULT)
        );
    }

    // T43 — --run-steps 重复 ⇒ DuplicateArgument
    #[test]
    fn t43_run_steps_duplicate_rejected() {
        let mut items = valid_base();
        items.extend_from_slice(&["--run-steps", "2", "--run-steps", "3"]);
        assert_eq!(
            parse(&items),
            Err(CliError::DuplicateArgument("--run-steps"))
        );
    }

    // T44 — 有界循环：恰好执行 run_steps 次 step（无 N+1）+ 摘要仅含非敏感观测
    #[test]
    fn t44_loop_runs_exact_step_budget() {
        let env = TempEnv::new("t44");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &[
                "--run-steps".to_string(),
                "3".to_string(),
                "--idle-ms".to_string(),
                "1".to_string(),
            ],
        );
        assert_eq!(cli.run_steps, 3);
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        assert_eq!(report.inbound_connections, 0);

        let outcome = run_node_loop(&mut runtime, &cli);
        assert!(outcome.error.is_none(), "full-node 无拨号 ⇒ step 不应失败");
        let s = outcome.summary;
        assert_eq!(s.steps, 3, "run_steps=3 ⇒ 恰好 3 次 step（无 N+1）");
        assert_eq!(s.run_steps, 3);
        assert_eq!(s.head_height, 0, "无对端 ⇒ head 停在 genesis head");
        assert_eq!(s.configured_peers, 0);
        assert_eq!(s.established_peers, 0);
        assert_eq!(s.inbound_connections, 0);
        assert_eq!(s.inbound_accepted, 0);
        runtime.shutdown().expect("shutdown ok");
    }

    // T45 — 预算边界：run_steps=1 ⇒ 恰好 1 次 step；默认预算亦为有限值
    #[test]
    fn t45_loop_budget_boundary_one_step() {
        let env = TempEnv::new("t45");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &["--run-steps".to_string(), "1".to_string()],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        assert!(report.peer_auth_enabled);
        let outcome = run_node_loop(&mut runtime, &cli);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.summary.steps, 1, "run_steps=1 ⇒ 恰好 1 次");
        runtime.shutdown().expect("shutdown ok");
    }

    // T46 — validator 形态亦可在循环中驱动（预算 1；既有 shutdown 正常）
    #[test]
    fn t46_loop_validator_mode_budget_one_step() {
        let env = TempEnv::new("t46");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let val_path = env.write_seed("val.seed", TEST_SEED_VAL);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &[
                "--validator".to_string(),
                "--safety-dir".to_string(),
                env.path("safety").to_string_lossy().to_string(),
                "--validator-seed-file".to_string(),
                val_path.to_string_lossy().to_string(),
                "--run-steps".to_string(),
                "1".to_string(),
                // G5-D.7.2：fresh safety dir（journal 不存在）⇒ 显式声明初始化。
                "--init-validator-safety".to_string(),
            ],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        assert!(report.peer_auth_enabled);
        let outcome = run_node_loop(&mut runtime, &cli);
        assert!(outcome.error.is_none(), "validator 单步不应失败");
        assert_eq!(outcome.summary.steps, 1);
        assert_eq!(outcome.summary.configured_peers, 0);
        assert_eq!(outcome.summary.inbound_accepted, 0);
        runtime.shutdown().expect("shutdown ok");
    }

    // T47 — pacing 存在且循环终止（无 busy loop / 无无限循环）：上限宽松断言
    #[test]
    fn t47_loop_terminates_with_pacing() {
        let env = TempEnv::new("t47");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &[
                "--run-steps".to_string(),
                "2".to_string(),
                "--idle-ms".to_string(),
                "50".to_string(),
            ],
        );
        assert_eq!(cli.idle_ms, 50);
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        assert_eq!(report.inbound_connections, 0);
        let started = std::time::Instant::now();
        let outcome = run_node_loop(&mut runtime, &cli);
        let elapsed = started.elapsed();
        assert!(outcome.error.is_none());
        assert_eq!(outcome.summary.steps, 2, "预算耗尽即退出（无额外轮次）");
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "循环必须有界终止（实测 {elapsed:?}）"
        );
        runtime.shutdown().expect("shutdown ok");
    }

    // OD-X8 — liveness 行暴露 `egress_prop_refreshed`（**字段暴露/格式化**测试；
    // **不**证明重播已发生：新装配 runtime 尚未发生任何 replay ⇒ 期望值为 0，
    // 实际重播次数必须从运行日志读取）。
    #[test]
    fn od_x8_liveness_line_exposes_refresh_counter() {
        let env = TempEnv::new("odx8");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &["--run-steps".to_string(), "1".to_string()],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, _report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");

        // 定向驱动（**不是** soak）：跑有限步，取**真实**运行读数（值本身不参与断言强度）。
        for _ in 0..12 {
            let _ = runtime.step();
        }

        let line = liveness_line(&runtime, &cli, STATUS_INTERVAL_STEPS);
        let counter = runtime.liveness_snapshot().egress_prop_refreshed;
        let expected = format!("egress_prop_refreshed={counter}");
        // 观测值直接打印（`--nocapture` 可见）；**不**断言其大于零。
        println!("OD-X8 observed egress_prop_refreshed={counter}");
        assert!(line.contains(&expected), "liveness 行缺少刷新计数: {line}");
        // 兼容性：既有相邻字段仍逐字存在（未重命名 / 未移除）。
        assert!(line.contains("egress_prop_enqueued="), "既有字段缺失: {line}");
        assert!(line.contains("egress_prop_no_peer="), "既有字段缺失: {line}");
        assert!(line.contains("round_adv_local="), "既有字段缺失: {line}");
        // 确定性（无墙钟 / 无随机 / 无 I/O）。
        assert_eq!(
            line,
            liveness_line(&runtime, &cli, STATUS_INTERVAL_STEPS),
            "liveness 行必须确定性"
        );
    }

    // T48（P1-A.9 / P1-3）— status 固定 interval：非每 step、非零、默认预算下无日志洪水
    #[test]
    fn t48_status_interval_is_fixed_and_not_per_step() {
        assert!(!should_emit_status(0), "step 0 不是有效 step");
        for s in 1..STATUS_INTERVAL_STEPS {
            assert!(!should_emit_status(s), "step {s} 不得输出 status");
        }
        assert!(should_emit_status(STATUS_INTERVAL_STEPS));
        assert!(should_emit_status(STATUS_INTERVAL_STEPS * 2));
        assert!(!should_emit_status(STATUS_INTERVAL_STEPS * 2 + 1));
        // 编译期事实（不得每 step 输出；默认预算下 status 行数有界）。
        const { assert!(STATUS_INTERVAL_STEPS > 1) };
        const { assert!(RUN_STEPS_DEFAULT / STATUS_INTERVAL_STEPS <= 64) };
    }

    // T49（P1-A.9 / P1-3）— status 行确定性 + 必需字段（不绑定完整字符串）
    #[test]
    fn t49_status_line_is_deterministic_and_has_required_fields() {
        let env = TempEnv::new("t49");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &["--run-steps".to_string(), "1".to_string()],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (runtime, _report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");

        let summary = summarize(&runtime, &cli, STATUS_INTERVAL_STEPS);
        assert_eq!(
            summary.block_inbound_skipped,
            runtime.block_inbound_skipped()
        );
        assert_eq!(
            summary.pending_external_qc,
            runtime.pending_external_qc_len()
        );
        assert_eq!(summary.qc_served, runtime.qc_served());

        let a = status_line(&runtime, &cli, STATUS_INTERVAL_STEPS);
        let b = status_line(&runtime, &cli, STATUS_INTERVAL_STEPS);
        assert_eq!(a, b, "status 行必须确定性（无墙钟 / 无随机）");
        assert!(a.starts_with("yazimao-node: status "), "status 前缀: {a}");
        assert!(a.ends_with('\n'), "status 行必须以换行结束");
        for key in [
            "steps=",
            "head_height=",
            "finalized_height=",
            "consensus_height=",
            "round=",
            "configured_peers=",
            "established_peers=",
            "inbound_connections=",
            "sync_pending=",
            "block_inbound_skipped=",
            "pending_external_qc=",
            "qc_served=",
            "validator_enabled=",
        ] {
            assert!(a.contains(key), "status 行缺少字段 {key}: {a}");
        }
        assert!(
            a.contains(&format!("steps={STATUS_INTERVAL_STEPS}")),
            "status 必须报告当前 steps: {a}"
        );
        runtime.shutdown().expect("shutdown ok");
    }

    // T49b（P1-A.17 F-1）— `BlockCommit` 错误格式化必须保留真实 inner error 文本
    #[test]
    fn t49b_blockcommit_fault_message_keeps_inner_error_display() {
        let err = RuntimeError::BlockCommit(nova_node::NodeBlockApplicationError::Pipeline(
            nova_runtime::BlockPipelineError::Storage(
                nova_storage::error::StorageError::BackendFailure,
            ),
        ));
        let msg = run_fault_message(&err);
        assert!(msg.starts_with("BlockCommit: "), "{msg:?}");
        assert!(msg.contains("block application pipeline:"), "{msg:?}");
        assert!(msg.contains("backend primitive failure"), "{msg:?}");
    }

    // T50（P1-A.9 / P1-3）— 退出摘要：保留 P1-A.3 契约字段 + 新增 A.8/P1-A.9 观测字段
    #[test]
    fn t50_summary_line_keeps_contract_and_adds_observation_fields() {
        let env = TempEnv::new("t50");
        let genesis_hash = write_valid_genesis(&env, vk_bytes(TEST_SEED_VAL));
        env.write_seed("net.seed", TEST_SEED_NET);
        let cli = assembly_cli(
            &env,
            genesis_hash,
            &["--run-steps".to_string(), "2".to_string()],
        );
        let (_identity, set) = preflight(&cli).expect("preflight ok");
        let (mut runtime, _report) = assemble_and_verify_runtime(&cli, &set).expect("assembly ok");
        let outcome = run_node_loop(&mut runtime, &cli);
        assert!(outcome.error.is_none());
        assert!(
            !outcome.status_write_failed,
            "stdout 可用时 status 写不得失败（2 steps < interval ⇒ 无 status）"
        );
        let line = summary_line(&outcome.summary);
        // P1-A.3 既有契约字段（集成测试依赖同名子串）。
        for key in [
            "stopped after ",
            "head_height=",
            "configured_peers=",
            "inbound_connections=",
            "inbound_accepted=",
            "runtime shut down",
        ] {
            assert!(line.contains(key), "摘要缺少契约字段 {key}: {line}");
        }
        // P1-A.9 新增观测字段。
        for key in [
            "finalized_height=",
            "consensus_height=",
            "round=",
            "sync_pending=",
            "peer_dial_attempts=",
            "peer_dial_failures=",
            "validator_enabled=",
        ] {
            assert!(line.contains(key), "摘要缺少新增字段 {key}: {line}");
        }
        runtime.shutdown().expect("shutdown ok");
    }
}
