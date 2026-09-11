//! YAZIMAO Node — production executable skeleton（**P1-A.1**）。
//!
//! # 本轮边界（P1-A.1 = CLI + genesis pre-flight + NodeConfig 组装）
//! ```text
//! process start
//!   → main()
//!   → 最小 CLI 解析（std::env::args；零新依赖；严格 fail-closed）
//!   → genesis pre-flight（read → decode → compute hash → 比对锚 → validate → ValidatorSet）
//!   → NodeConfig 组装（**不新增 / 不修改任何 NodeConfig 字段**）
//!   → STOP（runtime 装配 / 事件循环未实现 ⇒ P1-A.2 / P1-A.3）
//! ```
//!
//! **本 build 明确不是可运行节点**：不启动 `NodeRuntime`、不绑定 TCP、不读取 seed / 私钥、
//! 不连接 peer、不进入事件循环、不处理信号、不写日志。成功路径只做“配置门校验 + 组装”。
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
//!   `Cargo.toml` / `Cargo.lock`、`docs/**`、`README.md`、任何既有 node 模块。
//! - **未新增任何依赖**（不引入 CLI 解析库 / 信号处理库 / 日志框架）。

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use nova_consensus::validator::ValidatorSet;
use nova_crypto::address::NetworkId;
use nova_crypto::identity::{
    ChainIdentity, compute_genesis_hash, decode_genesis_bytes, validate_genesis_with_expected,
};
use nova_network::node_id::NodeId;
use nova_network::transport::ConnectionTarget;
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::KeyProviderConfig;

/// 程序名（help / version 输出）。
const PROGRAM: &str = "yazimao-node";
/// 软件版本（workspace 统一版本）。
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 有界空闲间隔默认值（ms）。
const IDLE_MS_DEFAULT: u64 = 1;
/// 有界空闲间隔上限（ms；越界 ⇒ fail-closed）。
const IDLE_MS_MAX: u64 = 50;

/// CLI 契约文本（非日志；不含任何完成度宣称）。
const HELP: &str = "\
YAZIMAO node
bootstrap/devnet/testnet oriented executable skeleton

NOT MAINNET READY

P1-A.1 scope: CLI parsing + genesis pre-flight validation + NodeConfig assembly ONLY.
Runtime assembly, TCP listener/dialer wiring, validator/network key loading and the
bounded event loop are NOT implemented in this build (deferred to P1-A.2 / P1-A.3).
This build validates configuration and exits; it does not run a node.

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
  --idle-ms <n>                 bounded idle interval in ms (default 1, maximum 50)
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
    /// `--validator` 未提供 `--safety-dir`。
    ValidatorRequiresSafetyDir,
    /// `--validator` 未提供 `--validator-seed-file`。
    ValidatorRequiresSeedFile,
    /// `--validator` + `--network-id mainnet`（Mainnet 级密钥管理未实现）。
    MainnetValidatorUnsupported,
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

/// 入口层错误（CLI / pre-flight / 输出写失败）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupError {
    /// CLI 解析 / 交叉校验失败。
    Cli(CliError),
    /// genesis pre-flight 失败。
    Preflight(PreflightError),
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
    network_seed_file: PathBuf,
    idle_ms: u64,
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
    let mut network_seed_file: Option<PathBuf> = None;
    let mut idle_ms: Option<u64> = None;

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

    // 交叉校验（validator 模式 + Mainnet 安全门）。
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
        network_seed_file,
        idle_ms: idle_ms.unwrap_or(IDLE_MS_DEFAULT),
    })
}

// ---------------------------------------------------------------------------
// genesis pre-flight（只读；fail-closed）
// ---------------------------------------------------------------------------

/// 启动前 genesis 校验：read → decode → hash → 锚比对 → 全量校验 → chain/network → ValidatorSet。
///
/// `--genesis-hash` 是**外部信任锚**：绝不从文件推导、绝不自动生成。
fn preflight(cli: &Cli) -> Result<ChainIdentity, PreflightError> {
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
    Ok(identity)
}

// ---------------------------------------------------------------------------
// NodeConfig 组装（不新增 / 不修改 NodeConfig 字段）
// ---------------------------------------------------------------------------

/// 由已校验 CLI 组装既有 `NodeConfig`（字段一一映射；无新字段）。
fn build_node_config(cli: &Cli) -> NodeConfig {
    NodeConfig {
        genesis_path: cli.genesis.clone(),
        expected_genesis_hash: cli.genesis_hash,
        expected_chain_id: cli.chain_id,
        expected_network_id: cli.network_id,
        storage_dir: cli.storage_dir.clone(),
        validator_enabled: cli.validator,
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

/// **P1-A.1 终点**：runtime 装配与事件循环 **未实现**（P1-A.2 / P1-A.3）。
///
/// 此处是后续阶段的唯一注入点：P1-A.2 完成“身份装载 + 网络装配”，P1-A.3 完成
/// “有界事件循环 + 信号优雅停机”。对应 API 属后续阶段（**本文件刻意不引用**，以免被误认为已接线）。
///
/// 本函数**刻意为空**：不启动 runtime、不开 socket、不读 seed、不落盘。
fn deferred_runtime_assembly(_config: &NodeConfig, _identity: &ChainIdentity, _idle_ms: u64) {
    // 见上：P1-A.1 到此为止（不伪装为可运行节点）。
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
            let identity = preflight(&cli).map_err(StartupError::Preflight)?;
            let config = build_node_config(&cli);
            deferred_runtime_assembly(&config, &identity, cli.idle_ms);
            write_stdout(&format!(
                "{PROGRAM}: configuration validated (P1-A.1 skeleton; \
                 runtime assembly deferred to P1-A.2)\n"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests（纯解析 / 组装；无 TCP / 无 NodeRuntime / 无文件系统）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    // T23 — genesis pre-flight 错误面（文件 / 解码；不依赖 fixture 内容）
    #[test]
    fn t23_preflight_missing_file_fails_closed() {
        let cli = parse(&valid_base()).expect("parse ok");
        let missing = PathBuf::from("/definitely/not/a/genesis/file.bin");
        let cli = Cli {
            genesis: missing,
            ..cli
        };
        assert_eq!(preflight(&cli), Err(PreflightError::GenesisRead));
    }
}
