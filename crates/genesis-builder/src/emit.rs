//! 产物写出与只读复核。
//!
//! # `build`
//! `genesis.json` → **自校验流水线** → 三件产物：
//! - `genesis.bin`：由 [`nova_crypto::identity::canonical_genesis_bytes`] 产出（**本 crate 不实现编码**）。
//! - `genesis_hash.txt`：由 [`nova_crypto::identity::compute_genesis_hash`] 产出（**本 crate 不实现 SHA-256**），
//!   内容为 **64 位小写 hex + 换行**。
//! - `genesis_summary.json`：人工复核摘要（字段快照、计数、canonical 长度、hash、排序报告、分配合计）。
//!
//! 自校验（fail-closed）：`decode_genesis_bytes(输出)` 回读 + `validate_genesis_with_expected`。
//! 该回读同时覆盖 **Ed25519 压缩点 canonical 校验**（由 `nova-crypto` 的 decode 路径执行）。
//!
//! **不覆盖已有文件**（除非 `force = true`）。
//!
//! # `verify`
//! 只读：读 `genesis.bin` + `genesis_hash.txt` → `decode_genesis_bytes` →
//! `validate_genesis_with_expected`。任意 1 字节篡改 ⇒ 失败（decode 失败或 hash 不匹配）。

use core::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use nova_crypto::identity::{
    GenesisError, canonical_genesis_bytes, compute_genesis_hash, decode_genesis_bytes,
    validate_genesis_with_expected,
};
use serde_json::json;

use crate::input::{InputError, parse_genesis_json};
use crate::normalize::{ReorderReport, normalize_lists};
use crate::preflight::{PreflightError, check_preconditions};

/// 产物文件名：canonical Genesis 二进制。
pub const ARTIFACT_GENESIS_BIN: &str = "genesis.bin";
/// 产物文件名：genesis hash（64 位小写 hex + 换行）。
pub const ARTIFACT_GENESIS_HASH: &str = "genesis_hash.txt";
/// 产物文件名：人工复核摘要。
pub const ARTIFACT_SUMMARY: &str = "genesis_summary.json";

/// `build` 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReport {
    /// canonical Genesis 的 SHA-256（小写 hex）。
    pub genesis_hash_hex: String,
    /// canonical 字节长度。
    pub canonical_len: usize,
    /// `genesis.bin` 绝对/相对路径（按调用方给出的 `out_dir`）。
    pub genesis_bin: PathBuf,
    /// `genesis_hash.txt` 路径。
    pub genesis_hash_file: PathBuf,
    /// `genesis_summary.json` 路径。
    pub genesis_summary_file: PathBuf,
    /// `chain_id`。
    pub chain_id: u64,
    /// `network_id`（u8 线格式）。
    pub network_id: u8,
    /// `genesis_timestamp`。
    pub genesis_timestamp: u64,
    /// validator 数量。
    pub validator_count: usize,
    /// account 数量。
    pub account_count: usize,
    /// 排序报告。
    pub reorder: ReorderReport,
}

/// `build` 错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// strict JSON 解析失败。
    Input(InputError),
    /// 预检失败。
    Preflight(PreflightError),
    /// `nova-crypto` 编码 / hash 失败。
    Genesis(GenesisError),
    /// I/O 失败（含目录创建）。
    Io(String),
    /// 目标产物已存在（且未指定 `force`）。
    ArtifactExists(String),
    /// 自校验失败（回读不一致；理论上不应发生 ⇒ 视为硬失败）。
    SelfVerification(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(e) => write!(f, "input: {e}"),
            Self::Preflight(e) => write!(f, "preflight: {e}"),
            Self::Genesis(e) => write!(f, "genesis: {e}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::ArtifactExists(p) => {
                write!(f, "artifact: `{p}` 已存在（如需覆盖请显式使用 --force）")
            }
            Self::SelfVerification(m) => write!(f, "self-verification: {m}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<InputError> for BuildError {
    fn from(e: InputError) -> Self {
        Self::Input(e)
    }
}

impl From<PreflightError> for BuildError {
    fn from(e: PreflightError) -> Self {
        Self::Preflight(e)
    }
}

impl From<GenesisError> for BuildError {
    fn from(e: GenesisError) -> Self {
        Self::Genesis(e)
    }
}

/// `verify` 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// 复核算出的 hash（小写 hex）。
    pub genesis_hash_hex: String,
    /// `chain_id`。
    pub chain_id: u64,
    /// `network_id`（u8 线格式）。
    pub network_id: u8,
    /// `genesis_timestamp`。
    pub genesis_timestamp: u64,
    /// validator 数量。
    pub validator_count: usize,
    /// account 数量。
    pub account_count: usize,
    /// canonical 字节长度。
    pub canonical_len: usize,
}

/// `verify` 错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// I/O 失败。
    Io(String),
    /// `genesis_hash.txt` 格式非法（须为 64 位小写 hex）。
    HashFileFormat(String),
    /// `genesis.bin` 解码失败（结构 / canonical / 尾随字节 / 公钥 canonical 等）。
    Decode(GenesisError),
    /// 校验失败（computed != configured，或语义非法）。
    Validation(GenesisError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "io: {m}"),
            Self::HashFileFormat(v) => write!(
                f,
                "genesis_hash.txt: 期望 64 位小写 hex（含换行），实际 `{v}`"
            ),
            Self::Decode(e) => write!(f, "genesis.bin: 解码失败：{e}"),
            Self::Validation(e) => write!(f, "genesis: 校验失败：{e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// 执行 `build`：解析 → 规范化 → 预检 → canonical 编码 → hash → 自校验 → 写出三件产物。
pub fn build_artifacts(
    input: &str,
    out_dir: &Path,
    force: bool,
) -> Result<BuildReport, BuildError> {
    let mut genesis = parse_genesis_json(input)?;
    let reorder = normalize_lists(&mut genesis);
    let preflight = check_preconditions(&genesis)?;

    // 编码与 hash 一律委托 nova-crypto（唯一来源）。
    let bytes = canonical_genesis_bytes(&genesis)?;
    let hash = compute_genesis_hash(&genesis)?;
    let hash_hex = crate::hex(&hash);

    // ---- 自校验（fail-closed）----
    let decoded = decode_genesis_bytes(&bytes)?;
    let identity = validate_genesis_with_expected(&decoded, &hash)?;
    if identity.chain_id != genesis.chain_id {
        return Err(BuildError::SelfVerification(
            "回读 chain_id 与输入不一致".to_string(),
        ));
    }
    if identity.network_id != genesis.network_id {
        return Err(BuildError::SelfVerification(
            "回读 network_id 与输入不一致".to_string(),
        ));
    }
    if identity.genesis_hash != hash {
        return Err(BuildError::SelfVerification(
            "回读 genesis_hash 与计算结果不一致".to_string(),
        ));
    }

    // ---- 产物路径 + 覆盖保护 ----
    let bin_path = out_dir.join(ARTIFACT_GENESIS_BIN);
    let hash_path = out_dir.join(ARTIFACT_GENESIS_HASH);
    let summary_path = out_dir.join(ARTIFACT_SUMMARY);
    if !force {
        for p in [&bin_path, &hash_path, &summary_path] {
            if p.exists() {
                return Err(BuildError::ArtifactExists(p.display().to_string()));
            }
        }
    }

    fs::create_dir_all(out_dir)
        .map_err(|e| BuildError::Io(format!("{}: {e}", out_dir.display())))?;

    let summary = build_summary_json(&genesis, &hash_hex, bytes.len(), &reorder, &preflight);
    let summary_text = serde_json::to_string_pretty(&summary)
        .map_err(|e| BuildError::Io(format!("summary json: {e}")))?;

    fs::write(&bin_path, &bytes)
        .map_err(|e| BuildError::Io(format!("{}: {e}", bin_path.display())))?;
    fs::write(&hash_path, format!("{hash_hex}\n"))
        .map_err(|e| BuildError::Io(format!("{}: {e}", hash_path.display())))?;
    fs::write(&summary_path, format!("{summary_text}\n"))
        .map_err(|e| BuildError::Io(format!("{}: {e}", summary_path.display())))?;

    Ok(BuildReport {
        genesis_hash_hex: hash_hex,
        canonical_len: bytes.len(),
        genesis_bin: bin_path,
        genesis_hash_file: hash_path,
        genesis_summary_file: summary_path,
        chain_id: genesis.chain_id,
        network_id: genesis.network_id.as_u8(),
        genesis_timestamp: genesis.genesis_timestamp,
        validator_count: genesis.initial_validator_set.len(),
        account_count: genesis.initial_accounts.len(),
        reorder,
    })
}

/// 只读复核：`genesis.bin` + `genesis_hash.txt`。
pub fn verify_artifacts(bin_path: &Path, hash_path: &Path) -> Result<VerifyReport, VerifyError> {
    let bytes =
        fs::read(bin_path).map_err(|e| VerifyError::Io(format!("{}: {e}", bin_path.display())))?;
    let hash_text = fs::read_to_string(hash_path)
        .map_err(|e| VerifyError::Io(format!("{}: {e}", hash_path.display())))?;
    let hash_hex = parse_hash_file(&hash_text)?;
    let expected = crate::parse_hex32(&hash_hex)
        .ok_or_else(|| VerifyError::HashFileFormat(hash_text.trim().to_string()))?;

    let genesis = decode_genesis_bytes(&bytes).map_err(VerifyError::Decode)?;
    let identity =
        validate_genesis_with_expected(&genesis, &expected).map_err(VerifyError::Validation)?;

    Ok(VerifyReport {
        genesis_hash_hex: crate::hex(&identity.genesis_hash),
        chain_id: identity.chain_id,
        network_id: identity.network_id.as_u8(),
        genesis_timestamp: genesis.genesis_timestamp,
        validator_count: genesis.initial_validator_set.len(),
        account_count: genesis.initial_accounts.len(),
        canonical_len: bytes.len(),
    })
}

/// 解析 `genesis_hash.txt`：忽略首尾空白，必须为 **64 位小写 hex**。
fn parse_hash_file(text: &str) -> Result<String, VerifyError> {
    let trimmed = text.trim();
    let ok = trimmed.len() == 64
        && trimmed
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok {
        Ok(trimmed.to_string())
    } else {
        Err(VerifyError::HashFileFormat(trimmed.to_string()))
    }
}

/// 构建复核摘要（**确定性**：不含时间戳、不含主机路径；`serde_json::Map` 按键有序）。
fn build_summary_json(
    genesis: &nova_crypto::identity::GenesisV1,
    hash_hex: &str,
    canonical_len: usize,
    reorder: &ReorderReport,
    preflight: &crate::preflight::PreflightReport,
) -> serde_json::Value {
    let ep = &genesis.economics_parameters;
    json!({
        "schema": "yazimao-genesis-summary-v1",
        "network_id": genesis.network_id.as_u8(),
        "chain_id": genesis.chain_id,
        "genesis_timestamp": genesis.genesis_timestamp,
        "genesis_hash": hash_hex,
        "canonical_len": canonical_len,
        "validator_count": preflight.validator_count,
        "account_count": preflight.account_count,
        "reorder": {
            "validators_reordered": reorder.validators_reordered,
            "accounts_reordered": reorder.accounts_reordered,
            "validators": reorder.validators.iter().map(|e| json!({
                "original_index": e.original_index,
                "canonical_index": e.canonical_index,
                "validator_id": e.key_hex,
            })).collect::<Vec<_>>(),
            "accounts": reorder.accounts.iter().map(|e| json!({
                "original_index": e.original_index,
                "canonical_index": e.canonical_index,
                "address_payload": e.key_hex,
            })).collect::<Vec<_>>(),
        },
        "allocation": {
            "total_supply": ep.total_supply.to_string(),
            "account_liquid_sum": preflight.account_liquid_sum.to_string(),
            "validator_liquid_sum": preflight.validator_liquid_sum.to_string(),
            "non_validator_liquid_sum": preflight.non_validator_liquid_sum.to_string(),
            "validator_bonded_sum": preflight.validator_bonded_sum.to_string(),
            "min_validator_stake": ep.min_validator_stake.to_string(),
        },
        "protocol_params": {
            "max_tx_bytes": genesis.protocol_parameters.max_tx_bytes,
            "max_block_bytes": genesis.protocol_parameters.max_block_bytes,
            "max_gas_per_block": genesis.protocol_parameters.max_gas_per_block,
            "max_contract_code_bytes": genesis.protocol_parameters.max_contract_code_bytes,
            "max_contract_storage_bytes": genesis.protocol_parameters.max_contract_storage_bytes,
            "epoch_length_blocks": genesis.protocol_parameters.epoch_length_blocks,
            "snapshot_interval_blocks": genesis.protocol_parameters.snapshot_interval_blocks,
        },
        "economics_params": {
            "total_supply": ep.total_supply.to_string(),
            "min_validator_stake": ep.min_validator_stake.to_string(),
            "unbonding_period_seconds": ep.unbonding_period_seconds,
            "fee_burn_bps": ep.fee_burn_bps,
        },
        "artifacts": {
            "genesis_bin": ARTIFACT_GENESIS_BIN,
            "genesis_hash": ARTIFACT_GENESIS_HASH,
            "summary": ARTIFACT_SUMMARY,
        },
        "decisions": {
            "ordering_policy": "AUTO_SORT_AND_REPORT",
            "unknown_fields": "REJECT",
            "sensitive_fields": "REJECT",
            "default_values": "NONE",
            "timestamp_policy": "OWNER_PROVIDED_ONLY",
            "u128_encoding": "DECIMAL_STRING",
        },
    })
}
