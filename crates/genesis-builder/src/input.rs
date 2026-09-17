//! 生产 Genesis 输入解析：**strict JSON → [`GenesisV1`]**。
//!
//! # 严格性（Owner 批准）
//! - **拒绝未知字段**：本 crate 以显式允许键集合实现，等价于 `deny_unknown_fields`
//!   （不引入 `serde` derive 依赖，遵守 workspace 依赖政策）。
//! - **拒绝敏感字段**：`private_key` / `seed` / `mnemonic` / `secret` / `keystore`
//!   ⇒ **硬失败**（绝不静默忽略；避免"文件里带了密钥却以为没问题"）。
//! - **`u128` 只接受十进制字符串**（如 `"1000000000"`）：拒绝 JSON 数字、浮点、指数格式、
//!   前导零、正负号、空白以外的任何字符。
//! - **无默认值**：任何字段缺失 ⇒ 立即失败；**不生成** `genesis_timestamp`，
//!   **不自动填写** `chain_id` / `network_id`。
//! - **占位符拒绝**：空字符串 / `TBD` / `PENDING`（大小写不敏感）。
//! - 安全：本模块**不实现**任何密码学；地址（bech32m）与公钥校验**委托 `nova-crypto`**。
//!
//! # 已知限制（诚实记录）
//! JSON 对象内**重复键**由 `serde_json` 以"后者覆盖"处理，本解析器**无法**检测重复键；
//! 该风险由"输入经人工复核 + `genesis_summary.json` 回显最终取值"缓解。

use core::fmt;
use nova_crypto::address::{NetworkId, YazimaoAddress};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
};
use nova_crypto::signature::VerifyingKey;
use serde_json::{Map, Value};

use crate::parse_hex32;

/// 根对象允许字段（**缺一即拒，多一即拒**）。
const ROOT_FIELDS: [&str; 7] = [
    "chain_id",
    "network_id",
    "genesis_timestamp",
    "validators",
    "accounts",
    "protocol_params",
    "economics_params",
];

/// `validators[]` 元素允许字段。
const VALIDATOR_FIELDS: [&str; 4] = [
    "account_address",
    "consensus_public_key",
    "bonded_stake",
    "commission_bps",
];

/// `accounts[]` 元素允许字段。
const ACCOUNT_FIELDS: [&str; 2] = ["address", "liquid_balance"];

/// `protocol_params` 允许字段。
const PROTOCOL_PARAM_FIELDS: [&str; 7] = [
    "max_tx_bytes",
    "max_block_bytes",
    "max_gas_per_block",
    "max_contract_code_bytes",
    "max_contract_storage_bytes",
    "epoch_length_blocks",
    "snapshot_interval_blocks",
];

/// `economics_params` 允许字段。
const ECONOMICS_PARAM_FIELDS: [&str; 4] = [
    "total_supply",
    "min_validator_stake",
    "unbonding_period_seconds",
    "fee_burn_bps",
];

/// 明令禁止的敏感字段（命中 ⇒ 硬失败）。
const SENSITIVE_FIELDS: [&str; 5] = ["private_key", "seed", "mnemonic", "secret", "keystore"];

/// 占位符（生产输入中出现 ⇒ 拒绝）。
const PLACEHOLDERS: [&str; 2] = ["TBD", "PENDING"];

/// 输入解析错误（结构化；禁止笼统单一错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// JSON 语法错误。
    JsonParse(String),
    /// 根值不是对象。
    NotAnObject { path: String },
    /// 出现明令禁止的敏感字段。
    SensitiveField { path: String, field: String },
    /// 出现未知字段。
    UnknownField { path: String, field: String },
    /// 缺少必填字段。
    MissingField { path: String, field: &'static str },
    /// 字段类型错误。
    WrongType {
        path: String,
        expected: &'static str,
    },
    /// 需要整数但值不是整数（含浮点/指数）。
    NotAnInteger { path: String, value: String },
    /// `u128` 字段不是十进制字符串。
    NotADecimalString { path: String, value: String },
    /// 数值超出目标类型范围。
    OutOfRange {
        path: String,
        value: String,
        max: &'static str,
    },
    /// 十进制字符串非 canonical（前导零等）。
    NonCanonicalDecimal { path: String, value: String },
    /// 占位符 / 空字符串。
    PlaceholderValue { path: String, value: String },
    /// 公钥 hex 非法（长度非 64 或含非小写 hex 字符）。
    InvalidHex { path: String, value: String },
    /// 公钥不是合法 Ed25519 点。
    InvalidPublicKey { path: String },
    /// 地址非法（bech32m 校验失败 / 大小写非 canonical 等）。
    InvalidAddress { path: String, source: String },
    /// 地址网络与 `network_id` 不一致。
    AddressNetworkMismatch {
        path: String,
        expected: u8,
        found: u8,
    },
    /// `network_id` 未注册（合法：0x01/0x02/0x03）。
    InvalidNetworkId { value: String },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonParse(m) => write!(f, "invalid JSON: {m}"),
            Self::NotAnObject { path } => write!(f, "{path}: 根值必须是 JSON 对象"),
            Self::SensitiveField { path, field } => {
                write!(f, "{path}.{field}: 禁止字段（私钥/种子类材料绝不接受）")
            }
            Self::UnknownField { path, field } => {
                write!(
                    f,
                    "{path}.{field}: 未知字段（strict schema：未知字段一律拒绝）"
                )
            }
            Self::MissingField { path, field } => write!(f, "{path}.{field}: 缺少必填字段"),
            Self::WrongType { path, expected } => write!(f, "{path}: 期望 {expected}"),
            Self::NotAnInteger { path, value } => {
                write!(f, "{path}: 期望整数（不接受浮点/指数），实际 `{value}`")
            }
            Self::NotADecimalString { path, value } => write!(
                f,
                "{path}: u128 必须写成十进制字符串（如 \"1000000000\"），实际 `{value}`"
            ),
            Self::OutOfRange { path, value, max } => {
                write!(f, "{path}: 超出范围（{max}），实际 `{value}`")
            }
            Self::NonCanonicalDecimal { path, value } => {
                write!(
                    f,
                    "{path}: 十进制字符串非 canonical（禁止前导零），实际 `{value}`"
                )
            }
            Self::PlaceholderValue { path, value } => {
                write!(f, "{path}: 占位值/空值不被接受（实际 `{value}`）")
            }
            Self::InvalidHex { path, value } => write!(
                f,
                "{path}: 期望 64 位小写 hex，实际 `{value}`（拒绝大写/非 hex 字符）"
            ),
            Self::InvalidPublicKey { path } => {
                write!(f, "{path}: 不是合法 Ed25519 压缩点（曲线校验失败）")
            }
            Self::InvalidAddress { path, source } => write!(f, "{path}: 地址非法：{source}"),
            Self::AddressNetworkMismatch {
                path,
                expected,
                found,
            } => write!(
                f,
                "{path}: 地址网络不匹配（期望 network_id={expected:#04x}，实际 {found:#04x}）"
            ),
            Self::InvalidNetworkId { value } => write!(
                f,
                "network_id: 未注册值 `{value}`（合法：0x01 mainnet / 0x02 testnet / 0x03 devnet）"
            ),
        }
    }
}

impl std::error::Error for InputError {}

/// 解析 `genesis.json` → [`GenesisV1`]（strict）。
pub fn parse_genesis_json(input: &str) -> Result<GenesisV1, InputError> {
    let root: Value =
        serde_json::from_str(input).map_err(|e| InputError::JsonParse(e.to_string()))?;
    let obj = root.as_object().ok_or_else(|| InputError::NotAnObject {
        path: "$".to_string(),
    })?;
    check_fields(obj, "$", &ROOT_FIELDS)?;

    let chain_id = parse_u64(field(obj, "$", "chain_id")?, "$.chain_id")?;
    let net_raw = parse_u64(field(obj, "$", "network_id")?, "$.network_id")?;
    let net_u8 = u8::try_from(net_raw).map_err(|_| InputError::InvalidNetworkId {
        value: net_raw.to_string(),
    })?;
    let network_id = NetworkId::try_from(net_u8).map_err(|_| InputError::InvalidNetworkId {
        value: net_raw.to_string(),
    })?;
    let genesis_timestamp =
        parse_u64(field(obj, "$", "genesis_timestamp")?, "$.genesis_timestamp")?;

    // ---- validators ----
    let varr = as_array(field(obj, "$", "validators")?, "$.validators")?;
    let mut initial_validator_set = Vec::with_capacity(varr.len());
    for (i, item) in varr.iter().enumerate() {
        let path = format!("$.validators[{i}]");
        let o = as_object(item, &path)?;
        check_fields(o, &path, &VALIDATOR_FIELDS)?;

        let addr_path = format!("{path}.account_address");
        let addr_s = as_str(field(o, &path, "account_address")?, &addr_path)?;
        let account_address = parse_address(addr_s, &addr_path, network_id)?;

        let pk_path = format!("{path}.consensus_public_key");
        let pk_s = as_str(field(o, &path, "consensus_public_key")?, &pk_path)?;
        let pk_bytes = parse_pubkey_hex(pk_s, &pk_path)?;
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| InputError::InvalidPublicKey {
            path: pk_path.clone(),
        })?;

        let stake_path = format!("{path}.bonded_stake");
        let bonded_stake = parse_u128_decimal(field(o, &path, "bonded_stake")?, &stake_path)?;

        let comm_path = format!("{path}.commission_bps");
        let comm_raw = parse_u64(field(o, &path, "commission_bps")?, &comm_path)?;
        let commission_bps = u16::try_from(comm_raw).map_err(|_| InputError::OutOfRange {
            path: comm_path.clone(),
            value: comm_raw.to_string(),
            max: "65535",
        })?;

        initial_validator_set.push(ValidatorInit {
            account_address,
            consensus_public_key: pk_bytes,
            bonded_stake,
            commission_bps,
        });
    }

    // ---- accounts ----
    let aarr = as_array(field(obj, "$", "accounts")?, "$.accounts")?;
    let mut initial_accounts = Vec::with_capacity(aarr.len());
    for (i, item) in aarr.iter().enumerate() {
        let path = format!("$.accounts[{i}]");
        let o = as_object(item, &path)?;
        check_fields(o, &path, &ACCOUNT_FIELDS)?;

        let addr_path = format!("{path}.address");
        let addr_s = as_str(field(o, &path, "address")?, &addr_path)?;
        let address = parse_address(addr_s, &addr_path, network_id)?;

        let bal_path = format!("{path}.liquid_balance");
        let liquid_balance = parse_u128_decimal(field(o, &path, "liquid_balance")?, &bal_path)?;

        initial_accounts.push(AccountInit {
            address,
            liquid_balance,
        });
    }

    // ---- protocol_params ----
    let pp_path = "$.protocol_params";
    let ppo = as_object(field(obj, "$", "protocol_params")?, pp_path)?;
    check_fields(ppo, pp_path, &PROTOCOL_PARAM_FIELDS)?;
    let protocol_parameters = ProtocolParamsV1 {
        max_tx_bytes: parse_u32(
            field(ppo, pp_path, "max_tx_bytes")?,
            &sub(pp_path, "max_tx_bytes"),
        )?,
        max_block_bytes: parse_u32(
            field(ppo, pp_path, "max_block_bytes")?,
            &sub(pp_path, "max_block_bytes"),
        )?,
        max_gas_per_block: parse_u64(
            field(ppo, pp_path, "max_gas_per_block")?,
            &sub(pp_path, "max_gas_per_block"),
        )?,
        max_contract_code_bytes: parse_u32(
            field(ppo, pp_path, "max_contract_code_bytes")?,
            &sub(pp_path, "max_contract_code_bytes"),
        )?,
        max_contract_storage_bytes: parse_u32(
            field(ppo, pp_path, "max_contract_storage_bytes")?,
            &sub(pp_path, "max_contract_storage_bytes"),
        )?,
        epoch_length_blocks: parse_u64(
            field(ppo, pp_path, "epoch_length_blocks")?,
            &sub(pp_path, "epoch_length_blocks"),
        )?,
        snapshot_interval_blocks: parse_u64(
            field(ppo, pp_path, "snapshot_interval_blocks")?,
            &sub(pp_path, "snapshot_interval_blocks"),
        )?,
    };

    // ---- economics_params ----
    let ep_path = "$.economics_params";
    let epo = as_object(field(obj, "$", "economics_params")?, ep_path)?;
    check_fields(epo, ep_path, &ECONOMICS_PARAM_FIELDS)?;
    let supply_path = sub(ep_path, "total_supply");
    let total_supply = parse_u128_decimal(field(epo, ep_path, "total_supply")?, &supply_path)?;
    let min_path = sub(ep_path, "min_validator_stake");
    let min_validator_stake =
        parse_u128_decimal(field(epo, ep_path, "min_validator_stake")?, &min_path)?;
    let unbond_path = sub(ep_path, "unbonding_period_seconds");
    let unbonding_period_seconds = parse_u64(
        field(epo, ep_path, "unbonding_period_seconds")?,
        &unbond_path,
    )?;
    let burn_path = sub(ep_path, "fee_burn_bps");
    let burn_raw = parse_u64(field(epo, ep_path, "fee_burn_bps")?, &burn_path)?;
    let fee_burn_bps = u16::try_from(burn_raw).map_err(|_| InputError::OutOfRange {
        path: burn_path.clone(),
        value: burn_raw.to_string(),
        max: "65535",
    })?;

    Ok(GenesisV1 {
        network_id,
        chain_id,
        genesis_timestamp,
        initial_validator_set,
        initial_accounts,
        protocol_parameters,
        economics_parameters: EconomicsParamsV1 {
            total_supply,
            min_validator_stake,
            unbonding_period_seconds,
            fee_burn_bps,
        },
    })
}

// =========================================================================
// 内部工具
// =========================================================================

fn sub(parent: &str, child: &str) -> String {
    format!("{parent}.{child}")
}

/// 未知字段 / 敏感字段检测（等价 `deny_unknown_fields`）。
///
/// `serde_json::Map` 默认按键有序（`BTreeMap`）⇒ 同一输入的报错稳定可复现。
fn check_fields(obj: &Map<String, Value>, path: &str, allowed: &[&str]) -> Result<(), InputError> {
    for key in obj.keys() {
        if SENSITIVE_FIELDS.contains(&key.as_str()) {
            return Err(InputError::SensitiveField {
                path: path.to_string(),
                field: key.clone(),
            });
        }
        if !allowed.contains(&key.as_str()) {
            return Err(InputError::UnknownField {
                path: path.to_string(),
                field: key.clone(),
            });
        }
    }
    Ok(())
}

fn field<'a>(
    obj: &'a Map<String, Value>,
    path: &str,
    name: &'static str,
) -> Result<&'a Value, InputError> {
    obj.get(name).ok_or_else(|| InputError::MissingField {
        path: path.to_string(),
        field: name,
    })
}

fn as_object<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>, InputError> {
    v.as_object().ok_or_else(|| InputError::WrongType {
        path: path.to_string(),
        expected: "JSON 对象",
    })
}

fn as_array<'a>(v: &'a Value, path: &str) -> Result<&'a Vec<Value>, InputError> {
    v.as_array().ok_or_else(|| InputError::WrongType {
        path: path.to_string(),
        expected: "JSON 数组",
    })
}

fn as_str<'a>(v: &'a Value, path: &str) -> Result<&'a str, InputError> {
    v.as_str().ok_or_else(|| InputError::WrongType {
        path: path.to_string(),
        expected: "字符串",
    })
}

/// 拒绝空字符串 / `TBD` / `PENDING` 占位值。
fn reject_placeholder(s: &str, path: &str) -> Result<(), InputError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(InputError::PlaceholderValue {
            path: path.to_string(),
            value: "<empty>".to_string(),
        });
    }
    let upper = trimmed.to_ascii_uppercase();
    if PLACEHOLDERS.contains(&upper.as_str()) {
        return Err(InputError::PlaceholderValue {
            path: path.to_string(),
            value: s.to_string(),
        });
    }
    Ok(())
}

/// 整数解析：接受 JSON 整数或十进制字符串；**拒绝浮点 / 指数 / 负数**。
fn parse_u64(v: &Value, path: &str) -> Result<u64, InputError> {
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(|| InputError::NotAnInteger {
            path: path.to_string(),
            value: n.to_string(),
        }),
        Value::String(s) => {
            let t = s.trim();
            reject_placeholder(t, path)?;
            if !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InputError::NotAnInteger {
                    path: path.to_string(),
                    value: s.clone(),
                });
            }
            if t.len() > 1 && t.starts_with('0') {
                return Err(InputError::NonCanonicalDecimal {
                    path: path.to_string(),
                    value: t.to_string(),
                });
            }
            t.parse::<u64>().map_err(|_| InputError::OutOfRange {
                path: path.to_string(),
                value: t.to_string(),
                max: "18446744073709551615",
            })
        }
        other => Err(InputError::NotAnInteger {
            path: path.to_string(),
            value: other.to_string(),
        }),
    }
}

fn parse_u32(v: &Value, path: &str) -> Result<u32, InputError> {
    let raw = parse_u64(v, path)?;
    u32::try_from(raw).map_err(|_| InputError::OutOfRange {
        path: path.to_string(),
        value: raw.to_string(),
        max: "4294967295",
    })
}

/// `u128`：**只接受十进制字符串**（拒绝 JSON 数字 / 浮点 / 指数 / 前导零 / 符号）。
fn parse_u128_decimal(v: &Value, path: &str) -> Result<u128, InputError> {
    match v {
        Value::String(s) => {
            let t = s.trim();
            reject_placeholder(t, path)?;
            if !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InputError::NotADecimalString {
                    path: path.to_string(),
                    value: s.clone(),
                });
            }
            parse_canonical_digits(t, path)
        }
        other => Err(InputError::NotADecimalString {
            path: path.to_string(),
            value: other.to_string(),
        }),
    }
}

/// 十进制字符串解析 + canonical（禁止前导零）+ 范围检查。
fn parse_canonical_digits(t: &str, path: &str) -> Result<u128, InputError> {
    if t.len() > 1 && t.starts_with('0') {
        return Err(InputError::NonCanonicalDecimal {
            path: path.to_string(),
            value: t.to_string(),
        });
    }
    t.parse::<u128>().map_err(|_| InputError::OutOfRange {
        path: path.to_string(),
        value: t.to_string(),
        max: "u128::MAX",
    })
}

/// 公钥 hex：64 位小写 hex（拒绝大写、非 hex 字符）。
fn parse_pubkey_hex(s: &str, path: &str) -> Result<[u8; 32], InputError> {
    reject_placeholder(s, path)?;
    parse_hex32(s).ok_or_else(|| InputError::InvalidHex {
        path: path.to_string(),
        value: s.to_string(),
    })
}

/// 地址：bech32m 解码（委托 `nova-crypto`）+ 网络一致性。
fn parse_address(s: &str, path: &str, network: NetworkId) -> Result<YazimaoAddress, InputError> {
    reject_placeholder(s, path)?;
    let addr = YazimaoAddress::decode(s).map_err(|e| InputError::InvalidAddress {
        path: path.to_string(),
        source: e.to_string(),
    })?;
    let found = addr.payload().network_id.as_u8();
    let expected = network.as_u8();
    if found != expected {
        return Err(InputError::AddressNetworkMismatch {
            path: path.to_string(),
            expected,
            found,
        });
    }
    Ok(addr)
}
