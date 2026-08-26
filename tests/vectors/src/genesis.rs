//! Genesis 向量校验（STEP 6B，ADR-0014/0015/0016）。
//!
//! loader 解析 JSON → 构造 `GenesisV1`（`genesis_from_json`），然后**委托生产实现**
//! `nova_crypto::identity::validate_genesis` 做完整 semantic/canonical 校验（含地址/公钥/
//! 排序/重复/stake/supply/protocol/economics），并对比回填的 `expected_genesis_hash`。
//! **不自行重新实现 Genesis 编码/校验**（genesis-v1.md §18 纪律）。

use crate::hex;
use crate::json;
use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisError, GenesisV1, ProtocolParamsV1, ValidatorInit,
};
use serde_json::Value;

/// Genesis 向量校验结果。
#[derive(Debug, Clone)]
pub struct GenesisValidation {
    /// 向量 id。
    pub id: String,
    /// 整体是否通过（validate_genesis + hash 与期望一致）。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// 首个错误分类名（与向量 `expected_error` 对应）。
    pub error_name: Option<String>,
}

/// 校验单个 genesis 向量 JSON：构造 GenesisV1 → `validate_genesis` → hash 对比。
pub fn validate_genesis_vector(input: &str) -> GenesisValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return GenesisValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                error_name: None,
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();

    // network_id 注册（genesis_from_json 构造需要 NetworkId；未注册 ⇒ InvalidNetwork）。
    if let Some(n) = get_u8(&value, "network_id")
        && NetworkId::try_from(n).is_err()
    {
        return invalid(&id, "InvalidNetwork", format!("network_id {n:#04x} 未注册"));
    }

    // 构造 GenesisV1（解析失败 ⇒ Structural）。
    let g = match genesis_from_json(input) {
        Ok(g) => g,
        Err(e) => return invalid(&id, "Structural", format!("genesis_from_json: {e}")),
    };

    // 完整校验：canonical + semantic（委托生产实现）。
    match nova_crypto::identity::validate_genesis(&g) {
        Err(e) => {
            let name = genesis_error_name(&e);
            invalid(&id, name, format!("{e}"))
        }
        Ok(ci) => {
            // configured genesis_hash 对比（若提供）。
            let expected = get_str(&value, "expected_genesis_hash").unwrap_or_default();
            if expected.is_empty() {
                GenesisValidation {
                    id,
                    ok: true,
                    errors: Vec::new(),
                    error_name: None,
                }
            } else {
                match decode_hash_hex(expected) {
                    Some(exp) if exp == ci.genesis_hash => GenesisValidation {
                        id,
                        ok: true,
                        errors: Vec::new(),
                        error_name: None,
                    },
                    _ => invalid(
                        &id,
                        "GenesisHashMismatch",
                        format!(
                            "computed {} != configured {expected}",
                            hex::encode_lower_hex(&ci.genesis_hash)
                        ),
                    ),
                }
            }
        }
    }
}

fn invalid(id: &str, name: &str, msg: impl Into<String>) -> GenesisValidation {
    GenesisValidation {
        id: id.to_string(),
        ok: false,
        errors: vec![format!("[{name}] {}", msg.into())],
        error_name: Some(name.to_string()),
    }
}

/// 解析 32B 严格小写 hex 为 `[u8; 32]`。
fn decode_hash_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let b = hex::decode_strict_lower_hex(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

fn value_u128(v: Option<&Value>) -> Option<u128> {
    match v {
        Some(Value::String(s)) => s.parse::<u128>().ok(),
        Some(Value::Number(n)) => n.as_u64().map(u128::from),
        _ => None,
    }
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn get_u8(v: &Value, key: &str) -> Option<u8> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u8::try_from(n).ok())
}

/// 将 `GenesisError` 映射为规范错误名（与向量 `expected_error` 一致）。
pub fn genesis_error_name(e: &GenesisError) -> &'static str {
    match e {
        GenesisError::InvalidNetwork => "InvalidNetwork",
        GenesisError::InvalidChainId => "InvalidChainId",
        GenesisError::InvalidTimestamp => "InvalidTimestamp",
        GenesisError::InvalidValidator => "InvalidValidator",
        GenesisError::DuplicateValidator => "DuplicateValidator",
        GenesisError::DuplicateAccount => "DuplicateAccount",
        GenesisError::InvalidStake => "InvalidStake",
        GenesisError::InvalidInitialState => "InvalidInitialState",
        GenesisError::InvalidProtocolParams => "InvalidProtocolParams",
        GenesisError::InvalidEconomicsParams => "InvalidEconomicsParams",
        GenesisError::NonCanonicalOrdering => "NonCanonicalOrdering",
        GenesisError::NonCanonicalEncoding => "NonCanonicalEncoding",
        GenesisError::GenesisHashMismatch => "GenesisHashMismatch",
        GenesisError::SupplyInvariantViolation => "SupplyInvariantViolation",
        GenesisError::InvalidAddress => "InvalidAddress",
        GenesisError::InvalidPublicKey => "InvalidPublicKey",
        GenesisError::EncodingOverflow => "EncodingOverflow",
        GenesisError::CollectionTooLarge => "CollectionTooLarge",
        GenesisError::DecodeError => "DecodeError",
        GenesisError::TrailingBytes => "TrailingBytes",
        GenesisError::StakeExceedsBalance => "StakeExceedsBalance",
        GenesisError::SupplyOverflow => "SupplyOverflow",
    }
}

/// 从 JSON 向量构造 `GenesisV1`（仅解析；语义校验由 loader 负责）。
///
/// 供 loader（STEP 6A canonical 层）与回填生成器复用，确保测试**真正调用** `nova_crypto::identity`。
pub fn genesis_from_json(input: &str) -> Result<GenesisV1, String> {
    let value = json::parse(input).map_err(|e| format!("parse: {e}"))?;
    let net = value["network_id"].as_u64().ok_or("network_id")? as u8;
    let network_id = nova_crypto::address::NetworkId::try_from(net)
        .map_err(|_| format!("invalid network_id {net:#04x}"))?;
    let chain_id = value["chain_id"].as_u64().ok_or("chain_id")?;
    let genesis_timestamp = value["genesis_timestamp"]
        .as_u64()
        .ok_or("genesis_timestamp")?;

    let mut initial_validator_set = Vec::new();
    let varr = value["initial_validator_set"]
        .as_array()
        .ok_or("initial_validator_set")?;
    for (i, item) in varr.iter().enumerate() {
        let tag = format!("validator[{i}]");
        let addr_s = item
            .get("account_address")
            .and_then(Value::as_str)
            .ok_or(format!("{tag} account_address"))?;
        let account_address =
            NovaAddress::decode(addr_s).map_err(|_| format!("{tag} address decode"))?;
        let pk_hex = item
            .get("consensus_public_key")
            .and_then(Value::as_str)
            .ok_or(format!("{tag} consensus_public_key"))?;
        let pk = hex::decode_strict_lower_hex(pk_hex).map_err(|_| format!("{tag} pubkey hex"))?;
        let mut consensus_public_key = [0u8; 32];
        if pk.len() != 32 {
            return Err(format!("{tag} pubkey not 32B"));
        }
        consensus_public_key.copy_from_slice(&pk);
        let bonded_stake =
            value_u128(item.get("bonded_stake")).ok_or(format!("{tag} bonded_stake"))?;
        let commission_bps = item["commission_bps"]
            .as_u64()
            .ok_or(format!("{tag} commission_bps"))? as u16;
        initial_validator_set.push(ValidatorInit {
            account_address,
            consensus_public_key,
            bonded_stake,
            commission_bps,
        });
    }

    let mut initial_accounts = Vec::new();
    let aarr = value["initial_accounts"]
        .as_array()
        .ok_or("initial_accounts")?;
    for (i, item) in aarr.iter().enumerate() {
        let tag = format!("account[{i}]");
        let addr_s = item
            .get("address")
            .and_then(Value::as_str)
            .ok_or(format!("{tag} address"))?;
        let address = NovaAddress::decode(addr_s).map_err(|_| format!("{tag} address decode"))?;
        let liquid_balance =
            value_u128(item.get("liquid_balance")).ok_or(format!("{tag} liquid_balance"))?;
        initial_accounts.push(AccountInit {
            address,
            liquid_balance,
        });
    }

    let pp = &value["protocol_parameters"];
    let protocol_parameters = ProtocolParamsV1 {
        max_tx_bytes: pp["max_tx_bytes"].as_u64().ok_or("max_tx_bytes")? as u32,
        max_block_bytes: pp["max_block_bytes"].as_u64().ok_or("max_block_bytes")? as u32,
        max_gas_per_block: pp["max_gas_per_block"]
            .as_u64()
            .ok_or("max_gas_per_block")?,
        max_contract_code_bytes: pp["max_contract_code_bytes"]
            .as_u64()
            .ok_or("max_contract_code_bytes")? as u32,
        max_contract_storage_bytes: pp["max_contract_storage_bytes"]
            .as_u64()
            .ok_or("max_contract_storage_bytes")? as u32,
        epoch_length_blocks: pp["epoch_length_blocks"]
            .as_u64()
            .ok_or("epoch_length_blocks")?,
        snapshot_interval_blocks: pp["snapshot_interval_blocks"]
            .as_u64()
            .ok_or("snapshot_interval_blocks")?,
    };

    let ep = &value["economics_parameters"];
    let economics_parameters = EconomicsParamsV1 {
        total_supply: value_u128(ep.get("total_supply")).ok_or("total_supply")?,
        min_validator_stake: value_u128(ep.get("min_validator_stake"))
            .ok_or("min_validator_stake")?,
        unbonding_period_seconds: ep["unbonding_period_seconds"]
            .as_u64()
            .ok_or("unbonding_period_seconds")?,
        fee_burn_bps: ep["fee_burn_bps"].as_u64().ok_or("fee_burn_bps")? as u16,
    };

    Ok(GenesisV1 {
        network_id,
        chain_id,
        genesis_timestamp,
        initial_validator_set,
        initial_accounts,
        protocol_parameters,
        economics_parameters,
    })
}

/// 从任意 bytes 构造 `GenesisV1`（fuzz 共享解析器；bounded、no-panic、确定性）。
///
/// - 输入不足 / 非法 network ⇒ `None`（不 panic）。
/// - 条目数由输入限制（≤ 8 条），避免 unbounded allocation。
/// - 供 `fuzz/genesis_canonicalize` 与 stable fuzz-like 测试复用（单一来源）。
pub fn genesis_from_bytes(data: &[u8]) -> Option<GenesisV1> {
    if data.len() < 3 {
        return None;
    }
    let mut pos = 0;
    let net_id = data[pos] % 4;
    pos += 1;
    let network_id = NetworkId::try_from(net_id).ok()?;
    let n_val = (data[pos] % 8) as usize;
    pos += 1;
    let n_acc = (data[pos] % 8) as usize;
    pos += 1;

    // 总字节需求（含 chain_id 8B）。
    let need = n_val * (32 + 32 + 16 + 2) + n_acc * (32 + 16) + 8;
    if data.len() < pos + need {
        return None;
    }

    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        if data.len() < *pos + n {
            return None;
        }
        let s = &data[*pos..*pos + n];
        *pos += n;
        Some(s)
    };

    let mut initial_validator_set = Vec::with_capacity(n_val);
    for _ in 0..n_val {
        let kh: [u8; 32] = take(&mut pos, 32)?.try_into().ok()?;
        let pk: [u8; 32] = take(&mut pos, 32)?.try_into().ok()?;
        let stake = u128::from_le_bytes(take(&mut pos, 16)?.try_into().ok()?);
        let comm = u16::from_le_bytes(take(&mut pos, 2)?.try_into().ok()?);
        initial_validator_set.push(ValidatorInit {
            account_address: NovaAddress::from_payload(NovaAddressPayload {
                address_version: 1,
                address_type: AddressType::UserAccount,
                network_id,
                key_hash: kh,
            }),
            consensus_public_key: pk,
            bonded_stake: stake,
            commission_bps: comm,
        });
    }

    let mut initial_accounts = Vec::with_capacity(n_acc);
    for _ in 0..n_acc {
        let kh: [u8; 32] = take(&mut pos, 32)?.try_into().ok()?;
        let liq = u128::from_le_bytes(take(&mut pos, 16)?.try_into().ok()?);
        initial_accounts.push(AccountInit {
            address: NovaAddress::from_payload(NovaAddressPayload {
                address_version: 1,
                address_type: AddressType::UserAccount,
                network_id,
                key_hash: kh,
            }),
            liquid_balance: liq,
        });
    }

    let chain_id = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    Some(GenesisV1 {
        network_id,
        chain_id,
        genesis_timestamp: 1,
        initial_validator_set,
        initial_accounts,
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 65_536,
            max_block_bytes: 1_048_576,
            max_gas_per_block: 1_000_000_000,
            max_contract_code_bytes: 32_768,
            max_contract_storage_bytes: 1_048_576,
            epoch_length_blocks: 100,
            snapshot_interval_blocks: 1_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: 6_500_000,
            min_validator_stake: 100_000,
            unbonding_period_seconds: 1_209_600,
            fee_burn_bps: 500,
        },
    })
}
