//! Genesis 向量校验（STEP 6 schema 冻结，ADR-0014/0015/0016）。
//!
//! 本 loader 做 **schema 层**校验（嵌套类型 / 注册表 / 重复 / 排序 / 基本范围 / stake
//! accounting / supply invariant），**不实现** canonical 编码或 `genesis_hash` 计算
//! （DEFERRED：STEP 6 IMPLEMENTATION 后由 `nova_crypto::identity` 实现并回填向量）。
//!
//! 不允许本模块自行重新设计 Genesis 编码（genesis-v1.md §18 纪律）。

use crate::hex;
use crate::json;
use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::hash::protocol_hash;
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisError, GenesisV1, ProtocolParamsV1, ValidatorInit,
};
use nova_crypto::signature::VerifyingKey;
use serde_json::Value;

/// V0.1 资源上限（ADR-0014）。
const MAX_VALIDATORS: usize = 10_000;
const MAX_ACCOUNTS: usize = 1_000_000;
const MAX_TX_BYTES: u32 = 1_048_576;
const MAX_BLOCK_BYTES: u32 = 8_388_608;
const MAX_GAS_PER_BLOCK: u64 = 100_000_000_000;
const MAX_CONTRACT_CODE_BYTES: u32 = 524_288;
const MAX_CONTRACT_STORAGE_BYTES: u32 = 16_777_216;
const MAX_EPOCH_LENGTH: u64 = 1_000_000;
const MAX_SNAPSHOT_INTERVAL: u64 = 10_000_000;
const MAX_COMMISSION_BPS: u16 = 10_000;
const MAX_FEE_BURN_BPS: u16 = 10_000;

/// Genesis 向量校验结果。
#[derive(Debug, Clone)]
pub struct GenesisValidation {
    /// 向量 id。
    pub id: String,
    /// 整体是否通过（schema + canonical/hash 与期望一致）。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// 首个错误分类名（与向量 `expected_error` 对应）。
    pub error_name: Option<String>,
}

struct ErrCtx {
    errors: Vec<String>,
    first: Option<String>,
}

/// 解析后的 validator 条目（用于唯一性 / 排序 / stake accounting）。
struct ValEntry {
    validator_id: [u8; 32],
    pubkey: Vec<u8>,
    account_addr: String,
    bonded_stake: u128,
}

impl ErrCtx {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            first: None,
        }
    }
    /// 记录错误；`name` 为 GenesisError 分类名（仅记录首个）。
    fn push(&mut self, name: &str, msg: impl Into<String>) {
        if self.first.is_none() {
            self.first = Some(name.to_string());
        }
        self.errors.push(format!("[{name}] {}", msg.into()));
    }
    fn has(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// 校验单个 genesis 向量 JSON（schema 层）。
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
    let mut ec = ErrCtx::new();

    // ---- 顶层字段存在性 ----
    for key in [
        "network_id",
        "chain_id",
        "genesis_timestamp",
        "initial_validator_set",
        "initial_accounts",
        "protocol_parameters",
        "economics_parameters",
        "expected_genesis_hash",
    ] {
        if value.get(key).is_none() {
            ec.push("Structural", format!("missing genesis field: {key}"));
        }
    }
    if ec.has() {
        return finish(&id, ec);
    }

    // ---- network validation（ADR-0011）----
    let net_id = get_u8(&value, "network_id").unwrap_or(0);
    let genesis_net = match NetworkId::try_from(net_id) {
        Ok(n) => n,
        Err(_) => {
            ec.push("InvalidNetwork", format!("network_id {net_id:#04x} 未注册"));
            return finish(&id, ec);
        }
    };

    // ---- chain_id validation ----
    let chain_id = value["chain_id"].as_u64().unwrap_or(0);
    if chain_id == 0 {
        ec.push("InvalidChainId", "chain_id=0 非法（须 > 0）");
    }

    // ---- timestamp validation ----
    let ts = value["genesis_timestamp"].as_u64().unwrap_or(0);
    if ts == 0 {
        ec.push("InvalidTimestamp", "genesis_timestamp=0 非法（须 > 0）");
    }

    // ---- validator / account 集合 ----
    let val_arr = value["initial_validator_set"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let acc_arr = value["initial_accounts"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if val_arr.is_empty() {
        ec.push(
            "InvalidValidator",
            "initial_validator_set 必须非空（PoS 无验证者无法运行）",
        );
    } else if val_arr.len() > MAX_VALIDATORS {
        ec.push(
            "InvalidValidator",
            format!("validator 数量 {} > 上限 {MAX_VALIDATORS}", val_arr.len()),
        );
    }
    if acc_arr.is_empty() {
        ec.push(
            "InvalidInitialState",
            "initial_accounts 必须非空（至少 1 账户）",
        );
    } else if acc_arr.len() > MAX_ACCOUNTS {
        ec.push(
            "InvalidInitialState",
            format!("account 数量 {} > 上限 {MAX_ACCOUNTS}", acc_arr.len()),
        );
    }

    // ---- validator 条目 ----
    let mut vals: Vec<ValEntry> = Vec::new();
    for (i, item) in val_arr.iter().enumerate() {
        let tag = format!("validator[{i}]");
        // account_address
        let Some(addr_s) = item.get("account_address").and_then(Value::as_str) else {
            ec.push(
                "InvalidValidator",
                format!("{tag} account_address 缺失/非字符串"),
            );
            continue;
        };
        let (_abytes, vnet) = match decode_addr(addr_s) {
            Some(x) => x,
            None => {
                ec.push(
                    "InvalidValidator",
                    format!("{tag} account_address 解码失败"),
                );
                continue;
            }
        };
        if vnet != genesis_net {
            ec.push(
                "InvalidValidator",
                format!("{tag} 地址网络与 Genesis network_id 不一致"),
            );
        }
        // consensus_public_key
        let pk = match item.get("consensus_public_key").and_then(Value::as_str) {
            Some(h) => match hex::decode_strict_lower_hex(h) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    ec.push(
                        "InvalidValidator",
                        format!("{tag} consensus_public_key 非 32B 严格小写 hex"),
                    );
                    continue;
                }
            },
            None => {
                ec.push(
                    "InvalidValidator",
                    format!("{tag} consensus_public_key 缺失"),
                );
                continue;
            }
        };
        if VerifyingKey::from_bytes(&pk).is_err() {
            ec.push(
                "InvalidValidator",
                format!("{tag} consensus_public_key 非法 Ed25519 压缩点"),
            );
        }
        // bonded_stake
        let stake = match value_u128(item.get("bonded_stake")) {
            Some(s) => s,
            None => {
                ec.push("InvalidValidator", format!("{tag} bonded_stake 非法 u128"));
                continue;
            }
        };
        if stake == 0 {
            ec.push(
                "InvalidValidator",
                format!("{tag} bonded_stake=0 非法（须 > 0）"),
            );
        }
        // commission_bps
        let comm = match item.get("commission_bps").and_then(Value::as_u64) {
            Some(c) if c <= u64::from(u16::MAX) => c as u16,
            _ => {
                ec.push("InvalidValidator", format!("{tag} commission_bps 非法 u16"));
                continue;
            }
        };
        if comm > MAX_COMMISSION_BPS {
            ec.push(
                "InvalidValidator",
                format!("{tag} commission_bps {comm} > {MAX_COMMISSION_BPS}"),
            );
        }
        let vid = protocol_hash(&pk);
        vals.push(ValEntry {
            validator_id: vid,
            pubkey: pk,
            account_addr: addr_s.to_string(),
            bonded_stake: stake,
        });
    }

    // ---- account 条目 ----
    // (address_payload_bytes, address_str, liquid)
    let mut accs: Vec<(Vec<u8>, String, u128)> = Vec::new();
    for (i, item) in acc_arr.iter().enumerate() {
        let tag = format!("account[{i}]");
        let Some(addr_s) = item.get("address").and_then(Value::as_str) else {
            ec.push(
                "InvalidInitialState",
                format!("{tag} address 缺失/非字符串"),
            );
            continue;
        };
        let (abytes, vnet) = match decode_addr(addr_s) {
            Some(x) => x,
            None => {
                ec.push("InvalidInitialState", format!("{tag} address 解码失败"));
                continue;
            }
        };
        if vnet != genesis_net {
            ec.push(
                "InvalidInitialState",
                format!("{tag} 地址网络与 Genesis network_id 不一致"),
            );
        }
        let Some(liq) = value_u128(item.get("liquid_balance")) else {
            ec.push(
                "InvalidInitialState",
                format!("{tag} liquid_balance 非法 u128"),
            );
            continue;
        };
        accs.push((abytes, addr_s.to_string(), liq));
    }

    // ---- 重复检测 ----
    // validator：account_address / consensus_public_key / validator_id
    for (i, a) in vals.iter().enumerate() {
        for b in vals.iter().skip(i + 1) {
            if a.account_addr == b.account_addr {
                ec.push(
                    "DuplicateValidator",
                    format!("validator account_address 重复：{}", a.account_addr),
                );
            }
            if a.pubkey == b.pubkey {
                ec.push("DuplicateValidator", "validator consensus_public_key 重复");
            }
            if a.validator_id == b.validator_id {
                ec.push("DuplicateValidator", "validator_id 重复");
            }
        }
    }
    // account：address
    for (i, a) in accs.iter().enumerate() {
        for b in accs.iter().skip(i + 1) {
            if a.1 == b.1 {
                ec.push("DuplicateAccount", format!("account address 重复：{}", a.1));
            }
        }
    }

    // ---- canonical ordering（ADR-0015）----
    for w in vals.windows(2) {
        if w[0].validator_id >= w[1].validator_id {
            ec.push("NonCanonicalOrdering", "validator 列表非 validator_id 升序");
            break;
        }
    }
    for w in accs.windows(2) {
        if w[0].0 >= w[1].0 {
            ec.push(
                "NonCanonicalOrdering",
                "account 列表非 address payload bytes 升序",
            );
            break;
        }
    }

    // ---- stake accounting（ADR-0016）----
    for v in &vals {
        // validator 账户必须存在于 initial_accounts 且 bonded_stake <= liquid
        let liquid = accs.iter().find(|a| a.1 == v.account_addr).map(|a| a.2);
        match liquid {
            None => ec.push(
                "InvalidStake",
                format!("validator 账户 {} 不在 initial_accounts", v.account_addr),
            ),
            Some(liq) if v.bonded_stake > liq => {
                ec.push(
                    "InvalidStake",
                    format!("bonded_stake {} > 对应账户 liquid {liq}", v.bonded_stake),
                );
            }
            _ => {}
        }
    }

    // ---- protocol parameters ----
    let pp = &value["protocol_parameters"];
    check_protocol(pp, &mut ec);

    // ---- economics parameters ----
    let ep = &value["economics_parameters"];
    let total_supply = check_economics(ep, &mut ec);

    // ---- supply invariant（ADR-0016）----
    if let Some(total) = total_supply {
        let mut sum: u128 = 0;
        let mut overflow = false;
        for (_b, _s, liq) in &accs {
            match sum.checked_add(*liq) {
                Some(s) => sum = s,
                None => {
                    overflow = true;
                    break;
                }
            }
        }
        if overflow {
            ec.push(
                "SupplyInvariantViolation",
                "Σ liquid_balance 溢出（checked）",
            );
        } else if sum != total {
            ec.push(
                "SupplyInvariantViolation",
                format!("total_supply {total} != Σ liquid {sum}"),
            );
        }
    }

    // ---- canonical 层（STEP 6A）：构造 GenesisV1 + 计算 hash + 对比 ----
    if ec.has() {
        return finish(&id, ec);
    }
    match genesis_from_json(input) {
        Ok(g) => match nova_crypto::identity::compute_genesis_hash(&g) {
            Ok(computed) => {
                let expected = value
                    .get("expected_genesis_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !expected.is_empty() && expected != hex::encode_lower_hex(&computed) {
                    ec.push(
                        "GenesisHashMismatch",
                        format!(
                            "computed {} != configured {expected}",
                            hex::encode_lower_hex(&computed)
                        ),
                    );
                }
            }
            Err(e) => {
                ec.push(
                    genesis_error_name(&e),
                    format!("canonical encoding rejected: {e}"),
                );
            }
        },
        Err(e) => ec.push("Structural", format!("genesis_from_json: {e}")),
    }

    finish(&id, ec)
}

/// 组装结果（hash 计算已实现，不再 DEFERRED）。
fn finish(id: &str, ec: ErrCtx) -> GenesisValidation {
    GenesisValidation {
        id: id.to_string(),
        ok: !ec.has(),
        errors: ec.errors,
        error_name: ec.first,
    }
}

fn decode_addr(s: &str) -> Option<(Vec<u8>, NetworkId)> {
    let addr = NovaAddress::decode(s).ok()?;
    let p = addr.payload();
    let mut b = vec![p.address_version, p.address_type as u8, p.network_id as u8];
    b.extend_from_slice(&p.key_hash);
    Some((b, p.network_id))
}

fn value_u128(v: Option<&Value>) -> Option<u128> {
    match v {
        Some(Value::String(s)) => s.parse::<u128>().ok(),
        Some(Value::Number(n)) => n.as_u64().map(u128::from),
        _ => None,
    }
}

fn check_protocol(pp: &Value, ec: &mut ErrCtx) {
    let get = |k: &str| pp.get(k).and_then(Value::as_u64);
    let mt = get("max_tx_bytes").unwrap_or(0) as u32;
    let mb = get("max_block_bytes").unwrap_or(0) as u32;
    let gas = get("max_gas_per_block").unwrap_or(0);
    let code = get("max_contract_code_bytes").unwrap_or(0) as u32;
    let stg = get("max_contract_storage_bytes").unwrap_or(0) as u32;
    let epoch = get("epoch_length_blocks").unwrap_or(0);
    let snap = get("snapshot_interval_blocks").unwrap_or(0);
    if mt == 0 {
        ec.push("InvalidProtocolParams", "max_tx_bytes 必须 > 0");
    } else if mt > MAX_TX_BYTES {
        ec.push(
            "InvalidProtocolParams",
            format!("max_tx_bytes {mt} > 上限 {MAX_TX_BYTES}"),
        );
    }
    if mb < mt {
        ec.push(
            "InvalidProtocolParams",
            format!("max_block_bytes {mb} < max_tx_bytes {mt}"),
        );
    } else if mb > MAX_BLOCK_BYTES {
        ec.push(
            "InvalidProtocolParams",
            format!("max_block_bytes {mb} > 上限 {MAX_BLOCK_BYTES}"),
        );
    }
    if gas == 0 {
        ec.push("InvalidProtocolParams", "max_gas_per_block 必须 > 0");
    } else if gas > MAX_GAS_PER_BLOCK {
        ec.push(
            "InvalidProtocolParams",
            format!("max_gas_per_block {gas} > 上限 {MAX_GAS_PER_BLOCK}"),
        );
    }
    if code == 0 {
        ec.push("InvalidProtocolParams", "max_contract_code_bytes 必须 > 0");
    } else if code > MAX_CONTRACT_CODE_BYTES {
        ec.push(
            "InvalidProtocolParams",
            format!("max_contract_code_bytes {code} > 上限 {MAX_CONTRACT_CODE_BYTES}"),
        );
    }
    if stg == 0 {
        ec.push(
            "InvalidProtocolParams",
            "max_contract_storage_bytes 必须 > 0",
        );
    } else if stg > MAX_CONTRACT_STORAGE_BYTES {
        ec.push(
            "InvalidProtocolParams",
            format!("max_contract_storage_bytes {stg} > 上限 {MAX_CONTRACT_STORAGE_BYTES}"),
        );
    }
    if epoch == 0 {
        ec.push("InvalidProtocolParams", "epoch_length_blocks 必须 > 0");
    } else if epoch > MAX_EPOCH_LENGTH {
        ec.push(
            "InvalidProtocolParams",
            format!("epoch_length_blocks {epoch} > 上限 {MAX_EPOCH_LENGTH}"),
        );
    }
    if snap == 0 {
        ec.push("InvalidProtocolParams", "snapshot_interval_blocks 必须 > 0");
    } else if snap > MAX_SNAPSHOT_INTERVAL {
        ec.push(
            "InvalidProtocolParams",
            format!("snapshot_interval_blocks {snap} > 上限 {MAX_SNAPSHOT_INTERVAL}"),
        );
    }
}

fn check_economics(ep: &Value, ec: &mut ErrCtx) -> Option<u128> {
    let total = value_u128(ep.get("total_supply"));
    let min_stake = value_u128(ep.get("min_validator_stake"));
    let unbond = ep
        .get("unbonding_period_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let burn = ep.get("fee_burn_bps").and_then(Value::as_u64).unwrap_or(0) as u16;
    match total {
        Some(t) if t > 0 => {}
        _ => ec.push("InvalidEconomicsParams", "total_supply 必须 > 0"),
    }
    match min_stake {
        Some(m) if m > 0 => {}
        _ => ec.push("InvalidEconomicsParams", "min_validator_stake 必须 > 0"),
    }
    if unbond == 0 {
        ec.push(
            "InvalidEconomicsParams",
            "unbonding_period_seconds 必须 > 0",
        );
    }
    if burn > MAX_FEE_BURN_BPS {
        ec.push(
            "InvalidEconomicsParams",
            format!("fee_burn_bps {burn} > {MAX_FEE_BURN_BPS}"),
        );
    }
    total
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
