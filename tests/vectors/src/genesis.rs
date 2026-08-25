//! Genesis 向量校验（STEP 1 仅 schema，**不实现 genesis canonical encoding**）。
//!
//! genesis-v1.md：canonical Genesis 子结构（ValidatorInit/AccountInit/ProtocolParams/
//! EconomicsParams）在对应 Phase 定稿。本阶段只校验 fixture 的 7 个顶层字段存在与类型；
//! `genesis_hash` 的实际计算标记为 `DEFERRED_VALIDATION`（PHASE 7 canonical 定稿后启用重算）。
//!
//! 不允许本模块自行重新设计 Genesis 编码（genesis-v1.md §5 纪律）。

use crate::json;
use serde_json::Value;

/// Genesis 向量校验结果。
#[derive(Debug, Clone)]
pub struct GenesisValidation {
    /// 向量 id。
    pub id: String,
    /// schema 是否通过。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// genesis_hash 计算是否延迟（本阶段恒为 true）。
    pub hash_deferred: bool,
}

/// 校验单个 genesis 向量 JSON。
pub fn validate_genesis_vector(input: &str) -> GenesisValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return GenesisValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                hash_deferred: true,
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();

    let mut errors: Vec<String> = Vec::new();

    // genesis-v1.md §1：7 个顶层字段必须存在。
    for key in [
        "network_id",
        "chain_id",
        "genesis_timestamp",
        "initial_validator_set",
        "initial_accounts",
        "protocol_parameters",
        "economics_parameters",
    ] {
        if value.get(key).is_none() {
            errors.push(format!("missing genesis field: {key}"));
        }
    }

    // 类型检查（顶层字段必须是对象/数组/数字等）。
    if value
        .get("initial_validator_set")
        .is_some_and(|v| !v.is_array())
    {
        errors.push("initial_validator_set must be an array".into());
    }
    if value.get("initial_accounts").is_some_and(|v| !v.is_array()) {
        errors.push("initial_accounts must be an array".into());
    }
    for key in ["protocol_parameters", "economics_parameters"] {
        if value.get(key).is_some_and(|v| !v.is_object()) {
            errors.push(format!("{key} must be an object"));
        }
    }
    for key in ["chain_id", "genesis_timestamp", "network_id"] {
        if value.get(key).is_some_and(|v| !v.is_u64()) {
            errors.push(format!("{key} must be an unsigned integer"));
        }
    }

    // expected_genesis_hash 字段应存在（记录；计算验证 DEFERRED_VALIDATION）。
    if value.get("expected_genesis_hash").is_none() {
        errors.push("missing field: expected_genesis_hash".into());
    }

    GenesisValidation {
        id,
        ok: errors.is_empty(),
        errors,
        // genesis_hash 计算本阶段不实现（PHASE 7 canonical 定稿）：恒为 DEFERRED。
        hash_deferred: true,
    }
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}
