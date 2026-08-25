//! Address 向量校验（STEP 1 仅 schema，**不实现 address codec**）。
//!
//! 本阶段禁止实现 address codec（§14）：本模块只校验向量 schema
//! （字段存在 / 类型 / network_id / address_type / address_version 注册表值），
//! 实际编码/解码验证标记为 `DEFERRED_VALIDATION`（STEP 5 实现后启用）。

use crate::json;
use serde_json::Value;

/// 已注册的 network_id（ADR-0011 Network Registry）。
pub fn is_registered_network(network_id: u8) -> bool {
    (0x01..=0x03).contains(&network_id)
}

/// 已注册的 address_version（ADR-0004）。
pub const ADDRESS_VERSION: u8 = 0x01;

/// Address 向量校验结果。
#[derive(Debug, Clone)]
pub struct AddressValidation {
    /// 向量 id。
    pub id: String,
    /// schema 是否通过。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// codec 验证是否延迟（本阶段恒为 true）。
    pub codec_deferred: bool,
}

/// 校验单个 address 向量 JSON。
pub fn validate_address_vector(input: &str) -> AddressValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return AddressValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                codec_deferred: true,
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();

    let mut errors: Vec<String> = Vec::new();

    // 必填字段存在性。
    for key in [
        "address",
        "network_id",
        "address_type",
        "address_version",
        "expected",
    ] {
        if value.get(key).is_none() {
            errors.push(format!("missing required field: {key}"));
        }
    }

    // 注册表值校验（未注册 ⇒ 拒绝）。
    if let Some(net) = get_u8(&value, "network_id").filter(|n| !is_registered_network(*n)) {
        errors.push(format!("network_id {net:#04x} not registered"));
    }
    if get_u8(&value, "address_version") != Some(ADDRESS_VERSION) {
        errors.push("address_version unsupported".into());
    }
    // address_type：0x01 已批准（User Account）；0x00/未注册 ⇒ 拒绝（address codec 未实现，
    // 此处只做注册表值预检；实际拒绝逻辑由 codec 在 STEP 5 执行）。
    if get_u8(&value, "address_type") == Some(0x00) {
        errors.push("address_type 0x00 is invalid".into());
    }
    if get_str(&value, "address").is_some_and(str::is_empty) {
        errors.push("address must not be empty".into());
    }

    AddressValidation {
        id,
        ok: errors.is_empty(),
        errors,
        // address codec 本阶段未实现（§14）：恒为 DEFERRED。
        codec_deferred: true,
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
