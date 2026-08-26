//! Address 向量校验（STEP 5：**真实 codec 验证**，不再 DEFERRED）。
//!
//! 委托 `nova_crypto::address`（生产 codec）执行实际编码/解码校验：
//! - VALID：`decode` 成功 + payload 字段（version/type/network/key_hash）匹配
//!   + canonical roundtrip（`decode(a).encode() == a`）。
//! - INVALID：`decode` 拒绝 + 错误类别与向量 `expected_error` 一致。
//!
//! 本 crate 仍是**测试基础设施**：不包含生产密码学实现，仅复用 codec 按冻结规范校验。

use crate::hex;
use crate::json;
use nova_crypto::address::{AddressError, NovaAddress, NovaAddressPayload};
use serde_json::Value;

/// 已注册的 network_id（ADR-0011 Network Registry）。
pub fn is_registered_network(network_id: u8) -> bool {
    (0x01..=0x03).contains(&network_id)
}

/// Address 向量校验结果。
#[derive(Debug, Clone)]
pub struct AddressValidation {
    /// 向量 id。
    pub id: String,
    /// 整体是否通过（schema + codec 与期望一致）。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// codec 验证是否延迟（STEP 5 起恒为 false）。
    pub codec_deferred: bool,
    /// 实际 codec 错误类别名（如 "InvalidChecksum"；无错误为 None）。
    pub codec_error: Option<String>,
}

/// 将 `AddressError` 映射为规范错误名（与向量 `expected_error` 一致）。
pub fn address_error_name(e: &AddressError) -> &'static str {
    match e {
        AddressError::InvalidHrp => "InvalidHrp",
        AddressError::InvalidChecksum => "InvalidChecksum",
        AddressError::EncodeDecode => "EncodeDecode",
        AddressError::InvalidLength => "InvalidLength",
        AddressError::UnsupportedVersion => "UnsupportedVersion",
        AddressError::UnknownAddressType(_) => "UnknownAddressType",
        AddressError::UnknownNetwork(_) => "UnknownNetwork",
        AddressError::NetworkMismatch => "NetworkMismatch",
        AddressError::TypeAlgorithmMismatch => "TypeAlgorithmMismatch",
        AddressError::NonCanonicalCase => "NonCanonicalCase",
        AddressError::InvalidPublicKey => "InvalidPublicKey",
    }
}

/// 校验单个 address 向量 JSON（schema + 真实 codec）。
pub fn validate_address_vector(input: &str) -> AddressValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return AddressValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                codec_deferred: false,
                codec_error: None,
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();
    let mut errors: Vec<String> = Vec::new();

    // ---- 必填字段存在性 ----
    for key in [
        "address",
        "network_id",
        "address_type",
        "address_version",
        "key_hash",
        "expected",
    ] {
        if value.get(key).is_none() {
            errors.push(format!("missing required field: {key}"));
        }
    }
    if errors.iter().any(|e| e.starts_with("missing")) {
        return AddressValidation {
            id,
            ok: false,
            errors,
            codec_deferred: false,
            codec_error: None,
        };
    }

    let address = get_str(&value, "address").unwrap_or_default();
    let expected = get_str(&value, "expected").unwrap_or_default();
    let expected_error = get_str(&value, "expected_error");
    let net_u8 = get_u8(&value, "network_id").unwrap_or(0);
    let at_u8 = get_u8(&value, "address_type").unwrap_or(0);
    let ver_u8 = get_u8(&value, "address_version").unwrap_or(0);
    let key_hash_hex = get_str(&value, "key_hash").unwrap_or_default();

    // ---- key_hash 必须为 32B 严格小写 hex ----
    let key_hash = match hex::decode_strict_lower_hex(key_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            k
        }
        _ => {
            errors.push(format!(
                "key_hash not 32-byte strict lower hex: {key_hash_hex}"
            ));
            return AddressValidation {
                id,
                ok: false,
                errors,
                codec_deferred: false,
                codec_error: None,
            };
        }
    };

    // ---- 真实 codec 校验（委托 nova_crypto::address）----
    let codec_result = NovaAddress::decode(address);

    match expected {
        "VALID" => match codec_result {
            Ok(addr) => {
                let p: &NovaAddressPayload = addr.payload();
                if p.address_version != ver_u8 {
                    errors.push(format!(
                        "address_version mismatch: expected {ver_u8:#04x}, got {:#04x}",
                        p.address_version
                    ));
                }
                if (p.address_type as u8) != at_u8 {
                    errors.push(format!(
                        "address_type mismatch: expected {at_u8:#04x}, got {:#04x}",
                        p.address_type as u8
                    ));
                }
                if (p.network_id as u8) != net_u8 {
                    errors.push(format!(
                        "network_id mismatch: expected {net_u8:#04x}, got {:#04x}",
                        p.network_id as u8
                    ));
                }
                if p.key_hash != key_hash {
                    errors.push("key_hash mismatch".into());
                }
                // canonical roundtrip：decode(a).encode() == a。
                match addr.encode() {
                    Ok(enc) if enc == address => {}
                    _ => errors.push("canonical roundtrip failed (decode(a).encode() != a)".into()),
                }
            }
            Err(e) => errors.push(format!(
                "expected VALID but decode rejected: {}",
                address_error_name(&e)
            )),
        },
        "INVALID" => match codec_result {
            Ok(_) => errors.push("expected INVALID but decode accepted".into()),
            Err(e) => {
                let name = address_error_name(&e);
                if let Some(want) = expected_error
                    && want != name
                {
                    errors.push(format!("expected_error {want} but got {name}"));
                }
            }
        },
        other => errors.push(format!("unknown expected value: {other}")),
    }

    AddressValidation {
        id,
        ok: errors.is_empty(),
        errors,
        codec_deferred: false,
        codec_error: codec_result
            .as_ref()
            .err()
            .map(|e| address_error_name(e).to_string()),
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
