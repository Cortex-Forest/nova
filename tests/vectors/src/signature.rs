//! Signature 向量校验（STEP 1 仅 schema + 链路重算）。
//!
//! 本阶段**不实现 Ed25519**（§8）：本模块校验 schema 并重算
//! `signed_bytes` / `message_hash`（链路就绪），但**签名/公钥的密码学验证标记为
//! `DEFERRED_VALIDATION`**——报告 `VECTOR_VALIDATION_READY` 而非伪造 `CRYPTO_SIGNATURE_PASS`。

use crate::domain::{build_signed_bytes, compute_message_hash, is_implemented_algorithm};
use crate::hex;
use crate::json;
use serde_json::Value;

/// Signature 向量校验结果。
#[derive(Debug, Clone)]
pub struct SignatureValidation {
    /// 向量 id。
    pub id: String,
    /// schema + 链路重算是否通过。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// 密码学验证是否延迟（本阶段恒为 true：Ed25519 未实现）。
    pub crypto_deferred: bool,
}

/// 校验单个 signature 向量 JSON。
pub fn validate_signature_vector(input: &str) -> SignatureValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return SignatureValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                crypto_deferred: true,
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();

    let mut errors: Vec<String> = Vec::new();
    let required = [
        "algorithm_id",
        "domain_id",
        "chain_id",
        "canonical_payload",
        "signed_bytes",
        "message_hash",
        "public_key",
        "signature",
        "expected",
    ];
    for key in required {
        if value.get(key).is_none() {
            errors.push(format!("missing required field: {key}"));
        }
    }

    // 注册表校验：algorithm_id 未实现（Reserved）⇒ 拒绝，禁止 fallback（ADR-0012）。
    if let Some(alg) = get_u8(&value, "algorithm_id").filter(|a| !is_implemented_algorithm(*a)) {
        errors.push(format!(
            "algorithm_id {alg:#04x} not implemented (Reserved); must REJECT, no fallback"
        ));
    }

    // hex 字段必须为合法小写 hex（不信任值，仅校验格式；重算由 loader 完成）。
    for key in [
        "canonical_payload",
        "signed_bytes",
        "message_hash",
        "public_key",
        "signature",
    ] {
        if let Some(e) = value
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| hex::decode_strict_lower_hex(s).err())
        {
            errors.push(format!("{key} hex: {e}"));
        }
    }

    // 链路重算（与 domain 相同规则）：signed_bytes / message_hash 重算比对。
    if let (
        Some(alg),
        Some(dom),
        Some(chain),
        Some(payload_hex),
        Some(signed_hex),
        Some(hash_hex),
    ) = (
        get_u8(&value, "algorithm_id"),
        get_u8(&value, "domain_id"),
        get_u64(&value, "chain_id"),
        get_str(&value, "canonical_payload"),
        get_str(&value, "signed_bytes"),
        get_str(&value, "message_hash"),
    ) {
        let payload = hex::decode_strict_lower_hex(payload_hex);
        let signed_exp = hex::decode_strict_lower_hex(signed_hex);
        let hash_exp = hex::decode_strict_lower_hex(hash_hex);
        if let (Ok(payload), Ok(signed_exp), Ok(hash_exp)) = (payload, signed_exp, hash_exp) {
            match build_signed_bytes(alg, dom, chain, &payload) {
                Ok(computed) => {
                    if computed != signed_exp {
                        errors.push("signed_bytes mismatch (recomputed != vector)".into());
                    }
                    let hash = compute_message_hash(&computed);
                    if hash.as_slice() != hash_exp.as_slice() {
                        errors
                            .push("message_hash mismatch (SHA-256(signed_bytes) != vector)".into());
                    }
                }
                Err(e) => errors.push(format!("build_signed_bytes: {e}")),
            }
        } else {
            errors.push("link recomputation skipped (hex decode failed)".into());
        }
    }

    SignatureValidation {
        id,
        ok: errors.is_empty(),
        errors,
        // Ed25519 密码学验证在本阶段未实现（§8）：恒为 DEFERRED。
        crypto_deferred: true,
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

fn get_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}
