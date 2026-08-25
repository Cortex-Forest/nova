//! Domain 向量校验：按冻结规范重算 `signed_bytes` / `message_hash`
//! （crypto-serialization-v1.md §10；loader 不定义协议，仅按冻结规范生成 LE 表示）。

use crate::hex;
use crate::json;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// 冻结注册的 `domain_id`（ADR-0005 Domain Registry）。
pub const DOMAIN_TRANSACTION: u8 = 0x01;
pub const DOMAIN_VALIDATOR_VOTE: u8 = 0x02;
pub const DOMAIN_BLOCK: u8 = 0x03;
pub const DOMAIN_GOVERNANCE: u8 = 0x04;
pub const DOMAIN_ADDRESS: u8 = 0x05;

/// 冻结注册的 `algorithm_id`（ADR-0012 Algorithm Registry）。
pub const ALGORITHM_ED25519: u8 = 0x01;

/// `domain_id` 是否已注册（未注册 ⇒ 拒绝）。
pub fn is_registered_domain(domain_id: u8) -> bool {
    matches!(
        domain_id,
        DOMAIN_TRANSACTION
            | DOMAIN_VALIDATOR_VOTE
            | DOMAIN_BLOCK
            | DOMAIN_GOVERNANCE
            | DOMAIN_ADDRESS
    )
}

/// `algorithm_id` 是否已实现（本阶段仅 Ed25519；其余 Reserved ⇒ 拒绝）。
pub fn is_implemented_algorithm(algorithm_id: u8) -> bool {
    algorithm_id == ALGORITHM_ED25519
}

/// 构造 signed_bytes 的错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSignedBytesError {
    /// canonical_payload 长度超出 u32。
    PayloadTooLarge(usize),
}

impl fmt::Display for BuildSignedBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge(n) => write!(f, "canonical_payload too large: {n} bytes"),
        }
    }
}

impl std::error::Error for BuildSignedBytesError {}

use std::fmt;

/// 冻结签名上下文构造（crypto-serialization-v1.md §10）：
/// `algorithm_id(1B) || domain_id(1B) || chain_id(8B LE) || payload_length(4B LE) || payload`。
pub fn build_signed_bytes(
    algorithm_id: u8,
    domain_id: u8,
    chain_id: u64,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, BuildSignedBytesError> {
    let len = u32::try_from(canonical_payload.len())
        .map_err(|_| BuildSignedBytesError::PayloadTooLarge(canonical_payload.len()))?;
    let mut out = Vec::with_capacity(1 + 1 + 8 + 4 + canonical_payload.len());
    out.push(algorithm_id);
    out.push(domain_id);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(canonical_payload);
    Ok(out)
}

/// 计算 `message_hash = SHA-256(signed_bytes)`。
pub fn compute_message_hash(signed_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(signed_bytes);
    h.finalize().into()
}

/// Domain 向量校验结果。
#[derive(Debug, Clone)]
pub struct DomainValidation {
    /// 向量 id。
    pub id: String,
    /// 是否通过（无错误）。
    pub ok: bool,
    /// 错误列表。
    pub errors: Vec<String>,
    /// 是否因算法/签名未实现而只到"验证就绪"（VECTOR_VALIDATION_READY）。
    pub validation_ready_only: bool,
}

/// 校验单个 domain 向量 JSON。
///
/// 重算并比对：`computed_signed_bytes == vector.signed_bytes`、
/// `SHA-256(computed_signed_bytes) == vector.message_hash`（§6/§7，不信任向量值）。
pub fn validate_domain_vector(input: &str) -> DomainValidation {
    let mut errors: Vec<String> = Vec::new();
    let mut validation_ready_only = false;

    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return DomainValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
                validation_ready_only: false,
            };
        }
    };

    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();
    let Some(algorithm_id) = get_u8(&value, "algorithm_id") else {
        return fail(&id, "missing/invalid algorithm_id", validation_ready_only);
    };
    let Some(domain_id) = get_u8(&value, "domain_id") else {
        return fail(&id, "missing/invalid domain_id", validation_ready_only);
    };
    let Some(chain_id) = get_u64(&value, "chain_id") else {
        return fail(&id, "missing/invalid chain_id", validation_ready_only);
    };

    // 注册表校验（§12 / §13）：未注册必须拒绝，禁止 fallback。
    if !is_registered_domain(domain_id) {
        errors.push(format!("domain_id {domain_id:#04x} not registered"));
    }
    if !is_implemented_algorithm(algorithm_id) {
        errors.push(format!(
            "algorithm_id {algorithm_id:#04x} not implemented (Reserved); must REJECT, no fallback"
        ));
        validation_ready_only = true;
    }

    // hex 字段解析。
    let Some(payload_hex) = get_str(&value, "canonical_payload") else {
        return fail(&id, "missing canonical_payload", validation_ready_only);
    };
    let Some(signed_hex) = get_str(&value, "signed_bytes") else {
        return fail(&id, "missing signed_bytes", validation_ready_only);
    };
    let Some(hash_hex) = get_str(&value, "message_hash") else {
        return fail(&id, "missing message_hash", validation_ready_only);
    };

    let payload = match hex::decode_strict_lower_hex(payload_hex) {
        Ok(p) => p,
        Err(e) => {
            return fail(
                &id,
                &format!("canonical_payload hex: {e}"),
                validation_ready_only,
            );
        }
    };
    let signed_expected = match hex::decode_strict_lower_hex(signed_hex) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                &id,
                &format!("signed_bytes hex: {e}"),
                validation_ready_only,
            );
        }
    };
    let hash_expected = match hex::decode_strict_lower_hex(hash_hex) {
        Ok(h) => h,
        Err(e) => {
            return fail(
                &id,
                &format!("message_hash hex: {e}"),
                validation_ready_only,
            );
        }
    };

    // 重算（§6/§7）。
    match build_signed_bytes(algorithm_id, domain_id, chain_id, &payload) {
        Ok(computed) => {
            if computed != signed_expected {
                errors.push("signed_bytes mismatch (recomputed != vector)".into());
            }
            let hash = compute_message_hash(&computed);
            if hash.as_slice() != hash_expected.as_slice() {
                errors.push("message_hash mismatch (SHA-256(signed_bytes) != vector)".into());
            }
        }
        Err(e) => errors.push(format!("build_signed_bytes: {e}")),
    }

    let ok = errors.is_empty();

    DomainValidation {
        id,
        ok,
        errors,
        validation_ready_only,
    }
}

fn fail(id: &str, msg: &str, validation_ready_only: bool) -> DomainValidation {
    DomainValidation {
        id: id.to_string(),
        ok: false,
        errors: vec![msg.to_string()],
        validation_ready_only,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode_lower_hex;

    #[test]
    fn signed_bytes_layout() {
        // algorithm_id=1, domain_id=1, chain_id=1, payload=[0x00,0x01]
        let sb = build_signed_bytes(1, 1, 1, &[0x00, 0x01]).unwrap();
        // 01 | 01 | chain_id(8B LE)=0100000000000000 | len(4B LE)=02000000 | 0001
        assert_eq!(encode_lower_hex(&sb), "01010100000000000000020000000001");
    }

    #[test]
    fn message_hash_deterministic() {
        let a = compute_message_hash(b"abc");
        let b = compute_message_hash(b"abc");
        assert_eq!(a, b);
        assert_ne!(a, compute_message_hash(b"abd"));
    }

    #[test]
    fn same_payload_diff_domain_diff_hash() {
        let sb1 = build_signed_bytes(1, 1, 1, b"x").unwrap();
        let sb2 = build_signed_bytes(1, 2, 1, b"x").unwrap();
        assert_ne!(sb1, sb2);
        assert_ne!(compute_message_hash(&sb1), compute_message_hash(&sb2));
    }

    #[test]
    fn same_payload_diff_chain_diff_hash() {
        let sb1 = build_signed_bytes(1, 1, 1, b"x").unwrap();
        let sb2 = build_signed_bytes(1, 1, 2, b"x").unwrap();
        assert_ne!(sb1, sb2);
        assert_ne!(compute_message_hash(&sb1), compute_message_hash(&sb2));
    }
}
