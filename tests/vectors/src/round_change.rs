//! O2 `RoundChangeCertificate` 测试向量校验（PHASE 6H-Y）。
//!
//! # 依据（全部 **FROZEN**；本模块不修改、不重定义任何协议）
//! - `ADR-0066` round-change certificate v1（结构 / 语义 / `to_round = from_round + 1`）
//! - `ADR-0070` canonical serialization v1（`validator_set_id(32) ‖ height(8 LE) ‖
//!   from_round(8 LE) ‖ evidence_count(2 LE) ‖ evidence[96×n]`）
//! - `ADR-0067` domain registry amendment（`RoundChangeCertificate = 0x10`）
//! - `ADR-0012` algorithm registry（Ed25519 `= 0x01`）
//!
//! # 边界（重要）
//! - 期望值**一律由实现阶段实际 codec**（`nova_consensus::round_change`）重算后与向量比对；
//!   **禁止手工构造字节**（PHASE 6H-Y §17）。
//! - 本模块覆盖 §17 要求的 codec / signing statement / hash / domain / algorithm /
//!   signature verification / quorum 算术；完整 `verify_certificate`（需 `ValidatorSet`）
//!   由 `nova-consensus` 聚焦单元测试覆盖（§18 项 1–12）。
//! - 向量含**公钥**，不含任何私钥材料。
//! - JSON 只是 Human-readable Test Vector Format，**不是** YAZIMAO 协议编码。

use crate::hex;
use crate::json;
use nova_consensus::round_change::{
    MAX_CERTIFICATE_BYTES, MAX_EVIDENCE_COUNT, RoundChangeCertificate, RoundChangeEvidence,
    abandon_message_hash, abandon_signed_bytes, canonical_abandon_payload, decode_certificate,
    encode_certificate,
};
use nova_consensus::validator::ValidatorId;
use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};
use serde_json::Value;

/// 冻结 `domain_id`：`DomainId::RoundChangeCertificate = 0x10`（ADR-0067）。
pub const ROUND_CHANGE_DOMAIN_ID: u8 = 0x10;
/// 冻结 `algorithm_id`：Ed25519 `= 0x01`（ADR-0012）。
pub const ROUND_CHANGE_ALGORITHM_ID: u8 = 0x01;

/// 单向量校验结果。
#[derive(Debug, Clone)]
pub struct RoundChangeValidation {
    /// 向量 id。
    pub id: String,
    /// 无错误即通过。
    pub ok: bool,
    /// 错误列表（逐项累积，不早退——便于一次看到全部偏差）。
    pub errors: Vec<String>,
}

fn as_u64(v: &Value, key: &str, errors: &mut Vec<String>) -> Option<u64> {
    match v.get(key).and_then(Value::as_u64) {
        Some(n) => Some(n),
        None => {
            errors.push(format!("field `{key}`: missing or not u64"));
            None
        }
    }
}

fn as_hex(v: &Value, key: &str, errors: &mut Vec<String>) -> Option<Vec<u8>> {
    let Some(s) = v.get(key).and_then(Value::as_str) else {
        errors.push(format!("field `{key}`: missing or not string"));
        return None;
    };
    match hex::decode_strict_lower_hex(s) {
        Ok(b) => Some(b),
        Err(e) => {
            errors.push(format!("field `{key}`: {e:?}"));
            None
        }
    }
}

fn as_u128(v: &Value, key: &str, errors: &mut Vec<String>) -> Option<u128> {
    match v.get(key).and_then(Value::as_u64) {
        Some(n) => Some(u128::from(n)),
        None => {
            errors.push(format!("field `{key}`: missing or not u64"));
            None
        }
    }
}

/// 校验单个 round-change 向量 JSON。
///
/// 重算并比对：canonical payload、`signed_bytes`、`message_hash`、证书 canonical 编码、
/// 证书长度派生、`to_round` 派生、evidence 严格升序 / 无重复、`validator_id` 派生、
/// 每条 evidence 的 Ed25519 签名验证、quorum 权重算术。
pub fn validate_round_change_vector(input: &str) -> RoundChangeValidation {
    let mut errors: Vec<String> = Vec::new();

    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return RoundChangeValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
            };
        }
    };
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing-id>")
        .to_string();

    // ---- 1. 编码空间常量（ADR-0012 / ADR-0067）----
    match as_u64(&value, "algorithm_id", &mut errors) {
        Some(1) => {}
        Some(other) => errors.push(format!(
            "algorithm_id must be {ROUND_CHANGE_ALGORITHM_ID} (Ed25519), got {other}"
        )),
        None => {}
    }
    match as_u64(&value, "domain_id", &mut errors) {
        Some(0x10) => {}
        Some(other) => errors.push(format!(
            "domain_id must be 0x10 (RoundChangeCertificate), got {other:#04x}"
        )),
        None => {}
    }

    let chain_id = as_u64(&value, "chain_id", &mut errors);
    let height = as_u64(&value, "height", &mut errors);
    let from_round = as_u64(&value, "from_round", &mut errors);

    // ---- 2. canonical payload（精确 16B；ADR-0070 §5）----
    if let (Some(h), Some(r)) = (height, from_round) {
        let expected_payload = canonical_abandon_payload(h, r);
        if let Some(actual) = as_hex(&value, "canonical_payload", &mut errors)
            && actual.as_slice() != expected_payload.as_slice()
        {
            errors.push(format!(
                "canonical_payload mismatch: expected {}, got {}",
                hex::encode_lower_hex(&expected_payload),
                hex::encode_lower_hex(&actual)
            ));
        }
    }

    // ---- 3. signing statement（signed_bytes；复用既有 build_signed_bytes）----
    let expected_hash = match (chain_id, height, from_round) {
        (Some(c), Some(h), Some(r)) => match abandon_signed_bytes(c, h, r) {
            Ok(expected_signed) => {
                if let Some(actual) = as_hex(&value, "signed_bytes", &mut errors)
                    && actual != expected_signed
                {
                    errors.push(format!(
                        "signed_bytes mismatch: expected {}, got {}",
                        hex::encode_lower_hex(&expected_signed),
                        hex::encode_lower_hex(&actual)
                    ));
                }
                // domain_id 必须落在 signed_bytes[1]（审计 §17「domain ID = 0x10」）
                if expected_signed.get(1) != Some(&ROUND_CHANGE_DOMAIN_ID) {
                    errors.push("signed_bytes[1] is not 0x10".to_string());
                }
                if expected_signed.first() != Some(&ROUND_CHANGE_ALGORITHM_ID) {
                    errors.push("signed_bytes[0] is not 0x01 (Ed25519)".to_string());
                }
                match abandon_message_hash(c, h, r) {
                    Ok(h_) => Some(h_),
                    Err(e) => {
                        errors.push(format!("abandon_message_hash failed: {e:?}"));
                        None
                    }
                }
            }
            Err(e) => {
                errors.push(format!("abandon_signed_bytes failed: {e:?}"));
                None
            }
        },
        _ => None,
    };
    if let Some(expected) = &expected_hash
        && let Some(actual) = as_hex(&value, "message_hash", &mut errors)
        && actual.as_slice() != expected.as_bytes()
    {
        errors.push(format!(
            "message_hash mismatch: expected {}, got {}",
            hex::encode_lower_hex(expected.as_bytes()),
            hex::encode_lower_hex(&actual)
        ));
    }

    // ---- 4. 证书 canonical 编码（ADR-0070 §6）----
    let validator_set_id = as_hex(&value, "validator_set_id", &mut errors);
    let evidence_items = value
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if evidence_items.is_empty() {
        errors.push("evidence: missing or empty".to_string());
    }

    let mut evidence: Vec<RoundChangeEvidence> = Vec::with_capacity(evidence_items.len());
    for (i, item) in evidence_items.iter().enumerate() {
        let vid = as_hex(item, "validator_id", &mut errors);
        let sig = as_hex(item, "signature", &mut errors);
        if let (Some(vid), Some(sig)) = (vid, sig) {
            let Ok(vid32) = <[u8; 32]>::try_from(vid.as_slice()) else {
                errors.push(format!("evidence[{i}].validator_id must be 32 bytes"));
                continue;
            };
            let Ok(sig64) = <[u8; 64]>::try_from(sig.as_slice()) else {
                errors.push(format!("evidence[{i}].signature must be 64 bytes"));
                continue;
            };
            evidence.push(RoundChangeEvidence {
                validator_id: ValidatorId::from_bytes(vid32),
                signature: sig64,
            });
        }
    }

    // evidence 顺序 / 唯一性（ADR-0070 §6：严格升序、无重复）
    for w in evidence.windows(2) {
        if w[0].validator_id == w[1].validator_id {
            errors.push("evidence: duplicate validator_id".to_string());
        } else if w[0].validator_id > w[1].validator_id {
            errors.push("evidence: validator_ids must be strictly ascending".to_string());
        }
    }
    if evidence.len() > MAX_EVIDENCE_COUNT {
        errors.push(format!(
            "evidence count {} exceeds MAX_EVIDENCE_COUNT {MAX_EVIDENCE_COUNT}",
            evidence.len()
        ));
    }

    if let (Some(vsid), Some(h), Some(r)) = (&validator_set_id, height, from_round) {
        match <[u8; 32]>::try_from(vsid.as_slice()) {
            Ok(vsid32) => {
                let cert = RoundChangeCertificate {
                    validator_set_id: vsid32,
                    height: h,
                    from_round: r,
                    evidence: evidence.clone(),
                };
                // 派生长度：50 + 96n（ADR-0070 §6）
                let derived_len = cert.encoded_len();
                if derived_len > MAX_CERTIFICATE_BYTES {
                    errors.push(format!(
                        "derived certificate length {derived_len} exceeds MAX_CERTIFICATE_BYTES {MAX_CERTIFICATE_BYTES}"
                    ));
                }
                if let Some(declared) = as_u64(&value, "certificate_len", &mut errors)
                    && declared != derived_len as u64
                {
                    errors.push(format!(
                        "certificate_len mismatch: expected {derived_len}, got {declared}"
                    ));
                }
                if let Some(declared_bytes) = as_hex(&value, "certificate_bytes", &mut errors) {
                    match encode_certificate(&cert) {
                        Ok(actual) => {
                            if actual != declared_bytes {
                                errors.push(format!(
                                    "certificate_bytes mismatch: expected {} bytes ({}), got {} bytes ({})",
                                    actual.len(),
                                    hex::encode_lower_hex(&actual),
                                    declared_bytes.len(),
                                    hex::encode_lower_hex(&declared_bytes)
                                ));
                            }
                        }
                        Err(e) => errors.push(format!("encode_certificate failed: {e:?}")),
                    }
                }
                // decode 往返：canonical 编码必须严格可逆
                if let Some(declared_bytes) = as_hex(&value, "certificate_bytes", &mut errors) {
                    match decode_certificate(&declared_bytes) {
                        Ok(back) => {
                            if back != cert {
                                errors.push("decode_certificate round-trip mismatch".to_string());
                            }
                        }
                        Err(e) => {
                            errors.push(format!("decode_certificate failed: {e:?}"));
                        }
                    }
                }
                // to_round 派生（ADR-0066 RC-2：唯一后继）
                if let Some(declared) = as_u64(&value, "to_round", &mut errors) {
                    let derived = r.checked_add(1);
                    if derived != Some(declared) {
                        errors.push(format!(
                            "to_round must be from_round + 1 = {r} + 1, got {declared}"
                        ));
                    }
                }
            }
            Err(_) => errors.push("validator_set_id must be 32 bytes".to_string()),
        }
    }

    // ---- 5. 签名验证（§17「signature verification」；用向量内公钥，无需私钥）----
    let validator_items = value
        .get("validators")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut total_weight: u128 = 0;
    let mut participating_weight: u128 = 0;
    for (i, item) in validator_items.iter().enumerate() {
        let pk = as_hex(item, "public_key", &mut errors);
        let vid = as_hex(item, "validator_id", &mut errors);
        let weight = as_u128(item, "weight", &mut errors);
        total_weight = total_weight.saturating_add(weight.unwrap_or(0));
        let (Some(pk), Some(vid)) = (pk, vid) else {
            continue;
        };
        let Ok(pk32) = <[u8; 32]>::try_from(pk.as_slice()) else {
            errors.push(format!("validators[{i}].public_key must be 32 bytes"));
            continue;
        };
        // validator_id 必须是 SHA-256(consensus_public_key)
        if ValidatorId::from_consensus_public_key(&pk32).as_bytes() != vid.as_slice() {
            errors.push(format!(
                "validators[{i}].validator_id != SHA-256(consensus_public_key)"
            ));
        }
    }
    for (i, e) in evidence.iter().enumerate() {
        // 定位公钥
        let entry = validator_items.iter().find(|item| {
            as_hex(item, "validator_id", &mut Vec::new())
                .is_some_and(|vid| vid.as_slice() == e.validator_id.as_bytes())
        });
        let Some(entry) = entry else {
            errors.push(format!(
                "evidence[{i}]: validator_id not present in `validators`"
            ));
            continue;
        };
        let pk = as_hex(entry, "public_key", &mut Vec::new()).unwrap_or_default();
        if let Some(w) = as_u128(entry, "weight", &mut Vec::new()) {
            participating_weight = participating_weight.saturating_add(w);
        }
        let Ok(pk32) = <[u8; 32]>::try_from(pk.as_slice()) else {
            errors.push(format!("evidence[{i}]: malformed public_key"));
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk32) else {
            errors.push(format!(
                "evidence[{i}]: VerifyingKey::from_bytes rejected key"
            ));
            continue;
        };
        let Ok(sig) = Signature::from_bytes(&e.signature) else {
            errors.push(format!("evidence[{i}]: Signature::from_bytes rejected"));
            continue;
        };
        let Some(h) = expected_hash.as_ref() else {
            continue;
        };
        if let Err(err) = verify_message_hash(&vk, h, &sig) {
            errors.push(format!(
                "evidence[{i}]: signature verification failed: {err:?}"
            ));
        }
    }

    // ---- 6. quorum 算术（ADR-0066：weight >= ceil(2T/3)）----
    if total_weight == 0 {
        errors.push("validators: total weight must be > 0".to_string());
    } else {
        let required = total_weight.saturating_mul(2).div_ceil(3);
        if participating_weight < required {
            errors.push(format!(
                "insufficient quorum in vector: participating weight {participating_weight} < required {required} (total {total_weight})"
            ));
        }
    }

    let ok = errors.is_empty();
    RoundChangeValidation { id, ok, errors }
}
