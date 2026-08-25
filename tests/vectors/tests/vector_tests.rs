//! 测试向量集成测试。
//!
//! 使用 `include_str!`（编译期内嵌）加载向量 —— 确定性：不依赖当前时间 / 随机 / 主机名 /
//! OS 随机 / 网络 / 文件系统顺序（STEP 1 §18）。
//!
//! 报告：失败断言携带 vector id、类别、字段期望/实际与规范章节（§17）。

use nova_test_vectors::address::validate_address_vector;
use nova_test_vectors::domain::validate_domain_vector;
use nova_test_vectors::genesis::validate_genesis_vector;
use nova_test_vectors::signature::validate_signature_vector;

// ---------------------------------------------------------------------------
// Domain vectors（§10/§11/§13）
// ---------------------------------------------------------------------------
const DOMAIN_VECTORS: &[(&str, &str)] = &[
    (
        "domain-tx-001",
        include_str!("../domain/domain-tx-001.json"),
    ),
    (
        "domain-vote-001",
        include_str!("../domain/domain-vote-001.json"),
    ),
    (
        "domain-block-001",
        include_str!("../domain/domain-block-001.json"),
    ),
    (
        "domain-gov-001",
        include_str!("../domain/domain-gov-001.json"),
    ),
    (
        "domain-addr-001",
        include_str!("../domain/domain-addr-001.json"),
    ),
    (
        "domain-cross-chain-001",
        include_str!("../domain/domain-cross-chain-001.json"),
    ),
    (
        "domain-diff-payload-001",
        include_str!("../domain/domain-diff-payload-001.json"),
    ),
    (
        "domain-unknown-domain-001",
        include_str!("../domain/domain-unknown-domain-001.json"),
    ),
    (
        "domain-unknown-algorithm-001",
        include_str!("../domain/domain-unknown-algorithm-001.json"),
    ),
    (
        "domain-inconsistent-signed-001",
        include_str!("../domain/domain-inconsistent-signed-001.json"),
    ),
];

fn vector_field(json: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

#[test]
fn domain_vectors_validate() {
    for (id, json) in DOMAIN_VECTORS {
        let r = validate_domain_vector(json);
        let expected = vector_field(json, "expected");
        if expected == "VALID" {
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: domain validation\nEXPECTED: valid\nACTUAL: {:?}\nSPEC: crypto-serialization-v1 §10",
                r.errors
            );
        } else {
            assert!(
                !r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: domain validation\nEXPECTED: invalid\nACTUAL: accepted\nSPEC: crypto-serialization-v1 §10"
            );
        }
    }
    assert_eq!(DOMAIN_VECTORS.len(), 10);
}

// ---------------------------------------------------------------------------
// Signature vectors（§8/§13；CRYPTO scope → DEFERRED_VALIDATION）
// ---------------------------------------------------------------------------
const SIGNATURE_VECTORS: &[(&str, &str)] = &[
    (
        "signature-schema-valid-001",
        include_str!("../signature/signature-schema-valid-001.json"),
    ),
    (
        "signature-malformed-hex-001",
        include_str!("../signature/signature-malformed-hex-001.json"),
    ),
    (
        "signature-malformed-hex-pk-001",
        include_str!("../signature/signature-malformed-hex-pk-001.json"),
    ),
    (
        "signature-truncated-001",
        include_str!("../signature/signature-truncated-001.json"),
    ),
    (
        "signature-oversized-001",
        include_str!("../signature/signature-oversized-001.json"),
    ),
    (
        "signature-wrong-chain-001",
        include_str!("../signature/signature-wrong-chain-001.json"),
    ),
    (
        "signature-wrong-domain-001",
        include_str!("../signature/signature-wrong-domain-001.json"),
    ),
    (
        "signature-wrong-algorithm-001",
        include_str!("../signature/signature-wrong-algorithm-001.json"),
    ),
];

#[test]
fn signature_vectors_validate() {
    for (id, json) in SIGNATURE_VECTORS {
        let r = validate_signature_vector(json);
        let scope = vector_field(json, "validation_scope");
        let expected = vector_field(json, "expected");
        if scope == "SCHEMA" {
            // schema 层可验证：ok 与 expected 一致。
            if expected == "VALID" {
                assert!(
                    r.ok,
                    "VECTOR FAILED\nID: {id}\nFIELD: schema\nEXPECTED: valid\nACTUAL: {:?}\nSPEC: crypto-test-vectors-v1 §3",
                    r.errors
                );
            } else {
                assert!(
                    !r.ok,
                    "VECTOR FAILED\nID: {id}\nFIELD: schema\nEXPECTED: invalid\nACTUAL: accepted\nSPEC: crypto-test-vectors-v1 §3"
                );
            }
        } else {
            // CRYPTO scope：本阶段只验证就绪（VECTOR_VALIDATION_READY），不伪造 PASS。
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: link (signed_bytes/message_hash)\nEXPECTED: ready\nACTUAL: {:?}\nSPEC: crypto-serialization-v1 §10",
                r.errors
            );
            assert!(
                r.crypto_deferred,
                "VECTOR FAILED\nID: {id}\nFIELD: crypto status\nEXPECTED: DEFERRED_VALIDATION\nACTUAL: not deferred"
            );
        }
    }
    assert_eq!(SIGNATURE_VECTORS.len(), 8);
}

// ---------------------------------------------------------------------------
// Address vectors（§14；codec → DEFERRED_VALIDATION，schema 层可验证）
// ---------------------------------------------------------------------------
const ADDRESS_VECTORS: &[(&str, &str)] = &[
    (
        "address-mainnet-valid-001",
        include_str!("../address/address-mainnet-valid-001.json"),
    ),
    (
        "address-testnet-valid-001",
        include_str!("../address/address-testnet-valid-001.json"),
    ),
    (
        "address-devnet-valid-001",
        include_str!("../address/address-devnet-valid-001.json"),
    ),
    (
        "address-wrong-hrp-001",
        include_str!("../address/address-wrong-hrp-001.json"),
    ),
    (
        "address-wrong-checksum-001",
        include_str!("../address/address-wrong-checksum-001.json"),
    ),
    (
        "address-wrong-network-001",
        include_str!("../address/address-wrong-network-001.json"),
    ),
    (
        "address-unknown-type-001",
        include_str!("../address/address-unknown-type-001.json"),
    ),
    (
        "address-unknown-version-001",
        include_str!("../address/address-unknown-version-001.json"),
    ),
    (
        "address-wrong-payload-length-001",
        include_str!("../address/address-wrong-payload-length-001.json"),
    ),
    (
        "address-uppercase-001",
        include_str!("../address/address-uppercase-001.json"),
    ),
    (
        "address-mixed-case-001",
        include_str!("../address/address-mixed-case-001.json"),
    ),
    (
        "address-mutated-char-001",
        include_str!("../address/address-mutated-char-001.json"),
    ),
    (
        "address-truncated-001",
        include_str!("../address/address-truncated-001.json"),
    ),
    (
        "address-extra-char-001",
        include_str!("../address/address-extra-char-001.json"),
    ),
];

#[test]
fn address_vectors_validate() {
    for (id, json) in ADDRESS_VECTORS {
        let r = validate_address_vector(json);
        let schema_expected = vector_field(json, "schema_expected");
        if schema_expected == "VALID" {
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: schema (network/version/type)\nEXPECTED: valid\nACTUAL: {:?}\nSPEC: ADR-0004 decode rules",
                r.errors
            );
        } else {
            assert!(
                !r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: schema (network/version/type)\nEXPECTED: invalid\nACTUAL: accepted\nSPEC: ADR-0004 decode rules"
            );
        }
        assert!(
            r.codec_deferred,
            "VECTOR FAILED\nID: {id}\nFIELD: codec status\nEXPECTED: DEFERRED_VALIDATION\nACTUAL: not deferred"
        );
    }
    assert_eq!(ADDRESS_VECTORS.len(), 14);
}

// ---------------------------------------------------------------------------
// Genesis vectors（§15；genesis_hash → DEFERRED_VALIDATION）
// ---------------------------------------------------------------------------
const GENESIS_VECTORS: &[(&str, &str)] = &[
    (
        "genesis-mainnet-001",
        include_str!("../genesis/genesis-mainnet-001.json"),
    ),
    (
        "genesis-testnet-001",
        include_str!("../genesis/genesis-testnet-001.json"),
    ),
];

#[test]
fn genesis_vectors_validate() {
    for (id, json) in GENESIS_VECTORS {
        let r = validate_genesis_vector(json);
        assert!(
            r.ok,
            "VECTOR FAILED\nID: {id}\nFIELD: genesis schema\nEXPECTED: valid fixture\nACTUAL: {:?}\nSPEC: genesis-v1.md §1",
            r.errors
        );
        assert!(
            r.hash_deferred,
            "VECTOR FAILED\nID: {id}\nFIELD: genesis_hash status\nEXPECTED: DEFERRED_VALIDATION\nACTUAL: not deferred"
        );
    }
    assert_eq!(GENESIS_VECTORS.len(), 2);
}
