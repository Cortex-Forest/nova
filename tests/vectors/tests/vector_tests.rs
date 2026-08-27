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
use nova_test_vectors::transaction::{
    validate_transaction_vector, validate_transaction_vector_on_store,
};

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
        let expected = vector_field(json, "expected");
        assert!(
            !r.codec_deferred,
            "VECTOR FAILED\nID: {id}\nFIELD: codec status\nEXPECTED: NOT deferred (STEP 5)\nACTUAL: deferred"
        );
        if expected == "VALID" {
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: codec (decode + field match + canonical roundtrip)\nEXPECTED: valid\nACTUAL: {:?}\nSPEC: ADR-0004 decode rules",
                r.errors
            );
        } else {
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: codec (reject + error category)\nEXPECTED: invalid ({})\nACTUAL: {:?}\nSPEC: ADR-0004 decode rules",
                vector_field(json, "expected_error"),
                r.errors
            );
        }
    }
    assert_eq!(ADDRESS_VECTORS.len(), 14);
}

// ---------------------------------------------------------------------------
// Genesis vectors（STEP 6 schema 冻结；genesis_hash → DEFERRED_VALIDATION）
// ---------------------------------------------------------------------------
const GENESIS_VECTORS: &[(&str, &str)] = &[
    (
        "genesis-mainnet-valid-001",
        include_str!("../genesis/genesis-mainnet-valid-001.json"),
    ),
    (
        "genesis-testnet-valid-001",
        include_str!("../genesis/genesis-testnet-valid-001.json"),
    ),
    (
        "genesis-devnet-valid-001",
        include_str!("../genesis/genesis-devnet-valid-001.json"),
    ),
    (
        "genesis-invalid-network-001",
        include_str!("../genesis/genesis-invalid-network-001.json"),
    ),
    (
        "genesis-invalid-chain-id-001",
        include_str!("../genesis/genesis-invalid-chain-id-001.json"),
    ),
    (
        "genesis-invalid-timestamp-001",
        include_str!("../genesis/genesis-invalid-timestamp-001.json"),
    ),
    (
        "genesis-duplicate-validator-001",
        include_str!("../genesis/genesis-duplicate-validator-001.json"),
    ),
    (
        "genesis-duplicate-account-001",
        include_str!("../genesis/genesis-duplicate-account-001.json"),
    ),
    (
        "genesis-invalid-stake-001",
        include_str!("../genesis/genesis-invalid-stake-001.json"),
    ),
    (
        "genesis-stake-exceeds-account-001",
        include_str!("../genesis/genesis-stake-exceeds-account-001.json"),
    ),
    (
        "genesis-invalid-protocol-params-001",
        include_str!("../genesis/genesis-invalid-protocol-params-001.json"),
    ),
    (
        "genesis-invalid-economics-001",
        include_str!("../genesis/genesis-invalid-economics-001.json"),
    ),
    (
        "genesis-wrong-validator-order-001",
        include_str!("../genesis/genesis-wrong-validator-order-001.json"),
    ),
    (
        "genesis-wrong-account-order-001",
        include_str!("../genesis/genesis-wrong-account-order-001.json"),
    ),
    (
        "genesis-tampered-genesis-001",
        include_str!("../genesis/genesis-tampered-genesis-001.json"),
    ),
    (
        "genesis-wrong-genesis-hash-001",
        include_str!("../genesis/genesis-wrong-genesis-hash-001.json"),
    ),
    (
        "genesis-supply-invariant-violation-001",
        include_str!("../genesis/genesis-supply-invariant-violation-001.json"),
    ),
];

#[test]
fn genesis_vectors_validate() {
    for (id, json) in GENESIS_VECTORS {
        let r = validate_genesis_vector(json);
        let expected = vector_field(json, "expected");
        let expected_error = vector_field(json, "expected_error");
        if expected == "VALID" {
            // schema + canonical/hash 全部通过。
            assert!(
                r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: genesis schema + canonical hash\nEXPECTED: valid\nACTUAL: {:?}\nSPEC: ADR-0014/0015/0016",
                r.errors
            );
        } else {
            assert!(
                !r.ok,
                "VECTOR FAILED\nID: {id}\nFIELD: genesis (INVALID)\nEXPECTED: reject\nACTUAL: accepted\nSPEC: ADR-0014/0015/0016"
            );
            assert_eq!(
                r.error_name.as_deref(),
                Some(expected_error.as_str()),
                "VECTOR FAILED\nID: {id}\nFIELD: error category\nEXPECTED: {expected_error}\nACTUAL: {:?}",
                r.error_name
            );
        }
    }
    assert_eq!(GENESIS_VECTORS.len(), 17);
}

// ---------------------------------------------------------------------------
// Transaction vectors（ADR-0024 / STEP 7H）
// ---------------------------------------------------------------------------
const TRANSACTION_VECTORS: &[(&str, &str)] = &[
    (
        "tx-normal-transfer-001",
        include_str!("../transaction/tx-normal-transfer-001.json"),
    ),
    (
        "tx-zero-amount-001",
        include_str!("../transaction/tx-zero-amount-001.json"),
    ),
    (
        "tx-self-transfer-001",
        include_str!("../transaction/tx-self-transfer-001.json"),
    ),
    (
        "tx-nonce-current-001",
        include_str!("../transaction/tx-nonce-current-001.json"),
    ),
    (
        "tx-nonce-too-low-001",
        include_str!("../transaction/tx-nonce-too-low-001.json"),
    ),
    (
        "tx-nonce-future-001",
        include_str!("../transaction/tx-nonce-future-001.json"),
    ),
    (
        "tx-nonce-max-001",
        include_str!("../transaction/tx-nonce-max-001.json"),
    ),
    (
        "tx-fee-normal-001",
        include_str!("../transaction/tx-fee-normal-001.json"),
    ),
    (
        "tx-fee-overflow-001",
        include_str!("../transaction/tx-fee-overflow-001.json"),
    ),
    (
        "tx-required-overflow-001",
        include_str!("../transaction/tx-required-overflow-001.json"),
    ),
    (
        "tx-gas-limit-invalid-001",
        include_str!("../transaction/tx-gas-limit-invalid-001.json"),
    ),
    (
        "tx-gas-price-invalid-001",
        include_str!("../transaction/tx-gas-price-invalid-001.json"),
    ),
    (
        "tx-wrong-chain-001",
        include_str!("../transaction/tx-wrong-chain-001.json"),
    ),
    (
        "tx-wrong-network-001",
        include_str!("../transaction/tx-wrong-network-001.json"),
    ),
    (
        "tx-expired-001",
        include_str!("../transaction/tx-expired-001.json"),
    ),
    (
        "tx-receiver-created-001",
        include_str!("../transaction/tx-receiver-created-001.json"),
    ),
    (
        "tx-receiver-existing-001",
        include_str!("../transaction/tx-receiver-existing-001.json"),
    ),
    (
        "tx-zero-value-no-create-001",
        include_str!("../transaction/tx-zero-value-no-create-001.json"),
    ),
    (
        "tx-signature-valid-001",
        include_str!("../transaction/tx-signature-valid-001.json"),
    ),
    (
        "tx-modified-payload-001",
        include_str!("../transaction/tx-modified-payload-001.json"),
    ),
    (
        "tx-modified-signature-001",
        include_str!("../transaction/tx-modified-signature-001.json"),
    ),
    (
        "tx-success-transition-001",
        include_str!("../transaction/tx-success-transition-001.json"),
    ),
    (
        "tx-failed-no-mutation-001",
        include_str!("../transaction/tx-failed-no-mutation-001.json"),
    ),
];

#[test]
fn transaction_vectors_validate() {
    for (id, json) in TRANSACTION_VECTORS {
        let r = validate_transaction_vector(json);
        assert!(
            r.ok,
            "VECTOR FAILED\nID: {id}\nEXPECTED: result/phase/error + six-layer recompute\nACTUAL: {:?}\nSPEC: ADR-0024",
            r.errors
        );
    }
    assert_eq!(TRANSACTION_VECTORS.len(), 23);
}

/// 8C-3：同一批 7H 向量在真实 `StateStore` 上验证完整执行链
/// （seed → apply_transaction → StateStore::apply）。
#[test]
fn transaction_vectors_state_store_validate() {
    for (id, json) in TRANSACTION_VECTORS {
        let r = validate_transaction_vector_on_store(json);
        assert!(
            r.ok,
            "VECTOR FAILED\nID: {id}\nEXPECTED: StateStore execution chain (seed → apply_transaction → StateStore::apply)\nACTUAL: {:?}\nSPEC: ADR-0028 D-6",
            r.errors
        );
    }
}
