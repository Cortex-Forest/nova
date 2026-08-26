//! STEP 5 Exit：接入 STEP 1 address 测试向量（现为**真实 Bech32m 地址**），验证
//! `nova_crypto::address` 正式实现与冻结向量完全一致（decode 接受/拒绝 + 字段匹配 +
//! canonical roundtrip + 错误类别）。
//!
//! 向量文件来自 `tests/vectors/address/`（生成器 `gen_address_vectors` 生成真实地址）；
//! 此处 `include_str!` 内嵌加载（确定性，不依赖文件系统顺序）。

use nova_crypto::address::{ADDRESS_VERSION, AddressError, AddressType, NetworkId, NovaAddress};
use serde_json::Value;

const ADDRESS_VECTORS: &[(&str, &str)] = &[
    (
        "address-mainnet-valid-001",
        include_str!("../../../tests/vectors/address/address-mainnet-valid-001.json"),
    ),
    (
        "address-testnet-valid-001",
        include_str!("../../../tests/vectors/address/address-testnet-valid-001.json"),
    ),
    (
        "address-devnet-valid-001",
        include_str!("../../../tests/vectors/address/address-devnet-valid-001.json"),
    ),
    (
        "address-wrong-hrp-001",
        include_str!("../../../tests/vectors/address/address-wrong-hrp-001.json"),
    ),
    (
        "address-wrong-checksum-001",
        include_str!("../../../tests/vectors/address/address-wrong-checksum-001.json"),
    ),
    (
        "address-wrong-network-001",
        include_str!("../../../tests/vectors/address/address-wrong-network-001.json"),
    ),
    (
        "address-unknown-type-001",
        include_str!("../../../tests/vectors/address/address-unknown-type-001.json"),
    ),
    (
        "address-unknown-version-001",
        include_str!("../../../tests/vectors/address/address-unknown-version-001.json"),
    ),
    (
        "address-wrong-payload-length-001",
        include_str!("../../../tests/vectors/address/address-wrong-payload-length-001.json"),
    ),
    (
        "address-uppercase-001",
        include_str!("../../../tests/vectors/address/address-uppercase-001.json"),
    ),
    (
        "address-mixed-case-001",
        include_str!("../../../tests/vectors/address/address-mixed-case-001.json"),
    ),
    (
        "address-mutated-char-001",
        include_str!("../../../tests/vectors/address/address-mutated-char-001.json"),
    ),
    (
        "address-truncated-001",
        include_str!("../../../tests/vectors/address/address-truncated-001.json"),
    ),
    (
        "address-extra-char-001",
        include_str!("../../../tests/vectors/address/address-extra-char-001.json"),
    ),
];

fn error_name(e: &AddressError) -> &'static str {
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

fn decode_hex(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect();
    assert_eq!(bytes.len(), 32, "key_hash must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

#[test]
fn address_vectors_match_implementation() {
    for &(id, json) in ADDRESS_VECTORS {
        let v: Value = serde_json::from_str(json).expect("valid json");
        let address = field(&v, "address");
        let expected = field(&v, "expected");
        let net: u8 = v["network_id"].as_u64().unwrap() as u8;
        let at: u8 = v["address_type"].as_u64().unwrap() as u8;
        let ver: u8 = v["address_version"].as_u64().unwrap() as u8;
        let key_hash = decode_hex(field(&v, "key_hash"));

        let result = NovaAddress::decode(address);
        if expected == "VALID" {
            let addr = result.unwrap_or_else(|e| {
                panic!(
                    "{id}: expected VALID but decode rejected: {}",
                    error_name(&e)
                )
            });
            let p = addr.payload();
            assert_eq!(p.address_version, ver, "{id}: version mismatch");
            assert_eq!(p.address_type as u8, at, "{id}: address_type mismatch");
            assert_eq!(p.network_id as u8, net, "{id}: network_id mismatch");
            assert_eq!(p.key_hash, key_hash, "{id}: key_hash mismatch");
            // canonical roundtrip
            let enc = addr
                .encode()
                .unwrap_or_else(|_| panic!("{id}: encode failed"));
            assert_eq!(enc, address, "{id}: canonical roundtrip failed");
            // payload 字段与 ADR 注册表一致
            assert_eq!(
                p.address_type,
                AddressType::UserAccount,
                "{id}: type registry"
            );
            assert!(
                matches!(
                    p.network_id,
                    NetworkId::Mainnet | NetworkId::Testnet | NetworkId::Devnet
                ),
                "{id}: network registry"
            );
            assert_eq!(p.address_version, ADDRESS_VERSION, "{id}: version registry");
        }
        // INVALID 向量由 address_vectors_reject_invalid 单独覆盖。
    }
}

#[test]
fn address_vectors_reject_invalid() {
    for &(id, json) in ADDRESS_VECTORS {
        let v: Value = serde_json::from_str(json).expect("valid json");
        if field(&v, "expected") != "INVALID" {
            continue;
        }
        let address = field(&v, "address");
        let expected_error = field(&v, "expected_error");
        match NovaAddress::decode(address) {
            Ok(_) => panic!("{id}: expected INVALID but decode accepted"),
            Err(e) => {
                let name = error_name(&e);
                assert_eq!(
                    name, expected_error,
                    "{id}: error category mismatch: expected {expected_error}, got {name}"
                );
            }
        }
    }
}
