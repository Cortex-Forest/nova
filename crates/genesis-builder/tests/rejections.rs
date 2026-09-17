//! 拒绝测试：**strict schema、敏感字段、缺字段、u128 编码、占位值、地址/公钥、唯一性、
//! 不变量、排序策略** 的完整覆盖。
//!
//! 每例都断言**具体错误类型**（不允许"失败即通过"的宽松断言）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use nova_crypto::address::{AddressType, NetworkId, YazimaoAddress};
use nova_crypto::identity::validator_id;
use nova_crypto::key::KeyPair;
use nova_crypto::signature::VerifyingKey;
use nova_genesis_builder::build_artifacts;
use nova_genesis_builder::emit::BuildError;
use nova_genesis_builder::input::InputError;
use nova_genesis_builder::normalize::DerivationError;
use nova_genesis_builder::preflight::PreflightError;
use serde_json::{Value, json};

const CHAIN_ID: u64 = 2002;
const TIMESTAMP: u64 = 1_750_000_200;

struct Node {
    pubkey_hex: String,
    address: String,
}

fn make_node_on(network: NetworkId) -> Node {
    let kp = KeyPair::generate().expect("keypair generation");
    let address =
        YazimaoAddress::from_verifying_key(kp.verifying_key(), AddressType::UserAccount, network)
            .expect("derive address")
            .encode()
            .expect("encode address");
    Node {
        pubkey_hex: hex32(&kp.verifying_key().to_bytes()),
        address,
    }
}

fn make_node() -> Node {
    make_node_on(NetworkId::Testnet)
}

/// 合法基线 JSON（2 validator + 1 treasury；Σ liquid = 1,000,000,000）。
fn baseline(v0: &Node, v1: &Node, treasury: &Node) -> Value {
    json!({
        "chain_id": CHAIN_ID,
        "network_id": 2,
        "genesis_timestamp": TIMESTAMP,
        "validators": [
            { "account_address": v0.address, "consensus_public_key": v0.pubkey_hex,
              "bonded_stake": "10000000", "commission_bps": 500 },
            { "account_address": v1.address, "consensus_public_key": v1.pubkey_hex,
              "bonded_stake": "10000000", "commission_bps": 500 },
        ],
        "accounts": [
            { "address": v0.address, "liquid_balance": "20000000" },
            { "address": v1.address, "liquid_balance": "20000000" },
            { "address": treasury.address, "liquid_balance": "960000000" },
        ],
        "protocol_params": {
            "max_tx_bytes": 65_536u32,
            "max_block_bytes": 1_048_576u32,
            "max_gas_per_block": 1_000_000_000u64,
            "max_contract_code_bytes": 32_768u32,
            "max_contract_storage_bytes": 1_048_576u32,
            "epoch_length_blocks": 100u64,
            "snapshot_interval_blocks": 1_000u64,
        },
        "economics_params": {
            "total_supply": "1000000000",
            "min_validator_stake": "1000000",
            "unbonding_period_seconds": 1_209_600u64,
            "fee_burn_bps": 0,
        },
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 0x0f)]));
    }
    out
}

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "nova-genesis-builder-{}-{tag}-{n}",
        std::process::id()
    ))
}

fn build(value: &Value, tag: &str) -> Result<nova_genesis_builder::BuildReport, BuildError> {
    build_artifacts(&value.to_string(), &temp_dir(tag), false)
}

fn expect_input(value: &Value, tag: &str) -> InputError {
    match build(value, tag) {
        Err(BuildError::Input(e)) => e,
        other => panic!("expected Input error, got {other:?}"),
    }
}

fn expect_preflight(value: &Value, tag: &str) -> PreflightError {
    match build(value, tag) {
        Err(BuildError::Preflight(e)) => e,
        other => panic!("expected Preflight error, got {other:?}"),
    }
}

fn with_field(value: &Value, key: &str, replacement: Value) -> Value {
    let mut v = value.clone();
    v[key] = replacement;
    v
}

// =========================================================================
// strict schema
// =========================================================================

#[test]
fn rejects_unknown_root_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["unexpected"] = json!(1);
    let err = expect_input(&value, "rej-unknown-root");
    assert!(
        matches!(&err, InputError::UnknownField { field, .. } if field.as_str() == "unexpected"),
        "got {err:?}"
    );
}

#[test]
fn rejects_unknown_nested_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["protocol_params"]["max_block_weight"] = json!(1);
    let err = expect_input(&value, "rej-unknown-nested");
    assert!(
        matches!(&err, InputError::UnknownField { field, .. } if field.as_str() == "max_block_weight"),
        "got {err:?}"
    );
}

#[test]
fn rejects_private_key_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["private_key"] = json!("0xdeadbeef");
    let err = expect_input(&value, "rej-private-key");
    assert!(
        matches!(&err, InputError::SensitiveField { field, .. } if field.as_str() == "private_key"),
        "got {err:?}"
    );
}

#[test]
fn rejects_nested_seed_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["seed"] = json!("abandon abandon");
    let err = expect_input(&value, "rej-nested-seed");
    assert!(
        matches!(&err, InputError::SensitiveField { field, .. } if field.as_str() == "seed"),
        "got {err:?}"
    );
}

#[test]
fn rejects_mnemonic_and_keystore_fields() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    for field in ["mnemonic", "keystore", "secret"] {
        let mut value = baseline(&v0, &v1, &t);
        value[field] = json!("x");
        let err = expect_input(&value, field);
        assert!(
            matches!(err, InputError::SensitiveField { .. }),
            "field {field}: got {err:?}"
        );
    }
}

#[test]
fn rejects_missing_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value
        .as_object_mut()
        .expect("object")
        .remove("genesis_timestamp");
    let err = expect_input(&value, "rej-missing");
    assert!(
        matches!(&err, InputError::MissingField { field, .. } if *field == "genesis_timestamp"),
        "got {err:?}"
    );
}

// =========================================================================
// u128 编码（只接受十进制字符串）
// =========================================================================

#[test]
fn rejects_u128_as_number() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["bonded_stake"] = json!(10_000_000u64);
    let err = expect_input(&value, "rej-u128-number");
    assert!(
        matches!(err, InputError::NotADecimalString { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_u128_float_and_exponent() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    for raw in [json!("10000000.0"), json!("1e7"), json!(1e7_f64)] {
        let mut value = baseline(&v0, &v1, &t);
        value["validators"][0]["bonded_stake"] = raw.clone();
        let err = expect_input(&value, "rej-u128-float");
        assert!(
            matches!(err, InputError::NotADecimalString { .. }),
            "raw {raw}: got {err:?}"
        );
    }
}

#[test]
fn rejects_u128_leading_zero_and_sign() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    for raw in ["01000000", "+10000000", "-10000000"] {
        let mut value = baseline(&v0, &v1, &t);
        value["validators"][0]["bonded_stake"] = json!(raw);
        let err = expect_input(&value, "rej-u128-canonical");
        assert!(
            matches!(
                err,
                InputError::NonCanonicalDecimal { .. } | InputError::NotADecimalString { .. }
            ),
            "raw `{raw}`: got {err:?}"
        );
    }
}

#[test]
fn rejects_placeholder_values() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    for raw in [json!("TBD"), json!("PENDING"), json!("pending"), json!("")] {
        let mut value = baseline(&v0, &v1, &t);
        value["validators"][0]["bonded_stake"] = raw.clone();
        let err = expect_input(&value, "rej-placeholder");
        assert!(
            matches!(err, InputError::PlaceholderValue { .. }),
            "raw {raw}: got {err:?}"
        );
    }
}

#[test]
fn rejects_float_in_integer_field() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["chain_id"] = json!(2002.0);
    let err = expect_input(&value, "rej-int-float");
    assert!(
        matches!(err, InputError::NotAnInteger { .. }),
        "got {err:?}"
    );
}

// =========================================================================
// 地址 / 公钥
// =========================================================================

#[test]
fn rejects_bad_address_checksum_and_case() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());

    // 校验和破坏
    let mut broken = baseline(&v0, &v1, &t);
    let mut addr = v0.address.clone();
    let last = addr.pop().expect("char");
    addr.push(if last == 'q' { 'p' } else { 'q' });
    broken["validators"][0]["account_address"] = json!(addr);
    let err = expect_input(&broken, "rej-addr-checksum");
    assert!(
        matches!(err, InputError::InvalidAddress { .. }),
        "got {err:?}"
    );

    // 大写（非 canonical）
    let mut upper = baseline(&v0, &v1, &t);
    upper["validators"][0]["account_address"] = json!(v0.address.to_ascii_uppercase());
    let err = expect_input(&upper, "rej-addr-upper");
    assert!(
        matches!(err, InputError::InvalidAddress { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_address_from_other_network() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let devnet = make_node_on(NetworkId::Devnet);
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["account_address"] = json!(devnet.address);
    value["validators"][0]["consensus_public_key"] = json!(devnet.pubkey_hex);
    let err = expect_input(&value, "rej-addr-network");
    assert!(
        matches!(err, InputError::AddressNetworkMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_bad_public_key_hex() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    for bad in ["abcd", v0.pubkey_hex.to_ascii_uppercase().as_str()] {
        let mut value = baseline(&v0, &v1, &t);
        value["validators"][0]["consensus_public_key"] = json!(bad);
        let err = expect_input(&value, "rej-pubkey-hex");
        assert!(
            matches!(err, InputError::InvalidHex { .. }),
            "bad `{bad}`: got {err:?}"
        );
    }
}

#[test]
fn rejects_public_key_inconsistent_with_address() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    // 公钥被替换成 "ff"×32（dalek 宽松解码可接受该点），地址仍来自 v0
    // ⇒ 必须在 preflight 的派生一致性检查处被拒绝（不得产出地址与公钥无派生关系的 Genesis）。
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["consensus_public_key"] = json!("ff".repeat(32));
    let err = expect_preflight(&value, "rej-pubkey-derivation");
    assert!(
        matches!(
            err,
            PreflightError::Derivation(DerivationError::Mismatch { .. })
        ),
        "got {err:?}"
    );
}

#[test]
fn rejects_non_canonical_public_key_encoding() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());

    // 非 canonical 编码：Y = p + 1 ≡ 1 (mod p)（LE：ee ff…ff 7f）。
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;

    // 地址从**同一字节串**派生 ⇒ 通过派生一致性，使错误精确定位到"非 canonical 公钥编码"。
    let vk_nc = VerifyingKey::from_bytes(&non_canonical).expect("lenient Ed25519 decode");
    let address_nc =
        YazimaoAddress::from_verifying_key(&vk_nc, AddressType::UserAccount, NetworkId::Testnet)
            .expect("derive")
            .encode()
            .expect("encode");

    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["account_address"] = json!(address_nc.clone());
    // 账户表同步替换（保持 Σ liquid 不变）。
    value["accounts"][0]["address"] = json!(address_nc);
    value["validators"][0]["consensus_public_key"] = json!(hex32(&non_canonical));

    let err = build(&value, "rej-pubkey-noncanonical")
        .expect_err("non-canonical public key encoding must be rejected");
    assert!(
        matches!(
            err,
            BuildError::Genesis(_) | BuildError::Input(InputError::InvalidPublicKey { .. })
        ),
        "expected Genesis(decode) or Input(InvalidPublicKey), got {err:?}"
    );
}

#[test]
fn rejects_address_public_key_derivation_mismatch() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    // 地址换成 treasury（存在且余额充足），但公钥仍是 v0 的 ⇒ 派生不一致必须被拦截。
    value["validators"][0]["account_address"] = json!(t.address);
    let err = expect_preflight(&value, "rej-derivation");
    assert!(
        matches!(
            err,
            PreflightError::Derivation(DerivationError::Mismatch { .. })
        ),
        "got {err:?}"
    );
}

// =========================================================================
// 唯一性 / 不变量
// =========================================================================

#[test]
fn rejects_duplicate_account_address() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["accounts"][2]["address"] = json!(v0.address);
    let err = expect_preflight(&value, "rej-dup-account");
    assert!(
        matches!(err, PreflightError::DuplicateAccountAddress { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_duplicate_consensus_public_key() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][1]["consensus_public_key"] = json!(v0.pubkey_hex);
    let err = expect_preflight(&value, "rej-dup-pubkey");
    assert!(
        matches!(
            err,
            PreflightError::DuplicateConsensusPublicKey { .. }
                | PreflightError::DuplicateValidatorAccount { .. }
                | PreflightError::Derivation(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn rejects_validator_account_missing_from_accounts() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    // 移除 v1 的账户条目，并同步供应量，使错误精确定位到 validator 账户缺失。
    value["accounts"].as_array_mut().expect("array").remove(1);
    value["economics_params"]["total_supply"] = json!("980000000");
    let err = expect_preflight(&value, "rej-missing-validator-account");
    assert!(
        matches!(err, PreflightError::ValidatorAccountMissing { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_stake_exceeding_liquid() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["bonded_stake"] = json!("25000000"); // > liquid 20,000,000
    let err = expect_preflight(&value, "rej-stake-over");
    assert!(
        matches!(err, PreflightError::StakeExceedsBalance { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_stake_below_minimum() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["economics_params"]["min_validator_stake"] = json!("20000000"); // == liquid > bonded
    let err = expect_preflight(&value, "rej-stake-under");
    assert!(
        matches!(err, PreflightError::StakeBelowMinimum { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_commission_out_of_range() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["validators"][0]["commission_bps"] = json!(10_001u32);
    let err = expect_preflight(&value, "rej-commission");
    assert!(
        matches!(
            err,
            PreflightError::CommissionOutOfRange { value: 10_001, .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn rejects_supply_mismatch() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let mut value = baseline(&v0, &v1, &t);
    value["economics_params"]["total_supply"] = json!("999999999");
    let err = expect_preflight(&value, "rej-supply");
    assert!(
        matches!(err, PreflightError::SupplyMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_zero_chain_id() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let value = with_field(&baseline(&v0, &v1, &t), "chain_id", json!(0));
    let err = expect_preflight(&value, "rej-chain-zero");
    assert!(matches!(err, PreflightError::ZeroChainId), "got {err:?}");
}

#[test]
fn rejects_zero_timestamp() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let value = with_field(&baseline(&v0, &v1, &t), "genesis_timestamp", json!(0));
    let err = expect_preflight(&value, "rej-ts-zero");
    assert!(matches!(err, PreflightError::ZeroTimestamp), "got {err:?}");
}

#[test]
fn rejects_unregistered_network_id() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let value = with_field(&baseline(&v0, &v1, &t), "network_id", json!(4));
    let err = expect_input(&value, "rej-network");
    assert!(
        matches!(err, InputError::InvalidNetworkId { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_empty_validator_or_account_list() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let empty_v = with_field(&baseline(&v0, &v1, &t), "validators", json!([]));
    assert!(matches!(
        expect_preflight(&empty_v, "rej-empty-v"),
        PreflightError::EmptyValidators
    ));

    let empty_a = with_field(&baseline(&v0, &v1, &t), "accounts", json!([]));
    assert!(matches!(
        expect_preflight(&empty_a, "rej-empty-a"),
        PreflightError::EmptyAccounts
    ));
}

// =========================================================================
// 排序策略：AUTO SORT + REPORT（不静默、不阻断）
// =========================================================================

#[test]
fn auto_sorts_and_reports_reordering() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());

    // 构造逆序输入：validator 按 validator_id 降序、account 按 payload 降序。
    let id_a = validator_id(&hex_to_32(&v0.pubkey_hex));
    let id_b = validator_id(&hex_to_32(&v1.pubkey_hex));
    let (first, second) = if id_a > id_b { (&v0, &v1) } else { (&v1, &v0) };

    let reversed = json!({
        "chain_id": CHAIN_ID,
        "network_id": 2,
        "genesis_timestamp": TIMESTAMP,
        "validators": [
            { "account_address": first.address, "consensus_public_key": first.pubkey_hex,
              "bonded_stake": "10000000", "commission_bps": 500 },
            { "account_address": second.address, "consensus_public_key": second.pubkey_hex,
              "bonded_stake": "10000000", "commission_bps": 500 },
        ],
        "accounts": descending_accounts(&[(&t.address, "960000000"), (&first.address, "20000000"), (&second.address, "20000000")]),
        "protocol_params": {
            "max_tx_bytes": 65_536u32,
            "max_block_bytes": 1_048_576u32,
            "max_gas_per_block": 1_000_000_000u64,
            "max_contract_code_bytes": 32_768u32,
            "max_contract_storage_bytes": 1_048_576u32,
            "epoch_length_blocks": 100u64,
            "snapshot_interval_blocks": 1_000u64,
        },
        "economics_params": {
            "total_supply": "1000000000",
            "min_validator_stake": "1000000",
            "unbonding_period_seconds": 1_209_600u64,
            "fee_burn_bps": 0,
        },
    });

    let report = build_artifacts(&reversed.to_string(), &temp_dir("sort-report"), false)
        .expect("auto sort must succeed");

    assert!(
        report.reorder.validators_reordered,
        "validators must be reported as reordered"
    );
    assert!(
        report.reorder.accounts_reordered,
        "accounts must be reported as reordered"
    );
    assert!(report.reorder.any_reordered());
    assert_eq!(report.reorder.validators.len(), 2);
    assert_eq!(report.reorder.accounts.len(), 3);

    // 映射必须是双射：canonical_index 连续且 original_index 各不同。
    let mut originals: Vec<usize> = report
        .reorder
        .validators
        .iter()
        .map(|e| e.original_index)
        .collect();
    originals.sort_unstable();
    assert_eq!(originals, vec![0, 1]);
    for (i, e) in report.reorder.validators.iter().enumerate() {
        assert_eq!(e.canonical_index, i, "canonical_index must be sequential");
        assert_eq!(e.key_hex.len(), 64, "validator key is validator_id hex");
    }
    for (i, e) in report.reorder.accounts.iter().enumerate() {
        assert_eq!(e.canonical_index, i);
        assert_eq!(e.key_hex.len(), 70, "account key is 35B payload hex");
    }
}

#[test]
fn already_canonical_input_is_not_reported_as_reordered() {
    let (v0, v1, t) = (make_node(), make_node(), make_node());
    let id_a = validator_id(&hex_to_32(&v0.pubkey_hex));
    let id_b = validator_id(&hex_to_32(&v1.pubkey_hex));
    let (first, second) = if id_a < id_b { (&v0, &v1) } else { (&v1, &v0) };

    let mut value = baseline(&v0, &v1, &t);
    value["validators"] = json!([
        { "account_address": first.address, "consensus_public_key": first.pubkey_hex,
          "bonded_stake": "10000000", "commission_bps": 500 },
        { "account_address": second.address, "consensus_public_key": second.pubkey_hex,
          "bonded_stake": "10000000", "commission_bps": 500 },
    ]);
    let mut accounts = vec![
        json!({ "address": first.address, "liquid_balance": "20000000" }),
        json!({ "address": second.address, "liquid_balance": "20000000" }),
        json!({ "address": t.address, "liquid_balance": "960000000" }),
    ];
    accounts.sort_by_key(|a| payload_of(a["address"].as_str().expect("addr")));
    value["accounts"] = json!(accounts);

    let report = build_artifacts(&value.to_string(), &temp_dir("sort-none"), false)
        .expect("canonical input must succeed");
    assert!(!report.reorder.validators_reordered);
    assert!(!report.reorder.accounts_reordered);
}

fn hex_to_32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("utf8");
        out[i] = u8::from_str_radix(s, 16).expect("hex");
    }
    out
}

fn payload_of(addr: &str) -> [u8; 35] {
    YazimaoAddress::decode(addr)
        .expect("decode address")
        .payload()
        .to_bytes()
}

/// 构造**确定性的逆 canonical** 账户列表（按 payload 降序）。
fn descending_accounts(entries: &[(&str, &str)]) -> Value {
    let mut items: Vec<(&str, &str)> = entries.to_vec();
    items.sort_by_key(|(addr, _)| std::cmp::Reverse(payload_of(addr)));
    json!(
        items
            .iter()
            .map(|(addr, balance)| json!({ "address": addr, "liquid_balance": balance }))
            .collect::<Vec<_>>()
    )
}
