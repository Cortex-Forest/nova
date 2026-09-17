//! 往返（roundtrip）与篡改检测：`json → build → genesis.bin → decode → validate` 必须成功；
//! **任意 1 字节篡改必须失败**。

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use nova_crypto::address::{AddressType, NetworkId, YazimaoAddress};
use nova_crypto::identity::{decode_genesis_bytes, validator_id};
use nova_crypto::key::KeyPair;
use nova_genesis_builder::emit::{BuildError, VerifyError};
use nova_genesis_builder::{build_artifacts, verify_artifacts};
use serde_json::{Value, json};

const CHAIN_ID: u64 = 2002;
const NETWORK_ID: u8 = 2;
const TIMESTAMP: u64 = 1_750_000_200;
const VALIDATOR_LIQUID: u128 = 20_000_000;
const VALIDATOR_BONDED: u128 = 10_000_000;
const TREASURY_LIQUID: u128 = 960_000_000;

struct Node {
    pubkey_hex: String,
    address: String,
}

fn make_node() -> Node {
    let kp = KeyPair::generate().expect("keypair generation");
    let pk = kp.verifying_key().to_bytes();
    let address = YazimaoAddress::from_verifying_key(
        kp.verifying_key(),
        AddressType::UserAccount,
        NetworkId::Testnet,
    )
    .expect("derive address")
    .encode()
    .expect("encode address");
    Node {
        pubkey_hex: hex32(&pk),
        address,
    }
}

fn valid_json(validators: &[Node], treasury: &Node) -> Value {
    let v: Vec<Value> = validators
        .iter()
        .map(|n| {
            json!({
                "account_address": n.address,
                "consensus_public_key": n.pubkey_hex,
                "bonded_stake": VALIDATOR_BONDED.to_string(),
                "commission_bps": 500,
            })
        })
        .collect();
    let mut accounts: Vec<Value> = validators
        .iter()
        .map(|n| json!({ "address": n.address, "liquid_balance": VALIDATOR_LIQUID.to_string() }))
        .collect();
    accounts.push(json!({
        "address": treasury.address,
        "liquid_balance": TREASURY_LIQUID.to_string(),
    }));

    json!({
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_timestamp": TIMESTAMP,
        "validators": v,
        "accounts": accounts,
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

/// canonical 布局长度：`1 + 8 + 8 + 4 + 85N + 4 + 51M + 40 + 42`（ADR-0015 §9）。
fn expected_len(n_validators: usize, n_accounts: usize) -> usize {
    1 + 8 + 8 + 4 + n_validators * 85 + 4 + n_accounts * 51 + 40 + 42
}

#[test]
fn build_then_decode_then_validate_roundtrip() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt");
    let report = build_artifacts(&input, &dir, false).expect("build");

    assert_eq!(report.chain_id, CHAIN_ID);
    assert_eq!(report.network_id, NETWORK_ID);
    assert_eq!(report.genesis_timestamp, TIMESTAMP);
    assert_eq!(report.validator_count, 2);
    assert_eq!(report.account_count, 3);
    assert_eq!(report.canonical_len, expected_len(2, 3));

    // hash 文件内容 = report hash + 换行。
    let hash_text = std::fs::read_to_string(&report.genesis_hash_file).expect("read hash");
    assert_eq!(hash_text, format!("{}\n", report.genesis_hash_hex));
    assert_eq!(hash_text.trim().len(), 64);

    // decode 回读：字段与输入一致。
    let bytes = std::fs::read(&report.genesis_bin).expect("read bin");
    let decoded = decode_genesis_bytes(&bytes).expect("decode canonical bytes");
    assert_eq!(decoded.chain_id, CHAIN_ID);
    assert_eq!(decoded.network_id.as_u8(), NETWORK_ID);
    assert_eq!(decoded.genesis_timestamp, TIMESTAMP);
    assert_eq!(decoded.initial_validator_set.len(), 2);
    assert_eq!(decoded.initial_accounts.len(), 3);
    assert_eq!(
        decoded.economics_parameters.total_supply,
        TREASURY_LIQUID + 2 * VALIDATOR_LIQUID
    );

    // canonical 顺序：validator_id 升序、地址 payload 升序（编码器会拒绝非序，这里再显式断言）。
    let ids: Vec<[u8; 32]> = decoded
        .initial_validator_set
        .iter()
        .map(|v| validator_id(&v.consensus_public_key))
        .collect();
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "validators must be in canonical (validator_id) order"
    );
    let payloads: Vec<[u8; 35]> = decoded
        .initial_accounts
        .iter()
        .map(|a| a.address.payload().to_bytes())
        .collect();
    assert!(
        payloads.windows(2).all(|w| w[0] < w[1]),
        "accounts must be in canonical (address payload) order"
    );

    // verify 模式：只读复核必须通过。
    let verified =
        verify_artifacts(&report.genesis_bin, &report.genesis_hash_file).expect("verify");
    assert_eq!(verified.genesis_hash_hex, report.genesis_hash_hex);
    assert_eq!(verified.chain_id, CHAIN_ID);
    assert_eq!(verified.network_id, NETWORK_ID);
    assert_eq!(verified.canonical_len, report.canonical_len);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_detects_single_byte_tamper_in_timestamp() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt-tamper-bin");
    let report = build_artifacts(&input, &dir, false).expect("build");

    let mut bytes = std::fs::read(&report.genesis_bin).expect("read bin");
    // offset 12 落在 genesis_timestamp（9..17，8B LE）内。
    bytes[12] ^= 0x01;
    std::fs::write(&report.genesis_bin, &bytes).expect("write tampered bin");

    let err = verify_artifacts(&report.genesis_bin, &report.genesis_hash_file)
        .expect_err("tampered genesis.bin must fail verification");
    assert!(
        matches!(err, VerifyError::Validation(_) | VerifyError::Decode(_)),
        "expected Validation/Decode failure, got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_detects_trailing_byte() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt-trailing");
    let report = build_artifacts(&input, &dir, false).expect("build");

    let mut bytes = std::fs::read(&report.genesis_bin).expect("read bin");
    bytes.push(0x00);
    std::fs::write(&report.genesis_bin, &bytes).expect("write bin with trailing byte");

    let err = verify_artifacts(&report.genesis_bin, &report.genesis_hash_file)
        .expect_err("trailing byte must fail verification");
    assert!(
        matches!(err, VerifyError::Decode(_)),
        "expected Decode failure (trailing bytes), got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_detects_hash_file_tamper() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt-tamper-hash");
    let report = build_artifacts(&input, &dir, false).expect("build");

    let mut hash = report.genesis_hash_hex.clone();
    // 翻转最后一个 hex 字符（保持格式合法，内容不同）。
    let last = hash.pop().expect("hash char");
    let flipped = if last == '0' { '1' } else { '0' };
    hash.push(flipped);
    std::fs::write(&report.genesis_hash_file, format!("{hash}\n")).expect("write tampered hash");

    let err = verify_artifacts(&report.genesis_bin, &report.genesis_hash_file)
        .expect_err("tampered genesis_hash.txt must fail verification");
    assert!(
        matches!(err, VerifyError::Validation(_)),
        "expected Validation (hash mismatch), got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_rejects_non_canonical_hash_file() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt-hash-format");
    let report = build_artifacts(&input, &dir, false).expect("build");

    // 大写 hex ⇒ 非 canonical（拒绝）。
    let upper = report.genesis_hash_hex.to_ascii_uppercase();
    std::fs::write(&report.genesis_hash_file, format!("{upper}\n")).expect("write uppercase hash");
    let err = verify_artifacts(&report.genesis_bin, &report.genesis_hash_file)
        .expect_err("uppercase hash must be rejected");
    assert!(
        matches!(err, VerifyError::HashFileFormat(_)),
        "expected HashFileFormat, got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_refuses_to_overwrite_existing_artifacts() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("rt-overwrite");
    build_artifacts(&input, &dir, false).expect("first build");
    let err = build_artifacts(&input, &dir, false).expect_err("second build must refuse");
    assert!(
        matches!(err, BuildError::ArtifactExists(_)),
        "expected ArtifactExists, got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
