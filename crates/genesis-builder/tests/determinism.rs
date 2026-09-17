//! 确定性测试：**同一输入两次生成 ⇒ 字节完全一致**（canonical + 摘要）。
//!
//! 为什么重要：`genesis_hash` 是链身份锚点，一旦分发即不可漂移。任何非确定性
//! （字段顺序、时间戳、主机路径、哈希随机化）都会让"两次生成得到两个链身份"。

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use nova_crypto::address::{AddressType, NetworkId, YazimaoAddress};
use nova_crypto::key::KeyPair;
use nova_genesis_builder::build_artifacts;
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
    let address = YazimaoAddress::from_verifying_key(
        kp.verifying_key(),
        AddressType::UserAccount,
        NetworkId::Testnet,
    )
    .expect("derive address")
    .encode()
    .expect("encode address");
    Node {
        pubkey_hex: hex32(&kp.verifying_key().to_bytes()),
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

fn read(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn same_input_twice_is_byte_identical() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let d1 = temp_dir("det-a");
    let d2 = temp_dir("det-b");

    let r1 = build_artifacts(&input, &d1, false).expect("first build");
    let r2 = build_artifacts(&input, &d2, false).expect("second build");

    assert_eq!(r1.genesis_hash_hex, r2.genesis_hash_hex, "hash must match");
    assert_eq!(r1.canonical_len, r2.canonical_len, "length must match");
    assert_eq!(
        read(&r1.genesis_bin),
        read(&r2.genesis_bin),
        "genesis.bin must be byte-identical"
    );
    assert_eq!(
        read(&r1.genesis_hash_file),
        read(&r2.genesis_hash_file),
        "genesis_hash.txt must be byte-identical"
    );
    assert_eq!(
        read(&r1.genesis_summary_file),
        read(&r2.genesis_summary_file),
        "genesis_summary.json must be byte-identical"
    );

    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn force_overwrite_same_dir_is_byte_identical() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("det-force");
    let r1 = build_artifacts(&input, &dir, false).expect("first build");
    let before = read(&r1.genesis_bin);

    // 未指定 --force ⇒ 拒绝覆盖。
    let err = build_artifacts(&input, &dir, false).expect_err("must refuse overwrite");
    assert!(
        matches!(
            err,
            nova_genesis_builder::emit::BuildError::ArtifactExists(_)
        ),
        "expected ArtifactExists, got {err:?}"
    );

    let r2 = build_artifacts(&input, &dir, true).expect("forced rebuild");
    assert_eq!(r1.genesis_hash_hex, r2.genesis_hash_hex);
    assert_eq!(before, read(&r2.genesis_bin));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn summary_carries_owner_timestamp_and_no_generated_clock_field() {
    let v0 = make_node();
    let v1 = make_node();
    let treasury = make_node();
    let input = valid_json(&[v0, v1], &treasury).to_string();

    let dir = temp_dir("det-summary");
    let report = build_artifacts(&input, &dir, false).expect("build");
    let text = std::fs::read_to_string(&report.genesis_summary_file).expect("read summary");

    // 摘要必须回显 Owner 提供的时间戳（而非"生成时刻"）。
    assert!(
        text.contains(&TIMESTAMP.to_string()),
        "summary must echo owner-provided genesis_timestamp"
    );
    assert!(
        !text.contains("generated_at"),
        "summary must not embed a wall clock"
    );
    assert!(!text.contains("temp"), "summary must not embed host paths");
    assert!(
        !text.contains("genesis.json"),
        "summary must not embed input paths"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
