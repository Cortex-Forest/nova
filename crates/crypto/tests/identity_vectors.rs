//! STEP 6A：接入 Genesis 向量，验证 `nova_crypto::identity` 的
//! `canonical_genesis_bytes` / `compute_genesis_hash` 与回填的 `expected_genesis_hash` 完全一致。
//!
//! - valid 向量：`computed == expected`。
//! - tampered / wrong-genesis-hash：`computed != expected`（篡改/错误 hash 检测）。
//! - 向量文件 `include_str!` 内嵌（确定性）。

use nova_crypto::address::{NetworkId, NovaAddress};
use nova_crypto::hash::protocol_hash;
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
};
use serde_json::Value;

const VALID_VECTORS: &[(&str, &str)] = &[
    (
        "genesis-mainnet-valid-001",
        include_str!("../../../tests/vectors/genesis/genesis-mainnet-valid-001.json"),
    ),
    (
        "genesis-testnet-valid-001",
        include_str!("../../../tests/vectors/genesis/genesis-testnet-valid-001.json"),
    ),
    (
        "genesis-devnet-valid-001",
        include_str!("../../../tests/vectors/genesis/genesis-devnet-valid-001.json"),
    ),
];

const MISMATCH_VECTORS: &[(&str, &str)] = &[
    (
        "genesis-tampered-genesis-001",
        include_str!("../../../tests/vectors/genesis/genesis-tampered-genesis-001.json"),
    ),
    (
        "genesis-wrong-genesis-hash-001",
        include_str!("../../../tests/vectors/genesis/genesis-wrong-genesis-hash-001.json"),
    ),
];

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn u128_str(v: &Value, key: &str) -> u128 {
    v.get(key)
        .and_then(Value::as_str)
        .expect("u128 str")
        .parse::<u128>()
        .expect("u128 parse")
}

/// 从向量 JSON 构造 `GenesisV1`（本地解析；仅结构，语义由测试断言）。
fn json_to_genesis(v: &Value) -> GenesisV1 {
    let net = v["network_id"].as_u64().unwrap() as u8;
    let network_id = NetworkId::try_from(net).expect("network");
    let validators = v["initial_validator_set"]
        .as_array()
        .expect("vals")
        .iter()
        .map(|item| {
            let addr =
                NovaAddress::decode(item["account_address"].as_str().unwrap()).expect("addr");
            let pk = decode_hex(item["consensus_public_key"].as_str().unwrap());
            assert_eq!(pk.len(), 32);
            let mut consensus_public_key = [0u8; 32];
            consensus_public_key.copy_from_slice(&pk);
            ValidatorInit {
                account_address: addr,
                consensus_public_key,
                bonded_stake: u128_str(item, "bonded_stake"),
                commission_bps: item["commission_bps"].as_u64().unwrap() as u16,
            }
        })
        .collect();
    let accounts = v["initial_accounts"]
        .as_array()
        .expect("accs")
        .iter()
        .map(|item| AccountInit {
            address: NovaAddress::decode(item["address"].as_str().unwrap()).expect("addr"),
            liquid_balance: u128_str(item, "liquid_balance"),
        })
        .collect();
    let pp = &v["protocol_parameters"];
    let ep = &v["economics_parameters"];
    GenesisV1 {
        network_id,
        chain_id: v["chain_id"].as_u64().unwrap(),
        genesis_timestamp: v["genesis_timestamp"].as_u64().unwrap(),
        initial_validator_set: validators,
        initial_accounts: accounts,
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: pp["max_tx_bytes"].as_u64().unwrap() as u32,
            max_block_bytes: pp["max_block_bytes"].as_u64().unwrap() as u32,
            max_gas_per_block: pp["max_gas_per_block"].as_u64().unwrap(),
            max_contract_code_bytes: pp["max_contract_code_bytes"].as_u64().unwrap() as u32,
            max_contract_storage_bytes: pp["max_contract_storage_bytes"].as_u64().unwrap() as u32,
            epoch_length_blocks: pp["epoch_length_blocks"].as_u64().unwrap(),
            snapshot_interval_blocks: pp["snapshot_interval_blocks"].as_u64().unwrap(),
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: u128_str(ep, "total_supply"),
            min_validator_stake: u128_str(ep, "min_validator_stake"),
            unbonding_period_seconds: ep["unbonding_period_seconds"].as_u64().unwrap(),
            fee_burn_bps: ep["fee_burn_bps"].as_u64().unwrap() as u16,
        },
    }
}

#[test]
fn valid_vectors_hash_match() {
    for &(id, json) in VALID_VECTORS {
        let v: Value = serde_json::from_str(json).expect("json");
        let g = json_to_genesis(&v);
        let computed = nova_crypto::identity::compute_genesis_hash(&g)
            .unwrap_or_else(|e| panic!("{id}: compute failed: {e}"));
        let expected = v["expected_genesis_hash"].as_str().unwrap();
        assert!(!expected.is_empty(), "{id}: expected_genesis_hash 未回填");
        assert_eq!(
            hex(&computed),
            expected,
            "{id}: computed genesis_hash != vector expected"
        );
        // canonical 字节确定性：两次计算一致
        let again = nova_crypto::identity::compute_genesis_hash(&g).unwrap();
        assert_eq!(computed, again, "{id}: hash not deterministic");
    }
    assert_eq!(VALID_VECTORS.len(), 3);
}

#[test]
fn tampered_and_wrong_hash_mismatch() {
    for &(id, json) in MISMATCH_VECTORS {
        let v: Value = serde_json::from_str(json).expect("json");
        let g = json_to_genesis(&v);
        let computed = nova_crypto::identity::compute_genesis_hash(&g)
            .unwrap_or_else(|e| panic!("{id}: compute failed: {e}"));
        let expected = v["expected_genesis_hash"].as_str().unwrap();
        assert!(!expected.is_empty(), "{id}: expected_genesis_hash 未设置");
        assert_ne!(
            hex(&computed),
            expected,
            "{id}: 预期 computed != configured（篡改/错误 hash 检测）"
        );
    }
    assert_eq!(MISMATCH_VECTORS.len(), 2);
}

#[test]
fn tampered_changes_hash_from_original() {
    // 篡改向量与 mainnet valid 结构相同，仅 timestamp 不同 ⇒ hash 必须不同。
    let orig: Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/genesis/genesis-mainnet-valid-001.json"
    ))
    .expect("json");
    let tampered: Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/genesis/genesis-tampered-genesis-001.json"
    ))
    .expect("json");
    let g0 = json_to_genesis(&orig);
    let gt = json_to_genesis(&tampered);
    assert_ne!(g0.genesis_timestamp, gt.genesis_timestamp);
    let h0 = nova_crypto::identity::compute_genesis_hash(&g0).unwrap();
    let ht = nova_crypto::identity::compute_genesis_hash(&gt).unwrap();
    assert_ne!(h0, ht, "篡改 timestamp 必须改变 genesis_hash");
    // tampered 向量的 configured hash 应等于原 mainnet hash（篡改后不匹配）。
    assert_eq!(
        tampered["expected_genesis_hash"].as_str().unwrap(),
        hex(&h0)
    );
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 验证 canonical bytes 遵循冻结布局（ADR-0015）：mainnet 样本长度。
#[test]
fn canonical_layout_length() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/genesis/genesis-mainnet-valid-001.json"
    ))
    .expect("json");
    let g = json_to_genesis(&v);
    let n_val = g.initial_validator_set.len();
    let n_acc = g.initial_accounts.len();
    let bytes = nova_crypto::identity::canonical_genesis_bytes(&g).unwrap();
    let expected_len = 1 + 8 + 8 + 4 + n_val * 85 + 4 + n_acc * 51 + 40 + 42;
    assert_eq!(bytes.len(), expected_len, "canonical layout length");
    // 注意：validator_id = SHA-256(pubkey) 不单独编码为 Genesis 字段（类型结构保证）；
    // 但若地址从同一公钥派生（key_hash = SHA-256(pubkey)），validator_id 会以地址 key_hash
    // 形式出现 —— 这是设计使然，不是显式存储 validator_id。
    for val in &g.initial_validator_set {
        let expected_vid = protocol_hash(&val.consensus_public_key);
        assert_eq!(expected_vid, val.account_address.payload().key_hash);
    }
}
