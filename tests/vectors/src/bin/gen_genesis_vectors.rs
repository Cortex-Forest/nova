//! 生成器（一次性开发工具）：生成**真实 Genesis 向量 fixture**（STEP 6 schema 冻结）。
//!
//! - 地址：用 `nova_crypto::address` 从**真实 Ed25519 公钥**派生（key_hash=SHA-256(pubkey)，
//!   符合"地址必须从公钥派生"纪律）。
//! - validator 排序：按 `validator_id = SHA-256(consensus_public_key)` 升序（ADR-0015）。
//! - account 排序：按地址 35B payload raw bytes 升序（ADR-0015）。
//! - 本工具**不含生产 canonical 编码实现**；`expected_genesis_hash` 留空（DEFERRED，
//!   STEP 6 IMPLEMENTATION 后回填）。
//! - 运行：`cargo run -p nova-test-vectors --bin gen_genesis_vectors`（一次性，固化后不再重跑）。

use nova_crypto::address::{AddressType, NetworkId, NovaAddress};
use nova_crypto::hash::protocol_hash;
use nova_crypto::key::KeyPair;
use nova_test_vectors::hex;
use serde_json::{Value, json};

#[derive(Clone)]
struct ProtocolParams {
    max_tx_bytes: u32,
    max_block_bytes: u32,
    max_gas_per_block: u64,
    max_contract_code_bytes: u32,
    max_contract_storage_bytes: u32,
    epoch_length_blocks: u64,
    snapshot_interval_blocks: u64,
}

impl ProtocolParams {
    fn v1() -> Self {
        Self {
            max_tx_bytes: 65_536,
            max_block_bytes: 1_048_576,
            max_gas_per_block: 1_000_000_000,
            max_contract_code_bytes: 32_768,
            max_contract_storage_bytes: 1_048_576,
            epoch_length_blocks: 100,
            snapshot_interval_blocks: 1_000,
        }
    }
    fn to_json(&self) -> Value {
        json!({
            "max_tx_bytes": self.max_tx_bytes,
            "max_block_bytes": self.max_block_bytes,
            "max_gas_per_block": self.max_gas_per_block,
            "max_contract_code_bytes": self.max_contract_code_bytes,
            "max_contract_storage_bytes": self.max_contract_storage_bytes,
            "epoch_length_blocks": self.epoch_length_blocks,
            "snapshot_interval_blocks": self.snapshot_interval_blocks,
        })
    }
}

fn addr_from_kp(kp: &KeyPair, net: NetworkId) -> NovaAddress {
    NovaAddress::from_verifying_key(kp.verifying_key(), AddressType::UserAccount, net)
        .expect("addr from key")
}

/// 地址的 35B payload bytes（account 排序键，ADR-0015）。
fn payload_bytes(addr: &NovaAddress) -> Vec<u8> {
    let p = addr.payload();
    let mut b = vec![p.address_version, p.address_type as u8, p.network_id as u8];
    b.extend_from_slice(&p.key_hash);
    b
}

fn write_vector(base: &std::path::Path, id: &str, v: Value) {
    let path = base.join(format!("{id}.json"));
    let out = serde_json::to_string_pretty(&v).expect("json");
    std::fs::write(&path, format!("{out}\n")).expect("write");
    println!("wrote: {}", path.display());
}

/// 单个网络的 Genesis 配置参数（build_network 输入）。
struct NetParams {
    net: NetworkId,
    net_id: u8,
    chain_id: u64,
    ts: u64,
    stake1: u128,
    liq1: u128,
    comm1: u16,
    stake2: u128,
    liq2: u128,
    comm2: u16,
    extra_liq: u128,
    total: u128,
    min_stake: u128,
    unbond: u64,
    burn: u16,
}

/// 构造一个网络的完整 valid genesis 向量（含排序后的 validator/account 列表）。
fn build_network(p: &NetParams) -> Value {
    let vk1 = KeyPair::generate().expect("kp1");
    let vk2 = KeyPair::generate().expect("kp2");
    let extra = KeyPair::generate().expect("kp3");
    let a1 = addr_from_kp(&vk1, p.net);
    let a2 = addr_from_kp(&vk2, p.net);
    let ae = addr_from_kp(&extra, p.net);

    // validator 按 validator_id（SHA-256(pubkey)）升序。
    let mut vals = vec![
        (
            protocol_hash(&vk1.verifying_key().to_bytes()),
            a1,
            hex::encode_lower_hex(&vk1.verifying_key().to_bytes()),
            p.stake1,
            p.comm1,
            p.liq1,
        ),
        (
            protocol_hash(&vk2.verifying_key().to_bytes()),
            a2,
            hex::encode_lower_hex(&vk2.verifying_key().to_bytes()),
            p.stake2,
            p.comm2,
            p.liq2,
        ),
    ];
    vals.sort_by_key(|v| v.0);
    let validators: Vec<Value> = vals
        .into_iter()
        .map(|(_, addr, pk, stake, comm, _)| {
            json!({
                "account_address": addr.encode().expect("addr"),
                "consensus_public_key": pk,
                "bonded_stake": stake.to_string(),
                "commission_bps": comm,
            })
        })
        .collect();

    // account 按 35B payload bytes 升序。
    let mut accs = vec![
        (payload_bytes(&a1), a1, p.liq1),
        (payload_bytes(&a2), a2, p.liq2),
        (payload_bytes(&ae), ae, p.extra_liq),
    ];
    accs.sort_by(|x, y| x.0.cmp(&y.0));
    let accounts: Vec<Value> = accs
        .into_iter()
        .map(|(_, addr, liq)| {
            json!({
                "address": addr.encode().expect("addr"),
                "liquid_balance": liq.to_string(),
            })
        })
        .collect();

    json!({
        "network_id": p.net_id,
        "chain_id": p.chain_id,
        "genesis_timestamp": p.ts,
        "initial_validator_set": validators,
        "initial_accounts": accounts,
        "protocol_parameters": ProtocolParams::v1().to_json(),
        "economics_parameters": json!({
            "total_supply": p.total.to_string(),
            "min_validator_stake": p.min_stake.to_string(),
            "unbonding_period_seconds": p.unbond,
            "fee_burn_bps": p.burn,
        }),
    })
}

fn with_meta(
    id: &str,
    expected: &str,
    expected_error: Option<&str>,
    note: &str,
    body: Value,
) -> Value {
    let mut v = body;
    v["id"] = json!(id);
    v["category"] = json!("genesis");
    v["expected"] = json!(expected);
    v["expected_error"] = match expected_error {
        Some(e) => json!(e),
        None => Value::Null,
    };
    v["expected_genesis_hash"] = json!("");
    v["note"] = json!(note);
    v
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("genesis");

    // ---- VALID 三网络 ----
    let mainnet = build_network(&NetParams {
        net: NetworkId::Mainnet,
        net_id: 0x01,
        chain_id: 1001,
        ts: 1_750_000_000,
        stake1: 1_000_000,
        liq1: 2_000_000,
        comm1: 1000,
        stake2: 800_000,
        liq2: 1_500_000,
        comm2: 800,
        extra_liq: 3_000_000,
        total: 6_500_000,
        min_stake: 100_000,
        unbond: 1_209_600,
        burn: 500,
    });
    let testnet = build_network(&NetParams {
        net: NetworkId::Testnet,
        net_id: 0x02,
        chain_id: 2002,
        ts: 1_750_000_100,
        stake1: 500_000,
        liq1: 1_000_000,
        comm1: 1000,
        stake2: 400_000,
        liq2: 800_000,
        comm2: 800,
        extra_liq: 1_200_000,
        total: 3_000_000,
        min_stake: 50_000,
        unbond: 604_800,
        burn: 500,
    });
    let devnet = build_network(&NetParams {
        net: NetworkId::Devnet,
        net_id: 0x03,
        chain_id: 3003,
        ts: 1_750_000_200,
        stake1: 300_000,
        liq1: 700_000,
        comm1: 1000,
        stake2: 200_000,
        liq2: 500_000,
        comm2: 800,
        extra_liq: 800_000,
        total: 2_000_000,
        min_stake: 30_000,
        unbond: 86_400,
        burn: 500,
    });

    write_vector(
        &base,
        "genesis-mainnet-valid-001",
        with_meta(
            "genesis-mainnet-valid-001",
            "VALID",
            None,
            "mainnet valid genesis (nova1, chain_id=1001)",
            mainnet.clone(),
        ),
    );
    write_vector(
        &base,
        "genesis-testnet-valid-001",
        with_meta(
            "genesis-testnet-valid-001",
            "VALID",
            None,
            "testnet valid genesis (novat1, chain_id=2002)",
            testnet.clone(),
        ),
    );
    write_vector(
        &base,
        "genesis-devnet-valid-001",
        with_meta(
            "genesis-devnet-valid-001",
            "VALID",
            None,
            "devnet valid genesis (novad1, chain_id=3003)",
            devnet.clone(),
        ),
    );

    // ---- INVALID（从 mainnet 派生）----
    let inv = mainnet.clone();

    // invalid-network：network_id=0x04 未注册（地址仍是 nova1 → 网络不一致亦触发）
    let mut v = inv.clone();
    v["network_id"] = json!(0x04);
    write_vector(
        &base,
        "genesis-invalid-network-001",
        with_meta(
            "genesis-invalid-network-001",
            "INVALID",
            Some("InvalidNetwork"),
            "network_id=0x04 未注册（ADR-0011）",
            v,
        ),
    );

    // invalid-chain-id：chain_id=0（未配置哨兵）
    let mut v = inv.clone();
    v["chain_id"] = json!(0);
    write_vector(
        &base,
        "genesis-invalid-chain-id-001",
        with_meta(
            "genesis-invalid-chain-id-001",
            "INVALID",
            Some("InvalidChainId"),
            "chain_id=0 非法（须 > 0）",
            v,
        ),
    );

    // invalid-timestamp：genesis_timestamp=0（未设置）
    let mut v = inv.clone();
    v["genesis_timestamp"] = json!(0);
    write_vector(
        &base,
        "genesis-invalid-timestamp-001",
        with_meta(
            "genesis-invalid-timestamp-001",
            "INVALID",
            Some("InvalidTimestamp"),
            "genesis_timestamp=0 非法（须 > 0）",
            v,
        ),
    );

    // duplicate-validator：追加一个同 consensus_public_key 的 validator
    let mut v = inv.clone();
    {
        let dup = v["initial_validator_set"][0].clone();
        v["initial_validator_set"]
            .as_array_mut()
            .expect("array")
            .push(dup);
    }
    write_vector(
        &base,
        "genesis-duplicate-validator-001",
        with_meta(
            "genesis-duplicate-validator-001",
            "INVALID",
            Some("DuplicateValidator"),
            "同 consensus_public_key / account_address 出现两次",
            v,
        ),
    );

    // duplicate-account：追加一个同 address 的 account
    let mut v = inv.clone();
    {
        let dup = v["initial_accounts"][0].clone();
        v["initial_accounts"]
            .as_array_mut()
            .expect("array")
            .push(dup);
    }
    write_vector(
        &base,
        "genesis-duplicate-account-001",
        with_meta(
            "genesis-duplicate-account-001",
            "INVALID",
            Some("DuplicateAccount"),
            "同 address 出现两次",
            v,
        ),
    );

    // invalid-stake：bonded_stake=0
    let mut v = inv.clone();
    v["initial_validator_set"][0]["bonded_stake"] = json!("0");
    write_vector(
        &base,
        "genesis-invalid-stake-001",
        with_meta(
            "genesis-invalid-stake-001",
            "INVALID",
            Some("InvalidValidator"),
            "bonded_stake=0 非法（须 > 0）",
            v,
        ),
    );

    // stake-exceeds-account：bonded_stake > 对应账户 liquid_balance
    let mut v = inv.clone();
    // validator[0] 对应账户在 initial_accounts 中（liquid=1_500_000）
    v["initial_validator_set"][0]["bonded_stake"] = json!("5000000");
    write_vector(
        &base,
        "genesis-stake-exceeds-account-001",
        with_meta(
            "genesis-stake-exceeds-account-001",
            "INVALID",
            Some("InvalidStake"),
            "bonded_stake(5M) > 对应账户 liquid(1.5M)",
            v,
        ),
    );

    // invalid-protocol-params：max_block_bytes < max_tx_bytes
    let mut v = inv.clone();
    v["protocol_parameters"]["max_block_bytes"] = json!(1024);
    write_vector(
        &base,
        "genesis-invalid-protocol-params-001",
        with_meta(
            "genesis-invalid-protocol-params-001",
            "INVALID",
            Some("InvalidProtocolParams"),
            "max_block_bytes < max_tx_bytes",
            v,
        ),
    );

    // invalid-economics：fee_burn_bps > 10_000
    let mut v = inv.clone();
    v["economics_parameters"]["fee_burn_bps"] = json!(10_001);
    write_vector(
        &base,
        "genesis-invalid-economics-001",
        with_meta(
            "genesis-invalid-economics-001",
            "INVALID",
            Some("InvalidEconomicsParams"),
            "fee_burn_bps > 10_000",
            v,
        ),
    );

    // wrong-validator-order：交换 validator 顺序（非 validator_id 升序）
    let mut v = inv.clone();
    {
        let arr = v["initial_validator_set"].as_array_mut().expect("array");
        arr.swap(0, 1);
    }
    write_vector(
        &base,
        "genesis-wrong-validator-order-001",
        with_meta(
            "genesis-wrong-validator-order-001",
            "INVALID",
            Some("NonCanonicalOrdering"),
            "validator 列表非 validator_id 升序",
            v,
        ),
    );

    // wrong-account-order：交换 account 顺序（非 payload bytes 升序）
    let mut v = inv.clone();
    {
        let arr = v["initial_accounts"].as_array_mut().expect("array");
        arr.swap(0, 1);
    }
    write_vector(
        &base,
        "genesis-wrong-account-order-001",
        with_meta(
            "genesis-wrong-account-order-001",
            "INVALID",
            Some("NonCanonicalOrdering"),
            "account 列表非 address payload bytes 升序",
            v,
        ),
    );

    // tampered-genesis：篡改 timestamp（结构合法；hash 层不匹配 → canonical 阶段验证）
    let mut v = inv.clone();
    v["genesis_timestamp"] = json!(1_999_999_999);
    write_vector(
        &base,
        "genesis-tampered-genesis-001",
        with_meta(
            "genesis-tampered-genesis-001",
            "INVALID",
            Some("GenesisHashMismatch"),
            "篡改 genesis_timestamp ⇒ 结构合法但 canonical genesis_hash 不匹配（canonical 层，DEFERRED）",
            v,
        ),
    );

    // wrong-genesis-hash：提供错误 expected_genesis_hash（canonical 层 GenesisHashMismatch）
    let mut v = inv.clone();
    v["expected_genesis_hash"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    write_vector(
        &base,
        "genesis-wrong-genesis-hash-001",
        with_meta(
            "genesis-wrong-genesis-hash-001",
            "INVALID",
            Some("GenesisHashMismatch"),
            "configured genesis_hash 与 computed 不匹配（canonical 层，DEFERRED）",
            v,
        ),
    );

    // supply-invariant-violation：total_supply != Σ liquid_balance
    let mut v = inv.clone();
    v["economics_parameters"]["total_supply"] = json!("99999999");
    write_vector(
        &base,
        "genesis-supply-invariant-violation-001",
        with_meta(
            "genesis-supply-invariant-violation-001",
            "INVALID",
            Some("SupplyInvariantViolation"),
            "total_supply != Σ AccountInit.liquid_balance",
            v,
        ),
    );

    Ok(())
}
