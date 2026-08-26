//! STEP 6A Property Tests（proptest）：Genesis canonical encoding / hash 性质。
//!
//! 覆盖（用户 §17）：Canonical Encoding Determinism、Genesis Hash Determinism、
//! Mutation Changes Hash、Canonical Ordering Rejection、Duplicate Detection、
//! Length / overflow safety。
//!
//! 生成策略：随机 validator/account 条目 → 去重 + 排序 → **canonical 有序** Genesis，
//! 再验证编码/哈希性质。

use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisError, GenesisV1, MAX_ACCOUNTS, MAX_VALIDATORS,
    ProtocolParamsV1, ValidatorInit, canonical_genesis_bytes, compute_genesis_hash, validator_id,
};
use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::HashSet;

fn proto() -> ProtocolParamsV1 {
    ProtocolParamsV1 {
        max_tx_bytes: 65_536,
        max_block_bytes: 1_048_576,
        max_gas_per_block: 1_000_000_000,
        max_contract_code_bytes: 32_768,
        max_contract_storage_bytes: 1_048_576,
        epoch_length_blocks: 100,
        snapshot_interval_blocks: 1_000,
    }
}

fn econ() -> EconomicsParamsV1 {
    EconomicsParamsV1 {
        total_supply: 6_500_000,
        min_validator_stake: 100_000,
        unbonding_period_seconds: 1_209_600,
        fee_burn_bps: 500,
    }
}

/// 生成一个 validator + 对应 account（地址从 key_hash 构造，非公钥派生以保持 key 独立）。
fn entry() -> impl Strategy<Value = (ValidatorInit, AccountInit)> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u128>(),
        any::<u16>(),
        any::<u128>(),
    )
        .prop_map(|(pk, kh, stake, comm, liq)| {
            let addr = NovaAddress::from_payload(NovaAddressPayload {
                address_version: 1,
                address_type: AddressType::UserAccount,
                network_id: NetworkId::Mainnet,
                key_hash: kh,
            });
            (
                ValidatorInit {
                    account_address: addr,
                    consensus_public_key: pk,
                    bonded_stake: stake,
                    commission_bps: comm,
                },
                AccountInit {
                    address: addr,
                    liquid_balance: liq,
                },
            )
        })
}

/// 构造 canonical 有序 Genesis（validator 按 validator_id、account 按 payload 升序，去重）。
fn canonical_genesis() -> impl Strategy<Value = GenesisV1> {
    vec(entry(), 1..=8).prop_map(|entries| {
        let mut seen = HashSet::new();
        let mut vals = Vec::new();
        let mut accs = Vec::new();
        for (v, a) in entries {
            // 去重（pubkey 唯一；地址唯一）
            if !seen.insert(v.consensus_public_key) || !seen.insert(a.address.payload().key_hash) {
                continue;
            }
            vals.push(v);
            accs.push(a);
        }
        vals.sort_by_key(|v| validator_id(&v.consensus_public_key));
        accs.sort_by_key(|a| nova_crypto::identity::address_payload_bytes(&a.address));
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 1_750_000_000,
            initial_validator_set: vals,
            initial_accounts: accs,
            protocol_parameters: proto(),
            economics_parameters: econ(),
        }
    })
}

proptest! {
    // Canonical encoding determinism + hash determinism
    #[test]
    fn encoding_and_hash_deterministic(g in canonical_genesis()) {
        let a = canonical_genesis_bytes(&g).unwrap();
        let b = canonical_genesis_bytes(&g).unwrap();
        prop_assert_eq!(&a, &b);
        let h1 = compute_genesis_hash(&g).unwrap();
        let h2 = compute_genesis_hash(&g).unwrap();
        prop_assert_eq!(h1, h2);
        // 长度与布局一致
        let n_val = g.initial_validator_set.len();
        let n_acc = g.initial_accounts.len();
        prop_assert_eq!(a.len(), 1 + 8 + 8 + 4 + n_val * 85 + 4 + n_acc * 51 + 40 + 42);
    }

    // Mutation changes hash（修改 bonded_stake）
    #[test]
    fn mutation_changes_hash(g in canonical_genesis()) {
        if g.initial_validator_set.is_empty() { return Ok(()); }
        let h0 = compute_genesis_hash(&g).unwrap();
        let mut m = g.clone();
        let e = m.initial_validator_set.get_mut(0).unwrap();
        e.bonded_stake = e.bonded_stake.wrapping_add(1);
        let hm = compute_genesis_hash(&m).unwrap();
        prop_assert_ne!(h0, hm, "bonded_stake mutation must change hash");
    }

    // Non-canonical ordering rejected（交换不自动排序）
    #[test]
    fn ordering_rejected(g in canonical_genesis()) {
        if g.initial_validator_set.len() < 2 { return Ok(()); }
        let mut wrong = g.clone();
        wrong.initial_validator_set.swap(0, 1);
        let r = canonical_genesis_bytes(&wrong);
        prop_assert_eq!(r, Err(GenesisError::NonCanonicalOrdering));

        if g.initial_accounts.len() >= 2 {
            let mut wa = g.clone();
            wa.initial_accounts.swap(0, 1);
            let r = canonical_genesis_bytes(&wa);
            prop_assert_eq!(r, Err(GenesisError::NonCanonicalOrdering));
        }
    }

    // Duplicate detection
    #[test]
    fn duplicate_rejected(g in canonical_genesis()) {
        if g.initial_validator_set.is_empty() { return Ok(()); }
        let mut d = g.clone();
        let dup = d.initial_validator_set[0].clone();
        d.initial_validator_set.push(dup);
        let r = canonical_genesis_bytes(&d);
        prop_assert_eq!(r, Err(GenesisError::DuplicateValidator));

        if !g.initial_accounts.is_empty() {
            let mut da = g.clone();
            let dup = da.initial_accounts[0].clone();
            da.initial_accounts.push(dup);
            let r = canonical_genesis_bytes(&da);
            prop_assert_eq!(r, Err(GenesisError::DuplicateAccount));
        }
    }

    // Length / overflow safety：任何合法大小 genesis 编码不 panic、不溢出
    #[test]
    fn length_safe(g in canonical_genesis()) {
        let bytes = canonical_genesis_bytes(&g).unwrap();
        // 编码长度有限（≤ 上限对应长度）
        prop_assert!(bytes.len() <= 1 + 8 + 8 + 4 + MAX_VALIDATORS * 85 + 4 + MAX_ACCOUNTS * 51 + 40 + 42);
    }
}

/// 集合超上限 ⇒ CollectionTooLarge（确定性，非随机）。
#[test]
fn collection_limit_deterministic() {
    let addr = NovaAddress::from_payload(NovaAddressPayload {
        address_version: 1,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: [0u8; 32],
    });
    // 超上限前先确保唯一
    let mut vals = Vec::new();
    let mut kh = [0u8; 32];
    for i in 0..=MAX_VALIDATORS {
        kh[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let a = NovaAddress::from_payload(NovaAddressPayload {
            address_version: 1,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        });
        let mut pk = [0u8; 32];
        pk[0..8].copy_from_slice(&((i as u64) ^ 0xFFFF).to_le_bytes());
        vals.push(ValidatorInit {
            account_address: a,
            consensus_public_key: pk,
            bonded_stake: 1,
            commission_bps: 0,
        });
    }
    vals.sort_by_key(|v| validator_id(&v.consensus_public_key));
    let g = GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: 1,
        genesis_timestamp: 1,
        initial_validator_set: vals,
        initial_accounts: vec![AccountInit {
            address: addr,
            liquid_balance: 0,
        }],
        protocol_parameters: proto(),
        economics_parameters: econ(),
    };
    assert_eq!(
        canonical_genesis_bytes(&g),
        Err(GenesisError::CollectionTooLarge)
    );
}
