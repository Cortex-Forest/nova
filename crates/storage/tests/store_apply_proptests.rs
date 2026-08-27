//! STEP 8C-3 Property Tests（proptest）：StateStore::apply 两阶段事务（ADR-0028 D-4/D-7）。
//!
//! 覆盖：
//! - **D-7 必测 2 — Backend/Trie consistency**：随机 changes apply 后，backend 账户 commitment
//!   == trie leaf `value_hash`（防 backend/trie 分叉）。
//! - account 回读 == 最后写入状态（同地址后者覆盖）。
//! - **可交换性**：唯一地址集合不同顺序 ⇒ 同 state_root（SMT 是集合承诺）。

use nova_core::state::{
    AccountChange, AccountState, AccountStateView, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT,
    account_commitment,
};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_storage::memory::MemoryBackend;
use nova_storage::state_root::calculate_state_root;
use nova_storage::store::StateStore;
use proptest::prelude::*;
use std::collections::HashMap;

fn change(key_hash: [u8; 32], balance: u128, nonce: u64) -> AccountChange {
    let addr = NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash,
    });
    AccountChange {
        address: addr,
        new_balance: balance,
        new_nonce: nonce,
        created: true,
    }
}

fn state_of(c: &AccountChange) -> AccountState {
    AccountState {
        balance: c.new_balance,
        nonce: c.new_nonce,
        code_hash: EMPTY_CODE_HASH,
        storage_root: EMPTY_STORAGE_ROOT,
    }
}

proptest! {
    // D-7 必测 2：backend commitment == trie leaf value_hash
    #[test]
    fn backend_trie_consistency(
        changes in prop::collection::vec(
            (any::<[u8; 32]>(), any::<u128>(), any::<u64>()),
            0..16,
        ),
    ) {
        let changes: Vec<AccountChange> = changes
            .iter()
            .map(|(kh, b, n)| change(*kh, *b, *n))
            .collect();
        let mut store = StateStore::new(MemoryBackend::new());
        store.apply(&changes).unwrap();
        for c in &changes {
            // backend 侧：account() 还原 → commitment
            let from_backend = account_commitment(&store.account(&c.address).unwrap());
            // trie 侧：commitment()（leaf value_hash）
            let from_trie = store.commitment(&c.address).unwrap();
            prop_assert_eq!(
                from_backend, from_trie,
                "backend commitment must equal trie leaf value_hash"
            );
            // account 回读 == 该 change 声明的最终状态
            let acc = store.account(&c.address).unwrap();
            prop_assert_eq!(&acc, &state_of(c));
        }
    }

    // account 回读一致性：同地址多次 → 最后写入覆盖
    #[test]
    fn last_write_wins(
        entries in prop::collection::vec(
            (any::<[u8; 32]>(), any::<u128>(), any::<u64>()),
            1..16,
        ),
    ) {
        let mut store = StateStore::new(MemoryBackend::new());
        for (kh, b, n) in &entries {
            store.apply(&[change(*kh, *b, *n)]).unwrap();
        }
        // 同地址最后写入生效
        let mut last = HashMap::new();
        for (kh, b, n) in entries {
            last.insert(kh, (b, n));
        }
        for (kh, (b, n)) in last {
            let addr = NovaAddress::from_payload(NovaAddressPayload {
                address_version: ADDRESS_VERSION,
                address_type: AddressType::UserAccount,
                network_id: NetworkId::Mainnet,
                key_hash: kh,
            });
            let acc = store.account(&addr).unwrap();
            prop_assert_eq!(acc.balance, b);
            prop_assert_eq!(acc.nonce, n);
        }
    }

    // 可交换性：唯一地址集合不同顺序 ⇒ 同 root（SMT 是集合承诺，非插入序列承诺）
    #[test]
    fn order_independent_root(
        entries in prop::collection::vec(
            (any::<[u8; 32]>(), any::<u128>(), any::<u64>()),
            1..8,
        ),
    ) {
        let mut map = HashMap::new();
        for (kh, b, n) in &entries {
            map.entry(*kh).or_insert((*b, *n));
        }
        let items: Vec<([u8; 32], u128, u64)> = map
            .into_iter()
            .map(|(k, (b, n))| (k, b, n))
            .collect();
        let changes: Vec<AccountChange> = items
            .iter()
            .map(|(kh, b, n)| change(*kh, *b, *n))
            .collect();
        let mut a = StateStore::new(MemoryBackend::new());
        let mut b = StateStore::new(MemoryBackend::new());
        a.apply(&changes).unwrap();
        let rev: Vec<AccountChange> = changes.iter().rev().cloned().collect();
        b.apply(&rev).unwrap();
        prop_assert_eq!(a.state_root(), b.state_root(), "SMT is set commitment");
    }

    // ADR-0030 C-7：calculate_state_root 只读 + 与 apply_block 等价
    #[test]
    fn calculate_equals_apply_block_and_read_only(
        seed in prop::collection::vec(
            (any::<[u8; 32]>(), any::<u128>(), any::<u64>()),
            0..8,
        ),
        more in prop::collection::vec(
            (any::<[u8; 32]>(), any::<u128>(), any::<u64>()),
            0..8,
        ),
    ) {
        let mut store = StateStore::new(MemoryBackend::new());
        let seed_changes: Vec<AccountChange> = seed
            .iter()
            .map(|(kh, b, n)| change(*kh, *b, *n))
            .collect();
        store.apply(&seed_changes).unwrap();
        let root_before = store.state_root();

        let more_changes: Vec<AccountChange> = more
            .iter()
            .map(|(kh, b, n)| change(*kh, *b, *n))
            .collect();
        let tx_changes: Vec<Vec<AccountChange>> = more_changes
            .iter()
            .map(|c| vec![c.clone()])
            .collect();
        let refs: Vec<&[AccountChange]> = tx_changes.iter().map(|v| v.as_slice()).collect();

        // 只读：calculate 前后 store 不变
        let calc = calculate_state_root(&store, &refs).unwrap();
        prop_assert_eq!(store.state_root(), root_before, "calculate must not mutate");
        // 等价：apply_block 返回同一 root
        let applied = store.apply_block(&refs).unwrap();
        prop_assert_eq!(calc, applied, "calculate == apply_block");
    }
}
