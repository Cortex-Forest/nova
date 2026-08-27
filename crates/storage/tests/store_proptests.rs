//! STEP 8C-2 Property Tests（proptest）：MemoryBackend + canonical account roundtrip
//! （ADR-0028 D-1/D-3）。
//!
//! - canonical roundtrip：任意 `AccountState` → 88B → decode == 原值。
//! - MemoryBackend put/get/delete roundtrip。
//! - snapshot → mutate → restore == 快照时状态（rollback 语义）；restore 幂等。
//!
//! **注意**：D-7 两个必测（Atomicity、Backend/Trie consistency）依赖 `StateStore::apply`，
//! 属 8C-3（两阶段事务落地后）实现，不在 8C-2 骨架范围。

use nova_core::state::{AccountState, canonical_account_bytes, decode_account_bytes};
use nova_storage::backend::StorageBackend;
use nova_storage::memory::MemoryBackend;
use proptest::prelude::*;
use std::collections::HashMap;

fn arb_account() -> impl Strategy<Value = AccountState> {
    (
        any::<u128>(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(balance, nonce, code_hash, storage_root)| AccountState {
            balance,
            nonce,
            code_hash,
            storage_root,
        })
}

proptest! {
    // canonical roundtrip：任意 AccountState → 88B → decode == 原值
    #[test]
    fn canonical_roundtrip(acc in arb_account()) {
        let bytes = canonical_account_bytes(&acc);
        prop_assert_eq!(bytes.len(), 88);
        prop_assert_eq!(decode_account_bytes(&bytes), acc);
    }

    // MemoryBackend put/get/delete roundtrip
    #[test]
    fn backend_put_get_roundtrip(
        key in any::<[u8; 35]>(),
        value in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let mut b = MemoryBackend::new();
        prop_assert_eq!(b.get(&key), None);
        b.put(key, value.clone()).unwrap();
        prop_assert_eq!(b.get(&key), Some(value));
        b.delete(&key).unwrap();
        prop_assert_eq!(b.get(&key), None);
    }

    // snapshot → mutate → restore == 快照时状态（rollback 语义）
    #[test]
    fn backend_snapshot_restore(
        base in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 0..16),
        extra in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 0..16),
    ) {
        let mut b = MemoryBackend::new();
        let mut map: HashMap<[u8; 35], Vec<u8>> = HashMap::new();
        for (k, v) in &base {
            b.put(*k, v.to_vec()).unwrap();
            map.insert(*k, v.to_vec());
        }
        let snap = b.snapshot();
        for (k, v) in &extra {
            b.put(*k, v.to_vec()).unwrap();
        }
        b.restore(&snap);
        prop_assert_eq!(b.len(), map.len());
        for (k, v) in &map {
            prop_assert_eq!(&b.get(k).unwrap(), v);
        }
    }

    // snapshot/restore 幂等：连续 restore 结果相同
    #[test]
    fn backend_restore_idempotent(
        base in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 0..16),
        mut0 in any::<[u8; 35]>(),
    ) {
        let mut b = MemoryBackend::new();
        for (k, v) in &base {
            b.put(*k, v.to_vec()).unwrap();
        }
        let snap = b.snapshot();
        b.put(mut0, vec![0u8; 88]).unwrap();
        b.restore(&snap);
        let after1 = b.len();
        b.restore(&snap);
        prop_assert_eq!(after1, b.len(), "restore idempotent");
    }
}
