//! STEP 8B-3 Property Tests（proptest）：Sparse Merkle Tree（ADR-0026 T-6）。
//!
//! 覆盖：insert/get roundtrip、update 替换、**可交换性**（同集合不同顺序 ⇒ 同 root）、
//! delete 全部 ⇒ EMPTY root、重插幂等。

use nova_storage::hashing::EMPTY_NODE_HASH;
use nova_storage::node::{NodeHash, TrieKey, ValueHash};
use nova_storage::trie::SparseMerkleTree;
use proptest::prelude::*;
use std::collections::HashMap;

proptest! {
    // insert/get roundtrip
    #[test]
    fn insert_get_roundtrip(key in any::<[u8; 35]>(), value in any::<[u8; 32]>()) {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&key, &value);
        prop_assert_eq!(smt.get(&key), Some(value));
    }

    // update 替换同 key
    #[test]
    fn update_replaces(key in any::<[u8; 35]>(), v1 in any::<[u8; 32]>(), v2 in any::<[u8; 32]>()) {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&key, &v1);
        smt.insert(&key, &v2);
        prop_assert_eq!(smt.get(&key), Some(v2));
    }

    // 可交换性：同集合（唯一 key）不同插入顺序 ⇒ 同 root
    #[test]
    fn insertion_order_independent(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..8),
    ) {
        let mut map = HashMap::new();
        for (k, v) in &entries {
            map.entry(*k).or_insert(*v);
        }
        let items: Vec<(TrieKey, ValueHash)> = map.into_iter().collect();
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        for (k, v) in &items {
            a.insert(k, v);
        }
        for (k, v) in items.iter().rev() {
            b.insert(k, v);
        }
        prop_assert_eq!(a.root(), b.root(), "SMT is set commitment, not insertion-sequence commitment");
    }

    // delete 全部 ⇒ EMPTY root
    #[test]
    fn delete_all_returns_empty(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..6),
    ) {
        let mut map = HashMap::new();
        for (k, v) in &entries {
            map.entry(*k).or_insert(*v);
        }
        let items: Vec<(TrieKey, ValueHash)> = map.into_iter().collect();
        let mut smt = SparseMerkleTree::new();
        for (k, v) in &items {
            smt.insert(k, v);
        }
        for (k, _) in &items {
            smt.delete(k);
        }
        prop_assert_eq!(smt.root(), NodeHash::from_bytes(EMPTY_NODE_HASH));
    }

    // 重插幂等：同集合插入两次 ⇒ 同 root
    #[test]
    fn reinsert_is_idempotent(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..6),
    ) {
        let mut map = HashMap::new();
        for (k, v) in &entries {
            map.entry(*k).or_insert(*v);
        }
        let items: Vec<(TrieKey, ValueHash)> = map.into_iter().collect();
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        for (k, v) in &items {
            a.insert(k, v);
        }
        for (k, v) in &items {
            b.insert(k, v);
        }
        for (k, v) in &items {
            b.insert(k, v); // 重复插入
        }
        prop_assert_eq!(a.root(), b.root(), "re-insert must be idempotent");
    }
}
