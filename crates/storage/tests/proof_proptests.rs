//! STEP 8B-4 Property Tests（proptest）：Sparse Merkle Proof（ADR-0027 P-1~P-5）。
//!
//! 覆盖：随机集合下所有存在 key 的 inclusion proof 验证通过 + encode/decode roundtrip 后仍验证；
//! 随机不存在 key 的 exclusion proof 验证通过；篡改 sibling / value / key ⇒ 验证失败。

use nova_storage::node::{NodeHash, TrieKey, ValueHash};
use nova_storage::proof::{SparseMerkleProof, verify_proof};
use nova_storage::trie::SparseMerkleTree;
use proptest::prelude::*;
use std::collections::HashMap;

/// 去重并排序（确定性集合）：同集合 ⇒ 同 root（可交换性）。
fn dedup(entries: &[(TrieKey, ValueHash)]) -> Vec<(TrieKey, ValueHash)> {
    let mut map = HashMap::new();
    for (k, v) in entries {
        map.entry(*k).or_insert(*v);
    }
    let mut items: Vec<(TrieKey, ValueHash)> = map.into_iter().collect();
    items.sort_unstable_by_key(|(k, _)| *k);
    items
}

fn build_tree(items: &[(TrieKey, ValueHash)]) -> SparseMerkleTree {
    let mut smt = SparseMerkleTree::new();
    for (k, v) in items {
        smt.insert(k, v);
    }
    smt
}

proptest! {
    // 随机集合：每个存在 key 的 inclusion proof 验证通过（含 encode/decode roundtrip）
    #[test]
    fn inclusion_verifies_for_all_present_keys(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..8),
        absent in any::<[u8; 35]>(),
    ) {
        let items = dedup(&entries);
        let smt = build_tree(&items);
        let root = smt.root();
        for (k, expected_v) in &items {
            let proof = smt.prove_inclusion(k).expect("present key has proof");
            prop_assert!(
                verify_proof(&proof, &root).is_ok(),
                "inclusion must verify"
            );
            if let SparseMerkleProof::Inclusion { value_hash, .. } = &proof {
                prop_assert_eq!(value_hash, expected_v, "proof carries exact value");
            }
            let decoded = SparseMerkleProof::decode(&proof.encode()).unwrap();
            prop_assert_eq!(&decoded, &proof, "encode/decode roundtrip");
            prop_assert!(
                verify_proof(&decoded, &root).is_ok(),
                "decoded proof must verify"
            );
        }
        // 与集合不同的 key ⇒ exclusion proof 验证通过（含 roundtrip）
        if !items.iter().any(|(k, _)| *k == absent) {
            let eproof = smt.prove_exclusion(&absent).expect("absent key has proof");
            prop_assert!(
                verify_proof(&eproof, &root).is_ok(),
                "exclusion must verify"
            );
            let edecoded = SparseMerkleProof::decode(&eproof.encode()).unwrap();
            prop_assert!(
                verify_proof(&edecoded, &root).is_ok(),
                "decoded exclusion must verify"
            );
        }
    }

    // 篡改任意 sibling ⇒ 验证失败
    #[test]
    fn tampered_sibling_rejected(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..8),
        idx in 0usize..280,
        byte in 0usize..32,
    ) {
        let items = dedup(&entries);
        let smt = build_tree(&items);
        let root = smt.root();
        let k0 = items[0].0;
        let mut proof = smt.prove_inclusion(&k0).unwrap();
        if let SparseMerkleProof::Inclusion { siblings, .. } = &mut proof {
            let mut arr = *siblings[idx].as_bytes();
            arr[byte] ^= 0x01; // 必定改变
            siblings[idx] = NodeHash::from_bytes(arr);
        }
        prop_assert!(
            verify_proof(&proof, &root).is_err(),
            "tampered sibling must fail"
        );
    }

    // 篡改 value_hash ⇒ 验证失败
    #[test]
    fn tampered_value_rejected(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..8),
        byte in 0usize..32,
    ) {
        let items = dedup(&entries);
        let smt = build_tree(&items);
        let root = smt.root();
        let k0 = items[0].0;
        let mut proof = smt.prove_inclusion(&k0).unwrap();
        if let SparseMerkleProof::Inclusion { value_hash, .. } = &mut proof {
            value_hash[byte] ^= 0x01;
        }
        prop_assert!(
            verify_proof(&proof, &root).is_err(),
            "tampered value must fail"
        );
    }

    // 篡改 key（inclusion）⇒ 验证失败
    #[test]
    fn tampered_key_rejected(
        entries in prop::collection::vec((any::<[u8; 35]>(), any::<[u8; 32]>()), 1..8),
        byte in 0usize..35,
    ) {
        let items = dedup(&entries);
        let smt = build_tree(&items);
        let root = smt.root();
        let k0 = items[0].0;
        let mut proof = smt.prove_inclusion(&k0).unwrap();
        if let SparseMerkleProof::Inclusion { key, .. } = &mut proof {
            key[byte] ^= 0x01;
        }
        prop_assert!(
            verify_proof(&proof, &root).is_err(),
            "tampered key must fail"
        );
    }
}
