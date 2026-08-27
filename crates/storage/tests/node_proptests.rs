//! STEP 8B-2 Property Tests（proptest）：SMT 节点 encode/decode roundtrip + hash 一致性
//! （ADR-0026 T-3/T-4）。

use nova_crypto::hash::protocol_hash;
use nova_storage::hashing::{EMPTY_NODE_HASH, STATE_BRANCH, STATE_LEAF};
use nova_storage::node::{Node, NodeHash};
use proptest::prelude::*;

proptest! {
    // roundtrip：decode(encode(node)) == node（Empty / Leaf / Branch）
    #[test]
    fn node_roundtrip(
        key in any::<[u8; 35]>(),
        value_hash in any::<[u8; 32]>(),
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>(),
    ) {
        let nodes = [
            Node::Empty,
            Node::Leaf { key, value_hash },
            Node::Branch {
                left: NodeHash::from_bytes(left),
                right: NodeHash::from_bytes(right),
            },
        ];
        for n in nodes {
            let d = Node::decode(&n.encode()).unwrap();
            prop_assert_eq!(&d, &n, "decode(encode(node)) == node");
        }
    }

    // hash 一致性：node.hash() == SHA-256(encode(node))（含 type 前缀）；Empty 用 golden
    #[test]
    fn node_hash_equals_protocol_hash_of_encoding(
        key in any::<[u8; 35]>(),
        value_hash in any::<[u8; 32]>(),
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>(),
    ) {
        let empty = Node::Empty;
        prop_assert_eq!(
            empty.hash(),
            NodeHash::from_bytes(EMPTY_NODE_HASH),
            "empty == SHA-256(0x00)"
        );

        let leaf = Node::Leaf { key, value_hash };
        let mut leaf_pre = Vec::with_capacity(68);
        leaf_pre.push(STATE_LEAF);
        leaf_pre.extend_from_slice(&key);
        leaf_pre.extend_from_slice(&value_hash);
        prop_assert_eq!(
            leaf.hash(),
            NodeHash::from_bytes(protocol_hash(&leaf_pre)),
            "leaf_hash == SHA-256(0x01‖key‖value)"
        );

        let branch = Node::Branch {
            left: NodeHash::from_bytes(left),
            right: NodeHash::from_bytes(right),
        };
        let mut br_pre = Vec::with_capacity(65);
        br_pre.push(STATE_BRANCH);
        br_pre.extend_from_slice(&left);
        br_pre.extend_from_slice(&right);
        prop_assert_eq!(
            branch.hash(),
            NodeHash::from_bytes(protocol_hash(&br_pre)),
            "branch_hash == SHA-256(0x02‖left‖right)"
        );

        // 域分离：同字节内容不同类型 ⇒ 不同 hash
        prop_assert_ne!(leaf.hash(), branch.hash());
    }

    // 修改任一字段 ⇒ hash 变化（leaf）
    #[test]
    fn leaf_hash_mutation_sensitive(
        key in any::<[u8; 35]>(),
        value_hash in any::<[u8; 32]>(),
    ) {
        let base = Node::Leaf { key, value_hash }.hash();
        let mut k2 = key;
        k2[0] ^= 0xff;
        let h_k = Node::Leaf { key: k2, value_hash }.hash();
        prop_assert_ne!(base, h_k, "key change must change hash");

        let mut v2 = value_hash;
        v2[0] ^= 0xff;
        let h_v = Node::Leaf { key, value_hash: v2 }.hash();
        prop_assert_ne!(base, h_v, "value change must change hash");
    }
}
