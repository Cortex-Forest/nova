//! SMT 域分离哈希（STEP 8B-2 — ADR-0026 T-4 / T-5）。
//!
//! 冻结（ADR-0026 §4/§5）：
//! ```text
//! STATE_EMPTY  = 0x00
//! STATE_LEAF   = 0x01
//! STATE_BRANCH = 0x02
//!
//! EMPTY_NODE_HASH = SHA-256(0x00)
//! leaf_hash       = SHA-256(0x01 ‖ key ‖ value_hash)
//! branch_hash     = SHA-256(0x02 ‖ left_hash ‖ right_hash)
//! ```
//!
//! - 统一经 `protocol_hash`（SHA-256，ADR-0006）。
//! - 分离 leaf / branch / empty hash 域 ⇒ 防类型混淆 / 二阶碰撞。
//! - `EMPTY_NODE_HASH` 为 **algorithm-derived golden**（generator → golden → loader 验证模式）；
//!   测试断言其等于 `SHA-256(0x00)`。

use nova_crypto::hash::protocol_hash;

/// 空子树域前缀（ADR-0026 T-4）。
pub const STATE_EMPTY: u8 = 0x00;
/// Leaf 节点域前缀（ADR-0026 T-4）。
pub const STATE_LEAF: u8 = 0x01;
/// Branch 节点域前缀（ADR-0026 T-4）。
pub const STATE_BRANCH: u8 = 0x02;

/// 空节点哈希 golden：`SHA-256(0x00)`（algorithm-derived；与 `empty_node_hash()` 一致性由测试验证）。
pub const EMPTY_NODE_HASH: [u8; 32] = [
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
];

/// 计算空节点哈希：`SHA-256(0x00)`（算法派生，供 golden 验证）。
pub fn empty_node_hash() -> [u8; 32] {
    protocol_hash(&[STATE_EMPTY])
}

/// 计算 Leaf 节点哈希：`SHA-256(0x01 ‖ key ‖ value_hash)`。
pub fn leaf_node_hash(key: &[u8; 35], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut pre = [0u8; 1 + 35 + 32];
    pre[0] = STATE_LEAF;
    pre[1..36].copy_from_slice(key);
    pre[36..68].copy_from_slice(value_hash);
    protocol_hash(&pre)
}

/// 计算 Branch 节点哈希：`SHA-256(0x02 ‖ left_hash ‖ right_hash)`。
pub fn branch_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut pre = [0u8; 1 + 32 + 32];
    pre[0] = STATE_BRANCH;
    pre[1..33].copy_from_slice(left);
    pre[33..65].copy_from_slice(right);
    protocol_hash(&pre)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_node_hash_matches_algorithm() {
        // golden 与算法派生一致（ADR-0026 T-5：algorithm-derived，非写死 hex）
        assert_eq!(EMPTY_NODE_HASH, empty_node_hash());
        assert_eq!(EMPTY_NODE_HASH, protocol_hash(&[STATE_EMPTY]));
    }

    #[test]
    fn leaf_hash_domain_separated() {
        let key = [0x11u8; 35];
        let value = [0x22u8; 32];
        let h = leaf_node_hash(&key, &value);
        // 与独立重算一致
        let mut pre = Vec::with_capacity(68);
        pre.push(STATE_LEAF);
        pre.extend_from_slice(&key);
        pre.extend_from_slice(&value);
        assert_eq!(h, protocol_hash(&pre));
        // 与空/分支哈希不同（域分离）
        assert_ne!(h, EMPTY_NODE_HASH);
    }

    #[test]
    fn branch_hash_domain_separated() {
        let left = [0x33u8; 32];
        let right = [0x44u8; 32];
        let h = branch_node_hash(&left, &right);
        let mut pre = Vec::with_capacity(65);
        pre.push(STATE_BRANCH);
        pre.extend_from_slice(&left);
        pre.extend_from_slice(&right);
        assert_eq!(h, protocol_hash(&pre));
        assert_ne!(h, EMPTY_NODE_HASH);
    }

    #[test]
    fn leaf_vs_branch_hashes_differ() {
        // 相同左/右字节 vs 相同 key/value：域前缀保证不同
        let l = branch_node_hash(&[0x01u8; 32], &[0x02u8; 32]);
        let leaf = leaf_node_hash(&[0x01u8; 35], &[0x02u8; 32]);
        assert_ne!(l, leaf);
    }
}
