//! Sparse Merkle Tree（STEP 8B-3 — State Root Algorithm；ADR-0026 T-1/T-6）。
//!
//! - **Binary SMT**，深度 = 280（key = `NovaAddressPayload` raw 35B）。
//! - 增量路径更新：insert / update / delete 只影响 leaf → 280 层 path → root（O(280)）。
//! - 位序：`depth 0` = key[0] 最高位；`bit 1 => right`，`bit 0 => left`。
//! - **可交换性**：SMT 是**集合承诺**（key→value 映射），非插入序列承诺；同集合 ⇒ 同 root。
//! - [`SparseMerkleTree::delete`] 为**数据结构原语**；协议层 V0.1 禁止账户删除
//!   （ADR-0017 §6），`AccountChange` 不产生 delete。
//! - **不实现**：StateStore.apply / backend / persistence / proof / block state root
//!   （8C / 8E / 8B-4 / 8D）。

use crate::hashing::branch_node_hash;
use crate::node::{Node, NodeHash, TrieKey, ValueHash};

/// 空状态根：`EMPTY_STATE_ROOT = EMPTY_NODE_HASH = SHA-256(0x00)`（ADR-0026 T-5）。
pub const EMPTY_STATE_ROOT: [u8; 32] = crate::hashing::EMPTY_NODE_HASH;

/// SMT 内部节点树（增量结构）。
#[derive(Debug, Clone)]
enum Tree {
    /// 空子树。
    Empty,
    /// 叶子：完整 key(35B) + value_hash(32B)。
    Leaf { key: TrieKey, value_hash: ValueHash },
    /// 分支：left = bit 0，right = bit 1；缓存 hash。
    Branch {
        left: Box<Tree>,
        right: Box<Tree>,
        hash: NodeHash,
    },
}

impl Tree {
    /// 子树根哈希（Empty = `EMPTY_NODE_HASH`；Leaf/Branch 域分离）。
    fn hash(&self) -> NodeHash {
        match self {
            Tree::Empty => Node::Empty.hash(),
            Tree::Leaf { key, value_hash } => Node::Leaf {
                key: *key,
                value_hash: *value_hash,
            }
            .hash(),
            Tree::Branch { hash, .. } => *hash,
        }
    }
}

/// Sparse Merkle Tree（V0.1 内存结构；持久化见 8E）。
pub struct SparseMerkleTree {
    root: Tree,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// 空树（root = `EMPTY_STATE_ROOT`）。
    pub fn new() -> Self {
        Self { root: Tree::Empty }
    }

    /// 当前 state root。
    pub fn root(&self) -> NodeHash {
        self.root.hash()
    }

    /// 插入或更新 `(key → value_hash)`（同 key 替换 value）。
    pub fn insert(&mut self, key: &TrieKey, value_hash: &ValueHash) {
        let old = std::mem::replace(&mut self.root, Tree::Empty);
        self.root = insert_impl(old, key, value_hash, 0);
    }

    /// 读取 `key` 的 value_hash（不存在 ⇒ `None`）。
    pub fn get(&self, key: &TrieKey) -> Option<ValueHash> {
        get_impl(&self.root, key, 0)
    }

    /// 删除 key（**数据结构原语**；V0.1 协议层不调用）。
    pub fn delete(&mut self, key: &TrieKey) {
        let old = std::mem::replace(&mut self.root, Tree::Empty);
        self.root = delete_impl(old, key, 0);
    }
}

/// SMT 固定深度：key 为 35B ⇒ 280 bit 路径（ADR-0026 T-2）。
const SMT_DEPTH: usize = 280;

/// 取 key 在 depth 位的 bit（depth 0 = key[0] 最高位；bit 1 => right，bit 0 => left）。
fn bit_at(key: &TrieKey, depth: usize) -> u8 {
    debug_assert!(depth < SMT_DEPTH, "SMT path depth out of range");
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

fn recompute_branch_hash(left: &Tree, right: &Tree) -> NodeHash {
    NodeHash::from_bytes(branch_node_hash(
        left.hash().as_bytes(),
        right.hash().as_bytes(),
    ))
}

/// 函数式 insert/update（**固定深度 SMT**：leaf 只在 depth == SMT_DEPTH；空子树 = EMPTY）。
///
/// 沿 280-bit 路径建 branch，底层 Leaf；同 key 更新 value。**不折叠单侧 branch**
/// （空子树用 Empty 表示）⇒ 同 key 集合 ⇒ 同 root（唯一表示，与历史无关）。
fn insert_impl(tree: Tree, key: &TrieKey, value_hash: &ValueHash, depth: usize) -> Tree {
    if depth == SMT_DEPTH {
        // 底层：Empty → Leaf；Leaf（同 key）→ update。
        return match tree {
            Tree::Empty => Tree::Leaf {
                key: *key,
                value_hash: *value_hash,
            },
            Tree::Leaf { key: k, .. } => {
                debug_assert!(&k == key, "fixed-depth SMT: leaf key mismatch at base");
                Tree::Leaf {
                    key: k,
                    value_hash: *value_hash,
                }
            }
            other => other, // 防御：不应出现 Branch at base
        };
    }
    match tree {
        Tree::Empty => {
            let child = insert_impl(Tree::Empty, key, value_hash, depth + 1);
            if bit_at(key, depth) == 1 {
                let hash = recompute_branch_hash(&Tree::Empty, &child);
                Tree::Branch {
                    left: Box::new(Tree::Empty),
                    right: Box::new(child),
                    hash,
                }
            } else {
                let hash = recompute_branch_hash(&child, &Tree::Empty);
                Tree::Branch {
                    left: Box::new(child),
                    right: Box::new(Tree::Empty),
                    hash,
                }
            }
        }
        Tree::Branch { left, right, .. } => {
            let (nl, nr) = if bit_at(key, depth) == 1 {
                (
                    left,
                    Box::new(insert_impl(*right, key, value_hash, depth + 1)),
                )
            } else {
                (
                    Box::new(insert_impl(*left, key, value_hash, depth + 1)),
                    right,
                )
            };
            let hash = recompute_branch_hash(&nl, &nr);
            Tree::Branch {
                left: nl,
                right: nr,
                hash,
            }
        }
        Tree::Leaf { .. } => unreachable!("fixed-depth SMT: leaf at non-base depth"),
    }
}

/// 读取（沿 280-bit 路径）。
fn get_impl(tree: &Tree, key: &TrieKey, depth: usize) -> Option<ValueHash> {
    match tree {
        Tree::Empty => None,
        Tree::Leaf { key: k, value_hash } => {
            debug_assert!(
                depth == SMT_DEPTH,
                "fixed-depth SMT: leaf at non-base depth"
            );
            (*k == *key).then_some(*value_hash)
        }
        Tree::Branch { left, right, .. } => {
            if bit_at(key, depth) == 1 {
                get_impl(right, key, depth + 1)
            } else {
                get_impl(left, key, depth + 1)
            }
        }
    }
}

/// 函数式 delete（固定深度；沿 280-bit 路径删 leaf，回溯 fold）。
fn delete_impl(tree: Tree, key: &TrieKey, depth: usize) -> Tree {
    if depth == SMT_DEPTH {
        return match tree {
            Tree::Leaf { key: k, .. } if &k == key => Tree::Empty,
            other => other,
        };
    }
    match tree {
        Tree::Empty => Tree::Empty,
        Tree::Branch { left, right, .. } => {
            let (nl, nr) = if bit_at(key, depth) == 1 {
                (left, Box::new(delete_impl(*right, key, depth + 1)))
            } else {
                (Box::new(delete_impl(*left, key, depth + 1)), right)
            };
            fold_branch(nl, nr)
        }
        Tree::Leaf { .. } => unreachable!("fixed-depth SMT: leaf at non-base depth"),
    }
}

/// 分支折叠（固定深度）：两侧都空 ⇒ Empty；否则**保留 branch**（空侧为 Empty）并重算 hash。
///
/// 固定深度 SMT **不提升单侧子树**（避免深度漂移导致 leaf 路径位失配），
/// 从而保证同 key 集合 ⇒ 同 root（唯一表示）。
fn fold_branch(left: Box<Tree>, right: Box<Tree>) -> Tree {
    match (left.as_ref(), right.as_ref()) {
        (Tree::Empty, Tree::Empty) => Tree::Empty,
        _ => {
            let hash = recompute_branch_hash(&left, &right);
            Tree::Branch { left, right, hash }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::EMPTY_NODE_HASH;
    use crate::node::NodeHash;

    // 固定账户集（golden；algorithm-derived + 固化）
    const K_A: TrieKey = [0x11u8; 35];
    const K_B: TrieKey = [0x22u8; 35];

    fn v(n: u8) -> ValueHash {
        [n; 32]
    }

    #[test]
    fn empty_tree_root_is_emtpry_state_root() {
        let smt = SparseMerkleTree::new();
        assert_eq!(smt.root(), NodeHash::from_bytes(EMPTY_NODE_HASH));
        assert_eq!(smt.root().as_bytes(), &EMPTY_STATE_ROOT);
    }

    #[test]
    fn insert_changes_root_from_empty() {
        let mut smt = SparseMerkleTree::new();
        let empty = smt.root();
        smt.insert(&K_A, &v(0xaa));
        assert_ne!(smt.root(), empty, "insert must change state root");
    }

    #[test]
    fn insert_get_roundtrip() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        assert_eq!(smt.get(&K_A), Some(v(0xaa)));
        assert_eq!(smt.get(&K_B), None);
    }

    #[test]
    fn update_replaces_value() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        let r1 = smt.root();
        smt.insert(&K_A, &v(0xbb)); // update
        assert_eq!(smt.get(&K_A), Some(v(0xbb)));
        assert_ne!(smt.root(), r1, "update must change root");
    }

    #[test]
    fn leaf_split_on_common_prefix() {
        // K_A=[0x11;35]（bit7=0），K_D 取 bit7=1 触发 depth0 分裂
        let mut kd = [0x11u8; 35];
        kd[0] |= 0x80; // 最高位置 1 ⇒ 与 K_A 在 depth0 分歧
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        smt.insert(&kd, &v(0xbb));
        assert_eq!(smt.get(&K_A), Some(v(0xaa)));
        assert_eq!(smt.get(&kd), Some(v(0xbb)));
        // 两个都保留
        assert_eq!(smt.root().as_bytes().len(), 32);
    }

    #[test]
    fn delete_last_returns_empty_root() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        smt.insert(&K_B, &v(0xbb));
        assert_ne!(smt.root(), NodeHash::from_bytes(EMPTY_NODE_HASH));
        smt.delete(&K_A);
        smt.delete(&K_B);
        assert_eq!(
            smt.root(),
            NodeHash::from_bytes(EMPTY_NODE_HASH),
            "delete all => empty root"
        );
    }

    #[test]
    fn delete_keeps_other_keys() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        smt.insert(&K_B, &v(0xbb));
        smt.delete(&K_A);
        assert_eq!(smt.get(&K_A), None);
        assert_eq!(smt.get(&K_B), Some(v(0xbb)));
    }

    #[test]
    fn insertion_order_independent() {
        // 同集合不同顺序 ⇒ 同 root（可交换性）
        let items = [(K_A, v(0xaa)), (K_B, v(0xbb))];
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        for (k, v) in items {
            a.insert(&k, &v);
        }
        for (k, v) in items.iter().rev() {
            b.insert(k, v);
        }
        assert_eq!(a.root(), b.root());
    }

    // ---- golden roots（algorithm-derived；固化 + loader 独立重算比对模式）----
    #[test]
    fn golden_single_account_root() {
        // 单账户（K_A → 0xaa；固定深度 SMT）：root = 3fb79e4e...
        let golden: [u8; 32] = [
            0x3f, 0xb7, 0x9e, 0x4e, 0xee, 0x4f, 0x1f, 0xfb, 0x83, 0x19, 0xc1, 0x31, 0xce, 0x78,
            0x72, 0xa4, 0xf4, 0x85, 0x2c, 0xc2, 0xef, 0x47, 0x8a, 0xdb, 0x3d, 0x2c, 0x79, 0xf8,
            0x80, 0xf0, 0x6c, 0x8d,
        ];
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        assert_eq!(smt.root().as_bytes(), &golden, "single-account root golden");
    }

    #[test]
    fn golden_two_accounts_root() {
        // 双账户（K_A → 0xaa；kd=[0x91;35] → 0xbb，depth0 分歧）：root = df4186e0...
        let golden: [u8; 32] = [
            0xdf, 0x41, 0x86, 0xe0, 0x0b, 0x6e, 0xe0, 0x2d, 0xd2, 0xc3, 0x11, 0x4b, 0xce, 0x1c,
            0x05, 0x4e, 0x0b, 0xec, 0x95, 0x66, 0xbe, 0x44, 0x2c, 0x50, 0xc4, 0xbc, 0x12, 0x17,
            0xce, 0x1b, 0x9b, 0x42,
        ];
        let mut kd = [0x11u8; 35];
        kd[0] |= 0x80;
        let mut smt = SparseMerkleTree::new();
        smt.insert(&K_A, &v(0xaa));
        smt.insert(&kd, &v(0xbb));
        assert_eq!(smt.root().as_bytes(), &golden, "two-account root golden");
    }
}
