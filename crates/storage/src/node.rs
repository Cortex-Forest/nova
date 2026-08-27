//! SMT 节点（STEP 8B-2 — ADR-0026 T-3 / T-4 / T-7）。
//!
//! 冻结（ADR-0026 §3/§4）：
//! ```text
//! EmptyNode:  （无字节表示；用 EMPTY_NODE_HASH 常量替代空子树根）
//! LeafNode:   type(1B, 0x01) ‖ key(35B) ‖ value_hash(32B)
//! BranchNode: type(1B, 0x02) ‖ left_hash(32B) ‖ right_hash(32B)
//! ```
//!
//! - `Node::hash` = `SHA-256(encode(node))`（encode 含 type 前缀 = 域前缀，ADR-0026 §4）。
//! - Leaf 保留**完整 35B key**（T-7，非 hash(key)）。
//! - **本 STEP 只实现节点层**：encode/decode/hash；**不实现** trie update / apply / 持久化 /
//!   proof / block state root（8B-3 / 8B-4 / 8C / 8D）。

use crate::hashing::{STATE_BRANCH, STATE_LEAF, branch_node_hash, empty_node_hash, leaf_node_hash};
use core::fmt;

/// SMT trie key = `NovaAddressPayload` raw bytes（35B；ADR-0026 T-2 / ADR-0018）。
pub type TrieKey = [u8; 35];
/// 叶子 value hash = `account_commitment`（32B；ADR-0018）。
pub type ValueHash = [u8; 32];

/// 节点哈希 newtype（防 `[u8;32]` 与普通哈希混淆）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeHash([u8; 32]);

impl NodeHash {
    /// 从 32 字节构造（反序列化恢复）。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 读取内部字节。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeHash({})", hex_str(&self.0))
    }
}

impl fmt::Display for NodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_str(&self.0))
    }
}

/// SMT 节点（ADR-0026 T-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    /// 空子树（无字节表示；hash = `EMPTY_NODE_HASH`）。
    Empty,
    /// 叶子：完整 key(35B) + value_hash(32B)（account_commitment）。
    Leaf { key: TrieKey, value_hash: ValueHash },
    /// 分支：left = bit 0，right = bit 1。
    Branch { left: NodeHash, right: NodeHash },
}

/// 节点编码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// 未知 type 字节（非 0x01 / 0x02）。
    UnknownType(u8),
    /// 长度与类型不符。
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(t) => write!(f, "unknown node type byte: {t:#04x}"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid node length: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for NodeError {}

impl Node {
    /// 编码（含 type 前缀；Empty 编码为空）。
    ///
    /// ```text
    /// Leaf:   0x01 ‖ key(35) ‖ value_hash(32) = 68 B
    /// Branch: 0x02 ‖ left(32) ‖ right(32)     = 65 B
    /// Empty:  （空）
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Empty => Vec::new(),
            Node::Leaf { key, value_hash } => {
                let mut out = Vec::with_capacity(1 + 35 + 32);
                out.push(STATE_LEAF);
                out.extend_from_slice(key);
                out.extend_from_slice(value_hash);
                out
            }
            Node::Branch { left, right } => {
                let mut out = Vec::with_capacity(1 + 32 + 32);
                out.push(STATE_BRANCH);
                out.extend_from_slice(left.as_bytes());
                out.extend_from_slice(right.as_bytes());
                out
            }
        }
    }

    /// 解码（canonical roundtrip；拒绝未知 type / 长度不符）。
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeError> {
        if bytes.is_empty() {
            return Ok(Node::Empty);
        }
        match bytes[0] {
            STATE_LEAF => {
                if bytes.len() != 1 + 35 + 32 {
                    return Err(NodeError::InvalidLength {
                        expected: 1 + 35 + 32,
                        actual: bytes.len(),
                    });
                }
                let mut key = [0u8; 35];
                key.copy_from_slice(&bytes[1..36]);
                let mut value_hash = [0u8; 32];
                value_hash.copy_from_slice(&bytes[36..68]);
                Ok(Node::Leaf { key, value_hash })
            }
            STATE_BRANCH => {
                if bytes.len() != 1 + 32 + 32 {
                    return Err(NodeError::InvalidLength {
                        expected: 1 + 32 + 32,
                        actual: bytes.len(),
                    });
                }
                let mut left = [0u8; 32];
                left.copy_from_slice(&bytes[1..33]);
                let mut right = [0u8; 32];
                right.copy_from_slice(&bytes[33..65]);
                Ok(Node::Branch {
                    left: NodeHash(left),
                    right: NodeHash(right),
                })
            }
            other => Err(NodeError::UnknownType(other)),
        }
    }

    /// 节点哈希（域分离；`SHA-256(encode(node))`；Empty 用 `EMPTY_NODE_HASH`）。
    pub fn hash(&self) -> NodeHash {
        match self {
            Node::Empty => NodeHash(empty_node_hash()),
            Node::Leaf { key, value_hash } => NodeHash(leaf_node_hash(key, value_hash)),
            Node::Branch { left, right } => {
                NodeHash(branch_node_hash(left.as_bytes(), right.as_bytes()))
            }
        }
    }
}

fn hex_str(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::EMPTY_NODE_HASH;

    fn leaf() -> Node {
        Node::Leaf {
            key: [0x11u8; 35],
            value_hash: [0x22u8; 32],
        }
    }

    fn branch() -> Node {
        Node::Branch {
            left: NodeHash([0x33u8; 32]),
            right: NodeHash([0x44u8; 32]),
        }
    }

    // ---- encoding ----
    #[test]
    fn leaf_encode_layout() {
        let e = leaf().encode();
        assert_eq!(e.len(), 1 + 35 + 32);
        assert_eq!(e[0], STATE_LEAF);
        assert_eq!(&e[1..36], &[0x11u8; 35]);
        assert_eq!(&e[36..68], &[0x22u8; 32]);
    }

    #[test]
    fn branch_encode_layout() {
        let e = branch().encode();
        assert_eq!(e.len(), 1 + 32 + 32);
        assert_eq!(e[0], STATE_BRANCH);
        assert_eq!(&e[1..33], &[0x33u8; 32]);
        assert_eq!(&e[33..65], &[0x44u8; 32]);
    }

    #[test]
    fn empty_encode_is_empty() {
        assert!(Node::Empty.encode().is_empty());
    }

    // ---- decode roundtrip ----
    #[test]
    fn decode_roundtrip() {
        for n in [Node::Empty, leaf(), branch()] {
            let d = Node::decode(&n.encode()).unwrap();
            assert_eq!(d, n, "decode(encode(node)) == node");
        }
    }

    #[test]
    fn decode_empty_bytes() {
        assert_eq!(Node::decode(&[]), Ok(Node::Empty));
    }

    #[test]
    fn decode_unknown_type_rejected() {
        assert_eq!(Node::decode(&[0x03]), Err(NodeError::UnknownType(0x03)));
        assert_eq!(
            Node::decode(&[0x00, 0x00]),
            Err(NodeError::UnknownType(0x00))
        );
    }

    #[test]
    fn decode_invalid_length_rejected() {
        // Leaf 缺 value_hash
        let mut short = vec![STATE_LEAF];
        short.extend_from_slice(&[0x11u8; 35]);
        assert_eq!(
            Node::decode(&short),
            Err(NodeError::InvalidLength {
                expected: 68,
                actual: 36
            })
        );
        // Branch 缺 right
        let mut sb = vec![STATE_BRANCH];
        sb.extend_from_slice(&[0x33u8; 32]);
        assert_eq!(
            Node::decode(&sb),
            Err(NodeError::InvalidLength {
                expected: 65,
                actual: 33
            })
        );
    }

    // ---- hashing ----
    #[test]
    fn empty_hash_is_golden() {
        assert_eq!(Node::Empty.hash(), NodeHash(EMPTY_NODE_HASH));
    }

    #[test]
    fn leaf_hash_matches_domain() {
        let n = leaf();
        let h = n.hash();
        let expect = leaf_node_hash(&[0x11u8; 35], &[0x22u8; 32]);
        assert_eq!(h, NodeHash(expect));
    }

    #[test]
    fn branch_hash_matches_domain() {
        let n = branch();
        let h = n.hash();
        let expect = branch_node_hash(&[0x33u8; 32], &[0x44u8; 32]);
        assert_eq!(h, NodeHash(expect));
    }

    #[test]
    fn hash_changes_with_value() {
        let a = Node::Leaf {
            key: [0x11u8; 35],
            value_hash: [0x22u8; 32],
        };
        let b = Node::Leaf {
            key: [0x11u8; 35],
            value_hash: [0x23u8; 32],
        };
        assert_ne!(a.hash(), b.hash(), "value change must change hash");
    }

    #[test]
    fn node_debug_prints_hex() {
        let d = format!("{:?}", Node::Empty.hash());
        assert_eq!(d, format!("NodeHash({})", hex_str(&EMPTY_NODE_HASH)));
    }
}
