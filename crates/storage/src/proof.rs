//! State Merkle Proof（STEP 8B-4 — ADR-0027）。
//!
//! # 冻结（ADR-0027 P-1~P-7）
//! - **Inclusion**：`key(35B) + value_hash(32B) + [NodeHash; 280]`（固定 sibling，不压缩 P-1/P-7）。
//! - **Exclusion**：`key(35B) + empty_depth(u16) + siblings`（首个空子树深度 0..=280，P-5）。
//! - 验证：**纯函数**，返回 `Result<(), ProofError>`（P-4），独立重算，不信任 sibling / 不读存储。
//! - 序列化：`PROOF_INCLUSION=0x01` / `PROOF_EXCLUSION=0x02` 域前缀（只用于编码，非 hash domain，P-6）。
//! - **不实现**：light client / RPC / network / state sync / fraud proof protocol。

use crate::hashing::{EMPTY_NODE_HASH, branch_node_hash, leaf_node_hash};
use crate::node::{NodeHash, TrieKey, ValueHash};
use core::fmt;

/// SMT 固定深度（ADR-0026 T-2）。
pub const SMT_DEPTH: usize = 280;
/// Inclusion proof 域前缀（P-3）。
pub const PROOF_INCLUSION: u8 = 0x01;
/// Exclusion proof 域前缀（P-3）。
pub const PROOF_EXCLUSION: u8 = 0x02;

/// Sparse Merkle proof（P-1/P-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseMerkleProof {
    /// 证明 `key → value_hash` 存在于 root 下。
    Inclusion {
        key: TrieKey,
        value_hash: ValueHash,
        /// 固定 280 sibling（空 sibling 用 `EMPTY_NODE_HASH` 填充）。
        siblings: Box<[NodeHash; SMT_DEPTH]>,
    },
    /// 证明 `key` 不存在于 root 下。
    Exclusion {
        key: TrieKey,
        /// 路径上第一个空子树深度（0..=280；P-5；**u16**，非平台相关类型）。
        empty_depth: u16,
        /// 到 `empty_depth` 的 sibling（`len == empty_depth`）。
        siblings: Vec<NodeHash>,
    },
}

/// Proof 错误（P-4：四类，统一覆盖 decode 与 verify）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// 未知 proof type（decode；非 0x01 / 0x02）。
    InvalidProofType,
    /// sibling 数量/长度不符（decode 长度不符 / verify sibling 数量错误）。
    InvalidSiblingLength,
    /// `empty_depth` 越界（非 0..=280）。
    InvalidDepth,
    /// 重算 root ≠ 给定 root（verify 失败）。
    RootMismatch,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProofType => write!(f, "invalid proof type byte"),
            Self::InvalidSiblingLength => write!(f, "invalid sibling length"),
            Self::InvalidDepth => {
                write!(f, "invalid empty_depth (must be 0..=280)")
            }
            Self::RootMismatch => write!(f, "recomputed root does not match"),
        }
    }
}

impl std::error::Error for ProofError {}

/// 取 key 在 depth 位的 bit（depth 0 = key[0] 最高位；bit 1 => right，bit 0 => left）。
pub(crate) fn bit_at(key: &TrieKey, depth: usize) -> u8 {
    debug_assert!(depth < SMT_DEPTH, "SMT path depth out of range");
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

/// 按 key 位组合子节点与 sibling：`bit 1 => branch(sib, h)`；`bit 0 => branch(h, sib)`。
fn combine(h: NodeHash, sib: NodeHash, bit: u8) -> NodeHash {
    if bit == 1 {
        NodeHash::from_bytes(branch_node_hash(sib.as_bytes(), h.as_bytes()))
    } else {
        NodeHash::from_bytes(branch_node_hash(h.as_bytes(), sib.as_bytes()))
    }
}

/// 验证 proof 对给定 root 成立（**纯函数**；P-4，返回 `Result` 区分失败原因）。
///
/// - Inclusion：从 `leaf_hash(key, value)` 沿 280 位向上组合 sibling → 比对 root。
/// - Exclusion：从 `empty_depth` 的 `EMPTY_NODE_HASH` 向上组合 sibling → 比对 root。
/// - 错误：`InvalidDepth`（empty_depth 越界）/ `InvalidSiblingLength`（数量不符）/ `RootMismatch`（重算不符）。
/// - 不信任 sibling 内容（只按位置组合）；不读存储。
pub fn verify_proof(proof: &SparseMerkleProof, root: &NodeHash) -> Result<(), ProofError> {
    match proof {
        SparseMerkleProof::Inclusion {
            key,
            value_hash,
            siblings,
        } => {
            let mut h = NodeHash::from_bytes(leaf_node_hash(key, value_hash));
            for depth in (0..SMT_DEPTH).rev() {
                h = combine(h, siblings[depth], bit_at(key, depth));
            }
            if &h == root {
                Ok(())
            } else {
                Err(ProofError::RootMismatch)
            }
        }
        SparseMerkleProof::Exclusion {
            key,
            empty_depth,
            siblings,
        } => {
            let d = *empty_depth as usize;
            if d > SMT_DEPTH {
                return Err(ProofError::InvalidDepth);
            }
            if siblings.len() != d {
                return Err(ProofError::InvalidSiblingLength);
            }
            let mut h = NodeHash::from_bytes(EMPTY_NODE_HASH);
            for depth in (0..d).rev() {
                h = combine(h, siblings[depth], bit_at(key, depth));
            }
            if &h == root {
                Ok(())
            } else {
                Err(ProofError::RootMismatch)
            }
        }
    }
}

impl SparseMerkleProof {
    /// canonical 二进制编码（P-3）。
    ///
    /// ```text
    /// Inclusion: 0x01 ‖ key(35) ‖ value_hash(32) ‖ siblings(280×32B)
    /// Exclusion: 0x02 ‖ key(35) ‖ empty_depth(u16 LE) ‖ siblings(empty_depth×32B)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SparseMerkleProof::Inclusion {
                key,
                value_hash,
                siblings,
            } => {
                let mut out = Vec::with_capacity(1 + 35 + 32 + SMT_DEPTH * 32);
                out.push(PROOF_INCLUSION);
                out.extend_from_slice(key);
                out.extend_from_slice(value_hash);
                for s in siblings.iter() {
                    out.extend_from_slice(s.as_bytes());
                }
                out
            }
            SparseMerkleProof::Exclusion {
                key,
                empty_depth,
                siblings,
            } => {
                let mut out = Vec::with_capacity(1 + 35 + 2 + siblings.len() * 32);
                out.push(PROOF_EXCLUSION);
                out.extend_from_slice(key);
                out.extend_from_slice(&empty_depth.to_le_bytes());
                for s in siblings {
                    out.extend_from_slice(s.as_bytes());
                }
                out
            }
        }
    }

    /// canonical 解码（拒绝未知 type / 长度不符 / 非法 empty_depth）。
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.is_empty() {
            return Err(ProofError::InvalidProofType);
        }
        match bytes[0] {
            PROOF_INCLUSION => {
                let total = 1 + 35 + 32 + SMT_DEPTH * 32;
                if bytes.len() != total {
                    return Err(ProofError::InvalidSiblingLength);
                }
                let mut key = [0u8; 35];
                key.copy_from_slice(&bytes[1..36]);
                let mut value_hash = [0u8; 32];
                value_hash.copy_from_slice(&bytes[36..68]);
                let mut siblings = Box::new([NodeHash::from_bytes([0u8; 32]); SMT_DEPTH]);
                for (i, s) in siblings.iter_mut().enumerate() {
                    let off = 68 + i * 32;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[off..off + 32]);
                    *s = NodeHash::from_bytes(arr);
                }
                Ok(SparseMerkleProof::Inclusion {
                    key,
                    value_hash,
                    siblings,
                })
            }
            PROOF_EXCLUSION => {
                if bytes.len() < 1 + 35 + 2 {
                    return Err(ProofError::InvalidSiblingLength);
                }
                let mut key = [0u8; 35];
                key.copy_from_slice(&bytes[1..36]);
                let depth = u16::from_le_bytes([bytes[36], bytes[37]]);
                let d = depth as usize;
                if d > SMT_DEPTH {
                    return Err(ProofError::InvalidDepth);
                }
                let expected = 1 + 35 + 2 + d * 32;
                if bytes.len() != expected {
                    return Err(ProofError::InvalidSiblingLength);
                }
                let mut siblings = Vec::with_capacity(d);
                for i in 0..d {
                    let off = 1 + 35 + 2 + i * 32;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[off..off + 32]);
                    siblings.push(NodeHash::from_bytes(arr));
                }
                Ok(SparseMerkleProof::Exclusion {
                    key,
                    empty_depth: depth,
                    siblings,
                })
            }
            _ => Err(ProofError::InvalidProofType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::SparseMerkleTree;

    fn v(n: u8) -> ValueHash {
        [n; 32]
    }

    #[test]
    fn inclusion_verify_ok() {
        let mut smt = SparseMerkleTree::new();
        let key = [0x11u8; 35];
        smt.insert(&key, &v(0xaa));
        let root = smt.root();
        let proof = smt.prove_inclusion(&key).unwrap();
        assert_eq!(verify_proof(&proof, &root), Ok(()), "inclusion must verify");
        // 错误 root ⇒ RootMismatch
        let wrong = NodeHash::from_bytes(EMPTY_NODE_HASH);
        assert_eq!(verify_proof(&proof, &wrong), Err(ProofError::RootMismatch));
    }

    #[test]
    fn inclusion_tamper_rejected() {
        let mut smt = SparseMerkleTree::new();
        let key = [0x11u8; 35];
        smt.insert(&key, &v(0xaa));
        let root = smt.root();
        // 篡改 value_hash
        let mut proof = smt.prove_inclusion(&key).unwrap();
        if let SparseMerkleProof::Inclusion { value_hash, .. } = &mut proof {
            value_hash[0] ^= 0xff;
        }
        assert_eq!(
            verify_proof(&proof, &root),
            Err(ProofError::RootMismatch),
            "tampered value must fail"
        );
        // 篡改 sibling（替换整个 NodeHash）
        let mut proof2 = smt.prove_inclusion(&key).unwrap();
        if let SparseMerkleProof::Inclusion { siblings, .. } = &mut proof2 {
            let mut arr = *siblings[0].as_bytes();
            arr[0] ^= 0xff;
            siblings[0] = NodeHash::from_bytes(arr);
        }
        assert_eq!(
            verify_proof(&proof2, &root),
            Err(ProofError::RootMismatch),
            "tampered sibling must fail"
        );
    }

    #[test]
    fn exclusion_verify_ok() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[0x11u8; 35], &v(0xaa));
        let root = smt.root();
        // 不存在的 key（不同路径）
        let absent = [0x22u8; 35];
        let proof = smt.prove_exclusion(&absent).unwrap();
        assert_eq!(verify_proof(&proof, &root), Ok(()), "exclusion must verify");
        // 空树 exclusion：empty_depth=0 ⇒ root == EMPTY
        let empty_smt = SparseMerkleTree::new();
        let proof_e = empty_smt.prove_exclusion(&absent).unwrap();
        assert_eq!(
            verify_proof(&proof_e, &NodeHash::from_bytes(EMPTY_NODE_HASH)),
            Ok(())
        );
    }

    #[test]
    fn exclusion_verify_fails_for_existing_key() {
        // prove_exclusion 对存在的 key 返回 None
        let mut smt = SparseMerkleTree::new();
        let key = [0x11u8; 35];
        smt.insert(&key, &v(0xaa));
        assert!(smt.prove_exclusion(&key).is_none());
        assert!(smt.prove_inclusion(&key).is_some());
    }

    // ---- encode / decode ----
    #[test]
    fn encode_decode_roundtrip() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[0x11u8; 35], &v(0xaa));
        smt.insert(&[0x91u8; 35], &v(0xbb));
        let key = [0x11u8; 35];
        let inc = smt.prove_inclusion(&key).unwrap();
        let bytes = inc.encode();
        assert_eq!(bytes.len(), 1 + 35 + 32 + 280 * 32);
        assert_eq!(SparseMerkleProof::decode(&bytes).unwrap(), inc);

        let absent = [0x33u8; 35];
        let exc = smt.prove_exclusion(&absent).unwrap();
        let ebytes = exc.encode();
        assert_eq!(SparseMerkleProof::decode(&ebytes).unwrap(), exc);
    }

    #[test]
    fn decode_rejects_unknown_type_and_length() {
        assert_eq!(
            SparseMerkleProof::decode(&[0x03]),
            Err(ProofError::InvalidProofType)
        );
        // inclusion 长度不足
        let mut short = vec![PROOF_INCLUSION];
        short.extend_from_slice(&[0u8; 10]);
        assert_eq!(
            SparseMerkleProof::decode(&short),
            Err(ProofError::InvalidSiblingLength)
        );
        // exclusion empty_depth > 280
        let mut bad = vec![PROOF_EXCLUSION];
        bad.extend_from_slice(&[0u8; 35]);
        bad.extend_from_slice(&281u16.to_le_bytes());
        assert_eq!(
            SparseMerkleProof::decode(&bad),
            Err(ProofError::InvalidDepth)
        );
    }

    #[test]
    fn verify_rejects_bad_exclusion_structure() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[0x11u8; 35], &v(0xaa));
        let root = smt.root();
        let absent = [0x22u8; 35];
        // siblings.len() != empty_depth ⇒ InvalidSiblingLength
        let mut proof = smt.prove_exclusion(&absent).unwrap();
        if let SparseMerkleProof::Exclusion { siblings, .. } = &mut proof {
            siblings.pop(); // 长度错配
        }
        assert_eq!(
            verify_proof(&proof, &root),
            Err(ProofError::InvalidSiblingLength)
        );
        // empty_depth > 280 ⇒ InvalidDepth
        let bad = SparseMerkleProof::Exclusion {
            key: absent,
            empty_depth: 281,
            siblings: vec![NodeHash::from_bytes(EMPTY_NODE_HASH); 281],
        };
        assert_eq!(verify_proof(&bad, &root), Err(ProofError::InvalidDepth));
    }
}
