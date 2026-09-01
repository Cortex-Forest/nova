//! Canonical ChainHead 持久化记录（PHASE 3 STEP 7-J；ADR-0048 / ADR-0031 E-3 amendment）。
//!
//! - [`HeadRecord`]：nova-storage 持有的 canonical head **逻辑记录**
//!   （`height` / `block_hash` / `parent_hash` / `state_root`）。Node 不接触本序列化内部。
//! - 编码为**确定性二进制**（**IMPLEMENTATION DESIGN，非协议冻结**）：
//!   沿用仓库 WAL/snapshot 惯例（magic + little-endian + `protocol_hash` SHA-256 checksum）。
//! - Node 经 [`crate::store::StateStore::enqueue_head`] 提交；head 与 state changes 同批次持久化。

use crate::error::StorageError;
use crate::node::NodeHash;
use nova_crypto::hash::protocol_hash;

/// HeadRecord 记录 magic（与 WAL `0x01` / snapshot `0x02` 区分）。
const HEAD_MAGIC: u8 = 0x03;
/// HeadRecord 版本（V0.1；未知版本 ⇒ 拒绝）。
const HEAD_VERSION: u8 = 0x01;
/// 定长 body：`magic(1) ‖ version(1) ‖ height(8 LE) ‖ block_hash(32) ‖ parent_hash(32) ‖ state_root(32)`。
const HEAD_BODY_LEN: usize = 1 + 1 + 8 + 32 + 32 + 32;
/// 全记录长度：body + checksum(32)。
const HEAD_LEN: usize = HEAD_BODY_LEN + 32;

/// Canonical head 记录（storage-owned；ADR-0048 §3 ChainHead 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRecord {
    /// 已提交高度。
    pub height: u64,
    /// 当前 head 的 block_hash（= 下一块 ⑤ 的 parent_hash）。
    pub block_hash: [u8; 32],
    /// 当前 head 的父块 hash。
    pub parent_hash: [u8; 32],
    /// 当前 head 的 state root（= 提交后 state root）。
    pub state_root: NodeHash,
}

/// 确定性编码（IMPLEMENTATION DESIGN，非协议冻结）。
///
/// 布局：`magic ‖ version ‖ height LE ‖ block_hash ‖ parent_hash ‖ state_root ‖ SHA-256(body)`。
/// 固定字段序 / LE / 无 HashMap / 无 serde-bincode。
pub fn encode_head_record(head: &HeadRecord) -> Vec<u8> {
    let mut body = Vec::with_capacity(HEAD_BODY_LEN);
    body.push(HEAD_MAGIC);
    body.push(HEAD_VERSION);
    body.extend_from_slice(&head.height.to_le_bytes());
    body.extend_from_slice(&head.block_hash);
    body.extend_from_slice(&head.parent_hash);
    body.extend_from_slice(head.state_root.as_bytes());
    let mut out = body.clone();
    out.extend_from_slice(&protocol_hash(&body));
    out
}

/// 严格解码：长度 / magic / version / checksum 全校验；拒未知 version、拒静默截断。
pub fn decode_head_record(bytes: &[u8]) -> Result<HeadRecord, StorageError> {
    if bytes.len() != HEAD_LEN {
        return Err(StorageError::CorruptedState);
    }
    if bytes[0] != HEAD_MAGIC {
        return Err(StorageError::CorruptedState);
    }
    if bytes[1] != HEAD_VERSION {
        return Err(StorageError::CorruptedState);
    }
    let body = &bytes[..HEAD_BODY_LEN];
    let cksum = &bytes[HEAD_BODY_LEN..];
    if protocol_hash(body) != cksum {
        return Err(StorageError::CorruptedState);
    }
    let height = u64::from_le_bytes(bytes[2..10].try_into().expect("len checked"));
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&bytes[10..42]);
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&bytes[42..74]);
    let state_root = NodeHash::from_bytes(bytes[74..106].try_into().expect("len checked"));
    Ok(HeadRecord {
        height,
        block_hash,
        parent_hash,
        state_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HeadRecord {
        HeadRecord {
            height: 42,
            block_hash: [0xaa; 32],
            parent_hash: [0xbb; 32],
            state_root: NodeHash::from_bytes([0xcc; 32]),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let h = sample();
        let bytes = encode_head_record(&h);
        assert_eq!(bytes.len(), HEAD_LEN);
        assert_eq!(decode_head_record(&bytes).unwrap(), h);
    }

    #[test]
    fn encoding_is_deterministic() {
        let h = sample();
        assert_eq!(encode_head_record(&h), encode_head_record(&h));
        let mut h2 = h;
        h2.height += 1;
        assert_ne!(encode_head_record(&h), encode_head_record(&h2));
    }

    #[test]
    fn decode_rejects_invalid_version() {
        let bytes = encode_head_record(&sample());
        let mut bad = bytes.clone();
        bad[1] = 0xff;
        assert_eq!(decode_head_record(&bad), Err(StorageError::CorruptedState));
    }

    #[test]
    fn decode_rejects_truncated() {
        let bytes = encode_head_record(&sample());
        assert_eq!(
            decode_head_record(&bytes[..bytes.len() - 1]),
            Err(StorageError::CorruptedState)
        );
        assert_eq!(
            decode_head_record(&bytes[..10]),
            Err(StorageError::CorruptedState)
        );
    }

    #[test]
    fn decode_rejects_checksum_failure() {
        let bytes = encode_head_record(&sample());
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff; // 篡改 checksum
        assert_eq!(decode_head_record(&bad), Err(StorageError::CorruptedState));
        // 篡改 height 载荷 ⇒ checksum 失配
        let mut bad2 = bytes.clone();
        bad2[2] ^= 0xff;
        assert_eq!(decode_head_record(&bad2), Err(StorageError::CorruptedState));
    }
}
