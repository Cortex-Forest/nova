//! Sync 边界（STEP 9-5 — ADR-0032 N-6）。
//!
//! - [`SyncBlockRequest`] / [`SyncBlockResponse`] 消息 payload 格式（canonical binary）。
//! - [`BlockPayload`] = 原始区块字节占位（完整 Block 格式 PHASE 7）。
//! - **不实现** 完整状态同步：状态下载 / state root 验证链 / fork resolution / checkpoint sync
//!   （STEP 10-12 + PHASE 7）。

use crate::message::NetworkError;
use nova_core::block::{Block, BlockCodecError, encode_block};

/// 区块负载（P7-5 F2：完整 Block wire = `encode_block` 输出；无额外前缀——外层 len 前缀）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPayload(pub Vec<u8>);

impl BlockPayload {
    /// 从完整 Block 构造 wire（P7-5 F2：`encode_block` 输出）。
    pub fn from_block(block: &Block) -> Result<Self, BlockCodecError> {
        Ok(Self(encode_block(block)?))
    }
}

/// 区块同步请求（ADR-0032 N-6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBlockRequest {
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

impl SyncBlockRequest {
    /// canonical 编码：`height(8B LE) ‖ has_hash(1B) ‖ hash(32B 若有)`。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + 32);
        out.extend_from_slice(&self.height.to_le_bytes());
        match self.block_hash {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h);
            }
            None => out.push(0),
        }
        out
    }

    /// canonical 解码。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() < 9 {
            return Err(NetworkError::InvalidLength {
                expected: 9,
                actual: bytes.len(),
            });
        }
        let height = u64::from_le_bytes(bytes[0..8].try_into().expect("len checked"));
        match bytes[8] {
            0 => {
                if bytes.len() != 9 {
                    return Err(NetworkError::InvalidLength {
                        expected: 9,
                        actual: bytes.len(),
                    });
                }
                Ok(Self {
                    height,
                    block_hash: None,
                })
            }
            1 => {
                if bytes.len() != 9 + 32 {
                    return Err(NetworkError::InvalidLength {
                        expected: 41,
                        actual: bytes.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[9..41]);
                Ok(Self {
                    height,
                    block_hash: Some(h),
                })
            }
            _ => Err(NetworkError::InvalidLength {
                expected: 9,
                actual: bytes.len(),
            }),
        }
    }
}

/// 区块同步响应（ADR-0032 N-6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBlockResponse {
    pub blocks: Vec<BlockPayload>,
}

impl SyncBlockResponse {
    /// canonical 编码：`count(4B LE) ‖ count×(len(4B LE) ‖ bytes)`。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for b in &self.blocks {
            out.extend_from_slice(&(b.0.len() as u32).to_le_bytes());
            out.extend_from_slice(&b.0);
        }
        out
    }

    /// canonical 解码。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() < 4 {
            return Err(NetworkError::InvalidLength {
                expected: 4,
                actual: bytes.len(),
            });
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().expect("len checked")) as usize;
        let mut pos = 4usize;
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 4 > bytes.len() {
                return Err(NetworkError::InvalidLength {
                    expected: pos + 4,
                    actual: bytes.len(),
                });
            }
            let len =
                u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("len checked")) as usize;
            pos += 4;
            if pos + len > bytes.len() {
                return Err(NetworkError::InvalidLength {
                    expected: pos + len,
                    actual: bytes.len(),
                });
            }
            blocks.push(BlockPayload(bytes[pos..pos + len].to_vec()));
            pos += len;
        }
        if pos != bytes.len() {
            return Err(NetworkError::InvalidLength {
                expected: pos,
                actual: bytes.len(),
            });
        }
        Ok(Self { blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_block_request_roundtrip() {
        // 无 hash
        let r1 = SyncBlockRequest {
            height: 42,
            block_hash: None,
        };
        assert_eq!(SyncBlockRequest::decode(&r1.encode()).unwrap(), r1);
        // 有 hash
        let r2 = SyncBlockRequest {
            height: 7,
            block_hash: Some([0xab; 32]),
        };
        let bytes = r2.encode();
        assert_eq!(bytes.len(), 41);
        assert_eq!(SyncBlockRequest::decode(&bytes).unwrap(), r2);
    }

    #[test]
    fn sync_block_response_roundtrip() {
        let r = SyncBlockResponse {
            blocks: vec![
                BlockPayload(vec![1, 2, 3]),
                BlockPayload(Vec::new()),
                BlockPayload(vec![9; 100]),
            ],
        };
        assert_eq!(SyncBlockResponse::decode(&r.encode()).unwrap(), r);
        let empty = SyncBlockResponse { blocks: Vec::new() };
        assert_eq!(SyncBlockResponse::decode(&empty.encode()).unwrap(), empty);
    }

    fn mk_block() -> nova_core::block::Block {
        nova_core::block::Block {
            header: nova_core::block::BlockHeader {
                version: nova_core::block::BLOCK_VERSION,
                chain_id: 1001,
                height: 1,
                parent_hash: [0xaa; 32],
                finality_reference: None,
                transaction_root: [0x11; 32],
                state_root: [0x22; 32],
                validator_set_hash: [0x33; 32],
                timestamp: 0,
            },
            body: nova_core::block::BlockBody { txs: vec![] },
            proposer_signature: [0xcc; 64],
        }
    }

    #[test]
    fn block_payload_from_block_is_block_wire() {
        // P7-5 F2：BlockPayload = encode_block 输出（完整 Block wire，无额外前缀）。
        let b = mk_block();
        let payload = BlockPayload::from_block(&b).unwrap();
        assert_eq!(payload.0, nova_core::block::encode_block(&b).unwrap());
        // 结构可 decode 还原
        assert_eq!(nova_core::block::decode_block(&payload.0).unwrap(), b);
    }

    #[test]
    fn sync_block_response_full_block_wire_roundtrip() {
        // P7-5：SyncBlockResponse 承载完整 Block wire，roundtrip 后每个 payload 可结构还原。
        let b = mk_block();
        let payload = BlockPayload::from_block(&b).unwrap();
        let r = SyncBlockResponse {
            blocks: vec![payload.clone()],
        };
        let decoded = SyncBlockResponse::decode(&r.encode()).unwrap();
        assert_eq!(decoded.blocks, vec![payload]);
        assert_eq!(
            nova_core::block::decode_block(&decoded.blocks[0].0).unwrap(),
            b
        );
    }

    #[test]
    fn sync_decode_rejects_bad_length() {
        assert!(SyncBlockRequest::decode(&[0u8; 4]).is_err());
        // has_hash=1 但缺 hash
        let mut bad = vec![0u8; 9];
        bad[8] = 1;
        assert!(SyncBlockRequest::decode(&bad).is_err());
        // response count 声明但字节不足
        let mut bad2 = vec![2u8, 0, 0, 0, 1, 0, 0, 0];
        bad2.extend_from_slice(&[0xaa; 3]); // 声称 2 块，只有 1 块的 3 字节
        assert!(SyncBlockResponse::decode(&bad2).is_err());
    }
}
