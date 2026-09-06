//! Sync 边界（STEP 9-5 — ADR-0032 N-6）。
//!
//! - [`SyncBlockRequest`] / [`SyncBlockResponse`] 消息 payload 格式（canonical binary）。
//! - [`BlockPayload`] = 原始区块字节占位（完整 Block 格式 PHASE 7）。
//! - **不实现** 完整状态同步：状态下载 / state root 验证链 / fork resolution / checkpoint sync
//!   （STEP 10-12 + PHASE 7）。

use crate::message::NetworkError;
use crate::security::RequestId;
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

/// 区块同步请求（ADR-0032 N-6；STEP 10-19-10-B2：request correlation）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBlockRequest {
    /// 请求关联 id（canonical 16B；`SyncBlockResponse` 必须回带同一 id ——
    /// **非 block hash / 非 height**；生成归上层 caller，CSPRNG deferred）。
    pub request_id: RequestId,
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

impl SyncBlockRequest {
    /// canonical 编码：`request_id(16B) ‖ height(8B LE) ‖ has_hash(1B) ‖ hash(32B 若有)`。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 8 + 1 + 32);
        out.extend_from_slice(self.request_id.as_bytes());
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

    /// canonical 解码（request_id 前置；长度严格）。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        const HDR: usize = 16 + 8 + 1; // request_id(16) + height(8) + has_hash tag(1)
        if bytes.len() < HDR {
            return Err(NetworkError::InvalidLength {
                expected: HDR,
                actual: bytes.len(),
            });
        }
        let request_id = RequestId::from_bytes(bytes[0..16].try_into().expect("len checked"));
        let height = u64::from_le_bytes(bytes[16..24].try_into().expect("len checked"));
        match bytes[24] {
            0 => {
                if bytes.len() != HDR {
                    return Err(NetworkError::InvalidLength {
                        expected: HDR,
                        actual: bytes.len(),
                    });
                }
                Ok(Self {
                    request_id,
                    height,
                    block_hash: None,
                })
            }
            1 => {
                if bytes.len() != HDR + 32 {
                    return Err(NetworkError::InvalidLength {
                        expected: HDR + 32,
                        actual: bytes.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[25..57]);
                Ok(Self {
                    request_id,
                    height,
                    block_hash: Some(h),
                })
            }
            _ => Err(NetworkError::InvalidLength {
                expected: HDR,
                actual: bytes.len(),
            }),
        }
    }
}

/// 区块同步响应（ADR-0032 N-6；STEP 10-19-10-B2：绑定请求）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBlockResponse {
    /// 回带请求关联 id（必须 == 对应 `SyncBlockRequest.request_id`；否则 correlation 拒绝）。
    pub request_id: RequestId,
    pub blocks: Vec<BlockPayload>,
}

impl SyncBlockResponse {
    /// canonical 编码：`request_id(16B) ‖ count(4B LE) ‖ count×(len(4B LE) ‖ bytes)`。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.request_id.as_bytes());
        out.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for b in &self.blocks {
            out.extend_from_slice(&(b.0.len() as u32).to_le_bytes());
            out.extend_from_slice(&b.0);
        }
        out
    }

    /// canonical 解码（request_id 前置；长度严格；拒 trailing）。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        const HDR: usize = 16 + 4; // request_id(16) + count(4)
        if bytes.len() < HDR {
            return Err(NetworkError::InvalidLength {
                expected: HDR,
                actual: bytes.len(),
            });
        }
        let request_id = RequestId::from_bytes(bytes[0..16].try_into().expect("len checked"));
        let count = u32::from_le_bytes(bytes[16..20].try_into().expect("len checked")) as usize;
        let mut pos = 20usize;
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
        Ok(Self { request_id, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(tag: u8) -> RequestId {
        RequestId::from_bytes([tag; 16])
    }

    #[test]
    fn sync_block_request_roundtrip() {
        // 无 hash
        let r1 = SyncBlockRequest {
            request_id: rid(1),
            height: 42,
            block_hash: None,
        };
        assert_eq!(SyncBlockRequest::decode(&r1.encode()).unwrap(), r1);
        // 有 hash
        let r2 = SyncBlockRequest {
            request_id: rid(2),
            height: 7,
            block_hash: Some([0xab; 32]),
        };
        let bytes = r2.encode();
        assert_eq!(bytes.len(), 16 + 8 + 1 + 32);
        assert_eq!(SyncBlockRequest::decode(&bytes).unwrap(), r2);
    }

    #[test]
    fn sync_block_response_roundtrip() {
        let r = SyncBlockResponse {
            request_id: rid(3),
            blocks: vec![
                BlockPayload(vec![1, 2, 3]),
                BlockPayload(Vec::new()),
                BlockPayload(vec![9; 100]),
            ],
        };
        assert_eq!(SyncBlockResponse::decode(&r.encode()).unwrap(), r);
        let empty = SyncBlockResponse {
            request_id: rid(4),
            blocks: Vec::new(),
        };
        assert_eq!(SyncBlockResponse::decode(&empty.encode()).unwrap(), empty);
    }

    // TEST 1（B2）：RequestId 经 request/response 编解码 roundtrip 保留（上方 roundtrip 已断言
    // request_id 字段相等）；此处显式验证 request_id 不是 hash / height 派生。
    #[test]
    fn request_id_preserved_and_not_hash_height() {
        let rid_bytes = [0x42; 16];
        let rid_value = RequestId::from_bytes(rid_bytes);
        let req = SyncBlockRequest {
            request_id: rid_value,
            height: 1,
            block_hash: Some([0xab; 32]),
        };
        let decoded_req = SyncBlockRequest::decode(&req.encode()).unwrap();
        assert_eq!(decoded_req.request_id, rid_value);
        // request_id ≠ block hash（长度/语义独立：16B correlation id vs 32B hash）
        assert_ne!(
            decoded_req.request_id.as_bytes()[0..16],
            decoded_req.block_hash.unwrap()[0..16]
        );
        let resp = SyncBlockResponse {
            request_id: rid_value,
            blocks: vec![BlockPayload(vec![1, 2, 3])],
        };
        let decoded_resp = SyncBlockResponse::decode(&resp.encode()).unwrap();
        assert_eq!(decoded_resp.request_id, rid_value);
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
            request_id: rid(5),
            blocks: vec![payload.clone()],
        };
        let decoded = SyncBlockResponse::decode(&r.encode()).unwrap();
        assert_eq!(decoded.request_id, rid(5));
        assert_eq!(decoded.blocks, vec![payload]);
        assert_eq!(
            nova_core::block::decode_block(&decoded.blocks[0].0).unwrap(),
            b
        );
    }

    #[test]
    fn sync_decode_rejects_bad_length() {
        // request：缺 request_id / 长度 < 25 ⇒ reject
        assert!(SyncBlockRequest::decode(&[0u8; 4]).is_err());
        assert!(SyncBlockRequest::decode(&[0u8; 24]).is_err());
        // request：has_hash tag=1 但缺 hash（25B，tag 位 = 24）⇒ reject
        let mut bad_req = vec![0u8; 25];
        bad_req[24] = 1;
        assert!(SyncBlockRequest::decode(&bad_req).is_err());
        // request：非法 tag ⇒ reject
        let mut bad_tag = vec![0u8; 25];
        bad_tag[24] = 2;
        assert!(SyncBlockRequest::decode(&bad_tag).is_err());
        // response：缺 request_id（< 20B）⇒ reject
        assert!(SyncBlockResponse::decode(&[0u8; 19]).is_err());
        // response：request_id(16) + count=2 但字节不足 ⇒ reject
        let mut bad2 = vec![0u8; 16];
        bad2.extend_from_slice(&2u32.to_le_bytes());
        bad2.extend_from_slice(&1u32.to_le_bytes());
        bad2.extend_from_slice(&[0xaa; 3]); // 声称 2 块，只有 1 块的 3 字节
        assert!(SyncBlockResponse::decode(&bad2).is_err());
    }
}
