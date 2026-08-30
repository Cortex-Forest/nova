//! Gossip 规则（STEP 9-4 — ADR-0032 N-5）。
//!
//! - 流程：`Verify Envelope Signature → Validate Tx Basic Rules → Deduplicate → TTL → Rate Limit →
//!   Forward`。
//! - **禁止** gossip 阶段执行交易（N-5：网络层不能影响执行确定性）。
//! - V0.1 只冻结**验证 / 转发决策逻辑**（纯函数），不实现 Gossipsub 调度（N-3）。

use crate::message::{MessageEnvelope, MessageType, NetworkError, verify_message};
use nova_core::block::{Block, decode_block};
use nova_crypto::signature::VerifyingKey;
use nova_crypto::transaction::{TransactionV1, decode_transaction};
use std::collections::HashSet;

/// Gossip 参数（N-5；V0.1 默认值，实现阶段可调）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipConfig {
    /// 最大转发跳数（TTL）。
    pub max_ttl: u8,
    /// 最大 gossip 消息字节。
    pub max_msg_bytes: usize,
    /// 每 peer 速率上限（msg/窗口）。
    pub peer_rate_limit: u32,
    /// 已见缓存大小（去重）。
    pub seen_cache_size: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_ttl: 3,
            max_msg_bytes: 64 * 1024,
            peer_rate_limit: 100,
            seen_cache_size: 10_000,
        }
    }
}

/// 转发决策（N-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipDecision {
    /// 转发。
    Forward,
    /// 已见（去重）。
    DropDuplicate,
    /// TTL 过期。
    DropTtlExpired,
    /// 消息过大。
    DropTooLarge,
    /// 无效（签名 / tx 结构失败）。
    DropInvalid,
}

/// 已见去重缓存 + 决策（纯逻辑，无网络 IO）。
#[derive(Debug)]
pub struct GossipValidator {
    config: GossipConfig,
    seen: HashSet<[u8; 32]>,
}

impl GossipValidator {
    /// 以默认或自定义配置构建。
    pub fn new(config: GossipConfig) -> Self {
        Self {
            config,
            seen: HashSet::new(),
        }
    }

    /// 消息大小检查。
    pub fn check_size(&self, msg_len: usize) -> bool {
        msg_len <= self.config.max_msg_bytes
    }

    /// 已见缓存：插入并返回是否为新（新 ⇒ true）。
    pub fn seen_insert(&mut self, msg_id: [u8; 32]) -> bool {
        if self.seen.len() >= self.config.seen_cache_size {
            self.seen.clear(); // V0.1 简单淘汰（实现阶段可换 LRU）
        }
        self.seen.insert(msg_id)
    }

    /// TTL 检查：`0 < ttl <= max_ttl`。
    pub fn check_ttl(&self, ttl: u8) -> bool {
        ttl > 0 && ttl <= self.config.max_ttl
    }

    /// 验证 gossip 交易信封 + tx 基本结构（N-5：**不执行**交易）。
    ///
    /// - envelope 签名验证（N-4）。
    /// - payload 大小（`max_msg_bytes`）。
    /// - tx canonical decode（结构合法；nonce/balance 等执行期校验不在此）。
    pub fn validate_gossip_tx(
        &self,
        vk: &VerifyingKey,
        envelope: &MessageEnvelope,
    ) -> Result<TransactionV1, NetworkError> {
        verify_message(vk, envelope)?;
        if !self.check_size(envelope.payload.len()) {
            return Err(NetworkError::InvalidLength {
                expected: self.config.max_msg_bytes,
                actual: envelope.payload.len(),
            });
        }
        decode_transaction(&envelope.payload).map_err(|_| NetworkError::InvalidSignature)
    }

    /// 验证 gossip 区块信封 + Block 结构（P7-5 F3；**不执行**、不解析语义——N-5）。
    ///
    /// - 消息类型必须为 `GossipBlock`（否则 `InvalidMessageType`）。
    /// - envelope 签名验证（N-4）。
    /// - payload 大小（`max_msg_bytes`）。
    /// - `decode_block` 结构验证（length/version/tag/trailing；P7-2）⇒ 失败 `InvalidBlockStructure`。
    /// - **不验证** signature/tx_root/state_root/height/parent/authority（归消费方 nova-runtime）。
    pub fn validate_gossip_block(
        &self,
        vk: &VerifyingKey,
        envelope: &MessageEnvelope,
    ) -> Result<Block, NetworkError> {
        if envelope.message_type != MessageType::GossipBlock {
            return Err(NetworkError::InvalidMessageType(
                envelope.message_type.as_u8(),
            ));
        }
        verify_message(vk, envelope)?;
        if !self.check_size(envelope.payload.len()) {
            return Err(NetworkError::InvalidLength {
                expected: self.config.max_msg_bytes,
                actual: envelope.payload.len(),
            });
        }
        decode_block(&envelope.payload).map_err(|_| NetworkError::InvalidBlockStructure)
    }

    /// 转发决策（去重 + TTL + 大小；N-5）。
    pub fn should_forward(&mut self, msg_id: [u8; 32], ttl: u8, msg_len: usize) -> GossipDecision {
        if !self.check_size(msg_len) {
            return GossipDecision::DropTooLarge;
        }
        if !self.check_ttl(ttl) {
            return GossipDecision::DropTtlExpired;
        }
        if !self.seen_insert(msg_id) {
            return GossipDecision::DropDuplicate;
        }
        GossipDecision::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageType;
    use crate::node_id::NodeId;
    use nova_crypto::key::KeyPair;

    fn msg_id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn gossip_forward_decision_rules() {
        let mut v = GossipValidator::new(GossipConfig::default());
        // 首次 → Forward
        assert_eq!(v.should_forward(msg_id(1), 3, 100), GossipDecision::Forward);
        // 重复 → DropDuplicate
        assert_eq!(
            v.should_forward(msg_id(1), 3, 100),
            GossipDecision::DropDuplicate
        );
        // TTL 过期（0 或 > max）
        assert_eq!(
            v.should_forward(msg_id(2), 0, 100),
            GossipDecision::DropTtlExpired
        );
        assert_eq!(
            v.should_forward(msg_id(3), 99, 100),
            GossipDecision::DropTtlExpired
        );
        // 过大
        assert_eq!(
            v.should_forward(msg_id(4), 3, usize::MAX),
            GossipDecision::DropTooLarge
        );
    }

    #[test]
    fn gossip_seen_cache_wraps() {
        let mut v = GossipValidator::new(GossipConfig {
            seen_cache_size: 2,
            ..GossipConfig::default()
        });
        assert!(v.seen_insert(msg_id(1)));
        assert!(v.seen_insert(msg_id(2)));
        // 缓存满 → 清空 → 旧 id 重新可见
        assert!(v.seen_insert(msg_id(3)));
        assert!(v.seen_insert(msg_id(1)), "缓存清空后 1 重新可见");
    }

    #[test]
    fn gossip_validate_rejects_bad_envelope() {
        let kp = KeyPair::generate().unwrap();
        let v = GossipValidator::new(GossipConfig::default());
        // 未签名 envelope ⇒ verify 失败
        let env = MessageEnvelope {
            version: 1,
            message_type: MessageType::GossipTransaction,
            payload: vec![0u8; 140],
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        assert_eq!(
            v.validate_gossip_tx(kp.verifying_key(), &env),
            Err(NetworkError::SenderMismatch),
            "未签名 envelope 验证失败"
        );
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
    fn gossip_validate_block_ok() {
        // P7-5 F3：合法 GossipBlock envelope + 完整 Block wire ⇒ 结构还原。
        let kp = KeyPair::generate().unwrap();
        let v = GossipValidator::new(GossipConfig::default());
        let block = mk_block();
        let mut env = MessageEnvelope {
            version: 1,
            message_type: MessageType::GossipBlock,
            payload: nova_core::block::encode_block(&block).unwrap(),
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        crate::message::sign_message(kp.signing_key(), &mut env).unwrap();
        let decoded = v.validate_gossip_block(kp.verifying_key(), &env).unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn gossip_validate_block_rejects() {
        // P7-5 F3 负路径：类型 / 结构 / 签名 / size。
        let kp = KeyPair::generate().unwrap();
        let v = GossipValidator::new(GossipConfig::default());
        let block = mk_block();
        let wire = nova_core::block::encode_block(&block).unwrap();
        let mut env = MessageEnvelope {
            version: 1,
            message_type: MessageType::GossipBlock,
            payload: wire.clone(),
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        crate::message::sign_message(kp.signing_key(), &mut env).unwrap();
        assert!(v.validate_gossip_block(kp.verifying_key(), &env).is_ok());

        // 错误消息类型 ⇒ InvalidMessageType
        let mut bad_type = env.clone();
        bad_type.message_type = MessageType::GossipTransaction;
        assert_eq!(
            v.validate_gossip_block(kp.verifying_key(), &bad_type),
            Err(NetworkError::InvalidMessageType(
                MessageType::GossipTransaction.as_u8()
            ))
        );

        // payload 结构非法（截断）⇒ InvalidBlockStructure
        let mut bad_struct = env.clone();
        bad_struct.payload = wire[..wire.len() - 1].to_vec();
        crate::message::sign_message(kp.signing_key(), &mut bad_struct).unwrap();
        assert_eq!(
            v.validate_gossip_block(kp.verifying_key(), &bad_struct),
            Err(NetworkError::InvalidBlockStructure)
        );

        // 签名篡改 ⇒ InvalidSignature
        let mut bad_sig = env.clone();
        bad_sig.signature[0] ^= 0xff;
        assert_eq!(
            v.validate_gossip_block(kp.verifying_key(), &bad_sig),
            Err(NetworkError::InvalidSignature)
        );

        // size 超限 ⇒ InvalidLength
        let small = GossipValidator::new(GossipConfig {
            max_msg_bytes: 10,
            ..GossipConfig::default()
        });
        assert_eq!(
            small.validate_gossip_block(kp.verifying_key(), &env),
            Err(NetworkError::InvalidLength {
                expected: 10,
                actual: env.payload.len()
            })
        );
    }
}
