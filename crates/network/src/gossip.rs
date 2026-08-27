//! Gossip 规则（STEP 9-4 — ADR-0032 N-5）。
//!
//! - 流程：`Verify Envelope Signature → Validate Tx Basic Rules → Deduplicate → TTL → Rate Limit →
//!   Forward`。
//! - **禁止** gossip 阶段执行交易（N-5：网络层不能影响执行确定性）。
//! - V0.1 只冻结**验证 / 转发决策逻辑**（纯函数），不实现 Gossipsub 调度（N-3）。

use crate::message::{MessageEnvelope, NetworkError, verify_message};
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
}
