//! P2P 消息信封（STEP 9-2 — ADR-0032 N-4）。
//!
//! - **签名覆盖** `version ‖ message_type ‖ payload`（**不覆盖 sender**——sender 由验证 key 决定，N-4）。
//! - `MessageType` V0.1 七类：`Handshake` / `Ping` / `Pong` / `GossipTransaction` /
//!   `SyncBlockRequest` / `SyncBlockResponse` / `Status`。
//! - 序列化 canonical binary；签名经 `hash_signing_message`（SHA-256）——**独立于链上
//!   Transaction/Vote/Block domain**（N-4；不新增 DomainId）。

use crate::node_id::NodeId;
use core::fmt;
use nova_crypto::domain::{SigningMessageHash, hash_signing_message};
use nova_crypto::signature::{
    Signature, SigningKey, VerifyingKey, sign_message_hash, verify_message_hash,
};

/// P2P 消息类型（V0.1 七类；ADR-0032 N-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// 握手（peer 身份交换）。
    Handshake = 0x01,
    /// 存活探测。
    Ping = 0x02,
    /// 存活响应。
    Pong = 0x03,
    /// 交易 gossip。
    GossipTransaction = 0x04,
    /// 区块同步请求（N-6）。
    SyncBlockRequest = 0x05,
    /// 区块同步响应（N-6）。
    SyncBlockResponse = 0x06,
    /// 状态广播（高度 / root 摘要）。
    Status = 0x07,
}

impl MessageType {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = NetworkError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Ping),
            0x03 => Ok(Self::Pong),
            0x04 => Ok(Self::GossipTransaction),
            0x05 => Ok(Self::SyncBlockRequest),
            0x06 => Ok(Self::SyncBlockResponse),
            0x07 => Ok(Self::Status),
            _ => Err(NetworkError::InvalidMessageType(v)),
        }
    }
}

/// 网络层错误（独立，nova-network 自有）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    /// 未知消息类型。
    InvalidMessageType(u8),
    /// 长度不符。
    InvalidLength { expected: usize, actual: usize },
    /// 签名无效（验证失败 / 畸形）。
    InvalidSignature,
    /// sender NodeId 与公钥派生身份不符（身份绑定失败）。
    SenderMismatch,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageType(t) => write!(f, "invalid message type: {t:#04x}"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid message length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignature => write!(f, "invalid message signature"),
            Self::SenderMismatch => write!(f, "sender NodeId does not match public key"),
        }
    }
}

impl std::error::Error for NetworkError {}

/// P2P 消息信封（ADR-0032 N-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: u8,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub sender: NodeId,
    pub signature: [u8; 64],
}

/// 签名覆盖部分：`version ‖ message_type ‖ payload`（不覆盖 sender）。
pub fn signed_payload(envelope: &MessageEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + envelope.payload.len());
    out.push(envelope.version);
    out.push(envelope.message_type.as_u8());
    out.extend_from_slice(&envelope.payload);
    out
}

/// 信封 message hash = `SHA-256(signed_payload)`（经 `hash_signing_message`）。
fn envelope_message_hash(envelope: &MessageEnvelope) -> SigningMessageHash {
    hash_signing_message(&signed_payload(envelope))
}

/// 签名信封（填 `sender` + `signature`；N-4）。
pub fn sign_message(
    signing: &SigningKey,
    envelope: &mut MessageEnvelope,
) -> Result<(), NetworkError> {
    envelope.sender = NodeId::from_verifying_key(&signing.verifying_key());
    let h = envelope_message_hash(envelope);
    envelope.signature = sign_message_hash(signing, &h).to_bytes();
    Ok(())
}

/// 验证信封（签名 + sender 身份绑定；N-4/N-7）。
pub fn verify_message(vk: &VerifyingKey, envelope: &MessageEnvelope) -> Result<(), NetworkError> {
    // 身份绑定：vk 派生 NodeId == sender（防伪装）。
    if NodeId::from_verifying_key(vk) != envelope.sender {
        return Err(NetworkError::SenderMismatch);
    }
    let h = envelope_message_hash(envelope);
    let sig =
        Signature::from_bytes(&envelope.signature).map_err(|_| NetworkError::InvalidSignature)?;
    verify_message_hash(vk, &h, &sig).map_err(|_| NetworkError::InvalidSignature)
}

/// canonical 二进制编码（N-4）：
/// `version(1B) ‖ type(1B) ‖ payload_len(4B LE) ‖ payload ‖ sender(32B) ‖ signature(64B)`。
pub fn encode(envelope: &MessageEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4 + envelope.payload.len() + 32 + 64);
    out.push(envelope.version);
    out.push(envelope.message_type.as_u8());
    out.extend_from_slice(&(envelope.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&envelope.payload);
    out.extend_from_slice(envelope.sender.as_bytes());
    out.extend_from_slice(&envelope.signature);
    out
}

/// canonical 二进制解码（拒绝未知类型 / 长度不符）。
pub fn decode(bytes: &[u8]) -> Result<MessageEnvelope, NetworkError> {
    if bytes.len() < 2 + 4 + 32 + 64 {
        return Err(NetworkError::InvalidLength {
            expected: 2 + 4 + 32 + 64,
            actual: bytes.len(),
        });
    }
    let version = bytes[0];
    let message_type = MessageType::try_from(bytes[1])?;
    let payload_len = u32::from_le_bytes(bytes[2..6].try_into().expect("len checked")) as usize;
    let expected = 2 + 4 + payload_len + 32 + 64;
    if bytes.len() != expected {
        return Err(NetworkError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    let payload = bytes[6..6 + payload_len].to_vec();
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[6 + payload_len..6 + payload_len + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[6 + payload_len + 32..6 + payload_len + 32 + 64]);
    Ok(MessageEnvelope {
        version,
        message_type,
        payload,
        sender: NodeId::from_bytes(sender),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::key::KeyPair;

    fn env(mt: MessageType, payload: Vec<u8>) -> MessageEnvelope {
        MessageEnvelope {
            version: 1,
            message_type: mt,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let kp = KeyPair::generate().unwrap();
        let mut e = env(MessageType::Handshake, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        assert_eq!(e.sender, NodeId::from_verifying_key(kp.verifying_key()));
        assert_eq!(
            verify_message(kp.verifying_key(), &e),
            Ok(()),
            "valid envelope verifies"
        );
    }

    #[test]
    fn verify_rejects_tampered_fields() {
        let kp = KeyPair::generate().unwrap();
        // payload 篡改
        let mut e = env(MessageType::GossipTransaction, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        e.payload[0] ^= 0xff;
        assert_eq!(
            verify_message(kp.verifying_key(), &e),
            Err(NetworkError::InvalidSignature),
            "tampered payload must fail"
        );
        // type 篡改
        let mut e2 = env(MessageType::GossipTransaction, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e2).unwrap();
        e2.message_type = MessageType::Ping;
        assert_eq!(
            verify_message(kp.verifying_key(), &e2),
            Err(NetworkError::InvalidSignature)
        );
        // version 篡改
        let mut e3 = env(MessageType::Handshake, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e3).unwrap();
        e3.version += 1;
        assert_eq!(
            verify_message(kp.verifying_key(), &e3),
            Err(NetworkError::InvalidSignature)
        );
        // sender 篡改（身份绑定失败）
        let mut e4 = env(MessageType::Handshake, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e4).unwrap();
        e4.sender = NodeId::from_bytes([0xee; 32]);
        assert_eq!(
            verify_message(kp.verifying_key(), &e4),
            Err(NetworkError::SenderMismatch)
        );
        // 错误 key 验证
        let kp2 = KeyPair::generate().unwrap();
        let mut e5 = env(MessageType::Handshake, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e5).unwrap();
        assert_eq!(
            verify_message(kp2.verifying_key(), &e5),
            Err(NetworkError::SenderMismatch),
            "wrong key fails identity binding"
        );
    }

    #[test]
    fn encode_decode_roundtrip_all_types() {
        let kp = KeyPair::generate().unwrap();
        for mt in [
            MessageType::Handshake,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::GossipTransaction,
            MessageType::SyncBlockRequest,
            MessageType::SyncBlockResponse,
            MessageType::Status,
        ] {
            let mut e = env(mt, vec![0xab; 17]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            let bytes = encode(&e);
            assert_eq!(decode(&bytes).unwrap(), e);
        }
    }

    #[test]
    fn decode_rejects_unknown_type_and_length() {
        // 未知 type
        let mut bad = vec![1u8, 0x08]; // type 0x08 未定义
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&[0u8; 32 + 64]);
        assert_eq!(decode(&bad), Err(NetworkError::InvalidMessageType(0x08)));
        // 长度不符
        let short = vec![1u8, 0x01, 0, 0, 0, 0, 0]; // 太短
        assert!(matches!(
            decode(&short),
            Err(NetworkError::InvalidLength { .. })
        ));
    }
}
