//! P2P 消息信封（STEP 9-2 — ADR-0032 N-4）。
//!
//! - **签名覆盖** `version ‖ message_type ‖ payload`（**不覆盖 sender**——sender 由验证 key 决定，N-4）。
//! - `MessageType` V0.1 十类：`Handshake` / `Ping` / `Pong` / `GossipTransaction` /
//!   `SyncBlockRequest` / `SyncBlockResponse` / `Status`（7 类，STEP 9-2）+ `ConsensusVote` /
//!   `ConsensusProposal` / `ConsensusQc`（3 类 Consensus wire discriminator，STEP 11-2；
//!   payload opaque，Network 不解析共识语义，不依赖 consensus crate；注册值 ≠ 协议语义）。
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
    /// 共识投票 wire discriminator（STEP 11-2；payload opaque；仅 wire 注册值，≠ 协议语义）。
    ConsensusVote = 0x08,
    /// 共识提案 wire discriminator（STEP 11-2；payload opaque；ProposalRef encoding 本 STEP 不定义）。
    ConsensusProposal = 0x09,
    /// 共识 QC wire discriminator（STEP 11-2；payload opaque；不代表存在可消费的 ingestion path）。
    ConsensusQc = 0x0A,
    /// 区块 gossip（P7-5；payload = 完整 Block wire；仅 wire 注册值，Network 不解析语义）。
    GossipBlock = 0x0B,
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
            0x08 => Ok(Self::ConsensusVote),
            0x09 => Ok(Self::ConsensusProposal),
            0x0a => Ok(Self::ConsensusQc),
            0x0b => Ok(Self::GossipBlock),
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
    /// Block 结构验证失败（decode_block 拒绝：length/version/tag/trailing；P7-5 F4）。
    InvalidBlockStructure,
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
            Self::InvalidBlockStructure => write!(f, "invalid block structure"),
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

/// Network envelope validation API（STEP 11-3，**非 Consensus validation**）。
///
/// 验证边界（Network 域）：
/// 1. N-4 envelope 签名 + sender 身份绑定（`verify_message`）。
/// 2. `message_type` ∈ {`ConsensusVote`, `ConsensusProposal`, `ConsensusQc`}（否则 `InvalidMessageType`）。
/// 3. payload 长度 ≤ `max_msg_bytes`（**既有消息大小约束**，非完整 payload validation）。
///
/// payload 保持 **OPAQUE**——不解析/不验证共识语义（Vote validity / QC evidence / quorum 归
/// Node/Consensus）；语义 replay 检测归 Consensus context guards（10-11 §7）。
pub fn validate_consensus_envelope(
    vk: &VerifyingKey,
    envelope: &MessageEnvelope,
    max_msg_bytes: usize,
) -> Result<MessageType, NetworkError> {
    verify_message(vk, envelope)?;
    match envelope.message_type {
        MessageType::ConsensusVote | MessageType::ConsensusProposal | MessageType::ConsensusQc => {}
        other => return Err(NetworkError::InvalidMessageType(other.as_u8())),
    }
    if envelope.payload.len() > max_msg_bytes {
        return Err(NetworkError::InvalidLength {
            expected: max_msg_bytes,
            actual: envelope.payload.len(),
        });
    }
    Ok(envelope.message_type)
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
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
            MessageType::GossipBlock,
        ] {
            let mut e = env(mt, vec![0xab; 17]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            let bytes = encode(&e);
            assert_eq!(decode(&bytes).unwrap(), e);
        }
    }

    #[test]
    fn decode_rejects_unknown_type_and_length() {
        // 未知 type（0x08~0x0B 已定义；0x0C 未知）
        let mut bad = vec![1u8, 0x0C];
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&[0u8; 32 + 64]);
        assert_eq!(decode(&bad), Err(NetworkError::InvalidMessageType(0x0C)));
        // 长度不符
        let short = vec![1u8, 0x01, 0, 0, 0, 0, 0]; // 太短
        assert!(matches!(
            decode(&short),
            Err(NetworkError::InvalidLength { .. })
        ));
    }

    #[test]
    fn consensus_wire_type_byte_values() {
        // T6: 字节值断言 + TryFrom 双向。
        assert_eq!(MessageType::ConsensusVote.as_u8(), 0x08);
        assert_eq!(MessageType::ConsensusProposal.as_u8(), 0x09);
        assert_eq!(MessageType::ConsensusQc.as_u8(), 0x0a);
        assert_eq!(MessageType::try_from(0x08), Ok(MessageType::ConsensusVote));
        assert_eq!(
            MessageType::try_from(0x09),
            Ok(MessageType::ConsensusProposal)
        );
        assert_eq!(MessageType::try_from(0x0a), Ok(MessageType::ConsensusQc));
        assert_eq!(MessageType::GossipBlock.as_u8(), 0x0b);
        assert_eq!(MessageType::try_from(0x0b), Ok(MessageType::GossipBlock));
    }

    #[test]
    fn consensus_wire_payload_opaque_roundtrip() {
        // T2/T7: 3 个 Consensus 类型 payload 在既有 size constraints 内对任意字节内容
        // opaque、无损 roundtrip；Network 不因 payload 内容而拒（语义中性）。
        let kp = KeyPair::generate().unwrap();
        let payloads: &[Vec<u8>] = &[
            vec![],
            vec![0x00],
            vec![0xff; 64],
            (0..=255u8).collect(),
            vec![0xab; 1024],
        ];
        for mt in [
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
        ] {
            for p in payloads {
                let mut e = env(mt, p.clone());
                sign_message(kp.signing_key(), &mut e).unwrap();
                assert_eq!(
                    decode(&encode(&e)).unwrap(),
                    e,
                    "consensus wire payload opaque roundtrip"
                );
            }
        }
    }

    #[test]
    fn consensus_wire_sign_verify_ok() {
        // T3: 3 个 Consensus 类型信封签名有效。
        let kp = KeyPair::generate().unwrap();
        for mt in [
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
        ] {
            let mut e = env(mt, vec![0x42; 16]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            assert_eq!(verify_message(kp.verifying_key(), &e), Ok(()));
        }
    }

    #[test]
    fn consensus_wire_tamper_rejected() {
        // T4: 对 Consensus 类型信封篡改 payload/type/version/sender ⇒ 验证拒绝（N-4）。
        let kp = KeyPair::generate().unwrap();
        // payload 篡改
        let mut e = env(MessageType::ConsensusVote, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        e.payload[0] ^= 0xff;
        assert_eq!(
            verify_message(kp.verifying_key(), &e),
            Err(NetworkError::InvalidSignature)
        );
        // type 篡改（ConsensusVote → ConsensusProposal）
        let mut e2 = env(MessageType::ConsensusVote, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e2).unwrap();
        e2.message_type = MessageType::ConsensusProposal;
        assert_eq!(
            verify_message(kp.verifying_key(), &e2),
            Err(NetworkError::InvalidSignature)
        );
        // version 篡改
        let mut e3 = env(MessageType::ConsensusQc, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e3).unwrap();
        e3.version += 1;
        assert_eq!(
            verify_message(kp.verifying_key(), &e3),
            Err(NetworkError::InvalidSignature)
        );
        // sender 篡改（身份绑定失败）
        let mut e4 = env(MessageType::ConsensusProposal, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e4).unwrap();
        e4.sender = NodeId::from_bytes([0xee; 32]);
        assert_eq!(
            verify_message(kp.verifying_key(), &e4),
            Err(NetworkError::SenderMismatch)
        );
    }

    #[test]
    fn validate_consensus_envelope_ok_all_types() {
        // T1: 3 个 Consensus 类型有效 envelope → Ok(MessageType)。
        let kp = KeyPair::generate().unwrap();
        for mt in [
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
        ] {
            let mut e = env(mt, vec![0x11; 32]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            assert_eq!(
                validate_consensus_envelope(kp.verifying_key(), &e, 64 * 1024),
                Ok(mt)
            );
        }
    }

    #[test]
    fn validate_consensus_envelope_rejects_non_consensus_type() {
        // T2: 非 Consensus discriminator → InvalidMessageType。
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
            let mut e = env(mt, vec![1, 2, 3]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            assert_eq!(
                validate_consensus_envelope(kp.verifying_key(), &e, 64 * 1024),
                Err(NetworkError::InvalidMessageType(mt.as_u8()))
            );
        }
    }

    #[test]
    fn validate_consensus_envelope_rejects_oversize() {
        // T3: payload 超既有 size constraint → InvalidLength。
        let kp = KeyPair::generate().unwrap();
        let mut e = env(MessageType::ConsensusVote, vec![0u8; 100]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e, 64),
            Err(NetworkError::InvalidLength {
                expected: 64,
                actual: 100,
            })
        );
    }

    #[test]
    fn validate_consensus_envelope_rejects_tampering() {
        // T4: 篡改 payload/type/version/sender ⇒ 拒（N-4 signature coverage + sender binding）。
        let kp = KeyPair::generate().unwrap();
        // payload 篡改
        let mut e = env(MessageType::ConsensusVote, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        e.payload[0] ^= 0xff;
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e, 64 * 1024),
            Err(NetworkError::InvalidSignature)
        );
        // type 篡改（ConsensusVote → ConsensusProposal）
        let mut e2 = env(MessageType::ConsensusVote, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e2).unwrap();
        e2.message_type = MessageType::ConsensusProposal;
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e2, 64 * 1024),
            Err(NetworkError::InvalidSignature)
        );
        // version 篡改
        let mut e3 = env(MessageType::ConsensusQc, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e3).unwrap();
        e3.version += 1;
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e3, 64 * 1024),
            Err(NetworkError::InvalidSignature)
        );
        // sender 篡改（身份绑定失败）
        let mut e4 = env(MessageType::ConsensusProposal, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e4).unwrap();
        e4.sender = NodeId::from_bytes([0xee; 32]);
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e4, 64 * 1024),
            Err(NetworkError::SenderMismatch)
        );
    }

    #[test]
    fn validate_consensus_envelope_payload_opaque() {
        // T5: 双层签名独立性 Network 侧——opaque payload（伪装 vote/QC 字节）→ Ok。
        // Network 不解析/不验证共识语义（vote 签名 / QC evidence 归 Node/Consensus）。
        let kp = KeyPair::generate().unwrap();
        // 伪装 vote payload（121B canonical + 64B signature 形态）
        let fake_vote = vec![0x5a; 121 + 64];
        // 伪装 QC payload（encode_qc 形态：93B header + count*136B）
        let fake_qc = vec![0x3c; 93 + 136];
        for (mt, payload) in [
            (MessageType::ConsensusVote, fake_vote),
            (MessageType::ConsensusProposal, vec![0x01; 32]),
            (MessageType::ConsensusQc, fake_qc),
        ] {
            let mut e = env(mt, payload);
            sign_message(kp.signing_key(), &mut e).unwrap();
            assert_eq!(
                validate_consensus_envelope(kp.verifying_key(), &e, 64 * 1024),
                Ok(mt),
                "Network 不解析/不验证 consensus semantic payload"
            );
        }
    }

    #[test]
    fn validate_consensus_envelope_zero_size_boundary() {
        // T6: max_msg_bytes=0 边界：空 payload Ok / 非空 Err。
        let kp = KeyPair::generate().unwrap();
        let mut e = env(MessageType::ConsensusVote, vec![]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e, 0),
            Ok(MessageType::ConsensusVote)
        );
        let mut e2 = env(MessageType::ConsensusVote, vec![0u8; 1]);
        sign_message(kp.signing_key(), &mut e2).unwrap();
        assert_eq!(
            validate_consensus_envelope(kp.verifying_key(), &e2, 0),
            Err(NetworkError::InvalidLength {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn validate_consensus_envelope_after_decode_roundtrip() {
        // T7: canonical envelope bytes roundtrip → validate 一致。
        let kp = KeyPair::generate().unwrap();
        for mt in [
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
        ] {
            let mut e = env(mt, vec![0x77; 48]);
            sign_message(kp.signing_key(), &mut e).unwrap();
            let decoded = decode(&encode(&e)).unwrap();
            assert_eq!(
                validate_consensus_envelope(kp.verifying_key(), &decoded, 64 * 1024),
                Ok(mt)
            );
        }
    }

    #[test]
    fn validate_consensus_envelope_no_replay_tracking() {
        // T9: replay boundary——Network 无状态，不跟踪语义 replay。
        // 同一有效 envelope 重复验证 → 均 Ok（语义 replay 检测归 Consensus context guards，10-11 §7）。
        let kp = KeyPair::generate().unwrap();
        let mut e = env(MessageType::ConsensusVote, vec![1, 2, 3]);
        sign_message(kp.signing_key(), &mut e).unwrap();
        for _ in 0..3 {
            assert_eq!(
                validate_consensus_envelope(kp.verifying_key(), &e, 64 * 1024),
                Ok(MessageType::ConsensusVote)
            );
        }
    }

    // T8（unknown discriminator 解码 0x0B → InvalidMessageType）由既有
    // `decode_rejects_unknown_type_and_length` 覆盖（decode 层），此处不重复创建。
}
