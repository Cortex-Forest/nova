//! O2 Round-Change wire 集成测试（**PHASE 6H-Y**）。
//!
//! 覆盖（ADR-0073 冻结分配 `ConsensusRoundChange = 0x0D`）：
//! - wire round-trip（envelope encode/decode）
//! - 0x0D 与既有取值并存，互不影响
//! - unknown MessageType 保持 fail-closed（含既有 0x0C 否定样本语义不变）
//! - 2066B 证书在既有 framing 上限（1 MiB）之下
//! - **混合版本 fail-closed**：旧节点对 0x0D 的行为 = `InvalidMessageType`（拒绝、不崩溃）

use nova_network::message::{MessageEnvelope, MessageType, decode, encode};
use nova_network::node_id::NodeId;
use nova_network::security::MAX_NETWORK_MESSAGE_PAYLOAD_BYTES;
use nova_network::transport::frame_encode;

/// 构造一个可编解码的 envelope（sender 为确定性 NodeId；签名仅需长度合法以测 wire）。
fn envelope_with(message_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: NodeId::from_bytes([0x07; 32]),
        signature: [0u8; 64],
    }
}

#[test]
fn message_type_0x0d_is_allocated_and_decodes() {
    assert_eq!(MessageType::ConsensusRoundChange.as_u8(), 0x0D);
    assert_eq!(
        MessageType::try_from(0x0D).unwrap(),
        MessageType::ConsensusRoundChange
    );
}

#[test]
fn wire_round_trip_0x0d() {
    let payload = vec![0xAB; 2066];
    let env = envelope_with(MessageType::ConsensusRoundChange, payload.clone());
    let encoded = encode(&env);
    let decoded = decode(&encoded).expect("decode");
    assert_eq!(decoded.message_type, MessageType::ConsensusRoundChange);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.sender, env.sender);
}

// ---------------------------------------------------------------------------
// PHASE 6H-AF — `0x0E = ConsensusAbandonAttestation`（ADR-0075 FROZEN）
// ---------------------------------------------------------------------------

#[test]
fn message_type_0x0e_is_allocated_and_decodes() {
    assert_eq!(MessageType::ConsensusAbandonAttestation.as_u8(), 0x0E);
    assert_eq!(
        MessageType::try_from(0x0E).unwrap(),
        MessageType::ConsensusAbandonAttestation
    );
    // 0x0E ≠ 0x0D（证书）—— 两个 MessageType 互不混用（ADR-0075 §6 / Rule M-3）。
    assert_ne!(
        MessageType::ConsensusAbandonAttestation,
        MessageType::ConsensusRoundChange
    );
}

#[test]
fn wire_round_trip_0x0e_carries_112_byte_container() {
    // ADR-0074：精确 112B canonical container。
    let att = nova_network::abandon_attestation::AbandonAttestation {
        height: 9,
        from_round: 4,
        validator_id: [0x11; 32],
        signature: [0x22; 64],
    };
    let payload = nova_network::abandon_attestation::encode(&att);
    assert_eq!(payload.len(), 112);
    let env = envelope_with(MessageType::ConsensusAbandonAttestation, payload.clone());
    let encoded = encode(&env);
    let decoded = decode(&encoded).expect("decode");
    assert_eq!(
        decoded.message_type,
        MessageType::ConsensusAbandonAttestation
    );
    assert_eq!(decoded.payload, payload);
    // 接收侧 payload → ADR-0074 decode 可逆。
    assert_eq!(
        nova_network::abandon_attestation::decode(&decoded.payload).expect("container decode"),
        att
    );
    // 既有 framing 可承载（112B ≪ 1 MiB）。
    let framed = frame_encode(&encoded, MAX_NETWORK_MESSAGE_PAYLOAD_BYTES).expect("frame");
    assert_eq!(framed.len(), 4 + encoded.len());
}

#[test]
fn allocated_types_coexist_without_collision() {
    // 0x0C = sentinel（未分配）；0x0D = 证书；0x0E = attestation —— 三者语义独立。
    assert!(MessageType::try_from(0x0C).is_err());
    assert_eq!(
        MessageType::try_from(0x0D).unwrap(),
        MessageType::ConsensusRoundChange
    );
    assert_eq!(
        MessageType::try_from(0x0E).unwrap(),
        MessageType::ConsensusAbandonAttestation
    );
    assert!(MessageType::try_from(0x0F).is_err());
    assert!(MessageType::try_from(0xFF).is_err());
}

#[test]
fn existing_message_types_unaffected() {
    for (value, expected) in [
        (0x01u8, MessageType::Handshake),
        (0x07, MessageType::Status),
        (0x08, MessageType::ConsensusVote),
        (0x0B, MessageType::GossipBlock),
    ] {
        assert_eq!(MessageType::try_from(value).unwrap(), expected);
    }
}

#[test]
fn unknown_message_types_still_fail_closed() {
    // 0x0C = 永久 unknown / negative-test sentinel（ADR-0075 §7；Owner D-3）。
    // 0x0E 已由 ADR-0075 §4 分配为 ConsensusAbandonAttestation（不再作为负向样本）。
    assert!(MessageType::try_from(0x0C).is_err());
    // 0xFF / 0x00 仍未分配。
    assert!(MessageType::try_from(0xFF).is_err());
    assert!(MessageType::try_from(0x00).is_err());
}

#[test]
fn mixed_version_old_node_rejects_unknown_type_fail_closed() {
    // 旧节点（其二进制不含 0x0D 分支）对未知类型走【同一条】fail-closed 路径。
    // 新二进制中 0x0D 已注册，故以【永久 sentinel】0x0C 复现该路径（ADR-0075 §7；Owner D-3）；
    // 旧节点对 0x0D 的行为与之完全一致（同一 `_ => Err(InvalidMessageType)` 分支）。
    let payload_len: u32 = 0;
    let mut raw = vec![1u8, 0x0C];
    raw.extend_from_slice(&payload_len.to_le_bytes());
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&[0u8; 64]);
    let err = decode(&raw).expect_err("未分配类型必须被拒绝");
    assert_eq!(
        err,
        nova_network::message::NetworkError::InvalidMessageType(0x0C)
    );
}

#[test]
fn certificate_size_fits_existing_frame_ceiling() {
    // ADR-0070 §8：MAX_CERTIFICATE_BYTES = 2066 ≪ 1 MiB。
    // 以运行期长度断言（避免常量断言），并验证既有 framing 仍可承载最大证书。
    let env = envelope_with(MessageType::ConsensusRoundChange, vec![0u8; 2066]);
    let encoded = encode(&env);
    assert!(encoded.len() <= MAX_NETWORK_MESSAGE_PAYLOAD_BYTES);
    assert!(encoded.len() > 2066);
    // 既有 framing：len(4B LE) ‖ payload；len ≤ max_frame
    let framed = frame_encode(&encoded, MAX_NETWORK_MESSAGE_PAYLOAD_BYTES).expect("frame");
    assert_eq!(framed.len(), 4 + encoded.len());
    let declared = u32::from_le_bytes(framed[0..4].try_into().unwrap()) as usize;
    assert_eq!(declared, encoded.len());
}
