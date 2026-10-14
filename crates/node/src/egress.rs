//! Node Production Egress Adapter（STEP 10-18I-N-IMPL）。
//!
//! # 定位
//! 把 Driver 已产生的 **semantic outbound**（`OutboundConsensusMessage`，验证 PASS 才 record）
//! 编码为 `MessageEnvelope` 并经 [`NetworkSigner`]（网络身份）签名 —— 供 NetworkService 发送。
//!
//! 边界（ADR-0059 NS-SEC-6/7/10）：
//! - 本模块**不做任何 consensus verification**（不 verify_qc / 不判 finality / 不 vote safety）；
//!   QC 只接受 Driver 已 `verify_qc` 后 record 的 `VerifiedQc`。
//! - 复用既有 canonical encoding：`canonical_vote_payload` / `encode_qc` /
//!   `encode_proposal_ref`（**不重新定义** wire）。
//! - 签名用 `NetworkSigner`（网络 key；sender = network NodeId）；与 ValidatorId/key 分离。
//! - 不直接操作 private key、不重实现 Ed25519、不改 NetworkIdentity。
//!
//! # 数据流
//! ```text
//! Driver.take_outbound() → OutboundConsensusMessage
//!   → encode_semantic() → (MessageType, canonical payload)
//!   → envelope_for()（NetworkSigner.sign_envelope）→ MessageEnvelope
//!   → NetworkService.broadcast/enqueue（established-only / queue bound 由 NS 负责）
//! ```

use nova_consensus::finality::encode_qc;
use nova_consensus::round::encode_proposal_ref;
use nova_consensus::vote::canonical_vote_payload;
use nova_network::message::{MessageEnvelope, MessageType};
use nova_network::node_id::NodeId;

use crate::network_identity::{NetworkSigner, NetworkSigningError};
use crate::outbound::OutboundConsensusMessage;

/// Node Egress 错误（fail-closed；不吞安全错误）。
#[derive(Debug)]
pub enum EgressError {
    /// 网络签名失败（NetworkSigner.sign_envelope）。
    Signing(NetworkSigningError),
    /// O2 `RoundChangeCertificate` canonical 编码失败（冻结 ADR-0070 codec；
    /// 组装保证下不应发生，但**绝不**静默产生畸形 payload）。
    RoundChangeEncode(nova_consensus::round_change::RoundChangeError),
}

impl core::fmt::Display for EgressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Signing(e) => write!(f, "network egress signing failed: {e:?}"),
            Self::RoundChangeEncode(e) => {
                write!(f, "round-change certificate encoding failed: {e:?}")
            }
        }
    }
}

impl core::error::Error for EgressError {}

/// consensus semantic → `(MessageType, canonical payload)`。
///
/// - `Vote`    → `ConsensusVote`：`canonical_vote_payload(121B) ‖ signature(64B)`（185B；与
///   inbound decode 对称）。
/// - `Proposal`→ `ConsensusProposal`：canonical `ProposalRef`（block_hash 32B ‖ proposer 32B）。
/// - `VerifiedQc` → `ConsensusQc`：canonical `QuorumCertificate`（仅 Driver 已 verify 的 QC）。
/// - `GossipBlock` → `GossipBlock`：**已编码** block wire 原样透传（发送侧不重编码 / 不二次序列化；
///   与 inbound 同一 wire 格式，由生产方经 `nova_runtime::encode_block` 产出）。
///
/// 不做任何 verify；只做确定性编码。
pub fn encode_semantic(
    msg: &OutboundConsensusMessage,
) -> Result<(MessageType, Vec<u8>), EgressError> {
    match msg {
        OutboundConsensusMessage::Vote { vote, signature } => {
            let mut payload = canonical_vote_payload(vote);
            payload.extend_from_slice(signature);
            Ok((MessageType::ConsensusVote, payload))
        }
        OutboundConsensusMessage::Proposal(pr) => {
            Ok((MessageType::ConsensusProposal, encode_proposal_ref(pr)))
        }
        OutboundConsensusMessage::VerifiedQc(qc) => Ok((MessageType::ConsensusQc, encode_qc(qc))),
        OutboundConsensusMessage::GossipBlock(wire) => Ok((MessageType::GossipBlock, wire.clone())),
        // PHASE 6H-Z D2-4：委托**冻结** ADR-0070 codec（**不**建立第二套 RC 序列化）。
        OutboundConsensusMessage::RoundChange(cert) => {
            let payload = nova_consensus::round_change::encode_certificate(cert)
                .map_err(EgressError::RoundChangeEncode)?;
            Ok((MessageType::ConsensusRoundChange, payload))
        }
        // PHASE 6H-AF：委托**冻结** ADR-0074 codec（精确 112B；定长 ⇒ 编码不可失败）。
        OutboundConsensusMessage::AbandonAttestation(attestation) => Ok((
            MessageType::ConsensusAbandonAttestation,
            nova_network::abandon_attestation::encode(attestation),
        )),
    }
}

/// semantic → 已签名 `MessageEnvelope`（`sender` = network NodeId；`signature` = network key）。
pub fn envelope_for(
    msg: &OutboundConsensusMessage,
    signer: &dyn NetworkSigner,
) -> Result<MessageEnvelope, EgressError> {
    let (message_type, payload) = encode_semantic(msg)?;
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: NodeId::from_bytes([0; 32]), // sign_envelope 会用网络 key 派生 sender
        signature: [0u8; 64],
    };
    signer
        .sign_envelope(&mut envelope)
        .map_err(EgressError::Signing)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::round::{ProposalRef, encode_proposal_ref};
    use nova_crypto::key::KeyPair;
    use nova_network::message::verify_message;

    use crate::network_identity::SoftwareNetworkIdentity;
    use crate::outbound::OutboundConsensusMessage;
    use nova_consensus::finality::QuorumCertificate;

    fn net_kp() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    fn proposal_ref() -> ProposalRef {
        ProposalRef {
            block_hash: [0xAA; 32],
            proposer: nova_consensus::validator::ValidatorId::from_bytes([0xBB; 32]),
        }
    }

    fn fake_qc() -> QuorumCertificate {
        // 仅用于编码层测试：VerifiedQc 只表达 Driver 已认可的 QC（此处不 verify —— 编码只做 wire）。
        use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
        QuorumCertificate {
            context: QcContext {
                chain_id: 1001,
                height: 0,
                round: 0,
                vote_type: nova_consensus::vote::VoteType::Precommit,
            },
            target: [0xAA; 32],
            validator_set_id: [0x11; 32],
            evidence: Vec::<QcEvidence>::new(),
        }
    }

    #[test]
    fn semantic_encoding_mapping() {
        // Vote
        let vote = nova_consensus::vote::ValidatorVote {
            round: 0,
            height: 0,
            target_block_hash: [0xAA; 32],
            vote_type: nova_consensus::vote::VoteType::Prevote,
            source_block_hash: [0; 32],
            validator_id: nova_consensus::validator::ValidatorId::from_bytes([0xBB; 32]),
            timestamp: 0,
        };
        let (mt, payload) = encode_semantic(&OutboundConsensusMessage::Vote {
            vote,
            signature: [0xCC; 64],
        })
        .expect("encode");
        assert_eq!(mt, MessageType::ConsensusVote);
        assert_eq!(payload.len(), 121 + 64, "canonical vote payload ‖ sig");
        // Proposal
        let (mt, payload) =
            encode_semantic(&OutboundConsensusMessage::Proposal(proposal_ref())).expect("encode");
        assert_eq!(mt, MessageType::ConsensusProposal);
        assert_eq!(
            payload,
            encode_proposal_ref(&proposal_ref()),
            "canonical ProposalRef（64B）"
        );
        assert_eq!(payload.len(), 64);
        // VerifiedQc
        let (mt, _payload) =
            encode_semantic(&OutboundConsensusMessage::VerifiedQc(fake_qc())).expect("encode");
        assert_eq!(mt, MessageType::ConsensusQc);
    }

    /// PHASE 6H-Z §14-D2-14：`RoundChange` → `MessageType::ConsensusRoundChange = 0x0D`，
    /// payload = **冻结** ADR-0070 canonical 证书编码（**不**建立第二套序列化）。
    #[test]
    fn round_change_egress_uses_0x0d_and_frozen_codec() {
        use nova_consensus::round_change::{RoundChangeCertificate, RoundChangeEvidence};
        let cert = RoundChangeCertificate {
            validator_set_id: [0xAB; 32],
            height: 7,
            from_round: 3,
            evidence: vec![RoundChangeEvidence {
                validator_id: nova_consensus::validator::ValidatorId::from_bytes([0xCD; 32]),
                signature: [0xEF; 64],
            }],
        };
        let (mt, payload) =
            encode_semantic(&OutboundConsensusMessage::RoundChange(cert.clone())).expect("encode");
        assert_eq!(mt, MessageType::ConsensusRoundChange);
        assert_eq!(mt.as_u8(), 0x0D, "ADR-0073 冻结分配");
        assert_eq!(
            payload,
            nova_consensus::round_change::encode_certificate(&cert).expect("frozen codec"),
            "必须与冻结 codec 字节一致（无第二套序列化）"
        );
        assert_eq!(payload.len(), 50 + 96, "50 + 96n（n = 1）");
        // 往返：冻结 decode 可逆。
        let back = nova_consensus::round_change::decode_certificate(&payload).expect("decode");
        assert_eq!(back, cert);
    }

    #[test]
    fn envelope_for_signs_with_network_identity() {
        let kp = net_kp();
        let vk = *kp.verifying_key(); // owned copy（VerifyingKey: Copy）
        let signer = SoftwareNetworkIdentity::new(kp);
        let env =
            envelope_for(&OutboundConsensusMessage::Proposal(proposal_ref()), &signer).unwrap();
        // sender 由 sign_envelope 填 = 网络 key NodeId（与 kp 派生一致）。
        assert_eq!(
            env.sender,
            nova_network::node_id::NodeId::from_verifying_key(&vk),
            "sender = network NodeId"
        );
        // 签名有效（网络 key 验签）。
        verify_message(&vk, &env).expect("network identity signature valid");
        assert_eq!(env.message_type, MessageType::ConsensusProposal);
    }

    #[test]
    fn proposal_wire_is_64_bytes() {
        let payload = encode_proposal_ref(&proposal_ref());
        assert_eq!(payload.len(), 64, "block_hash 32B ‖ proposer 32B");
    }
}
