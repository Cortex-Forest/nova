//! Node 组装层（STEP 11-4）：Network envelope → classify → construct `ConsensusEvent` →
//! `transition` → `TransitionResult` 路由。
//!
//! # 范围（11-4 DESIGN FREEZE）
//! - **Vote 路径**：`ConsensusVote` wire → `validate_consensus_envelope`（Network）→
//!   classify → `decode_validator_vote`（Consensus 冻结 API）→ `ConsensusEvent::Vote` → `transition`。
//! - **RoundTimeout**：Node-local event（B-3，不经过 Network）→ `ConsensusEvent::RoundTimeout` → `transition`。
//!
//! # 边界（11-4 DESIGN FREEZE）
//! - **Node 不执行 Consensus verification**（`verify_vote` / `verify_qc` 归 Consensus）。
//! - **Node 不做 semantic replay / context 判定**（Consensus guards 归 Consensus）。
//! - Proposal / QC ingestion / A11：**DEFERRED**（本模块不实现）。
//! - Vote 的 V-5 验证边界由 Consensus 保证（MF-2 hard precondition）；调用点归 11-6 明确。

use nova_consensus::dag::Dag;
use nova_consensus::error::ConsensusError;
use nova_consensus::finality::FinalityState;
use nova_consensus::integration::{
    ConsensusEvent, ConsensusState, IntegrationContext, TransitionResult, transition,
};
use nova_consensus::round::RoundState;
use nova_consensus::validator::ValidatorSet;
use nova_consensus::vote::{ValidatorVote, decode_validator_vote, verify_vote_input};
use nova_crypto::signature::VerifyingKey;
use nova_network::message::{
    MessageEnvelope, MessageType, NetworkError, validate_consensus_envelope,
};

/// Vote wire payload 常量（11-1 §3）：`canonical_vote_payload(121B) ‖ signature(64B)`。
const VOTE_PAYLOAD_LEN: usize = 121;
const VOTE_SIGNATURE_LEN: usize = 64;
const VOTE_WIRE_LEN: usize = VOTE_PAYLOAD_LEN + VOTE_SIGNATURE_LEN;

/// Node 组装层错误（node crate 自有；不新增 network/consensus 错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// envelope 验证失败（network 域：签名 / sender / discriminator / size）。
    InvalidEnvelope(NetworkError),
    /// 非 Vote 消息（本轮仅 Vote + RoundTimeout）。
    UnsupportedMessage(MessageType),
    /// Vote wire payload 长度不符（非 185B）。
    InvalidVotePayloadLength { expected: usize, actual: usize },
    /// Vote canonical payload 结构解析失败（Consensus 域）。
    VoteDecode(ConsensusError),
    /// Vote 签名验证失败（Consensus 门面 V-5；MF-2 precondition 未满足）。
    VoteVerification(ConsensusError),
}

/// 组装节点：持有 Consensus 状态 + 上下文 + 冻结参数。
///
/// - `state` / `context`：Consensus canonical state + derived cache（MF-1/MF-12）。
/// - `chain_id` / `set` / `genesis_hash` / `dag`：transition 冻结参数。
/// - `state` 更新规则：`Applied` ⇒ 应用 `next_state`；`Ignored`/`Rejected` ⇒ 不变（MF-12 契约 3）。
pub struct ConsensusNode {
    state: ConsensusState,
    context: IntegrationContext,
    chain_id: u64,
    set: ValidatorSet,
    genesis_hash: [u8; 32],
    dag: Dag,
}

impl ConsensusNode {
    /// 初始状态；`(height, round)` 必须与初始 `ConsensusState.round` 一致（契约）。
    pub fn new(
        height: u64,
        round: u64,
        chain_id: u64,
        set: ValidatorSet,
        genesis_hash: [u8; 32],
        dag: Dag,
    ) -> Self {
        Self {
            state: ConsensusState {
                round: RoundState::new(height, round),
                finality: FinalityState::default(),
            },
            context: IntegrationContext::new(height, round),
            chain_id,
            set,
            genesis_hash,
            dag,
        }
    }

    /// 当前 Consensus 状态（只读）。
    pub fn state(&self) -> &ConsensusState {
        &self.state
    }

    /// 处理网络到达的 consensus envelope（Vote 路径）。
    ///
    /// 流程：`validate_consensus_envelope`（Network 域）→ classify → Vote decode → construct →
    /// `transition` → 返回 `TransitionResult`。`peer_vk` = 发送者公钥（envelope 签名验证）。
    pub fn handle_envelope(
        &mut self,
        peer_vk: &VerifyingKey,
        envelope: &MessageEnvelope,
        max_msg_bytes: usize,
    ) -> Result<TransitionResult, NodeError> {
        let mt = validate_consensus_envelope(peer_vk, envelope, max_msg_bytes)
            .map_err(NodeError::InvalidEnvelope)?;
        match mt {
            MessageType::ConsensusVote => self.handle_vote(&envelope.payload),
            other => Err(NodeError::UnsupportedMessage(other)),
        }
    }

    /// Node-local RoundTimeout（B-3）：不经过 Network，直接构造 `ConsensusEvent::RoundTimeout`。
    pub fn round_timeout(&mut self) -> TransitionResult {
        let result = transition(
            &self.state,
            ConsensusEvent::RoundTimeout,
            &mut self.context,
            self.chain_id,
            &self.set,
            &self.genesis_hash,
            &self.dag,
        );
        self.apply_result(&result);
        result
    }

    /// Vote 路径：decode wire payload → Consensus 验证门面（MF-2）→ construct
    /// `ConsensusEvent::Vote` → `transition`。
    fn handle_vote(&mut self, payload: &[u8]) -> Result<TransitionResult, NodeError> {
        let (vote, signature) = classify_vote_payload(payload)?;
        // Consensus 验证门面（GAP-1 解决；MF-2 precondition）——Node 不拥有 V-5 语义。
        verify_vote_input(&vote, &signature, self.chain_id, &self.set)
            .map_err(NodeError::VoteVerification)?;
        let result = transition(
            &self.state,
            ConsensusEvent::Vote { vote, signature },
            &mut self.context,
            self.chain_id,
            &self.set,
            &self.genesis_hash,
            &self.dag,
        );
        self.apply_result(&result);
        Ok(result)
    }

    /// `Applied` ⇒ 应用 `next_state`；`Ignored`/`Rejected` ⇒ 不变（MF-12 契约 3）。
    fn apply_result(&mut self, result: &TransitionResult) {
        if let TransitionResult::Applied { next_state, .. } = result {
            self.state = next_state.clone();
        }
    }
}

/// 解析 Vote wire payload（11-1 §3）：`canonical_vote_payload(121B) ‖ signature(64B)`。
///
/// - 长度严格 = 185B（拒截断/超长/trailing）。
/// - `decode_validator_vote`（Consensus 冻结 API）仅结构解析，不做 membership/签名验证。
fn classify_vote_payload(payload: &[u8]) -> Result<(ValidatorVote, [u8; 64]), NodeError> {
    if payload.len() != VOTE_WIRE_LEN {
        return Err(NodeError::InvalidVotePayloadLength {
            expected: VOTE_WIRE_LEN,
            actual: payload.len(),
        });
    }
    let vote =
        decode_validator_vote(&payload[..VOTE_PAYLOAD_LEN]).map_err(NodeError::VoteDecode)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload[VOTE_PAYLOAD_LEN..]);
    Ok((vote, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::validator::ValidatorId;
    use nova_consensus::vote::{VoteType, canonical_vote_payload};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use nova_network::message::sign_message;
    use nova_network::node_id::NodeId;

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn genesis_with(v: ValidatorInit) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 0,
            initial_validator_set: vec![v],
            initial_accounts: Vec::new(),
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 64 * 1024,
                max_block_bytes: 8 * 1024 * 1024,
                max_gas_per_block: 100_000_000_000,
                max_contract_code_bytes: 0,
                max_contract_storage_bytes: 0,
                epoch_length_blocks: 1_000_000,
                snapshot_interval_blocks: 10_000_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 1_000_000_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 100,
            },
        }
    }

    fn vote_sig(
        signing: &nova_crypto::signature::SigningKey,
        vote: &ValidatorVote,
        chain_id: u64,
    ) -> [u8; 64] {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            chain_id,
            &payload,
        )
        .unwrap();
        sign_message_hash(signing, &hash_signing_message(&signed)).to_bytes()
    }

    fn setup() -> (ConsensusNode, KeyPair, ValidatorSet, [u8; 32]) {
        let vk_kp = KeyPair::generate().unwrap();
        let v = ValidatorInit {
            account_address: addr([0xaa; 32]),
            consensus_public_key: vk_kp.verifying_key().to_bytes(),
            bonded_stake: 100,
            commission_bps: 100,
        };
        let genesis = genesis_with(v);
        let set = ValidatorSet::from_genesis(&genesis);
        let genesis_hash = [0xaa; 32];
        let node = ConsensusNode::new(0, 0, 1001, set.clone(), genesis_hash, Dag::new());
        (node, vk_kp, set, genesis_hash)
    }

    fn vote_envelope(
        signer_kp: &KeyPair,
        node_key: &KeyPair,
        round: u64,
        height: u64,
        chain_id: u64,
    ) -> MessageEnvelope {
        let vote = ValidatorVote {
            round,
            height,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(
                &node_key.verifying_key().to_bytes(),
            ),
            timestamp: 0,
        };
        let sig = vote_sig(node_key.signing_key(), &vote, chain_id);
        let mut payload = canonical_vote_payload(&vote);
        payload.extend_from_slice(&sig);
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusVote,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(signer_kp.signing_key(), &mut envelope).unwrap();
        envelope
    }

    /// envelope 有效 + vote 签名无效（双层签名独立）：vote.validator_id 指向 set validator，
    /// 但 vote 由非 validator key 签名 ⇒ Consensus 门面 V-5 拒（envelope 本身有效）。
    fn invalid_vote_sig_envelope(
        signer_kp: &KeyPair,
        validator_kp: &KeyPair,
        wrong_kp: &KeyPair,
        round: u64,
        height: u64,
        chain_id: u64,
    ) -> MessageEnvelope {
        let vote = ValidatorVote {
            round,
            height,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(
                &validator_kp.verifying_key().to_bytes(),
            ),
            timestamp: 0,
        };
        let sig = vote_sig(wrong_kp.signing_key(), &vote, chain_id);
        let mut payload = canonical_vote_payload(&vote);
        payload.extend_from_slice(&sig);
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusVote,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(signer_kp.signing_key(), &mut envelope).unwrap();
        envelope
    }

    #[test]
    fn handle_valid_vote_envelope_applies() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        // vote validator = set 中 validator（门面 V-5 要求 validator 在 set 且签名有效）
        let envelope = vote_envelope(&validator_kp, &validator_kp, 0, 0, 1001);
        let result = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap();
        assert!(matches!(result, TransitionResult::Applied { .. }));
        // 未达 quorum ⇒ observation 全 false
        if let TransitionResult::Applied {
            observation,
            derived,
            ..
        } = result
        {
            assert!(!observation.prevote_quorum);
            assert!(derived.prevote_qc.is_none());
        }
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_vote_wrong_context_ignored() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        // height/round 不匹配 state(0,0)（vote 签名有效 ⇒ 门面 Ok ⇒ transition guards 拒）
        let envelope = vote_envelope(&validator_kp, &validator_kp, 5, 5, 1001);
        let result = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap();
        assert!(matches!(
            result,
            TransitionResult::Ignored {
                reason: nova_consensus::integration::IgnoreReason::ContextMismatch
            }
        ));
        // state 不变（MF-12 契约 3）
        assert_eq!(node.state().round.round, 0);
        let _ = (set, genesis_hash);
    }

    #[test]
    fn round_timeout_advances_round() {
        let (mut node, _peer_kp, set, genesis_hash) = setup();
        let result = node.round_timeout();
        assert!(matches!(result, TransitionResult::Applied { .. }));
        assert_eq!(node.state().round.round, 1);
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_envelope_rejects_bad_envelope_signature() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        let mut envelope = vote_envelope(&validator_kp, &validator_kp, 0, 0, 1001);
        // 篡改 payload ⇒ envelope 签名失效（Network 域拒）
        envelope.payload[0] ^= 0xff;
        let err = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::InvalidEnvelope(nova_network::message::NetworkError::InvalidSignature)
        ));
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_envelope_rejects_invalid_vote_signature() {
        // 双层签名独立闭合：envelope 有效 + vote 签名无效 ⇒ Node 拒（Consensus 门面 V-5）。
        let (mut node, validator_kp, set, genesis_hash) = setup();
        let wrong_kp = KeyPair::generate().unwrap();
        let envelope =
            invalid_vote_sig_envelope(&validator_kp, &validator_kp, &wrong_kp, 0, 0, 1001);
        let err = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::VoteVerification(nova_consensus::error::ConsensusError::InvalidSignature)
        ));
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_envelope_rejects_unsupported_message() {
        let (mut node, peer_kp, set, genesis_hash) = setup();
        // ConsensusProposal wire（本轮不支持——Proposal DEFERRED）
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusProposal,
            payload: vec![0u8; 32],
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(peer_kp.signing_key(), &mut envelope).unwrap();
        let err = node
            .handle_envelope(peer_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert_eq!(
            err,
            NodeError::UnsupportedMessage(MessageType::ConsensusProposal)
        );
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_vote_rejects_bad_payload_length() {
        let (mut node, peer_kp, set, genesis_hash) = setup();
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusVote,
            payload: vec![0u8; 100], // 非 185B
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(peer_kp.signing_key(), &mut envelope).unwrap();
        let err = node
            .handle_envelope(peer_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert!(matches!(err, NodeError::InvalidVotePayloadLength { .. }));
        let _ = (set, genesis_hash);
    }

    #[test]
    fn classify_vote_payload_roundtrip() {
        let node_kp = KeyPair::generate().unwrap();
        let vote = ValidatorVote {
            round: 0,
            height: 0,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(
                &node_kp.verifying_key().to_bytes(),
            ),
            timestamp: 0,
        };
        let sig = vote_sig(node_kp.signing_key(), &vote, 1001);
        let mut payload = canonical_vote_payload(&vote);
        payload.extend_from_slice(&sig);
        let (v, s) = classify_vote_payload(&payload).unwrap();
        assert_eq!(v, vote);
        assert_eq!(s, sig);
    }
}
