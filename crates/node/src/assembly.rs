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

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::error::ConsensusError;
use nova_consensus::finality::{
    Applicability, FinalityError, FinalityState, InapplicableReason, QuorumCertificate, UpdateMode,
    check_finality_applicability, update_finalized_reference,
};
use nova_consensus::integration::{
    ConsensusEvent, ConsensusState, IntegrationContext, TransitionResult, transition,
};
use nova_consensus::round::{ProposalRef, RoundState, decode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, decode_validator_vote, verify_vote_input};
use nova_crypto::signature::VerifyingKey;
use nova_network::message::{
    MessageEnvelope, MessageType, NetworkError, validate_consensus_envelope,
};

/// P1-A.7（ADR-0064）— Verified External Finality Adoption 的结果（node-local；无新共识语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionOutcome {
    /// `Applicable::Advance` ⇒ `finalized_reference` 已推进到 `qc.target`。
    Adopted,
    /// 同 target（幂等；零状态变更）。
    Idempotent,
    /// `qc.target` 是现有 finality 的 ancestor（过时；零状态变更）。
    Stale,
    /// 与现有 finality 无 ancestry 关系（**非错误**；零状态变更，绝不 rollback）。
    Conflict,
    /// frozen 强制拒绝（例如非 PrecommitQC）。
    Rejected(FinalityError),
}

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
    /// ProposalRef canonical payload 结构解析失败（Consensus 域；ADR-0041）。
    ProposalDecode(ConsensusError),
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
    /// D10-C Step 4 — 最近一次与当前 `finalized_reference` 一致的 PrecommitQC（node-local 观测；
    /// 供 Finality Recovery Fact 持久化 —— finality 由 frozen transition ⑥ 产生，本缓存只捕获
    /// 同一 transition 派生的 QC 证据，不制造 finality / QC）。
    last_precommit_qc: Option<QuorumCertificate>,
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
            last_precommit_qc: None,
        }
    }

    /// 当前 Consensus 状态（只读）。
    pub fn state(&self) -> &ConsensusState {
        &self.state
    }

    /// chain_id（transition 冻结参数；只读）。
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// ValidatorSet（transition 冻结参数；只读，供 `verify_vote_input` / `verify_qc` / `select_proposer`）。
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.set
    }

    /// genesis hash（= QC `validator_set_id` 锚；只读）。
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// DAG（只读；供 `acquire_lock` / `verify_qc` / fork choice 消费）。
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// 最近一次与当前 `finalized_reference` 一致的 PrecommitQC（只读；D10-C Step 4）。
    ///
    /// 捕获规则：`Applied` transition 且 `derived.precommit_qc` 的 `target == next_state.finality
    /// .finalized_reference`（即该 QC 正是推进 finality 的 PrecommitQC）。无 ⇒ `None`。
    pub fn last_precommit_qc(&self) -> Option<&QuorumCertificate> {
        self.last_precommit_qc.as_ref()
    }

    /// P1-A.7（ADR-0064）— **Verified External Finality Adoption** 的 node 层**薄 facade**。
    ///
    /// 只复用 **frozen public API**（与 frozen transition ⑥ 同源同序）：
    /// `check_finality_applicability(qc, finalized, dag)` → `update_finalized_reference(..)`。
    ///
    /// # 前置契约（调用方保证；本方法**不**重复验证）
    /// - `qc` 已经过既有 `verify_qc`（`target ∈ DAG` / validator_set_id / evidence 升序 / 无重复 /
    ///   逐条签名 / quorum 全 PASS）；
    /// - `qc.target` 对应块已在本地 DAG，且为 local canonical head 的**严格 child**
    ///   （`parent_hash == head.block_hash` ∧ `height == head.height + 1`）；
    /// - `qc.context.height + 1 == block.height` ∧ `qc.target == block_hash`。
    ///
    /// # 语义（**不新增共识规则**）
    /// - `Advance` ⇒ `finalized_reference = qc.target`（并镜像既有 `last_precommit_qc` 捕获规则，
    ///   使既有 durable-before-bridge fact 持久化路径可继续使用同一 QC）；
    /// - `Idempotent` / `Stale` / `Conflict` ⇒ **零状态变更**（frozen `update_finalized_reference` 语义）；
    /// - 非 PrecommitQC ⇒ `Rejected`（frozen 代码级强制）。
    ///
    /// **绝不**触碰 `ChainHead` / BlockStore / StateStore / WAL：head 推进只属既有
    /// `finality_commit_bridge → apply_block`。
    pub fn adopt_verified_external_finality(&mut self, qc: &QuorumCertificate) -> AdoptionOutcome {
        let applicability = check_finality_applicability(
            qc,
            self.state.finality.finalized_reference.as_ref(),
            &self.dag,
        );
        if let Err(e) = update_finalized_reference(&mut self.state.finality, qc, applicability) {
            return AdoptionOutcome::Rejected(e);
        }
        match applicability {
            Applicability::Applicable {
                mode: UpdateMode::Advance,
            } => {
                // 与 frozen transition ⑥ 的节点侧捕获同规则：该 QC 正是推进 finality 的 QC。
                self.last_precommit_qc = Some(qc.clone());
                AdoptionOutcome::Adopted
            }
            Applicability::Applicable {
                mode: UpdateMode::Idempotent,
            } => AdoptionOutcome::Idempotent,
            Applicability::Inapplicable {
                reason: InapplicableReason::Stale,
            } => AdoptionOutcome::Stale,
            Applicability::Inapplicable {
                reason: InapplicableReason::Conflict,
            } => AdoptionOutcome::Conflict,
        }
    }

    /// D10-C Step 4 — 恢复注入 `finalized_reference`（**仅启动恢复路径**；所有 QC / identity /
    /// block / DAG 验证已在 `bootstrap::restore_finality_fact` 完成 —— 本方法不绕过任何验证）。
    ///
    /// 单调守卫：仅当当前 `finalized_reference` 为 `None`（fresh consensus）或与 `reference` 相同
    /// （幂等）时设置；绝不回退已存在 finality。恢复场景（start 时默认 `None`）⇒ 恒可设。
    pub fn restore_finalized_reference(&mut self, reference: [u8; 32]) {
        match self.state.finality.finalized_reference {
            None => self.state.finality.finalized_reference = Some(reference),
            Some(existing) => debug_assert!(
                existing == reference,
                "恢复不得回退 / 覆盖既有 finality（既有 {existing:?} ≠ {reference:?}）"
            ),
        }
    }

    /// 登记一个**已验证 canonical-next** 块承诺为 DAG 节点（node orchestration；D10-A Step 3；
    /// D10-C Step 7-A 修正 registration mapping）。
    ///
    /// 以块**真实** `header.height` 与 `header.parent_hash` 登记 DAG reference：
    /// `height = block.header.height`、`parents = [block.header.parent_hash]`（genesis / `height == 0`
    /// 时 `parents = []`）—— 使 `A(height=H) → B(height=H+1, parent=A)` 在 DAG 中真实成边，
    /// `dag.is_ancestor(A, B) == true`（frozen lock applicability 据此判定 descendant）。
    ///
    /// - **round semantics 不变**：本方法不读取 / 不推进 `state.round`（`round.height` 仍为父高轮；
    ///   canonical-next 块高 = `round.height + 1`，由调用方从 block header 提供）。
    /// - **首块 genesis 根**：若 parent（= genesis hash）尚未在 DAG（首启 `rebuild` 空 DAG）⇒ 先补
    ///   genesis 根 reference（height 0 / parents 空）再登记；非 genesis 的未知 parent ⇒
    ///   `InvalidDagReference`（fail-closed，不跳过）。
    /// - **幂等**：已登记同一 hash ⇒ `Ok`（不重复 / 不报 DuplicateBlock）。
    /// - 不修改任何共识规则（`Dag::add_block` 全验证保留）；块必须已通过 D9 proposer 验证。
    pub fn register_block(
        &mut self,
        block_hash: [u8; 32],
        height: u64,
        parent_hash: [u8; 32],
        proposer: ValidatorId,
    ) -> Result<(), ConsensusError> {
        if self.dag.contains(&block_hash) {
            return Ok(());
        }
        let parents = if height == 0 {
            // genesis / 无 parent block：合法空 parent reference。
            Vec::new()
        } else {
            if !self.dag.contains(&parent_hash) {
                if parent_hash == self.genesis_hash {
                    // 首块：DAG 无 genesis 根（首启 rebuild 空）⇒ 补根（node 层 orchestration）。
                    self.dag.add_block(BlockReference {
                        block_hash: self.genesis_hash,
                        height: 0,
                        parents: Vec::new(),
                        proposer: ValidatorId::from_bytes([0u8; 32]),
                    })?;
                } else {
                    // 非 genesis 未知 parent ⇒ fail-closed（不猜测 / 不断链）。
                    return Err(ConsensusError::InvalidDagReference);
                }
            }
            vec![parent_hash]
        };
        self.dag.add_block(BlockReference {
            block_hash,
            height,
            parents,
            proposer,
        })?;
        Ok(())
    }

    /// D10-C Step 7-B — 按 canonical head 高度进入**下一高度轮**（node orchestration；
    /// **不新增 / 不修改任何共识规则**）。
    ///
    /// 语义（单调 / 幂等）：
    /// - `height <= self.state.round.height` ⇒ `false`（no-op；重复调用不重复清空 round/proposal）。
    /// - `height > self.state.round.height` ⇒ 重建 round 为 `RoundState::new(height, 0)`
    ///   （`step = Propose`、`proposal = None`、prevote/precommit accumulator 空）并以
    ///   `IntegrationContext::new(height, 0)` 重建 context（`round_evidence` bound 重置 ⇒
    ///   旧高度证据不再参与 QC 组装）⇒ `true`。
    ///
    /// **保留（safety-critical，绝不清除）**：`finality`（已 finalized 的引用单调保留 ——
    /// 下一高度的 Applicability 仍需其 ancestry）、`dag`、`set`、`chain_id`、`genesis_hash`；
    /// node 层 BlockStore / SafetyStore / VoteLedger / LockedState 不被本方法触碰。
    ///
    /// 调用契约（Runtime orchestration）：**仅在 canonical commit 成功之后**、以 durable head
    /// 驱动调用（`commit → head durable → advance`，绝不 advance-before-commit）；本方法是
    /// 纯内存确定性状态转移（无 storage I/O），不参与 commit 成败，无 rollback 语义。
    pub fn advance_to_height(&mut self, height: u64) -> bool {
        if height <= self.state.round.height {
            return false;
        }
        self.state.round = RoundState::new(height, 0);
        self.context = IntegrationContext::new(height, 0);
        true
    }

    /// 提交 proposal（STEP 10-15O driver 路径）：`ConsensusEvent::SetProposal` → `transition` →
    /// 应用 `next_state`；返回完整 `TransitionResult`（derived 保留，供 driver 消费）。
    pub fn submit_proposal(&mut self, proposal_ref: ProposalRef) -> TransitionResult {
        let result = transition(
            &self.state,
            ConsensusEvent::SetProposal(proposal_ref),
            &mut self.context,
            self.chain_id,
            &self.set,
            &self.genesis_hash,
            &self.dag,
        );
        self.apply_result(&result);
        result
    }

    /// 提交**已验证** vote（MF-2 caller 契约；OPTION A —— 本地与远程共用同一 `verify_vote_input`
    /// 门面后到达此处）：`ConsensusEvent::Vote` → `transition` → 应用 `next_state`；返回完整
    /// `TransitionResult`（`derived.precommit_qc` 保留，供 driver `verify_qc` + lock routing）。
    pub fn submit_verified_vote(
        &mut self,
        vote: ValidatorVote,
        signature: [u8; 64],
    ) -> TransitionResult {
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
        result
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
            MessageType::ConsensusProposal => self.handle_proposal(&envelope.payload),
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
        Ok(self.submit_verified_vote(vote, signature))
    }

    /// Proposal 路径：decode wire payload（ADR-0041 64B）→ construct 既有
    /// `ConsensusEvent::SetProposal` → `transition`（不修改）。阶段守卫归 transition。
    fn handle_proposal(&mut self, payload: &[u8]) -> Result<TransitionResult, NodeError> {
        let proposal_ref = decode_proposal_ref(payload).map_err(NodeError::ProposalDecode)?;
        Ok(self.submit_proposal(proposal_ref))
    }

    /// `Applied` ⇒ 应用 `next_state`；`Ignored`/`Rejected` ⇒ 不变（MF-12 契约 3）。
    ///
    /// D10-C Step 4：`Applied` 且该 transition 派生 PrecommitQC 的 `target == next_state.finality
    /// .finalized_reference` ⇒ 缓存该 QC（Recovery Fact 数据源；finality 仍只由 frozen ⑥ 产生）。
    fn apply_result(&mut self, result: &TransitionResult) {
        if let TransitionResult::Applied {
            next_state,
            derived,
            ..
        } = result
        {
            self.state = next_state.clone();
            if let Some(qc) = &derived.precommit_qc
                && next_state.finality.finalized_reference == Some(qc.target)
            {
                self.last_precommit_qc = Some(qc.clone());
            }
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
    use nova_consensus::finality::QcContext;
    use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
    use nova_consensus::validator::ValidatorId;
    use nova_consensus::vote::{VoteType, canonical_vote_payload};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use nova_network::message::sign_message;
    use nova_network::node_id::NodeId;

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
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
        // ConsensusQc wire（QC ingestion DEFERRED——仍不支持）
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusQc,
            payload: vec![0u8; 32],
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(peer_kp.signing_key(), &mut envelope).unwrap();
        let err = node
            .handle_envelope(peer_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert_eq!(err, NodeError::UnsupportedMessage(MessageType::ConsensusQc));
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

    fn proposal_envelope(
        signer_kp: &KeyPair,
        block_hash: [u8; 32],
        proposer: ValidatorId,
    ) -> MessageEnvelope {
        let p = ProposalRef {
            block_hash,
            proposer,
        };
        let payload = encode_proposal_ref(&p);
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusProposal,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(signer_kp.signing_key(), &mut envelope).unwrap();
        envelope
    }

    #[test]
    fn handle_valid_proposal_envelope_applies() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        let envelope = proposal_envelope(
            &validator_kp,
            [0x22; 32],
            ValidatorId::from_bytes([0x01; 32]),
        );
        let result = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap();
        assert!(matches!(result, TransitionResult::Applied { .. }));
        // step Propose → Prevote（set_proposal 成功，B-1）
        assert_eq!(node.state().round.step, RoundStep::Prevote);
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_proposal_rejects_bad_payload() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        let mut envelope = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusProposal,
            payload: vec![0u8; 32], // 非 64B
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(validator_kp.signing_key(), &mut envelope).unwrap();
        let err = node
            .handle_envelope(validator_kp.verifying_key(), &envelope, 64 * 1024)
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::ProposalDecode(
                nova_consensus::error::ConsensusError::InvalidProposalEncoding
            )
        ));
        let _ = (set, genesis_hash);
    }

    #[test]
    fn handle_proposal_wrong_phase_ignored() {
        let (mut node, validator_kp, set, genesis_hash) = setup();
        // 第一次 SetProposal（Propose→Prevote）
        let e1 = proposal_envelope(
            &validator_kp,
            [0x22; 32],
            ValidatorId::from_bytes([0x01; 32]),
        );
        node.handle_envelope(validator_kp.verifying_key(), &e1, 64 * 1024)
            .unwrap();
        // 第二次 SetProposal（Prevote 阶段）⇒ transition 守卫 Ignored{ContextMismatch}
        let e2 = proposal_envelope(
            &validator_kp,
            [0x33; 32],
            ValidatorId::from_bytes([0x02; 32]),
        );
        let result = node
            .handle_envelope(validator_kp.verifying_key(), &e2, 64 * 1024)
            .unwrap();
        assert!(matches!(
            result,
            TransitionResult::Ignored {
                reason: nova_consensus::integration::IgnoreReason::ContextMismatch
            }
        ));
        let _ = (set, genesis_hash);
    }

    /// T7（ADR-0064）— **Verified External Finality Adoption** 的 facade 语义：
    /// 只 Advance 前进；`Idempotent` / `Stale` / `Conflict` / 非 Precommit **零状态变更**，
    /// 且**绝不 rollback / 绝不覆盖**；不触碰 `round`（即不直接修改 head）。
    #[test]
    fn p1a7_adoption_is_monotonic_and_never_rolls_back() {
        let (mut node, _kp, _set, gh) = setup();
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let proposer = ValidatorId::from_bytes([0x33; 32]);
        // DAG：genesis 根 + 两个同父兄弟 A / B（height 1）⇒ A 与 B **无 ancestry**（Conflict 语义）。
        node.register_block(a, 1, gh, proposer).unwrap();
        node.register_block(b, 1, gh, proposer).unwrap();
        assert!(node.dag().contains(&a) && node.dag().contains(&b));

        let qc = |height: u64, target: [u8; 32], vote_type: VoteType| QuorumCertificate {
            context: QcContext {
                chain_id: 1001,
                height,
                round: 0,
                vote_type,
            },
            target,
            validator_set_id: gh,
            evidence: Vec::new(),
        };

        // Advance：finality 前进到 A。
        assert_eq!(
            node.adopt_verified_external_finality(&qc(0, a, VoteType::Precommit)),
            AdoptionOutcome::Adopted
        );
        assert_eq!(node.state().finality.finalized_reference, Some(a));

        // 幂等：同 target 重复采纳 ⇒ 无变化。
        assert_eq!(
            node.adopt_verified_external_finality(&qc(0, a, VoteType::Precommit)),
            AdoptionOutcome::Idempotent
        );
        assert_eq!(node.state().finality.finalized_reference, Some(a));

        // Conflict（无 ancestry）⇒ 拒绝且**绝不 rollback / 绝不 overwrite**。
        assert_eq!(
            node.adopt_verified_external_finality(&qc(0, b, VoteType::Precommit)),
            AdoptionOutcome::Conflict
        );
        assert_eq!(
            node.state().finality.finalized_reference,
            Some(a),
            "conflict 不得 rollback / 不得 overwrite"
        );

        // Stale（target 是当前 finality 的 ancestor）⇒ 拒绝且不回退。
        assert_eq!(
            node.adopt_verified_external_finality(&qc(0, gh, VoteType::Precommit)),
            AdoptionOutcome::Stale
        );
        assert_eq!(node.state().finality.finalized_reference, Some(a));

        // 非 PrecommitQC ⇒ frozen 代码级拒绝。
        assert!(matches!(
            node.adopt_verified_external_finality(&qc(0, b, VoteType::Prevote)),
            AdoptionOutcome::Rejected(_)
        ));
        assert_eq!(node.state().finality.finalized_reference, Some(a));

        // 不直接修改 head：round / height 不变。
        assert_eq!(
            node.state().round.height,
            0,
            "facade 不得直接修改 head/round"
        );
    }
}
