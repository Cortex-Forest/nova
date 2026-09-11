//! Node Consensus Driver（STEP 10-15O）：把已核实的 `ValidatorActor` / `LocalVoteContext` /
//! `SoftwareSigner` capability（10-15L）接入 Node consensus 事件路径的最小同步编排层。
//!
//! # 职责（仅 orchestration；不重新实现 consensus）
//! 1. `submit_proposal`：`ProposalRef` → `ConsensusEvent::SetProposal` → canonical transition。
//! 2. `submit_local_vote`：`LocalVoteRequest` → `ValidatorActor`（authorize + construct + sign）→
//!    **统一 MF-2 门面 `verify_vote_input`**（OPTION A —— 与 remote 同一边界）→
//!    `ConsensusNode::submit_verified_vote` → canonical transition。
//! 3. `submit_remote_vote`：已解码 remote vote → 同一 `verify_vote_input` 门面 →
//!    `ConsensusNode::submit_verified_vote` → canonical transition（STEP 10-15P）。
//! 4. `process_transition_derived`：从 `TransitionResult::Applied` 提取 `derived.precommit_qc` →
//!    **显式 `verify_qc`**（`is_some() ≠ 已验证`，STEP 10-15N §11）→ 通过后 **broadcast** 至每个
//!    本地 `ValidatorActor::on_verified_precommit_qc`（各自 `acquire_lock` L-8；只改自身 LockedState）。
//! 5. `auto_drive`（D10-A）：**node 层自动推进** —— 读当前 canonical round：`Prevote` 阶段 ⇒ 本地
//!    Prevote；`Precommit` 阶段 ⇒ 本地 Precommit（幂等；重复调用不 double-vote）；proposer-authority
//!    gate（本地 `select_proposer` 推导期望当选者）不匹配 ⇒ [`AutoDriveStep::WrongProposer`]，不驱动。
//!    只编排 —— 不重新实现 consensus / quorum / finality / pacemaker。
//!
//! # 边界
//! - `ConsensusNode` 拥有 canonical `ConsensusState`；`ValidatorActor` 拥有 local validator state；
//!   本 Driver 只编排 —— 不复制 state、不实现 quorum / finality / fork_choice / proposer / pacemaker。
//! - Canonical state 保持 identity-independent / replayable；`LockedState` 留在 `LocalVoteContext`。
//! - 同步架构：不引入 async runtime / actor framework；`ValidatorActor` 为 logical actor。
//! - 依赖方向：node → consensus / crypto；wallet / runtime 不参与投票签名。

use nova_consensus::error::ConsensusError;
use nova_consensus::finality::{FinalityError, QuorumCertificate, verify_qc};
use nova_consensus::integration::{ConsensusEvent, TransitionResult};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::ValidatorId;
use nova_consensus::vote::{ValidatorVote, VoteType, verify_vote_input};

use crate::assembly::ConsensusNode;
use crate::outbound::OutboundConsensusMessage;
use crate::signer::SigningCapability;
use crate::validator::{LocalVoteRequest, ValidatorActor, ValidatorActorError};

/// Node Consensus Driver 错误（node operational；错误来源保持清晰，不静默吞掉）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// 本地 actor 索引越界。
    NoActor(usize),
    /// local vote 未通过统一 MF-2 门面 `verify_vote_input`（不会进入 canonical transition）。
    VoteVerification(ConsensusError),
    /// derived PrecommitQC 未通过 `verify_qc`（不路由 ⇒ 无 actor lock 更新）。
    QcVerification(FinalityError),
    /// actor lock transition / durable 持久化失败（`acquire_lock` 或 safety store `commit_lock`）。
    ActorLock(ValidatorActorError),
    /// ValidatorActor 失败（含 Double-Vote 拒绝 —— 同 `(height,round,vote_type)` 已签其它 target）。
    Actor(ValidatorActorError),
    /// 本地期望 proposer 推导失败（`select_proposer` Err，如空 ValidatorSet）——自动推进不驱动。
    ProposerSelection(ConsensusError),
}

/// 一次自动推进（D10-A）的决策结果（node 层 orchestration 决策；非共识错误）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDriveStep {
    /// 无可投票阶段（`Propose` / `Finalized` / 无 proposal）——无本地 action。
    Idle,
    /// 已对当前 proposal 提交本地 Prevote（`actors` = 实际提交 / 幂等复用的 actor 数）。
    Prevote { actors: usize },
    /// 已对当前 proposal 提交本地 Precommit（`actors` = 实际提交 / 幂等复用的 actor 数）。
    Precommit { actors: usize },
    /// 当前 round proposal 的 proposer ≠ 本地 `select_proposer` 期望当选者 —— 拒绝驱动
    /// （不投票 / 不推进；D9 proposer validation 边界在 auto-drive 不绕过）。
    WrongProposer {
        actual: ValidatorId,
        expected: ValidatorId,
    },
}

/// Node Consensus Driver：编排「本地投票 → 统一验证 → canonical transition → QC → 本地 lock」。
///
/// - `consensus`：owns canonical ConsensusState（`ConsensusNode`）。
/// - `actors`：owns 各本地 validator state（`ValidatorActor<S>`）。
pub struct NodeConsensusDriver<S: SigningCapability> {
    consensus: ConsensusNode,
    actors: Vec<ValidatorActor<S>>,
    /// 待广播的 consensus **semantic** output（验证 PASS 的 vote/QC + **本地生产**的
    /// proposal/block（D9 Egress）；Driver 不负责发送）。
    pending_outbound: Vec<OutboundConsensusMessage>,
}

impl<S: SigningCapability> NodeConsensusDriver<S> {
    /// 构造：consensus 拥有 canonical state；actors 拥有各本地 validator state。
    pub fn new(consensus: ConsensusNode, actors: Vec<ValidatorActor<S>>) -> Self {
        Self {
            consensus,
            actors,
            pending_outbound: Vec::new(),
        }
    }

    /// canonical consensus 节点（只读）。
    pub fn consensus(&self) -> &ConsensusNode {
        &self.consensus
    }

    /// canonical consensus 节点（可变；供需要直接调用 ConsensusNode 的路径使用）。
    pub fn consensus_mut(&mut self) -> &mut ConsensusNode {
        &mut self.consensus
    }

    /// 全部本地 ValidatorActor（只读）。
    pub fn actors(&self) -> &[ValidatorActor<S>] {
        &self.actors
    }

    /// 第 `idx` 个本地 actor（只读）。
    pub fn actor(&self, idx: usize) -> Option<&ValidatorActor<S>> {
        self.actors.get(idx)
    }

    /// 第 `idx` 个本地 actor（可变）。
    pub fn actor_mut(&mut self, idx: usize) -> Option<&mut ValidatorActor<S>> {
        self.actors.get_mut(idx)
    }

    /// 本地 actor 数量。
    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    /// 提交 proposal（`ProposalRef` → canonical transition；driver 只编排，不验证 proposal 内容）。
    pub fn submit_proposal(&mut self, proposal: ProposalRef) -> TransitionResult {
        self.consensus.submit_proposal(proposal)
    }

    /// 本地投票（OPTION A）：上下文门 → actor（authorize + construct + sign）→ 统一
    /// `verify_vote_input` → `submit_verified_vote`（canonical transition）。
    ///
    /// - `Ok(None)`：未授权（NotMember / IdentityMismatch / LockConflict）或与当前 round 上下文
    ///   不符（无事件产生、无状态变化）。
    /// - `Ok(Some(result))`：投票已提交；`result` 含完整 `derived`（供 `process_transition_derived`）。
    /// - `Err`：actor 索引越界 / 统一验证门面拒绝（`VoteVerification`）。
    pub fn submit_local_vote(
        &mut self,
        actor_idx: usize,
        request: &LocalVoteRequest,
    ) -> Result<Option<TransitionResult>, DriverError> {
        // ① 上下文门：本地只投「当前 round 的当前 proposal」对应 phase 的票（读取 state，不复制）。
        if !self.vote_matches_current_round(request) {
            return Ok(None);
        }
        // ② authorize + construct + sign（ValidatorActor；锁兼容 + VoteLedger DV guard 在 actor 内判定）。
        let produced = self
            .actors
            .get(actor_idx)
            .ok_or(DriverError::NoActor(actor_idx))?
            .produce_vote(
                request,
                self.consensus.validator_set(),
                self.consensus.dag(),
            )
            .map_err(DriverError::Actor)?;
        let Some(event) = produced else {
            // 授权拒绝 ⇒ 不产生事件（无 vote / 无 sign / 无 ConsensusEvent）。
            return Ok(None);
        };
        let (vote, signature) = match event {
            ConsensusEvent::Vote { vote, signature } => (vote, signature),
            // produce_vote 唯一构造 ConsensusEvent::Vote —— 不可达 invariant（防静默吞掉）。
            _ => unreachable!("produce_vote 只产出 ConsensusEvent::Vote"),
        };
        // ③ OPTION A：与 remote（assembly handle_vote）同一边界 —— 先验证后进 canonical transition。
        verify_vote_input(
            &vote,
            &signature,
            self.consensus.chain_id(),
            self.consensus.validator_set(),
        )
        .map_err(DriverError::VoteVerification)?;
        // ⑤ outbound semantic：仅 `verify_vote_input` PASS 后才可能进入待广播
        //    （unverified never outbound）。vote 随后被 `submit_verified_vote` 消耗 ⇒ 先 clone。
        self.pending_outbound.push(OutboundConsensusMessage::Vote {
            vote: vote.clone(),
            signature,
        });
        // ④ 提交已验证 vote（canonical transition 由 ConsensusNode 持有；driver 不触碰共识状态）。
        let result = self.consensus.submit_verified_vote(vote, signature);
        Ok(Some(result))
    }

    /// 提交一条**已解码 remote vote**（STEP 10-15P；OPTION A —— 与 local / network handle_vote
    /// 同一 `verify_vote_input` 门面）：验证通过 → `submit_verified_vote` → 同一 canonical
    /// transition；返回完整 `TransitionResult`（derived 保留）。
    ///
    /// - 不做本地 phase/context 预判：remote vote 是否适用由 canonical transition 的 guards
    ///   判定（`Ignored`/`Applied`）—— 与 assembly::handle_vote 行为一致。
    /// - 调用方应将返回结果交给**单一** `process_transition_derived` choke 以路由 derived
    ///   precommit QC（`verify_qc` → broadcast）至各本地 actor —— 与 local 路径共用。
    pub fn submit_remote_vote(
        &mut self,
        vote: ValidatorVote,
        signature: [u8; 64],
    ) -> Result<TransitionResult, DriverError> {
        // MF-2：与 local 同一边界 —— 先 verify_vote_input 后进 canonical transition。
        verify_vote_input(
            &vote,
            &signature,
            self.consensus.chain_id(),
            self.consensus.validator_set(),
        )
        .map_err(DriverError::VoteVerification)?;
        Ok(self.consensus.submit_verified_vote(vote, signature))
    }

    /// 处理一次 transition 结果：从 `Applied` 提取 `derived.precommit_qc` → 显式 `verify_qc`
    /// → 通过后 **broadcast** 至所有本地 actor（各自 `acquire_lock` L-8；只改自身 LockedState）。
    ///
    /// - `Ignored` / `Rejected` / `Applied` 无 `precommit_qc` ⇒ `Ok`（不触发 lock routing）。
    /// - `precommit_qc` 存在但 `verify_qc` 失败 ⇒ `Err(QcVerification)`，**不更新任何 actor lock**。
    pub fn process_transition_derived(
        &mut self,
        result: &TransitionResult,
    ) -> Result<(), DriverError> {
        let TransitionResult::Applied { derived, .. } = result else {
            return Ok(());
        };
        let Some(qc) = derived.precommit_qc.as_ref() else {
            return Ok(());
        };
        // CRITICAL：derived.precommit_qc.is_some() ≠ 已验证（STEP 10-15N §11）——先 verify_qc。
        let genesis_hash = self.consensus.genesis_hash();
        verify_qc(
            qc,
            self.consensus.validator_set(),
            &genesis_hash,
            self.consensus.dag(),
        )
        .map_err(DriverError::QcVerification)?;
        // outbound semantic：仅 `verify_qc` PASS 的 QC 才可广播（unverified / FAIL ⇒ no outbound）。
        self.pending_outbound
            .push(OutboundConsensusMessage::VerifiedQc(qc.clone()));
        // Broadcast-to-all-local：每 actor 独立 acquire_lock（L-8；QC 是共享 evidence，
        // LockedState 是 validator-local —— 不把 QC 直接写入任何 actor）。
        for i in 0..self.actors.len() {
            self.actors[i]
                .on_verified_precommit_qc(qc, self.consensus.dag())
                .map_err(DriverError::ActorLock)?;
        }
        Ok(())
    }

    /// 取走当前待广播的 consensus **semantic** output（只有经既有验证门面的消息才可能在其中；
    /// 网络层发送由 [`crate::outbound::NetworkEgress`] seam 负责 —— Driver 不拥有网络）。
    pub fn take_outbound(&mut self) -> Vec<OutboundConsensusMessage> {
        std::mem::take(&mut self.pending_outbound)
    }

    /// 当前待广播 semantic output 数量。
    pub fn outbound_pending_len(&self) -> usize {
        self.pending_outbound.len()
    }

    /// D9 Egress — 登记**本地生产**的 canonical proposal + block 到 outbound（node orchestration seam）。
    ///
    /// 调用契约（由 `runtime_propose` / `NodeRuntime::step` 侧保证；Driver 不重复判定 consensus 语义）：
    /// - proposal 已 `submit_proposal` 且 block 已 `register_block` **成功**（任一失败 ⇒ 调用方不调用
    ///   ⇒ 无 outbound；绝不广播半成品）；
    /// - `proposal.block_hash` == `block_hash(&block)`（`build_proposal` 同一 `result.block_hash`
    ///   单一来源；**不复制 hash 算法**）；
    /// - **仅本地生产路径**调用：remote 到达的 proposal 不重播（relay 不在本步范围）。
    ///
    /// 同批入队（egress 同批签名广播）：`Proposal(ref)` → `GossipBlock(wire)`。有界沿用既有
    /// `pending_outbound`（每 step 由 egress drain；生产速率 = 每 `(height, round)` 至多一次）。
    pub fn record_local_proposal(&mut self, proposal: ProposalRef, block_wire: Vec<u8>) {
        self.pending_outbound
            .push(OutboundConsensusMessage::Proposal(proposal));
        self.pending_outbound
            .push(OutboundConsensusMessage::GossipBlock(block_wire));
    }

    /// 处理**网络到达**的 QC（STEP 10-18G-1 inbound QC）。
    ///
    /// 顺序（不可变）：`decode_qc`（node adapter 层完成）→ 本方法 `verify_qc` →
    /// PASS ⇒ 每个本地 `ValidatorActor` 独立 `acquire_lock`（L-8；只改自身 LockedState）。
    ///
    /// - `verify_qc` FAIL ⇒ `Err(QcVerification)`：**无 lock / 无 outbound / 无 canonical 变化**。
    /// - 不 record outbound（inbound QC 是外部证据，不是本地待广播 QC）。
    /// - 不进 canonical `ConsensusState`（外部 QC ingestion DEFERRED —— canonical 只由 votes 推进）。
    pub fn submit_inbound_qc(&mut self, qc: QuorumCertificate) -> Result<(), DriverError> {
        verify_qc(
            &qc,
            self.consensus.validator_set(),
            &self.consensus.genesis_hash(),
            self.consensus.dag(),
        )
        .map_err(DriverError::QcVerification)?;
        // 每个本地 actor 独立 acquire_lock（与 process_transition_derived 的 actor 段同一语义）。
        for i in 0..self.actors.len() {
            self.actors[i]
                .on_verified_precommit_qc(&qc, self.consensus.dag())
                .map_err(DriverError::ActorLock)?;
        }
        Ok(())
    }

    /// 本地投票是否绑定当前 canonical round：`(height, round)` 匹配、存在当前 proposal 且
    /// `target == proposal.block_hash`、`vote_type` 与 `RoundStep` 阶段一致。
    ///
    /// 只读取 canonical state（不复制 / 不派生第二份 round state）。
    fn vote_matches_current_round(&self, request: &LocalVoteRequest) -> bool {
        let round = &self.consensus.state().round;
        if request.height != round.height || request.round != round.round {
            return false;
        }
        let Some(proposal) = round.proposal.as_ref() else {
            return false;
        };
        if proposal.block_hash != request.target_block_hash {
            return false;
        }
        match request.vote_type {
            VoteType::Prevote => round.step == RoundStep::Prevote,
            VoteType::Precommit => round.step == RoundStep::Precommit,
        }
    }

    /// 自动推进（D10-A）：读取当前 canonical round 状态，对本 driver 全部本地 actor 执行当前
    /// 被授权的 consensus action（node 层 orchestration —— **不重新实现 consensus**）。
    ///
    /// 语义（幂等 / 可重复调用）：
    /// 1. 读 `consensus.state().round`：`step == Prevote` ⇒ 本地 Prevote；`step == Precommit`
    ///    ⇒ 本地 Precommit；否则（`Propose` / `Finalized` / 无 proposal）⇒ [`AutoDriveStep::Idle`]。
    /// 2. **Proposer-authority gate**（不绕过 D9 proposer validation）：期望 proposer 由本地
    ///    `ValidatorSet` 独立推导（`select_proposer(chain_id, round.height, round.round,
    ///    genesis_hash, set)`，ADR-0050 —— 与 block_dispatch 的 expected-proposer 同一来源）；
    ///    `round.proposal.proposer` ≠ 期望 ⇒ [`AutoDriveStep::WrongProposer`]，**不投票**。
    /// 3. 本地 vote 经既有 [`Self::submit_local_vote`] 全链（context 门 → `ValidatorActor::
    ///    produce_vote` 授权 + DV guard → `verify_vote_input` → `submit_verified_vote` → canonical
    ///    transition）；每票结果经 [`Self::process_transition_derived`]（`derived.precommit_qc` →
    ///    `verify_qc` → 各 actor `acquire_lock` + outbound）。重复调用由 actor VoteLedger（同
    ///    VoteKey 同 target 幂等复用签名，不重复签名）与 consensus accumulator 去重守卫 ——
    ///    不 double-vote、不改 safety。
    ///
    /// `source_block_hash` / `timestamp` 取与 D9 基线一致的占位值（当前轮无见证块源 / 无外部时钟；
    /// `verify_vote_input` V-5 不校验此二字段；consensus 冻结规则不受影响）。
    pub fn auto_drive(&mut self) -> Result<AutoDriveStep, DriverError> {
        let round = self.consensus.state().round.clone();
        let Some(proposal) = round.proposal.clone() else {
            return Ok(AutoDriveStep::Idle);
        };
        // Proposer-authority gate：本地独立推导期望当选者（只读；不改 consensus）。
        let expected = select_proposer(
            self.consensus.chain_id(),
            round.height,
            round.round,
            &self.consensus.genesis_hash(),
            self.consensus.validator_set(),
        )
        .map_err(DriverError::ProposerSelection)?;
        if proposal.proposer != expected {
            return Ok(AutoDriveStep::WrongProposer {
                actual: proposal.proposer,
                expected,
            });
        }
        let vote_type = match round.step {
            RoundStep::Prevote => VoteType::Prevote,
            RoundStep::Precommit => VoteType::Precommit,
            // Propose / Finalized：无本地投票 action。
            RoundStep::Propose | RoundStep::Finalized => return Ok(AutoDriveStep::Idle),
        };
        let request = LocalVoteRequest {
            height: round.height,
            round: round.round,
            target_block_hash: proposal.block_hash,
            vote_type,
            source_block_hash: [0u8; 32],
            timestamp: 0,
        };
        let mut actors = 0usize;
        for idx in 0..self.actors.len() {
            // 上下文门 + actor 授权 + DV guard 全在 submit_local_vote / produce_vote 内判定
            //（幂等：同 VoteKey 同 target 复用既有签名，不重复签名）。
            if let Some(result) = self.submit_local_vote(idx, &request)? {
                self.process_transition_derived(&result)?;
                actors += 1;
            }
        }
        Ok(match vote_type {
            VoteType::Prevote => AutoDriveStep::Prevote { actors },
            VoteType::Precommit => AutoDriveStep::Precommit { actors },
        })
    }
}
