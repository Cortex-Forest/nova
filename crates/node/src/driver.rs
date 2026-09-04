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
//!
//! # 边界
//! - `ConsensusNode` 拥有 canonical `ConsensusState`；`ValidatorActor` 拥有 local validator state；
//!   本 Driver 只编排 —— 不复制 state、不实现 quorum / finality / fork_choice / proposer / pacemaker。
//! - Canonical state 保持 identity-independent / replayable；`LockedState` 留在 `LocalVoteContext`。
//! - 同步架构：不引入 async runtime / actor framework；`ValidatorActor` 为 logical actor。
//! - 依赖方向：node → consensus / crypto；wallet / runtime 不参与投票签名。

use nova_consensus::error::ConsensusError;
use nova_consensus::finality::{FinalityError, verify_qc};
use nova_consensus::integration::{ConsensusEvent, TransitionResult};
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::vote::{ValidatorVote, VoteType, verify_vote_input};

use crate::assembly::ConsensusNode;
use crate::signer::SigningCapability;
use crate::validator::{LocalVoteRequest, ValidatorActor};

/// Node Consensus Driver 错误（node operational；错误来源保持清晰，不静默吞掉）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// 本地 actor 索引越界。
    NoActor(usize),
    /// local vote 未通过统一 MF-2 门面 `verify_vote_input`（不会进入 canonical transition）。
    VoteVerification(ConsensusError),
    /// derived PrecommitQC 未通过 `verify_qc`（不路由 ⇒ 无 actor lock 更新）。
    QcVerification(FinalityError),
    /// actor lock transition 失败（`acquire_lock`；如非 Precommit QC —— derived 不应出现）。
    ActorLock(FinalityError),
}

/// Node Consensus Driver：编排「本地投票 → 统一验证 → canonical transition → QC → 本地 lock」。
///
/// - `consensus`：owns canonical ConsensusState（`ConsensusNode`）。
/// - `actors`：owns 各本地 validator state（`ValidatorActor<S>`）。
pub struct NodeConsensusDriver<S: SigningCapability> {
    consensus: ConsensusNode,
    actors: Vec<ValidatorActor<S>>,
}

impl<S: SigningCapability> NodeConsensusDriver<S> {
    /// 构造：consensus 拥有 canonical state；actors 拥有各本地 validator state。
    pub fn new(consensus: ConsensusNode, actors: Vec<ValidatorActor<S>>) -> Self {
        Self { consensus, actors }
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
        // ② authorize + construct + sign（ValidatorActor；锁兼容在 actor 内判定）。
        let event = self
            .actors
            .get(actor_idx)
            .ok_or(DriverError::NoActor(actor_idx))?
            .produce_vote(
                request,
                self.consensus.validator_set(),
                self.consensus.dag(),
            );
        let Some(event) = event else {
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
        // Broadcast-to-all-local：每 actor 独立 acquire_lock（L-8；QC 是共享 evidence，
        // LockedState 是 validator-local —— 不把 QC 直接写入任何 actor）。
        for i in 0..self.actors.len() {
            self.actors[i]
                .on_verified_precommit_qc(qc, self.consensus.dag())
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
}
