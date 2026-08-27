//! BFT Round（STEP 10-5 — ADR-0037 B-1~B-6）。
//!
//! - [`RoundState`] / [`RoundStep`]：`(height, round)` 唯一 context，纯计算（B-1）。
//! - [`VoteAccumulator`]：按 target 聚合权重（同 validator 对同 target 去重）（B-2）。
//! - [`process_vote`]：已验证 vote → 聚合 → quorum → step 推进（B-2）。
//! - [`LockedState`]：单 block lock + 兼容规则（B-5；higher justified override 归 10-6）。
//! - [`RoundTimeoutConfig`]：本地事件（非共识输入；B-3）。

use crate::validator::ValidatorId;
use crate::vote::{ValidatorVote, VoteType};
use std::collections::{HashMap, HashSet};

/// Round 阶段（B-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundStep {
    /// 等待 proposal。
    Propose,
    /// 已收到 proposal，可投 prevote。
    Prevote,
    /// 已达成 prevote quorum，可投 precommit。
    Precommit,
    /// 已达成 precommit quorum（finality 判定归 10-6）。
    Finalized,
}

/// 当前 proposal 引用（BlockReference；PHASE 7 完整 Block）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalRef {
    pub block_hash: [u8; 32],
    pub proposer: ValidatorId,
}

/// 投票权重聚合（按 target 去重；B-2）。
#[derive(Debug, Clone, Default)]
pub struct VoteAccumulator {
    weights: HashMap<[u8; 32], u128>,
    voters: HashMap<[u8; 32], HashSet<ValidatorId>>,
}

impl VoteAccumulator {
    /// 空聚合器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录投票；同 validator 对同 target **只计一次**（防重复计权）。
    /// 返回该 target 当前累计权重。
    pub fn record(&mut self, target: [u8; 32], validator: ValidatorId, weight: u128) -> u128 {
        let voters = self.voters.entry(target).or_default();
        if voters.insert(validator) {
            *self.weights.entry(target).or_insert(0) += weight;
        }
        self.weights.get(&target).copied().unwrap_or(0)
    }

    /// 某 target 累计权重。
    pub fn weight_of(&self, target: &[u8; 32]) -> u128 {
        self.weights.get(target).copied().unwrap_or(0)
    }
}

/// Round 转移结果（B-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoundTransition {
    /// 新 step（若推进）。
    pub new_step: Option<RoundStep>,
    /// 是否达成 prevote quorum。
    pub prevote_quorum: bool,
    /// 是否达成 precommit quorum。
    pub precommit_quorum: bool,
    /// finalized target（precommit quorum 时）。
    pub finalized_target: Option<[u8; 32]>,
}

/// BFT Round 状态（B-1；纯计算）。
#[derive(Debug, Clone)]
pub struct RoundState {
    pub height: u64,
    pub round: u64,
    pub proposal: Option<ProposalRef>,
    pub prevotes: VoteAccumulator,
    pub precommits: VoteAccumulator,
    pub step: RoundStep,
}

impl RoundState {
    /// 新 round。
    pub fn new(height: u64, round: u64) -> Self {
        Self {
            height,
            round,
            proposal: None,
            prevotes: VoteAccumulator::new(),
            precommits: VoteAccumulator::new(),
            step: RoundStep::Propose,
        }
    }

    /// 设置 proposal（仅 `Propose` 阶段；成功则推进到 `Prevote`）。
    pub fn set_proposal(&mut self, p: ProposalRef) -> bool {
        if self.step != RoundStep::Propose {
            return false;
        }
        self.proposal = Some(p);
        self.step = RoundStep::Prevote;
        true
    }
}

/// 处理**已验证** vote：聚合权重 → quorum 判定 → 推进 step（B-2；纯计算）。
///
/// - 只推进与当前 proposal.target 匹配的 quorum。
/// - `quorum` = `ValidatorSet::quorum()`（≥2/3 weighted，C-5）。
/// - **不**验证交易 / 执行 block / 修改 state root。
pub fn process_vote(
    state: &mut RoundState,
    vote: &ValidatorVote,
    weight: u128,
    quorum: u128,
) -> RoundTransition {
    let mut t = RoundTransition::default();
    match vote.vote_type {
        VoteType::Prevote => {
            let total = state
                .prevotes
                .record(vote.target_block_hash, vote.validator_id, weight);
            if let Some(p) = &state.proposal
                && p.block_hash == vote.target_block_hash
                && total >= quorum
                && state.step == RoundStep::Prevote
            {
                state.step = RoundStep::Precommit;
                t.new_step = Some(state.step);
                t.prevote_quorum = true;
            }
        }
        VoteType::Precommit => {
            let total = state
                .precommits
                .record(vote.target_block_hash, vote.validator_id, weight);
            if let Some(p) = &state.proposal
                && p.block_hash == vote.target_block_hash
                && total >= quorum
            {
                state.step = RoundStep::Finalized;
                t.new_step = Some(state.step);
                t.precommit_quorum = true;
                t.finalized_target = Some(p.block_hash);
            }
        }
    }
    t
}

/// Locked block（B-5；**Lock Object = 单 block**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockedState {
    pub locked_block_hash: Option<[u8; 32]>,
    pub locked_round: Option<u64>,
}

impl LockedState {
    /// 空 lock。
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否已锁定。
    pub fn is_locked(&self) -> bool {
        self.locked_block_hash.is_some()
    }

    /// 兼容性（B-5）：`same block` / `descendant（parents 含 locked）` ⇒ OK；`unrelated` ⇒ reject。
    ///
    /// 更高层 justify override 归 10-6 / Consensus spec。
    pub fn is_compatible(&self, proposal_hash: &[u8; 32], parents: &[[u8; 32]]) -> bool {
        match self.locked_block_hash {
            None => true,
            Some(locked) => proposal_hash == &locked || parents.contains(&locked),
        }
    }

    /// 达成 precommit quorum 时锁定（B-5）。
    pub fn lock(&mut self, block_hash: [u8; 32], round: u64) {
        self.locked_block_hash = Some(block_hash);
        self.locked_round = Some(round);
    }
}

/// Round timeout 配置（B-3；**本地事件，非共识输入**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundTimeoutConfig {
    pub initial_timeout: u64,
    pub max_timeout: u64,
    pub backoff_factor: u64,
}

impl Default for RoundTimeoutConfig {
    fn default() -> Self {
        Self {
            initial_timeout: 1000,
            max_timeout: 60_000,
            backoff_factor: 2,
        }
    }
}

impl RoundTimeoutConfig {
    /// `timeout(round) = initial × backoff^round`，cap 于 `max_timeout`。
    pub fn timeout_for(&self, round: u64) -> u64 {
        let mut t = self.initial_timeout;
        for _ in 0..round {
            t = t.saturating_mul(self.backoff_factor).min(self.max_timeout);
            if t == self.max_timeout {
                break;
            }
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_bytes([b; 32])
    }

    fn vote(target: u8, vt: VoteType, v: u8) -> ValidatorVote {
        ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [target; 32],
            vote_type: vt,
            source_block_hash: [0; 32],
            validator_id: vid(v),
            timestamp: 0,
        }
    }

    #[test]
    fn vote_accumulator_dedup_and_aggregate() {
        let mut acc = VoteAccumulator::new();
        // 同 validator 对同 target 重复投票只计一次
        assert_eq!(acc.record([0x01; 32], vid(1), 100), 100);
        assert_eq!(acc.record([0x01; 32], vid(1), 100), 100, "去重");
        // 不同 validator 累计
        assert_eq!(acc.record([0x01; 32], vid(2), 100), 200);
        // 不同 target 独立
        assert_eq!(acc.record([0x02; 32], vid(1), 50), 50);
        assert_eq!(acc.weight_of(&[0x01; 32]), 200);
        assert_eq!(acc.weight_of(&[0x02; 32]), 50);
        assert_eq!(acc.weight_of(&[0x99; 32]), 0);
    }

    #[test]
    fn process_vote_prevote_then_precommit_to_finalized() {
        let mut state = RoundState::new(1, 0);
        assert!(state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        }));
        assert_eq!(state.step, RoundStep::Prevote);
        let quorum = 200u128; // total 300 → ceil(200)
        // 未达 quorum（100）
        let t1 = process_vote(&mut state, &vote(0x01, VoteType::Prevote, 1), 100, quorum);
        assert!(!t1.prevote_quorum);
        assert_eq!(state.step, RoundStep::Prevote);
        // 达 quorum（+100 → 200）
        let t2 = process_vote(&mut state, &vote(0x01, VoteType::Prevote, 2), 100, quorum);
        assert!(t2.prevote_quorum);
        assert_eq!(state.step, RoundStep::Precommit);
        // precommit 未达 quorum
        let t3 = process_vote(&mut state, &vote(0x01, VoteType::Precommit, 1), 100, quorum);
        assert!(!t3.precommit_quorum);
        // precommit 达 quorum ⇒ Finalized
        let t4 = process_vote(&mut state, &vote(0x01, VoteType::Precommit, 2), 100, quorum);
        assert!(t4.precommit_quorum);
        assert_eq!(t4.finalized_target, Some([0x01; 32]));
        assert_eq!(state.step, RoundStep::Finalized);
    }

    #[test]
    fn process_vote_ignores_non_proposal_target() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // 投其他 target ⇒ 不推进（proposal 是 0x01，vote 是 0x02）
        let t = process_vote(&mut state, &vote(0x02, VoteType::Prevote, 1), 200, quorum);
        assert!(!t.prevote_quorum);
        assert_eq!(state.step, RoundStep::Prevote);
    }

    #[test]
    fn locked_state_compatibility() {
        let mut lk = LockedState::new();
        assert!(lk.is_compatible(&[0x01; 32], &[]), "无 lock 全兼容");
        lk.lock([0x01; 32], 0);
        assert_eq!(lk.locked_round, Some(0));
        // same block ⇒ OK
        assert!(lk.is_compatible(&[0x01; 32], &[]));
        // descendant（parents 含 locked）⇒ OK
        assert!(lk.is_compatible(&[0x02; 32], &[[0x01; 32]]));
        // unrelated ⇒ reject
        assert!(!lk.is_compatible(&[0x03; 32], &[[0x99; 32]]));
        // 空 parents + 不同 block ⇒ reject
        assert!(!lk.is_compatible(&[0x04; 32], &[]));
    }

    #[test]
    fn round_timeout_backoff_and_cap() {
        let cfg = RoundTimeoutConfig {
            initial_timeout: 1000,
            max_timeout: 5000,
            backoff_factor: 2,
        };
        assert_eq!(cfg.timeout_for(0), 1000);
        assert_eq!(cfg.timeout_for(1), 2000);
        assert_eq!(cfg.timeout_for(2), 4000);
        assert_eq!(cfg.timeout_for(3), 5000, "cap at max");
        assert_eq!(cfg.timeout_for(100), 5000);
    }

    #[test]
    fn set_proposal_only_in_propose_step() {
        let mut state = RoundState::new(1, 0);
        assert!(state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1)
        }));
        // 已在 Prevote，不能重复 set
        assert!(!state.set_proposal(ProposalRef {
            block_hash: [0x02; 32],
            proposer: vid(2)
        }));
        assert_eq!(state.proposal.as_ref().unwrap().block_hash, [0x01; 32]);
    }
}
