//! BFT Round（STEP 10-5 — ADR-0037 B-1~B-6）。
//!
//! - [`RoundState`] / [`RoundStep`]：`(height, round)` 唯一 context，纯计算（B-1）。
//! - [`VoteAccumulator`]：按 target 聚合权重（同 validator 对同 target 去重）（B-2）。
//! - [`process_vote`]：已验证 vote → 聚合 → quorum → step 推进（B-2）。
//! - [`LockedState`]：单 block lock + 兼容规则（B-5；higher justified override 归 10-6）。
//! - [`RoundTimeoutConfig`]：本地事件（非共识输入；B-3）。

use crate::error::ConsensusError;
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

/// Canonical wire 编码（ADR-0041 PR-1）：`block_hash(32B) ‖ proposer(32B)` = 64B 定长。
pub fn encode_proposal_ref(p: &ProposalRef) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&p.block_hash);
    out.extend_from_slice(p.proposer.as_bytes());
    out
}

/// Decode（ADR-0041 PR-3/PR-4）：长度严格 64B（拒截断/超长/trailing）；
/// `proposer` = `ValidatorId::from_bytes`；**不做** authority/membership/signature 验证（归 consensus 逻辑）。
pub fn decode_proposal_ref(bytes: &[u8]) -> Result<ProposalRef, ConsensusError> {
    const PROPOSAL_REF_LEN: usize = 64;
    if bytes.len() != PROPOSAL_REF_LEN {
        return Err(ConsensusError::InvalidProposalEncoding);
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&bytes[0..32]);
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&bytes[32..64]);
    Ok(ProposalRef {
        block_hash,
        proposer: ValidatorId::from_bytes(pid),
    })
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
/// - **上下文守卫（10-5.1 修复 A）**：`vote` 必须属于当前 `(height, round)` context；
///   否则**忽略**——不进入 accumulator、不计入 quorum、不改任何状态/transition。
/// - **终态守卫（10-5.1 修复 B）**：`RoundStep::Finalized` 之后任何 vote **忽略**——
///   不 record、不产生 `precommit_quorum` / `finalized_target` 推进事件（状态稳定）。
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
    // 修复 A：vote 必须绑定当前 (height, round) context；否则忽略（防跨 round/height 重放）。
    if vote.height != state.height || vote.round != state.round {
        return t;
    }
    // 修复 B：Finalized 之后任何 vote 不得改变共识状态（无重复推进事件）。
    if state.step == RoundStep::Finalized {
        return t;
    }
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
///
/// **A3（Owner 授权，Testnet 基线）**：数值单位 = **毫秒**（单调时长），默认
/// `(initial 10_000 ms = 10s, max 120_000 ms = 120s, backoff ×2)` ⇒ 序列
/// 10s · 20s · 40s · 80s · 120s · 120s …（cap 先行）。
/// 数值**非**共识常量（ADR-0049 §3.5「exact timeout numeric values = OPEN」）；
/// `timeout_for` 的**形状**（`min(initial × backoff^round, max)`）保持不变。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundTimeoutConfig {
    /// 初始（round 0）超时窗口（**毫秒**）。
    pub initial_timeout: u64,
    /// 窗口上限（**毫秒**）。
    pub max_timeout: u64,
    /// 退避倍数（每 round 乘一次，饱和后 cap）。
    pub backoff_factor: u64,
}

impl Default for RoundTimeoutConfig {
    fn default() -> Self {
        Self {
            initial_timeout: 10_000,
            max_timeout: 120_000,
            backoff_factor: 2,
        }
    }
}

impl RoundTimeoutConfig {
    /// 退避循环的迭代上界（**只**约束终止性，不改变任何输出数值）。
    ///
    /// `initial_timeout ≥ 1` 且 `backoff_factor ≥ 2` 时，`initial × 2^64` 必然 saturate 到
    /// `u64::MAX` ⇒ 最迟第 64 次乘幂即达 `max_timeout`（`max_timeout ≤ u64::MAX`）。
    /// 非增长配置（`backoff_factor ≤ 1` 或 `initial_timeout == 0`）走闭式解，不进入循环。
    const MAX_BACKOFF_STEPS: u64 = 64;

    /// `timeout(round) = initial × backoff^round`，cap 于 `max_timeout`。
    ///
    /// - **语义形状**由 ADR-0049 §3.5 冻结；**数值与单位**属 node-local 配置
    ///   （ADR-0049 §3.5 / §10「exact timeout numeric values = OPEN」）⇒ 本类型**不假定单位**，
    ///   由调用方解释（例如 node 层以逻辑 step tick 解释）。本函数**不**做任何单位换算。
    /// - **终止性**：对任意 `round`（含 `u64::MAX`）均在常数步数（≤ [`Self::MAX_BACKOFF_STEPS`]）
    ///   内返回；输出与朴素 `round` 次迭代定义**逐值一致**（见 `timeout_for_matches_reference_semantics`）。
    /// - `round == 0` 返回 `initial_timeout`（**不**施加 cap —— 与既有行为一致；合法配置应满足
    ///   `initial_timeout ≤ max_timeout`）。
    /// - 不引入新的 panic / unwrap：全程 `saturating_mul` + `min`，无溢出、无 `round` 次循环。
    pub fn timeout_for(&self, round: u64) -> u64 {
        // 非增长序列（`backoff_factor ≤ 1` 或 `initial_timeout == 0`）：首次乘幂后数值恒定
        // （`saturating_mul` 与 `min` 对非负输入单调）⇒ 闭式解，避免 O(round) 迭代。
        if self.backoff_factor <= 1 || self.initial_timeout == 0 {
            if round == 0 {
                return self.initial_timeout;
            }
            return self
                .initial_timeout
                .saturating_mul(self.backoff_factor)
                .min(self.max_timeout);
        }
        // 增长序列：至多 `MAX_BACKOFF_STEPS` 次乘幂即达 cap（见常量 doc）。
        let mut t = self.initial_timeout;
        for _ in 0..round.min(Self::MAX_BACKOFF_STEPS) {
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

    /// 参考实现（朴素 `round` 次迭代 = 语义定义）—— **仅**用于等价性比对（round 取小值）。
    fn reference_timeout_for(cfg: &RoundTimeoutConfig, round: u64) -> u64 {
        let mut t = cfg.initial_timeout;
        for _ in 0..round {
            t = t.saturating_mul(cfg.backoff_factor).min(cfg.max_timeout);
            if t == cfg.max_timeout {
                break;
            }
        }
        t
    }

    #[test]
    fn timeout_for_matches_reference_semantics() {
        let configs = [
            // 生产默认（ADR-0049 §3.5 数值 OPEN，单位由调用方解释）
            RoundTimeoutConfig {
                initial_timeout: 1000,
                max_timeout: 60_000,
                backoff_factor: 2,
            },
            RoundTimeoutConfig {
                initial_timeout: 1000,
                max_timeout: 5000,
                backoff_factor: 2,
            },
            // 平坦 / 退化（非增长）：闭式解路径
            RoundTimeoutConfig {
                initial_timeout: 5,
                max_timeout: 1_000_000,
                backoff_factor: 1,
            },
            RoundTimeoutConfig {
                initial_timeout: 5,
                max_timeout: 1_000,
                backoff_factor: 0,
            },
            RoundTimeoutConfig {
                initial_timeout: 0,
                max_timeout: 60_000,
                backoff_factor: 2,
            },
            // 边界：零上限、initial > max、极限上限、全 MAX
            RoundTimeoutConfig {
                initial_timeout: 7,
                max_timeout: 0,
                backoff_factor: 3,
            },
            RoundTimeoutConfig {
                initial_timeout: 9,
                max_timeout: 4,
                backoff_factor: 2,
            },
            RoundTimeoutConfig {
                initial_timeout: 1,
                max_timeout: u64::MAX,
                backoff_factor: 2,
            },
            RoundTimeoutConfig {
                initial_timeout: u64::MAX,
                max_timeout: u64::MAX,
                backoff_factor: u64::MAX,
            },
        ];
        for cfg in configs {
            for round in [0u64, 1, 2, 3, 5, 7, 10, 31, 63, 64, 65, 100, 1_000] {
                assert_eq!(
                    cfg.timeout_for(round),
                    reference_timeout_for(&cfg, round),
                    "cfg={cfg:?} round={round} 必须与朴素定义逐值一致"
                );
            }
        }
    }

    #[test]
    fn timeout_for_terminates_for_degenerate_configs_and_huge_rounds() {
        // 旧实现（`for _ in 0..round`）在以下输入上会迭代 ~2^64 次 ⇒ 若回归为 O(round)，
        // 本测试将**不终止**（终止性即判据）。
        let flat = RoundTimeoutConfig {
            initial_timeout: 5,
            max_timeout: 1_000_000,
            backoff_factor: 1,
        };
        assert_eq!(flat.timeout_for(u64::MAX), 5);
        let zero_initial = RoundTimeoutConfig {
            initial_timeout: 0,
            max_timeout: 60_000,
            backoff_factor: 2,
        };
        assert_eq!(zero_initial.timeout_for(u64::MAX), 0);
        let saturating = RoundTimeoutConfig {
            initial_timeout: 1,
            max_timeout: u64::MAX,
            backoff_factor: 2,
        };
        assert_eq!(saturating.timeout_for(u64::MAX), u64::MAX);
        // 期望值由**当前配置**派生（不硬编码默认数值；ADR-0049 §3.5 数值 OPEN）。
        // 恒真上界：`round ≥ 1 ⇒ 结果 ≤ max_timeout`。“已达 cap” 仅在前提成立时断言：
        // `initial_timeout ≤ max_timeout` 且 `backoff_factor ≥ 2` ⇒ 至多 64 步即达 cap
        // （见 `MAX_BACKOFF_STEPS`）；前提不成立（序列不增长）时**不**假设达到 cap。
        let capped = RoundTimeoutConfig::default();
        assert!(
            capped.timeout_for(u64::MAX) <= capped.max_timeout,
            "极大 round ⇒ 结果不超过 cap"
        );
        if capped.initial_timeout <= capped.max_timeout && capped.backoff_factor >= 2 {
            assert_eq!(
                capped.timeout_for(u64::MAX),
                capped.max_timeout,
                "前提成立 ⇒ 极大 round 达到 cap"
            );
        }
    }

    #[test]
    fn timeout_for_is_monotonic_and_bounded_by_cap() {
        let cfg = RoundTimeoutConfig::default();
        // round 0 = initial（**不施 cap** —— 既有行为，见本测试末尾 `invalid` 用例）；
        // 期望值由**当前配置**派生，不硬编码默认数值。
        assert_eq!(
            cfg.timeout_for(0),
            cfg.initial_timeout,
            "round 0 = initial（不施 cap，既有行为）"
        );
        // 自 round 1 起：`结果 ≤ cap` 恒成立；且序列非递减（round 0 → 1 在非法配置
        // `initial > max` 下是既有例外，故不在此处断言，仍由末尾 `invalid` 用例覆盖）。
        let mut prev = cfg.timeout_for(1);
        assert!(prev <= cfg.max_timeout, "round 1: 不超过 cap");
        for round in 2..80u64 {
            let v = cfg.timeout_for(round);
            assert!(v >= prev, "round {round}: 序列非递减（round ≥ 1）");
            assert!(v <= cfg.max_timeout, "round {round}: 不超过 cap");
            prev = v;
        }
        // “已在 64 步内达到 cap” 的前提：`initial ≤ max` 且 `backoff ≥ 2`（否则序列不增长，
        // 不应无条件假设达到 cap）。
        if cfg.initial_timeout <= cfg.max_timeout && cfg.backoff_factor >= 2 {
            assert_eq!(
                cfg.timeout_for(64),
                cfg.max_timeout,
                "前提成立 ⇒ 64 步内达到 cap"
            );
        }
        // initial > max 的非法配置：round 0 仍返回 initial（既有行为）；round ≥ 1 ⇒ cap
        let invalid = RoundTimeoutConfig {
            initial_timeout: 9,
            max_timeout: 4,
            backoff_factor: 2,
        };
        assert_eq!(invalid.timeout_for(0), 9);
        assert_eq!(invalid.timeout_for(1), 4);
        assert_eq!(invalid.timeout_for(u64::MAX), 4);
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

    // ---- 10-5.1 修复 A：vote 必须绑定当前 (height, round) context ----

    #[test]
    fn process_vote_accepts_same_height_and_round() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // 同 height=1 / round=0 ⇒ accepted（prevote 达 quorum → Precommit）
        let t = process_vote(&mut state, &vote(0x01, VoteType::Prevote, 1), 200, quorum);
        assert!(t.prevote_quorum);
        assert_eq!(state.step, RoundStep::Precommit);
        assert_eq!(state.prevotes.weight_of(&[0x01; 32]), 200);
    }

    #[test]
    fn process_vote_ignores_wrong_height() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // wrong height（vote.height=99 ≠ state.height=1）⇒ 忽略：不进 accumulator、不推进
        let mut v = vote(0x01, VoteType::Prevote, 1);
        v.height = 99;
        let t = process_vote(&mut state, &v, 200, quorum);
        assert!(!t.prevote_quorum);
        assert_eq!(state.step, RoundStep::Prevote);
        assert_eq!(
            state.prevotes.weight_of(&[0x01; 32]),
            0,
            "不得进入 accumulator"
        );
    }

    #[test]
    fn process_vote_ignores_wrong_round() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // wrong round（vote.round=7 ≠ state.round=0）⇒ 忽略
        let mut v = vote(0x01, VoteType::Prevote, 1);
        v.round = 7;
        let t = process_vote(&mut state, &v, 200, quorum);
        assert!(!t.prevote_quorum);
        assert_eq!(state.step, RoundStep::Prevote);
        assert_eq!(state.prevotes.weight_of(&[0x01; 32]), 0);
    }

    #[test]
    fn process_vote_old_round_vote_cannot_affect_quorum() {
        let mut state = RoundState::new(1, 1);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // 旧 round（vote.round=0 < state.round=1）⇒ 不能帮助达 quorum
        let mut old = vote(0x01, VoteType::Prevote, 1);
        old.round = 0;
        let t = process_vote(&mut state, &old, 200, quorum);
        assert!(!t.prevote_quorum);
        assert_eq!(state.prevotes.weight_of(&[0x01; 32]), 0);
        // 正确的当前 round vote 仍有效
        let mut cur = vote(0x01, VoteType::Prevote, 1);
        cur.round = 1;
        let t2 = process_vote(&mut state, &cur, 200, quorum);
        assert!(t2.prevote_quorum);
    }

    #[test]
    fn process_vote_future_round_vote_cannot_affect_quorum() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // future round（vote.round=5 > state.round=0）⇒ 忽略
        let mut f = vote(0x01, VoteType::Prevote, 1);
        f.round = 5;
        let t = process_vote(&mut state, &f, 200, quorum);
        assert!(!t.prevote_quorum);
        assert_eq!(state.prevotes.weight_of(&[0x01; 32]), 0);
        assert_eq!(state.step, RoundStep::Prevote);
    }

    // ---- 10-5.1 修复 B：Finalized 之后状态稳定 ----

    #[test]
    fn process_vote_finalized_state_stays_stable() {
        let mut state = RoundState::new(1, 0);
        state.set_proposal(ProposalRef {
            block_hash: [0x01; 32],
            proposer: vid(1),
        });
        let quorum = 200u128;
        // 正常流程：prevote quorum → Precommit；precommit quorum → Finalized
        process_vote(&mut state, &vote(0x01, VoteType::Prevote, 1), 100, quorum);
        process_vote(&mut state, &vote(0x01, VoteType::Prevote, 2), 100, quorum);
        assert_eq!(state.step, RoundStep::Precommit);
        process_vote(&mut state, &vote(0x01, VoteType::Precommit, 1), 100, quorum);
        let t2 = process_vote(&mut state, &vote(0x01, VoteType::Precommit, 2), 100, quorum);
        assert_eq!(state.step, RoundStep::Finalized);
        assert_eq!(t2.finalized_target, Some([0x01; 32]));
        // Finalized 后新 precommit ⇒ 忽略：无新事件、无重复 finalized_target、不 record
        let t3 = process_vote(&mut state, &vote(0x01, VoteType::Precommit, 3), 100, quorum);
        assert!(!t3.precommit_quorum);
        assert_eq!(t3.finalized_target, None);
        assert_eq!(state.step, RoundStep::Finalized);
        assert_eq!(
            state.precommits.weight_of(&[0x01; 32]),
            200,
            "Finalized 后不得再 record"
        );
        // Finalized 后 prevote 同样忽略
        let t4 = process_vote(&mut state, &vote(0x01, VoteType::Prevote, 3), 100, quorum);
        assert!(!t4.prevote_quorum);
        assert_eq!(state.prevotes.weight_of(&[0x01; 32]), 200);
    }

    // ---- 11-7 / ADR-0041：ProposalRef canonical serialization ----

    #[test]
    fn proposal_ref_roundtrip() {
        let p = ProposalRef {
            block_hash: [0x11; 32],
            proposer: vid(7),
        };
        let bytes = encode_proposal_ref(&p);
        assert_eq!(bytes.len(), 64);
        assert_eq!(decode_proposal_ref(&bytes), Ok(p));
    }

    #[test]
    fn proposal_ref_rejects_bad_length() {
        let p = ProposalRef {
            block_hash: [0x11; 32],
            proposer: vid(7),
        };
        let bytes = encode_proposal_ref(&p);
        // 截断
        assert_eq!(
            decode_proposal_ref(&bytes[..63]),
            Err(ConsensusError::InvalidProposalEncoding)
        );
        // 超长 / trailing
        let mut long = bytes.clone();
        long.push(0x00);
        assert_eq!(
            decode_proposal_ref(&long),
            Err(ConsensusError::InvalidProposalEncoding)
        );
        // 空
        assert_eq!(
            decode_proposal_ref(&[]),
            Err(ConsensusError::InvalidProposalEncoding)
        );
    }

    #[test]
    fn proposal_ref_field_accuracy() {
        let p = ProposalRef {
            block_hash: [0xab; 32],
            proposer: vid(9),
        };
        let bytes = encode_proposal_ref(&p);
        // block_hash = bytes[0..32]
        assert_eq!(&bytes[0..32], &[0xab; 32]);
        // proposer = bytes[32..64]（ValidatorId raw）
        assert_eq!(&bytes[32..64], vid(9).as_bytes());
        // decode 恢复
        let d = decode_proposal_ref(&bytes).unwrap();
        assert_eq!(d.block_hash, [0xab; 32]);
        assert_eq!(d.proposer, vid(9));
    }

    #[test]
    fn proposal_ref_decode_no_authority_check() {
        // decode 不做 authority/membership 验证（任意 proposer 32B 接受；归 consensus 逻辑）
        let mut bytes = [0u8; 64];
        bytes[32..64].copy_from_slice(&[0xee; 32]);
        let d = decode_proposal_ref(&bytes).unwrap();
        assert_eq!(d.proposer, ValidatorId::from_bytes([0xee; 32]));
    }
}
