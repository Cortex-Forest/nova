//! Consensus State Machine Integration（STEP 10-9.3 —
//! `docs/protocols/consensus-integration-implementation-design-v2.md`，FROZEN）。
//!
//! # 核心契约（10-9.2 冻结）
//! - `transition` 为**三元组确定性映射**（MF-12）：
//!   `(ConsensusState, IntegrationContext, ConsensusEvent) →
//!    (ConsensusState', IntegrationContext', TransitionResult)`。
//! - `ConsensusState = { round: RoundState, finality: FinalityState }`（MF-1）；**不含**
//!   QcRegistry / RoundEvidence / LockedState。
//! - `IntegrationContext` = bounded + deterministic + **rebuildable** derived cache（H-3），
//!   非 canonical state（MF-1/MF-10/MF-11/MF-12）。
//! - `QcRegistry` = **PrevoteQC-only** canonical bounded set（MF-9/MF-10）：identity =
//!   `encode_qc(qc)`（复用冻结编码）；rank = identity 字典序；lowest-N（N=64）由
//!   `BTreeMap` 全序 + `pop_last` 维持 ⇒ permutation invariant。
//! - `RoundEvidence` = 当前 (height, round) 已验证票（ephemeral，MF-11），仅用于 QC
//!   construction（MF-8 只组装冻结 `QuorumCertificate`）。
//! - PrecommitQC **不进 registry**（§3.0）：pipeline ⑥ 直接驱动 finality/checkpoint。
//! - RoundTimeout ≠ 证据：仅推进 round（`checked_successor`）；`MAX_ROUND + timeout`
//!   ⇒ `Rejected{RoundOverflow}`（MF-5/MF-7）。
//!
//! # 冻结边界（禁令）
//! - 不新增 quorum/signature/target/QC-validity 规则（MF-8）；不新增 consensus primitive。
//! - 不改 `round.rs`/`finality.rs`/`checkpoint.rs`/`fork_choice.rs`/`vote.rs`/`dag.rs`/
//!   `validator.rs`/`error.rs`/`witness.rs`/冻结 ADR。
//! - `fork_choice` 仅下游消费（不反向产生 finality）；同 snapshot（MF-4）。

use crate::checkpoint::{Checkpoint, derive_checkpoint};
use crate::dag::Dag;
use crate::finality::{
    Applicability, FinalityState, QcContext, QcEvidence, QuorumCertificate, UpdateMode,
    check_finality_applicability, encode_qc, update_finalized_reference, verify_qc,
};
use crate::fork_choice::fork_choice;
use crate::round::{ProposalRef, RoundState, RoundStep, process_vote};
use crate::validator::{ValidatorId, ValidatorSet};
use crate::vote::{ValidatorVote, VoteType};
use std::collections::{BTreeMap, HashMap};

/// Bounded **Prevote**-QC registry 容量（MF-10；Review-4 H-4 ACCEPT，冻结）。
pub const MAX_QC_REGISTRY_ENTRIES: usize = 64;

/// 协议冻结 round 上限（MF-5）：类型上界，`checked_successor` = `checked_add(1)`，不 wrap。
pub const MAX_ROUND: u64 = u64::MAX;

/// `round.checked_add(1)`；`None`（r == MAX_ROUND）⇒ `Rejected{RoundOverflow}`。
pub fn checked_successor(r: u64) -> Option<u64> {
    r.checked_add(1)
}

/// Consensus canonical state（MF-1）：仅 round + finality；可持久化、可 replay 比对。
#[derive(Debug, Clone)]
pub struct ConsensusState {
    pub round: RoundState,
    pub finality: FinalityState,
}

/// ConsensusEvent（MF-2 / MF-5）。
///
/// `Vote` 中的 `vote` MUST 已通过 V-5 验证（**硬 precondition，调用方保证**）；
/// integration **不重新验证签名**，但绝不把未经验证的 Vote 视为协议有效。
/// `signature` 仅用于 MF-8 QC 组装（evidence.signature）。
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    Vote {
        vote: ValidatorVote,
        signature: [u8; 64],
    },
    SetProposal(ProposalRef),
    RoundTimeout,
}

/// 派生观察结果（本次 transition 的派生事实，非长期状态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransitionObservation {
    pub prevote_quorum: bool,
    pub precommit_quorum: bool,
    pub finalized_advance: bool,
}

/// 同 snapshot 的派生输出（MF-4/MF-7）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransitionDerived {
    /// 仅 prevote quorum 时 Some（MF-8 组装；已 admit 进 registry）。
    pub prevote_qc: Option<QuorumCertificate>,
    /// 仅 precommit quorum 时 Some（MF-8 组装；**不经 registry**）。
    pub precommit_qc: Option<QuorumCertificate>,
    /// 仅 finality Advance 时 Some（CP-MF-4）。
    pub checkpoint: Option<Checkpoint>,
    /// 同 snapshot（MF-4）。
    pub fork_choice_head: Option<[u8; 32]>,
}

/// Ignored 原因（state 与 context 均不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    /// vote context（height/round）或 SetProposal 阶段不符。
    ContextMismatch,
    /// `RoundStep::Finalized` 之后的 vote。
    Terminal,
}

/// Rejected 原因（state 与 context 均不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `MAX_ROUND + timeout`（不 wrap）。
    RoundOverflow,
}

/// Transition 结果（MF-7）：`Applied` 产生完整 next_state + 确定性 context 更新；
/// `Ignored`/`Rejected` ⇒ state 与 context 均不变（MF-12 契约 3）。
/// （`Applied` 携带完整 next_state，必然大于 Ignored/Rejected；Box 不改变协议语义，故 allow。）
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum TransitionResult {
    Applied {
        next_state: ConsensusState,
        observation: TransitionObservation,
        derived: TransitionDerived,
    },
    Ignored {
        reason: IgnoreReason,
    },
    Rejected {
        reason: RejectReason,
    },
}

/// IntegrationContext（MF-12）：bounded + deterministic + rebuildable derived cache，非 canonical state。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationContext {
    pub qc_registry: QcRegistry,
    pub round_evidence: RoundEvidence,
}

impl IntegrationContext {
    /// 初始 context；`(height, round)` 必须与初始 `ConsensusState.round` 一致（契约）。
    pub fn new(height: u64, round: u64) -> Self {
        Self {
            qc_registry: QcRegistry::new(),
            round_evidence: RoundEvidence::new(height, round),
        }
    }
}

/// QC identity：直接复用冻结 `encode_qc`（MF-9；不新写编码）。
fn qc_identity(qc: &QuorumCertificate) -> Vec<u8> {
    encode_qc(qc)
}

/// PrevoteQC-only bounded registry（MF-9/MF-10）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QcRegistry {
    /// key = `qc_identity`（全序）；value = PrevoteQC。
    inner: BTreeMap<Vec<u8>, QuorumCertificate>,
}

/// `admit` 结果（对 registry content 的净效果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QcAdmission {
    /// same identity 已在 registry（去重）；content 不变。
    Noop,
    /// 未满插入，或满时按 canonical rank 替换 worst；content 增加候选。
    Inserted,
    /// 满且候选不优于 worst；content 不变。
    Rejected,
}

impl QcRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 不变式：`inner.len() <= MAX_QC_REGISTRY_ENTRIES`（admit 维持）。
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.len() >= MAX_QC_REGISTRY_ENTRIES
    }

    pub fn contains(&self, qc: &QuorumCertificate) -> bool {
        self.inner.contains_key(&qc_identity(qc))
    }

    /// canonical bounded set admission（MF-9 方案 A；**Prevote-only**，§3.0）：
    /// 调用方保证只对 PrevoteQC 调用（pipeline ⑤ 仅 prevote 分支调 admit）。
    /// ① same identity ⇒ `Noop`；② 未满 ⇒ 插入；③ 满 ⇒ 候选 rank 优于当前 worst ⇒
    /// 替换 worst；否则 ⇒ `Rejected`。结果 = lowest-N（permutation invariant）。
    pub fn admit(&mut self, qc: QuorumCertificate) -> QcAdmission {
        let k = qc_identity(&qc);
        if self.inner.contains_key(&k) {
            return QcAdmission::Noop;
        }
        if self.inner.len() >= MAX_QC_REGISTRY_ENTRIES {
            // 满：仅当候选 rank（字典序）优于当前 worst（最大 key）时替换。
            let replace = match self.inner.keys().next_back() {
                Some(worst) => k < *worst,
                None => false, // len >= MAX >= 1 ⇒ 不可达；防御
            };
            if !replace {
                return QcAdmission::Rejected;
            }
            self.inner.pop_last();
        }
        self.inner.insert(k, qc);
        QcAdmission::Inserted
    }

    /// 供 fork_choice 消费的 prevote_qcs（全为 Prevote，§3.0）。
    /// 迭代顺序 = BTreeMap key 序（确定性）。
    pub fn prevote_qcs(&self) -> Vec<QuorumCertificate> {
        self.inner.values().cloned().collect()
    }
}

/// target → 按 validator_id 升序的已验证 (vote, signature)。
type TargetEvidence = BTreeMap<ValidatorId, (ValidatorVote, [u8; 64])>;
type EvidenceByTarget = HashMap<[u8; 32], TargetEvidence>;

/// 当前 (height, round) 已验证票（ephemeral，MF-11）——仅用于 QC construction。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoundEvidence {
    by_target: EvidenceByTarget,
    bound: (u64, u64),
}

impl RoundEvidence {
    pub fn new(height: u64, round: u64) -> Self {
        Self {
            by_target: HashMap::new(),
            bound: (height, round),
        }
    }

    /// 记录已验证票（MF-2 hard precondition）。bound 守卫：不匹配当前 (height,round) 忽略
    /// （防御；transition ① 上下文守卫已保证匹配）。
    pub fn record(&mut self, vote: &ValidatorVote, signature: &[u8; 64]) {
        if vote.height != self.bound.0 || vote.round != self.bound.1 {
            return;
        }
        self.by_target
            .entry(vote.target_block_hash)
            .or_default()
            .insert(vote.validator_id, (vote.clone(), *signature));
    }

    /// round 推进时 reset（timeout 路径）；绑定新 (height, round)。
    pub fn reset(&mut self, height: u64, round: u64) {
        self.by_target.clear();
        self.bound = (height, round);
    }

    /// 组装 QC（MF-8：只组装冻结 `QuorumCertificate`；evidence 升序 = BTreeMap 迭代序）。
    /// 空 evidence ⇒ `None`。
    pub fn assemble_qc(
        &self,
        chain_id: u64,
        validator_set_id: &[u8; 32],
        target: [u8; 32],
        vote_type: VoteType,
        height: u64,
        round: u64,
    ) -> Option<QuorumCertificate> {
        let entries = self.by_target.get(&target)?;
        let evidence: Vec<QcEvidence> = entries
            .iter()
            .map(|(vid, (v, sig))| QcEvidence {
                validator_id: *vid,
                source_block_hash: v.source_block_hash,
                timestamp: v.timestamp,
                signature: *sig,
            })
            .collect();
        if evidence.is_empty() {
            return None;
        }
        Some(QuorumCertificate {
            context: QcContext {
                chain_id,
                height,
                round,
                vote_type,
            },
            target,
            validator_set_id: *validator_set_id,
            evidence,
        })
    }
}

/// 原子 consensus transition（MF-3/MF-7/MF-12）。
///
/// - `state` 只读；成功 ⇒ 完整 `next_state` + 确定性 `context` 更新；`Ignored`/`Rejected`
///   ⇒ 原状态不变 **且 context 不变**（MF-12 契约 3）。
/// - `chain_id` = 域绑定（QC context / vote 域分离），由调用方传入（冻结不变）。
/// - 顺序：Round → QC → Finality → Checkpoint → ForkChoice（§5.2）。
#[allow(clippy::too_many_arguments)]
pub fn transition(
    state: &ConsensusState,
    event: ConsensusEvent,
    context: &mut IntegrationContext,
    chain_id: u64,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> TransitionResult {
    match event {
        ConsensusEvent::SetProposal(p) => {
            let mut round = state.round.clone();
            if !round.set_proposal(p) {
                // step != Propose ⇒ 上下文不符（context 不变）。
                return TransitionResult::Ignored {
                    reason: IgnoreReason::ContextMismatch,
                };
            }
            TransitionResult::Applied {
                next_state: ConsensusState {
                    round,
                    finality: state.finality.clone(),
                },
                observation: TransitionObservation::default(),
                derived: TransitionDerived::default(),
            }
        }
        ConsensusEvent::RoundTimeout => {
            let Some(next_round) = checked_successor(state.round.round) else {
                // MAX_ROUND + timeout ⇒ 不 wrap；state 与 context 不变。
                return TransitionResult::Rejected {
                    reason: RejectReason::RoundOverflow,
                };
            };
            let height = state.round.height;
            let round = RoundState::new(height, next_round);
            // timeout ≠ 证据：仅推进 round 并重置 evidence（MF-5/MF-11）。
            context.round_evidence.reset(height, next_round);
            TransitionResult::Applied {
                next_state: ConsensusState {
                    round,
                    finality: state.finality.clone(),
                },
                observation: TransitionObservation::default(),
                derived: TransitionDerived::default(),
            }
        }
        ConsensusEvent::Vote { vote, signature } => {
            // ① 上下文守卫（10-5.1）：vote 必须绑定当前 (height, round)。
            if vote.height != state.round.height || vote.round != state.round.round {
                return TransitionResult::Ignored {
                    reason: IgnoreReason::ContextMismatch,
                };
            }
            // ② 终态守卫（10-5.1）：Finalized 之后任何 vote 忽略。
            if state.round.step == RoundStep::Finalized {
                return TransitionResult::Ignored {
                    reason: IgnoreReason::Terminal,
                };
            }
            // ③ 记录已验证票（hard precondition；MF-11）。
            context.round_evidence.record(&vote, &signature);
            // ④ Round transition（副本；B-2）。
            let mut round = state.round.clone();
            let weight = set.weight_of(&vote.validator_id).unwrap_or(0);
            let quorum = set.quorum();
            let t = process_vote(&mut round, &vote, weight, quorum);

            let height = state.round.height;
            let rnd = state.round.round;
            let mut finality = state.finality.clone();
            let mut observation = TransitionObservation {
                prevote_quorum: t.prevote_quorum,
                precommit_quorum: false,
                finalized_advance: false,
            };
            let mut derived = TransitionDerived::default();

            // ⑤ prevote quorum ⇒ 组装 PrevoteQC（仅 Prevote 入 registry，§3.0）。
            if t.prevote_quorum {
                derived.prevote_qc = context.round_evidence.assemble_qc(
                    chain_id,
                    expected_genesis_hash,
                    vote.target_block_hash,
                    VoteType::Prevote,
                    height,
                    rnd,
                );
                if let Some(qc) = &derived.prevote_qc {
                    context.qc_registry.admit(qc.clone());
                }
            }
            // ⑥ precommit quorum ⇒ 组装 PrecommitQC（**不经 registry**，MF-10 S1）
            //    → verify_qc（Validity）→ applicability → update_finalized_reference。
            if t.precommit_quorum {
                observation.precommit_quorum = true;
                if let Some(target) = t.finalized_target {
                    derived.precommit_qc = context.round_evidence.assemble_qc(
                        chain_id,
                        expected_genesis_hash,
                        target,
                        VoteType::Precommit,
                        height,
                        rnd,
                    );
                    if let Some(qc) = &derived.precommit_qc
                        && verify_qc(qc, set, expected_genesis_hash, dag).is_ok()
                    {
                        let app = check_finality_applicability(
                            qc,
                            finality.finalized_reference.as_ref(),
                            dag,
                        );
                        let _ = update_finalized_reference(&mut finality, qc, app);
                        // 仅 Advance 才算 finalized_advance（Idempotent/Stale/Conflict 不算）。
                        observation.finalized_advance = matches!(
                            app,
                            Applicability::Applicable {
                                mode: UpdateMode::Advance
                            }
                        );
                        // checkpoint 仅 finality Advance（CP-MF-4）。
                        if observation.finalized_advance
                            && let Some(fr) = finality.finalized_reference
                        {
                            derived.checkpoint = derive_checkpoint(fr, qc);
                        }
                    }
                }
            }
            // ⑦ 完整 next_state（原子）。
            let next_state = ConsensusState { round, finality };
            // ⑧ ForkChoice 消费同一 snapshot（MF-4）。
            derived.fork_choice_head = fork_choice(
                dag,
                next_state.finality.finalized_reference.as_ref(),
                &context.qc_registry.prevote_qcs(),
                set,
                expected_genesis_hash,
            );
            // ⑨
            TransitionResult::Applied {
                next_state,
                observation,
                derived,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::BlockReference;
    use crate::finality::QcEvidence;
    use crate::vote::canonical_vote_payload;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use proptest::prelude::*;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];
    const TARGET: [u8; 32] = [0xAA; 32];
    const ZERO: [u8; 32] = [0x00; 32];

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn vin(pk: [u8; 32], stake: u128, kh: [u8; 32]) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: stake,
            commission_bps: 100,
        }
    }

    fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_timestamp: 0,
            initial_validator_set: vals,
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

    struct TestCtx {
        set: ValidatorSet,
        kps: Vec<KeyPair>,
    }

    fn test_ctx(n: usize, stake: u128) -> TestCtx {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().unwrap();
            let pk = kp.verifying_key().to_bytes();
            kps.push(kp);
            vals.push(vin(pk, stake, [i as u8 + 0x10; 32]));
        }
        TestCtx {
            set: ValidatorSet::from_genesis(&genesis_with(vals)),
            kps,
        }
    }

    fn validator_id_of(ctx: &TestCtx, i: usize) -> ValidatorId {
        ValidatorId::from_consensus_public_key(&ctx.kps[i].verifying_key().to_bytes())
    }

    fn sign_vote(signing: &nova_crypto::signature::SigningKey, vote: &ValidatorVote) -> [u8; 64] {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .unwrap();
        sign_message_hash(signing, &hash_signing_message(&signed)).to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_vote(
        ctx: &TestCtx,
        i: usize,
        target: [u8; 32],
        round: u64,
        height: u64,
        vt: VoteType,
        source: [u8; 32],
        timestamp: u64,
    ) -> ValidatorVote {
        ValidatorVote {
            round,
            height,
            target_block_hash: target,
            vote_type: vt,
            source_block_hash: source,
            validator_id: validator_id_of(ctx, i),
            timestamp,
        }
    }

    /// 直接构造带真实签名的 QC（registry 单元测试/identity 测试用）。
    #[allow(clippy::too_many_arguments)]
    fn make_qc_typed(
        ctx: &TestCtx,
        idxs: &[usize],
        target: [u8; 32],
        round: u64,
        height: u64,
        vt: VoteType,
        source: [u8; 32],
        timestamp: u64,
    ) -> QuorumCertificate {
        let mut evidence: Vec<QcEvidence> = Vec::with_capacity(idxs.len());
        for &i in idxs {
            let vote = make_vote(ctx, i, target, round, height, vt, source, timestamp);
            let sig = sign_vote(ctx.kps[i].signing_key(), &vote);
            evidence.push(QcEvidence {
                validator_id: vote.validator_id,
                source_block_hash: source,
                timestamp,
                signature: sig,
            });
        }
        evidence.sort_by_key(|e| e.validator_id);
        QuorumCertificate {
            context: QcContext {
                chain_id: CHAIN_ID,
                height,
                round,
                vote_type: vt,
            },
            target,
            validator_set_id: GENESIS_HASH,
            evidence,
        }
    }

    /// DAG：A(0) → B(1) → C(2)；X(0) 独立分支。
    fn build_dag() -> Dag {
        let mut dag = Dag::new();
        dag.add_block(BlockReference {
            block_hash: [0xAA; 32],
            height: 0,
            parents: vec![],
            proposer: ValidatorId::from_bytes([0xAA; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0xBB; 32],
            height: 1,
            parents: vec![[0xAA; 32]],
            proposer: ValidatorId::from_bytes([0xBB; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0xCC; 32],
            height: 2,
            parents: vec![[0xBB; 32]],
            proposer: ValidatorId::from_bytes([0xCC; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0x11; 32],
            height: 0,
            parents: vec![],
            proposer: ValidatorId::from_bytes([0x11; 32]),
        })
        .unwrap();
        dag
    }

    fn state0() -> ConsensusState {
        ConsensusState {
            round: RoundState::new(0, 0),
            finality: FinalityState::default(),
        }
    }

    fn expect_applied(
        r: TransitionResult,
    ) -> (ConsensusState, TransitionObservation, TransitionDerived) {
        match r {
            TransitionResult::Applied {
                next_state,
                observation,
                derived,
            } => (next_state, observation, derived),
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    /// ConsensusState 等价（RoundState 无 PartialEq ⇒ 比较可观察关键字段）。
    fn state_eq(a: &ConsensusState, b: &ConsensusState) -> bool {
        a.finality == b.finality
            && a.round.height == b.round.height
            && a.round.round == b.round.round
            && a.round.step == b.round.step
            && a.round.proposal == b.round.proposal
    }

    fn vote_event(ctx: &TestCtx, i: usize, vt: VoteType, timestamp: u64) -> ConsensusEvent {
        let v = make_vote(ctx, i, TARGET, 0, 0, vt, ZERO, timestamp);
        ConsensusEvent::Vote {
            vote: v.clone(),
            signature: sign_vote(ctx.kps[i].signing_key(), &v),
        }
    }

    /// 指定 height 的 vote event（t7/t22 使用 height>0 的 state）。
    fn vote_event_at(
        ctx: &TestCtx,
        i: usize,
        vt: VoteType,
        timestamp: u64,
        height: u64,
    ) -> ConsensusEvent {
        let v = make_vote(ctx, i, TARGET, 0, height, vt, ZERO, timestamp);
        ConsensusEvent::Vote {
            vote: v.clone(),
            signature: sign_vote(ctx.kps[i].signing_key(), &v),
        }
    }

    fn propose_event(ctx: &TestCtx) -> ConsensusEvent {
        ConsensusEvent::SetProposal(ProposalRef {
            block_hash: TARGET,
            proposer: validator_id_of(ctx, 0),
        })
    }

    // ---- T1：完整生命周期 ----
    #[test]
    fn t1_full_lifecycle() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);

        // SetProposal(A)
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        assert_eq!(state.round.step, RoundStep::Prevote);

        // prevote v0（未达 quorum：1×100 < 134）
        let (s2, o2, d2) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        assert!(!o2.prevote_quorum);
        assert!(d2.prevote_qc.is_none());

        // prevote v1（达 quorum：2×100 = 200 >= 134）
        let (s3, o3, d3) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s3;
        assert!(o3.prevote_quorum);
        let pqc = d3.prevote_qc.expect("prevote qc");
        assert_eq!(pqc.context.vote_type, VoteType::Prevote);
        assert_eq!(context.qc_registry.len(), 1, "registry 含 1 个 PrevoteQC");

        // precommit v0（未达 quorum）
        let (s4, o4, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Precommit, 200),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s4;
        assert!(!o4.precommit_quorum);

        // precommit v1（达 quorum → finality Advance）
        let (s5, o5, d5) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Precommit, 200),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s5;
        assert!(o5.precommit_quorum);
        assert!(o5.finalized_advance);
        assert!(d5.precommit_qc.is_some());
        assert!(
            d5.checkpoint.is_some(),
            "finality Advance ⇒ checkpoint Some"
        );
        assert_eq!(
            d5.fork_choice_head,
            Some(TARGET),
            "FC-12：head == finalized"
        );
        assert_eq!(state.finality.finalized_reference, Some(TARGET));
        assert_eq!(
            context.qc_registry.len(),
            1,
            "PrecommitQC 不入 registry（§3.0）"
        );
        assert_eq!(state.round.step, RoundStep::Finalized);
    }

    // ---- T2：上下文不符 ⇒ Ignored（state 与 context 均不变）----
    #[test]
    fn t2_context_mismatch_ignored() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        // 先推进到 Prevote
        let (s, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s;

        let before = context.clone();
        // height 不符的 vote（height=1）
        let v = make_vote(&ctx, 0, TARGET, 0, 1, VoteType::Prevote, ZERO, 100);
        let ev = ConsensusEvent::Vote {
            vote: v.clone(),
            signature: sign_vote(ctx.kps[0].signing_key(), &v),
        };
        let r = transition(
            &state,
            ev,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Ignored {
                reason: IgnoreReason::ContextMismatch
            }
        ));
        assert_eq!(context, before, "Ignored ⇒ context 不变（T18）");
    }

    // ---- T3：幂等（同 validator 同 target 重复 prevote 不改变状态）----
    #[test]
    fn t3_idempotent_vote() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let (s, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s;

        // v0 prevote 两次
        let (s1, o1, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        let (s2, o2, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        assert!(
            !o1.prevote_quorum && !o2.prevote_quorum,
            "重复票不触发 quorum"
        );
        assert_eq!(
            state.round.prevotes.weight_of(&TARGET),
            100,
            "同 validator 只计一次"
        );
    }

    // ---- T4：replay（同事件序列 ⇒ 同最终状态 + 同 context）----
    #[test]
    fn t4_replay() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();

        let s1 = state0();
        let mut c1 = IntegrationContext::new(0, 0);
        let s2 = state0();
        let mut c2 = IntegrationContext::new(0, 0);

        let seq = [
            ConsensusEvent::SetProposal(ProposalRef {
                block_hash: TARGET,
                proposer: validator_id_of(&ctx, 0),
            }),
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            vote_event(&ctx, 0, VoteType::Precommit, 200),
            vote_event(&ctx, 1, VoteType::Precommit, 200),
        ];
        for ev in &seq {
            let r1 = transition(
                &s1,
                ev.clone(),
                &mut c1,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            let r2 = transition(
                &s2,
                ev.clone(),
                &mut c2,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            assert_eq!(std::mem::discriminant(&r1), std::mem::discriminant(&r2));
        }
        assert!(state_eq(&s1, &s2), "replay 同最终状态");
        assert_eq!(c1, c2, "replay 同 context（MF-12）");
    }

    // ---- T5：Finalized 后 vote ⇒ Ignored{Terminal} ----
    #[test]
    fn t5_finalized_ignored_terminal() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        // 推进到 finalized
        let mut run = |ev: ConsensusEvent| {
            let (s, _, _) = expect_applied(transition(
                &state,
                ev,
                &mut context,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            ));
            state = s;
        };
        run(propose_event(&ctx));
        run(vote_event(&ctx, 0, VoteType::Prevote, 100));
        run(vote_event(&ctx, 1, VoteType::Prevote, 100));
        run(vote_event(&ctx, 0, VoteType::Precommit, 200));
        run(vote_event(&ctx, 1, VoteType::Precommit, 200));
        assert_eq!(state.round.step, RoundStep::Finalized);

        let before = context.clone();
        let r = transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Ignored {
                reason: IgnoreReason::Terminal
            }
        ));
        assert_eq!(context, before, "Terminal ⇒ context 不变（T18）");
    }

    // ---- T6：ForkChoice 下游（finality ⇒ head；反向不成立）----
    #[test]
    fn t6_fork_choice_downstream() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);

        // 只有 prevote（无 finality）
        let (s1, o1, d1) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        let (s2, _, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        let (s3, o3, d3) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s3;
        assert!(o3.prevote_quorum);
        assert_eq!(
            state.finality.finalized_reference, None,
            "prevote 不产生 finality（反向不成立）"
        );
        let _ = o1;
        let _ = d1;
        let _ = d3;

        // precommit ⇒ finality ⇒ head == finalized
        let (s4, _, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Precommit, 200),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s4;
        let (s5, _, d5) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Precommit, 200),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s5;
        assert_eq!(state.finality.finalized_reference, Some(TARGET));
        assert_eq!(
            d5.fork_choice_head,
            Some(TARGET),
            "finality 变化 ⇒ head 更新为 finalized"
        );
    }

    // ---- T7：checkpoint 仅 finality Advance（Idempotent ⇒ None）----
    #[test]
    fn t7_checkpoint_only_on_advance() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        // 构造"已 final 到 A"的 state（新 height=1），再对 A 达 precommit quorum ⇒ Idempotent
        let mut state = ConsensusState {
            round: RoundState::new(1, 0),
            finality: FinalityState {
                finalized_reference: Some(TARGET),
                highest_precommit_qc: None,
            },
        };
        let mut context = IntegrationContext::new(1, 0);
        // SetProposal(A)（新 height round）
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        // prevote quorum（height=1）
        let (s2, _, _) = expect_applied(transition(
            &state,
            vote_event_at(&ctx, 0, VoteType::Prevote, 100, 1),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        let (s3, _, _) = expect_applied(transition(
            &state,
            vote_event_at(&ctx, 1, VoteType::Prevote, 100, 1),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s3;
        // precommit quorum target=A，与 finalized_reference=A 相同 ⇒ Idempotent
        let (s4, _, _) = expect_applied(transition(
            &state,
            vote_event_at(&ctx, 0, VoteType::Precommit, 200, 1),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s4;
        let (_, o5, d5) = expect_applied(transition(
            &state,
            vote_event_at(&ctx, 1, VoteType::Precommit, 200, 1),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert!(o5.precommit_quorum);
        assert!(!o5.finalized_advance, "Idempotent 非 Advance");
        assert!(
            d5.checkpoint.is_none(),
            "非 Advance ⇒ checkpoint None（CP-MF-4）"
        );
        assert_eq!(
            d5.fork_choice_head,
            Some(TARGET),
            "FC-12：head == finalized（Idempotent 仍成立）"
        );
    }

    // ---- T8：timeout 推进 round，finality 保留，derived 全 None ----
    #[test]
    fn t8_timeout_advances_round() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        // 先有 prevote 累积
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        let (s2, _, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;

        let (s3, o3, d3) = expect_applied(transition(
            &state,
            ConsensusEvent::RoundTimeout,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert_eq!(s3.round.round, 1, "round+1");
        assert_eq!(s3.round.step, RoundStep::Propose, "新 round 重置为 Propose");
        assert_eq!(s3.finality.finalized_reference, None, "finality 不变");
        assert!(!o3.prevote_quorum && !o3.precommit_quorum && !o3.finalized_advance);
        assert!(d3.prevote_qc.is_none() && d3.precommit_qc.is_none());
        assert!(
            d3.checkpoint.is_none() && d3.fork_choice_head.is_none(),
            "timeout≠证据（T14）"
        );
        assert_eq!(
            context.round_evidence,
            RoundEvidence::new(0, 1),
            "timeout reset evidence（MF-11）"
        );
    }

    // ---- T9：determinism（proptest 随机事件序列 ⇒ 同输入同输出）----
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EventKind {
        Propose,
        Timeout,
        Vote0,
        Vote1,
        Pre0,
        Pre1,
    }

    fn apply(
        state: &mut ConsensusState,
        context: &mut IntegrationContext,
        kind: EventKind,
        ctx: &TestCtx,
        dag: &Dag,
    ) {
        let ev = match kind {
            EventKind::Propose => ConsensusEvent::SetProposal(ProposalRef {
                block_hash: TARGET,
                proposer: validator_id_of(ctx, 0),
            }),
            EventKind::Timeout => ConsensusEvent::RoundTimeout,
            EventKind::Vote0 => vote_event(ctx, 0, VoteType::Prevote, 100),
            EventKind::Vote1 => vote_event(ctx, 1, VoteType::Prevote, 100),
            EventKind::Pre0 => vote_event(ctx, 0, VoteType::Precommit, 200),
            EventKind::Pre1 => vote_event(ctx, 1, VoteType::Precommit, 200),
        };
        let r = transition(state, ev, context, CHAIN_ID, &ctx.set, &GENESIS_HASH, dag);
        if let TransitionResult::Applied { next_state, .. } = r {
            *state = next_state;
        }
    }

    proptest! {
        #[test]
        fn t9_determinism(
            seq in prop::collection::vec(
                prop_oneof![
                    Just(EventKind::Propose),
                    Just(EventKind::Timeout),
                    Just(EventKind::Vote0),
                    Just(EventKind::Vote1),
                    Just(EventKind::Pre0),
                    Just(EventKind::Pre1),
                ],
                0..12,
            )
        ) {
            let ctx = test_ctx(2, 100);
            let dag = build_dag();
            let mut s1 = state0();
            let mut c1 = IntegrationContext::new(0, 0);
            let mut s2 = state0();
            let mut c2 = IntegrationContext::new(0, 0);
            for &k in &seq {
                apply(&mut s1, &mut c1, k, &ctx, &dag);
                apply(&mut s2, &mut c2, k, &ctx, &dag);
            }
            assert!(state_eq(&s1, &s2), "state divergence at {seq:?}");
            assert_eq!(c1, c2, "context divergence at {seq:?}");
        }
    }

    // ---- T10：不引入新 consensus state / 冻结 API 消费（结构审查 + smoke）----
    #[test]
    fn t10_no_new_state_and_api() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut context = IntegrationContext::new(0, 0);
        let r = transition(
            &state0(),
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        // 结构断言：ConsensusState 仅 round+finality 字段（类型定义保证）；
        // 此处验证 transition 可正常运行且 derived 无新 primitive 输出。
        let (_, _, d) = expect_applied(r);
        assert!(d.prevote_qc.is_none() && d.precommit_qc.is_none() && d.checkpoint.is_none());
    }

    // ---- T11：Atomic（拒绝路径 ⇒ state 与 context 均无 partial mutation）----
    #[test]
    fn t11_atomic_rejection() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut context = IntegrationContext::new(0, 0);
        // ContextMismatch
        let before = context.clone();
        let v = make_vote(&ctx, 0, TARGET, 0, 9, VoteType::Prevote, ZERO, 100);
        let ev = ConsensusEvent::Vote {
            vote: v.clone(),
            signature: sign_vote(ctx.kps[0].signing_key(), &v),
        };
        let r = transition(
            &state0(),
            ev,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(r, TransitionResult::Ignored { .. }));
        assert_eq!(
            context, before,
            "ContextMismatch ⇒ context 无 partial mutation"
        );
    }

    // ---- T12：Snapshot（fork_choice_head 与 next_state.finality 同 snapshot）----
    #[test]
    fn t12_snapshot_consistency() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let mut run = |ev: ConsensusEvent| {
            let (s, _, _) = expect_applied(transition(
                &state,
                ev,
                &mut context,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            ));
            state = s;
        };
        run(propose_event(&ctx));
        run(vote_event(&ctx, 0, VoteType::Prevote, 100));
        run(vote_event(&ctx, 1, VoteType::Prevote, 100));
        run(vote_event(&ctx, 0, VoteType::Precommit, 200));
        let (s, _, d) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Precommit, 200),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert_eq!(s.finality.finalized_reference, Some(TARGET));
        assert_eq!(
            d.fork_choice_head, s.finality.finalized_reference,
            "head 与 finality 同 snapshot"
        );
    }

    // ---- T13：VerifiedVote 边界（integration 不重验签名；hard precondition）----
    #[test]
    fn t13_verified_vote_boundary() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        // 已验证票（签名正确）进入
        let (s2, o, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        assert!(!o.prevote_quorum);
        // 签名损坏的票仍被 accumulator 处理（integration 信任硬 precondition，不重验 verify_vote）。
        // 这证明 V-5 验证责任在调用方（MF-2），integration 不自行调用 verify_vote。
        let v = make_vote(&ctx, 1, TARGET, 0, 0, VoteType::Prevote, ZERO, 100);
        let mut bad_sig = sign_vote(ctx.kps[1].signing_key(), &v);
        bad_sig[0] ^= 0xFF;
        let (_, o2, _) = expect_applied(transition(
            &state,
            ConsensusEvent::Vote {
                vote: v.clone(),
                signature: bad_sig,
            },
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert!(
            o2.prevote_quorum,
            "integration 不重验签名（信任 precondition）——prevote quorum 正常触发"
        );
    }

    // ---- T14：timeout 不产生证据（并入 T8，此处独立断言 registry/finality）----
    #[test]
    fn t14_timeout_no_evidence() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let (s, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s;
        let registry_before = context.qc_registry.clone();
        let finality_before = state.finality.clone();
        let (s2, o, d) = expect_applied(transition(
            &state,
            ConsensusEvent::RoundTimeout,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert_eq!(s2.finality, finality_before, "timeout 不改 FinalityState");
        assert_eq!(context.qc_registry, registry_before, "timeout 不新增 QC");
        assert!(d.prevote_qc.is_none() && d.precommit_qc.is_none() && d.checkpoint.is_none());
        assert!(!o.prevote_quorum && !o.precommit_quorum && !o.finalized_advance);
    }

    // ---- T15：MAX_ROUND + timeout ⇒ Rejected{RoundOverflow}，不 wrap ----
    #[test]
    fn t15_round_overflow_rejected() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let state = ConsensusState {
            round: RoundState::new(0, MAX_ROUND),
            finality: FinalityState::default(),
        };
        let mut context = IntegrationContext::new(0, MAX_ROUND);
        let r = transition(
            &state,
            ConsensusEvent::RoundTimeout,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Rejected {
                reason: RejectReason::RoundOverflow
            }
        ));
        assert_eq!(state.round.round, MAX_ROUND, "不 wrap");
        assert_eq!(
            context.round_evidence,
            RoundEvidence::new(0, MAX_ROUND),
            "Rejected ⇒ context 不变"
        );
    }

    // ---- T16：registry bounded（Prevote-only）----
    #[test]
    fn t16_registry_bounded() {
        let ctx = test_ctx(3, 100);
        let mut reg = QcRegistry::new();
        for i in 0..(MAX_QC_REGISTRY_ENTRIES + 6) {
            let qc = make_qc_typed(
                &ctx,
                &[0, 1, 2],
                TARGET,
                i as u64,
                0,
                VoteType::Prevote,
                ZERO,
                i as u64,
            );
            reg.admit(qc);
        }
        assert!(reg.len() <= MAX_QC_REGISTRY_ENTRIES, "bounded");
        assert_eq!(reg.len(), MAX_QC_REGISTRY_ENTRIES);
        // duplicate ⇒ Noop（one identity）
        let qc0 = make_qc_typed(&ctx, &[0, 1, 2], TARGET, 0, 0, VoteType::Prevote, ZERO, 0);
        assert_eq!(reg.admit(qc0), QcAdmission::Noop);
        assert_eq!(reg.len(), MAX_QC_REGISTRY_ENTRIES);
    }

    // ---- T17：permutation invariance（canonical lowest-N）----
    #[test]
    fn t17_permutation_invariance() {
        let ctx = test_ctx(3, 100);
        let qcs: Vec<QuorumCertificate> = (0..(MAX_QC_REGISTRY_ENTRIES + 10))
            .map(|i| {
                make_qc_typed(
                    &ctx,
                    &[0, 1, 2],
                    TARGET,
                    i as u64,
                    0,
                    VoteType::Prevote,
                    ZERO,
                    i as u64,
                )
            })
            .collect();
        let mut r1 = QcRegistry::new();
        for qc in &qcs {
            r1.admit(qc.clone());
        }
        let mut r2 = QcRegistry::new();
        for qc in qcs.iter().rev() {
            r2.admit(qc.clone());
        }
        assert_eq!(r1, r2, "不同 insertion order ⇒ 相同 canonical content");
        // 验证 lowest-N：与"identity 排序取前 N"一致
        let mut ids: Vec<Vec<u8>> = qcs.iter().map(qc_identity).collect();
        ids.sort();
        let expected: Vec<Vec<u8>> = ids.iter().take(MAX_QC_REGISTRY_ENTRIES).cloned().collect();
        let mut actual: Vec<Vec<u8>> = r1.prevote_qcs().iter().map(qc_identity).collect();
        actual.sort();
        assert_eq!(actual, expected, "canonical lowest-N");
    }

    // ---- T18：Rejection semantics（ContextMismatch / Finalized / Overflow ⇒ state+context 不变）----
    #[test]
    fn t18_rejection_semantics() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();

        // (a) height/round mismatch
        let mut context = IntegrationContext::new(0, 0);
        let v = make_vote(&ctx, 0, TARGET, 0, 5, VoteType::Prevote, ZERO, 100);
        let ev = ConsensusEvent::Vote {
            vote: v.clone(),
            signature: sign_vote(ctx.kps[0].signing_key(), &v),
        };
        let before = context.clone();
        let r = transition(
            &state0(),
            ev,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Ignored {
                reason: IgnoreReason::ContextMismatch
            }
        ));
        assert_eq!(context, before);

        // (b) Finalized 违例
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let mut run = |ev: ConsensusEvent| {
            let (s, _, _) = expect_applied(transition(
                &state,
                ev,
                &mut context,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            ));
            state = s;
        };
        run(propose_event(&ctx));
        run(vote_event(&ctx, 0, VoteType::Prevote, 100));
        run(vote_event(&ctx, 1, VoteType::Prevote, 100));
        run(vote_event(&ctx, 0, VoteType::Precommit, 200));
        run(vote_event(&ctx, 1, VoteType::Precommit, 200));
        let before = context.clone();
        let r = transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Ignored {
                reason: IgnoreReason::Terminal
            }
        ));
        assert_eq!(context, before);

        // (c) MAX_ROUND timeout
        let state = ConsensusState {
            round: RoundState::new(0, MAX_ROUND),
            finality: FinalityState::default(),
        };
        let mut context = IntegrationContext::new(0, MAX_ROUND);
        let before = context.clone();
        let r = transition(
            &state,
            ConsensusEvent::RoundTimeout,
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        );
        assert!(matches!(
            r,
            TransitionResult::Rejected {
                reason: RejectReason::RoundOverflow
            }
        ));
        assert_eq!(context, before);
    }

    // ---- T19：Frozen QC construction（transition 输出 == 直接 assemble）----
    #[test]
    fn t19_frozen_qc_construction() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        let mut state = state0();
        let mut context = IntegrationContext::new(0, 0);
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s1;
        let (s2, _, _) = expect_applied(transition(
            &state,
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        state = s2;
        let (_, o, d) = expect_applied(transition(
            &state,
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert!(o.prevote_quorum);
        let expected = context
            .round_evidence
            .assemble_qc(CHAIN_ID, &GENESIS_HASH, TARGET, VoteType::Prevote, 0, 0)
            .expect("assemble");
        assert_eq!(
            d.prevote_qc,
            Some(expected),
            "transition 只组装冻结结构（MF-8）"
        );
    }

    // ---- T20：QC Identity Completeness（encode_qc 全字段 injective）----
    #[test]
    fn t20_qc_identity_completeness() {
        let ctx = test_ctx(2, 100);
        let base = make_qc_typed(&ctx, &[0, 1], TARGET, 1, 0, VoteType::Precommit, ZERO, 100);
        let id = qc_identity(&base);

        let mut m = base.clone();
        m.context.chain_id += 1;
        assert_ne!(qc_identity(&m), id, "chain_id");
        let mut m = base.clone();
        m.context.height = 7;
        assert_ne!(qc_identity(&m), id, "height");
        let mut m = base.clone();
        m.context.round = 9;
        assert_ne!(qc_identity(&m), id, "round");
        let mut m = base.clone();
        m.context.vote_type = VoteType::Prevote;
        assert_ne!(qc_identity(&m), id, "vote_type");
        let mut m = base.clone();
        m.target = [0x0B; 32];
        assert_ne!(qc_identity(&m), id, "target");
        let mut m = base.clone();
        m.validator_set_id = [0x99; 32];
        assert_ne!(qc_identity(&m), id, "validator_set_id");
        let mut m = base.clone();
        m.evidence[0].validator_id = ValidatorId::from_bytes([0xEE; 32]);
        assert_ne!(qc_identity(&m), id, "evidence.validator_id");
        let mut m = base.clone();
        m.evidence[0].source_block_hash = [0x77; 32];
        assert_ne!(qc_identity(&m), id, "evidence.source_block_hash");
        let mut m = base.clone();
        m.evidence[0].timestamp += 1;
        assert_ne!(qc_identity(&m), id, "evidence.timestamp");
        let mut m = base.clone();
        m.evidence[0].signature[0] ^= 1;
        assert_ne!(qc_identity(&m), id, "evidence.signature");
    }

    // ---- T21：Registry adversarial（混合 Prevote/Precommit + permutation）----
    #[test]
    fn t21_registry_adversarial_mixed_types() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();

        // 顺序 A：v0 prevote → v1 prevote → v0 precommit → v1 precommit
        let mut s_a = state0();
        let mut c_a = IntegrationContext::new(0, 0);
        let seq_a: Vec<ConsensusEvent> = vec![
            propose_event(&ctx),
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            vote_event(&ctx, 0, VoteType::Precommit, 200),
            vote_event(&ctx, 1, VoteType::Precommit, 200),
        ];
        for ev in &seq_a {
            let r = transition(
                &s_a,
                ev.clone(),
                &mut c_a,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            if let TransitionResult::Applied { next_state, .. } = r {
                s_a = next_state;
            }
        }

        // 顺序 B：v1 prevote → v0 prevote → v1 precommit → v0 precommit（reverse）
        let mut s_b = state0();
        let mut c_b = IntegrationContext::new(0, 0);
        let seq_b: Vec<ConsensusEvent> = vec![
            propose_event(&ctx),
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            vote_event(&ctx, 1, VoteType::Precommit, 200),
            vote_event(&ctx, 0, VoteType::Precommit, 200),
        ];
        for ev in &seq_b {
            let r = transition(
                &s_b,
                ev.clone(),
                &mut c_b,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            if let TransitionResult::Applied { next_state, .. } = r {
                s_b = next_state;
            }
        }

        // 两种顺序：state 等价 + context（registry + evidence）等价（MF-12/MF-9）
        assert!(state_eq(&s_a, &s_b), "混合顺序 state 等价");
        assert_eq!(c_a, c_b, "混合顺序 context 等价");
        // registry 只含 PrevoteQC
        let qcs = c_a.qc_registry.prevote_qcs();
        assert!(!qcs.is_empty());
        assert!(
            qcs.iter().all(|q| q.context.vote_type == VoteType::Prevote),
            "registry 只含 PrevoteQC"
        );
        // PrecommitQC 不入 registry：registry 只含 1 个 prevote QC（precommit 未进）
        assert_eq!(
            c_a.qc_registry.len(),
            1,
            "PrecommitQC 不进入 registry（§3.0）"
        );
        // Finality 只消费对应 PrecommitQC（不经 registry）
        assert_eq!(s_a.finality.finalized_reference, Some(TARGET));
    }

    // ---- T22：MF-10 截断安全（finalized ∈ DAG ⇒ registry 截断不改变 head）----
    #[test]
    fn t22_truncation_safety() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        // 构造"极端超 N"的 full_qcs（canonical 截断到 N）
        let full_qcs: Vec<QuorumCertificate> = (0..(MAX_QC_REGISTRY_ENTRIES + 10))
            .map(|i| {
                make_qc_typed(
                    &ctx,
                    &[0, 1, 2],
                    TARGET,
                    i as u64,
                    0,
                    VoteType::Prevote,
                    ZERO,
                    i as u64,
                )
            })
            .collect();

        // S2：finalized ∈ DAG ⇒ FC-12 绝对短路，head == finalized，与 registry 内容无关。
        let empty: Vec<QuorumCertificate> = Vec::new();
        assert_eq!(
            fork_choice(&dag, Some(&TARGET), &empty, &ctx.set, &GENESIS_HASH),
            Some(TARGET),
            "空 registry ⇒ head == finalized（FC-12）"
        );
        assert_eq!(
            fork_choice(&dag, Some(&TARGET), &full_qcs, &ctx.set, &GENESIS_HASH),
            Some(TARGET),
            "registry 截断不改变已 final head（MF-10 S2）"
        );

        // 集成路径：state 已 final 到 A，registry 塞满，Vote transition 的 head 仍 == A。
        let state = ConsensusState {
            round: RoundState::new(1, 0),
            finality: FinalityState {
                finalized_reference: Some(TARGET),
                highest_precommit_qc: None,
            },
        };
        let mut context = IntegrationContext::new(1, 0);
        for qc in &full_qcs {
            context.qc_registry.admit(qc.clone());
        }
        assert_eq!(context.qc_registry.len(), MAX_QC_REGISTRY_ENTRIES);
        let (s1, _, _) = expect_applied(transition(
            &state,
            propose_event(&ctx),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        // prevote vote（height=1）触发 Vote 路径的 fork_choice 计算（同 snapshot）
        let (_, _, d) = expect_applied(transition(
            &s1,
            vote_event_at(&ctx, 0, VoteType::Prevote, 100, 1),
            &mut context,
            CHAIN_ID,
            &ctx.set,
            &GENESIS_HASH,
            &dag,
        ));
        assert_eq!(
            d.fork_choice_head,
            Some(TARGET),
            "集成：registry 满仍 head == finalized（MF-10 S2）"
        );
    }

    // ---- T23：Context Determinism / Replay（不同 insertion order ⇒ 相同结果）----
    #[test]
    fn t23_context_determinism_replay() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();

        // logical history：propose + prevote v0 + prevote v1（两种提交顺序）
        let mut s1 = state0();
        let mut c1 = IntegrationContext::new(0, 0);
        let seq1 = vec![
            propose_event(&ctx),
            vote_event(&ctx, 0, VoteType::Prevote, 100),
            vote_event(&ctx, 1, VoteType::Prevote, 100),
        ];
        let mut derived1 = Vec::new();
        for ev in &seq1 {
            let r = transition(
                &s1,
                ev.clone(),
                &mut c1,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            if let TransitionResult::Applied {
                next_state,
                derived,
                ..
            } = r
            {
                s1 = next_state;
                derived1.push(derived);
            }
        }

        let mut s2 = state0();
        let mut c2 = IntegrationContext::new(0, 0);
        let seq2 = vec![
            propose_event(&ctx),
            vote_event(&ctx, 1, VoteType::Prevote, 100),
            vote_event(&ctx, 0, VoteType::Prevote, 100),
        ];
        let mut derived2 = Vec::new();
        for ev in &seq2 {
            let r = transition(
                &s2,
                ev.clone(),
                &mut c2,
                CHAIN_ID,
                &ctx.set,
                &GENESIS_HASH,
                &dag,
            );
            if let TransitionResult::Applied {
                next_state,
                derived,
                ..
            } = r
            {
                s2 = next_state;
                derived2.push(derived);
            }
        }

        assert!(state_eq(&s1, &s2), "T23 state 等价");
        assert_eq!(
            c1, c2,
            "T23 context 等价（QcRegistry + RoundEvidence 一致）"
        );
        // 最终 derived：两种顺序的最后一个 prevote_qc 一致
        let final_qc1 = derived1.last().and_then(|d| d.prevote_qc.clone());
        let final_qc2 = derived2.last().and_then(|d| d.prevote_qc.clone());
        assert_eq!(final_qc1, final_qc2, "T23 derived QC 一致");
    }
}
