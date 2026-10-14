//! NodeRuntime —— 生产节点生命周期装配层（STEP 10-16；Phase 1 骨架）。
//!
//! # 职责（仅装配 / 生命周期；不实现共识算法）
//! 固定启动顺序：`Config → Genesis → ChainIdentity 校验 → chain storage →（validator mode）
//! KeyProvider → derive ValidatorId → SafetyStore open → strict recover → ValidatorActor →
//! ConsensusNode → NodeConsensusDriver`（STEP 10-18I-C：Runtime 经 [`crate::driver::NodeConsensusDriver`]
//! 持有 ConsensusNode + ValidatorActor）。Stage C（STEP 10-18I-G）：Network / EventLoop /
//! NetworkIdentity 以可选 `NetworkStack` 装配（`start` = 网络 disabled；`start_with_network` = 启用）。
//!
//! # 边界
//! - [`NodeRuntime`] **拥有生命周期**（组件创建顺序 / 注入），但：
//!   - 不持有共识状态（`ConsensusNode` 是 canonical 状态 owner，Runtime 只持 handle 引用层）；
//!   - 不改变 `ConsensusState` / 共识算法 / DAG / finality / fork choice；
//!   - 不替代 [`crate::validator::ValidatorActor`]（安全逻辑仍在 actor 内）；
//!   - **不存储私钥 / vote history / SafetyRecord**（私钥在 SigningCapability 边界内；
//!     vote history 在 ValidatorSafetyStore / actor ledger）。
//! - chain storage（`config.storage_dir`）与 validator safety storage（`config.safety_dir`）
//!   **目录分离**，绝不混用；SafetyStore recover 失败 = validator mode 启动失败（fail closed）。
//! - **G5-D.7.2（missing-journal fail closed）**：`safety.journal` 缺失时**不**隐式初始化 ——
//!   未声明 `validator_safety_init` ⇒ [`NodeRuntimeError::SafetyJournalMissing`]（启动失败）；
//!   已声明 ⇒ 显式 `create_new`（已存在则 [`NodeRuntimeError::SafetyJournalAlreadyExists`]）。
//! - full-node（`validator_enabled=false`）：跳过 key / safety / validator，不触碰 Provider。

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nova_consensus::dag::Dag;
use nova_consensus::finality::{FinalityError, QuorumCertificate};
use nova_consensus::integration::{ConsensusState, TransitionResult};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep, RoundTimeoutConfig};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
// PHASE 6H-Z（Owner D1-1 = D1-B）— O2 入站 `RoundChangeCertificate` 权威路径（仅 decode +
// 有界暂存存储；验证 / 适用性 / 应用均在 `round_change_inbound` 的冻结委托路径中）。
use nova_consensus::round_change::{
    AdmitOutcome, RoundChangeCertificate, RoundChangeError, RoundChangeEvidence, RoundChangeStore,
    decode_certificate,
};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_network::event_loop::{EventLoop, EventLoopConfig, EventLoopError};
use nova_network::message::{MessageEnvelope, MessageType};
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceError};
use nova_network::node_id::NodeId;
// PHASE 6H-AF：ADR-0074（FROZEN）canonical attestation container（精确 112B）。
use nova_network::abandon_attestation::{
    ABANDON_ATTESTATION_LEN, AbandonAttestation, decode as decode_abandon_attestation,
};
use nova_network::security::{NetworkSecurityError, random_request_id};
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, SessionError, handshake_payload_encode, random_session_nonce,
};
use nova_network::sync::SyncBlockResponse;
use nova_network::transport::{BoxTransport, ConnectionTarget, TcpDialer, Transport};
use nova_storage::error::StorageError;
use nova_storage::persistent::PersistentBackend;

use crate::assembly::{AdoptionOutcome, ConsensusNode};
use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter, NodeBlockApplicationError};
use crate::block_dispatch::{
    dispatch_gossip_block_round_aware, dispatch_sync_block_response_round_aware,
    resolve_expected_proposer_vk_at, resolve_inbound_block_round,
    resolve_proposer_round_evidence, resolve_proposer_round_from_evidences, wire_block_hash,
};
use crate::block_inbound::{InboundBlockError, InboundBlockVerdict};
use crate::block_safety::{BlockSafetyError, BlockSafetyIdentity, BlockSafetyJournal};
use crate::bootstrap::{self, ConnectionTargetError, NodeConfig, NodeStartupError};
use crate::driver::{DriverError, NodeConsensusDriver};
use crate::inbound::{
    InboundDiagnostics, InboundDropReason, InboundListenerError, InboundListenerState,
    InboundMultiplexTransport, peer_key,
};
use crate::intent_ledger::{
    BlockInboundSource, MissingAncestorIntent, MissingAncestorIntentLedger,
};
use crate::key_provider::{KeyProvider, KeyProviderError};
use crate::network_identity::{NetworkSigner, NetworkSigningError};
use crate::outbound::OutboundConsensusMessage;
use crate::proposer::{ProposalBuild, ProposerError, build_proposal};
use crate::qc_history::{QcHistory, QcHistoryError};
use crate::round_change_inbound::{RoundChangeApplication, apply_verified_round_change};
use crate::round_change_pool::{LocalExpireObservation, PoolOutcome, RoundChangeAttestationPool};
use crate::safety_store::{SafetyIdentity, ValidatorSafetyError, ValidatorSafetyStore};
use crate::signer::SigningCapability;
use crate::sync_correlator::{LogicalTick, SyncRequestCorrelator, SyncRequestTarget};
use crate::sync_dispatch::{NetworkSyncDispatcher, dispatch_batch};
use crate::sync_responder::{SyncRespondDiagnostics, serve_requests as serve_sync_requests};
use crate::sync_scheduler::{
    PeerCandidate, PeerSelectionPolicy, ScheduleResult, SyncRequestIntent, SyncRequestScheduler,
    select_peer,
};
use crate::validator::{ValidatorActor, ValidatorActorError};
use crate::wiring::{
    BlockInboundMessage, NodeConsensusCommand, NodeConsensusHandler, process_command,
};

/// ValidatorActor 的签名能力类型（Phase 1：trait object）。
type DynSigner = Box<dyn SigningCapability>;

/// block inbound 观测队列有界容量（Node-local；满则丢最早 —— 不累积无限历史）。
const BLOCK_INBOUND_OUTCOME_CAP: usize = 128;

/// missing-ancestor intent ledger 有界容量（Node-local；满 ⇒ FIFO evict —— 不无限增长）。
const MISSING_ANCESTOR_LEDGER_CAP: usize = 256;

/// outbound sync request scheduler 有界容量（D8-2；满 ⇒ 丢弃多余 intent —— bounded）。
const SYNC_SCHEDULER_CAP: usize = 64;

/// outbound sync request correlator 有界容量（D8-2；满 ⇒ register Full 拒 —— bounded）。
const SYNC_CORRELATOR_CAP: usize = 64;

/// 每 step 从 ledger 调度入 scheduler 的最大 intent 数（bounded；防每 step 无限发送）。
const SYNC_SCHEDULE_MAX_PER_STEP: usize = 8;

/// 每 step 从 scheduler 出队并 register/dispatch 的最大条数（bounded dispatch）。
const SYNC_DISPATCH_MAX_PER_STEP: usize = 8;

/// register 用 deadline horizon（D8-3-1：expire release-only —— 悬挂 request 在该 step 数后
/// 被 `expire_at` 释放；无 retry / 无 backoff；correlator capacity 即有界）。
const SYNC_DEADLINE_HORIZON: u64 = 64;

/// B2-C2 —— Trigger #3（低频 proactive catch-up probe）间隔（逻辑 tick；Owner 已批准 Option C′）。
///
/// 与 `SYNC_DEADLINE_HORIZON`（=64）**对齐**：一个无响应 request（对端 behind ⇒ responder
/// `Missing` ⇒ 静默不响应）或未 resolve 的 request 最迟在 64 tick 被 `expire_at` 释放；
/// probe 间隔 ≥ deadline horizon ⇒ **同一高度不会在前一个 request 尚未自然释放前被反复探测**
/// （无 tight loop / 无 retry storm）。复用既有 step-driven `sync_tick` ⇒ **零新增状态**
/// （无 `last_probe_tick` / `last_probe_height` / `last_probe_peer` / backoff / 持久化）。
const SYNC_PROBE_INTERVAL: u64 = 64;

/// P1-A.17 —— catch-up 驱动：每步最多补记的「head+1 追赶 intent」条数（bounded = 1/步）。
///
/// 仅当**无 in-flight 同步请求**时补记 ⇒ 自然退化为「单次串行追赶」：每步至多 1 个请求，
/// 无 retry storm / 无重复请求风暴 / 无新状态。
const SYNC_CATCHUP_INTENTS_PER_STEP: usize = 1;

/// P1-A.7 — 入站 QC 的**有界** pending 缓冲上限（ADR-0064）。
///
/// 当入站 QC 的 `target` 当前不在本节点 DAG（既有 `UnknownTarget` = **不适用**）时，把该 QC
/// 暂存至多 8 条（dedup key = `qc.target`；满 ⇒ FIFO 逐出最旧），等对应 block 落 DAG/
/// BlockStore 后再做**采纳前置检查**。无无界增长 / 无 retry storm / 无阻塞等待。
const PENDING_EXTERNAL_QC_CAP: usize = 8;

/// P1-A.7 — 每 step 最多尝试采纳的外部 QC 数（bounded work；其余留待下一 step）。
const EXTERNAL_QC_ADOPT_MAX_PER_STEP: usize = 2;

// ---------------------------------------------------------------------------
// PHASE 6H-A11 U1 — Bounded Pending Proposal Store（ADR-0076 PADR-5.2 / PADR-5.3）
// ---------------------------------------------------------------------------
//
// 授权：PHASE 6H-A11-IMPLEMENT-AUTHORIZATION（OD-C1 = A / OD-C3 / OD-C5）。
// 本单元（U1）**仅**实现容器基础设施：容量 / 去重 / 到期（确定性 tick）/ 计数。
// **不含** admission guard、**不含** recovery checkpoint（归 U2 / U3）⇒ 本单元
// **不改变任何共识流程**（零共识状态变更 / 无 progress / 无 RESET 影响）。

/// PHASE 6H-A11 U1 — pending proposal 有界容量（ADR-0076 PADR-5.2；OD-21 冻结）。
///
/// 满 ⇒ **FIFO deterministic** 淘汰最旧 + `evicted` 计数；**MUST NOT 无限缓存**。
/// 容量是内存有界性的最终保证（独立于到期机制）。
pub const MAX_PENDING_PROPOSALS: usize = 64;

/// PHASE 6H-A11 U1 — 到期换算因子（ADR-0076 `MAX_PENDING_TICKS = 2 rounds`；OD-C3 冻结）。
///
/// `expiry_tick = arrival_tick + 2 * round_timeout_window_ticks(config, arrival_round)`（饱和算术）。
///
/// **A3 变更告知（行为影响已评估）**：`round_timeout_window_ticks` 返回的仍是
/// `RoundTimeoutConfig` 的**数值**，而 A3 把该配置的默认单位从「逻辑 step tick」
/// （1000 / 60_000）改为**毫秒**（10_000 / 120_000）⇒ 该函数返回值随之变大，
/// 因此 pending 提案在**步数**上的保留期也等比变长（round 0：2 × 10_000 步，饱和）。
/// 评估：这不改变任何共识判定（pending 仅缓存 incoming proposal），且内存有界性仍由
/// [`MAX_PENDING_PROPOSALS`]（FIFO 淘汰）**硬保证**；A3 授权范围仅覆盖 round-timeout
/// 计时器，故此处**不**重设计 pending 到期模型（保持冻结公式），仅记录该后果。
pub const PENDING_EXPIRY_ROUNDS: u64 = 2;

/// PHASE 6H-A11 U1 — 每次 sweep 的**固定**检查上界（OD-C3 附加冻结 2：禁止非确定性扫描）。
pub const PENDING_SWEEP_MAX_PER_STEP: usize = 64;

/// PHASE 6H-A11 U1 — 计算 pending 条目到期 tick（确定性；无 wall clock / 无新增 timer）。
///
/// 语义（OD-C3）：
/// - 使用**既有**逻辑 step tick 与**既有**冻结函数 [`round_timeout_window_ticks`]；
/// - 全程 `saturating_*`（**饱和/有界**）：不 panic / 不环绕；极端取值下 `expiry_tick` 可能
///   大到实际不可达 —— 此时内存有界性仍由 [`MAX_PENDING_PROPOSALS`] 保证（FIFO 淘汰）。
pub fn pending_expiry_tick(
    config: &RoundTimeoutConfig,
    arrival_tick: u64,
    arrival_round: u64,
) -> u64 {
    let window = round_timeout_window_ticks(config, arrival_round);
    arrival_tick.saturating_add(window.saturating_mul(PENDING_EXPIRY_ROUNDS))
}

/// PHASE 6H-A11 U1 — 单个 pending 提案条目（binding metadata；**不**参与任何共识状态）。
///
/// `arrival_round` 的冻结用法（OD-C2）：**仅**作为 proposal-bound 证据输入
/// （`resolve_proposer_round_evidence` 的 `proposal` 参数）；**不得**当作 `round_now`、
/// **不得**覆盖 proposer evidence、**不得**修改 consensus round / finality / QC / lock。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProposal {
    /// 原始提案引用（`block_hash` + `proposer`）。
    pub proposal_ref: ProposalRef,
    /// 去重键（= `proposal_ref.block_hash`；显式保存以便 O(1) 比较/检索）。
    pub block_hash: [u8; 32],
    /// 到达时的共识高度（父高轮语义；**仅**元数据）。
    pub arrival_height: u64,
    /// 到达时的本地共识轮（**仅** binding metadata；OD-C2）。
    pub arrival_round: u64,
    /// 到达时的确定性 tick（逻辑 step 计数；无墙钟）。
    pub received_tick: u64,
    /// 到期 tick（[`pending_expiry_tick`] 结果；饱和）。
    pub expiry_tick: u64,
}

/// PHASE 6H-A11 U1 — [`PendingProposalStore::insert`] 结果（确定性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingInsertOutcome {
    /// 已插入（可能伴随一次 FIFO 容量淘汰，见 [`PendingProposalStore::evicted_count`]）。
    Inserted,
    /// 同 `block_hash` 已存在 ⇒ **不**产生第二条目（幂等）。
    Duplicate,
}

/// PHASE 6H-A11 DIAG — Guard 拒绝原因（**仅观测**；不参与任何判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardReject {
    /// 无 canonical adapter / 无 block store。
    NoStore,
    /// 存储读取错误（fail-closed）。
    StorageError,
    /// 区块尚未本地可用（Guard A1）。
    MissingBlock,
    /// Guard A2：父高轮上下文不匹配。
    HeightContext,
    /// `block.header.height == 0`（无父高轮）。
    HeightUnderflow,
    /// Guard C：绑定证据不可用 / 矛盾（resolver `Err`）。
    Evidence,
    /// Guard C：期望 proposer 推导失败（空集 / 非成员 / 非法公钥）。
    Proposer,
    /// Guard C：签名验证失败（含零签名）。
    Signature,
}

/// PHASE 6H-A11 U1 — **有界** pending proposal 存储（Node-local；**不**持有共识状态）。
///
/// 不变量：
/// - `entries.len() <= `[`MAX_PENDING_PROPOSALS`]（FIFO 淘汰保证）；
/// - 同一 `block_hash` 至多一条；
/// - 所有方法**零**共识状态变更（本类型无法访问 `ConsensusState`）。
#[derive(Debug)]
pub struct PendingProposalStore {
    entries: VecDeque<PendingProposal>,
    admitted: u64,
    rejected: u64,
    expired: u64,
    evicted: u64,
    /// PHASE 6H-A11 DIAG — 首次入 pending 次数（**仅观测**）。
    pended: u64,
    /// PHASE 6H-A11 DIAG — 按 [`GuardReject`] 分类的拒绝次数（**仅观测**）。
    guard_rejects: [u64; 8],
}

impl PendingProposalStore {
    /// 空存储。
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            admitted: 0,
            rejected: 0,
            expired: 0,
            evicted: 0,
            pended: 0,
            guard_rejects: [0; 8],
        }
    }

    /// 当前条目数（≤ [`MAX_PENDING_PROPOSALS`]）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否已存在该 `block_hash`（去重键）。
    pub fn contains(&self, block_hash: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| &e.block_hash == block_hash)
    }

    /// 只读取回条目（U3 recovery 读取证据用；不消费）。
    pub fn get(&self, block_hash: &[u8; 32]) -> Option<&PendingProposal> {
        self.entries.iter().find(|e| &e.block_hash == block_hash)
    }

    /// 插入（去重 + 容量 FIFO 淘汰）；**不**触碰共识状态。
    pub fn insert(&mut self, entry: PendingProposal) -> PendingInsertOutcome {
        if self.contains(&entry.block_hash) {
            return PendingInsertOutcome::Duplicate;
        }
        if self.entries.len() >= MAX_PENDING_PROPOSALS {
            let _ = self.entries.pop_front();
            self.evicted = self.evicted.saturating_add(1);
        }
        self.entries.push_back(entry);
        PendingInsertOutcome::Inserted
    }

    /// 消费（移除并返回）指定条目（U3 准入/拒绝后调用）。
    pub fn remove(&mut self, block_hash: &[u8; 32]) -> Option<PendingProposal> {
        let idx = self
            .entries
            .iter()
            .position(|e| &e.block_hash == block_hash)?;
        self.entries.remove(idx)
    }

    /// 到期 sweep：仅检查**队首起最多 `max_checks` 条**（固定上界 ⇒ 确定性），移除其中
    /// `now_tick >= expiry_tick` 的条目；返回移除数。**不**改变共识状态。
    ///
    /// 注意（MUST）：`expiry_tick` 在插入序上**不保证单调**（窗口随 round 变化；高度推进后
    /// round 可回落到 0 ⇒ 窗口变小）⇒ **必须**在固定上界内全量检查该窗口，**MUST NOT** 见到
    /// 首个未到期条目就提前终止。
    pub fn sweep_expired(&mut self, now_tick: u64, max_checks: usize) -> usize {
        let bound = max_checks.min(self.entries.len());
        let mut kept: VecDeque<PendingProposal> =
            VecDeque::with_capacity(self.entries.len().saturating_sub(bound));
        let mut removed = 0usize;
        for _ in 0..bound {
            match self.entries.pop_front() {
                Some(e) if now_tick >= e.expiry_tick => removed += 1,
                Some(e) => kept.push_back(e),
                None => break,
            }
        }
        // 保留原相对顺序：先放回已检查且未到期的，再追加未检查的尾部。
        kept.append(&mut self.entries);
        self.entries = kept;
        if removed > 0 {
            self.expired = self.expired.saturating_add(removed as u64);
        }
        removed
    }

    /// PHASE 6H-A11 U3 — 有界证据快照：至多 `max` 条 `(block_hash, arrival_round)`。
    ///
    /// 供 recovery checkpoint 在**无借用冲突**下遍历（`remove` 需 `&mut self`）；
    /// 固定上界 ⇒ 确定性、**无**无界扫描。`arrival_round` 仅作 proposal-bound 证据输入（OD-C2）。
    pub fn evidence_bounded(&self, max: usize) -> Vec<([u8; 32], u64)> {
        self.entries
            .iter()
            .take(max)
            .map(|e| (e.block_hash, e.arrival_round))
            .collect()
    }

    /// 准入成功次数（U2/U3 起自增；确定性诊断计数）。
    pub fn admitted_count(&self) -> u64 {
        self.admitted
    }

    /// 准入拒绝次数（U2/U3 起自增；确定性诊断计数）。
    pub fn rejected_count(&self) -> u64 {
        self.rejected
    }

    /// 到期淘汰次数。
    pub fn expired_count(&self) -> u64 {
        self.expired
    }

    /// 容量（FIFO）淘汰次数。
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// 记录一次**成功准入**（由 U2/U3 调用；本单元仅提供计数槽位）。
    pub fn note_admitted(&mut self) {
        self.admitted = self.admitted.saturating_add(1);
    }

    /// 记录一次**准入拒绝**（由 U2/U3 调用）。
    pub fn note_rejected(&mut self) {
        self.rejected = self.rejected.saturating_add(1);
    }

    /// PHASE 6H-A11 DIAG — 记录一次**首次入 pending**（**仅观测**）。
    pub fn note_pended(&mut self) {
        self.pended = self.pended.saturating_add(1);
    }

    /// PHASE 6H-A11 DIAG — 按原因记一次拒绝（同时计入总数；**仅观测**）。
    pub fn note_guard_reject(&mut self, reason: GuardReject) {
        self.rejected = self.rejected.saturating_add(1);
        let idx = reason as usize;
        if let Some(slot) = self.guard_rejects.get_mut(idx) {
            *slot = slot.saturating_add(1);
        }
    }

    /// PHASE 6H-A11 DIAG — 首次入 pending 次数（**仅观测**）。
    pub fn pended_count(&self) -> u64 {
        self.pended
    }

    /// PHASE 6H-A11 DIAG — 指定原因的拒绝次数（**仅观测**）。
    pub fn guard_reject_count(&self, reason: GuardReject) -> u64 {
        self.guard_rejects
            .get(reason as usize)
            .copied()
            .unwrap_or(0)
    }

    /// P1-A.30 **D0** — 全部 8 类拒绝计数（**仅观测**；顺序 = `GuardReject` 判别值：
    /// `[NoStore, StorageError, MissingBlock, HeightContext, HeightUnderflow, Evidence, Proposer,
    /// Signature]`）。
    ///
    /// 与 [`Self::guard_reject_count`] **同一数据源**（无第二套计数）；数组之和 == [`Self::rejected_count`]。
    pub fn guard_reject_counts(&self) -> [u64; 8] {
        let mut out = [0u64; 8];
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = self.guard_rejects.get(idx).copied().unwrap_or(0);
        }
        out
    }
}

impl Default for PendingProposalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod pending_proposal_tests {
    use super::*;

    fn pref(byte: u8) -> ProposalRef {
        ProposalRef {
            block_hash: [byte; 32],
            proposer: ValidatorId::from_consensus_public_key(&[byte; 32]),
        }
    }

    fn entry(byte: u8, tick: u64, round: u64) -> PendingProposal {
        let config = RoundTimeoutConfig::default();
        PendingProposal {
            proposal_ref: pref(byte),
            block_hash: [byte; 32],
            arrival_height: round.saturating_add(1),
            arrival_round: round,
            received_tick: tick,
            expiry_tick: pending_expiry_tick(&config, tick, round),
        }
    }

    #[test]
    fn u1_insert_contains_get_remove_roundtrip() {
        let mut store = PendingProposalStore::new();
        assert!(store.is_empty());
        assert_eq!(
            store.insert(entry(0x11, 10, 0)),
            PendingInsertOutcome::Inserted
        );
        assert_eq!(store.len(), 1);
        assert!(store.contains(&[0x11; 32]));
        let got = store.get(&[0x11; 32]).expect("entry present");
        assert_eq!(got.block_hash, [0x11; 32]);
        assert_eq!(got.arrival_round, 0);
        assert_eq!(got.arrival_height, 1);
        assert_eq!(got.received_tick, 10);
        let removed = store.remove(&[0x11; 32]).expect("removed");
        assert_eq!(removed.proposal_ref.block_hash, [0x11; 32]);
        assert!(store.is_empty());
        assert!(store.remove(&[0x11; 32]).is_none());
    }

    #[test]
    fn u1_duplicate_block_hash_is_rejected() {
        let mut store = PendingProposalStore::new();
        assert_eq!(
            store.insert(entry(0x22, 10, 0)),
            PendingInsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(entry(0x22, 20, 3)),
            PendingInsertOutcome::Duplicate
        );
        assert_eq!(store.len(), 1);
        // 元数据保持首次值（不被后续重复插入覆盖）。
        assert_eq!(store.get(&[0x22; 32]).expect("entry").received_tick, 10);
    }

    #[test]
    fn u1_capacity_is_64_and_evicts_oldest_fifo() {
        assert_eq!(MAX_PENDING_PROPOSALS, 64);
        let mut store = PendingProposalStore::new();
        for i in 0..65u8 {
            assert_eq!(
                store.insert(entry(i, 100, 0)),
                PendingInsertOutcome::Inserted
            );
        }
        assert_eq!(store.len(), MAX_PENDING_PROPOSALS);
        assert_eq!(store.evicted_count(), 1);
        assert!(!store.contains(&[0u8; 32]), "最旧条目应被 FIFO 淘汰");
        assert!(store.contains(&[64u8; 32]), "最新条目应在");
    }

    #[test]
    fn u1_expiry_mapping_is_two_round_windows() {
        let config = RoundTimeoutConfig::default();
        // 冻结映射（OD-C3）：round 0 ⇒ +2×10_000；round 1 ⇒ +2×20_000（A3 默认基线单位 = 毫秒）。
        assert_eq!(pending_expiry_tick(&config, 100, 0), 20_100);
        assert_eq!(pending_expiry_tick(&config, 100, 1), 40_100);
    }

    #[test]
    fn u1_sweep_removes_expired_not_only_head() {
        // 非单调 expiry（窗口随 round 变化）：A（round 5）晚到期（241_000），B（round 0）先到期（21_000）。
        let mut store = PendingProposalStore::new();
        assert_eq!(
            store.insert(entry(0xA1, 1_000, 5)),
            PendingInsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(entry(0xB2, 1_000, 0)),
            PendingInsertOutcome::Inserted
        );
        let removed = store.sweep_expired(30_000, PENDING_SWEEP_MAX_PER_STEP);
        assert_eq!(removed, 1, "只应淘汰已到期条目");
        assert!(store.contains(&[0xA1; 32]), "未到期条目必须保留");
        assert!(!store.contains(&[0xB2; 32]), "已到期条目必须淘汰");
        assert_eq!(store.expired_count(), 1);
    }

    #[test]
    fn u1_sweep_respects_fixed_bound() {
        let mut store = PendingProposalStore::new();
        for i in 0..3u8 {
            assert_eq!(
                store.insert(entry(i, 10, 0)),
                PendingInsertOutcome::Inserted
            );
        }
        let removed = store.sweep_expired(1_000_000, 1);
        assert_eq!(removed, 1, "每次 sweep 至多检查/移除 1 条");
        assert_eq!(store.len(), 2);
        assert_eq!(store.expired_count(), 1);
    }

    #[test]
    fn u1_saturation_never_panics_and_capacity_still_bounds() {
        let config = RoundTimeoutConfig::default();
        assert_eq!(pending_expiry_tick(&config, u64::MAX, 0), u64::MAX);
        let mut store = PendingProposalStore::new();
        let mut e = entry(0xC3, u64::MAX, 0);
        assert_eq!(e.expiry_tick, u64::MAX);
        e.proposal_ref = pref(0xC3);
        assert_eq!(store.insert(e), PendingInsertOutcome::Inserted);
        assert_eq!(
            store.sweep_expired(u64::MAX - 1, PENDING_SWEEP_MAX_PER_STEP),
            0
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn u1_diagnostic_counters_are_deterministic_slots() {
        let mut store = PendingProposalStore::new();
        assert_eq!(store.admitted_count(), 0);
        assert_eq!(store.rejected_count(), 0);
        assert_eq!(store.expired_count(), 0);
        assert_eq!(store.evicted_count(), 0);
        store.note_admitted();
        store.note_rejected();
        assert_eq!(store.admitted_count(), 1);
        assert_eq!(store.rejected_count(), 1);
        assert!(store.is_empty(), "计数不改变容器内容");
    }
}

// ---------------------------------------------------------------------------
// P1-A.8 — Configured peer lifecycle / reconnect backoff（node-local；零新依赖）
// ---------------------------------------------------------------------------
//
// 目的：一个不可达（黑洞）configured peer **不得**每个 runtime round 都阻塞 `TcpTransport`
// 的 `connect_timeout`（2s）—— 否则 step 速率从 ~1000/s 塔到 ~0.5/s，直接放大 P1-A.6 的
// logical round-timeout 墙钟时长。
//
// 时钟：**逻辑 peer tick**（每次 `establish_configured_peers()` 入口 +1；无 Instant / 无墙钟 /
// 无 RNG）—— 与 P1-A.6 的 consensus round timer **完全独立**（不互读写）。

/// 退避基准（逻辑 tick）：首次失败 ⇒ `delay(1) = 2`。
const BASE_BACKOFF_TICKS: u64 = 2;
/// 退避上限（逻辑 tick）：`delay(n ≥ 12) = 4096`（冻结公式的 bounded 上界）。
const MAX_BACKOFF_TICKS: u64 = 4096;
/// 失败计数饱和上限（u32）：达 12 后**不再增长**（对应 delay 饱和于 4096）。
const MAX_FAILURE_COUNT: u32 = 12;
/// 移位上限：`BASE << shift ≤ 2 << 11 = 4096 = MAX`（防位移溢出 / 防无界增长）。
const BACKOFF_SHIFT_CAP: u32 = MAX_FAILURE_COUNT - 1;
/// 每轮（每次 `establish_configured_peers()`）最多允许的 dial 次数（bounded work）。
const MAX_DIAL_ATTEMPTS_PER_CALL: usize = 1;

/// 网络 peer-auth 协议版本（与 `PeerAuthConfig.protocol_version` 一致；非 genesis 字段）。
const NETWORK_PROTOCOL_VERSION: u8 = 1;

/// D9 Step 7 — 入站连接握手 pending 超时（逻辑 step 数）。
///
/// 接受连接后若在 N 个 step 内既未 Established 也未失败 ⇒ 关闭连接 + `disconnect_peer`
/// （防未认证连接长期占用槽位）。逻辑 step 计数 = `NodeRuntime::inbound_tick`（每网络 step +1；
/// 无系统时钟依赖，确定性）。
const INBOUND_PENDING_TIMEOUT_STEPS: u64 = 1000;

/// P1-A.17-SYNC-STABILITY —— `RuntimeError::BlockStore` **来源标注**（取证专用观测）。
///
/// **语义完全不变**：返回的错误变体 / payload / 控制流与 `RuntimeError::BlockStore(e)` 逐字相同；
/// 仅在返回前向 **stderr** 追加一行 stage 标签（node 无日志/遥测依赖；stderr 由真实进程测试捕获）。
///
/// 目的：区分三个映射点（`local_proposal_put` / `finality_commit_get` / `remote_canonical_put`）
/// 与底层 `StorageError` 变体（`BackendFailure`（IO）/ `CorruptedState`（记录校验或 hash 不一致）/
/// `SerializationFailure`（编码））—— 这是「catch-up 中途 `Error: Run("BlockStore")`」定性的唯一
/// 可观测手段：bin 层 `run_fault_kind` 只输出类别名（不携底层细节）。
fn blockstore_stage(stage: &str, e: StorageError) -> RuntimeError {
    eprintln!("BlockStore stage={stage} err={e:?}");
    RuntimeError::BlockStore(e)
}

/// P1-A.18 RC-1 —— **proposal-bound** 轮证据（仅「父高轮 + 已接受 proposal」时给出）。
///
/// 语义：`(state.round.round, proposal.block_hash)`；`head_height` 必须等于 `round.height`
/// （`build_proposal` 的高度同步 gate ⇒ 产块轮高 = 父高 = head）。绑定键校验（块 hash 严格相等）
/// 由 `block_dispatch::resolve_proposer_round_evidence` 完成 —— 本函数**不**猜测、不筛选。
fn proposal_round_evidence(state: &ConsensusState, head_height: u64) -> Option<(u64, [u8; 32])> {
    if state.round.height != head_height {
        return None;
    }
    state
        .round
        .proposal
        .as_ref()
        .map(|p| (state.round.round, p.block_hash))
}

/// P1-A.18 RC-1 —— **QC-bound** 轮证据（本地 `last_precommit_qc()` ⇒ `(round, target)`）。
///
/// 绑定键 = `qc.target`；仅当其与待验证 / 待登记 / 待提交块 hash **严格相等**时才被使用（见
/// `block_dispatch::resolve_proposer_round_evidence`）。不新造规则 / 不引入新状态 / 无 wall clock。
fn last_precommit_round_evidence(node: &ConsensusNode) -> Option<(u64, [u8; 32])> {
    node.last_precommit_qc()
        .map(|qc| (qc.context.round, qc.target))
}

/// D10 Recovery C（Phase 1 / D-1）—— **三源**轮次证据统一处理（**复用**冻结
/// [`block_dispatch::resolve_proposer_round_evidence`]，不新造轮次规则、不引入新状态）。
///
/// 契约（与双源版本逐条一致）：
/// - 三源**均未**绑定 X ⇒ `Ok(None)` ⇒ 调用方 **defer**（**不以 round 0 兜底**）；
/// - 恰一源绑定 ⇒ 用其 round（**可为 0，合法**）；
/// - 多源绑定且轮不一致 ⇒ `Err(())` ⇒ 调用方 **defer**（不静默择一 / 不降级）。
///
/// 调用方已各自 `.filter(target == x)`（未绑定 ⇒ `None`）；本函数先把「本地 + 历史」交给既有
/// helper 做同一冲突判定，再与「恢复 fact QC」求交。
#[allow(clippy::result_unit_err)]
fn resolve_proposer_round_evidence_with_recovery(
    x: [u8; 32],
    local: Option<(u64, [u8; 32])>,
    history: Option<(u64, [u8; 32])>,
    restored: Option<(u64, [u8; 32])>,
) -> Result<Option<u64>, ()> {
    let a = resolve_proposer_round_evidence(x, local, history)?;
    let b = resolve_proposer_round_evidence(x, restored, None)?;
    let a_bound = local.is_some() || history.is_some();
    let b_bound = restored.is_some();
    match (a_bound, b_bound) {
        (false, false) => Ok(None),
        (true, false) => Ok(Some(a)),
        (false, true) => Ok(Some(b)),
        (true, true) => {
            if a == b {
                Ok(Some(a))
            } else {
                Err(())
            }
        }
    }
}

/// Node-local proposer step（STEP 10-19-6 OPT-1）：本节点为当前 proposer 时经真实 BlockBuilder
/// 产出 Block + ProposalRef → submit ProposalRef。
///
/// - 纯编排：`build_proposal` 只读判定 + build（真实 BlockHash；**非 placeholder**）；签名走
///   `ValidatorActor::sign_block`（不暴露私钥）；提交走 `driver.submit_proposal`。
/// - 高度同步 gate / 阶段守卫 / 幂等由 `build_proposal` 与 consensus 保证（非 proposer /
///   不同步 / 已提案 ⇒ `Ok(None)`，no-op）。
/// - 返回 `Some(ProposalBuild)`（本地保留 Block，**不持久化 / 不推进 head**）；无 adapter /
///   无 actor ⇒ `Ok(None)`。
///
/// **SAFETY-REJECT-SKIP（Owner 授权）** — 本地出块签名错误的**唯一**可恢复性判定点。
///
/// 语义（MUST）：
///
/// - 唯一可恢复情形 = `block_safety` F2/F3/F4 的**常态冲突拒绝**（`ConflictingTarget`）：
///   本地已为同一 `height` 签过**不同** target（`declared_round` 不是 slot 维度 ⇒ F3）⇒ 安全门
///   **正确地**拒签 ⇒ 本次提案必须被放弃（既不签名也不广播），但**不得**终止节点。
///   合法安全拒绝 ≠ 故障：把它当 fatal 会把安全性守卫变成 liveness 事故。
/// - 其余**全部**变体（journal I/O / 损坏 / 未恢复 / identity 失配 / 链或高失配 / 签名失败 /
///   自检失败 / 无 safety gate / double-vote / lock / abandon）⇒ **不可恢复**（保持 fatal）。
///
/// 本函数是**唯一**判定点：不得在别处 catch `RuntimeError::Validator`、不得按错误文本匹配。
fn is_recoverable_proposal_refusal(e: &ValidatorActorError) -> bool {
    matches!(
        e,
        ValidatorActorError::BlockSignSafety(BlockSafetyError::ConflictingTarget { .. })
    )
}

fn runtime_propose(
    driver: &mut NodeConsensusDriver<DynSigner>,
    block_production: &Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    timestamp: u64,
    live: &mut LivenessObservability,
) -> Result<Option<ProposalBuild>, RuntimeError> {
    // PHASE 6H-A30 OD-X7 — 只读观测：调用计数（**不**参与任何判定）。
    live.prop_calls = live.prop_calls.saturating_add(1);
    // G4（Owner 决策）—— **无 recovery hard guard**：恢复窗口内也照常出块。
    // 恒不 freeze 活性；finality 冲突保护仍由 frozen `check_finality_applicability`
    // （Conflict ⇒ 零状态变更）与既有 lock 语义承担。
    let Some(adapter) = block_production.as_ref() else {
        return Ok(None);
    };
    let Some(local_id) = driver.actor(0).map(|a| a.validator_id()) else {
        return Ok(None);
    };
    let proposal = build_proposal(local_id, driver.consensus(), adapter, timestamp)
        .map_err(RuntimeError::Proposer)?;
    let Some(mut pb) = proposal else {
        // PHASE 6H-A30 OD-X7 — 跳过原因**只读复算**（OD-X4 = A2；AC-4 残差法）。
        // 边界（MUST）：不改任何判定 / 不重试 / 不建第二套规则；不确定者一律归残差。
        {
            let rs = &driver.consensus().state().round;
            let (rs_step, rs_has_proposal, rs_height, rs_round) =
                (rs.step, rs.proposal.is_some(), rs.height, rs.round);
            let head_height = adapter.head().height;
            if rs_step != RoundStep::Propose || rs_has_proposal {
                live.prop_skip_step_guard = live.prop_skip_step_guard.saturating_add(1);
            } else if rs_height != head_height {
                live.prop_skip_height_desync = live.prop_skip_height_desync.saturating_add(1);
            } else {
                let set_id = driver.consensus().genesis_hash();
                let elected = select_proposer(
                    driver.consensus().chain_id(),
                    rs_height,
                    rs_round,
                    &set_id,
                    driver.consensus().validator_set(),
                );
                if matches!(elected, Ok(sel) if sel != local_id) {
                    live.prop_skip_not_elected = live.prop_skip_not_elected.saturating_add(1);
                }
                // 其余（含选择失败 / 未知原因）⇒ **残差**（`prop_skip_fail`），不猜测。
            }
        }
        return Ok(None);
    };
    // 出块签名（ValidatorActor 授权；signature ∉ block_hash —— hash 在签名前已定）。
    //
    // **SAFETY-REJECT-SKIP**：区分「**常态安全拒绝**」与「真故障」（判定点 =
    // [`is_recoverable_proposal_refusal`]）。冲突拒绝 ⇒ 放弃**这一次**提案（不签名 / 不写
    // BlockStore / 不 submit / 不广播）且节点继续运行；**绝不**重试同一冲突 target。其余错误
    // 保持 fatal（fail-closed、不吞错）。
    if let Some(a) = driver.actor(0) {
        match a.sign_block(&mut pb.block) {
            Ok(()) => {}
            Err(e) if is_recoverable_proposal_refusal(&e) => {
                live.prop_skip_conflict_target = live.prop_skip_conflict_target.saturating_add(1);
                return Ok(None);
            }
            Err(e) => return Err(RuntimeError::Validator(e)),
        }
    }
    // D10-C Step 4：本地 produced block 尽早 durable 进 BlockStore（只写 block；不推进 head /
    // state / 不提前 commit）—— 使「finality 后 commit 前 crash」时，
    // restart 可经 BlockStore 取回完整 block 由 bridge 完成 commit。
    //
    // P1-A.20-C Phase 2：改用 **verified multi-encoding** 写入（`put_verified`：hash 重算 +
    // 签名复验先于落盘）。proposer/vk/chain_id 均来自**既有** authority（本地 validator
    // identity + ValidatorSet）；storage **不**猜 proposer / 不落未验证 bytes。
    if let Some(adapter) = block_production.as_ref()
        && let Some(bs) = adapter.block_store()
    {
        let set = driver.consensus().validator_set();
        let Some(info) = set.info(&local_id) else {
            // 本地 id 不在集合（装配不一致）⇒ 保守 no-op（不落盘 / 不提交提案；不猜 / 不伪造）。
            return Ok(Some(pb));
        };
        let Ok(vk) = VerifyingKey::from_bytes(&info.consensus_public_key) else {
            return Ok(Some(pb));
        };
        let chain_id = driver.consensus().chain_id();
        let max_encodings = set.len();
        bs.put_verified(&pb.block, local_id.as_bytes(), &vk, chain_id, max_encodings)
            .map_err(|e| blockstore_stage("local_proposal_put", e))?;
    }
    // 提交共识（ProposalRef 64B；只记 hash，不含 Block）。
    let _ = driver.submit_proposal(pb.proposal_ref.clone());
    // PHASE 6H-A30 OD-X7 — 只读观测：成功构造**并提交**（**不**参与判定）。
    live.prop_build_ok = live.prop_build_ok.saturating_add(1);
    Ok(Some(pb))
}

/// PHASE 6H-A30 OD-X7 — **只读**瞬态观测（每 step 调用一次；**不**参与任何判定）。
///
/// - `prop_absent_steps`：当前 `(height, round)` 内 `proposal_present == false` 的**连续 step** 数；
///   `(height, round)` 变化或提案出现 ⇒ 归零（确定性）。
///   **与 `timer_elapsed`（tick 语义）不同**，不得混用。
/// - `elected_is_self`：`select_proposer` 与本地 validator id 的**只读**比较；无法判定 ⇒ `false`。
fn observe_liveness_transient(
    driver: &NodeConsensusDriver<DynSigner>,
    live: &mut LivenessObservability,
) {
    let (h_now, r_now) = {
        let s = driver.consensus().state();
        (s.round.height, s.round.round)
    };
    if live.prop_absent_key != (h_now, r_now) {
        live.prop_absent_key = (h_now, r_now);
        live.prop_absent_steps = 0;
    }
    if driver.consensus().state().round.proposal.is_some() {
        live.prop_absent_steps = 0;
    } else {
        live.prop_absent_steps = live.prop_absent_steps.saturating_add(1);
    }
    let set_id = driver.consensus().genesis_hash();
    let local = driver.actor(0).map(|a| a.validator_id());
    live.elected_is_self = match (
        local,
        select_proposer(
            driver.consensus().chain_id(),
            h_now,
            r_now,
            &set_id,
            driver.consensus().validator_set(),
        ),
    ) {
        (Some(lid), Ok(sel)) => sel == lid,
        _ => false,
    };
}

/// D10-A Step 3：本地 consensus 自动推进（enabled 网络主循环每 step 调用；free fn —— 不借 Runtime）。
///
/// 对当前 canonical round 执行本节点被授权的本地 vote（`NodeConsensusDriver::auto_drive`：
/// Prevote / Precommit 幂等推进）。错误按 Driver 门面 fail-closed 传出（不 panic）；`Idle`
/// （Propose / Finalized / 无 proposal）与 `WrongProposer`（外部坏 proposal 已被 driver
/// proposer-authority gate 拦截 —— 不驱动）均为无本地 action，忽略。auto-drive 只产生**本地**
/// vote；远端参与仍走既有 `submit_remote_vote` 路径（本 step 不改变）。
///
/// # P1-A.5：唯一的**非致命** Driver 失败（「QC 不适用」）
/// 派生 QC 经 `process_transition_derived` → `verify_qc` 时，若其 `target` **当前不在本节点 DAG**
/// （冻结检查 ①；`FinalityError::UnknownTarget`），则该 QC 对本节点**尚不适用** —— 这**不是**
/// 「QC 已验证有效」，也**不是**本节点运行错误：
/// - 该错误在 lock routing / outbound push **之前**产生 ⇒ **零** canonical 变更（无 lock /
///   无 outbound / 无 finality 推进 / 无 DAG 修改 / 不改 `ConsensusState`）；`verify_qc` 未被绕过。
/// - 与冻结 transition ⑥ 内部对该条件的既有容忍同语义（`integration.rs` 用 `is_ok()` 守卫：失败
///   仅不 `update_finalized_reference`，不报错）。
/// - 可达性（丢包 / 缺块；**无需恶意输入**）：proposal 的 `block_hash` 尚未进入本地 DAG 时，本地
///   vote 若恰好完成 precommit quorum，即会派生此类 QC ⇒ 修复前为**本地致命**（validator 退出）。
///
/// 计数经 `not_applicable`（saturating；**只**计数 —— 不保留 payload / target hash / 签名 /
/// 对端身份 / 错误文本）。**其余全部** Driver 失败保持 fail-closed：`VoteVerification` /
/// `Actor*` / `ActorLock` / `ProposerSelection` / `NoActor` / 其它 `QcVerification(..)`
/// （`UnknownTarget` 之外的一切 `FinalityError`）⇒ `RuntimeError::Driver`。容错范围**不扩大**。
fn drive_local_consensus(
    driver: &mut NodeConsensusDriver<DynSigner>,
    not_applicable: &mut u64,
) -> Result<(), RuntimeError> {
    // G4（Owner 决策）—— **无 recovery vote guard**：`auto_drive()` 恒正常执行
    // （不跳过 vote / 不跳过本地 QC 派生）—— 避免以“等待 bridge 成功”为条件的活性冻结。
    match driver.auto_drive() {
        Ok(_) => Ok(()),
        Err(err) if derived_qc_not_applicable(&err) => {
            *not_applicable = not_applicable.saturating_add(1);
            Ok(())
        }
        Err(other) => Err(RuntimeError::Driver(other)),
    }
}

/// P1-A.5 — 「派生 QC 不适用」**唯一**容忍判定（`drive_local_consensus` 的守卫）。
///
/// 精确等于 `DriverError::QcVerification(FinalityError::UnknownTarget)`：
/// `matches!` 只有**单一**模式 ⇒ `Err(_)` / `QcVerification(_)` / 其它 `FinalityError` /
/// 其它 `DriverError` 变体**一律** false（⇒ 走 `Err(other) => RuntimeError::Driver`，fail-closed）。
///
/// 独立成 fn 的唯一目的：使该边界可被**穷举负向测试**（`mod tests`），防止未来被写成通配符而
/// 悄悄扩大容错范围。
fn derived_qc_not_applicable(err: &DriverError) -> bool {
    matches!(
        err,
        DriverError::QcVerification(FinalityError::UnknownTarget)
    )
}

// ---------------------------------------------------------------------------
// P1-A.6 — Round Timeout Pacemaker（node-local liveness；ADR-0049 冻结语义）
// ---------------------------------------------------------------------------
//
// 时间基准 = **逻辑 step tick**（每 `NodeRuntime::step()` 恰好 +1）。
// **无**墙钟（无 `Instant` / `SystemTime`）、无 OS timer、无后台线程、无持久化 —— 与仓内既有
// `LogicalTick` / `sync_tick` / `inbound_tick` 超时机制同构（确定性、可重放）。
//
// 边界（不得越界）：timeout 的**唯一**动作是调用冻结的 `ConsensusNode::round_timeout()`；
// 它**不**产生 vote / QC / finality / lock / DAG 变更，也**不**广播（非证据、非 certificate）。

/// `RoundTimeoutConfig::timeout_for` 退避循环的迭代上界（见 [`round_timeout_window_ms`]）。
const ROUND_TIMEOUT_MAX_BACKOFF_STEPS: u64 = 64;

/// 毫秒 → 纳秒。
const NANOS_PER_MS: u64 = 1_000_000;

// ===== A3 — 单调时钟 seam（Owner 授权：Testnet 基线 10s / ×2 / 120s）=====
//
// 生产 = `std::time::Instant`（**单调**；不受墙钟调整影响）；测试 = 确定性 fake（显式 `advance`，
// **不** sleep）。计时决策从"step tick 计数"改为"单调已历时 ≥ 窗口"；**事件矩阵不变**
//（ADR-0049 §3.3/§3.4/§3.4.1：arm / reset / expire / height 前进重置 / RC 交互全部保持）。

/// A3 单调时钟：返回自时钟起点起的单调已历时（**永不回退**；**不**是墙钟时间戳）。
pub trait MonotonicClock {
    /// 单调已历时（生产 = `Instant::elapsed`；测试 = fake 计数）。
    fn elapsed(&self) -> Duration;
}

/// 生产单调时钟（`Instant`；与墙钟/时区/NTP 调整无关联）。
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// 以 `Instant::now()` 为单调起点。
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// 测试用**确定性** fake 时钟（无 `sleep` / 无线程 / 与机器负载无关）。
///
/// - [`Self::advance_ms`] / [`Self::advance_ns`]：显式前进；
/// - [`Self::set_ns`]：绝对设定（**允许回拨** —— 用于验证"回拨不得造成误到期 / 不得 panic"）。
#[derive(Debug, Default)]
pub struct FakeClock {
    now_ns: Cell<u64>,
}

impl FakeClock {
    /// 从 0 开始。
    pub fn new() -> Self {
        Self::default()
    }

    /// 前进 `ms` 毫秒（饱和）。
    pub fn advance_ms(&self, ms: u64) {
        self.advance_ns(ms.saturating_mul(NANOS_PER_MS));
    }

    /// 前进 `ns` 纳秒（饱和）。
    pub fn advance_ns(&self, ns: u64) {
        self.now_ns.set(self.now_ns.get().saturating_add(ns));
    }

    /// 绝对设定读数（可回拨；仅测试）。
    pub fn set_ns(&self, ns: u64) {
        self.now_ns.set(ns);
    }

    /// 当前读数（纳秒）。
    pub fn now_ns(&self) -> u64 {
        self.now_ns.get()
    }
}

impl MonotonicClock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.now_ns.get())
    }
}

/// 读取单调时钟（纳秒；饱和到 `u64::MAX` ⇒ 无 panic / 无环绕）。
fn clock_ns(clock: &dyn MonotonicClock) -> u64 {
    u64::try_from(clock.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// A3 — 本 round 的单调超时窗口（**毫秒**）：`min(initial × backoff^round, max)`
///（冻结 `RoundTimeoutConfig` 语义 / 形状；数值为 node-local —— ADR-0049 §3.5）。
///
/// 溢出安全：`timeout_for` 内部 `saturating_mul(...).min(max)`；这里额外把 round 夹到
/// [`ROUND_TIMEOUT_MAX_BACKOFF_STEPS`]；下界 1 ms（防退化 0 窗口）。
pub(crate) fn round_timeout_window_ms(config: &RoundTimeoutConfig, round: u64) -> u64 {
    config
        .timeout_for(round.min(ROUND_TIMEOUT_MAX_BACKOFF_STEPS))
        .max(1)
}

/// A3 — 窗口（**纳秒**，计时器实际使用的单位）。
pub(crate) fn round_timeout_window_ns(config: &RoundTimeoutConfig, round: u64) -> u64 {
    round_timeout_window_ms(config, round).saturating_mul(NANOS_PER_MS)
}

/// **A3 之前的 step-tick 窗口函数（冻结镜像；与 A3 单调超时域分离）**。
///
/// 仍以 **step tick** 解释配置数值，仅供 pending-proposal 的 step-tick 到期换算
///（[`pending_expiry_tick`]；ADR-0076 OD-C3 「2 rounds」语义）使用；**不**再被计时器使用。
pub(crate) fn round_timeout_window_ticks(config: &RoundTimeoutConfig, round: u64) -> u64 {
    round_timeout_window_ms(config, round)
}

/// P1-A.6 / A3 — 当前 `(height, round)` 的本地计时器（**只**含位置 + 单调 deadline 元数据）。
///
/// `armed_at_ns` = 本计时器（重新）ARM 时的**单调读数**（纳秒）；`window_ns` = 该
/// `(height, round)` 允许的最大单调时长（纳秒）；`now - armed_at >= window` ⇒ 到期。
///
/// 不保留任何 proposal / block hash / QC / 签名 / 对端材料。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoundTimer {
    pub(crate) height: u64,
    pub(crate) round: u64,
    /// ARM/RESET 时刻的单调读数（纳秒）。
    pub(crate) armed_at_ns: u64,
    /// 本 `(height, round)` 的单调窗口（纳秒）。
    pub(crate) window_ns: u64,
}

impl RoundTimer {
    /// 本计时器已历时（单调；`saturating_sub` ⇒ 时钟回拨**不**造成误到期、不 panic）。
    pub(crate) fn elapsed_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.armed_at_ns)
    }
}

/// P1-A.6 — 计时器推进结果（纯计算；便于穷举单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundTimerTick {
    /// 新 `(height, round)` ⇒ 已 ARM（`armed_at = now`；**不**继承上一轮 deadline）。
    Armed,
    /// 计时中（单调已历时 < 窗口）。
    Waiting,
    /// 单调已历时 ≥ 窗口 ⇒ 应触发一次本地 round timeout。
    Expired,
    /// 当前 round 内观测到 canonical 进展 ⇒ 窗口重开（`armed_at = now`）。
    Reset,
}

/// P1-A.6 / A3 — 计时器推进一步（**纯函数**：同输入同输出；无墙钟 / 无随机 / 无 I/O）。
///
/// - **ARM**：`prev` 为空或 `(height, round)` 变化 ⇒ 新计时器（`armed_at = now_ns`）；ADR-0049 §3.3
///   「round transition MUST NOT inherit stale deadline」⇒ 绝不继承上一轮 deadline。
/// - **RESET**：本 step 在**当前** `(height, round)` 内观测到 canonical 进展 ⇒ 窗口重开
///   （`armed_at = now_ns`；不增窗、不改 round）。只有**真实状态变化**能 reset ⇒ invalid / stale /
///   duplicate / spam 输入（不改变状态）**不可能** reset（ADR-0049 §3.4 MUST NOT）。
/// - **EXPIRE**：`now - armed_at >= window_ns` ⇒ 到期（**单调**判定；与 step 次数无关）。
///
/// PHASE 6H-Y：`pub(crate)` **仅**为让 O2 入站 seam 复用本状态机（ARM / 替换语义）。
#[allow(clippy::too_many_arguments)] // 与仓内既有 `transition` / RC 路径同处置（不相交借用参数）
pub(crate) fn round_timer_tick(
    prev: Option<RoundTimer>,
    height: u64,
    round: u64,
    window_ns: u64,
    progressed: bool,
    now_ns: u64,
) -> (RoundTimer, RoundTimerTick) {
    let same_round = prev.is_some_and(|t| t.height == height && t.round == round);
    if !same_round {
        return (
            RoundTimer {
                height,
                round,
                armed_at_ns: now_ns,
                window_ns,
            },
            RoundTimerTick::Armed,
        );
    }
    let mut timer = prev.expect("same_round ⇒ prev 必为 Some");
    if progressed {
        timer.armed_at_ns = now_ns;
        timer.window_ns = window_ns;
        return (timer, RoundTimerTick::Reset);
    }
    let tick = if timer.elapsed_ns(now_ns) >= timer.window_ns {
        RoundTimerTick::Expired
    } else {
        RoundTimerTick::Waiting
    };
    (timer, tick)
}

/// P1-A.6 — 本 round 是否**已被 finality 确认**（唯一 DISARM 判据）。
///
/// **必须**三项同时成立：`step == Finalized` **且** proposal 存在 **且**
/// `finality.finalized_reference == proposal.block_hash`。
///
/// 单看 `step == Finalized` **不可**作为 disarm 判据：P1-A.5 已实测存在「派生 QC
/// `UnknownTarget` ⇒ step 到 Finalized 但 finality 未推进」的状态（且该状态下 vote 已进终态守卫
/// ⇒ 无法自行恢复）；该状态**必须**仍可 timeout，否则该高度永久滞留。
fn round_finalized_by_finality(state: &ConsensusState) -> bool {
    state.round.step == RoundStep::Finalized
        && state
            .round
            .proposal
            .as_ref()
            .is_some_and(|p| state.finality.finalized_reference == Some(p.block_hash))
}

/// P1-A.6 — 计时器决策所需的状态观测（**仅**本 step 内瞬时使用；不跨 step 保留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundObservation {
    height: u64,
    round: u64,
    step: RoundStep,
    proposal_hash: Option<[u8; 32]>,
    finalized_reference: Option<[u8; 32]>,
}

/// P1-A.6 — 当前 canonical state 的计时器观测快照（只读；不变更任何状态）。
fn observe_round(node: &ConsensusNode) -> RoundObservation {
    let state = node.state();
    RoundObservation {
        height: state.round.height,
        round: state.round.round,
        step: state.round.step,
        proposal_hash: state.round.proposal.as_ref().map(|p| p.block_hash),
        finalized_reference: state.finality.finalized_reference,
    }
}

/// P1-A.6 — Round Timeout Pacemaker 主体（**free fn**：`step()` 网络段已持 `network_stack`
/// 可变借用 ⇒ 只能经不相交字段引用调用，与 `drive_local_consensus` / `finality_commit_bridge` 同构）。
///
/// # 契约（ADR-0049 冻结语义；本函数只做 node-local liveness）
/// - 时间基准 = **逻辑 step tick**（每 `step()` +1；无墙钟 / 无线程 / 不持久化）。
/// - 唯一动作 = 调用冻结的 `ConsensusNode::round_timeout()`；**不**产生 vote / QC / finality /
///   lock / DAG / canonical 变更，也**不**广播（timeout 非证据、非 certificate、不计入 quorum）。
/// - 检查点在 `runtime_propose` **之前** ⇒ round change 后新当选 proposer 可在**同一 step**
///   内走既有提案路径（liveness 在一个 step 内闭合）。
///
/// # 决策
/// 1. DISARM：本 round 已被 finality 确认（[`round_finalized_by_finality`]）⇒ 停止计时并返回。
/// 2. ARM / RESET / EXPIRE：见 [`round_timer_tick`]（`progressed` = 本 step 在**当前**
///    `(height, round)` 内观测到 canonical 进展 ⇒ 窗口重开；invalid / stale / duplicate 输入
///    不改变状态 ⇒ 结构上无法 reset）。
/// 3. EXPIRE ⇒ `ConsensusNode::round_timeout()`；`Applied` ⇒ 计数 + 立即对新
///    `(height, round)` 重开窗口；`Rejected`（`RoundOverflow`）/ `Ignored` ⇒ 计数 + 重开窗口
///    （不 wrap / 不 panic / state 不变 —— 遵循既有 `TransitionResult` 语义）。
///
/// PHASE 6H-Z §11 — 每 step 从 handler 队列取走的入站 RC payload 上界（**node-local drain bound**；
/// **非**协议参数 —— 协议级限速由 Network 层冻结 D3 limiter 承担：4 msg/s/peer、burst 8）。
const ROUND_CHANGES_PER_STEP: usize = 8;

/// P1-A.30 **D0** — RC 拒绝原因**分类桶**（**仅观测**：不改变任何拒绝条件 / 判定结果 / 状态）。
///
/// 桶边界固定且穷尽（[`Self::Other`] 为兜底）；**不**引入新的拒绝语义，**不**放宽 / 收紧
/// `verify_certificate` 的任何条件；**不**携带 payload / hash / 签名 / 对端身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundChangeRejectKind {
    /// 解码失败 / 结构 / 长度 / 证据数量 / 升序 / 重复成员（`node` 层 `decode_certificate`
    /// 失败亦归此桶）—— 即「字节层面不可解释」。
    Malformed,
    /// 证书过期（`to_round <= local_round`）。
    Stale,
    /// 高度不符（`cert.height != 本地高度`；ADR-0066 §6.2 wrong height）。
    WrongHeight,
    /// 证据权重未达 quorum。
    Quorum,
    /// 成员 / 身份 / 域 / 签名 / `validator_set_id` 绑定类失败。
    Identity,
    /// 其余（含 `RoundOverflow`）；兜底桶 ⇒ 分类穷尽。
    Other,
}

impl RoundChangeRejectKind {
    /// 桶数量（固定；`[u64; COUNT]` 计数槽）。
    pub const COUNT: usize = 6;

    /// 稳定索引（与 [`RoundChangeDiag::rejects`] 槽位一一对应）。
    const fn index(self) -> usize {
        match self {
            Self::Malformed => 0,
            Self::Stale => 1,
            Self::WrongHeight => 2,
            Self::Quorum => 3,
            Self::Identity => 4,
            Self::Other => 5,
        }
    }

    /// 冻结 [`RoundChangeError`] ⇒ 桶（**唯一**映射点；穷尽 match ⇒ 新增变体必须显式归类）。
    const fn of_error(error: RoundChangeError) -> Self {
        match error {
            RoundChangeError::TooManyEvidence
            | RoundChangeError::EmptyEvidence
            | RoundChangeError::CertificateTooLarge
            | RoundChangeError::Truncated
            | RoundChangeError::InvalidLength
            | RoundChangeError::InvalidEvidenceCount
            | RoundChangeError::EvidenceNotAscending
            | RoundChangeError::DuplicateValidator => Self::Malformed,
            RoundChangeError::StaleCertificate => Self::Stale,
            RoundChangeError::WrongHeight => Self::WrongHeight,
            RoundChangeError::InsufficientQuorum => Self::Quorum,
            RoundChangeError::ValidatorSetMismatch
            | RoundChangeError::UnknownValidator
            | RoundChangeError::ValidatorIdentityMismatch
            | RoundChangeError::InvalidDomain
            | RoundChangeError::InvalidSignature => Self::Identity,
            RoundChangeError::RoundOverflow => Self::Other,
        }
    }
}

/// P1-A.30 **D0** — RC 观测计数集合（**仅计数**；不参与任何判定；无 payload / hash / 签名 / 对端材料）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RoundChangeDiag {
    /// 拒绝原因**分类桶**（索引见 [`RoundChangeRejectKind::index`]）。
    rejects: [u64; RoundChangeRejectKind::COUNT],
    /// G-1 暂存证书**重新评估尝试**次数（每 step ≤ 1；仅「暂存区命中当前 `(height, local_round)`」才计）。
    reeval_attempts: u64,
    /// 暂存证书重新评估**成功应用**次数（恒 `<=` `reeval_attempts`）。
    reeval_applied: u64,
}

impl RoundChangeDiag {
    /// 记一次拒绝（**唯一**计数入口；与 `round_changes_rejected` 总数同步递增）。
    fn note_reject(&mut self, kind: RoundChangeRejectKind) {
        if let Some(slot) = self.rejects.get_mut(kind.index()) {
            *slot = slot.saturating_add(1);
        }
    }

    fn reject_count(&self, kind: RoundChangeRejectKind) -> u64 {
        self.rejects.get(kind.index()).copied().unwrap_or(0)
    }

    fn note_reeval_attempt(&mut self) {
        self.reeval_attempts = self.reeval_attempts.saturating_add(1);
    }

    fn note_reeval_applied(&mut self) {
        self.reeval_applied = self.reeval_applied.saturating_add(1);
    }
}

/// P1-A.30 **D0** — 本地 round timeout 的**结果分类**（**仅观测**；`round_timeouts` 仍为总数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundTimeoutOutcome {
    /// 冻结 `round_timeout()` 返回 `Applied`（round 真实 +1）。
    Applied,
    /// 返回 `Ignored`。
    ///
    /// **当前冻结 transition 对 `RoundTimeout` 不产生 `Ignored`**（`integration.rs`：
    /// `RoundTimeout` ⇒ `checked_successor` ⇒ 仅 `Applied` / `Rejected{RoundOverflow}`）
    /// ⇒ 本桶为**防御性分类**（不改判定；仅保证三分支穷尽且可观测）。
    Ignored,
    /// 返回 `Rejected`（当前唯一来源 = `u64::MAX` 轮 `RoundOverflow`）。
    Rejected,
}

impl RoundTimeoutOutcome {
    /// 桶数量（固定；`[u64; COUNT]` 计数槽）。
    pub const COUNT: usize = 3;

    /// 稳定索引。
    const fn index(self) -> usize {
        match self {
            Self::Applied => 0,
            Self::Ignored => 1,
            Self::Rejected => 2,
        }
    }
}

/// 记一次 timeout 结果（**唯一**计数入口；saturating、越界零操作）。
fn note_timeout_outcome(
    outcomes: &mut [u64; RoundTimeoutOutcome::COUNT],
    outcome: RoundTimeoutOutcome,
) {
    if let Some(slot) = outcomes.get_mut(outcome.index()) {
        *slot = slot.saturating_add(1);
    }
}

/// PHASE 6H-AF §9 — 每 step 从 handler 队列取走的入站 Abandon attestation payload 上界
/// （**node-local drain bound**；**非**协议参数 —— D3 限速仍 **NOT AUTHORIZED**）。
const ABANDON_ATTESTATIONS_PER_STEP: usize = 16;

/// PHASE 6H-Z §3.1/§5/§11/§13 — O2 入站 `RoundChangeCertificate` 权威路径
/// （**唯一**调用点：`NodeRuntime::step`；free fn ⇒ 与 `drive_round_timeout` 同构）。
///
/// # 语义边界（Owner D1-1 = D1-B；ADR-0066 §7.1/§11；ADR-0072 §3.4，全部 FROZEN）
/// - 唯一动作 = 冻结 `verify_certificate` → 节点层适用性前置 →
///   **既有冻结** round transition（`ConsensusNode::round_timeout()`）→ 既有计时器重开。
/// - **不**新增 consensus primitive / **不**新增 `ConsensusEvent` / **不**修改 `checked_successor`。
/// - **不**产生 vote / QC / finality / lock / DAG / `QcRegistry` / `VoteAccumulator` 变更。
/// - 归因（Owner D1-3 / G-2）：应用成功 ⇒ `round_changes_by_authority += 1`；
///   **绝不**计入 `round_timeouts`（本地超时语义保持不变）。
/// - G-1（Owner D1-2）：`from_round > local_round` ⇒ **仅暂存**（bounded `RoundChangeStore`；
///   不推进 / 不重开计时器）。
/// - fail-closed：malformed / invalid / stale / overflow / 低 quorum / 高度不符 ⇒ 拒绝 + 计数，
///   **零** round 变化。
/// - 无墙钟 / 无随机 / 无持久化（`RoundChangeStore` 为**有界内存**；重启即丢）。
// `too_many_arguments`：与既有 `transition`（consensus）同处置 —— 参数为**不相交借用**的
// 显式字段（timer / 三个独立归因计数 / D0 观测集合 / 暂存区），合并为结构体会引入额外的借用手续。
#[allow(clippy::too_many_arguments)]
fn drive_round_change_authority(
    driver: &mut NodeConsensusDriver<DynSigner>,
    config: &RoundTimeoutConfig,
    now_ns: u64,
    timer: &mut Option<RoundTimer>,
    by_authority: &mut u64,
    rejected: &mut u64,
    deferred: &mut u64,
    diag: &mut RoundChangeDiag,
    store: &mut RoundChangeStore,
    inbound: Vec<(NodeId, Vec<u8>)>,
) {
    for (_sender, payload) in inbound {
        // decode：结构畸形 ⇒ 拒（零状态变更；不记录 payload）。
        let Ok(cert) = decode_certificate(&payload) else {
            *rejected = rejected.saturating_add(1);
            diag.note_reject(RoundChangeRejectKind::Malformed);
            continue;
        };
        apply_inbound_round_change(
            driver,
            config,
            now_ns,
            timer,
            by_authority,
            rejected,
            deferred,
            diag,
            store,
            cert,
        );
    }
    // G-1 重新评估（每 step ≤ 1 次；有界）：本地 round 已前进 ⇒ 暂存证书可能变为可应用。
    reevaluate_stored_round_change(
        driver,
        config,
        now_ns,
        timer,
        by_authority,
        deferred,
        diag,
        store,
    );
}

/// PHASE 6H-Z — 单张已 decode 证书的权威适用（验证 / 适用性 / 应用 / 暂存 / 拒绝）。
#[allow(clippy::too_many_arguments)] // 同上（不相交借用；与 `transition` 同处置）
fn apply_inbound_round_change(
    driver: &mut NodeConsensusDriver<DynSigner>,
    config: &RoundTimeoutConfig,
    now_ns: u64,
    timer: &mut Option<RoundTimer>,
    by_authority: &mut u64,
    rejected: &mut u64,
    deferred: &mut u64,
    diag: &mut RoundChangeDiag,
    store: &mut RoundChangeStore,
    cert: RoundChangeCertificate,
) {
    let node = driver.consensus_mut();
    let local_round = node.state().round.round;
    let expected_validator_set_id = node.genesis_hash();
    match apply_verified_round_change(
        node,
        &cert,
        &expected_validator_set_id,
        local_round,
        config,
        *timer,
        now_ns,
    ) {
        RoundChangeApplication::Applied {
            timer: next_timer, ..
        } => {
            *timer = Some(next_timer);
            *by_authority = by_authority.saturating_add(1);
        }
        RoundChangeApplication::Stored { .. } => {
            // G-1：仅暂存（bounded；幂等）。
            // D0：`deferred` = 「暂存**新增**」−「重评**应用**」的累计差（gauge）⇒ **仅**
            // `AdmitOutcome::Admitted` 计 +1：
            // - `Duplicate`（同一 `(height, from_round)` 重复入站）⇒ **不**计（幂等）；
            // - store 自身**淘汰**（`evicted_height` / `evicted_certificate`）⇒ 不计入本 gauge
            //（否则容量满时 `total()` 不变会被误判为"未新增"）；store 真实条目数见
            // `round_change_store_len()`。
            if matches!(store.admit(cert), AdmitOutcome::Admitted { .. }) {
                *deferred = deferred.saturating_add(1);
            }
        }
        RoundChangeApplication::Rejected { error } => {
            *rejected = rejected.saturating_add(1);
            // D0：拒绝原因**分类**（唯一映射点；不改变拒绝本身）。
            diag.note_reject(RoundChangeRejectKind::of_error(error));
        }
    }
}

/// PHASE 6H-Z — G-1 暂存证书的**有界**重新评估（每 step 至多应用 1 张）。
///
/// 触发条件 = 暂存区存在「当前 `(height, local_round)`」的证书（即本地 round 已追平其
/// `from_round`）。仅应用**一张**：避免同 step 内无界级联；后续 step 继续收敛（确定性）。
///
/// A3：新增 `now_ns`（单调读数；仅用于重新 arm 新窗口）⇒ 参数 8/7。
#[allow(clippy::too_many_arguments)] // 同上（不相交借用；与 `transition` / RC 路径同处置）
fn reevaluate_stored_round_change(
    driver: &mut NodeConsensusDriver<DynSigner>,
    config: &RoundTimeoutConfig,
    now_ns: u64,
    timer: &mut Option<RoundTimer>,
    by_authority: &mut u64,
    deferred: &mut u64,
    diag: &mut RoundChangeDiag,
    store: &mut RoundChangeStore,
) {
    let (height, local_round) = {
        let state = driver.consensus().state();
        (state.round.height, state.round.round)
    };
    // 暂存区里必须存在恰好匹配当前 (height, local_round) 的证书才尝试（有界：单次 lookup）。
    let Some(cert) = store.get(height, local_round).cloned() else {
        return;
    };
    // D0："暂存后**已尝试**重新评估"（不含未命中 lookup）—— 每 step ≤ 1 次。
    diag.note_reeval_attempt();
    let node = driver.consensus_mut();
    let expected_validator_set_id = node.genesis_hash();
    if let RoundChangeApplication::Applied {
        timer: next_timer, ..
    } = apply_verified_round_change(
        node,
        &cert,
        &expected_validator_set_id,
        local_round,
        config,
        *timer,
        now_ns,
    ) {
        *timer = Some(next_timer);
        *by_authority = by_authority.saturating_add(1);
        *deferred = deferred.saturating_sub(1);
        diag.note_reeval_applied();
    }
}

/// PHASE 6H-AF §8 / PHASE 6H-AH §3 — 本地**真实 EXPIRE** ⇒ A-C 专用签名（每个本地 actor 一条）
/// ⇒ 池 ⇒（**新增**）返回本次**首次收录**的 `0x0E` wire container 供调用方广播。
///
/// 只能经 [`drive_round_timeout`] 输出的 [`LocalExpireObservation`] 调用
/// ⇒ 无 future-round 签名 / 无 historical back-signing / 无 caller 指定 `(height, from_round)`。
/// 签名路径 = `ValidatorActor::sign_abandon`（使用**已有** signer；**不**新建 signer / 不新增私钥 /
/// 不接触 `VoteLedger` / vote journal / block-safety journal / `LockedState`）。
/// 入池后由 [`RoundChangeAttestationPool::admit`] 的冻结 `verify_evidence` 验签（自签也必验）。
///
/// 返回值 = **仅** `PoolOutcome::Recorded`（该 `(height, from_round, validator_id)` 首次收录）对应的
/// attestation，**按 actor 索引升序**（确定性）；`Duplicate` / `AlreadyAssembled` ⇒ 不返回。
/// ⇒ 幂等边界由**既有池状态**承担（**不**新增 dedup 结构；无持久化 / 无 journal / 无 safety 语义）。
fn produce_local_abandon_attestations(
    driver: &NodeConsensusDriver<DynSigner>,
    pool: &mut RoundChangeAttestationPool,
    observation: &LocalExpireObservation,
    produced: &mut u64,
) -> Vec<AbandonAttestation> {
    let chain_id = driver.consensus().chain_id();
    let mut newly_recorded: Vec<AbandonAttestation> = Vec::new();
    // fail-closed：池绑定与共识链不符 ⇒ 不签名（也不出站）。
    if pool.chain_id() != chain_id {
        return newly_recorded;
    }
    let set = driver.consensus().validator_set().clone();
    for idx in 0..driver.actor_count() {
        let Some(actor) = driver.actor(idx) else {
            continue;
        };
        let Ok(evidence) = actor.sign_abandon(chain_id, observation) else {
            // 签名失败 ⇒ 不产出（fail-closed；无副作用）。
            continue;
        };
        let outcome = pool.admit(
            &set,
            observation.height(),
            observation.observed_from_round(),
            &evidence,
        );
        // PHASE 6H-AH §5 幂等：同一 `(height, from_round)` 只出站一次（仅首次收录）。
        if matches!(outcome, PoolOutcome::Recorded { .. }) {
            newly_recorded.push(AbandonAttestation {
                height: observation.height(),
                from_round: observation.observed_from_round(),
                validator_id: *evidence.validator_id.as_bytes(),
                signature: evidence.signature,
            });
        }
        *produced = produced.saturating_add(1);
    }
    newly_recorded
}

/// PHASE 6H-AF §9 — 入站 `0x0E` ⇒ ADR-0074 decode ⇒ 池 `admit`（内含冻结 `verify_evidence`：
/// membership → identity → 域 `0x10` → hash → `verify_strict`）⇒ 池。
///
/// **fail-closed**：长度不符 / decode 失败 / 验签失败 / 非成员 / 身份不符 / 冲突签名 ⇒ 拒绝计数，
/// **零**状态变更（不推进 round / 不广播 / 不触碰 QC / finality / lock / vote）。
fn admit_inbound_abandon_attestations(
    driver: &NodeConsensusDriver<DynSigner>,
    pool: &mut RoundChangeAttestationPool,
    rejected: &mut u64,
    inbound: Vec<(NodeId, Vec<u8>)>,
) {
    let chain_id = driver.consensus().chain_id();
    if pool.chain_id() != chain_id {
        *rejected = rejected.saturating_add(u64::try_from(inbound.len()).unwrap_or(u64::MAX));
        return;
    }
    let set = driver.consensus().validator_set().clone();
    for (_sender, payload) in inbound {
        if payload.len() != ABANDON_ATTESTATION_LEN {
            *rejected = rejected.saturating_add(1);
            continue;
        }
        let Ok(attestation) = decode_abandon_attestation(&payload) else {
            *rejected = rejected.saturating_add(1);
            continue;
        };
        // ADR-0074 §6.2：`validator_id` **不**在签名 payload 内 ⇒ 由池内 identity 检查绑定；
        // `height` / `from_round` 已在签名范围内 ⇒ 跨高度 / 跨 round 重放由验签阻断。
        let evidence = RoundChangeEvidence {
            validator_id: ValidatorId::from_bytes(attestation.validator_id),
            signature: attestation.signature,
        };
        match pool.admit(&set, attestation.height, attestation.from_round, &evidence) {
            PoolOutcome::Rejected(_) => *rejected = rejected.saturating_add(1),
            PoolOutcome::Recorded { .. }
            | PoolOutcome::Assembled(_)
            | PoolOutcome::Duplicate
            | PoolOutcome::AlreadyAssembled => {}
        }
    }
}

/// `entry` = 本 step 入口的观测快照（用于 `progressed` 判定；仅本 step 内有效）。
/// PHASE 6H-AF §8：本函数同时**输出**真实 EXPIRE 观测（`expired`）—— 供调用方在
/// **同一 step** 内走 A-C 签名路径。观测只能来自真实到期计时器状态（见
/// [`LocalExpireObservation::from_expired_timer`]）；**不**允许调用方自行构造。
// `too_many_arguments`：与 `drive_round_change_authority` / consensus `transition` 同处置 ——
// 参数为**不相交借用**的显式字段（D0 观测数组亦为独立字段），合并为结构体会引入额外借用手续。
#[allow(clippy::too_many_arguments)]
fn drive_round_timeout(
    driver: &mut NodeConsensusDriver<DynSigner>,
    config: &RoundTimeoutConfig,
    now_ns: u64,
    timer: &mut Option<RoundTimer>,
    round_timeouts: &mut u64,
    outcomes: &mut [u64; RoundTimeoutOutcome::COUNT],
    round_adv_local: &mut u64,
    entry: RoundObservation,
    expired: &mut Option<LocalExpireObservation>,
) {
    // DISARM：必须**已被 finality 确认**（不是单看 `step == Finalized` —— 见谓词 doc）。
    if round_finalized_by_finality(driver.consensus().state()) {
        *timer = None;
        return;
    }
    let observed = observe_round(driver.consensus());
    // A3：窗口为**单调时长**（ms → ns）；到期判定 = `now - armed_at >= window`（与 step 次数无关）。
    let window_ns = round_timeout_window_ns(config, observed.round);
    let (next, tick) = round_timer_tick(
        *timer,
        observed.height,
        observed.round,
        window_ns,
        observed != entry,
        now_ns,
    );
    *timer = Some(next);
    if tick != RoundTimerTick::Expired {
        return;
    }
    // PHASE 6H-AF §8：先留下**真实 EXPIRE 观测**（`(height, from_round)` 取自到期计时器本身），
    // 再执行冻结 transition —— 保证 A-C 签名路径只能针对本 step 真实到期的 round。
    *expired = LocalExpireObservation::from_expired_timer(next, tick, now_ns);
    // EXPIRE ⇒ 冻结的 node-local RoundTimeout（不新增任何共识语义）。
    match driver.consensus_mut().round_timeout() {
        TransitionResult::Applied { .. } => {
            *round_timeouts = round_timeouts.saturating_add(1);
            note_timeout_outcome(outcomes, RoundTimeoutOutcome::Applied);
            // PHASE 6H-A30 OD-X7 — 只读观测：**仅**真实推进（`Applied`）计数（**不**参与判定）。
            *round_adv_local = round_adv_local.saturating_add(1);
        }
        // D0：`Ignored` 与 `Rejected` 拆分为**独立观测桶**（判定与 §既有行为完全不变）。
        TransitionResult::Ignored { .. } => {
            *round_timeouts = round_timeouts.saturating_add(1);
            note_timeout_outcome(outcomes, RoundTimeoutOutcome::Ignored);
        }
        // `u64::MAX` 轮：`checked_successor` ⇒ `None` ⇒ `Rejected{RoundOverflow}`（不 wrap、
        // state 与 context 不变）。计该次尝试；不 panic、不视为致命错误。
        TransitionResult::Rejected { .. } => {
            *round_timeouts = round_timeouts.saturating_add(1);
            note_timeout_outcome(outcomes, RoundTimeoutOutcome::Rejected);
        }
    }
    // 立即对新 `(height, round)` 重开窗口（不继承 stale deadline；窗口 = 新轮的 `timeout_for`）。
    let after = observe_round(driver.consensus());
    *timer = Some(RoundTimer {
        height: after.height,
        round: after.round,
        armed_at_ns: now_ns,
        window_ns: round_timeout_window_ns(config, after.round),
    });
}

/// P1-A.7 — pending external QC 条目（ADR-0064）。
///
/// `verified` = 该 QC 是否已经过**既有 driver 门面**（`verify_qc` + 每 actor `acquire_lock`）。
/// 只有 `verified == true` 的条目才允许进入采纳前置检查与 facade（**不绕过 `verify_qc`**）。
pub(crate) struct PendingExternalQc {
    qc: QuorumCertificate,
    verified: bool,
}

/// P1-A.7 — **有界**入队（dedup by `qc.target`；满 ⇒ FIFO 逐出最旧）。
///
/// - 同 target 已在 pending：若新到达为 `verified == true` ⇒ 升级该条目（幂等不增长）。
/// - 返回 `false` = 未新增条目（重复 / 升级）。
fn defer_external_qc(
    pending: &mut VecDeque<PendingExternalQc>,
    qc: QuorumCertificate,
    verified: bool,
) -> bool {
    if let Some(existing) = pending.iter_mut().find(|p| p.qc.target == qc.target) {
        if verified {
            existing.verified = true;
            existing.qc = qc;
        }
        return false;
    }
    if pending.len() >= PENDING_EXTERNAL_QC_CAP {
        // 满：FIFO 逐出最旧（确定性；无扫描 / 无排序）—— 保证新证据总有槽位。
        let _ = pending.pop_front();
    }
    pending.push_back(PendingExternalQc { qc, verified });
    true
}

/// P1-A.7 — **bounded** external finality adoption（每 step ≤ [`EXTERNAL_QC_ADOPT_MAX_PER_STEP`]）。
///
/// 前置检查（**全部**满足才调 `assembly` facade）：
/// 0. **`verify_qc` 必经**：`verified == false` 的条目（入站时 `UnknownTarget`）在 target 进入
///    本地 DAG 后，经**既有** driver 门面（`verify_qc` + `acquire_lock`）重新验证；
///    仅 `Ok(())` 才继续（**不重实现任何 QC 验证**）；
/// 1. `qc.target ∈ 本地 DAG`（未到达 ⇒ **保留 pending**，等 block 登记）；
/// 2. `BlockStore::get(qc.target)` 命中（durable；未落盘 ⇒ **保留 pending**）；
/// 3. `block.height == head.height + 1` ∧ `block.parent_hash == head.block_hash`（**严格
///    canonical-next**；不跳高度 / 不回退）；
/// 4. `qc.context.height + 1 == block.height`（与 ADR-0064 / frozen fact 同一严格关系）；
/// 5. `qc.target == block_hash(block)`（由 `BlockStore::get` 的 strict decode + hash 重算保证）。
///
/// 任一失败 ⇒ **drop**（不保留）+ `rejected += 1`、**零 canonical 变更 / 无 head 修改 /
/// 无 finality 修改 / 无 outbound**。
/// 满足 ⇒ [`ConsensusNode::adopt_verified_external_finality`]；仅 `Adopted` 计 adopted 并记录 QC
/// （供既有 durable fact 路径使用）；`Idempotent`/`Stale`/`Conflict`/`Rejected` 计 rejected 并 drop。
fn adopt_pending_external_finality(
    driver: &mut NodeConsensusDriver<DynSigner>,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    pending: &mut VecDeque<PendingExternalQc>,
    adopted: &mut u64,
    rejected: &mut u64,
    last_adopted: &mut Option<QuorumCertificate>,
) {
    if pending.is_empty() {
        return;
    }
    let head = adapter.head();
    let mut kept: VecDeque<PendingExternalQc> = VecDeque::with_capacity(pending.len());
    let mut attempts = 0usize;
    while let Some(mut entry) = pending.pop_front() {
        if attempts >= EXTERNAL_QC_ADOPT_MAX_PER_STEP {
            kept.push_back(entry);
            continue;
        }
        // 1. target ∉ DAG ⇒ 证据尚不可验证（等 block）；**保留**（bounded）。
        if !driver.consensus().dag().contains(&entry.qc.target) {
            kept.push_back(entry);
            continue;
        }
        attempts += 1;
        // 0. 未验证条目：经既有 driver 门面验证（`verify_qc` + `acquire_lock`；不绕过）。
        if !entry.verified {
            match driver.submit_inbound_qc(entry.qc.clone()) {
                Ok(()) => entry.verified = true,
                Err(DriverError::QcVerification(FinalityError::UnknownTarget)) => {
                    kept.push_back(entry);
                    continue;
                }
                Err(_) => {
                    *rejected = rejected.saturating_add(1);
                    continue;
                }
            }
        }
        // 2. durable block（未落盘 ⇒ 保留等待；不猜 / 不按高度取块）。
        //    P1-A.20-C Phase 2：内容型读取 ⇒ `get_content`（legacy 或任一 encoding；内容逐字节相同）。
        let block = adapter
            .block_store()
            .and_then(|bs| bs.get_content(&entry.qc.target).ok().flatten());
        let Some(block) = block else {
            kept.push_back(entry);
            continue;
        };
        // 3/4. 严格 canonical-next + 高度关系（跳高度 / parent 不符 ⇒ drop + 计数）。
        let canonical_next = block.header.height == head.height.saturating_add(1)
            && block.header.parent_hash == head.block_hash;
        let height_ok = entry.qc.context.height.saturating_add(1) == block.header.height;
        if !canonical_next || !height_ok {
            *rejected = rejected.saturating_add(1);
            continue;
        }
        match driver
            .consensus_mut()
            .adopt_verified_external_finality(&entry.qc)
        {
            AdoptionOutcome::Adopted => {
                *adopted = adopted.saturating_add(1);
                *last_adopted = Some(entry.qc.clone());
            }
            AdoptionOutcome::Idempotent
            | AdoptionOutcome::Stale
            | AdoptionOutcome::Conflict
            | AdoptionOutcome::Rejected(_) => {
                *rejected = rejected.saturating_add(1);
            }
        }
    }
    *pending = kept;
}

/// P1-A.7 — durable **per-height PrecommitQC history** 写入（ADR-0064）。
///
/// 调用点紧随既有 `persist_finality_fact_if_needed`（⇒ **persist-before-broadcast**：egress
/// 物理发送在本 step 末；本函数在该之前）。
///
/// - 只写与当前 `finalized_reference` **一致**的 PrecommitQC（`qc.target == x`）；
/// - 同一 reference 已写 ⇒ no-op（in-memory 锚 + store 自身幂等双重）；
/// - 失败 ⇒ `Err`（**不**设锚 ⇒ 下一 step 重试）；**调用方**（runtime）将其计为观测失败。
///
/// 失败**不** halting consensus：QC history 是**对端服务能力**（不参与本地 safety / finality /
/// commit 不变式）；且 `QcHistoryError` 无法上升为 `RuntimeError` —— 后者为 bin 穷尽匹配类型
/// （`run_fault_kind` 强制新增变体必须改 bin，而 bin 不在本轮 scope）。因此本地 fail-closed 的
/// 语义由**存储 API**保证（冲突永不覆盖、损坏拒绝服务），而写入失败仅计观测 + 重试。
fn persist_qc_history_if_needed(
    history: &mut Option<QcHistory>,
    finalized: Option<[u8; 32]>,
    qc: Option<&QuorumCertificate>,
    persisted: &mut Option<[u8; 32]>,
    written: &mut u64,
) -> Result<(), QcHistoryError> {
    let Some(history) = history.as_mut() else {
        return Ok(());
    };
    let Some(x) = finalized else {
        return Ok(());
    };
    if *persisted == Some(x) {
        return Ok(());
    }
    let Some(qc) = qc else {
        return Ok(());
    };
    if qc.target != x {
        return Ok(());
    }
    let height = qc.context.height.saturating_add(1);
    history.put(height, qc)?;
    *written = written.saturating_add(1);
    *persisted = Some(x);
    Ok(())
}

/// PHASE 6H-A11 U2 — 入站 proposal admission 的可变输入（仅借用；避免参数爆炸）。
struct PendingAdmission<'a> {
    /// U1 有界 pending 容器（**不**重实现）。
    store: &'a mut PendingProposalStore,
    /// round timeout 窗口参数（用于 U1 冻结的 expiry 映射）。
    config: &'a RoundTimeoutConfig,
    /// 确定性逻辑 step tick（= `NodeRuntime::inbound_tick`；无墙钟）。
    tick: u64,
}

/// PHASE 6H-A11 U2 — 入站 proposal admission 判定（确定性；**不含** recovery）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalAdmission {
    /// Guard A + Guard C 全部通过 ⇒ 交既有 `process_command` → `driver.submit_proposal`。
    Admitted,
    /// 区块尚未本地可用 ⇒ 已入 U1 有界 pending（非 progress；NO RESET；恢复归 U3）。
    Pended,
    /// Guard A / Guard C 拒绝 ⇒ 丢弃（非 progress；NO RESET）。
    Rejected,
}

/// PHASE 6H-A11 U2 — Guard A2 纯判定：当前上下文是否匹配（**父高轮**语义；OD-11）。
///
/// `true` ⟺ `block.header.height - 1 == round_height`。
/// **禁止**把 `block.header.height` 字面作为 proposer selection height（OD-11）。
fn proposal_height_context_matches(round_height: u64, block_height: u64) -> bool {
    block_height.checked_sub(1) == Some(round_height)
}

/// PHASE 6H-A11 U2 — **入站 proposal admission guard**（ADR-0076 PADR-3 / PADR-4）。
///
/// 位置：`process_inbound_consensus_command` 内、`process_command` **之前** ⇒ 必然早于
/// `driver.submit_proposal` → `ConsensusNode::submit_proposal` → `transition(SetProposal)` →
/// `round.set_proposal`；且**不**改变 `step()` 顶层阶段顺序。
///
/// 边界（MUST）：
/// - 只读判定 + 有界 pending 插入 + 计数；**不**调用任何 consensus transition；
/// - `ProposalRef.proposer` **不**作为授权来源（PADR-1）；
/// - `round_now` **只**来自 `resolve_proposer_round_evidence`（OD-17）；**禁止**用
///   `consensus.state().round.round` 直接作为 `round_now`（后者仅作 pending binding metadata）；
/// - `height_now = block.header.height - 1`（OD-11）；
/// - 不复制 future-round / proposer-resolution / canonical admission 规则（OD-C4）。
///
/// 注：期望 proposer → VK 的三行粘合与 `block_dispatch::resolve_expected_proposer_vk_at_round`
/// 同源（同 `select_proposer` + 同 `ValidatorSet`）；该函数当前为模块私有，其可见性调整属
/// **U4**（本单元不修改 `block_dispatch.rs`）⇒ U4 后改为直接复用。
fn guard_inbound_proposal(
    driver: &NodeConsensusDriver<DynSigner>,
    block_production: &Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    admission: &mut PendingAdmission<'_>,
    proposal_ref: &ProposalRef,
) -> ProposalAdmission {
    let block_hash = proposal_ref.block_hash;
    // ---- Guard A1：本地可用性（BlockStore.contains）----
    let Some(adapter) = block_production.as_ref() else {
        // 无 canonical adapter ⇒ 无法判定可用性 / 上下文 ⇒ fail-closed（不入 pending、不猜测）。
        admission.store.note_guard_reject(GuardReject::NoStore);
        return ProposalAdmission::Rejected;
    };
    let Some(store) = adapter.block_store() else {
        admission.store.note_guard_reject(GuardReject::NoStore);
        return ProposalAdmission::Rejected;
    };
    match store.contains(&block_hash) {
        Ok(true) => {}
        // 尚未本地可用 ⇒ 入 U1 **有界** pending（arrival_round 仅作 binding metadata；OD-C2）。
        Ok(false) => {
            let state = driver.consensus().state();
            let arrival_round = state.round.round;
            let arrival_height = state.round.height;
            let entry = PendingProposal {
                proposal_ref: proposal_ref.clone(),
                block_hash,
                arrival_height,
                arrival_round,
                received_tick: admission.tick,
                expiry_tick: pending_expiry_tick(admission.config, admission.tick, arrival_round),
            };
            // 幂等：同 `block_hash` 不重复插入 / 不覆盖首次 arrival metadata（U1 容器保证）。
            let outcome = admission.store.insert(entry);
            // PHASE 6H-A11 DIAG — 仅观测：区分首次入 pending 与重复命中。
            if outcome == PendingInsertOutcome::Inserted {
                admission.store.note_pended();
            }
            return ProposalAdmission::Pended;
        }
        // 存储错误 ⇒ fail-closed（**不得**当作"暂缺"入 pending）。
        Err(_) => {
            admission.store.note_guard_reject(GuardReject::StorageError);
            return ProposalAdmission::Rejected;
        }
    }
    // ---- Guard A2 + Guard C（**共享判定**；与 U3 recovery checkpoint 同一实现）----
    //
    // proposal-bound 证据：`(本 step 当前轮, block_hash)`；绑定键 = `block_hash`
    //（**不**直接用作 `round_now`；`round_now` 始终为 resolver 输出 — OD-17）。
    let proposal_evidence = Some((driver.consensus().state().round.round, block_hash));
    match guard_block_admits_proposal(driver, adapter, block_hash, proposal_evidence) {
        Ok(()) => {
            admission.store.note_admitted();
            ProposalAdmission::Admitted
        }
        Err(reason) => {
            admission.store.note_guard_reject(reason);
            ProposalAdmission::Rejected
        }
    }
}

/// PHASE 6H-A11 U2/U3 — **Guard A2 + Guard C 共享判定**（无 pending 插入；无副作用）。
///
/// 前置：调用方已确认区块本地可用（Guard A1）或该提案已在本节点 pending 集内。
/// 顺序（MUST）：
///   ① 取回区块实体 ② Guard A2（`block.header.height - 1 == round.height`；OD-11）
///   ③ Guard C（`round_now` 仅来自 `resolve_proposer_round_evidence`；OD-17；
///      expected proposer 仅来自 ADR-0050 `select_proposer`；签名验签经既有 runtime 门面）
///
/// `proposal_evidence` = proposal-bound 证据 `(round, block_hash)`
///（U2 = 当前轮；U3 = pending `arrival_round`）；绑定键校验由 resolver 完成（hash 不匹配 ⇒ 不可用）。
///
/// 返回 `Ok(())` = 判定通过；`Err(())` = 拒绝（**单一信号**，非错误载体；与
/// `resolve_proposer_round_evidence` 同约定）。调用方负责计数 / 移除 pending / 丢弃。
#[allow(clippy::result_unit_err)]
fn guard_block_admits_proposal(
    driver: &NodeConsensusDriver<DynSigner>,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    block_hash: [u8; 32],
    proposal_evidence: Option<(u64, [u8; 32])>,
) -> Result<(), GuardReject> {
    let Some(store) = adapter.block_store() else {
        return Err(GuardReject::NoStore);
    };
    // ① 区块实体（header + proposer_signature）；读取失败 ⇒ fail-closed。
    //
    // PHASE 6H-A11 U5 — **内容寻址读取**：登记经 `put_verified`（proposer-aware `(hash, P)` 多编码）
    // 写入 ⇒ legacy `get(hash)` 不可见（`contains==true` 但 `get==None` ⇒ 误判 `MissingBlock`）。
    // 本路径随后**独立**完成 proposer 授权与签名验证（② ③）⇒ 内容型读取不降低安全边界。
    let Ok(Some(block)) = store.get_content(&block_hash) else {
        return Err(GuardReject::MissingBlock);
    };
    // ② Guard A2：父高轮上下文（含旧 / 未来高度拒绝）。
    if !proposal_height_context_matches(
        driver.consensus().state().round.height,
        block.header.height,
    ) {
        return Err(GuardReject::HeightContext);
    }
    let Some(height_now) = block.header.height.checked_sub(1) else {
        return Err(GuardReject::HeightUnderflow);
    };
    // ③ Guard C — `round_now` **必须**来自冻结证据解析（OD-17 / PADR-4）。
    let qc_evidence = last_precommit_round_evidence(driver.consensus());
    let Ok(round_now) = resolve_proposer_round_evidence(block_hash, proposal_evidence, qc_evidence)
    else {
        // 绑定证据矛盾（或不可用）⇒ fail-closed（不静默择一 / 不降级）。
        return Err(GuardReject::Evidence);
    };
    let chain_id = driver.consensus().chain_id();
    // 期望 proposer（**单一来源**）：复用 `block_dispatch` 的 `(height, round)` 显式版本
    // （ADR-0076 OD-11：`height_now = block.header.height - 1`）⇒ 不在本模块重复派生规则。
    let Ok(expected_vk) = resolve_expected_proposer_vk_at(
        adapter,
        driver.consensus().validator_set(),
        height_now,
        round_now,
    ) else {
        return Err(GuardReject::Proposer);
    };
    // 区块 proposer 签名验证：复用既有 runtime 门面（**不**新造签名派生规则）。
    // 零签名 / 错 proposer / 错 chain_id ⇒ 均拒绝（PADR-8）。
    if nova_runtime::validate_block_signature(&block, &expected_vk, chain_id).is_err() {
        return Err(GuardReject::Signature);
    }
    Ok(())
}

// ===== PHASE 6H-A30 OD-X8 — 本地提案**有界重播**（in-round refresh）=====
//
// 目的（唯一）：修复「本地提案已发出，但某个**合法**接收方此刻仍处于上一轮 ⇒ Guard C 取证轮
// 与生产轮不匹配 ⇒ 提案被一次性丢弃（`Rejected`，不入 pending）」⇒ 在**零冗余 quorum**
// （5/7：Q = 全 5 票）下该轮永远无法形成 QC ⇒ 高度停滞。
//
// 语义边界（MUST —— 本机制**不**改变任何共识语义）：
// - 重播的是**逐字节相同**的 `ProposalRef` + wire block（同一签名 / 同一编码 / 同一签名域）；
// - Guard C 逐字不变 ⇒ 接收方**只有**在自己当前轮 == 生产轮时才会准入（**不**扩大接受范围）；
// - 投票 / QC / lock / RC / finality / 票轮上下文全部不变（重播走**同一条**既有入站路径）；
// - 仅**本地生产**路径登记（remote 到达的提案**不**转发 —— relay 仍不在范围内）；
// - 每个 `(height, round)` 至多 [`MAX_PROPOSAL_REFRESH`] 次、相邻两次至少间隔
//   [`PROPOSAL_REFRESH_INTERVAL_TICKS`] 个入站 tick（确定性逻辑 step，**无墙钟**）⇒ 有界；
// - `(height, round)` 变化 / 本轮提案已非本次产出 / 已达上限 ⇒ 停止或清空（无陈旧重播）。

/// 单个 `(height, round)` 内允许的重播次数上限（**有界**；不构成洪泛 / 放大）。
pub const MAX_PROPOSAL_REFRESH: u32 = 3;

/// 相邻两次重播之间的最小入站 tick 间隔（确定性逻辑 step；**无**墙钟读取）。
pub const PROPOSAL_REFRESH_INTERVAL_TICKS: u64 = 10;

/// 本地提案重播状态（Node-local；**不含**共识语义；**不**参与任何判定输入）。
#[derive(Debug, Clone)]
pub struct ProposalRefresh {
    /// 产出该提案时的共识高度。
    pub height: u64,
    /// 产出该提案时的共识轮。
    pub round: u64,
    /// 原提案引用（逐字复用；**不**重算 / **不**重新签名）。
    pub proposal_ref: ProposalRef,
    /// 原 wire block（**逐字节相同**；接收方按 `block_hash` 幂等）。
    pub block_wire: Vec<u8>,
    /// 已重播次数（`<= `[`MAX_PROPOSAL_REFRESH`]）。
    pub refreshes: u32,
    /// 上次重播（或首次登记）时的入站 tick。
    pub last_tick: u64,
}

/// 重播决策（纯值；无副作用 ⇒ 可确定性单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshDecision {
    /// 状态已陈旧（`(height, round)` 变化 / 本轮提案已非本次产出）⇒ 清空。
    Clear,
    /// 保持（间隔未到 / 已达上限）⇒ 本 tick 不发送。
    Hold,
    /// 本 tick 重播一次（逐字节相同）。
    Resend,
}

/// 重播决策（**纯函数**；无副作用 / 无墙钟 / 无 I/O ⇒ 确定性可测）。
#[allow(clippy::too_many_arguments)]
pub fn proposal_refresh_decision(
    bound_height: u64,
    bound_round: u64,
    refreshes: u32,
    last_tick: u64,
    round_height: u64,
    round_round: u64,
    round_holds_our_proposal: bool,
    tick: u64,
) -> RefreshDecision {
    if round_height != bound_height || round_round != bound_round || !round_holds_our_proposal {
        return RefreshDecision::Clear;
    }
    if refreshes >= MAX_PROPOSAL_REFRESH {
        return RefreshDecision::Hold;
    }
    if tick.saturating_sub(last_tick) < PROPOSAL_REFRESH_INTERVAL_TICKS {
        return RefreshDecision::Hold;
    }
    RefreshDecision::Resend
}

/// 驱动本地提案的**有界**重播（唯一副作用点：命中 `Resend` 时按**同一字节**再入队一次）。
///
/// 复用**既有** `Driver::record_local_proposal`（与首次广播同一入口 / 同一 egress / 同一队尾
/// ⇒ 不新增传输机制、不新增 wire 类型、不改 codec、不改任何 consensus 调用点）。
fn drive_proposal_refresh(
    driver: &mut NodeConsensusDriver<DynSigner>,
    refresh: &mut Option<ProposalRefresh>,
    tick: u64,
    liveness: &mut LivenessObservability,
) {
    let Some(bound) = refresh.as_ref() else {
        return;
    };
    let (bound_height, bound_round, refreshes, last_tick) =
        (bound.height, bound.round, bound.refreshes, bound.last_tick);
    let (round_height, round_round, holds) = {
        let round = &driver.consensus().state().round;
        let holds = match refresh.as_ref() {
            Some(state) => round.proposal.as_ref() == Some(&state.proposal_ref),
            None => false,
        };
        (round.height, round.round, holds)
    };
    match proposal_refresh_decision(
        bound_height,
        bound_round,
        refreshes,
        last_tick,
        round_height,
        round_round,
        holds,
        tick,
    ) {
        RefreshDecision::Clear => {
            *refresh = None;
        }
        RefreshDecision::Hold => {}
        RefreshDecision::Resend => {
            let Some(state) = refresh.as_mut() else {
                return;
            };
            driver.record_local_proposal(state.proposal_ref.clone(), state.block_wire.clone());
            state.refreshes = state.refreshes.saturating_add(1);
            state.last_tick = tick;
            liveness.egress_prop_refreshed = liveness.egress_prop_refreshed.saturating_add(1);
        }
    }
}

/// PHASE 6H-A30 OD-X8 — 登记本地生产提案的重播状态（**仅**本地生产路径调用）。
///
/// `block_wire = None`（编码失败）⇒ **不**登记（保持既有「无半成品」语义；**不**新增错误路径）。
/// `(bound_height, bound_round)` 取自本节点**当前共识轮**（与产出该提案的轮同一来源）。
///
/// 备注：以**free fn + 不相交字段引用**形式提供 —— `step()` 网络段已持 `network_stack`
/// 可变借用，`&mut self` 方法调用会与之冲突（因此与既有 helper 同一风格）。
fn register_proposal_refresh(
    slot: &mut Option<ProposalRefresh>,
    pb: &ProposalBuild,
    block_wire: Option<Vec<u8>>,
    bound_height: u64,
    bound_round: u64,
    tick: u64,
) {
    let Some(block_wire) = block_wire else {
        return;
    };
    *slot = Some(ProposalRefresh {
        height: bound_height,
        round: bound_round,
        proposal_ref: pb.proposal_ref.clone(),
        block_wire,
        refreshes: 0,
        last_tick: tick,
    });
}

/// PHASE 6H-A11 DIAG — 只读诊断计数（**不参与任何判定**；无共识语义）。
#[derive(Debug, Default)]
struct A11Diag {
    recovery_runs: u64,
    recovery_candidates: u64,
    recovery_kept_missing_block: u64,
    recovery_admitted: u64,
    recovery_rejected: u64,
    recovery_evidence_conflict: u64,
    recovery_submit_err: u64,
    block_inbound_processed: u64,
    block_canonical_next: u64,
    block_register_ok: u64,
    block_conflict_skipped: u64,
    // PHASE 6H-A30-OD-X7h — 仅观测：入站 block **来源类别**（Gossip / SyncResponse）计数。
    // 数据源 = 既有 dispatch 判定点（`step()` 内既有 `source`，由既有 match 分支决定）；
    // bounded + saturating；**不**重新执行 validation、**不**改变 verdict / 控制流 / 返回值。
    block_src_gossip_total: u64,
    block_src_gossip_invalid_proposer_signature: u64,
    block_src_sync_total: u64,
    block_src_sync_invalid_proposer_signature: u64,
    // PHASE 6H-A30-OD-X7i — 仅观测：**Gossip** 路径 `InvalidProposerSignature` 来源分类。
    // A = `resolve_proposer_round_evidence` 冲突（dispatcher 在验签**之前**返回）；
    // B = `validate_block_signature` 真实验签失败（仅当 A 未发生时可达）。
    // bounded + saturating；数据来自**同一输入上的只读复算**（不重新验签 / 不新增状态）。
    block_gossip_invalid_proposer_signature_evidence_conflict: u64,
    block_gossip_invalid_proposer_signature_signature_failure: u64,
    // PHASE 6H-A30-ROOTFIX-M3 — 仅观测：**登记阶段**轮派生结果（bounded + saturating）。
    // 三项均**不参与判定**（判定见 `register_remote_canonical_block`）：
    // - `block_register_round_conflict`：proposal 与 QC 绑定证据轮冲突 ⇒ 保守 no-op 计数；
    // - `block_arrival_round_mismatch`：pending arrival 轮 ≠ 登记解析轮（arrival 轮**已不作轮来源**，
    //   此处仅记录“到达轮偏离生产轮”的频度，**不**导致拒绝）；
    // - `block_register_label_mismatch`：解析轮 ⇒ 期望 proposer key 与区块签名**不符** ⇒ 保守 no-op
    //   （防“本地标签错 ⇒ `put_verified` ⇒ `CorruptedState` 致命退出”）。
    block_register_round_conflict: u64,
    block_arrival_round_mismatch: u64,
    block_register_label_mismatch: u64,
}

/// PHASE 6H-A11 U3 — **pending proposal recovery checkpoint**（ADR-0076 PADR-5.3；OD-C1 = A）。
///
/// 触发：`register_remote_canonical_block` **成功返回后**，同 step、同 block inbound stage 内
/// 立即调用（**不**改变 `step()` 顶层阶段顺序 / **不**新增 pipeline phase）。
///
/// 固定顺序（MUST；§3）：
///   1. 恢复 pending proposal-bound evidence `(arrival_round, block_hash)`（**不**猜 round）
///   2. `resolve_proposer_round_evidence`（在共享判定内；Ok(r) / Ok(0) / Err ⇒ 拒绝）
///   3. Guard A（`BlockStore.contains` + `block.header.height - 1 == round.height`）
///   4. Guard C（expected proposer + signature + chain_id）
///   5. 全部通过 ⇒ 经**既有唯一** orchestration seam `process_command` → `driver.submit_proposal`
///      → `process_transition_derived`（与 inbound proposal 路径**逐字同语义**）⇒ 随后 `set_proposal`
///
/// 有界：单次 checkpoint 至多处理 [`MAX_PENDING_PROPOSALS`] 条（**无** while 无界扫描 / 无 wall clock）。
/// 不变量：失败 ⇒ `remove` + `note_rejected`（零共识状态变更 ⇒ `RoundObservation` 不变 ⇒ NO RESET）；
/// 仅第 5 步成功才产生 progress（允许既有 RESET 逻辑）。
fn recover_pending_proposals(
    driver: &mut NodeConsensusDriver<DynSigner>,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    pending: &mut PendingProposalStore,
    inbound_consensus_rejected: &mut u64,
    diag: &mut A11Diag,
) {
    // PHASE 6H-A11 DIAG — 仅观测：checkpoint 被调用（即"区块登记成功之后"）。
    diag.recovery_runs = diag.recovery_runs.saturating_add(1);
    let Some(store) = adapter.block_store() else {
        return;
    };
    // 有界快照（≤ MAX_PENDING_PROPOSALS）：避免遍历时与 `remove` 的借用冲突。
    let candidates = pending.evidence_bounded(MAX_PENDING_PROPOSALS);
    for (block_hash, arrival_round) in candidates {
        diag.recovery_candidates = diag.recovery_candidates.saturating_add(1);
        // Step 1/3：区块可用性。尚未可用 ⇒ **保留** pending（由容量 + 到期约束，不无限缓存）。
        match store.contains(&block_hash) {
            Ok(true) => {}
            Ok(false) => {
                diag.recovery_kept_missing_block =
                    diag.recovery_kept_missing_block.saturating_add(1);
                continue;
            }
            // 存储错误 ⇒ fail-closed：移除 + 计数（**不得**当作"暂缺"继续保留）。
            Err(_) => {
                diag.recovery_rejected = diag.recovery_rejected.saturating_add(1);
                let _ = pending.remove(&block_hash);
                pending.note_guard_reject(GuardReject::StorageError);
                continue;
            }
        }
        // Step 1/2/3/4：proposal-bound 证据 = `(arrival_round, block_hash)`（OD-C2 / OD-C3）。
        let evidence = Some((arrival_round, block_hash));
        match guard_block_admits_proposal(driver, adapter, block_hash, evidence) {
            Ok(()) => {
                // Step 5：全部通过 ⇒ 经既有唯一准入路径提交（与 inbound 路径同语义）。
                let Some(entry) = pending.remove(&block_hash) else {
                    continue;
                };
                if process_command(driver, NodeConsensusCommand::Proposal(entry.proposal_ref))
                    .is_err()
                {
                    // 与 inbound 路径同一纪律：peer 提供的内容 **不得**致命；计数并继续。
                    *inbound_consensus_rejected = (*inbound_consensus_rejected).saturating_add(1);
                    diag.recovery_submit_err = diag.recovery_submit_err.saturating_add(1);
                    pending.note_rejected();
                } else {
                    diag.recovery_admitted = diag.recovery_admitted.saturating_add(1);
                    pending.note_admitted();
                }
            }
            Err(reason) => {
                // 拒绝 ⇒ 移除 + 计数（零共识状态变更）。
                diag.recovery_rejected = diag.recovery_rejected.saturating_add(1);
                if reason == GuardReject::Evidence {
                    diag.recovery_evidence_conflict =
                        diag.recovery_evidence_conflict.saturating_add(1);
                }
                let _ = pending.remove(&block_hash);
                pending.note_guard_reject(reason);
            }
        }
    }
}

#[cfg(test)]
mod proposal_admission_tests {
    use super::*;

    #[test]
    fn u2_height_context_is_parent_round_semantics() {
        // OD-11：`block.header.height - 1 == round.height`（父高轮；无 off-by-one）。
        assert!(proposal_height_context_matches(3, 4));
        assert!(
            !proposal_height_context_matches(4, 4),
            "以 block.header.height 字面作 selection height 必须失败（OD-11）"
        );
        assert!(!proposal_height_context_matches(2, 4));
    }

    #[test]
    fn u2_height_context_rejects_zero_and_boundary_heights() {
        // height 0 区块（genesis / 非 canonical-next）永不被接受；u64 边界不 panic。
        assert!(!proposal_height_context_matches(0, 0));
        assert!(!proposal_height_context_matches(u64::MAX, 0));
        assert!(proposal_height_context_matches(u64::MAX - 1, u64::MAX));
    }

    /// PHASE 6H-A30 OD-X8 — 重播决策**有界性 / 陈旧清理**（纯函数；确定性）。
    #[test]
    fn od_x8_refresh_decision_is_bounded_and_clears_when_stale() {
        // 同轮 + 本轮提案仍为本次产出 + 间隔未到 ⇒ Hold（不发送）。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 7, 2, true, 109),
            RefreshDecision::Hold
        );
        // 间隔到达（>= 10 tick）⇒ Resend。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 7, 2, true, 110),
            RefreshDecision::Resend
        );
        // 高度推进 ⇒ Clear（无陈旧重播）。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 8, 0, false, 110),
            RefreshDecision::Clear
        );
        // 轮推进 ⇒ Clear。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 7, 3, false, 110),
            RefreshDecision::Clear
        );
        // 本轮提案已非本次产出（被替换 / 被清空）⇒ Clear。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 7, 2, false, 110),
            RefreshDecision::Clear
        );
        // 已达上限 ⇒ Hold（不再增加发送；状态保留，由轮/高度变化清空 —— **有界**）。
        assert_eq!(
            proposal_refresh_decision(7, 2, MAX_PROPOSAL_REFRESH, 100, 7, 2, true, 10_000),
            RefreshDecision::Hold
        );
        // 上限 -1 ⇒ 仍可发送一次（边界）。
        assert_eq!(
            proposal_refresh_decision(7, 2, MAX_PROPOSAL_REFRESH - 1, 100, 7, 2, true, 10_000),
            RefreshDecision::Resend
        );
        // 单调性：timestamp 回退（`tick < last_tick`，saturating）⇒ 不误触发发送。
        assert_eq!(
            proposal_refresh_decision(7, 2, 0, 100, 7, 2, true, 5),
            RefreshDecision::Hold
        );
    }

    #[test]
    fn u2_admission_enum_is_deterministic_and_copy() {
        // 三态判定是 Copy 的纯值（无内部状态；重放确定）。
        let a = ProposalAdmission::Admitted;
        let p = ProposalAdmission::Pended;
        let r = ProposalAdmission::Rejected;
        assert_ne!(a, p);
        assert_ne!(p, r);
        assert_eq!(a, ProposalAdmission::Admitted);
    }
}

/// P1-A.7 — **入站共识命令统一处理入口**（step 网络路径与内部/测试直接调用**同一语义**）。
///
/// 保持既有契约：`DriverError` 原样传出（不吞错 / 不改 canonical 状态）。附加（仅 ADR-0064）：
/// - `Ok(())`（已验证 QC）⇒ 交采纳检查点（`pending_external_qc`，`verified = true`）；
/// - `Err(QcVerification(UnknownTarget))`（既有「不适用」语义）⇒ 计 `inbound_qc_deferred`、
///   以**更高高度证据**复用既有 intent ledger 触发 `local_head + 1` 请求、并有界缓冲
///   （`verified = false`，待 target 落 DAG 后由检查点经**既有** driver 门面重新验证）；
/// - 其余 `Err` ⇒ 仅原样传出（**不**缓冲 —— fail-closed）。
///
/// free fn + 不相交字段引用（`step` 网络段已持 `network_stack` 可变借用）。
fn process_inbound_consensus_command(
    driver: &mut NodeConsensusDriver<DynSigner>,
    block_production: &Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    admission: &mut PendingAdmission<'_>,
    ledger: &mut MissingAncestorIntentLedger,
    pending: &mut VecDeque<PendingExternalQc>,
    deferred: &mut u64,
    command: NodeConsensusCommand,
) -> Result<(), DriverError> {
    // PHASE 6H-A11 U2 — 入站 **proposal** admission guard（Guard A / Guard C）。
    //
    // MUST 早于 `process_command`（→ `driver.submit_proposal` → `ConsensusNode::submit_proposal`
    // → `transition(SetProposal)` → `round.set_proposal`）；**不**改变 step() 顶层阶段顺序。
    // 未准入（Pended / Rejected）⇒ 直接返回：**零** consensus 状态变更（无 progress / NO RESET）。
    if let NodeConsensusCommand::Proposal(proposal_ref) = &command {
        match guard_inbound_proposal(driver, block_production, admission, proposal_ref) {
            // 通过 Guard A + Guard C ⇒ 继续走既有 process_command（唯一准入路径）。
            ProposalAdmission::Admitted => {}
            // 区块尚未本地可用 ⇒ 已入 U1 有界 pending（恢复归 U3）；本 step 到此为止。
            ProposalAdmission::Pended => return Ok(()),
            // Guard A / Guard C 拒绝 ⇒ 丢弃；本 step 到此为止。
            ProposalAdmission::Rejected => return Ok(()),
        }
    }
    let inbound_qc = match &command {
        NodeConsensusCommand::InboundQc(qc) => Some(qc.clone()),
        _ => None,
    };
    match process_command(driver, command) {
        Ok(()) => {
            if let Some(qc) = inbound_qc {
                let _ = defer_external_qc(pending, qc, true);
            }
            Ok(())
        }
        Err(err) => {
            if let Some(qc) = inbound_qc
                && derived_qc_not_applicable(&err)
            {
                *deferred = deferred.saturating_add(1);
                // tip hint / 更高高度证据 ⇒ 复用**既有** intent ledger 触发 `local_head + 1`
                // 请求（**不建第二套发送机制**；source 用既有变体）。
                if qc.context.vote_type == VoteType::Precommit {
                    let observed_height = qc.context.height.saturating_add(1);
                    let head = block_production
                        .as_ref()
                        .map(|a| a.head().height)
                        .unwrap_or(0);
                    if observed_height > head {
                        ledger.record(MissingAncestorIntent {
                            observed_height,
                            observed_block_hash: qc.target,
                            local_head_height: head,
                            source: BlockInboundSource::SyncResponse,
                            count: 1,
                        });
                    }
                }
                let _ = defer_external_qc(pending, qc, false);
            }
            Err(err)
        }
    }
}

/// D10-C Step 4 — Finality Advance 后 durable 写 Recovery Fact（**durable-before-bridge**；幂等）。
///
/// - 观察 frozen transition ⑥ 产出的 `finalized_reference = Some(X)`（consensus 只读；不制造
///   finality / QC）；QC 取同一 transition 派生的 PrecommitQC（`qc.target == X` 才写 —— 否则
///   保守跳过，绝不写 reference-only fact）。
/// - 幂等：`X` 已持久化（完整字节一致）⇒ no-op（避免每 tick 重写同一 fact）。
/// - `height` = canonical-next 块高（`qc.context.height + 1`；与 restore 校验一致）。
/// - **D11-25（Model B）**：runtime `R` 前进到**低于**已有 durable evidence 的高度 ⇒
///   `persist_finality_fact` **不写**并返回 `Ok`（非致命跳过，保留更高证据）⇒ 本调用
///   **不得**因此产生 fatal Err / 进程退出；只有**同高度证据冲突**才 fail-closed。
/// - 写失败 ⇒ `Err`（fail-closed；bridge 不执行 —— 不进入「finality 未 durable 却 commit」）。
/// - free fn：step 网络段持有 `network_stack` 可变借用时，经不相交字段引用调用（不整 &mut self）。
fn persist_finality_fact_if_needed(
    driver: &NodeConsensusDriver<DynSigner>,
    identity: &ChainIdentity,
    path: &Path,
    persisted: &mut Option<[u8; 32]>,
) -> Result<(), RuntimeError> {
    let Some(x) = driver.consensus().state().finality.finalized_reference else {
        return Ok(());
    };
    if *persisted == Some(x) {
        return Ok(());
    }
    let Some(qc) = driver.consensus().last_precommit_qc().cloned() else {
        return Ok(());
    };
    if qc.target != x {
        return Ok(());
    }
    let height = qc.context.height.saturating_add(1);
    bootstrap::persist_finality_fact(
        path,
        identity.network_id,
        identity.chain_id,
        identity.genesis_hash,
        height,
        x,
        &qc,
    )
    .map_err(RuntimeError::FinalityFact)?;
    *persisted = Some(x);
    Ok(())
}

/// D10-B — Finality → Commit Bridge（每 tick 幂等；一个 tick 至多 commit 一个 finalized block）。
///
/// 从共识读取 `finalized_reference`（**只读**；finality 只由 frozen consensus transition ⑥ 产生，
/// 本桥不制造 finality / QC / votes）。Gate（**全部满足**才 commit）：
/// 1. `finalized_reference = Some(X)`（无 finality ⇒ NO COMMIT）；
/// 2. `X != adapter.head().block_hash`（幂等锚：已 commit ⇒ no-op —— stale / duplicate 安全）；
/// 3. X 解析为完整块且 `block_hash(block) == X`（**严格 match**；V0.1 seam = 本地 `last_proposal`；
///    不 match ⇒ NO COMMIT，绝不 fallback 任意块）；
/// 4. proposer 解析 = **hash 绑定**轮次证据（`target == X`）→ `select_proposer` →
///    `ValidatorSet.info` → `VerifyingKey`；**B2-D1**：证据来源 = 本地 `last_precommit_qc`
///    与既有 per-height `qc_history`（key = 块高 H ⇒ `qc.target == block_hash(H) == X`）
///    无绑定证据 / 两源冲突 ⇒ **defer（no-op）**（不猜轮 / 不以 round 0 兜底 / 不致命退出）；
///    绑定 QC 的 round 本身为 0 ⇒ 合法使用 0；
/// 5. `adapter.apply_block(wire, vk)`（复用冻结 ①~⑥ durable commit：height/parent 线性防护、
///    block durable-first、state+head 同 WAL 批、head 仅 ⑥ 成功推进）。
///
/// 任何 gate 不满足 ⇒ 安全 no-op（不 commit / 不改 head / 无 partial）。**只处理共识-finalized
/// 的 canonical block**：remote valid-but-unfinalized inbound block 从不进入（block inbound 只读）。
fn finality_commit_bridge(
    driver: &mut NodeConsensusDriver<DynSigner>,
    adapter: Option<&mut NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    last_proposal: Option<&ProposalBuild>,
    qc_history: Option<&QcHistory>,
    restored_qc: Option<&QuorumCertificate>,
) -> Result<(), RuntimeError> {
    let Some(adapter) = adapter else {
        return Ok(()); // 无 canonical adapter（P1-A.24 后仅防御性不可达）⇒ 无 commit
    };
    // Gate 1：无 finality ⇒ NO COMMIT。
    let Some(x) = driver.consensus().state().finality.finalized_reference else {
        return Ok(());
    };
    // Gate 2：已 commit（head 已 == X）⇒ 幂等 no-op（stale / duplicate tick 安全）。
    if adapter.head().block_hash == x {
        return Ok(());
    }
    // Gate 3：解析 finalized 块 —— D10-C Step 4：优先本地 `last_proposal`（strict hash == X）；
    //    restart 恢复路径（`last_proposal` 已丢失）⇒ **proposer-aware** 从
    //    `BlockStore.get_for_proposer_verified(X, P, vk_P, chain_id)` 解析
    //    （P1-A.17 F-1 **Candidate A 修复**：不再使用 proposer-blind `get_content`；
    //    encoding identity = `(block_hash, proposer)` ⇒ P 的 encoding 唯一；已 strict decode +
    //    hash 重算 == X + 以 P 的 key 验签）。两者皆失败 ⇒ NO COMMIT（绝不按 height / proposer 猜块）。
    let (block, proposer) = if let Some(pb) = last_proposal.filter(|pb| pb.block_hash == x) {
        (pb.block.clone(), pb.proposal_ref.proposer)
    } else {
        let set = driver.consensus().validator_set();
        let Some(bs) = adapter.block_store() else {
            return Ok(());
        };
        // P1-A.17 F-1 **Candidate A 修复（Option A）**：待提交块的 canonical-next 高度
        // **不再**由 proposer-blind 内容读取得出 —— finality commit 只处理 head 的**严格 child**
        // （`height == head.height + 1` ∧ `parent == head.block_hash`）；该不变式由既有 gate 强制
        // （`adopt_verified_external_finality` 前置契约 / `restore_finality_fact` check 6 /
        // `apply_block_inner` 门⑤）⇒ 轮次证据与期望 proposer 均在检索**之前**确定。
        let next_height = adapter.head().height.saturating_add(1);
        // proposer（V0.1 parent-height 语义；与 D9 / rebuild / restore 同源 —— 不新造规则）。
        //
        // P1-A.18 RC-1 + **B2-D1**：轮次只取 **hash 绑定**证据（`target == X`），两个来源：
        // - 来源 A = 本地 `last_precommit_qc`（**单一槽位**，会被更新 QC 覆盖 ⇒ 可能已不绑定 X）；
        // - 来源 B = 既有 per-height `qc_history`（key = 块高 H ⇒ `qc.target == block_hash(H) == X`；
        //   store 层已双向强制 `height == qc.context.height + 1` / `reference == qc.target` /
        //   `vote_type == Precommit`（**复用 API，不重造存储校验**）；本 step 已在 commit 之前写入
        //   与 `finalized_reference` 绑定的 QC（含外部采纳 QC）⇒ 重启后仍可用）。
        // `resolve_proposer_round_evidence` 统一处理：恰一个绑定 ⇒ 用其 round（**可为 0，合法**）；
        // 都未绑定 ⇒ `Ok(None)`；都绑定但轮不同 ⇒ `Err(())`。
        // Owner 裁决：`Ok(None)` / `Err(())` 一律 **defer（no-op）** —— 不猜 round、
        // **绝不以 round 0 兜底**、不致命退出（节点不因缺证据而终止；下一 tick 若证据到位可再试）。
        let chain_id = driver.consensus().chain_id();
        let genesis_hash = driver.consensus().genesis_hash();
        // 两个来源都必须**严格绑定 X**（`target == X`）；未绑定 ⇒ 视为“无证据”（不得当证据用）。
        let local_evidence =
            last_precommit_round_evidence(driver.consensus()).filter(|(_, t)| *t == x);
        let history_evidence = qc_history
            .and_then(|h| h.get(next_height).ok().flatten())
            .filter(|qc| qc.target == x)
            .map(|qc| (qc.context.round, qc.target));
        // 来源 C（D10 Recovery C / D-1）：启动时从 finality fact 恢复、已过 Check 1–7 + `verify_qc`
        // 的 PrecommitQC。同样**必须严格绑定 X**（未绑定 ⇒ 视为无证据）。与其它两源同权参与
        // “恰一绑定 / 冲突 ⇒ defer” 判定（见 `resolve_proposer_round_evidence_with_recovery`）。
        let restored_evidence = restored_qc
            .filter(|qc| qc.target == x)
            .map(|qc| (qc.context.round, qc.target));
        // Owner 裁决：**无绑定证据 ⇒ defer**（不猜 round / **不以 round 0 兜底**）。
        // 注意：绑定 QC 的 `round == 0` 是**合法**证据 ⇒ 走下方正常路径使用 0（二者严格区分）。
        if local_evidence.is_none() && history_evidence.is_none() && restored_evidence.is_none() {
            return Ok(());
        }
        // 三源统一处理：恰一个绑定 ⇒ 其 round（可为 0）；多源绑定但轮不同 ⇒ `Err(())` ⇒ **defer**
        // （不静默择一 / 不降级 round 0 / 不致命）。无绑定已在上方 return。
        let Ok(Some(round)) = resolve_proposer_round_evidence_with_recovery(
            x,
            local_evidence,
            history_evidence,
            restored_evidence,
        ) else {
            return Ok(());
        };
        let Some(p) = select_proposer(
            chain_id,
            next_height.saturating_sub(1),
            round,
            &genesis_hash,
            set,
        )
        .ok() else {
            return Ok(());
        };
        // 期望 proposer P 的验证 key（与下方 Gate 4 同源：`ValidatorSet.info` ⇒ `VerifyingKey`）——
        // 仅本分支需要它来**定向**检索 P 的 encoding；Gate 4 语义未变。
        let Some(p_info) = set.info(&p) else {
            return Ok(());
        };
        let Ok(p_vk) = VerifyingKey::from_bytes(&p_info.consensus_public_key) else {
            return Ok(());
        };
        // **proposer-aware 检索**（Option A；写侧不变式：`put_verified` 要求「写入 `(hash, P)` 的
        // 字节必须由 P 签名且验证先于落盘」⇒ 读侧必须按 P 定向，否则读写两侧不自洽）：
        // - P encoding **不存在** ⇒ `Ok(None)` ⇒ **defer**（既有语义；不猜、**绝不回退**它人 encoding）；
        // - P encoding 存在但记录损坏 / hash 不符 / 文件名 proposer 与实际签名者不符 / 签名不符 /
        //   chain_id 不符 ⇒ `Err(StorageError::CorruptedState)` ⇒ **fail-closed（fatal，不吞错）**。
        let Some(b) = bs
            .get_for_proposer_verified(&x, p.as_bytes(), &p_vk, chain_id)
            .map_err(|e| blockstore_stage(&format!("finality_commit_get hash={x:02x?}"), e))?
        else {
            return Ok(());
        };
        (b, p)
    };
    // Gate 4：proposer 验证 key（本地登记 proposer → ValidatorSet.info → VerifyingKey）。
    let set = driver.consensus().validator_set();
    let Some(info) = set.info(&proposer) else {
        return Ok(());
    };
    let Ok(vk) = VerifyingKey::from_bytes(&info.consensus_public_key) else {
        return Ok(());
    };
    // Gate 5：encode + 冻结 apply_block（durable commit；错误 fail-closed）。
    let wire = nova_runtime::encode_block(&block).map_err(RuntimeError::BlockCodec)?;
    // P1-A.20-C Phase 2：⑥a 走 **verified multi-encoding**（`put_verified`）——
    // `proposer` / `vk` 均来自上文的**既有**解析（绑定证据 + ValidatorSet）；
    // ⚠️ round 解析语义**未变**（`last_precommit_qc` 绑定 / 回退 round 0 保留给 Phase 3 迁移）。
    let max_encodings = set.len();
    let applied = adapter.apply_block_with_proposer(&wire, &vk, proposer.as_bytes(), max_encodings);
    // P1-A.17 F-1 **最小观测**（Owner 授权；`runtime.rs` 唯一新增）——Gate 5 失败时把
    // R（QC 绑定轮）/ R'（实际签名者对应轮）/ 期望 proposer / 实际签名者落到 **stderr**
    // （与本文件既有 `blockstore_stage` 同款先例）。**仅观测**：
    // - **不**改控制流（下方仍以**逐字相同**的 `map_err(RuntimeError::BlockCommit)` 传播）；
    // - **不**改错误值 / 退出码 / 状态 / 存储 / 轮次 / proposer / QC / finality / sync；
    // - **无** round 0 兜底、无 retry、无 fallback、无忽略错误；
    // - 仅失败路径执行（成功路径零额外开销）。
    if let Err(e) = &applied
        && let Ok(x_diag) = nova_runtime::block_hash(&block)
    {
        let diag_chain_id = driver.consensus().chain_id();
        let diag_genesis = driver.consensus().genesis_hash();
        let st_round = &driver.consensus().state().round;
        let r_local = last_precommit_round_evidence(driver.consensus())
            .filter(|(_, t)| *t == x_diag)
            .map(|(r, _)| r);
        let r_hist = qc_history
            .and_then(|h| h.get(block.header.height).ok().flatten())
            .filter(|qc| qc.target == x_diag)
            .map(|qc| qc.context.round);
        let r_used = resolve_proposer_round_evidence(
            x_diag,
            r_local.map(|r| (r, x_diag)),
            r_hist.map(|r| (r, x_diag)),
        )
        .ok();
        // 实际签名者识别（**只读**：以集合内每个成员 key 复验同一 wire；不写状态、不改 block）。
        let mut actual_id = None;
        let mut actual_keys: Vec<[u8; 32]> = Vec::new();
        for v in set.validators() {
            if let Some(info) = set.info(&v.validator_id)
                && let Ok(cand) = VerifyingKey::from_bytes(&info.consensus_public_key)
                && nova_runtime::validate_block_signature(&block, &cand, diag_chain_id).is_ok()
            {
                actual_id = Some(v.validator_id);
                actual_keys.push(v.validator_id.as_bytes().to_owned());
            }
        }
        // 与「实际签名者」自洽的候选 round（= R' 的直接证据；上界有界，不猜、不写状态）。
        let mut r_matches: Vec<u64> = Vec::new();
        for r in 0..=st_round.round.saturating_add(8) {
            if let Ok(pp) = select_proposer(
                diag_chain_id,
                block.header.height.saturating_sub(1),
                r,
                &diag_genesis,
                set,
            ) && Some(pp) == actual_id
            {
                r_matches.push(r);
            }
        }
        eprintln!(
            "F1DIAG stage=gate5_apply_fail block_height={} block_hash={:02x?} parent_hash={:02x?}",
            block.header.height, x_diag, block.header.parent_hash
        );
        eprintln!(
            "F1DIAG head_height={} state_round=(h{},r{}) state_proposal={:02x?} from_local_proposal={}",
            adapter.head().height,
            st_round.height,
            st_round.round,
            st_round.proposal.as_ref().map(|p| p.block_hash),
            last_proposal.is_some_and(|pb| pb.block_hash == x_diag)
        );
        eprintln!(
            "F1DIAG qc_round_local={:?} qc_round_history={:?} round_used_R={:?} \
             rounds_matching_actual_signer={:?}",
            r_local, r_hist, r_used, r_matches
        );
        eprintln!(
            "F1DIAG expected_proposer={:02x?} actual_signer={:02x?}",
            proposer.as_bytes(),
            actual_keys
        );
        eprintln!(
            "F1DIAG chain_id={} validator_set_id={:02x?} err={}",
            diag_chain_id, diag_genesis, e
        );
    }
    applied.map_err(RuntimeError::BlockCommit)?;
    Ok(())
}

/// D10-C Step 8 — 远端**已验证** canonical-next block ⇒ durable store + 共识 DAG 登记（node orchestration）。
///
/// - 前置（调用契约）：`wire` 已经 `block_dispatch` 用**本地** `ValidatorSet` 推导期望 proposer 并完成
///   真实签名验证（verdict = `CanonicalNextCandidate`；即 `height == head.height + 1` /
///   `parent_hash == head.block_hash`）—— 本函数**不**重复评价该语义，也不信任将未验证 payload。
/// - 顺序：**durable-first**（`BlockStore::put`，同 hash 同 bytes 幂等；冲突 ⇒ `CorruptedState`）→
///   `register_block`（真实 height / parent；未知非 genesis parent ⇒ `InvalidDagReference` fail-closed）。
/// - **不** commit / **不** 推进 head / **不** 产生 finality / **不** 授予任何 vote 权限：本函数只使该
///   已到达的 canonical block 具备「可被 frozen `verify_qc`（target ∈ DAG）与 commit bridge
///   （`BlockStore.get`）消费」的前提；是否 finality / commit 仍完全由 frozen transition 与
///   `finality_commit_bridge`（finality 唯一 commit 授权）决定。
/// - proposer 推导与 `block_dispatch` / `finality_commit_bridge` **同源**（parent-height 语义：
///   `select_proposer(chain_id, height - 1, 0, genesis_hash, set)`）—— 不新造规则。
/// - Gossip 与 SyncResponse 共用本函数（统一处理；两者均先经同一 validator seam）。
fn register_remote_canonical_block(
    driver: &mut NodeConsensusDriver<DynSigner>,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    wire: &[u8],
    pending: &PendingProposalStore,
    resolved_round: Option<u64>,
    diag: &mut A11Diag,
) -> Result<(), RuntimeError> {
    let block = nova_runtime::decode_block(wire).map_err(RuntimeError::BlockDecode)?;
    let height = block.header.height;
    if height == 0 {
        // genesis / 非 canonical-next：verdict 语义保证不至此处；保守 no-op（不猜 / 不登记）。
        return Ok(());
    }
    // 登记键取**实际解码字节**重算的 hash（单一来源；不依赖 verdict 携带值）。
    let block_hash = nova_runtime::block_hash(&block).map_err(RuntimeError::BlockCodec)?;
    let chain_id = driver.consensus().chain_id();
    let genesis_hash = driver.consensus().genesis_hash();
    // PHASE 6H-A30-ROOTFIX-M3（Owner 授权）—— **register ↔ validate parity**：登记所用轮次必须与
    // validation（`block_dispatch` 两条 dispatcher）**逐字同规则** ⇒ 共用唯一 helper
    // `block_dispatch::resolve_inbound_block_round`：
    // - `qc_evidence` = **sync validation 已据以验签通过**的那一轮（`resolved_round`，调用方以同一
    //   有界 QC 证据切片 + 同一 canonical hash 解析；见 `step()` 的 `SyncBlockResponse` 分支），
    //   gossip / 本地路径为 `None` ⇒ 回退本地 `last_precommit_qc`；
    // - `proposal_evidence` = **仅已接受 proposal**（hash 严格相等）；
    // - **无绑定证据 ⇒ `header.round`**（已签名 / 已被 block hash 承诺）——**不再**回退 round 0。
    //
    // ⚠️ **pending arrival 轮不再作为轮来源**（旧 U4/OD-20 语义）：arrival 轮是“本节点**何时**收到
    // 该提案”，与“proposer **生产**该块时的轮”可合法不同（例：round 2 的块在本地 round 5 到达）
    // ⇒ 用它作轮来源会得到**与签名者不符**的 proposer 标签（进而 `put_verified` ⇒ `CorruptedState`
    // ⇒ 进程致命退出）。现改为：**仅作一致性观测计数**（`block_arrival_round_mismatch`），
    // 不参与任何判定 —— 持久化的 proposer 标签由下方**登记前签名自验**保证自洽。
    //
    // ⚠️ 高度语义不变（仍为父高轮 `height - 1`）；`select_proposer` 语义不变。
    let qc_evidence = resolved_round
        .map(|r| (r, block_hash))
        .or_else(|| last_precommit_round_evidence(driver.consensus()));
    let proposal_evidence = proposal_round_evidence(
        driver.consensus().state(),
        adapter.head().height,
    )
    .filter(|(_, h)| *h == block_hash);
    let header_round = block.header.round;
    let Ok(round) = resolve_inbound_block_round(
        block_hash,
        header_round,
        proposal_evidence,
        qc_evidence,
    ) else {
        // 绑定证据冲突 ⇒ 保守 no-op（不登记 / 不写存储 / **不**致命退出）。
        diag.block_register_round_conflict = diag.block_register_round_conflict.saturating_add(1);
        return Ok(());
    };
    // arrival 轮仅作**一致性观测**（不参与判定；见上方说明）。
    if let Some(entry) = pending.get(&block_hash)
        && entry.arrival_round != round
    {
        diag.block_arrival_round_mismatch = diag.block_arrival_round_mismatch.saturating_add(1);
    }
    let proposer = select_proposer(
        chain_id,
        height.saturating_sub(1),
        round,
        &genesis_hash,
        driver.consensus().validator_set(),
    )
    .map_err(RuntimeError::DagRegister)?;
    // durable-first：与本地 proposal 路径同语义（幂等；不推进 head / state）。
    //
    // P1-A.20-C Phase 2：改用 **verified multi-encoding** 写入 —— `proposer` 来自上文
    // **绑定证据**解析结果，`expected_vk` 来自**既有** ValidatorSet；storage 复验签名后才落盘
    // （zero-persist）。⚠️ `proposer` 仍然仅写入 storage 的**索引标签**，不写 round。
    let set = driver.consensus().validator_set();
    let Some(info) = set.info(&proposer) else {
        // proposer 不在集合（装配不一致）⇒ 保守 no-op（不落盘 / 不登记；不猜 / 不伪造）。
        return Ok(());
    };
    let Ok(vk) = VerifyingKey::from_bytes(&info.consensus_public_key) else {
        return Ok(());
    };
    // **登记前签名自验**（Owner 要求 B.4 / B.5）：解析轮 ⇒ 该轮当选 proposer 的 key；
    // 若签名与该 key 不符 ⇒ 说明**本节点的轮派生**与真实签名者不一致（非存储损坏）⇒
    // **保守 no-op**（不落盘 / 不登记 / 计数），**绝不**让本地标签错误经 `put_verified` 变成
    // `CorruptedState` 致命退出。真实存储错误仍由下方 `blockstore_stage` fail-closed 透传。
    if nova_runtime::validate_block_signature(&block, &vk, chain_id).is_err() {
        diag.block_register_label_mismatch = diag.block_register_label_mismatch.saturating_add(1);
        return Ok(());
    }
    let max_encodings = set.len();
    if let Some(bs) = adapter.block_store() {
        bs.put_verified(&block, proposer.as_bytes(), &vk, chain_id, max_encodings)
            .map_err(|e| blockstore_stage(&format!("remote_canonical_put height={height}"), e))?;
    }
    driver
        .consensus_mut()
        .register_block(block_hash, height, block.header.parent_hash, proposer)
        .map_err(RuntimeError::DagRegister)?;
    Ok(())
}

/// D9 Step 7 — 入站 listener 前半段（accept → KEEP-FIRST 判定 → connect → 本端 Handshake Init）。
///
/// - accept 由 node-only multiplex 执行（nonblocking；每 step ≤ `MAX_ACCEPT_PER_STEP`；达连接
///   上限立即关闭不注册）——**不在** `NetworkService` 内、**不改** frozen transport。
/// - **KEEP-FIRST**：peer 已 `connected` 或已 `Established` ⇒ 丢弃新入站连接（不替换 / 不迁移
///   session / 不断开既有）——与 frozen `dial_peer` 的 `AlreadyConnected` 拒绝语义一致。
/// - `connect_peer` 只标记 **connected**（**≠ 认证**）：唯一目的满足 frozen `enqueue_outbound`
///   的 connected 前置。**Established 仍然只能来自 frozen `process_handshake`**
///   （本函数不新增任何认证 / session / replay 逻辑）。
/// - 本端 Handshake Init 复用既有 `build_outbound_handshake`（同 network/chain/genesis/protocol /
///   新 nonce / real envelope 签名 / `MessageType::Handshake` 豁免路径）；**每连接恰好一次**
///   （不重发 ⇒ 不消耗 frozen per-peer handshake rate limit）。
/// - 无 `Err` 传播：入站维护失败只计数（不中断共识 step；与既有 egress `let _ =` 一致）。
fn inbound_accept_and_greet(
    inbound: Option<&InboundListenerState>,
    ns: &mut NetworkService<BoxTransport>,
    signer: &dyn NetworkSigner,
    pending: &mut BTreeMap<[u8; 32], u64>,
    tick: u64,
) {
    let Some(inbound) = inbound else {
        return;
    };
    for peer in inbound.accept_bounded() {
        if ns.is_connected(peer) || ns.is_peer_established(peer) {
            // NETDIAG：KEEP-FIRST 丢弃（**仅**区分原因计数；行为与 `drop_peer` 逐字相同）。
            let _ = inbound.drop_peer_reason(peer, InboundDropReason::GreetKeepFirst);
            continue;
        }
        if ns.connect_peer(peer).is_err() {
            let _ = inbound.drop_peer_reason(peer, InboundDropReason::GreetConnectFailed);
            continue;
        }
        if let Some(auth) = ns.config().peer_auth
            && let Ok(env) = NodeRuntime::build_outbound_handshake(signer, &auth)
            && ns.enqueue_outbound(peer, env).is_ok()
        {
            let _ = ns.flush_outbound();
        }
        pending.insert(peer_key(&peer), tick);
    }
}

/// D9 Step 7 — 入站 listener 后半段（EOF 清理 + pending 状态机）；**poll 之后**调用。
///
/// 1. EOF / 读错误 / 写失败关闭 ⇒ 移除连接 + `disconnect_peer`（session / connected 同步清理
///    ⇒ 无 stale connected / established / transport）。
/// 2. pending：`Established` ⇒ 完成（保留连接 —— 它就是 consensus 出站路由）；
///    被 frozen `close_peer`（认证失败：`sessions.remove` + `peers.disconnect`）⇒ 回收连接 +
///    移出 pending；超过 `INBOUND_PENDING_TIMEOUT_STEPS` ⇒ 回收连接 + `disconnect_peer`。
/// - 无 `Err` 传播（入站维护不得中断共识 step）。
fn inbound_reconcile(
    inbound: Option<&InboundListenerState>,
    ns: &mut NetworkService<BoxTransport>,
    pending: &mut BTreeMap<[u8; 32], u64>,
    tick: u64,
) {
    let Some(inbound) = inbound else {
        return;
    };
    for peer in inbound.sweep_closed() {
        let _ = ns.disconnect_peer(peer);
        pending.remove(&peer_key(&peer));
    }
    let peers: Vec<NodeId> = pending.keys().map(|k| NodeId::from_bytes(*k)).collect();
    for peer in peers {
        let key = peer_key(&peer);
        let Some(accepted_tick) = pending.get(&key).copied() else {
            continue;
        };
        if ns.is_peer_established(peer) {
            pending.remove(&key);
            continue;
        }
        if !ns.is_connected(peer) {
            // frozen 握手失败路径（`close_peer`）⇒ 回收入站连接（不残留 pending）。
            let _ = inbound.drop_peer_reason(peer, InboundDropReason::HandshakeFailed);
            pending.remove(&key);
            continue;
        }
        if tick.saturating_sub(accepted_tick) > INBOUND_PENDING_TIMEOUT_STEPS {
            let _ = inbound.drop_peer_reason(peer, InboundDropReason::PendingTimeout);
            let _ = ns.disconnect_peer(peer);
            pending.remove(&key);
        }
    }
}

/// NodeRuntime 启动错误（node-local；typed；fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRuntimeError {
    /// D9 Step 7：入站 listener 绑定失败（bind / nonblocking；fail-closed）。
    InboundListener(InboundListenerError),
    /// genesis / storage / identity 校验失败（复用 bootstrap NodeStartupError）。
    Startup(NodeStartupError),
    /// validator mode 但未提供 KeyProvider（fail closed：不默认生成不稳定密钥）。
    KeyNotProvisioned,
    /// KeyProvider 加载 signer 失败。
    KeyProvider(KeyProviderError),
    /// SafetyStore create / recover / identity 校验失败。
    Safety(ValidatorSafetyError),
    /// G5-D.7.2：validator safety journal **缺失**且未声明显式初始化 ⇒ fail closed。
    ///
    /// 语义（可诊断；**不**伪装为普通 IO failure）：
    /// *Safety journal is missing; validator startup requires explicit safety
    /// initialization or restoration from backup.*
    /// 初始化（`validator_safety_init = true`）建立的是**新的**安全状态，不是恢复。
    SafetyJournalMissing,
    /// G5-D.7.2：已声明显式初始化但 safety journal **已存在** ⇒ 拒绝（既有历史保持不变）。
    SafetyJournalAlreadyExists,
    /// **D-5.3.4**：B2-B signer-owned Block safety journal（`block-safety.journal`）
    /// create / recover / 校验失败（fail-closed；validator mode 启动失败）。
    BlockSafety(BlockSafetyError),
    /// ValidatorActor 构造 / 恢复失败（含 identity mismatch）。
    Validator(ValidatorActorError),
    /// configured connection target 校验失败（self / duplicate；dial **前** fail-closed）。
    NetworkTarget(ConnectionTargetError),
}

/// Runtime 运行期错误（Stage C `step`；分层、不吞错、不改底层语义）。
#[derive(Debug)]
pub enum RuntimeError {
    /// EventLoop / Network 错误（poll/dispatch 层；NS 错误经 `EventLoopError::Network` 内嵌）。
    EventLoop(EventLoopError),
    /// Driver 验证 / transition 门面失败（与网络错误分层 —— 不伪装成 NetworkError）。
    Driver(DriverError),
    /// Node Egress 网络签名失败（fail-closed；不吞安全错误）。
    Egress(crate::egress::EgressError),
    /// Node-local Proposer orchestration 失败（selection / block build / head；fail-closed）。
    Proposer(ProposerError),
    /// ValidatorActor 出块签名失败（`sign_block`；fail-closed）。
    Validator(ValidatorActorError),
    /// outbound dial 失败（NetworkServiceError 透传；不自动 retry / 不自动换 peer）。
    NetworkDial(NetworkServiceError),
    /// handshake 构造 / nonce 生成失败（session 域 typed 错误）。
    Session(SessionError),
    /// outbound handshake envelope 签名失败（network identity 域）。
    NetworkSigning(NetworkSigningError),
    /// NetworkService 未装配 peer-auth（handshake 编排前置缺失；fail-closed）。
    PeerAuthMissing,
    /// authenticated remote NodeId ≠ configured peer_id（address 正确 ≠ identity 正确）。
    IdentityMismatch { configured: NodeId },
    /// sync RequestId 生成失败（OS CSPRNG 不可用；fail-closed —— 不退回弱随机）。
    NetworkSecurity(NetworkSecurityError),
    /// 本地已验证 canonical block 登记进共识 DAG 失败（DAG 一致性；Consensus 域）。
    DagRegister(nova_consensus::error::ConsensusError),
    /// Finality → Commit：`apply_block`（冻结 ①~⑥ durable commit 管线）失败 ⇒ fail-closed
    /// （head 不推进 / 无 partial canonical commit —— adapter 保证）。
    BlockCommit(NodeBlockApplicationError),
    /// Finality → Commit：本地 finalized block 编码 wire 失败（结构错误；几乎不可达）。
    BlockCodec(nova_runtime::BlockCodecError),
    /// D10-C Step 4：BlockStore node 层访问失败（本地 proposal durable put / bridge resolve get）。
    BlockStore(StorageError),
    /// D10-C Step 8：远端 canonical block wire decode 失败（结构错误；fail-closed —— 不落盘 / 不登记）。
    BlockDecode(nova_runtime::BlockPipelineError),
    /// D10-C Step 4：Finality Recovery Fact 持久化失败（durable-before-bridge；fail-closed）。
    FinalityFact(NodeStartupError),
}

/// `establish_configured_peer` 单次推进后的握手判定（Node 只编排；session 验证归 NetworkService）。
#[derive(Debug, PartialEq, Eq)]
enum HandshakeOutcome {
    /// configured peer 已认证（Established）且身份匹配。
    Established(NodeId),
    /// 尚未收到对端合法握手（后续 step 再推进；不重发 / 不重 dial）。
    Pending,
    /// 收到其它 peer 的合法握手（identity mismatch；fail-closed 断开）。
    ForeignEstablished(Vec<NodeId>),
}

/// 单个 configured peer 的建立状态（STEP 10-19-10-B7-A1-D7-Implementation-3；每 peer 独立）。
#[derive(Debug)]
pub enum PeerStatus {
    /// 已认证（Established）且身份匹配（不重复 dial / 不重复 Init）。
    Established,
    /// 尚未（已 dial / 已发 Init 或等待对端握手；后续轮再推进）。
    Pending,
    /// 本 peer 建立失败（dial / Init / 签名 typed error；**不阻塞其它 peer**）。
    Failed(RuntimeError),
    /// P1-A.8 — 该 peer 处于**重连退避**中（本轮**未 dial**；逻辑 tick 门控；不阻塞其它 peer）。
    ///
    /// `failure_count` = 连续失败次数（saturating ≤ 12）；`remaining_ticks` = 距离下次允许尝试的
    /// 剩余逻辑 tick（`next_allowed_attempt_tick - peer_tick`，≥ 1）。首次 dial **不会**进入本状态
    /// （无 state ⇒ 立即尝试）；dial **成功**后失败历史被清除。
    Backoff {
        /// 连续 dial/准备失败次数（saturating ≤ 12）。
        failure_count: u32,
        /// 距离下次允许 dial 的剩余逻辑 tick（≥ 1）。
        remaining_ticks: u64,
    },
    /// 网络未启用（无 NetworkStack）。
    Unavailable,
}

/// 单个 configured peer 的建立结果（peer_id + 独立状态；D7-Implementation-3）。
#[derive(Debug)]
pub struct PeerEstablishment {
    pub peer_id: NodeId,
    pub status: PeerStatus,
}

/// P1-A.8 — per-peer 重连退避状态（node-local；**纯整数逻辑 tick**，无墙钟）。
///
/// 仅当该 peer 出现**真正的失败**（dial / 准备错误；**不含** `AlreadyConnected` 幂等信号）时插入；
/// dial 成功 ⇒ 移除（失败历史清零，下一失败序列从 0 起）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLifecycleState {
    /// 连续失败次数（saturating ≤ [`MAX_FAILURE_COUNT`]）。
    pub failure_count: u32,
    /// 下次允许 dial 的逻辑 tick（`peer_tick` 达此值才允许重试）。
    pub next_allowed_attempt_tick: u64,
}

/// P1-A.8 — 退避延迟（逻辑 tick）。
///
/// 冻结公式：`delay(n) = min(BASE_BACKOFF_TICKS << min(n - 1, BACKOFF_SHIFT_CAP), MAX_BACKOFF_TICKS)`
///
/// ```text
/// 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096, …
/// ```
/// `n == 0` ⇒ 0（无失败 ⇒ 无延迟）。使用 `checked_shl` + `min` + 入口饱和 ⇒ **无 panic /
/// 无位移溢出 / 无无界增长**。
fn backoff_delay_ticks(failure_count: u32) -> u64 {
    if failure_count == 0 {
        return 0;
    }
    let shift = failure_count.saturating_sub(1).min(BACKOFF_SHIFT_CAP);
    BASE_BACKOFF_TICKS
        .checked_shl(shift)
        .unwrap_or(MAX_BACKOFF_TICKS)
        .min(MAX_BACKOFF_TICKS)
}

/// P1-A.8 — 单 peer 在本轮 `establish_configured_peers()` 中的处理结果（内部）。
enum PeerStep {
    /// 已执行既有 `establish_prepare`（`Some` = 该 peer 本轮失败；`None` = 正常/幂等）。
    Prepared(Option<RuntimeError>),
    /// 本轮**未 dial**：失败后处于退避（或 dial 刚失败并进入退避）。
    Backoff(PeerLifecycleState),
    /// 本轮**未 dial**：dial 预算已用尽（非退避；后续轮再试）。
    Deferred,
}

/// Runtime 关闭错误（Stage C `shutdown`；仅 Storage 可失败 ——
/// EventLoop/NetworkService shutdown 均 infallible，Driver 无显式 shutdown）。
#[derive(Debug)]
pub enum ShutdownError {
    /// ChainStorage 关闭失败（`PersistentBackend::close`）。
    Storage(StorageError),
}

/// Stage C 网络子栈（最小 owned container；非 factory / provider / framework）。
///
/// - `ns`：网络状态 owner（own `Transport` / peers / queues；内部经 `Box<dyn Transport>` 注入）。
/// - `el`：dispatch-only（own handler / queue / timer；**不拥有** `ns` —— poll 经注入借用）。
/// - `signer`：网络身份（NodeId + envelope 签名；与 validator identity 分离）。
struct NetworkStack {
    ns: NetworkService<BoxTransport>,
    el: EventLoop<NodeConsensusHandler>,
    signer: Box<dyn NetworkSigner>,
    /// D9 Step 7：入站 listener（`None` = 未启用：`NodeConfig::listen_addr = None`）。
    /// 与注入 `ns` 的 `InboundMultiplexTransport` **共享同一状态**（单线程 `Rc<RefCell<..>>`）。
    inbound: Option<InboundListenerState>,
}

impl NetworkStack {
    /// 本网络身份 NodeId（= 网络 key pubkey；≠ ValidatorId）。
    fn node_id(&self) -> NodeId {
        self.signer.node_id()
    }
}

/// 单验证者只读 **compatibility view**（STEP 10-18I-C；非 owning）。
///
/// - ValidatorActor 的真正 ownership 在 [`NodeConsensusDriver`]（`actors: Vec<ValidatorActor<DynSigner>>`）。
/// - [`NodeRuntime::validator`] 在调用时**动态构造**本 view（含对 `driver.actor(0)` 的借用），
///   避免 self-referential ownership；不长期存储 actor 引用字段。
pub struct ValidatorView<'a> {
    validator_id: ValidatorId,
    journal_path: &'a std::path::Path,
    actor: &'a ValidatorActor<DynSigner>,
}

impl ValidatorView<'_> {
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// 本地 ValidatorActor（只读；safety/signing owner 在 actor —— 经 driver 拥有）。
    pub fn actor(&self) -> &ValidatorActor<DynSigner> {
        self.actor
    }

    pub fn journal_path(&self) -> &std::path::Path {
        self.journal_path
    }
}

/// PHASE 6H-A30 OD-X7 — **只读** liveness 观测快照（供 CLI 独立 `liveness` 行）。
///
/// **不参与任何判定**（零共识语义）；全部为 saturating 计数或只读派生。
/// 不保留 payload / hash / 签名 / 对端身份 / 错误文本。
/// `prop_skip_fail` 为**残差**（`calls − ok − known_skips`）：**不**推断未知原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessSnapshot {
    /// 提案构造**调用**总数（含所有跳过路径）。
    pub prop_calls: u64,
    /// 成功构造**并提交**提案次数。
    pub prop_build_ok: u64,
    /// 因"非当选者"跳过（只读复算）。
    pub prop_skip_not_elected: u64,
    /// 因 `rs.height != head.height` 跳过（只读复算）。
    pub prop_skip_height_desync: u64,
    /// 因阶段/幂等守卫（`step != Propose` 或已有提案）跳过（只读复算）。
    pub prop_skip_step_guard: u64,
    /// **SAFETY-REJECT-SKIP** — 出块签名被 `block_safety` 冲突门正确拒绝（F2/F3/F4
    /// `ConflictingTarget`）⇒ 该次提案被放弃（不签名 / 不广播），节点继续运行（非 fatal）。
    pub prop_skip_conflict_target: u64,
    /// **残差**跳过（含 `build_block` 失败 / 无 adapter / 无 actor / 持久化失败等）。
    pub prop_skip_fail: u64,
    /// 入站**成功解码并消费**的提案数。
    pub inbound_prop_ok: u64,
    /// 本地提案被登记出站（`record_local_proposal`）次数。
    pub egress_prop_enqueued: u64,
    /// PHASE 6H-A30 OD-X8 — 本地提案**有界重播**实际入队次数（逐字节相同的 `ProposalRef`
    /// + wire block；`<= MAX_PROPOSAL_REFRESH x 本地提案数`）。
    pub egress_prop_refreshed: u64,
    /// 单发广播**提案**时 `Established 对端 = 0`（静默丢弃）次数。
    pub egress_prop_no_peer: u64,
    /// 本地 pacemaker **实际**推进 round 的次数。
    pub round_adv_local: u64,
    /// 因高度推进（`advance_to_height`）导致 round 归零的次数。
    pub round_adv_height: u64,
    /// 经 RC 权威推进 round 的次数（= 既有 `round_changes_by_authority`，**仅暴露**）。
    pub round_adv_rc: u64,
    /// 当前 `(height, round)` 当选者是否本节点（只读派生；无法判定 ⇒ `false`）。
    pub elected_is_self: bool,
    /// 当前 `(height, round)` 内 `proposal_present == false` 的**连续 step** 数（瞬态）。
    pub prop_absent_steps: u64,
    /// PHASE 6H-A30 OD-X7b — **入站 proposal admission 生命周期**（直接读取既有真实计数槽位；
    /// **不**新增增量点、**不**根据结果猜测）：
    /// `PendingProposalStore::admitted` —— `guard_inbound_proposal` 中 Guard A2 + Guard C
    /// 全部通过（`note_admitted()`）的次数。
    pub proposal_admitted: u64,
    /// `PendingProposalStore::pended` —— Guard A1 `Ok(false)`（区块未本地可用）且
    /// `insert` 返回 `Inserted`（`note_pended()`）的**首次**入 pending 次数。
    ///\n    /// 语义：**累计决策结果**，非当前队列长度（队列长度见 `pending_proposals_len()`）。
    pub proposal_pending: u64,
    /// `PendingProposalStore::rejected` —— 准入拒绝累计（`note_guard_reject()` 直拒 +
    /// `note_rejected()` recovery 拒；两者均走真实代码路径）。按原因明细仍在
    /// `a11_diag_summary()`（本行不重复暴露）。
    pub proposal_rejected: u64,
    /// `PendingProposalStore::expired` —— `sweep_expired()` 确定性 tick 到期淘汰次数。
    pub proposal_expired: u64,
    /// PHASE 6H-A30 OD-X7d — **只读** egress→ingress 黑洞定位面（直读既有
    /// `NetworkService::diagnostics()` / `EventLoop::diagnostics()`；无网络时全 0）。
    /// **不**新增计数器 / **不**新增状态机 / **不**改变 send-receive-queue 控制流。
    pub net_frames_received: u64,
    pub net_events_enqueued: u64,
    pub net_sent: u64,
    pub net_dropped_invalid: u64,
    pub net_dropped_overflow: u64,
    pub net_unauthenticated_drops: u64,
    pub el_handler_errors: u64,
    pub el_events_dropped_overflow: u64,
    /// PHASE 6H-A30 OD-X7e — **recovery / block readiness 面**（直读既有 `A11Diag` 字段；
    /// **不**新增计数点 / **不**修改 recovery 逻辑 / **不**修改 guard / **不**修改 pending store）。
    pub recovery_runs: u64,
    pub recovery_candidates: u64,
    pub recovery_kept_missing_block: u64,
    pub recovery_admitted: u64,
    pub recovery_rejected: u64,
    pub block_inbound_processed: u64,
    pub block_canonical_next: u64,
    pub block_register_ok: u64,
    /// PHASE 6H-A30 OD-X7f — **`InboundBlockVerdict` 分类面**（只读：对**既有**
    /// [`NodeRuntime::block_inbound_outcomes`] 窗口（≤ `BLOCK_INBOUND_OUTCOME_CAP` = 128）
    /// 做分类计数；**不**新增计数器 / **不**新增状态机 / **不**修改任何判定）。
    ///
    /// 语义（MUST）：**窗口内**（最近 ≤128 条）分类，**非**累计；六项之和 == 窗口长度。
    /// `other` 为**残差**（含 `CanonicalNextCandidate` 与其余 `InboundBlockError` 变体）。
    pub block_verdict_future_missing_ancestor: u64,
    pub block_verdict_already_known: u64,
    /// 真实变体为 `Stale`（**无** `Duplicate` 变体；不得虚构）。
    pub block_verdict_stale: u64,
    /// 真实变体为 `ConflictingParent`（**无** `UnknownTarget` 变体；不得虚构）。
    pub block_verdict_conflicting_parent: u64,
    /// `Err(InboundBlockError::Malformed)`。
    pub block_verdict_malformed: u64,
    /// **残差**（窗口长度 − 上述五类）。
    /// PHASE 6H-A30 OD-X7g 起语义**收紧**：再减去下列 `block_err_*` 十类 ⇒
    /// 本项 == 窗口内 `Ok(CanonicalNextCandidate)` 数（避免与新键重复计数）。
    pub block_verdict_other: u64,
    /// PHASE 6H-A30 OD-X7g — `Err(InboundBlockError)` **细分类**（真实变体 1:1；
    /// `block_inbound.rs:112-137`；仍为**窗口内**计数，非累计）。
    /// 不变量：`5 个 Ok 类 + malformed + 上述 10 类 + other` == 窗口长度。
    pub block_err_oversized: u64,
    pub block_err_wrong_version: u64,
    pub block_err_wrong_chain: u64,
    pub block_err_hash_mismatch: u64,
    pub block_err_invalid_proposer_signature: u64,
    pub block_err_transaction_root_mismatch: u64,
    pub block_err_noncanonical_transaction_ordering: u64,
    pub block_err_state_root_mismatch: u64,
    pub block_err_unsupported_validation: u64,
    pub block_err_storage: u64,
    /// PHASE 6H-A30-OD-X7h — **入站 block 来源类别**（`GossipBlock` vs `SyncBlockResponse`）
    /// 的 `InvalidProposerSignature` 归属面。
    ///
    /// 语义（MUST）：**累计**（非窗口），bounded + saturating；数据源 = `step()` 内**既有**
    /// `source`（既有 match 分支已决定）+ 该块**既有** verdict（不重新执行 validation）。
    /// 一致性关系：`block_src_gossip_invalid_proposer_signature +
    /// block_src_sync_invalid_proposer_signature` == 累计 `InvalidProposerSignature` 判定数；
    /// 当判定总数 ≤ `BLOCK_INBOUND_OUTCOME_CAP`（128）时 == 窗口内 `block_err_invalid_proposer_signature`。
    pub block_src_gossip_total: u64,
    pub block_src_gossip_invalid_proposer_signature: u64,
    pub block_src_sync_total: u64,
    pub block_src_sync_invalid_proposer_signature: u64,
    /// PHASE 6H-A30-OD-X7i — **Gossip 路径 `InvalidProposerSignature` 来源分类**（累计，非窗口）。
    ///
    /// gossip dispatcher 固定顺序：① `resolve_proposer_round_evidence`（证据轮冲突 ⇒ 直接 IPS）
    /// → ② `validate_block_inbound` ⑦c `validate_block_signature`（验签失败 ⇒ IPS）。
    /// 因此在**同一输入**上只读复算①即可**精确**归类：① Err ⇒ 本项 +1；① Ok ⇒ 只能是②。
    /// **不**执行验签 / **不**新增 proposer·consensus·validation state / **不**改变控制流。
    pub block_gossip_invalid_proposer_signature_evidence_conflict: u64,
    pub block_gossip_invalid_proposer_signature_signature_failure: u64,
}

/// PHASE 6H-A30 OD-X7 — 内部累计计数器（**不参与任何判定**；零共识语义）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LivenessObservability {
    prop_calls: u64,
    prop_build_ok: u64,
    prop_skip_not_elected: u64,
    prop_skip_height_desync: u64,
    prop_skip_step_guard: u64,
    /// SAFETY-REJECT-SKIP — 出块签名被 `block_safety` 冲突门正确拒绝而放弃的提案数。
    prop_skip_conflict_target: u64,
    inbound_prop_ok: u64,
    egress_prop_enqueued: u64,
    /// PHASE 6H-A30 OD-X8 — 本地提案**有界重播**实际入队次数（`<= 3 x 本地提案数`）。
    egress_prop_refreshed: u64,
    egress_prop_no_peer: u64,
    round_adv_local: u64,
    round_adv_height: u64,
    // 瞬态（每 step 由 [`observe_liveness_transient`] 重算）
    elected_is_self: bool,
    prop_absent_steps: u64,
    prop_absent_key: (u64, u64),
}

impl LivenessObservability {
    /// 残差跳过（`calls − ok − known_skips`；saturating ⇒ 恒 ≥ 0）。
    fn skip_fail(&self) -> u64 {
        self.prop_calls
            .saturating_sub(self.prop_build_ok)
            .saturating_sub(self.prop_skip_not_elected)
            .saturating_sub(self.prop_skip_height_desync)
            .saturating_sub(self.prop_skip_step_guard)
            .saturating_sub(self.prop_skip_conflict_target)
    }
}

/// 生产节点生命周期装配根（STEP 10-16 Phase 1 骨架；STEP 10-18I-C ownership migration；
/// STEP 10-18I-G Stage C Full Composition）。
///
/// - **ConsensusNode + ValidatorActor 的实际 ownership 在 [`NodeConsensusDriver`]**（`driver` 字段）；
///   Runtime **不再**独立持有 ConsensusNode / ValidatorActor（避免 duplication，ADR-0057）。
/// - 网络（NetworkService / EventLoop / NetworkSigner）以可选 [`NetworkStack`] 装配：
///   `start()` ⇒ `None`（网络 disabled，不生成网络身份）；`start_with_network()` ⇒ `Some`。
/// - Runtime 只负责 composition / lifecycle / accessor delegation（最终 lifecycle coordinator）。
pub struct NodeRuntime {
    chain_identity: ChainIdentity,
    /// chain storage owner（full-node 形态：Phase 1 裸 PersistentBackend handle）。validator ⇒ `None`。
    chain_storage: Option<PersistentBackend>,
    /// validator-mode 形态：bootstrap 装配的 NodeBlockAdapter（canonical StateStore + ChainHead +
    /// genesis 参数单一 owner；BlockBuilder 只读出块输入）。full-node ⇒ `None`。
    block_production: Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    driver: NodeConsensusDriver<DynSigner>,
    /// 可选网络子栈（Stage C；`start` ⇒ `None`）。
    network_stack: Option<NetworkStack>,
    /// 静态 configured connection targets（STEP 10-19-10-B7-A3；来自 `config.peers`）。
    configured_targets: Vec<ConnectionTarget>,
    /// 已为各 configured peer 发送过 outbound Handshake Init 的集合（per-peer；防重复发送）。
    /// D7-Implementation-3：每 peer 独立 —— disconnect(A) 只清 A，不影响 B/C。
    handshake_init_sent_for: HashSet<NodeId>,
    /// validator 元数据（safety journal 路径；actor 本体在 driver）。full-node ⇒ `None`。
    validator_journal: Option<PathBuf>,
    /// step-driven proposer 出块的显式 timestamp（默认 0；无系统时钟；调用方可配置）。
    proposal_timestamp: u64,
    /// 最近一次本地出块产物（本地保留；不持久化 / 不推进 head）。
    last_proposal: Option<ProposalBuild>,
    /// D10-C Step 4 — Finality Recovery Fact 文件路径（chain storage 目录；durable-before-bridge）。
    finality_fact_path: PathBuf,
    /// D10-C Step 4 / **D11-25** — 已**处理**的 finality reference（幂等：避免每 tick 重写同一 fact）。
    ///
    /// D11-25（Model B）语义：`persist_finality_fact` 在「既有 durable evidence 更高」时**不写**
    /// 并返回 `Ok`（非致命跳过）⇒ 本标记含义 = 「该 reference 已被评估/处理」，
    /// **不**等价于「该 reference 已在 fact 文件中」。
    finality_fact_persisted: Option<[u8; 32]>,
    /// 协议最大块字节（来自 genesis `protocol_parameters`；block inbound validation 上限；
    /// 不修改协议参数 —— 只读供 `block_dispatch` context 使用）。
    max_block_bytes: usize,
    /// block inbound dispatch 的 typed 观测（STEP 10-19-10-A；bounded，满则丢最早）。
    /// 只读验证结果；**不 commit / 不写存储 / 不推进 head**。
    block_inbound_outcomes: VecDeque<Result<InboundBlockVerdict, InboundBlockError>>,
    /// 无 canonical 上下文（full-node / 无 adapter）而跳过的 block inbound payload 数。
    block_inbound_skipped: u64,
    /// missing-ancestor intent ledger（STEP 10-19-10-B1；bounded + dedup）。
    /// 仅记录 `FutureMissingAncestor` 观察；**不发送 / 不写存储 / 不触发 finality**。
    missing_ancestor_ledger: MissingAncestorIntentLedger,
    /// outbound sync request scheduler（D8-2；bounded FIFO；不拥有 transport）。
    sync_scheduler: SyncRequestScheduler,
    /// outbound sync request correlator（D8-2；register/resolve/timeout 状态机；不拥有 transport）。
    sync_correlator: SyncRequestCorrelator,
    /// sync 编排确定性逻辑 tick（每网络 step 自增；D8-3-1 驱动 expire_at release-only）。
    sync_tick: LogicalTick,
    /// 收到且 correlation 成功的 SyncBlockResponse 数（request lifecycle 完成；观测）。
    sync_resolved_responses: u64,
    /// 收到但无对应 active request / 结构损坏而被拒的 SyncBlockResponse 数（Unknown；观测）。
    sync_unknown_responses: u64,
    /// P1-A.4：**入站（peer 提供）** consensus command 被 Driver 拒绝的计数（观测）。
    ///
    /// 只统计 `take_commands() → process_command(..)` 这条**网络来源**路径；本地路径
    /// （`drive_local_consensus` / proposer / commit bridge / DAG 登记 / egress）仍 fail-closed
    /// —— P1-A.5 的**唯一**本地例外是「派生 QC target ∉ 本节点 DAG」（`UnknownTarget`，
    /// 语义 = 不适用），由 [`Self::derived_qc_not_applicable`] 单独计数（**不**并入本计数）。
    /// 拒绝 = 该命令**零 canonical 变更**（driver verify-then-transition；无 lock / 无 outbound）。
    inbound_consensus_rejected: u64,
    /// P1-A.5：**本地/派生**路径上「派生 QC 的 target 当前不在本节点 DAG」的次数（观测）。
    ///
    /// 语义 = `DriverError::QcVerification(FinalityError::UnknownTarget)` ⇒ **不适用**（非有效 QC、
    /// 非运行错误）：零状态变更（无 lock / 无 outbound / 无 canonical / 无 finality / 无 DAG 修改）。
    /// 仅 `u64` 计数（saturating **不保留** QC payload / target hash / 签名 / 对端身份 / 错误文本）。
    derived_qc_not_applicable: u64,
    /// P1-A.6 / A3 — round timeout 窗口参数（**单调时长：毫秒**；默认 `RoundTimeoutConfig::default()`）。
    ///
    /// node-local 配置面：非协议常量（ADR-0049 §3.5）、非 CLI flag、不进 `NodeConfig`、不持久化。
    /// A3：单位从"逻辑 step tick"改为**毫秒**（授权 Testnet 基线 10_000 / 120_000 / ×2 ⇒
    /// 10s→20s→40s→80s→120s→120s…）。
    round_timeout_config: RoundTimeoutConfig,
    /// A3 — 单调时钟（生产 = [`SystemClock`]；测试经 [`Self::set_clock`] 注入 [`FakeClock`]）。
    ///
    /// **不**作为任何共识判定输入；只用于本地计时器到期判断（与墙钟无关联）。
    clock: Box<dyn MonotonicClock>,
    /// A3 — 本 step 读取到的单调读数（纳秒；供**只读诊断** accessor 使用，**不**参与判定）。
    ///
    /// 目的：`round_timeout_elapsed_ms()` 不得为了读数而额外读时钟（否则会干扰注入式 fake
    /// 时钟的时间轴）；它报告的永远是**最后一次 `step()`** 的已历时。
    last_tick_ns: u64,
    /// P1-A.6 — 当前 `(height, round)` 的本地计时器（`None` = 尚未 arm / 已被 finality disarm）。
    /// **只**含位置 + tick 计数（无 payload / 无 hash / 无签名 / 无对端材料）。
    round_timer: Option<RoundTimer>,
    /// P1-A.6 — 本地 round timeout 触发次数（saturating；诊断观测，不携带任何共识材料）。
    round_timeouts: u64,
    /// PHASE 6H-Z（Owner D1-3 / G-2）— **权威驱动** round 变更次数（独立归因；saturating）。
    ///
    /// 仅在「已验证 `RoundChangeCertificate` 且 `from_round == local_round` ⇒ 应用 ⇒ 恰 +1」
    /// 时递增。**与 [`Self::round_timeouts`] 严格分离**（本地超时 ≠ 外部权威；
    /// ADR-0072 §3.4 有限附随语义效果；**不**改变 `round_timeouts` 既有语义）。
    round_changes_by_authority: u64,
    /// PHASE 6H-Z — 入站 RC 被拒次数（fail-closed 观测；saturating）。
    round_changes_rejected: u64,
    /// PHASE 6H-Z — G-1 暂存区「**新增 − 重评应用**」计数（gauge；`Duplicate` 不计、store 淘汰不计）。
    round_changes_deferred: u64,
    /// P1-A.30 **D0** — RC 拒绝原因分类 + 暂存重评计数（**仅观测**；不参与任何判定）。
    round_change_diag: RoundChangeDiag,
    /// P1-A.30 **D0** — RC 证书广播时**零 Established 对端**（`broadcast()` 返回 `Ok(0)`）的次数。
    round_change_broadcast_no_peer: u64,
    /// P1-A.30 **D0** — Abandon attestation 广播时**零 Established 对端**的次数。
    abandon_broadcast_no_peer: u64,
    /// P1-A.30 **D0** — 本地 timeout 结果分类 `[applied, ignored, rejected]`。
    /// `round_timeouts` 仍为**总数**（本数组仅拆分同一批事件，**不**新增计数事件）。
    round_timeout_outcomes: [u64; RoundTimeoutOutcome::COUNT],
    /// PHASE 6H-Z — G-1 暂存区（**有界内存**：`DEFAULT_MAX_TRACKED_HEIGHTS` × 64/height；
    /// 重启即丢、**无持久化**）。**不**参与任何 consensus transition。
    round_change_store: RoundChangeStore,
    /// PHASE 6H-AF — O2 attestation 池（**有界内存**；**无持久化**；ADR-0074/0075 生产路径）。
    /// 绑定 `chain_id` + `genesis_hash`（= `validator_set_id`）。
    round_change_pool: RoundChangeAttestationPool,
    /// PHASE 6H-AF — 本地**真实 EXPIRE** 产生的 Abandon attestation 数（saturating 观测）。
    abandon_attestations_produced: u64,
    /// PHASE 6H-AF — 入站 attestation 被拒数（malformed / 验签失败 / 非成员 / 身份不符）。
    abandon_attestations_rejected: u64,
    /// PHASE 6H-AH — 已**发出**（`NetworkService::broadcast` 已入队）的本地 attestation 数
    /// （saturating 观测）。仅在池 `admit` 返回 `Recorded`（该 `(height, from_round)` **首次收录**）
    /// 时 +1 ⇒ 同一 EXPIRE 观测只产生一条 `0x0E` 出站（ADR-0074 §11 幂等语义，无新增去重状态）。
    abandon_attestations_broadcast: u64,
    /// PHASE 6H-AF — 池内组装完成并经**既有 `0x0D`** 广播的证书数（saturating 观测）。
    round_change_certificates_assembled: u64,
    /// D9 Step 7：入站 listener 逻辑 step 计数（每网络 step +1；pending 超时基准；无系统时钟）。
    inbound_tick: u64,
    /// PHASE 6H-A30 OD-X8 — 本地提案**有界重播**状态（Node-local；无共识语义；见
    /// [`ProposalRefresh`]）。仅本地生产路径写入；`(height, round)` 变化即清空。
    proposal_refresh: Option<ProposalRefresh>,
    /// D9 Step 7：入站连接握手 pending（peer 字节键 → 接受时 tick；Established / 失败 / 超时后移除）。
    /// 键用 `[u8; 32]`（`NodeId` 无 `Ord`）⇒ 确定性字典序与 inbound 连接表一致。
    inbound_pending: BTreeMap<[u8; 32], u64>,
    /// D9 Step 8A：Production Sync Responder 观测（只读计数；非协议）。
    sync_respond: SyncRespondDiagnostics,
    /// P1-A.7 — per-height PrecommitQC history（ADR-0064；有 canonical adapter 时才装配）。
    /// **只服务**（供既有 sync 响应附发）；**不产生** finality / commit / head 推进。
    qc_history: Option<QcHistory>,
    /// P1-A.7 — 已写入 qc_history 的 reference（幂等锚；避免每 step 重写同一高度）。
    qc_history_persisted: Option<[u8; 32]>,
    /// P1-A.7 — 已写入 QC history 的次数（观测）。
    qc_history_written: u64,
    /// P1-A.7 — QC history 写入**失败**次数（观测；不 halting consensus，下一 step 重试）。
    qc_history_write_failed: u64,
    /// D10 Recovery C — 启动时恢复、**尚未 commit** 的 finality（D-1 证据源；`None` = 无恢复）。
    /// G4 决策：**仅作 bridge 证据 + 只读观测**，**不** gate 任何 proposal / vote 行为；
    /// `head == reference` 后清空（状态清理）。**不**参与任何共识规则。
    restored_finality: Option<bootstrap::RestoredFinality>,
    /// P1-A.7 — 入站 QC 「target ∉ DAG」而被**有界**暂存的次数（观测；含 tip hint 驱动）。
    inbound_qc_deferred: u64,
    /// P1-A.7 — 成功采纳外部 finality 的次数（仅 `Adopted`；观测）。
    external_finality_adopted: u64,
    /// P1-A.7 — 外部 QC **未**被采纳的次数（前置检查失败 / 幂等 / 过时 / 冲突 / frozen 拒绝；观测）。
    external_finality_rejected: u64,
    /// P1-A.7 — 有界 pending external QC（dedup by target；≤ [`PENDING_EXTERNAL_QC_CAP`]）。
    pending_external_qc: VecDeque<PendingExternalQc>,
    /// P1-A.7 — 最近一次**采纳**的外部 QC（供既有 durable fact 持久化同源取用；无则 `None`）。
    last_adopted_qc: Option<QuorumCertificate>,
    /// P1-A.8 — peer lifecycle 逻辑 tick（每次 `establish_configured_peers()` 入口 saturating +1）。
    /// **与 P1-A.6 consensus round timer 完全独立**（不互读写；无墙钟）。
    peer_tick: u64,
    /// P1-A.8 — per-peer 重连退避状态（key = `NodeId` 字节；基数 ≤ configured peers；
    /// 每次调用 prune ⇒ **不随重试次数增长**）。
    peer_lifecycle: BTreeMap<[u8; 32], PeerLifecycleState>,
    /// P1-A.8 — dial 尝试总次数（saturating；只读观测）。
    peer_dial_attempts_total: u64,
    /// P1-A.8 — dial 失败总次数（saturating；只读观测）。
    peer_dial_failures_total: u64,
    /// PHASE 6H-A11 U1 — **有界** pending proposal 存储（ADR-0076 PADR-5.2；OD-C3）。
    /// U1 仅提供容器与诊断槽位；**准入 guard / recovery checkpoint 归 U2 / U3** ⇒ 本字段
    /// 当前不参与任何共识流程（零共识语义变更 / 无 progress / 无 RESET 影响）。
    pending_proposals: PendingProposalStore,
    /// PHASE 6H-A11 DIAG — 只读诊断计数（**不参与任何判定**；零共识语义）。
    a11_diag: A11Diag,
    /// PHASE 6H-A30 OD-X7 — 只读 liveness 观测（**不参与任何判定**；零共识语义）。
    liveness: LivenessObservability,
}

impl NodeRuntime {
    /// 启动（网络 disabled）：Consensus + Storage（+ validator）正常启动；**不**装配
    /// NetworkStack（不生成网络身份）。行为与 Stage C 前完全兼容。
    pub fn start(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, None)
    }

    /// 启动（Stage C Full Composition）：在 `start` 基础上注入网络 assets ——
    /// `transport: Box<dyn Transport>`（MemoryTransport test/dev；未来 production adapter 注入）
    /// 与 `network_identity: Box<dyn NetworkSigner>`（网络身份；**不得**用 validator key）。
    ///
    /// 顺序保证：`NetworkIdentity → node_id() → NetworkService::new(self_id, transport)`；
    /// `NodeId = NetworkSigner::node_id()`（≠ ValidatorId）。
    pub fn start_with_network(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        transport: Box<dyn Transport>,
        network_identity: Box<dyn NetworkSigner>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, Some((transport, network_identity)))
    }

    /// 内部启动：固定顺序（§模块 doc）。任何安全失败 ⇒ `Err`（fail closed）。
    ///
    /// - `key_provider`：validator mode 时**必须**提供（None ⇒ `KeyNotProvisioned`）；
    ///   full-node 时忽略。
    /// - `network_assets`：`Some((transport, network_identity))` ⇒ 装配 NetworkStack。
    /// - SafetyStore 打开 / recover 仍在 Runtime lifecycle（`build_validator`）；
    ///   Driver 只接收已构造好的 `ConsensusNode` + `ValidatorActor(s)`。
    fn start_inner(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        network_assets: Option<(Box<dyn Transport>, Box<dyn NetworkSigner>)>,
    ) -> Result<Self, NodeRuntimeError> {
        // 2/3. Genesis + ChainIdentity validation（expected hash/chain/network）。
        let (genesis, identity) =
            bootstrap::load_genesis(config).map_err(NodeRuntimeError::Startup)?;

        // 4. chain storage owner（**P1-A.24**：canonical adapter 与 validator 权威 **解耦**）：
        //    - validator mode：canonical adapter（＋下方 5–11 的 validator actor）；
        //    - full-node / observer：**同一个** canonical adapter —— 获得 validation /
        //      registration / external-finality adoption / commit / sync-serve 能力，
        //      但 actors = []（无 key / 无 signer / 无 safety journal ⇒ 结构性不可能
        //      propose / vote / 签名；见 5–11 分支与 `runtime_propose` 的 `driver.actor(0)` gate）。
        //    `bootstrap::start` 只做：genesis 加载 + storage 打开 + state/head 恢复（首启 bootstrap
        //    genesis state）+ BlockStore 装配 + committed-head 一致性校验 —— **不读**
        //    `validator_enabled` / **不触碰** KeyProvider / **不创建** actor / **不产生**共识输出。
        let (chain_storage, block_production, consensus_start_height) = {
            let adapter = bootstrap::start(NoAccountsKeyResolver, config)
                .map_err(NodeRuntimeError::Startup)?;
            let head_height = adapter.head().height;
            (None, Some(adapter), head_height)
        };

        // 10. ConsensusNode（canonical state owner）——随后装配进 NodeConsensusDriver。
        //     初始共识高度 = canonical head height（ChainHead 单一高度源；validator 与
        //     full-node / observer 同源 —— P1-A.24）。
        let set = ValidatorSet::from_genesis(&genesis);

        // P1-A.7 / P1-A.20-C Phase 2：per-height PrecommitQC history（ADR-0064）。
        // - 仅在有 canonical adapter（能验证 / 提交）时装配 —— 无 adapter 的形态不产生无主 artifact。
        //   （P1-A.24：validator 与 full-node / observer 均有 adapter ⇒ 两者都会产出/使用 artifact；
        //   full-node 的 artifact 来自**采纳**的外部 QC，使其能作为 P1-A.23 exact catch-up 的 responder。）
        // - **D11-25 D5**：tip 必须 ≤ 实际可用 coverage ⇒ fact 高度仅作**上界**，由
        //   `seed_tip_from_store` 向下**有界**探测现有 artifact（不扫描目录 / 不遍历历史）；
        //   未命中 ⇒ tip 保持 `None`（不发 hint）；fact 缺失 / 不可读 ⇒ 同样不播种。
        //   （tip 属 sync/service hint，**不是** consensus safety primitive；本改动不引入任何新
        //     的 durable 语义对象，也不改变既有术语集合。）
        // - **Phase 2 顺序调整**：在 DAG 重建**之前**构造 —— 重建需要按高度读取历史 QC 的
        //   `context.round` 以解析历史（round ≥ 1）块的 proposer（见 `rebuild_consensus_dag`）。
        let mut qc_history = block_production.as_ref().map(|_| {
            QcHistory::open(
                &config.storage_dir,
                identity.network_id,
                identity.chain_id,
                identity.genesis_hash,
            )
        });
        if let Some(history) = qc_history.as_mut()
            && let Ok(Some((height, _))) = bootstrap::read_finality_fact(
                &config.storage_dir.join(bootstrap::FINALITY_FACT_FILE),
            )
        {
            history.seed_tip_from_store(height);
        }
        // D10-C Step 2 — DAG Restart Rebuild：validator（bootstrap 装配 canonical BlockStore）在
        //    restart 后沿 canonical head → parent 链重建 Consensus DAG ancestry（consensus DAG 不
        //    persisted 的补偿 seam），使 safety lock / ancestry 判定在重启后可安全继续；重建只读
        //    storage、fail closed。首启（head == genesis）⇒ 仅 genesis 根。无 adapter 的形态
        //    维持空 DAG（P1-A.24 后仅防御性不可达）。
        // D10-C Step 4 — Finality Recovery Fact 恢复：在 rebuild 后读取 durable fact；未 commit 的
        //    finalized 候选经 identity / block / QC / head-relation 全验证后注入 finalized_reference
        //    （fail-closed；见 bootstrap::restore_finality_fact）。
        let (dag, restored_finality) = match block_production.as_ref() {
            Some(adapter) => {
                let dag = bootstrap::rebuild_consensus_dag(adapter, &set, qc_history.as_ref())
                    .map_err(NodeRuntimeError::Startup)?;
                let fact_path = config.storage_dir.join(bootstrap::FINALITY_FACT_FILE);
                bootstrap::restore_finality_fact(
                    &fact_path,
                    adapter,
                    &set,
                    identity.network_id,
                    identity.chain_id,
                    identity.genesis_hash,
                    dag,
                )
                .map_err(NodeRuntimeError::Startup)?
            }
            None => (Dag::new(), None),
        };
        let mut consensus = ConsensusNode::new(
            consensus_start_height,
            0,
            identity.chain_id,
            set,
            identity.genesis_hash,
            dag,
        );
        // 恢复注入（仅当 fact 全验证通过；单调 —— 不回退 / 不覆盖既有 finality）。
        // D10 Recovery C：恢复结果本身（含已验证 QC）保留在 runtime ⇒ bridge 证据源
        // （G4 决策：**不** gate proposal / vote；仅证据 + 只读观测）。
        if let Some(restored) = restored_finality.as_ref() {
            consensus.restore_finalized_reference(restored.reference);
        }

        // 5–11. validator mode：KeyProvider → id → SafetyStore → recover → ValidatorActor
        //      （Runtime lifecycle）→ 与 ConsensusNode 一并装配进 NodeConsensusDriver。
        let (driver, validator_journal) = if config.validator_enabled {
            let (actor, journal_path) = Self::build_validator(config, &identity, key_provider)?;
            let driver = NodeConsensusDriver::new(consensus, vec![actor]);
            (driver, Some(journal_path))
        } else {
            // full-node：consensus-only driver（actors = []）；不触碰 Provider。
            let driver = NodeConsensusDriver::<DynSigner>::new(consensus, Vec::new());
            (driver, None)
        };

        // PHASE 6H-AF：池绑定链身份（`chain_id` + `genesis_hash` = `validator_set_id`；
        // 与 D1 的 `expected_validator_set_id` 同源）——构造前捕获，避免依赖 `identity` 后续所有权。
        let round_change_pool =
            RoundChangeAttestationPool::new(identity.chain_id, identity.genesis_hash);

        // Stage C：网络资产注入 ⇒ NetworkStack（identity → node_id → NetworkService）。
        //   configured peers 校验（self / duplicate）在 dial 前启动时执行（fail-closed）；
        //   NS 注入 TcpDialer（复用 D4 seam；Node 不直调 TcpTransport::dial）。
        let network_stack = match network_assets {
            Some((transport, network_identity)) => {
                let self_id = network_identity.node_id();
                config
                    .validate_network_targets(self_id)
                    .map_err(NodeRuntimeError::NetworkTarget)?;
                // D5：装配 peer-auth（network/chain/genesis/protocol/caps/rate/replay）——
                //   使 inbound process_handshake 能执行认证（session owner = NetworkService）。
                let auth = Self::network_peer_auth(&identity);
                let ns_config = NetworkServiceConfig {
                    peer_auth: Some(auth),
                    ..Default::default()
                };
                // D9 Step 7：入站 listener（仅 `config.listen_addr = Some`）。`max_frame` 与出站
                // dial **同源**（`NetworkServiceConfig::max_msg_bytes`）⇒ 双向 frame 上限一致；
                // 绑定失败 ⇒ 启动 fail-closed（不静默降级为无 listener）。
                let inbound = match config.listen_addr {
                    Some(addr) => Some(
                        InboundListenerState::bind(addr, self_id, ns_config.max_msg_bytes)
                            .map_err(NodeRuntimeError::InboundListener)?,
                    ),
                    None => None,
                };
                // 注入 transport：无 listener ⇒ **原样注入**（D9 Step 7 之前行为完全不变）；
                // 有 listener ⇒ 入站 multiplex（`fallback` = 原注入 transport ⇒ 既有注入 /
                // 测试语义保留：非入站 peer 仍走原 transport）。
                let injected: Box<dyn Transport> = match &inbound {
                    Some(state) => {
                        let mux: InboundMultiplexTransport = state.transport(Some(transport));
                        Box::new(mux)
                    }
                    None => transport,
                };
                let ns = NetworkService::new(ns_config, self_id, BoxTransport::new(injected))
                    .with_dialer(Box::new(TcpDialer));
                let el = EventLoop::new(EventLoopConfig::default(), NodeConsensusHandler::new());
                Some(NetworkStack {
                    ns,
                    el,
                    signer: network_identity,
                    inbound,
                })
            }
            None => None,
        };

        // 协议参数（block inbound size 上限；来自 genesis；只读）。
        let max_block_bytes = genesis.protocol_parameters.max_block_bytes as usize;

        Ok(Self {
            chain_identity: identity,
            chain_storage,
            block_production,
            driver,
            network_stack,
            configured_targets: config.peers.clone(),
            handshake_init_sent_for: HashSet::new(),
            validator_journal,
            proposal_timestamp: 0,
            last_proposal: None,
            finality_fact_path: config.storage_dir.join(bootstrap::FINALITY_FACT_FILE),
            finality_fact_persisted: None,
            max_block_bytes,
            block_inbound_outcomes: VecDeque::new(),
            block_inbound_skipped: 0,
            missing_ancestor_ledger: MissingAncestorIntentLedger::new(MISSING_ANCESTOR_LEDGER_CAP),
            sync_scheduler: SyncRequestScheduler::new(SYNC_SCHEDULER_CAP),
            sync_correlator: SyncRequestCorrelator::new(SYNC_CORRELATOR_CAP),
            sync_tick: 0,
            sync_resolved_responses: 0,
            sync_unknown_responses: 0,
            inbound_consensus_rejected: 0,
            derived_qc_not_applicable: 0,
            round_timeout_config: RoundTimeoutConfig::default(),
            clock: Box::new(SystemClock::new()),
            last_tick_ns: 0,
            round_timer: None,
            round_timeouts: 0,
            round_changes_by_authority: 0,
            round_changes_rejected: 0,
            round_changes_deferred: 0,
            round_change_diag: RoundChangeDiag::default(),
            round_change_broadcast_no_peer: 0,
            abandon_broadcast_no_peer: 0,
            round_timeout_outcomes: [0; RoundTimeoutOutcome::COUNT],
            round_change_store: RoundChangeStore::new(
                nova_consensus::round_change::DEFAULT_MAX_TRACKED_HEIGHTS,
            ),
            round_change_pool,
            abandon_attestations_produced: 0,
            abandon_attestations_rejected: 0,
            abandon_attestations_broadcast: 0,
            round_change_certificates_assembled: 0,
            inbound_tick: 0,
            proposal_refresh: None,
            inbound_pending: BTreeMap::new(),
            sync_respond: SyncRespondDiagnostics::default(),
            qc_history,
            qc_history_persisted: None,
            qc_history_written: 0,
            qc_history_write_failed: 0,
            restored_finality,
            inbound_qc_deferred: 0,
            external_finality_adopted: 0,
            external_finality_rejected: 0,
            pending_external_qc: VecDeque::new(),
            last_adopted_qc: None,
            peer_tick: 0,
            peer_lifecycle: BTreeMap::new(),
            peer_dial_attempts_total: 0,
            peer_dial_failures_total: 0,
            pending_proposals: PendingProposalStore::new(),
            a11_diag: A11Diag::default(),
            liveness: LivenessObservability::default(),
        })
    }

    /// validator mode 生命周期装配（key provider → derive id → safety store → recover → actor）。
    /// 返回 `(actor, journal_path)`；actor 随后移入 Driver（ownership）。
    ///
    /// G5-D.7.2（missing-journal fail closed）：journal 缺失时**绝不**隐式初始化 ——
    /// 必须由 `config.validator_safety_init` 显式声明；已存在时声明初始化亦被拒绝。
    fn build_validator(
        config: &NodeConfig,
        identity: &ChainIdentity,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<(ValidatorActor<DynSigner>, PathBuf), NodeRuntimeError> {
        // 5. KeyProvider（validator mode 必填；不默认生成不稳定生产密钥）。
        let provider = key_provider.ok_or(NodeRuntimeError::KeyNotProvisioned)?;
        let signer = provider
            .load_signer()
            .map_err(NodeRuntimeError::KeyProvider)?;
        let public_key = signer.public_key().to_bytes();

        // 6. derive ValidatorId（单一来源）。
        let validator_id = derive_validator_id(&public_key);

        // 7. SafetyIdentity + SafetyStore open（独立 safety_dir；与 chain storage 分离）。
        let safety_identity = SafetyIdentity::new(
            identity.network_id,
            identity.chain_id,
            identity.genesis_hash,
            &validator_id,
        );
        // G5-D.7.2 + P-6 修复（初始化原子性前置）：两枚 journal 的存在性必须在**任何 create 之前**
        // 一起判定。旧实现先按 vote 分支可能 `create`，之后才在 block 分支拒绝 ⇒
        // “仅 block 存在 + 显式初始化”会在**失败启动**中新建一枚空 vote journal。
        //
        // 判定规则（先判后写；不删除、不补齐、不改写）：
        //   · 仅一枚存在 + 未声明初始化 ⇒ `SafetyJournalMissing`（**零写入**）；
        //   · 仅一枚存在 + 已声明初始化 ⇒ `SafetyJournalAlreadyExists`（既有安全状态与
        //     “全新节点”声明矛盾；同样在**写入之前**拒绝）；
        //   · 两枚均存在 + 已声明初始化 ⇒ `SafetyJournalAlreadyExists`（既有字节不变）；
        //   · 两枚均不存在 + 未声明初始化 ⇒ `SafetyJournalMissing`（可诊断；不伪装为 IO failure）；
        //   · 两枚均不存在 + 已声明初始化 ⇒ **唯一**允许 `create` 的路径。
        // 原子性边界（不得过度声称）：`exists()` **不提供跨进程原子性**；并发启动仍由
        // `create_new(true)` 兜底（失败方 fail closed，不会损坏或覆盖既有 journal）。
        let journal_path = config.safety_dir.join("safety.journal");
        let block_journal_path = config.safety_dir.join("block-safety.journal");
        let journal_exists = journal_path.exists();
        let block_journal_exists = block_journal_path.exists();

        if journal_exists != block_journal_exists {
            return Err(if config.validator_safety_init {
                NodeRuntimeError::SafetyJournalAlreadyExists
            } else {
                NodeRuntimeError::SafetyJournalMissing
            });
        }
        if journal_exists && config.validator_safety_init {
            return Err(NodeRuntimeError::SafetyJournalAlreadyExists);
        }
        if !journal_exists && !config.validator_safety_init {
            return Err(NodeRuntimeError::SafetyJournalMissing);
        }

        let store = if config.validator_safety_init {
            ValidatorSafetyStore::create(&journal_path, safety_identity)
                .map_err(NodeRuntimeError::Safety)?
        } else {
            ValidatorSafetyStore::at(&journal_path, safety_identity)
        };

        // 7b. **D-5.3.4 B2-B**：signer-owned Block safety journal（与 vote safety journal
        //     **文件分离**；沿用同一“缺失即 fail closed / 显式初始化不覆写既有历史”纪律）。
        //     生产出块签名必须经该 journal：`ValidatorActor::sign_block` 无 journal ⇒ 拒绝签名。
        let block_identity = BlockSafetyIdentity::new(
            identity.network_id,
            identity.chain_id,
            identity.genesis_hash,
            &validator_id,
        );
        let block_safety = if config.validator_safety_init {
            BlockSafetyJournal::create(&block_journal_path, block_identity)
                .map_err(NodeRuntimeError::BlockSafety)?
        } else {
            let j = BlockSafetyJournal::at(&block_journal_path, block_identity);
            j.recover().map_err(NodeRuntimeError::BlockSafety)?;
            j
        };

        // 8/9. strict recover（restore 内部执行）→ 构造 ValidatorActor（已附加 B2-B safety gate）。
        //      recover / identity mismatch ⇒ Err ⇒ validator mode 启动失败（fail closed）。
        let actor = ValidatorActor::restore(validator_id, signer, identity.chain_id, store)
            .map_err(NodeRuntimeError::Validator)?
            .with_block_safety(block_safety);

        Ok((actor, journal_path))
    }

    pub fn chain_identity(&self) -> &ChainIdentity {
        &self.chain_identity
    }

    /// chain storage handle（full-node 形态；validator ⇒ `None`）。
    pub fn chain_storage(&self) -> Option<&PersistentBackend> {
        self.chain_storage.as_ref()
    }

    /// validator-mode block-production adapter（canonical store + head + genesis 参数；只读）。
    pub fn block_production(
        &self,
    ) -> Option<&NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>> {
        self.block_production.as_ref()
    }

    /// 最近一次本地出块产物（本地保留；不持久化 / 不推进 head）。
    pub fn last_proposal(&self) -> Option<&ProposalBuild> {
        self.last_proposal.as_ref()
    }

    /// D10 Recovery C — 是否处于恢复窗口（**只读观测**；G4 后不再 gate 任何行为）。
    ///
    /// 定义：启动恢复了一个**尚未 commit** 的 finality（`restored_finality.is_some()`）且
    /// canonical head 仍未到达该 reference。`head == reference` 后清除（`step` 内状态清理）。
    /// 只读；不做 I/O；不改变任何共识 / 存储状态；**不**禁止 proposal / vote。
    pub fn recovering_finality(&self) -> bool {
        let Some(restored) = self.restored_finality.as_ref() else {
            return false;
        };
        match self.block_production.as_ref() {
            Some(adapter) => adapter.head().block_hash != restored.reference,
            None => false,
        }
    }

    /// 取走 block inbound dispatch 观测（STEP 10-19-10-A；FIFO；bounded）。
    ///
    /// 每项 = `Ok(verdict)`（含 `CanonicalNextCandidate` 等分类）或 `Err(reason)`
    /// （`Oversized`/`Malformed`/`WrongChain`/…/`UnsupportedValidation`）。
    /// 只读观测：**不 commit / 不写存储 / 不推进 head**。
    pub fn take_block_inbound_outcomes(
        &mut self,
    ) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
        self.block_inbound_outcomes.drain(..).collect()
    }

    /// 当前 block inbound 观测深度。
    pub fn block_inbound_outcome_len(&self) -> usize {
        self.block_inbound_outcomes.len()
    }

    /// 无 canonical 上下文（full-node）而跳过的 block inbound payload 计数。
    pub fn block_inbound_skipped(&self) -> u64 {
        self.block_inbound_skipped
    }

    /// 当前 missing-ancestor intent ledger 深度（STEP 10-19-10-B1）。
    pub fn missing_ancestor_intent_len(&self) -> usize {
        self.missing_ancestor_ledger.len()
    }

    /// 取走全部 missing-ancestor intents（FIFO；consuming）。只读/消费观测；不发送 / 不写存储。
    pub fn take_missing_ancestor_intents(
        &mut self,
    ) -> Vec<crate::intent_ledger::MissingAncestorIntent> {
        self.missing_ancestor_ledger.take_all()
    }

    /// 收到且 correlation 成功的 SyncBlockResponse 数（D8-3-1；request lifecycle resolve）。
    pub fn sync_resolved_responses(&self) -> u64 {
        self.sync_resolved_responses
    }

    /// 收到但 Unknown / 结构损坏而被拒的 SyncBlockResponse 数（D8-3-1；安全拒绝观测）。
    pub fn sync_unknown_responses(&self) -> u64 {
        self.sync_unknown_responses
    }

    /// P1-A.4：被拒的**入站** consensus command 数（peer 提供内容；观测）。
    ///
    /// 仅计数（不携带 payload / 签名 / 错误文本）；本地路径错误不以本计数表达。
    pub fn inbound_consensus_rejected(&self) -> u64 {
        self.inbound_consensus_rejected
    }

    /// P1-A.5：本地/派生路径上「派生 QC 的 target 不在本节点 DAG」（`UnknownTarget`）次数。
    ///
    /// 该条件被判定为**不适用**（非有效 QC、非运行错误）⇒ 不终止 runtime、零状态变更；
    /// 仅计数（不携带 QC payload / target hash / 签名 / 对端身份 / 错误文本）。
    pub fn derived_qc_not_applicable(&self) -> u64 {
        self.derived_qc_not_applicable
    }

    /// P1-A.6：本地 round timeout 已触发（调用冻结 `round_timeout()`）的次数（saturating 观测）。
    ///
    /// 计数 = 计时器到期并执行一次本地 RoundTimeout **尝试**（含 `u64::MAX` 轮被冻结
    /// `checked_successor` 拒绝的尝试）；不携带任何 payload / hash / 签名 / 对端材料。
    pub fn round_timeouts(&self) -> u64 {
        self.round_timeouts
    }

    /// PHASE 6H-Z（Owner D1-3 / G-2）— **权威驱动** round 变更次数（独立归因；观测）。
    ///
    /// 仅在「已验证 RC 且 `from_round == local_round` ⇒ 应用 ⇒ 恰 +1」时递增。
    /// 与 [`Self::round_timeouts`]（**本地**超时）**严格分离**：两者互不包含、互不混淆。
    pub fn round_changes_by_authority(&self) -> u64 {
        self.round_changes_by_authority
    }

    /// PHASE 6H-Z — 入站 RC 被拒次数（malformed / invalid / stale / overflow / 低 quorum / 高度不符）。
    pub fn round_changes_rejected(&self) -> u64 {
        self.round_changes_rejected
    }

    /// PHASE 6H-Z — G-1 暂存（`from_round > local_round`）的「新增 − 重评应用」计数（gauge；
    /// `Duplicate` 不计；store 淘汰不计 —— 真实条目数见 [`Self::round_change_store_len`]）。
    pub fn round_changes_deferred(&self) -> u64 {
        self.round_changes_deferred
    }

    /// P1-A.30 **D0** — RC 拒绝原因**分类**计数（仅观测；总数仍见 [`Self::round_changes_rejected`]）。
    pub fn round_change_reject_count(&self, kind: RoundChangeRejectKind) -> u64 {
        self.round_change_diag.reject_count(kind)
    }

    /// P1-A.30 **D0** — RC 证书广播时**零 Established 对端**的次数（"已组装但无处可发"的观测）。
    ///
    /// **不得**据此推断"证书永久丢失"：本计数仅说明**该次**广播的 `Ok(0)`
    ///（无 Established 对端）；本流程**未实现**补发 / 重传 / 按需获取。
    pub fn round_change_broadcast_no_peer(&self) -> u64 {
        self.round_change_broadcast_no_peer
    }

    /// P1-A.30 **D0** — Abandon attestation 广播时零 Established 对端的次数（同上语义边界）。
    pub fn abandon_broadcast_no_peer(&self) -> u64 {
        self.abandon_broadcast_no_peer
    }

    /// P1-A.30 **D0** — 暂存证书重新评估 `(attempts, applied)`（仅观测）。
    pub fn round_change_reeval(&self) -> (u64, u64) {
        (
            self.round_change_diag.reeval_attempts,
            self.round_change_diag.reeval_applied,
        )
    }

    /// P1-A.30 **D0** — 本地 timeout 结果分类计数（`applied` / `ignored` / `rejected`）。
    pub fn round_timeout_outcome(&self, outcome: RoundTimeoutOutcome) -> u64 {
        self.round_timeout_outcomes
            .get(outcome.index())
            .copied()
            .unwrap_or(0)
    }

    /// P1-A.30 **D0′** — 入站**队列溢出丢弃**计数
    /// `[block_inbound, sync_requests, round_changes, abandon_attestations]`（**仅观测**）。
    ///
    /// 数据源 = 既有 [`NodeConsensusHandler`] 计数（唯一递增点 = 各 `collect_*` 的容量分支）；
    /// 本方法**只读**。无网络栈 ⇒ 全 0（与既有 `liveness_snapshot` 的 `None ⇒ 0` 一致）。
    /// **不改变**队列容量 / 保留策略 / 广播语义 / 共识行为。
    pub fn inbound_queue_drops(&self) -> [u64; 4] {
        self.network_stack.as_ref().map_or([0; 4], |s| {
            let h = s.el.handler();
            [
                h.block_inbound_dropped(),
                h.sync_requests_dropped(),
                h.round_changes_dropped(),
                h.abandon_attestations_dropped(),
            ]
        })
    }

    /// P1-A.30 **D0** — Guard C 准入拒绝**分类**计数（8 类固定序；**仅观测**）。
    ///
    /// 数据源 = 既有 `PendingProposalStore`（唯一计数点）；本方法**不**新增计数。
    /// 用途：区分 A30/A12 运行中 `proposal_rejected` 是否来自 `Signature` / `Proposer` /
    /// `HeightContext` / `Evidence` / `MissingBlock` 等（过去只能标为 UNKNOWN）。
    pub fn guard_reject_counts(&self) -> [u64; 8] {
        self.pending_proposals.guard_reject_counts()
    }

    /// PHASE 6H-Z — G-1 暂存区当前证书数（有界内存；无持久化）。
    pub fn round_change_store_len(&self) -> usize {
        self.round_change_store.total()
    }

    /// PHASE 6H-AF — 本地真实 EXPIRE 产生的 Abandon attestation 数。
    pub fn abandon_attestations_produced(&self) -> u64 {
        self.abandon_attestations_produced
    }

    /// PHASE 6H-AF — 入站 attestation 被拒数（fail-closed 观测）。
    pub fn abandon_attestations_rejected(&self) -> u64 {
        self.abandon_attestations_rejected
    }

    /// PHASE 6H-AH — 已发出的本地 `0x0E` attestation 数（`broadcast` 已入队数；saturating）。
    pub fn abandon_attestations_broadcast(&self) -> u64 {
        self.abandon_attestations_broadcast
    }

    /// PHASE 6H-AF — 池内组装完成并经既有 `0x0D` 广播的证书数。
    pub fn round_change_certificates_assembled(&self) -> u64 {
        self.round_change_certificates_assembled
    }

    /// PHASE 6H-AF — 池内待广播证书数（有界；无持久化）。
    pub fn round_change_pending_broadcast(&self) -> usize {
        self.round_change_pool.pending_broadcast_len()
    }

    /// A3：当前计时器已历时（**毫秒**；`None` = 尚未 arm / 已被 finality disarm）。
    ///
    /// 读数 = **最后一次 `step()` 的**单调读数 − `armed_at`（saturating，毫秒）；本 accessor
    /// **不**读时钟（不得干扰注入式 fake 时钟的时间轴）。与 `round_timeouts`（触发次数）不同。
    pub fn round_timeout_elapsed_ms(&self) -> Option<u64> {
        self.round_timer
            .map(|t| t.elapsed_ns(self.last_tick_ns) / NANOS_PER_MS)
    }

    /// A3：当前计时器窗口（**毫秒**；`None` = 未 arm）。只读观测（诊断 / 确定测试）。
    pub fn round_timeout_window_ms(&self) -> Option<u64> {
        self.round_timer.map(|t| t.window_ns / NANOS_PER_MS)
    }

    /// PHASE 6H-A11 U1 — pending proposal 当前条目数（有界：≤ [`MAX_PENDING_PROPOSALS`]）。
    pub fn pending_proposals_len(&self) -> usize {
        self.pending_proposals.len()
    }

    /// PHASE 6H-A11 U1 — pending 准入成功数（U2/U3 起自增；确定性诊断计数）。
    pub fn pending_proposals_admitted(&self) -> u64 {
        self.pending_proposals.admitted_count()
    }

    /// PHASE 6H-A11 U1 — pending 准入拒绝数（U2/U3 起自增）。
    pub fn pending_proposals_rejected(&self) -> u64 {
        self.pending_proposals.rejected_count()
    }

    /// PHASE 6H-A11 U1 — pending 到期淘汰数（确定性 tick）。
    pub fn pending_proposals_expired(&self) -> u64 {
        self.pending_proposals.expired_count()
    }

    /// PHASE 6H-A11 U1 — pending 容量（FIFO）淘汰数。
    pub fn pending_proposals_evicted(&self) -> u64 {
        self.pending_proposals.evicted_count()
    }

    /// PHASE 6H-A11 DIAG — 单行只读诊断汇总（pending / guard 拒绝原因 / recovery / block 入站）。
    ///
    /// **仅观测**：不参与任何判定，不影响共识语义；供集成测试打印以定位停滞。
    pub fn a11_diag_summary(&self) -> String {
        let s = &self.pending_proposals;
        let d = &self.a11_diag;
        format!(
            "pending(len={}, pended={}, admitted={}, rejected={}, expired={}, evicted={}; \
             rej[nostore={}, store={}, missing={}, height={}, under={}, evid={}, prop={}, sig={}]) \
             recovery(runs={}, cand={}, kept_missing={}, admitted={}, rejected={}, evid_conflict={}, submit_err={}) \
             blocks(proc={}, canonical_next={}, register_ok={}, conflict_skipped={}, skipped={}) \
             reg(round_conflict={}, arrival_mismatch={}, label_mismatch={})",
            s.len(),
            s.pended_count(),
            s.admitted_count(),
            s.rejected_count(),
            s.expired_count(),
            s.evicted_count(),
            s.guard_reject_count(GuardReject::NoStore),
            s.guard_reject_count(GuardReject::StorageError),
            s.guard_reject_count(GuardReject::MissingBlock),
            s.guard_reject_count(GuardReject::HeightContext),
            s.guard_reject_count(GuardReject::HeightUnderflow),
            s.guard_reject_count(GuardReject::Evidence),
            s.guard_reject_count(GuardReject::Proposer),
            s.guard_reject_count(GuardReject::Signature),
            d.recovery_runs,
            d.recovery_candidates,
            d.recovery_kept_missing_block,
            d.recovery_admitted,
            d.recovery_rejected,
            d.recovery_evidence_conflict,
            d.recovery_submit_err,
            d.block_inbound_processed,
            d.block_canonical_next,
            d.block_register_ok,
            d.block_conflict_skipped,
            self.block_inbound_skipped,
            d.block_register_round_conflict,
            d.block_arrival_round_mismatch,
            d.block_register_label_mismatch,
        )
    }

    /// P1-A.6 / A3 — **测试 / 开发 seam**：设置 round timeout 窗口参数（**毫秒**，单调时长）。
    ///
    /// - 非生产配置面：无 CLI flag / 不进 `NodeConfig` / 不持久化 / 不改任何共识语义。
    /// - 调用后丢弃当前计时器，下一 `step()` 按新参数重新 arm（确定测试无需等待 / 无 sleep）。
    /// - 生产默认 = `RoundTimeoutConfig::default()`（10_000 / 120_000 / 2，**毫秒**）。
    pub fn set_round_timeout_config(&mut self, config: RoundTimeoutConfig) {
        self.round_timeout_config = config;
        self.round_timer = None;
    }

    /// A3 测试 seam — 注入**确定性** fake 时钟（生产默认 = [`SystemClock`]）。
    ///
    /// 语义边界：只影响本地计时器的"已历时"读数；**不**影响任何共识判定 / 验证 / 广播。
    /// 注入后计时器**不**被修改（调用方可继续用 [`Self::set_round_timeout_config`] 重置）。
    pub fn set_clock(&mut self, clock: Box<dyn MonotonicClock>) {
        self.clock = clock;
    }

    /// 当前 outbound sync correlator 中 active（未 resolve / 未 expire）request 数
    /// （D8-3-1 观测：request lifecycle register→resolve→release 的 active 深度）。
    pub fn sync_pending_requests(&self) -> usize {
        self.sync_correlator.len()
    }

    /// 显式设置 step-driven 出块 timestamp（无系统时钟；默认 0；确定性由调用方保证）。
    pub fn set_proposal_timestamp(&mut self, timestamp: u64) {
        self.proposal_timestamp = timestamp;
    }

    /// NodeConsensusDriver（只读；ConsensusNode + ValidatorActor 的 owner）。
    pub fn driver(&self) -> &NodeConsensusDriver<DynSigner> {
        &self.driver
    }

    /// 网络身份 NodeId（`start_with_network` 启用时 `Some`）。
    /// NodeId 来自网络 key pubkey（≠ ValidatorId；Network/Validator identity 分离）。
    pub fn network_node_id(&self) -> Option<NodeId> {
        self.network_stack.as_ref().map(NetworkStack::node_id)
    }

    /// configured peer 当前是否已认证 Established（D7-Implementation-3 观测；只读）。
    pub fn network_peer_established(&self, peer_id: NodeId) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.is_peer_established(peer_id))
            .unwrap_or(false)
    }

    /// configured peer 当前是否 connected（D7-Implementation-3 观测；只读）。
    pub fn network_peer_connected(&self, peer_id: NodeId) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.is_connected(peer_id))
            .unwrap_or(false)
    }

    /// 连接第一个 configured connection target（STEP 10-19-10-B7-A3；single-active）。
    ///
    /// - 无网络栈 / 无 configured peers / 已有 active connection ⇒ `Ok(None)`（幂等）。
    /// - 配置校验（self / duplicate）已在启动（`start_with_network`）时 fail-closed；此处直接
    ///   dial `configured_targets[0]`（ordered；不并发 / 不多连接）。
    /// - 成功 ⇒ `Ok(Some(peer_id))`（仅 `Connected`；**不 handshake / 不 Established**）。
    /// - dial 失败 ⇒ `Err(NetworkDial(..))`（不自动 retry / 不自动换 peer / 不自动 next）。
    pub fn connect_configured_peer(&mut self) -> Result<Option<NodeId>, RuntimeError> {
        if self.configured_targets.is_empty() {
            return Ok(None);
        }
        let max_frame = {
            let Some(stack) = &self.network_stack else {
                return Ok(None);
            };
            if stack.ns.connected_peer_count() > 0 {
                // single-active：已有 active connection（不重连 / 不静默替换）。
                return Ok(None);
            }
            stack.ns.config().max_msg_bytes
        };
        let t = self.configured_targets[0];
        let Some(stack) = &mut self.network_stack else {
            return Ok(None);
        };
        stack
            .ns
            .dial_peer(t.address, t.peer_id, max_frame, None)
            .map_err(RuntimeError::NetworkDial)?;
        Ok(Some(t.peer_id))
    }

    /// 是否已装配 network peer-auth（`start_with_network` 网络启用时为 `true`）。
    pub fn network_peer_auth_enabled(&self) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.config().peer_auth.is_some())
            .unwrap_or(false)
    }

    /// D9 Step 7：入站 listener 实际绑定地址（`None` = 未启用 / 未装配网络）。
    ///
    /// `NodeConfig::listen_addr` 用 port 0（测试）时返回内核分配的真实端口。
    pub fn network_listen_addr(&self) -> Option<SocketAddr> {
        self.network_stack
            .as_ref()
            .and_then(|s| s.inbound.as_ref())
            .and_then(|i| i.local_addr())
    }

    /// D9 Step 7：入站 listener 只读观测（`None` = 未启用）。
    pub fn network_inbound_diagnostics(&self) -> Option<InboundDiagnostics> {
        self.network_stack
            .as_ref()
            .and_then(|s| s.inbound.as_ref())
            .map(|i| i.diagnostics())
    }

    /// D9 Step 7：当前并存入站连接数（未启用 ⇒ 0）。
    pub fn network_inbound_connection_count(&self) -> usize {
        self.network_stack
            .as_ref()
            .and_then(|s| s.inbound.as_ref())
            .map(|i| i.connection_count())
            .unwrap_or(0)
    }

    /// NETDIAG（**只读**）：本节点当前是否持有该 peer 的**入站**连接。
    pub fn network_inbound_contains(&self, peer_id: NodeId) -> bool {
        self.network_stack
            .as_ref()
            .and_then(|s| s.inbound.as_ref())
            .map(|i| i.contains(peer_id))
            .unwrap_or(false)
    }

    /// D9 Step 8A：Production Sync Responder 观测（只读；不含敏感性字段）。
    pub fn sync_respond_diagnostics(&self) -> SyncRespondDiagnostics {
        self.sync_respond
    }

    /// P1-A.7：被**有界暂存**（target ∉ DAG）的入站 QC 次数（观测）。
    pub fn inbound_qc_deferred(&self) -> u64 {
        self.inbound_qc_deferred
    }

    /// P1-A.7：成功采纳外部 finality 的次数（仅 `Adopted`；观测）。
    pub fn external_finality_adopted(&self) -> u64 {
        self.external_finality_adopted
    }

    /// P1-A.7：外部 QC 未被采纳的次数（前置检查失败 / 幂等 / 过时 / 冲突 / frozen 拒绝；观测）。
    pub fn external_finality_rejected(&self) -> u64 {
        self.external_finality_rejected
    }

    /// P1-A.7：已写入 per-height QC history 的次数（观测）。
    pub fn qc_history_written(&self) -> u64 {
        self.qc_history_written
    }

    /// P1-A.7：QC history 写入失败次数（观测；不 halting consensus）。
    pub fn qc_history_write_failed(&self) -> u64 {
        self.qc_history_write_failed
    }

    /// P1-A.7：当前 pending external QC 条数（bounded ≤ 8）。
    pub fn pending_external_qc_len(&self) -> usize {
        self.pending_external_qc.len()
    }

    /// P1-A.7：QC history 当前 tip 高度（`None` = 未知；不扫描目录）。
    pub fn qc_history_tip_height(&self) -> Option<u64> {
        self.qc_history.as_ref().and_then(|h| h.tip_height())
    }

    /// P1-A.7：已附发的历史 Q C 数（既有 `ConsensusQc`；含对应高度 QC 与 tip hint；观测）。
    pub fn qc_served(&self) -> u64 {
        self.sync_respond.qc_served
    }

    /// P1-A.7：QC 附发被跳过的次数（超尺寸 / 签名失败 / artifact 损坏；观测）。
    pub fn qc_serve_skipped(&self) -> u64 {
        self.sync_respond.qc_serve_skipped
    }

    /// P1-A.8：peer lifecycle 逻辑 tick（每次 `establish_configured_peers()` +1；只读）。
    pub fn peer_tick(&self) -> u64 {
        self.peer_tick
    }

    /// P1-A.8：当前 peer lifecycle 状态条目数（≤ configured peer 数；只读）。
    pub fn peer_lifecycle_len(&self) -> usize {
        self.peer_lifecycle.len()
    }

    /// P1-A.8：某 peer 的退避状态（`None` = 无失败历史；只读）。
    pub fn peer_lifecycle(&self, peer_id: NodeId) -> Option<PeerLifecycleState> {
        self.peer_lifecycle.get(peer_id.as_bytes()).copied()
    }

    /// P1-A.8：dial 尝试总次数（saturating；只读观测）。
    pub fn peer_dial_attempts_total(&self) -> u64 {
        self.peer_dial_attempts_total
    }

    /// P1-A.8：dial 失败总次数（saturating；只读观测）。
    pub fn peer_dial_failures_total(&self) -> u64 {
        self.peer_dial_failures_total
    }

    /// 建立 configured peer（STEP 10-19-10-B7-A1-D5；single-active）。
    ///
    /// 只编排（**不实现握手协议** —— 信封签名 / session 验证全归 NetworkSigner 与
    /// NetworkService `process_handshake`）：dial（若未连）→ 发本端 Handshake Init（每目标一次；
    /// 每次新 nonce）→ poll 一次推进 → 判定：
    /// - configured peer `Established` ⇒ `Ok(Some(peer_id))`（authenticated 且 == configured）；
    /// - 尚无对端握手 ⇒ `Ok(None)`（pending；后续 step 再调本方法推进，不重 dial / 不重发）；
    /// - 收到**其它** peer 合法握手（identity mismatch）⇒ 断开 + `Err(IdentityMismatch)`
    ///   （fail-closed：address 正确 ≠ identity 正确）；
    /// - dial / 构造 / 签名 / 发送失败 ⇒ typed error（不自动 retry / 不自动换 peer / 不 sleep）。
    pub fn establish_configured_peer(&mut self) -> Result<Option<NodeId>, RuntimeError> {
        let Some(target) = self.configured_targets.first().copied() else {
            return Ok(None);
        };
        // 0. 已 Established 目标 ⇒ 完成（幂等）。
        let established_now = self
            .network_stack
            .as_ref()
            .map(|s| s.ns.is_peer_established(target.peer_id))
            .unwrap_or(false);
        if established_now {
            self.handshake_init_sent_for.remove(&target.peer_id);
            return Ok(Some(target.peer_id));
        }
        // 1. dial（无 active connection 时）。
        let dial_needed = self
            .network_stack
            .as_ref()
            .map(|s| s.ns.connected_peer_count() == 0)
            .unwrap_or(false);
        if dial_needed {
            let (addr, remote, max_frame) = {
                let Some(stack) = &self.network_stack else {
                    return Ok(None);
                };
                let max_frame = stack.ns.config().max_msg_bytes;
                (target.address, target.peer_id, max_frame)
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .ns
                .dial_peer(addr, remote, max_frame, None)
                .map_err(RuntimeError::NetworkDial)?;
        }
        // 2. 发送本端 Handshake Init（每目标一次；新 nonce）。
        if !self.handshake_init_sent_for.contains(&target.peer_id) {
            let env = {
                let Some(stack) = &self.network_stack else {
                    return Ok(None);
                };
                let auth = stack
                    .ns
                    .config()
                    .peer_auth
                    .ok_or(RuntimeError::PeerAuthMissing)?;
                Self::build_outbound_handshake(stack.signer.as_ref(), &auth)?
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .ns
                .enqueue_outbound(target.peer_id, env)
                .map_err(RuntimeError::NetworkDial)?;
            let _ = stack.ns.flush_outbound();
            self.handshake_init_sent_for.insert(target.peer_id);
        }
        // 3. poll 一次推进（读对端握手；无 while / 无 sleep）。
        let outcome = {
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .el
                .poll_once(&mut stack.ns)
                .map_err(RuntimeError::EventLoop)?;
            if stack.ns.is_peer_established(target.peer_id) {
                HandshakeOutcome::Established(target.peer_id)
            } else {
                let foreign: Vec<NodeId> = stack.ns.established_peers();
                if foreign.is_empty() {
                    HandshakeOutcome::Pending
                } else {
                    HandshakeOutcome::ForeignEstablished(foreign)
                }
            }
        };
        match outcome {
            HandshakeOutcome::Established(id) => {
                self.handshake_init_sent_for.remove(&id);
                Ok(Some(id))
            }
            HandshakeOutcome::Pending => Ok(None),
            HandshakeOutcome::ForeignEstablished(others) => {
                // address 正确 ≠ identity 正确：收到其它 peer 的合法握手 → fail-closed 断开。
                if let Some(stack) = &mut self.network_stack {
                    for o in &others {
                        let _ = stack.ns.disconnect_peer(*o);
                    }
                    let _ = stack.ns.disconnect_peer(target.peer_id);
                }
                for o in &others {
                    self.handshake_init_sent_for.remove(o);
                }
                self.handshake_init_sent_for.remove(&target.peer_id);
                Err(RuntimeError::IdentityMismatch {
                    configured: target.peer_id,
                })
            }
        }
    }

    /// 断开 first configured peer 并清其握手状态（STEP 10-19-10-B7-A1-D6 生命周期；兼容单 peer）。
    ///
    /// - 调用 `NetworkService::disconnect_peer`（PeerManager connected 清除 + session 清除；
    ///   session owner = NetworkService，此处不手工改 session）。
    /// - 清该 peer 的 `handshake_init_sent_for` ⇒ 之后可重新 dial + 生成 **新 nonce** + 发送
    ///   新 Init（reconnect；L5/L6）。幂等（未连接 / 空 peers ⇒ Ok）。
    pub fn disconnect_configured_peer(&mut self) -> Result<(), RuntimeError> {
        let Some(target) = self.configured_targets.first().copied() else {
            return Ok(());
        };
        self.disconnect_configured_peer_for(target.peer_id)
    }

    /// 断开指定 configured peer 并清其 per-peer Init 状态（D7-Implementation-3）。
    ///
    /// **只影响该 peer**：其它 configured peers 的 connection / session / handshake 状态不受影响
    /// （`NetworkService::disconnect_peer` 本身即单 peer 清理 —— D7-1/2 隔离语义）。非 configured
    /// peer 或未连接 ⇒ 幂等 Ok。不自动 reconnect（之后显式 `establish_configured_peers` 可重建）。
    pub fn disconnect_configured_peer_for(&mut self, peer_id: NodeId) -> Result<(), RuntimeError> {
        if !self.configured_targets.iter().any(|t| t.peer_id == peer_id) {
            return Ok(());
        }
        if let Some(stack) = &mut self.network_stack {
            stack
                .ns
                .disconnect_peer(peer_id)
                .map_err(RuntimeError::NetworkDial)?;
        }
        self.handshake_init_sent_for.remove(&peer_id);
        Ok(())
    }

    /// 建立**全部** configured peers（STEP 10-19-10-B7-A1-D7-Implementation-3；multi-peer）。
    ///
    /// 单次调用 = 一轮受控推进，对每个 configured target（配置顺序，确定性）：
    /// （1）已 Established ⇒ 跳过（不重复 dial / 不重复 Init）；
    /// （2）未 connected ⇒ `dial_peer`（KEEP-FIRST 防同 NodeId 重复连接）；
    /// （3）已 connected 但本 peer 未发过 Init ⇒ 发送一次（per-peer `handshake_init_sent_for`）；
    ///     已发 ⇒ 等待后续 poll。
    /// 随后 **一次 bounded poll**（`EventLoop::poll_once` ⇒ `NetworkService::poll_transport`
    /// 轮询全部 connections —— NS 是 A/B/C connections owner；Runtime 不直连 Transport）。
    ///
    /// 错误隔离：单个 peer 的 dial / Init / 签名失败只进该 peer 的 `PeerStatus::Failed`，
    /// **不阻塞其它 peer**；仅全局 poll（EventLoop/NS 层）失败 ⇒ `Err(RuntimeError)`。
    /// 返回 `Ok(Vec<PeerEstablishment>)`（按 `configured_targets` 顺序，每 peer 独立结果）。
    ///
    /// 幂等 / 显式 reconnect：Established 不重复建立；EOF/断开后的 peer 再次调用本方法
    /// （无自动 reconnect / 无 retry / 无 timer）即可重建。
    pub fn establish_configured_peers(&mut self) -> Result<Vec<PeerEstablishment>, RuntimeError> {
        let targets: Vec<ConnectionTarget> = self.configured_targets.clone();
        // ===== P1-A.8 — peer lifecycle（逻辑 tick；无墙钟 / 无 RNG）=====
        // 1. 逻辑 tick 推进（每次调用 +1；与 P1-A.6 consensus tick 无关）。
        self.peer_tick = self.peer_tick.saturating_add(1);
        // 2. state 基数恒定以 configured peers 为界（配置不可变，但仍显式 prune）。
        self.prune_peer_lifecycle(&targets);
        if self.network_stack.is_none() {
            return Ok(targets
                .iter()
                .map(|t| PeerEstablishment {
                    peer_id: t.peer_id,
                    status: PeerStatus::Unavailable,
                })
                .collect());
        }
        // A. per-peer 准备（dial / Init）；错误隔离 + **per-peer 退避门控** + **每轮 dial 预算**。
        //    顺序 = `configured_targets` 配置顺序（确定性；不随机选 peer）。
        let mut prepare: Vec<PeerStep> = Vec::with_capacity(targets.len());
        let mut dial_budget = MAX_DIAL_ATTEMPTS_PER_CALL;
        for t in &targets {
            let key = *t.peer_id.as_bytes();
            let established = self
                .network_stack
                .as_ref()
                .map(|s| s.ns.is_peer_established(t.peer_id))
                .unwrap_or(false);
            let connected = self
                .network_stack
                .as_ref()
                .map(|s| s.ns.is_connected(t.peer_id))
                .unwrap_or(false);
            // P1-A.9（P1-2）—— 与 NetworkService **实际会话状态**对账：
            // 连接与会话都消失（TCP/session EOF、对端重启、链路抖动）⇒ 清本 peer 的 per-peer
            // Init 标记，使**下一次 dial 能重新发送** Handshake Init。否则 stale 标记会永久阻止
            // 重握手（dial 成功但 Init 永不重发 ⇒ 单向失联，仅在进程重启后才自愈）。
            //
            // 安全边界（均为必须）：
            // - 仅在 **既未 `connected` 也未 `established`** 时清 ⇒ 有效 session 不受影响；
            // - `connected && !established`（握手进行中）**不**清 ⇒ 不重发 Init / 不消耗 frozen
            //   per-peer handshake rate limit；
            // - 不改 network crate / 不新增握手消息 / 不改 wire protocol / 不绕过认证；
            // - 与 A.8 `peer_lifecycle` 退避是**独立维度**（此处不碰 `failure_count` /
            //   `next_allowed_attempt_tick`）。
            if !connected && !established {
                self.handshake_init_sent_for.remove(&t.peer_id);
            }
            // 已认证 / 已连接：**不 dial**（不在退避门控范围；由既有 prepare 内部跳过 dial）。
            if established || connected {
                match self.establish_prepare(t.peer_id, t.address) {
                    Ok(()) => prepare.push(PeerStep::Prepared(None)),
                    Err(e) => prepare.push(PeerStep::Prepared(Some(e))),
                }
                continue;
            }
            // 需要 dial：先过**退避门**（`peer_tick < next_allowed_attempt_tick` ⇒ NO DIAL）。
            let state = self.peer_lifecycle.get(&key).copied();
            if let Some(s) = state
                && self.peer_tick < s.next_allowed_attempt_tick
            {
                prepare.push(PeerStep::Backoff(s));
                continue;
            }
            // 再过**预算门**（每轮 ≤ MAX_DIAL_ATTEMPTS_PER_CALL；其余本轮不 dial）。
            if dial_budget == 0 {
                prepare.push(PeerStep::Deferred);
                continue;
            }
            dial_budget -= 1;
            self.peer_dial_attempts_total = self.peer_dial_attempts_total.saturating_add(1);
            match self.establish_prepare(t.peer_id, t.address) {
                Ok(()) => {
                    // dial 成功 ⇒ **清除**该 peer 失败历史（下一失败序列从 0 起）。
                    self.peer_lifecycle.remove(&key);
                    prepare.push(PeerStep::Prepared(None));
                }
                Err(RuntimeError::NetworkDial(NetworkServiceError::AlreadyConnected)) => {
                    // KEEP-FIRST 幂等信号：**不是**失败（不计失败 / 不进退避 / 不计数失败）。
                    prepare.push(PeerStep::Prepared(None));
                }
                Err(e) => {
                    let failures = state
                        .map_or(0, |s| s.failure_count)
                        .saturating_add(1)
                        .min(MAX_FAILURE_COUNT);
                    let delay = backoff_delay_ticks(failures);
                    let next = PeerLifecycleState {
                        failure_count: failures,
                        next_allowed_attempt_tick: self.peer_tick.saturating_add(delay),
                    };
                    self.peer_dial_failures_total = self.peer_dial_failures_total.saturating_add(1);
                    self.peer_lifecycle.insert(key, next);
                    match e {
                        // dial 失败 ⇒ 报 `Backoff`（含 failure_count 与剩余 tick；本轮确实**尝试过**）。
                        RuntimeError::NetworkDial(NetworkServiceError::Dial(_)) => {
                            prepare.push(PeerStep::Backoff(next));
                        }
                        // 其余准备错误（Init / 签名 / auth 装配）⇒ 同样计入退避，但保留错误详情。
                        other => prepare.push(PeerStep::Prepared(Some(other))),
                    }
                }
            }
        }
        // B. 一次 bounded poll（推进全部连接的握手；无 while / 无 sleep / 无 async）。
        if let Some(stack) = &mut self.network_stack {
            stack
                .el
                .poll_once(&mut stack.ns)
                .map_err(RuntimeError::EventLoop)?;
        }
        // C. 观察每 target 状态（Established / Pending / Failed / Backoff）。
        let mut out = Vec::with_capacity(targets.len());
        for (t, step) in targets.iter().zip(prepare) {
            let status = match step {
                PeerStep::Prepared(Some(e)) => PeerStatus::Failed(e),
                PeerStep::Backoff(s) => PeerStatus::Backoff {
                    failure_count: s.failure_count,
                    remaining_ticks: s.next_allowed_attempt_tick.saturating_sub(self.peer_tick),
                },
                PeerStep::Deferred | PeerStep::Prepared(None) => {
                    let established = self
                        .network_stack
                        .as_ref()
                        .map(|s| s.ns.is_peer_established(t.peer_id))
                        .unwrap_or(false);
                    if established {
                        PeerStatus::Established
                    } else {
                        PeerStatus::Pending
                    }
                }
            };
            out.push(PeerEstablishment {
                peer_id: t.peer_id,
                status,
            });
        }
        Ok(out)
    }

    /// P1-A.8 — `peer_lifecycle` 基数保证：只保留当前 configured peers 对应的条目
    /// （确定性；防无界增长）。配置本不可变，但**不因此省略该保护**。
    fn prune_peer_lifecycle(&mut self, targets: &[ConnectionTarget]) {
        if self.peer_lifecycle.is_empty() {
            return;
        }
        let keep: BTreeSet<[u8; 32]> = targets.iter().map(|t| *t.peer_id.as_bytes()).collect();
        self.peer_lifecycle.retain(|k, _| keep.contains(k));
    }

    /// 单 target 的 dial / Init 准备（D7-Implementation-3；per-peer；不 poll）。
    ///
    /// - 已 Established ⇒ 不 dial / 不 Init（返回 Ok）。
    /// - 未 connected ⇒ `dial_peer`（dial 失败 ⇒ Err；由调用方隔离）。
    /// - 已 connected 但本 peer 未发过 Init ⇒ 构造 + 发送一次（每 target 一次；新 nonce）。
    fn establish_prepare(
        &mut self,
        remote: NodeId,
        address: std::net::SocketAddr,
    ) -> Result<(), RuntimeError> {
        let Some(stack) = &self.network_stack else {
            return Ok(());
        };
        if stack.ns.is_peer_established(remote) {
            return Ok(());
        }
        // dial（若未连；per-peer —— NS KEEP-FIRST 保证同 NodeId 不重复连接）。
        if !stack.ns.is_connected(remote) {
            let max_frame = stack.ns.config().max_msg_bytes;
            let Some(stack) = &mut self.network_stack else {
                return Ok(());
            };
            stack
                .ns
                .dial_peer(address, remote, max_frame, None)
                .map_err(RuntimeError::NetworkDial)?;
        }
        // 发送 Init（本 peer 未发过；per-peer 集合）。
        if !self.handshake_init_sent_for.contains(&remote) {
            let env = {
                let Some(stack) = &self.network_stack else {
                    return Ok(());
                };
                let auth = stack
                    .ns
                    .config()
                    .peer_auth
                    .ok_or(RuntimeError::PeerAuthMissing)?;
                Self::build_outbound_handshake(stack.signer.as_ref(), &auth)?
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(());
            };
            stack
                .ns
                .enqueue_outbound(remote, env)
                .map_err(RuntimeError::NetworkDial)?;
            let _ = stack.ns.flush_outbound();
            self.handshake_init_sent_for.insert(remote);
        }
        Ok(())
    }

    /// outbound sync orchestration（STEP 10-19-10-B7-A1-D8-2；同步、确定性、有界；无 self ——
    /// step 内字段级借用调用，避免与活跃 NetworkStack 借用冲突）。
    ///
    /// 每 step 一轮：
    /// （1）candidate = Established peers（`ns`；D7 建立；无 Established ⇒ 不产生 / 不发送 ——
    ///      不 dial / 不 handshake / 不 reconnect）；
    /// （2）有界消费 `ledger` intents（`SYNC_SCHEDULE_MAX_PER_STEP`/step），每条经
    ///      `schedule_from_missing_ancestor`（ADR-0062：target = { local_head_height + 1,
    ///      block_hash: None }；**不伪造 ancestor hash / 不猜 head+1 的 hash**）入 scheduler
    ///      （deterministic peer selection 用候选 Established peers）；
    /// （3）`dispatch_batch`：correlator.register（**register-before-send**）→ dispatcher
    ///      （`NetworkSyncDispatcher`：Established gate → SyncBlockRequest → 网络签名 →
    ///      `NetworkService::enqueue_outbound`）。
    ///
    /// 边界：同步 / deterministic / bounded（scheduler/correlator/queue 均 bounded）；不 dial /
    /// 不自动 retry / 不 backoff / 不重新选 peer；expire 为 **release-only**（释放 active，不重发）；
    /// SyncBlockResponse → persist/commit 不在此（保持既有 inbound validation / observation）。
    fn sync_orchestrate(
        ns: &mut NetworkService<BoxTransport>,
        signer: &dyn NetworkSigner,
        scheduler: &mut SyncRequestScheduler,
        correlator: &mut SyncRequestCorrelator,
        tick: &mut LogicalTick,
        ledger: &mut MissingAncestorIntentLedger,
        head_height: Option<u64>,
    ) -> Result<(), RuntimeError> {
        // 0. D8-3-1-E：每 step 推进 deterministic tick + expire 到期 active request。
        //    P1-A.17：仍为 **release-only**（不开启 correlator 自动 retry seam）—— 释放后的槽位由
        //    调用侧的 catch-up 驱动（`record_catchup_intent`）在下一步以**新 request_id + 轮换 peer**
        //    重新发起 ⇒ 有界重发（无 retry storm / 无重复 register 语义冲突）。
        *tick = tick.saturating_add(1);
        let _expired = correlator.expire_at(*tick);
        // 1. candidate = Established peers（SI-6：只向 Established 发送）。
        let candidates: Vec<PeerCandidate> = ns
            .established_peers()
            .into_iter()
            .map(|id| PeerCandidate { peer_id: id })
            .collect();
        if candidates.is_empty() {
            // 无 Established peer ⇒ 不产生 request（不 dial / 不 reconnect —— 属 D7 lifecycle）。
            return Ok(());
        }
        let policy = PeerSelectionPolicy::default();
        // P1-A.17 —— deterministic peer rotation（无新状态 / 无假 health / 无随机 / 无墙钟）：
        // `select_peer` 内部对输入再排序（NodeId canonical bytes 字典序）⇒ 仅轮转输入无效；
        // 因此显式构造同一稳定序，并按逻辑 tick 轮转**被排除的前缀**（attempted）⇒ 同一
        // `head+1` target 的多次重发在多个 Established peer 间轮换（单 peer 网络退化为原行为）。
        let mut stable: Vec<PeerCandidate> = candidates.clone();
        stable.sort_by(|a, b| a.peer_id.as_bytes().cmp(b.peer_id.as_bytes()));
        let rotate = (*tick as usize) % stable.len().max(1);
        let attempted: Vec<NodeId> = stable.iter().take(rotate).map(|c| c.peer_id).collect();
        // 2. 有界消费 ledger intents（take_all ≤ cap；本 step 上限 SYNC_SCHEDULE_MAX_PER_STEP）。
        let intents = ledger.take_all();
        let mut scheduled = 0usize;
        for intent in intents {
            if scheduled >= SYNC_SCHEDULE_MAX_PER_STEP {
                break;
            }
            // 陈旧过滤：本地 canonical head 已 ≥ observed 高度 ⇒ 该区间不再待补。
            if let Some(hh) = head_height
                && intent.observed_height <= hh
            {
                continue;
            }
            let peer = match select_peer(&policy, &candidates, &attempted) {
                Ok(p) => p,
                Err(_) => continue, // 无可用候选（candidates 非空时不会发生）
            };
            let request_id = random_request_id().map_err(RuntimeError::NetworkSecurity)?;
            let r = scheduler.schedule_from_missing_ancestor(request_id, peer, &intent);
            if r == ScheduleResult::Scheduled {
                scheduled += 1;
            }
            // Duplicate / Full：bounded 丢弃（不自动重试；同一 intent 只消费一次 —— T10）。
        }
        // B2-C2 —— Trigger #3：低频 proactive catch-up probe（Owner 已批准 Option C′）。
        //
        // 动机（trigger starvation，B2-C2 PRECHECK 实测）：节点已连接 Established peer 但对端**停产**
        // ⇒ 既无 `FutureMissingAncestor` 也无更高外部 QC 证据 ⇒ 既有 Trigger#1/#2 永不触发 ⇒ 落后
        // 节点可永久停在旧高度（head 停滞数万 step、`sync_pending` 恒 0）。
        //
        // 本 probe **只触发既有 pipeline**：scheduler → `dispatch_batch`（correlator.register =
        // register-before-send）→ `NetworkSyncDispatcher` → 既有响应验证 / 登记 / finality commit。
        // **不**构造 `MissingAncestorIntent`（不伪造 `observed_block_hash`、**不写 ledger**）、
        // **不**新建发送 / 验证 / commit 路径、**不**改动 wire / consensus / storage / 既有 limits。
        //
        // 安全边界：
        // - target = `{ height: local_head + 1, block_hash: None }`（ADR-0062 height-anchored：
        //   `None` 诚实表达“target hash 未知”）—— **绝不**使用 head hash / 前块 hash / 零值 /
        //   哨兵 / 猜测 hash；真实 hash 由既有响应验证链决定。
        // - dedup gate（§7 硬要求）：`correlator` active 与 eligible **均空**（request_id 去重
        //   **≠** target-height 去重，故**不**依赖 request_id）；并额外要求 `scheduler` 队列为空
        //   —— 确保本 step 已由真实证据排入的请求不会与同高度 probe 重复（只加强，不弱化）。
        // - 频率：每 `SYNC_PROBE_INTERVAL` 个逻辑 tick 至多 1 次 —— 复用既有 `*tick`。
        // - peer：复用既有 `select_peer` + 既有 tick 轮转（`attempted`）⇒ one peer per probe，不广播。
        // - request_id：复用既有 `random_request_id()`（CSPRNG；无新计数器 / 无持久状态）。
        if tick.is_multiple_of(SYNC_PROBE_INTERVAL)
            && scheduler.is_empty()
            && correlator.is_empty()
            && correlator.eligible_len() == 0
            && let Some(hh) = head_height
            && let Ok(peer) = select_peer(&policy, &candidates, &attempted)
        {
            let request_id = random_request_id().map_err(RuntimeError::NetworkSecurity)?;
            // Duplicate / Full 在此不可达（gate 已保证队列空 + request_id 全新）；仍 bounded 丢弃。
            let _ = scheduler.schedule(SyncRequestIntent {
                request_id,
                peer,
                target: SyncRequestTarget {
                    height: hh.saturating_add(1),
                    block_hash: None,
                },
            });
        }
        if scheduler.is_empty() {
            return Ok(());
        }
        // 3. dispatch（register-before-send）：deadline = 当前 tick + horizon（expire 在函数头
        //    已驱动；D8-3-1 不自动 retry）。
        let deadline = tick.saturating_add(SYNC_DEADLINE_HORIZON);
        let mut dispatcher = NetworkSyncDispatcher::new(ns, signer);
        // dispatch_batch：register-before-send；send 失败（Rejected）⇒ release 该 request（D8-3-1-B）。
        let report = dispatch_batch(
            scheduler,
            correlator,
            &mut dispatcher,
            deadline,
            SYNC_DISPATCH_MAX_PER_STEP,
        );
        let _ = report;
        Ok(())
    }

    /// 构造 outbound Handshake Init envelope（本端身份；`claimed = signer.node_id()`，**非**
    /// configured peer）。复用 session `handshake_payload_encode` + `random_session_nonce`
    /// （每次新 nonce）+ 既有 `MessageEnvelope` + `NetworkSigner::sign_envelope`。
    fn build_outbound_handshake(
        signer: &dyn NetworkSigner,
        auth: &PeerAuthConfig,
    ) -> Result<MessageEnvelope, RuntimeError> {
        let nonce = random_session_nonce().map_err(RuntimeError::Session)?;
        let local = signer.node_id();
        let payload = handshake_payload_encode(
            HandshakeKind::Init,
            auth.network_id,
            auth.chain_id,
            auth.genesis_hash,
            auth.protocol_version,
            &local,
            &nonce,
            auth.capabilities,
        )
        .map_err(RuntimeError::Session)?;
        let mut env = MessageEnvelope {
            version: 1,
            message_type: MessageType::Handshake,
            payload,
            sender: local,
            signature: [0u8; 64],
        };
        signer
            .sign_envelope(&mut env)
            .map_err(RuntimeError::NetworkSigning)?;
        Ok(env)
    }

    /// network peer-auth 配置（ChainIdentity 绑定 network/chain/genesis + 协议常量）。
    fn network_peer_auth(identity: &ChainIdentity) -> PeerAuthConfig {
        PeerAuthConfig {
            network_id: identity.network_id,
            chain_id: identity.chain_id,
            genesis_hash: identity.genesis_hash,
            protocol_version: NETWORK_PROTOCOL_VERSION,
            capabilities: b"",
            per_peer_handshake_limit: 8,
            global_handshake_limit: 128,
            replay_cache_capacity: 256,
        }
    }

    /// 取走 Driver 验证 PASS 后待广播的 consensus outbound **semantic**（手动提取 / 测试用；
    /// `step()` 会自行 drain + egress）。网络 disabled 亦可调用（outbound 在 Driver，独立于
    /// NetworkStack）。
    pub fn take_consensus_outbound(&mut self) -> Vec<OutboundConsensusMessage> {
        self.driver.take_outbound()
    }

    /// consensus orchestration 入口（STEP 10-18I-D-A Option A）：把 node 层 consensus command
    /// （EventLoop → Handler decode queue → Runtime 承接）交给 Driver 的既有安全门面。
    /// - verify/decode/transition 门面 FAIL 原样以 `DriverError` 传出（不吞错、不改状态）。
    /// - outbound：验证 PASS 后入 Driver pending（STEP 10-18I-N-IMPL：`step()` 末尾 drain →
    ///   egress adapter 签名 → `NetworkService` broadcast）；本方法仅承接 command。
    /// - 借用生命周期严格限当前调用（不长期借 Driver；无 self-reference）。
    pub fn process_consensus_command(
        &mut self,
        command: NodeConsensusCommand,
    ) -> Result<(), DriverError> {
        // PHASE 6H-A30 OD-X7 — 只读观测：入站提案消费计数。
        // 边界（MUST）：不改变顺序 / guard / 处理结果；**不**触碰 `wiring.rs`。
        if matches!(&command, NodeConsensusCommand::Proposal(_)) {
            self.liveness.inbound_prop_ok = self.liveness.inbound_prop_ok.saturating_add(1);
        }
        process_inbound_consensus_command(
            &mut self.driver,
            &self.block_production,
            &mut PendingAdmission {
                store: &mut self.pending_proposals,
                config: &self.round_timeout_config,
                tick: self.inbound_tick,
            },
            &mut self.missing_ancestor_ledger,
            &mut self.pending_external_qc,
            &mut self.inbound_qc_deferred,
            command,
        )
    }

    /// PHASE 6H-A30 OD-X7 — **只读** liveness 观测快照（供 CLI 独立 `liveness` 行）。
    ///
    /// - **不参与任何判定**（零共识语义）；全部为 saturating 计数或只读派生。
    /// - `prop_skip_fail` 为**残差**（`calls − ok − known_skips`），**不**推断未知原因。
    /// - `round_adv_rc` 直接暴露**既有** `round_changes_by_authority`（**不**新增计数）。
    pub fn liveness_snapshot(&self) -> LivenessSnapshot {
        // PHASE 6H-A30 OD-X7d — 只读快照：既有 `diagnostics()`（`&self`）；無网络 ⇒ `None` ⇒ 0。
        let net_diag = self.network_stack.as_ref().map(|s| s.ns.diagnostics());
        let el_diag = self.network_stack.as_ref().map(|s| s.el.diagnostics());
        // PHASE 6H-A30 OD-X7f — 只读：对**既有** outcomes 窗口分类（无新增计数点 / 无推算）。
        let mut bv_total = 0u64;
        let mut bv_future = 0u64;
        let mut bv_known = 0u64;
        let mut bv_stale = 0u64;
        let mut bv_conflict = 0u64;
        let mut bv_malformed = 0u64;
        // PHASE 6H-A30 OD-X7g — `Err(InboundBlockError)` 细分（真实变体；零新增计数点）。
        let mut be_oversized = 0u64;
        let mut be_wrong_version = 0u64;
        let mut be_wrong_chain = 0u64;
        let mut be_hash_mismatch = 0u64;
        let mut be_invalid_proposer_sig = 0u64;
        let mut be_tx_root_mismatch = 0u64;
        let mut be_noncanonical_tx_order = 0u64;
        let mut be_state_root_mismatch = 0u64;
        let mut be_unsupported_validation = 0u64;
        let mut be_storage = 0u64;
        for outcome in &self.block_inbound_outcomes {
            bv_total = bv_total.saturating_add(1);
            match outcome {
                Ok(InboundBlockVerdict::FutureMissingAncestor { .. }) => {
                    bv_future = bv_future.saturating_add(1);
                }
                Ok(InboundBlockVerdict::AlreadyKnown { .. }) => {
                    bv_known = bv_known.saturating_add(1);
                }
                Ok(InboundBlockVerdict::Stale { .. }) => {
                    bv_stale = bv_stale.saturating_add(1);
                }
                Ok(InboundBlockVerdict::ConflictingParent { .. }) => {
                    bv_conflict = bv_conflict.saturating_add(1);
                }
                Err(InboundBlockError::Malformed) => {
                    bv_malformed = bv_malformed.saturating_add(1);
                }
                Err(InboundBlockError::Oversized { .. }) => {
                    be_oversized = be_oversized.saturating_add(1);
                }
                Err(InboundBlockError::WrongVersion { .. }) => {
                    be_wrong_version = be_wrong_version.saturating_add(1);
                }
                Err(InboundBlockError::WrongChain { .. }) => {
                    be_wrong_chain = be_wrong_chain.saturating_add(1);
                }
                Err(InboundBlockError::HashMismatch { .. }) => {
                    be_hash_mismatch = be_hash_mismatch.saturating_add(1);
                }
                Err(InboundBlockError::InvalidProposerSignature) => {
                    be_invalid_proposer_sig = be_invalid_proposer_sig.saturating_add(1);
                }
                Err(InboundBlockError::TransactionRootMismatch) => {
                    be_tx_root_mismatch = be_tx_root_mismatch.saturating_add(1);
                }
                Err(InboundBlockError::NonCanonicalTransactionOrdering) => {
                    be_noncanonical_tx_order = be_noncanonical_tx_order.saturating_add(1);
                }
                Err(InboundBlockError::StateRootMismatch) => {
                    be_state_root_mismatch = be_state_root_mismatch.saturating_add(1);
                }
                Err(InboundBlockError::UnsupportedValidation(_)) => {
                    be_unsupported_validation = be_unsupported_validation.saturating_add(1);
                }
                Err(InboundBlockError::Storage(_)) => {
                    be_storage = be_storage.saturating_add(1);
                }
                // 仅剩 `CanonicalNextCandidate` ⇒ 归严格残差（== 窗口内 canonical-next 数）。
                Ok(InboundBlockVerdict::CanonicalNextCandidate { .. }) => {}
            }
        }
        let bv_other = bv_total
            .saturating_sub(bv_future)
            .saturating_sub(bv_known)
            .saturating_sub(bv_stale)
            .saturating_sub(bv_conflict)
            .saturating_sub(bv_malformed);
        // PHASE 6H-A30 OD-X7g — 再减去 10 个 `block_err_*`（上方原式逐字保持不变）⇒
        // 严格残差 == 窗口内 `Ok(CanonicalNextCandidate)` 数。
        let bv_other = bv_other
            .saturating_sub(be_oversized)
            .saturating_sub(be_wrong_version)
            .saturating_sub(be_wrong_chain)
            .saturating_sub(be_hash_mismatch)
            .saturating_sub(be_invalid_proposer_sig)
            .saturating_sub(be_tx_root_mismatch)
            .saturating_sub(be_noncanonical_tx_order)
            .saturating_sub(be_state_root_mismatch)
            .saturating_sub(be_unsupported_validation)
            .saturating_sub(be_storage);
        LivenessSnapshot {
            prop_calls: self.liveness.prop_calls,
            prop_build_ok: self.liveness.prop_build_ok,
            prop_skip_not_elected: self.liveness.prop_skip_not_elected,
            prop_skip_height_desync: self.liveness.prop_skip_height_desync,
            prop_skip_step_guard: self.liveness.prop_skip_step_guard,
            prop_skip_conflict_target: self.liveness.prop_skip_conflict_target,
            prop_skip_fail: self.liveness.skip_fail(),
            inbound_prop_ok: self.liveness.inbound_prop_ok,
            egress_prop_enqueued: self.liveness.egress_prop_enqueued,
            egress_prop_refreshed: self.liveness.egress_prop_refreshed,
            egress_prop_no_peer: self.liveness.egress_prop_no_peer,
            round_adv_local: self.liveness.round_adv_local,
            round_adv_height: self.liveness.round_adv_height,
            round_adv_rc: self.round_changes_by_authority,
            elected_is_self: self.liveness.elected_is_self,
            prop_absent_steps: self.liveness.prop_absent_steps,
            // PHASE 6H-A30 OD-X7b — 直接读取真实计数槽位（无增量点 / 无结果猜测）。
            proposal_admitted: self.pending_proposals.admitted_count(),
            proposal_pending: self.pending_proposals.pended_count(),
            proposal_rejected: self.pending_proposals.rejected_count(),
            proposal_expired: self.pending_proposals.expired_count(),
            // PHASE 6H-A30 OD-X7d — 直读既有网络/事件环诊断（无增量点 / 无推算）。
            net_frames_received: net_diag.map_or(0, |d| d.frames_received),
            net_events_enqueued: net_diag.map_or(0, |d| d.events_enqueued),
            net_sent: net_diag.map_or(0, |d| d.sent),
            net_dropped_invalid: net_diag.map_or(0, |d| d.dropped_invalid),
            net_dropped_overflow: net_diag.map_or(0, |d| d.dropped_overflow),
            net_unauthenticated_drops: net_diag.map_or(0, |d| d.unauthenticated_drops),
            el_handler_errors: el_diag.map_or(0, |d| d.handler_errors),
            el_events_dropped_overflow: el_diag.map_or(0, |d| d.events_dropped_overflow),
            // PHASE 6H-A30 OD-X7e — 直读既有 `A11Diag` 字段（无新增计数点 / 无推算）。
            recovery_runs: self.a11_diag.recovery_runs,
            recovery_candidates: self.a11_diag.recovery_candidates,
            recovery_kept_missing_block: self.a11_diag.recovery_kept_missing_block,
            recovery_admitted: self.a11_diag.recovery_admitted,
            recovery_rejected: self.a11_diag.recovery_rejected,
            block_inbound_processed: self.a11_diag.block_inbound_processed,
            block_canonical_next: self.a11_diag.block_canonical_next,
            block_register_ok: self.a11_diag.block_register_ok,
            // PHASE 6H-A30 OD-X7f — 窗口内分类（既有 outcomes；残差法）。
            block_verdict_future_missing_ancestor: bv_future,
            block_verdict_already_known: bv_known,
            block_verdict_stale: bv_stale,
            block_verdict_conflicting_parent: bv_conflict,
            block_verdict_malformed: bv_malformed,
            block_verdict_other: bv_other,
            // PHASE 6H-A30 OD-X7g — Err 细分（窗口内；与 Ok 五类 + malformed + other 穷尽）。
            block_err_oversized: be_oversized,
            block_err_wrong_version: be_wrong_version,
            block_err_wrong_chain: be_wrong_chain,
            block_err_hash_mismatch: be_hash_mismatch,
            block_err_invalid_proposer_signature: be_invalid_proposer_sig,
            block_err_transaction_root_mismatch: be_tx_root_mismatch,
            block_err_noncanonical_transaction_ordering: be_noncanonical_tx_order,
            block_err_state_root_mismatch: be_state_root_mismatch,
            block_err_unsupported_validation: be_unsupported_validation,
            block_err_storage: be_storage,
            // PHASE 6H-A30-OD-X7h — 来源类别累计（直读既有 `A11Diag`；无推算 / 无增量点）。
            block_src_gossip_total: self.a11_diag.block_src_gossip_total,
            block_src_gossip_invalid_proposer_signature: self
                .a11_diag
                .block_src_gossip_invalid_proposer_signature,
            block_src_sync_total: self.a11_diag.block_src_sync_total,
            block_src_sync_invalid_proposer_signature: self
                .a11_diag
                .block_src_sync_invalid_proposer_signature,
            // PHASE 6H-A30-OD-X7i — gossip IPS 来源分类累计（直读既有 `A11Diag`）。
            block_gossip_invalid_proposer_signature_evidence_conflict: self
                .a11_diag
                .block_gossip_invalid_proposer_signature_evidence_conflict,
            block_gossip_invalid_proposer_signature_signature_failure: self
                .a11_diag
                .block_gossip_invalid_proposer_signature_signature_failure,
        }
    }

    /// canonical consensus node handle（只读）—— **delegate** `driver.consensus()`（不复制）。
    pub fn consensus(&self) -> &ConsensusNode {
        self.driver.consensus()
    }

    /// validator mode 是否启用 —— **delegate** `driver.actor_count()`。
    pub fn validator_enabled(&self) -> bool {
        self.driver.actor_count() > 0
    }

    /// 单验证者只读 view（validator mode 时为 `Some`）—— **delegate** `driver.actor(0)`。
    /// 调用时动态构造（含对 actor 的借用）；不长期存储 actor 引用（无 self-reference）。
    pub fn validator(&self) -> Option<ValidatorView<'_>> {
        let actor = self.driver.actor(0)?;
        let journal = self.validator_journal.as_ref()?;
        Some(ValidatorView {
            validator_id: actor.validator_id(),
            journal_path: journal.as_path(),
            actor,
        })
    }

    /// **P1-A.14** — 网络生命周期 helper（**仅**网络层；**零**共识副作用）。
    ///
    /// 严格等价于抽取前 `step()` 的既有网络段（顺序与语义**不变**，不复制/不重写网络逻辑）：
    ///
    /// 1. `inbound_tick` 递增（既有网络侧计数）。
    /// 2. `inbound.begin_step()`（重置本 step 入站帧预算 ≤ `MAX_INBOUND_FRAMES_PER_POLL`）。
    /// 3. `inbound_accept_and_greet(..)`（accept ≤ `MAX_ACCEPT_PER_STEP`；KEEP-FIRST；
    ///    `connect_peer`（connected ≠ authenticated）；本端 Handshake Init；失败只计数 ⇒ 无 Err）。
    /// 4. `stack.el.poll_once(&mut stack.ns)`（握手 / 会话 / EOF 处理；错误映射 `EventLoop`）。
    /// 5. `inbound_reconcile(..)`（EOF 清理 + pending 状态机）。
    ///
    /// **不**执行（因此共识状态零变更）：`take_commands()` / `process_inbound_consensus_command`
    /// / `take_block_inbound` / sync 编排 / `drive_round_timeout` / `runtime_propose` / 提案 egress /
    /// `drive_local_consensus` / finality 持久化 / QC history / commit bridge / `advance_to_height` /
    /// egress drain。网络 stack 产生的 command / block-inbound 事件**保留在既有有界队列**中，
    /// 由随后的正式 `step()` drain（不新增队列、不改容量、不改协议）。
    ///
    /// 网络 disabled（`network_stack == None`）⇒ `Ok(())`（与 `step()` 的原早退分支一致）。
    fn poll_network_lifecycle(&mut self) -> Result<(), RuntimeError> {
        let Some(stack) = &mut self.network_stack else {
            return Ok(());
        };
        // D9 Step 7 — 入站 listener 前半段（1. inbound accept/greet；bounded；nonblocking）。
        // - `begin_step` 重置本 step 入站帧预算（≤ MAX_INBOUND_FRAMES_PER_POLL）。
        // - accept ≤ MAX_ACCEPT_PER_STEP；KEEP-FIRST；connect_peer（connected ≠ authenticated）；
        //   本端 Handshake Init（复用既有原语；每连接一次）。
        // - 失败只计数（无 Err 传播）⇒ 不中断共识 step。
        self.inbound_tick = self.inbound_tick.wrapping_add(1);
        if let Some(inbound) = stack.inbound.as_ref() {
            inbound.begin_step();
        }
        inbound_accept_and_greet(
            stack.inbound.as_ref(),
            &mut stack.ns,
            stack.signer.as_ref(),
            &mut self.inbound_pending,
            self.inbound_tick,
        );
        stack
            .el
            .poll_once(&mut stack.ns)
            .map_err(RuntimeError::EventLoop)?;
        // D9 Step 7 — 入站 listener 后半段（EOF 清理 + pending 状态机；基于 poll 后最新状态）。
        // 顺序：accept/greet（poll 前）→ poll → reconcile（poll 后）—— 保持既有 step 顺序不变，
        // 只在最小位置插入入站生命周期。
        inbound_reconcile(
            stack.inbound.as_ref(),
            &mut stack.ns,
            &mut self.inbound_pending,
            self.inbound_tick,
        );
        Ok(())
    }

    /// **P1-A.14** — 网络生命周期**窄口**（启动 warm-up 专用）：仅驱动 1–5 步网络生命周期，
    /// **不** drain / 不处理任何 consensus command / block inbound / sync / round-timeout /
    /// proposer / 投票 / QC / finality / commit / head advance / egress。
    ///
    /// 用途：与 `establish_configured_peers()` 交替调用，使**双向**（含 listener 侧 accept/greet）
    /// 的网络生命周期可在**不进入共识**的前提下推进 —— 纯 `establish_configured_peers()` 只驱动
    /// 本端 dial 侧，无法完成 listener 侧（P1-A.13 实测：`established_peers=0~1` 耗尽 300 轮）。
    ///
    /// 安全边界：见 `poll_network_lifecycle()` 文档（proposal / vote / QC / finality / commit /
    /// head advance / round mutation 全部为 NO）。
    pub fn poll_network_only(&mut self) -> Result<(), RuntimeError> {
        self.poll_network_lifecycle()
    }

    /// P1-A.17 —— **catch-up 驱动**（node-layer；无新协议 / 无新状态 / 不伪造 hash）。
    ///
    /// # 问题（P1-A.16 判定）
    /// 追赶 intent 只由**新到的** QC / block verdict 事件产生（`MissingAncestorIntentLedger`），
    /// 而远端每产生**一个新高度**才带来 1 条 intent ⇒ 落后节点每步最多补 1 块，且补块速率被
    /// 锚定为「远端产块速率」⇒ **gap 永不收敛**（即使窗口足够大）。
    ///
    /// # 本函数做什么
    /// 用**既有**可观测证据自持地补记 intent：
    /// - 证据 = `pending_external_qc` 中**保留**的 future external QC（其 `target` 尚未进本地 DAG
    ///   ⇒ 其高度严格高于本地 head）——这正是「远端存在更高链」的**既有**证据（复用 ADR-0064 的
    ///   pending 缓冲，**不新增** Status 解析 / 不改 wire / 不加状态）；
    /// - 仅在 **无 in-flight**（correlator active + eligible 均为空）时补记 ⇒ 每步 ≤
    ///   [`SYNC_CATCHUP_INTENTS_PER_STEP`]，天然 bounded；上一请求一旦 resolve/expire，下一步即补发
    ///   ⇒ 这就是**有界重发**（新 `request_id` + 轮换 peer），无需开启 correlator 的自动 retry seam；
    /// - `observed_height` = 该 QC 的真实高度（真实证据）；dedup key = 其 `target`
    ///   （**不伪造** `head+1` 的 hash）；target 仍按既有 ADR-0062 规则（`local_head + 1` / `hash = None`）；
    /// - 追平后：pending 中的 future QC 被采纳路径消费 / 清空 ⇒ 证据消失 ⇒ **驱动自动停止**（无空转）。
    fn record_catchup_intent(
        ledger: &mut MissingAncestorIntentLedger,
        pending: &VecDeque<PendingExternalQc>,
        correlator: &SyncRequestCorrelator,
        head_height: Option<u64>,
        budget: usize,
    ) -> usize {
        if budget == 0 {
            return 0;
        }
        let Some(head) = head_height else {
            return 0;
        };
        if !correlator.is_empty() || correlator.eligible_len() > 0 {
            return 0;
        }
        let Some(entry) = pending
            .iter()
            .find(|p| p.qc.context.height.saturating_add(1) > head)
        else {
            return 0;
        };
        ledger.record(MissingAncestorIntent {
            observed_height: entry.qc.context.height.saturating_add(1),
            observed_block_hash: entry.qc.target,
            local_head_height: head,
            source: BlockInboundSource::SyncResponse,
            count: 1,
        });
        1
    }

    /// 一轮运行时驱动（Stage C）：网络 disabled（`start`）⇒ `Ok(())`（不产生网络 identity）；
    /// 启用网络（`start_with_network`）⇒ EventLoop poll NetworkService → dispatch →
    /// Handler 产 **owned** `NodeConsensusCommand` → Runtime drain → `process_command` →
    /// Driver（既有验证门面）→ ConsensusNode / ValidatorActor。
    ///
    /// borrow-safe：`poll_once` 临时借 `stack.el` + `stack.ns`（同栈内 disjoint 字段）；
    /// `take_commands()` 返回 owned commands 后即释放 EventLoop 借用；随后才 `&mut self.driver`。
    /// 无 `Handler → &mut Driver/Runtime`、无 self-reference（无 Rc/RefCell/Arc/unsafe/async）。
    pub fn step(&mut self) -> Result<(), RuntimeError> {
        if self.network_stack.is_none() {
            // 网络 disabled：node-local proposer orchestration（真实 BlockBuilder；显式 timestamp）。
            let proposal = runtime_propose(
                &mut self.driver,
                &self.block_production,
                self.proposal_timestamp,
                &mut self.liveness,
            )?;
            if let Some(pb) = proposal {
                self.last_proposal = Some(pb);
            }
            // PHASE 6H-A30 OD-X7 — 只读瞬态观测（不相交字段引用；**不**参与判定）。
            observe_liveness_transient(&self.driver, &mut self.liveness);
            return Ok(());
        }
        // P1-A.6 — round-timeout 决策的**入口观测快照**：仅用于判定「本 step 是否在当前
        // `(height, round)` 内观测到 canonical 进展」（⇒ RESET）；仅本 step 内瞬时有效，
        // **不**进入计时器状态、不跨 step 保留 hash。
        let round_entry = observe_round(self.driver.consensus());
        // P1-A.14 — 网络生命周期（既有 1–5 步）抽取为 `poll_network_lifecycle()`：
        // **顺序与语义完全不变**（本调用即原内联代码位置）；窄口 `poll_network_only()` 复用同一
        // helper（抽取而非复制 ⇒ 不存在第二套网络逻辑）。
        self.poll_network_lifecycle()?;
        let Some(stack) = &mut self.network_stack else {
            // 不可达（上方已判 `None`）；保留「无网络栈 ⇒ 无网络阶段」的既有语义。
            return Ok(());
        };
        let commands = stack.el.handler_mut().take_commands();
        // P1-A.4：**入站（peer 提供）consensus command** 的 Driver 拒绝边界。
        //
        // 与本地路径（`drive_local_consensus` / proposer / commit bridge / DAG 登记 / egress）
        // **故意不同**：本路径的输入完全由已认证 peer 提供，必须为「拒绝 + 计数 + 继续」而非致命
        // 错误 —— 否则任何一个 peer 都能用一条非法 vote 或不可应用（target ∉ 本节点 DAG）的 QC
        // 远程终止本节点。拒绝语义本身不变：driver 先验证后转移（verify-then-transition），失败
        // ⇒ 零 canonical 变更 / 无 lock / 无 outbound；被拒命令仅被丢弃，不产生任何状态变更。
        // （P1-A.5：本地路径仅对**同一**条件「派生 QC target ∉ DAG」做同类容忍 —— 见
        //  `drive_local_consensus`；`inbound_consensus_rejected` 与 `derived_qc_not_applicable`
        //  是两个独立计数，不互相混合。）
        for command in commands {
            // PHASE 6H-A30 OD-X7 — 只读观测：入站提案消费计数。
            // 边界（MUST）：不改变顺序 / guard / 处理结果；**不**触碰 `wiring.rs`。
            if matches!(&command, NodeConsensusCommand::Proposal(_)) {
                self.liveness.inbound_prop_ok = self.liveness.inbound_prop_ok.saturating_add(1);
            }
            // P1-A.4：**入站（peer 提供）** consensus command 的 Driver 拒绝边界（拒绝 + 计数 + 继续）。
            // P1-A.7：同一入口内附加有界 pending / defer 计数 / 恢复 hint（见 free fn doc）。
            if process_inbound_consensus_command(
                &mut self.driver,
                &self.block_production,
                &mut PendingAdmission {
                    store: &mut self.pending_proposals,
                    config: &self.round_timeout_config,
                    tick: self.inbound_tick,
                },
                &mut self.missing_ancestor_ledger,
                &mut self.pending_external_qc,
                &mut self.inbound_qc_deferred,
                command,
            )
            .is_err()
            {
                // 不记录错误文本 / payload / 签名（避免运行期材料外泄）；至少一次计数、不 panic。
                self.inbound_consensus_rejected = self.inbound_consensus_rejected.saturating_add(1);
            }
        }
        // STEP 10-19-10-A：Node-level block inbound dispatch —— wiring 收集的 GossipBlock /
        // SyncBlockResponse payload → block_inbound validator（只读）→ typed verdict 观测。
        // 不 commit / 不写存储 / 不推进 head（CanonicalNextCandidate 非 finality-authorized）。
        let block_msgs = stack.el.handler_mut().take_block_inbound();
        // PHASE 6H-Z §11：入站 O2 `RoundChangeCertificate`（bounded 队列；D3 限速在 Network 层
        // 已完成）—— 本层只搬 payload；decode / 验证 / 适用性 / 应用在
        // [`drive_round_change_authority`]（委托冻结 `verify_certificate`）。
        let round_change_msgs = stack
            .el
            .handler_mut()
            .take_round_changes_bounded(ROUND_CHANGES_PER_STEP);
        // PHASE 6H-AF §9：入站 O2 `ConsensusAbandonAttestation`（`0x0E`；ADR-0075）—— 只搬 payload；
        // ADR-0074 decode 与冻结验签（`verify_evidence`，经池 `admit`）在下方权威段完成。
        let abandon_attestation_msgs = stack
            .el
            .handler_mut()
            .take_abandon_attestations_bounded(ABANDON_ATTESTATIONS_PER_STEP);
        // D10-A Step 3：向 D9 proposer validation 提供本地 ValidatorSet（解除生产 None seam 的
        // canonical-next 假阻塞）—— 远端 canonical-next 块经本地 `select_proposer` → expected VK
        // 真实验签；**不 commit / 不推进 head**（block inbound 仍只读观测；远端块自动进入共识 =
        // D10-D 多节点网络 E2E 授权，本 step 不实施）。
        let validator_set = self.driver.consensus().validator_set().clone();
        for msg in block_msgs {
            // PHASE 6H-A11 DIAG — 仅观测：入站 block 消息处理计数。
            self.a11_diag.block_inbound_processed =
                self.a11_diag.block_inbound_processed.saturating_add(1);
            // D8-3-1-A/C：SyncBlockResponse 先做 request_id correlation —— resolve 匹配的 active
            // request（释放 active capacity；request lifecycle 完成）；Unknown / 结构损坏 ⇒ 安全
            // 拒（不 dispatch 未请求数据 / 不 commit / 不改 canonical / 不创建 request / 不 panic）。
            let msg = match msg {
                BlockInboundMessage::SyncBlockResponse(payload) => {
                    let request_id = match SyncBlockResponse::decode(&payload) {
                        Ok(r) => r.request_id,
                        Err(_) => {
                            // 结构损坏：无法取得 request_id ⇒ 拒（记 unknown；不产生 request）。
                            self.sync_unknown_responses += 1;
                            continue;
                        }
                    };
                    match self.sync_correlator.resolve(request_id) {
                        Ok(_target) => {
                            // resolved：request lifecycle 完成（D8-3-1-C）；block payload 原样交
                            // 后续阶段（本步只 correlation —— 不验证 / 不持久化 / 不 commit）。
                            self.sync_resolved_responses += 1;
                        }
                        Err(_) => {
                            // Unknown request：安全拒绝（不改 correlator / 不创建 / 不 panic）。
                            self.sync_unknown_responses += 1;
                            continue;
                        }
                    }
                    // resolved ⇒ 继续既有 block inbound（adapter 只读验证观测；不 commit）。
                    BlockInboundMessage::SyncBlockResponse(payload)
                }
                other => other,
            };
            // P1-A.18 / A3（register ↔ validate parity）：本 step sync 入站的**同一**有界 QC 证据切片，
            // 同时供 validation 与 registration 使用（gossip 分支保持空切片 ⇒ 既有本地证据链不变）。
            // 仅值传递、不新增任何长期状态；生命周期 = 本 step 本次迭代。
            let mut sync_qc_evidences: Vec<(u64, [u8; 32])> = Vec::new();
            let (source, outcomes, wires) = match (&self.block_production, msg) {
                (Some(adapter), BlockInboundMessage::GossipBlock(wire)) => {
                    // PHASE 6H-A30-ROOTFIX-M3（Owner 授权）—— gossip 轮证据来源：**仅**已接受 proposal
                    // （`proposal_round_evidence`：hash 严格相等 + 父高轮 gate 在函数内保证）。
                    // **不**使用 pending arrival 轮（到达轮 ≠ 生产轮，会把正常 round>0 的块误判）。
                    // 无绑定证据 ⇒ `evidence = None` ⇒ `dispatch_gossip_block_round_aware` 经
                    // [`resolve_inbound_block_round`] **回退到 `header.round`**（已签名 / 已被 block hash
                    // 承诺；M3 取代了旧的隐式 round 0 回退）⇒ round>0 的诚实提案可正常验证 / 登记 /
                    // 恢复（t7_3 5/7、t7_2 6/7 场景）。
                    // 结构损坏（无法取得 hash）⇒ `None`（validator 自身以 `Malformed` 拒，既有行为）。
                    let evidence = match wire_block_hash(&wire) {
                        Some(h) => proposal_round_evidence(
                            self.driver.consensus().state(),
                            adapter.head().height,
                        )
                        .filter(|(_, bh)| *bh == h),
                        None => None,
                    };
                    (
                        BlockInboundSource::Gossip,
                        vec![dispatch_gossip_block_round_aware(
                            adapter,
                            self.max_block_bytes,
                            &wire,
                            &validator_set,
                            // D9 Step 8A（G1）：注入本地 DAG ⇒ 已落盘但不在 DAG 的块不短路为
                            // AlreadyKnown，走完 ⑥/⑦ 全验证 ⇒ 可幂等补登记（不 commit / 不推 head）。
                            Some(self.driver.consensus().dag()),
                            evidence,
                            last_precommit_round_evidence(self.driver.consensus()),
                        )],
                        vec![Some(wire)],
                    )
                }
                (Some(adapter), BlockInboundMessage::SyncBlockResponse(payload)) => {
                    // P1-A.18 RC-1（Stage 2）：**绑定** QC 证据（**有界**；复用既有
                    // `pending_external_qc`，不新增任何长期状态）。仅当 `qc.target ==` 入站块
                    // hash 时该 QC 的 `context.round` 才会被采用（绑定校验在 dispatcher 内完成）；
                    // 无证据 ⇒ 回退 round 0；同一块 hash 出现两个不同轮 ⇒ 拒绝（不放宽验证）。
                    let qc_evidences: Vec<(u64, [u8; 32])> = self
                        .pending_external_qc
                        .iter()
                        .map(|p| (p.qc.context.round, p.qc.target))
                        .collect();
                    let outcomes = dispatch_sync_block_response_round_aware(
                        adapter,
                        self.max_block_bytes,
                        &payload,
                        &validator_set,
                        Some(self.driver.consensus().dag()),
                        &qc_evidences,
                    );
                    // A3：把**同一**切片交给后续登记阶段（仅值移动；不复制 / 不重算）。
                    sync_qc_evidences = qc_evidences;
                    // D10-C Step 8：逐块 wire（与 outcomes **同序**；结构损坏 ⇒ 单条 None，
                    // 对应 `Err(Malformed)` —— 不登记 / 不落盘）。
                    let wires = match SyncBlockResponse::decode(&payload) {
                        Ok(r) => r.blocks.iter().map(|b| Some(b.0.clone())).collect(),
                        Err(_) => vec![None],
                    };
                    (BlockInboundSource::SyncResponse, outcomes, wires)
                }
                (None, _) => {
                    // 无 canonical adapter（P1-A.24 后仅防御性不可达）：无法验证
                    // （无 state/head 上下文）→ 丢弃并计数。
                    self.block_inbound_skipped += 1;
                    continue;
                }
            };
            for (idx, outcome) in outcomes.into_iter().enumerate() {
                // PHASE 6H-A30-OD-X7i — 仅观测：**Gossip** 路径 `InvalidProposerSignature` 来源分类
                //（A = 绑定证据轮冲突 / B = 真实验签失败）。
                // 依据：gossip dispatcher 顺序固定 —— 先 `resolve_proposer_round_evidence`
                //（Err ⇒ 直接 IPS），后 `validate_block_signature`（失败 ⇒ IPS）。
                // 故在同一输入上**只读复算**证据解析即可精确归类：Err ⇒ A；Ok ⇒ 只能为 B。
                // 严格只读：不执行验签 / 不新增状态 / 不改变 verdict / 不改变控制流。
                if source == BlockInboundSource::Gossip
                    && matches!(&outcome, Err(InboundBlockError::InvalidProposerSignature))
                {
                    let origin = match wires.get(idx) {
                        Some(Some(wire)) => match wire_block_hash(wire) {
                            Some(h) => {
                                let qc_evidence =
                                    last_precommit_round_evidence(self.driver.consensus());
                                match proposal_round_evidence(
                                    self.driver.consensus().state(),
                                    self.block_production
                                        .as_ref()
                                        .map_or(0, |a| a.head().height),
                                )
                                .filter(|(_, bh)| *bh == h)
                                {
                                    // M1 起：无绑定证据 ⇒ 不可能出现 IPS（已归 UnsupportedValidation）
                                    // ⇒ 若出现则视为与 dispatcher 判定域不一致 ⇒ 归 A（不落入 B）。
                                    None => Some(true),
                                    Some(evidence) => Some(
                                        resolve_proposer_round_evidence(
                                            h,
                                            Some(evidence),
                                            qc_evidence,
                                        )
                                        .is_err(),
                                    ),
                                }
                            }
                            None => None,
                        },
                        _ => None,
                    };
                    match origin {
                        Some(true) => {
                            self.a11_diag
                                .block_gossip_invalid_proposer_signature_evidence_conflict = self
                                .a11_diag
                                .block_gossip_invalid_proposer_signature_evidence_conflict
                                .saturating_add(1);
                        }
                        Some(false) => {
                            self.a11_diag
                                .block_gossip_invalid_proposer_signature_signature_failure = self
                                .a11_diag
                                .block_gossip_invalid_proposer_signature_signature_failure
                                .saturating_add(1);
                        }
                        None => {}
                    }
                }
                // PHASE 6H-A30-OD-X7h — 仅观测：按**既有**入站来源分类该块 verdict
                //（`GossipBlock` vs `SyncBlockResponse`；与既有 verdict **同源同序**）。
                // 严格只读：**不**重新执行 validation、**不**改变 verdict / 控制流 / 返回值；
                // saturating + bounded；`source` 为既有 `Copy` 值（不影响后续 `observe`）。
                match source {
                    BlockInboundSource::Gossip => {
                        self.a11_diag.block_src_gossip_total =
                            self.a11_diag.block_src_gossip_total.saturating_add(1);
                        if matches!(&outcome, Err(InboundBlockError::InvalidProposerSignature)) {
                            self.a11_diag.block_src_gossip_invalid_proposer_signature = self
                                .a11_diag
                                .block_src_gossip_invalid_proposer_signature
                                .saturating_add(1);
                        }
                    }
                    BlockInboundSource::SyncResponse => {
                        self.a11_diag.block_src_sync_total =
                            self.a11_diag.block_src_sync_total.saturating_add(1);
                        if matches!(&outcome, Err(InboundBlockError::InvalidProposerSignature)) {
                            self.a11_diag.block_src_sync_invalid_proposer_signature = self
                                .a11_diag
                                .block_src_sync_invalid_proposer_signature
                                .saturating_add(1);
                        }
                    }
                }
                // observation（bounded outcomes；保留既有语义）
                if self.block_inbound_outcomes.len() >= BLOCK_INBOUND_OUTCOME_CAP {
                    self.block_inbound_outcomes.pop_front();
                }
                if let Ok(verdict) = &outcome {
                    // STEP 10-19-10-B1：FutureMissingAncestor → intent ledger（bounded + dedup；
                    // 只记录，不发送 / 不触发 finality）。
                    self.missing_ancestor_ledger.observe(verdict, source);
                    // D10-C Step 8：远端**已验证** canonical-next block ⇒ durable store + 共识 DAG 登记
                    //（node orchestration；不 commit / 不推进 head / 不授予 finality —— 仅使其可被
                    // frozen `verify_qc` 与 commit bridge 消费）。Gossip 与 SyncResponse 统一。
                    if let InboundBlockVerdict::CanonicalNextCandidate { block_hash, .. } = verdict
                        && let Some(Some(wire)) = wires.get(idx)
                        && let Some(adapter) = self.block_production.as_ref()
                    {
                        // PHASE 6H-A11 DIAG — 仅观测：canonical-next 候选计数。
                        self.a11_diag.block_canonical_next =
                            self.a11_diag.block_canonical_next.saturating_add(1);
                        // P1-A.18 / A3 + M3：registration 必须与 validation 使用**同一**轮派生规则。
                        // - sync 分支：用**同一** `sync_qc_evidences` + 同一 canonical hash（verdict 携带，
                        //   与 validation 逐字同一值）解析 ⇒ 同一 round；
                        // - gossip 分支：切片为空 ⇒ `Ok(None)` ⇒ `register_remote_canonical_block`
                        //   内部经**同一** `resolve_inbound_block_round`（证据优先 → `header.round`）
                        //   解析 —— 与 gossip dispatcher **逐字同规则**；
                        // - `Err(冲突轮)` ⇒ **保守拒绝该块**（不落盘 / 不登记）。
                        match resolve_proposer_round_from_evidences(*block_hash, &sync_qc_evidences)
                        {
                            Ok(resolved_round) => {
                                register_remote_canonical_block(
                                    &mut self.driver,
                                    adapter,
                                    wire,
                                    &self.pending_proposals,
                                    resolved_round,
                                    &mut self.a11_diag,
                                )?;
                                // PHASE 6H-A11 DIAG — 仅观测：区块登记成功计数。
                                self.a11_diag.block_register_ok =
                                    self.a11_diag.block_register_ok.saturating_add(1);
                                // PHASE 6H-A11 U3 — pending recovery checkpoint：**同 step / 同
                                // block inbound stage 内**，区块登记成功后立即尝试恢复（OD-C1 = A）。
                                recover_pending_proposals(
                                    &mut self.driver,
                                    adapter,
                                    &mut self.pending_proposals,
                                    &mut self.inbound_consensus_rejected,
                                    &mut self.a11_diag,
                                );
                            }
                            Err(()) => {
                                self.block_inbound_skipped =
                                    self.block_inbound_skipped.saturating_add(1);
                            }
                        }
                    }
                }
                self.block_inbound_outcomes.push_back(outcome);
            }
        }
        // PHASE 6H-A11 U3 — pending **到期 sweep**（每 step **固定**检查上界
        // [`PENDING_SWEEP_MAX_PER_STEP`]；确定性逻辑 tick；**无** wall clock / **无** 新增 timer /
        // **无** while 无界扫描）。淘汰仅计数，**不**产生 progress / **不**触发 RESET。
        let _ = self
            .pending_proposals
            .sweep_expired(self.inbound_tick, PENDING_SWEEP_MAX_PER_STEP);
        // ===== P1-A.7 — bounded External Finality Adoption（ADR-0064）=====
        // 顺序固定：入站 commands（verify_qc + acquire_lock + pending）→ block inbound
        //（register_remote_canonical_block）→ **本采纳检查点** → sync 编排 → round timeout →
        // 提案 → 本地 consensus → finality fact → QC history → commit bridge → advance → egress。
        // 前置检查全部满足才调 `assembly` facade；其余 drop + 计数（不跳高度 / 不改 head）。
        if let Some(adapter) = self.block_production.as_ref() {
            adopt_pending_external_finality(
                &mut self.driver,
                adapter,
                &mut self.pending_external_qc,
                &mut self.external_finality_adopted,
                &mut self.external_finality_rejected,
                &mut self.last_adopted_qc,
            );
        }
        // D9 Step 8A — Production Sync Responder：入站 `SyncBlockRequest`（**Established-only**，
        // 非 Established 已由 `NetworkService` 对非 Handshake 消息 fail-closed 丢弃）→ 每 step
        // 有界 serve（`MAX_SYNC_RESPONSES_PER_STEP`）：BlockStore **只读**查找 → 既有
        // `SyncBlockResponse` codec（单块；`request_id` 原样回带）→ 既有 `NetworkSigner` →
        // 既有 `enqueue_outbound`（本 step 末尾既有 flush 负责真实发送）。
        // **不**产生 finality / **不** commit / **不**推进 head / **不**直接写 socket。
        let requests = stack
            .el
            .handler_mut()
            .take_sync_requests_bounded(crate::sync_responder::MAX_SYNC_RESPONSES_PER_STEP);
        if !requests.is_empty() {
            serve_sync_requests(
                self.block_production.as_ref(),
                &mut stack.ns,
                stack.signer.as_ref(),
                requests,
                &mut self.sync_respond,
                self.qc_history.as_ref(),
            );
        }
        // STEP 10-19-10-B7-A1-D8-2：outbound sync orchestration —— 消费 bounded missing-ancestor
        // intents → ADR-0062 height-based target（head+1 / hash=None）→ deterministic peer
        // selection → scheduler → correlator.register（register-before-send）→ dispatcher →
        // NetworkService.enqueue_outbound（Established-only）。有界；不 dial / 不 retry / 不
        // timeout 策略（D8-2 边界）；Response→persist/commit 不属本步。
        let sync_head = self.block_production.as_ref().map(|a| a.head().height);
        // P1-A.17 —— catch-up 驱动（见 free fn doc）：以**保留的 future external QC** 为证据，
        // 在无 in-flight 请求时自持地补记一条 `head+1` intent ⇒ 落后节点以每步 ≤1 块的速率
        // **自主收敛**（不再被“远端产块速率”锚定）；追平后证据消失、驱动自停。
        let _ = Self::record_catchup_intent(
            &mut self.missing_ancestor_ledger,
            &self.pending_external_qc,
            &self.sync_correlator,
            sync_head,
            SYNC_CATCHUP_INTENTS_PER_STEP,
        );
        Self::sync_orchestrate(
            &mut stack.ns,
            stack.signer.as_ref(),
            &mut self.sync_scheduler,
            &mut self.sync_correlator,
            &mut self.sync_tick,
            &mut self.missing_ancestor_ledger,
            sync_head,
        )?;
        // ===== P1-A.6 — Round Timeout Pacemaker（唯一检查点）=====
        // 顺序固定：sync 编排 → **round-timeout 检查** → `runtime_propose`（本地提案）→
        // `drive_local_consensus`。放在提案生成**之前**，使 round change 后新当选 proposer 能
        // **同一 step** 内走既有提案路径（liveness 在一个 step 内闭合）；其余阶段顺序不变。
        // （free fn + 不相交字段引用：网络段已持 `network_stack` 可变借用。）
        // ===== PHASE 6H-Z — O2 入站 RoundChangeCertificate 权威路径（唯一检查点）=====
        // 顺序固定：**RC 权威应用** → round-timeout 检查 → runtime_propose → drive_local_consensus。
        // 放在 pacemaker **之前**：应用时新 round 的计时器已重开（`elapsed = 1`）⇒ 同一步内
        // pacemaker 看到的是新 `(height, round)` 的**新鲜**窗口 —— 不可能 double timeout /
        // double increment / 为错误 height arm timer。
        // ===== PHASE 6H-A30 OD-X7 — 只读观测：每个 step 读取**一次**单调时钟 =====
        // A3：本 step 内所有计时决策（RC 重开 / pacemaker 到期）共用**同一个**读数
        // ⇒ 同一步内不可能出现"两个不同的 now"导致的时序偏差（单步确定性）。
        let now_ns = clock_ns(self.clock.as_ref());
        // A3：供只读诊断 accessor 使用的"最后一次 step 读数"（**不**参与判定）。
        self.last_tick_ns = now_ns;
        drive_round_change_authority(
            &mut self.driver,
            &self.round_timeout_config,
            now_ns,
            &mut self.round_timer,
            &mut self.round_changes_by_authority,
            &mut self.round_changes_rejected,
            &mut self.round_changes_deferred,
            &mut self.round_change_diag,
            &mut self.round_change_store,
            round_change_msgs,
        );
        // PHASE 6H-AF §8：本 step 的真实 EXPIRE 观测（仅本 step 内有效；`None` = 本 step 未到期）。
        // 由 `drive_round_timeout` 以**真实到期计时器状态**填充（见 [`LocalExpireObservation`]）。
        let mut expired_observation: Option<LocalExpireObservation> = None;
        drive_round_timeout(
            &mut self.driver,
            &self.round_timeout_config,
            now_ns,
            &mut self.round_timer,
            &mut self.round_timeouts,
            &mut self.round_timeout_outcomes,
            &mut self.liveness.round_adv_local,
            round_entry,
            &mut expired_observation,
        );
        // ===== PHASE 6H-AF — O2 attestation 生产 / 入池 / 证书广播（唯一检查点）=====
        // 顺序固定：迁移的本地 EXPIRE 观测 ⇒ **A-C 本地签名** ⇒ 池；随后入池入站 `0x0E`；
        // 最后把池内**已组装**证书经**既有** `0x0D` egress 广播（本 step 末尾既有 flush 发出去）。
        let newly_recorded = if let Some(observation) = expired_observation.as_ref() {
            produce_local_abandon_attestations(
                &self.driver,
                &mut self.round_change_pool,
                observation,
                &mut self.abandon_attestations_produced,
            )
        } else {
            Vec::new()
        };
        // ===== PHASE 6H-AH §3 — O2 **个人 attestation 出站**（唯一新增网络边）=====
        // EXPIRE → sign → pool（`Recorded` 首次收录）⇒ 构造 `OutboundConsensusMessage::AbandonAttestation`
        // ⇒ **既有** `egress`（ADR-0074 冻结 codec，精确 112B）⇒ **既有** `NetworkService::broadcast`
        // ⇒ 本 step 末尾**既有** `flush_outbound`（真 TCP）。
        // 逐字冻结：`0x0E` = 个人 attestation；`0x0D` = 证书（**绝不**把 attestation 塞入 `0x0D`，
        // 也**绝不**由本地 attestation 直接产生本地证书而绕过**跨节点** attestation 累积）。
        // 无对端 Established ⇒ `broadcast` 返回 0（尽力而为，**不**重试、**不**新增队列语义）。
        for attestation in newly_recorded {
            let message = OutboundConsensusMessage::AbandonAttestation(attestation);
            let envelope = crate::egress::envelope_for(&message, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            // D0：`Ok(0)` == "本 step 无任何 Established 对端"（既有 `let _ =` 的**忽略错误**
            // 语义保持不变：`Err` 路径仍不计数、不传播、不重试）。
            let no_peer = matches!(stack.ns.broadcast(envelope), Ok(0));
            if no_peer {
                self.abandon_broadcast_no_peer = self.abandon_broadcast_no_peer.saturating_add(1);
            }
            self.abandon_attestations_broadcast =
                self.abandon_attestations_broadcast.saturating_add(1);
        }
        admit_inbound_abandon_attestations(
            &self.driver,
            &mut self.round_change_pool,
            &mut self.abandon_attestations_rejected,
            abandon_attestation_msgs,
        );
        for certificate in self.round_change_pool.take_pending_broadcast() {
            self.round_change_certificates_assembled =
                self.round_change_certificates_assembled.saturating_add(1);
            // 既有 0x0D 路径：不重设计 certificate transport（ADR-0070 codec + ADR-0073 0x0D）。
            let message = OutboundConsensusMessage::RoundChange(certificate);
            let envelope = crate::egress::envelope_for(&message, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            // D0："已组装但零 Established 对端" 的**唯一**观测点（同上：`Err` 仍不计数）。
            let no_peer = matches!(stack.ns.broadcast(envelope), Ok(0));
            if no_peer {
                self.round_change_broadcast_no_peer =
                    self.round_change_broadcast_no_peer.saturating_add(1);
            }
        }
        // STEP 10-19-6 OPT-1：node-local proposer orchestration —— 仅本节点为当前 proposer 且
        // 阶段 Propose 且本轮未提案时，经 BlockBuilder 产出真实 Block + ProposalRef 并提交；
        // 否则幂等 no-op。不自动投票（vote 仍走既有路径）。
        let proposal = runtime_propose(
            &mut self.driver,
            &self.block_production,
            self.proposal_timestamp,
            &mut self.liveness,
        )?;
        if let Some(pb) = &proposal {
            // 本地产出（本地接受的真实 canonical block；runtime_propose 已 submit proposal）→
            // 登记进共识 DAG（幂等；供 verify_qc / finality 消费）。块由本 actor 真实 build +
            // sign（proposer = 本节点 = select，D9 proposer 边界保持）。
            // D10-C Step 7-A：以块**真实** height/parent 登记（canonical-next B 成为前块 child ⇒
            // lock descendant 判定正确）。
            self.driver
                .consensus_mut()
                .register_block(
                    pb.block_hash,
                    pb.block.header.height,
                    pb.block.header.parent_hash,
                    pb.proposal_ref.proposer,
                )
                .map_err(RuntimeError::DagRegister)?;
            // D9 Egress：本地 canonical proposal + block → outbound（**仅登记成功之后**）。
            // 顺序固定：build/sign → BlockStore.put → submit_proposal → register_block → queue
            //（proposal 先入队，block 后入队；同一 hash 来源由 `build_proposal` 保证）。
            // 失败（encode 失败）⇒ `?` 返回 ⇒ **不进入** outbound（无半成品）；
            // 入队仅本 tick（`build_proposal` 幂等守卫 + 每 step drain ⇒ 不重复广播）。
            let block_wire =
                nova_runtime::encode_block(&pb.block).map_err(RuntimeError::BlockCodec)?;
            // PHASE 6H-A30 OD-X8 — 登记**有界**重播状态（wire 逐字节复用；见 [`ProposalRefresh`]）。
            // 仅在**本次**生产成功后登记（失败路径 `?` 在上方 ⇒ 不会登记半成品）。
            let (bound_height, bound_round) = {
                let round = &self.driver.consensus().state().round;
                (round.height, round.round)
            };
            register_proposal_refresh(
                &mut self.proposal_refresh,
                pb,
                Some(block_wire.clone()),
                bound_height,
                bound_round,
                self.inbound_tick,
            );
            self.driver
                .record_local_proposal(pb.proposal_ref.clone(), block_wire);
            // PHASE 6H-A30 OD-X7 — 只读观测：提案已登记出站（**不**参与判定）。
            self.liveness.egress_prop_enqueued =
                self.liveness.egress_prop_enqueued.saturating_add(1);
            self.last_proposal = Some(pb.clone());
        }
        // PHASE 6H-A30 OD-X8 — 本地提案**有界重播**（in-round refresh）。
        //
        // **不**改任何准入 / 投票 / QC / lock / RC / finality 语义：重播逐字节相同的
        // `ProposalRef` + wire block，经**同一** egress / **同一**入站路径；接收方只有在
        // 自己当前轮 == 生产轮时才会准入（Guard C 逐字不变）。
        //
        // 触发条件：`(height, round)` 未变 ∧ 本轮提案仍为本次产出 ∧ 间隔 ≥ 10 tick
        // ∧ 重播次数 < 3。陈旧状态（轮/高度变化、本轮提案被替换）⇒ 立即清空。
        drive_proposal_refresh(
            &mut self.driver,
            &mut self.proposal_refresh,
            self.inbound_tick,
            &mut self.liveness,
        );
        // PHASE 6H-A30 OD-X7 — 只读瞬态观测（不相交字段引用；**不**参与判定）。
        observe_liveness_transient(&self.driver, &mut self.liveness);
        // D10-A Step 3：本地 consensus 自动推进（每 step 幂等 —— 本地产出的 canonical
        // proposal 自动执行本地 Prevote/Precommit → QC/finality 由既有 transition 产生）。
        // P1-A.5：派生 QC 的 target 不在本节点 DAG（`UnknownTarget`）⇒ **不适用**（非错误）：
        // 计数后继续；其余 Driver 失败仍 fail-closed（见 helper doc）。
        drive_local_consensus(&mut self.driver, &mut self.derived_qc_not_applicable)?;
        // D10-C Step 4：Finality → durable Recovery Fact（**durable-before-bridge**；幂等）。
        // 观察 frozen transition ⑥ 产出的 finalized_reference + 同一 transition 派生的
        // PrecommitQC（consensus 只读；经不相交字段调用 —— 网络段已持 network_stack 借用）。
        // D11-25（Model B）：R 低于既有 durable evidence ⇒ 不写 + 非致命继续（保留更高证据）。
        persist_finality_fact_if_needed(
            &self.driver,
            &self.chain_identity,
            &self.finality_fact_path,
            &mut self.finality_fact_persisted,
        )?;
        // ===== P1-A.7 — durable per-height PrecommitQC history（ADR-0064）=====
        // 与 fact 同点（**persist-before-broadcast**：egress 物理发送在本 step 末）。
        // QC 来源：采纳的外部 QC（`last_adopted_qc`）优先，否则既有本地派生 QC（同一 transition）。
        // 失败：计观测 + 不设锚（下一 step 重试）；**不** halting consensus（纯服务能力）。
        if persist_qc_history_if_needed(
            &mut self.qc_history,
            self.driver.consensus().state().finality.finalized_reference,
            self.last_adopted_qc
                .as_ref()
                .or_else(|| self.driver.consensus().last_precommit_qc()),
            &mut self.qc_history_persisted,
            &mut self.qc_history_written,
        )
        .is_err()
        {
            self.qc_history_write_failed = self.qc_history_write_failed.saturating_add(1);
        }
        // D10-B：Finality → Commit Bridge（每 tick 至多 commit 一个共识-finalized 本地块；
        // 复用 NodeBlockAdapter::apply_block 的冻结 durable commit —— 不重新实现 storage）。
        // B2-D1：同时传入既有 per-height `qc_history`（hash 绑定 QC ⇒ correct round evidence）。
        finality_commit_bridge(
            &mut self.driver,
            self.block_production.as_mut(),
            self.last_proposal.as_ref(),
            self.qc_history.as_ref(),
            self.restored_finality.as_ref().map(|r| &r.qc),
        )?;
        // D10-C Step 7-B：commit 成功后，以 **durable canonical head** 推进 consensus 到下一高度轮
        //（`finality → commit → head durable → advance`；绝不 advance-before-commit）。
        // head 未超过当前 consensus 高度（== 或 <）⇒ no-op（幂等；每 tick 调用安全，不重复清空
        // round/proposal）。advance 为纯内存确定性转移（不触碰 storage）；commit 已 durable，
        // advance 不参与其成败（无「advance 失败 ⇒ 假装 commit 失败」路径）。
        // 同进程内 bridge 每 tick 至多 commit 一个 finalized 块（apply_block ⑤ 强制
        // `height == head.height + 1`）⇒ 高度每次 +1；本调用不做 catch-up 协议。
        let head_height = self.block_production.as_ref().map(|a| a.head().height);
        if let Some(head_height) = head_height
            && head_height > self.driver.consensus().state().round.height
        {
            self.driver.consensus_mut().advance_to_height(head_height);
            // PHASE 6H-A30 OD-X7 — 只读观测：高度推进导致的 round 归零（**不**参与判定）。
            self.liveness.round_adv_height = self.liveness.round_adv_height.saturating_add(1);
        }
        // D10 Recovery C — 恢复状态清理（**非 gate**）：bridge commit 后 canonical head 已到达
        // 恢复的 finalized reference ⇒ 清空 `restored_finality`（不再充当 bridge 证据）。
        // G4 决策：此清理**不**影响 proposal / vote（hard guard 已撤销）；未到达则保留（下 step 可再试）。
        if let Some(reference) = self.restored_finality.as_ref().map(|r| r.reference)
            && self
                .block_production
                .as_ref()
                .is_some_and(|a| a.head().block_hash == reference)
        {
            self.restored_finality = None;
        }
        // STEP 10-18I-N-IMPL：production egress —— drain Driver semantic outbound →
        // NetworkSigner 编码签名 → NetworkService.broadcast（established-only/queue 由 NS 负责）
        // → flush（TCP send）。sign 失败 fail-closed；NS broadcast/flush 失败（queue full / 无
        // established）按 backpressure drop —— 不 panic、不阻塞共识。
        let outbound = self.driver.take_outbound();
        for msg in outbound {
            // PHASE 6H-A30 OD-X7 — 只读观测：仅**提案**消息统计"零 Established 对端"。
            // 语义不变：`Err` 仍忽略（**不**新增 retry / fallback / relay / 错误传播）。
            let is_proposal = matches!(msg, OutboundConsensusMessage::Proposal(_));
            let envelope = crate::egress::envelope_for(&msg, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            let broadcasted = stack.ns.broadcast(envelope);
            if is_proposal && matches!(broadcasted, Ok(0)) {
                self.liveness.egress_prop_no_peer =
                    self.liveness.egress_prop_no_peer.saturating_add(1);
            }
        }
        let _ = stack.ns.flush_outbound();
        Ok(())
    }

    /// 确定性生命周期终止（D2 冻结；**consuming** `self`）。
    ///
    /// 顺序（destructure 一次析构全部字段，显式顺序调用）：
    /// EventLoop stop → NetworkService stop → Driver 生命周期结束（owns ConsensusNode +
    /// ValidatorActor）→ `ChainStorage::close(self)`（最后；consuming）。
    /// - 网络 disabled：跳过 EventLoop/NetworkService；仍 Driver drop + Storage close。
    /// - `PersistentBackend::close` 是唯一可失败子调用 ⇒ `ShutdownError::Storage`。
    /// - 不用 Option 化 Storage / Rc / Arc / Mutex / mem::replace（无绕 ownership workaround）。
    pub fn shutdown(self) -> Result<(), ShutdownError> {
        let Self {
            chain_identity: _,
            chain_storage,
            block_production,
            driver,
            network_stack,
            configured_targets: _,
            handshake_init_sent_for: _,
            validator_journal: _,
            proposal_timestamp: _,
            proposal_refresh: _,
            last_proposal: _,
            finality_fact_path: _,
            finality_fact_persisted: _,
            max_block_bytes: _,
            block_inbound_outcomes: _,
            block_inbound_skipped: _,
            missing_ancestor_ledger: _,
            sync_scheduler: _,
            sync_correlator: _,
            sync_tick: _,
            sync_resolved_responses: _,
            sync_unknown_responses: _,
            inbound_consensus_rejected: _,
            derived_qc_not_applicable: _,
            round_timeout_config: _,
            clock: _,
            last_tick_ns: _,
            round_timer: _,
            round_timeouts: _,
            round_changes_by_authority: _,
            round_changes_rejected: _,
            round_changes_deferred: _,
            round_change_diag: _,
            round_change_broadcast_no_peer: _,
            abandon_broadcast_no_peer: _,
            round_timeout_outcomes: _,
            round_change_store: _,
            round_change_pool: _,
            abandon_attestations_produced: _,
            abandon_attestations_rejected: _,
            abandon_attestations_broadcast: _,
            round_change_certificates_assembled: _,
            inbound_tick: _,
            inbound_pending: _,
            sync_respond: _,
            qc_history: _,
            qc_history_persisted: _,
            qc_history_written: _,
            qc_history_write_failed: _,
            restored_finality: _,
            inbound_qc_deferred: _,
            external_finality_adopted: _,
            external_finality_rejected: _,
            pending_external_qc: _,
            last_adopted_qc: _,
            peer_tick: _,
            peer_lifecycle: _,
            peer_dial_attempts_total: _,
            peer_dial_failures_total: _,
            pending_proposals: _,
            a11_diag: _,
            liveness: _,
        } = self;

        if let Some(mut stack) = network_stack {
            // D9 Step 7：关闭入站 listener + 全部入站连接（幂等；先于 NetworkService shutdown）。
            if let Some(inbound) = stack.inbound.as_ref() {
                inbound.shutdown();
            }
            // EventLoop stop → NetworkService stop（独立 owner；EventLoop 不级联 NS）。
            stack.el.shutdown();
            stack.ns.shutdown();
            // signer（Box<dyn NetworkSigner>）随 stack drop（无显式 shutdown）。
        }
        // Driver 生命周期结束（ConsensusNode + ValidatorActor drop；safety 已 durable journal）。
        drop(driver);
        // Storage 最后关闭：
        // - full-node 形态：显式 `PersistentBackend::close`（flush）。
        // - validator 形态：block-production adapter drop（bootstrap/apply 已完成同步 flush，
        //   无待刷写 —— storage crate 无 `StateStore::into_backend` / close seam；BlockStorage STEP
        //   将补正式 close seam）。
        drop(block_production);
        if let Some(storage) = chain_storage {
            storage.close().map_err(ShutdownError::Storage)?;
        }
        Ok(())
    }
}

/// ValidatorId 单一来源（STEP 10-16）：node 装配层统一入口。
///
/// 实现委托 consensus `ValidatorId::from_consensus_public_key`（= SHA-256(pubkey)，crypto 冻结）。
/// 未来把 crypto `identity::validator_id` 与共识实现收敛至此（本步保持值不变，仅统一调用入口）。
pub fn derive_validator_id(public_key: &[u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::identity::validator_id as crypto_validator_id;
    // PHASE 6H-Z：RC 测试需用**冻结** codec 组帧（不建立第二套 RC 编码）。
    use nova_consensus::round_change::encode_certificate;

    /// PHASE 6H-Z — RC 权威路径测试常量（devnet 编码空间；非主网参数）。
    const RC_TEST_CHAIN_ID: u64 = 1001;
    const RC_TEST_HEIGHT: u64 = 5;
    const RC_TEST_ROUND: u64 = 3;
    const RC_TEST_VSID: [u8; 32] = [0xAB; 32];

    // -----------------------------------------------------------------------
    // P1-A.8 — peer reconnect backoff（冻结公式 + 溢出安全）
    // -----------------------------------------------------------------------

    /// T2（公式层）— 冻结延迟序列 `2,4,8,…,2048,4096,4096,…`；无溢出 / 无 panic / 有界。
    #[test]
    fn p1a8_backoff_delay_table_is_frozen_and_bounded() {
        let expected = [
            2u64, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096, 4096,
        ];
        for (i, want) in expected.iter().enumerate() {
            let n = (i as u32) + 1;
            assert_eq!(backoff_delay_ticks(n), *want, "delay({n})");
        }
        assert_eq!(backoff_delay_ticks(0), 0, "无失败 ⇒ 无延迟");
        // 饱和 / 溢出安全：极大 n 仍为 MAX（不 panic）。
        assert_eq!(backoff_delay_ticks(MAX_FAILURE_COUNT), MAX_BACKOFF_TICKS);
        assert_eq!(backoff_delay_ticks(u32::MAX), MAX_BACKOFF_TICKS);
        // 严格非降 + 始终有界。
        let mut prev = 0u64;
        for n in 1..=64u32 {
            let d = backoff_delay_ticks(n);
            assert!(d >= prev, "delay 非降");
            assert!(d <= MAX_BACKOFF_TICKS, "delay 有界");
            prev = d;
        }
    }
    use nova_crypto::key::KeyPair;

    /// 单一来源一致性：derive_validator_id == consensus impl == crypto identity::validator_id。
    #[test]
    fn derive_validator_id_matches_existing_sources() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let derived = derive_validator_id(&pk);
        assert_eq!(
            derived,
            ValidatorId::from_consensus_public_key(&pk),
            "derive == consensus 实现"
        );
        assert_eq!(
            *derived.as_bytes(),
            crypto_validator_id(&pk),
            "derive == crypto identity::validator_id（值不变）"
        );
    }

    /// P1-A.5 T2（单元负向穷举）：容忍边界**必须**精确等于 `QcVerification(UnknownTarget)`。
    ///
    /// 证明「不能扩大容错范围」：`FinalityError` 全部**其它**变体 + 其它 `DriverError` 变体
    /// 一律 ⇒ `false` ⇒ `drive_local_consensus` 走 `Err(other) => RuntimeError::Driver` ⇒ fail-closed。
    /// （防未来退化为 `Err(_) => Ok(())` 或 `QcVerification(_) => Ok(())`。）
    #[test]
    fn p1a5_tolerance_is_exactly_qc_unknown_target() {
        use crate::validator::ValidatorActorError;
        use nova_consensus::error::ConsensusError;

        // 唯一被容忍的失败（精确变体）。
        assert!(
            derived_qc_not_applicable(&DriverError::QcVerification(FinalityError::UnknownTarget)),
            "QcVerification(UnknownTarget) 是唯一「QC 不适用」（非致命）"
        );

        // `FinalityError` 其余全部变体 ⇒ 不容忍。
        let other_finality = [
            FinalityError::InvalidQcStructure,
            FinalityError::DuplicateValidator,
            FinalityError::ValidatorSetMismatch,
            FinalityError::InsufficientQuorum,
            FinalityError::Evidence(ConsensusError::InvalidSignature),
            FinalityError::NotPrecommitQc,
        ];
        for e in other_finality {
            assert!(
                !derived_qc_not_applicable(&DriverError::QcVerification(e)),
                "QcVerification({e:?}) 不得被容忍（不得写成 QcVerification(_)）"
            );
        }

        // 其它 `DriverError` 变体 ⇒ 不容忍（不得写成 `Err(_) => Ok(())`）。
        let other_driver = [
            DriverError::NoActor(0),
            DriverError::VoteVerification(ConsensusError::InvalidSignature),
            DriverError::ActorLock(ValidatorActorError::IdentityMismatch),
            DriverError::Actor(ValidatorActorError::BlockSigning),
            DriverError::ProposerSelection(ConsensusError::EmptyValidatorSet),
        ];
        for e in other_driver {
            assert!(
                !derived_qc_not_applicable(&e),
                "DriverError::{e:?} 不得被容忍（fail-closed 必须保持）"
            );
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 6H-Z §14-D1 2/5/11/12/16 —— 运行路径：RC 权威应用 / 暂存 / 拒绝 + 独立归因
    // -----------------------------------------------------------------------

    /// 构造最小的 full-node driver（actors = []；RC 应用不需要 actor）。
    fn rc_test_driver(n: usize) -> (NodeConsensusDriver<DynSigner>, Vec<KeyPair>, [u8; 32]) {
        use nova_consensus::dag::Dag;
        use nova_crypto::address::{
            ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
        };
        use nova_crypto::identity::{
            EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
        };

        let mut kps: Vec<KeyPair> = Vec::new();
        let mut vals: Vec<ValidatorInit> = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().expect("keypair");
            vals.push(ValidatorInit {
                account_address: YazimaoAddress::from_payload(YazimaoAddressPayload {
                    address_version: ADDRESS_VERSION,
                    address_type: AddressType::UserAccount,
                    network_id: NetworkId::Mainnet,
                    key_hash: [0xa0 + i as u8; 32],
                }),
                consensus_public_key: kp.verifying_key().to_bytes(),
                bonded_stake: 100,
                commission_bps: 0,
            });
            kps.push(kp);
        }
        vals.sort_by_key(|v| v.consensus_public_key);
        let genesis = GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: RC_TEST_CHAIN_ID,
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
        };
        let set = ValidatorSet::from_genesis(&genesis);
        let consensus = ConsensusNode::new(
            RC_TEST_HEIGHT,
            RC_TEST_ROUND,
            RC_TEST_CHAIN_ID,
            set,
            RC_TEST_VSID,
            Dag::new(),
        );
        (
            NodeConsensusDriver::<DynSigner>::new(consensus, Vec::new()),
            kps,
            RC_TEST_VSID,
        )
    }

    fn rc_test_cert(
        kps: &[KeyPair],
        vsid: [u8; 32],
        height: u64,
        from_round: u64,
    ) -> RoundChangeCertificate {
        use nova_consensus::round_change::{RoundChangeEvidence, abandon_message_hash};
        use nova_crypto::signature::sign_message_hash;
        let hash = abandon_message_hash(RC_TEST_CHAIN_ID, height, from_round).expect("hash");
        let mut evidence: Vec<RoundChangeEvidence> = kps
            .iter()
            .map(|kp| RoundChangeEvidence {
                validator_id: ValidatorId::from_consensus_public_key(
                    &kp.verifying_key().to_bytes(),
                ),
                signature: sign_message_hash(kp.signing_key(), &hash).to_bytes(),
            })
            .collect();
        evidence.sort_by_key(|e| e.validator_id);
        RoundChangeCertificate {
            validator_set_id: vsid,
            height,
            from_round,
            evidence,
        }
    }

    #[test]
    fn phase6hz_rc_authority_apply_store_reject_with_independent_attribution() {
        let (mut driver, kps, vsid) = rc_test_driver(3);
        let config = RoundTimeoutConfig::default();
        let mut timer: Option<RoundTimer> = None;
        let mut by_authority = 0u64;
        let mut rejected = 0u64;
        let mut deferred = 0u64;
        let mut diag = RoundChangeDiag::default();
        let mut store =
            RoundChangeStore::new(nova_consensus::round_change::DEFAULT_MAX_TRACKED_HEIGHTS);

        // ① 无效入站（畸形字节）⇒ 拒绝 + 计数；round 不变（§14-D1-16）。
        let round_before = driver.consensus().state().round.round;
        drive_round_change_authority(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            vec![(NodeId::from_bytes([0x01; 32]), vec![0xFF; 3])],
        );
        assert_eq!(rejected, 1, "malformed ⇒ 拒绝");
        assert_eq!(
            diag.reject_count(RoundChangeRejectKind::Malformed),
            1,
            "D0：解码失败 ⇒ Malformed 桶"
        );
        assert_eq!(by_authority, 0);
        assert_eq!(
            driver.consensus().state().round.round,
            round_before,
            "零 round 变化"
        );

        // ② G-1：future round（from_round > local_round）⇒ **仅暂存**，不推进 / 不重开（§14-D1-2）。
        let future_round = round_before + 2;
        let future = rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, future_round);
        let future_bytes = encode_certificate(&future).expect("encode");
        drive_round_change_authority(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            vec![(NodeId::from_bytes([0x02; 32]), future_bytes)],
        );
        assert_eq!(deferred, 1, "future ⇒ 暂存");
        assert_eq!(by_authority, 0, "暂存不计入权威应用");
        assert_eq!(store.total(), 1, "证书已暂存（有界内存）");
        assert_eq!(
            driver.consensus().state().round.round,
            round_before,
            "不推进"
        );
        assert!(timer.is_none(), "不重开计时器");

        // ③ 当前 round 的合法证书 ⇒ 恰好 +1 + 计时器重开 + **独立**归因（§14-D1-5/10/11/12）。
        let current = rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, round_before);
        let current_bytes = encode_certificate(&current).expect("encode");
        drive_round_change_authority(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            vec![(NodeId::from_bytes([0x03; 32]), current_bytes)],
        );
        assert_eq!(by_authority, 1, "权威应用计数 +1");
        assert_eq!(
            driver.consensus().state().round.round,
            round_before + 1,
            "恰好 +1"
        );
        let armed = timer.expect("已重开计时器");
        assert_eq!(
            (armed.height, armed.round, armed.armed_at_ns),
            (RC_TEST_HEIGHT, round_before + 1, 0),
            "新 round 的新鲜窗口（armed_at = 本 step 单调读数）"
        );
        assert_eq!(armed.elapsed_ns(0), 0, "刚 ARM ⇒ 已历时 0");
        assert_eq!(
            armed.window_ns,
            round_timeout_window_ns(&config, round_before + 1)
        );
        // 归因分离：本函数**不**接受 `round_timeouts` 参数 ⇒ 本地超时计数**结构上不可能**被 RC 影响。
        assert_eq!(timer.map(|t| t.elapsed_ns(0)), Some(0));
        // D0（仅观测）：合法证书不计入任何拒绝桶；暂存 gauge = ② 的 1 张；无重评尝试。
        assert_eq!(rejected, 1, "本用例仅 ① 为拒绝");
        assert_eq!(deferred, 1, "仅 ② 的 future 证书暂存");
        assert_eq!(
            diag.reeval_attempts, 0,
            "无命中当前 (height, local_round) 的暂存证书"
        );
        assert_eq!(diag.reeval_applied, 0);
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Stale), 0);
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Other), 0);
    }

    // -----------------------------------------------------------------------
    // P1-A.30 D0 — 诊断补全（**仅观测**：分类 / 计数 / 归因；零判定变化）
    // -----------------------------------------------------------------------

    /// D0 测试专用：把单条 payload 作为"一次入站批"喂给权威路径（`None` = 空批，仅触发重评）。
    #[allow(clippy::too_many_arguments)]
    fn rc_feed(
        driver: &mut NodeConsensusDriver<DynSigner>,
        timer: &mut Option<RoundTimer>,
        by_authority: &mut u64,
        rejected: &mut u64,
        deferred: &mut u64,
        diag: &mut RoundChangeDiag,
        store: &mut RoundChangeStore,
        payload: Option<&[u8]>,
    ) {
        let inbound = payload
            .map(|p| vec![(NodeId::from_bytes([0x11; 32]), p.to_vec())])
            .unwrap_or_default();
        drive_round_change_authority(
            driver,
            &RoundTimeoutConfig::default(),
            0,
            timer,
            by_authority,
            rejected,
            deferred,
            diag,
            store,
            inbound,
        );
    }

    /// D0 测试专用：`kps` 全量 **+ 一个非成员密钥** ⇒ 必落入 `Identity` 桶（与检查次序无关）。
    fn rc_test_cert_with_foreign_member(
        kps: &[KeyPair],
        vsid: [u8; 32],
        height: u64,
        from_round: u64,
    ) -> RoundChangeCertificate {
        use nova_consensus::round_change::{RoundChangeEvidence, abandon_message_hash};
        use nova_crypto::signature::sign_message_hash;
        let foreign = KeyPair::generate().expect("keypair");
        let hash = abandon_message_hash(RC_TEST_CHAIN_ID, height, from_round).expect("hash");
        let mut evidence: Vec<RoundChangeEvidence> = kps
            .iter()
            .chain(std::iter::once(&foreign))
            .map(|kp| RoundChangeEvidence {
                validator_id: ValidatorId::from_consensus_public_key(
                    &kp.verifying_key().to_bytes(),
                ),
                signature: sign_message_hash(kp.signing_key(), &hash).to_bytes(),
            })
            .collect();
        evidence.sort_by_key(|e| e.validator_id);
        RoundChangeCertificate {
            validator_set_id: vsid,
            height,
            from_round,
            evidence,
        }
    }

    /// P1-A.30 **S5-2**：**同一步**内 `RC 应用` 与 `pacemaker` 的固定顺序 —— 恰一次 +1、无二次超时。
    ///
    /// `step()` 冻结顺序 = `drive_round_change_authority` → `drive_round_timeout`；RC 应用后新 round
    /// 的窗口已重开（`elapsed = 1`）⇒ 同一步 pacemaker 看到 `progressed = true` ⇒ **Reset**（非
    /// Expired）⇒ 不可能 double timeout / double increment / 为错误 round arm 计时器。
    #[test]
    fn p1a30_s5_same_step_rc_apply_and_pacemaker_do_not_double_advance() {
        let (mut driver, kps, vsid) = rc_test_driver(3);
        // 窗口 = 1 tick ⇒ 若本 step 无 RC，pacemaker 必然 EXPIRE。
        let config = RoundTimeoutConfig {
            initial_timeout: 1,
            max_timeout: 2,
            backoff_factor: 1,
        };
        let mut timer: Option<RoundTimer> = None;
        let mut by_authority = 0u64;
        let mut rejected = 0u64;
        let mut deferred = 0u64;
        let mut diag = RoundChangeDiag::default();
        let mut store =
            RoundChangeStore::new(nova_consensus::round_change::DEFAULT_MAX_TRACKED_HEIGHTS);
        let mut round_timeouts = 0u64;
        let mut outcomes = [0u64; RoundTimeoutOutcome::COUNT];
        let mut round_adv_local = 0u64;
        let mut expired: Option<LocalExpireObservation> = None;

        // step 0（ARM）：RC 批为空；入口观测 == 当前观测 ⇒ 不计到期。
        let entry0 = observe_round(driver.consensus());
        drive_round_change_authority(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Vec::new(),
        );
        drive_round_timeout(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut round_timeouts,
            &mut outcomes,
            &mut round_adv_local,
            entry0,
            &mut expired,
        );
        assert_eq!(round_timeouts, 0, "arming step 未到期");
        assert_eq!(by_authority, 0);

        // step 1：**同一步**内先应用当前 round 证书，再跑 pacemaker（入场快照 = 应用前）。
        //
        // A3：单调读数取到**已越过窗口**（1ms 窗口 ⇒ now = 1ms）⇒ 若无 RC 重开，本 step 必然 EXPIRED；
        // RC 在同一读数重开（armed_at = now）⇒ 已历时 0 ⇒ 仍 Waiting（不 double advance）。
        let now_ns: u64 = 1_000_000;
        let entry1 = observe_round(driver.consensus());
        assert_eq!(entry1.round, RC_TEST_ROUND);
        let cert = encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, RC_TEST_ROUND))
            .expect("enc");
        drive_round_change_authority(
            &mut driver,
            &config,
            now_ns,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            vec![(NodeId::from_bytes([0x21; 32]), cert)],
        );
        assert_eq!(by_authority, 1, "RC 权威应用恰一次");
        assert_eq!(rejected, 0);
        drive_round_timeout(
            &mut driver,
            &config,
            now_ns,
            &mut timer,
            &mut round_timeouts,
            &mut outcomes,
            &mut round_adv_local,
            entry1,
            &mut expired,
        );
        // 断言：恰一次 +1；本地超时**未被**触发（归因分离）；计时器为新 round 的新鲜窗口。
        assert_eq!(
            driver.consensus().state().round.round,
            RC_TEST_ROUND + 1,
            "恰 +1（无 double increment）"
        );
        assert_eq!(round_timeouts, 0, "RC 应用后同一步不得产生本地 EXPIRED");
        assert_eq!(round_adv_local, 0);
        assert_eq!(outcomes[RoundTimeoutOutcome::Applied.index()], 0);
        assert!(expired.is_none(), "无真实 EXPIRE 观测");
        let t = timer.expect("已重开计时器");
        assert_eq!(
            (t.height, t.round, t.armed_at_ns, t.window_ns),
            (RC_TEST_HEIGHT, RC_TEST_ROUND + 1, now_ns, 1_000_000)
        );
    }

    /// D0-5：`deferred` gauge = **仅** `Admitted` 计 +1（幂等 + **淘汰**均不干扰）。
    #[test]
    fn p1a30_d0_deferred_gauge_counts_admitted_only() {
        let (mut driver, kps, vsid) = rc_test_driver(3);
        let mut timer: Option<RoundTimer> = None;
        let mut by_authority = 0u64;
        let mut rejected = 0u64;
        let mut deferred = 0u64;
        let mut diag = RoundChangeDiag::default();
        // 极小容量：`max_per_height = 1` ⇒ 第 2 张必然触发 store 自身 FIFO 淘汰。
        let mut store = RoundChangeStore::with_caps(1, 1);

        // ① future round（from_round = local + 1）⇒ 暂存 +1。
        let c1 = encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, RC_TEST_ROUND + 1))
            .expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&c1),
        );
        assert_eq!(deferred, 1);

        // ② 同一 key 重复入站 ⇒ `Duplicate` ⇒ **不**增（幂等）。
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&c1),
        );
        assert_eq!(deferred, 1, "Duplicate 不得重复计数");
        assert_eq!(store.total(), 1);

        // ③ 第三个 future round ⇒ `Admitted` **且伴随淘汰**（total 不变）⇒ 仍必须 +1。
        let c2 = encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, RC_TEST_ROUND + 2))
            .expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&c2),
        );
        assert_eq!(store.total(), 1, "容量 1 ⇒ 淘汰后 total 不变");
        assert_eq!(deferred, 2, "Admitted 必计（不得被淘汰掩盖）");
        assert_eq!(rejected, 0);
        assert_eq!(driver.consensus().state().round.round, RC_TEST_ROUND);
    }

    /// D0-4：Guard C 拒绝**分类**计数直通（唯一来源 = 既有 `PendingProposalStore`；无第二套计数）。
    #[test]
    fn p1a30_d0_guard_reject_counts_are_exposed() {
        let mut store = PendingProposalStore::new();
        store.note_guard_reject(GuardReject::Signature);
        store.note_guard_reject(GuardReject::Signature);
        store.note_guard_reject(GuardReject::Evidence);
        store.note_guard_reject(GuardReject::HeightContext);
        let counts = store.guard_reject_counts();
        assert_eq!(counts.len(), 8, "8 类固定序");
        assert_eq!(counts[GuardReject::Signature as usize], 2);
        assert_eq!(counts[GuardReject::Evidence as usize], 1);
        assert_eq!(counts[GuardReject::HeightContext as usize], 1);
        assert_eq!(counts.iter().sum::<u64>(), 4, "分类之和 == 拒绝总数");
        assert_eq!(store.rejected_count(), 4);
        // 与既有单类访问器**一致**（同一数据源；不新增计数点）。
        assert_eq!(store.guard_reject_count(GuardReject::Signature), 2);
        assert_eq!(counts[GuardReject::NoStore as usize], 0);
    }

    /// D0-1：拒绝原因**分类**穷尽、互斥，且分类之和 == `round_changes_rejected` 总数。
    #[test]
    fn p1a30_d0_reject_reasons_are_classified() {
        let (mut driver, kps, vsid) = rc_test_driver(3);
        let mut timer: Option<RoundTimer> = None;
        let mut by_authority = 0u64;
        let mut rejected = 0u64;
        let mut deferred = 0u64;
        let mut diag = RoundChangeDiag::default();
        let mut store =
            RoundChangeStore::new(nova_consensus::round_change::DEFAULT_MAX_TRACKED_HEIGHTS);
        assert_eq!(RoundChangeRejectKind::COUNT, 6, "桶数量固定");

        // ① 解码失败 ⇒ Malformed
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&[0xFF; 3]),
        );
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Malformed), 1);

        // ② stale（`from_round = 2` ⇒ `to_round = 3 <= local 3`）
        let stale = encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, 2)).expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&stale),
        );
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Stale), 1);

        // ③ 高度不符（`verify_certificate` 通过 ⇒ 由高度适用性拒绝）
        let wrong_height =
            encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT + 1, RC_TEST_ROUND))
                .expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&wrong_height),
        );
        assert_eq!(diag.reject_count(RoundChangeRejectKind::WrongHeight), 1);

        // ④ 权重不足（1/3，100 < quorum 200）
        let low_quorum = encode_certificate(&rc_test_cert(
            &kps[..1],
            vsid,
            RC_TEST_HEIGHT,
            RC_TEST_ROUND,
        ))
        .expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&low_quorum),
        );
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Quorum), 1);

        // ⑤ 非成员证据（3 成员 + 1 外来密钥）
        let foreign = encode_certificate(&rc_test_cert_with_foreign_member(
            &kps,
            vsid,
            RC_TEST_HEIGHT,
            RC_TEST_ROUND,
        ))
        .expect("enc");
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            Some(&foreign),
        );
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Identity), 1);

        // 分类穷尽（Other = 兜底，本用例为 0）+ 总数一致 + 零状态变化。
        let buckets = [
            RoundChangeRejectKind::Malformed,
            RoundChangeRejectKind::Stale,
            RoundChangeRejectKind::WrongHeight,
            RoundChangeRejectKind::Quorum,
            RoundChangeRejectKind::Identity,
            RoundChangeRejectKind::Other,
        ];
        let sum: u64 = buckets.iter().map(|k| diag.reject_count(*k)).sum();
        assert_eq!(sum, rejected, "桶之和 == 拒绝总数（穷尽 / 互斥）");
        assert_eq!(rejected, 5);
        assert_eq!(diag.reject_count(RoundChangeRejectKind::Other), 0);
        assert_eq!(by_authority, 0, "零权威应用");
        assert_eq!(deferred, 0, "零暂存");
        assert_eq!(
            driver.consensus().state().round.round,
            RC_TEST_ROUND,
            "零 round 变化"
        );
        assert!(timer.is_none(), "未重开计时器");
    }

    /// D0-2：暂存 gauge **不重复计数**；重评 attempts / applied 精确且 `applied <= attempts`。
    #[test]
    fn p1a30_d0_deferred_gauge_and_reeval_are_exact() {
        let (mut driver, kps, vsid) = rc_test_driver(3);
        let mut timer: Option<RoundTimer> = None;
        let mut by_authority = 0u64;
        let mut rejected = 0u64;
        let mut deferred = 0u64;
        let mut diag = RoundChangeDiag::default();
        let mut store =
            RoundChangeStore::new(nova_consensus::round_change::DEFAULT_MAX_TRACKED_HEIGHTS);

        // ① future round（local 3 ⇒ from_round 4）⇒ 暂存；重复入站**不得**重复计数。
        let next_round =
            encode_certificate(&rc_test_cert(&kps, vsid, RC_TEST_HEIGHT, RC_TEST_ROUND + 1))
                .expect("enc");
        for _ in 0..2 {
            rc_feed(
                &mut driver,
                &mut timer,
                &mut by_authority,
                &mut rejected,
                &mut deferred,
                &mut diag,
                &mut store,
                Some(&next_round),
            );
        }
        assert_eq!(
            deferred, 1,
            "gauge：同一 (height, from_round) 重复入站只计 1"
        );
        assert_eq!(rejected, 0);
        assert_eq!(
            diag.reeval_attempts, 0,
            "未命中当前 (height, local_round) ⇒ 不计尝试"
        );
        assert_eq!(diag.reeval_applied, 0);
        assert_eq!(store.total(), 1, "暂存区 1 条（幂等 admit）");

        // ② 本地真实超时推进：round 3 ⇒ 4（既有冻结转移；此处仅为构造重评前提）。
        assert!(matches!(
            driver.consensus_mut().round_timeout(),
            TransitionResult::Applied { .. }
        ));
        assert_eq!(driver.consensus().state().round.round, RC_TEST_ROUND + 1);

        // ③ 空入站批 ⇒ 仅重评：恰好 1 次尝试 + 1 次应用（每 step ≤ 1）。
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            None,
        );
        assert_eq!(diag.reeval_attempts, 1);
        assert_eq!(diag.reeval_applied, 1);
        assert_eq!(by_authority, 1, "重评应用计入独立归因");
        assert_eq!(deferred, 0, "应用后 gauge 归零");
        assert_eq!(rejected, 0);
        assert_eq!(
            driver.consensus().state().round.round,
            RC_TEST_ROUND + 2,
            "恰好 +1"
        );
        assert!(timer.is_some(), "重评应用后计时器已重开");

        // ④ 再跑一次：暂存已空 ⇒ 不计尝试（有界 / 不空转计数）。
        rc_feed(
            &mut driver,
            &mut timer,
            &mut by_authority,
            &mut rejected,
            &mut deferred,
            &mut diag,
            &mut store,
            None,
        );
        assert_eq!(diag.reeval_attempts, 1, "无匹配证书 ⇒ 尝试数不变");
        assert_eq!(by_authority, 1);
    }

    /// D0-3：本地 timeout 结果分类（`applied` / `ignored` / `rejected`）与 `round_timeouts` 总数一致。
    #[test]
    fn p1a30_d0_round_timeout_outcomes_are_counted() {
        let (mut driver, _kps, _vsid) = rc_test_driver(3);
        // 窗口固定 1ms（`min(initial × backoff^round, max)` = 1）⇒ 越过后必然到期。
        let config = RoundTimeoutConfig {
            initial_timeout: 1,
            max_timeout: 2,
            backoff_factor: 1,
        };
        assert_eq!(round_timeout_window_ms(&config, RC_TEST_ROUND), 1);
        assert_eq!(round_timeout_window_ns(&config, RC_TEST_ROUND), 1_000_000);
        assert_eq!(RoundTimeoutOutcome::COUNT, 3);

        let mut timer: Option<RoundTimer> = None;
        let mut round_timeouts = 0u64;
        let mut outcomes = [0u64; RoundTimeoutOutcome::COUNT];
        let mut round_adv_local = 0u64;
        let mut expired: Option<LocalExpireObservation> = None;

        // step 1：ARM（armed_at = 本读数）—— arming step 不计到期。
        let entry = observe_round(driver.consensus());
        drive_round_timeout(
            &mut driver,
            &config,
            0,
            &mut timer,
            &mut round_timeouts,
            &mut outcomes,
            &mut round_adv_local,
            entry,
            &mut expired,
        );
        assert_eq!(round_timeouts, 0);
        assert!(expired.is_none());
        assert_eq!(round_adv_local, 0);

        // step 2：单调读数越过窗口 ⇒ 到期 ⇒ `Applied`（round +1）+ 观测填充。
        let entry = observe_round(driver.consensus());
        drive_round_timeout(
            &mut driver,
            &config,
            1_000_000,
            &mut timer,
            &mut round_timeouts,
            &mut outcomes,
            &mut round_adv_local,
            entry,
            &mut expired,
        );
        assert_eq!(round_timeouts, 1, "总数计数不变（既有字段）");
        assert_eq!(outcomes[RoundTimeoutOutcome::Applied.index()], 1);
        assert_eq!(outcomes[RoundTimeoutOutcome::Ignored.index()], 0);
        assert_eq!(outcomes[RoundTimeoutOutcome::Rejected.index()], 0);
        assert_eq!(round_adv_local, 1);
        assert!(expired.is_some(), "真实 EXPIRE 观测已填充");

        // 分类器级：`Ignored` / `Rejected` 分支的**唯一**计数入口（当前冻结 transition：
        // `RoundTimeout` ⇒ `checked_successor` ⇒ 仅 `Applied` / `Rejected{RoundOverflow}`；
        // 故二者不通过本用例的运行路径触发，仅在此钉住映射与槽位）。
        note_timeout_outcome(&mut outcomes, RoundTimeoutOutcome::Ignored);
        note_timeout_outcome(&mut outcomes, RoundTimeoutOutcome::Rejected);
        assert_eq!(outcomes[RoundTimeoutOutcome::Ignored.index()], 1);
        assert_eq!(outcomes[RoundTimeoutOutcome::Rejected.index()], 1);
        assert_eq!(outcomes[RoundTimeoutOutcome::Applied.index()], 1);
    }

    // -----------------------------------------------------------------------
    // P1-A.6 T1（单元）：纯计时状态机 / 窗口算术 / DISARM 判据
    // （集成层时序与可观测行为见 `tests/d10_p1_a6_round_timeout_liveness.rs`）
    // -----------------------------------------------------------------------

    /// 窗口算术 = 冻结 `min(initial × backoff^round, max)`（**毫秒**）；含 cap / 退化 / 极大 round。
    #[test]
    fn p1a6_window_follows_backoff_and_cap() {
        let cfg = RoundTimeoutConfig {
            initial_timeout: 10,
            max_timeout: 25,
            backoff_factor: 2,
        };
        assert_eq!(round_timeout_window_ms(&cfg, 0), 10);
        assert_eq!(round_timeout_window_ms(&cfg, 1), 20);
        assert_eq!(round_timeout_window_ms(&cfg, 2), 25, "40 ⇒ cap 25");
        assert_eq!(round_timeout_window_ms(&cfg, 3), 25, "cap 后恒定");
        assert_eq!(
            round_timeout_window_ms(&cfg, u64::MAX),
            25,
            "极大 round 有界（不 O(round)）"
        );
        assert_eq!(
            round_timeout_window_ns(&cfg, 2),
            25_000_000,
            "ns = ms × 1e6"
        );

        // **A3 授权基线（Testnet）**：10s / ×2 / 120s ⇒ 10 · 20 · 40 · 80 · 120 · 120 …
        let base = RoundTimeoutConfig::default();
        assert_eq!(base.initial_timeout, 10_000);
        assert_eq!(base.max_timeout, 120_000);
        assert_eq!(base.backoff_factor, 2);
        let seq: Vec<u64> = (0..8)
            .map(|r| round_timeout_window_ms(&base, r) / 1_000)
            .collect();
        assert_eq!(
            seq,
            vec![10, 20, 40, 80, 120, 120, 120, 120],
            "授权超时序列（秒）"
        );
        assert_eq!(
            round_timeout_window_ns(&base, 0),
            10_000_000_000,
            "round 0 = 10s"
        );
        assert_eq!(
            round_timeout_window_ns(&base, 1),
            20_000_000_000,
            "round 1 = 20s"
        );

        // 退化配置：0 窗口 ⇒ 下界 1ms；backoff == 1 ⇒ 不增长（且不退化循环）。
        let zero = RoundTimeoutConfig {
            initial_timeout: 0,
            max_timeout: 120_000,
            backoff_factor: 2,
        };
        assert_eq!(round_timeout_window_ms(&zero, 0), 1);
        let flat = RoundTimeoutConfig {
            initial_timeout: 5,
            max_timeout: 120_000,
            backoff_factor: 1,
        };
        assert_eq!(round_timeout_window_ms(&flat, u64::MAX), 5);
    }

    /// A3 — **单调 deadline** 状态机：ARM / 未到期 / 恰好到期 / 不继承 deadline / RESET / 确定性。
    #[test]
    fn p1a6_timer_arms_waits_expires_and_resets() {
        let w: u64 = 3_000_000; // 3ms（ns）
        // ARM：新 (height, round) ⇒ armed_at = 本读数；已历时 0；不继承任何历史。
        let (armed, tick) = round_timer_tick(None, 0, 0, w, false, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!((armed.height, armed.round, armed.window_ns), (0, 0, w));
        assert_eq!(armed.elapsed_ns(0), 0);

        // 未到期（窗口 − 1ns）⇒ Waiting。
        let (waiting, tick) = round_timer_tick(Some(armed), 0, 0, w, false, w - 1);
        assert_eq!(tick, RoundTimerTick::Waiting);
        assert_eq!(waiting.elapsed_ns(w - 1), w - 1);
        // 恰好到期（边界 `>=`）。
        let (expired, tick) = round_timer_tick(Some(armed), 0, 0, w, false, w);
        assert_eq!(tick, RoundTimerTick::Expired, "恰好到达窗口 ⇒ 到期");

        // 新 round ⇒ 全新 deadline（`armed_at` 归到当前读数；不继承旧已历时）＋新窗口。
        let (next_round, tick) = round_timer_tick(Some(expired), 0, 1, 6_000_000, false, w);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(next_round.armed_at_ns, w);
        assert_eq!(next_round.elapsed_ns(w), 0, "round 变更后已历时归零");
        assert_eq!(next_round.window_ns, 6_000_000);

        // height 变更 ⇒ 同样 fresh（丢弃旧高度计时）。
        let (next_height, tick) = round_timer_tick(Some(next_round), 1, 0, w, false, w + 5);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!((next_height.height, next_height.round), (1, 0));
        assert_eq!(next_height.elapsed_ns(w + 5), 0);

        // RESET：同 round 内进展 ⇒ 窗口重开（armed_at = now；不增窗、不改 round）。
        let (reset, tick) = round_timer_tick(Some(expired), 0, 0, w, true, 2 * w);
        assert_eq!(tick, RoundTimerTick::Reset);
        assert_eq!(reset.armed_at_ns, 2 * w);
        assert_eq!(reset.elapsed_ns(2 * w), 0);
        assert_eq!((reset.height, reset.round), (0, 0));
        // 重开后需再满一个窗口 ⇒ 同一读数不得到期。
        let (_, tick) = round_timer_tick(Some(reset), 0, 0, w, false, 2 * w);
        assert_eq!(tick, RoundTimerTick::Waiting);

        // 确定性 / 无墙钟：同一序列重复执行 ⇒ 结果逐项相同。
        let run = || {
            let mut seen = Vec::new();
            let mut current = None;
            for (now, progressed) in [
                (0u64, false),
                (1_000_000, false),
                (2_000_000, false),
                (3_000_000, true),
                (4_000_000, false),
            ] {
                let (timer, tick) = round_timer_tick(current, 2, 7, w, progressed, now);
                seen.push((timer.armed_at_ns, tick));
                current = Some(timer);
            }
            seen
        };
        assert_eq!(run(), run(), "同输入同输出（无外部时钟 / 无随机）");
    }

    /// **A3 必测项**：注入式 fake 时钟的边界与健壮性
    ///（重复读数 / 回拨 / 长停顿 / 伪造 EXPIRE 观测）。
    #[test]
    fn a3_monotonic_clock_boundaries_and_robustness() {
        let clock = FakeClock::new();
        assert_eq!(clock.now_ns(), 0);
        clock.advance_ms(10_000);
        assert_eq!(
            clock.now_ns(),
            10_000_000_000,
            "fake 时钟显式推进（无 sleep）"
        );

        let w = round_timeout_window_ns(&RoundTimeoutConfig::default(), 0);
        assert_eq!(w, 10_000_000_000, "round 0 窗口 = 10s");

        // ① ARM；推进 9.999s ⇒ 未到期；再推进 1ms ⇒ **恰好**到期。
        let now = clock_ns(&clock);
        let (armed, tick) = round_timer_tick(None, 5, 0, w, false, now);
        assert_eq!(tick, RoundTimerTick::Armed);
        clock.advance_ms(9_999);
        let (_, tick) = round_timer_tick(Some(armed), 5, 0, w, false, clock_ns(&clock));
        assert_eq!(tick, RoundTimerTick::Waiting, "未到期");
        clock.advance_ms(1);
        let (expired, tick) = round_timer_tick(Some(armed), 5, 0, w, false, clock_ns(&clock));
        assert_eq!(tick, RoundTimerTick::Expired, "恰好 10s ⇒ 到期");
        assert!(
            LocalExpireObservation::from_expired_timer(expired, tick, clock_ns(&clock)).is_some()
        );

        // ② 重复读数**不**产生第二次到期事件：到期后 round 由冻结 transition +1，并在**同一读数**
        //   重开（仿真 `drive_round_timeout` 的立即重开）⇒ 同一读数下不再 Expired。
        let now = clock_ns(&clock);
        let (rearmed, _) = round_timer_tick(None, 5, 1, w, false, now);
        let (_, tick) = round_timer_tick(Some(rearmed), 5, 1, w, false, now);
        assert_eq!(
            tick,
            RoundTimerTick::Waiting,
            "同一读数不得二次到期（无 double advance）"
        );

        // ③ 读数**回拨**（墙钟回退）⇒ 不 panic、不误到期：`elapsed_ns` 饱和到 0。
        let back = now.saturating_sub(60_000_000_000);
        clock.set_ns(back);
        let (_, tick) = round_timer_tick(Some(rearmed), 5, 1, w, false, clock_ns(&clock));
        assert_eq!(tick, RoundTimerTick::Waiting, "读数回退不得造成误到期");
        assert_eq!(rearmed.elapsed_ns(back), 0, "饱和，无环绕");

        // ④ 长停顿（极大读数）⇒ 恰好一次到期，且无算术溢出。
        let (_, tick) = round_timer_tick(Some(rearmed), 5, 1, w, false, u64::MAX);
        assert_eq!(tick, RoundTimerTick::Expired, "长停顿 ⇒ 到期（一次事件）");
        assert_eq!(
            rearmed.elapsed_ns(u64::MAX),
            u64::MAX - rearmed.armed_at_ns,
            "无溢出"
        );
        assert!(rearmed.elapsed_ns(u64::MAX) >= w);

        // ⑤ 刚 ARM 的计时器不可用于构造 EXPIRE 观测（即使伪造 `Expired` 也被双重守卫拒绝）。
        let (fresh, _) = round_timer_tick(None, 9, 0, w, false, now);
        assert!(
            LocalExpireObservation::from_expired_timer(fresh, RoundTimerTick::Expired, now)
                .is_none(),
            "已历时 = 0 ⇒ 伪造 Expired 亦被拒"
        );
    }

    /// **SAFETY-REJECT-SKIP** — 可恢复性分类表（**唯一**判定点；纯函数、无 I/O、无时序）。
    ///
    /// 不变量：**只有** `block_safety` F2/F3/F4 的常态冲突拒绝（同 height 不同 target）可恢复；
    /// 其余（I/O / 损坏 / 未恢复 / identity / 链高失配 / 签名失败 / 自检 / 无 safety gate /
    /// double-vote / lock / abandon）**一律保持 fatal**。
    #[test]
    fn safety_reject_skip_classification_is_exact() {
        use crate::block_safety::BlockSafetyError as B;
        use crate::safety_store::ValidatorSafetyError as S;
        use crate::validator::ValidatorActorError as V;

        assert!(
            is_recoverable_proposal_refusal(&V::BlockSignSafety(B::ConflictingTarget {
                existing_target: [0x11; 32],
                requested_target: [0x22; 32],
            })),
            "同 height 不同 target 的常态冲突拒绝 ⇒ 可恢复（放弃本次提案，不终止节点）"
        );

        let must_stay_fatal = [
            V::BlockSignSafety(B::Io),
            V::BlockSignSafety(B::UnknownMagic),
            V::BlockSignSafety(B::UnknownVersion),
            V::BlockSignSafety(B::CorruptHeader),
            V::BlockSignSafety(B::IdentityMismatch),
            V::BlockSignSafety(B::CorruptRecord),
            V::BlockSignSafety(B::ChecksumMismatch),
            V::BlockSignSafety(B::TruncatedRecord),
            V::BlockSignSafety(B::MissingReservation),
            V::BlockSignSafety(B::AlreadyExists),
            V::BlockSignSafety(B::NotRecovered),
            V::BlockSignSafety(B::RequestIdentityMismatch),
            V::BlockSignSafety(B::SignerIdentityMismatch),
            V::BlockSignSafety(B::ProposerIdentityMismatch),
            V::BlockSignSafety(B::ChainIdMismatch),
            V::BlockSignSafety(B::DeclaredHeightMismatch),
            V::BlockSignSafety(B::PayloadInvalid),
            V::BlockSignSafety(B::TargetReconstruction),
            V::BlockSignSafety(B::SigningFailed),
            V::BlockSignSafety(B::SignatureInvalid),
            V::BlockSafetyUnavailable,
            V::IdentityMismatch,
            V::BlockSigning,
            V::Safety(S::Io),
            V::Safety(S::IdentityMismatch),
            V::Safety(S::ConflictingRecord),
            V::AbandonSigning,
        ];
        for e in must_stay_fatal {
            assert!(
                !is_recoverable_proposal_refusal(&e),
                "必须保持 fatal（不得 blanket-catch）：{e:?}"
            );
        }
    }

    /// DISARM 判据：**必须** `step == Finalized` **且** proposal 存在 **且**
    /// `finalized_reference == proposal.block_hash`（单看 Finalized 不够）。
    #[test]
    fn p1a6_disarm_requires_matching_finality() {
        use nova_consensus::finality::FinalityState;
        use nova_consensus::round::{ProposalRef, RoundState, VoteAccumulator};

        let state = |step: RoundStep, proposal: Option<[u8; 32]>, finalized: Option<[u8; 32]>| {
            ConsensusState {
                round: RoundState {
                    height: 3,
                    round: 1,
                    proposal: proposal.map(|block_hash| ProposalRef {
                        block_hash,
                        proposer: ValidatorId::from_bytes([1u8; 32]),
                    }),
                    prevotes: VoteAccumulator::new(),
                    precommits: VoteAccumulator::new(),
                    step,
                },
                finality: FinalityState {
                    finalized_reference: finalized,
                    highest_precommit_qc: None,
                },
            }
        };

        let x = [0x11u8; 32];
        assert!(
            round_finalized_by_finality(&state(RoundStep::Finalized, Some(x), Some(x))),
            "Finalized + proposal + finality 匹配 ⇒ DISARM"
        );
        assert!(
            !round_finalized_by_finality(&state(RoundStep::Precommit, Some(x), Some(x))),
            "未 Finalized ⇒ 不 disarm"
        );
        assert!(
            !round_finalized_by_finality(&state(RoundStep::Finalized, None, Some(x))),
            "无 proposal ⇒ 不 disarm"
        );
        assert!(
            !round_finalized_by_finality(&state(RoundStep::Finalized, Some(x), None)),
            "P1-A.5 场景（Finalized 但无 finality）⇒ **必须**仍可 timeout"
        );
        assert!(
            !round_finalized_by_finality(&state(RoundStep::Finalized, Some(x), Some([0x22u8; 32]))),
            "finality 与 proposal 不匹配 ⇒ 不 disarm"
        );
    }
}
