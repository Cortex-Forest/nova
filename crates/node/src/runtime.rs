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
//! - full-node（`validator_enabled=false`）：跳过 key / safety / validator，不触碰 Provider。

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use nova_consensus::dag::Dag;
use nova_consensus::finality::{FinalityError, QuorumCertificate};
use nova_consensus::integration::{ConsensusState, TransitionResult};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{RoundStep, RoundTimeoutConfig};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_network::event_loop::{EventLoop, EventLoopConfig, EventLoopError};
use nova_network::message::{MessageEnvelope, MessageType};
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceError};
use nova_network::node_id::NodeId;
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
    resolve_proposer_round_evidence, resolve_proposer_round_from_evidences,
};
use crate::block_inbound::{InboundBlockError, InboundBlockVerdict};
use crate::bootstrap::{self, ConnectionTargetError, NodeConfig, NodeStartupError};
use crate::driver::{DriverError, NodeConsensusDriver};
use crate::inbound::{
    InboundDiagnostics, InboundListenerError, InboundListenerState, InboundMultiplexTransport,
    peer_key,
};
use crate::intent_ledger::{
    BlockInboundSource, MissingAncestorIntent, MissingAncestorIntentLedger,
};
use crate::key_provider::{KeyProvider, KeyProviderError};
use crate::network_identity::{NetworkSigner, NetworkSigningError};
use crate::outbound::OutboundConsensusMessage;
use crate::proposer::{ProposalBuild, ProposerError, build_proposal};
use crate::qc_history::{QcHistory, QcHistoryError};
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
fn runtime_propose(
    driver: &mut NodeConsensusDriver<DynSigner>,
    block_production: &Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    timestamp: u64,
) -> Result<Option<ProposalBuild>, RuntimeError> {
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
        return Ok(None);
    };
    // 出块签名（ValidatorActor 授权；signature ∉ block_hash —— hash 在签名前已定）。
    if let Some(a) = driver.actor(0) {
        a.sign_block(&mut pb.block)
            .map_err(RuntimeError::Validator)?;
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
    Ok(Some(pb))
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

/// `RoundTimeoutConfig::timeout_for` 退避循环的迭代上界（见 [`round_timeout_window_ticks`]）。
const ROUND_TIMEOUT_MAX_BACKOFF_STEPS: u64 = 64;

/// 窗口下界（保证 arming 后至少有一个 step 的宽限期；防退化的 0 窗口立即触发）。
const ROUND_TIMEOUT_MIN_WINDOW_TICKS: u64 = 1;

/// P1-A.6 — `window(round) = min(initial × backoff^round, max)`（冻结 `RoundTimeoutConfig` 语义）。
///
/// 数值以 **逻辑 step tick** 解释（node-local 配置，**非**协议常量 —— ADR-0049 §3.5）。
/// 溢出安全：`timeout_for` 内部为 `saturating_mul(...).min(max)`；这里额外把 round 夹到
/// [`ROUND_TIMEOUT_MAX_BACKOFF_STEPS`] 以避免退化配置（如 `backoff_factor == 1` 且
/// `initial < max`）在极大 round 上退化为 O(round) 循环：`backoff ≥ 2` 时 `initial × 2^64`
/// 必然 saturate 到 cap ⇒ 结果与真实 round **完全一致**；`backoff == 1` 时窗口与迭代次数无关。
fn round_timeout_window_ticks(config: &RoundTimeoutConfig, round: u64) -> u64 {
    config
        .timeout_for(round.min(ROUND_TIMEOUT_MAX_BACKOFF_STEPS))
        .max(ROUND_TIMEOUT_MIN_WINDOW_TICKS)
}

/// P1-A.6 — 当前 `(height, round)` 的本地计时器（**只**含位置 + tick 计数）。
///
/// `elapsed_ticks` = 本计时器（重新）arm 之后**已历经的 step 数**（arming 的那一步记 1）。
/// 语义：`window_ticks` = 该 `(height, round)` 允许的最大 step 数；`elapsed >= window` ⇒ 到期。
///
/// 不保留任何 proposal / block hash / QC / 签名 / 对端材料（hash 仅瞬时存在于本 step 的观测快照，
/// 见 [`RoundObservation`] —— 不进计时器状态、不跨 step 保留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundTimer {
    height: u64,
    round: u64,
    elapsed_ticks: u64,
    window_ticks: u64,
}

/// P1-A.6 — 计时器推进结果（纯计算；便于穷举单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundTimerTick {
    /// 新 `(height, round)` ⇒ 已 ARM（`elapsed = 1`：arming step 计入本 round；**不**继承上一轮 elapsed）。
    Armed,
    /// 计时中（尚未到期）。
    Waiting,
    /// 本 tick 达到窗口 ⇒ 应触发一次本地 round timeout。
    Expired,
    /// 当前 round 内观测到 canonical 进展 ⇒ 窗口重开（`elapsed = 1`：本 step 计入新窗口）。
    Reset,
}

/// P1-A.6 — 计时器推进一步（**纯函数**；无墙钟 / 无随机 / 无 I/O —— 同输入同输出）。
///
/// - **ARM**：`prev` 为空或 `(height, round)` 变化 ⇒ 新计时器（`elapsed = 1`）；ADR-0049 §3.3
///   「round transition MUST NOT inherit stale deadline」⇒ 绝不继承上一轮 elapsed。
/// - **RESET**：本 step 在**当前** `(height, round)` 内观测到 canonical 进展 ⇒ 窗口重开
///   （`elapsed = 1`；不增窗、不改 round）。只有**真实状态变化**能 reset ⇒ invalid / stale /
///   duplicate / spam 输入（不改变状态）**不可能** reset（ADR-0049 §3.4 MUST NOT）。
/// - **EXPIRE**：`elapsed >= window` ⇒ 到期（`window` = 该 round 允许的最大 step 数）。
fn round_timer_tick(
    prev: Option<RoundTimer>,
    height: u64,
    round: u64,
    window_ticks: u64,
    progressed: bool,
) -> (RoundTimer, RoundTimerTick) {
    let same_round = prev.is_some_and(|t| t.height == height && t.round == round);
    if !same_round {
        return (
            RoundTimer {
                height,
                round,
                elapsed_ticks: 1,
                window_ticks,
            },
            RoundTimerTick::Armed,
        );
    }
    let mut timer = prev.expect("same_round ⇒ prev 必为 Some");
    if progressed {
        timer.elapsed_ticks = 1;
        timer.window_ticks = window_ticks;
        return (timer, RoundTimerTick::Reset);
    }
    timer.elapsed_ticks = timer.elapsed_ticks.saturating_add(1);
    let tick = if timer.elapsed_ticks >= timer.window_ticks {
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
/// `entry` = 本 step 入口的观测快照（用于 `progressed` 判定；仅本 step 内有效）。
fn drive_round_timeout(
    driver: &mut NodeConsensusDriver<DynSigner>,
    config: &RoundTimeoutConfig,
    timer: &mut Option<RoundTimer>,
    round_timeouts: &mut u64,
    entry: RoundObservation,
) {
    // DISARM：必须**已被 finality 确认**（不是单看 `step == Finalized` —— 见谓词 doc）。
    if round_finalized_by_finality(driver.consensus().state()) {
        *timer = None;
        return;
    }
    let observed = observe_round(driver.consensus());
    let window_ticks = round_timeout_window_ticks(config, observed.round);
    let (next, tick) = round_timer_tick(
        *timer,
        observed.height,
        observed.round,
        window_ticks,
        observed != entry,
    );
    *timer = Some(next);
    if tick != RoundTimerTick::Expired {
        return;
    }
    // EXPIRE ⇒ 冻结的 node-local RoundTimeout（不新增任何共识语义）。
    match driver.consensus_mut().round_timeout() {
        TransitionResult::Applied { .. } => {
            *round_timeouts = round_timeouts.saturating_add(1);
        }
        // `u64::MAX` 轮：`checked_successor` ⇒ `None` ⇒ `Rejected{RoundOverflow}`（不 wrap、
        // state 与 context 不变）。计该次尝试；不 panic、不视为致命错误。
        TransitionResult::Rejected { .. } | TransitionResult::Ignored { .. } => {
            *round_timeouts = round_timeouts.saturating_add(1);
        }
    }
    // 立即对新 `(height, round)` 重开窗口（elapsed 不继承；窗口 = 新轮的 `timeout_for`）。
    let after = observe_round(driver.consensus());
    *timer = Some(RoundTimer {
        height: after.height,
        round: after.round,
        elapsed_ticks: 1,
        window_ticks: round_timeout_window_ticks(config, after.round),
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
    ledger: &mut MissingAncestorIntentLedger,
    pending: &mut VecDeque<PendingExternalQc>,
    deferred: &mut u64,
    command: NodeConsensusCommand,
) -> Result<(), DriverError> {
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
    resolved_round: Option<u64>,
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
    // P1-A.18 RC-1 + A3（register ↔ validate parity）：登记 proposer 必须与**绑定证据**给出的轮一致。
    //
    // `resolved_round` = **sync validation 已据以验签通过**的那一轮（调用方以**同一**有界 QC 证据切片
    // + **同一** canonical hash 解析所得，见 `step()` 的 `SyncBlockResponse` 分支）；gossip / 本地路径为
    // `None`。它作为**QC 侧绑定证据** `(r, block_hash)` 参与**同一个** `resolve_proposer_round_evidence`：
    // - `Some(r)` ⇒ 与本地 proposal 证据同权参与；二者冲突 ⇒ `Err` ⇒ 保守 no-op（**不登记**，且**不**以
    //   `Err` 让节点 fail-closed 退出）；二者均无绑定 ⇒ 仍回退既有 round 0；
    // - `None` ⇒ 逐字保持既有本地证据链（proposal → last_precommit → round 0）——gossip 行为零变化。
    //
    // ⚠️ 高度语义不变（仍为父高轮 `height - 1`）；`select_proposer` / `BlockStore::put_verified` 语义不变。
    let qc_evidence = resolved_round
        .map(|r| (r, block_hash))
        .or_else(|| last_precommit_round_evidence(driver.consensus()));
    let Ok(round) = resolve_proposer_round_evidence(
        block_hash,
        proposal_round_evidence(driver.consensus().state(), adapter.head().height),
        qc_evidence,
    ) else {
        return Ok(());
    };
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
            let _ = inbound.drop_peer(peer);
            continue;
        }
        if ns.connect_peer(peer).is_err() {
            let _ = inbound.drop_peer(peer);
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
            let _ = inbound.drop_peer(peer);
            pending.remove(&key);
            continue;
        }
        if tick.saturating_sub(accepted_tick) > INBOUND_PENDING_TIMEOUT_STEPS {
            let _ = inbound.drop_peer(peer);
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
    /// P1-A.6 — round timeout 窗口参数（**逻辑 step tick** 单位；默认 `RoundTimeoutConfig::default()`）。
    ///
    /// node-local 配置面：非协议常量（ADR-0049 §3.5）、非 CLI flag、不进 `NodeConfig`、不持久化。
    round_timeout_config: RoundTimeoutConfig,
    /// P1-A.6 — 当前 `(height, round)` 的本地计时器（`None` = 尚未 arm / 已被 finality disarm）。
    /// **只**含位置 + tick 计数（无 payload / 无 hash / 无签名 / 无对端材料）。
    round_timer: Option<RoundTimer>,
    /// P1-A.6 — 本地 round timeout 触发次数（saturating；诊断观测，不携带任何共识材料）。
    round_timeouts: u64,
    /// D9 Step 7：入站 listener 逻辑 step 计数（每网络 step +1；pending 超时基准；无系统时钟）。
    inbound_tick: u64,
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
            round_timer: None,
            round_timeouts: 0,
            inbound_tick: 0,
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
        })
    }

    /// validator mode 生命周期装配（key provider → derive id → safety store → recover → actor）。
    /// 返回 `(actor, journal_path)`；actor 随后移入 Driver（ownership）。
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
        let journal_path = config.safety_dir.join("safety.journal");
        let store = if journal_path.exists() {
            ValidatorSafetyStore::at(&journal_path, safety_identity)
        } else {
            ValidatorSafetyStore::create(&journal_path, safety_identity)
                .map_err(NodeRuntimeError::Safety)?
        };

        // 8/9. strict recover（restore 内部执行）→ 构造 ValidatorActor。
        //      recover / identity mismatch ⇒ Err ⇒ validator mode 启动失败（fail closed）。
        let actor = ValidatorActor::restore(validator_id, signer, identity.chain_id, store)
            .map_err(NodeRuntimeError::Validator)?;

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

    /// P1-A.6：当前计时器已历 step 数（arming step 记 1；`None` = 尚未 arm / 已被 finality disarm）。
    pub fn round_timeout_elapsed_ticks(&self) -> Option<u64> {
        self.round_timer.map(|t| t.elapsed_ticks)
    }

    /// P1-A.6：当前计时器窗口（tick；`None` = 未 arm）。只读观测（诊断 / 确定测试）。
    pub fn round_timeout_window_ticks(&self) -> Option<u64> {
        self.round_timer.map(|t| t.window_ticks)
    }

    /// P1-A.6 — **测试 / 开发 seam**：设置 round timeout 窗口参数（**tick** 单位）。
    ///
    /// - 非生产配置面：无 CLI flag / 不进 `NodeConfig` / 不持久化 / 不改任何共识语义。
    /// - 调用后丢弃当前计时器，下一 `step()` 按新参数重新 arm（确定测试无需等待 / 无 sleep）。
    /// - 生产默认 = `RoundTimeoutConfig::default()`（1000 / 60_000 / 2）。
    pub fn set_round_timeout_config(&mut self, config: RoundTimeoutConfig) {
        self.round_timeout_config = config;
        self.round_timer = None;
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
        process_inbound_consensus_command(
            &mut self.driver,
            &self.block_production,
            &mut self.missing_ancestor_ledger,
            &mut self.pending_external_qc,
            &mut self.inbound_qc_deferred,
            command,
        )
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
            )?;
            if let Some(pb) = proposal {
                self.last_proposal = Some(pb);
            }
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
            // P1-A.4：**入站（peer 提供）** consensus command 的 Driver 拒绝边界（拒绝 + 计数 + 继续）。
            // P1-A.7：同一入口内附加有界 pending / defer 计数 / 恢复 hint（见 free fn doc）。
            if process_inbound_consensus_command(
                &mut self.driver,
                &self.block_production,
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
        // D10-A Step 3：向 D9 proposer validation 提供本地 ValidatorSet（解除生产 None seam 的
        // canonical-next 假阻塞）—— 远端 canonical-next 块经本地 `select_proposer` → expected VK
        // 真实验签；**不 commit / 不推进 head**（block inbound 仍只读观测；远端块自动进入共识 =
        // D10-D 多节点网络 E2E 授权，本 step 不实施）。
        let validator_set = self.driver.consensus().validator_set().clone();
        for msg in block_msgs {
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
                (Some(adapter), BlockInboundMessage::GossipBlock(wire)) => (
                    BlockInboundSource::Gossip,
                    vec![dispatch_gossip_block_round_aware(
                        adapter,
                        self.max_block_bytes,
                        &wire,
                        &validator_set,
                        // D9 Step 8A（G1）：注入本地 DAG ⇒ 已落盘但不在 DAG 的块不短路为
                        // AlreadyKnown，走完 ⑥/⑦ 全验证 ⇒ 可幂等补登记（不 commit / 不推 head）。
                        Some(self.driver.consensus().dag()),
                        // P1-A.18 RC-1：**绑定证据**（无证据 ⇒ 回退 round 0；两个来源冲突 ⇒ 拒绝）。
                        proposal_round_evidence(
                            self.driver.consensus().state(),
                            adapter.head().height,
                        ),
                        last_precommit_round_evidence(self.driver.consensus()),
                    )],
                    vec![Some(wire)],
                ),
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
                        // P1-A.18 / A3：registration 必须与 validation 使用**同一**已解析 round。
                        // - sync 分支：用**同一** `sync_qc_evidences` + 同一 canonical hash（verdict 携带，
                        //   与 validation 逐字同一值）再次解析 ⇒ 同一 round；
                        // - gossip 分支：切片为空 ⇒ `Ok(None)` ⇒ 逐字保持既有本地证据链
                        //   （proposal → last_precommit → round 0）；
                        // - `Err(冲突轮)` ⇒ **保守拒绝该块**（不落盘 / 不登记；**不得**回退 round 0）。
                        match resolve_proposer_round_from_evidences(*block_hash, &sync_qc_evidences)
                        {
                            Ok(resolved_round) => {
                                register_remote_canonical_block(
                                    &mut self.driver,
                                    adapter,
                                    wire,
                                    resolved_round,
                                )?;
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
        drive_round_timeout(
            &mut self.driver,
            &self.round_timeout_config,
            &mut self.round_timer,
            &mut self.round_timeouts,
            round_entry,
        );
        // STEP 10-19-6 OPT-1：node-local proposer orchestration —— 仅本节点为当前 proposer 且
        // 阶段 Propose 且本轮未提案时，经 BlockBuilder 产出真实 Block + ProposalRef 并提交；
        // 否则幂等 no-op。不自动投票（vote 仍走既有路径）。
        let proposal = runtime_propose(
            &mut self.driver,
            &self.block_production,
            self.proposal_timestamp,
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
            self.driver
                .record_local_proposal(pb.proposal_ref.clone(), block_wire);
            self.last_proposal = Some(pb.clone());
        }
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
            let envelope = crate::egress::envelope_for(&msg, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            let _ = stack.ns.broadcast(envelope);
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
            round_timer: _,
            round_timeouts: _,
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
    // P1-A.6 T1（单元）：纯计时状态机 / 窗口算术 / DISARM 判据
    // （集成层时序与可观测行为见 `tests/d10_p1_a6_round_timeout_liveness.rs`）
    // -----------------------------------------------------------------------

    /// 窗口算术 = 冻结 `min(initial × backoff^round, max)`；含 cap / 退化配置 / 极大 round 有界。
    #[test]
    fn p1a6_window_follows_backoff_and_cap() {
        let cfg = RoundTimeoutConfig {
            initial_timeout: 10,
            max_timeout: 25,
            backoff_factor: 2,
        };
        assert_eq!(round_timeout_window_ticks(&cfg, 0), 10);
        assert_eq!(round_timeout_window_ticks(&cfg, 1), 20);
        assert_eq!(round_timeout_window_ticks(&cfg, 2), 25, "40 ⇒ cap 25");
        assert_eq!(round_timeout_window_ticks(&cfg, 3), 25, "cap 后恒定");
        assert_eq!(
            round_timeout_window_ticks(&cfg, u64::MAX),
            25,
            "极大 round 有界（不 O(round)；结果 = cap）"
        );

        // 生产默认（tick 单位；node config 非协议常量）：1000 / 60_000 / 2。
        let default_cfg = RoundTimeoutConfig::default();
        assert_eq!(round_timeout_window_ticks(&default_cfg, 0), 1_000);
        assert_eq!(round_timeout_window_ticks(&default_cfg, 1), 2_000);
        assert_eq!(round_timeout_window_ticks(&default_cfg, 6), 60_000);
        assert_eq!(round_timeout_window_ticks(&default_cfg, u64::MAX), 60_000);

        // 退化配置：0 窗口 ⇒ 下界 1；backoff == 1 ⇒ 不增长（且不退化循环）。
        let zero = RoundTimeoutConfig {
            initial_timeout: 0,
            max_timeout: 60_000,
            backoff_factor: 2,
        };
        assert_eq!(round_timeout_window_ticks(&zero, 0), 1);
        let flat = RoundTimeoutConfig {
            initial_timeout: 5,
            max_timeout: 60_000,
            backoff_factor: 1,
        };
        assert_eq!(round_timeout_window_ticks(&flat, u64::MAX), 5);
    }

    /// ARM / 未到期 / 恰好到期 / 不继承 elapsed / RESET / 确定性。
    #[test]
    fn p1a6_timer_arms_waits_expires_and_resets() {
        // ARM：新 (height, round) ⇒ elapsed = 1（arming step 计入）；不继承任何历史。
        let (armed, tick) = round_timer_tick(None, 0, 0, 3, false);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(armed.elapsed_ticks, 1);
        assert_eq!((armed.height, armed.round, armed.window_ticks), (0, 0, 3));

        // 未到期 → 恰好到期（window = 3 ⇒ elapsed 1、2 为 Waiting；3 为 Expired）。
        let (waiting, tick) = round_timer_tick(Some(armed), 0, 0, 3, false);
        assert_eq!(tick, RoundTimerTick::Waiting);
        assert_eq!(waiting.elapsed_ticks, 2);
        let (expired, tick) = round_timer_tick(Some(waiting), 0, 0, 3, false);
        assert_eq!(tick, RoundTimerTick::Expired, "恰好到达 window ⇒ 到期");
        assert_eq!(expired.elapsed_ticks, 3);

        // 新 round ⇒ 全新窗口（不继承 elapsed = 3）；窗口按新 round 传入。
        let (next_round, tick) = round_timer_tick(Some(expired), 0, 1, 6, false);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(next_round.elapsed_ticks, 1, "round 变更后 elapsed 不继承");
        assert_eq!(next_round.window_ticks, 6);

        // height 变更 ⇒ 同样 fresh（丢弃旧高度计时）。
        let (next_height, tick) = round_timer_tick(Some(next_round), 1, 0, 3, false);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!((next_height.height, next_height.round), (1, 0));
        assert_eq!(next_height.elapsed_ticks, 1);

        // RESET：同 round 内进展 ⇒ 窗口重开（elapsed 回 1；不增窗、不改 round）。
        let (reset, tick) = round_timer_tick(Some(expired), 0, 0, 3, true);
        assert_eq!(tick, RoundTimerTick::Reset);
        assert_eq!(reset.elapsed_ticks, 1);
        assert_eq!((reset.height, reset.round), (0, 0));
        // 重开后需再满一个窗口 ⇒ 下一 tick 不得到期。
        let (_, tick) = round_timer_tick(Some(reset), 0, 0, 3, false);
        assert_eq!(tick, RoundTimerTick::Waiting);

        // 确定性 / 无墙钟：同一序列重复执行 ⇒ 结果逐项相同。
        let run = || {
            let mut seen = Vec::new();
            let mut current = None;
            for progressed in [false, false, false, true, false, false, false] {
                let (timer, tick) = round_timer_tick(current, 2, 7, 3, progressed);
                seen.push((timer.elapsed_ticks, tick));
                current = Some(timer);
            }
            seen
        };
        assert_eq!(run(), run(), "同输入同输出（无外部时钟 / 无随机）");
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
