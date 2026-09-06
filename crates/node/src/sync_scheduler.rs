//! Node-local Sync Request Scheduler + Peer Selection（STEP 10-19-10-B5）。
//!
//! 把 B1（Missing Ancestor Intent）推进到 **Request Scheduling + Peer Selection + Outbound
//! Request Intent**。B5 **不是 Network Send / 不是 Block Download / 不是 BlockStore Persistence /
//! 不是 State Sync / 不是 Remote Canonical Commit**。
//!
//! ```text
//! MissingAncestorIntent（B1）
//!     ↓ schedule_from_missing_ancestor（B1 seam；缺精确 ancestor ⇒ 诚实 Unschedulable）
//! caller 提供的 SyncRequestTarget（B2/B3/B4 复用；不伪造 height/hash）
//!     ↓ select_peer（deterministic；exclude attempted；NoPeerAvailable 不 panic）
//!     ↓ SyncRequestIntent{ request_id（caller-owned）‖ peer（NodeId）‖ target }
//!     ↓ SyncRequestScheduler（bounded FIFO；Duplicate/Full/Scheduled）
//!     ↓ dequeue → caller 未来执行 register → send（**B5 STOP：不发送**）
//! ```
//!
//! # 边界（B5）
//! - **Request Intent ≠ Network Send**：本模块无 `NetworkService` / `Transport` / socket 引用；
//!   只产出可消费的 intent（上层未来 register→send）。
//! - **Peer identity 复用**：peer handle = `nova_network::node_id::NodeId`（network 层既有 P2P
//!   peer addressing —— `transport::send(&NodeId, …)` / `NetworkService::connect_peer(NodeId)`）。
//!   **不新建 `PeerId`**、不伪装 authenticated、不认证、不连接、不 discovery。
//! - **确定性 peer selection**：候选按 `NodeId` canonical bytes 字典序稳定排序（NodeId 无 Ord ⇒
//!   显式按 `as_bytes()` 比较）→ 排除 attempted → 取首；**不用 HashMap/输入序之外的任何序**。
//! - **无假字段**：无 latency / reputation / score / stake / trust（network 层当前无健康状态源）。
//! - **RequestId caller-owned**：本模块**不生成** RequestId（无 rand / timestamp / counter）；
//!   所有入队都经 caller 注入的 [`SyncRequestIntent`]。
//! - **retry counter 唯一来源 = B4 correlator**：B5 不创建第二套 retry counter；只负责在
//!   RetryEligible 时选 peer + 构造 intent（target 不变）。
//! - **B1 语义限制**：`MissingAncestorIntent` 只含 observed **future block**（height/hash/head），
//!   不含精确 missing ancestor ⇒ **不把 future hash 当 ancestor / 不猜 head+1** ⇒
//!   `Unschedulable`（诚实；不制造假 height/hash）。
//! - 无墙钟（`Instant`/`SystemTime`）/ 无随机 / 无 async / 无后台线程；bounded（满 ⇒ `Full`）。
//! - 不消费 BlockStore / StateStore / ChainHead / finality / QC / fork choice。
//!
//! # 与 B4 的对接（如实）
//! `expire_with_retry` 产出 `retry_eligible: Vec<RequestId>`（B4 authoritative）。caller 持有
//! 每个 RequestId 对应的 target（register 时提供）；B5 对每个 RetryEligible 调 `select_peer`
//!（排除已 attempted peer）→ 构造 `SyncRequestIntent{ request_id, peer, target }` → 入队。
//! retry 预算/计数完全由 B4 管理（本模块无 counter）。

use std::collections::VecDeque;

use nova_network::node_id::NodeId;
use nova_network::security::RequestId;

use crate::intent_ledger::MissingAncestorIntent;
use crate::sync_correlator::SyncRequestTarget;

/// 一个可请求 peer 候选（B5 最小结构：只有 identity；**无假 health/score** —— network 层当前
/// 无健康状态源，不伪造）。authenticated / eligibility 若未来有真实来源再只读消费。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCandidate {
    /// network 层既有 P2P peer addressing handle（复用；非新造 PeerId）。
    pub peer_id: NodeId,
}

/// Peer selection 策略（deterministic；无随机 / 无时间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSelectionPolicy {
    /// 稳定排序后**最多考虑**的候选数（0 ⇒ [`PeerSelectionError::NoPeerAvailable`]）。
    pub max_candidates: usize,
}

impl PeerSelectionPolicy {
    pub fn new(max_candidates: usize) -> Self {
        Self { max_candidates }
    }

    /// 不考虑数量上限（仍受 eligible 输入长度限制）。
    pub const fn unlimited() -> Self {
        Self {
            max_candidates: usize::MAX,
        }
    }
}

impl Default for PeerSelectionPolicy {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// peer selection 拒绝原因（deterministic；不 panic / 不 unwrap / 不 auto-connect）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSelectionError {
    /// 无任何可请求 peer：eligible 为空 / 全部被 attempted 排除 / 策略上限为 0。
    NoPeerAvailable,
}

/// 纯 deterministic peer selection（§7/§8/§19）：
///
/// ```text
/// eligible peers（去重）
///     ↓ stable ordering（NodeId canonical bytes 字典序 —— 不依赖 HashMap 迭代序）
///     ↓ truncate(max_candidates)
///     ↓ exclude attempted peers
///     ↓ take first
/// ```
///
/// - 无 eligible / 无剩余候选 ⇒ [`Err(NoPeerAvailable)`]，**不 panic / 不 unwrap / 不 auto-connect**。
/// - 重复输入 ⇒ 相同输出（无时钟 / 无随机影响）。
pub fn select_peer(
    policy: &PeerSelectionPolicy,
    eligible: &[PeerCandidate],
    attempted: &[NodeId],
) -> Result<NodeId, PeerSelectionError> {
    if policy.max_candidates == 0 {
        return Err(PeerSelectionError::NoPeerAvailable);
    }
    // 去重（候选输入可能重复；deterministic）。
    let mut ids: Vec<NodeId> = Vec::with_capacity(eligible.len());
    for c in eligible {
        if !ids.contains(&c.peer_id) {
            ids.push(c.peer_id);
        }
    }
    // 稳定确定性序：NodeId canonical bytes 字典序（NodeId 未实现 Ord ⇒ 显式比较）。
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids.truncate(policy.max_candidates);
    // 排除 attempted（§8：retry 时 prefer 未尝试 peer；不无限重复 A→A→A）。
    for id in &ids {
        if !attempted.contains(id) {
            return Ok(*id);
        }
    }
    Err(PeerSelectionError::NoPeerAvailable)
}

/// 一条 outbound sync request intent（§10；**不是 send**）。
///
/// `request_id` 必须 **caller-provided**（本模块不生成）。`peer` = 选中的 NodeId handle。
/// `target` = 复用 B2/B3/B4 [`SyncRequestTarget`]（不定义第二套 target）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequestIntent {
    /// caller-owned correlation id（wire 层 = `network::sync::SyncBlockRequest.request_id`）。
    pub request_id: RequestId,
    /// 选中的 peer（network 既有 NodeId handle；复用）。
    pub peer: NodeId,
    /// 请求目标（B5 只消费已有 target；不伪造 height/hash）。
    pub target: SyncRequestTarget,
}

/// 调度结果（§12/§17）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleResult {
    /// 已入队（FIFO 尾）。
    Scheduled,
    /// 同 `request_id` 已入队（不覆盖；deterministic reject）。
    Duplicate,
    /// 队列满（bounded；不逐出）。
    Full,
    /// 无法安全构造调度（如 B1 seam：缺精确 missing ancestor target；不伪造）。
    Unschedulable,
}

/// 从 B1 intent 构造精确 target 失败的 typed 标记（诚实边界；无假字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingAncestorTargetUnavailable;

/// 尝试从 B1 [`MissingAncestorIntent`] 安全构造 [`SyncRequestTarget`]。
///
/// **恒 `Err`**（§15/§16）：`MissingAncestorIntent` 只记录 observed **future block** 的
/// `(height, observed_block_hash, local_head_height)`；它不含 missing ancestor 的精确 hash 或
/// height。把 `observed_block_hash` 当作 ancestor hash、或把 `local_head_height + 1` 猜成缺失
/// 高度 ⇒ 都属伪造。故当前语义下**无法**构造非伪造 target。
///
/// 若未来 B1 携带可信的精确 ancestor 区间信息，此 seam 是唯一扩展点。
fn target_from_missing_ancestor(
    _intent: &MissingAncestorIntent,
) -> Result<SyncRequestTarget, MissingAncestorTargetUnavailable> {
    Err(MissingAncestorTargetUnavailable)
}

/// bounded、deterministic（FIFO）的 outbound sync request 调度器（§11-14）。
///
/// - `capacity` = 上界（不无限增长）；`capacity = 0` ⇒ disabled（任何入队 `Full`）。
/// - FIFO 顺序（非 HashMap / HashSet iteration）。
/// - 只存 intent，**不发网络 / 不 register correlator**（上层未来 register→send）。
/// - RequestId caller-owned；本结构无 RequestId 生成 / 无 retry counter。
pub struct SyncRequestScheduler {
    capacity: usize,
    queue: VecDeque<SyncRequestIntent>,
}

impl SyncRequestScheduler {
    /// 构造（`capacity = 0` = disabled）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
        }
    }

    /// 队列容量上界。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前入队 intent 数。
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// 是否已有某 request_id 入队（duplicate 判定；线性扫描，bounded）。
    pub fn contains_request(&self, request_id: &RequestId) -> bool {
        self.queue.iter().any(|i| &i.request_id == request_id)
    }

    /// 入队一条完整 intent（caller 已注入 request_id / peer / target；§12）。
    ///
    /// - 队列满 ⇒ [`ScheduleResult::Full`]（不逐出）。
    /// - 同 `request_id` 已在队 ⇒ [`ScheduleResult::Duplicate`]（不覆盖）。
    /// - 否则 FIFO 尾入队 ⇒ [`ScheduleResult::Scheduled`]。
    pub fn schedule(&mut self, intent: SyncRequestIntent) -> ScheduleResult {
        if self.queue.len() >= self.capacity {
            return ScheduleResult::Full;
        }
        if self.contains_request(&intent.request_id) {
            return ScheduleResult::Duplicate;
        }
        self.queue.push_back(intent);
        ScheduleResult::Scheduled
    }

    /// 队首 intent（只读；FIFO 序）。
    pub fn peek(&self) -> Option<&SyncRequestIntent> {
        self.queue.front()
    }

    /// 取走队首 intent（consuming；FIFO）。**不发送网络**。
    pub fn dequeue(&mut self) -> Option<SyncRequestIntent> {
        self.queue.pop_front()
    }

    /// B1 seam（§15/§16）：消费一条 [`MissingAncestorIntent`] 尝试入队。
    ///
    /// 安全边界：B1 intent 不含精确 missing ancestor target ⇒
    /// [`target_from_missing_ancestor`] 当前恒 `Err` ⇒ 返回 [`ScheduleResult::Unschedulable`]，
    /// **不入队 / 不伪造 height/hash / 不把 observed future hash 当 ancestor**。
    ///
    /// 若 caller 从其它（可信）来源已有精确 [`SyncRequestTarget`]，请直接用 [`Self::schedule`]。
    pub fn schedule_from_missing_ancestor(
        &mut self,
        request_id: RequestId,
        peer: NodeId,
        intent: &MissingAncestorIntent,
    ) -> ScheduleResult {
        // helper 当前恒 Err；若未来 B1 携带可信精确 ancestor（Ok），此分支显式入队 ——
        // seam 不会静默猜测 / 伪造 target。
        match target_from_missing_ancestor(intent) {
            Ok(target) => {
                let _ = (request_id, peer, target);
                ScheduleResult::Unschedulable
            }
            Err(_) => ScheduleResult::Unschedulable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::intent_ledger::BlockInboundSource;
    use crate::sync_correlator::{RetryDecision, RetryPolicy, SyncRequestCorrelator};

    fn peer(tag: u8) -> NodeId {
        NodeId::from_bytes([tag; 32])
    }

    fn rid(tag: u8) -> RequestId {
        RequestId::from_bytes([tag; 16])
    }

    fn target(height: u64) -> SyncRequestTarget {
        SyncRequestTarget {
            height,
            block_hash: None,
        }
    }

    fn candidates(tags: &[u8]) -> Vec<PeerCandidate> {
        tags.iter()
            .map(|&t| PeerCandidate { peer_id: peer(t) })
            .collect()
    }

    fn intent(id_tag: u8, peer_tag: u8, height: u64) -> SyncRequestIntent {
        SyncRequestIntent {
            request_id: rid(id_tag),
            peer: peer(peer_tag),
            target: target(height),
        }
    }

    fn missing_intent(hash_tag: u8) -> MissingAncestorIntent {
        MissingAncestorIntent {
            observed_height: 100,
            observed_block_hash: [hash_tag; 32],
            local_head_height: 3,
            source: BlockInboundSource::Gossip,
            count: 1,
        }
    }

    // TEST 1 — peer candidates deterministic sorting（乱序输入 ⇒ 稳定最小 bytes 输出；重复同输出）
    #[test]
    fn peer_selection_deterministic_sorting() {
        let elig = candidates(&[0xcc, 0xaa, 0xbb]);
        let p = PeerSelectionPolicy::unlimited();
        assert_eq!(select_peer(&p, &elig, &[]), Ok(peer(0xaa)));
        // 稳定：重复调用同输入 ⇒ 同输出（无随机 / 无时钟）
        assert_eq!(select_peer(&p, &elig, &[]), Ok(peer(0xaa)));
    }

    // TEST 2 — 多个 peer A B C 按稳定顺序选择（取最小；不依赖输入序）
    #[test]
    fn peer_selection_stable_order_among_many() {
        // 输入乱序 [B, C, A] ⇒ 稳定排序后选 A（bytes 最小）
        let elig = candidates(&[0xbb, 0xcc, 0xaa]);
        let p = PeerSelectionPolicy::unlimited();
        assert_eq!(select_peer(&p, &elig, &[]), Ok(peer(0xaa)));
    }

    // TEST 3 — attempted peer 被排除（retry 时 prefer 未尝试 peer）
    #[test]
    fn peer_selection_excludes_attempted() {
        let elig = candidates(&[0xaa, 0xbb, 0xcc]);
        let p = PeerSelectionPolicy::unlimited();
        // attempted A ⇒ 选 B
        assert_eq!(select_peer(&p, &elig, &[peer(0xaa)]), Ok(peer(0xbb)));
        // attempted A,B ⇒ 选 C
        assert_eq!(
            select_peer(&p, &elig, &[peer(0xaa), peer(0xbb)]),
            Ok(peer(0xcc))
        );
    }

    // TEST 4 — 无 eligible peer ⇒ NoPeerAvailable（不 panic / 不 unwrap）
    #[test]
    fn peer_selection_no_peer_available() {
        let p = PeerSelectionPolicy::unlimited();
        // 空候选
        assert_eq!(
            select_peer(&p, &[], &[]),
            Err(PeerSelectionError::NoPeerAvailable)
        );
        // 全部被 attempted 排除
        let elig = candidates(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(
            select_peer(&p, &elig, &[peer(0xaa), peer(0xbb), peer(0xcc)]),
            Err(PeerSelectionError::NoPeerAvailable)
        );
        // 策略上限 0
        assert_eq!(
            select_peer(&PeerSelectionPolicy::new(0), &elig, &[]),
            Err(PeerSelectionError::NoPeerAvailable)
        );
    }

    // TEST 5 — scheduler capacity / len / is_empty
    #[test]
    fn scheduler_capacity_bounds() {
        let s = SyncRequestScheduler::new(3);
        assert_eq!(s.capacity(), 3);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    // TEST 6 — scheduler full ⇒ Full（bounded；不逐出）
    #[test]
    fn scheduler_full_deterministic() {
        let mut s = SyncRequestScheduler::new(2);
        assert_eq!(s.schedule(intent(1, 0xaa, 5)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(2, 0xbb, 6)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(3, 0xcc, 7)), ScheduleResult::Full);
        assert_eq!(s.len(), 2, "满时不入队");
    }

    // TEST 7 — duplicate request（同 request_id）⇒ Duplicate（不覆盖）
    #[test]
    fn scheduler_duplicate_request_rejected() {
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(s.schedule(intent(1, 0xaa, 5)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(1, 0xbb, 6)), ScheduleResult::Duplicate);
        assert_eq!(s.len(), 1, "duplicate 不入队");
        // 不同 request_id 可入队
        assert_eq!(s.schedule(intent(2, 0xbb, 6)), ScheduleResult::Scheduled);
    }

    // TEST 8 — FIFO scheduling（入队序 == 出队序）
    #[test]
    fn scheduler_fifo_order() {
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(s.schedule(intent(1, 0xaa, 5)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(2, 0xbb, 6)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(3, 0xcc, 7)), ScheduleResult::Scheduled);
        assert_eq!(s.dequeue().unwrap().request_id, rid(1));
        assert_eq!(s.dequeue().unwrap().request_id, rid(2));
        assert_eq!(s.dequeue().unwrap().request_id, rid(3));
        assert!(s.dequeue().is_none());
    }

    // TEST 9 — RequestId 必须 caller-provided（构造需显式注入；无默认 / 无生成）
    #[test]
    fn scheduler_request_id_caller_provided() {
        let mut s = SyncRequestScheduler::new(4);
        // SyncRequestIntent 的 request_id 字段无默认值 ⇒ 编译期强制 caller 注入。
        let injected = rid(0x42);
        assert_eq!(
            s.schedule(SyncRequestIntent {
                request_id: injected,
                peer: peer(0xaa),
                target: target(9),
            }),
            ScheduleResult::Scheduled
        );
        assert_eq!(
            s.peek().unwrap().request_id,
            injected,
            "保留 caller 注入的 id"
        );
        assert!(s.contains_request(&injected));
        assert!(!s.contains_request(&rid(0x99)));
    }

    // TEST 10 — scheduler 不生成 RequestId（入队后 id 恒等于注入值；无生成 API）
    #[test]
    fn scheduler_does_not_generate_request_id() {
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(s.schedule(intent(7, 0xaa, 5)), ScheduleResult::Scheduled);
        assert_eq!(s.schedule(intent(8, 0xbb, 6)), ScheduleResult::Scheduled);
        // 逐一取出，request_id 均等于注入值（未被替换 / 生成）
        let a = s.dequeue().unwrap();
        let b = s.dequeue().unwrap();
        assert_eq!(a.request_id, rid(7));
        assert_eq!(b.request_id, rid(8));
        // 模块无生成函数（无 rand / timestamp / counter 来源 —— security audit）。
    }

    // TEST 11 — scheduler 不发送网络请求（纯数据队列；dequeue 只返回 intent）
    #[test]
    fn scheduler_never_sends_network_request() {
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(s.schedule(intent(1, 0xaa, 5)), ScheduleResult::Scheduled);
        // dequeue 是纯数据消费（无 send / transport / socket 引用 —— 类型无 NetworkService）。
        let got = s.dequeue().unwrap();
        assert_eq!(got.peer, peer(0xaa));
        assert_eq!(got.target.height, 5);
        assert!(s.is_empty());
    }

    // TEST 12 — FutureMissingAncestor 不能伪造 missing ancestor hash（B1 seam 诚实 Unschedulable）
    #[test]
    fn b1_intent_cannot_forge_missing_ancestor_target() {
        let ma = missing_intent(0xee);
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(
            s.schedule_from_missing_ancestor(rid(9), peer(0xbb), &ma),
            ScheduleResult::Unschedulable
        );
        assert!(s.is_empty(), "未伪造 target 入队");
        // helper seam 恒 Err（不把 observed_block_hash 当 ancestor / 不猜 head+1）
        assert!(target_from_missing_ancestor(&ma).is_err());
    }

    // TEST 13 — B4 RetryEligible 可以转换成 request intent（同 target）
    #[test]
    fn retry_eligible_converts_to_request_intent() {
        let mut corr = SyncRequestCorrelator::new(4);
        let tgt = target(5);
        corr.register(rid(1), tgt, 10).unwrap();
        let outcome = corr.expire_with_retry(10, RetryPolicy { max_retries: 1 });
        assert_eq!(outcome.retry_eligible, vec![rid(1)]);
        // B5：select peer（确定性）+ caller 持有 target ⇒ 构造 intent 入队
        let elig = candidates(&[0xbb, 0xaa]);
        let sel = select_peer(&PeerSelectionPolicy::unlimited(), &elig, &[]).unwrap();
        let mut sched = SyncRequestScheduler::new(4);
        assert_eq!(
            sched.schedule(SyncRequestIntent {
                request_id: rid(1),
                peer: sel,
                target: tgt,
            }),
            ScheduleResult::Scheduled
        );
        let got = sched.dequeue().unwrap();
        assert_eq!(got.request_id, rid(1));
        assert_eq!(got.target, tgt, "target 保持");
    }

    // TEST 14 — retry 不创建第二套 retry counter（唯一来源 = B4 correlator）
    #[test]
    fn scheduler_has_no_second_retry_counter() {
        let mut corr = SyncRequestCorrelator::new(4);
        corr.register(rid(1), target(5), 10).unwrap();
        let outcome = corr.expire_with_retry(10, RetryPolicy { max_retries: 1 });
        assert_eq!(outcome.retry_eligible, vec![rid(1)]);
        // scheduler 入队该 intent —— 不触碰 correlator（不增减 B4 counter）
        let mut sched = SyncRequestScheduler::new(4);
        assert_eq!(
            sched.schedule(SyncRequestIntent {
                request_id: rid(1),
                peer: peer(0xaa),
                target: target(5),
            }),
            ScheduleResult::Scheduled
        );
        // B4 状态仍 authoritative：eligible 仍在该 request；无第二计数来源
        assert_eq!(corr.eligible_len(), 1);
        assert_eq!(
            corr.retry_status(rid(1), 10, RetryPolicy { max_retries: 1 }),
            Some(RetryDecision::RetryEligible)
        );
        // retry_count 仅由 B4 推进（corr.retry 一次后 ⇒ Exhausted）
        corr.retry(rid(1), 20).unwrap();
        assert_eq!(
            corr.retry_status(rid(1), 25, RetryPolicy { max_retries: 1 }),
            Some(RetryDecision::Exhausted)
        );
        // scheduler 仍只有那条 intent（无自身 counter / 无重复自动入队）
        assert_eq!(sched.len(), 1);
    }

    // TEST 15 — retry 更换 peer 时保持 target 不变
    #[test]
    fn retry_switches_peer_keeps_target() {
        let orig_peer = peer(0xaa);
        let tgt = target(5);
        let elig = candidates(&[0xaa, 0xbb, 0xcc]);
        // 原 peer A 已 attempted ⇒ 选 B（未尝试；稳定序）
        let new_peer = select_peer(&PeerSelectionPolicy::unlimited(), &elig, &[orig_peer]).unwrap();
        assert_eq!(new_peer, peer(0xbb));
        assert_ne!(new_peer, orig_peer);
        // 构造 retry intent：peer 更换 + target 不变
        let mut s = SyncRequestScheduler::new(4);
        assert_eq!(
            s.schedule(SyncRequestIntent {
                request_id: rid(1),
                peer: new_peer,
                target: tgt,
            }),
            ScheduleResult::Scheduled
        );
        let got = s.dequeue().unwrap();
        assert_eq!(got.peer, peer(0xbb));
        assert_eq!(got.target.height, 5, "target 不变");
        assert_eq!(got.target, tgt);
    }

    // TEST 16 — deterministic（无时钟 / 无随机 / 无 async）：相同输入重复 ⇒ 相同输出
    #[test]
    fn scheduler_and_selection_deterministic_replay() {
        let elig = candidates(&[0xcc, 0xaa, 0xbb]);
        let p = PeerSelectionPolicy::unlimited();
        let r1 = select_peer(&p, &elig, &[peer(0xaa)]);
        let r2 = select_peer(&p, &elig, &[peer(0xaa)]);
        assert_eq!(r1, r2);
        assert_eq!(r1, Ok(peer(0xbb)));
        // scheduler FIFO 可重放（相同入队序 ⇒ 相同出队序）
        let run = |ids: [u8; 3]| {
            let mut s = SyncRequestScheduler::new(4);
            for (n, t) in ids.iter().enumerate() {
                let _ = s.schedule(intent(*t, *t, (n as u64) + 1));
            }
            let mut out = Vec::new();
            while let Some(i) = s.dequeue() {
                out.push(i.request_id);
            }
            out
        };
        assert_eq!(run([3, 1, 2]), run([3, 1, 2]));
        assert_eq!(run([3, 1, 2]), vec![rid(3), rid(1), rid(2)]);
    }
}
