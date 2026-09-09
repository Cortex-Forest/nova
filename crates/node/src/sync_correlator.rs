//! Node-local Sync Request/Response Correlator（STEP 10-19-10-B2 correlation + B3 timeout +
//! B4 **bounded retry lifecycle**）。
//!
//! 在 wire 层（`network::sync` 的 `SyncBlockRequest.request_id` / `SyncBlockResponse.request_id`，
//! canonical 16B `RequestId`）之上建立 **pending request correlation** + **deterministic timeout** +
//! **显式 retry 状态机**：
//!
//! ```text
//! caller 构造 SyncBlockRequest{request_id, ...}
//!     ↓ correlator.register(request_id, target, deadline_tick)  （bounded；duplicate/full reject）
//!     ↓ （future 发送 seam —— 本模块不发网络）
//! remote SyncBlockResponse{request_id, blocks}
//!     ↓ correlator.resolve(response.request_id)      （consuming；unknown ⇒ reject）
//!     ↓ 匹配成功 ⇒ Resolved（**不 imply 块有效/canonical/finality**）
//!     ↓ block payload → block_inbound::validate_block_inbound（既有 seam）
//! caller 周期显式调用 expire_with_retry(current_tick, policy)   （B3+B4）
//!     ↓ 对过期 active：retry_count < max ⇒ RetryEligible（移出可 resolve，等 caller）
//!     ↓                 retry_count >= max ⇒ Exhausted（终结）
//!     ↓ caller 显式 retry(id, new_deadline) ⇒ 回 Pending（retry_count+1）；或 abandon(id)
//! ```
//!
//! # 时间模型（B3+B4 —— 确定性逻辑 tick，非墙钟）
//! - [`LogicalTick`] 由 **caller 提供**（如 runtime step 计数）；本模块**不读真实时钟**。
//! - `deadline_tick = 10` ⇒ tick 9 = Pending；tick 10 / 11 = 过期（`current_tick >= deadline`）。
//! - timeout 只产出状态（RetryEligible / Exhausted）：**不 retry / 不生成新 RequestId /
//!   不换 peer / 不自动 register**（实际发送/重发归未来 STEP）。
//!
//! # Retry 语义（B4）
//! - [`RetryPolicy`]`{ max_retries }`：`attempt 0` = 首次；`max_retries = 0` ⇒ 首次 timeout 即
//!   Exhausted；`max_retries = N` ⇒ 至多 N 次 retry 后 Exhausted。
//! - retry 计数由 correlator 维护（`register` 起 0；每次显式 [`SyncRequestCorrelator::retry`] +1）。
//! - **不自动**：`expire_with_retry` 不 register / 不生成 RequestId；caller 观察 outcome 后显式
//!   `retry` / `abandon`。
//! - Resolved（resolve 成功移除）之后**不能**回到 RetryEligible / 再 expire（防重入）。
//! - RetryEligible 的 request 已移出 active ⇒ 迟到 response 的 `resolve` 报 `Unknown`（reject）——
//!   response-after-expiry 绝不 accept。
//!
//! # 边界（B2+B3+B4）
//! - **RequestId = 显式 correlation identity**：不是 block hash / 不是 height / 不是 peer。
//! - **无网络 I/O / 无 peer scoring**；生成归 caller（CSPRNG deferred）。
//! - **无 eviction**：满 ⇒ deterministic `Full` reject（不逐出）；active+eligible 总量 bounded。
//! - **resolve 为 consuming**：同 request_id 的第二次 response ⇒ `Unknown`。
//! - 本模块不消费 BlockStore / StateStore / ChainHead / finality；correlation 成功 ≠ 块可信。
//! - 无墙钟（无 `Instant`/`SystemTime`）/ 无随机 / 无 async / 无后台线程。
//!
//! # 与 B1 的连接（如实）
//! B1 `MissingAncestorIntent` 只有 observed future-block 的 `(height, block_hash, head_height)`；
//! 它**不携带可安全构造 sync target 的祖先区间语义**（不伪造 ancestor）。因此本模块**不**从
//! B1 intent 自动触发 request；request 生成 seam 由上层 caller 显式提供 target（未来 STEP）。
//! 本模块只负责已发出的 request 的 correlation / timeout / retry 状态机。

use std::collections::{HashMap, VecDeque};

use nova_network::security::RequestId;

/// 确定性逻辑 tick（caller 提供；本模块不读真实时钟）。等价于 runtime step / event-loop 计数。
pub type LogicalTick = u64;

/// 请求目标（最小语义：与 `SyncBlockRequest{height, block_hash}` 一致；非伪造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRequestTarget {
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

/// retry 策略（确定性；无时间 / 无随机 / 无指数退避）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// 该逻辑请求**允许的 retry 次数**（attempt 0 = 首次）。
    /// `max_retries = 0` ⇒ 首次 timeout 即 Exhausted（不 retry）。
    pub max_retries: u8,
}

/// retry 状态判定（B4 查询）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// 仍在有效 deadline 内（`current_tick < deadline_tick`）。
    Pending,
    /// deadline 已到但 retry 预算未尽（caller 可显式 `retry`）。
    RetryEligible,
    /// deadline 已到且 retry 预算耗尽（终结；不自动重发）。
    Exhausted,
}

/// `expire_with_retry` 的结果（FIFO 注册序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireOutcome {
    /// 可 retry（caller 决定是否显式 `retry` / `abandon`）—— 已移出 active（response 不可 resolve）。
    pub retry_eligible: Vec<RequestId>,
    /// 预算耗尽，已终结（不再追踪）。
    pub exhausted: Vec<RequestId>,
}

impl ExpireOutcome {
    fn empty() -> Self {
        Self {
            retry_eligible: Vec::new(),
            exhausted: Vec::new(),
        }
    }
}

/// correlation / timeout 拒绝原因（typed；deterministic；无 String / panic）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncCorrelateError {
    /// 同 `RequestId` 已 outstanding（active 或 RetryEligible；不覆盖；deterministic reject）。
    Duplicate,
    /// response / retry / abandon 的 `RequestId` 无对应 active / eligible request
    /// （未知 / 已消费 replay / 已过期）。
    Unknown,
    /// pending 已满（不逐出 + retry；deterministic reject）。
    Full,
}

/// 一条 active pending sync request（可 resolve；含 timeout deadline + retry 计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSyncRequest {
    target: SyncRequestTarget,
    /// 逻辑 tick 期限：`current_tick >= deadline_tick` ⇒ 过期。
    deadline_tick: LogicalTick,
    /// 已 retry 次数（`register` 起 0；显式 `retry` +1）。
    retry_count: u8,
}

/// 一条 RetryEligible（deadline 已到、预算未尽；等 caller 显式 retry / abandon）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligibleRequest {
    target: SyncRequestTarget,
    /// 该逻辑请求迄今已 retry 次数（供判定 Exhausted）。
    retry_count: u8,
}

/// pending sync request correlator（bounded；consuming resolve；deterministic tick timeout；
/// 显式 retry 状态机；无 eviction / 无自动重发 / 无网络）。
pub struct SyncRequestCorrelator {
    capacity: usize,
    /// key = `request_id`（active pending，可 resolve）。
    active: HashMap<RequestId, PendingSyncRequest>,
    /// key = `request_id`（RetryEligible，等 caller 决定；不可 resolve —— response-after-expiry reject）。
    eligible: HashMap<RequestId, EligibleRequest>,
    /// 注册序（FIFO；deterministic expiry 顺序；无 eviction）。
    order: VecDeque<RequestId>,
}

impl SyncRequestCorrelator {
    /// 构造（`capacity = 0` ⇒ 任何 register 均 `Full`）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            active: HashMap::new(),
            eligible: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前 active（未过期 / 未消费 / 未进 RetryEligible）request 数。
    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// 当前 RetryEligible（等 caller）request 数。
    pub fn eligible_len(&self) -> usize {
        self.eligible.len()
    }

    /// active + eligible 总占用（bounded by capacity）。
    fn total_len(&self) -> usize {
        self.active.len() + self.eligible.len()
    }

    /// 登记一个已发出请求（caller 已构造 `SyncBlockRequest`；本模块不发送网络）。
    ///
    /// - active 或 RetryEligible 已有同 request_id ⇒ `Err(Duplicate)`（不覆盖；先 resolve /
    ///   retry / abandon）。
    /// - active + eligible 总量已满 ⇒ `Err(Full)`（不逐出；无 retry 语义）。
    /// - `deadline_tick` = 逻辑 tick 期限（caller 提供；非墙钟）。
    /// - retry_count 起 0（首次 attempt）。
    pub fn register(
        &mut self,
        request_id: RequestId,
        target: SyncRequestTarget,
        deadline_tick: LogicalTick,
    ) -> Result<(), SyncCorrelateError> {
        if self.active.contains_key(&request_id) || self.eligible.contains_key(&request_id) {
            return Err(SyncCorrelateError::Duplicate);
        }
        if self.total_len() >= self.capacity {
            return Err(SyncCorrelateError::Full);
        }
        self.active.insert(
            request_id,
            PendingSyncRequest {
                target,
                deadline_tick,
                retry_count: 0,
            },
        );
        self.order.push_back(request_id);
        Ok(())
    }

    /// 使到达 / 超过 `deadline_tick` 的 active request 过期并**全部终结**（B3；无 retry 预算）。
    ///
    /// 保留以向后兼容 B3 语义；有 retry 预算时请用 [`Self::expire_with_retry`]。
    /// - `current_tick < deadline` ⇒ Pending（保留）；`current_tick >= deadline` ⇒ Expired（移除）。
    /// - 返回过期 `RequestId`，**按注册序（FIFO）**。
    /// - **幂等**：已过期者已移除，重复调用不再产生重复 expiry。
    pub fn expire_at(&mut self, current_tick: LogicalTick) -> Vec<RequestId> {
        let mut expired = Vec::new();
        let mut remaining = VecDeque::new();
        while let Some(id) = self.order.pop_front() {
            match self.active.get(&id) {
                Some(p) if p.deadline_tick <= current_tick => {
                    self.active.remove(&id);
                    expired.push(id);
                }
                Some(_) => remaining.push_back(id),
                // 已消费（resolve）/ 已进 eligible / 先前已过期 —— 丢弃 order 残留
                None => {}
            }
        }
        self.order = remaining;
        expired
    }

    /// 带 retry 预算的过期判定（B4；deterministic FIFO）。
    ///
    /// 遍历 active（注册序）：`current_tick < deadline` ⇒ Pending（保留）；
    /// `current_tick >= deadline`：
    /// - `retry_count < policy.max_retries` ⇒ **RetryEligible**（移出 active 至 eligible ——
    ///   迟到 response 的 `resolve` 将报 `Unknown`；等 caller 显式 `retry` / `abandon`）；
    /// - `retry_count >= policy.max_retries` ⇒ **Exhausted**（终结移除，不再追踪）。
    ///
    /// **不自动 retry / 不生成 RequestId / 不 register**（B4 state/intent only）。
    pub fn expire_with_retry(
        &mut self,
        current_tick: LogicalTick,
        policy: RetryPolicy,
    ) -> ExpireOutcome {
        let mut outcome = ExpireOutcome::empty();
        let mut remaining = VecDeque::new();
        while let Some(id) = self.order.pop_front() {
            match self.active.get(&id) {
                Some(p) if p.deadline_tick <= current_tick => {
                    let retry_count = p.retry_count;
                    let target = p.target;
                    self.active.remove(&id);
                    if retry_count < policy.max_retries {
                        // RetryEligible：保留预算与 target，等 caller 显式 retry / abandon。
                        self.eligible.insert(
                            id,
                            EligibleRequest {
                                target,
                                retry_count,
                            },
                        );
                        outcome.retry_eligible.push(id);
                    } else {
                        outcome.exhausted.push(id);
                    }
                }
                Some(_) => remaining.push_back(id),
                None => {}
            }
        }
        self.order = remaining;
        outcome
    }

    /// caller 显式推进一个 RetryEligible request 到下一 attempt（B4；**非自动**）。
    ///
    /// - 该 id 必须在 eligible（先前 `expire_with_retry` 判为 RetryEligible）⇒ 移除 eligible，
    ///   retry_count +1，回 active Pending（新 `deadline_tick`），注册序移至队尾。
    /// - 不在 eligible ⇒ `Err(Unknown)`；已在 active ⇒ `Err(Duplicate)`。
    /// - 不生成新 RequestId / 不换 peer（caller 决定是否换 id）。
    pub fn retry(
        &mut self,
        request_id: RequestId,
        new_deadline_tick: LogicalTick,
    ) -> Result<(), SyncCorrelateError> {
        if self.active.contains_key(&request_id) {
            return Err(SyncCorrelateError::Duplicate);
        }
        let Some(e) = self.eligible.remove(&request_id) else {
            return Err(SyncCorrelateError::Unknown);
        };
        self.active.insert(
            request_id,
            PendingSyncRequest {
                target: e.target,
                deadline_tick: new_deadline_tick,
                retry_count: e.retry_count.saturating_add(1),
            },
        );
        self.order.push_back(request_id);
        Ok(())
    }

    /// caller 放弃一个 RetryEligible request（终结；释放槽位）。非 eligible ⇒ `false`。
    pub fn abandon(&mut self, request_id: RequestId) -> bool {
        self.eligible.remove(&request_id).is_some()
    }

    /// 无条件释放一个 request（active 或 RetryEligible 均移除）并清理注册序
    /// （STEP 10-19-10-B7-A1-D8-3-1：send-failure / 显式放弃 active request —— 释放 capacity）。
    ///
    /// - 不存在 / 已 resolve / 已 expire ⇒ `false`（幂等；不 panic）。
    /// - 不自动 retry / 不重新选 peer / 不重新 register（caller 显式决定）。
    /// - 不改变其它 request（active 数量只减该条）。
    pub fn release(&mut self, request_id: RequestId) -> bool {
        let removed = self.active.remove(&request_id).is_some()
            || self.eligible.remove(&request_id).is_some();
        if removed {
            self.order.retain(|id| *id != request_id);
        }
        removed
    }

    /// 查询某 request 的 retry 状态（只读；不 mutate）。
    ///
    /// - active 且 `tick < deadline` ⇒ `Pending`；
    /// - active 且 `tick >= deadline`：`retry_count < max` ⇒ `RetryEligible`，否则 `Exhausted`；
    /// - eligible（已 RetryEligible）⇒ `RetryEligible`；
    /// - 已 resolve / Exhausted / 从未注册 ⇒ `None`（Resolved 后不可能再回 RetryEligible）。
    pub fn retry_status(
        &self,
        request_id: RequestId,
        current_tick: LogicalTick,
        policy: RetryPolicy,
    ) -> Option<RetryDecision> {
        if let Some(p) = self.active.get(&request_id) {
            if current_tick < p.deadline_tick {
                return Some(RetryDecision::Pending);
            }
            return Some(if p.retry_count < policy.max_retries {
                RetryDecision::RetryEligible
            } else {
                RetryDecision::Exhausted
            });
        }
        if self.eligible.contains_key(&request_id) {
            return Some(RetryDecision::RetryEligible);
        }
        None
    }

    /// 解析一个收到的 response request_id（**consuming**：成功则移除，防 replay）。
    ///
    /// - 仅 active 可成功；RetryEligible / 未知 / 已消费 ⇒ `Err(Unknown)`
    ///   （response-after-expiry 绝不 accept）。
    pub fn resolve(
        &mut self,
        request_id: RequestId,
    ) -> Result<SyncRequestTarget, SyncCorrelateError> {
        self.active
            .remove(&request_id)
            .map(|p| p.target)
            .ok_or(SyncCorrelateError::Unknown)
    }

    /// 是否 active outstanding。
    pub fn contains(&self, request_id: &RequestId) -> bool {
        self.active.contains_key(request_id)
    }
}

/// 纯 correlation 比较 seam：`expected request_id == response request_id`。
///
/// 仅绑定 request；**不 imply 块有效 / canonical / finalized / committed**。
pub fn response_matches(expected_request: RequestId, response_request: RequestId) -> bool {
    expected_request == response_request
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用远 deadline（避免 B2 语义测试被误过期）。
    const FAR: LogicalTick = 1_000_000;

    fn rid(tag: u8) -> RequestId {
        RequestId::from_bytes([tag; 16])
    }

    fn target(height: u64) -> SyncRequestTarget {
        SyncRequestTarget {
            height,
            block_hash: None,
        }
    }

    fn register_far(c: &mut SyncRequestCorrelator, id: u8, height: u64) {
        c.register(rid(id), target(height), FAR).unwrap();
    }

    // TEST 4 — matching RequestId ⇒ accepted
    #[test]
    fn matching_request_id_accepted() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        let resolved = c.resolve(rid(1)).unwrap();
        assert_eq!(resolved.height, 5);
        assert!(response_matches(rid(1), rid(1)));
        assert!(c.is_empty(), "consuming resolve");
    }

    // TEST 5 — mismatching RequestId ⇒ rejected（resolve unknown + seam false）
    #[test]
    fn mismatching_request_id_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert_eq!(c.resolve(rid(2)), Err(SyncCorrelateError::Unknown));
        assert!(!response_matches(rid(1), rid(2)));
        // 原 outstanding 保留（错误 response 不影响）
        assert!(c.contains(&rid(1)));
    }

    // TEST 6 — unknown RequestId ⇒ rejected
    #[test]
    fn unknown_request_id_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        assert_eq!(c.resolve(rid(9)), Err(SyncCorrelateError::Unknown));
    }

    // TEST 7 — same response replay ⇒ 不产生第二逻辑请求（consuming resolve ⇒ second Unknown）
    #[test]
    fn response_replay_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert!(c.resolve(rid(1)).is_ok());
        assert_eq!(
            c.resolve(rid(1)),
            Err(SyncCorrelateError::Unknown),
            "replay 拒绝"
        );
        assert_eq!(c.len(), 0, "不产生第二逻辑请求");
    }

    // duplicate request_id ⇒ deterministic reject（不覆盖）
    #[test]
    fn duplicate_request_id_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert_eq!(
            c.register(rid(1), target(6), FAR),
            Err(SyncCorrelateError::Duplicate)
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5, "原 target 保留");
    }

    // full ⇒ deterministic reject（无 eviction + retry）
    #[test]
    fn full_rejects_deterministically() {
        let mut c = SyncRequestCorrelator::new(1);
        register_far(&mut c, 1, 5);
        assert_eq!(
            c.register(rid(2), target(6), FAR),
            Err(SyncCorrelateError::Full)
        );
        assert!(c.contains(&rid(1)));
    }

    // capacity = 0 ⇒ 任何 register Full（不 panic）
    #[test]
    fn zero_capacity_always_full() {
        let mut c = SyncRequestCorrelator::new(0);
        assert_eq!(
            c.register(rid(1), target(5), FAR),
            Err(SyncCorrelateError::Full)
        );
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown));
    }

    // ---- B3：deterministic tick timeout lifecycle ----

    // TEST 1 — tick < deadline ⇒ Pending（不过期）
    #[test]
    fn b3_before_deadline_stays_pending() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        let expired = c.expire_at(9);
        assert!(expired.is_empty(), "tick 9 < deadline 10 ⇒ Pending");
        assert!(c.contains(&rid(1)));
        // 仍可正常 resolve
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5);
    }

    // TEST 2 — tick == deadline ⇒ Expired
    #[test]
    fn b3_at_deadline_expires() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        let expired = c.expire_at(10);
        assert_eq!(expired, vec![rid(1)], "tick 10 == deadline ⇒ Expired");
        assert!(!c.contains(&rid(1)));
    }

    // TEST 3 — tick > deadline ⇒ Expired
    #[test]
    fn b3_after_deadline_expires() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        let expired = c.expire_at(11);
        assert_eq!(expired, vec![rid(1)]);
        assert!(c.is_empty());
    }

    // TEST 4 — expired 后 resolve ⇒ reject（Unknown；response-after-expiry 绝不 accept）
    #[test]
    fn b3_resolve_after_expiry_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        c.expire_at(10);
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown));
    }

    // TEST 5 — resolve 后 expire ⇒ no-op（不产生重复/幽灵 expiry）
    #[test]
    fn b3_expire_after_resolve_noop() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        assert!(c.resolve(rid(1)).is_ok());
        let expired = c.expire_at(10);
        assert!(expired.is_empty(), "resolve 先发生 ⇒ expire no-op");
        assert!(c.is_empty());
    }

    // TEST 6 — 重复 expire ⇒ 每 RequestId 至多一次 Expired（幂等）
    #[test]
    fn b3_repeated_expire_idempotent() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        c.register(rid(2), target(6), 20).unwrap();
        assert_eq!(c.expire_at(10), vec![rid(1)]);
        assert_eq!(
            c.expire_at(10),
            Vec::<RequestId>::new(),
            "同 tick 重复 ⇒ 空"
        );
        assert_eq!(c.expire_at(20), vec![rid(2)], "更高 tick 只过期尚未过期的");
        assert_eq!(c.expire_at(30), Vec::<RequestId>::new(), "全部过期后 ⇒ 空");
    }

    // TEST 7 — 多个同时过期 ⇒ registration order（FIFO）
    #[test]
    fn b3_multiple_expiry_deterministic_order() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(3), target(30), 10).unwrap();
        c.register(rid(1), target(10), 10).unwrap();
        c.register(rid(2), target(20), 10).unwrap();
        // 注册序 = 3,1,2 ⇒ expiry 返回同序（非 HashMap 迭代序 / 非 id 序）
        let expired = c.expire_at(10);
        assert_eq!(expired, vec![rid(3), rid(1), rid(2)]);
        assert!(c.is_empty());
    }

    // TEST 8 — capacity：即使引入 deadline，pending 仍 bounded
    #[test]
    fn b3_capacity_still_bounded() {
        let mut c = SyncRequestCorrelator::new(2);
        c.register(rid(1), target(5), 100).unwrap();
        c.register(rid(2), target(6), 100).unwrap();
        assert_eq!(
            c.register(rid(3), target(7), 100),
            Err(SyncCorrelateError::Full)
        );
        // 过期后释放容量
        assert_eq!(c.expire_at(100).len(), 2);
        c.register(rid(3), target(7), 100).unwrap();
        assert_eq!(c.len(), 1);
    }

    // TEST 9 — duplicate RequestId：B2 语义保持（active duplicate 仍拒绝）
    #[test]
    fn b3_duplicate_semantics_preserved() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        assert_eq!(
            c.register(rid(1), target(6), 20),
            Err(SyncCorrelateError::Duplicate)
        );
        // 过期移除后同 id 显式重登记 = 新 request（caller 显式；非自动 retry）
        c.expire_at(10);
        c.register(rid(1), target(7), 30).unwrap();
        assert_eq!(c.resolve(rid(1)).unwrap().height, 7);
    }

    // TEST 10 — zero capacity ⇒ deterministic Full（B3 下不变）
    #[test]
    fn b3_zero_capacity_full() {
        let mut c = SyncRequestCorrelator::new(0);
        assert_eq!(
            c.register(rid(1), target(5), 10),
            Err(SyncCorrelateError::Full)
        );
    }

    // TEST 11 — 无 SystemTime / Instant：代码层面无真实时钟（类型 + 无墙钟 API；见 security scan）。
    #[test]
    fn b3_no_wall_clock_dependency() {
        // 逻辑 tick 由 caller 提供；register/expire 均以 LogicalTick 判定，无时间读取。
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 7).unwrap();
        assert!(c.expire_at(6).is_empty());
        assert_eq!(c.expire_at(7), vec![rid(1)]);
    }

    // ---- B4：deterministic bounded retry lifecycle ----

    fn policy(max_retries: u8) -> RetryPolicy {
        RetryPolicy { max_retries }
    }

    // TEST 1 — max_retries = 0 ⇒ Pending → (timeout) → Exhausted
    #[test]
    fn b4_max_retries_zero_exhausts_immediately() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        let o = c.expire_with_retry(10, policy(0));
        assert!(o.retry_eligible.is_empty());
        assert_eq!(o.exhausted, vec![rid(1)]);
        assert!(!c.contains(&rid(1)));
        assert_eq!(c.retry_status(rid(1), 10, policy(0)), None, "终结后无状态");
    }

    // TEST 2 — max_retries = 1 ⇒ Pending → RetryEligible → (caller retry) → Pending → Exhausted
    #[test]
    fn b4_max_retries_one_lifecycle() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        // 首次 timeout：预算未尽 ⇒ RetryEligible（移出 active；response 不可 resolve）
        let o1 = c.expire_with_retry(10, policy(1));
        assert_eq!(o1.retry_eligible, vec![rid(1)]);
        assert!(o1.exhausted.is_empty());
        assert!(!c.contains(&rid(1)), "RetryEligible 已移出 active");
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown));
        // caller 显式 retry → 回 Pending（新 deadline 20）
        assert!(c.retry(rid(1), 20).is_ok());
        assert!(c.contains(&rid(1)));
        // 第二次 timeout：retry_count(1) >= max(1) ⇒ Exhausted
        let o2 = c.expire_with_retry(20, policy(1));
        assert!(o2.retry_eligible.is_empty());
        assert_eq!(o2.exhausted, vec![rid(1)]);
    }

    // TEST 3 — max_retries = 2 ⇒ initial → retry#1 → retry#2 → exhausted
    #[test]
    fn b4_max_retries_two_lifecycle() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        // attempt 0 timeout → RetryEligible
        assert_eq!(
            c.expire_with_retry(10, policy(2)).retry_eligible,
            vec![rid(1)]
        );
        c.retry(rid(1), 20).unwrap();
        // attempt 1 (retry#1) timeout → RetryEligible
        assert_eq!(
            c.expire_with_retry(20, policy(2)).retry_eligible,
            vec![rid(1)]
        );
        c.retry(rid(1), 30).unwrap();
        // attempt 2 (retry#2) timeout → Exhausted
        let o = c.expire_with_retry(30, policy(2));
        assert!(o.retry_eligible.is_empty());
        assert_eq!(o.exhausted, vec![rid(1)]);
    }

    // TEST 4 — deadline 未到 ⇒ Pending（retry_status）
    #[test]
    fn b4_before_deadline_pending_status() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        assert_eq!(
            c.retry_status(rid(1), 9, policy(2)),
            Some(RetryDecision::Pending)
        );
    }

    // TEST 5 — tick == deadline ⇒ timeout 生效（expire_with_retry 处理；max=0 Exhausted）
    #[test]
    fn b4_at_deadline_timeout_effective() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        let o = c.expire_with_retry(10, policy(0));
        assert_eq!(o.exhausted, vec![rid(1)]);
        // 预算未尽时同 tick ⇒ RetryEligible
        c.register(rid(2), target(6), 10).unwrap();
        assert_eq!(
            c.expire_with_retry(10, policy(1)).retry_eligible,
            vec![rid(2)]
        );
    }

    // TEST 6 — response 与 deadline 同 tick ⇒ Resolved（resolve 先于 expire；不判 RetryEligible）
    #[test]
    fn b4_response_at_deadline_resolves() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        // caller 顺序：先处理 response（resolve）→ Resolved
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5);
        // 随后 expire 不产任何状态（该 id 已 Resolved）
        let o = c.expire_with_retry(10, policy(1));
        assert!(o.retry_eligible.is_empty());
        assert!(o.exhausted.is_empty());
        assert_eq!(c.retry_status(rid(1), 10, policy(1)), None);
    }

    // TEST 7 — resolved request 不能再次进入 RetryEligible（防重入）
    #[test]
    fn b4_resolved_never_reenters_retry() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        c.resolve(rid(1)).unwrap();
        // 任何更高 tick 的 expire / retry / status 均不得复活
        let o = c.expire_with_retry(100, policy(5));
        assert!(o.retry_eligible.is_empty() && o.exhausted.is_empty());
        assert_eq!(c.retry(rid(1), 200), Err(SyncCorrelateError::Unknown));
        assert_eq!(c.retry_status(rid(1), 200, policy(5)), None);
    }

    // TEST 8 — retry 不自动生成 RequestId（同 id 串行推进；无 rand/timestamp/counter 隐藏生成）
    #[test]
    fn b4_retry_keeps_same_request_id() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(7), target(5), 10).unwrap();
        c.expire_with_retry(10, policy(1));
        // caller 显式 retry 使用**同一** id（模块无生成 API）
        c.retry(rid(7), 20).unwrap();
        assert!(c.contains(&rid(7)), "id 未变");
        assert_eq!(
            c.retry_status(rid(7), 15, policy(1)),
            Some(RetryDecision::Pending)
        );
    }

    // TEST 9 — retry 不自动 register（expire 后不会自动回 active；需 caller 显式 retry）
    #[test]
    fn b4_expire_does_not_auto_register() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        c.expire_with_retry(10, policy(1));
        assert!(!c.contains(&rid(1)), "未自动回 active");
        assert_eq!(c.eligible_len(), 1, "停在 RetryEligible 等 caller");
        // 不调 retry 则一直停在那（无自动重发）
        assert_eq!(
            c.expire_with_retry(20, policy(1)).retry_eligible,
            Vec::<RequestId>::new()
        );
    }

    // TEST 10 — capacity bounded：active + eligible 总量不超 capacity（retry 不突破）
    #[test]
    fn b4_capacity_bounded_including_eligible() {
        let mut c = SyncRequestCorrelator::new(2);
        c.register(rid(1), target(5), 10).unwrap();
        c.register(rid(2), target(6), 10).unwrap();
        // 两个都进 RetryEligible（total 仍 = 2）
        let o = c.expire_with_retry(10, policy(1));
        assert_eq!(o.retry_eligible.len(), 2);
        assert_eq!(c.len() + c.eligible_len(), 2, "total bounded");
        // 无槽 → register 新 request Full（retry 不突破 bounded）
        assert_eq!(
            c.register(rid(3), target(7), 10),
            Err(SyncCorrelateError::Full)
        );
        // abandon 释放槽位 → 可再 register
        assert!(c.abandon(rid(1)));
        c.register(rid(3), target(7), 10).unwrap();
        assert_eq!(c.len() + c.eligible_len(), 2);
    }

    // TEST 11 — 多个同时 timeout ⇒ deterministic FIFO order（retry_eligible / exhausted）
    #[test]
    fn b4_multiple_timeout_deterministic_order() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(3), target(30), 10).unwrap();
        c.register(rid(1), target(10), 10).unwrap();
        c.register(rid(2), target(20), 10).unwrap();
        // 注册序 3,1,2（max=1：全部 RetryEligible，FIFO）
        let o = c.expire_with_retry(10, policy(1));
        assert_eq!(o.retry_eligible, vec![rid(3), rid(1), rid(2)]);
        assert!(o.exhausted.is_empty());
    }

    // TEST 12 — duplicate RequestId：B2 语义保持（active 与 eligible 均不可重复）
    #[test]
    fn b4_duplicate_semantics_preserved() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        assert_eq!(
            c.register(rid(1), target(6), 20),
            Err(SyncCorrelateError::Duplicate)
        );
        // eligible 状态期间 register 同 id 也 Duplicate（须先 retry / abandon）
        c.expire_with_retry(10, policy(1));
        assert_eq!(
            c.register(rid(1), target(7), 30),
            Err(SyncCorrelateError::Duplicate)
        );
    }

    // ---- STEP 10-19-10-B7-A1-D8-3-1：request lifecycle release / resolve / expire ----

    // T1 — register → resolve ⇒ active 1 → 0（consuming resolve 释放）。
    #[test]
    fn d8_3_1_register_then_resolve_releases() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert_eq!(c.len(), 1);
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5);
        assert_eq!(c.len(), 0, "active 1 → 0");
        assert!(c.is_empty());
    }

    // T2 — duplicate resolve：第二次失败（不二次释放 / 不改变其它）。
    #[test]
    fn d8_3_1_duplicate_resolve_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert!(c.resolve(rid(1)).is_ok());
        assert_eq!(
            c.resolve(rid(1)),
            Err(SyncCorrelateError::Unknown),
            "dup fail"
        );
        assert_eq!(c.len(), 0, "active 不再变化");
    }

    // T3 — unknown response：不存在 request_id ⇒ reject + correlator unchanged。
    #[test]
    fn d8_3_1_unknown_response_rejected_unchanged() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        assert_eq!(c.resolve(rid(9)), Err(SyncCorrelateError::Unknown));
        assert_eq!(c.len(), 1, "correlator unchanged");
        assert!(c.contains(&rid(1)));
        assert_eq!(
            c.resolve(rid(1)).unwrap().height,
            5,
            "原 request 仍可正常 resolve"
        );
    }

    // T4 — register → send failure → release：active capacity 恢复。
    #[test]
    fn d8_3_1_send_failure_releases() {
        let mut c = SyncRequestCorrelator::new(2);
        register_far(&mut c, 1, 5);
        register_far(&mut c, 2, 6);
        assert_eq!(c.len(), 2);
        // send-failure 释放 id 1（release 移除 active）。
        assert!(c.release(rid(1)), "release active");
        assert_eq!(c.len(), 1, "active 释放一个");
        assert!(!c.contains(&rid(1)));
        // capacity 恢复：可 register 新 request。
        register_far(&mut c, 3, 7);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&rid(2)) && c.contains(&rid(3)));
    }

    // T5 — register → response → resolve：response request_id 正确释放 request。
    #[test]
    fn d8_3_1_response_resolves_correct_request() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5);
        register_far(&mut c, 2, 6);
        assert_eq!(c.resolve(rid(2)).unwrap().height, 6, "response id=2 释放 2");
        assert!(!c.contains(&rid(2)));
        assert!(c.contains(&rid(1)), "其它 request 不受影响");
    }

    // T6 — register → expire：tick 超过 deadline ⇒ 释放（release-only；无 retry 状态）。
    #[test]
    fn d8_3_1_expire_releases() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        assert!(c.expire_at(9).is_empty(), "deadline 前不释放");
        assert_eq!(c.expire_at(10), vec![rid(1)], "deadline 到 ⇒ 释放");
        assert!(c.is_empty());
    }

    // T7 — expired request cannot resolve（release-only 后 resolve 失败）。
    #[test]
    fn d8_3_1_expired_cannot_resolve() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5), 10).unwrap();
        c.expire_at(10);
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown), "T7");
        assert!(c.is_empty());
    }

    // T8 — capacity recovery：填满 → 第 N+1 失败；release 一个 → 可再 register。
    #[test]
    fn d8_3_1_capacity_recovery_after_release() {
        let n = 64usize;
        let mut c = SyncRequestCorrelator::new(n);
        for i in 0..n as u8 {
            register_far(&mut c, i, i as u64);
        }
        assert_eq!(c.len(), n);
        assert_eq!(
            c.register(rid(0xFF), target(200), FAR),
            Err(SyncCorrelateError::Full),
            "第 65 个失败"
        );
        assert!(c.release(rid(0u8)), "release 一个");
        assert_eq!(c.len(), n - 1);
        register_far(&mut c, 0xFF, 200);
        assert_eq!(c.len(), n, "新 request 可 register");
    }

    // T9 — duplicate response isolation：resolve A 后重复 resolve A 失败；B 仍 active。
    #[test]
    fn d8_3_1_duplicate_response_does_not_affect_other() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5); // A
        register_far(&mut c, 2, 6); // B
        assert!(c.resolve(rid(1)).is_ok());
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown), "dup A");
        assert!(c.contains(&rid(2)), "B 仍 active");
        assert_eq!(c.len(), 1);
    }

    // T10 — multi-peer isolation：peer 不进入 correlator（request_id 绑定）；
    // resolve A 不触 B（request 独立 lifecycle）。
    #[test]
    fn d8_3_1_request_isolation_between_requests() {
        let mut c = SyncRequestCorrelator::new(4);
        register_far(&mut c, 1, 5); // peer A 的 request
        register_far(&mut c, 2, 6); // peer B 的 request
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5);
        assert!(
            c.contains(&rid(2)),
            "peer B request 仍 active（resolve 只消费匹配 id）"
        );
        assert_eq!(c.resolve(rid(2)).unwrap().height, 6);
        assert!(c.is_empty());
    }
}
