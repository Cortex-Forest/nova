//! Node-local Sync Request/Response Correlator（STEP 10-19-10-B2 + B3 timeout lifecycle）。
//!
//! 在 wire 层（`network::sync` 的 `SyncBlockRequest.request_id` / `SyncBlockResponse.request_id`，
//! canonical 16B `RequestId`）之上建立 **pending request correlation** + **deterministic timeout**：
//!
//! ```text
//! caller 构造 SyncBlockRequest{request_id, ...}
//!     ↓ correlator.register(request_id, target, deadline_tick)  （bounded；duplicate/full reject）
//!     ↓ （future 发送 seam —— 本模块不发网络）
//! remote SyncBlockResponse{request_id, blocks}
//!     ↓ correlator.resolve(response.request_id)      （consuming；unknown ⇒ reject）
//!     ↓ 匹配成功 ⇒ 该 response 绑定该 request（**不 imply 块有效/canonical/finality**）
//!     ↓ block payload → block_inbound::validate_block_inbound（既有 seam）
//!     ↓ STOP
//! caller 周期显式调用 correlator.expire_at(current_tick)   （B3；确定性逻辑 tick）
//!     ↓ 返回 expired RequestId（registration order；幂等）
//! ```
//!
//! # 时间模型（B3 —— 确定性逻辑 tick，非墙钟）
//! - [`LogicalTick`] 由 **caller 提供**（如 runtime step 计数）；本模块**不读真实时钟**。
//! - `deadline_tick = 10` ⇒ tick 9 = Pending；tick 10 / 11 = Expired（`current_tick >= deadline`）。
//! - timeout 只产出 `Expired(RequestId)`：**不 retry / 不生成新 RequestId / 不换 peer**（B4/B5）。
//! - expire 幂等：每个 RequestId 至多一次 Expired；resolve 先发生 ⇒ expire no-op；expire 先发生
//!   ⇒ 后续 response 的 resolve 报 `Unknown`（reject）—— response-after-expiry 绝不 accept。
//!
//! # 边界（B2 + B3）
//! - **RequestId = 显式 correlation identity**：不是 block hash / 不是 height / 不是 peer。
//! - **无网络 I/O / 无 retry / 无 peer scoring**；生成归 caller（CSPRNG deferred）。
//! - **无 eviction**：满 ⇒ deterministic `Full` reject（不逐出）。
//! - **resolve 为 consuming**：同 request_id 的第二次 response ⇒ `Unknown`。
//! - 本模块不消费 BlockStore / StateStore / ChainHead / finality；correlation 成功 ≠ 块可信。
//! - 无墙钟（无 `Instant`/`SystemTime`）/ 无随机 / 无 async / 无后台线程。
//!
//! # 与 B1 的连接（如实）
//! B1 `MissingAncestorIntent` 只有 observed future-block 的 `(height, block_hash, head_height)`；
//! 它**不携带可安全构造 sync target 的祖先区间语义**（不伪造 ancestor）。因此本模块**不**从
//! B1 intent 自动触发 request；request 生成 seam 由上层 caller 显式提供 target（未来 STEP）。
//! 本模块只负责已发出的 request 与其 response 的 correlation / timeout。

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

/// correlation / timeout 拒绝原因（typed；deterministic；无 String / panic）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncCorrelateError {
    /// 同 `RequestId` 已 outstanding（不覆盖；deterministic reject）。
    Duplicate,
    /// response 的 `RequestId` 无对应 active request（未知 / 已消费 replay / 已过期）。
    Unknown,
    /// pending 已满（不逐出 + retry；deterministic reject）。
    Full,
}

/// 一条 pending sync request（active；含 timeout deadline）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSyncRequest {
    target: SyncRequestTarget,
    /// 逻辑 tick 期限：`current_tick >= deadline_tick` ⇒ expired。
    deadline_tick: LogicalTick,
}

/// pending sync request correlator（bounded；consuming resolve；deterministic tick timeout；
/// 无 eviction/retry/网络）。
pub struct SyncRequestCorrelator {
    capacity: usize,
    /// key = `request_id`（active pending）。
    outstanding: HashMap<RequestId, PendingSyncRequest>,
    /// 注册序（FIFO；deterministic expiry 顺序；无 eviction）。
    order: VecDeque<RequestId>,
}

impl SyncRequestCorrelator {
    /// 构造（`capacity = 0` ⇒ 任何 register 均 `Full`）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            outstanding: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前 active（未过期 / 未消费）request 数。
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// 登记一个已发出请求（caller 已构造 `SyncBlockRequest`；本模块不发送网络）。
    ///
    /// - active duplicate request_id ⇒ `Err(Duplicate)`（不覆盖；B2 语义保持）。
    /// - 满 ⇒ `Err(Full)`（不逐出；无 retry 语义）。
    /// - `deadline_tick` = 逻辑 tick 期限（caller 提供；非墙钟）。
    ///
    /// 已过期 / 已消费的 request_id 不在 active map ⇒ 可被 caller 显式重新登记（新 request；
    /// **非自动 retry** —— 自动重发归未来 STEP）。
    pub fn register(
        &mut self,
        request_id: RequestId,
        target: SyncRequestTarget,
        deadline_tick: LogicalTick,
    ) -> Result<(), SyncCorrelateError> {
        if self.outstanding.contains_key(&request_id) {
            return Err(SyncCorrelateError::Duplicate);
        }
        if self.outstanding.len() >= self.capacity {
            return Err(SyncCorrelateError::Full);
        }
        self.outstanding.insert(
            request_id,
            PendingSyncRequest {
                target,
                deadline_tick,
            },
        );
        self.order.push_back(request_id);
        Ok(())
    }

    /// 使到达 / 超过 `deadline_tick` 的 pending request 过期（B3；deterministic）。
    ///
    /// - `current_tick < deadline` ⇒ Pending（保留）；`current_tick >= deadline` ⇒ Expired（移除）。
    /// - 返回过期 `RequestId`，**按注册序（FIFO）** —— 不依赖 HashMap 迭代序。
    /// - **幂等**：已过期者已移除，重复 `expire_at` 同 / 更高 tick 不再产生重复 expiry。
    /// - **无 retry / 无新 RequestId / 无 peer 切换**（B4/B5 负责）。
    pub fn expire_at(&mut self, current_tick: LogicalTick) -> Vec<RequestId> {
        let mut expired = Vec::new();
        let mut remaining = VecDeque::new();
        while let Some(id) = self.order.pop_front() {
            match self.outstanding.get(&id) {
                Some(p) if p.deadline_tick <= current_tick => {
                    self.outstanding.remove(&id);
                    expired.push(id);
                }
                Some(_) => remaining.push_back(id),
                // 已消费（resolve）或先前已过期 —— 丢弃 order 残留
                None => {}
            }
        }
        self.order = remaining;
        expired
    }

    /// 解析一个收到的 response request_id（**consuming**：成功则移除，防 replay）。
    ///
    /// - 无对应 active outstanding ⇒ `Err(Unknown)`（未知 / 已消费 replay / **已过期** ——
    ///   response-after-expiry 绝不 accept）。
    pub fn resolve(
        &mut self,
        request_id: RequestId,
    ) -> Result<SyncRequestTarget, SyncCorrelateError> {
        self.outstanding
            .remove(&request_id)
            .map(|p| p.target)
            .ok_or(SyncCorrelateError::Unknown)
    }

    /// 是否 active outstanding。
    pub fn contains(&self, request_id: &RequestId) -> bool {
        self.outstanding.contains_key(request_id)
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
}
