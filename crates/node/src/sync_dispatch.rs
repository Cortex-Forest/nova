//! Node-local Outbound Sync Request Dispatch Seam（STEP 10-19-10-B6）。
//!
//! 把 B5 调度产物推进到 **Node → Network 的 outbound sync request dispatch**：
//!
//! ```text
//! SyncRequestScheduler（B5；bounded FIFO）
//!     ↓ dequeue（bounded batch：dispatch_batch）
//!     ↓ SyncRequestIntent{ request_id, peer, target }（B5）
//!     ↓ sync_block_request_from_intent（复用 network::sync::SyncBlockRequest —— 无第二套 wire）
//!     ↓ OutboundSyncDispatcher（Node-side adapter seam）
//!     ↓ existing NetworkService outbound boundary（真实 adapter 内：pre-signed envelope →
//!       enqueue_outbound(peer, envelope)）—— B6 不直接 socket / 不 bypass NetworkService
//! ```
//!
//! # 边界（B6 —— OUTBOUND ONLY）
//! - **不接收 / 不处理 `SyncBlockResponse`**（无 response handler；无 resolve 消费驱动）。
//! - **不写 BlockStore / StateStore / 不改 ChainHead / 不做 finality / QC / canonical commit**。
//! - **不自动 retry / 不自动换 peer / 不 peer discovery / 不 peer connect**（send 失败 ⇒
//!   [`SyncDispatchResult::Rejected`]，由 caller 显式走 B4 retry/abandon 生命周期）。
//! - **RequestId caller-owned**：本模块不生成 RequestId（无 rand / timestamp / counter）。
//! - **register-before-send**：correlation 在真正 outbound dispatch 之前完成（见下）。
//! - **bounded dispatch**：单次处理至多 `max_items`；不 `while let` 无限排空。
//! - **确定性顺序**：按 scheduler FIFO 序逐条 dispatch。
//! - 无墙钟 / 无随机 / 无 async / 无后台线程；本模块无私钥（pre-signed envelope 由调用方签名边界
//!   提供，NetworkService 不自签）。
//!
//! # Correlation 顺序（§7/§23 —— 本轮最重要的安全点）
//! 真实发送路径采用：
//!
//! ```text
//! correlator.register(intent.request_id, intent.target, deadline_tick)   // register-before-send
//!     ↓ 成功
//! dispatcher.dispatch(&intent)                                           // Node→Network 边界
//! ```
//!
//! register 先行 ⇒ 避免 "response 到达但 correlator 尚未注册" 的 race。若 register 失败
//!（Duplicate / Full）⇒ **不 dispatch**（不重复发送 / bounded）。
//!
//! send 失败（`Rejected`）时：该 request 已 register（pending 保留于 correlator）。**不自动
//! retry / 不自动 abandon / 不自动换 peer** —— caller 观察 report 后显式决定（B4 authoritative：
//! `retry` / `abandon` / 等 timeout）。
//!
//! # 与现有 NetworkService 的对接（如实）
//! `nova_network` 已有 outbound 边界：`NetworkService::enqueue_outbound(peer, pre-signed
//! MessageEnvelope)`（peer 需 connected；auth 启用时需 Established session）。真实 Node adapter
//! 应：`intent → SyncBlockRequest → MessageEnvelope(SyncBlockRequest)`（网络签名在调用方签名
//! 边界）→ `enqueue_outbound(intent.peer, envelope)`。本模块**不携带私钥 / 不建立连接 / 不改
//! NetworkService**；B6 只定义 seam 与语义，供未来 authenticated peer source 注入的 adapter 实现。

use nova_network::sync::SyncBlockRequest;

use crate::sync_correlator::{LogicalTick, SyncRequestCorrelator};
use crate::sync_scheduler::{SyncRequestIntent, SyncRequestScheduler};

/// 单条 outbound dispatch 结果（§9；最小分类；不为 B6 制造复杂错误体系）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDispatchResult {
    /// 已接受送入 Node→Network outbound 边界（**不 imply** 对端已收到 / 已处理）。
    Sent,
    /// 被拒绝（如 transport/queue/peer 状态）；**不自动 retry / 不自动换 peer**。
    Rejected,
}

/// Node-side outbound sync dispatcher seam（§4/§13）。
///
/// 真实 adapter 应把 [`SyncRequestIntent`] 经 `sync_block_request_from_intent` 复用 wire
/// `SyncBlockRequest` → pre-signed `MessageEnvelope` → 既有
/// `NetworkService::enqueue_outbound(peer, envelope)`。**Node 不得直接 socket / 不得绕过
/// NetworkService**；本 trait 不携带私钥 / 连接 / peer discovery。
pub trait OutboundSyncDispatcher {
    /// 把一条 intent 送入既有 Node→Network outbound 边界。
    fn dispatch(&mut self, intent: &SyncRequestIntent) -> SyncDispatchResult;
}

/// B5 intent → 既有 wire request 的纯转换（§5/§6）。
///
/// 直接复用 `network::sync::SyncBlockRequest`（禁止第二套 wire model）：
///
/// ```text
/// request_id = intent.request_id
/// height     = intent.target.height
/// block_hash = intent.target.block_hash
/// ```
///
/// **不修改 target**；`peer` 不进入 wire（由 dispatcher 用作发送目标）。
pub fn sync_block_request_from_intent(intent: &SyncRequestIntent) -> SyncBlockRequest {
    SyncBlockRequest {
        request_id: intent.request_id,
        height: intent.target.height,
        block_hash: intent.target.block_hash,
    }
}

/// `dispatch_batch` 的累计结果（bounded；无 panic）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchBatchReport {
    /// 成功送入 Node→Network 边界的条数。
    pub sent: usize,
    /// 被 dispatcher 拒绝的条数（**不自动 retry / 不自动换 peer**；pending 保留于 correlator）。
    pub rejected: usize,
    /// correlation register 失败（Duplicate / Full）而未发送的条数（不重复发送 / bounded）。
    pub registration_failed: usize,
}

impl DispatchBatchReport {
    /// 已尝试 dispatch 的总数（sent + rejected）。
    pub fn attempted(&self) -> usize {
        self.sent + self.rejected
    }
}

/// 从 scheduler 取队首至多 `max_items` 条 intent，**register-before-send** 逐条 dispatch
///（§7/§12/§14/§17）。
///
/// 对每条（FIFO 序）：
/// 1. `scheduler.dequeue()`；
/// 2. `correlator.register(request_id, target, deadline_tick)` —— **先注册**；
///    - 成功 ⇒ 继续；
///    - `Duplicate`（同 id 已 active / eligible）或 `Full`（correlator 无槽）⇒
///      `registration_failed += 1`，**不 dispatch**（不重复发送 / bounded）；
/// 3. `dispatcher.dispatch(&intent)`：
///    - `Sent` ⇒ `sent += 1`；
///    - `Rejected` ⇒ `rejected += 1`（pending 保留于 correlator；caller 显式决定
///      abandon/retry/timeout —— **本函数不自动 retry / 不自动换 peer**）。
///
/// `max_items = 0` ⇒ no-op。空 scheduler ⇒ report 全 0。
pub fn dispatch_batch(
    scheduler: &mut SyncRequestScheduler,
    correlator: &mut SyncRequestCorrelator,
    dispatcher: &mut dyn OutboundSyncDispatcher,
    deadline_tick: LogicalTick,
    max_items: usize,
) -> DispatchBatchReport {
    let mut report = DispatchBatchReport::default();
    for _ in 0..max_items {
        let Some(intent) = scheduler.dequeue() else {
            break;
        };
        // register-before-send（§7）：register 失败 ⇒ 不发送（不重复 / bounded）。
        if correlator
            .register(intent.request_id, intent.target, deadline_tick)
            .is_err()
        {
            report.registration_failed += 1;
            continue;
        }
        match dispatcher.dispatch(&intent) {
            SyncDispatchResult::Sent => report.sent += 1,
            SyncDispatchResult::Rejected => {
                report.rejected += 1;
                // send 失败：不自动 retry / 不自动 abandon / 不自动换 peer（§8）。pending 保留，
                // caller 观察 report 后显式决定（B4 authoritative retry/abandon）。
            }
        }
    }
    report
}

/// 无真实 outbound 边界可用的默认 dispatcher（诚实拒绝；不吞错误 / 不假装发送）。
///
/// 用于 runtime 尚无 authenticated peer source / NetworkService adapter 的场合 —— 明确拒绝并
/// 计数，而非伪造成功或直接触网。
pub struct NoOpRejectDispatcher;

impl OutboundSyncDispatcher for NoOpRejectDispatcher {
    fn dispatch(&mut self, _intent: &SyncRequestIntent) -> SyncDispatchResult {
        SyncDispatchResult::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nova_network::node_id::NodeId;
    use nova_network::security::RequestId;

    use crate::sync_scheduler::SyncRequestScheduler;

    /// 测试用远 deadline（避免误过期）。
    const FAR: LogicalTick = 1_000_000;

    fn rid(tag: u8) -> RequestId {
        RequestId::from_bytes([tag; 16])
    }

    fn peer(tag: u8) -> NodeId {
        NodeId::from_bytes([tag; 32])
    }

    fn intent(id_tag: u8, peer_tag: u8, height: u64) -> SyncRequestIntent {
        SyncRequestIntent {
            request_id: rid(id_tag),
            peer: peer(peer_tag),
            target: crate::sync_correlator::SyncRequestTarget {
                height,
                block_hash: None,
            },
        }
    }

    fn intent_with_hash(id_tag: u8, peer_tag: u8, height: u64, h: [u8; 32]) -> SyncRequestIntent {
        SyncRequestIntent {
            request_id: rid(id_tag),
            peer: peer(peer_tag),
            target: crate::sync_correlator::SyncRequestTarget {
                height,
                block_hash: Some(h),
            },
        }
    }

    /// 记录调用的 mock dispatcher（结果可配置）。
    struct MockDispatcher {
        calls: Vec<SyncRequestIntent>,
        outcome: SyncDispatchResult,
    }

    impl MockDispatcher {
        fn new(outcome: SyncDispatchResult) -> Self {
            Self {
                calls: Vec::new(),
                outcome,
            }
        }
    }

    impl OutboundSyncDispatcher for MockDispatcher {
        fn dispatch(&mut self, intent: &SyncRequestIntent) -> SyncDispatchResult {
            self.calls.push(intent.clone());
            self.outcome
        }
    }

    fn seed(sched: &mut SyncRequestScheduler, items: &[(u8, u8, u64)]) {
        for &(id, p, h) in items {
            let _ = sched.schedule(intent(id, p, h));
        }
    }

    // TEST 1 — intent 正确转换为 SyncBlockRequest（字段映射）
    #[test]
    fn intent_converts_to_sync_block_request() {
        let i = intent_with_hash(1, 0xaa, 42, [0x5a; 32]);
        let r = sync_block_request_from_intent(&i);
        assert_eq!(r.request_id, i.request_id);
        assert_eq!(r.height, 42);
        assert_eq!(r.block_hash, Some([0x5a; 32]));
        // 无 hash 情形
        let r2 = sync_block_request_from_intent(&intent(2, 0xbb, 7));
        assert_eq!(r2.block_hash, None);
        assert_eq!(r2.height, 7);
    }

    // TEST 2 — request_id 完整保留
    #[test]
    fn request_id_preserved_through_conversion() {
        let i = intent(9, 0xaa, 5);
        let r = sync_block_request_from_intent(&i);
        assert_eq!(r.request_id, rid(9));
    }

    // TEST 3 — height 完整保留
    #[test]
    fn height_preserved_through_conversion() {
        let i = intent(1, 0xaa, 123_456);
        let r = sync_block_request_from_intent(&i);
        assert_eq!(r.height, 123_456);
    }

    // TEST 4 — block_hash 完整保留
    #[test]
    fn block_hash_preserved_through_conversion() {
        let h = [0xde; 32];
        let r = sync_block_request_from_intent(&intent_with_hash(1, 0xaa, 5, h));
        assert_eq!(r.block_hash, Some(h));
    }

    // TEST 5 — peer NodeId 完整保留（dispatcher 收到原 peer handle；wire 不含 peer —— 由
    // dispatcher 用作发送目标）
    #[test]
    fn peer_node_id_preserved_to_dispatcher() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xbb, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.sent, 1);
        assert_eq!(d.calls[0].peer, peer(0xbb));
    }

    // TEST 6 — register-before-send：send 仅在 register 成功后发生；register 失败 ⇒ 不发送
    #[test]
    fn register_before_send_ordering() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.sent, 1);
        // register 已先发生 ⇒ dispatch 后 correlator 含该 pending request
        assert!(corr.contains(&rid(1)));
        assert_eq!(d.calls.len(), 1);
        // 对照：若 register 已失败（同 id 已 active），则不 dispatch（不重复发送）→ TEST 14
    }

    // TEST 7 — send success ⇒ Sent + correlator registered + scheduler 消费
    #[test]
    fn dispatch_send_success() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(
            rep,
            DispatchBatchReport {
                sent: 1,
                rejected: 0,
                registration_failed: 0
            }
        );
        assert!(corr.contains(&rid(1)));
        assert!(sched.is_empty(), "已消费");
        assert_eq!(d.calls.len(), 1);
    }

    // TEST 8 — send failure ⇒ Rejected（pending 保留；caller 后续显式决定）
    #[test]
    fn dispatch_send_failure_reported() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Rejected);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.rejected, 1);
        // pending 保留于 correlator（register 先行 ⇒ 未被自动清除）
        assert!(corr.contains(&rid(1)));
        assert!(sched.is_empty(), "该 intent 已出队（不重入 scheduler）");
    }

    // TEST 9 — send failure 不自动 retry（dispatcher 只被调用一次；无 retry 状态推进）
    #[test]
    fn send_failure_does_not_auto_retry() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Rejected);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.rejected, 1);
        assert_eq!(d.calls.len(), 1, "仅尝试一次（无自动 retry）");
        // correlator 中该 request 仍在 active（无 retry() 推进 / 无重复 register）
        assert!(corr.contains(&rid(1)));
    }

    // TEST 10 — send failure 不自动选择其他 peer（dispatcher 收到原 intent.peer，仅一次）
    #[test]
    fn send_failure_does_not_auto_switch_peer() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xcc, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Rejected);
        let _ = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(d.calls[0].peer, peer(0xcc), "peer 未被替换");
    }

    // TEST 11 — dispatcher 不生成 RequestId（wire request id == intent 注入 id）
    #[test]
    fn dispatcher_does_not_generate_request_id() {
        let i = intent(0x3a, 0xaa, 5);
        let r = sync_block_request_from_intent(&i);
        assert_eq!(r.request_id, rid(0x3a), "保留注入 id（无生成）");
        // dispatch_batch 也不改 id
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(0x3a, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let _ = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(d.calls[0].request_id, rid(0x3a));
    }

    // TEST 12 — bounded dispatch（max_items 上限；scheduler 剩余保留）
    #[test]
    fn bounded_dispatch_batch() {
        let mut sched = SyncRequestScheduler::new(8);
        let mut corr = SyncRequestCorrelator::new(8);
        seed(&mut sched, &[(1, 0xaa, 1), (2, 0xbb, 2), (3, 0xcc, 3)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 2);
        assert_eq!(rep.attempted(), 2);
        assert_eq!(sched.len(), 1, "剩余保留（不无限排空）");
        // max_items = 0 ⇒ no-op
        let rep0 = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 0);
        assert_eq!(rep0, DispatchBatchReport::default());
    }

    // TEST 13 — empty scheduler ⇒ report 全 0
    #[test]
    fn empty_scheduler_noop() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep, DispatchBatchReport::default());
        assert!(d.calls.is_empty());
    }

    // TEST 14 — duplicate request 不重复发送（register Duplicate ⇒ 不 dispatch）
    #[test]
    fn duplicate_request_not_resent() {
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        // 同 request_id 已在 correlator active（先前发送过 / 或本 pending）
        assert!(
            corr.register(
                rid(1),
                crate::sync_correlator::SyncRequestTarget {
                    height: 5,
                    block_hash: None,
                },
                FAR
            )
            .is_ok()
        );
        // scheduler 又出现同 id intent（异常/竞态）⇒ register Duplicate ⇒ 不重复发送
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.registration_failed, 1);
        assert_eq!(rep.sent, 0);
        assert!(d.calls.is_empty(), "不重复发送");
    }

    // TEST 15/16 — Network boundary 无存储写入 / 无 head 状态突变（结构性）：本模块无任何
    // storage / head 引用；dispatch 只产出 wire SyncBlockRequest + peer（BlockStore/StateStore/
    // ChainHead 写入为 0 —— 源码 audit 保证）。
    #[test]
    fn network_boundary_no_storage_or_head_mutation() {
        // 行为代理：dispatch 只调用 dispatcher，不触碰任何 storage / head 状态。
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.sent, 1);
        // correlator 状态仅含该 pending（无其它突变可测；storage/head 为 0 由 audit 保证）
        assert_eq!(corr.len(), 1);
    }

    // TEST 17 — deterministic dispatch order（FIFO：与 scheduler 入队序一致）
    #[test]
    fn deterministic_dispatch_order() {
        let mut sched = SyncRequestScheduler::new(8);
        let mut corr = SyncRequestCorrelator::new(8);
        seed(&mut sched, &[(3, 0xaa, 1), (1, 0xbb, 2), (2, 0xcc, 3)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 8);
        assert_eq!(rep.sent, 3);
        let order: Vec<RequestId> = d.calls.iter().map(|i| i.request_id).collect();
        assert_eq!(order, vec![rid(3), rid(1), rid(2)], "FIFO 注册序");
    }

    // TEST 18 — response 仍不在 B6 处理（模块无 response 处理入口；resolve 不被自动触发）
    #[test]
    fn sync_response_not_handled_in_b6() {
        // B6 只发送：无 response 处理代码路径（不 poll_inbound / 不 resolve 驱动 / 不写 BlockStore）。
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let mut d = MockDispatcher::new(SyncDispatchResult::Sent);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.sent, 1);
        // dispatch 后 correlator 中 request 仍未 resolve —— resolve 只由未来 inbound STEP（caller）
        // 显式调用；B6 不处理 response。
        assert!(corr.contains(&rid(1)));
        assert!(corr.resolve(rid(1)).is_ok());
    }

    // TEST — NoOpRejectDispatcher 诚实拒绝（不吞错误 / 不假装发送）
    #[test]
    fn noop_dispatcher_rejects_honestly() {
        let i = intent(1, 0xaa, 5);
        let mut d = NoOpRejectDispatcher;
        assert_eq!(d.dispatch(&i), SyncDispatchResult::Rejected);
        // 完整 dispatch_batch：Rejected（不吞错误；report 反映）
        let mut sched = SyncRequestScheduler::new(4);
        let mut corr = SyncRequestCorrelator::new(4);
        seed(&mut sched, &[(1, 0xaa, 5)]);
        let rep = dispatch_batch(&mut sched, &mut corr, &mut d, FAR, 4);
        assert_eq!(rep.rejected, 1);
        assert!(corr.contains(&rid(1)), "pending 保留；caller 显式决定");
    }
}
