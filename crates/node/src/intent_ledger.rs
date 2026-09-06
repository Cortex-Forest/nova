//! Node-local Missing-Ancestor Intent Ledger（STEP 10-19-10-B1）。
//!
//! 把 `FutureMissingAncestor`（block_inbound verdict）从"仅 observation"升级为
//! **bounded + deduplicated 的缺失祖先需求记账**。
//!
//! ```text
//! FutureMissingAncestor
//!     ↓ runtime step（网络分支）
//!     ↓ ledger.observe(verdict, source)
//!     ↓ record（dedup by observed_block_hash；count saturating）
//!     ↓ bounded（cap；满 ⇒ FIFO evict oldest）
//!     ↓ STOP
//! ```
//!
//! # 边界（Intent Ledger ≠ Sync / 存储 / finality）
//! - **不发送网络请求 / 不构造 SyncBlockRequest / 无 peer selection / 无 retry / 无 timeout**。
//! - **不碰 BlockStore / StateStore / ChainHead / NodeBlockAdapter**（不是 orphan storage）。
//! - **不产生 finality / 不改 consensus**；future block 不因 valid 而 canonical。
//! - 无墙钟：无 `Instant` / `SystemTime`；eviction 为确定性 FIFO（非 random）。
//! - 无 panic：capacity=0 ⇒ record no-op（disabled）；count 用 `saturating_add`。
//!
//! # Dedup 语义（不伪造 parent）
//! `FutureMissingAncestor` verdict 只携带 `{ observed_height, observed_block_hash,
//! local_head_height }`（block_inbound 不暴露远端块 parent 的"可信缺失"语义 —— 我们**不伪造
//! parent hash**）。故 dedup key = **`observed_block_hash`**（该远端 future block 的唯一身份）：
//! 同一 future block 重复观察（Gossip 重复 / Gossip+Sync 同块）⇒ 同一 intent，`count += 1`，
//! **不新增 entry**。source 为 message class（Gossip / SyncResponse），**不是 peer identity**
//! （当前 dispatch 无可靠 peer 信息，不伪造 peer）。

use std::collections::{HashMap, VecDeque};

use crate::block_inbound::InboundBlockVerdict;

/// 该 intent 的来源消息类别（message class；**非 peer identity** —— 当前 dispatch 无可靠 peer）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockInboundSource {
    /// 经 `GossipBlock` 观察到。
    Gossip,
    /// 经 `SyncBlockResponse` 观察到。
    SyncResponse,
}

/// 一条缺失祖先需求（Node-local 观察事实；bounded、deterministic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingAncestorIntent {
    /// 观察到的远端 future block 高度（verdict.height）。
    pub observed_height: u64,
    /// 观察到的远端 future block hash（canonical 重算；= dedup key）。
    pub observed_block_hash: [u8; 32],
    /// 观察时本地 canonical head 高度（verdict.head_height；缺失祖先区间上界参考）。
    pub local_head_height: u64,
    /// 首次观察到的消息类别（重复观察保留首次 source —— 确定性）。
    pub source: BlockInboundSource,
    /// 同 dedup key 的观察次数（saturating；**不新增 entry**）。
    pub count: u64,
}

/// bounded、dedup 的缺失祖先 intent 账本（FIFO eviction；无墙钟 / 无随机）。
///
/// - `capacity = 0` ⇒ disabled（`record` no-op；不 panic）。
/// - dedup key = `observed_block_hash`；重复 ⇒ `count` saturating +1。
/// - 满且新 key ⇒ 逐出最旧（FIFO order）。
pub struct MissingAncestorIntentLedger {
    capacity: usize,
    /// key = `observed_block_hash`。
    entries: HashMap<[u8; 32], MissingAncestorIntent>,
    /// FIFO 插入序（eviction 用；非 random）。
    order: VecDeque<[u8; 32]>,
}

impl MissingAncestorIntentLedger {
    /// 构造（`capacity = 0` = disabled）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// 容量上界。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前 entry 数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否已记录某 observed block hash（dedup key）。
    pub fn contains(&self, observed_block_hash: &[u8; 32]) -> bool {
        self.entries.contains_key(observed_block_hash)
    }

    /// 按 dedup key 查询（只读）。
    pub fn get(&self, observed_block_hash: &[u8; 32]) -> Option<&MissingAncestorIntent> {
        self.entries.get(observed_block_hash)
    }

    /// 记录一条 intent（dedup by `observed_block_hash`；count saturating；满 ⇒ FIFO evict）。
    ///
    /// `capacity = 0` ⇒ no-op（disabled，不 panic）。
    pub fn record(&mut self, intent: MissingAncestorIntent) {
        if self.capacity == 0 {
            return;
        }
        let key = intent.observed_block_hash;
        if let Some(existing) = self.entries.get_mut(&key) {
            // 同一 intent：不新增 entry，仅累加观察次数（保留首次 source）。
            existing.count = existing.count.saturating_add(intent.count);
            return;
        }
        if self.entries.len() >= self.capacity {
            // 满：逐出最旧（FIFO；deterministic）。
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key);
        self.entries.insert(key, intent);
    }

    /// 观察一个 inbound verdict：仅 `FutureMissingAncestor` 触发 record；其它 verdict no-op。
    pub fn observe(&mut self, verdict: &InboundBlockVerdict, source: BlockInboundSource) {
        if let InboundBlockVerdict::FutureMissingAncestor {
            height,
            block_hash,
            head_height,
        } = verdict
        {
            self.record(MissingAncestorIntent {
                observed_height: *height,
                observed_block_hash: *block_hash,
                local_head_height: *head_height,
                source,
                count: 1,
            });
        }
    }

    /// 取走全部 intent（FIFO order；consuming）—— 供 Runtime 只读/消费观测。
    pub fn take_all(&mut self) -> Vec<MissingAncestorIntent> {
        let mut out = Vec::with_capacity(self.order.len());
        while let Some(key) = self.order.pop_front() {
            if let Some(intent) = self.entries.remove(&key) {
                out.push(intent);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(hash_tag: u8, source: BlockInboundSource) -> MissingAncestorIntent {
        MissingAncestorIntent {
            observed_height: 100,
            observed_block_hash: [hash_tag; 32],
            local_head_height: 3,
            source,
            count: 1,
        }
    }

    // TEST 1 — empty
    #[test]
    fn ledger_empty_on_new() {
        let l = MissingAncestorIntentLedger::new(4);
        assert_eq!(l.len(), 0);
        assert!(l.is_empty());
    }

    // TEST 2 — single insert
    #[test]
    fn ledger_single_insert() {
        let mut l = MissingAncestorIntentLedger::new(4);
        l.record(intent(0xaa, BlockInboundSource::Gossip));
        assert_eq!(l.len(), 1);
        assert!(l.contains(&[0xaa; 32]));
        assert_eq!(l.get(&[0xaa; 32]).unwrap().count, 1);
    }

    // TEST 3 — duplicate: same intent ⇒ len unchanged, count += 1
    #[test]
    fn ledger_duplicate_dedups_and_counts() {
        let mut l = MissingAncestorIntentLedger::new(4);
        l.record(intent(0xaa, BlockInboundSource::Gossip));
        l.record(intent(0xaa, BlockInboundSource::SyncResponse)); // 跨 source 同块 ⇒ 同 intent
        assert_eq!(l.len(), 1, "duplicate 不新增 entry");
        assert_eq!(l.get(&[0xaa; 32]).unwrap().count, 2);
        assert_eq!(
            l.get(&[0xaa; 32]).unwrap().source,
            BlockInboundSource::Gossip,
            "保留首次 source（确定性）"
        );
    }

    // TEST 4 — distinct intents
    #[test]
    fn ledger_distinct_intents() {
        let mut l = MissingAncestorIntentLedger::new(4);
        l.record(intent(0xaa, BlockInboundSource::Gossip));
        l.record(intent(0xbb, BlockInboundSource::SyncResponse));
        assert_eq!(l.len(), 2);
        assert!(l.contains(&[0xaa; 32]));
        assert!(l.contains(&[0xbb; 32]));
    }

    // TEST 5 — bounded FIFO eviction
    #[test]
    fn ledger_bounded_fifo_eviction() {
        let mut l = MissingAncestorIntentLedger::new(2);
        l.record(intent(0xaa, BlockInboundSource::Gossip)); // A
        l.record(intent(0xbb, BlockInboundSource::Gossip)); // B
        l.record(intent(0xcc, BlockInboundSource::Gossip)); // C ⇒ 逐出 A（最旧）
        assert_eq!(l.len(), 2);
        assert!(!l.contains(&[0xaa; 32]), "A evicted (oldest)");
        assert!(l.contains(&[0xbb; 32]), "B retained");
        assert!(l.contains(&[0xcc; 32]), "C retained");
    }

    // TEST 6 — count saturation: 不 overflow
    #[test]
    fn ledger_count_saturates() {
        let mut l = MissingAncestorIntentLedger::new(4);
        let mut maxed = intent(0xaa, BlockInboundSource::Gossip);
        maxed.count = u64::MAX;
        l.record(maxed);
        // 再观察同块 ⇒ saturating_add(1) 仍为 MAX（不 panic / 不溢出）
        l.record(intent(0xaa, BlockInboundSource::SyncResponse));
        assert_eq!(l.get(&[0xaa; 32]).unwrap().count, u64::MAX);
        // 反复观察也不溢出
        for _ in 0..100 {
            l.record(intent(0xaa, BlockInboundSource::Gossip));
        }
        assert_eq!(l.get(&[0xaa; 32]).unwrap().count, u64::MAX);
    }

    // capacity = 0 ⇒ disabled（record no-op，不 panic）
    #[test]
    fn ledger_zero_capacity_disabled() {
        let mut l = MissingAncestorIntentLedger::new(0);
        l.record(intent(0xaa, BlockInboundSource::Gossip));
        assert_eq!(l.len(), 0);
        assert!(l.take_all().is_empty());
    }

    // take_all：FIFO order + consuming
    #[test]
    fn ledger_take_all_fifo_and_consumes() {
        let mut l = MissingAncestorIntentLedger::new(4);
        l.record(intent(0xaa, BlockInboundSource::Gossip));
        l.record(intent(0xbb, BlockInboundSource::SyncResponse));
        let taken = l.take_all();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].observed_block_hash, [0xaa; 32], "FIFO 序");
        assert_eq!(taken[1].observed_block_hash, [0xbb; 32]);
        assert!(l.is_empty(), "consuming");
    }

    // observe：仅 FutureMissingAncestor 触发；其它 verdict no-op
    #[test]
    fn ledger_observe_only_future_missing_ancestor() {
        let mut l = MissingAncestorIntentLedger::new(4);
        l.observe(
            &InboundBlockVerdict::FutureMissingAncestor {
                height: 100,
                block_hash: [0xcc; 32],
                head_height: 3,
            },
            BlockInboundSource::Gossip,
        );
        assert_eq!(l.len(), 1);
        assert_eq!(l.get(&[0xcc; 32]).unwrap().observed_height, 100);
        assert_eq!(l.get(&[0xcc; 32]).unwrap().local_head_height, 3);
        // 非 future verdict ⇒ no-op
        l.observe(
            &InboundBlockVerdict::CanonicalNextCandidate {
                block_hash: [0xdd; 32],
                height: 4,
            },
            BlockInboundSource::SyncResponse,
        );
        l.observe(
            &InboundBlockVerdict::Stale {
                height: 2,
                block_hash: [0xee; 32],
                head_height: 3,
            },
            BlockInboundSource::Gossip,
        );
        assert_eq!(l.len(), 1, "仅 FutureMissingAncestor 记账");
    }
}
