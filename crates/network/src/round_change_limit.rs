//! O2 Round-Change 专属限流（**PHASE 6H-Y**；Owner implementation policy **D3**）。
//!
//! # 政策（Owner 固定；本模块不自选数值）
//! - `4 ConsensusRoundChange messages/sec/peer`（持续速率）
//! - `burst = 8`（初始 / 累积突发额度）
//! - 超限 ⇒ [`RateLimitDecision::Drop`]（DROP / REJECT）
//! - **不自动 BAN**、不断开、不修改 validator 状态 / consensus round / finality / lock
//!
//! # 时间基准（**治理约束**）
//! 使用 **network 层 wall-clock**（`Instant` / `Duration`）—— 这是网络层限流的合法位置。
//! **绝不**把 wall-clock 引入共识确定性（consensus 仍为逻辑 tick；ADR-0049 §3.5）。
//!
//! # 算法（整数 token bucket；无浮点、无随机）
//! - 桶容量 = `burst`；每**整秒**补充 `max_per_second` 个 token（上限 = 容量）。
//! - 每张证书消耗 1 token；无 token ⇒ `Drop`。
//! - 行为完全确定（给定 `now`），可注入时钟进行测试。

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// 持续速率：每 peer 每秒允许的 `ConsensusRoundChange` 条数（**Owner D3**）。
pub const ROUND_CHANGE_MAX_PER_SECOND: u32 = 4;
/// 突发额度（**Owner D3**）。
pub const ROUND_CHANGE_BURST: u32 = 8;
/// 限流器跟踪的 peer 数上限（有界内存；确定性淘汰最低 peer id）。
pub const DEFAULT_MAX_TRACKED_PEERS: usize = 1024;

/// 限流判定（**仅两种结果**；无 BAN 状态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// 允许处理（会消耗 1 token）。
    Allow,
    /// 丢弃 / 拒绝（DROP / REJECT）；**不**自动 BAN、**不**断开、**不**修改任何共识状态。
    Drop,
}

#[derive(Debug, Clone, Copy)]
struct PeerBucket {
    tokens: u32,
    last_refill: Instant,
}

/// 每 peer 的 `ConsensusRoundChange` 限流器（有界、确定性、无 BAN）。
#[derive(Debug, Clone)]
pub struct RoundChangeRateLimiter {
    max_per_second: u32,
    burst: u32,
    max_peers: usize,
    peers: BTreeMap<[u8; 32], PeerBucket>,
}

impl Default for RoundChangeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundChangeRateLimiter {
    /// 以 Owner policy D3 默认值构造（4/sec · burst 8）。
    pub fn new() -> Self {
        Self {
            max_per_second: ROUND_CHANGE_MAX_PER_SECOND,
            burst: ROUND_CHANGE_BURST,
            max_peers: DEFAULT_MAX_TRACKED_PEERS,
            peers: BTreeMap::new(),
        }
    }

    /// 以显式参数构造（仅供测试；生产用 [`Self::new`]）。
    pub fn with_caps(max_per_second: u32, burst: u32, max_peers: usize) -> Self {
        Self {
            max_per_second,
            burst,
            max_peers: max_peers.max(1),
            peers: BTreeMap::new(),
        }
    }

    /// 策略参数（只读）。
    pub fn policy(&self) -> (u32, u32) {
        (self.max_per_second, self.burst)
    }

    /// 跟踪的 peer 数（有界）。
    pub fn tracked_peers(&self) -> usize {
        self.peers.len()
    }

    /// 以当前时刻判定（生产入口）。
    pub fn check(&mut self, peer: &[u8; 32]) -> RateLimitDecision {
        self.check_at(peer, Instant::now())
    }

    /// 以注入时刻判定（确定性测试入口）。
    pub fn check_at(&mut self, peer: &[u8; 32], now: Instant) -> RateLimitDecision {
        if !self.peers.contains_key(peer) && self.peers.len() >= self.max_peers {
            // 确定性淘汰：移除最低 peer id（BTreeMap 首元素，与插入顺序无关）。
            let _evicted = self.peers.pop_first();
        }
        let bucket = self.peers.entry(*peer).or_insert(PeerBucket {
            tokens: self.burst,
            last_refill: now,
        });
        // 整秒补充（保留亚秒余量；无浮点、无随机）。
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        let whole = elapsed.as_secs();
        if whole > 0 {
            let refill = u32::try_from(whole.saturating_mul(u64::from(self.max_per_second)))
                .unwrap_or(u32::MAX);
            bucket.tokens = bucket.tokens.saturating_add(refill).min(self.burst);
            bucket.last_refill = bucket
                .last_refill
                .checked_add(Duration::from_secs(whole))
                .unwrap_or(now);
        }
        if bucket.tokens == 0 {
            return RateLimitDecision::Drop;
        }
        bucket.tokens -= 1;
        RateLimitDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: [u8; 32] = [0x11; 32];
    const Q: [u8; 32] = [0x22; 32];

    #[test]
    fn policy_constants_match_owner_d3() {
        assert_eq!(ROUND_CHANGE_MAX_PER_SECOND, 4);
        assert_eq!(ROUND_CHANGE_BURST, 8);
        let l = RoundChangeRateLimiter::new();
        assert_eq!(l.policy(), (4, 8));
    }

    #[test]
    fn burst_allowance_is_exactly_8_then_drops() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..8 {
            assert_eq!(
                l.check_at(&P, t0),
                RateLimitDecision::Allow,
                "burst 内第 {i} 条应允许"
            );
        }
        // 第 9 条（同一时刻、无时间推进）⇒ DROP
        assert_eq!(l.check_at(&P, t0), RateLimitDecision::Drop);
    }

    #[test]
    fn refill_is_4_per_second() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..8 {
            assert_eq!(l.check_at(&P, t0), RateLimitDecision::Allow);
        }
        assert_eq!(l.check_at(&P, t0), RateLimitDecision::Drop);
        // +1s ⇒ 补充 4（上限 8）
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Allow
        );
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Allow
        );
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Allow
        );
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Allow
        );
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Drop
        );
    }

    #[test]
    fn refill_is_capped_at_burst() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        // 空闲 60s ⇒ token 仍被 cap 在 burst = 8
        for _ in 0..8 {
            assert_eq!(
                l.check_at(&P, t0 + Duration::from_secs(60)),
                RateLimitDecision::Allow
            );
        }
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(60)),
            RateLimitDecision::Drop
        );
    }

    #[test]
    fn peers_are_isolated() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..8 {
            assert_eq!(l.check_at(&P, t0), RateLimitDecision::Allow);
        }
        assert_eq!(l.check_at(&P, t0), RateLimitDecision::Drop);
        // Q 未受限
        assert_eq!(l.check_at(&Q, t0), RateLimitDecision::Allow);
    }

    #[test]
    fn no_ban_state_and_no_side_effects() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..8 {
            l.check_at(&P, t0);
        }
        for _ in 0..100 {
            assert_eq!(l.check_at(&P, t0), RateLimitDecision::Drop);
        }
        // 无 BAN：时间推进后立即恢复允许（不叠加惩罚）
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_secs(1)),
            RateLimitDecision::Allow
        );
    }

    #[test]
    fn tracked_peers_are_bounded_with_deterministic_eviction() {
        let mut l = RoundChangeRateLimiter::with_caps(4, 8, 2);
        let t0 = Instant::now();
        l.check_at(&[0x03; 32], t0);
        l.check_at(&[0x01; 32], t0);
        assert_eq!(l.tracked_peers(), 2);
        // 新 peer ⇒ 淘汰最低 peer id（0x01）
        l.check_at(&[0x05; 32], t0);
        assert_eq!(l.tracked_peers(), 2);
    }

    #[test]
    fn sub_second_remainder_is_preserved() {
        let mut l = RoundChangeRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..8 {
            l.check_at(&P, t0);
        }
        // 0.5s 后 ⇒ 不补充
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_millis(500)),
            RateLimitDecision::Drop
        );
        // 再有 0.6s（累计 1.1s）⇒ 补充 4
        assert_eq!(
            l.check_at(&P, t0 + Duration::from_millis(1100)),
            RateLimitDecision::Allow
        );
    }
}
