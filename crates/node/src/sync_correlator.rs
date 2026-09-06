//! Node-local Sync Request/Response Correlator（STEP 10-19-10-B2）。
//!
//! 在 wire 层（`network::sync` 的 `SyncBlockRequest.request_id` / `SyncBlockResponse.request_id`，
//! canonical 16B `RequestId`）之上建立 **pending request correlation**：
//!
//! ```text
//! caller 构造 SyncBlockRequest{request_id, ...}
//!     ↓ correlator.register(request_id, target)     （bounded；duplicate/full ⇒ deterministic reject）
//!     ↓ （future 发送 seam —— 本模块不发网络）
//! remote SyncBlockResponse{request_id, blocks}
//!     ↓ correlator.resolve(response.request_id)      （consuming；unknown ⇒ reject）
//!     ↓ 匹配成功 ⇒ 该 response 绑定该 request（**不 imply 块有效/canonical/finality**）
//!     ↓ block payload → block_inbound::validate_block_inbound（既有 seam）
//!     ↓ STOP
//! ```
//!
//! # 边界（B2）
//! - **RequestId = 显式 correlation identity**：不是 block hash / 不是 height / 不是 peer。
//! - **无网络 I/O / 无 timeout / 无 retry / 无 peer scoring**；生成归 caller（CSPRNG deferred）。
//! - **无 eviction + retry**：满 ⇒ deterministic `Full` reject（不逐出）。
//! - **resolve 为 consuming**：同 request_id 的第二次 response ⇒ `Unknown`（replay 不产生第二逻辑请求）。
//! - 本模块不消费 BlockStore / StateStore / ChainHead / finality；correlation 成功 ≠ 块可信。
//! - 无墙钟 / 无随机 / 无 async。
//!
//! # 与 B1 的连接（如实）
//! B1 `MissingAncestorIntent` 只有 observed future-block 的 `(height, block_hash, head_height)`；
//! 它**不携带可安全构造 sync target 的祖先区间语义**（不伪造 ancestor）。因此本模块**不**从
//! B1 intent 自动触发 request；request 生成 seam 由上层 caller 显式提供 target（未来 STEP）。
//! 本模块只负责已发出的 request 与其 response 的 correlation。

use std::collections::HashMap;

use nova_network::security::RequestId;

/// 请求目标（最小语义：与 `SyncBlockRequest{height, block_hash}` 一致；非伪造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRequestTarget {
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

/// correlation 拒绝原因（typed；deterministic；无 String / panic）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncCorrelateError {
    /// 同 `RequestId` 已 outstanding（不覆盖；deterministic reject）。
    Duplicate,
    /// response 的 `RequestId` 无对应 outstanding request（未知 / 已消费 / replay）。
    Unknown,
    /// pending 已满（不逐出 + retry；deterministic reject）。
    Full,
}

/// pending sync request correlator（bounded；consuming resolve；无 eviction/retry/网络）。
pub struct SyncRequestCorrelator {
    capacity: usize,
    outstanding: HashMap<RequestId, SyncRequestTarget>,
}

impl SyncRequestCorrelator {
    /// 构造（`capacity = 0` ⇒ 任何 register 均 `Full`）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            outstanding: HashMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前 outstanding request 数。
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// 登记一个已发出请求（caller 已构造 `SyncBlockRequest`；本模块不发送网络）。
    ///
    /// - duplicate request_id ⇒ `Err(Duplicate)`（不覆盖）。
    /// - 满 ⇒ `Err(Full)`（不逐出；无 retry 语义）。
    pub fn register(
        &mut self,
        request_id: RequestId,
        target: SyncRequestTarget,
    ) -> Result<(), SyncCorrelateError> {
        if self.outstanding.contains_key(&request_id) {
            return Err(SyncCorrelateError::Duplicate);
        }
        if self.outstanding.len() >= self.capacity {
            return Err(SyncCorrelateError::Full);
        }
        self.outstanding.insert(request_id, target);
        Ok(())
    }

    /// 解析一个收到的 response request_id（**consuming**：成功则移除，防 replay）。
    ///
    /// - 无对应 outstanding ⇒ `Err(Unknown)`（未知 / 已消费的 replay）。
    pub fn resolve(
        &mut self,
        request_id: RequestId,
    ) -> Result<SyncRequestTarget, SyncCorrelateError> {
        self.outstanding
            .remove(&request_id)
            .ok_or(SyncCorrelateError::Unknown)
    }

    /// 是否 outstanding。
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

    fn rid(tag: u8) -> RequestId {
        RequestId::from_bytes([tag; 16])
    }

    fn target(height: u64) -> SyncRequestTarget {
        SyncRequestTarget {
            height,
            block_hash: None,
        }
    }

    // TEST 4 — matching RequestId ⇒ accepted
    #[test]
    fn matching_request_id_accepted() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5)).unwrap();
        let resolved = c.resolve(rid(1)).unwrap();
        assert_eq!(resolved.height, 5);
        assert!(response_matches(rid(1), rid(1)));
        assert!(c.is_empty(), "consuming resolve");
    }

    // TEST 5 — mismatching RequestId ⇒ rejected（resolve unknown + seam false）
    #[test]
    fn mismatching_request_id_rejected() {
        let mut c = SyncRequestCorrelator::new(4);
        c.register(rid(1), target(5)).unwrap();
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
        c.register(rid(1), target(5)).unwrap();
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
        c.register(rid(1), target(5)).unwrap();
        assert_eq!(
            c.register(rid(1), target(6)),
            Err(SyncCorrelateError::Duplicate)
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c.resolve(rid(1)).unwrap().height, 5, "原 target 保留");
    }

    // full ⇒ deterministic reject（无 eviction + retry）
    #[test]
    fn full_rejects_deterministically() {
        let mut c = SyncRequestCorrelator::new(1);
        c.register(rid(1), target(5)).unwrap();
        assert_eq!(c.register(rid(2), target(6)), Err(SyncCorrelateError::Full));
        assert!(c.contains(&rid(1)));
    }

    // capacity = 0 ⇒ 任何 register Full（不 panic）
    #[test]
    fn zero_capacity_always_full() {
        let mut c = SyncRequestCorrelator::new(0);
        assert_eq!(c.register(rid(1), target(5)), Err(SyncCorrelateError::Full));
        assert_eq!(c.resolve(rid(1)), Err(SyncCorrelateError::Unknown));
    }
}
