//! 区块级执行结果（STEP 8D — ADR-0029 D-1）。
//!
//! - [`BlockExecutionResult`]：`execute_block`（nova-execution）的产物；**不含** final state root
//!   （由 nova-storage `apply_block` 计算——execution 无 SMT，ADR-0029 D-1/D-2 边界）。
//! - **不冻结** 完整 BlockHeader / block_hash / receipt root（PHASE 7，ADR-0009）。

use crate::state::StateTransition;

/// 区块执行结果（ADR-0029 D-1；协议类型）。
///
/// - `tx_transitions` 只含**成功** tx（失败 tx 被 skip，ADR-0029 D-3 Model A），顺序 = block 内顺序。
/// - `gas_used_total` = 成功 tx 的 `StateTransition::gas_used` 累计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionResult {
    /// 成功 tx 的状态转换（顺序 = block 内顺序）。
    pub tx_transitions: Vec<StateTransition>,
    /// 全部成功 tx 累计 gas。
    pub gas_used_total: u64,
}
