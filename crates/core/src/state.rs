//! Nova Chain 账户状态与交易结果协议类型（STEP 7G — State Transition）。
//!
//! 严格依据冻结规范：**ADR-0017/0018**（AccountState、EMPTY_CODE_HASH）、**ADR-0023**
//! （G1 / G4 / G-I / G-J）。
//!
//! # 边界
//! - 本模块只定义**协议数据结构**（`AccountState` / `AccountChange` / `TransactionReceipt` /
//!   `StateTransition`）；**不实现**任何执行逻辑（`nova-execution`）。
//! - `EMPTY_STORAGE_ROOT` 数值 **DEFERRED TO STEP 8**（禁止提前定义）。
//! - [`EMPTY_CODE_HASH`] = `SHA-256(empty)`（ADR-0017 §3 冻结；本模块落实常量）。
//! - [`StateTransition::changes`] 顺序固定：sender → receiver（ADR-0023 G-J 确定性）。
//! - `StateTransition` **不含 events**（V0.1 无事件机制；Event API 留 WASM Phase）。

use nova_crypto::address::NovaAddress;

/// 空代码哈希：`SHA-256(empty bytes)`（ADR-0017 §3 冻结）。
///
/// User Account（`0x01`）默认 `code_hash = EMPTY_CODE_HASH`；Contract（`0x02` Reserved）
/// 由 PHASE 12 定义。
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// 账户状态（ADR-0017 §2；协议数据结构；**不包含** address / account_type）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    /// User Account = [`EMPTY_CODE_HASH`]。
    pub code_hash: [u8; 32],
    /// V0.1 = `EMPTY_STORAGE_ROOT`（**数值 DEFERRED TO STEP 8**）。
    pub storage_root: [u8; 32],
}

/// 单个账户的确定性变更（成功交易产生；供 STEP 8 trie 化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountChange {
    pub address: NovaAddress,
    pub new_balance: u128,
    pub new_nonce: u64,
    /// 隐式创建（ADR-0017 §3：positive value + valid execution）。
    pub created: bool,
}

/// 交易状态（V0.1 仅 Success；失败无 on-chain receipt，ADR-0023 G-B）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Success,
}

/// 交易收据（ADR-0023 G4；执行后派生数据，**不进入** signature / txid coverage）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReceipt {
    /// txid（7C：`SHA-256(canonical_tx_payload ‖ signature)`）。
    pub tx_hash: [u8; 32],
    pub status: TxStatus,
    /// 成功 = `TRANSFER_INTRINSIC_GAS`。
    pub gas_used: u64,
    /// 成功 = actual_fee。
    pub fee_paid: u128,
    /// 成功 = `compute_burn(actual_fee, fee_burn_bps)`。
    pub burned_fee: u128,
}

/// 状态转换结果（ADR-0023 G1）。
///
/// - [`changes`](StateTransition::changes)：确定性 AccountChange 列表（**顺序 sender → receiver**，G-J；
///   self-transfer 仅 sender）。
/// - 原子性（G-I）：本类型只承载成功路径变更；失败不产生 StateTransition。
/// - [`gas_used`](StateTransition::gas_used)：供区块级 `max_gas_per_block` 聚合（G6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    pub changes: Vec<AccountChange>,
    pub receipt: TransactionReceipt,
    pub gas_used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_code_hash_matches_sha256_empty() {
        // 落实 ADR-0017 §3：EMPTY_CODE_HASH = SHA-256(empty)
        assert_eq!(EMPTY_CODE_HASH, nova_crypto::hash::protocol_hash(&[]));
    }

    #[test]
    fn empty_code_hash_is_known_constant() {
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(EMPTY_CODE_HASH, expected);
    }
}
