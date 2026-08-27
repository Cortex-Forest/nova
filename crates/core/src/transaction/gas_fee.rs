//! Nova Chain 交易 Gas / Fee Accounting（STEP 7F）。
//!
//! 严格依据冻结规范：**ADR-0019 §8/§9**、**ADR-0022**（F1–F10）、ADR-0014（`fee_burn_bps`）、
//! ADR-0016 §4（供应上限 / burned 累计）。
//!
//! # 边界（ADR-0022）
//! - 只做**纯计算**：`fee_max` / `required` / `actual_fee` / `burn` / balance sufficiency /
//!   gas 参数校验。
//! - **不实现**：state transition / 扣费落账 / nonce 写入 / revert（7G）。
//! - 所有运算 **checked**；禁 panic / 回绕 / silent saturation（F9）。
//! - [`TRANSFER_INTRINSIC_GAS`] 是 **core 常量**（V0.1 Transfer 无 WASM，`gas_used = intrinsic`）；
//!   **非 genesis 字段**（不改 genesis hash，F4）。
//! - fee burn 不改变 `total_supply`（cap 语义）；`burned_supply` 落账由 7G state 承载（F7）。
//! - min gas price 为 Mempool 本地 Policy，**无共识 min gas price**；`max_gas_per_block` 归
//!   7G/Block STEP 应用（F10）。

use core::fmt;

/// V0.1 Transfer 固有 gas（F4；core 常量，**非 genesis 字段**）。
///
/// V0.1 Transfer 无 WASM 执行，`gas_used = TRANSFER_INTRINSIC_GAS`（与 payload 无关，payload 恒空）。
/// 数值 `21_000`（对齐 EVM 生态惯例）。未来交易类型 / WASM 引入时经新 ADR。
pub const TRANSFER_INTRINSIC_GAS: u64 = 21_000;

/// Gas / Fee 错误（ADR-0022 §9；7F 底层分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasFeeError {
    /// `checked_mul(gas_limit, gas_price)` 溢出（F1）。
    FeeMaxOverflow,
    /// `checked_add(amount, fee_max)` 溢出（F2）。
    RequiredOverflow,
    /// `checked_mul(gas_used, gas_price)` 溢出（F5，防御）。
    ActualFeeOverflow,
    /// burn 计算溢出（F7）。
    BurnOverflow,
    /// `balance < required`（F3）。
    InsufficientBalance,
    /// `gas_limit == 0` 或 `gas_price == 0`（F10）。
    InvalidGasParams,
    /// `gas_used > gas_limit`（F5）。
    GasExceedsLimit,
}

impl fmt::Display for GasFeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeeMaxOverflow => write!(f, "fee_max overflow (gas_limit * gas_price)"),
            Self::RequiredOverflow => write!(f, "required overflow (amount + fee_max)"),
            Self::ActualFeeOverflow => write!(f, "actual_fee overflow (gas_used * gas_price)"),
            Self::BurnOverflow => write!(f, "burn overflow (actual_fee * fee_burn_bps)"),
            Self::InsufficientBalance => write!(f, "insufficient balance (balance < required)"),
            Self::InvalidGasParams => write!(f, "invalid gas params (gas_limit or gas_price = 0)"),
            Self::GasExceedsLimit => write!(f, "gas_used exceeds gas_limit"),
        }
    }
}

impl std::error::Error for GasFeeError {}

/// F1 — `fee_max = gas_limit * gas_price`（checked；溢出 ⇒ `FeeMaxOverflow`）。
///
/// ADR-0019 §8：溢出 ⇒ Reject。禁 wrap / panic。
pub fn compute_fee_max(gas_limit: u64, gas_price: u128) -> Result<u128, GasFeeError> {
    (gas_limit as u128)
        .checked_mul(gas_price)
        .ok_or(GasFeeError::FeeMaxOverflow)
}

/// F2 — `required = amount + fee_max`（checked；溢出 ⇒ `RequiredOverflow`）。
///
/// ADR-0019 §8：溢出 ⇒ Reject。
pub fn compute_required(amount: u128, fee_max: u128) -> Result<u128, GasFeeError> {
    amount
        .checked_add(fee_max)
        .ok_or(GasFeeError::RequiredOverflow)
}

/// F3 — balance sufficiency（`balance >= required` 否则 `InsufficientBalance`）。
///
/// 纯判断（不扣款）；7G 执行时用真实 state 调用。Mempool 预检只是快照，
/// **Admission snapshot 不是最终执行保证**（ADR-0019 §15）。
pub fn check_balance_sufficient(balance: u128, required: u128) -> Result<(), GasFeeError> {
    if balance >= required {
        Ok(())
    } else {
        Err(GasFeeError::InsufficientBalance)
    }
}

/// F10 — gas 参数协议约束：`gas_limit > 0` 且 `gas_price > 0`（否则 `InvalidGasParams`）。
///
/// ADR-0019 §8 / ADR-0022 F10（Consensus 字段约束）。
pub fn check_gas_params(gas_limit: u64, gas_price: u128) -> Result<(), GasFeeError> {
    if gas_limit == 0 || gas_price == 0 {
        return Err(GasFeeError::InvalidGasParams);
    }
    Ok(())
}

/// F5 — `gas_used <= gas_limit` 必须（否则 `GasExceedsLimit`）。
///
/// ADR-0019 §9。
pub fn check_gas_used(gas_used: u64, gas_limit: u64) -> Result<(), GasFeeError> {
    if gas_used > gas_limit {
        return Err(GasFeeError::GasExceedsLimit);
    }
    Ok(())
}

/// F5 — `actual_fee = gas_used * gas_price`（checked；防御溢出 ⇒ `ActualFeeOverflow`）。
///
/// 因 `gas_used <= gas_limit` 且 `fee_max` 不溢出，故不溢出；仍 checked 防御。ADR-0019 §9。
pub fn compute_actual_fee(gas_used: u64, gas_price: u128) -> Result<u128, GasFeeError> {
    (gas_used as u128)
        .checked_mul(gas_price)
        .ok_or(GasFeeError::ActualFeeOverflow)
}

/// F7 — `burn = actual_fee * fee_burn_bps / 10_000`（整数除法向下取整；checked）。
///
/// - 前置：`fee_burn_bps <= 10_000`（Genesis 已保证）；`burn <= actual_fee`。
/// - `total_supply` 为供应上限（cap），不因 burn 递减（ADR-0016 §4 修订）；`burned_supply`
///   落账由 7G state 承载。
pub fn compute_burn(actual_fee: u128, fee_burn_bps: u16) -> Result<u128, GasFeeError> {
    let numerator = actual_fee
        .checked_mul(fee_burn_bps as u128)
        .ok_or(GasFeeError::BurnOverflow)?;
    Ok(numerator / 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- F1 fee_max ----
    #[test]
    fn fee_max_normal() {
        assert_eq!(compute_fee_max(21_000, 100), Ok(2_100_000));
        assert_eq!(compute_fee_max(0, 100), Ok(0));
    }

    #[test]
    fn fee_max_overflow_rejected() {
        // gas_limit=u64::MAX, gas_price=u128::MAX ⇒ 溢出
        assert_eq!(
            compute_fee_max(u64::MAX, u128::MAX),
            Err(GasFeeError::FeeMaxOverflow)
        );
        // gas_price=0 时结果 0（不溢出；但 F10 会拒 0 price）
        assert_eq!(compute_fee_max(u64::MAX, 0), Ok(0));
    }

    // ---- F2 required ----
    #[test]
    fn required_normal() {
        assert_eq!(compute_required(1_000_000, 2_100_000), Ok(3_100_000));
        assert_eq!(compute_required(0, 0), Ok(0));
    }

    #[test]
    fn required_overflow_rejected() {
        assert_eq!(
            compute_required(u128::MAX, 1),
            Err(GasFeeError::RequiredOverflow)
        );
    }

    // ---- F3 balance sufficiency ----
    #[test]
    fn balance_sufficient_boundary() {
        assert_eq!(check_balance_sufficient(3_100_000, 3_100_000), Ok(()));
        assert_eq!(check_balance_sufficient(3_100_001, 3_100_000), Ok(()));
        assert_eq!(
            check_balance_sufficient(3_099_999, 3_100_000),
            Err(GasFeeError::InsufficientBalance)
        );
        assert_eq!(
            check_balance_sufficient(0, 1),
            Err(GasFeeError::InsufficientBalance)
        );
    }

    // ---- F10 gas params ----
    #[test]
    fn gas_params_positive() {
        assert_eq!(check_gas_params(21_000, 100), Ok(()));
        assert_eq!(check_gas_params(1, 1), Ok(()));
        assert_eq!(check_gas_params(0, 100), Err(GasFeeError::InvalidGasParams));
        assert_eq!(
            check_gas_params(21_000, 0),
            Err(GasFeeError::InvalidGasParams)
        );
        assert_eq!(check_gas_params(0, 0), Err(GasFeeError::InvalidGasParams));
    }

    // ---- F5 gas_used ----
    #[test]
    fn gas_used_within_limit() {
        assert_eq!(check_gas_used(21_000, 21_000), Ok(()));
        assert_eq!(check_gas_used(20_999, 21_000), Ok(()));
        assert_eq!(
            check_gas_used(21_001, 21_000),
            Err(GasFeeError::GasExceedsLimit)
        );
        assert_eq!(check_gas_used(1, 0), Err(GasFeeError::GasExceedsLimit));
    }

    // ---- F5 actual_fee ----
    #[test]
    fn actual_fee_normal_and_overflow() {
        assert_eq!(compute_actual_fee(21_000, 100), Ok(2_100_000));
        assert_eq!(compute_actual_fee(0, 100), Ok(0));
        assert_eq!(
            compute_actual_fee(u64::MAX, u128::MAX),
            Err(GasFeeError::ActualFeeOverflow)
        );
    }

    // ---- F7 burn ----
    #[test]
    fn burn_normal() {
        // actual_fee=2_100_000, bps=1000 (10%) ⇒ 210_000
        assert_eq!(compute_burn(2_100_000, 1_000), Ok(210_000));
        // bps=0 ⇒ 0
        assert_eq!(compute_burn(2_100_000, 0), Ok(0));
        // bps=10_000 (100%) ⇒ 全部
        assert_eq!(compute_burn(2_100_000, 10_000), Ok(2_100_000));
        // 向下取整：actual_fee=999, bps=10_000 ⇒ 999
        assert_eq!(compute_burn(999, 10_000), Ok(999));
        // actual_fee=999, bps=1000 ⇒ 99
        assert_eq!(compute_burn(999, 1_000), Ok(99));
    }

    #[test]
    fn burn_never_exceeds_fee_for_valid_bps() {
        // bps <= 10_000 ⇒ burn <= actual_fee（含边界）
        for bps in [0u16, 1, 500, 9_999, 10_000] {
            let burn = compute_burn(2_100_000, bps).unwrap();
            assert!(burn <= 2_100_000, "burn must not exceed actual_fee");
        }
    }

    #[test]
    fn intrinsic_gas_constant() {
        assert_eq!(TRANSFER_INTRINSIC_GAS, 21_000);
    }
}
