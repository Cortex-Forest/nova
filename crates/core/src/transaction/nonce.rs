//! Nova Chain 交易 Nonce 规则（STEP 7E — Nonce / Replay Protection）。
//!
//! 严格依据冻结规范：**ADR-0021** §1–§3（N1/N7/N8/N9/N15）。
//!
//! # 边界（ADR-0021）
//! - [`classify_nonce`] 是 **Consensus 中立纯函数**：不接收 `MAX_FUTURE_NONCE_GAP` /
//!   `current_height` / `balance` / `gas` / `mempool` / `policy` 任何参数（防 policy 渗入）。
//! - `Future(gap)` 本身不含阈值；gap 是否可接受由 **Mempool Policy** 层判断（本地，非 consensus）。
//! - [`checked_next_nonce`]：成功路径 nonce 递增边界（N15）；**禁止** wrapping / unwrap。
//! - **不实现**：fee / gas / balance sufficiency / state transition / revert（7F/7G）。
//! - invalid 交易（含 TooLow / Exhausted 边界）⇒ **nonce 不变**（ADR-0017 D7 / ADR-0021 N8）。

use core::cmp::Ordering;
use core::fmt;

/// Nonce 分类（ADR-0021 §1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceClass {
    /// `tx_nonce == account_nonce`：可执行。
    Current,
    /// `tx_nonce > account_nonce`：future；`gap = tx_nonce - account_nonce`
    /// （阈值由 Mempool Policy 判断，本分类不含阈值）。
    Future(u64),
    /// `tx_nonce < account_nonce`：已使用/重放 ⇒ consensus Invalid。
    TooLow,
}

/// 分类 nonce（Consensus 中立纯函数）。
///
/// - 执行前提 = `Current`；否则 Invalid（N1）。
/// - `TooLow` ⇒ consensus Invalid（N7）。
/// - `Future(gap)` 仅供 Mempool Policy 层判断是否暂存（N2/N3）；本函数不持有阈值。
pub fn classify_nonce(tx_nonce: u64, account_nonce: u64) -> NonceClass {
    match tx_nonce.cmp(&account_nonce) {
        Ordering::Less => NonceClass::TooLow,
        Ordering::Equal => NonceClass::Current,
        Ordering::Greater => NonceClass::Future(tx_nonce - account_nonce),
    }
}

/// Nonce 错误（ADR-0021 §3；7E 底层分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// `account.nonce == u64::MAX`：不存在合法下一 nonce（N15）。
    Exhausted,
}

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => write!(f, "nonce exhausted (u64::MAX)"),
        }
    }
}

impl std::error::Error for NonceError {}

/// 成功执行路径的 nonce 递增（N15；7G 应用）。
///
/// - `< u64::MAX` ⇒ `Ok(account_nonce + 1)`
/// - `== u64::MAX` ⇒ `Err(Exhausted)`（不存在合法下一 nonce，交易不能成功完成）
///
/// **禁止** `wrapping_add`（静默回绕）与 `checked_add(...).unwrap()`（panic/掩盖）。
pub fn checked_next_nonce(account_nonce: u64) -> Result<u64, NonceError> {
    account_nonce.checked_add(1).ok_or(NonceError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_equal_is_current() {
        assert_eq!(classify_nonce(5, 5), NonceClass::Current);
        assert_eq!(classify_nonce(0, 0), NonceClass::Current);
        assert_eq!(classify_nonce(u64::MAX, u64::MAX), NonceClass::Current);
    }

    #[test]
    fn classify_future_returns_gap() {
        assert_eq!(classify_nonce(6, 5), NonceClass::Future(1));
        assert_eq!(classify_nonce(5, 0), NonceClass::Future(5));
        assert_eq!(classify_nonce(64, 0), NonceClass::Future(64));
        assert_eq!(classify_nonce(65, 0), NonceClass::Future(65));
        assert_eq!(classify_nonce(u64::MAX, 0), NonceClass::Future(u64::MAX));
    }

    #[test]
    fn classify_too_low() {
        assert_eq!(classify_nonce(4, 5), NonceClass::TooLow);
        assert_eq!(classify_nonce(0, 1), NonceClass::TooLow);
        assert_eq!(classify_nonce(9, u64::MAX), NonceClass::TooLow);
    }

    #[test]
    fn checked_next_nonce_increments() {
        assert_eq!(checked_next_nonce(0), Ok(1));
        assert_eq!(checked_next_nonce(5), Ok(6));
        assert_eq!(checked_next_nonce(u64::MAX - 1), Ok(u64::MAX));
    }

    #[test]
    fn checked_next_nonce_exhausted_at_max() {
        assert_eq!(checked_next_nonce(u64::MAX), Err(NonceError::Exhausted));
    }

    #[test]
    fn exhausted_error_display() {
        assert_eq!(
            NonceError::Exhausted.to_string(),
            "nonce exhausted (u64::MAX)"
        );
    }
}
