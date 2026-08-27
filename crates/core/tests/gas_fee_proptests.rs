//! STEP 7F Property Tests（proptest）：Gas / Fee Accounting（ADR-0022）。
//!
//! 覆盖：`actual_fee <= fee_max`（当 gas_used <= gas_limit）、`burn <= actual_fee`（bps <= 10_000）、
//! `required >= amount` 且 `required >= fee_max`、overflow 逆否（checked 数学一致）。

use nova_core::transaction::gas_fee::{
    GasFeeError, check_balance_sufficient, compute_actual_fee, compute_burn, compute_fee_max,
    compute_required,
};
use proptest::prelude::*;

proptest! {
    // F5：gas_used <= gas_limit 且 fee_max 不溢出 ⇒ actual_fee <= fee_max
    #[test]
    fn actual_fee_le_fee_max(
        gas_limit in any::<u64>(),
        gas_price in any::<u128>(),
        gas_used in any::<u64>(),
    ) {
        if let Ok(fee_max) = compute_fee_max(gas_limit, gas_price)
            && gas_used <= gas_limit
        {
            let actual = compute_actual_fee(gas_used, gas_price).unwrap();
            prop_assert!(actual <= fee_max, "actual_fee must not exceed fee_max");
        }
    }

    // F7：bps <= 10_000 ⇒ burn <= actual_fee；且 burn = actual_fee*bps/10000
    #[test]
    fn burn_le_actual_fee(
        actual_fee in any::<u128>(),
        fee_burn_bps in 0u16..=10_000u16,
    ) {
        match compute_burn(actual_fee, fee_burn_bps) {
            Ok(burn) => {
                prop_assert!(burn <= actual_fee, "burn must not exceed actual_fee");
                prop_assert_eq!(
                    burn,
                    actual_fee * (fee_burn_bps as u128) / 10_000,
                    "integer division floor"
                );
            }
            Err(GasFeeError::BurnOverflow) => {
                // 溢出 ⇔ checked_mul 溢出（逆否）
                prop_assert!(actual_fee.checked_mul(fee_burn_bps as u128).is_none());
            }
            Err(other) => prop_assert!(false, "unexpected error: {other:?}"),
        }
    }

    // F2：required 不溢出 ⇒ required >= amount 且 required >= fee_max
    #[test]
    fn required_dominates(amount in any::<u128>(), fee_max in any::<u128>()) {
        if let Ok(required) = compute_required(amount, fee_max) {
            prop_assert!(required >= amount, "required >= amount");
            prop_assert!(required >= fee_max, "required >= fee_max");
            // balance == required ⇒ sufficient（F3 边界）
            prop_assert!(check_balance_sufficient(required, required).is_ok());
        }
    }

    // overflow 逆否：compute_fee_max 成功 ⇔ 数学 checked_mul 不溢出
    #[test]
    fn fee_max_overflow_iff_math(gas_limit in any::<u64>(), gas_price in any::<u128>()) {
        let expect_ok = (gas_limit as u128).checked_mul(gas_price).is_some();
        prop_assert_eq!(
            compute_fee_max(gas_limit, gas_price).is_ok(),
            expect_ok,
            "compute_fee_max must agree with checked arithmetic"
        );
    }
}
