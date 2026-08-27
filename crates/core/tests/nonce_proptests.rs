//! STEP 7E Property Tests（proptest）：Nonce 分类与递增边界（ADR-0021）。
//!
//! 覆盖：`classify_nonce` 逆否性质（Current ⇔ tx==acc；Future(gap) ⇒ gap==tx-acc；TooLow ⇔ tx<acc）、
//! `checked_next_nonce` exhaustion 边界（u64::MAX ⇒ Exhausted）。

use nova_core::transaction::nonce::{NonceClass, NonceError, checked_next_nonce, classify_nonce};
use proptest::prelude::*;

proptest! {
    // classify_nonce 是确定性纯函数：三种分类互斥且完备
    #[test]
    fn classify_nonce_invariants(tx in any::<u64>(), acc in any::<u64>()) {
        let cls = classify_nonce(tx, acc);
        // Current ⇔ tx == acc
        prop_assert_eq!(matches!(cls, NonceClass::Current), tx == acc);
        // TooLow ⇔ tx < acc
        prop_assert_eq!(matches!(cls, NonceClass::TooLow), tx < acc);
        // Future(gap) ⇒ tx > acc 且 gap == tx - acc
        if let NonceClass::Future(gap) = cls {
            prop_assert!(tx > acc);
            prop_assert_eq!(gap, tx - acc);
        }
    }

    // checked_next_nonce：u64::MAX ⇒ Exhausted；其余 ⇒ Ok(nonce+1)
    #[test]
    fn checked_next_nonce_boundary(acc in any::<u64>()) {
        if acc == u64::MAX {
            prop_assert_eq!(checked_next_nonce(acc), Err(NonceError::Exhausted));
        } else {
            prop_assert_eq!(checked_next_nonce(acc), Ok(acc + 1));
        }
    }
}
