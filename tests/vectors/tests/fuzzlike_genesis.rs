//! STEP 6A：stable fuzz-like 测试（无 nightly 时验证 fuzz 核心逻辑）。
//!
//! 复用 `nova_test_vectors::genesis::genesis_from_bytes`（fuzz 共享解析器，bounded、no-panic），
//! 用确定性伪随机输入验证：
//! - **no panic**：任意长度/内容输入，解析器与 canonical/hash 不 panic。
//! - **deterministic**：相同输入 ⇒ 相同 canonical bytes / hash。
//! - **bounded**：成功解析的 Genesis 条目数 ≤ 8。

use nova_crypto::identity::{canonical_genesis_bytes, compute_genesis_hash};
use nova_test_vectors::genesis::genesis_from_bytes;

/// 确定性 LCG 伪随机字节流。
fn next_lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    *state
}

#[test]
fn genesis_from_bytes_no_panic_and_deterministic() {
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut accepted = 0usize;
    let mut canonical_ok = 0usize;
    for _ in 0..20_000 {
        let len = (next_lcg(&mut state) % 256) as usize;
        let mut data = vec![0u8; len];
        for b in data.iter_mut() {
            *b = (next_lcg(&mut state) >> 32) as u8;
        }

        let g = genesis_from_bytes(&data);
        if let Some(genesis) = g {
            accepted += 1;
            // bounded：条目数 ≤ 8（解析器保证）
            assert!(genesis.initial_validator_set.len() <= 8);
            assert!(genesis.initial_accounts.len() <= 8);
            // canonical/hash：不 panic；成功路径确定
            if let Ok(bytes) = canonical_genesis_bytes(&genesis) {
                canonical_ok += 1;
                let h1 = compute_genesis_hash(&genesis).unwrap();
                let h2 = compute_genesis_hash(&genesis).unwrap();
                assert_eq!(h1, h2, "hash must be deterministic");
                let again = canonical_genesis_bytes(&genesis).unwrap();
                assert_eq!(again, bytes, "canonical bytes must be deterministic");
            }
        }
    }
    // 必须覆盖到"成功解析 + canonical 成功"的路径（否则测试无意义）。
    assert!(accepted > 0, "fuzz-like 输入应至少成功解析若干 Genesis");
    assert!(
        canonical_ok > 0,
        "至少一个解析成功的 Genesis 应通过 canonical 编码"
    );
}
