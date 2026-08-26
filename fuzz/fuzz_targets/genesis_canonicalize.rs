//! Fuzz target：`genesis_canonicalize`（STEP 6A）。
//!
//! 从任意 bytes 构造结构化 `GenesisV1`（共享解析器 `nova_test_vectors::genesis::genesis_from_bytes`，
//! bounded、no-panic），调用 `canonical_genesis_bytes` / `compute_genesis_hash`。
//!
//! 要求（用户 §18）：
//! - **no panic**（解析器返回 `Option`，canonical 调用不 unwrap 失败路径）
//! - **bounded allocation**（条目数由输入限制）
//! - **no infinite loop**（线性解析）
//! - **deterministic result**（相同输入 ⇒ 相同输出，debug_assert 校验）

#![no_main]

use libfuzzer_sys::fuzz_target;
use nova_crypto::identity::{canonical_genesis_bytes, compute_genesis_hash};
use nova_test_vectors::genesis::genesis_from_bytes;

fuzz_target!(|data: &[u8]| {
    let Some(genesis) = genesis_from_bytes(data) else {
        return;
    };
    if let Ok(bytes) = canonical_genesis_bytes(&genesis) {
        let h1 = compute_genesis_hash(&genesis).expect("hash after canonical success");
        let h2 = compute_genesis_hash(&genesis).expect("hash deterministic");
        debug_assert_eq!(h1, h2);
        debug_assert_eq!(canonical_genesis_bytes(&genesis).expect("re-encode"), bytes);
    }
});
