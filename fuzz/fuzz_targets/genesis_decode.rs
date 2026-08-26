//! Fuzz target：`genesis_decode`（STEP 6B）。
//!
//! 任意 bytes → `decode_genesis_bytes`。
//!
//! 要求（用户 §21）：no panic / no OOM / bounded allocation / deterministic。
//! - decode 内部长度预检（`take` → `DecodeError`），集合超限 → `CollectionTooLarge`（无大分配）。
//! - 成功解码 → 重新 canonical 编码 → 再解码稳定（deterministic debug_assert）。

#![no_main]

use libfuzzer_sys::fuzz_target;
use nova_crypto::identity::{canonical_genesis_bytes, decode_genesis_bytes};

fuzz_target!(|data: &[u8]| {
    let Ok(genesis) = decode_genesis_bytes(data) else {
        return;
    };
    // decode 成功：canonical 编码 → 再解码稳定（deterministic、no panic）。
    if let Ok(bytes) = canonical_genesis_bytes(&genesis) {
        debug_assert!(decode_genesis_bytes(&bytes).is_ok());
    }
});
