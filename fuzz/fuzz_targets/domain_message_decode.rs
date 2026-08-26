#![no_main]
//! Fuzz target: `domain_message_decode`
//!
//! 喂任意字节作为 payload / chain_id，构造 `signed_bytes` 与 `SigningMessageHash`。
//! 必须**安全失败**（不 panic、不无限、无未定义状态）。
//!
//! 运行（需 nightly，方案 B）：
//! ```bash
//! cd fuzz && cargo +nightly fuzz run domain_message_decode
//! ```

use libfuzzer_sys::fuzz_target;
use nova_crypto::domain::{build_signed_bytes, hash_signing_message, AlgorithmId, DomainId};

fuzz_target!(|data: &[u8]| {
    // 前 8 字节作为 chain_id（LE），其余作为 payload
    let chain_bytes: [u8; 8] = data.get(..8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        a
    }).unwrap_or([0u8; 8]);
    let chain_id = u64::from_le_bytes(chain_bytes);
    let payload = data.get(8..).unwrap_or(&[]);

    if let Ok(sb) = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, chain_id, payload) {
        let _h = hash_signing_message(&sb);
    }
    // 未知 domain/algorithm 必须被拒绝（禁 fallback）
    let _ = DomainId::try_from(data.first().copied().unwrap_or(0x00));
    let _ = AlgorithmId::try_from(data.get(1).copied().unwrap_or(0x00));
});
