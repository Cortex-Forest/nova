#![no_main]
//! Fuzz target: `signature_decode`
//!
//! 喂任意字节给签名/公钥解析，必须**安全失败**（不 panic、不 UB、不无限耗时、
//! 对恶意输入返回错误而非崩溃）。要求：malformed/truncated/oversized ⇒ 拒绝。
//!
//! 运行（需 nightly，方案 B）：
//! ```bash
//! cd fuzz && cargo +nightly fuzz run signature_decode
//! ```

use libfuzzer_sys::fuzz_target;
use nova_crypto::signature::{Signature, VerifyingKey};

fuzz_target!(|data: &[u8]| {
    // 任意长度/内容的字节必须被安全解析或拒绝
    let _ = Signature::from_bytes(data);
    let _ = VerifyingKey::from_bytes(data);
});
