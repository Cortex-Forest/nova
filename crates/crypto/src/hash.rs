//! Nova Chain 哈希（STEP 2 — Hash Infrastructure）。
//!
//! # 冻结 API（ADR-0006 / crypto-serialization-v1.md）
//! - [`protocol_hash`]：SHA-256，**只能用于 ADR-0006 Protocol Hash Registry 注册的共识协议位置**
//!   （地址 key_hash、交易/区块/Merkle/状态承诺、签名消息 `SHA-256(signed_bytes)`、genesis_hash）。
//!   本模块**不公开**"通用 SHA-256 wrapper"——语义由函数名与模块文档约束（ADR-0013 §5）。
//! - [`content_hash`]：BLAKE3，链下内容哈希（大文件：音乐/视频/AI 模型，Master Prompt §34）。
//!   **不得进入** transaction/block hash、state root、validator vote、finality proof
//!   （除非未来 ADR 明确批准）。
//!
//! # 实现纪律（Master Prompt §16）
//! 使用成熟密码库（`sha2` / `blake3`），**禁止自研哈希**。

use sha2::{Digest, Sha256};

/// 协议哈希：`SHA-256(data)`，输出 32 字节。
///
/// 只用于 ADR-0006 Protocol Hash Registry 注册的协议位置。
pub fn protocol_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// 内容哈希：`BLAKE3(data)`，输出 32 字节。
///
/// 链下内容哈希；**不得进入共识承诺**（transaction/block hash、state root、
/// validator vote、finality proof），除非未来 ADR 批准。
pub fn content_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析 64 位小写 hex 为 32 字节（测试辅助；严格校验）。
    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "hex32 requires 64 hex chars");
        let bytes = s.as_bytes();
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            let hi = nibble(bytes[i * 2]);
            let lo = nibble(bytes[i * 2 + 1]);
            *b = (hi << 4) | lo;
        }
        out
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex in test helper"),
        }
    }

    // ------------------------------------------------------------------
    // Known vectors（交付要求 3）：标准测试向量
    // ------------------------------------------------------------------
    #[test]
    fn protocol_hash_known_vectors() {
        // NIST/SHA-256 标准向量
        assert_eq!(
            protocol_hash(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            protocol_hash(b"abc"),
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn content_hash_known_vectors() {
        // BLAKE3 官方测试向量
        assert_eq!(
            content_hash(b""),
            hex32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
        assert_eq!(
            content_hash(b"abc"),
            hex32("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        );
    }

    // ------------------------------------------------------------------
    // Empty input（交付要求 4）
    // ------------------------------------------------------------------
    #[test]
    fn empty_input_hashes_match_library() {
        // 与底层库直接计算一致（额外一致性校验）
        let mut sha = Sha256::new();
        sha.update(b"");
        let d: [u8; 32] = sha.finalize().into();
        assert_eq!(protocol_hash(b""), d);

        let b3 = blake3::hash(b"");
        assert_eq!(content_hash(b""), *b3.as_bytes());
    }

    // ------------------------------------------------------------------
    // Large input（交付要求 5）
    // ------------------------------------------------------------------
    #[test]
    fn large_input_hashes_match_library() {
        // 1 MiB 固定模式数据
        let data: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();

        let mut sha = Sha256::new();
        sha.update(&data);
        let d: [u8; 32] = sha.finalize().into();
        assert_eq!(protocol_hash(&data), d);

        let b3 = blake3::hash(&data);
        assert_eq!(content_hash(&data), *b3.as_bytes());
    }

    // ------------------------------------------------------------------
    // Deterministic（交付要求 6）
    // ------------------------------------------------------------------
    #[test]
    fn hashes_are_deterministic() {
        let data = b"nova chain deterministic test";
        assert_eq!(protocol_hash(data), protocol_hash(data));
        assert_eq!(content_hash(data), content_hash(data));

        // 不同输入必须不同
        assert_ne!(protocol_hash(b"a"), protocol_hash(b"b"));
        assert_ne!(content_hash(b"a"), content_hash(b"b"));
    }
}
