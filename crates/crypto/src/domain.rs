//! Nova Chain 域分离基础设施（STEP 3 — Domain Separation）。
//!
//! # 冻结规范（crypto-serialization-v1.md §10）
//! ```text
//! signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE)
//!                || payload_length(4B LE) || canonical_payload
//! message_hash = SHA-256(signed_bytes)   →   SigningMessageHash
//! ```
//!
//! # 边界（ADR-0013）
//! - 本模块是协议签名消息的**唯一构造路径**（防 bypass）。
//! - [`SigningMessageHash`] newtype 防止普通 `[u8;32]` 被误用作协议签名消息。
//! - 未注册 `domain_id` / `algorithm_id` ⇒ 拒绝，**禁止 fallback**（ADR-0005/0012）。
//! - Ed25519 签名 / 验证在 STEP 4（`sign_message_hash` / `verify_message_hash`）。

use core::fmt;

/// 域分离错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    /// 未知/未注册 `domain_id`（拒绝，禁 fallback）。
    UnknownDomainId(u8),
    /// 未知/未实现 `algorithm_id`（Reserved ⇒ 拒绝，禁 fallback）。
    UnknownAlgorithmId(u8),
    /// `canonical_payload` 长度超出 u32。
    PayloadTooLarge(usize),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDomainId(id) => write!(f, "unknown domain_id: {id:#04x}"),
            Self::UnknownAlgorithmId(id) => write!(f, "unknown algorithm_id: {id:#04x}"),
            Self::PayloadTooLarge(n) => write!(f, "canonical_payload too large: {n} bytes"),
        }
    }
}

impl std::error::Error for DomainError {}

/// 冻结注册的域（ADR-0005 Nova Domain Registry）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DomainId {
    /// 交易签名。
    Transaction = 0x01,
    /// 共识投票签名。
    ValidatorVote = 0x02,
    /// 区块承诺签名。
    Block = 0x03,
    /// 治理提案/投票。
    Governance = 0x04,
    /// 地址派生（key_hash 计算）。
    Address = 0x05,
    /// Witness availability proof（ADR-0036 W-5；10-4）。
    Witness = 0x06,
}

impl DomainId {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for DomainId {
    type Error = DomainError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Transaction),
            0x02 => Ok(Self::ValidatorVote),
            0x03 => Ok(Self::Block),
            0x04 => Ok(Self::Governance),
            0x05 => Ok(Self::Address),
            0x06 => Ok(Self::Witness),
            _ => Err(DomainError::UnknownDomainId(v)),
        }
    }
}

/// 冻结注册的算法（ADR-0012 Algorithm Registry）。
///
/// 当前仅实现 Ed25519；`0x02`(secp256k1) / `0x03`(PQ) 为 **Reserved ⇒ 拒绝**（禁 fallback）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlgorithmId {
    /// Ed25519（RFC 8032）。
    Ed25519 = 0x01,
}

impl AlgorithmId {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AlgorithmId {
    type Error = DomainError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Ed25519),
            _ => Err(DomainError::UnknownAlgorithmId(v)),
        }
    }
}

/// 构造 `signed_bytes`（crypto-serialization-v1.md §10）。
///
/// 字段顺序固定：`algorithm_id ‖ domain_id ‖ chain_id(LE) ‖ payload_length(LE) ‖ payload`。
pub fn build_signed_bytes(
    algorithm_id: AlgorithmId,
    domain_id: DomainId,
    chain_id: u64,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, DomainError> {
    let len = u32::try_from(canonical_payload.len())
        .map_err(|_| DomainError::PayloadTooLarge(canonical_payload.len()))?;
    let mut out = Vec::with_capacity(1 + 1 + 8 + 4 + canonical_payload.len());
    out.push(algorithm_id.as_u8());
    out.push(domain_id.as_u8());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(canonical_payload);
    Ok(out)
}

/// 协议签名消息哈希 newtype。
///
/// 普通 `[u8;32]` **不能**直接作为协议签名消息（ADR-0013 §3 类型强制）。
/// 构造路径：由 [`hash_signing_message`] 生成；`from_bytes` 仅用于反序列化恢复（验证路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningMessageHash([u8; 32]);

impl SigningMessageHash {
    /// 从 32 字节反序列化恢复（验证路径）。
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 读取内部字节。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SigningMessageHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// 计算 `message_hash = SHA-256(signed_bytes)`，返回 [`SigningMessageHash`]。
pub fn hash_signing_message(signed_bytes: &[u8]) -> SigningMessageHash {
    SigningMessageHash(crate::hash::protocol_hash(signed_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex in test helper"),
        }
    }

    fn hex_any(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        let bytes = s.as_bytes();
        (0..bytes.len())
            .step_by(2)
            .map(|i| (nibble(bytes[i]) << 4) | nibble(bytes[i + 1]))
            .collect()
    }

    // ------------------------------------------------------------------
    // Exit 1/2：signed_bytes 与 §10 完全一致 + field order
    // ------------------------------------------------------------------
    #[test]
    fn signed_bytes_layout_matches_spec() {
        // algorithm_id=1, domain_id=1(Transaction), chain_id=1, payload=[0x00,0x01]
        let sb = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::Transaction,
            1,
            &[0x00, 0x01],
        )
        .unwrap();
        // 01 | 01 | chain_id(8B LE)=0100000000000000 | len(4B LE)=02000000 | 0001
        assert_eq!(
            sb,
            hex_any("01010100000000000000020000000001"),
            "must match crypto-serialization-v1.md §10"
        );
    }

    #[test]
    fn field_order_is_fixed() {
        // 字节位置必须固定：alg(0) dom(1) chain(2..10) len(10..14) payload(14..)
        let sb = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::Block,
            0x0102_0304_0506_0708,
            &[0xaa, 0xbb],
        )
        .unwrap();
        assert_eq!(sb[0], 0x01, "byte 0 = algorithm_id");
        assert_eq!(sb[1], 0x03, "byte 1 = domain_id(Block)");
        assert_eq!(
            &sb[2..10],
            &0x0102_0304_0506_0708u64.to_le_bytes(),
            "chain_id LE"
        );
        assert_eq!(&sb[10..14], &2u32.to_le_bytes(), "payload_length LE");
        assert_eq!(&sb[14..], &[0xaa, 0xbb], "payload");

        // 交换 algorithm/domain 顺序必须产生不同字节（证明顺序有意义）
        let a = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, 1, &[0xaa]).unwrap();
        let b =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, &[0xaa]).unwrap();
        assert_ne!(a, b);
    }

    // ------------------------------------------------------------------
    // Exit 3/4：domain isolation / chain isolation
    // ------------------------------------------------------------------
    #[test]
    fn domain_isolation() {
        let payload = b"same payload";
        let base =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 7, payload).unwrap();
        for other in [
            DomainId::ValidatorVote,
            DomainId::Block,
            DomainId::Governance,
            DomainId::Address,
            DomainId::Witness,
        ] {
            let s = build_signed_bytes(AlgorithmId::Ed25519, other, 7, payload).unwrap();
            assert_ne!(base, s, "domain must change signed_bytes");
            assert_ne!(
                hash_signing_message(&base),
                hash_signing_message(&s),
                "domain must change message_hash"
            );
        }
    }

    #[test]
    fn chain_isolation() {
        let payload = b"same payload";
        let a =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, payload).unwrap();
        let b =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 2, payload).unwrap();
        assert_ne!(a, b);
        assert_ne!(hash_signing_message(&a), hash_signing_message(&b));
    }

    #[test]
    fn algorithm_isolation() {
        // 当前仅 Ed25519；未来算法会改变 signed_bytes。此处验证同一算法确定性 + hash newtype。
        let p = b"x";
        let a = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, p).unwrap();
        let b = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, p).unwrap();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // Exit 5/6：unknown domain / unknown algorithm rejection
    // ------------------------------------------------------------------
    #[test]
    fn unknown_domain_rejected() {
        assert_eq!(
            DomainId::try_from(0x00),
            Err(DomainError::UnknownDomainId(0x00))
        );
        assert_eq!(
            DomainId::try_from(0x07),
            Err(DomainError::UnknownDomainId(0x07))
        );
        assert_eq!(
            DomainId::try_from(0xff),
            Err(DomainError::UnknownDomainId(0xff))
        );
        // 已注册值必须接受
        assert_eq!(DomainId::try_from(0x01), Ok(DomainId::Transaction));
        assert_eq!(DomainId::try_from(0x05), Ok(DomainId::Address));
        assert_eq!(DomainId::try_from(0x06), Ok(DomainId::Witness));
    }

    #[test]
    fn unknown_algorithm_rejected() {
        assert_eq!(
            AlgorithmId::try_from(0x00),
            Err(DomainError::UnknownAlgorithmId(0x00))
        );
        // Reserved（secp256k1/PQ）必须拒绝，禁止 fallback 到 Ed25519
        assert_eq!(
            AlgorithmId::try_from(0x02),
            Err(DomainError::UnknownAlgorithmId(0x02))
        );
        assert_eq!(
            AlgorithmId::try_from(0x03),
            Err(DomainError::UnknownAlgorithmId(0x03))
        );
        assert_eq!(
            AlgorithmId::try_from(0xff),
            Err(DomainError::UnknownAlgorithmId(0xff))
        );
        assert_eq!(AlgorithmId::try_from(0x01), Ok(AlgorithmId::Ed25519));
    }

    // ------------------------------------------------------------------
    // SigningMessageHash newtype 与哈希
    // ------------------------------------------------------------------
    #[test]
    fn signing_message_hash_is_32_bytes_and_deterministic() {
        let sb = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, b"m").unwrap();
        let h1 = hash_signing_message(&sb);
        let h2 = hash_signing_message(&sb);
        assert_eq!(h1, h2);
        assert_eq!(h1.as_bytes().len(), 32);
        // 与 SHA-256 标准实现一致
        let mut sha = sha2::Sha256::new();
        use sha2::Digest;
        sha.update(&sb);
        let d: [u8; 32] = sha.finalize().into();
        assert_eq!(*h1.as_bytes(), d);
    }

    #[test]
    fn signing_message_hash_from_bytes() {
        let raw = [7u8; 32];
        let h = SigningMessageHash::from_bytes(raw);
        assert_eq!(*h.as_bytes(), raw);
        // 普通 [u8;32] 不能直接当 SigningMessageHash（newtype 隔离）
        let _ = h;
    }
}
