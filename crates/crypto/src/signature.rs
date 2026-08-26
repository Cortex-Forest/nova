//! Nova Chain Ed25519 签名（STEP 4 — Ed25519 Signature）。
//!
//! # 冻结 API（crypto-serialization-v1.md §10 / ADR-0002 / ADR-0013）
//! - **不允许 arbitrary message signing**：协议签名只接受 [`SigningMessageHash`]
//!   （`nova_crypto::domain`），调用方必须先构造 `signed_bytes` → `hash_signing_message`
//!   → `sign_message_hash`（防 bypass）。
//! - **strict canonical verification**：`verify_message_hash` 使用 `verify_strict`
//!   （拒绝非规范签名、small-order、weak key、malformed 输入）。
//! - Ed25519 实现使用成熟库 `ed25519-dalek`（3.x，`zeroize` feature）；
//!   **禁止自研**（Master Prompt §16）。
//!
//! # 密钥安全（ADR-0007 / 评审 §7）
//! - [`SigningKey`] **不暴露私钥字节**、**不实现 `Clone`**、`Debug` 打码；
//! - `ed25519-dalek` 的 `zeroize` feature ⇒ `SigningKey` 在 Drop 时自动零化 secret。
//! - 详见 [`crate::key`]（密钥材料生命周期）。

use crate::domain::SigningMessageHash;
use core::fmt;

/// 签名错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// 签名/公钥字节长度非法。
    InvalidLength,
    /// 畸形签名（无法解析）。
    MalformedSignature,
    /// 畸形公钥（无法解析 / 非曲线点）。
    MalformedPublicKey,
    /// 签名验证失败（无效签名 / 非规范表示）。
    InvalidSignature,
    /// OS 随机源失败（无 fallback）。
    RngFailure,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid length"),
            Self::MalformedSignature => write!(f, "malformed signature"),
            Self::MalformedPublicKey => write!(f, "malformed public key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::RngFailure => write!(f, "CSPRNG failure (no fallback)"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Ed25519 签名密钥（持有私钥）。
///
/// **安全约束**：不暴露私钥字节；不实现 `Clone`（防复制 secret）；`Debug` 打码；
/// Drop 时经 `ed25519-dalek` `zeroize` feature 自动零化。
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl SigningKey {
    /// 从 32B 种子构建（**仅内部**：密钥生成/安全恢复路径使用，不公开）。
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// 派生的验证密钥（公钥）。
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 绝不暴露私钥
        write!(f, "SigningKey([REDACTED])")
    }
}

/// Ed25519 验证密钥（公钥，非秘密）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    /// 序列化为 32 字节压缩点。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// 从 32 字节解析；畸形/非曲线点 ⇒ 拒绝。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignatureError::MalformedPublicKey)?;
        let inner = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|_| SignatureError::MalformedPublicKey)?;
        Ok(Self { inner })
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", hex_str(&self.to_bytes()))
    }
}

/// Ed25519 签名（64 字节，`R ‖ S`）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// 从字节解析（必须恰为 64 字节）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidLength)?;
        Ok(Self(arr))
    }

    /// 序列化为 64 字节。
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub(crate) fn from_inner(inner: ed25519_dalek::Signature) -> Self {
        Self(inner.to_bytes())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex_str(&self.0))
    }
}

/// 对协议签名消息哈希签名。
///
/// 只接受 [`SigningMessageHash`]（由 `nova_crypto::domain::hash_signing_message` 产生），
/// 防止调用方对任意字节签名（ADR-0013 §3）。
pub fn sign_message_hash(signing: &SigningKey, msg: &SigningMessageHash) -> Signature {
    use ed25519_dalek::Signer;
    Signature::from_inner(signing.inner.sign(msg.as_bytes()))
}

/// 严格验证协议签名消息哈希上的签名。
///
/// 唯一验证路径（crypto-serialization-v1.md §10）：
/// `canonical payload → signed_bytes → SHA-256 → SigningMessageHash → verify_strict`。
/// 使用 `verify_strict`：拒绝非规范 `S`、small-order、weak key、malformed 输入。
pub fn verify_message_hash(
    verifying: &VerifyingKey,
    msg: &SigningMessageHash,
    sig: &Signature,
) -> Result<(), SignatureError> {
    // sig.0 为 [u8;64]，from_bytes 接受定长数组（无错路径）。
    let inner = ed25519_dalek::Signature::from_bytes(&sig.0);
    verifying
        .inner
        .verify_strict(msg.as_bytes(), &inner)
        .map_err(|_| SignatureError::InvalidSignature)
}

fn hex_str(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use ed25519_dalek::Signer as DalekSigner;

    fn hex_arr64(s: &str) -> [u8; 64] {
        assert_eq!(s.len(), 128);
        let b = s.as_bytes();
        let mut out = [0u8; 64];
        for (i, x) in out.iter_mut().enumerate() {
            *x = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        }
        out
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }

    // ------------------------------------------------------------------
    // Exit 6：RFC 8032 Ed25519 标准测试向量
    // ------------------------------------------------------------------
    #[test]
    fn rfc8032_test_vector_1() {
        // SECRET=9d61..., PUBLIC=d75a..., MSG=(empty), SIG=e556...
        let secret =
            hex_arr64_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
        assert_eq!(
            sk.verifying_key().to_bytes(),
            hex_arr64_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = sk.sign(b"");
        assert_eq!(
            sig.to_bytes(),
            hex_arr64(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
    }

    #[test]
    fn rfc8032_test_vector_2() {
        let secret =
            hex_arr64_32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
        assert_eq!(
            sk.verifying_key().to_bytes(),
            hex_arr64_32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        let sig = sk.sign(&[0x72]);
        assert_eq!(
            sig.to_bytes(),
            hex_arr64(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        );
    }

    #[test]
    fn rfc8032_test_vector_3() {
        let secret =
            hex_arr64_32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
        assert_eq!(
            sk.verifying_key().to_bytes(),
            hex_arr64_32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        );
        let sig = sk.sign(&[0xaf, 0x82]);
        assert_eq!(
            sig.to_bytes(),
            hex_arr64(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            )
        );
    }

    fn hex_arr64_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        for (i, x) in out.iter_mut().enumerate() {
            *x = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        }
        out
    }

    // ------------------------------------------------------------------
    // Exit 1/2：只能接受 SigningMessageHash（roundtrip via domain pipeline）
    // ------------------------------------------------------------------
    #[test]
    fn sign_and_verify_via_message_hash() {
        let sk = SigningKey::from_seed([7u8; 32]);
        let vk = sk.verifying_key();

        // 经冻结域管道构造 SigningMessageHash
        let payload = b"tx payload";
        let sb =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, payload).unwrap();
        let msg = hash_signing_message(&sb);

        let sig = sign_message_hash(&sk, &msg);
        assert_eq!(sig.to_bytes().len(), 64);
        assert!(verify_message_hash(&vk, &msg, &sig).is_ok());
    }

    // ------------------------------------------------------------------
    // Exit 3/4：private key 不暴露 / 不 Clone / Debug 打码
    // ------------------------------------------------------------------
    #[test]
    fn signing_key_does_not_leak_via_debug() {
        let sk = SigningKey::from_seed([9u8; 32]);
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("REDACTED"));
        // 私钥字节不得出现在 Debug 输出中
        assert!(!dbg.contains("0909090909090909090909090909090909090909090909090909090909090909"));
    }

    // 注意：SigningKey 有意未实现 Clone / 不暴露私钥字节（Exit 3/4）；
    // 这是结构层面的保证（未 derive Clone、from_seed 为 pub(crate)、无 secret 访问器）。

    // ------------------------------------------------------------------
    // Exit 7：malformed / truncated / oversized signature rejection
    // ------------------------------------------------------------------
    #[test]
    fn signature_length_rejection() {
        assert!(Signature::from_bytes(&[0u8; 63]).is_err()); // truncated
        assert!(Signature::from_bytes(&[0u8; 65]).is_err()); // oversized
        assert!(Signature::from_bytes(&[0u8; 64]).is_ok()); // exact
        assert!(Signature::from_bytes(&[]).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = SigningKey::from_seed([3u8; 32]);
        let vk = sk.verifying_key();
        let sb = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, b"m").unwrap();
        let msg = hash_signing_message(&sb);
        let sig = sign_message_hash(&sk, &msg);

        // 篡改签名一个字节 → 验证失败
        let mut bad = sig.to_bytes();
        bad[0] ^= 0x01;
        let bad_sig = Signature::from_bytes(&bad).unwrap();
        assert!(verify_message_hash(&vk, &msg, &bad_sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_message_and_wrong_key() {
        let sk = SigningKey::from_seed([5u8; 32]);
        let vk = sk.verifying_key();
        let sb1 =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, b"m1").unwrap();
        let sb2 =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 1, b"m2").unwrap();
        let msg1 = hash_signing_message(&sb1);
        let msg2 = hash_signing_message(&sb2);
        let sig = sign_message_hash(&sk, &msg1);

        // 不同 message_hash → 失败
        assert!(verify_message_hash(&vk, &msg2, &sig).is_err());
        // 不同链 → 不同 message_hash → 失败（跨链重放防护）
        let sb3 =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Transaction, 2, b"m1").unwrap();
        let msg3 = hash_signing_message(&sb3);
        assert!(verify_message_hash(&vk, &msg3, &sig).is_err());

        // 不同密钥 → 失败
        let other = SigningKey::from_seed([6u8; 32]).verifying_key();
        assert!(verify_message_hash(&other, &msg1, &sig).is_err());
    }

    // ------------------------------------------------------------------
    // VerifyingKey 解析
    // ------------------------------------------------------------------
    #[test]
    fn verifying_key_roundtrip() {
        let sk = SigningKey::from_seed([11u8; 32]);
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        let parsed = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), bytes);
        // 长度错误 ⇒ 拒绝（畸形公钥）
        assert!(VerifyingKey::from_bytes(&bytes[..31]).is_err());
        let too_long = [0u8; 33];
        assert!(VerifyingKey::from_bytes(&too_long).is_err());
    }
}
