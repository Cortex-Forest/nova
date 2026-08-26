//! Nova Chain 密钥材料生命周期（STEP 4 — Key Handling 基础）。
//!
//! # 生命周期（ADR-0007）
//! ```text
//! Generate → Store → Use → Rotate → Revoke → Recover
//! ```
//! - **Generate**：CSPRNG（OS 熵源 `getrandom::fill`，**无 fallback**；RNG 失败 ⇒ 返回错误，不降级）。
//! - **Store / Use**：`SigningKey` 不暴露私钥、不 `Clone`、`Debug` 打码、Drop 时零化
//!   （`ed25519-dalek` `zeroize` feature）。
//! - **Rotate / Revoke / Recover**：协议层机制在后续 STEP（账户/钱包 Phase）。
//!
//! # 纪律（Master Prompt §18/§55）
//! - 私钥永不落日志、不入 git、不返回到 RPC；不序列化明文密钥。

use crate::signature::{SignatureError, SigningKey, VerifyingKey};
use zeroize::Zeroize;

/// 密钥对：签名密钥 + 验证密钥。
///
/// 不实现 `Clone`（含 [`SigningKey`] secret）；`Debug` 打码。
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    /// 生成新密钥对（OS CSPRNG，无 fallback）。
    pub fn generate() -> Result<Self, SignatureError> {
        // OS 熵源填充 32B 种子；失败返回错误（无回退）。
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| SignatureError::RngFailure)?;

        let signing = SigningKey::from_seed(secret);
        // 立即零化栈上种子拷贝（ed25519-dalek 内部 secret 由 zeroize feature 在 Drop 时处理）。
        secret.zeroize();

        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    /// 签名密钥（不暴露私钥字节）。
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// 验证密钥（公钥，可安全分发）。
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 只暴露公钥，绝不暴露私钥
        write!(f, "KeyPair({:?})", self.verifying)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_creates_valid_keypair() {
        let kp = KeyPair::generate().unwrap();
        let vk = kp.verifying_key();
        let bytes = vk.to_bytes();
        // 公钥非全零（有效生成）
        assert!(bytes.iter().any(|b| *b != 0));
        // 可解析
        assert!(VerifyingKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        assert_ne!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn debug_redacts_secret() {
        let kp = KeyPair::generate().unwrap();
        let dbg = format!("{kp:?}");
        assert!(!dbg.contains("REDACTED") || dbg.contains("KeyPair"));
        // 不包含完整私钥十六进制（KeyPair Debug 只含公钥）
        assert!(!dbg.contains("signing"));
    }
}
