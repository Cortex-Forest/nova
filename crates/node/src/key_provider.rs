//! Key Provider seam（STEP 10-16；Node Lifecycle —— KeyProvider）。
//!
//! # 职责
//! - [`KeyProvider`]：把「密钥来源」抽象为 `load_signer() -> Box<dyn SigningCapability>`。
//!   `ValidatorActor` / safety 逻辑 **不知道** 私钥位置 / 存储方式 / 是否远程；只依赖
//!   [`SigningCapability`]（`public_key()` + `sign(&SigningMessageHash)`）。
//! - **不修改 `SigningCapability`**；本 seam 是纯加法。
//! - Phase 1 实现 [`SoftwareKeyProvider`]（内存持有 `KeyPair`；测试可注入）。生产持久化密钥导入 /
//!   HSM / Remote signer / Cloud KMS 为 DEFERRED 载体（未来实现同一 trait）。
//! - 私钥永不出 Provider 边界；`KeyProvider` 从不把 key 交给 SafetyStore / Runtime 之外。
//!
//! # 与 SafetyStore 的关系
//! - SafetyStore 只保存 `ValidatorId`（公钥派生）、vote evidence / signature、lock、chain identity；
//!   **绝不保存 private key / seed / mnemonic**（10-15T 冻结边界；此处再次声明）。

use std::cell::RefCell;

use nova_crypto::key::KeyPair;

use crate::signer::{SigningCapability, SoftwareSigner};

/// KeyProvider 错误（node-local；fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProviderError {
    /// 未配置 / 调用方未注入 provider。
    NotConfigured,
    /// 载体不可用（HSM / remote / KMS 未实现；CSPRNG 失败等）。
    Unavailable,
    /// signer 已被取走（`load_signer` 多次调用）。
    AlreadyProvisioned,
}

/// KeyProvider 配置（Phase 1 最小）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyProviderConfig {
    /// 未配置 / 由调用方注入 provider 实例（Phase 1 路径）。
    #[default]
    None,
    /// SoftwareKeyProvider（密钥材料由调用方提供；生产导入 DEFERRED）。
    Software,
}

/// KeyProvider seam：加载签名能力（不暴露私钥 / 不暴露密钥存储细节）。
pub trait KeyProvider {
    /// 加载签名器。实现返回的 `SigningCapability` 拥有私钥；Provider 边界外不可见私钥。
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError>;
}

/// SoftwareKeyProvider（Phase 1）：内存持有单个 `KeyPair`（`RefCell<Option>`，取走即消费一次）。
///
/// - 测试 / dev：`from_keypair` / `generate` 注入。
/// - 生产持久化密钥导入（加密 seed 文件等）为 DEFERRED —— 未来在同一 trait 下实现，本结构不变。
pub struct SoftwareKeyProvider {
    keypair: RefCell<Option<KeyPair>>,
}

impl SoftwareKeyProvider {
    /// 从既有 `KeyPair` 构造（注入；测试 / 未来 KeyManager 产出）。
    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self {
            keypair: RefCell::new(Some(keypair)),
        }
    }

    /// 生成新密钥（dev / test 便捷；**非**生产默认路径）。
    pub fn generate() -> Result<Self, KeyProviderError> {
        let keypair = KeyPair::generate().map_err(|_| KeyProviderError::Unavailable)?;
        Ok(Self::from_keypair(keypair))
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        let keypair = self
            .keypair
            .borrow_mut()
            .take()
            .ok_or(KeyProviderError::AlreadyProvisioned)?;
        Ok(Box::new(SoftwareSigner::new(keypair)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::signature::VerifyingKey;

    #[test]
    fn software_provider_loads_signer_once() {
        let kp = KeyPair::generate().unwrap();
        let vk = *kp.verifying_key();
        let provider = SoftwareKeyProvider::from_keypair(kp);
        let signer = provider.load_signer().unwrap();
        assert_eq!(signer.public_key(), vk);
        // 第二次加载 ⇒ 密钥已消费（fail closed）
        assert!(
            matches!(
                provider.load_signer(),
                Err(KeyProviderError::AlreadyProvisioned)
            ),
            "signer 已被取走 ⇒ AlreadyProvisioned"
        );
    }

    #[test]
    fn signer_public_key_is_verifying_key() {
        let provider = SoftwareKeyProvider::generate().unwrap();
        let signer = provider.load_signer().unwrap();
        let vk: VerifyingKey = signer.public_key();
        assert_eq!(vk.to_bytes().len(), 32);
    }
}
