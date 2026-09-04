//! Node-local signing boundary（STEP 10-15L；ADR-0053 validator-local vote production 的签名边界）。
//!
//! # 职责
//! - [`SigningCapability`]：本地 validator 的签名能力抽象 —— **只接受** [`SigningMessageHash`]
//!   （已含 `DomainId::ValidatorVote` + `chain_id` 的 domain separation，ADR-0013 §3），
//!   不接受任意 `&[u8]`；不负责 DomainId / chain_id / canonical serialization / ValidatorId 派生。
//! - [`SoftwareSigner`]：基于 [`KeyPair`] 的软件签名器（dev/test 构造用 `KeyPair::generate()`；
//!   生产持久化 KeyManager / HSM / external signer 为后续独立设计）。
//!
//! # 安全边界
//! - 不持有 / 不暴露 private key bytes；不暴露 [`SigningKey`]；不实现 `Clone`；Debug 打码
//!   （`KeyPair` Debug 只显示公钥）。
//! - 同步 API；不引入 async runtime。
//! - 依赖方向：node → crypto（复用既有 Ed25519 primitive；不重写私钥逻辑）。

use nova_crypto::domain::SigningMessageHash;
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, VerifyingKey, sign_message_hash};

/// 本地签名错误（node operational error；**非** consensus 协议错误）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// 底层签名失败（当前 `sign_message_hash` 对有效密钥不可失败；保留供 HSM / external 载体）。
    SigningFailed,
}

/// 本地投票签名能力抽象。
///
/// - `public_key()`：身份校验来源（ValidatorActor 据此派生 / 比对 `ValidatorId`）。
/// - `sign(&SigningMessageHash)`：对**已 domain-bound** 的消息哈希签名；
///   绝不接受任意字节（ADR-0013 §3 类型强制）。
pub trait SigningCapability {
    /// 该签名者的验证（公）密钥。
    fn public_key(&self) -> VerifyingKey;

    /// 对协议签名消息哈希签名。
    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError>;
}

/// 软件签名器：持有 [`KeyPair`]（secret 生命周期 = KeyPair 所有；不 Clone）。
pub struct SoftwareSigner {
    keypair: KeyPair,
}

impl SoftwareSigner {
    /// 从既有 `KeyPair` 构造（dev / test：`KeyPair::generate()`；生产 KeyManager 后续独立设计）。
    pub fn new(keypair: KeyPair) -> Self {
        Self { keypair }
    }
}

impl SigningCapability for SoftwareSigner {
    fn public_key(&self) -> VerifyingKey {
        *self.keypair.verifying_key()
    }

    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(self.keypair.signing_key(), message_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::signature::verify_message_hash;

    #[test]
    fn public_key_matches_keypair() {
        let kp = KeyPair::generate().unwrap();
        let expected = kp.verifying_key().to_bytes();
        let signer = SoftwareSigner::new(kp);
        assert_eq!(
            signer.public_key().to_bytes(),
            expected,
            "public_key 与 KeyPair 公钥一致"
        );
    }

    #[test]
    fn signature_verifies_with_public_key() {
        let kp = KeyPair::generate().unwrap();
        let signer = SoftwareSigner::new(kp);
        // 构造任意已 domain-bound 消息哈希（仅用于验证 signer 原语；ValidatorVote 真实哈希见 validator 测试）
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            1001,
            &[0xAA; 32],
        )
        .unwrap();
        let msg = hash_signing_message(&signed);
        let sig = signer.sign(&msg).unwrap();
        assert_eq!(
            verify_message_hash(&signer.public_key(), &msg, &sig),
            Ok(()),
            "signature 可被对应公钥验证"
        );
    }

    #[test]
    fn wrong_message_fails_verification() {
        let kp = KeyPair::generate().unwrap();
        let signer = SoftwareSigner::new(kp);
        let mk = |b: u8| {
            let signed = build_signed_bytes(
                AlgorithmId::Ed25519,
                DomainId::ValidatorVote,
                1001,
                &[b; 32],
            )
            .unwrap();
            hash_signing_message(&signed)
        };
        let msg1 = mk(0x01);
        let msg2 = mk(0x02);
        let sig = signer.sign(&msg1).unwrap();
        assert_eq!(
            verify_message_hash(&signer.public_key(), &msg2, &sig),
            Err(nova_crypto::signature::SignatureError::InvalidSignature),
            "不同消息 ⇒ 验证失败"
        );
    }

    #[test]
    fn sign_api_rejects_raw_bytes_by_type() {
        // 编译期保证：SigningCapability::sign 只接受 &SigningMessageHash；
        // 普通 &[u8;32] / &[u8] 无法传入（类型强制，ADR-0013 §3）。
        let kp = KeyPair::generate().unwrap();
        let signer = SoftwareSigner::new(kp);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            1001,
            &[0u8; 1],
        )
        .unwrap();
        let msg = hash_signing_message(&signed);
        // 以下调用能编译即证明只接受 SigningMessageHash（raw [u8;32] 无 From 自动转换路径）
        let _sig: Signature = signer.sign(&msg).unwrap();
    }
}
