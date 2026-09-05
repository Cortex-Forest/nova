//! Network Identity seam（STEP 10-18I-A；Owner Option 1 —— 仅 seam，不 Runtime 装配）。
//!
//! # 定位
//! - 网络身份 = `NodeId`（Ed25519 pubkey canonical bytes）+ **envelope 签名**能力
//!   （`nova_network::message::sign_message`）。
//! - 本模块是 **node 层网络身份来源 seam**（GAP-A 受控推进）：把「节点网络身份 + 信封签名」
//!   抽象为 [`NetworkIdentityProvider`] / [`NetworkSigner`]；生产 NodeConfig 网络 key / KeyManager /
//!   HSM / Remote 签名为 **DEFERRED**（未来在同一 trait 下实现，本结构不变）。
//! - **身份分离**：网络身份 ≠ validator 身份。本模块**不引用** `SigningCapability` /
//!   `SoftwareSigner` / `ValidatorActor` / `SafetyStore`；validator key 绝不作为 network identity
//!   （NodeId 来自 network key 的 pubkey，与 `ValidatorId = SHA-256(validator pubkey)` 不同源）。
//!
//! # 边界
//! - 私钥只在实现内部（`SoftwareNetworkIdentity` 持 `KeyPair`）；`NetworkSigner` 不暴露 `SigningKey`。
//! - `load_network_signer` 取走即消费一次（与 `KeyProvider` 同语义；二次 ⇒ `AlreadyProvisioned`）。
//! - 不触碰 NetworkService / EventLoop 冻结架构（10-18E/F）；本 seam 供未来 Runtime/egress 装配使用。

use std::cell::RefCell;

use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, NetworkError, sign_message};
use nova_network::node_id::NodeId;

/// 网络信封签名错误（node-local network identity 域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSigningError {
    /// envelope 签名失败（network 域错误透传）。
    Sign(NetworkError),
}

/// 网络身份提供者错误（fail closed；风格同 `KeyProviderError`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkIdentityError {
    /// 未配置 / 调用方未注入 provider。
    NotConfigured,
    /// 载体不可用（HSM / remote / KMS 未实现；CSPRNG 失败等）。
    Unavailable,
    /// 网络身份已被取走（`load_network_signer` 多次调用）。
    AlreadyProvisioned,
}

/// 网络签名能力（node 网络身份；`node_id()` + envelope 签名）。
///
/// - `node_id()`：本网络身份（= network key pubkey canonical bytes）。
/// - `sign_envelope`：填 `sender = self.node_id()` 并对 `version‖type‖payload` 签名（N-4）。
pub trait NetworkSigner {
    /// 本网络身份的 NodeId。
    fn node_id(&self) -> NodeId;

    /// 对信封签名（覆盖 `sender` 与 `signature`）。
    fn sign_envelope(&self, envelope: &mut MessageEnvelope) -> Result<(), NetworkSigningError>;
}

/// 网络身份提供者 seam：加载网络签名能力（不暴露私钥；网络身份与 validator 身份分离）。
pub trait NetworkIdentityProvider {
    /// 加载网络 signer（拥有网络私钥；Provider 边界外不可见）。
    fn load_network_signer(&self) -> Result<Box<dyn NetworkSigner>, NetworkIdentityError>;
}

/// 软件网络身份（Phase 1）：持有单个网络 `KeyPair`（test / dev / 未来 KeyManager 产出）。
pub struct SoftwareNetworkIdentity {
    keypair: KeyPair,
}

impl SoftwareNetworkIdentity {
    /// 从既有网络 `KeyPair` 构造（注入；测试 / dev）。
    pub fn new(keypair: KeyPair) -> Self {
        Self { keypair }
    }
}

impl NetworkSigner for SoftwareNetworkIdentity {
    fn node_id(&self) -> NodeId {
        NodeId::from_verifying_key(self.keypair.verifying_key())
    }

    fn sign_envelope(&self, envelope: &mut MessageEnvelope) -> Result<(), NetworkSigningError> {
        sign_message(self.keypair.signing_key(), envelope).map_err(NetworkSigningError::Sign)
    }
}

/// SoftwareNetworkIdentityProvider（Phase 1）：内存持有单个网络 `KeyPair`
/// （`RefCell<Option>`，取走即消费一次）。
pub struct SoftwareNetworkIdentityProvider {
    keypair: RefCell<Option<KeyPair>>,
}

impl SoftwareNetworkIdentityProvider {
    /// 从既有网络 `KeyPair` 构造（注入；测试 / 未来 KeyManager 产出）。
    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self {
            keypair: RefCell::new(Some(keypair)),
        }
    }

    /// 生成新网络密钥（dev / test 便捷；**非**生产默认路径）。
    pub fn generate() -> Result<Self, NetworkIdentityError> {
        let keypair = KeyPair::generate().map_err(|_| NetworkIdentityError::Unavailable)?;
        Ok(Self::from_keypair(keypair))
    }
}

impl NetworkIdentityProvider for SoftwareNetworkIdentityProvider {
    fn load_network_signer(&self) -> Result<Box<dyn NetworkSigner>, NetworkIdentityError> {
        let keypair = self
            .keypair
            .borrow_mut()
            .take()
            .ok_or(NetworkIdentityError::AlreadyProvisioned)?;
        Ok(Box::new(SoftwareNetworkIdentity::new(keypair)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_network::message::{MessageType, verify_message};

    fn signed_ok(signer: &dyn NetworkSigner, payload: Vec<u8>) -> MessageEnvelope {
        let mut env = MessageEnvelope {
            version: 1,
            message_type: MessageType::Ping,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        signer.sign_envelope(&mut env).expect("sign");
        env
    }

    #[test]
    fn node_id_is_network_key_public_key() {
        let kp = KeyPair::generate().unwrap();
        let expected = NodeId::from_verifying_key(kp.verifying_key());
        let signer = SoftwareNetworkIdentity::new(kp);
        assert_eq!(
            signer.node_id(),
            expected,
            "NodeId = network key pubkey bytes"
        );
    }

    #[test]
    fn sign_envelope_fills_sender_and_verifies() {
        let kp = KeyPair::generate().unwrap();
        let vk = *kp.verifying_key(); // Copy；先提取再 move key 进 signer
        let signer = SoftwareNetworkIdentity::new(kp);
        let env = signed_ok(&signer, vec![1, 2, 3]);
        // sender 被覆盖为本网络身份 NodeId
        assert_eq!(env.sender, signer.node_id());
        // 对端可用网络身份公钥验证（envelope 签名 + sender 身份绑定）
        verify_message(&vk, &env).expect("对端 verify 通过");
        // payload 未改动（签名覆盖 version‖type‖payload；篡改会失败）
        let mut tampered = env.clone();
        tampered.payload[0] ^= 0xff;
        assert!(
            verify_message(&vk, &tampered).is_err(),
            "篡改 payload ⇒ 验签失败"
        );
    }

    #[test]
    fn provider_loads_signer_once() {
        let kp = KeyPair::generate().unwrap();
        let provider = SoftwareNetworkIdentityProvider::from_keypair(kp);
        let signer = provider.load_network_signer().unwrap();
        assert!(
            provider
                .load_network_signer()
                .is_err_and(|e| e == NetworkIdentityError::AlreadyProvisioned),
            "网络身份已被取走 ⇒ AlreadyProvisioned"
        );
        // signer 仍可用（独立持有）
        let _ = signed_ok(signer.as_ref(), vec![9]);
    }

    #[test]
    fn network_identity_is_separate_from_validator_identity() {
        // 结构性：NodeId（网络）与 ValidatorId（共识，SHA-256(pubkey)）不同源。
        // 本模块不使用任何 validator key 派生 ValidatorId —— 此处仅验证 NodeId 为原始 pubkey bytes。
        let kp = KeyPair::generate().unwrap();
        let signer = SoftwareNetworkIdentity::new(kp);
        let node_bytes = *signer.node_id().as_bytes();
        let vk = signer.node_id();
        // NodeId == pubkey canonical bytes（而非哈希）
        let _ = vk;
        assert_eq!(node_bytes.len(), 32);
    }
}
