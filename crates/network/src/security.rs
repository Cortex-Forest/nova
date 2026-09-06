//! Network Security Primitives v1（STEP 10-18I-K；ADR-0059 Network Security Architecture v1
//! —— DESIGN FROZEN）。
//!
//! # 定位
//! - 纯安全原语 + 确定性编码：canonical signing bytes → SHA-256 → 既有 Ed25519
//!   `sign_message_hash` / `verify_message_hash`（crypto crate 冻结 API；不新增算法）。
//! - **不 wire 进** NetworkService / EventLoop / Runtime（本阶段有意保持 primitive-only；
//!   安全域绑定走演进路径，不改 `MessageEnvelope` wire / `sign_message` / `verify_message` 语义）。
//! - 全部 deterministic、canonical、bounded、fail-closed；无 Rc/Arc/Mutex/async/serde/JSON/
//!   Debug-format / 内存布局编码。
//!
//! # Canonical signing domain（ADR-0059 §Canonical Signing Domain；无 payload_length —— 前缀定长）
//! ```text
//! canonical = DOMAIN_TAG
//!            ‖ network_id(1B)
//!            ‖ chain_id(8B LE)
//!            ‖ genesis_hash(32B)
//!            ‖ protocol_version(1B)
//!            ‖ message_type(1B)
//!            ‖ payload
//! ```
//! 前缀（tag + 1+8+32+1+1）定长 ⇒ payload 尾随无歧义；canonical 唯一。

use nova_crypto::address::NetworkId;
use nova_crypto::domain::{SigningMessageHash, hash_signing_message};
use nova_crypto::signature::{
    Signature, SigningKey, VerifyingKey, sign_message_hash, verify_message_hash,
};

use crate::message::MessageType;
use crate::node_id::NodeId;

/// 网络消息签名域固定 domain tag（固定 bytes 常量；非动态字符串）。
const DOMAIN_TAG: &[u8] = b"Nova/network-message/v1";

/// 网络握手 commitment 固定 domain tag（与消息域分离，防跨域混淆）。
const HANDSHAKE_TAG: &[u8] = b"Nova/network-handshake/v1";

/// 网络安全原语最大 payload（与 `NetworkServiceConfig::max_msg_bytes` 默认 1 MiB 语义一致；
/// network crate 内部唯一安全常量 —— 不散落多处）。
pub const MAX_NETWORK_MESSAGE_PAYLOAD_BYTES: usize = 1024 * 1024;

/// 网络安全原语错误（fail-closed；不以 bool 作为唯一错误信息）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSecurityError {
    /// payload 超过 `MAX_NETWORK_MESSAGE_PAYLOAD_BYTES`（拒绝，不编码）。
    PayloadTooLarge { max: usize, actual: usize },
    /// 声称 NodeId 与给定公钥派生的 NodeId 不符（身份绑定失败）。
    InvalidNodeId,
    /// 签名验证失败（Ed25519 strict 拒绝）。
    InvalidSignature,
    /// 输入不合法（结构 / 长度等；fail-closed）。
    InvalidInput,
}

impl core::fmt::Display for NetworkSecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge { max, actual } => {
                write!(f, "network payload too large: max {max}, actual {actual}")
            }
            Self::InvalidNodeId => write!(f, "NodeId does not match public key"),
            Self::InvalidSignature => write!(f, "invalid network message signature"),
            Self::InvalidInput => write!(f, "invalid network security input"),
        }
    }
}

impl core::error::Error for NetworkSecurityError {}

/// 网络消息签名上下文：把每条网络消息签名唯一绑定其网络 / 链 / 协议上下文
/// （ADR-0059 Canonical Signing Domain；`NS-SEC-1/2/3/9`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkMessageSigningContext {
    /// 网络 id（Mainnet/Testnet/Devnet；跨网络 replay 分离）。
    pub network_id: NetworkId,
    /// 链 id（u64；与网络/创世共同构成链身份绑定）。
    pub chain_id: u64,
    /// genesis hash（链的创世承诺；32B）。
    pub genesis_hash: [u8; 32],
    /// 协议版本（显式；防 downgrade —— 拒绝不支持版本）。
    pub protocol_version: u8,
    /// 消息类型（payload 语义分类进入签名域）。
    pub message_type: MessageType,
}

impl NetworkMessageSigningContext {
    /// canonical signing bytes（ADR-0059；前缀定长 ⇒ 无歧义；payload 超限 ⇒ Err）。
    fn canonical_bytes(&self, payload: &[u8]) -> Result<Vec<u8>, NetworkSecurityError> {
        if payload.len() > MAX_NETWORK_MESSAGE_PAYLOAD_BYTES {
            return Err(NetworkSecurityError::PayloadTooLarge {
                max: MAX_NETWORK_MESSAGE_PAYLOAD_BYTES,
                actual: payload.len(),
            });
        }
        let mut out = Vec::with_capacity(DOMAIN_TAG.len() + 1 + 8 + 32 + 1 + 1 + payload.len());
        out.extend_from_slice(DOMAIN_TAG);
        out.push(self.network_id.as_u8());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.push(self.protocol_version);
        out.push(self.message_type.as_u8());
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// 网络消息签名 digest：`canonical bytes → SHA-256 → [u8;32]`（deterministic）。
///
/// 注意：签名/验证内部使用 `SigningMessageHash` newtype（防绕过）；本函数为测试 / 外部对比
/// 暴露 32B digest。
pub fn network_message_signing_digest(
    context: &NetworkMessageSigningContext,
    payload: &[u8],
) -> Result<[u8; 32], NetworkSecurityError> {
    Ok(*signing_hash(context, payload)?.as_bytes())
}

/// 签名内部 digest（`SigningMessageHash` newtype；唯一签名构造路径）。
fn signing_hash(
    context: &NetworkMessageSigningContext,
    payload: &[u8],
) -> Result<SigningMessageHash, NetworkSecurityError> {
    let canonical = context.canonical_bytes(payload)?;
    Ok(hash_signing_message(&canonical))
}

/// 对网络消息签名（复用 crypto Ed25519 `sign_message_hash`；不 double-hash）。
pub fn sign_network_message(
    signing: &SigningKey,
    context: &NetworkMessageSigningContext,
    payload: &[u8],
) -> Result<Signature, NetworkSecurityError> {
    let hash = signing_hash(context, payload)?;
    Ok(sign_message_hash(signing, &hash))
}

/// 验证网络消息签名（`verify_message_hash` strict；fail-closed）。
pub fn verify_network_message(
    public_key: &VerifyingKey,
    context: &NetworkMessageSigningContext,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), NetworkSecurityError> {
    let hash = signing_hash(context, payload)?;
    verify_message_hash(public_key, &hash, signature)
        .map_err(|_| NetworkSecurityError::InvalidSignature)
}

/// NodeId 身份绑定：`derived NodeId(public_key) == claimed NodeId`，否则 Err。
///
/// 主安全验证为 Ed25519 签名（strict）；此处绑定比较的是公开 pubkey canonical bytes
/// （非 secret），故复用普通相等比较即可（不自行实现 constant-time 密码原语）。
pub fn verify_node_identity(
    node_id: &NodeId,
    public_key: &VerifyingKey,
) -> Result<(), NetworkSecurityError> {
    if *node_id == NodeId::from_verifying_key(public_key) {
        Ok(())
    } else {
        Err(NetworkSecurityError::InvalidNodeId)
    }
}

/// Session nonce（会话类消息；canonical 16B）。不在此生成（生成归未来 session manager /
/// CSPRNG 域）；仅提供确定性编码 / 比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNonce([u8; 16]);

impl SessionNonce {
    pub const LEN: usize = 16;
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Request id（请求 / 响应绑定；canonical 16B）。不在此生成；仅确定性编码 / 比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId([u8; 16]);

impl RequestId {
    pub const LEN: usize = 16;
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Handshake commitment（纯确定性函数；ADR-0059 Handshake；**不实现** handshake runtime）。
///
/// commitment = SHA-256(
///   HANDSHAKE_TAG ‖ network_id ‖ chain_id ‖ genesis_hash ‖ protocol_version ‖
///   claimed_node_id(32B) ‖ session_nonce(16B) ‖ capabilities
/// )
/// 绑链身份 + 声称 NodeId + nonce，供握手阶段证明链上下文一致与身份绑定（Ack 验证用）。
pub fn handshake_commitment(
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    protocol_version: u8,
    claimed_node_id: &NodeId,
    session_nonce: &SessionNonce,
    capabilities: &[u8],
) -> Result<[u8; 32], NetworkSecurityError> {
    if capabilities.len() > MAX_NETWORK_MESSAGE_PAYLOAD_BYTES {
        return Err(NetworkSecurityError::PayloadTooLarge {
            max: MAX_NETWORK_MESSAGE_PAYLOAD_BYTES,
            actual: capabilities.len(),
        });
    }
    let mut out =
        Vec::with_capacity(HANDSHAKE_TAG.len() + 1 + 8 + 32 + 1 + 32 + 16 + capabilities.len());
    out.extend_from_slice(HANDSHAKE_TAG);
    out.push(network_id.as_u8());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&genesis_hash);
    out.push(protocol_version);
    out.extend_from_slice(claimed_node_id.as_bytes());
    out.extend_from_slice(session_nonce.as_bytes());
    out.extend_from_slice(capabilities);
    Ok(*hash_signing_message(&out).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::key::KeyPair;

    fn ctx(
        network_id: NetworkId,
        chain_id: u64,
        genesis: [u8; 32],
        protocol: u8,
        ty: MessageType,
    ) -> NetworkMessageSigningContext {
        NetworkMessageSigningContext {
            network_id,
            chain_id,
            genesis_hash: genesis,
            protocol_version: protocol,
            message_type: ty,
        }
    }

    #[test]
    fn signing_roundtrip_and_cross_context_rejection() {
        let kp = KeyPair::generate().unwrap();
        let c = ctx(
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            1,
            MessageType::ConsensusVote,
        );
        let payload = b"vote-wire";
        let sig = sign_network_message(kp.signing_key(), &c, payload).unwrap();
        verify_network_message(kp.verifying_key(), &c, payload, &sig).expect("valid");
        // 跨 context（不同 network）验证必须失败。
        let c2 = ctx(
            NetworkId::Testnet,
            1001,
            [0x42; 32],
            1,
            MessageType::ConsensusVote,
        );
        assert!(verify_network_message(kp.verifying_key(), &c2, payload, &sig).is_err());
    }

    #[test]
    fn cross_domain_field_separation() {
        let base = ctx(
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            1,
            MessageType::ConsensusVote,
        );
        let payload = b"p";
        let d = network_message_signing_digest(&base, payload).unwrap();
        // 单一字段改变 ⇒ digest 改变。
        let net = ctx(
            NetworkId::Testnet,
            1001,
            [0x42; 32],
            1,
            MessageType::ConsensusVote,
        );
        assert_ne!(d, network_message_signing_digest(&net, payload).unwrap());
        let chain = ctx(
            NetworkId::Mainnet,
            1002,
            [0x42; 32],
            1,
            MessageType::ConsensusVote,
        );
        assert_ne!(d, network_message_signing_digest(&chain, payload).unwrap());
        let genesis = ctx(
            NetworkId::Mainnet,
            1001,
            [0x43; 32],
            1,
            MessageType::ConsensusVote,
        );
        assert_ne!(
            d,
            network_message_signing_digest(&genesis, payload).unwrap()
        );
        let proto = ctx(
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            2,
            MessageType::ConsensusVote,
        );
        assert_ne!(d, network_message_signing_digest(&proto, payload).unwrap());
        let ty = ctx(
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            1,
            MessageType::ConsensusQc,
        );
        assert_ne!(d, network_message_signing_digest(&ty, payload).unwrap());
        assert_ne!(d, network_message_signing_digest(&base, b"q").unwrap());
    }

    #[test]
    fn deterministic_encoding_and_digest() {
        let c = ctx(
            NetworkId::Devnet,
            7,
            [0xAA; 32],
            3,
            MessageType::GossipTransaction,
        );
        assert_eq!(
            network_message_signing_digest(&c, b"x").unwrap(),
            network_message_signing_digest(&c, b"x").unwrap(),
            "same input ⇒ same digest"
        );
    }

    #[test]
    fn oversized_payload_rejected() {
        let c = ctx(NetworkId::Mainnet, 1, [0; 32], 1, MessageType::Ping);
        let big = vec![0u8; MAX_NETWORK_MESSAGE_PAYLOAD_BYTES + 1];
        assert!(matches!(
            network_message_signing_digest(&c, &big),
            Err(NetworkSecurityError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn node_identity_binding() {
        let kp = KeyPair::generate().unwrap();
        let id = NodeId::from_verifying_key(kp.verifying_key());
        verify_node_identity(&id, kp.verifying_key()).expect("match");
        let other = NodeId::from_verifying_key(KeyPair::generate().unwrap().verifying_key());
        assert_eq!(
            verify_node_identity(&other, kp.verifying_key()),
            Err(NetworkSecurityError::InvalidNodeId)
        );
    }

    #[test]
    fn handshake_commitment_deterministic_and_chain_bound() {
        let nonce = SessionNonce::from_bytes([7; 16]);
        let node = NodeId::from_bytes([9; 32]);
        let caps = b"consensus,sync";
        let a = handshake_commitment(NetworkId::Mainnet, 1, [0x42; 32], 1, &node, &nonce, caps)
            .unwrap();
        let b = handshake_commitment(NetworkId::Mainnet, 1, [0x42; 32], 1, &node, &nonce, caps)
            .unwrap();
        assert_eq!(a, b, "deterministic");
        // 不同 network ⇒ 不同 commitment（防连错网络）。
        let c = handshake_commitment(NetworkId::Testnet, 1, [0x42; 32], 1, &node, &nonce, caps)
            .unwrap();
        assert_ne!(a, c);
    }
}
