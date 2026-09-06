//! Handshake / Session Security Runtime 纯状态与编解码（STEP 10-18I-L；ADR-0059 Network
//! Security Architecture v1 —— DESIGN FROZEN）。
//!
//! # 定位
//! - 本模块承载 network crate 内 **peer session 状态 / 握手 canonical payload / bounded
//!   replay cache / 握手速率决策** 的确定性逻辑，供 [`crate::network_service::NetworkService`]
//!   （session owner）集成调用。
//! - 复用 ADR-0059 已实现安全原语（`security.rs`）：`SessionNonce` / `RequestId` /
//!   `verify_node_identity` / `NetworkMessageSigningContext`；**不复制**密码学实现。
//! - 不实现 production transport / handshake runtime manager / peer discovery。
//! - Session state **不属于** ConsensusState / ValidatorActor / VoteLedger（保持 NS-INV 边界）。

use nova_crypto::address::NetworkId;
use std::collections::VecDeque;

use crate::node_id::NodeId;
use crate::security::{NetworkSecurityError, SessionNonce};

/// 握手 payload 子类型（单一 `MessageType::Handshake`；以 payload 首字节区分，不改 MessageType 编号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeKind {
    /// 发起方声明（network/chain/genesis/protocol/NodeId/capabilities/nonce）。
    Init = 0x01,
    /// 响应确认（ACK；当前阶段接受并同样校验上下文 —— 未来 Ack 可携带对端本地 nonce）。
    Ack = 0x02,
}

impl HandshakeKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Peer session 状态机（NS 拥有；EventLoop 只 dispatch）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessionState {
    /// 尚未握手 / 会话已关闭（禁止承载普通流量）。
    Unauthenticated,
    /// 已发送或已收到握手，验证进行中。
    Handshaking,
    /// 握手验证通过（身份 + 链上下文一致）。
    Authenticated,
    /// 会话建立（允许普通 authenticated network 消息）。
    Established,
    /// 关闭中（terminating）。
    Closing,
    /// 已关闭。
    Closed,
}

impl PeerSessionState {
    pub fn allows_authenticated_traffic(&self) -> bool {
        matches!(self, Self::Established)
    }
}

/// Session 域错误（fail-closed；typed；不吞错）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// 握手 payload 超限（canonical 编码拒绝）。
    HandshakeTooLarge,
    /// 握手 payload 结构 / 长度非法。
    MalformedHandshake,
    /// claimed NodeId ≠ envelope sender 派生身份。
    InvalidNodeId,
    /// network_id 不匹配（跨网络拒绝）。
    WrongNetworkId,
    /// chain_id 不匹配。
    WrongChainId,
    /// genesis_hash 不匹配（同 NodeId + 不同创世 = REJECT）。
    WrongGenesisHash,
    /// 不支持的 protocol_version（拒绝，不降级）。
    UnsupportedProtocolVersion,
    /// 握手已被记录（replay）。
    Replay,
    /// CSPRNG 失败（生成 nonce；无 fallback）。
    RngFailure,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HandshakeTooLarge => write!(f, "handshake payload too large"),
            Self::MalformedHandshake => write!(f, "malformed handshake payload"),
            Self::InvalidNodeId => write!(f, "handshake claimed NodeId mismatch"),
            Self::WrongNetworkId => write!(f, "handshake network_id mismatch"),
            Self::WrongChainId => write!(f, "handshake chain_id mismatch"),
            Self::WrongGenesisHash => write!(f, "handshake genesis_hash mismatch"),
            Self::UnsupportedProtocolVersion => write!(f, "unsupported protocol version"),
            Self::Replay => write!(f, "handshake replay detected"),
            Self::RngFailure => write!(f, "CSPRNG failure (no fallback)"),
        }
    }
}

impl core::error::Error for SessionError {}

impl From<NetworkSecurityError> for SessionError {
    fn from(e: NetworkSecurityError) -> Self {
        match e {
            NetworkSecurityError::PayloadTooLarge { .. } => Self::HandshakeTooLarge,
            NetworkSecurityError::InvalidNodeId => Self::InvalidNodeId,
            NetworkSecurityError::InvalidSignature => Self::MalformedHandshake,
            NetworkSecurityError::InvalidInput => Self::MalformedHandshake,
        }
    }
}

/// 本地期望的 peer-auth 配置（注入 NetworkService；`NetworkServiceConfig` 保持 Copy）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAuthConfig {
    /// 本节点期望网络（错配 ⇒ 拒）。
    pub network_id: NetworkId,
    /// 期望链 id。
    pub chain_id: u64,
    /// 期望创世承诺。
    pub genesis_hash: [u8; 32],
    /// 支持的协议版本（拒绝其它版本）。
    pub protocol_version: u8,
    /// 本节点宣告的 capabilities（canonical bytes；空则无）。
    pub capabilities: &'static [u8],
    /// per-peer 握手尝试上界（超出 ⇒ reject/close）。
    pub per_peer_handshake_limit: u32,
    /// 全局握手尝试上界。
    pub global_handshake_limit: u32,
    /// replay cache 容量（bounded；FIFO 确定性驱逐）。
    pub replay_cache_capacity: usize,
}

/// Handshake 解码后的字段（canonical）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePayload {
    pub kind: HandshakeKind,
    pub network_id: NetworkId,
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
    pub protocol_version: u8,
    pub claimed_node_id: NodeId,
    pub session_nonce: SessionNonce,
    pub capabilities: Vec<u8>,
}

/// Handshake payload 固定前缀长度（kind 之后到 capabilities 之前为定长）。
const FIXED_LEN: usize = 1 + 8 + 32 + 1 + 32 + 16;

/// Handshake payload 上限（capabilities 长度 ≤ 0xFFFF；整体 ≤ 2B 前缀 + 64KiB caps）。
pub const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 2 + FIXED_LEN + 65535;

/// Canonical handshake payload：
/// `kind(1B) ‖ network_id(1B) ‖ chain_id(8B LE) ‖ genesis_hash(32B) ‖
///  protocol_version(1B) ‖ claimed_node_id(32B) ‖ session_nonce(16B) ‖ caps_len(2B BE) ‖ caps`。
///
/// 底层 canonical 编码器：字段平坦（全为协议域字段），参数多属必要；不做 struct 装箱绕借。
#[allow(clippy::too_many_arguments)]
pub fn handshake_payload_encode(
    kind: HandshakeKind,
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    protocol_version: u8,
    claimed_node_id: &NodeId,
    session_nonce: &SessionNonce,
    capabilities: &[u8],
) -> Result<Vec<u8>, SessionError> {
    if capabilities.len() > u16::MAX as usize {
        return Err(SessionError::HandshakeTooLarge);
    }
    let mut out = Vec::with_capacity(2 + FIXED_LEN + capabilities.len());
    out.push(kind.as_u8());
    out.push(network_id.as_u8());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&genesis_hash);
    out.push(protocol_version);
    out.extend_from_slice(claimed_node_id.as_bytes());
    out.extend_from_slice(session_nonce.as_bytes());
    out.extend_from_slice(&(capabilities.len() as u16).to_be_bytes());
    out.extend_from_slice(capabilities);
    Ok(out)
}

/// Canonical decode（结构 / 长度非法 ⇒ Err）。
pub fn handshake_payload_decode(bytes: &[u8]) -> Result<HandshakePayload, SessionError> {
    // 最小长度 = kind(1) + FIXED_LEN(90) + cap_len(2) = 93。
    if bytes.len() < 3 + FIXED_LEN {
        return Err(SessionError::MalformedHandshake);
    }
    let kind = match bytes[0] {
        0x01 => HandshakeKind::Init,
        0x02 => HandshakeKind::Ack,
        _ => return Err(SessionError::MalformedHandshake),
    };
    let network_id = match bytes[1] {
        0x01 => NetworkId::Mainnet,
        0x02 => NetworkId::Testnet,
        0x03 => NetworkId::Devnet,
        _ => return Err(SessionError::MalformedHandshake),
    };
    let mut chain = [0u8; 8];
    chain.copy_from_slice(&bytes[2..10]);
    let chain_id = u64::from_le_bytes(chain);
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(&bytes[10..42]);
    let protocol_version = bytes[42];
    let mut claimed = [0u8; 32];
    claimed.copy_from_slice(&bytes[43..75]);
    let claimed_node_id = NodeId::from_bytes(claimed);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[75..91]);
    let session_nonce = SessionNonce::from_bytes(nonce);
    let cap_len = u16::from_be_bytes([bytes[91], bytes[92]]) as usize;
    // 总长度 = kind(1) + FIXED_LEN(90) + cap_len(2) + caps。
    if bytes.len() != 3 + FIXED_LEN + cap_len {
        return Err(SessionError::MalformedHandshake);
    }
    Ok(HandshakePayload {
        kind,
        network_id,
        chain_id,
        genesis_hash: genesis,
        protocol_version,
        claimed_node_id,
        session_nonce,
        capabilities: bytes[3 + FIXED_LEN..].to_vec(),
    })
}

/// 链上下文校验：payload 网络/链/创世/协议必须 == 本地期望（任何不符 ⇒ 对应错误；fail-closed）。
///
/// 关键：`same NodeId + different genesis_hash = REJECT`（NS-SEC-2 / NS-SEC-9）。
pub fn validate_handshake_context(
    payload: &HandshakePayload,
    expected: &PeerAuthConfig,
) -> Result<(), SessionError> {
    if payload.network_id != expected.network_id {
        return Err(SessionError::WrongNetworkId);
    }
    if payload.chain_id != expected.chain_id {
        return Err(SessionError::WrongChainId);
    }
    if payload.genesis_hash != expected.genesis_hash {
        return Err(SessionError::WrongGenesisHash);
    }
    if payload.protocol_version != expected.protocol_version {
        return Err(SessionError::UnsupportedProtocolVersion);
    }
    Ok(())
}

/// Bounded replay cache（握手去重；FIFO 确定性驱逐最旧；无随机 eviction；不无限增长）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayKey {
    pub peer: NodeId,
    pub nonce: SessionNonce,
}

/// 固定容量 FIFO replay cache。
#[derive(Debug, Clone)]
pub struct ReplayCache {
    capacity: usize,
    entries: VecDeque<ReplayKey>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: &ReplayKey) -> bool {
        self.entries.contains(key)
    }

    /// 记录；若已达容量则确定性驱逐最旧（FIFO）。返回是否为新记录。
    pub fn insert(&mut self, key: ReplayKey) -> bool {
        if self.contains(&key) {
            return false;
        }
        self.entries.push_back(key);
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
        true
    }
}

/// 生成新 SessionNonce（OS CSPRNG `getrandom`，无 fallback；每次握手必须新 nonce）。
pub fn random_session_nonce() -> Result<SessionNonce, SessionError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| SessionError::RngFailure)?;
    Ok(SessionNonce::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PeerAuthConfig {
        PeerAuthConfig {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_hash: [0x42; 32],
            protocol_version: 1,
            capabilities: b"consensus",
            per_peer_handshake_limit: 3,
            global_handshake_limit: 100,
            replay_cache_capacity: 8,
        }
    }

    #[test]
    fn handshake_roundtrip_canonical() {
        let node = NodeId::from_bytes([9; 32]);
        let nonce = SessionNonce::from_bytes([1; 16]);
        let encoded = handshake_payload_encode(
            HandshakeKind::Init,
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            1,
            &node,
            &nonce,
            b"cap",
        )
        .unwrap();
        let decoded = handshake_payload_decode(&encoded).unwrap();
        assert_eq!(decoded.kind, HandshakeKind::Init);
        assert_eq!(decoded.chain_id, 1001);
        assert_eq!(decoded.genesis_hash, [0x42; 32]);
        assert_eq!(decoded.claimed_node_id, node);
        assert_eq!(decoded.session_nonce, nonce);
        assert_eq!(decoded.capabilities, b"cap");
        // deterministic
        let again = handshake_payload_encode(
            HandshakeKind::Init,
            NetworkId::Mainnet,
            1001,
            [0x42; 32],
            1,
            &node,
            &nonce,
            b"cap",
        )
        .unwrap();
        assert_eq!(encoded, again);
    }

    #[test]
    fn malformed_rejected() {
        assert!(matches!(
            handshake_payload_decode(b"\x09"),
            Err(SessionError::MalformedHandshake)
        ));
        assert!(matches!(
            handshake_payload_decode(&[0u8; 40]),
            Err(SessionError::MalformedHandshake)
        ));
    }

    #[test]
    fn context_mismatch_rejected() {
        let expected = cfg();
        let node = NodeId::from_bytes([9; 32]);
        let nonce = SessionNonce::from_bytes([1; 16]);
        let base = HandshakePayload {
            kind: HandshakeKind::Init,
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_hash: [0x42; 32],
            protocol_version: 1,
            claimed_node_id: node,
            session_nonce: nonce,
            capabilities: vec![],
        };
        assert!(validate_handshake_context(&base, &expected).is_ok());
        let wrong_net = HandshakePayload {
            network_id: NetworkId::Testnet,
            ..base.clone()
        };
        assert_eq!(
            validate_handshake_context(&wrong_net, &expected),
            Err(SessionError::WrongNetworkId)
        );
        let wrong_chain = HandshakePayload {
            chain_id: 999,
            ..base.clone()
        };
        assert_eq!(
            validate_handshake_context(&wrong_chain, &expected),
            Err(SessionError::WrongChainId)
        );
        let wrong_gen = HandshakePayload {
            genesis_hash: [0x43; 32],
            ..base
        };
        assert_eq!(
            validate_handshake_context(&wrong_gen, &expected),
            Err(SessionError::WrongGenesisHash)
        );
    }

    #[test]
    fn replay_cache_bounded_fifo() {
        let mut cache = ReplayCache::new(2);
        let a = ReplayKey {
            peer: NodeId::from_bytes([1; 32]),
            nonce: SessionNonce::from_bytes([1; 16]),
        };
        let b = ReplayKey {
            peer: NodeId::from_bytes([1; 32]),
            nonce: SessionNonce::from_bytes([2; 16]),
        };
        let c = ReplayKey {
            peer: NodeId::from_bytes([1; 32]),
            nonce: SessionNonce::from_bytes([3; 16]),
        };
        assert!(cache.insert(a.clone()));
        assert!(cache.insert(b.clone()));
        assert!(!cache.insert(a.clone()), "duplicate rejected");
        assert_eq!(cache.len(), 2);
        // 满后插入 c ⇒ 驱逐最旧 a（FIFO deterministic）
        assert!(cache.insert(c.clone()));
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&a), "oldest evicted");
        assert!(cache.contains(&b));
        assert!(cache.contains(&c));
    }

    #[test]
    fn session_state_gating() {
        assert!(!PeerSessionState::Unauthenticated.allows_authenticated_traffic());
        assert!(!PeerSessionState::Authenticated.allows_authenticated_traffic());
        assert!(PeerSessionState::Established.allows_authenticated_traffic());
    }

    #[test]
    fn random_nonce_is_16_bytes_distinct() {
        let n1 = random_session_nonce().unwrap();
        let n2 = random_session_nonce().unwrap();
        assert_eq!(n1.as_bytes().len(), 16);
        assert_ne!(n1, n2, "每次握手必须新 nonce");
    }
}
