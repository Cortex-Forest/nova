//! NetworkService 核心骨架（STEP 10-18E；ADR-0055 NetworkService Architecture v1 —— FROZEN）。
//!
//! # 职责（网络状态 owner；**无共识语义**）
//! - 拥有 `Transport`、`PeerManager`（最小 peer 状态机）、inbound/outbound **bounded** queue、
//!   message classification、network lifecycle（Running / Stopped）。
//! - Inbound：`Transport → decode MessageEnvelope → validate envelope / sender NodeId →
//!   classify MessageType → NetworkEvent → inbound queue`。
//!   NetworkService **可以**做 envelope 解码 / NodeId 校验 / 信封签名校验 / MessageType 分类；
//!   **不做** `verify_vote_input` / `verify_qc` / consensus transition / ValidatorActor /
//!   SafetyStore / finality decision（payload 保持 opaque —— classify，不 interpret）。
//! - Outbound：调用方提供 **pre-signed `MessageEnvelope`**（签名/私钥在调用方签名边界；
//!   NetworkService 不持 private key、不自签 vote/QC）→ 编码 → `Transport.send` / broadcast。
//! - Shutdown：idempotent；stopped 后不接受新 outbound / 不产生新 network event / 不 peer op；
//!   绝不触碰 ConsensusState / ValidatorActor / SafetyStore。
//!
//! # 边界（结构性）
//! - 本模块只依赖 `nova-network` 自身原语（message/transport/node_id）+ crypto 验签类型；
//!   **无 consensus / node / validator / safety 依赖** ⇒ NetworkService 不拥有 ConsensusState /
//!   ValidatorActor / VoteLedger / SafetyStore / private key（NS-INV-1..4 结构性成立）。
//! - NodeId（网络身份）与 ValidatorId（共识身份）**不混用**（NS-INV-10）。
//! - 同步、无 async runtime；`poll_transport` 为**单次 drain**（非永久 loop；EventLoop 归 10-18F）。

use crate::message::{MessageEnvelope, MessageType, NetworkError, decode, encode, verify_message};
use crate::node_id::NodeId;
use crate::transport::Transport;
use core::fmt;
use nova_crypto::signature::VerifyingKey;
use std::collections::{HashMap, VecDeque};

/// NetworkService 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkServiceState {
    Running,
    Stopped,
}

/// NetworkService 配置（bounded 队列容量 / 消息大小上界）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkServiceConfig {
    /// 单条入站 payload 允许最大字节数（超出 ⇒ 丢弃，避免无限内存）。
    pub max_msg_bytes: usize,
    /// inbound queue 容量（bounded；满 ⇒ 按策略 drop incoming + 计数）。
    pub inbound_capacity: usize,
    /// outbound queue 容量（bounded；满 ⇒ `QueueFull`）。
    pub outbound_capacity: usize,
}

impl Default for NetworkServiceConfig {
    fn default() -> Self {
        Self {
            max_msg_bytes: 1024 * 1024,
            inbound_capacity: 1024,
            outbound_capacity: 1024,
        }
    }
}

/// 诊断计数（供 queue-full / invalid 策略观察；非日志系统）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkDiagnostics {
    /// 已从 transport 读取的帧数。
    pub frames_received: u64,
    /// 已入队 inbound 的有效事件数。
    pub events_enqueued: u64,
    /// 因 invalid envelope / sender / 超限而丢弃的帧数。
    pub dropped_invalid: u64,
    /// 因 inbound queue 满而丢弃的事件数。
    pub dropped_overflow: u64,
    /// 已成功发出的出站消息数。
    pub sent: u64,
}

/// NetworkService 错误（node-local 网络域；fail-safe：不 panic、不改共识）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkServiceError {
    /// 服务已停止。
    Stopped,
    /// transport 层错误（send/recv）。
    Transport(NetworkError),
    /// envelope 解码失败（结构非法 / 长度不符）。
    InvalidEnvelope,
    /// 未知 / 不支持的消息类型。
    UnknownMessageType(u8),
    /// sender NodeId 非法（非 canonical pubkey）或签名验证失败。
    InvalidSender,
    /// 目标 peer 未注册。
    UnknownPeer,
    /// 目标 peer 未连接。
    PeerNotConnected,
    /// outbound queue 已满。
    QueueFull,
}

impl fmt::Display for NetworkServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "network service stopped"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::InvalidEnvelope => write!(f, "invalid envelope"),
            Self::UnknownMessageType(t) => write!(f, "unknown message type: {t:#04x}"),
            Self::InvalidSender => write!(f, "invalid sender"),
            Self::UnknownPeer => write!(f, "unknown peer"),
            Self::PeerNotConnected => write!(f, "peer not connected"),
            Self::QueueFull => write!(f, "outbound queue full"),
        }
    }
}

impl std::error::Error for NetworkServiceError {}

/// 最小 peer 状态（不含任何共识/validator/safety 字段；NS-INV 约束）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerState {
    pub node: NodeId,
    pub connected: bool,
}

impl PeerState {
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            connected: false,
        }
    }
}

/// PeerManager：NodeId → PeerState（network identity；与 ValidatorId 无关）。
#[derive(Debug, Default)]
pub struct PeerManager {
    peers: HashMap<NodeId, PeerState>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// 注册 peer（初始 Disconnected；已存在则 no-op）。
    pub fn register(&mut self, node: NodeId) {
        self.peers
            .entry(node)
            .or_insert_with(|| PeerState::new(node));
    }

    /// 标记 connected（未注册则自动注册后置 connected）。
    pub fn connect(&mut self, node: NodeId) {
        self.register(node);
        if let Some(p) = self.peers.get_mut(&node) {
            p.connected = true;
        }
    }

    /// 标记 disconnected（保留注册）。
    pub fn disconnect(&mut self, node: NodeId) {
        if let Some(p) = self.peers.get_mut(&node) {
            p.connected = false;
        }
    }

    /// 移除 peer。
    pub fn remove(&mut self, node: NodeId) {
        self.peers.remove(&node);
    }

    pub fn is_connected(&self, node: NodeId) -> bool {
        self.peers.get(&node).map(|p| p.connected).unwrap_or(false)
    }

    pub fn contains(&self, node: NodeId) -> bool {
        self.peers.contains_key(&node)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// 当前 connected peers（无特定顺序；broadcast 目标集）。
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| p.connected)
            .map(|p| p.node)
            .collect()
    }
}

/// 入站网络事件（分类结果；payload **opaque** —— NetworkService 不解析共识语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
    Handshake { sender: NodeId, payload: Vec<u8> },
    Ping { sender: NodeId, payload: Vec<u8> },
    Pong { sender: NodeId, payload: Vec<u8> },
    GossipTransaction { sender: NodeId, payload: Vec<u8> },
    GossipBlock { sender: NodeId, payload: Vec<u8> },
    SyncBlockRequest { sender: NodeId, payload: Vec<u8> },
    SyncBlockResponse { sender: NodeId, payload: Vec<u8> },
    Status { sender: NodeId, payload: Vec<u8> },
    ConsensusVote { sender: NodeId, payload: Vec<u8> },
    ConsensusProposal { sender: NodeId, payload: Vec<u8> },
    ConsensusQc { sender: NodeId, payload: Vec<u8> },
}

impl NetworkEvent {
    pub fn sender(&self) -> NodeId {
        match self {
            Self::Handshake { sender, .. }
            | Self::Ping { sender, .. }
            | Self::Pong { sender, .. }
            | Self::GossipTransaction { sender, .. }
            | Self::GossipBlock { sender, .. }
            | Self::SyncBlockRequest { sender, .. }
            | Self::SyncBlockResponse { sender, .. }
            | Self::Status { sender, .. }
            | Self::ConsensusVote { sender, .. }
            | Self::ConsensusProposal { sender, .. }
            | Self::ConsensusQc { sender, .. } => *sender,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Handshake { payload, .. }
            | Self::Ping { payload, .. }
            | Self::Pong { payload, .. }
            | Self::GossipTransaction { payload, .. }
            | Self::GossipBlock { payload, .. }
            | Self::SyncBlockRequest { payload, .. }
            | Self::SyncBlockResponse { payload, .. }
            | Self::Status { payload, .. }
            | Self::ConsensusVote { payload, .. }
            | Self::ConsensusProposal { payload, .. }
            | Self::ConsensusQc { payload, .. } => payload,
        }
    }

    /// 分类的 MessageType。
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Handshake { .. } => MessageType::Handshake,
            Self::Ping { .. } => MessageType::Ping,
            Self::Pong { .. } => MessageType::Pong,
            Self::GossipTransaction { .. } => MessageType::GossipTransaction,
            Self::GossipBlock { .. } => MessageType::GossipBlock,
            Self::SyncBlockRequest { .. } => MessageType::SyncBlockRequest,
            Self::SyncBlockResponse { .. } => MessageType::SyncBlockResponse,
            Self::Status { .. } => MessageType::Status,
            Self::ConsensusVote { .. } => MessageType::ConsensusVote,
            Self::ConsensusProposal { .. } => MessageType::ConsensusProposal,
            Self::ConsensusQc { .. } => MessageType::ConsensusQc,
        }
    }
}

/// Bounded FIFO（`VecDeque + capacity`；无 async channel）。
#[derive(Debug, Clone)]
pub struct BoundedQueue<T> {
    deque: VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            deque: VecDeque::new(),
            capacity,
        }
    }

    pub fn push_back(&mut self, item: T) -> Result<(), T> {
        if self.deque.len() >= self.capacity {
            return Err(item);
        }
        self.deque.push_back(item);
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.deque.pop_front()
    }

    pub fn is_full(&self) -> bool {
        self.deque.len() >= self.capacity
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clear(&mut self) {
        self.deque.clear();
    }
}

/// NetworkService（网络状态 owner；同步；无共识语义）。
pub struct NetworkService<T: Transport> {
    state: NetworkServiceState,
    transport: T,
    peers: PeerManager,
    inbound: BoundedQueue<NetworkEvent>,
    outbound: BoundedQueue<(NodeId, MessageEnvelope)>,
    config: NetworkServiceConfig,
    diagnostics: NetworkDiagnostics,
}

impl<T: Transport> NetworkService<T> {
    /// 构造（Running）。`self_id` = 本节点网络身份（供 outbound envelope sender 校验/诊断；
    /// 私钥不进入本服务）。
    pub fn new(config: NetworkServiceConfig, self_id: NodeId, transport: T) -> Self {
        // self_id 保留为文档化身份锚（未来 10-18G 可用于拒绝 sender≠self 的 outbound）。
        let _ = self_id;
        Self {
            state: NetworkServiceState::Running,
            transport,
            peers: PeerManager::new(),
            inbound: BoundedQueue::new(config.inbound_capacity),
            outbound: BoundedQueue::new(config.outbound_capacity),
            config,
            diagnostics: NetworkDiagnostics::default(),
        }
    }

    pub fn state(&self) -> NetworkServiceState {
        self.state
    }

    pub fn config(&self) -> NetworkServiceConfig {
        self.config
    }

    pub fn diagnostics(&self) -> NetworkDiagnostics {
        self.diagnostics
    }

    /// 本服务拥有的 transport（可变；供 EventLoop/测试直接驱动）。
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    // ---------- peer ops（network identity only） ----------

    pub fn register_peer(&mut self, node: NodeId) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        self.peers.register(node);
        Ok(())
    }

    /// connect：标记 connected（未注册自动注册）。
    pub fn connect_peer(&mut self, node: NodeId) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        self.peers.connect(node);
        Ok(())
    }

    pub fn disconnect_peer(&mut self, node: NodeId) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        self.peers.disconnect(node);
        Ok(())
    }

    pub fn remove_peer(&mut self, node: NodeId) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        self.peers.remove(node);
        Ok(())
    }

    pub fn is_connected(&self, node: NodeId) -> bool {
        self.peers.is_connected(node)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn connected_peer_count(&self) -> usize {
        self.peers.connected_peers().len()
    }

    // ---------- outbound ----------

    /// 入队一条 **pre-signed** envelope 发往单 peer（bounded；满 ⇒ `QueueFull`）。
    ///
    /// 签名/私钥在调用方（签名边界）；NetworkService 不自签、不持 key。
    pub fn enqueue_outbound(
        &mut self,
        peer: NodeId,
        envelope: MessageEnvelope,
    ) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        if !self.peers.is_connected(peer) {
            return if self.peers.contains(peer) {
                Err(NetworkServiceError::PeerNotConnected)
            } else {
                Err(NetworkServiceError::UnknownPeer)
            };
        }
        self.outbound
            .push_back((peer, envelope))
            .map_err(|_| NetworkServiceError::QueueFull)
    }

    /// 广播到所有 connected peers（入队；部分满 ⇒ 返回 `Err(QueueFull)`，不部分静默丢）。
    pub fn broadcast(&mut self, envelope: MessageEnvelope) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let peers = self.peers.connected_peers();
        for peer in &peers {
            self.outbound
                .push_back((*peer, envelope.clone()))
                .map_err(|_| NetworkServiceError::QueueFull)?;
        }
        Ok(peers.len())
    }

    /// 排空 outbound：编码 envelope → `Transport.send`。返回成功发送数。
    pub fn flush_outbound(&mut self) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let mut sent = 0usize;
        while let Some((peer, envelope)) = self.outbound.pop_front() {
            let bytes = encode(&envelope);
            // 单条发送失败 ⇒ 跳过并计数（不 panic / 不改共识）；send 错误透出仅当持续失败时由上层重试。
            match self.transport.send(&peer, bytes) {
                Ok(()) => {
                    sent += 1;
                    self.diagnostics.sent += 1;
                }
                Err(e) => {
                    // 记录为 invalid（尽力而为）；不断言、不 panic。
                    let _ = e;
                    self.diagnostics.dropped_invalid += 1;
                }
            }
        }
        Ok(sent)
    }

    // ---------- inbound ----------

    /// **单次** drain transport（非永久 loop；完整 wakeup/timer 归 10-18F）。
    ///
    /// 对每条可用帧：decode → validate(sender/signature) → classify → inbound queue。
    /// 返回成功入队数；invalid 帧 drop + 计数（不 panic、不进 consensus）。
    pub fn poll_transport(&mut self) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let mut accepted = 0usize;
        loop {
            match self.transport.try_recv() {
                Ok(Some((raw_sender, bytes))) => {
                    self.diagnostics.frames_received += 1;
                    if self.handle_inbound_frame(raw_sender, &bytes) {
                        accepted += 1;
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(NetworkServiceError::Transport(e)),
            }
        }
        Ok(accepted)
    }

    /// 取走当前 inbound 事件（FIFO；priority/重排由未来 EventLoop 负责 —— NS 不做 QoS）。
    pub fn drain_inbound(&mut self) -> Vec<NetworkEvent> {
        let mut events = Vec::new();
        while let Some(e) = self.inbound.pop_front() {
            events.push(e);
        }
        events
    }

    pub fn inbound_len(&self) -> usize {
        self.inbound.len()
    }

    /// 处理单条帧。返回 true=有效事件已入队；false=drop（invalid / overflow）。
    fn handle_inbound_frame(&mut self, raw_sender: NodeId, bytes: &[u8]) -> bool {
        // 1. decode envelope（结构非法 / 未知类型 / 长度不符）。
        let envelope = match decode(bytes) {
            Ok(e) => e,
            Err(NetworkError::InvalidMessageType(t)) => {
                self.diagnostics.dropped_invalid += 1;
                let _ = t;
                return false;
            }
            Err(_) => {
                self.diagnostics.dropped_invalid += 1;
                return false;
            }
        };
        // 2. sender NodeId 校验 + 信封签名验证（NodeId = Ed25519 pubkey canonical）。
        if envelope.sender != raw_sender {
            self.diagnostics.dropped_invalid += 1;
            return false;
        }
        let vk = match VerifyingKey::from_bytes(envelope.sender.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                self.diagnostics.dropped_invalid += 1;
                return false;
            }
        };
        if verify_message(&vk, &envelope).is_err() {
            self.diagnostics.dropped_invalid += 1;
            return false;
        }
        // 3. payload 大小约束（避免无限内存）。
        if envelope.payload.len() > self.config.max_msg_bytes {
            self.diagnostics.dropped_invalid += 1;
            return false;
        }
        // 4. classify → NetworkEvent（payload opaque；不解析共识语义）。
        let event = classify(&envelope);
        // 5. bounded inbound；满 ⇒ drop + overflow 计数（consensus/gossip/sync/block 一致策略）。
        match self.inbound.push_back(event) {
            Ok(()) => {
                self.diagnostics.events_enqueued += 1;
                true
            }
            Err(_) => {
                self.diagnostics.dropped_overflow += 1;
                false
            }
        }
    }

    // ---------- lifecycle ----------

    /// Shutdown：idempotent。置 Stopped + 清理队列；不接受新 work / 不再 peer op。
    /// 绝不触碰 ConsensusState / ValidatorActor / SafetyStore。
    pub fn shutdown(&mut self) {
        self.state = NetworkServiceState::Stopped;
        self.inbound.clear();
        self.outbound.clear();
        self.peers = PeerManager::new();
    }

    fn ensure_running(&self) -> Result<(), NetworkServiceError> {
        if self.state == NetworkServiceState::Running {
            Ok(())
        } else {
            Err(NetworkServiceError::Stopped)
        }
    }
}

/// MessageType → NetworkEvent（纯分类；payload opaque）。
fn classify(envelope: &MessageEnvelope) -> NetworkEvent {
    let sender = envelope.sender;
    let payload = envelope.payload.clone();
    match envelope.message_type {
        MessageType::Handshake => NetworkEvent::Handshake { sender, payload },
        MessageType::Ping => NetworkEvent::Ping { sender, payload },
        MessageType::Pong => NetworkEvent::Pong { sender, payload },
        MessageType::GossipTransaction => NetworkEvent::GossipTransaction { sender, payload },
        MessageType::GossipBlock => NetworkEvent::GossipBlock { sender, payload },
        MessageType::SyncBlockRequest => NetworkEvent::SyncBlockRequest { sender, payload },
        MessageType::SyncBlockResponse => NetworkEvent::SyncBlockResponse { sender, payload },
        MessageType::Status => NetworkEvent::Status { sender, payload },
        MessageType::ConsensusVote => NetworkEvent::ConsensusVote { sender, payload },
        MessageType::ConsensusProposal => NetworkEvent::ConsensusProposal { sender, payload },
        MessageType::ConsensusQc => NetworkEvent::ConsensusQc { sender, payload },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::sign_message;
    use crate::transport::MemoryTransport;
    use nova_crypto::key::KeyPair;

    // ---------- fixtures ----------

    fn cfg(cap: usize) -> NetworkServiceConfig {
        NetworkServiceConfig {
            max_msg_bytes: 4096,
            inbound_capacity: cap,
            outbound_capacity: cap,
        }
    }

    /// 建立一对 MemoryTransport + 其 NodeId；返回 (A_id, B_id, a_transport, b_transport)。
    fn pair(kp_a: &KeyPair, kp_b: &KeyPair) -> (NodeId, NodeId, MemoryTransport, MemoryTransport) {
        let a = NodeId::from_verifying_key(kp_a.verifying_key());
        let b = NodeId::from_verifying_key(kp_b.verifying_key());
        let (ta, tb) = MemoryTransport::pair(a, b);
        (a, b, ta, tb)
    }

    /// 由 key 签名的 envelope（sender 自动 = NodeId(pubkey)）。
    fn signed_env(
        signing: &nova_crypto::signature::SigningKey,
        mt: MessageType,
        payload: Vec<u8>,
    ) -> MessageEnvelope {
        let mut e = MessageEnvelope {
            version: 1,
            message_type: mt,
            payload,
            sender: NodeId::from_bytes([0u8; 32]),
            signature: [0u8; 64],
        };
        sign_message(signing, &mut e).unwrap();
        e
    }

    /// 把 B 签名的消息推入 A 的 transport（模拟 peer → A 入站）。
    fn deliver_b_to_a(b_transport: &mut MemoryTransport, a_id: NodeId, envelope: &MessageEnvelope) {
        b_transport
            .send(&a_id, encode(envelope))
            .expect("memory send");
    }

    #[test]
    fn ns_1_transport_send_receive_via_service() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc_a = NetworkService::new(cfg(16), a, ta);
        svc_a.connect_peer(b).unwrap();
        let env = signed_env(kb.signing_key(), MessageType::ConsensusVote, vec![0xAB; 8]);
        deliver_b_to_a(&mut tb, a, &env);
        let accepted = svc_a.poll_transport().unwrap();
        assert_eq!(accepted, 1);
        let events = svc_a.drain_inbound();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message_type(), MessageType::ConsensusVote);
        assert_eq!(events[0].sender(), b);
    }

    #[test]
    fn ns_2_memory_transport_bidirectional_pair() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, tb) = pair(&ka, &kb);
        let mut svc_a = NetworkService::new(cfg(16), a, ta);
        let mut svc_b = NetworkService::new(cfg(16), b, tb);
        svc_a.connect_peer(b).unwrap();
        svc_b.connect_peer(a).unwrap();
        // A → B
        let e1 = signed_env(ka.signing_key(), MessageType::Ping, vec![1]);
        svc_a.enqueue_outbound(b, e1).unwrap();
        assert_eq!(svc_a.flush_outbound().unwrap(), 1);
        svc_b.poll_transport().unwrap();
        assert_eq!(svc_b.drain_inbound()[0].message_type(), MessageType::Ping);
        // B → A
        let e2 = signed_env(kb.signing_key(), MessageType::Pong, vec![2]);
        svc_b.enqueue_outbound(a, e2).unwrap();
        svc_b.flush_outbound().unwrap();
        svc_a.poll_transport().unwrap();
        assert_eq!(svc_a.drain_inbound()[0].message_type(), MessageType::Pong);
    }

    #[test]
    fn ns_3_invalid_envelope_rejected_no_event() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc_a = NetworkService::new(cfg(16), a, ta);
        svc_a.connect_peer(b).unwrap();
        // 有效签名后篡改 payload ⇒ verify 失败
        let mut env = signed_env(kb.signing_key(), MessageType::ConsensusVote, vec![1, 2, 3]);
        env.payload[0] ^= 0xff;
        deliver_b_to_a(&mut tb, a, &env);
        let accepted = svc_a.poll_transport().unwrap();
        assert_eq!(accepted, 0);
        assert!(svc_a.drain_inbound().is_empty());
        assert_eq!(svc_a.diagnostics().dropped_invalid, 1);
    }

    #[test]
    fn ns_4_unknown_message_rejected_no_panic() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc_a = NetworkService::new(cfg(16), a, ta);
        svc_a.connect_peer(b).unwrap();
        // 未知 type 0x0C 的原始帧
        let mut raw = vec![1u8, 0x0C];
        raw.extend_from_slice(&0u32.to_le_bytes());
        tb.send(&a, raw).unwrap();
        let accepted = svc_a.poll_transport().unwrap();
        assert_eq!(accepted, 0);
        assert!(svc_a.drain_inbound().is_empty());
        assert_eq!(svc_a.diagnostics().dropped_invalid, 1);
    }

    #[test]
    fn ns_5_peer_connect_disconnect() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, _tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(16), a, ta);
        svc.connect_peer(b).unwrap();
        assert!(svc.is_connected(b));
        assert_eq!(svc.peer_count(), 1);
        assert_eq!(svc.connected_peer_count(), 1);
        svc.disconnect_peer(b).unwrap();
        assert!(!svc.is_connected(b));
        assert_eq!(svc.connected_peer_count(), 0);
        svc.remove_peer(b).unwrap();
        assert_eq!(svc.peer_count(), 0);
        assert!(!svc.is_connected(b));
    }

    #[test]
    fn ns_6_queue_capacity_and_overflow() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(2), a, ta);
        svc.connect_peer(b).unwrap();
        // inbound overflow：填 3 帧（cap=2）⇒ 第 3 帧 drop + overflow 计数
        for i in 0..3u8 {
            let env = signed_env(kb.signing_key(), MessageType::Ping, vec![i]);
            deliver_b_to_a(&mut tb, a, &env);
        }
        let accepted = svc.poll_transport().unwrap();
        assert_eq!(accepted, 2, "cap=2：仅 2 帧入队");
        assert_eq!(svc.inbound_len(), 2);
        assert_eq!(svc.diagnostics().dropped_overflow, 1);
        // outbound overflow：cap=2；放 3 次（同一 connected peer）⇒ 第 3 次 QueueFull
        let mut svc2 = NetworkService::new(cfg(2), a, MemoryTransport::pair(a, b).0);
        svc2.connect_peer(b).unwrap();
        for _ in 0..2 {
            svc2.enqueue_outbound(b, signed_env(ka.signing_key(), MessageType::Ping, vec![0]))
                .unwrap();
        }
        let err = svc2
            .enqueue_outbound(b, signed_env(ka.signing_key(), MessageType::Ping, vec![0]))
            .unwrap_err();
        assert_eq!(err, NetworkServiceError::QueueFull);
    }

    #[test]
    fn ns_7_shutdown_idempotent() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, _tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(4), a, ta);
        svc.connect_peer(b).unwrap();
        svc.shutdown();
        svc.shutdown();
        assert_eq!(svc.state(), NetworkServiceState::Stopped);
        assert_eq!(svc.peer_count(), 0);
        assert!(svc.drain_inbound().is_empty());
    }

    #[test]
    fn ns_8_stopped_service_rejects_new_work() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, _tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(4), a, ta);
        svc.connect_peer(b).unwrap();
        svc.shutdown();
        assert_eq!(
            svc.enqueue_outbound(b, signed_env(ka.signing_key(), MessageType::Ping, vec![0])),
            Err(NetworkServiceError::Stopped)
        );
        assert_eq!(svc.connect_peer(b), Err(NetworkServiceError::Stopped));
        assert_eq!(svc.poll_transport(), Err(NetworkServiceError::Stopped));
        assert_eq!(svc.flush_outbound(), Err(NetworkServiceError::Stopped));
    }

    #[test]
    fn ns_9_consensus_message_classification() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(16), a, ta);
        svc.connect_peer(b).unwrap();
        for mt in [
            MessageType::ConsensusVote,
            MessageType::ConsensusProposal,
            MessageType::ConsensusQc,
        ] {
            let env = signed_env(kb.signing_key(), mt, vec![0xEE; 4]);
            deliver_b_to_a(&mut tb, a, &env);
            svc.poll_transport().unwrap();
            let ev = svc.drain_inbound().pop().expect("事件");
            assert_eq!(ev.message_type(), mt);
        }
    }

    #[test]
    fn ns_10_gossip_message_classification() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(16), a, ta);
        svc.connect_peer(b).unwrap();
        for mt in [MessageType::GossipTransaction, MessageType::GossipBlock] {
            let env = signed_env(kb.signing_key(), mt, vec![0xDD; 4]);
            deliver_b_to_a(&mut tb, a, &env);
            svc.poll_transport().unwrap();
            let ev = svc.drain_inbound().pop().expect("事件");
            assert_eq!(ev.message_type(), mt);
        }
    }

    #[test]
    fn ns_11_sync_message_classification() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut svc = NetworkService::new(cfg(16), a, ta);
        svc.connect_peer(b).unwrap();
        for mt in [
            MessageType::SyncBlockRequest,
            MessageType::SyncBlockResponse,
        ] {
            let env = signed_env(kb.signing_key(), mt, vec![0xCC; 4]);
            deliver_b_to_a(&mut tb, a, &env);
            svc.poll_transport().unwrap();
            let ev = svc.drain_inbound().pop().expect("事件");
            assert_eq!(ev.message_type(), mt);
        }
    }
}
