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
use crate::session::{
    PeerAuthConfig, PeerSessionState, ReplayCache, ReplayKey, handshake_payload_decode,
    validate_handshake_context,
};
use crate::transport::{BoxTransport, ConnectionDialer, Transport};
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
    /// peer-auth / handshake / session / replay（ADR-0059；STEP 10-18I-L）。
    /// `None` = 关闭（保持既有行为，不与 NS-INV 冲突）。
    pub peer_auth: Option<PeerAuthConfig>,
}

impl Default for NetworkServiceConfig {
    fn default() -> Self {
        Self {
            max_msg_bytes: 1024 * 1024,
            inbound_capacity: 1024,
            outbound_capacity: 1024,
            peer_auth: None,
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
    /// 握手尝试总数（STEP 10-18I-L；ADR-0059）。
    pub handshake_attempts: u64,
    /// 握手成功数。
    pub handshake_success: u64,
    /// 握手失败数（身份 / 链上下文 / 结构 / 速率）。
    pub handshake_failures: u64,
    /// replay 检测丢弃数。
    pub replay_drops: u64,
    /// 未认证（非 Established session）消息丢弃数。
    pub unauthenticated_drops: u64,
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
    /// 尝试 outbound dial 但本服务未注入 dialer。
    DialerUnavailable,
    /// single-active connection：已有 connected peer（不静默替换在用 transport）。
    AlreadyConnected,
    /// outbound dial 失败（transport 错误透传；不标记 connected / 不自动 retry）。
    Dial(NetworkError),
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
            Self::DialerUnavailable => write!(f, "no connection dialer injected"),
            Self::AlreadyConnected => write!(f, "already connected (single active)"),
            Self::Dial(e) => write!(f, "outbound dial failed: {e}"),
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

/// 单次 poll 中每个 dial connection 处理的帧数上界（bounded/fairness；非无限 drain）。
const MAX_FRAMES_PER_CONNECTION: usize = 16;

/// NetworkService（网络状态 owner；同步；无共识语义）。
///
/// 连接模型（STEP 10-19-10-B7-A1-D7-Implementation-1）：
/// - `transport`：外部注入的 transport（预建；单连接 / 测试 / dev 注入；peer 关联经
///   PeerManager/session；`transport()` accessor 保留供 EventLoop/测试驱动）。
/// - `connections`：dial 建立的 per-peer connections（multi-peer；key = NodeId —— canonical
///   connection owner；NodeId ≠ SocketAddr）。
/// - poll = 注入 transport（drain）+ 每条 connections（NodeId bytes 序、bounded、per-peer 隔离）。
pub struct NetworkService<T: Transport> {
    state: NetworkServiceState,
    /// 外部注入的 transport（预建；见模块 doc）。
    transport: T,
    /// dial 建立的 per-peer connections（NodeId → transport；KEEP-FIRST）。
    connections: HashMap<NodeId, T>,
    peers: PeerManager,
    inbound: BoundedQueue<NetworkEvent>,
    outbound: BoundedQueue<(NodeId, MessageEnvelope)>,
    config: NetworkServiceConfig,
    diagnostics: NetworkDiagnostics,
    /// peer-auth 配置（ADR-0059/STEP 10-18I-L；`None` = 关闭 gate）。
    auth: Option<PeerAuthConfig>,
    /// peer → session state（NetworkService owns；EventLoop 不决定认证）。
    sessions: HashMap<NodeId, PeerSessionState>,
    /// per-peer 握手尝试计数（rate limit）。
    handshake_attempts: HashMap<NodeId, u32>,
    /// 全局握手尝试计数。
    global_handshake_attempts: u32,
    /// bounded replay cache（握手去重；FIFO 驱逐）。
    replay: ReplayCache,
    /// 本端网络身份锚（dial 首包 local / 未来 sender 校验）。
    self_id: NodeId,
    /// 可选 outbound dialer（NetworkService 拥有 connection lifecycle；None = 无 dial 能力）。
    dialer: Option<Box<dyn ConnectionDialer>>,
}

impl<T: Transport> NetworkService<T> {
    /// 构造（Running）。`self_id` = 本节点网络身份（供 outbound envelope sender 校验/诊断；
    /// 私钥不进入本服务）。
    pub fn new(config: NetworkServiceConfig, self_id: NodeId, transport: T) -> Self {
        let replay_capacity = config
            .peer_auth
            .map(|a| a.replay_cache_capacity)
            .unwrap_or(0);
        Self {
            state: NetworkServiceState::Running,
            transport,
            connections: HashMap::new(),
            peers: PeerManager::new(),
            inbound: BoundedQueue::new(config.inbound_capacity),
            outbound: BoundedQueue::new(config.outbound_capacity),
            config,
            diagnostics: NetworkDiagnostics::default(),
            auth: config.peer_auth,
            sessions: HashMap::new(),
            handshake_attempts: HashMap::new(),
            global_handshake_attempts: 0,
            replay: ReplayCache::new(replay_capacity),
            self_id,
            dialer: None,
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

    // ---------- peer-auth / session 观察（ADR-0059；STEP 10-18I-L） ----------

    /// peer 当前 session 状态（auth 模式；无记录 = 未认证 / 已关闭）。
    pub fn peer_session(&self, node: NodeId) -> Option<PeerSessionState> {
        self.sessions.get(&node).copied()
    }

    /// peer 是否 Established（允许承载 authenticated 流量）。
    pub fn is_peer_established(&self, node: NodeId) -> bool {
        matches!(
            self.sessions.get(&node),
            Some(PeerSessionState::Established)
        )
    }

    /// 当前 Established peers（确定性：NodeId canonical bytes 升序；session owner = NetworkService）。
    /// 供 Node 层编排核对：authenticated peer 集合 vs configured target（identity match）。
    pub fn established_peers(&self) -> Vec<NodeId> {
        let mut peers: Vec<NodeId> = self
            .sessions
            .iter()
            .filter(|(_, s)| **s == PeerSessionState::Established)
            .map(|(id, _)| *id)
            .collect();
        peers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        peers
    }

    /// per-peer 握手尝试数（诊断 / rate 观察）。
    pub fn handshake_attempts_for(&self, node: NodeId) -> u32 {
        self.handshake_attempts.get(&node).copied().unwrap_or(0)
    }

    /// 本服务拥有的 transport（可变；供 EventLoop/测试直接驱动）。
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    /// 注入 outbound dialer（builder seam；不改 `new` 注入语义）。
    ///
    /// 仅 `NetworkService<BoxTransport>` 特化的 [`Self::dial_peer`] 使用；`None` =
    /// `dial_peer` 报 [`NetworkServiceError::DialerUnavailable`]。
    pub fn with_dialer(mut self, dialer: Box<dyn ConnectionDialer>) -> Self {
        self.dialer = Some(dialer);
        self
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
        // STEP 10-18I-L：断连 ⇒ 会话关闭（session/rate 状态清理；replay cache 保留防跨会话重放）。
        self.sessions.remove(&node);
        self.handshake_attempts.remove(&node);
        // multi-peer：仅移除该 peer 的 dial connection（不影响其它 peer；注入 transport 保留）。
        self.connections.remove(&node);
        Ok(())
    }

    pub fn remove_peer(&mut self, node: NodeId) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        self.peers.remove(node);
        // STEP 10-18I-L：移除 ⇒ 会话关闭（session/rate 状态清理；replay cache 保留）。
        self.sessions.remove(&node);
        self.handshake_attempts.remove(&node);
        self.connections.remove(&node);
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
        // STEP 10-18I-M：auth 启用时仅 Established 对端可收（未认证/关闭 ⇒ 拒发，防串发）；
        // Handshake 例外 —— 握手本就是建立认证的消息，允许发给未认证对端。
        if self.auth.is_some()
            && !self.is_peer_established(peer)
            && envelope.message_type != MessageType::Handshake
        {
            return Err(NetworkServiceError::PeerNotConnected);
        }
        self.outbound
            .push_back((peer, envelope))
            .map_err(|_| NetworkServiceError::QueueFull)
    }

    /// 广播（auth 启用时仅 Established peers；peer 过滤有界）。部分满 ⇒ `Err(QueueFull)`。
    pub fn broadcast(&mut self, envelope: MessageEnvelope) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let connected = self.peers.connected_peers();
        let peers: Vec<NodeId> = if self.auth.is_some() {
            connected
                .into_iter()
                .filter(|p| self.is_peer_established(*p))
                .collect()
        } else {
            connected
        };
        for peer in &peers {
            self.outbound
                .push_back((*peer, envelope.clone()))
                .map_err(|_| NetworkServiceError::QueueFull)?;
        }
        Ok(peers.len())
    }

    /// 排空 outbound：编码 envelope → **per-peer 路由**（dial connection 或注入 transport）。
    /// 返回成功发送数。
    pub fn flush_outbound(&mut self) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let mut sent = 0usize;
        while let Some((peer, envelope)) = self.outbound.pop_front() {
            let bytes = encode(&envelope);
            // 路由：peer 在 dial connections ⇒ 用该 peer 的 transport；否则注入 transport
            // （单连接注入模型；TcpTransport 会校验 peer==remote 防串发）。
            let res = if let Some(conn) = self.connections.get_mut(&peer) {
                conn.send(&peer, bytes)
            } else {
                self.transport.send(&peer, bytes)
            };
            match res {
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

    /// **单次** poll：注入 transport（drain；既有单连接语义）→ 每条 dial connection
    /// （NodeId bytes 字典序；每连接 bounded；per-peer 错误隔离）。非永久 loop；无 async。
    ///
    /// 对每条可用帧：decode → validate(sender/signature) → classify → inbound queue。
    /// 返回成功入队数；invalid 帧 drop + 计数（不 panic、不进共识）。
    pub fn poll_transport(&mut self) -> Result<usize, NetworkServiceError> {
        self.ensure_running()?;
        let mut accepted = 0usize;
        // 1. 注入 transport（兼容既有注入/测试语义）。
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
        // 2. dial connections：确定性 NodeId 序；每连接 bounded（fairness）；单 peer 错误隔离。
        let mut conn_peers: Vec<NodeId> = self.connections.keys().copied().collect();
        conn_peers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for peer in conn_peers {
            let frames: Vec<(NodeId, Vec<u8>)> = {
                let Some(conn) = self.connections.get_mut(&peer) else {
                    continue;
                };
                let mut out = Vec::new();
                for _ in 0..MAX_FRAMES_PER_CONNECTION {
                    match conn.try_recv() {
                        Ok(Some(f)) => out.push(f),
                        Ok(None) => break,
                        Err(_) => break, // per-peer isolation：跳过该 peer，继续其它
                    }
                }
                out
            };
            for (raw_sender, bytes) in frames {
                self.diagnostics.frames_received += 1;
                if self.handle_inbound_frame(raw_sender, &bytes) {
                    accepted += 1;
                }
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
        // 4. peer-auth / session gate（ADR-0059；`auth` 启用时）：
        //    Handshake → 握手处理（身份 / 链上下文 / 速率 / replay → 建 Established session）；
        //    其它消息 → 仅 Established session 允许（否则 fail-closed drop，不进入 classify）。
        if let Some(auth) = self.auth {
            if envelope.message_type == MessageType::Handshake {
                return self.process_handshake(auth, envelope.sender, &envelope.payload);
            }
            if !self.is_peer_established(envelope.sender) {
                self.diagnostics.unauthenticated_drops += 1;
                return false;
            }
        }
        // 5. classify → NetworkEvent（payload opaque；不解析共识语义）。
        let event = classify(&envelope);
        // 6. bounded inbound；满 ⇒ drop + overflow 计数（consensus/gossip/sync/block 一致策略）。
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

    /// 入站握手处理（ADR-0059/STEP 10-18I-L；NetworkService owns session）。
    /// 成功 ⇒ peer 置 `Established` + 入队 `NetworkEvent::Handshake`；
    /// 任何失败 ⇒ fail-closed（drop + 计数）；身份 / 链上下文 / 速率失败 ⇒ 关闭 peer session。
    fn process_handshake(&mut self, auth: PeerAuthConfig, sender: NodeId, payload: &[u8]) -> bool {
        self.diagnostics.handshake_attempts += 1;
        // STEP 10-18I-M：已 Established 的 peer 再次握手 ⇒ 确定性拒绝（先到连接胜出；
        // reconnect 必须先 remove/disconnect 清 session）。
        if self.is_peer_established(sender) {
            self.diagnostics.replay_drops += 1;
            return false;
        }
        self.global_handshake_attempts += 1;
        // 速率：全局上界。
        if self.global_handshake_attempts > auth.global_handshake_limit {
            self.diagnostics.handshake_failures += 1;
            self.close_peer(sender);
            return false;
        }
        // 速率：per-peer 上界（不无限 retry；达到上界后后续尝试不再增长计数）。
        let attempts = self.handshake_attempts.entry(sender).or_insert(0);
        if *attempts >= auth.per_peer_handshake_limit {
            self.diagnostics.handshake_failures += 1;
            self.close_peer(sender);
            return false;
        }
        *attempts += 1;
        // 结构 decode。
        let decoded = match handshake_payload_decode(payload) {
            Ok(d) => d,
            Err(_) => {
                self.diagnostics.handshake_failures += 1;
                self.close_peer(sender);
                return false;
            }
        };
        // 身份：claimed NodeId == envelope sender（sender 已由 verify_message 保证 == vk 派生）。
        if decoded.claimed_node_id != sender {
            self.diagnostics.handshake_failures += 1;
            self.close_peer(sender);
            return false;
        }
        // 链上下文：network / chain / genesis / protocol（错误链 = REJECT / close）。
        if validate_handshake_context(&decoded, &auth).is_err() {
            self.diagnostics.handshake_failures += 1;
            self.close_peer(sender);
            return false;
        }
        // replay：同 (peer, nonce) 握手已记录 ⇒ drop（不重复建立 / 不占 cache 之外空间）。
        let key = ReplayKey {
            peer: sender,
            nonce: decoded.session_nonce,
        };
        if !self.replay.insert(key) {
            self.diagnostics.replay_drops += 1;
            return false;
        }
        // 成功：Established + 入队 Handshake event。
        self.sessions.insert(sender, PeerSessionState::Established);
        self.diagnostics.handshake_success += 1;
        match self.inbound.push_back(NetworkEvent::Handshake {
            sender,
            payload: payload.to_vec(),
        }) {
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

    /// 关闭 peer session（fail-closed；会话移除 + 断开 = 非 Established，不再承载流量）。
    fn close_peer(&mut self, node: NodeId) {
        self.sessions.remove(&node);
        self.peers.disconnect(node);
    }

    // ---------- lifecycle ----------

    /// Shutdown：idempotent。置 Stopped + 清理队列；不接受新 work / 不再 peer op。
    /// 绝不触碰 ConsensusState / ValidatorActor / SafetyStore。
    pub fn shutdown(&mut self) {
        self.state = NetworkServiceState::Stopped;
        self.inbound.clear();
        self.outbound.clear();
        self.peers = PeerManager::new();
        self.connections.clear();
        // STEP 10-18I-L：会话 / replay / rate 状态清理（NetworkService owns network session state）。
        self.sessions.clear();
        self.handshake_attempts.clear();
        self.global_handshake_attempts = 0;
        self.replay = ReplayCache::new(0);
    }

    fn ensure_running(&self) -> Result<(), NetworkServiceError> {
        if self.state == NetworkServiceState::Running {
            Ok(())
        } else {
            Err(NetworkServiceError::Stopped)
        }
    }
}

impl NetworkService<BoxTransport> {
    /// 建立一条 outbound connection（**multi-peer**；STEP 10-19-10-B7-A1-D7-Implementation-1）。
    ///
    /// 成功顺序（§dial success）：`dialer.dial`（真实建连）→ 成功后才登记 `connections[remote]`
    /// + `connected`。**绝不先标记 connected 再 dial**。
    ///
    /// 错误语义：
    /// - remote 已有 dial connection ⇒ `Err(AlreadyConnected)`（KEEP-FIRST；不覆盖）。
    /// - 无注入 dialer ⇒ `Err(DialerUnavailable)`。
    /// - dial 失败 ⇒ `Err(Dial(NetworkError))`：**不登记 connected / 不建 fake session /
    ///   不自动 retry / 不自动选 peer**。
    ///
    /// 只到 `Connected`：**不做 handshake / nonce / auth / Established**（后续 STEP）。
    pub fn dial_peer(
        &mut self,
        addr: std::net::SocketAddr,
        remote: NodeId,
        max_frame: usize,
        idle_timeout: Option<std::time::Duration>,
    ) -> Result<(), NetworkServiceError> {
        self.ensure_running()?;
        // KEEP-FIRST：同 NodeId 已有 dial connection ⇒ 拒绝（不覆盖；防连接替换/替身）。
        if self.connections.contains_key(&remote) {
            return Err(NetworkServiceError::AlreadyConnected);
        }
        let local = self.self_id;
        let conn = {
            let dialer = self
                .dialer
                .as_ref()
                .ok_or(NetworkServiceError::DialerUnavailable)?;
            dialer
                .dial(addr, local, remote, max_frame, idle_timeout)
                .map_err(NetworkServiceError::Dial)?
        };
        // dial 成功后才登记（原子：connections insert + PeerManager connected）。
        self.connections.insert(remote, BoxTransport::new(conn));
        self.peers.connect(remote);
        Ok(())
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
            peer_auth: None,
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

    // ---------- STEP 10-19-10-B7-A1-D7-Implementation-1：multi-peer connection set ----------

    /// 可观测 fake connection：rx（对端→NS 入站帧）+ sent（NS→对端记录）。
    #[derive(Default)]
    struct Spec {
        rx: std::collections::VecDeque<(NodeId, Vec<u8>)>,
        sent: Vec<(NodeId, Vec<u8>)>,
    }

    struct FakeConn {
        spec: std::rc::Rc<std::cell::RefCell<Spec>>,
    }

    impl Transport for FakeConn {
        fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
            self.spec.borrow_mut().sent.push((*peer, message));
            Ok(())
        }
        fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
            Ok(self.spec.borrow_mut().rx.pop_front())
        }
    }

    /// fake dialer：per-remote 一条 FakeConn（测试可 seed 入站帧 / 观察出站）。
    #[derive(Clone)]
    struct FakeDialer {
        specs: std::rc::Rc<
            std::cell::RefCell<
                std::collections::HashMap<NodeId, std::rc::Rc<std::cell::RefCell<Spec>>>,
            >,
        >,
    }

    impl FakeDialer {
        fn new() -> Self {
            Self {
                specs: std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new())),
            }
        }
        fn spec(&self, remote: NodeId) -> std::rc::Rc<std::cell::RefCell<Spec>> {
            self.specs.borrow_mut().entry(remote).or_default().clone()
        }
        fn push_inbound(&self, remote: NodeId, sender: NodeId, bytes: Vec<u8>) {
            self.spec(remote).borrow_mut().rx.push_back((sender, bytes));
        }
        fn sent_len(&self, remote: NodeId) -> usize {
            self.spec(remote).borrow().sent.len()
        }
    }

    impl ConnectionDialer for FakeDialer {
        fn dial(
            &self,
            _target_addr: std::net::SocketAddr,
            _local: NodeId,
            remote: NodeId,
            _max_frame: usize,
            _idle_timeout: Option<std::time::Duration>,
        ) -> Result<Box<dyn Transport>, NetworkError> {
            Ok(Box::new(FakeConn {
                spec: self.spec(remote),
            }))
        }
    }

    fn fake_addr() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// dial 型 service：注入空闲 MemoryTransport（poll 首段恒空）+ fake dialer。
    fn dial_svc(a: NodeId, dialer: FakeDialer) -> NetworkService<BoxTransport> {
        let (mem_a, _) = MemoryTransport::pair(a, NodeId::from_bytes([0xfe; 32]));
        NetworkService::<BoxTransport>::new(cfg(256), a, BoxTransport::new(Box::new(mem_a)))
            .with_dialer(Box::new(dialer))
    }

    /// peer 签名的 Ping 帧（payload = 单 byte tag）；返回 (sender, encoded)。
    fn ping_frame(signing: &nova_crypto::signature::SigningKey, tag: u8) -> (NodeId, Vec<u8>) {
        let env = signed_env(signing, MessageType::Ping, vec![tag]);
        (env.sender, encode(&env))
    }

    // T6 — poll：dial connections 按 NodeId bytes 字典序轮询；per-peer 路由无串扰；组内 FIFO。
    #[test]
    fn d7_1_poll_multi_connection_ordered_and_routed() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let kc = KeyPair::generate().unwrap();
        let a = NodeId::from_verifying_key(ka.verifying_key());
        let b = NodeId::from_verifying_key(kb.verifying_key());
        let c = NodeId::from_verifying_key(kc.verifying_key());
        let dialer = FakeDialer::new();
        for tag in [0u8, 1, 2] {
            let (s, bytes) = ping_frame(kb.signing_key(), tag);
            dialer.push_inbound(b, s, bytes);
        }
        let (cs, cbytes) = ping_frame(kc.signing_key(), 9);
        dialer.push_inbound(c, cs, cbytes);
        let mut svc = dial_svc(a, dialer);
        svc.dial_peer(fake_addr(), b, 4096, None).unwrap();
        svc.dial_peer(fake_addr(), c, 4096, None).unwrap();
        assert_eq!(svc.poll_transport().unwrap(), 4, "四条帧全部入站");
        let evs = svc.drain_inbound();
        assert_eq!(evs.len(), 4);
        let seq: Vec<(NodeId, u8)> = evs
            .iter()
            .map(|e| match e {
                NetworkEvent::Ping { sender, payload } => (*sender, payload[0]),
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        // 顺序 = NodeId bytes 序（较小者先）；组内 FIFO（b tags 0,1,2 保持）。
        let (first, second) = if b.as_bytes() < c.as_bytes() {
            (b, c)
        } else {
            (c, b)
        };
        let (first_tags, second_tags): (Vec<u8>, Vec<u8>) = if first == b {
            (vec![0, 1, 2], vec![9])
        } else {
            (vec![9], vec![0, 1, 2])
        };
        assert_eq!(seq.len(), first_tags.len() + second_tags.len(), "全帧分组");
        for (i, t) in first_tags.iter().enumerate() {
            assert_eq!(seq[i], (first, *t), "first-ordered connection 组内 FIFO");
        }
        for (i, t) in second_tags.iter().enumerate() {
            let n = first_tags.len() + i;
            assert_eq!(seq[n], (second, *t), "second-ordered connection 组内 FIFO");
        }
    }

    // T7 — poll bounded + fairness：每 connection 每 poll ≤16 帧（不无限 drain / 不饿死其它 peer）。
    #[test]
    fn d7_1_poll_bounded_per_connection_fair() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let kc = KeyPair::generate().unwrap();
        let a = NodeId::from_verifying_key(ka.verifying_key());
        let b = NodeId::from_verifying_key(kb.verifying_key());
        let c = NodeId::from_verifying_key(kc.verifying_key());
        let dialer = FakeDialer::new();
        for tag in 0u8..20 {
            let (s, bytes) = ping_frame(kb.signing_key(), tag);
            dialer.push_inbound(b, s, bytes);
        }
        for tag in 100u8..120 {
            let (s, bytes) = ping_frame(kc.signing_key(), tag);
            dialer.push_inbound(c, s, bytes);
        }
        let mut svc = dial_svc(a, dialer);
        svc.dial_peer(fake_addr(), b, 4096, None).unwrap();
        svc.dial_peer(fake_addr(), c, 4096, None).unwrap();
        // 每 connection 16 帧上界：两连接共 32（非 40）—— bounded。
        assert_eq!(svc.poll_transport().unwrap(), 32, "bounded 16/connection");
        // 剩余各 4 帧第二轮收完。
        assert_eq!(svc.poll_transport().unwrap(), 8, "剩余公平收完");
    }

    // T8 — flush：enqueue_outbound(peer) 只经该 peer 的 connection 发送（per-peer 路由）。
    #[test]
    fn d7_1_flush_routes_to_peer_connection() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let kc = KeyPair::generate().unwrap();
        let a = NodeId::from_verifying_key(ka.verifying_key());
        let b = NodeId::from_verifying_key(kb.verifying_key());
        let c = NodeId::from_verifying_key(kc.verifying_key());
        let dialer = FakeDialer::new();
        let mut svc = dial_svc(a, dialer.clone());
        svc.dial_peer(fake_addr(), b, 4096, None).unwrap();
        svc.dial_peer(fake_addr(), c, 4096, None).unwrap();
        let env = signed_env(ka.signing_key(), MessageType::Ping, vec![0xAB]);
        svc.enqueue_outbound(b, env).unwrap();
        assert_eq!(svc.flush_outbound().unwrap(), 1);
        assert_eq!(dialer.sent_len(b), 1, "b 的帧走 b connection");
        assert_eq!(dialer.sent_len(c), 0, "不串到 c connection");
    }

    // T9 — disconnect：只影响单 peer（connection/session 移除；其它 connection 保留可用）。
    #[test]
    fn d7_1_disconnect_isolates_single_peer() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let kc = KeyPair::generate().unwrap();
        let a = NodeId::from_verifying_key(ka.verifying_key());
        let b = NodeId::from_verifying_key(kb.verifying_key());
        let c = NodeId::from_verifying_key(kc.verifying_key());
        let dialer = FakeDialer::new();
        let mut svc = dial_svc(a, dialer.clone());
        svc.dial_peer(fake_addr(), b, 4096, None).unwrap();
        svc.dial_peer(fake_addr(), c, 4096, None).unwrap();
        assert_eq!(svc.connected_peer_count(), 2);
        svc.disconnect_peer(b).unwrap();
        assert!(!svc.is_connected(b), "b 已断连");
        assert!(svc.is_connected(c), "c 不受影响");
        assert_eq!(svc.connected_peer_count(), 1);
        // b 已断（仍 registered）⇒ 拒发 PeerNotConnected；c 正常收发。
        let env_b = signed_env(ka.signing_key(), MessageType::Ping, vec![0x01]);
        assert_eq!(
            svc.enqueue_outbound(b, env_b),
            Err(NetworkServiceError::PeerNotConnected)
        );
        let env_c = signed_env(ka.signing_key(), MessageType::Ping, vec![0x02]);
        svc.enqueue_outbound(c, env_c).unwrap();
        assert_eq!(svc.flush_outbound().unwrap(), 1);
        assert_eq!(dialer.sent_len(b), 0, "断连后不再发 b");
        assert_eq!(dialer.sent_len(c), 1);
        // 断连后可重建 dial（KEEP-FIRST 不阻挡 reconnect）。
        assert!(svc.dial_peer(fake_addr(), b, 4096, None).is_ok());
        assert!(svc.is_connected(b));
    }
}
