//! EventLoop —— 同步单线程 dispatch 层（STEP 10-18F；ADR-0056 EventLoop Architecture v1 —— FROZEN）。
//!
//! # 定位（只 dispatch；不实现共识 / 不拥有状态）
//! EventLoop 只负责：
//! ```text
//! poll（NetworkService） → 收拢事件入队 → dispatch（统一 FIFO） → shutdown
//! ```
//! - 消费已由 [`crate::network_service::NetworkService`] 完成解码/验签/分类的
//!   [`crate::network_service::NetworkEvent`]；**不** decode `MessageEnvelope`、
//!   **不** verify signature、**不** 解析 payload 语义（payload opaque）。
//! - EventLoop **不拥有**：`ConsensusState` / `ConsensusNode` / `ValidatorActor` /
//!   `VoteLedger` / `LockedState` / `SafetyStore` / private key / `SigningCapability` /
//!   `ChainStorage` / PeerManager internal / Transport internal。
//! - 结构性保证：本 crate（`nova-network`）**不依赖** consensus / node / validator / safety
//!   ⇒ EventLoop 无法调用 `verify_vote_input` / `verify_qc` / `acquire_lock` / consensus
//!   transition / `ValidatorActor` / `SafetyStore`（EL-INV-5..8/10 结构性成立；EL-INV-1..4/9）。
//! - 完整 consensus / Driver / outbound wiring 归 **10-18G**；本步只建立 dispatch seam
//!   （[`EventHandler`] trait），EventLoop 不写死任何上层 owner。
//! - 同步、无 async runtime；`poll_once` 为**受控单轮**（不 busy-loop）。
//! - EventLoop 事件队列 **bounded**；满 ⇒ drop incoming + 计数（与 NetworkService 一致策略）。
//! - Timer 只产生 [`TimerEvent`]（事件源）；不 advance consensus / 不产 vote / 不改 finality。
//! - restart 语义：EventLoop 不持久化任何状态；drop 即释放。Validator safety recovery 仍由
//!   `NodeRuntime → SafetyStore → ValidatorActor` 负责（本 crate 不参与）。
//! - EventLoop 只处理 `NodeId`（network identity）；不假设 `one NodeId == one ValidatorId`。

use crate::network_service::{BoundedQueue, NetworkEvent, NetworkService, NetworkServiceError};
use crate::transport::Transport;
use core::fmt;
use std::time::{Duration, Instant};

/// EventLoop 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLoopState {
    Running,
    Stopped,
}

/// EventLoop 配置（队列 / timer 容量均 bounded）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLoopConfig {
    /// EventLoop 自身事件队列容量（bounded；满 ⇒ drop incoming + 计数）。
    pub queue_capacity: usize,
    /// 同步 timer 槽位容量（bounded；防无限增长）。
    pub timer_capacity: usize,
}

impl Default for EventLoopConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            timer_capacity: 256,
        }
    }
}

/// TimerId —— 上层（未来 10-18G Driver）自定义映射的 timer 标识；本层不解释其语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u64);

/// TimerEvent —— 仅「到期」事件源；Timer 不 advance consensus / 不产生 vote / 不改 finality。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerEvent {
    /// 已到期的 timer（携带上层自定义 id）。
    Expired(TimerId),
}

/// InternalEvent —— node-local 内部信号（事件源；不携带共识语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalEvent {
    /// 通用内部唤醒（flush / retry 触发）。
    Wakeup,
}

/// BlockEvent —— block 相关事件源；EventLoop 不执行块 / 不判 finality（决策在上层 BlockHandler）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockEvent {
    /// 新块（本地产生 / 同步获取）；交由上层决定处理方式。
    NewBlock { height: u64 },
}

/// NodeEvent —— 统一事件（EventLoop 队列元素；dispatch 单元）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    Network(NetworkEvent),
    Timer(TimerEvent),
    Internal(InternalEvent),
    Block(BlockEvent),
}

impl NodeEvent {
    /// 事件类别（诊断 / 排序参考；本版统一 FIFO，不实现 QoS）。
    pub fn kind(&self) -> NodeEventKind {
        match self {
            Self::Network(_) => NodeEventKind::Network,
            Self::Timer(_) => NodeEventKind::Timer,
            Self::Internal(_) => NodeEventKind::Internal,
            Self::Block(_) => NodeEventKind::Block,
        }
    }
}

/// 事件类别（见 [`NodeEvent::kind`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEventKind {
    Network,
    Timer,
    Internal,
    Block,
}

/// EventLoop 错误（node-local dispatch 域；fail-safe：不 panic、不改共识）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLoopError {
    /// EventLoop 已停止，拒绝新事件 / poll / timer 操作。
    Stopped,
    /// EventLoop 事件队列已满（caller 侧 push 被拒；inbound 侧 drop + 计数）。
    QueueFull,
    /// 事件非法（本层不做 payload 验证；预留分类，供未来校验 seam）。
    InvalidEvent,
    /// handler 处理失败（dispatch 不中断：记录 `handler_errors` 并继续）。
    HandlerError,
    /// timer 操作失败（槽位满 / 溢出）。
    TimerError,
    /// 网络层错误透传（transport 读 / peer 状态等）。
    Network(NetworkServiceError),
}

impl fmt::Display for EventLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "event loop stopped"),
            Self::QueueFull => write!(f, "event loop queue full"),
            Self::InvalidEvent => write!(f, "invalid event"),
            Self::HandlerError => write!(f, "event handler error"),
            Self::TimerError => write!(f, "timer error"),
            Self::Network(e) => write!(f, "network error: {e}"),
        }
    }
}

impl std::error::Error for EventLoopError {}

/// 诊断计数（queue-full / handler 失败观察；非日志系统）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventLoopDiagnostics {
    /// 已成功 dispatch（handler 返回 Ok）的事件数。
    pub events_dispatched: u64,
    /// 因 EventLoop 队列满而丢弃的事件数（Network/Timer 入队侧）。
    pub events_dropped_overflow: u64,
    /// handler 返回 Err 的次数（dispatch 不中断）。
    pub handler_errors: u64,
    /// 已到期的 timer 数。
    pub timers_expired: u64,
}

/// 同步 timer entry。
#[derive(Debug, Clone, Copy)]
struct TimerEntry {
    id: TimerId,
    deadline: Instant,
}

/// Dispatch seam —— EventLoop 不直接拥有 Driver / consensus / validator。
///
/// 未来 10-18G 由 node 层实现具体 handler（接 Driver / BlockAdapter / outbound）；
/// EventLoop 只通过本 trait 把已分类事件交给上层，**不**替上层做共识决策。
pub trait EventHandler {
    /// 处理一条已分类事件。返回 `Err` 时 EventLoop 记录 `handler_errors` 并继续
    /// （fail-safe：不 panic、不阻塞后续事件）。
    fn handle(&mut self, event: &NodeEvent) -> Result<(), EventLoopError>;
}

/// EventLoop —— 同步单线程 dispatch 层。
///
/// - 拥有 [`NetworkService<T>`]（网络状态 owner；poll 经其方法，不直接碰 Transport/Peer 内部）。
/// - 拥有统一 bounded 事件队列（`VecDeque<NodeEvent>`；deterministic FIFO，本版无 QoS）。
/// - 拥有同步 timer 表（仅到期事件源）。
/// - **不拥有**任何 consensus / validator / safety / key / storage 状态（见模块 doc）。
pub struct EventLoop<T: Transport, H: EventHandler> {
    state: EventLoopState,
    config: EventLoopConfig,
    network: NetworkService<T>,
    handler: H,
    queue: BoundedQueue<NodeEvent>,
    timers: Vec<TimerEntry>,
    diagnostics: EventLoopDiagnostics,
}

impl<T: Transport, H: EventHandler> EventLoop<T, H> {
    /// 构造（Running）。`network` 由本层拥有；`handler` 由调用方注入（dispatch seam）。
    pub fn new(config: EventLoopConfig, network: NetworkService<T>, handler: H) -> Self {
        Self {
            state: EventLoopState::Running,
            config,
            network,
            handler,
            queue: BoundedQueue::new(config.queue_capacity),
            timers: Vec::new(),
            diagnostics: EventLoopDiagnostics::default(),
        }
    }

    pub fn state(&self) -> EventLoopState {
        self.state
    }

    pub fn config(&self) -> EventLoopConfig {
        self.config
    }

    pub fn diagnostics(&self) -> EventLoopDiagnostics {
        self.diagnostics
    }

    /// 底层 NetworkService（只读）。
    pub fn network(&self) -> &NetworkService<T> {
        &self.network
    }

    /// 底层 NetworkService（可变；供 10-18G outbound 注入 / 测试驱动）。
    pub fn network_mut(&mut self) -> &mut NetworkService<T> {
        &mut self.network
    }

    /// 注入的 handler（只读）。
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// 注入的 handler（可变；测试 / 运行时检查）。
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// 当前排队待 dispatch 的事件数（bounded queue 深度）。
    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    // ---------- inbound ----------

    /// 单轮 poll：`NetworkService.poll_transport`（transport → NS inbound）→
    /// 取走 NS inbound → 移入本层 bounded 队列（满 ⇒ drop + 计数）。
    /// 返回成功移入队列的事件数；不做永久 loop（busy-loop 禁止；等待/唤醒归 10-18G）。
    pub fn poll_network(&mut self) -> Result<usize, EventLoopError> {
        self.ensure_running()?;
        // transport → NS inbound（单次 drain；由 NS 完成 decode/验签/classify —— 本层不解析）。
        self.network
            .poll_transport()
            .map_err(EventLoopError::Network)?;
        let events = self.network.drain_inbound();
        let mut moved = 0usize;
        for event in events {
            match self.queue.push_back(NodeEvent::Network(event)) {
                Ok(()) => moved += 1,
                Err(_) => self.diagnostics.events_dropped_overflow += 1,
            }
        }
        Ok(moved)
    }

    /// 使已到期的 timer 到期为 [`TimerEvent`] 并入队（同步；仅事件源）。
    pub fn expire_due_timers(&mut self) -> Result<usize, EventLoopError> {
        self.ensure_running()?;
        let now = Instant::now();
        let mut due = Vec::new();
        let mut remaining = Vec::with_capacity(self.timers.len());
        for entry in self.timers.drain(..) {
            if entry.deadline <= now {
                due.push(entry.id);
            } else {
                remaining.push(entry);
            }
        }
        self.timers = remaining;
        let expired = due.len();
        let mut enqueued = 0usize;
        for id in due {
            match self
                .queue
                .push_back(NodeEvent::Timer(TimerEvent::Expired(id)))
            {
                Ok(()) => enqueued += 1,
                Err(_) => self.diagnostics.events_dropped_overflow += 1,
            }
        }
        self.diagnostics.timers_expired += expired as u64;
        Ok(enqueued)
    }

    /// dispatch 全部排队事件（统一 FIFO；deterministic）。
    /// handler `Err` ⇒ 记录 `handler_errors` 并继续（不中断 / 不 panic）。
    /// 返回成功处理（handler Ok）的事件数。
    pub fn dispatch_queued(&mut self) -> Result<usize, EventLoopError> {
        self.ensure_running()?;
        let mut dispatched = 0u64;
        while let Some(event) = self.queue.pop_front() {
            match self.handler.handle(&event) {
                Ok(()) => dispatched += 1,
                Err(_) => self.diagnostics.handler_errors += 1,
            }
        }
        self.diagnostics.events_dispatched += dispatched;
        Ok(dispatched as usize)
    }

    /// 受控单轮：poll → expire timers → dispatch。返回 dispatch 成功数。
    /// 不做无限 busy-loop；调用方（NodeRuntime / 10-18G）决定轮询节奏与睡眠。
    pub fn poll_once(&mut self) -> Result<usize, EventLoopError> {
        self.poll_network()?;
        self.expire_due_timers()?;
        self.dispatch_queued()
    }

    // ---------- caller-push / timer ----------

    /// caller 侧 push 事件入队（bounded；满 ⇒ `Err(QueueFull)`，由 caller 决定策略）。
    pub fn push_event(&mut self, event: NodeEvent) -> Result<(), EventLoopError> {
        self.ensure_running()?;
        self.queue
            .push_back(event)
            .map_err(|_| EventLoopError::QueueFull)
    }

    /// 注册 / 更新 timer（同步；同 id 覆盖；槽位满 ⇒ `Err(TimerError)`）。
    pub fn set_timer(&mut self, id: TimerId, after: Duration) -> Result<(), EventLoopError> {
        self.ensure_running()?;
        let deadline = Instant::now()
            .checked_add(after)
            .ok_or(EventLoopError::TimerError)?;
        if let Some(entry) = self.timers.iter_mut().find(|e| e.id == id) {
            entry.deadline = deadline;
            return Ok(());
        }
        if self.timers.len() >= self.config.timer_capacity {
            return Err(EventLoopError::TimerError);
        }
        self.timers.push(TimerEntry { id, deadline });
        Ok(())
    }

    /// 取消 timer。返回是否确有一个被取消；不存在 ⇒ `Ok(false)`（幂等）。
    pub fn cancel_timer(&mut self, id: TimerId) -> Result<bool, EventLoopError> {
        self.ensure_running()?;
        let before = self.timers.len();
        self.timers.retain(|e| e.id != id);
        Ok(self.timers.len() != before)
    }

    // ---------- lifecycle ----------

    /// Shutdown：**幂等**。置 Stopped + 清空事件队列 / timer 表 + 关闭 NetworkService。
    /// 停止后：不产生新 vote / 不写 SafetyStore / 不发送 network message / 拒绝 push / poll。
    pub fn shutdown(&mut self) {
        if self.state == EventLoopState::Stopped {
            return;
        }
        self.state = EventLoopState::Stopped;
        self.queue.clear();
        self.timers.clear();
        self.network.shutdown();
    }

    fn ensure_running(&self) -> Result<(), EventLoopError> {
        if self.state == EventLoopState::Running {
            Ok(())
        } else {
            Err(EventLoopError::Stopped)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{MessageType, NetworkError, encode, sign_message};
    use crate::network_service::NetworkServiceState;
    use crate::node_id::NodeId;
    use crate::transport::MemoryTransport;
    use nova_crypto::key::KeyPair;

    // ---------- fixtures ----------

    fn cfg() -> EventLoopConfig {
        EventLoopConfig {
            queue_capacity: 64,
            timer_capacity: 8,
        }
    }

    fn ns_cfg(cap: usize) -> crate::network_service::NetworkServiceConfig {
        crate::network_service::NetworkServiceConfig {
            max_msg_bytes: 4096,
            inbound_capacity: cap,
            outbound_capacity: cap,
        }
    }

    /// 记录所有 dispatch 到的 NodeEvent（顺序保留）。
    #[derive(Default)]
    struct Recorder {
        events: Vec<NodeEvent>,
    }

    impl EventHandler for Recorder {
        fn handle(&mut self, event: &NodeEvent) -> Result<(), EventLoopError> {
            self.events.push(event.clone());
            Ok(())
        }
    }

    /// 始终失败的 handler（验证 dispatch 不中断 + handler_errors 计数）。
    struct Failing;

    impl EventHandler for Failing {
        fn handle(&mut self, _event: &NodeEvent) -> Result<(), EventLoopError> {
            Err(EventLoopError::HandlerError)
        }
    }

    /// transport 读错误（验证 Network 错误透传）。
    struct ErrTransport;

    impl Transport for ErrTransport {
        fn send(&mut self, _peer: &NodeId, _message: Vec<u8>) -> Result<(), NetworkError> {
            Ok(())
        }
        fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
            Err(NetworkError::SenderMismatch)
        }
    }

    /// (A_id, B_id, a_transport, b_transport)。
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
    ) -> crate::message::MessageEnvelope {
        let mut e = crate::message::MessageEnvelope {
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
    fn deliver_b_to_a(
        b_transport: &mut MemoryTransport,
        a_id: NodeId,
        envelope: &crate::message::MessageEnvelope,
    ) {
        b_transport
            .send(&a_id, encode(envelope))
            .expect("memory send");
    }

    // ---------- EL tests ----------

    /// EL-1：NetworkEvent dispatch（完整 inbound 路径：transport → NS 验签/分类 → queue → handler）。
    #[test]
    fn el_1_network_event_dispatch() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut ns = NetworkService::new(ns_cfg(16), a, ta);
        ns.connect_peer(b).unwrap();
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        let env = signed_env(kb.signing_key(), MessageType::Ping, vec![0x42; 4]);
        deliver_b_to_a(&mut tb, a, &env);
        let handled = el.poll_once().unwrap();
        assert_eq!(handled, 1);
        assert_eq!(el.pending_len(), 0);
        let events = &el.handler().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), NodeEventKind::Network);
        assert_eq!(
            events[0],
            NodeEvent::Network(NetworkEvent::Ping {
                sender: b,
                payload: vec![0x42; 4],
            })
        );
        assert_eq!(el.diagnostics().events_dispatched, 1);
    }

    /// EL-2：TimerEvent dispatch（到期 → 事件源 → handler）。
    #[test]
    fn el_2_timer_event_dispatch() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.set_timer(TimerId(7), Duration::ZERO).unwrap();
        let handled = el.poll_once().unwrap();
        assert_eq!(handled, 1);
        let events = &el.handler().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), NodeEventKind::Timer);
        assert_eq!(events[0], NodeEvent::Timer(TimerEvent::Expired(TimerId(7))));
        assert_eq!(el.diagnostics().timers_expired, 1);
    }

    /// EL-3：InternalEvent dispatch（caller push → dispatch）。
    #[test]
    fn el_3_internal_event_dispatch() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.push_event(NodeEvent::Internal(InternalEvent::Wakeup))
            .unwrap();
        let handled = el.poll_once().unwrap();
        assert_eq!(handled, 1);
        let events = &el.handler().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), NodeEventKind::Internal);
        assert_eq!(events[0], NodeEvent::Internal(InternalEvent::Wakeup));
    }

    /// EL-4：BlockEvent dispatch（caller push → dispatch）。
    #[test]
    fn el_4_block_event_dispatch() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.push_event(NodeEvent::Block(BlockEvent::NewBlock { height: 9 }))
            .unwrap();
        let handled = el.poll_once().unwrap();
        assert_eq!(handled, 1);
        let events = &el.handler().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), NodeEventKind::Block);
        assert_eq!(
            events[0],
            NodeEvent::Block(BlockEvent::NewBlock { height: 9 })
        );
    }

    /// EL-5：bounded queue（push 到容量即 QueueFull，不增长）。
    #[test]
    fn el_5_bounded_queue() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let config = EventLoopConfig {
            queue_capacity: 2,
            timer_capacity: 4,
        };
        let mut el = EventLoop::new(config, ns, Recorder::default());
        let ev = NodeEvent::Internal(InternalEvent::Wakeup);
        assert!(el.push_event(ev.clone()).is_ok());
        assert!(el.push_event(ev.clone()).is_ok());
        assert_eq!(el.push_event(ev), Err(EventLoopError::QueueFull));
        assert_eq!(el.pending_len(), 2);
    }

    /// EL-6：queue full（inbound 溢出 → drop incoming + dropped_overflow 计数）。
    #[test]
    fn el_6_queue_full_drops_overflow() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, mut tb) = pair(&ka, &kb);
        let mut ns = NetworkService::new(ns_cfg(8), a, ta);
        ns.connect_peer(b).unwrap();
        let config = EventLoopConfig {
            queue_capacity: 2,
            timer_capacity: 4,
        };
        let mut el = EventLoop::new(config, ns, Recorder::default());
        // 3 条有效入站 → queue cap=2 ⇒ 1 条 overflow drop。
        for i in 0..3u8 {
            let env = signed_env(kb.signing_key(), MessageType::Ping, vec![i]);
            deliver_b_to_a(&mut tb, a, &env);
        }
        let moved = el.poll_network().unwrap();
        assert_eq!(moved, 2);
        assert_eq!(el.pending_len(), 2);
        assert_eq!(el.diagnostics().events_dropped_overflow, 1);
        // dispatch 后 queue 清空；handler 收到 2 条。
        let dispatched = el.dispatch_queued().unwrap();
        assert_eq!(dispatched, 2);
        assert_eq!(el.pending_len(), 0);
        assert_eq!(el.handler().events.len(), 2);
    }

    /// EL-7：shutdown（清空 queue；stopped 状态）。
    #[test]
    fn el_7_shutdown() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.push_event(NodeEvent::Internal(InternalEvent::Wakeup))
            .unwrap();
        el.shutdown();
        assert_eq!(el.state(), EventLoopState::Stopped);
        assert_eq!(el.pending_len(), 0);
        assert_eq!(el.network().state(), NetworkServiceState::Stopped);
    }

    /// EL-8：shutdown 幂等（多次调用安全）。
    #[test]
    fn el_8_shutdown_idempotent() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.shutdown();
        el.shutdown();
        el.shutdown();
        assert_eq!(el.state(), EventLoopState::Stopped);
        assert_eq!(el.pending_len(), 0);
    }

    /// EL-9：stopped 后拒绝新事件 / poll / timer。
    #[test]
    fn el_9_stopped_rejects_work() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        el.shutdown();
        assert_eq!(
            el.push_event(NodeEvent::Internal(InternalEvent::Wakeup)),
            Err(EventLoopError::Stopped)
        );
        assert_eq!(el.poll_network(), Err(EventLoopError::Stopped));
        assert_eq!(
            el.set_timer(TimerId(1), Duration::ZERO),
            Err(EventLoopError::Stopped)
        );
        assert_eq!(el.dispatch_queued(), Err(EventLoopError::Stopped));
    }

    /// EL-10：无 network → consensus direct bypass —— ConsensusVote 事件只 dispatch（payload
    /// opaque，不验签 / 不解析 / 不改共识）；由未来 10-18G handler 决定下游处理。
    #[test]
    fn el_10_consensus_passthrough_no_bypass() {
        let ka = KeyPair::generate().unwrap();
        let kb = KeyPair::generate().unwrap();
        let (a, b, ta, _tb) = pair(&ka, &kb);
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        let payload = vec![0xAA; 8];
        // caller push：ConsensusVote 原样入队 → handler（EventLoop 不做任何 verify）。
        el.push_event(NodeEvent::Network(NetworkEvent::ConsensusVote {
            sender: b,
            payload: payload.clone(),
        }))
        .unwrap();
        let handled = el.poll_once().unwrap();
        assert_eq!(handled, 1);
        let events = &el.handler().events;
        assert_eq!(events.len(), 1);
        match &events[0] {
            NodeEvent::Network(NetworkEvent::ConsensusVote { sender, payload: p }) => {
                assert_eq!(*sender, b);
                // payload opaque：原样透传，EventLoop 不解码 / 不解析。
                assert_eq!(p, &payload);
            }
            other => panic!("expected ConsensusVote passthrough, got {other:?}"),
        }
    }

    /// handler 失败不中断 dispatch（fail-safe；handler_errors 计数）。
    #[test]
    fn el_handler_error_non_fatal() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let mut el = EventLoop::new(cfg(), ns, Failing);
        el.push_event(NodeEvent::Internal(InternalEvent::Wakeup))
            .unwrap();
        el.push_event(NodeEvent::Internal(InternalEvent::Wakeup))
            .unwrap();
        // dispatch 不中断：两条都消费，全部记为 handler 错误。
        let handled = el.dispatch_queued().unwrap();
        assert_eq!(handled, 0);
        assert_eq!(el.pending_len(), 0);
        assert_eq!(el.diagnostics().handler_errors, 2);
    }

    /// transport 读错误透传为 Network 错误（不 panic、不改状态）。
    #[test]
    fn el_network_transport_error() {
        let self_id = NodeId::from_bytes([0u8; 32]);
        let ns = NetworkService::new(ns_cfg(16), self_id, ErrTransport);
        let mut el = EventLoop::new(cfg(), ns, Recorder::default());
        match el.poll_network() {
            Err(EventLoopError::Network(NetworkServiceError::Transport(
                NetworkError::SenderMismatch,
            ))) => {}
            other => panic!("expected network transport error, got {other:?}"),
        }
        // 仍可继续运行（fail-safe）。
        assert_eq!(el.state(), EventLoopState::Running);
    }

    /// timer 槽位 bounded（满 ⇒ TimerError）；cancel 后释放槽位。
    #[test]
    fn el_timer_capacity_and_cancel() {
        let ka = KeyPair::generate().unwrap();
        let (a, _b, ta, _tb) = pair(&ka, &KeyPair::generate().unwrap());
        let ns = NetworkService::new(ns_cfg(16), a, ta);
        let config = EventLoopConfig {
            queue_capacity: 16,
            timer_capacity: 2,
        };
        let mut el = EventLoop::new(config, ns, Recorder::default());
        assert!(el.set_timer(TimerId(1), Duration::from_secs(60)).is_ok());
        assert!(el.set_timer(TimerId(2), Duration::from_secs(60)).is_ok());
        assert_eq!(
            el.set_timer(TimerId(3), Duration::from_secs(60)),
            Err(EventLoopError::TimerError)
        );
        // cancel 释放槽位。
        assert!(el.cancel_timer(TimerId(1)).unwrap());
        assert!(el.set_timer(TimerId(3), Duration::from_secs(60)).is_ok());
        // 不存在的 id：cancel 幂等 false。
        assert!(!el.cancel_timer(TimerId(99)).unwrap());
    }
}
