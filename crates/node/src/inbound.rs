//! D9 Step 7 — Inbound Listener（node-only；ADR-0032 / ADR-0059 复用）。
//!
//! # 职责（单一）
//! 把**入站** TCP 连接接入**既有** `NetworkService`：
//! ```text
//! TcpListener（node 拥有；nonblocking）
//!     → accept（每 step ≤ MAX_ACCEPT_PER_STEP）
//!     → TcpTransport::from_accepted（frozen transport：32B 首包身份关联 + 既有 framing/timeout/EOF）
//!     → BTreeMap<NodeId, TcpTransport>（本模块 multiplex）
//!     → impl Transport（注入 NetworkService 的 transport 槽）
//!     → 既有 NetworkService::poll_transport（decode / verify / handshake / classify）
//! ```
//!
//! # 边界（严格遵守）
//! - **不实现**握手 / 认证 / session / replay / 速率限制 / envelope 校验 —— 全部归既有的
//!   `NetworkService::process_handshake` + `validate_handshake_context` + `ReplayKey`
//!   （本模块只搬字节；`envelope.sender` 强校验仍由 frozen `handle_inbound_frame` 执行）。
//! - **不复制** transport 语义：framing（4B LE 长度前缀）/ `max_frame` / `read_poll` /
//!   `write_timeout` / idle / EOF / closed 全部由 `TcpTransport` 提供（`from_accepted` seam）。
//! - **不做** multiplex 之外的协议：`send` 只按 NodeId 路由到既有连接；无 priority / score /
//!   role / DNS / reconnect policy / peer arbitration。
//! - **无** async / Tokio / 后台线程 / `unsafe`。accept 为 nonblocking + 每 step 有界。
//! - `TcpTransport` 本身仍为 **单对端 1:1**（本模块不改其语义；multiplex 是 node 侧新类型）。
//!
//! # 共享句柄（`Rc<RefCell<..>>`；单线程、非重入）
//! `NodeRuntime` 需要（a）accept、（b）KEEP-FIRST 判定、（c）EOF/超时清理，而注入
//! `NetworkService` 的 transport 已由 service 拥有（`T = BoxTransport`；frozen `sync_dispatch`
//! 依赖该具体类型，不得改动）⇒ 两侧共享同一 `Rc<RefCell<InboundState>>`。
//! 借用纪律：所有 `borrow_mut()` 都在**不调用 `NetworkService`** 的短作用域内完成（本模块内
//! 每个方法自成作用域），故不存在嵌套借用 ⇒ 无 `RefCell` panic 路径。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::rc::Rc;

use nova_network::message::NetworkError;
use nova_network::node_id::NodeId;
use nova_network::transport::{TcpTransport, Transport};

/// 每 step 最多接受的入站连接数（bounded accept；防 accept 洪泛占满 step）。
pub const MAX_ACCEPT_PER_STEP: usize = 4;

/// 并存入站连接上限（达到上限 ⇒ 立即关闭新连接，不注册；不 panic）。
pub const MAX_INBOUND_CONNECTIONS: usize = 64;

/// 每 poll（≈每 step）最多交给 `NetworkService` 的入站帧数。
///
/// 必要性：`NetworkService::poll_transport` 对**注入 transport** 是 `loop { try_recv() }`，
/// **无** per-poll 帧上限（只有 dial connections 有 `MAX_FRAMES_PER_CONNECTION`）⇒ 上限必须由
/// 本 multiplex 自行实施，否则单条恶意连接可无限占用一个 step。
pub const MAX_INBOUND_FRAMES_PER_POLL: usize = 64;

/// 单次 `try_recv` 最多**检视**的连接数（work bound）。
///
/// 必要性：`TcpTransport::try_recv` 的读语义 = blocking + `read_poll`（10ms 轮询粒度；与 frozen
/// dial connections 相同）⇒ 遍历 N 条空闲连接会花费 ≈N×10ms。没有该上限时，64 条连接会让一个
/// step 阻塞 ≈640ms。上限 + `cursor` 轮转 ⇒ 每 step 检视有界、跨 step 公平，且总预算仍由
/// `MAX_INBOUND_FRAMES_PER_POLL` 约束。
pub const MAX_CONNS_POLLED_PER_CALL: usize = 8;

/// 入站 listener 错误（node-local；typed，fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundListenerError {
    /// `TcpListener::bind` 失败（地址占用 / 权限 / 非法地址）。
    Bind,
    /// `set_nonblocking(true)` 失败（无法保证 step 非阻塞 ⇒ 拒绝启用）。
    Nonblocking,
}

/// 入站 listener 观测（只读；node-local，非协议字段）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboundDiagnostics {
    /// 成功注册的入站连接数（累计）。
    pub accepted: u64,
    /// 同一 peer 重复入站连接被拒数（KEEP-FIRST；不替换 / 不迁移 session）。
    pub duplicate_drops: u64,
    /// 超过 `MAX_INBOUND_CONNECTIONS` 被拒数（未注册即关闭）。
    pub overflow_drops: u64,
    /// 32B 身份首包读取失败被拒数（非本协议对端 / 立即断开）。
    pub header_drops: u64,
    /// `accept()` 非 `WouldBlock` 错误数（本 step 停止 accept）。
    pub accept_error_drops: u64,
    /// 检测到 EOF / 读错误 / 已关闭而移除的连接数（累计）。
    pub closed_drops: u64,
    /// 当前并存入站连接数。
    pub connections: usize,
}

/// 连接表键：`NodeId` 字节（`NodeId` 无 `Ord` ⇒ 用 `[u8; 32]` 保证**确定性字典序**，
/// 与 frozen `NetworkService::poll_transport` 对 dial connections 的排序键一致）。
pub(crate) fn peer_key(peer: &NodeId) -> [u8; 32] {
    *peer.as_bytes()
}

/// 共享入站状态（listener + 连接表 + 预算 + 计数）。
struct InboundState {
    listener: Option<TcpListener>,
    local: NodeId,
    max_frame: usize,
    /// 确定性（NodeId 字节字典序）连接表；每 peer 独占一条 `TcpTransport`。
    conns: BTreeMap<[u8; 32], TcpTransport>,
    /// 公平轮询起点（确定性 round-robin；防固定优先级饿死）。
    cursor: usize,
    /// 本 step 已交付帧数（`begin_step` 重置；`try_recv` 超预算即返回 `Ok(None)`）。
    frames_this_step: usize,
    closed: bool,
    accepted: u64,
    duplicate_drops: u64,
    overflow_drops: u64,
    header_drops: u64,
    accept_error_drops: u64,
    closed_drops: u64,
}

impl InboundState {
    /// 有界 accept（≤ `MAX_ACCEPT_PER_STEP`）；返回本 step **新注册**的 peer（NodeId 序）。
    fn accept_bounded(&mut self) -> Vec<NodeId> {
        let mut newly = Vec::new();
        for _ in 0..MAX_ACCEPT_PER_STEP {
            let Some(listener) = self.listener.as_ref() else {
                break;
            };
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // 上限：达到上限 ⇒ 立即关闭、不注册（bounded；不 panic）。
                    if self.conns.len() >= MAX_INBOUND_CONNECTIONS {
                        self.overflow_drops += 1;
                        drop(stream);
                        continue;
                    }
                    match TcpTransport::from_accepted(stream, self.local, self.max_frame, None) {
                        Ok(mut conn) => {
                            let peer = conn.peer_id();
                            let key = peer_key(&peer);
                            // KEEP-FIRST（multiplex 视角）：同 peer 已注册 ⇒ 关闭新连接。
                            if self.conns.contains_key(&key) {
                                conn.close();
                                self.duplicate_drops += 1;
                                continue;
                            }
                            self.conns.insert(key, conn);
                            self.accepted += 1;
                            newly.push(peer);
                        }
                        // 首包（32B dialer NodeId）失败 ⇒ 该连接关闭（stream 已被消费/drop）。
                        Err(_) => self.header_drops += 1,
                    }
                }
                // nonblocking：无待处理连接 ⇒ 立即结束（不阻塞 step）。
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // 其它 accept 错误：本 step 停止 accept（不 fail step；计数观测）。
                Err(_) => {
                    self.accept_error_drops += 1;
                    break;
                }
            }
        }
        newly.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        newly
    }

    /// 移除并返回已关闭（EOF / 读错误）的连接。
    fn sweep_closed(&mut self) -> Vec<NodeId> {
        let closed: Vec<NodeId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.is_closed())
            .map(|(k, _)| NodeId::from_bytes(*k))
            .collect();
        for peer in &closed {
            self.conns.remove(&peer_key(peer));
            self.closed_drops += 1;
        }
        self.normalize_cursor();
        closed
    }

    fn normalize_cursor(&mut self) {
        if self.conns.is_empty() {
            self.cursor = 0;
        } else {
            self.cursor %= self.conns.len();
        }
    }
}

/// 入站 listener 的 node 侧句柄（listener + 连接表 + 观测）；`Clone` 共享同一状态。
#[derive(Clone)]
pub struct InboundListenerState {
    inner: Rc<RefCell<InboundState>>,
}

impl InboundListenerState {
    /// 绑定并启用 nonblocking listener（fail-closed：bind / nonblocking 失败 ⇒ `Err`）。
    ///
    /// `local` = 本节点网络 NodeId（transport 级身份关联；**不等于**认证）；`max_frame` 与
    /// 出站 dial 使用**同一来源**（`NetworkServiceConfig::max_msg_bytes`）⇒ 双向 frame 上限一致。
    pub fn bind(
        addr: SocketAddr,
        local: NodeId,
        max_frame: usize,
    ) -> Result<Self, InboundListenerError> {
        let listener = TcpListener::bind(addr).map_err(|_| InboundListenerError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| InboundListenerError::Nonblocking)?;
        Ok(Self {
            inner: Rc::new(RefCell::new(InboundState {
                listener: Some(listener),
                local,
                max_frame,
                conns: BTreeMap::new(),
                cursor: 0,
                frames_this_step: 0,
                closed: false,
                accepted: 0,
                duplicate_drops: 0,
                overflow_drops: 0,
                header_drops: 0,
                accept_error_drops: 0,
                closed_drops: 0,
            })),
        })
    }

    /// 注入 `NetworkService` 的 multiplex transport（与 `self` 共享同一状态）。
    ///
    /// `fallback`：非入站 peer 仍走**既有注入 transport**（保持既有注入/测试语义不变）。
    pub fn transport(&self, fallback: Option<Box<dyn Transport>>) -> InboundMultiplexTransport {
        InboundMultiplexTransport {
            inner: Rc::clone(&self.inner),
            fallback,
        }
    }

    /// step 边界：重置本 step 帧预算（由 `NodeRuntime::step` 调用；幂等）。
    pub fn begin_step(&self) {
        self.inner.borrow_mut().frames_this_step = 0;
    }

    /// 有界 accept（≤ `MAX_ACCEPT_PER_STEP`）；返回新注册 peer（NodeId 序）。
    pub fn accept_bounded(&self) -> Vec<NodeId> {
        self.inner.borrow_mut().accept_bounded()
    }

    /// 关闭并移除指定 peer 的入站连接（KEEP-FIRST 拒绝 / 握手失败 / 超时）。
    ///
    /// 返回 `true` = 该 peer 原先存在入站连接。
    pub fn drop_peer(&self, peer: NodeId) -> bool {
        let mut st = self.inner.borrow_mut();
        let removed = st.conns.remove(&peer_key(&peer)).is_some();
        if removed {
            st.closed_drops += 1;
            st.normalize_cursor();
        }
        removed
    }

    /// 移除并返回已关闭（EOF / 读错误）的 peer（调用方负责 `NetworkService::disconnect_peer`）。
    pub fn sweep_closed(&self) -> Vec<NodeId> {
        self.inner.borrow_mut().sweep_closed()
    }

    /// 当前是否持有该 peer 的入站连接。
    pub fn contains(&self, peer: NodeId) -> bool {
        self.inner.borrow().conns.contains_key(&peer_key(&peer))
    }

    /// 当前并存入站连接数。
    pub fn connection_count(&self) -> usize {
        self.inner.borrow().conns.len()
    }

    /// 实际绑定地址（`Some` = listener 已启用；测试可用 port 0 获取真实端口）。
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .borrow()
            .listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
    }

    /// 只读观测。
    pub fn diagnostics(&self) -> InboundDiagnostics {
        let st = self.inner.borrow();
        InboundDiagnostics {
            accepted: st.accepted,
            duplicate_drops: st.duplicate_drops,
            overflow_drops: st.overflow_drops,
            header_drops: st.header_drops,
            accept_error_drops: st.accept_error_drops,
            closed_drops: st.closed_drops,
            connections: st.conns.len(),
        }
    }

    /// 关闭 listener 与全部入站连接（幂等；`shutdown` 用）。
    pub fn shutdown(&self) {
        let mut st = self.inner.borrow_mut();
        st.listener = None;
        for (_, conn) in st.conns.iter_mut() {
            conn.close();
        }
        st.conns.clear();
        st.cursor = 0;
        st.closed = true;
    }
}

/// 入站 multiplex transport（实现**既有** `Transport` trait；不改 trait）。
///
/// - `send(peer, ..)`：该 peer 有入站连接 ⇒ 委派该 `TcpTransport`（其自身仍只允许发给关联
///   对端 —— 防串发）；否则回落到 `fallback`（既有注入 transport 语义）。
/// - `try_recv()`：既有注入 transport（优先，保持既有语义）→ 入站连接按 NodeId 字典序
///   round-robin（`cursor`；确定性公平）；单次调用**全局**预算 = `MAX_INBOUND_FRAMES_PER_POLL`。
/// - 单连接错误（EOF / 读错误）**不**向外传播（per-peer 隔离；移除该连接后继续）——避免单条
///   坏连接让 `NetworkService::poll_transport` 整体 `Err`（那会中断 step）。
pub struct InboundMultiplexTransport {
    inner: Rc<RefCell<InboundState>>,
    fallback: Option<Box<dyn Transport>>,
}

impl InboundMultiplexTransport {
    /// 当前并存入站连接数（观测）。
    pub fn connection_count(&self) -> usize {
        self.inner.borrow().conns.len()
    }
}

impl Transport for InboundMultiplexTransport {
    fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
        // 入站连接优先（同 peer 只有一条；frozen `TcpTransport::send` 仍校验 peer == remote）。
        {
            let mut st = self.inner.borrow_mut();
            if let Some(conn) = st.conns.get_mut(&peer_key(peer)) {
                let res = conn.send(peer, message);
                if res.is_err() {
                    // 写失败 ⇒ fail-closed 关闭连接（下次 sweep 清理；不 panic / 不静默保留）。
                    conn.close();
                }
                return res;
            }
        }
        // 非入站 peer：既有注入 transport 语义（无 fallback ⇒ 保持 frozen `TransportIo`）。
        match self.fallback.as_mut() {
            Some(fb) => fb.send(peer, message),
            None => Err(NetworkError::TransportIo),
        }
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        // 1. 既有注入 transport 优先（保持既有语义；不改变其错误传播）。
        if let Some(fb) = self.fallback.as_mut()
            && let Some(frame) = fb.try_recv()?
        {
            self.inner.borrow_mut().frames_this_step += 1;
            return Ok(Some(frame));
        }
        // 2. 预算检查（防单连接/单 step 无界）。
        let mut st = self.inner.borrow_mut();
        if st.closed || st.frames_this_step >= MAX_INBOUND_FRAMES_PER_POLL {
            return Ok(None);
        }
        // 3. 确定性 round-robin（cursor 起点；每连接单次 try_recv）。
        let keys: Vec<[u8; 32]> = st.conns.keys().copied().collect();
        let n = keys.len();
        if n == 0 {
            return Ok(None);
        }
        let start = st.cursor % n;
        let visits = n.min(MAX_CONNS_POLLED_PER_CALL);
        let mut conn_failures: Vec<[u8; 32]> = Vec::new();
        for i in 0..visits {
            let idx = (start + i) % n;
            let key = keys[idx];
            let Some(conn) = st.conns.get_mut(&key) else {
                continue;
            };
            let outcome = conn.try_recv();
            let closed = conn.is_closed();
            if closed {
                // **不在此处移除**：由 `NodeRuntime::step` 的 `sweep_closed()` 统一移除并调用
                // `NetworkService::disconnect_peer`（session / connected 清理）—— 若在此静默移除，
                // runtime 将无法得知该 peer 已断开 ⇒ 残留 stale established/connected。
                continue;
            }
            match outcome {
                Ok(Some(frame)) => {
                    st.cursor = (idx + 1) % n;
                    st.frames_this_step += 1;
                    return Ok(Some(frame));
                }
                Ok(None) => {}
                Err(_) => {
                    // per-peer 隔离：坏连接**不**向 service 传播（不中断 step）；标记关闭后由
                    // sweep 统一回收（`frame_decode_buf` / 读错误路径已置 closed）。
                    conn_failures.push(key);
                }
            }
        }
        for key in conn_failures {
            if let Some(conn) = st.conns.get_mut(&key) {
                conn.close();
            }
        }
        Ok(None)
    }

    fn is_closed(&self) -> bool {
        // 显式 shutdown 才为 closed（注入 transport 槽的 closed 状态不被 NetworkService 消费；
        // 单连接 liveness 由本模块 sweep + `disconnect_peer` 表达）。
        self.inner.borrow().closed
    }
}
