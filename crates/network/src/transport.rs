//! Transport 抽象（STEP 9-3 — ADR-0032 N-3）。
//!
//! - [`Transport`] trait：`send` / `try_recv`（消息帧 = 已编码 envelope bytes）。
//! - [`MemoryTransport`]：内存 1:1 通道对（测试 / 单节点）。
//! - **libp2p / QUIC / Noise / Kademlia / Gossipsub 暂不引入**（N-3：先冻结协议，不绑定实现；
//!   未来 adapter 不破坏上层协议）。

use crate::message::NetworkError;
use crate::node_id::NodeId;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// 内存邮箱（1:1 通道端点）。
#[derive(Clone)]
struct Mailbox {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn push(&self, bytes: Vec<u8>) {
        self.queue.lock().expect("mailbox lock").push_back(bytes);
    }

    fn pop(&self) -> Option<Vec<u8>> {
        self.queue.lock().expect("mailbox lock").pop_front()
    }
}

/// 传输层抽象（ADR-0032 N-3）。
pub trait Transport {
    /// 向 peer 发送一条已编码消息。
    fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError>;

    /// 非阻塞接收下一条 `(发送者, 消息)`；无消息 ⇒ `Ok(None)`。
    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError>;
}

/// 内存传输（测试 / 单节点；1:1 通道对）。
pub struct MemoryTransport {
    id: NodeId,
    peer_id: NodeId,
    /// 发送到 peer 的 inbox。
    outbox: Mailbox,
    /// 接收 peer 的消息。
    inbox: Mailbox,
}

impl MemoryTransport {
    /// 建立一对互连的传输端点（A↔B）。
    pub fn pair(a: NodeId, b: NodeId) -> (Self, Self) {
        let ab = Mailbox::new();
        let ba = Mailbox::new();
        (
            Self {
                id: a,
                peer_id: b,
                outbox: ba.clone(),
                inbox: ab.clone(),
            },
            Self {
                id: b,
                peer_id: a,
                outbox: ab,
                inbox: ba,
            },
        )
    }

    /// 本端 NodeId。
    pub fn id(&self) -> NodeId {
        self.id
    }
}

impl Transport for MemoryTransport {
    fn send(&mut self, _peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
        self.outbox.push(message);
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        Ok(self.inbox.pop().map(|m| (self.peer_id, m)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn memory_transport_bidirectional() {
        let (mut a, mut b) = MemoryTransport::pair(nid(0xaa), nid(0xbb));
        assert_eq!(a.try_recv().unwrap(), None, "初始无消息");
        // A → B
        a.send(&nid(0xbb), vec![1, 2, 3]).unwrap();
        let (from, msg) = b.try_recv().unwrap().expect("B 收到 A 消息");
        assert_eq!(from, nid(0xaa));
        assert_eq!(msg, vec![1, 2, 3]);
        // B → A
        b.send(&nid(0xaa), vec![9, 9]).unwrap();
        let (from, msg) = a.try_recv().unwrap().expect("A 收到 B 消息");
        assert_eq!(from, nid(0xbb));
        assert_eq!(msg, vec![9, 9]);
        // 队列空
        assert_eq!(a.try_recv().unwrap(), None);
        assert_eq!(b.try_recv().unwrap(), None);
    }

    #[test]
    fn memory_transport_preserves_order() {
        let (mut a, mut b) = MemoryTransport::pair(nid(0xaa), nid(0xbb));
        for i in 0..5 {
            a.send(&nid(0xbb), vec![i]).unwrap();
        }
        for i in 0..5 {
            let (_, msg) = b.try_recv().unwrap().expect("order");
            assert_eq!(msg, vec![i], "FIFO 顺序");
        }
    }
}

// ===== STEP 10-18I-M：Production Transport（同步 std::net TCP；ADR-0059 secure transport）=====
//
// - `TcpTransport`：单对端 1:1 同步 TCP（dial 或 accept 侧），实现 `Transport` trait
//   （bytes only；不解析 envelope/共识）。无 async runtime；无第三方网络库（std::net）。
// - frame = `len(4B LE) ‖ payload`；`len ≤ max_frame`（拒绝超限/畸形；不无限 read）。
// - 连接身份首包：dial 方 connect 后先写 32B 自身 NodeId；accept 方读 32B 得对端身份
//   （transport 级 peer association；握手后由 NetworkService 以 envelope sender 复核）。
// - 读：blocking + `read_timeout`（轮询粒度）；无数据 ⇒ `Ok(None)`；idle 超时 ⇒ 关闭。
// - 写：blocking `write_all` + `write_timeout`（防挂死）。任何 io 失败 ⇒ closed（fail-closed）。

use std::collections::VecDeque as _StdVecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// transport frame：`len(4B LE) ‖ payload`；`len ≤ max_frame`（拒绝超限）。
pub fn frame_encode(payload: &[u8], max_frame: usize) -> Result<Vec<u8>, NetworkError> {
    if payload.len() > max_frame {
        return Err(NetworkError::FrameTooLarge {
            max: max_frame,
            actual: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从 read buffer 解析尽可能多的完整帧到 `out`（不足帧保留；超限 ⇒ Err，fail-closed）。
fn frame_decode_buf(
    buf: &mut Vec<u8>,
    max_frame: usize,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), NetworkError> {
    loop {
        if buf.len() < 4 {
            return Ok(());
        }
        let len = u32::from_le_bytes(buf[..4].try_into().expect("len>=4 checked")) as usize;
        if len > max_frame {
            return Err(NetworkError::FrameTooLarge {
                max: max_frame,
                actual: len,
            });
        }
        if buf.len() < 4 + len {
            return Ok(());
        }
        out.push(buf[4..4 + len].to_vec());
        buf.drain(..4 + len);
    }
}

/// 单对端同步 TCP transport（生产；std::net）。
pub struct TcpTransport {
    stream: TcpStream,
    local: NodeId,
    remote: NodeId,
    max_frame: usize,
    read_buf: Vec<u8>,
    frames: _StdVecDeque<Vec<u8>>,
    idle_timeout: Option<Duration>,
    last_activity: Instant,
    closed: bool,
}

impl TcpTransport {
    /// 默认单次读轮询超时（blocking read 粒度）。
    pub const DEFAULT_READ_POLL: Duration = Duration::from_millis(10);
    /// 默认写超时（防挂死）。
    pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
    /// 默认 connect 超时。
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// 连接身份首包长度（dialer NodeId，32B）。
    pub const NODE_ID_HEADER_LEN: usize = 32;

    fn new(
        stream: TcpStream,
        local: NodeId,
        remote: NodeId,
        max_frame: usize,
        read_poll: Duration,
        write_timeout: Duration,
        idle_timeout: Option<Duration>,
    ) -> Self {
        let _ = stream.set_read_timeout(Some(read_poll));
        let _ = stream.set_write_timeout(Some(write_timeout));
        let _ = stream.set_nodelay(true);
        Self {
            stream,
            local,
            remote,
            max_frame,
            read_buf: Vec::with_capacity(8192),
            frames: _StdVecDeque::new(),
            idle_timeout,
            last_activity: Instant::now(),
            closed: false,
        }
    }

    /// 本端 NodeId。
    pub fn local_id(&self) -> NodeId {
        self.local
    }

    /// 对端 NodeId（dial = 目标；accept = dialer 首包）。
    pub fn peer_id(&self) -> NodeId {
        self.remote
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// 主动连接（dial）。connect 后写 32B 本端 NodeId 首包。
    pub fn dial(
        addr: SocketAddr,
        local: NodeId,
        remote: NodeId,
        max_frame: usize,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, NetworkError> {
        let stream = TcpStream::connect_timeout(&addr, Self::DEFAULT_CONNECT_TIMEOUT)
            .map_err(|_| NetworkError::TransportIo)?;
        let mut t = Self::new(
            stream,
            local,
            remote,
            max_frame,
            Self::DEFAULT_READ_POLL,
            Self::DEFAULT_WRITE_TIMEOUT,
            idle_timeout,
        );
        t.stream
            .write_all(local.as_bytes())
            .map_err(|_| NetworkError::TransportIo)?;
        Ok(t)
    }

    /// 接受一条连接（server）。阻塞读 32B dialer NodeId 首包后完成。
    pub fn accept(
        listener: &TcpListener,
        local: NodeId,
        max_frame: usize,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, NetworkError> {
        let (stream, _peer_addr) = listener.accept().map_err(|_| NetworkError::TransportIo)?;
        let mut t = Self::new(
            stream,
            local,
            NodeId::from_bytes([0; 32]),
            max_frame,
            Self::DEFAULT_READ_POLL,
            Self::DEFAULT_WRITE_TIMEOUT,
            idle_timeout,
        );
        let mut head = [0u8; Self::NODE_ID_HEADER_LEN];
        t.stream
            .read_exact(&mut head)
            .map_err(|_| NetworkError::TransportIo)?;
        t.remote = NodeId::from_bytes(head);
        Ok(t)
    }

    /// 主动关闭（shutdown + 标记 closed；幂等）。
    pub fn close(&mut self) {
        if !self.closed {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.closed = true;
        }
    }

    /// 单次非阻塞读轮询：读入 read_buf → 解析完整帧；无新帧 ⇒ `false`。
    fn poll_read(&mut self) -> Result<bool, NetworkError> {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    // 对端关闭（EOF）⇒ 关闭本端。
                    self.closed = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.last_activity = Instant::now();
                    self.read_buf.extend_from_slice(&chunk[..n]);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => {
                    // 读错误（连接重置等）⇒ fail-closed 关闭。
                    self.closed = true;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
        if self.closed {
            return Err(NetworkError::TransportIo);
        }
        if peer != &self.remote {
            // 只允许发给本连接关联的对端（防串发）。
            return Err(NetworkError::TransportIo);
        }
        if message.len() > self.max_frame {
            return Err(NetworkError::FrameTooLarge {
                max: self.max_frame,
                actual: message.len(),
            });
        }
        let frame = frame_encode(&message, self.max_frame)?;
        self.stream
            .write_all(&frame)
            .map_err(|_| NetworkError::TransportIo)?;
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        if self.closed {
            return Ok(None);
        }
        let _ = self.poll_read()?;
        // 解析已读缓冲中的完整帧（超限 ⇒ 关闭 + Err）。
        let mut new_frames = Vec::new();
        if let Err(e) = frame_decode_buf(&mut self.read_buf, self.max_frame, &mut new_frames) {
            self.closed = true;
            return Err(e);
        }
        for f in new_frames {
            self.frames.push_back(f);
        }
        // idle 超时：无新活动超过 idle_timeout ⇒ 关闭（无消息返回）。
        if let Some(idle) = self.idle_timeout
            && self.last_activity.elapsed() > idle
            && self.frames.is_empty()
        {
            self.close();
            return Ok(None);
        }
        Ok(self.frames.pop_front().map(|f| (self.remote, f)))
    }
}

// ===== STEP 10-19-10-B7-A1-D4：NetworkService-owned outbound dial seam =====
//
// - [`ConnectionDialer`]：object-safe outbound connection factory seam（NetworkService 拥有并编排
//   connection lifecycle；**Node 不直接 dial**）。
// - [`TcpDialer`]：真实 TCP dialer —— 内部**复用** `TcpTransport::dial`（不复制 TCP 建连逻辑、
//   不创建第二套 TCP connection implementation、不改 `TcpTransport::dial` 语义）。
// - [`BoxTransport`]：`Box<dyn Transport>` 载体（network 层；dial 产物可装箱进 NetworkService
//   的泛型 transport 槽 —— 仅当 `T = BoxTransport` 时）。
// - 本段只负责 `dial → Connected` 的 connection primitive；**不做 handshake / nonce / auth /
//   bootstrap / reconnect policy**（后续 STEP）。

/// dyn transport 载体（network 层 wrapper；`impl Transport` delegate）。
pub struct BoxTransport(Box<dyn Transport>);

impl BoxTransport {
    pub fn new(inner: Box<dyn Transport>) -> Self {
        Self(inner)
    }
}

impl Transport for BoxTransport {
    fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
        self.0.send(peer, message)
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        self.0.try_recv()
    }
}

/// outbound connection factory seam（object-safe；NetworkService 拥有并调用）。
///
/// 参数复用 `TcpTransport::dial` 的真实签名语义：`addr` = 目标 socket 地址；`local` = 本端
/// NodeId（dial 首包）；`remote` = 对端预期 NodeId（关联身份）；`max_frame` / `idle_timeout` =
/// transport frame / idle 参数。返回已连接 transport（dyn 装箱）。
pub trait ConnectionDialer {
    fn dial(
        &self,
        addr: SocketAddr,
        local: NodeId,
        remote: NodeId,
        max_frame: usize,
        idle_timeout: Option<Duration>,
    ) -> Result<Box<dyn Transport>, NetworkError>;
}

/// 真实 TCP dialer：委托 `TcpTransport::dial`（无状态）。
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

impl ConnectionDialer for TcpDialer {
    fn dial(
        &self,
        addr: SocketAddr,
        local: NodeId,
        remote: NodeId,
        max_frame: usize,
        idle_timeout: Option<Duration>,
    ) -> Result<Box<dyn Transport>, NetworkError> {
        // 复用既有 dial —— 禁止出现第二套 TcpStream::connect。
        Ok(Box::new(TcpTransport::dial(
            addr,
            local,
            remote,
            max_frame,
            idle_timeout,
        )?))
    }
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn nid(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn pair_tcp() -> (
        SocketAddr,
        thread::JoinHandle<Result<TcpTransport, NetworkError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            TcpTransport::accept(&listener, nid(0xbb), 4096, Some(Duration::from_secs(2)))
        });
        (addr, handle)
    }

    #[test]
    fn tcp_roundtrip_and_peer_association() {
        let (addr, server) = pair_tcp();
        let mut a = TcpTransport::dial(addr, nid(0xaa), nid(0xbb), 4096, None).unwrap();
        let b = server.join().unwrap().unwrap();
        // 身份关联：a.remote=bb；b.remote=aa（首包）。
        assert_eq!(a.peer_id(), nid(0xbb));
        assert_eq!(b.peer_id(), nid(0xaa));
        // A → B
        a.send(&nid(0xbb), vec![1, 2, 3]).unwrap();
        let mut b = b;
        let (from, msg) = b.try_recv().unwrap().expect("B recv");
        assert_eq!(from, nid(0xaa));
        assert_eq!(msg, vec![1, 2, 3]);
        // B → A
        b.send(&nid(0xaa), vec![7, 8]).unwrap();
        let (from, msg) = a.try_recv().unwrap().expect("A recv");
        assert_eq!(from, nid(0xbb));
        assert_eq!(msg, vec![7, 8]);
        // 只允许关联对端发送
        assert!(a.send(&nid(0xcc), vec![0]).is_err(), "M-5 only peer send");
    }

    #[test]
    fn tcp_oversized_frame_rejected() {
        let (addr, server) = pair_tcp();
        let mut a = TcpTransport::dial(addr, nid(0xaa), nid(0xbb), 16, None).unwrap();
        let server = server.join().unwrap();
        assert!(
            a.send(&nid(0xbb), vec![0u8; 17]).is_err(),
            "M-3 oversized rejected"
        );
        // server 侧仍存活（未因错误帧而崩）
        assert!(server.is_ok());
    }

    #[test]
    fn frame_roundtrip_ordering() {
        let max = 64;
        let mut frames = Vec::new();
        let mut buf = Vec::new();
        for i in 0..3u8 {
            let f = frame_encode(&[i; 5], max).unwrap();
            buf.extend_from_slice(&f);
        }
        frame_decode_buf(&mut buf, max, &mut frames).unwrap();
        assert_eq!(frames.len(), 3, "M-2/4 frames decoded in order");
        assert_eq!(frames[0], vec![0; 5]);
        // 超限帧 ⇒ Err
        let mut bad = Vec::new();
        bad.extend_from_slice(&(200u32).to_le_bytes());
        assert!(frame_decode_buf(&mut bad, 64, &mut Vec::new()).is_err());
    }

    #[test]
    fn tcp_idle_timeout_closes() {
        let (addr, server) = pair_tcp();
        let mut a = TcpTransport::dial(
            addr,
            nid(0xaa),
            nid(0xbb),
            4096,
            Some(Duration::from_millis(50)),
        )
        .unwrap();
        let _b = server.join().unwrap().unwrap();
        std::thread::sleep(Duration::from_millis(120));
        // idle 超时后 try_recv ⇒ None（连接已关闭标记）。
        assert_eq!(a.try_recv().unwrap(), None);
        assert!(a.is_closed(), "M-20 idle timeout closes");
    }
}
