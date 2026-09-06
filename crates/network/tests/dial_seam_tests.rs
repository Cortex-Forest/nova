//! NetworkService-owned outbound dial seam（STEP 10-19-10-B7-A1-D4）—— 集成测试。
//!
//! 验证 `NetworkService<BoxTransport>::dial_peer` 的 connection lifecycle：
//! dial 成功才 owns transport + 登记 connected；失败不产生虚假 connected / 不自动 retry；
//! single-active 不静默替换；target 正确传递；`TcpDialer` 复用 `TcpTransport::dial`。
//! 只到 `Connected` —— **不做 handshake / auth / Established**（无 process_handshake 调用）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nova_network::message::NetworkError;
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceError};
use nova_network::node_id::NodeId;
use nova_network::transport::{BoxTransport, ConnectionDialer, TcpDialer, Transport};

fn nid(tag: u8) -> NodeId {
    NodeId::from_bytes([tag; 32])
}

fn addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// 测试用哑 transport（无真实通道；dial success 返回它以证明 NS 持有 + 状态，不发公网）。
struct DummyTransport;

impl Transport for DummyTransport {
    fn send(&mut self, _peer: &NodeId, _message: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        Ok(None)
    }
}

/// 测试用 fake dialer：记录目标 + 可配置 success/failure（Arc 共享状态供测试断言）。
struct FakeState {
    success: bool,
    last_addr: Mutex<Option<SocketAddr>>,
    last_remote: Mutex<Option<NodeId>>,
}

struct FakeDialer {
    inner: Arc<FakeState>,
}

impl Clone for FakeDialer {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl FakeDialer {
    fn new(success: bool) -> Self {
        Self {
            inner: Arc::new(FakeState {
                success,
                last_addr: Mutex::new(None),
                last_remote: Mutex::new(None),
            }),
        }
    }
    fn ok() -> Self {
        Self::new(true)
    }
    fn failing() -> Self {
        Self::new(false)
    }
    fn last_addr(&self) -> Option<SocketAddr> {
        *self.inner.last_addr.lock().expect("test lock")
    }
    fn last_remote(&self) -> Option<NodeId> {
        *self.inner.last_remote.lock().expect("test lock")
    }
}

impl ConnectionDialer for FakeDialer {
    fn dial(
        &self,
        target_addr: SocketAddr,
        _local: NodeId,
        remote: NodeId,
        _max_frame: usize,
        _idle_timeout: Option<Duration>,
    ) -> Result<Box<dyn Transport>, NetworkError> {
        *self.inner.last_addr.lock().expect("test lock") = Some(target_addr);
        *self.inner.last_remote.lock().expect("test lock") = Some(remote);
        if self.inner.success {
            Ok(Box::new(DummyTransport))
        } else {
            Err(NetworkError::TransportIo)
        }
    }
}

fn svc_with(fake: FakeDialer) -> NetworkService<BoxTransport> {
    NetworkService::<BoxTransport>::new(
        NetworkServiceConfig::default(),
        nid(0xaa),
        BoxTransport::new(Box::new(DummyTransport)),
    )
    .with_dialer(Box::new(fake))
}

// T1 — existing injection 保留：`NetworkService::new(..., transport)` 仍可构造（本文件各测试即经
// 注入 BoxTransport 构造；现有 MemoryTransport 注入测试由既有测试面覆盖）。

// T2 — dial success ⇒ NetworkService owns transport + 登记 connected
#[test]
fn dial_success_owns_and_marks_connected() {
    let fake = FakeDialer::ok();
    let mut svc = svc_with(fake);
    let target = addr();
    assert!(svc.dial_peer(target, nid(0xbb), 4096, None).is_ok());
    assert!(svc.is_connected(nid(0xbb)), "dial 成功后才登记 connected");
}

// T3 — dial failure ⇒ real error + 不登记 connected
#[test]
fn dial_failure_not_connected() {
    let fake = FakeDialer::failing();
    let mut svc = svc_with(fake);
    let res = svc.dial_peer(addr(), nid(0xbb), 4096, None);
    assert!(
        matches!(res, Err(NetworkServiceError::Dial(_))),
        "真实错误透传"
    );
    assert!(!svc.is_connected(nid(0xbb)), "失败不得登记 connected");
}

// T4 — target propagation：FakeDialer 收到与调用方完全一致的 SocketAddr（与 remote）
#[test]
fn dial_target_propagated_exactly() {
    let fake = FakeDialer::ok();
    let mut svc = svc_with(fake.clone());
    let target = SocketAddr::from(([10, 0, 0, 9], 4321));
    svc.dial_peer(target, nid(0xbb), 4096, None).unwrap();
    assert_eq!(fake.last_addr(), Some(target), "SocketAddr 完全一致");
    assert_eq!(fake.last_remote(), Some(nid(0xbb)), "remote NodeId 一致");
}

// T5 — multi-peer：不同 remote 可同时 connected；同 remote 重复 dial ⇒ KEEP-FIRST
//（STEP 10-19-10-B7-A1-D7-Implementation-1：不再 single-active 全拒）
#[test]
fn dial_multi_peer_keep_first_rejects_duplicate() {
    let fake = FakeDialer::ok();
    let mut svc = svc_with(fake);
    svc.dial_peer(addr(), nid(0xbb), 4096, None).unwrap();
    // 多 peer：不同 remote 允许并行连接。
    svc.dial_peer(addr(), nid(0xcc), 4096, None).unwrap();
    assert!(svc.is_connected(nid(0xbb)));
    assert!(svc.is_connected(nid(0xcc)));
    assert_eq!(svc.connected_peer_count(), 2);
    // KEEP-FIRST：同 remote 再 dial ⇒ AlreadyConnected（不覆盖在用连接）。
    let dup = svc.dial_peer(addr(), nid(0xbb), 4096, None);
    assert_eq!(dup, Err(NetworkServiceError::AlreadyConnected));
    assert!(svc.is_connected(nid(0xbb)), "原连接未被替换");
    assert_eq!(svc.connected_peer_count(), 2, "重复 dial 不新增连接");
}

// — 无 dialer ⇒ DialerUnavailable（明确错误，不 panic / 不假连接）
#[test]
fn dial_without_dialer_rejected() {
    let mut svc = NetworkService::<BoxTransport>::new(
        NetworkServiceConfig::default(),
        nid(0xaa),
        BoxTransport::new(Box::new(DummyTransport)),
    );
    let res = svc.dial_peer(addr(), nid(0xbb), 4096, None);
    assert_eq!(res, Err(NetworkServiceError::DialerUnavailable));
    assert!(!svc.is_connected(nid(0xbb)));
}

// T6/T7 — BoxTransport 兼容 + TcpDialer 复用（真实 TCP 本地回环；不依赖公网）
#[test]
fn tcp_dialer_reuses_tcp_transport_dial() {
    // 本地回环 listener（transport 既有测试同款；127.0.0.1 非公网）。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let laddr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        nova_network::transport::TcpTransport::accept(
            &listener,
            nid(0xbb),
            4096,
            Some(Duration::from_secs(2)),
        )
        .unwrap()
    });
    let dialer = TcpDialer;
    // 经 ConnectionDialer seam 调用 —— 内部复用 TcpTransport::dial（无第二套 connect）。
    let conn = dialer
        .dial(laddr, nid(0xaa), nid(0xbb), 4096, None)
        .expect("dial");
    let srv = server.join().expect("server");
    // transport 级身份关联成立（dial 首包 + accept 读首包）。
    // 通过 NetworkService<BoxTransport> 注入 dialed transport 并登记 connected（T6 编译证明）。
    let mut svc = NetworkService::<BoxTransport>::new(
        NetworkServiceConfig::default(),
        nid(0xaa),
        BoxTransport::new(conn),
    );
    svc.register_peer(nid(0xbb)).unwrap();
    svc.connect_peer(nid(0xbb)).unwrap();
    assert!(svc.is_connected(nid(0xbb)));
    let _ = srv;
}
