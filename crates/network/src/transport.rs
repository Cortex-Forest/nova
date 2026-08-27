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
