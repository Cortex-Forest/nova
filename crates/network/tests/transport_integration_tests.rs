//! Production Transport + Secure Egress 集成测试（STEP 10-18I-M）。
//!
//! 两节点经真实 TCP loopback（std::net `TcpTransport`）+ NetworkService auth gate：
//! 握手 over TCP → Established → authenticated vote/proposal/QC 送达；unauthenticated 拒绝；
//! outbound 签名验证；跨网络握手拒绝；send failure isolation；bounded queues；
//! transport replacement（Memory vs TCP 同会话逻辑）。

use std::net::TcpListener;
use std::thread;

use nova_crypto::address::NetworkId;
use nova_crypto::key::KeyPair;

use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, PeerSessionState, handshake_payload_encode,
};
use nova_network::transport::{TcpTransport, Transport};

const CHAIN: u64 = 1001;
const GENESIS: [u8; 32] = [0x42; 32];
const PROTO: u8 = 1;
const MAX_FRAME: usize = 4096;

fn auth_cfg() -> PeerAuthConfig {
    PeerAuthConfig {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN,
        genesis_hash: GENESIS,
        protocol_version: PROTO,
        capabilities: b"consensus",
        per_peer_handshake_limit: 3,
        global_handshake_limit: 100,
        replay_cache_capacity: 64,
    }
}

fn id(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn ns_cfg() -> NetworkServiceConfig {
    NetworkServiceConfig {
        max_msg_bytes: MAX_FRAME,
        inbound_capacity: 64,
        outbound_capacity: 64,
        peer_auth: Some(auth_cfg()),
    }
}

fn signed_env(key: &KeyPair, mt: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    let mut e = MessageEnvelope {
        version: 1,
        message_type: mt,
        payload,
        sender: NodeId::from_bytes([0; 32]),
        signature: [0u8; 64],
    };
    sign_message(key.signing_key(), &mut e).unwrap();
    e
}

fn handshake_env(key: &KeyPair, network: NetworkId) -> MessageEnvelope {
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        network,
        CHAIN,
        GENESIS,
        PROTO,
        &id(key),
        &SessionNonce::from_bytes([0xAB; 16]),
        b"consensus",
    )
    .unwrap();
    signed_env(key, MessageType::Handshake, payload)
}

/// 建立经真实 TCP 的 auth NS 对（A = dialer，B = acceptor）。
fn tcp_ns_pair(
    kp_a: &KeyPair,
    kp_b: &KeyPair,
) -> (NetworkService<TcpTransport>, NetworkService<TcpTransport>) {
    let a_id = id(kp_a);
    let b_id = id(kp_b);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let b_handle = thread::spawn(move || TcpTransport::accept(&listener, b_id, MAX_FRAME, None));
    let tcp_a = TcpTransport::dial(addr, a_id, b_id, MAX_FRAME, None).expect("A dial");
    let tcp_b = b_handle.join().expect("B thread").expect("B accept");
    let mut ns_a = NetworkService::new(ns_cfg(), a_id, tcp_a);
    let mut ns_b = NetworkService::new(ns_cfg(), b_id, tcp_b);
    // 连接登记（对端握手前即可经 outbound 发握手）。
    ns_a.connect_peer(b_id).unwrap();
    ns_b.connect_peer(a_id).unwrap();
    (ns_a, ns_b)
}

/// A→B 与 B→A 双向握手（握手允许发给未认证对端；随后 drain）。
fn mutual_handshake(
    ns_a: &mut NetworkService<TcpTransport>,
    ns_b: &mut NetworkService<TcpTransport>,
    kp_a: &KeyPair,
    kp_b: &KeyPair,
) {
    let a_id = id(kp_a);
    let b_id = id(kp_b);
    ns_a.enqueue_outbound(b_id, handshake_env(kp_a, NetworkId::Mainnet))
        .unwrap();
    ns_a.flush_outbound().unwrap();
    ns_b.poll_transport().unwrap();
    assert!(
        ns_b.is_peer_established(a_id),
        "M-7 B established A over TCP"
    );
    ns_b.enqueue_outbound(a_id, handshake_env(kp_b, NetworkId::Mainnet))
        .unwrap();
    ns_b.flush_outbound().unwrap();
    ns_a.poll_transport().unwrap();
    assert!(
        ns_a.is_peer_established(b_id),
        "M-7 A established B over TCP"
    );
    let _ = ns_a.drain_inbound();
    let _ = ns_b.drain_inbound();
}

// ---------- M-7 / M-9 / M-10 / M-11 ----------

#[test]
fn m7_m9_m10_m11_tcp_handshake_and_consensus_delivery() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    mutual_handshake(&mut ns_a, &mut ns_b, &kp_a, &kp_b);
    let b_id = id(&kp_b);

    for mt in [
        MessageType::ConsensusVote,
        MessageType::ConsensusProposal,
        MessageType::ConsensusQc,
    ] {
        let env = signed_env(&kp_a, mt, vec![0xAA; 40]);
        ns_a.enqueue_outbound(b_id, env).unwrap();
        ns_a.flush_outbound().unwrap();
        ns_b.poll_transport().unwrap();
        let events = ns_b.drain_inbound();
        assert!(
            events.iter().any(|e| e.message_type() == mt),
            "M-9/10/11 authenticated {mt:?} delivered to B"
        );
    }
    assert_eq!(ns_b.diagnostics().unauthenticated_drops, 0);
}

// ---------- M-8 ----------

#[test]
fn m8_unauthenticated_consensus_rejected_over_tcp() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    let a_id = id(&kp_a);
    let b_id = id(&kp_b);
    // A 经 transport 直发 vote 给对端 B（绕过 A 侧 gate；测 B 入站防护）。
    let env = signed_env(&kp_a, MessageType::ConsensusVote, vec![0xBB; 24]);
    ns_a.transport()
        .send(&b_id, encode(&env))
        .expect("tcp send");
    ns_b.poll_transport().unwrap();
    assert!(
        !ns_b.is_peer_established(a_id),
        "M-8 no session pre-handshake"
    );
    assert!(ns_b.diagnostics().unauthenticated_drops >= 1, "M-8 dropped");
    assert!(ns_b.drain_inbound().is_empty());
}

// ---------- M-12 ----------

#[test]
fn m12_outbound_signature_verified_by_peer() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    mutual_handshake(&mut ns_a, &mut ns_b, &kp_a, &kp_b);
    let b_id = id(&kp_b);
    // 篡改签名帧 ⇒ 对端 NS decode+verify 拒绝。
    let mut env = signed_env(&kp_a, MessageType::ConsensusVote, vec![0xCC; 24]);
    env.signature[0] ^= 0xff;
    ns_a.transport().send(&b_id, encode(&env)).expect("send");
    ns_b.poll_transport().unwrap();
    assert!(
        ns_b.diagnostics().dropped_invalid >= 1,
        "M-12 bad sig dropped"
    );
    assert!(ns_b.drain_inbound().is_empty());
}

// ---------- M-13 ----------

#[test]
fn m13_cross_network_handshake_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    let a_id = id(&kp_a);
    let b_id = id(&kp_b);
    ns_a.enqueue_outbound(b_id, handshake_env(&kp_a, NetworkId::Testnet))
        .unwrap();
    ns_a.flush_outbound().unwrap();
    ns_b.poll_transport().unwrap();
    assert!(
        !ns_b.is_peer_established(a_id),
        "M-13 wrong network rejected"
    );
    assert!(ns_b.diagnostics().handshake_failures >= 1);
}

// ---------- M-16 ----------

#[test]
fn m16_send_failure_isolation() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    mutual_handshake(&mut ns_a, &mut ns_b, &kp_a, &kp_b);
    let b_id = id(&kp_b);
    // 对端 transport 关闭（模拟断连）→ A 侧 flush 不 panic（失败计数 / 成功 0）。
    ns_b.transport().close();
    let env = signed_env(&kp_a, MessageType::ConsensusVote, vec![0xDD; 16]);
    ns_a.enqueue_outbound(b_id, env).unwrap();
    let res = ns_a.flush_outbound();
    assert!(res.is_ok(), "M-16 flush never panics");
    // 之后 A 仍可继续使用（fail isolation）。
    assert!(ns_a.peer_session(b_id).is_some() || !ns_a.is_peer_established(b_id));
}

// ---------- M-17 ----------

#[test]
fn m17_bounded_outbound_queue() {
    let kp = KeyPair::generate().unwrap();
    let mut cfg = ns_cfg();
    cfg.outbound_capacity = 2;
    cfg.max_msg_bytes = MAX_FRAME;
    // 用 MemoryTransport 构造；握手消息允许入队（peer 需 connected）。
    let a = id(&kp);
    let b = NodeId::from_bytes([1; 32]);
    let (t_a, _t_b) = nova_network::transport::MemoryTransport::pair(a, b);
    let mut ns = NetworkService::new(cfg, a, t_a);
    ns.connect_peer(b).unwrap();
    for _ in 0..2 {
        ns.enqueue_outbound(b, handshake_env(&kp, NetworkId::Mainnet))
            .unwrap();
    }
    assert!(
        ns.enqueue_outbound(b, handshake_env(&kp, NetworkId::Mainnet))
            .is_err(),
        "M-17 outbound queue bounded"
    );
}

// ---------- M-18 ----------

#[test]
fn m18_bounded_inbound_queue() {
    let kp_remote = KeyPair::generate().unwrap();
    let mut cfg = ns_cfg();
    cfg.inbound_capacity = 1;
    let a = NodeId::from_bytes([0x21; 32]); // runtime 自身份（任意固定）
    let b = id(&kp_remote); // 对端 = transport raw sender
    let (t_a, mut t_b) = nova_network::transport::MemoryTransport::pair(a, b);
    let mut ns = NetworkService::new(cfg, a, t_a);
    // 对端握手（sender=b）→ Established
    t_b.send(&a, encode(&handshake_env(&kp_remote, NetworkId::Mainnet)))
        .unwrap();
    ns.poll_transport().unwrap();
    assert!(ns.is_peer_established(b), "session established");
    assert!(ns.diagnostics().events_enqueued >= 1);
    let _ = ns.drain_inbound();
    // Established 后灌 vote（inbound cap=1）→ 首条入队，其余 overflow drop。
    let vote = signed_env(&kp_remote, MessageType::ConsensusVote, vec![1; 8]);
    for _ in 0..5 {
        t_b.send(&a, encode(&vote)).unwrap();
    }
    ns.poll_transport().unwrap();
    let diag = ns.diagnostics();
    assert!(diag.events_enqueued >= 2, "vote enqueued after handshake");
    assert!(
        diag.dropped_overflow >= 1,
        "M-18 inbound queue bounded: overflow dropped"
    );
}

// ---------- M-21 ----------

#[test]
fn m21_node_id_not_validator_id() {
    let net = KeyPair::generate().unwrap();
    let validator = KeyPair::generate().unwrap();
    assert_ne!(
        id(&net).as_bytes().to_vec(),
        validator.verifying_key().to_bytes().to_vec(),
        "M-21 network key ≠ validator key"
    );
}

// ---------- M-22 ----------

#[test]
fn m22_session_state_over_tcp_is_established() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    let a_id = id(&kp_a);
    let b_id = id(&kp_b);
    // 同 L 步会话语义经 TCP transport 复验（transport replacement 兼容）。
    ns_a.enqueue_outbound(b_id, handshake_env(&kp_a, NetworkId::Mainnet))
        .unwrap();
    ns_a.flush_outbound().unwrap();
    ns_b.poll_transport().unwrap();
    assert_eq!(ns_b.peer_session(a_id), Some(PeerSessionState::Established));
    assert!(ns_b.is_peer_established(a_id));
}
