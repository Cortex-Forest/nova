//! Session Security 集成测试（STEP 10-18I-L；ADR-0059；L-8..L-16）。
//!
//! auth NetworkService：unauthenticated consensus 消息（vote/proposal/QC）拒绝；
//! authenticated（握手后 Established）接受；session 状态迁移；duplicate/replay 拒绝；
//! cross-session replay 隔离；bounded replay cache。

use nova_crypto::address::NetworkId;
use nova_crypto::key::KeyPair;

use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, PeerSessionState, ReplayCache, ReplayKey,
    handshake_payload_encode,
};
use nova_network::transport::{MemoryTransport, Transport};

const CHAIN: u64 = 1001;
const GENESIS: [u8; 32] = [0x42; 32];
const PROTO: u8 = 1;

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

fn auth_ns(
    runtime_kp: &KeyPair,
    peer_kp: &KeyPair,
) -> (NetworkService<MemoryTransport>, NodeId, MemoryTransport) {
    let runtime_id = id(runtime_kp);
    let peer_id = id(peer_kp);
    let (t_runtime, t_peer) = MemoryTransport::pair(runtime_id, peer_id);
    let cfg = NetworkServiceConfig {
        max_msg_bytes: 4096,
        inbound_capacity: 64,
        outbound_capacity: 64,
        peer_auth: Some(auth_cfg()),
    };
    (
        NetworkService::new(cfg, runtime_id, t_runtime),
        peer_id,
        t_peer,
    )
}

fn signed(mt: MessageType, payload: Vec<u8>, key: &KeyPair) -> MessageEnvelope {
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

fn handshake(peer: &KeyPair, nonce: SessionNonce) -> MessageEnvelope {
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &id(peer),
        &nonce,
        b"consensus",
    )
    .unwrap();
    signed(MessageType::Handshake, payload, peer)
}

fn send(
    ns: &mut NetworkService<MemoryTransport>,
    t_peer: &mut MemoryTransport,
    runtime_id: &NodeId,
    env: &MessageEnvelope,
) {
    t_peer.send(runtime_id, encode(env)).unwrap();
    ns.poll_transport().unwrap();
}

// ---------- L-8..L-10 ----------

/// L-8/L-9/L-10：unauthenticated consensus 消息（vote/proposal/QC）⇒ REJECT（fail-closed）。
#[test]
fn l8_l10_unauthenticated_consensus_rejected() {
    for mt in [
        MessageType::ConsensusVote,
        MessageType::ConsensusProposal,
        MessageType::ConsensusQc,
    ] {
        let runtime = KeyPair::generate().unwrap();
        let peer = KeyPair::generate().unwrap();
        let (mut ns, _peer_id, mut t_peer) = auth_ns(&runtime, &peer);
        let runtime_id = id(&runtime);
        let env = signed(mt, vec![0xAB; 24], &peer);
        send(&mut ns, &mut t_peer, &runtime_id, &env);
        assert!(
            ns.diagnostics().unauthenticated_drops >= 1,
            "L-{:?} unauthenticated rejected",
            mt
        );
        assert!(
            ns.drain_inbound().is_empty(),
            "no event for unauthenticated"
        );
    }
}

// ---------- L-11 / L-12 ----------

/// L-11/L-12：握手后 Established；authenticated ConsensusVote 被接受入队。
#[test]
fn l11_l12_authenticated_message_accepted_after_session() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer);
    let runtime_id = id(&runtime);
    // 握手 → Established
    send(
        &mut ns,
        &mut t_peer,
        &runtime_id,
        &handshake(&peer, SessionNonce::from_bytes([1; 16])),
    );
    assert_eq!(
        ns.peer_session(peer_id),
        Some(PeerSessionState::Established),
        "L-12 transition"
    );
    // 清掉握手事件
    let _ = ns.drain_inbound();
    // authenticated vote
    send(
        &mut ns,
        &mut t_peer,
        &runtime_id,
        &signed(MessageType::ConsensusVote, vec![0xCD; 24], &peer),
    );
    let events = ns.drain_inbound();
    assert_eq!(events.len(), 1, "L-11 authenticated accepted");
    assert_eq!(events[0].message_type(), MessageType::ConsensusVote);
}

// ---------- L-13 / L-14 ----------

/// L-13/L-14：duplicate session nonce（同握手重放）⇒ replay rejected（不重复建立/不入队）。
#[test]
fn l13_l14_duplicate_handshake_replay_rejected() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, _peer_id, mut t_peer) = auth_ns(&runtime, &peer);
    let runtime_id = id(&runtime);
    let hs = handshake(&peer, SessionNonce::from_bytes([2; 16]));
    send(&mut ns, &mut t_peer, &runtime_id, &hs);
    assert_eq!(ns.diagnostics().handshake_success, 1);
    let _ = ns.drain_inbound();
    // 重放同一握手（同 nonce）→ replay drop
    send(&mut ns, &mut t_peer, &runtime_id, &hs);
    assert_eq!(
        ns.diagnostics().replay_drops,
        1,
        "L-13/L-14 duplicate replay rejected"
    );
    assert_eq!(
        ns.diagnostics().handshake_success,
        1,
        "no second establishment"
    );
    assert!(ns.drain_inbound().is_empty(), "replay not re-enqueued");
}

// ---------- L-15 ----------

/// L-15：cross-session replay —— 旧 session 的握手（同 peer 同 nonce）在会话关闭重连后仍被拒。
#[test]
fn l15_cross_session_replay_rejected() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer);
    let runtime_id = id(&runtime);
    let hs = handshake(&peer, SessionNonce::from_bytes([3; 16]));
    send(&mut ns, &mut t_peer, &runtime_id, &hs);
    assert_eq!(
        ns.peer_session(peer_id),
        Some(PeerSessionState::Established)
    );
    // 会话关闭（remove/disconnect 模拟断连）；replay cache 保留旧 nonce。
    ns.remove_peer(peer_id).unwrap();
    assert!(ns.peer_session(peer_id).is_none(), "session closed");
    // 重放旧握手（跨 session）→ replay 拒（不因断开而可重用旧 nonce）。
    send(&mut ns, &mut t_peer, &runtime_id, &hs);
    assert_eq!(
        ns.diagnostics().replay_drops,
        1,
        "L-15 cross-session replay rejected"
    );
    assert!(
        ns.peer_session(peer_id).is_none(),
        "not re-established via replay"
    );
}

// ---------- L-16 ----------

/// L-16：bounded replay cache —— 固定容量 FIFO；满则确定性驱逐最旧；不无限增长。
#[test]
fn l16_replay_cache_bounded() {
    let mut cache = ReplayCache::new(2);
    let peer = NodeId::from_bytes([1; 32]);
    let k1 = ReplayKey {
        peer,
        nonce: SessionNonce::from_bytes([1; 16]),
    };
    let k2 = ReplayKey {
        peer,
        nonce: SessionNonce::from_bytes([2; 16]),
    };
    let k3 = ReplayKey {
        peer,
        nonce: SessionNonce::from_bytes([3; 16]),
    };
    assert!(cache.insert(k1.clone()));
    assert!(cache.insert(k2.clone()));
    assert!(
        cache.insert(k3.clone()),
        "capacity eviction is deterministic FIFO"
    );
    assert_eq!(cache.len(), 2, "L-16 bounded");
    assert!(!cache.contains(&k1), "oldest evicted");
    assert!(cache.contains(&k2));
    assert!(cache.contains(&k3));
}
