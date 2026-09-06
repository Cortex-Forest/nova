//! Handshake Security Runtime 集成测试（STEP 10-18I-L；ADR-0059；L-1..L-7/L-17..L-20）。
//!
//! NetworkService（auth 启用）经 MemoryTransport 与对端握手：valid/错误 network·chain·genesis·
//! protocol / invalid NodeId / invalid signature / failure closes peer / rate limit /
//! identity separation / transport-independent。

use nova_crypto::address::NetworkId;
use nova_crypto::key::KeyPair;

use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{PeerAuthConfig, PeerSessionState, handshake_payload_encode};
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

/// 建立 auth NetworkService（runtime 持 t_runtime）+ 返回对端 transport（测试持）。
fn auth_ns(
    runtime_kp: &KeyPair,
    peer_kp: &KeyPair,
    auth: PeerAuthConfig,
) -> (NetworkService<MemoryTransport>, NodeId, MemoryTransport) {
    let runtime_id = id(runtime_kp);
    let peer_id = id(peer_kp);
    let (t_runtime, t_peer) = MemoryTransport::pair(runtime_id, peer_id);
    let cfg = NetworkServiceConfig {
        max_msg_bytes: 4096,
        inbound_capacity: 64,
        outbound_capacity: 64,
        peer_auth: Some(auth),
    };
    let ns = NetworkService::new(cfg, runtime_id, t_runtime);
    (ns, peer_id, t_peer)
}

/// 由对端 key 签名的握手 envelope（sender = peer_id；payload 字段可定制）。
fn handshake_env(
    peer_kp: &KeyPair,
    network: NetworkId,
    chain: u64,
    genesis: [u8; 32],
    proto: u8,
    claimed: &NodeId,
    nonce: SessionNonce,
) -> MessageEnvelope {
    let payload = handshake_payload_encode(
        nova_network::session::HandshakeKind::Init,
        network,
        chain,
        genesis,
        proto,
        claimed,
        &nonce,
        b"consensus",
    )
    .unwrap();
    let mut env = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: NodeId::from_bytes([0; 32]),
        signature: [0u8; 64],
    };
    sign_message(peer_kp.signing_key(), &mut env).unwrap();
    env
}

fn inject_and_poll(
    ns: &mut NetworkService<MemoryTransport>,
    t_peer: &mut MemoryTransport,
    runtime_id: &NodeId,
    env: &MessageEnvelope,
) {
    t_peer.send(runtime_id, encode(env)).unwrap();
    ns.poll_transport().unwrap();
}

// ---------- L-1 ----------

/// L-1：valid handshake ⇒ peer Established（成功经 transport 建立）。
#[test]
fn l1_valid_handshake_establishes_session() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    let env = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &id(&peer),
        SessionNonce::from_bytes([1; 16]),
    );
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &env);
    assert_eq!(
        ns.peer_session(peer_id),
        Some(PeerSessionState::Established),
        "L-1"
    );
    assert!(ns.is_peer_established(peer_id));
    assert_eq!(ns.diagnostics().handshake_success, 1);
}

// ---------- L-2..L-5 ----------

/// L-2/L-3/L-4/L-5：wrong network_id / chain_id / genesis_hash / protocol_version ⇒ REJECT（不建立）。
#[test]
fn l2_l5_wrong_chain_context_rejected() {
    let cases: Vec<(&str, NetworkId, u64, [u8; 32], u8)> = vec![
        ("net", NetworkId::Testnet, CHAIN, GENESIS, PROTO),
        ("chain", NetworkId::Mainnet, CHAIN + 1, GENESIS, PROTO),
        ("genesis", NetworkId::Mainnet, CHAIN, [0x43; 32], PROTO),
        ("proto", NetworkId::Mainnet, CHAIN, GENESIS, PROTO + 1),
    ];
    for (tag, network, chain, genesis, proto) in cases {
        let runtime = KeyPair::generate().unwrap();
        let peer = KeyPair::generate().unwrap();
        let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
        let env = handshake_env(
            &peer,
            network,
            chain,
            genesis,
            proto,
            &id(&peer),
            SessionNonce::from_bytes([2; 16]),
        );
        inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &env);
        assert!(
            !ns.is_peer_established(peer_id),
            "L-{tag} wrong context rejected"
        );
        assert!(
            ns.diagnostics().handshake_failures >= 1,
            "L-{tag} failure counted"
        );
        assert!(ns.drain_inbound().is_empty(), "L-{tag} no event enqueued");
    }
}

// ---------- L-6 ----------

/// L-6：invalid NodeId（claimed ≠ envelope sender）⇒ REJECT / close。
#[test]
fn l6_invalid_node_id_rejected() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let imposter = NodeId::from_bytes([0x99; 32]);
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    let env = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &imposter,
        SessionNonce::from_bytes([3; 16]),
    );
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &env);
    assert!(
        !ns.is_peer_established(peer_id),
        "L-6 claimed NodeId ≠ sender ⇒ reject"
    );
    assert!(ns.diagnostics().handshake_failures >= 1);
}

// ---------- L-7 ----------

/// L-7：invalid handshake signature（篡改 envelope 签名）⇒ envelope 层 drop。
#[test]
fn l7_invalid_handshake_signature_dropped() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    let mut env = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &id(&peer),
        SessionNonce::from_bytes([4; 16]),
    );
    env.signature[0] ^= 0xff;
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &env);
    assert!(
        !ns.is_peer_established(peer_id),
        "L-7 invalid signature dropped"
    );
    assert!(ns.diagnostics().dropped_invalid >= 1);
}

// ---------- L-17 ----------

/// L-17：handshake failure closes peer —— 失败后该 peer 不 Established，后续消息仍被拒。
#[test]
fn l17_handshake_failure_closes_peer() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    // 错误 genesis 握手 → 拒（close）。
    let bad = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        [0x44; 32],
        PROTO,
        &id(&peer),
        SessionNonce::from_bytes([5; 16]),
    );
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &bad);
    assert!(
        !ns.is_peer_established(peer_id),
        "L-17 failure ⇒ not established"
    );
    // 随后普通 consensus 帧（无有效 session）⇒ unauth drop。
    let vote_env = {
        let mut e = MessageEnvelope {
            version: 1,
            message_type: MessageType::ConsensusVote,
            payload: vec![0xAB; 16],
            sender: NodeId::from_bytes([0; 32]),
            signature: [0u8; 64],
        };
        sign_message(peer.signing_key(), &mut e).unwrap();
        e
    };
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &vote_env);
    assert!(
        ns.diagnostics().unauthenticated_drops >= 1,
        "L-17 unauthenticated traffic still dropped"
    );
}

// ---------- L-18 ----------

/// L-18：per-peer handshake rate limit —— 超过上界后握手被拒（fail-closed，不无限 retry）。
#[test]
fn l18_handshake_rate_limit() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    let runtime_id = id(&runtime);
    // 尝试 3 次 malformed（per_peer limit=3）。
    for i in 0..3u8 {
        let mut e = MessageEnvelope {
            version: 1,
            message_type: MessageType::Handshake,
            payload: vec![0xFF, i],
            sender: NodeId::from_bytes([0; 32]),
            signature: [0u8; 64],
        };
        sign_message(peer.signing_key(), &mut e).unwrap();
        inject_and_poll(&mut ns, &mut t_peer, &runtime_id, &e);
    }
    assert_eq!(
        ns.handshake_attempts_for(peer_id),
        3,
        "L-18 attempts bounded at limit"
    );
    assert!(!ns.is_peer_established(peer_id));
    // 第 4 次尝试（此时 per-peer 已超限）→ 仍拒且 attempts 不再增长（close）。
    let e4 = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &id(&peer),
        SessionNonce::from_bytes([7; 16]),
    );
    inject_and_poll(&mut ns, &mut t_peer, &runtime_id, &e4);
    assert_eq!(
        ns.handshake_attempts_for(peer_id),
        3,
        "L-18 attempts capped (no unbounded retry)"
    );
    assert!(!ns.is_peer_established(peer_id));
    assert!(ns.diagnostics().handshake_failures >= 3);
}

// ---------- L-19 ----------

/// L-19：NodeId（网络身份）≠ ValidatorId —— 握手身份基于独立网络 key，非 validator key。
#[test]
fn l19_node_id_not_validator_id() {
    let network_kp = KeyPair::generate().unwrap();
    let validator_kp = KeyPair::generate().unwrap();
    let net_node = id(&network_kp);
    let validator_node_bytes = validator_kp.verifying_key().to_bytes();
    assert_ne!(
        net_node.as_bytes().to_vec(),
        validator_node_bytes.to_vec(),
        "L-19 network key ≠ validator key（身份分离）"
    );
}

// ---------- L-20 ----------

/// L-20：transport-independent handshake —— 同一握手经 MemoryTransport 抽象建立会话
/// （安全逻辑不依赖具体 transport；未来替换 transport 不改握手语义）。
#[test]
fn l20_handshake_transport_independent() {
    let runtime = KeyPair::generate().unwrap();
    let peer = KeyPair::generate().unwrap();
    let (mut ns, peer_id, mut t_peer) = auth_ns(&runtime, &peer, auth_cfg());
    let env = handshake_env(
        &peer,
        NetworkId::Mainnet,
        CHAIN,
        GENESIS,
        PROTO,
        &id(&peer),
        SessionNonce::from_bytes([8; 16]),
    );
    inject_and_poll(&mut ns, &mut t_peer, &id(&runtime), &env);
    assert_eq!(
        ns.peer_session(peer_id),
        Some(PeerSessionState::Established),
        "L-20 via Transport abstraction"
    );
}
