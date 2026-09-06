//! Network Security Primitives 集成测试（STEP 10-18I-K；SEC-P1..SEC-P19）。
//!
//! 验证 ADR-0059 冻结的安全原语：valid/invalid 签名、跨域拒绝（network/chain/genesis/
//! protocol/type）、确定性、NodeId 绑定、payload 上界、handshake commitment、nonce 编码。
//! 只测纯原语 —— 不涉及 NetworkService/EventLoop/Runtime（本阶段未 wire）。

use nova_crypto::key::KeyPair;

use nova_network::message::MessageType;
use nova_network::node_id::NodeId;
use nova_network::security::{
    MAX_NETWORK_MESSAGE_PAYLOAD_BYTES, NetworkMessageSigningContext, NetworkSecurityError,
    RequestId, SessionNonce, handshake_commitment, network_message_signing_digest,
    sign_network_message, verify_network_message, verify_node_identity,
};

fn ctx(
    network: nova_crypto::address::NetworkId,
    chain: u64,
    genesis: [u8; 32],
    proto: u8,
    ty: MessageType,
) -> NetworkMessageSigningContext {
    NetworkMessageSigningContext {
        network_id: network,
        chain_id: chain,
        genesis_hash: genesis,
        protocol_version: proto,
        message_type: ty,
    }
}

const MAIN: nova_crypto::address::NetworkId = nova_crypto::address::NetworkId::Mainnet;
const TEST: nova_crypto::address::NetworkId = nova_crypto::address::NetworkId::Testnet;
const GEN_A: [u8; 32] = [0x42; 32];
const GEN_B: [u8; 32] = [0x43; 32];

// ---------- SEC-P1 / P2 / P3 ----------

/// SEC-P1/P2/P3：valid sign / invalid signature / payload mutation。
#[test]
fn sec_p1_p2_p3_sign_mutation_fail_closed() {
    let kp = KeyPair::generate().unwrap();
    let c = ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusVote);
    let payload = b"vote-wire-1234";
    let sig = sign_network_message(kp.signing_key(), &c, payload).expect("P1 sign");
    verify_network_message(kp.verifying_key(), &c, payload, &sig).expect("P1 valid");

    // P2：篡改签名 ⇒ fail
    let raw = sig.to_bytes();
    let bad = nova_crypto::signature::Signature::from_bytes(&[raw[0] ^ 0xff; 64]).unwrap();
    assert!(
        verify_network_message(kp.verifying_key(), &c, payload, &bad).is_err(),
        "P2"
    );

    // P3：篡改 payload ⇒ fail
    assert!(
        verify_network_message(kp.verifying_key(), &c, b"vote-wire-1235", &sig).is_err(),
        "P3 payload mutation rejected"
    );
}

// ---------- SEC-P4 / P5 ----------

/// SEC-P4/P5：message type / protocol version mutation ⇒ 拒。
#[test]
fn sec_p4_p5_type_and_protocol_mutation() {
    let kp = KeyPair::generate().unwrap();
    let c = ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusVote);
    let payload = b"p";
    let sig = sign_network_message(kp.signing_key(), &c, payload).unwrap();

    let type_mut = ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusProposal);
    assert!(
        verify_network_message(kp.verifying_key(), &type_mut, payload, &sig).is_err(),
        "P4 message_type mutation rejected"
    );
    let proto_mut = ctx(MAIN, 1001, GEN_A, 2, MessageType::ConsensusVote);
    assert!(
        verify_network_message(kp.verifying_key(), &proto_mut, payload, &sig).is_err(),
        "P5 protocol_version mutation rejected"
    );
}

// ---------- SEC-P6 / P7 / P8 ----------

/// SEC-P6/P7/P8：network_id / chain_id / genesis_hash 分离。
#[test]
fn sec_p6_p7_p8_chain_identity_separation() {
    let kp = KeyPair::generate().unwrap();
    let c = ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusVote);
    let payload = b"p";
    let sig = sign_network_message(kp.signing_key(), &c, payload).unwrap();

    assert!(
        verify_network_message(
            kp.verifying_key(),
            &ctx(TEST, 1001, GEN_A, 1, MessageType::ConsensusVote),
            payload,
            &sig
        )
        .is_err(),
        "P6 network_id separation"
    );
    assert!(
        verify_network_message(
            kp.verifying_key(),
            &ctx(MAIN, 1002, GEN_A, 1, MessageType::ConsensusVote),
            payload,
            &sig
        )
        .is_err(),
        "P7 chain_id separation"
    );
    assert!(
        verify_network_message(
            kp.verifying_key(),
            &ctx(MAIN, 1001, GEN_B, 1, MessageType::ConsensusVote),
            payload,
            &sig
        )
        .is_err(),
        "P8 genesis_hash separation"
    );
}

// ---------- SEC-P9 ----------

/// SEC-P9：NodeId mismatch。
#[test]
fn sec_p9_node_id_mismatch() {
    let kp = KeyPair::generate().unwrap();
    let ok = NodeId::from_verifying_key(kp.verifying_key());
    verify_node_identity(&ok, kp.verifying_key()).expect("match");
    let other = NodeId::from_verifying_key(KeyPair::generate().unwrap().verifying_key());
    assert_eq!(
        verify_node_identity(&other, kp.verifying_key()),
        Err(NetworkSecurityError::InvalidNodeId),
        "P9 NodeId mismatch rejected"
    );
}

// ---------- SEC-P10 / P11 / P13 ----------

/// SEC-P10/P11/P13：deterministic encoding / digest；same ctx+payload ⇒ same digest。
#[test]
fn sec_p10_p11_p13_deterministic() {
    let c = ctx(MAIN, 7, GEN_B, 3, MessageType::GossipTransaction);
    let d1 = network_message_signing_digest(&c, b"tx").unwrap();
    let d2 = network_message_signing_digest(&c, b"tx").unwrap();
    assert_eq!(d1, d2, "P10/P11/P13 deterministic");
}

// ---------- SEC-P14 / P15 ----------

/// SEC-P14/P15：same payload different network ⇒ 不同 digest；same network different genesis ⇒ 不同 digest。
#[test]
fn sec_p14_p15_cross_network_and_genesis_digest_differ() {
    let payload = b"p";
    let a = network_message_signing_digest(&ctx(MAIN, 1, GEN_A, 1, MessageType::Ping), payload)
        .unwrap();
    let b = network_message_signing_digest(&ctx(TEST, 1, GEN_A, 1, MessageType::Ping), payload)
        .unwrap();
    assert_ne!(a, b, "P14 cross-network digest differs");
    let g = network_message_signing_digest(&ctx(MAIN, 1, GEN_B, 1, MessageType::Ping), payload)
        .unwrap();
    assert_ne!(a, g, "P15 genesis differs");
}

// ---------- SEC-P16 ----------

/// SEC-P16：signature 无法在另一 context 验证（cross-domain rejection）。
#[test]
fn sec_p16_signature_cannot_verify_across_context() {
    let kp = KeyPair::generate().unwrap();
    let payload = b"shared-payload";
    let sig = sign_network_message(
        kp.signing_key(),
        &ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusVote),
        payload,
    )
    .unwrap();
    for other in [
        ctx(TEST, 1001, GEN_A, 1, MessageType::ConsensusVote),
        ctx(MAIN, 1002, GEN_A, 1, MessageType::ConsensusVote),
        ctx(MAIN, 1001, GEN_B, 1, MessageType::ConsensusVote),
        ctx(MAIN, 1001, GEN_A, 2, MessageType::ConsensusVote),
        ctx(MAIN, 1001, GEN_A, 1, MessageType::ConsensusProposal),
    ] {
        assert!(
            verify_network_message(kp.verifying_key(), &other, payload, &sig).is_err(),
            "P16 cross-context rejected"
        );
    }
}

// ---------- SEC-P12 / P17 ----------

/// SEC-P12/P17：oversized payload / malformed input ⇒ fail-closed（typed error）。
#[test]
fn sec_p12_p17_oversized_and_invalid_input_fail_closed() {
    let c = ctx(MAIN, 1, GEN_A, 1, MessageType::Ping);
    let big = vec![0u8; MAX_NETWORK_MESSAGE_PAYLOAD_BYTES + 1];
    assert!(
        matches!(
            network_message_signing_digest(&c, &big),
            Err(NetworkSecurityError::PayloadTooLarge { .. })
        ),
        "P12 oversized rejected"
    );
    let kp = KeyPair::generate().unwrap();
    assert!(
        sign_network_message(kp.signing_key(), &c, &big).is_err(),
        "P17 oversized sign fails closed"
    );
}

// ---------- SEC-P18 / P19 ----------

/// SEC-P18：handshake commitment determinism + chain binding。
#[test]
fn sec_p18_handshake_commitment() {
    let nonce = SessionNonce::from_bytes([3; 16]);
    let node = NodeId::from_bytes([9; 32]);
    let caps = b"consensus,sync";
    let a = handshake_commitment(MAIN, 1, GEN_A, 1, &node, &nonce, caps).unwrap();
    let b = handshake_commitment(MAIN, 1, GEN_A, 1, &node, &nonce, caps).unwrap();
    assert_eq!(a, b, "P18 deterministic");
    assert_ne!(
        a,
        handshake_commitment(TEST, 1, GEN_A, 1, &node, &nonce, caps).unwrap(),
        "P18 network-bound"
    );
}

/// SEC-P19：session/request nonce canonical encoding helper。
#[test]
fn sec_p19_nonce_encoding() {
    let sn = SessionNonce::from_bytes([1; 16]);
    assert_eq!(sn.as_bytes(), &[1; 16]);
    let rq = RequestId::from_bytes([2; 16]);
    assert_eq!(rq.as_bytes(), &[2; 16]);
    assert_eq!(SessionNonce::LEN, 16);
    assert_eq!(RequestId::LEN, 16);
}
