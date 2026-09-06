//! Node Production Egress Adapter 集成测试（STEP 10-18I-N-IMPL）。
//!
//! # 覆盖（N-IMPL-1..7）
//! - N-IMPL-1：Driver 本地 vote semantic → adapter → 已签名 `MessageEnvelope`
//!   （`ConsensusVote`；sender = 网络 NodeId；网络 key 验签通过）。
//! - N-IMPL-2：`Proposal` semantic → `ConsensusProposal`（canonical 64B ProposalRef payload）。
//! - N-IMPL-3：`VerifiedQc` semantic（Driver 已 `verify_qc` PASS 路径）→ `ConsensusQc` envelope。
//! - N-IMPL-4：TCP end-to-end —— Driver(A) 产 vote → adapter → A NS broadcast（B established）
//!   → 真实 TcpTransport → B NS poll → `ConsensusVote` 送达。
//! - N-IMPL-5：tamper ⇒ fail-closed（envelope 网络签名失效 + 共识签名 verify 拒绝 ——
//!   tamper 不会静默通过 / 不产生任何可接受消息）。
//! - N-IMPL-6：unauthenticated（未握手）⇒ egress data 不可达对方（established-only gate；
//!   对方无 event）。
//! - N-IMPL-7：网络 NodeId ≠ consensus ValidatorId（身份分离）。
//!
//! # 边界
//! - Driver 只产 semantic outbound（验证 PASS 才 record）；adapter 只编码/签名（不 verify）。
//! - B 侧 NS 对 data 是 opaque 分类（consensus verify 在装配层）；本测试聚焦 egress adapter
//!   与投递 gate —— tamper 可检测性由 N-IMPL-5 在 network/consensus 两层直接断言。

use std::net::TcpListener;
use std::thread;

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::encode_qc;
use nova_consensus::integration::TransitionResult;
use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload, verify_vote_input};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::VerifyingKey;

use nova_network::message::{MessageEnvelope, MessageType, sign_message, verify_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceError};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, PeerSessionState, handshake_payload_encode,
};
use nova_network::transport::TcpTransport;

use nova_node::assembly::ConsensusNode;
use nova_node::driver::NodeConsensusDriver;
use nova_node::egress::{encode_semantic, envelope_for};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::outbound::OutboundConsensusMessage;
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_FRAME: usize = 4096;

// ---------- consensus fixtures（复制 driver_tests 单验证者套路） ----------

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 0,
        initial_validator_set: vals,
        initial_accounts: Vec::new(),
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: 100_000_000_000,
            max_contract_code_bytes: 0,
            max_contract_storage_bytes: 0,
            epoch_length_blocks: 1_000_000,
            snapshot_interval_blocks: 10_000_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: 1_000_000_000,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 100,
        },
    }
}

fn actor_of(kp: KeyPair) -> (ValidatorActor<SoftwareSigner>, VerifyingKey) {
    let vk = *kp.verifying_key();
    let id = ValidatorId::from_consensus_public_key(&vk.to_bytes());
    let actor = ValidatorActor::new(id, SoftwareSigner::new(kp), CHAIN_ID).unwrap();
    (actor, vk)
}

fn dag1() -> Dag {
    let mut dag = Dag::new();
    dag.add_block(BlockReference {
        block_hash: [0xAA; 32],
        height: 0,
        parents: vec![],
        proposer: ValidatorId::from_bytes([0xAA; 32]),
    })
    .unwrap();
    dag
}

fn prevote_req(target: [u8; 32]) -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type: VoteType::Prevote,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

fn precommit_req(target: [u8; 32]) -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type: VoteType::Precommit,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

/// 单验证者 driver（consensus key = set 唯一成员；dag 含 AA target）。
/// 返回共识 `VerifyingKey`（owned copy；供静态验签 / 构造同 set 使用）。
fn setup_single() -> (NodeConsensusDriver<SoftwareSigner>, [u8; 32], VerifyingKey) {
    let kp = KeyPair::generate().unwrap();
    let vk = *kp.verifying_key();
    let target = [0xAA; 32];
    let set = ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: vk.to_bytes(),
        bonded_stake: 100,
        commission_bps: 100,
    }]));
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let (actor, _) = actor_of(kp);
    let driver = NodeConsensusDriver::new(consensus, vec![actor]);
    (driver, target, vk)
}

fn submit_proposal_for(driver: &mut NodeConsensusDriver<SoftwareSigner>, target: [u8; 32]) {
    let proposer = driver.actor(0).unwrap().validator_id();
    let r = driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer,
    });
    assert!(
        matches!(r, TransitionResult::Applied { .. }),
        "proposal Applied"
    );
}

/// 让单验证者 driver 走到 prevote，返回其 semantic vote outbound（consensus key 签名）。
fn driver_local_prevote() -> (NodeConsensusDriver<SoftwareSigner>, ValidatorVote, [u8; 64]) {
    let (mut driver, target, _cons_vk) = setup_single();
    submit_proposal_for(&mut driver, target);
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("prevote 提交");
    let outbound = driver.take_outbound();
    let (vote, signature) = outbound
        .into_iter()
        .find_map(|m| match m {
            OutboundConsensusMessage::Vote { vote, signature } => Some((vote, signature)),
            _ => None,
        })
        .expect("driver 本地 prevote semantic outbound");
    (driver, vote, signature)
}

// ---------- 网络 fixtures（复制 network transport_integration 套路） ----------

fn net_id(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn auth_cfg() -> PeerAuthConfig {
    PeerAuthConfig {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
        protocol_version: 1,
        capabilities: b"consensus",
        per_peer_handshake_limit: 3,
        global_handshake_limit: 100,
        replay_cache_capacity: 64,
    }
}

fn ns_cfg() -> NetworkServiceConfig {
    NetworkServiceConfig {
        max_msg_bytes: MAX_FRAME,
        inbound_capacity: 64,
        outbound_capacity: 64,
        peer_auth: Some(auth_cfg()),
    }
}

fn handshake_env(key: &KeyPair, network: NetworkId) -> MessageEnvelope {
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        network,
        CHAIN_ID,
        GENESIS_HASH,
        1,
        &net_id(key),
        &SessionNonce::from_bytes([0xAB; 16]),
        b"consensus",
    )
    .unwrap();
    let mut e = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: NodeId::from_bytes([0; 32]),
        signature: [0u8; 64],
    };
    sign_message(key.signing_key(), &mut e).unwrap();
    e
}

/// 经真实 TCP 的 auth NS 对（A = dialer，B = acceptor；两端已 connect peer）。
fn tcp_ns_pair(
    kp_a: &KeyPair,
    kp_b: &KeyPair,
) -> (NetworkService<TcpTransport>, NetworkService<TcpTransport>) {
    let a_id = net_id(kp_a);
    let b_id = net_id(kp_b);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let b_handle = thread::spawn(move || TcpTransport::accept(&listener, b_id, MAX_FRAME, None));
    let tcp_a = TcpTransport::dial(addr, a_id, b_id, MAX_FRAME, None).expect("A dial");
    let tcp_b = b_handle.join().expect("B thread").expect("B accept");
    let mut ns_a = NetworkService::new(ns_cfg(), a_id, tcp_a);
    let mut ns_b = NetworkService::new(ns_cfg(), b_id, tcp_b);
    ns_a.connect_peer(b_id).unwrap();
    ns_b.connect_peer(a_id).unwrap();
    (ns_a, ns_b)
}

fn mutual_handshake(
    ns_a: &mut NetworkService<TcpTransport>,
    ns_b: &mut NetworkService<TcpTransport>,
    kp_a: &KeyPair,
    kp_b: &KeyPair,
) {
    let a_id = net_id(kp_a);
    let b_id = net_id(kp_b);
    ns_a.enqueue_outbound(b_id, handshake_env(kp_a, NetworkId::Mainnet))
        .unwrap();
    ns_a.flush_outbound().unwrap();
    ns_b.poll_transport().unwrap();
    assert!(ns_b.is_peer_established(a_id), "B established A");
    ns_b.enqueue_outbound(a_id, handshake_env(kp_b, NetworkId::Mainnet))
        .unwrap();
    ns_b.flush_outbound().unwrap();
    ns_a.poll_transport().unwrap();
    assert!(ns_a.is_peer_established(b_id), "A established B");
    let _ = ns_a.drain_inbound();
    let _ = ns_b.drain_inbound();
}

// ---------- N-IMPL-1：Driver local vote → signed envelope ----------

#[test]
fn nimpl1_local_vote_semantic_to_signed_envelope() {
    let (mut _driver, vote, signature) = driver_local_prevote();
    let net_kp = KeyPair::generate().unwrap();
    let net_vk = *net_kp.verifying_key();
    let signer = SoftwareNetworkIdentity::new(net_kp);

    let canonical = canonical_vote_payload(&vote);
    let env = envelope_for(&OutboundConsensusMessage::Vote { vote, signature }, &signer)
        .expect("adapter envelope");

    assert_eq!(env.message_type, MessageType::ConsensusVote);
    // canonical vote payload(121) ‖ consensus signature(64)。
    assert_eq!(env.payload.len(), 121 + 64, "canonical vote ‖ sig 布局");
    assert_eq!(
        env.payload[..121],
        canonical[..],
        "载荷首 121B = canonical vote"
    );
    // sender = 网络 NodeId（网络 key；非 validator id —— N-IMPL-7）。
    assert_eq!(env.sender, NodeId::from_verifying_key(&net_vk));
    // envelope 网络签名有效（网络 key 验签）。
    verify_message(&net_vk, &env).expect("network identity signature valid");
}

// ---------- N-IMPL-2：Proposal → ConsensusProposal envelope ----------

#[test]
fn nimpl2_proposal_semantic_to_signed_envelope() {
    let (driver, target, _cons_vk) = setup_single();
    let proposer = driver.actor(0).unwrap().validator_id();
    let pr = ProposalRef {
        block_hash: target,
        proposer,
    };
    let net_kp = KeyPair::generate().unwrap();
    let net_vk = *net_kp.verifying_key();
    let signer = SoftwareNetworkIdentity::new(net_kp);

    let env = envelope_for(&OutboundConsensusMessage::Proposal(pr.clone()), &signer)
        .expect("adapter envelope");
    assert_eq!(env.message_type, MessageType::ConsensusProposal);
    // canonical 64B：block_hash 32B ‖ proposer 32B。
    assert_eq!(env.payload, encode_proposal_ref(&pr));
    assert_eq!(env.payload.len(), 64);
    verify_message(&net_vk, &env).expect("network identity signature valid");
    // semantic 编码（不经签名）与 envelope payload 一致。
    let (mt, payload) = encode_semantic(&OutboundConsensusMessage::Proposal(pr));
    assert_eq!(mt, MessageType::ConsensusProposal);
    assert_eq!(payload, env.payload);
}

// ---------- N-IMPL-3：VerifiedQc（Driver verify_qc PASS）→ ConsensusQc envelope ----------

#[test]
fn nimpl3_verified_qc_semantic_to_signed_envelope() {
    let (mut driver, target, _cons_vk) = setup_single();
    submit_proposal_for(&mut driver, target);
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("prevote 提交");
    let res = driver
        .submit_local_vote(0, &precommit_req(target))
        .unwrap()
        .expect("precommit 提交");
    assert!(matches!(&res, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Finalized);
    driver
        .process_transition_derived(&res)
        .expect("qc verify PASS");
    let outbound = driver.take_outbound();
    let qc = outbound
        .into_iter()
        .find_map(|m| match m {
            OutboundConsensusMessage::VerifiedQc(qc) => Some(qc),
            _ => None,
        })
        .expect("Driver verify_qc 后应 record VerifiedQc");

    let net_kp = KeyPair::generate().unwrap();
    let net_vk = *net_kp.verifying_key();
    let signer = SoftwareNetworkIdentity::new(net_kp);
    let env = envelope_for(&OutboundConsensusMessage::VerifiedQc(qc.clone()), &signer)
        .expect("adapter envelope");
    assert_eq!(env.message_type, MessageType::ConsensusQc);
    assert_eq!(env.payload, encode_qc(&qc), "canonical QC wire");
    verify_message(&net_vk, &env).expect("network identity signature valid");
}

// ---------- N-IMPL-4：TCP end-to-end（driver → adapter → NS A → TCP → NS B） ----------

#[test]
fn nimpl4_tcp_end_to_end_driver_vote_via_adapter_to_peer() {
    let (_driver, vote, signature) = driver_local_prevote();
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let a_id = net_id(&kp_a);
    let _b_id = net_id(&kp_b);
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    mutual_handshake(&mut ns_a, &mut ns_b, &kp_a, &kp_b);

    // node egress adapter：semantic → 签名 envelope（网络身份 A）。
    let signer_a = SoftwareNetworkIdentity::new(kp_a);
    let env = envelope_for(
        &OutboundConsensusMessage::Vote { vote, signature },
        &signer_a,
    )
    .expect("adapter envelope");
    assert_eq!(env.sender, a_id);

    // 经 A NS broadcast（established B）→ flush（TCP）→ B poll → ConsensusVote 送达。
    // NS 入站 gate 已对每条 data 验网络签名（verify_message fail ⇒ dropped_invalid）——
    // 送达即表示 envelope 网络签名有效。
    let delivered = ns_a.broadcast(env).expect("broadcast to established B");
    assert_eq!(delivered, 1, "exactly B established");
    ns_a.flush_outbound().expect("A flush");
    ns_b.poll_transport().expect("B poll");
    let events = ns_b.drain_inbound();
    let vote_event = events
        .iter()
        .find(|e| e.message_type() == MessageType::ConsensusVote)
        .expect("B 收到 ConsensusVote（NS 验签通过后分类）");
    assert_eq!(vote_event.sender(), a_id, "sender = A 网络 NodeId");
    assert_eq!(
        vote_event.payload().len(),
        121 + 64,
        "canonical 布局跨 TCP 保持"
    );
    assert_eq!(ns_b.diagnostics().dropped_invalid, 0, "无验签 drop");
}

// ---------- N-IMPL-5：tamper ⇒ fail-closed（不静默通过） ----------

#[test]
fn nimpl5_tampered_payload_detected_and_rejected() {
    // 原 vote：driver 用共识 key 真实签名。
    let (mut driver, target, cons_vk) = setup_single();
    submit_proposal_for(&mut driver, target);
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("prevote 提交");
    let (vote, signature) = driver
        .take_outbound()
        .into_iter()
        .find_map(|m| match m {
            OutboundConsensusMessage::Vote { vote, signature } => Some((vote, signature)),
            _ => None,
        })
        .expect("vote outbound");
    // 同一共识 set（成员 = cons_vk）供静态 verify_vote_input。
    let set = ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: cons_vk.to_bytes(),
        bonded_stake: 100,
        commission_bps: 100,
    }]));

    // (b) 共识签名层：任何 tamper（改内容或改签名）⇒ verify_vote_input 拒（fail-closed）。
    let mut tampered_vote = vote.clone();
    tampered_vote.target_block_hash[0] ^= 0xFF;
    assert!(
        verify_vote_input(&tampered_vote, &signature, CHAIN_ID, &set).is_err(),
        "改 vote 内容 ⇒ 共识验签拒"
    );
    let mut tampered_sig = signature;
    tampered_sig[63] ^= 0xFF;
    assert!(
        verify_vote_input(&vote, &tampered_sig, CHAIN_ID, &set).is_err(),
        "改签名 ⇒ 共识验签拒"
    );

    // 网络层（node adapter 签名 envelope）。
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let _b_id = net_id(&kp_b);
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    mutual_handshake(&mut ns_a, &mut ns_b, &kp_a, &kp_b);
    let vk_a = *kp_a.verifying_key();
    let signer_a = SoftwareNetworkIdentity::new(kp_a);

    // (c) 内容篡改：network 签名对原内容有效 ⇒ tamper 后本地验签必失败。
    let env_ok = envelope_for(
        &OutboundConsensusMessage::Vote {
            vote: vote.clone(),
            signature,
        },
        &signer_a,
    )
    .expect("adapter envelope");
    let mut tampered_env = env_ok.clone();
    tampered_env.payload[0] ^= 0xFF;
    assert!(
        verify_message(&vk_a, &tampered_env).is_err(),
        "tamper payload ⇒ envelope 网络签名失效"
    );
    // 经 TCP 送达 B：NS 入站对每条 data 验网络签名 ⇒ tamper 必被 B fail-closed（dropped_invalid，
    // 不产生任何 ConsensusVote event）。
    let before = ns_b.diagnostics().dropped_invalid;
    ns_a.broadcast(tampered_env).expect("broadcast");
    ns_a.flush_outbound().expect("A flush");
    ns_b.poll_transport().expect("B poll");
    let events = ns_b.drain_inbound();
    assert!(
        !events
            .iter()
            .any(|e| e.message_type() == MessageType::ConsensusVote),
        "tamper ⇒ B 不产生 ConsensusVote event（NS fail-closed）"
    );
    assert!(
        ns_b.diagnostics().dropped_invalid > before,
        "B dropped_invalid 计数增加（tamper 被拒）"
    );

    // (d) 共识签名区篡改但 envelope 网络签名仍有效 ⇒ NS 放行（envelope 层无感知）
    //     但共识层（B decode + verify_vote_input）必拒 —— 上面 (b) 已静态证明；
    //     端到端：该 event 抵达 B，payload 内 tampered 签名无法通过共识 verify。
    let env_bad_consensus = envelope_for(
        &OutboundConsensusMessage::Vote {
            vote: vote.clone(),
            signature: tampered_sig,
        },
        &signer_a,
    )
    .expect("adapter envelope（错误共识签名）");
    ns_a.broadcast(env_bad_consensus).expect("broadcast");
    ns_a.flush_outbound().expect("A flush");
    ns_b.poll_transport().expect("B poll");
    let events2 = ns_b.drain_inbound();
    let arrived = events2
        .iter()
        .find(|e| e.message_type() == MessageType::ConsensusVote)
        .expect("network 层接受（网络签名有效）");
    assert_eq!(arrived.payload().len(), 121 + 64);
    // payload 的 consensus signature 区 = tampered_sig（内容仍可解码；但 (b) 已证明该签名
    // 无法通过共识 verify_vote_input ⇒ B 的共识装配 decode+verify 必拒，fail-closed）。
    assert_eq!(&arrived.payload()[121..], tampered_sig.as_slice());
}

// ---------- N-IMPL-6：unauthenticated ⇒ egress data 不可达 ----------

#[test]
fn nimpl6_unauthenticated_peer_cannot_receive_egress_data() {
    let (_driver, vote, signature) = driver_local_prevote();
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let a_id = net_id(&kp_a);
    let b_id = net_id(&kp_b);
    let (mut ns_a, mut ns_b) = tcp_ns_pair(&kp_a, &kp_b);
    // 不做握手：B 眼中 A 没有 Established session（None 或 Unauthenticated —— 均非认证）。
    assert!(
        !matches!(
            ns_b.peer_session(a_id),
            Some(PeerSessionState::Established) | Some(PeerSessionState::Authenticated)
        ),
        "未握手 ⇒ B 侧 A 未认证"
    );

    let signer_a = SoftwareNetworkIdentity::new(kp_a);
    let env = envelope_for(
        &OutboundConsensusMessage::Vote { vote, signature },
        &signer_a,
    )
    .expect("adapter envelope");

    // (a) 单发：auth 启用且对端未 established ⇒ enqueue 拒发（established-only gate）。
    assert!(
        matches!(
            ns_a.enqueue_outbound(b_id, env.clone()),
            Err(NetworkServiceError::PeerNotConnected)
        ),
        "unauth 对端 data enqueue 必须拒发"
    );
    // (b) broadcast：过滤掉非 established ⇒ 0 送达（不会发出）。
    let delivered = ns_a.broadcast(env).expect("broadcast");
    assert_eq!(delivered, 0, "unauth 对端无 broadcast 投递");
    ns_a.flush_outbound().expect("flush（空队列）");

    // (c) B 侧：从未握手 ⇒ 无任何 ConsensusVote event。
    ns_b.poll_transport().expect("B poll");
    let events = ns_b.drain_inbound();
    assert!(
        !events
            .iter()
            .any(|e| e.message_type() == MessageType::ConsensusVote),
        "unauth ⇒ B 无 vote event"
    );
    assert!(
        !matches!(
            ns_b.peer_session(a_id),
            Some(PeerSessionState::Established) | Some(PeerSessionState::Authenticated)
        ),
        "B 侧 A 仍未认证"
    );
}

// ---------- N-IMPL-7：网络 NodeId ≠ consensus ValidatorId ----------

#[test]
fn nimpl7_network_node_id_differs_from_consensus_validator_id() {
    let (driver, target, _cons_vk) = setup_single();
    let cons_vid = driver.actor(0).unwrap().validator_id();
    let net_kp = KeyPair::generate().unwrap();
    let net_node = net_id(&net_kp);
    // 不同源：ValidatorId = SHA-256(consensus pubkey)；NodeId = Ed25519 pubkey bytes。
    assert_ne!(
        net_node.as_bytes(),
        cons_vid.as_bytes(),
        "网络身份与共识身份必须不同源"
    );
    // adapter 产物 sender 是网络 NodeId，绝不被当作 validator id。
    let signer = SoftwareNetworkIdentity::new(net_kp);
    let env = envelope_for(
        &OutboundConsensusMessage::Proposal(ProposalRef {
            block_hash: target,
            proposer: cons_vid,
        }),
        &signer,
    )
    .expect("adapter envelope");
    assert_eq!(env.sender, net_node);
}
