//! Node Consensus Wiring 集成测试（STEP 10-18G-1；Owner Option 1）。
//!
//! 覆盖：NetworkEvent（vote/proposal/qc）经 EventLoop → NodeConsensusHandler → Driver
//! （既有验证门面）→ ConsensusNode；Driver → outbound semantic → NetworkEgress seam；
//! QC 验证前后广播/锁语义；multi-validator 独立 lock；G-14/G-15 结构边界。
//!
//! 全部 deterministic（无随机路径）；fixture 复用既有 consensus/crypto 原语。
//! 测试用 egress 之网络签名路径使用 test-only KeyPair（不修改生产 NodeRuntime）。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate, encode_qc, verify_qc};
use nova_consensus::integration::TransitionResult;
use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, VerifyingKey, sign_message_hash};
use nova_network::event_loop::{EventHandler, EventLoop, EventLoopConfig, NodeEvent};
use nova_network::message::{
    MessageEnvelope, MessageType, decode, encode, sign_message, verify_message,
};
use nova_network::network_service::{NetworkEvent, NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::transport::{MemoryTransport, Transport};

use nova_node::assembly::ConsensusNode;
use nova_node::driver::NodeConsensusDriver;
use nova_node::outbound::{NetworkEgress, OutboundConsensusMessage};
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};
use nova_node::wiring::NodeConsensusHandler;

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];

// ---------- fixtures（与 driver_tests 同套路） ----------

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

fn vid_of(kp: &KeyPair) -> ValidatorId {
    ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// n 个等 stake(100) 验证者：quorum = ceil(2T/3)。
fn make_ctx(n: usize) -> (Vec<KeyPair>, ValidatorSet) {
    let mut kps = Vec::new();
    let mut vals = Vec::new();
    for i in 0..n {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        kps.push(kp);
        vals.push(ValidatorInit {
            account_address: addr([i as u8 + 0x10; 32]),
            consensus_public_key: pk,
            bonded_stake: 100,
            commission_bps: 100,
        });
    }
    let set = ValidatorSet::from_genesis(&genesis_with(vals));
    (kps, set)
}

fn actor_of(kp: KeyPair) -> ValidatorActor<SoftwareSigner> {
    let vk = *kp.verifying_key();
    let id = ValidatorId::from_consensus_public_key(&vk.to_bytes());
    ValidatorActor::new(id, SoftwareSigner::new(kp), CHAIN_ID).unwrap()
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

fn dag2() -> Dag {
    let mut dag = Dag::new();
    for (hash, height, parents) in [
        (0xAAu8, 0u64, vec![] as Vec<u8>),
        (0xBB, 0, vec![]),
        (0xCC, 1, vec![0xAA]),
    ] {
        dag.add_block(BlockReference {
            block_hash: [hash; 32],
            height,
            parents: parents.iter().map(|p| [*p; 32]).collect(),
            proposer: ValidatorId::from_bytes([hash; 32]),
        })
        .unwrap();
    }
    dag
}

fn sign_vote(sk: &SigningKey, vote: &ValidatorVote) -> [u8; 64] {
    let payload = canonical_vote_payload(vote);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        CHAIN_ID,
        &payload,
    )
    .unwrap();
    sign_message_hash(sk, &hash_signing_message(&signed)).to_bytes()
}

fn make_precommit_qc(
    target: &[u8; 32],
    signers: &[(ValidatorId, &KeyPair)],
    validator_set_id: [u8; 32],
) -> QuorumCertificate {
    let mut evidence: Vec<QcEvidence> = signers
        .iter()
        .map(|(vid, kp)| {
            let vote = ValidatorVote {
                round: 0,
                height: 0,
                target_block_hash: *target,
                vote_type: VoteType::Precommit,
                source_block_hash: [0; 32],
                validator_id: *vid,
                timestamp: 0,
            };
            QcEvidence {
                validator_id: *vid,
                source_block_hash: [0; 32],
                timestamp: 0,
                signature: sign_vote(kp.signing_key(), &vote),
            }
        })
        .collect();
    evidence.sort_by_key(|e| e.validator_id);
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target: *target,
        validator_set_id,
        evidence,
    }
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

fn remote_vote(
    kp: &KeyPair,
    vote_type: VoteType,
    target: [u8; 32],
    height: u64,
    round: u64,
) -> (ValidatorVote, [u8; 64]) {
    let vote = ValidatorVote {
        round,
        height,
        target_block_hash: target,
        vote_type,
        source_block_hash: [0; 32],
        validator_id: vid_of(kp),
        timestamp: 0,
    };
    let signature = sign_vote(kp.signing_key(), &vote);
    (vote, signature)
}

/// 单验证者 driver（set n=1；dag 含 AA；无 pre-lock）。
fn setup_single_driver() -> (NodeConsensusDriver<SoftwareSigner>, [u8; 32]) {
    let (mut kps, set) = make_ctx(1);
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let actor = actor_of(kps.remove(0));
    let driver = NodeConsensusDriver::new(consensus, vec![actor]);
    (driver, target)
}

// ---------- EventLoop / event 装配 ----------

/// 记录 egress（收集 driver 产出的 outbound semantic batch）。
#[derive(Default)]
struct RecordingEgress {
    batches: Vec<Vec<OutboundConsensusMessage>>,
}

impl RecordingEgress {
    fn all(&self) -> Vec<OutboundConsensusMessage> {
        self.batches
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect()
    }
    fn is_empty(&self) -> bool {
        self.all().is_empty()
    }
}

impl NetworkEgress for RecordingEgress {
    fn send_outbound(&mut self, messages: Vec<OutboundConsensusMessage>) {
        if !messages.is_empty() {
            self.batches.push(messages);
        }
    }
}

fn make_loop<E: NetworkEgress>(
    driver: NodeConsensusDriver<SoftwareSigner>,
    egress: E,
) -> EventLoop<MemoryTransport, NodeConsensusHandler<SoftwareSigner, E>> {
    let self_node = NodeId::from_bytes([0xEE; 32]);
    let peer = NodeId::from_bytes([0xDD; 32]);
    let (ta, _tb) = MemoryTransport::pair(self_node, peer);
    let ns = NetworkService::new(NetworkServiceConfig::default(), self_node, ta);
    let handler = NodeConsensusHandler::new(driver, egress);
    EventLoop::new(EventLoopConfig::default(), ns, handler)
}

fn run<H: EventHandler>(el: &mut EventLoop<MemoryTransport, H>, event: NodeEvent) {
    el.push_event(event).expect("push_event");
    el.poll_once().expect("poll_once");
}

fn vote_event(sender: NodeId, vote: ValidatorVote, signature: [u8; 64]) -> NodeEvent {
    let mut payload = canonical_vote_payload(&vote);
    payload.extend_from_slice(&signature);
    NodeEvent::Network(NetworkEvent::ConsensusVote { sender, payload })
}

fn proposal_event(sender: NodeId, pr: &ProposalRef) -> NodeEvent {
    NodeEvent::Network(NetworkEvent::ConsensusProposal {
        sender,
        payload: encode_proposal_ref(pr),
    })
}

fn qc_event(sender: NodeId, qc: &QuorumCertificate) -> NodeEvent {
    NodeEvent::Network(NetworkEvent::ConsensusQc {
        sender,
        payload: encode_qc(qc),
    })
}

// ---------- G-1 ----------

/// G-1：NetworkEvent::ConsensusVote 经 EventLoop → handler → Driver → canonical transition。
#[test]
fn g1_vote_reaches_driver() {
    let (ks, set) = make_ctx(3);
    let b = &ks[0];
    let c = &ks[1];
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::<SoftwareSigner>::new(consensus, Vec::new());
    let mut el = make_loop(driver, RecordingEgress::default());

    run(
        &mut el,
        proposal_event(
            node_id_of(b),
            &ProposalRef {
                block_hash: target,
                proposer: vid_of(b),
            },
        ),
    );
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Prevote,
        "proposal Applied ⇒ step=Prevote"
    );

    for kp in [b, c] {
        let (vote, sig) = remote_vote(kp, VoteType::Prevote, target, 0, 0);
        run(&mut el, vote_event(node_id_of(kp), vote, sig));
    }
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Precommit,
        "remote votes 经 EventLoop 到达 Driver 并推进 round"
    );
    assert!(el.handler().egress().is_empty());
}

// ---------- G-2 ----------

/// G-2：remote vote 使用既有 verification facade（坏签名被拒；无状态变化）。
#[test]
fn g2_remote_vote_uses_verify_facade() {
    let (ks, set) = make_ctx(3);
    let b = &ks[0];
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::<SoftwareSigner>::new(consensus, Vec::new());
    let mut el = make_loop(driver, RecordingEgress::default());
    run(
        &mut el,
        proposal_event(
            node_id_of(b),
            &ProposalRef {
                block_hash: target,
                proposer: vid_of(b),
            },
        ),
    );
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Prevote
    );

    // 声称是 B（set 成员）但由 outsider 签名 ⇒ verify_vote_input 拒
    let outsider = KeyPair::generate().unwrap();
    let (vote, _) = remote_vote(&outsider, VoteType::Prevote, target, 0, 0);
    let forged = ValidatorVote {
        validator_id: vid_of(b),
        ..vote
    };
    let bad_sig = sign_vote(outsider.signing_key(), &forged);
    run(&mut el, vote_event(node_id_of(&outsider), forged, bad_sig));

    assert!(
        el.diagnostics().handler_errors >= 1,
        "坏签名必须在 handler 层被拒"
    );
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Prevote,
        "invalid vote 不得推进 consensus"
    );
    assert!(el.handler().egress().is_empty());
}

// ---------- G-3 ----------

/// G-3：remote vote 绝不停留在本地 ValidatorActor::VoteLedger。
#[test]
fn g3_remote_vote_never_enters_local_ledger() {
    let (mut ks, set) = make_ctx(3);
    let a = ks.remove(0); // local actor A
    let b = &ks[0];
    let c = &ks[1];
    let a_id = vid_of(&a);
    let a_node = node_id_of(&a);
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(a)]);
    let mut el = make_loop(driver, RecordingEgress::default());

    run(
        &mut el,
        proposal_event(
            a_node,
            &ProposalRef {
                block_hash: target,
                proposer: a_id,
            },
        ),
    );
    // remote prevote B、C（A 不参与本地 prevote）
    for kp in [b, c] {
        let (vote, sig) = remote_vote(kp, VoteType::Prevote, target, 0, 0);
        run(&mut el, vote_event(node_id_of(kp), vote, sig));
    }
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Precommit
    );
    // remote precommit B、C → Finalized + derived QC（本地 A 不投任何票）
    for kp in [b, c] {
        let (vote, sig) = remote_vote(kp, VoteType::Precommit, target, 0, 0);
        run(&mut el, vote_event(node_id_of(kp), vote, sig));
    }
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        RoundStep::Finalized
    );
    assert!(
        el.handler()
            .driver()
            .actor(0)
            .unwrap()
            .vote_ledger()
            .is_empty(),
        "remote vote 不得进入本地 VoteLedger"
    );
}

// ---------- G-4 ----------

/// G-4：valid ProposalRef 经 EventLoop → Driver → ConsensusNode。
#[test]
fn g4_valid_proposal_reaches_driver() {
    let (driver, target) = setup_single_driver();
    let proposer = driver.actor(0).unwrap().validator_id();
    let sender = NodeId::from_bytes([0x99; 32]);
    let pr = ProposalRef {
        block_hash: target,
        proposer,
    };
    let mut el = make_loop(driver, RecordingEgress::default());
    run(&mut el, proposal_event(sender, &pr));
    let state = el.handler().driver().consensus().state();
    assert_eq!(state.round.proposal, Some(pr));
    assert_eq!(state.round.step, RoundStep::Prevote);
}

// ---------- G-5 ----------

/// G-5：invalid ProposalRef 不改变 consensus。
#[test]
fn g5_invalid_proposal_no_mutation() {
    let (driver, _target) = setup_single_driver();
    let mut el = make_loop(driver, RecordingEgress::default());
    let before = el.handler().driver().consensus().state().round.step;

    let bad = NodeEvent::Network(NetworkEvent::ConsensusProposal {
        sender: NodeId::from_bytes([0x77; 32]),
        payload: vec![0x00; 63],
    });
    run(&mut el, bad);

    assert!(el.diagnostics().handler_errors >= 1);
    let state = el.handler().driver().consensus().state();
    assert!(state.round.proposal.is_none());
    assert_eq!(state.round.step, before);
}

// ---------- G-6 ----------

/// G-6：valid QC 经 EventLoop → Driver.submit_inbound_qc（verify_qc PASS → local lock）。
#[test]
fn g6_valid_qc_reaches_driver() {
    let (mut ks, set) = make_ctx(1);
    let a = ks.remove(0);
    let a_id = vid_of(&a);
    let a_node = node_id_of(&a);
    let target = [0xAA; 32];

    // fixture：先构造真实可验 QC（借用 key）再 move key 进 actor
    let qc = make_precommit_qc(&target, &[(a_id, &a)], GENESIS_HASH);
    let vdag = dag1();
    verify_qc(&qc, &set, &GENESIS_HASH, &vdag).expect("valid precommit QC");

    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(a)]);
    let mut el = make_loop(driver, RecordingEgress::default());
    run(&mut el, qc_event(a_node, &qc));

    let lock = el.handler().driver().actor(0).unwrap().locked_state();
    assert_eq!(lock.locked_block_hash, Some(target));
    assert_eq!(lock.locked_round, Some(0));
    assert!(el.handler().egress().is_empty(), "inbound QC 不重广播");
}

// ---------- G-7 / G-8 ----------

/// G-7/G-8：invalid QC ⇒ 无 outbound 且无 lock。
#[test]
fn g7_g8_invalid_qc_no_outbound_no_lock() {
    let (mut ks, set) = make_ctx(1);
    let a = ks.remove(0);
    let outsider = KeyPair::generate().unwrap();
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(a)]);
    let mut el = make_loop(driver, RecordingEgress::default());

    let bad_qc = make_precommit_qc(&target, &[(vid_of(&outsider), &outsider)], GENESIS_HASH);
    run(&mut el, qc_event(node_id_of(&outsider), &bad_qc));

    assert!(
        el.diagnostics().handler_errors >= 1,
        "invalid QC 必须被 handler 拒"
    );
    assert!(
        el.handler().egress().is_empty(),
        "G-7：invalid QC 不得 outbound"
    );
    let lock = el.handler().driver().actor(0).unwrap().locked_state();
    assert_eq!(lock.locked_block_hash, None, "G-8：invalid QC 不得 lock");
    assert_eq!(lock.locked_round, None);
}

// ---------- G-9 ----------

/// G-9：valid QC 到达每个本地 ValidatorActor（verify_qc PASS → 每 actor lock）。
#[test]
fn g9_valid_qc_reaches_every_local_actor() {
    let (mut ks, set) = make_ctx(3);
    let a = ks.remove(0);
    let b = ks.remove(0);
    let c = ks.remove(0);
    let a_id = vid_of(&a);
    let c_id = vid_of(&c);
    let target = [0xAA; 32];

    let qc = make_precommit_qc(&target, &[(a_id, &a), (c_id, &c)], GENESIS_HASH);
    let vdag = dag1();
    verify_qc(&qc, &set, &GENESIS_HASH, &vdag).expect("valid precommit QC");

    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(a), actor_of(b)]);
    let mut el = make_loop(driver, RecordingEgress::default());
    run(&mut el, qc_event(node_id_of(&c), &qc));

    let actor_a = el.handler().driver().actor(0).unwrap();
    assert_eq!(actor_a.locked_state().locked_block_hash, Some(target));
    let actor_b = el.handler().driver().actor(1).unwrap();
    assert_eq!(actor_b.locked_state().locked_block_hash, Some(target));
}

// ---------- G-10 ----------

/// G-10：每个 ValidatorActor 独立 acquire_lock（同一 QC 不共享/不串改 LockedState）。
#[test]
fn g10_each_actor_independently_acquires_lock() {
    let (mut ks, set) = make_ctx(3);
    let a = ks.remove(0);
    let b = ks.remove(0);
    let c = ks.remove(0);
    let a_id = vid_of(&a);
    let b_id = vid_of(&b);
    let c_id = vid_of(&c);
    let aa = [0xAA; 32];
    let bb = [0xBB; 32];
    let cc = [0xCC; 32];

    // 前置：A 锁 AA，B 锁 BB（各自独立历史）—— 先构造各 QC（借用 keys）
    let qc_aa = make_precommit_qc(&aa, &[(a_id, &a), (c_id, &c)], GENESIS_HASH);
    let qc_bb = make_precommit_qc(&bb, &[(b_id, &b), (c_id, &c)], GENESIS_HASH);
    let qc_cc = make_precommit_qc(&cc, &[(a_id, &a), (c_id, &c)], GENESIS_HASH);
    let vdag = dag2();
    verify_qc(&qc_cc, &set, &GENESIS_HASH, &vdag).expect("valid precommit QC");

    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag2());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(a), actor_of(b)]);
    let mut el = make_loop(driver, RecordingEgress::default());

    let pre_dag = dag2();
    el.handler_mut()
        .driver_mut()
        .actor_mut(0)
        .unwrap()
        .on_verified_precommit_qc(&qc_aa, &pre_dag)
        .unwrap();
    el.handler_mut()
        .driver_mut()
        .actor_mut(1)
        .unwrap()
        .on_verified_precommit_qc(&qc_bb, &pre_dag)
        .unwrap();

    // inbound valid QC target CC → A advance；B（unrelated）不变
    run(&mut el, qc_event(node_id_of(&c), &qc_cc));

    assert_eq!(
        el.handler()
            .driver()
            .actor(0)
            .unwrap()
            .locked_state()
            .locked_block_hash,
        Some(cc),
        "A: descendant ⇒ advance"
    );
    assert_eq!(
        el.handler()
            .driver()
            .actor(1)
            .unwrap()
            .locked_state()
            .locked_block_hash,
        Some(bb),
        "B: unrelated ⇒ 不被同一 QC 改写（独立 lock）"
    );
}

// ---------- G-11 ----------

/// G-11：local vote 仅在验证/提交成功后才进入 outbound semantic。
#[test]
fn g11_local_vote_outbound_only_after_verification_success() {
    // positive：单验证者本地 prevote（proposal Applied → verify PASS → record outbound）
    let (mut driver, target) = setup_single_driver();
    let proposer = driver.actor(0).unwrap().validator_id();
    let res = driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer,
    });
    assert!(matches!(res, TransitionResult::Applied { .. }));
    let out = driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("本地 prevote 应提交");
    assert!(matches!(out, TransitionResult::Applied { .. }));
    let mut pending = driver.take_outbound();
    assert_eq!(pending.len(), 1, "verify PASS ⇒ 恰好一条 outbound vote");
    match pending.pop().unwrap() {
        OutboundConsensusMessage::Vote { vote, .. } => {
            assert_eq!(vote.target_block_hash, target);
            assert_eq!(vote.vote_type, VoteType::Prevote);
        }
        other => panic!("expected Vote outbound, got {other:?}"),
    }

    // negative：无 proposal（上下文门拒）⇒ 无 sign / 无 outbound
    let (driver2, target2) = setup_single_driver();
    let mut d2 = driver2;
    let none = d2.submit_local_vote(0, &prevote_req(target2)).unwrap();
    assert!(none.is_none(), "无当前 proposal ⇒ 不投");
    assert_eq!(d2.outbound_pending_len(), 0, "未授权 ⇒ 无 outbound");
    assert!(d2.take_outbound().is_empty());
}

// ---------- G-12 ----------

/// G-12：outbound vote 以 semantic output 表达（且可被 NetworkEgress seam 消费）。
#[test]
fn g12_outbound_vote_is_semantic_output() {
    let (mut driver, target) = setup_single_driver();
    let proposer = driver.actor(0).unwrap().validator_id();
    driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer,
    });
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("prevote 提交");
    let pending = driver.take_outbound();
    assert_eq!(pending.len(), 1);

    let mut eg = RecordingEgress::default();
    let msg = pending[0].clone();
    eg.send_outbound(vec![msg.clone()]);
    assert_eq!(eg.all(), vec![msg]);
}

// ---------- G-13 ----------

/// G-13：verified QC 以 semantic output 表达（derived QC 经 verify_qc PASS 后 record）。
#[test]
fn g13_verified_qc_semantic_output() {
    let (mut driver, target) = setup_single_driver();
    let proposer = driver.actor(0).unwrap().validator_id();
    driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer,
    });
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .unwrap();
    let _ = driver.take_outbound(); // 清掉 prevote outbound，聚焦 derived QC

    let res = driver
        .submit_local_vote(0, &precommit_req(target))
        .unwrap()
        .expect("precommit 提交");
    assert!(matches!(
        &res,
        TransitionResult::Applied { derived, .. } if derived.precommit_qc.is_some()
    ));
    // submit 自身已 record precommit vote outbound（verify PASS）——先取走，聚焦 derived QC
    assert_eq!(
        driver.outbound_pending_len(),
        1,
        "precommit vote 已入 outbound"
    );
    let _ = driver.take_outbound();
    driver.process_transition_derived(&res).unwrap();

    let pending = driver.take_outbound();
    assert_eq!(
        pending.len(),
        1,
        "verify_qc PASS ⇒ 一条 outbound verified QC"
    );
    match &pending[0] {
        OutboundConsensusMessage::VerifiedQc(qc) => {
            assert_eq!(qc.target, target);
        }
        other => panic!("expected VerifiedQc outbound, got {other:?}"),
    }
}

// ---------- G-14 / G-15（结构边界） ----------

/// G-14/G-15：Driver / ValidatorActor 不拥有 Transport / NetworkService。
/// 类型层面证明：Driver 仅由 consensus + actors 构造（无 transport/NS/socket 参数）；
/// ValidatorActor 仅由 signer 构造。静态 rg 审计见报告。
#[test]
fn g14_g15_driver_and_actor_have_no_transport_dependency() {
    let (mut kps, set) = make_ctx(1);
    let kp = kps.remove(0);
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let _driver = NodeConsensusDriver::new(consensus, vec![actor_of(kp)]);
}

// ---------- 附加：非 consensus 事件不塞入 Driver ----------

#[test]
fn gossip_sync_never_reach_driver() {
    let (driver, _target) = setup_single_driver();
    let mut el = make_loop(driver, RecordingEgress::default());
    let before = el.handler().driver().consensus().state().round.step;

    run(
        &mut el,
        NodeEvent::Network(NetworkEvent::Ping {
            sender: NodeId::from_bytes([0x11; 32]),
            payload: vec![1, 2, 3],
        }),
    );
    run(
        &mut el,
        NodeEvent::Network(NetworkEvent::SyncBlockRequest {
            sender: NodeId::from_bytes([0x22; 32]),
            payload: vec![0xAA; 8],
        }),
    );
    run(
        &mut el,
        NodeEvent::Network(NetworkEvent::GossipTransaction {
            sender: NodeId::from_bytes([0x33; 32]),
            payload: vec![0xBB; 8],
        }),
    );

    assert_eq!(el.handler().non_consensus_seen(), 3);
    assert_eq!(
        el.handler().driver().consensus().state().round.step,
        before,
        "gossip/sync 不得经 ConsensusNode 伪装进入共识"
    );
    assert!(el.handler().egress().is_empty());
    assert_eq!(el.diagnostics().handler_errors, 0);
}

// ---------- 附加：NetworkEgress 真实网络路径（test-only KeyPair + MemoryTransport） ----------

/// test-only egress：用真实 test KeyPair 把 outbound semantic 编码 + 签 envelope + 发送，
/// 证明「Driver outbound intent → envelope → transport」整条路径未来可接生产（GAP-A 解除后）。
struct TestEgress {
    key: KeyPair,
    tx: MemoryTransport,
    peer: NodeId,
}

impl NetworkEgress for TestEgress {
    fn send_outbound(&mut self, messages: Vec<OutboundConsensusMessage>) {
        for msg in messages {
            let (message_type, payload) = match msg {
                OutboundConsensusMessage::Vote { vote, signature } => {
                    let mut p = canonical_vote_payload(&vote);
                    p.extend_from_slice(&signature);
                    (MessageType::ConsensusVote, p)
                }
                OutboundConsensusMessage::VerifiedQc(qc) => {
                    (MessageType::ConsensusQc, encode_qc(&qc))
                }
                OutboundConsensusMessage::Proposal(pr) => {
                    (MessageType::ConsensusProposal, encode_proposal_ref(&pr))
                }
            };
            let sender = NodeId::from_verifying_key(self.key.verifying_key());
            let mut envelope = MessageEnvelope {
                version: 1,
                message_type,
                payload,
                sender,
                signature: [0u8; 64],
            };
            sign_message(self.key.signing_key(), &mut envelope).expect("sign envelope");
            let bytes = encode(&envelope);
            self.tx.send(&self.peer, bytes).expect("send");
        }
    }
}

#[test]
fn egress_real_network_path() {
    let self_kp = KeyPair::generate().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let self_node = node_id_of(&self_kp);
    let peer_node = node_id_of(&peer_kp);
    let (eg_tx, mut peer_rx) = MemoryTransport::pair(self_node, peer_node);

    let (vote, signature) = remote_vote(&self_kp, VoteType::Prevote, [0xAA; 32], 0, 0);
    // 期望 payload（发送前借用 vote 计算）
    let mut want = canonical_vote_payload(&vote);
    want.extend_from_slice(&signature);
    let mut egress = TestEgress {
        key: self_kp,
        tx: eg_tx,
        peer: peer_node,
    };
    egress.send_outbound(vec![OutboundConsensusMessage::Vote { vote, signature }]);

    let (sender, bytes) = peer_rx.try_recv().unwrap().expect("peer 应收到帧");
    assert_eq!(sender, self_node);
    let envelope = decode(&bytes).expect("envelope decode");
    assert_eq!(envelope.message_type, MessageType::ConsensusVote);
    assert_eq!(envelope.payload, want);
    let vk = VerifyingKey::from_bytes(self_node.as_bytes()).unwrap();
    verify_message(&vk, &envelope).expect("envelope 签名有效");
}
