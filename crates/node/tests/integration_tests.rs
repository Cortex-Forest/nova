//! Node Network/EventLoop/Driver 集成测试（STEP 10-18H；H-1..H-6）。
//!
//! 真实连接：NetworkService（MemoryTransport）+ EventLoop + Node wiring + Consensus Driver。
//! - H-1：single node assembly（start/shutdown）。
//! - H-2：two-node MemoryTransport：A vote → NS → EventLoop → handler → B Driver。
//! - H-3：invalid message（坏 signature / 坏 sender / 坏 payload）⇒ drop；consensus 不变。
//! - H-4：QC flow（vote → derived QC → verify_qc → actor lock；不直接 finalize）。
//! - H-5：shutdown 顺序（EventLoop → NS → Driver drop）；停止后无新 vote / 拒新事件。
//! - H-6：restart（SafetyStore restore + consensus 重建 + 网络重新建立）。
//!
//! 纪律：不改生产 EventLoop/NetworkService/Driver/consensus。出站「envelope 签名」在测试装配层
//! 使用 test-only network KeyPair（GAP-A：生产 Node Network Identity DEFERRED）；本地 validator
//! 真实签名（SoftwareSigner）。H-6 restart 采用 restart_safety_tests 的可重建 FixedSigner 模式
//! （validator identity 不可克隆 ⇒ restart 网络重建用独立测试网络 key 验证）。

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::encode_qc;
use nova_consensus::integration::{ConsensusEvent, ConsensusState, TransitionResult};
use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, VerifyingKey};
use nova_network::event_loop::{
    EventLoop, EventLoopConfig, EventLoopError, EventLoopState, InternalEvent, NodeEvent,
};
use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceState};
use nova_network::node_id::NodeId;
use nova_network::transport::{MemoryTransport, Transport};

use nova_node::assembly::ConsensusNode;
use nova_node::driver::NodeConsensusDriver;
use nova_node::outbound::{NetworkEgress, OutboundConsensusMessage};
use nova_node::safety_store::{SafetyIdentity, ValidatorSafetyStore};
use nova_node::signer::{SigningCapability, SigningError, SoftwareSigner};
use nova_node::validator::{LocalVoteRequest, ValidatorActor};
use nova_node::vote_ledger::VoteKey;
use nova_node::wiring::NodeConsensusHandler;

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const TARGET: [u8; 32] = [0xAA; 32];

// ---------- consensus fixtures ----------

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

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// 单验证者 set（validator = kp；stake 100；quorum = 67）。
fn set_for(kp: &KeyPair) -> ValidatorSet {
    ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: kp.verifying_key().to_bytes(),
        bonded_stake: 100,
        commission_bps: 100,
    }]))
}

fn actor_of(kp: KeyPair) -> ValidatorActor<SoftwareSigner> {
    let vk = *kp.verifying_key();
    let id = ValidatorId::from_consensus_public_key(&vk.to_bytes());
    ValidatorActor::new(id, SoftwareSigner::new(kp), CHAIN_ID).unwrap()
}

fn dag_aa() -> Dag {
    let mut dag = Dag::new();
    dag.add_block(BlockReference {
        block_hash: TARGET,
        height: 0,
        parents: vec![],
        proposer: ValidatorId::from_bytes([0xAA; 32]),
    })
    .unwrap();
    dag
}

fn proposal_for(driver: &NodeConsensusDriver<SoftwareSigner>) -> ProposalRef {
    ProposalRef {
        block_hash: TARGET,
        proposer: driver.actor(0).expect("actor").validator_id(),
    }
}

fn prevote_req() -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: TARGET,
        vote_type: VoteType::Prevote,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

fn precommit_req() -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: TARGET,
        vote_type: VoteType::Precommit,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

fn proposer_ref(id: ValidatorId) -> ProposalRef {
    ProposalRef {
        block_hash: TARGET,
        proposer: id,
    }
}

// ---------- 网络装配（测试层；GAP-A：test-only network key） ----------

/// 把 consensus outbound semantic 编码 + 用 node 网络 test key 签成 MessageEnvelope。
fn envelope_for(net_key: &KeyPair, msg: &OutboundConsensusMessage) -> MessageEnvelope {
    let (message_type, payload) = match msg {
        OutboundConsensusMessage::Vote { vote, signature } => {
            let mut p = canonical_vote_payload(vote);
            p.extend_from_slice(signature);
            (MessageType::ConsensusVote, p)
        }
        OutboundConsensusMessage::VerifiedQc(qc) => (MessageType::ConsensusQc, encode_qc(qc)),
        OutboundConsensusMessage::Proposal(pr) => {
            (MessageType::ConsensusProposal, encode_proposal_ref(pr))
        }
    };
    sign_envelope(net_key, message_type, payload)
}

/// 用 test network key 签任意 payload 信封（H-3 坏帧 / H-6 Ping/Pong）。
fn sign_envelope(
    net_key: &KeyPair,
    message_type: MessageType,
    payload: Vec<u8>,
) -> MessageEnvelope {
    let sender = node_id_of(net_key);
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender,
        signature: [0u8; 64],
    };
    sign_message(net_key.signing_key(), &mut envelope).expect("sign envelope");
    envelope
}

/// handler 侧 outbound 收集器（NodeConsensusHandler 经 NetworkEgress seam 写入；测试 drain）。
#[derive(Clone)]
struct CollectorEgress {
    buf: Rc<RefCell<Vec<OutboundConsensusMessage>>>,
}

impl CollectorEgress {
    fn new() -> Self {
        Self {
            buf: Rc::new(RefCell::new(Vec::new())),
        }
    }
    fn drain(&self) -> Vec<OutboundConsensusMessage> {
        std::mem::take(&mut *self.buf.borrow_mut())
    }
    fn len(&self) -> usize {
        self.buf.borrow().len()
    }
}

impl NetworkEgress for CollectorEgress {
    fn send_outbound(&mut self, messages: Vec<OutboundConsensusMessage>) {
        for m in messages {
            self.buf.borrow_mut().push(m);
        }
    }
}

/// 单节点装配（ADR-0058：独立拥有 NS 与 EL）：NetworkService + EventLoop + NodeConsensusHandler。
/// NS 由 Rig 独立持有；EventLoop 不拥有 NS（poll 经 `&mut NetworkService` 注入）。
struct Rig {
    peer: NodeId,
    net_key: KeyPair,
    ns: NetworkService<MemoryTransport>,
    el: EventLoop<NodeConsensusHandler<SoftwareSigner, CollectorEgress>>,
    egress: CollectorEgress,
}

impl Rig {
    fn driver(&self) -> &NodeConsensusDriver<SoftwareSigner> {
        self.el.handler().driver()
    }
    fn driver_mut(&mut self) -> &mut NodeConsensusDriver<SoftwareSigner> {
        self.el.handler_mut().driver_mut()
    }
    fn state(&self) -> &ConsensusState {
        self.el.handler().driver().consensus().state()
    }
    /// 一轮 inbound：transport → NS → EventLoop → handler → driver（EL 经 &mut NS 注入）。
    fn poll(&mut self) {
        let el = &mut self.el;
        let ns = &mut self.ns;
        el.poll_once(ns).expect("poll_once");
    }
    /// 取走本节点当前全部 outbound（driver pending + handler egress 收集）。
    fn collect_outbound(&mut self) -> Vec<OutboundConsensusMessage> {
        let mut v = self.driver_mut().take_outbound();
        v.extend(self.egress.drain());
        v
    }
    /// 把 intent 编码 + 签名（test network key）经本节点 NS 发给 peer。
    fn send_consensus(&mut self, msgs: Vec<OutboundConsensusMessage>) {
        for m in &msgs {
            let env = envelope_for(&self.net_key, m);
            self.ns
                .enqueue_outbound(self.peer, env)
                .expect("enqueue outbound");
        }
        self.ns.flush_outbound().expect("flush");
        assert!(!msgs.is_empty(), "应有 outbound 可发");
    }
    /// 注入原始帧到 peer（经本节点 transport 直发；H-3 测 NS 层 drop）。
    fn inject_raw_to_peer(&mut self, raw: Vec<u8>) {
        self.ns
            .transport()
            .send(&self.peer, raw)
            .expect("inject raw");
    }
}

fn make_rig(
    driver: NodeConsensusDriver<SoftwareSigner>,
    net_key: KeyPair,
    peer: NodeId,
    ta: MemoryTransport,
) -> Rig {
    let id = node_id_of(&net_key);
    let egress = CollectorEgress::new();
    let mut ns = NetworkService::new(NetworkServiceConfig::default(), id, ta);
    ns.connect_peer(peer).expect("connect peer");
    let handler = NodeConsensusHandler::new(driver, egress.clone());
    let el = EventLoop::new(EventLoopConfig::default(), handler);
    Rig {
        peer,
        net_key,
        ns,
        el,
        egress,
    }
}

// ---------- H-1 ----------

/// H-1：single node assembly —— 创建 NetworkService+EventLoop+Driver；启动 / shutdown 通过。
#[test]
fn h1_single_node_assembly() {
    let (kp, peer_kp) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let a_id = node_id_of(&kp);
    let b_id = node_id_of(&peer_kp);
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set_for(&kp), GENESIS_HASH, dag_aa());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(kp)]);
    let (ta, _tb) = MemoryTransport::pair(a_id, b_id);
    let mut rig = make_rig(driver, KeyPair::generate().unwrap(), b_id, ta);

    assert_eq!(rig.el.state(), EventLoopState::Running);
    assert_eq!(rig.driver().actor_count(), 1);
    rig.poll();
    assert_eq!(rig.el.diagnostics().handler_errors, 0);

    // 生命周期独立：先停 EventLoop，再独立停 NetworkService
    rig.el.shutdown();
    assert_eq!(rig.el.state(), EventLoopState::Stopped);
    assert_eq!(rig.el.pending_len(), 0);
    rig.ns.shutdown();
    assert_eq!(rig.ns.state(), NetworkServiceState::Stopped);
}

// ---------- H-2 ----------

/// H-2：two-node MemoryTransport —— A vote → NS → EventLoop → handler → B Driver 成功。
#[test]
fn h2_two_node_vote_reaches_peer_driver() {
    let kp_a = KeyPair::generate().unwrap();
    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let set = set_for(&kp_a); // n=1：validator = A

    // A：validator 节点（本地 actor）
    let consensus_a = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, dag_aa());
    let driver_a = NodeConsensusDriver::new(consensus_a, vec![actor_of(kp_a)]);
    // B：观察者节点（无 actor；set 含 A 以接受并验证 vote）
    let consensus_b = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag_aa());
    let driver_b = NodeConsensusDriver::<SoftwareSigner>::new(consensus_b, Vec::new());

    let (ta, tb) = MemoryTransport::pair(a_id, b_id);
    let mut rig_a = make_rig(driver_a, net_a, b_id, ta);
    let mut rig_b = make_rig(driver_b, net_b, a_id, tb);

    // 两侧同步同一 proposal
    let pr = proposal_for(rig_a.driver());
    assert!(matches!(
        rig_a.driver_mut().submit_proposal(pr.clone()),
        TransitionResult::Applied { .. }
    ));
    assert!(matches!(
        rig_b.driver_mut().submit_proposal(pr),
        TransitionResult::Applied { .. }
    ));
    assert_eq!(rig_a.state().round.step, RoundStep::Prevote);

    // A 本地投 prevote → outbound semantic → 真实编码+签名 → NS → transport → B
    rig_a
        .driver_mut()
        .submit_local_vote(0, &prevote_req())
        .unwrap()
        .expect("A prevote 提交");
    let out = rig_a.collect_outbound();
    assert_eq!(out.len(), 1, "A 本地 prevote 应产生 outbound");
    rig_a.send_consensus(out);

    // B：一轮 inbound（transport → NS 验签 → EventLoop → handler → B Driver）
    rig_b.poll();
    assert_eq!(
        rig_b.state().round.step,
        RoundStep::Precommit,
        "A vote 必须到达 B Driver 并经 canonical transition"
    );
    assert_eq!(rig_b.el.diagnostics().handler_errors, 0);
}

// ---------- H-3 ----------

/// H-3：invalid message（坏 signature / 坏 sender / 坏 payload）⇒ drop；consensus state 不变。
#[test]
fn h3_invalid_messages_dropped_no_state_change() {
    let kp_a = KeyPair::generate().unwrap();
    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let set = set_for(&kp_a);

    let consensus_a = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, dag_aa());
    let consensus_b = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag_aa());
    let driver_a = NodeConsensusDriver::<SoftwareSigner>::new(consensus_a, Vec::new());
    let driver_b = NodeConsensusDriver::<SoftwareSigner>::new(consensus_b, Vec::new());

    let (ta, tb) = MemoryTransport::pair(a_id, b_id);
    let mut rig_a = make_rig(driver_a, net_a, b_id, ta);
    let mut rig_b = make_rig(driver_b, net_b, a_id, tb);
    let step_before = rig_b.state().round.step;

    // (1) 坏 signature：有效编码 + 篡改信封签名 ⇒ NS drop
    {
        let mut env = sign_envelope(&rig_a.net_key, MessageType::ConsensusVote, vec![0xAB; 185]);
        env.signature[0] ^= 0xff;
        rig_a.inject_raw_to_peer(encode(&env));
        rig_b.poll();
        assert!(
            rig_b.ns.diagnostics().dropped_invalid >= 1,
            "坏 signature 必须被 NS drop"
        );
        assert_eq!(rig_b.state().round.step, step_before);
    }
    // (2) 坏 sender：sender ≠ 签名 key 的公钥 ⇒ NS drop（sender mismatch）
    {
        let mut env = sign_envelope(&rig_a.net_key, MessageType::ConsensusVote, vec![0xAB; 185]);
        env.sender = NodeId::from_bytes([0x77; 32]);
        rig_a.inject_raw_to_peer(encode(&env));
        rig_b.poll();
        let dropped = rig_b.ns.diagnostics().dropped_invalid;
        assert!(dropped >= 2, "坏 sender 必须被 NS drop (dropped={dropped})");
        assert_eq!(rig_b.state().round.step, step_before);
    }
    // (3) 坏 payload：信封有效但 vote wire 长度错 ⇒ handler decode 拒（consensus 不变）
    {
        let env = sign_envelope(&rig_a.net_key, MessageType::ConsensusVote, vec![0xAB; 5]);
        rig_a.inject_raw_to_peer(encode(&env));
        rig_b.poll();
        assert!(
            rig_b.el.diagnostics().handler_errors >= 1,
            "坏 payload 必须在 handler decode 拒"
        );
        assert_eq!(rig_b.state().round.step, step_before);
    }
    assert_eq!(rig_b.state().round.proposal, None, "坏帧不得改 consensus");
}

// ---------- H-4 ----------

/// H-4：QC flow —— vote → derived QC → verify_qc → actor lock；不直接 finalize。
#[test]
fn h4_qc_flow_verified_lock_no_direct_finalize() {
    let kp_a = KeyPair::generate().unwrap();
    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let set = set_for(&kp_a);

    let consensus_a = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, dag_aa());
    let driver_a = NodeConsensusDriver::new(consensus_a, vec![actor_of(kp_a)]);
    let consensus_b = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag_aa());
    let driver_b = NodeConsensusDriver::<SoftwareSigner>::new(consensus_b, Vec::new());

    let (ta, tb) = MemoryTransport::pair(a_id, b_id);
    let mut rig_a = make_rig(driver_a, net_a, b_id, ta);
    let mut rig_b = make_rig(driver_b, net_b, a_id, tb);

    let pr = proposal_for(rig_a.driver());
    rig_a.driver_mut().submit_proposal(pr.clone());
    rig_b.driver_mut().submit_proposal(pr);

    // A：prevote + precommit → derived precommit QC（verify_qc PASS）
    rig_a
        .driver_mut()
        .submit_local_vote(0, &prevote_req())
        .unwrap()
        .expect("prevote");
    let _ = rig_a.collect_outbound(); // 清 prevote vote outbound
    let res = rig_a
        .driver_mut()
        .submit_local_vote(0, &precommit_req())
        .unwrap()
        .expect("precommit");
    assert!(matches!(
        &res,
        TransitionResult::Applied { derived, .. } if derived.precommit_qc.is_some()
    ));
    rig_a.driver_mut().process_transition_derived(&res).unwrap();
    // A actor lock（verify_qc PASS 后 acquire_lock）
    assert_eq!(
        rig_a
            .driver()
            .actor(0)
            .unwrap()
            .locked_state()
            .locked_block_hash,
        Some(TARGET)
    );

    // outbound：verified QC → 编码+签名 → B（只发 QC，隔离「QC 不直接 finalize」路径；
    // A 的 precommit Vote 是本步之前的正常 outbound，不发给 B）
    let out = rig_a.collect_outbound();
    let qc_msgs: Vec<OutboundConsensusMessage> = out
        .into_iter()
        .filter(|m| matches!(m, OutboundConsensusMessage::VerifiedQc(_)))
        .collect();
    assert_eq!(qc_msgs.len(), 1, "verified QC 必须是 outbound");
    rig_a.send_consensus(qc_msgs);

    // B：inbound QC → decode_qc → submit_inbound_qc（verify_qc PASS；无 actor ⇒ 空 lock loop）。
    // inbound QC 不经 canonical（外部 QC ingestion DEFERRED）⇒ 不直接 finalize（B finality 保持 None）。
    rig_b.poll();
    assert_eq!(
        rig_b.el.diagnostics().handler_errors,
        0,
        "有效 QC verify PASS"
    );
    assert_eq!(
        rig_b.state().finality.finalized_reference,
        None,
        "inbound QC 不得直接 finalize"
    );
}

// ---------- H-5 ----------

/// H-5：shutdown —— EventLoop → NS → Driver drop；停止后无新 vote / 拒新事件 / 无新 outbound。
#[test]
fn h5_shutdown_order_blocks_new_votes() {
    let kp_a = KeyPair::generate().unwrap();
    let net_a = KeyPair::generate().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let a_id = node_id_of(&kp_a);
    let b_id = node_id_of(&peer_kp);
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set_for(&kp_a), GENESIS_HASH, dag_aa());
    let driver = NodeConsensusDriver::new(consensus, vec![actor_of(kp_a)]);
    let (ta, _tb) = MemoryTransport::pair(a_id, b_id);
    let mut rig = make_rig(driver, net_a, b_id, ta);

    // 先处理一票
    let pr = proposal_for(rig.driver());
    rig.driver_mut().submit_proposal(pr);
    rig.driver_mut()
        .submit_local_vote(0, &prevote_req())
        .unwrap()
        .unwrap();
    assert_eq!(rig.driver().outbound_pending_len(), 1);
    let _ = rig.collect_outbound();

    rig.el.shutdown();
    // 顺序：EventLoop stop → NS stop（独立 owner 顺序）；队列清空
    assert_eq!(rig.el.state(), EventLoopState::Stopped);
    assert_eq!(rig.el.pending_len(), 0);
    rig.ns.shutdown();
    assert_eq!(rig.ns.state(), NetworkServiceState::Stopped);

    // 停止后：拒绝新事件 / poll；handler 不再被调用（无新 vote、无新 outbound）
    assert_eq!(
        rig.el
            .push_event(NodeEvent::Internal(InternalEvent::Wakeup)),
        Err(EventLoopError::Stopped)
    );
    assert_eq!(rig.el.poll_once(&mut rig.ns), Err(EventLoopError::Stopped));
    let dispatched = rig.el.diagnostics().events_dispatched;
    rig.el.shutdown(); // 幂等
    assert_eq!(
        rig.el.diagnostics().events_dispatched,
        dispatched,
        "无新 dispatch"
    );
    assert_eq!(rig.el.handler().driver().outbound_pending_len(), 0);
    assert_eq!(rig.egress.len(), 0, "shutdown 后无新 outbound");
    // Driver drop 随本测试 rig 作用域结束（本装配无 SafetyStore ⇒ 不写 store）
}

// ---------- H-6 ----------

/// 唯一临时目录（Drop 清理）。
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nova_h6_{}_{}_{}", std::process::id(), n, tag));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }
    fn journal(&self) -> PathBuf {
        self.path.join("safety.journal")
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 固定公钥测试 signer（validator identity 可重建；Restart Safety 语义不需要真实密码签名）。
struct FixedSigner {
    public: [u8; 32],
    count: Rc<Cell<usize>>,
}
impl SigningCapability for FixedSigner {
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public).expect("固定公钥合法")
    }
    fn sign(&self, _message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        self.count.set(self.count.get() + 1);
        Ok(Signature::from_bytes(&[0x5A; 64]).expect("sig"))
    }
}

fn valid_public_key() -> [u8; 32] {
    KeyPair::generate().unwrap().verifying_key().to_bytes()
}
fn vid_of_pk(pk: &[u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(pk)
}
fn identity_for(pk: &[u8; 32]) -> SafetyIdentity {
    SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, GENESIS_HASH, &vid_of_pk(pk))
}
fn set_for_pk(pk: [u8; 32]) -> ValidatorSet {
    ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: pk,
        bonded_stake: 100,
        commission_bps: 100,
    }]))
}
fn req_vote(target: [u8; 32], vt: VoteType) -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type: vt,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}
fn key_of(vt: VoteType) -> VoteKey {
    VoteKey {
        height: 0,
        round: 0,
        vote_type: vt,
    }
}
fn ev_sig(ev: &ConsensusEvent) -> [u8; 64] {
    match ev {
        ConsensusEvent::Vote { signature, .. } => *signature,
        other => panic!("必须为 ConsensusEvent::Vote，got {other:?}"),
    }
}

/// H-6：restart —— SafetyStore restore + consensus 重建 + 网络重新建立。
#[test]
fn h6_restart_restores_safety_and_rebuilds_network() {
    let tmp = TempDir::new("h6");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let vid = vid_of_pk(&pk);
    let set = set_for_pk(pk);
    let dag = dag_aa();

    // --- 首启：durable actor（写 header + prevote intent/signature）---
    let store1 = ValidatorSafetyStore::create(&journal, identity_for(&pk)).unwrap();
    let count1 = Rc::new(Cell::new(0usize));
    let actor1 = ValidatorActor::restore(
        vid,
        FixedSigner {
            public: pk,
            count: count1.clone(),
        },
        CHAIN_ID,
        store1,
    )
    .expect("首启恢复");
    let ev1 = actor1
        .produce_vote(&req_vote(TARGET, VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次 prevote");
    drop(actor1); // clean shutdown（journal durable）

    // --- restart：SafetyStore restore → ledger 恢复 ---
    let store2 = ValidatorSafetyStore::at(&journal, identity_for(&pk));
    let count2 = Rc::new(Cell::new(0usize));
    let actor2 = ValidatorActor::restore(
        vid,
        FixedSigner {
            public: pk,
            count: count2.clone(),
        },
        CHAIN_ID,
        store2,
    )
    .expect("restart 恢复");
    let rec = actor2
        .vote_ledger()
        .lookup(&key_of(VoteType::Prevote))
        .expect("ledger 恢复");
    assert_eq!(rec.target_block_hash, TARGET);
    assert!(rec.signature.is_some(), "signature 恢复");
    // 幂等复用（同 target 不再双投新签名）
    let ev2 = actor2
        .produce_vote(&req_vote(TARGET, VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("恢复后同 target 允许");
    assert_eq!(
        ev_sig(&ev1),
        ev_sig(&ev2),
        "restart 后复用同一签名（不 double-sign）"
    );

    // --- consensus 重建：新 ConsensusNode + driver 装配可继续（round 由对等重建）---
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag);
    let mut driver = NodeConsensusDriver::new(consensus, vec![actor2]);
    let r = driver.submit_proposal(proposer_ref(vid));
    assert!(matches!(r, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);
    assert_eq!(driver.actor_count(), 1);

    // --- 网络重新建立：新 NS+EventLoop（新测试网络 key）→ Ping/Pong 真实往返成功 ---
    let net_x = KeyPair::generate().unwrap();
    let net_y = KeyPair::generate().unwrap();
    let x_id = node_id_of(&net_x);
    let y_id = node_id_of(&net_y);
    let (tx, ty) = MemoryTransport::pair(x_id, y_id);
    let egress_x = CollectorEgress::new();
    let egress_y = CollectorEgress::new();
    let mut ns_x = NetworkService::new(NetworkServiceConfig::default(), x_id, tx);
    let mut ns_y = NetworkService::new(NetworkServiceConfig::default(), y_id, ty);
    let driver_x = NodeConsensusDriver::<SoftwareSigner>::new(
        ConsensusNode::new(0, 0, CHAIN_ID, set_for_pk(pk), GENESIS_HASH, dag_aa()),
        Vec::new(),
    );
    let driver_y = NodeConsensusDriver::<SoftwareSigner>::new(
        ConsensusNode::new(0, 0, CHAIN_ID, set_for_pk(pk), GENESIS_HASH, dag_aa()),
        Vec::new(),
    );
    let mut el_x = EventLoop::new(
        EventLoopConfig::default(),
        NodeConsensusHandler::new(driver_x, egress_x.clone()),
    );
    let mut el_y = EventLoop::new(
        EventLoopConfig::default(),
        NodeConsensusHandler::new(driver_y, egress_y.clone()),
    );
    ns_x.connect_peer(y_id).unwrap();
    ns_y.connect_peer(x_id).unwrap();

    // x → y Ping
    let ping = sign_envelope(&net_x, MessageType::Ping, vec![7]);
    ns_x.enqueue_outbound(y_id, ping).expect("enqueue ping");
    ns_x.flush_outbound().unwrap();
    el_y.poll_once(&mut ns_y).expect("y poll");
    assert_eq!(
        el_y.handler().non_consensus_seen(),
        1,
        "Ping 经验签到达 handler"
    );
    // y → x Pong
    let pong = sign_envelope(&net_y, MessageType::Pong, vec![8]);
    ns_y.enqueue_outbound(x_id, pong).expect("enqueue pong");
    ns_y.flush_outbound().unwrap();
    el_x.poll_once(&mut ns_x).expect("x poll");
    assert_eq!(
        el_x.handler().non_consensus_seen(),
        1,
        "Pong 经验签到达 handler"
    );

    // 生命周期独立：EventLoop 与 NetworkService 各自 shutdown
    el_x.shutdown();
    el_y.shutdown();
    ns_x.shutdown();
    ns_y.shutdown();
    assert_eq!(ns_x.state(), NetworkServiceState::Stopped);
    assert_eq!(ns_y.state(), NetworkServiceState::Stopped);
}
