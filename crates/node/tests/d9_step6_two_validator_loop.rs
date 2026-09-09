//! D9 Step 6 — Two-Validator A/B loop（真实生产原语）。
//!
//! 证明：ValidatorSet(A,B)（各 stake 100、total 200 → 生产 quorum = ValidatorSet::quorum()，
//! 不硬编码 134）下，经生产 `select_proposer` 选出 P；P 真实产块/签名；非 proposer Q 经 D9 A11
//! seam 独立验证 P 的 proposer 签名（expected = select，不信任 block 自证）后与 P 各自 apply
//! 同一真实 block（两节点 head 各 +1）；A、B 以真实 ValidatorActor 产 vote 并相互传播
//! （对方节点经真实 verify_vote_input + canonical transition）达成 prevote/precommit quorum →
//! 生产 PrecommitQC → 双方 finalized_reference == 真实 block_hash。
//!
//! T6-1 two_validator_full_loop
//! T6-2 wrong_proposer_rejected（成员但非当选 ⇒ InvalidProposerSignature，head 不变）
//! T6-3 corrupted_proposer_signature_rejected
//! T6-4 single_vote_insufficient_for_qc（仅 A ⇒ 无 prevote quorum / 无 QC / 无 finality）
//! T6-5 two_votes_create_qc_and_finality（A+B 真实 vote ⇒ 生产 QC + finality；QC 字段校验）
//! T6-6 wrong_parent_or_height_rejected（ConflictingParent / FutureMissingAncestor，head 不变）
//!
//! 测试使用确定性 genesis（chain=1001、空 accounts、真实 Ed25519 key）；不修改
//! consensus 规则 / 协议 / golden / D8；不 mock / 不伪造 QC。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::integration::{ConsensusEvent, TransitionResult};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{VerifyingKey, sign_message_hash};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;

use nova_node::assembly::ConsensusNode;
use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::block_dispatch::dispatch_gossip_block_with_validator_set;
use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict};
use nova_node::driver::NodeConsensusDriver;
use nova_node::proposer::build_proposal;
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;

type MemAdapter = NodeBlockAdapter<MemoryBackend, NoAccountsKeyResolver>;
type MemDriver = NodeConsensusDriver<SoftwareSigner>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn vin(kp: &KeyPair, stake: u128) -> ValidatorInit {
    ValidatorInit {
        account_address: addr([0x11; 32]),
        consensus_public_key: kp.verifying_key().to_bytes(),
        bonded_stake: stake,
        commission_bps: 100,
    }
}

fn genesis_with(validators: Vec<ValidatorInit>) -> GenesisV1 {
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 0,
        initial_validator_set: validators,
        initial_accounts: Vec::new(),
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: MAX_GAS,
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

fn id_of(kp: &KeyPair) -> ValidatorId {
    ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
}

fn empty_root() -> [u8; 32] {
    *StateStore::new(MemoryBackend::new())
        .state_root()
        .as_bytes()
}

/// 空 canonical-next 块（height1/parent=genesis/root=空）+ 真实 proposer 域签名（`sk`）。
fn block_signed_by(sk: &nova_crypto::signature::SigningKey) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

/// wrong-parent 空块（height1、parent≠genesis）。
fn block_wrong_parent(sk: &nova_crypto::signature::SigningKey) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: [0x99; 32],
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

/// wrong-height 空块（height2、parent=genesis）。
fn block_future_height(sk: &nova_crypto::signature::SigningKey) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 2,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

fn wire(block: &Block) -> Vec<u8> {
    encode_block(block).unwrap()
}

fn fresh_adapter() -> MemAdapter {
    let store = StateStore::new(MemoryBackend::new());
    let head = ChainHead::genesis(GENESIS_HASH, store.state_root());
    NodeBlockAdapter::new(
        store,
        NoAccountsKeyResolver,
        CHAIN_ID,
        GENESIS_HASH,
        MAX_GAS,
        0,
        head,
        NetworkId::Mainnet,
    )
}

fn vote_request(target: [u8; 32], vote_type: VoteType) -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

fn dag_with(block_hash: [u8; 32], proposer: ValidatorId) -> Dag {
    let mut dag = Dag::new();
    dag.add_block(BlockReference {
        block_hash,
        height: 0,
        parents: vec![],
        proposer,
    })
    .unwrap();
    dag
}

fn actor_of(kp: KeyPair, id: ValidatorId) -> ValidatorActor<SoftwareSigner> {
    ValidatorActor::new(id, SoftwareSigner::new(kp), CHAIN_ID).unwrap()
}

fn event_parts(event: ConsensusEvent) -> (ValidatorVote, [u8; 64]) {
    match event {
        ConsensusEvent::Vote { vote, signature } => (vote, signature),
        _ => unreachable!("produce_vote 只产出 ConsensusEvent::Vote"),
    }
}

/// 双验证者 setup：genesis(A,B) → 真实 actor_a/actor_b + 各自 adapter。
struct AB {
    set: ValidatorSet,
    id_a: ValidatorId,
    id_b: ValidatorId,
    vk_a: VerifyingKey,
    vk_b: VerifyingKey,
    quorum: u128,
    adapter_a: MemAdapter,
    adapter_b: MemAdapter,
}

fn setup_ab() -> (
    AB,
    ValidatorActor<SoftwareSigner>,
    ValidatorActor<SoftwareSigner>,
) {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let vk_a = VerifyingKey::from_bytes(&kp_a.verifying_key().to_bytes()).unwrap();
    let vk_b = VerifyingKey::from_bytes(&kp_b.verifying_key().to_bytes()).unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let ab = AB {
        quorum: set.quorum(),
        id_a,
        id_b,
        vk_a,
        vk_b,
        adapter_a: fresh_adapter(),
        adapter_b: fresh_adapter(),
        set: set.clone(),
    };
    let actor_a = actor_of(kp_a, id_a);
    let actor_b = actor_of(kp_b, id_b);
    (ab, actor_a, actor_b)
}

/// 双节点投票：A、B 各投本地真实 vote，并相互以 submit_remote_vote 传播。
fn submit_vote_pair(d_a: &mut MemDriver, d_b: &mut MemDriver, request: &LocalVoteRequest) {
    d_a.submit_local_vote(0, request).unwrap();
    d_b.submit_local_vote(0, request).unwrap();
    let ev_a = d_a
        .actor(0)
        .unwrap()
        .produce_vote(
            request,
            d_a.consensus().validator_set(),
            d_a.consensus().dag(),
        )
        .unwrap()
        .expect("A vote 应被授权");
    let (va, sa) = event_parts(ev_a);
    d_b.submit_remote_vote(va, sa).unwrap();
    let ev_b = d_b
        .actor(0)
        .unwrap()
        .produce_vote(
            request,
            d_b.consensus().validator_set(),
            d_b.consensus().dag(),
        )
        .unwrap()
        .expect("B vote 应被授权");
    let (vb, sb) = event_parts(ev_b);
    d_a.submit_remote_vote(vb, sb).unwrap();
}

// ---------------------------------------------------------------------------
// T6-1 — 双验证者完整闭环
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t1_two_validator_full_loop() {
    let (ab, actor_a, actor_b) = setup_ab();
    let (set, id_a, id_b, vk_a, vk_b, quorum, adapter_a, adapter_b) = (
        ab.set.clone(),
        ab.id_a,
        ab.id_b,
        ab.vk_a,
        ab.vk_b,
        ab.quorum,
        ab.adapter_a,
        ab.adapter_b,
    );
    assert!(
        100 < quorum && 200 >= quorum,
        "生产 quorum={quorum}：单方不足、双方达"
    );

    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected proposer must be A or B"
    );
    let p_is_a = selected == id_a;
    let vk_p = if p_is_a { vk_a } else { vk_b };
    let (actor_a, actor_b) = (actor_a, actor_b);

    // ① P 真实 build（临时 consensus 只读判定：rs.height==head.height==0）
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(selected, &tmp, &adapter_a, 0)
        .unwrap()
        .expect("proposer 必须产出真实 proposal");
    assert_eq!(pb.proposal_ref.proposer, selected);

    // ② P 真实签名（当选者的 actor）
    let mut block = pb.block;
    if p_is_a {
        actor_a.sign_block(&mut block).unwrap();
    } else {
        actor_b.sign_block(&mut block).unwrap();
    }
    let gossip = wire(&block);

    // ③ 双节点入站验证（A11 seam：expected=select；Q 节点独立验证 P 的 proposer 签名）
    let r_a = dispatch_gossip_block_with_validator_set(&adapter_a, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        r_a,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: pb.block_hash,
            height: 1
        })
    );
    let r_b = dispatch_gossip_block_with_validator_set(&adapter_b, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        r_b,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: pb.block_hash,
            height: 1
        })
    );

    // ④ 双节点 apply（同一 canonical 块，proposer vk = P）
    let mut adapter_a = adapter_a;
    let mut adapter_b = adapter_b;
    adapter_a.apply_block(&gossip, &vk_p).unwrap();
    adapter_b.apply_block(&gossip, &vk_p).unwrap();
    assert_eq!(adapter_a.head().height, 1);
    assert_eq!(adapter_b.head().height, 1);

    // ⑤ 双节点共识：各自 ConsensusNode（DAG 含真实 block）注册 P 的 proposal
    let mut d_a = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set.clone(),
            GENESIS_HASH,
            dag_with(pb.block_hash, selected),
        ),
        vec![actor_a],
    );
    let mut d_b = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set.clone(),
            GENESIS_HASH,
            dag_with(pb.block_hash, selected),
        ),
        vec![actor_b],
    );
    d_a.submit_proposal(pb.proposal_ref);
    d_b.submit_proposal(ProposalRef {
        block_hash: pb.block_hash,
        proposer: selected,
    });
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Prevote);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Prevote);

    // ⑥ prevote：A+B（相互传播）→ prevote quorum → Precommit（两节点各自）
    submit_vote_pair(
        &mut d_a,
        &mut d_b,
        &vote_request(pb.block_hash, VoteType::Prevote),
    );
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Precommit);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Precommit);

    // ⑦ precommit：A+B → 各自 PrecommitQC + finality
    submit_vote_pair(
        &mut d_a,
        &mut d_b,
        &vote_request(pb.block_hash, VoteType::Precommit),
    );
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        Some(pb.block_hash)
    );
    assert_eq!(
        d_b.consensus().state().finality.finalized_reference,
        Some(pb.block_hash)
    );

    // ⑧ 双节点 head 均推进同一真实 block
    assert_eq!(adapter_a.head().height, 1, "A head +1");
    assert_eq!(adapter_b.head().height, 1, "B head +1");
}

// ---------------------------------------------------------------------------
// T6-2 — 成员但非当选 proposer：proposer 验签被拒；head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t2_wrong_proposer_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter_a = fresh_adapter();
    let adapter_b = fresh_adapter();
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected must be a member"
    );
    // 用「另一成员（非当选）」签名
    let q_kp = if selected == id_a { &kp_b } else { &kp_a };
    let gossip = wire(&block_signed_by(q_kp.signing_key()));
    let r_a = dispatch_gossip_block_with_validator_set(&adapter_a, MAX_BLOCK_BYTES, &gossip, &set);
    let r_b = dispatch_gossip_block_with_validator_set(&adapter_b, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(r_a, Err(InboundBlockError::InvalidProposerSignature));
    assert_eq!(r_b, Err(InboundBlockError::InvalidProposerSignature));
    assert_eq!(adapter_a.head().height, 0, "A head 不变");
    assert_eq!(adapter_b.head().height, 0, "B head 不变");
}

// ---------------------------------------------------------------------------
// T6-3 — 篡改 proposer signature
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t3_corrupted_proposer_signature_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter = fresh_adapter();
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected must be a member"
    );
    let p_kp = if selected == id_a { &kp_a } else { &kp_b };
    let mut block = block_signed_by(p_kp.signing_key());
    block.proposer_signature[0] ^= 0xFF;
    let r =
        dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &wire(&block), &set);
    assert_eq!(r, Err(InboundBlockError::InvalidProposerSignature));
    assert_eq!(adapter.head().height, 0, "head 不变");
}

// ---------------------------------------------------------------------------
// T6-4 — 仅 A 一票：不足以形成 QC / finality
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t4_single_vote_insufficient_for_qc() {
    let (ab, actor_a, _actor_b) = setup_ab();
    let set = ab.set.clone();
    let quorum = ab.quorum;
    assert!(100 < quorum, "单方 100 < quorum {quorum}");
    let target = [0xAB; 32];
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();

    let mut driver = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set,
            GENESIS_HASH,
            dag_with(target, selected),
        ),
        vec![actor_a],
    );
    driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer: selected,
    });
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);

    // 仅 A prevote：一票 100 < quorum ⇒ 无 prevote quorum、step 不推进
    let r = driver
        .submit_local_vote(0, &vote_request(target, VoteType::Prevote))
        .unwrap()
        .expect("A prevote 应被提交");
    assert!(
        matches!(&r, TransitionResult::Applied { observation, .. } if !observation.prevote_quorum)
    );
    assert_eq!(
        driver.consensus().state().round.step,
        RoundStep::Prevote,
        "无 prevote quorum 不推进"
    );
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        None
    );

    // precommit 尝试：上下文门（step 未 Precommit）⇒ 无事件
    assert!(
        driver
            .submit_local_vote(0, &vote_request(target, VoteType::Precommit))
            .unwrap()
            .is_none(),
        "单方 prevote 未达 quorum ⇒ precommit 不被接受"
    );
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
}

// ---------------------------------------------------------------------------
// T6-5 — A+B 两票形成生产 QC 与 finality（QC 字段校验）
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t5_two_votes_create_qc_and_finality() {
    let (ab, actor_a, actor_b) = setup_ab();
    let set = ab.set.clone();
    let target = [0xCD; 32];
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();

    let mut driver = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set,
            GENESIS_HASH,
            dag_with(target, selected),
        ),
        vec![actor_a, actor_b],
    );
    driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer: selected,
    });

    // prevote：A（idx0）不足 → B（idx1）达 quorum
    let r0 = driver
        .submit_local_vote(0, &vote_request(target, VoteType::Prevote))
        .unwrap()
        .unwrap();
    assert!(
        matches!(&r0, TransitionResult::Applied { observation, .. } if !observation.prevote_quorum)
    );
    let r1 = driver
        .submit_local_vote(1, &vote_request(target, VoteType::Prevote))
        .unwrap()
        .unwrap();
    assert!(
        matches!(&r1, TransitionResult::Applied { observation, .. } if observation.prevote_quorum)
    );
    assert_eq!(driver.consensus().state().round.step, RoundStep::Precommit);
    driver.process_transition_derived(&r1).unwrap();

    // precommit：A + B → 生产 precommit QC + finality
    let r2 = driver
        .submit_local_vote(0, &vote_request(target, VoteType::Precommit))
        .unwrap()
        .unwrap();
    let r3 = driver
        .submit_local_vote(1, &vote_request(target, VoteType::Precommit))
        .unwrap()
        .unwrap();
    assert!(
        matches!(&r2, TransitionResult::Applied { observation, .. } if !observation.precommit_quorum)
    );
    let qc = match &r3 {
        TransitionResult::Applied { derived, .. } => {
            derived.precommit_qc.as_ref().expect("precommit QC")
        }
        _ => panic!("precommit 必须 Applied"),
    };
    assert_eq!(qc.context.vote_type, VoteType::Precommit);
    assert_eq!(
        qc.validator_set_id, GENESIS_HASH,
        "validator_set_id = genesis_hash"
    );
    assert_eq!(qc.target, target, "QC target == proposal");
    assert_eq!(driver.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        Some(target)
    );

    // 生产 verify_qc 门面（driver 路由）：通过且 actor lock 达成
    driver.process_transition_derived(&r3).unwrap();
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        Some(target)
    );
    assert_eq!(
        driver.actor(1).unwrap().locked_state().locked_block_hash,
        Some(target)
    );
}

// ---------------------------------------------------------------------------
// T6-6 — wrong parent / wrong height：分类拒绝，head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_s6_t6_wrong_parent_or_height_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter_a = fresh_adapter();
    let adapter_b = fresh_adapter();
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected must be a member"
    );
    let p_kp = if selected == id_a { &kp_a } else { &kp_b };

    // wrong parent（当选签名）：height1 但 parent≠genesis ⇒ ConflictingParent（分类在 proposer 前）
    let gossip_p = wire(&block_wrong_parent(p_kp.signing_key()));
    let r = dispatch_gossip_block_with_validator_set(&adapter_a, MAX_BLOCK_BYTES, &gossip_p, &set);
    assert!(matches!(
        r,
        Ok(InboundBlockVerdict::ConflictingParent { height: 1, .. })
    ));

    // wrong height：height2（> head+1）⇒ FutureMissingAncestor
    let gossip_h = wire(&block_future_height(p_kp.signing_key()));
    let r = dispatch_gossip_block_with_validator_set(&adapter_b, MAX_BLOCK_BYTES, &gossip_h, &set);
    assert!(matches!(
        r,
        Ok(InboundBlockVerdict::FutureMissingAncestor { height: 2, .. })
    ));

    assert_eq!(adapter_a.head().height, 0, "A head 不变");
    assert_eq!(adapter_b.head().height, 0, "B head 不变");
}
