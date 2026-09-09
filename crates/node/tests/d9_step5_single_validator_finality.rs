//! D9 Step 5 — Single-Validator propose → vote → QC/finality 闭环（真实生产原语）。
//!
//! 目标链路（全部复用冻结 consensus / node 原语，不新建第二套共识、不 mock、不手工伪造 QC）：
//!
//! ```text
//! Genesis → ValidatorSet(1)
//!   → select_proposer(round 0) == 本地 validator（真实 ADR-0050 加权选择）
//!   → build_proposal（真实 block_builder 产空块）+ ValidatorActor::sign_block（真实 proposer 签名）
//!   → dispatch_gossip_block_with_validator_set（D9 A11 seam：真实 proposer 验签）→ CanonicalNextCandidate
//!   → apply（真实 block_adapter，head 0 → 1）
//!   → ValidatorActor::produce_vote（真实 ValidatorVote + domain 签名）
//!   → NodeConsensusDriver（真实 verify_vote_input + submit_verified_vote + transition）
//!   → prevote quorum → precommit quorum → derived.precommit_qc
//!   → process_transition_derived（真实 verify_qc）→ 本地 lock
//!   → state.finality.finalized_reference == 真实 block_hash（最终性）
//! ```
//!
//! T5-1：单验证者端到端闭环 → finality PASS。
//! T5-2：非当选 proposer 块在 proposer 验签步被拒（无 apply/vote/QC/finality）。
//! T5-3：篡改 proposer signature 被拒（InvalidProposerSignature）。
//! T5-4：无效 vote（非成员 / 坏签名）经统一 verify 门面被拒，无法形成 QC / finality。
//! T5-5：无 ValidatorSet 的观测入口仍诚实（None ≠ 跳过 proposer 验证）。
//!
//! 测试使用确定性测试 genesis（chain_id=1001、空 accounts、真实 Ed25519 KeyPair）；
//! 不修改生产 genesis / 协议标识符 / 共识规则 / golden vectors。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::integration::{ConsensusEvent, TransitionResult};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, VerifyingKey, sign_message_hash};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;

use nova_node::assembly::ConsensusNode;
use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::block_dispatch::{dispatch_gossip_block, dispatch_gossip_block_with_validator_set};
use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict, UnverifiableItem};
use nova_node::driver::NodeConsensusDriver;
use nova_node::proposer::build_proposal;
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;

type MemAdapter = NodeBlockAdapter<MemoryBackend, NoAccountsKeyResolver>;

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

/// 空 canonical-next 块（height1 / parent=genesis / root=空 root）+ 真实 proposer 签名
/// （DomainId::Block + chain_id + canonical header；签名者 = `sk`）。
fn block_signed_by(sk: &SigningKey) -> Block {
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

fn local_vote_request(target: [u8; 32], vote_type: VoteType) -> LocalVoteRequest {
    LocalVoteRequest {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type,
        source_block_hash: [0; 32],
        timestamp: 0,
    }
}

/// 把真实 block 以共识视图加入 DAG（与既有 driver 测试同一形态：round 0 / 无父 / proposer=本地）。
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

/// 真实签名投票（DomainId::ValidatorVote），用于构造远端/无效 vote 输入。
fn signed_vote(
    sk: &SigningKey,
    validator_id: ValidatorId,
    target: [u8; 32],
    vote_type: VoteType,
) -> (ValidatorVote, [u8; 64]) {
    let vote = ValidatorVote {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type,
        source_block_hash: [0; 32],
        validator_id,
        timestamp: 0,
    };
    let payload = canonical_vote_payload(&vote);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        CHAIN_ID,
        &payload,
    )
    .unwrap();
    let sig = sign_message_hash(sk, &hash_signing_message(&signed)).to_bytes();
    (vote, sig)
}

// ---------------------------------------------------------------------------
// T5-1 — 单验证者端到端闭环：真实 block → seam → apply → prevote/precommit → QC → finality
// ---------------------------------------------------------------------------

#[test]
fn d9_s5_t1_single_validator_full_finality() {
    let kp = KeyPair::generate().unwrap();
    let local_id = id_of(&kp);
    let vk = VerifyingKey::from_bytes(&kp.verifying_key().to_bytes()).unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    assert_eq!(
        select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap(),
        local_id,
        "单验证者 (0,0) 必为 proposer"
    );

    let adapter = fresh_adapter();

    // ① 真实 proposer build（临时 consensus 只读判定：高度同步 gate rs.height==head.height==0）
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(local_id, &tmp, &adapter, 0)
        .unwrap()
        .expect("本地为 proposer ⇒ 必须产出真实 proposal");
    assert_eq!(pb.proposal_ref.block_hash, pb.block_hash);
    assert_eq!(pb.proposal_ref.proposer, local_id);

    // ② 真实 proposer 签名（node identity == validator identity；单一 key 移入 actor）
    let actor = ValidatorActor::new(local_id, SoftwareSigner::new(kp), CHAIN_ID).unwrap();
    let mut block = pb.block;
    actor.sign_block(&mut block).unwrap();

    // ③ 经 D9 A11 seam 做真实 canonical/proposer 验证（block 不携带 proposer 自证）
    let gossip = wire(&block);
    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: pb.block_hash,
            height: 1,
        }),
        "当选 proposer 的签名块必须通过 full canonical validation"
    );

    // ④ 真实 apply（head 0 → 1）
    let mut adapter = adapter;
    let applied = adapter.apply_block(&gossip, &vk).unwrap();
    assert_eq!(applied.block_hash, pb.block_hash);
    assert_eq!(adapter.head().height, 1, "head 推进 +1");

    // ⑤ 真实共识驱动：proposal → prevote → precommit → precommit QC → finality + lock
    let mut driver = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set,
            GENESIS_HASH,
            dag_with(pb.block_hash, local_id),
        ),
        vec![actor],
    );

    let r0 = driver.submit_proposal(pb.proposal_ref);
    assert!(
        matches!(r0, TransitionResult::Applied { .. }),
        "proposal Applied"
    );
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);

    // prevote（单验证者权重 100 >= quorum ceil(2*100/3)=67）
    let r1 = driver
        .submit_local_vote(0, &local_vote_request(pb.block_hash, VoteType::Prevote))
        .unwrap()
        .expect("本地 prevote 应提交");
    assert!(matches!(&r1, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Precommit);
    driver.process_transition_derived(&r1).unwrap();

    // precommit → precommit QC → finality advance
    let r2 = driver
        .submit_local_vote(0, &local_vote_request(pb.block_hash, VoteType::Precommit))
        .unwrap()
        .expect("本地 precommit 应提交");
    assert!(matches!(&r2, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Finalized);
    let has_qc = matches!(
        &r2,
        TransitionResult::Applied { derived, .. } if derived.precommit_qc.is_some()
    );
    assert!(has_qc, "derived.precommit_qc 不得丢失");
    driver.process_transition_derived(&r2).unwrap();

    // ⑥ 最终性：finalized_reference == 真实 proposed block reference；本地 lock 达成
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        Some(pb.block_hash),
        "finalized reference 必须是本节点产出的真实 block"
    );
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        Some(pb.block_hash),
        "本地 validator 在 precommit QC 后 lock 该 block"
    );
}

// ---------------------------------------------------------------------------
// T5-2 — 非当选 proposer：proposer 验签被拒；无 apply/vote/QC/finality
// ---------------------------------------------------------------------------

#[test]
fn d9_s5_t2_wrong_proposer_cannot_enter_finality() {
    let kp_member = KeyPair::generate().unwrap();
    let kp_outsider = KeyPair::generate().unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_member, 100)]));
    let adapter = fresh_adapter();
    let head_before = adapter.head().clone();

    // 非成员（非当选）签名的 block
    let gossip = wire(&block_signed_by(kp_outsider.signing_key()));
    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Err(InboundBlockError::InvalidProposerSignature),
        "非当选 proposer 必须在 proposer 验签步被拒"
    );
    assert_eq!(adapter.head(), &head_before, "无 apply");
}

// ---------------------------------------------------------------------------
// T5-3 — 篡改 proposer signature：InvalidProposerSignature
// ---------------------------------------------------------------------------

#[test]
fn d9_s5_t3_corrupted_proposer_signature_cannot_enter_finality() {
    let kp = KeyPair::generate().unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let adapter = fresh_adapter();
    let head_before = adapter.head().clone();

    let mut block = block_signed_by(kp.signing_key());
    block.proposer_signature[0] ^= 0xFF; // 篡改（block_hash 不含 signature）
    let result =
        dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &wire(&block), &set);
    assert_eq!(
        result,
        Err(InboundBlockError::InvalidProposerSignature),
        "篡改 proposer signature 必须被拒"
    );
    assert_eq!(adapter.head(), &head_before, "无 apply");
}

// ---------------------------------------------------------------------------
// T5-4 — 无效 vote 无法形成 QC / finality（统一 verify_vote_input 门面拒绝）
// ---------------------------------------------------------------------------

#[test]
fn d9_s5_t4_invalid_vote_cannot_create_qc() {
    let kp = KeyPair::generate().unwrap();
    let local_id = id_of(&kp);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let target = [0xAA; 32];
    let mut driver = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set.clone(),
            GENESIS_HASH,
            dag_with(target, local_id),
        ),
        vec![ValidatorActor::new(local_id, SoftwareSigner::new(kp), CHAIN_ID).unwrap()],
    );
    let r0 = driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer: local_id,
    });
    assert!(matches!(r0, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);

    // (a) 非成员 vote（outsider 签名）：verify_vote_input membership 拒 ⇒ 无法进 transition
    let outsider = KeyPair::generate().unwrap();
    let (vote_outsider, sig_outsider) = signed_vote(
        outsider.signing_key(),
        id_of(&outsider),
        target,
        VoteType::Prevote,
    );
    assert!(
        driver
            .submit_remote_vote(vote_outsider, sig_outsider)
            .is_err()
    );
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        None,
        "非成员 vote 不得形成 finality"
    );

    // (b) 成员身份但坏签名：先取真实成员 prevote 事件，篡改签名后提交 ⇒ verify 门面拒
    let req = local_vote_request(target, VoteType::Prevote);
    let event = driver
        .actor(0)
        .unwrap()
        .produce_vote(
            &req,
            driver.consensus().validator_set(),
            driver.consensus().dag(),
        )
        .unwrap()
        .expect("成员 prevote 应被授权");
    let (vote, mut signature) = match event {
        ConsensusEvent::Vote { vote, signature } => (vote, signature),
        _ => unreachable!("produce_vote 只产出 ConsensusEvent::Vote"),
    };
    signature[0] ^= 0xFF;
    assert!(driver.submit_remote_vote(vote, signature).is_err());
    assert_eq!(
        driver.consensus().state().finality.finalized_reference,
        None,
        "坏签名 vote 不得形成 finality"
    );
    // 阶段未被无效 vote 推进（状态不变）
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);
}

// ---------------------------------------------------------------------------
// T5-5 — None 观测入口保持诚实
// ---------------------------------------------------------------------------

#[test]
fn d9_s5_t5_none_entry_remains_strict() {
    let kp = KeyPair::generate().unwrap();
    let _set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let adapter = fresh_adapter();
    let gossip = wire(&block_signed_by(kp.signing_key()));

    // 同一合法块：无 ValidatorSet 的观测入口仍 Unsupported（不放宽为跳过验证）
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &gossip);
    assert_eq!(
        result,
        Err(InboundBlockError::UnsupportedValidation(
            UnverifiableItem::ProposerSignature
        ))
    );
    // 有 ValidatorSet 的 seam 才能验证通过（T5-1 已证明）
}
