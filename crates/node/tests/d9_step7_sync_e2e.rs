//! D9 Step 7 — Sync E2E（证明 **Sync ≠ trusted input**）。
//!
//! 核心安全性质：远端同步得到的 block **不能绕过 D9 A11 proposer verification**。同步只是
//! 传输方式，不是信任边界 —— 远端 block 必须仍由接收方以自己的 `ValidatorSet` 独立推导
//! expected proposer（`select_proposer(parent_height, round)`）→ expected proposer VK →
//! 执行 proposer 签名验证；验证通过才 `CanonicalNextCandidate` → apply → vote → consensus。
//!
//! 场景（Node A / Node B，ValidatorSet(A,B) 各 stake 100、total 200；生产 quorum =
//! `ValidatorSet::quorum()`，不硬编码）：`select_proposer` 真实选出 P（P 可能是 A 或 B，
//! 不人为改变 selection）；P 真实产块/签名 → 生产者本地经 D9 A11 gossip seam
//! （`dispatch_gossip_block_with_validator_set`）验证 + apply；另一节点 Q 经 **真实 SyncBlockResponse
//! 传输**（sync response codec）→ sync dispatch → inbound validation 获得同一 block ——
//! 使用 Sync 对称 A11 seam（`dispatch_sync_block_response_with_validator_set`，本地 ValidatorSet
//! 注入 expected proposer VK）执行 proposer 验签 → `CanonicalNextCandidate` → apply；
//! A/B 双节点以真实 ValidatorActor 产 vote 互传 → prevote/precommit quorum → 生产 PrecommitQC →
//! 双方 finalized_reference == 真实 block_hash。
//!
//! T7-1 normal sync E2E（producer + receiver 闭环）
//! T7-2 wrong proposer through sync（成员但非当选 ⇒ InvalidProposerSignature；无 apply / vote / QC / finality）
//! T7-3 corrupted proposer signature through sync
//! T7-4 wrong parent / height through sync（复用既有 ConflictingParent / FutureMissingAncestor 分类）
//! T7-5 unknown proposer through sync（非 ValidatorSet 成员签名 ⇒ InvalidProposerSignature）
//! T7-6 honest None seam（无 ValidatorSet 的 sync 入口对 canonical-next ⇒ UnsupportedValidation，
//!       None ≠ skip：绝不绕过 proposer 验证放行）
//!
//! 禁止 fake：block 必须真实 `build_proposal` + 真实 proposer 签名；验证经真实生产
//! validator logic（不 mock、不伪造 QC/vote/finality、不手动改 head）。不修改 consensus 规则 /
//! 协议 / golden / D8；不触碰 runtime.rs / sync_scheduler / sync_correlator / handshake。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::integration::ConsensusEvent;
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
use nova_network::security::RequestId;
use nova_network::sync::{BlockPayload, SyncBlockResponse};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;

use nova_node::assembly::ConsensusNode;
use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::block_dispatch::{
    dispatch_gossip_block_with_validator_set, dispatch_sync_block_response,
    dispatch_sync_block_response_with_validator_set,
};
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
// Fixtures（与 D9 Step 6 一致：确定性 genesis、真实 Ed25519、无 mock）
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

/// 空块（给定 height / parent / root / 时间戳）+ 真实 proposer 域签名（`sk`）。
fn raw_block(
    sk: &nova_crypto::signature::SigningKey,
    height: u64,
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    timestamp: u64,
) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height,
        parent_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: [0u8; 32],
        timestamp,
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

/// 空 canonical-next 块（height1 / parent=genesis / root=空）+ 真实签名。
fn canonical_next_block(sk: &nova_crypto::signature::SigningKey) -> Block {
    raw_block(sk, 1, GENESIS_HASH, empty_root(), 0)
}

/// wrong-parent 空块（height1、parent≠genesis）。
fn block_wrong_parent(sk: &nova_crypto::signature::SigningKey) -> Block {
    raw_block(sk, 1, [0x99; 32], empty_root(), 0)
}

/// future-height 空块（height2、parent=genesis ⇒ 祖先缺失分类）。
fn block_future_height(sk: &nova_crypto::signature::SigningKey) -> Block {
    raw_block(sk, 2, GENESIS_HASH, empty_root(), 0)
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

/// 把单个 block 编成真实 SyncBlockResponse payload（生产 codec：request_id + count + blocks）。
fn sync_payload(block: &Block) -> Vec<u8> {
    SyncBlockResponse {
        request_id: RequestId::from_bytes([0x42; 16]),
        blocks: vec![BlockPayload(wire(block))],
    }
    .encode()
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
// T7-1 — 正常 Sync E2E：P 产块 → P 本地验证+apply → Q 经 sync 收（A11 验 proposer）
//        → Q apply → A/B vote → 双方 finality == 真实 block
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t1_normal_sync_e2e() {
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
    assert!(100 < quorum && 200 >= quorum, "生产 quorum={quorum}");

    // ① select_proposer 真实选出 P（父高轮 height 0 / round 0）—— 不人为改变 selection。
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected proposer must be A or B"
    );
    let p_is_a = selected == id_a;
    let vk_p = if p_is_a { vk_a } else { vk_b };
    // producer 用自己 node（本地验证+apply）；另一节点 Q 经 **sync** 收同一 block。
    let (mut producer_adapter, mut receiver_adapter) = if p_is_a {
        (adapter_a, adapter_b)
    } else {
        (adapter_b, adapter_a)
    };

    // ② P 真实 build（临时 consensus 只读判定：rs.height == head.height == 0）。
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(selected, &tmp, &producer_adapter, 0)
        .unwrap()
        .expect("proposer 必须产出真实 proposal");
    assert_eq!(pb.proposal_ref.proposer, selected);
    let mut block = pb.block;
    if p_is_a {
        actor_a.sign_block(&mut block).unwrap();
    } else {
        actor_b.sign_block(&mut block).unwrap();
    }
    let block_hash = pb.block_hash;
    let gossip = wire(&block);
    assert_eq!(
        nova_runtime::block_hash(&block).unwrap(),
        block_hash,
        "sign 不改 block hash"
    );

    // ③ 生产者本地验证（D9 A11 gossip seam：expected = select；canonical-next 验 proposer）。
    let r_p =
        dispatch_gossip_block_with_validator_set(&producer_adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        r_p,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash,
            height: 1
        })
    );
    // ④ 生产者本地 apply → head = block.height = 1。
    producer_adapter.apply_block(&gossip, &vk_p).unwrap();
    assert_eq!(producer_adapter.head().height, 1, "producer head +1");

    // ⑤ Q 经真实 SyncBlockResponse 传输收块：sync response → sync dispatch → inbound validation。
    //    Receiver 用 **自己本地 ValidatorSet** 推导 expected proposer 并验签（Sync ≠ trusted）。
    let payload = sync_payload(&block);
    let outcomes = dispatch_sync_block_response_with_validator_set(
        &receiver_adapter,
        MAX_BLOCK_BYTES,
        &payload,
        &set,
    );
    assert_eq!(
        outcomes,
        vec![Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash,
            height: 1
        })],
        "sync 收块：本地 ValidatorSet 验 proposer 通过 ⇒ CanonicalNextCandidate"
    );
    assert_eq!(
        receiver_adapter.head().height,
        0,
        "dispatch 只读，receiver head 未动"
    );
    // ⑥ Q apply（真实 apply_block；proposer vk = 本地推导的 expected）。
    receiver_adapter.apply_block(&gossip, &vk_p).unwrap();
    assert_eq!(receiver_adapter.head().height, 1, "receiver head +1");

    // ⑦ A/B 双节点真实共识：各自 ConsensusNode（DAG 含真实 block）注册 proposal → prevote →
    //    precommit（互传真实 vote）→ 生产 PrecommitQC → 双方 finality == 真实 block_hash。
    let mut d_a = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set.clone(),
            GENESIS_HASH,
            dag_with(block_hash, selected),
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
            dag_with(block_hash, selected),
        ),
        vec![actor_b],
    );
    d_a.submit_proposal(ProposalRef {
        block_hash,
        proposer: selected,
    });
    d_b.submit_proposal(ProposalRef {
        block_hash,
        proposer: selected,
    });
    submit_vote_pair(
        &mut d_a,
        &mut d_b,
        &vote_request(block_hash, VoteType::Prevote),
    );
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Precommit);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Precommit);
    submit_vote_pair(
        &mut d_a,
        &mut d_b,
        &vote_request(block_hash, VoteType::Precommit),
    );
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        Some(block_hash),
        "A finalized == 真实 sync block"
    );
    assert_eq!(
        d_b.consensus().state().finality.finalized_reference,
        Some(block_hash),
        "B finalized == 真实 sync block"
    );
    assert_eq!(producer_adapter.head().height, 1);
    assert_eq!(receiver_adapter.head().height, 1);
}

// ---------------------------------------------------------------------------
// T7-2 — Wrong proposer through sync：selected=A，实际签名=B（成员但非当选）
//        ⇒ InvalidProposerSignature；head 不变；无 apply / vote / QC / finality
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t2_wrong_proposer_through_sync_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter_b = fresh_adapter(); // receiver（B 视角：本地 ValidatorSet 判定谁是 proposer）
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected must be a member"
    );
    // 构造 selected 但用「另一成员（非当选）」签名。
    let q_kp = if selected == id_a { &kp_b } else { &kp_a };
    let block = canonical_next_block(q_kp.signing_key());
    let payload = sync_payload(&block);

    let outcomes = dispatch_sync_block_response_with_validator_set(
        &adapter_b,
        MAX_BLOCK_BYTES,
        &payload,
        &set,
    );
    assert_eq!(
        outcomes,
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "sync 收块：本地推导 expected proposer ≠ 签名者 ⇒ 拒"
    );
    assert_eq!(adapter_b.head().height, 0, "head 不变：无 apply");

    // B 从未获得合法 block ⇒ 无法进入共识：无 vote / QC / finality。
    let mut d_b = NodeConsensusDriver::new(
        ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new()),
        vec![actor_of(kp_b, id_b)],
    );
    assert_eq!(
        d_b.consensus().state().finality.finalized_reference,
        None,
        "B 无 finality"
    );
    assert_ne!(d_b.consensus().state().round.step, RoundStep::Finalized);
    // 被拒块 hash 无法作为 vote target（无 proposal ⇒ step 非授权）→ 无 vote / 无 QC。
    let target = nova_runtime::block_hash(&block).unwrap();
    assert!(
        d_b.submit_local_vote(0, &vote_request(target, VoteType::Prevote))
            .unwrap()
            .is_none(),
        "无合法 proposal ⇒ B 不产 vote"
    );
    assert_eq!(
        d_b.consensus().state().finality.finalized_reference,
        None,
        "无 QC / 无 finality"
    );
}

// ---------------------------------------------------------------------------
// T7-3 — Corrupted proposer signature through sync：正确 proposer + 篡改签名
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t3_corrupted_signature_through_sync_rejected() {
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
    let mut block = canonical_next_block(p_kp.signing_key());
    block.proposer_signature[0] ^= 0xFF;
    let payload = sync_payload(&block);

    let outcomes =
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &payload, &set);
    assert_eq!(
        outcomes,
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "正确 proposer + 篡改签名 ⇒ 验签失败拒"
    );
    assert_eq!(adapter.head().height, 0, "head 不变");
}

// ---------------------------------------------------------------------------
// T7-4 — Wrong parent / height through sync：复用既有分类；head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t4_wrong_parent_or_height_through_sync_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter = fresh_adapter();
    // 真实 proposer 签名（排除 proposer 因素，专测分类）。
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    let p_kp = if selected == id_of(&kp_a) {
        &kp_a
    } else {
        &kp_b
    };

    // wrong parent（height1、parent≠genesis）⇒ ConflictingParent（分类在 proposer 前）。
    let wp = sync_payload(&block_wrong_parent(p_kp.signing_key()));
    let wp_outcomes =
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &wp, &set);
    assert!(
        matches!(
            wp_outcomes.as_slice(),
            [Ok(InboundBlockVerdict::ConflictingParent { height: 1, .. })]
        ),
        "wrong parent 复用既有 ConflictingParent 分类"
    );
    assert_eq!(adapter.head().height, 0);

    // future height（height2 ⇒ 祖先缺失）⇒ FutureMissingAncestor。
    let fh = sync_payload(&block_future_height(p_kp.signing_key()));
    let fh_outcomes =
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &fh, &set);
    assert!(
        matches!(
            fh_outcomes.as_slice(),
            [Ok(InboundBlockVerdict::FutureMissingAncestor {
                height: 2,
                ..
            })]
        ),
        "future height 复用既有 FutureMissingAncestor 分类"
    );
    assert_eq!(adapter.head().height, 0, "head 不变");
}

// ---------------------------------------------------------------------------
// T7-5 — Unknown proposer through sync：非 ValidatorSet 成员签名 ⇒ 拒（不因 sync 绕过）
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t5_unknown_proposer_through_sync_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_x = KeyPair::generate().unwrap(); // 非成员
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter = fresh_adapter();
    assert_ne!(id_of(&kp_x), id_of(&kp_a), "x 非成员（与 A/B 都不同）");
    assert_ne!(id_of(&kp_x), id_of(&kp_b));

    // 非成员签 canonical-next block → sync 路径发给接收方。
    let block = canonical_next_block(kp_x.signing_key());
    let payload = sync_payload(&block);
    let outcomes =
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &payload, &set);
    assert_eq!(
        outcomes,
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "未知 proposer 签名 ⇒ 本地 ValidatorSet 验签失败拒（sync 不能绕过）"
    );
    assert_eq!(adapter.head().height, 0, "head 不变：无 apply");
}

// ---------------------------------------------------------------------------
// T7-6 — Honest None seam：无 ValidatorSet 的 sync 入口对 canonical-next 严格拒绝
//        （None ≠ skip validation；Sync ≠ trusted input）
// ---------------------------------------------------------------------------

#[test]
fn d9_s7_t6_none_seam_sync_not_trusted() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let adapter = fresh_adapter();
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    let p_kp = if selected == id_of(&kp_a) {
        &kp_a
    } else {
        &kp_b
    };
    // 真实当选者签名的 canonical-next block。
    let block = canonical_next_block(p_kp.signing_key());
    let payload = sync_payload(&block);

    // 无 ValidatorSet 的既有 sync 入口：canonical-next ⇒ UnsupportedValidation(ProposerSignature)
    // —— 绝不 None→accept（诚实能力边界：无法验证 proposer 就不放行，而不是当 trusted）。
    let outcomes = dispatch_sync_block_response(&adapter, MAX_BLOCK_BYTES, &payload);
    assert_eq!(
        outcomes,
        vec![Err(InboundBlockError::UnsupportedValidation(
            nova_node::block_inbound::UnverifiableItem::ProposerSignature
        ))],
        "None seam：canonical-next 无 proposer 验证能力 ⇒ 严格拒绝（Sync ≠ trusted）"
    );
    assert_eq!(adapter.head().height, 0, "head 不变：未放行");

    // 对照：同 block 带本地 ValidatorSet ⇒ 验签通过 ⇒ CanonicalNextCandidate。
    let with_set =
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &payload, &set);
    assert!(
        matches!(
            with_set.as_slice(),
            [Ok(InboundBlockVerdict::CanonicalNextCandidate {
                height: 1,
                ..
            })]
        ),
        "with ValidatorSet：canonical-next 经真实验签放行为候选"
    );
    assert_eq!(adapter.head().height, 0, "验证只读，head 不变");
}
