//! D10-A — Production Consensus Auto-Drive（node driver 层自动推进）。
//!
//! 目标：把 D9 已验证的 `Proposal → Prevote → Precommit → QC → Finality` 从「测试手动调用
//! `submit_local_vote`」提升为 **node driver 层可复用的生产自动推进能力**
//! （`NodeConsensusDriver::auto_drive`）。**不重新实现 consensus**：auto-drive 只读当前
//! canonical round 状态、对全部本地 actor 执行当前被授权 action，复用既有冻结原语
//! （`ValidatorActor::produce_vote` / `verify_vote_input` / `submit_verified_vote` / `transition` /
//! `verify_qc` / `acquire_lock` / FinalityState）。
//!
//! 安全性质：
//! - auto-drive **不绕过 D9 proposer validation**：proposal 进入 consensus 前须经 A11 seam
//!   （`dispatch_gossip_block_with_validator_set`，本地 ValidatorSet → expected proposer VK 验签）；
//!   auto-drive 另有 proposer-authority gate（本地 `select_proposer` 期望当选者 ≠ proposal.proposer
//!   ⇒ `AutoDriveStep::WrongProposer`，不投票 / 不推进）。
//! - auto-drive **不发明 QC / finality**：QC 只来自现有 transition / verify_qc；finality 只来自
//!   现有 ConsensusNode FinalityState（`finalized_reference` 由 transition ⑥ 更新，绝不手设）。
//! - auto-drive 幂等：重复调用由 actor VoteLedger（同 VoteKey 同 target 复用签名，不重复签名）
//!   与 consensus accumulator 去重守卫 —— 不 double-vote / 不违反 safety。
//!
//! T10-1 single-validator automatic finality（无手动 submit_local_vote）
//! T10-2 two-validator automatic local vote production（真实 remote 互传 → QC → finality）
//! T10-3 insufficient quorum（单方票不足 ⇒ no QC / no finality）
//! T10-4 duplicate auto-drive idempotent（无重复计权 / 无重复签名）
//! T10-5 wrong proposer cannot auto-drive（proposer-authority gate 拒绝，无 vote）
//! T10-6 invalid proposer signature cannot auto-drive（A11 seam 拒；auto-drive Idle，无推进）
//!
//! 测试使用真实 genesis（chain=1001、空 accounts、真实 Ed25519 key）；不修改 consensus 规则 /
//! 协议 / golden / D8；不 mock；不手动改 ConsensusState / FinalityState / QC / head。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::ValidatorVote;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;

use nova_node::assembly::ConsensusNode;
use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::block_dispatch::dispatch_gossip_block_with_validator_set;
use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict};
use nova_node::driver::{AutoDriveStep, NodeConsensusDriver};
use nova_node::outbound::OutboundConsensusMessage;
use nova_node::proposer::build_proposal;
use nova_node::signer::SoftwareSigner;
use nova_node::validator::ValidatorActor;

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;

type MemAdapter = NodeBlockAdapter<MemoryBackend, NoAccountsKeyResolver>;
type MemDriver = NodeConsensusDriver<SoftwareSigner>;

// ---------------------------------------------------------------------------
// Fixtures（与 D9 Step 5/6 一致：确定性 genesis、真实 Ed25519、无 mock）
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

/// 从 driver 待广播队列取下一个本地已签名 vote（auto-drive 经 submit_local_vote 产生）。
fn take_vote(d: &mut MemDriver) -> (ValidatorVote, [u8; 64]) {
    for msg in d.take_outbound() {
        if let OutboundConsensusMessage::Vote { vote, signature } = msg {
            return (vote, signature);
        }
    }
    panic!("outbound 无本地 vote");
}

/// 把 `src` 的本地 vote relay 到 `dst`（真实 submit_remote_vote + process_transition_derived）。
fn relay_vote(dst: &mut MemDriver, src: &mut MemDriver) {
    let (vote, signature) = take_vote(src);
    let result = dst
        .submit_remote_vote(vote, signature)
        .expect("remote vote ok");
    dst.process_transition_derived(&result).expect("derived ok");
}

/// 单验证者 setup：genesis(A=100) → quorum=1。
fn setup_single() -> (ValidatorSet, ValidatorId, KeyPair, MemAdapter) {
    let kp = KeyPair::generate().unwrap();
    let id = id_of(&kp);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let adapter = fresh_adapter();
    (set, id, kp, adapter)
}

/// 双验证者 setup：genesis(A=100,B=100) → quorum = ValidatorSet::quorum()。
fn setup_ab() -> (
    ValidatorSet,
    ValidatorId,
    KeyPair,
    ValidatorId,
    KeyPair,
    MemAdapter,
    MemAdapter,
) {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let id_a = id_of(&kp_a);
    let id_b = id_of(&kp_b);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    (
        set,
        id_a,
        kp_a,
        id_b,
        kp_b,
        fresh_adapter(),
        fresh_adapter(),
    )
}

// ---------------------------------------------------------------------------
// T10-1 — 单验证者：proposal → auto-drive → Prevote → Precommit → QC → Finality
//         （测试不手动调用 submit_local_vote 完成推进）
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t1_single_validator_automatic_finality() {
    let (set, id, kp, adapter) = setup_single();
    // 单验证者：唯一 validator weight 100 ≥ quorum = ceil(100*2/3) = 67 ⇒ 自投一票即达 quorum
    //（不硬编码 quorum；只断言单方可达）。
    assert!(
        set.quorum() <= 100,
        "单验证者自身可达 quorum（{} ≤ 100）",
        set.quorum()
    );

    // ① select_proposer（父高轮 0/round 0）必为唯一验证者。
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert_eq!(selected, id, "单验证者必为当选者");

    // ② P 真实 build（临时 consensus 只读判定：rs.height == head.height == 0）。
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(selected, &tmp, &adapter, 0)
        .unwrap()
        .expect("proposer 必须产出真实 proposal");
    assert_eq!(pb.proposal_ref.proposer, selected);

    // ③ P 真实签名（同一 actor 稍后进 driver；KeyPair 单 move）。
    let actor = actor_of(kp, id);
    let mut block = pb.block;
    actor.sign_block(&mut block).unwrap();
    let block_hash = pb.block_hash;
    let gossip = nova_runtime::encode_block(&block).unwrap();
    assert_eq!(nova_runtime::block_hash(&block).unwrap(), block_hash);

    // ④ D9 A11 seam：proposal 进入 consensus 前必须经 proposer 验证（不绕过）。
    let r = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        r,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash,
            height: 1
        })
    );

    // ⑤ driver + auto-drive 闭环（无手动 submit_local_vote）。
    let mut d = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set,
            GENESIS_HASH,
            dag_with(block_hash, selected),
        ),
        vec![actor],
    );
    d.submit_proposal(ProposalRef {
        block_hash,
        proposer: selected,
    });
    assert_eq!(d.consensus().state().round.step, RoundStep::Prevote);
    assert_eq!(
        d.consensus().state().finality.finalized_reference,
        None,
        "初始无 finality"
    );

    // ⑥ 首次 auto-drive = Prevote（quorum=1 ⇒ 推进到 Precommit）。
    let step1 = d.auto_drive().unwrap();
    assert!(matches!(step1, AutoDriveStep::Prevote { actors: 1 }));
    assert_eq!(
        d.consensus().state().round.step,
        RoundStep::Precommit,
        "auto prevote quorum(1) → Precommit"
    );

    // ⑦ 第二次 auto-drive = Precommit ⇒ quorum(1) ⇒ 生产 PrecommitQC + Finality。
    let step2 = d.auto_drive().unwrap();
    assert!(matches!(step2, AutoDriveStep::Precommit { actors: 1 }));
    assert_eq!(d.consensus().state().round.step, RoundStep::Finalized);
    assert_eq!(
        d.consensus().state().finality.finalized_reference,
        Some(block_hash),
        "finality == 真实 block（由 transition ⑥ 产生，非手设）"
    );
    // QC（verify_qc PASS 后经 process_transition_derived）→ actor lock（L-8）。
    assert_eq!(
        d.actor(0).unwrap().locked_state().locked_block_hash,
        Some(block_hash),
        "验证 PASS 的 PrecommitQC 已路由至本地 lock"
    );

    // ⑧ Finalized 后 auto-drive = Idle（稳定终态）。
    assert_eq!(d.auto_drive().unwrap(), AutoDriveStep::Idle);
}

// ---------------------------------------------------------------------------
// T10-2 — 双验证者：A/B 各自 auto-drive 产本地 vote；真实 remote 互传 → QC → Finality
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t2_two_validator_automatic_votes_and_finality() {
    let (set, id_a, kp_a, id_b, kp_b, adapter_a, adapter_b) = setup_ab();
    let quorum = set.quorum();
    assert!(
        100 < quorum && 200 >= quorum,
        "双验证者：单方 100 不足、双方 200 达（生产 quorum={quorum}）"
    );

    // ① select_proposer 真实选出 P（父高轮 0；不人为改变 selection）。
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        selected == id_a || selected == id_b,
        "selected proposer must be A or B"
    );
    let p_is_a = selected == id_a;

    // ② P 真实 build + 签名（P 的 actor 稍后进 P 的 driver）。
    let actor_a = actor_of(kp_a, id_a);
    let actor_b = actor_of(kp_b, id_b);
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(selected, &tmp, &adapter_a, 0)
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
    let gossip = nova_runtime::encode_block(&block).unwrap();
    assert_eq!(nova_runtime::block_hash(&block).unwrap(), block_hash);

    // ③ 双节点各自本地 ValidatorSet 验证（A11 seam；proposer 验证不绕过）。
    let ra = dispatch_gossip_block_with_validator_set(&adapter_a, MAX_BLOCK_BYTES, &gossip, &set);
    let rb = dispatch_gossip_block_with_validator_set(&adapter_b, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        ra,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash,
            height: 1
        })
    );
    assert_eq!(
        rb,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash,
            height: 1
        })
    );

    // ④ 双 driver（各一真实 actor）。
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
    let proposal = ProposalRef {
        block_hash,
        proposer: selected,
    };
    d_a.submit_proposal(proposal.clone());
    d_b.submit_proposal(proposal);
    assert_eq!(d_a.consensus().state().round.step, RoundStep::Prevote);
    assert_eq!(d_b.consensus().state().round.step, RoundStep::Prevote);

    // ⑤ auto-drive：A/B 各自自动产本地 Prevote（不手动 submit_local_vote）。
    assert!(matches!(
        d_a.auto_drive().unwrap(),
        AutoDriveStep::Prevote { actors: 1 }
    ));
    assert!(matches!(
        d_b.auto_drive().unwrap(),
        AutoDriveStep::Prevote { actors: 1 }
    ));

    // ⑥ 真实 remote 互传 prevote（单票不足 quorum=2 → 互传后 prevote quorum → Precommit）。
    relay_vote(&mut d_b, &mut d_a);
    relay_vote(&mut d_a, &mut d_b);
    assert_eq!(
        d_a.consensus().state().round.step,
        RoundStep::Precommit,
        "A prevote quorum → Precommit"
    );
    assert_eq!(
        d_b.consensus().state().round.step,
        RoundStep::Precommit,
        "B prevote quorum → Precommit"
    );

    // ⑦ auto-drive：A/B 各自自动产本地 Precommit。
    assert!(matches!(
        d_a.auto_drive().unwrap(),
        AutoDriveStep::Precommit { actors: 1 }
    ));
    assert!(matches!(
        d_b.auto_drive().unwrap(),
        AutoDriveStep::Precommit { actors: 1 }
    ));

    // ⑧ 真实 remote 互传 precommit → 双方 PrecommitQC + Finality。
    relay_vote(&mut d_b, &mut d_a);
    relay_vote(&mut d_a, &mut d_b);
    assert_eq!(
        d_a.consensus().state().round.step,
        RoundStep::Finalized,
        "A precommit quorum → Finalized"
    );
    assert_eq!(
        d_b.consensus().state().round.step,
        RoundStep::Finalized,
        "B precommit quorum → Finalized"
    );
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        Some(block_hash),
        "A finality == 真实 block"
    );
    assert_eq!(
        d_b.consensus().state().finality.finalized_reference,
        Some(block_hash),
        "B finality == 真实 block"
    );
}

// ---------------------------------------------------------------------------
// T10-3 — 双验证者，仅一方 vote：no QC / no finality（auto-drive 不伪造推进）
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t3_insufficient_quorum_no_finality() {
    let (set, id_a, kp_a, _id_b, _kp_b, _adapter_a, _adapter_b) = setup_ab();
    let quorum = set.quorum();
    assert!(100 < quorum, "单方 100 < 生产 quorum {quorum}");
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    let block_hash = [0xAB; 32];

    // 仅 A 一个本地 actor（set 仍双人 ⇒ quorum=2 需两票）。
    let mut d_a = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set,
            GENESIS_HASH,
            dag_with(block_hash, selected),
        ),
        vec![actor_of(kp_a, id_a)],
    );
    d_a.submit_proposal(ProposalRef {
        block_hash,
        proposer: selected,
    });
    // A auto-drive prevote：单票 100 < quorum 2 ⇒ 不推进。
    assert!(matches!(
        d_a.auto_drive().unwrap(),
        AutoDriveStep::Prevote { actors: 1 }
    ));
    assert_eq!(
        d_a.consensus().state().round.step,
        RoundStep::Prevote,
        "单票不足 quorum 不推进"
    );
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
    // 重复 auto-drive 亦不伪造推进。
    assert!(matches!(
        d_a.auto_drive().unwrap(),
        AutoDriveStep::Prevote { actors: 1 }
    ));
    assert_eq!(
        d_a.consensus().state().round.step,
        RoundStep::Prevote,
        "仍无 quorum"
    );
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        None,
        "auto-drive 不伪造 QC / finality"
    );
}

// ---------------------------------------------------------------------------
// T10-4 — 重复 auto-drive 幂等：accumulator 不重复计权 / actor 不重复签名（safety 保持）
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t4_duplicate_auto_drive_idempotent() {
    let (set, id_a, kp_a, _id_b, _kp_b, _adapter_a, _adapter_b) = setup_ab();
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    let block_hash = [0xCD; 32];

    let mut d_a = NodeConsensusDriver::new(
        ConsensusNode::new(
            0,
            0,
            CHAIN_ID,
            set.clone(),
            GENESIS_HASH,
            dag_with(block_hash, selected),
        ),
        vec![actor_of(kp_a, id_a)],
    );
    d_a.submit_proposal(ProposalRef {
        block_hash,
        proposer: selected,
    });

    // 多次重复 auto-drive（同 VoteKey 同 target）：不 double-vote、不重复计权。
    // 每轮 drive 产出一条本地 prevote（幂等复用同一已签 vote —— 不重复签名）。
    let mut signatures = Vec::new();
    for _ in 0..3 {
        let step = d_a.auto_drive().expect("auto-drive ok");
        assert!(
            matches!(step, AutoDriveStep::Prevote { actors: 1 }),
            "幂等：仍 Prevote（单票不足 quorum）"
        );
        let (_, sig) = take_vote(&mut d_a);
        signatures.push(sig);
    }
    // 单票 100 < quorum ⇒ step 仍 Prevote（重复 auto-drive 未翻倍计权成 quorum）。
    assert_eq!(
        d_a.consensus().state().round.step,
        RoundStep::Prevote,
        "accumulator 同 validator 只计一次 ⇒ 无重复 quorum"
    );
    assert_eq!(
        d_a.consensus().state().finality.finalized_reference,
        None,
        "无伪造 finality"
    );
    // 幂等：3 轮产出的 outbound vote 为**同一已签 vote**（签名相同 ⇒ 无重复签名；actor
    // VoteLedger 复用既有签名，不 double-sign / 不违反 safety）。
    assert!(
        signatures.windows(2).all(|w| w[0] == w[1]),
        "重复 auto-drive 复用同一已签 vote（幂等，无新签名）"
    );
    assert_eq!(d_a.outbound_pending_len(), 0, "outbound 已取空");
}

// ---------------------------------------------------------------------------
// T10-5 — Wrong proposer 不能 auto-drive：proposer-authority gate 拒绝，无 vote
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t5_wrong_proposer_cannot_auto_drive() {
    let (set, id_a, kp_a, id_b, _kp_b, _adapter_a, _adapter_b) = setup_ab();
    let expected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert!(
        expected == id_a || expected == id_b,
        "expected must be A or B"
    );
    // 构造 wrong proposer：另一成员（非当选）。
    let wrong = if expected == id_a { id_b } else { id_a };
    let block_hash = [0xEF; 32];

    let mut d = NodeConsensusDriver::new(
        ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, Dag::new()),
        vec![actor_of(kp_a, id_a)],
    );
    // 强行 SetProposal（模拟绕过 seam 的坏 proposer 标记 —— consensus 不校验当选者）。
    d.submit_proposal(ProposalRef {
        block_hash,
        proposer: wrong,
    });
    assert_eq!(d.consensus().state().round.step, RoundStep::Prevote);
    // auto-drive proposer-authority gate：proposer ≠ 本地 select ⇒ 拒绝驱动（不投票）。
    let step = d.auto_drive().unwrap();
    assert!(
        matches!(
            step,
            AutoDriveStep::WrongProposer {
                actual,
                expected: e
            } if actual == wrong && e == expected
        ),
        "wrong proposer 拒绝驱动（不投票）"
    );
    assert_eq!(
        d.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
    assert_eq!(
        d.consensus().state().round.step,
        RoundStep::Prevote,
        "无 vote ⇒ 无推进"
    );
    assert_eq!(d.outbound_pending_len(), 0, "无任何 outbound（无 vote）");
}

// ---------------------------------------------------------------------------
// T10-6 — Invalid proposer signature 不能 auto-drive：A11 seam 拒；driver 无推进
// ---------------------------------------------------------------------------

#[test]
fn d10_s1_t6_invalid_signature_cannot_auto_drive() {
    let (set, id, kp, adapter) = setup_single();

    // ① P 真实 build + 签名，然后篡改 proposer_signature。
    let selected = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert_eq!(selected, id);
    let actor = actor_of(kp, id);
    let tmp = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, Dag::new());
    let pb = build_proposal(selected, &tmp, &adapter, 0)
        .unwrap()
        .expect("proposer 必须产出真实 proposal");
    let mut block = pb.block;
    actor.sign_block(&mut block).unwrap();
    block.proposer_signature[0] ^= 0xFF; // 篡改
    let gossip = nova_runtime::encode_block(&block).unwrap();

    // ② D9 A11 seam：篡改签名 block ⇒ InvalidProposerSignature（proposer 验证不绕过）。
    let r = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        r,
        Err(InboundBlockError::InvalidProposerSignature),
        "A11 seam 拒篡改签名 block"
    );

    // ③ driver 从未获得合法 proposal（坏块从未 Set）⇒ auto-drive Idle：无 vote / QC / finality。
    let mut d = NodeConsensusDriver::new(
        ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, Dag::new()),
        vec![actor],
    );
    assert_eq!(d.auto_drive().unwrap(), AutoDriveStep::Idle);
    assert_eq!(
        d.consensus().state().round.step,
        RoundStep::Propose,
        "无 proposal ⇒ 无推进"
    );
    assert_eq!(
        d.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
    assert_eq!(d.outbound_pending_len(), 0, "无 vote outbound");
}
