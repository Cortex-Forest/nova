//! Node Consensus Driver 集成测试（STEP 10-15O；Test A–F）。
//!
//! 覆盖：Proposal → LocalVote → 统一 verify_vote_input → canonical transition →
//! TransitionDerived(precommit_qc) → verify_qc → broadcast 至各本地 ValidatorActor → acquire_lock。
//! 全部 deterministic（无随机路径）；fixture 复用既有 consensus/crypto 原语。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate, verify_qc};
use nova_consensus::integration::{
    ConsensusEvent, TransitionDerived, TransitionObservation, TransitionResult,
};
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload, verify_vote_input};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, VerifyingKey, sign_message_hash};

use nova_node::assembly::ConsensusNode;
use nova_node::driver::{DriverError, NodeConsensusDriver};
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];

// ---------- fixtures ----------

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

/// n 个等 stake(100) 验证者：quorum = ceil(2T/3)。n=1 ⇒ 67；n=3 ⇒ 200。
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

/// 两条独立 root（AA / BB）+ AA 的 child（CC）：供多验证者 per-actor lock 隔离测试。
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

/// 构造 **真实可验** 的 PrecommitQC（对 target 由各 signer 真实签名；evidence 升序）。
/// 调用方须保证 signers 合计权重 ≥ quorum（verify_qc 通过）。
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

/// 单验证者 driver（set n=1；dag 含 AA）。
fn setup_single() -> (NodeConsensusDriver<SoftwareSigner>, [u8; 32]) {
    let (mut kps, set) = make_ctx(1);
    let target = [0xAA; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let (actor, _) = actor_of(kps.remove(0));
    let driver = NodeConsensusDriver::new(consensus, vec![actor]);
    (driver, target)
}

/// 提交当前 target 的 proposal（driver.actor(0) 为 proposer）。
fn submit_proposal_for(driver: &mut NodeConsensusDriver<SoftwareSigner>, target: [u8; 32]) {
    let proposer = driver.actor(0).unwrap().validator_id();
    let r = driver.submit_proposal(ProposalRef {
        block_hash: target,
        proposer,
    });
    assert!(
        matches!(r, TransitionResult::Applied { .. }),
        "proposal 必须 Applied"
    );
}

// ---------- Test A ----------

#[test]
fn a_proposal_to_local_vote_through_verify_into_transition() {
    let (mut driver, target) = setup_single();
    submit_proposal_for(&mut driver, target);
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);

    let res = driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("本地 prevote 应经统一验证并提交");
    assert!(matches!(&res, TransitionResult::Applied { .. }));
    // 单验证者 prevote 达 quorum ⇒ canonical transition 推进到 Precommit
    assert_eq!(driver.consensus().state().round.step, RoundStep::Precommit);
    if let TransitionResult::Applied { observation, .. } = &res {
        assert!(observation.prevote_quorum);
    }
    // 阶段已推进 ⇒ 再投 prevote 被 driver 上下文门拒绝（无事件、无状态变化）
    assert!(
        driver
            .submit_local_vote(0, &prevote_req(target))
            .unwrap()
            .is_none(),
        "step=Precommit 后 prevote 不应被接受"
    );
}

// ---------- Test C ----------

#[test]
fn c_precommit_qc_verified_and_local_lock_acquired() {
    let (mut driver, target) = setup_single();
    submit_proposal_for(&mut driver, target);
    driver
        .submit_local_vote(0, &prevote_req(target))
        .unwrap()
        .expect("prevote 提交");

    let res = driver
        .submit_local_vote(0, &precommit_req(target))
        .unwrap()
        .expect("本地 precommit 应提交");
    assert!(matches!(&res, TransitionResult::Applied { .. }));
    assert_eq!(driver.consensus().state().round.step, RoundStep::Finalized);
    // derived.precommit_qc 必须保留（未被丢弃）
    let has_qc =
        matches!(&res, TransitionResult::Applied { derived, .. } if derived.precommit_qc.is_some());
    assert!(has_qc, "derived.precommit_qc 不得丢失");

    // routing：verify_qc 通过 → 路由至本地 actor → acquire_lock
    driver.process_transition_derived(&res).unwrap();
    let lock = driver.actor(0).unwrap().locked_state();
    assert_eq!(lock.locked_block_hash, Some(target));
    assert_eq!(lock.locked_round, Some(0));
}

// ---------- Test B ----------

#[test]
fn b_local_vote_uses_same_verify_boundary_as_remote() {
    let (mut driver, target) = setup_single();
    submit_proposal_for(&mut driver, target);
    let req = prevote_req(target);

    // 本地投票（actor produce —— 与 remote 完全相同的 vote 形状）
    let (vote, signature) = {
        let actor = driver.actor(0).unwrap();
        let ev = actor
            .produce_vote(
                &req,
                driver.consensus().validator_set(),
                driver.consensus().dag(),
            )
            .expect("本地 prevote 应授权");
        match ev {
            ConsensusEvent::Vote { vote, signature } => (vote, signature),
            other => panic!("produce_vote 必须产出标准 ConsensusEvent::Vote，got {other:?}"),
        }
    };
    // 与 remote（assembly handle_vote → verify_vote_input）同一 MF-2 门面 ⇒ 通过
    verify_vote_input(
        &vote,
        &signature,
        CHAIN_ID,
        driver.consensus().validator_set(),
    )
    .expect("本地 vote 必须通过统一 verify_vote_input");
    // 篡改签名 ⇒ 同一门面拒绝（remote 亦如此拒错）
    let mut bad = signature;
    bad[0] ^= 0xff;
    assert!(
        verify_vote_input(&vote, &bad, CHAIN_ID, driver.consensus().validator_set()).is_err(),
        "坏签名必须在统一门面被拒"
    );
    // OPTION A 全路径：driver 经同一门面提交真实本地 vote
    let res = driver.submit_local_vote(0, &req).unwrap();
    assert!(res.is_some(), "driver 应经 verify_vote_input 提交本地 vote");
}

// ---------- Test D ----------

#[test]
fn d_same_verified_qc_routed_all_actors_per_validator_lock_isolation() {
    let (mut kps, set) = make_ctx(3); // quorum = 200
    let a = kps.remove(0);
    let b = kps.remove(0);
    let c = kps.remove(0);
    let a_id = vid_of(&a);
    let b_id = vid_of(&b);
    let c_id = vid_of(&c);
    let aa = [0xAA; 32];
    let bb = [0xBB; 32];
    let cc = [0xCC; 32]; // AA 的 child

    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, dag2());
    // 真实 valid QC（2×100 = 200 ≥ quorum）：AA 由 A+C 签；BB 由 B+C 签；CC 由 A+C 签。
    let qc_aa = make_precommit_qc(&aa, &[(a_id, &a), (c_id, &c)], GENESIS_HASH);
    let qc_bb = make_precommit_qc(&bb, &[(b_id, &b), (c_id, &c)], GENESIS_HASH);
    let qc_cc = make_precommit_qc(&cc, &[(a_id, &a), (c_id, &c)], GENESIS_HASH);
    let dag = dag2();
    verify_qc(&qc_aa, &set, &GENESIS_HASH, &dag).unwrap();
    verify_qc(&qc_bb, &set, &GENESIS_HASH, &dag).unwrap();
    verify_qc(&qc_cc, &set, &GENESIS_HASH, &dag).unwrap();

    let (actor_a, _) = actor_of(a);
    let (actor_b, _) = actor_of(b);
    let mut driver = NodeConsensusDriver::new(consensus, vec![actor_a, actor_b]);

    // 前置：A 锁 AA，B 锁 BB（各自独立历史）
    driver
        .actor_mut(0)
        .unwrap()
        .on_verified_precommit_qc(&qc_aa, &dag)
        .unwrap();
    driver
        .actor_mut(1)
        .unwrap()
        .on_verified_precommit_qc(&qc_bb, &dag)
        .unwrap();
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        Some(aa)
    );
    assert_eq!(
        driver.actor(1).unwrap().locked_state().locked_block_hash,
        Some(bb)
    );

    // 同一 verified QC(CC) 经 driver routing（synthetic Applied 携带 derived.precommit_qc）
    let derived = TransitionDerived {
        precommit_qc: Some(qc_cc),
        ..Default::default()
    };
    let result = TransitionResult::Applied {
        next_state: driver.consensus().state().clone(),
        observation: TransitionObservation::default(),
        derived,
    };
    driver.process_transition_derived(&result).unwrap();

    // broadcast：A（lock AA，CC 是 descendant）⇒ advance 到 CC；
    // B（lock BB，CC 与其 unrelated）⇒ lock 不变 —— 同一 QC 不会把 B 直接改写成 CC。
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        Some(cc),
        "A: descendant ⇒ acquire_lock advance"
    );
    assert_eq!(
        driver.actor(1).unwrap().locked_state().locked_block_hash,
        Some(bb),
        "B: unrelated ⇒ lock 不被同一 QC / A 直接修改"
    );
}

// ---------- Test E ----------

#[test]
fn e_invalid_derived_qc_not_routed_no_lock_update() {
    let (mut driver, target) = setup_single();
    let outsider = KeyPair::generate().unwrap();
    let outsider_id = vid_of(&outsider);
    // 非成员 evidence ⇒ verify_qc 必失败（UnknownValidator）
    let bad_qc = make_precommit_qc(&target, &[(outsider_id, &outsider)], GENESIS_HASH);
    assert!(
        verify_qc(
            &bad_qc,
            driver.consensus().validator_set(),
            &GENESIS_HASH,
            driver.consensus().dag(),
        )
        .is_err(),
        "fixture：derived QC 必须无法通过 verify_qc"
    );
    let derived = TransitionDerived {
        precommit_qc: Some(bad_qc),
        ..Default::default()
    };
    let result = TransitionResult::Applied {
        next_state: driver.consensus().state().clone(),
        observation: TransitionObservation::default(),
        derived,
    };
    // driver 显式 verify_qc ⇒ FAIL ⇒ Err，且不更新任何 actor lock
    let err = driver.process_transition_derived(&result).unwrap_err();
    assert!(matches!(err, DriverError::QcVerification(_)));
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        None,
        "verify_qc FAIL ⇒ 不得路由 / 不得更新 lock"
    );
}

// ---------- Test F ----------

#[test]
fn f_no_derived_qc_no_lock_routing() {
    let (mut driver, _target) = setup_single();
    let result = TransitionResult::Applied {
        next_state: driver.consensus().state().clone(),
        observation: TransitionObservation::default(),
        derived: TransitionDerived::default(), // precommit_qc = None
    };
    driver.process_transition_derived(&result).unwrap();
    assert_eq!(
        driver.actor(0).unwrap().locked_state().locked_block_hash,
        None,
        "无 precommit_qc ⇒ 不触发 lock routing"
    );
}
