//! A3.4 — P4 liveness **invariant characterization** (test-only; no production change).
//!
//! # Purpose
//! These tests are **defensive characterization** of invariants established by the
//! read-only audits A3.2 (`A32-REPORT.md`) and A3.3 (`A33-REPORT.md`). They do **not**
//! claim to fix a root cause, and no root cause is asserted by their passing.
//!
//! # Why a separate file (and not the A2 devnet file)
//! `crates/node/tests/d10_p1_a30_seven_validator_devnet.rs` is a multi-process 7-validator
//! devnet harness (`t7_3` / `t7_5` / `t7_8`) built around real child processes and
//! wall-clock windows. The invariants below are pure, deterministic state-machine
//! properties. Hosting them there would require duplicating unrelated fixtures and would
//! make a sub-millisecond assertion pay a ~2–3 minute process harness. No existing test
//! file covers these exact properties (verified by search in A3.2/A3.3).
//!
//! # Coverage map
//! | Test | Candidate | Property |
//! |---|---|---|
//! | `g2_*` | G2 / R5 | vote-before-proposal retention; **no** replay on install; one new vote completes quorum |
//! | `g5_*` | G5 / R3 | QC round is signature-bound **but not bound to any block-header round** |
//! | `g1_*` | G1 / R4 | `RoundTimeout` escapes `Finalized` even when the DISARM predicate's three conjuncts all hold |
//! | `g3_*` | G3 / R2 | pending-proposal entries survive **two** round timeouts |
//!
//! # What these tests do NOT prove
//! * They do not demonstrate that the runtime-layer DISARM (`round_finalized_by_finality`)
//!   is ever combined with a permanently-deferring commit bridge in production.
//! * They do not exercise `finality_commit_bridge`, `get_for_proposer_verified`,
//!   `recover_pending_proposals`, Guard C, or `auto_drive` (all node-private or
//!   runtime-orchestrated paths).
//! * They do not constitute a production failure reproduction.

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::{
    FinalityState, QcContext, QcEvidence, QuorumCertificate, verify_qc,
};
use nova_consensus::integration::{
    ConsensusEvent, ConsensusState, IntegrationContext, TransitionResult, transition,
};
use nova_consensus::round::{ProposalRef, RoundState, RoundStep, RoundTimeoutConfig};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_node::runtime::pending_expiry_tick;

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
/// canonical-next block under test (registered in the DAG at height 0 by both fixtures).
const TARGET: [u8; 32] = [0xAA; 32];

// ---------- fixtures ----------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
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

struct Fixture {
    kps: Vec<KeyPair>,
    vids: Vec<ValidatorId>,
    set: ValidatorSet,
}

/// `n` equal-stake(100) validators. `n = 3` ⇒ total 300, quorum = ceil(2·300/3) = 200,
/// so **two** 100-weight votes reach quorum.
fn fixture(n: usize) -> Fixture {
    let mut kps = Vec::new();
    let mut vids = Vec::new();
    let mut vals = Vec::new();
    for i in 0..n {
        let kp = KeyPair::generate().unwrap();
        let vk = kp.verifying_key().to_bytes();
        let vid = ValidatorId::from_consensus_public_key(&vk);
        vids.push(vid);
        vals.push(ValidatorInit {
            account_address: addr([i as u8 + 0x10; 32]),
            consensus_public_key: vk,
            bonded_stake: 100,
            commission_bps: 100,
        });
        kps.push(kp);
    }
    Fixture {
        kps,
        vids,
        set: ValidatorSet::from_genesis(&genesis_with(vals)),
    }
}

/// DAG containing only `TARGET` (height 0). Note: `BlockReference` has **no `round`
/// field** — the DAG structurally cannot express a block production round.
fn dag_with_target() -> Dag {
    let mut dag = Dag::new();
    dag.add_block(BlockReference {
        block_hash: TARGET,
        height: 0,
        parents: Vec::new(),
        proposer: ValidatorId::from_bytes([0xAA; 32]),
    })
    .unwrap();
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

fn vote_at(f: &Fixture, idx: usize, vt: VoteType, round: u64) -> ConsensusEvent {
    let vote = ValidatorVote {
        round,
        height: 0,
        target_block_hash: TARGET,
        vote_type: vt,
        source_block_hash: [0u8; 32],
        validator_id: f.vids[idx],
        timestamp: 0,
    };
    let signature = sign_vote(f.kps[idx].signing_key(), &vote);
    ConsensusEvent::Vote { vote, signature }
}

fn proposal_event(f: &Fixture) -> ConsensusEvent {
    ConsensusEvent::SetProposal(ProposalRef {
        block_hash: TARGET,
        proposer: f.vids[0],
    })
}

/// Apply one event; mirror `apply_result` semantics (state advances only on `Applied`).
fn apply(
    state: &mut ConsensusState,
    ctx: &mut IntegrationContext,
    f: &Fixture,
    dag: &Dag,
    ev: ConsensusEvent,
) -> TransitionResult {
    let r = transition(state, ev, ctx, CHAIN_ID, &f.set, &GENESIS_HASH, dag);
    if let TransitionResult::Applied { next_state, .. } = &r {
        *state = next_state.clone();
    }
    r
}

fn fresh_state() -> ConsensusState {
    ConsensusState {
        round: RoundState::new(0, 0),
        finality: FinalityState::default(),
    }
}

// ---------- G2 / R5 — vote before proposal ----------

/// **Proves (source-backed behaviour, previously untested):**
/// 1. A valid Precommit received while `proposal == None` is **retained** — its weight is
///    accumulated into `RoundState.precommits` and its full evidence into `RoundEvidence`.
/// 2. Installing the proposal afterwards does **not** replay the retained votes:
///    `set_proposal` only performs `Propose -> Prevote` and reports no quorum.
/// 3. A **single** further vote is then sufficient to reach quorum, because the retained
///    weight is still counted.
///
/// **Does not prove:** what makes that further vote arrive in production (no vote
/// retransmission exists in the node layer — see `A33-REPORT.md` §5 item 4).
#[test]
fn g2_vote_before_proposal_is_retained_and_not_replayed_on_install() {
    let f = fixture(3);
    let dag = dag_with_target();
    let mut ctx = IntegrationContext::new(0, 0);
    let mut state = fresh_state();

    // (1) Prevote arrives with no proposal installed.
    let r1 = apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 0, VoteType::Prevote, 0));
    let TransitionResult::Applied { observation, .. } = &r1 else {
        panic!("vote with matching (height,round) must be Applied, got {r1:?}");
    };
    assert!(!observation.prevote_quorum, "no proposal ⇒ no quorum flag");
    assert_eq!(
        state.round.step,
        RoundStep::Propose,
        "no proposal ⇒ step must not advance"
    );
    assert_eq!(
        state.round.prevotes.weight_of(&TARGET),
        100,
        "retained: the vote weight IS accumulated even without a proposal"
    );

    // (2) Proposal now installs — and must NOT replay the retained vote.
    let r2 = apply(&mut state, &mut ctx, &f, &dag, proposal_event(&f));
    let TransitionResult::Applied { observation, .. } = &r2 else {
        panic!("proposal in Propose step must be Applied, got {r2:?}");
    };
    assert_eq!(state.round.step, RoundStep::Prevote, "Propose -> Prevote");
    assert!(
        !observation.prevote_quorum,
        "no automatic replay: installing the proposal must not re-evaluate retained votes"
    );
    assert_eq!(
        state.round.prevotes.weight_of(&TARGET),
        100,
        "retained weight survives proposal installation"
    );

    // (3) One more vote completes the quorum using the retained weight.
    let r3 = apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 1, VoteType::Prevote, 0));
    let TransitionResult::Applied { observation, .. } = &r3 else {
        panic!("second vote must be Applied, got {r3:?}");
    };
    assert!(
        observation.prevote_quorum,
        "retained 100 + new 100 = 200 >= quorum(200) ⇒ quorum"
    );
    assert_eq!(state.round.step, RoundStep::Precommit);
}

// ---------- G5 / R3 — QC round vs block-header round ----------

/// Builds a real, signature-valid PrecommitQC at `round` over `TARGET`.
fn make_precommit_qc_at(f: &Fixture, round: u64) -> QuorumCertificate {
    let mut evidence: Vec<QcEvidence> = (0..2)
        .map(|i| {
            let vote = ValidatorVote {
                round,
                height: 0,
                target_block_hash: TARGET,
                vote_type: VoteType::Precommit,
                source_block_hash: [0u8; 32],
                validator_id: f.vids[i],
                timestamp: 0,
            };
            QcEvidence {
                validator_id: f.vids[i],
                source_block_hash: [0u8; 32],
                timestamp: 0,
                signature: sign_vote(f.kps[i].signing_key(), &vote),
            }
        })
        .collect();
    evidence.sort_by_key(|e| e.validator_id);
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round,
            vote_type: VoteType::Precommit,
        },
        target: TARGET,
        validator_set_id: GENESIS_HASH,
        evidence,
    }
}

/// **Proves:** `verify_qc` accepts a QC whose `context.round` is unrelated to anything the
/// DAG knows about the target — because `BlockReference` carries no round and `verify_qc`
/// performs **no** comparison between `qc.context.round` and a block-header round.
/// Simultaneously proves the round *is* signature-bound (relabelling the QC invalidates it),
/// so this is "unbound to the block", **not** "forgeable".
///
/// **Does not prove** that such a QC is constructible through honest node behaviour; the
/// node layer ties vote rounds to the current consensus round and to Guard C.
#[test]
fn g5_qc_round_is_signature_bound_but_not_bound_to_block_header_round() {
    let f = fixture(3);
    let dag = dag_with_target();

    let qc = make_precommit_qc_at(&f, 7);
    assert!(
        verify_qc(&qc, &f.set, &GENESIS_HASH, &dag).is_ok(),
        "a correctly-signed QC at round 7 verifies against a round-less DAG node"
    );

    // Relabelling the QC round must invalidate it (round is inside the signed payload).
    let mut relabelled = qc.clone();
    relabelled.context.round = 8;
    assert!(
        verify_qc(&relabelled, &f.set, &GENESIS_HASH, &dag).is_err(),
        "relabelled QC round must be rejected by signature verification"
    );
}

// ---------- G1 / R4 — timeout escapes Finalized ----------

/// **Proves:** the exact state the runtime DISARM predicate tests for
/// (`step == Finalized` ∧ `proposal` present ∧ `finalized_reference == proposal.block_hash`)
/// is reachable at the consensus layer, and that `ConsensusEvent::RoundTimeout` **still
/// advances the round** from it (`integration.rs` has no `step` guard on that branch).
///
/// Consequently the only thing that can suppress recovery is the **node-layer** DISARM
/// (`runtime.rs::drive_round_timeout`), not the consensus state machine.
///
/// **Does not prove** that the runtime ever reaches this state together with a permanently
/// deferring commit bridge (G1 itself remains `UNKNOWN`).
#[test]
fn g1_round_timeout_escapes_finalized_with_matching_finalized_reference() {
    let f = fixture(3);
    let dag = dag_with_target();
    let mut ctx = IntegrationContext::new(0, 0);
    let mut state = fresh_state();

    apply(&mut state, &mut ctx, &f, &dag, proposal_event(&f));
    apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 0, VoteType::Prevote, 0));
    apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 1, VoteType::Prevote, 0));
    assert_eq!(state.round.step, RoundStep::Precommit);

    apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 0, VoteType::Precommit, 0));
    apply(&mut state, &mut ctx, &f, &dag, vote_at(&f, 1, VoteType::Precommit, 0));

    // All three DISARM conjuncts hold.
    assert_eq!(state.round.step, RoundStep::Finalized);
    let proposal_hash = state
        .round
        .proposal
        .as_ref()
        .expect("proposal present")
        .block_hash;
    assert_eq!(proposal_hash, TARGET);
    assert_eq!(
        state.finality.finalized_reference,
        Some(TARGET),
        "precommit quorum + verify_qc + applicability Advance ⇒ finalized_reference = target"
    );

    // The timeout transition is unconditional on step.
    let r = apply(
        &mut state,
        &mut ctx,
        &f,
        &dag,
        ConsensusEvent::RoundTimeout,
    );
    let TransitionResult::Applied { .. } = &r else {
        panic!("RoundTimeout from Finalized must be Applied (no step guard), got {r:?}");
    };
    assert_eq!(state.round.round, 1, "round advanced despite step == Finalized");
    assert_eq!(
        state.round.step,
        RoundStep::Propose,
        "fresh round state starts at Propose"
    );
    assert!(
        state.round.proposal.is_none(),
        "fresh round state has no proposal"
    );
    assert_eq!(
        state.finality.finalized_reference,
        Some(TARGET),
        "finality is preserved across the round timeout (safety-critical)"
    );
}

// ---------- G3 / R2 — pending expiry window ----------

/// **Proves:** with the frozen default `RoundTimeoutConfig` (10s / 120s / ×2), a pending
/// proposal entry inserted at round 0 lives for `2 × 10_000` ticks, i.e. it survives **two**
/// round timeouts (`round.rs::timeout_for` gives 10_000 for round 0 and 20_000 for round 1).
/// This is the precondition that makes a cross-round pending recovery possible at all.
///
/// **Does not prove** that such an entry is subsequently mis-admitted; `recover_pending_proposals`
/// and Guard C are node-private and are not exercised here.
#[test]
fn g3_pending_proposal_survives_two_round_timeouts() {
    let cfg = RoundTimeoutConfig::default();
    assert_eq!(cfg.initial_timeout, 10_000);
    assert_eq!(cfg.max_timeout, 120_000);
    assert_eq!(cfg.backoff_factor, 2);
    assert_eq!(cfg.timeout_for(0), 10_000);
    assert_eq!(cfg.timeout_for(1), 20_000);

    // 2 × timeout_for(round) window, per `PENDING_EXPIRY_ROUNDS = 2`.
    assert_eq!(pending_expiry_tick(&cfg, 0, 0), 20_000);
    assert_eq!(pending_expiry_tick(&cfg, 0, 1), 40_000);
    assert_eq!(pending_expiry_tick(&cfg, 1_000, 0), 21_000);
}
