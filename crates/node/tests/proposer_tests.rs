//! Node Proposer → Real BlockBuilder 集成测试（STEP 10-19-6 OPT-1；P-7/P-8）。
//!
//! 复用真实 ValidatorSet / ChainIdentity / ConsensusNode / NodeConsensusDriver / NodeBlockAdapter：
//! - P-7：`build_proposal`（真实 BlockV1 + BlockHash，**非 placeholder**）经 `ValidatorActor::sign_block`
//!   签名 + `NodeConsensusDriver::submit_proposal` 进入 `ConsensusNode`（Applied → Prevote），
//!   idempotent（后续 no-op）。
//! - P-8：proposal 成功后仍走既有 local vote 路径（`submit_local_vote` prevote → quorum 推进），
//!   未引入第二套 proposer-vote pipeline。
//!
//! P-1..P-6 / P-9 / P-10 / OPT-* 在 `crates/node/src/proposer.rs` 单测（判定 + build 层）。

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::integration::TransitionResult;
use nova_consensus::round::RoundStep;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::VerifyingKey;

use nova_node::assembly::ConsensusNode;
use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::driver::NodeConsensusDriver;
use nova_node::proposer::build_proposal;
use nova_node::signer::SoftwareSigner;
use nova_node::validator::{LocalVoteRequest, ValidatorActor};
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];

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

/// 单验证者 driver + block-production adapter（MemoryBackend；head=genesis；本地为唯一 proposer）。
/// 返回 `(driver, adapter, verifying_key)`（vk 供签名验证）。
fn setup_single() -> (
    NodeConsensusDriver<SoftwareSigner>,
    NodeBlockAdapter<MemoryBackend, NoAccountsKeyResolver>,
    VerifyingKey,
) {
    let kp = KeyPair::generate().unwrap();
    let vk = *kp.verifying_key();
    let set = ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: vk.to_bytes(),
        bonded_stake: 100,
        commission_bps: 100,
    }]));
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
    let (actor, _) = actor_of(kp);
    let store = StateStore::new(MemoryBackend::new());
    let root = store.state_root();
    let adapter = NodeBlockAdapter::new(
        store,
        NoAccountsKeyResolver,
        CHAIN_ID,
        GENESIS_HASH,
        100_000_000_000,
        100,
        ChainHead::genesis(GENESIS_HASH, root),
        NetworkId::Mainnet,
    );
    (
        NodeConsensusDriver::new(consensus, vec![actor]),
        adapter,
        vk,
    )
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

// P-7：真实 ProposalBuild（build_proposal 产出）经签名 + Driver 进入 ConsensusNode。
#[test]
fn p7_proposal_through_driver_into_consensus() {
    let (mut driver, adapter, vk) = setup_single();
    let local = driver.actor(0).unwrap().validator_id();

    let pb = build_proposal(local, driver.consensus(), &adapter, 0)
        .expect("select ok")
        .expect("本地为 (0,0) proposer");
    // ProposalRef.block_hash == BlockHash(block)（真实；非 placeholder）
    assert_eq!(pb.proposal_ref.block_hash, pb.block_hash);
    assert_eq!(pb.block_hash, nova_runtime::block_hash(&pb.block).unwrap());
    // 出块签名：signature ∉ block_hash；可由 proposer 公钥验证（core P7-3）
    let mut signed = pb.block.clone();
    driver
        .actor(0)
        .unwrap()
        .sign_block(&mut signed)
        .expect("sign block");
    assert_eq!(
        nova_runtime::block_hash(&signed).unwrap(),
        pb.block_hash,
        "signature excluded from block hash"
    );
    nova_runtime::validate_block_signature(&signed, &vk, CHAIN_ID).expect("signature verifies");

    let res = driver.submit_proposal(pb.proposal_ref);
    assert!(
        matches!(res, TransitionResult::Applied { .. }),
        "proposal Applied"
    );
    assert_eq!(driver.consensus().state().round.step, RoundStep::Prevote);
    assert!(driver.consensus().state().round.proposal.is_some());
    // 幂等：已提案 ⇒ build no-op（不重复 SetProposal / 不二次 transition）
    assert!(
        build_proposal(local, driver.consensus(), &adapter, 0)
            .unwrap()
            .is_none()
    );
}

// P-8：proposal 成功后仍走既有 local vote 路径（未引入第二套 pipeline）。
#[test]
fn p8_proposal_then_existing_local_vote_path() {
    let (mut driver, adapter, _vk) = setup_single();
    let local = driver.actor(0).unwrap().validator_id();
    let pb = build_proposal(local, driver.consensus(), &adapter, 0)
        .unwrap()
        .unwrap();
    let proposal_hash = pb.block_hash;
    driver.submit_proposal(pb.proposal_ref);

    // 既有 vote 路径：ValidatorActor produce → verify_vote_input → submit_verified_vote。
    let res = driver
        .submit_local_vote(0, &prevote_req(proposal_hash))
        .unwrap()
        .expect("本地 prevote 提交");
    assert!(matches!(&res, TransitionResult::Applied { .. }));
    // 单验证者 prevote 达 quorum ⇒ 推进到 Precommit（canonical transition，无第二 pipeline）
    if let TransitionResult::Applied { observation, .. } = &res {
        assert!(observation.prevote_quorum, "prevote quorum");
    }
    assert_eq!(driver.consensus().state().round.step, RoundStep::Precommit);
    assert_eq!(driver.actor(0).unwrap().validator_id(), local);
}
