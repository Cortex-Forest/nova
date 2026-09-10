//! D10-C Step 7-A — `ConsensusNode::register_block` DAG registration 正确性（node-only）。
//!
//! 修正后：`register_block(block_hash, height, parent_hash, proposer)` 以块**真实**
//! `header.height` / `header.parent_hash` 登记 DAG reference（genesis/height==0 ⇒ parents 空），
//! 使 canonical-next `A(height=H) → B(height=H+1, parent=A)` 在 DAG 中真实成边 ⇒
//! `dag.is_ancestor(A, B) == true` ⇒ frozen lock applicability（ADR-0053 L-4/L-8）允许
//! `lock=A` 下对 B 投票（不再保守 LockConflict）。
//!
//! 本文件为纯 node 层 DAG registration 测试：不 mock `is_ancestor`、不重写 Dag、不触碰 consensus。

use nova_consensus::dag::Dag;
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, VerifyingKey};

use nova_node::assembly::ConsensusNode;
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::validator::{LocalVoteRequest, ValidatorActor};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn single_validator_genesis(pk: [u8; 32]) -> GenesisV1 {
    let account = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: account.address,
            consensus_public_key: pk,
            bonded_stake: STAKE,
            commission_bps: 0,
        }],
        initial_accounts: vec![account],
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: 1_000_000,
            max_contract_code_bytes: 1024,
            max_contract_storage_bytes: 1024,
            epoch_length_blocks: 1_000,
            snapshot_interval_blocks: 10_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: 1_000_000,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

/// Test-local 固定 signer（真实 identity；签名字节固定 —— 本文件断言 authorization 决策，
/// 签名内容不参与 DAG/lock 判定）。
struct FixedSigner {
    public: [u8; 32],
}

impl SigningCapability for FixedSigner {
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public).expect("valid Ed25519 pk")
    }
    fn sign(&self, _m: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(Signature::from_bytes(&[0x5A; 64]).unwrap())
    }
}

fn setup() -> (ConsensusNode, ValidatorId, [u8; 32], ValidatorSet) {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let genesis_hash = compute_genesis_hash(&genesis).unwrap();
    let set = ValidatorSet::from_genesis(&genesis);
    let id = ValidatorId::from_consensus_public_key(&pk);
    // 首启语义：head=genesis ⇒ round.height=0，DAG 空（rebuild head0 ⇒ 空）。
    let node = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), genesis_hash, Dag::new());
    (node, id, genesis_hash, set)
}

fn req(h: u64, r: u64, target: [u8; 32], vt: VoteType) -> LocalVoteRequest {
    LocalVoteRequest {
        height: h,
        round: r,
        target_block_hash: target,
        vote_type: vt,
        source_block_hash: [0u8; 32],
        timestamp: 0,
    }
}

// ---------------------------------------------------------------------------
// T7-A-1 — 注册 A（canonical-next of genesis）⇒ DAG contains A
// ---------------------------------------------------------------------------

#[test]
fn d10_c7a_t1_register_a_in_dag() {
    let (mut node, id, genesis_hash, _set) = setup();
    let a = [0xA1; 32];
    // A: height=1（round.height 0 的 canonical-next），parent = genesis。
    node.register_block(a, 1, genesis_hash, id).unwrap();
    let dag = node.dag();
    assert!(dag.contains(&genesis_hash), "首块登记补 genesis 根");
    assert!(dag.contains(&a), "DAG contains A");
    assert_eq!(dag.parents_of(&a), Some(&[genesis_hash][..]));
}

// ---------------------------------------------------------------------------
// T7-A-2 — 注册 B（A 的 canonical-next）⇒ A → B 真实边 + ancestor
// ---------------------------------------------------------------------------

#[test]
fn d10_c7a_t2_register_b_creates_ancestry() {
    let (mut node, id, genesis_hash, _set) = setup();
    let a = [0xA1; 32];
    let b = [0xB2; 32];
    node.register_block(a, 1, genesis_hash, id).unwrap();
    node.register_block(b, 2, a, id).unwrap(); // B.height = A.height+1, B.parent = A
    let dag = node.dag();
    assert!(dag.contains(&a));
    assert!(dag.contains(&b));
    assert!(dag.is_ancestor(&a, &b), "A is ancestor of B");
    assert!(!dag.is_ancestor(&b, &a), "反向非祖先");
    assert_eq!(dag.parents_of(&b), Some(&[a][..]), "B.parents == [A]");
}

// ---------------------------------------------------------------------------
// T7-A-3 — lock=A + vote target=B（真实 frozen lock applicability）⇒ NOT LockConflict
// ---------------------------------------------------------------------------

#[test]
fn d10_c7a_t3_lock_a_allows_vote_b() {
    let (mut node, id, genesis_hash, set) = setup();
    let a = [0xA1; 32];
    let b = [0xB2; 32];
    node.register_block(a, 1, genesis_hash, id).unwrap();
    node.register_block(b, 2, a, id).unwrap();

    // 真实 ValidatorActor：以 A 的 Precommit QC 取得 lock=A（frozen acquire_lock；unlocked ⇒ lock）。
    let mut actor = ValidatorActor::new(
        id,
        FixedSigner {
            public: set_key(&set),
        },
        CHAIN_ID,
    )
    .unwrap();
    let qc_a = QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target: a,
        validator_set_id: genesis_hash,
        evidence: vec![QcEvidence {
            validator_id: id,
            source_block_hash: [0u8; 32],
            timestamp: 0,
            signature: [0x5A; 64],
        }],
    };
    actor.on_verified_precommit_qc(&qc_a, node.dag()).unwrap();
    assert_eq!(actor.locked_state().locked_block_hash, Some(a));

    // vote target = B（A 的 descendant）⇒ 真实授权通过 ⇒ 产出 Vote event（NOT LockConflict）。
    let produced_b = actor
        .produce_vote(&req(1, 0, b, VoteType::Prevote), &set, node.dag())
        .expect("no actor error");
    assert!(
        produced_b.is_some(),
        "lock=A + target=B(descendant) ⇒ Authorized（非 LockConflict no-op）"
    );

    // 对照：unrelated target ⇒ 仍保守拒绝（frozen lock 语义未变；无 event）。
    let produced_z = actor
        .produce_vote(&req(1, 0, [0xEE; 32], VoteType::Prevote), &set, node.dag())
        .expect("no actor error");
    assert!(
        produced_z.is_none(),
        "unrelated target ⇒ 保守拒绝（LockConflict no-op）"
    );
}

// ---------------------------------------------------------------------------
// T7-A-4 — 使用 ConsensusNode 的真实 DAG（非 helper）证明 ancestry 结构
// ---------------------------------------------------------------------------

#[test]
fn d10_c7a_t4_real_dag_ancestry_chain() {
    let (mut node, id, genesis_hash, _set) = setup();
    let a = [0xA1; 32];
    let b = [0xB2; 32];
    let c = [0xC3; 32];
    node.register_block(a, 1, genesis_hash, id).unwrap();
    node.register_block(b, 2, a, id).unwrap();
    node.register_block(c, 3, b, id).unwrap();
    let dag = node.dag();
    // genesis → A → B → C 全传递 ancestry 于真实 node DAG。
    assert!(dag.is_ancestor(&genesis_hash, &c));
    assert!(dag.is_ancestor(&a, &c));
    assert!(dag.is_ancestor(&b, &c));
    assert_eq!(dag.parents_of(&c), Some(&[b][..]));
    // 幂等：重复登记同 hash ⇒ Ok（不重复插入）。
    node.register_block(c, 3, b, id).unwrap();
    assert_eq!(node.dag().len(), 4, "genesis + A + B + C（幂等不重复）");
}

/// 单验证者集合的公钥（用于构造与 set 一致的 signer identity）。
fn set_key(set: &ValidatorSet) -> [u8; 32] {
    set.validators()
        .first()
        .expect("single validator")
        .consensus_public_key
}
