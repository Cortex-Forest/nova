//! D10-C Step 6 — Test-only Same-Key Provider Seam + Same-Key Restart E2E。
//!
//! Owner-authorized（Option A）：`crypto::signature::SigningKey::from_seed` 提为 `pub`
//! （test/dev-only deterministic reconstruction；不改变签名算法 / 协议 / production key
//! loading / mainnet identity）。本文件用固定 test seed 跨**独立 runtime / provider / signer
//! 实例**重建同一真实 Ed25519 validator key，验证：
//!   Genesis → A commit → REAL RESTART（同 storage + 同 seed）→ …
//! 以及 crash-after-prevote / conflicting-vote / lock / finality-fact 恢复。
//!
//! 诚实边界（见实现报告）：V0.1 production `register_block` 以空 parent + round-height 登记
//! canonical-next ⇒ 存在 lock 后**跨块**（A→B）runtime 续产被 LockConflict 保守阻断 —— 本文件
//! 对单块 commit / 单块恢复 / 同 key prevote 续接 / lock / finality crash 提供真实 PASS 测试，
//! 并以探针测试如实记录跨块缺口（跨块 seam 属 D10-C Step 7 / 生产授权，不在此伪造 PASS）。

use std::path::PathBuf;

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
use nova_consensus::validator::ValidatorId;
use nova_consensus::vote::VoteType;
use nova_crypto::address::{NetworkId, YazimaoAddress};
use nova_crypto::domain::{
    AlgorithmId, DomainId, SigningMessageHash, build_signed_bytes, hash_signing_message,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{
    Signature, SigningKey, VerifyingKey, sign_message_hash, verify_message_hash,
};
use nova_network::node_id::NodeId;
use nova_network::transport::MemoryTransport;
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, block_hash, compute_transaction_root,
    encode_block_header,
};

use nova_node::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::bootstrap::{
    FINALITY_FACT_FILE, NodeConfig, persist_finality_fact, read_finality_fact,
};
use nova_node::key_provider::{KeyProvider, KeyProviderError};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::validator::{LocalVoteRequest, ValidatorActorError};
use nova_node::vote_ledger::VoteKey;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

/// **Test-only** 固定 seed（非生产密钥；仅用于确定性重建同一真实 test Ed25519 key 跨 runtime）。
const TEST_VALIDATOR_SEED: [u8; 32] = [0x5A; 32];

type FileAdapter =
    NodeBlockAdapter<nova_storage::persistent::PersistentBackend, NoAccountsKeyResolver>;

// ---------------------------------------------------------------------------
// Test-only 确定性 key / signer / provider（node tests；不触碰 production provider）
// ---------------------------------------------------------------------------

/// Test-only signer：真实 Ed25519 签名（seed 重建；经 crypto 公开 API `sign_message_hash`）。
struct SeedSigner {
    key: SigningKey,
}

impl SigningCapability for SeedSigner {
    fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(&self.key, message_hash))
    }
}

/// Test-only provider：每次 `load_signer` 从固定 seed **重新构造** SigningKey（不同实例 ⇒ 同一
/// 私钥；不共享对象 / 无 global / 无 Arc —— 真正模拟 restart 后 seed 重建）。
#[derive(Clone, Copy)]
struct SeedKeyProvider {
    seed: [u8; 32],
}

impl SeedKeyProvider {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl KeyProvider for SeedKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        Ok(Box::new(SeedSigner {
            key: SigningKey::from_seed(self.seed),
        }))
    }
}

fn pubkey_from_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    use nova_crypto::address::{ADDRESS_VERSION, AddressType, YazimaoAddressPayload};
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn genesis_with(validator_pk: [u8; 32]) -> GenesisV1 {
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
            consensus_public_key: validator_pk,
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

struct Env {
    dir: PathBuf,
    genesis_hash: [u8; 32],
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(seed: [u8; 32]) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let genesis = genesis_with(pubkey_from_seed(seed));
        let dir = std::env::temp_dir().join(format!("nova_d10c6_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(&genesis).unwrap();
        std::fs::write(
            dir.join("genesis.bin"),
            canonical_genesis_bytes(&genesis).unwrap(),
        )
        .unwrap();
        Self {
            genesis_hash,
            chain_dir: dir.join("chain"),
            safety_dir: dir.join("safety"),
            dir,
        }
    }

    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.dir.join("genesis.bin"),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// REAL RESTART：同一 `config`（同 storage/safety/fact 目录）→ **新 provider 实例**（同 seed）
/// → **新 runtime 实例**。
fn build_test_runtime(config: &NodeConfig, seed: [u8; 32]) -> NodeRuntime {
    let provider = SeedKeyProvider::new(seed);
    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    NodeRuntime::start_with_network(config, Some(&provider), Box::new(tx_a), Box::new(identity))
        .expect("同 key validator + network 启动")
}

fn step_until_head_height(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..40 {
        runtime.step().expect("step ok");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
    }
    panic!("head 未推进到 {want_height}");
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
// T1 — same seed ⇒ same real public key / validator id + valid signature
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t1_same_seed_same_identity() {
    let mut pks = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let provider = SeedKeyProvider::new(TEST_VALIDATOR_SEED);
        let signer = provider.load_signer().expect("load");
        pks.push(signer.public_key().to_bytes());
        ids.push(ValidatorId::from_consensus_public_key(
            &signer.public_key().to_bytes(),
        ));
    }
    assert_eq!(pks[0], pks[1], "provider1 与 provider2 同公钥");
    assert_eq!(pks[1], pks[2], "provider2 与 provider3 同公钥");
    assert_eq!(ids[0], ids[1]);
    assert_eq!(ids[1], ids[2]);

    // 真实签名可验证（seed 重建 key 经 crypto 公开 API）。
    let sk = SigningKey::from_seed(TEST_VALIDATOR_SEED);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        CHAIN_ID,
        &[0xAB; 32],
    )
    .unwrap();
    let msg = hash_signing_message(&signed);
    let sig = sign_message_hash(&sk, &msg);
    assert_eq!(
        verify_message_hash(&sk.verifying_key(), &msg, &sig),
        Ok(()),
        "seed 重建签名可由同一公钥验证"
    );
}

// ---------------------------------------------------------------------------
// T2 — Runtime#1：Genesis → A finality → A commit
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t2_genesis_to_a_commit() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    step_until_head_height(&mut r1, 1);
    let head = r1.block_production().unwrap().head().clone();
    let a_hash = head.block_hash;
    assert_eq!(head.height, 1, "A committed");
    assert_eq!(
        r1.consensus().state().finality.finalized_reference,
        Some(a_hash)
    );
    let bs =
        nova_storage::block_store::BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    assert!(bs.contains(&a_hash).unwrap(), "A ∈ BlockStore");
    assert!(r1.consensus().dag().contains(&a_hash), "A ∈ runtime DAG");
    assert!(
        config.storage_dir.join(FINALITY_FACT_FILE).exists(),
        "RecoveryFact durable"
    );
    r1.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T3 — REAL RESTART：同 storage + 同 seed → A recovered（head / DAG / journal / lock / fact）
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t3_restart_recovers_a() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    r1.shutdown().unwrap();

    let r2 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    let head = r2.block_production().unwrap().head().clone();
    assert_eq!(head.height, 1);
    assert_eq!(head.block_hash, a_hash, "head 恢复 == A");
    let dag = r2.consensus().dag();
    assert!(dag.contains(&env.genesis_hash), "DAG 重建含 genesis 根");
    assert!(dag.contains(&a_hash), "DAG 重建含 committed A");
    {
        let view = r2.validator().expect("validator");
        let actor = view.actor();
        assert_eq!(
            actor.locked_state().locked_block_hash,
            Some(a_hash),
            "LockedState 恢复 == A"
        );
        let rec = actor
            .vote_ledger()
            .lookup(&VoteKey {
                height: 0,
                round: 0,
                vote_type: VoteType::Prevote,
            })
            .expect("VoteLedger 恢复");
        assert_eq!(rec.target_block_hash, a_hash);
    }
    let fact = read_finality_fact(&config.storage_dir.join(FINALITY_FACT_FILE)).unwrap();
    assert_eq!(fact, Some((1, a_hash)), "fact 恢复/idempotent");
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T4 probe — 跨块（A→B）runtime 续产真实缺口记录（不伪造 PASS）
//   当前 V0.1 register_block 空 parent 登记 ⇒ lock=A 后 B 的 prevote 被 LockConflict 保守阻断。
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t4_probe_cross_block_continuation_gap() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    r1.shutdown().unwrap();

    let mut r2 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    assert_eq!(r2.block_production().unwrap().head().block_hash, a_hash);
    for _ in 0..14 {
        r2.step()
            .expect("step 不报错（LockConflict 为保守 no-op，非错误）");
    }
    let head = r2.block_production().unwrap().head().clone();
    assert_eq!(
        head.block_hash, a_hash,
        "跨块 A→B 续产被 V0.1 register_block 空 parent + lock 保守阻断（D10-C Step 7 seam）"
    );
    assert_eq!(head.height, 1);
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T7 — crash after local prevote → restart（同 key）→ VoteLedger 恢复 → 同 target 幂等 → commit A
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t7_crash_after_prevote_idempotent_reuse() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    // Runtime#1：恰产 A + local prevote（未 precommit / 未 commit）—— journal 每写即时 fsync ⇒ durable。
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    r1.step().expect("step1");
    let target = r1.last_proposal().expect("本地 proposal").block_hash;
    let rec1 = r1
        .validator()
        .expect("validator")
        .actor()
        .vote_ledger()
        .lookup(&VoteKey {
            height: 0,
            round: 0,
            vote_type: VoteType::Prevote,
        })
        .expect("prevote 已签");
    assert_eq!(rec1.target_block_hash, target);
    assert_eq!(r1.block_production().unwrap().head().height, 0, "未 commit");
    r1.shutdown().unwrap();

    // REAL RESTART：ledger 恢复 → 同 VoteKey 同 target 幂等复用（不重签）→ 续 precommit → finality → commit A。
    let mut r2 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    let rec2 = r2
        .validator()
        .expect("validator")
        .actor()
        .vote_ledger()
        .lookup(&VoteKey {
            height: 0,
            round: 0,
            vote_type: VoteType::Prevote,
        })
        .expect("VoteLedger 恢复");
    assert_eq!(
        rec2.target_block_hash, rec1.target_block_hash,
        "同 target 恢复"
    );
    assert_eq!(rec2.signature, rec1.signature, "幂等复用同一签名（不重签）");
    step_until_head_height(&mut r2, 1);
    assert_eq!(r2.block_production().unwrap().head().height, 1, "A commit");
    assert_eq!(
        r2.consensus().state().finality.finalized_reference,
        Some(r2.block_production().unwrap().head().block_hash)
    );
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T8 — conflicting vote（同 key restart 后同 VoteKey 异 target）⇒ DoubleVote / 无新签名
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t8_conflicting_vote_rejected_after_restart() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    r1.step().expect("step1");
    let target = r1.last_proposal().expect("本地 proposal").block_hash;
    r1.shutdown().unwrap();

    let r2 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    {
        let view = r2.validator().expect("validator");
        let actor = view.actor();
        let set = r2.consensus().validator_set().clone();
        let dag = r2.consensus().dag().clone();
        let different = if target == [0xBB; 32] {
            [0xCC; 32]
        } else {
            [0xBB; 32]
        };
        let err = actor
            .produce_vote(&req(0, 0, different, VoteType::Prevote), &set, &dag)
            .expect_err("conflicting vote 必须拒绝");
        assert!(
            matches!(err, ValidatorActorError::DoubleVote { .. }),
            "restart 后异 target ⇒ DoubleVote（实际 {err:?}）"
        );
        let rec = actor
            .vote_ledger()
            .lookup(&VoteKey {
                height: 0,
                round: 0,
                vote_type: VoteType::Prevote,
            })
            .expect("ledger 恢复");
        assert_eq!(rec.target_block_hash, target, "目标未被覆盖");
    }
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T9 — lock survives restart；descendant 允许 / unrelated 保守拒绝
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t9_lock_survives_restart() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let mut r1 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    r1.shutdown().unwrap();

    let r2 = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    {
        let view = r2.validator().expect("validator");
        let actor = view.actor();
        let set = r2.consensus().validator_set().clone();
        let proposer =
            ValidatorId::from_consensus_public_key(&pubkey_from_seed(TEST_VALIDATOR_SEED));
        assert_eq!(
            actor.locked_state().locked_block_hash,
            Some(a_hash),
            "LockedState 跨 restart 恢复"
        );
        assert_eq!(actor.locked_state().locked_round, Some(0));

        // unrelated（runtime committed DAG 无此块 / 无 ancestry）⇒ LockConflict 保守拒绝（无事件）。
        let dag_committed = r2.consensus().dag().clone();
        let out = actor
            .produce_vote(
                &req(1, 0, [0xEE; 32], VoteType::Prevote),
                &set,
                &dag_committed,
            )
            .expect("无错误");
        assert!(out.is_none(), "unrelated ⇒ LockConflict 保守拒绝");

        // descendant Y（child of A）自建 DAG 边 ⇒ 允许（真实签名事件）。
        let mut dag_y = Dag::new();
        for (h, p, hgt) in [
            (env.genesis_hash, None, 0u64),
            (a_hash, Some(env.genesis_hash), 1),
        ] {
            let parents = p.map(|x| vec![x]).unwrap_or_default();
            dag_y
                .add_block(BlockReference {
                    block_hash: h,
                    height: hgt,
                    parents,
                    proposer,
                })
                .unwrap();
        }
        let y = [0x10; 32];
        dag_y
            .add_block(BlockReference {
                block_hash: y,
                height: 2,
                parents: vec![a_hash],
                proposer,
            })
            .unwrap();
        let out = actor
            .produce_vote(&req(1, 0, y, VoteType::Prevote), &set, &dag_y)
            .expect("无错误");
        assert!(out.is_some(), "descendant Y ⇒ 允许投票（真实签名）");
    }
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T10 — finality durable / commit 未发生 crash → REAL RESTART（同 seed）→ RecoveryFact 恢复 →
//        QC verify → BlockStore resolve X → bridge commit X（head==X；不重新签名 vote）
// ---------------------------------------------------------------------------

#[test]
fn d10_c6_t10_finality_crash_same_key_recovery_commit() {
    let env = Env::new(TEST_VALIDATOR_SEED);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    // crash 状态：X(=A, height1, parent genesis, seed 真实签名) durable 于 BlockStore + Fact(X)。
    let a_hash;
    {
        let adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        let state_root = *adapter.store().state_root().as_bytes();
        let (block, _) =
            seed_empty_block_at(&config, genesis_hash, 1, state_root, TEST_VALIDATOR_SEED);
        a_hash = block_hash(&block).unwrap();
        adapter.block_store().unwrap().put(&block).unwrap();
    }
    let sig = seed_precommit_signature(TEST_VALIDATOR_SEED, a_hash, 0, 0);
    let qc = QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target: a_hash,
        validator_set_id: genesis_hash,
        evidence: vec![QcEvidence {
            validator_id: ValidatorId::from_consensus_public_key(&pubkey_from_seed(
                TEST_VALIDATOR_SEED,
            )),
            source_block_hash: [0u8; 32],
            timestamp: 0,
            signature: sig,
        }],
    };
    persist_finality_fact(
        &config.storage_dir.join(FINALITY_FACT_FILE),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        a_hash,
        &qc,
    )
    .unwrap();

    // REAL RESTART（同 seed）：RecoveryFact 恢复注入 X → bridge 从 BlockStore commit X。
    let mut r = build_test_runtime(&config, TEST_VALIDATOR_SEED);
    assert_eq!(
        r.consensus().state().finality.finalized_reference,
        Some(a_hash),
        "RecoveryFact 恢复注入 X"
    );
    step_until_head_height(&mut r, 1);
    assert_eq!(
        r.block_production().unwrap().head().block_hash,
        a_hash,
        "bridge 完成 commit X"
    );
    r.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// seed 空块 / seed precommit 签名（真实生产 block/vote 构造；签名经 crypto 公开 API）
// ---------------------------------------------------------------------------

/// 空 canonical block（seed key 真实 block-domain 签名）。
fn seed_empty_block_at(
    config: &NodeConfig,
    parent: [u8; 32],
    height: u64,
    state_root: [u8; 32],
    seed: [u8; 32],
) -> (Block, Vec<u8>) {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height,
        parent_hash: parent,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: config.expected_genesis_hash,
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    let sk = SigningKey::from_seed(seed);
    let block = Block {
        header,
        body,
        proposer_signature: sign_message_hash(&sk, &msg).to_bytes(),
    };
    let wire = nova_runtime::encode_block(&block).unwrap();
    (block, wire)
}

/// seed key 对 precommit vote 的真实签名（vote domain）。
fn seed_precommit_signature(seed: [u8; 32], target: [u8; 32], height: u64, round: u64) -> [u8; 64] {
    use nova_consensus::vote::{ValidatorVote, canonical_vote_payload};
    let sk = SigningKey::from_seed(seed);
    let id = ValidatorId::from_consensus_public_key(&sk.verifying_key().to_bytes());
    let vote = ValidatorVote {
        height,
        round,
        target_block_hash: target,
        vote_type: VoteType::Precommit,
        source_block_hash: [0u8; 32],
        validator_id: id,
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
    sign_message_hash(&sk, &hash_signing_message(&signed)).to_bytes()
}

// 引用 FileAdapter 类型以固定装配类型（供后续 Step 扩展），避免未用告警。
#[allow(dead_code)]
fn _adapter_type(_: &FileAdapter) {}
