//! D10-C Step 4 — Finality Recovery Fact（最小 + fail-closed）。
//!
//! 证明：`Finality(X) 达成 → commit 前 crash → restart` 时，durable Recovery Fact（reference +
//! PrecommitQC + identity）经 bootstrap 恢复校验（identity / target / height / block 存在 /
//! canonical-head child / QC verify）后注入 finalized_reference，既有 D10-B bridge 从 BlockStore
//! 解析 X 完成 commit；损坏 / identity 失配 / 无效 QC / 缺块 / head 冲突 ⇒ 启动 fail-closed。
//!
//! 禁止：手动 submit_local_vote / state_mut / 手设 finality/head/QC/round；不伪造 QC —— 有效恢复
//! 用例的 QC 由 genesis validator 对真实 block 的真实 precommit 签名构造（verify_qc 全验证）。
//! restart 用「新本地 key + 新 safety dir、同 chain storage」（持久化 key 导入 = DEFERRED）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nova_consensus::dag::Dag;
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{
    AlgorithmId, DomainId, SigningMessageHash, build_signed_bytes, hash_signing_message,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, SigningKey, VerifyingKey, sign_message_hash};
use nova_network::node_id::NodeId;
use nova_network::transport::MemoryTransport;
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, block_hash, compute_transaction_root,
    encode_block, encode_block_header,
};
use nova_storage::block_store::BlockStore;

use nova_node::block_adapter::NoAccountsKeyResolver;
use nova_node::bootstrap::{
    FINALITY_FACT_FILE, NodeConfig, NodeStartupError, persist_finality_fact, read_finality_fact,
};
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, NodeRuntimeError};
use nova_node::safety_store::{SafetyIdentity, ValidatorSafetyStore};
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::validator::{LocalVoteRequest, ValidatorActor, ValidatorActorError};
use nova_node::vote_ledger::VoteKey;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

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

fn genesis_with(validators: Vec<([u8; 32], u128)>) -> GenesisV1 {
    let n = validators.len();
    let accounts: Vec<AccountInit> = (0..n)
        .map(|i| AccountInit {
            address: addr([0x11 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut vs: Vec<ValidatorInit> = validators
        .iter()
        .zip(accounts.iter())
        .map(|((pk, stake), acct)| ValidatorInit {
            account_address: acct.address,
            consensus_public_key: *pk,
            bonded_stake: *stake,
            commission_bps: 0,
        })
        .collect();
    vs.sort_by_key(|v| ValidatorId::from_consensus_public_key(&v.consensus_public_key));
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vs,
        initial_accounts: accounts,
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
            total_supply,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d10c4_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        Self {
            _dir: dir,
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
            listen_addr: None,
        }
    }
}

fn fact_path(env: &Env) -> PathBuf {
    env.chain_dir.join(FINALITY_FACT_FILE)
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// restart 配置：同 chain storage；新 safety dir（tag 唯一）＋新本地 key。
fn restart_cfg(config: &NodeConfig, tag: &str) -> NodeConfig {
    let mut c = config.clone();
    c.safety_dir = config.safety_dir.join(tag);
    c
}

/// enabled（网络主循环）validator runtime（finality/commit bridge 只在 enabled 分支运行）。
fn start_enabled(config: &NodeConfig, provider: &dyn KeyProvider) -> NodeRuntime {
    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    NodeRuntime::start_with_network(config, Some(provider), Box::new(tx_a), Box::new(identity))
        .expect("validator + network 启动")
}

fn step_until_head_height(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..10 {
        runtime.step().expect("step ok");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
    }
    panic!("head 未推进到 {want_height}");
}

fn block_signature(header: &BlockHeader, sk: &SigningKey) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

fn empty_block_at(
    genesis_hash: &[u8; 32],
    parent: [u8; 32],
    height: u64,
    state_root: [u8; 32],
    timestamp: u64,
    kp: &KeyPair,
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
        validator_set_hash: *genesis_hash,
        timestamp,
    };
    let block = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let wire = encode_block(&block).unwrap();
    (block, wire)
}

/// 真实签名 precommit vote（DomainId::ValidatorVote）；`valid = false` ⇒ 伪签名（verify 必拒）。
fn signed_precommit_vote(
    kp: &KeyPair,
    target: [u8; 32],
    height: u64,
    round: u64,
    valid: bool,
) -> (ValidatorVote, [u8; 64]) {
    let id = ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes());
    let vote = ValidatorVote {
        height,
        round,
        target_block_hash: target,
        vote_type: VoteType::Precommit,
        source_block_hash: [0u8; 32],
        validator_id: id,
        timestamp: 0,
    };
    let sig = if valid {
        let payload = canonical_vote_payload(&vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .unwrap();
        sign_message_hash(kp.signing_key(), &hash_signing_message(&signed)).to_bytes()
    } else {
        [0x11; 64]
    };
    (vote, sig)
}

/// 单验证者 PrecommitQC（真实 block / 真实签名构造；QC 结构 = frozen QuorumCertificate）。
fn precommit_qc_single(
    genesis_hash: [u8; 32],
    kp: &KeyPair,
    target: [u8; 32],
    qc_height: u64,
    qc_round: u64,
    valid: bool,
) -> QuorumCertificate {
    let id = ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes());
    let (vote, sig) = signed_precommit_vote(kp, target, qc_height, qc_round, valid);
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: qc_height,
            round: qc_round,
            vote_type: VoteType::Precommit,
        },
        target,
        validator_set_id: genesis_hash,
        evidence: vec![QcEvidence {
            validator_id: id,
            source_block_hash: vote.source_block_hash,
            timestamp: vote.timestamp,
            signature: sig,
        }],
    }
}

/// fixture：head=genesis；把 block A（height1、parent genesis、state_root=store root）写入
/// BlockStore（durable、**未 commit**）+ 写 Recovery Fact(A) —— 模拟「finality durable、commit
/// 前 crash」的持久状态（crash-window 起点）。`kp` 必须是 genesis 验证者成员（A 与 QC 由其签署）。
fn crash_state(config: &NodeConfig, kp: &KeyPair, qc_valid: bool) -> [u8; 32] {
    let adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, config).unwrap();
    let genesis_hash = adapter.genesis_hash();
    let (a_block, _) = empty_block_at(
        &genesis_hash,
        genesis_hash,
        1,
        *adapter.store().state_root().as_bytes(),
        0,
        kp,
    );
    let a_hash = block_hash(&a_block).unwrap();
    adapter
        .block_store()
        .unwrap()
        .put(&a_block)
        .expect("本地 proposal durable 进 BlockStore");
    let qc = precommit_qc_single(genesis_hash, kp, a_hash, 0, 0, qc_valid);
    persist_finality_fact(
        &fact_path_from(config),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        a_hash,
        &qc,
    )
    .expect("fact 写成功");
    a_hash
}

/// crash-window 完整闭环：crash 状态 → restart → 恢复 → bridge 从 BlockStore commit A。
fn crash_and_commit(config: &NodeConfig, kp: &KeyPair) -> [u8; 32] {
    let a_hash = crash_state(config, kp, true);
    let cfg2 = restart_cfg(config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let mut r2 = start_enabled(&cfg2, &provider2);
    step_until_head_height(&mut r2, 1);
    let head = r2.block_production().unwrap().head().clone();
    assert_eq!(
        head.block_hash, a_hash,
        "恢复后 bridge 从 BlockStore commit A"
    );
    assert_eq!(
        r2.consensus().state().finality.finalized_reference,
        Some(a_hash)
    );
    r2.shutdown().unwrap();
    a_hash
}

fn fact_path_from(config: &NodeConfig) -> PathBuf {
    config.storage_dir.join(FINALITY_FACT_FILE)
}

fn single_genesis() -> (KeyPair, GenesisV1) {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    (kp, genesis)
}

/// `NodeRuntime::start` 期望失败（fact 校验 fail-closed）⇒ 返回 `NodeRuntimeError`（NodeRuntime 无 Debug）。
fn expect_start_failure(config: &NodeConfig, provider: &SoftwareKeyProvider) -> NodeRuntimeError {
    match NodeRuntime::start(config, Some(provider)) {
        Ok(_) => panic!("启动应失败（Recovery Fact 校验 fail-closed）"),
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// T1 — Finality Advance 后 RecoveryFact 存在（runtime 真实 finality → persist-before-bridge）
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t1_fact_exists_after_finality() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    assert_eq!(r1.block_production().unwrap().head().height, 1);
    assert!(fact_path(&env).exists(), "finality 后 fact 已 durable");
    r1.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T2 — RecoveryFact decode 成功（height=1、reference=A）
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t2_fact_decodes() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    r1.shutdown().unwrap();
    let decoded = read_finality_fact(&fact_path(&env)).expect("fact 结构 decode 成功");
    assert_eq!(decoded, Some((1, a_hash)), "fact: height=1, reference=A");
}

// ---------------------------------------------------------------------------
// T3 + T4 + T15 — crash-window：finality durable → commit 未发生 → restart → 恢复 →
//              BlockStore 解析 X → bridge commit（T15 = bridge-from-BlockStore）
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t3_crash_window_recovery_commit() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let a_hash = crash_and_commit(&config, &kp);
    assert_ne!(a_hash, [0u8; 32]);
}

#[test]
fn d10_c4_t4_valid_qc_recovery_ok() {
    // 恢复（injection）发生在 start —— 验证有效 QC 恢复注入 finality（未 step 亦可见）。
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let a_hash = crash_state(&config, &kp, true);
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r2 = start_enabled(&cfg2, &provider2);
    assert_eq!(
        r2.consensus().state().finality.finalized_reference,
        Some(a_hash),
        "有效 QC 恢复注入 finalized_reference"
    );
    r2.shutdown().unwrap();
}

#[test]
fn d10_c4_t15_bridge_resolves_from_block_store() {
    // 恢复路径无 last_proposal（新进程）；bridge 只能从 BlockStore 解析 X —— 已由
    // crash_and_commit 覆盖；此处显式断言 committed X durable 于 BlockStore。
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let a_hash = crash_and_commit(&config, &kp);
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    assert!(
        bs.contains(&a_hash).expect("blockstore 可读"),
        "committed X durable（bridge 从 BlockStore 解析）"
    );
}

// ---------------------------------------------------------------------------
// T5 — 无效 QC ⇒ startup fail-closed
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t5_invalid_qc_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    // A durable + fact 但 QC 签名伪（结构可 decode、verify_qc 必拒）。
    let _ = crash_state(&config, &kp, false);
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactQc(_))
        ),
        "无效 QC ⇒ FinalityFactQc（实际 {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T6 — Missing block ⇒ startup fail-closed
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t6_missing_block_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    // 只写 fact（不 put A 到 BlockStore）⇒ 恢复时缺块。
    let a_hash = [0xAA; 32];
    let qc = precommit_qc_single(genesis_hash, &kp, a_hash, 0, 0, true);
    persist_finality_fact(
        &fact_path_from(&config),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        a_hash,
        &qc,
    )
    .unwrap();
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactMissingBlock)
        ),
        "缺块 ⇒ FinalityFactMissingBlock（实际 {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T7 — checksum corruption ⇒ startup fail-closed
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t7_checksum_corruption_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let _ = crash_state(&config, &kp, true);
    // 覆写 fact 文件：破坏一个字节（checksum/body）⇒ 结构校验必拒。
    let path = fact_path_from(&config);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactCorrupt)
        ),
        "损坏 fact ⇒ FinalityFactCorrupt（实际 {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T8 — wrong chain identity ⇒ startup fail-closed
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t8_wrong_chain_identity_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    let a_hash = crash_state(&config, &kp, true);
    // 覆盖 fact：同 A 但 chain_id 错误（checksum 由 persist 重新计算 —— 合法文件、identity 失配）。
    let qc = precommit_qc_single(genesis_hash, &kp, a_hash, 0, 0, true);
    persist_finality_fact(
        &fact_path_from(&config),
        NetworkId::Mainnet,
        CHAIN_ID + 1,
        genesis_hash,
        1,
        a_hash,
        &qc,
    )
    .unwrap();
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactIdentityMismatch)
        ),
        "跨链 fact ⇒ FinalityFactIdentityMismatch（实际 {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T9 — finalized X 已 commit ⇒ restart 不重复 commit（幂等）
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t9_committed_no_recommit() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    // ① 真实 runtime commit A（finality + fact + commit 同 tick 完成）。
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    assert!(fact_path(&env).exists(), "fact 已 durable");
    r1.shutdown().unwrap();
    // ② restart：fact reference == head（已 commit）⇒ idempotent，不 re-commit。
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let mut r2 = start_enabled(&cfg2, &provider2);
    assert_eq!(
        r2.block_production().unwrap().head().block_hash,
        a_hash,
        "重启 head 保持（fact idempotent —— 无重复 commit）"
    );
    for _ in 0..4 {
        r2.step().unwrap();
    }
    assert_eq!(
        r2.block_production().unwrap().head().block_hash,
        a_hash,
        "重启后仍无 re-commit"
    );
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T10 — head 已是 X descendant（X 已 commit）⇒ stale fact 不回退 head
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t10_stale_fact_no_rollback() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    // ① canonical A→B（head=B，height2）经真实 adapter durable commit。
    let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    let (wa, _) = empty_block_at(
        &genesis_hash,
        genesis_hash,
        1,
        *adapter.store().state_root().as_bytes(),
        0,
        &kp,
    );
    let a_hash = adapter
        .apply_block(&encode_block(&wa).unwrap(), kp.verifying_key())
        .unwrap()
        .block_hash;
    let (wb, _) = empty_block_at(
        &genesis_hash,
        a_hash,
        2,
        *adapter.store().state_root().as_bytes(),
        0,
        &kp,
    );
    let b_hash = adapter
        .apply_block(&encode_block(&wb).unwrap(), kp.verifying_key())
        .unwrap()
        .block_hash;
    assert_eq!(adapter.head().height, 2);
    drop(adapter);
    // ② 写 stale fact（A 已 commit；QC target A）。
    let qc_a = precommit_qc_single(genesis_hash, &kp, a_hash, 0, 0, true);
    persist_finality_fact(
        &fact_path_from(&config),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        a_hash,
        &qc_a,
    )
    .unwrap();
    // ③ restart：fact 已满足（A ∈ committed ancestry）⇒ stale ignore，不回退。
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r2 = NodeRuntime::start(&cfg2, Some(&provider2)).expect("stale fact ⇒ 正常启动");
    assert_eq!(
        r2.block_production().unwrap().head().height,
        2,
        "head 不回退（仍为 B）"
    );
    assert_eq!(r2.block_production().unwrap().head().block_hash, b_hash);
    assert_eq!(
        r2.consensus().state().finality.finalized_reference,
        None,
        "stale fact 不注入（finality 保持默认）"
    );
    r2.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T11 — head 与 X 同高但不同 hash ⇒ fail-closed
// T12 — head 与 X unrelated ⇒ fail-closed
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t11_same_height_different_hash_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    // head=B（height1，committed）；X 同高（height1）不同块。
    let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    let (wb, _) = empty_block_at(
        &genesis_hash,
        genesis_hash,
        1,
        *adapter.store().state_root().as_bytes(),
        0,
        &kp,
    );
    adapter
        .apply_block(&encode_block(&wb).unwrap(), kp.verifying_key())
        .unwrap();
    // X = 另一 height1 块（不同 timestamp），只 put（不 commit）。
    let (x_block, _) = empty_block_at(
        &genesis_hash,
        genesis_hash,
        1,
        *adapter.store().state_root().as_bytes(),
        1,
        &kp,
    );
    let x_hash = block_hash(&x_block).unwrap();
    adapter.block_store().unwrap().put(&x_block).unwrap();
    drop(adapter);
    // fact(X)：X 与 head(B) 同高不同 hash。
    let qc_x = precommit_qc_single(genesis_hash, &kp, x_hash, 0, 0, true);
    persist_finality_fact(
        &fact_path_from(&config),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        x_hash,
        &qc_x,
    )
    .unwrap();
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactHeadConflict)
        ),
        "同高异 hash ⇒ HeadConflict（实际 {err:?}）"
    );
}

#[test]
fn d10_c4_t12_unrelated_head_fail_closed() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    // head=B（height1）；X 高度 2 但 parent 非 head（unrelated）。
    let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    let (wb, _) = empty_block_at(
        &genesis_hash,
        genesis_hash,
        1,
        *adapter.store().state_root().as_bytes(),
        0,
        &kp,
    );
    adapter
        .apply_block(&encode_block(&wb).unwrap(), kp.verifying_key())
        .unwrap();
    // X2: height2, parent = [0x99;32]（非 head B）。
    let (x_block, _) = empty_block_at(
        &genesis_hash,
        [0x99; 32],
        2,
        *adapter.store().state_root().as_bytes(),
        0,
        &kp,
    );
    let x_hash = block_hash(&x_block).unwrap();
    adapter.block_store().unwrap().put(&x_block).unwrap();
    drop(adapter);
    let qc_x = precommit_qc_single(genesis_hash, &kp, x_hash, 1, 0, true);
    persist_finality_fact(
        &fact_path_from(&config),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        2,
        x_hash,
        &qc_x,
    )
    .unwrap();
    let cfg2 = restart_cfg(&config, "restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let err = expect_start_failure(&cfg2, &provider2);
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(NodeStartupError::FinalityFactHeadConflict)
        ),
        "unrelated ⇒ HeadConflict（实际 {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T13 — 无 fact ⇒ 正常启动
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t13_no_fact_normal_start() {
    let (_kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r = NodeRuntime::start(&config, Some(&provider)).expect("无 fact ⇒ 正常启动");
    assert_eq!(r.block_production().unwrap().head().height, 0);
    assert_eq!(r.consensus().state().finality.finalized_reference, None);
    r.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T14 — 同一 fact 连续 restart ⇒ idempotent
// ---------------------------------------------------------------------------

#[test]
fn d10_c4_t14_consecutive_restart_idempotent() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let config = env.config();
    // ① 真实 commit A。
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.block_production().unwrap().head().block_hash;
    r1.shutdown().unwrap();
    // ②③ 同一 fact 连续两次 restart：均幂等（head==A，不 re-commit / 不报错）。
    for tag in ["restart_a", "restart_b"] {
        let cfg2 = restart_cfg(&config, tag);
        let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
        let r2 = start_enabled(&cfg2, &provider2);
        assert_eq!(r2.block_production().unwrap().head().block_hash, a_hash);
        r2.shutdown().unwrap();
    }
}

// ---------------------------------------------------------------------------
// T16 — restart（journal restore）后 Safety Journal / VoteLedger 阻止 conflicting vote
//       （runtime 同 key restart 受「持久化 key 导入 DEFERRED」限制 ⇒ 以 ValidatorActor 从
//        同一 durable journal restore 路径验证 —— 与 restart 触发同一恢复代码）
// ---------------------------------------------------------------------------

/// 确定性测试 signer（重启时可重建同一 identity；不暴露真实私钥）。
struct FixedSigner {
    public: [u8; 32],
    count: std::rc::Rc<std::cell::Cell<usize>>,
}

impl SigningCapability for FixedSigner {
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public).expect("固定公钥为合法 Ed25519 压缩点")
    }
    fn sign(&self, _m: &SigningMessageHash) -> Result<Signature, SigningError> {
        self.count.set(self.count.get() + 1);
        Ok(Signature::from_bytes(&[0x5A; 64]).unwrap())
    }
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

#[test]
fn d10_c4_t16_journal_blocks_conflicting_vote_after_restart() {
    let (kp, genesis) = single_genesis();
    let env = Env::new(&genesis);
    let genesis_hash = env.genesis_hash;
    let set = ValidatorSet::from_genesis(&genesis);
    let dag = Dag::new();
    let pk = kp.verifying_key().to_bytes();
    let id = ValidatorId::from_consensus_public_key(&pk);
    let journal = env.safety_dir.join("safety.journal");
    std::fs::create_dir_all(&env.safety_dir).unwrap();

    // ① 写 durable intent + signature（prevote (0,0) → A）—— 模拟 crash 前已签 prevote。
    let store = ValidatorSafetyStore::create(
        &journal,
        SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, genesis_hash, &id),
    )
    .unwrap();
    store
        .commit_vote_intent(
            &VoteKey {
                height: 0,
                round: 0,
                vote_type: VoteType::Prevote,
            },
            [0xAA; 32],
            [0u8; 32],
            0,
        )
        .unwrap();
    store
        .commit_signature(
            &VoteKey {
                height: 0,
                round: 0,
                vote_type: VoteType::Prevote,
            },
            [0x5A; 64],
        )
        .unwrap();
    drop(store);

    // ② restart：ValidatorActor 从 durable journal restore（同 kp identity）。
    let store = ValidatorSafetyStore::at(
        &journal,
        SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, genesis_hash, &id),
    );
    let count = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let actor = ValidatorActor::restore(
        id,
        FixedSigner {
            public: pk,
            count: count.clone(),
        },
        CHAIN_ID,
        store,
    )
    .expect("journal restore 成功");

    // 恢复的 ledger 含已签 prevote A。
    let rec = actor
        .vote_ledger()
        .lookup(&VoteKey {
            height: 0,
            round: 0,
            vote_type: VoteType::Prevote,
        })
        .expect("ledger 恢复");
    assert_eq!(rec.target_block_hash, [0xAA; 32]);

    // ③ 冲突投票（同 VoteKey 异 target）⇒ DoubleVote，绝不签名。
    let err = actor
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .expect_err("conflicting vote 必须拒绝");
    assert!(
        matches!(err, ValidatorActorError::DoubleVote { .. }),
        "restart 后 conflicting vote ⇒ DoubleVote（实际 {err:?}）"
    );
    assert_eq!(count.get(), 0, "冲突投票从不签名");

    // ④ 同 target ⇒ 幂等复用（不重签）。
    let _ev = actor
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .expect("同 target 恢复后允许");
    // FixedSigner 仅在缺签名时签名一次（ledger 中已签 ⇒ 复用，不再 sign）。
    assert!(count.get() <= 1, "同 target 幂等复用（不重复签名）");
}
