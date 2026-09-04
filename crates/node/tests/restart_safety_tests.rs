//! Validator Restart Safety 集成测试（STEP 10-15T；RT-1..RT-11 + RT-20..RT-23）。
//!
//! 覆盖（对应 10-15T DESIGN FREEZE 测试矩阵；store 级 corruption 测试在 safety_store.rs 单测：
//! RT-12/13/14/15/16/17/18/19/24）：
//! - RT-1..RT-4：crash window / clean shutdown → restart 恢复（intent / signature / lock）。
//! - RT-5..RT-10：restart 后 DV 语义（同 target 允许 / 异 target 拒绝 / round / height / type 独立）。
//! - RT-11：persistence failure before sign ⇒ fail closed（不签名）。
//! - RT-20..RT-23：multi-validator isolation / remote-vote 不污染 / restored lock 校验 / 签名复用。
//!
//! 用 **固定公钥测试 signer**（`FixedSigner`：公钥 = 真实 Ed25519 压缩点、签名 = 确定性伪签名 +
//! 计数）以便 restart 场景以同一 validator identity 重建 actor（Restart Safety 语义测试不需要真实
//! 密码签名——签名正确性已由 signer/validator 既有测试覆盖；本文件专注 ledger/lock/store/持久化语义）。

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::finality::{QcContext, QuorumCertificate};
use nova_consensus::integration::ConsensusEvent;
use nova_consensus::round::LockedState;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, VerifyingKey};

use nova_node::assembly::ConsensusNode;
use nova_node::driver::NodeConsensusDriver;
use nova_node::safety_store::{SafetyIdentity, ValidatorSafetyError, ValidatorSafetyStore};
use nova_node::signer::{SigningCapability, SigningError, SoftwareSigner};
use nova_node::validator::{LocalVoteRequest, ValidatorActor, ValidatorActorError};
use nova_node::vote_ledger::VoteKey;

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

/// 真实 Ed25519 压缩点字节（测试固定公钥；FakeSigner 公钥恒等重建）。
fn valid_public_key() -> [u8; 32] {
    KeyPair::generate().unwrap().verifying_key().to_bytes()
}

/// 单验证者 set（validator_id = SHA-256(pk)）。
fn set_for(pk: [u8; 32]) -> ValidatorSet {
    ValidatorSet::from_genesis(&genesis_with(vec![ValidatorInit {
        account_address: addr([0x10; 32]),
        consensus_public_key: pk,
        bonded_stake: 100,
        commission_bps: 100,
    }]))
}

fn vid_of(pk: &[u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(pk)
}

/// DAG：AA(0xAA,h0) root、BB(0xBB,h0) root、CC(0xCC,h1,parent AA)。
fn dag_ab() -> Dag {
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

/// 结构 Precommit QC（`acquire_lock` 只依赖 type/target/dag；evidence 由 verify_qc 层负责）。
fn precommit_qc(target: [u8; 32], round: u64) -> QuorumCertificate {
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round,
            vote_type: VoteType::Precommit,
        },
        target,
        validator_set_id: GENESIS_HASH,
        evidence: Vec::new(),
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

fn key_of(h: u64, r: u64, vt: VoteType) -> VoteKey {
    VoteKey {
        height: h,
        round: r,
        vote_type: vt,
    }
}

fn ev_sig(ev: &ConsensusEvent) -> [u8; 64] {
    match ev {
        ConsensusEvent::Vote { signature, .. } => *signature,
        other => panic!("必须为 ConsensusEvent::Vote，got {other:?}"),
    }
}

/// 唯一临时目录（进程内计数，保证并行测试隔离；Drop 清理）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nova_rt_{}_{}_{}", std::process::id(), n, tag));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn journal(&self) -> PathBuf {
        self.path.join("safety.journal")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 固定公钥确定性测试 signer：重启时可重建同一 identity；sign 计数供「不重签」断言。
struct FixedSigner {
    public: [u8; 32],
    count: Rc<Cell<usize>>,
}

impl SigningCapability for FixedSigner {
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public).expect("固定公钥为合法 Ed25519 压缩点")
    }

    fn sign(&self, _message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        self.count.set(self.count.get() + 1);
        Ok(Signature::from_bytes(&[0x5A; 64]).unwrap())
    }
}

fn identity_for(pk: &[u8; 32]) -> SafetyIdentity {
    SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, GENESIS_HASH, &vid_of(pk))
}

/// 首启 durable actor（写 header + 空恢复）。
fn fresh_actor(pk: [u8; 32], journal: &Path) -> (ValidatorActor<FixedSigner>, Rc<Cell<usize>>) {
    let store = ValidatorSafetyStore::create(journal, identity_for(&pk)).unwrap();
    let count = Rc::new(Cell::new(0usize));
    let signer = FixedSigner {
        public: pk,
        count: count.clone(),
    };
    let actor =
        ValidatorActor::restore(vid_of(&pk), signer, CHAIN_ID, store).expect("首启恢复成功");
    (actor, count)
}

/// restart durable actor（重放既有 journal）。
fn restart_actor(pk: [u8; 32], journal: &Path) -> (ValidatorActor<FixedSigner>, Rc<Cell<usize>>) {
    let store = ValidatorSafetyStore::at(journal, identity_for(&pk));
    let count = Rc::new(Cell::new(0usize));
    let signer = FixedSigner {
        public: pk,
        count: count.clone(),
    };
    let actor =
        ValidatorActor::restore(vid_of(&pk), signer, CHAIN_ID, store).expect("restart 恢复成功");
    (actor, count)
}

// ---------- RT-1 : clean shutdown / restore ----------

#[test]
fn rt_1_clean_shutdown_restore_preserves_ledger_and_lock() {
    let tmp = TempDir::new("rt1");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (mut actor1, _c1) = fresh_actor(pk, &journal);
    let ev1 = actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次投票");
    actor1
        .on_verified_precommit_qc(&precommit_qc([0xAA; 32], 0), &dag)
        .unwrap();
    assert_eq!(actor1.locked_state().locked_block_hash, Some([0xAA; 32]));
    drop(actor1); // clean shutdown

    // restart ⇒ VoteLedger + LockedState 必须恢复
    let (actor2, _c2) = restart_actor(pk, &journal);
    let rec = actor2
        .vote_ledger()
        .lookup(&key_of(0, 0, VoteType::Prevote))
        .expect("ledger 恢复");
    assert_eq!(rec.target_block_hash, [0xAA; 32]);
    assert!(rec.signature.is_some(), "signature 恢复");
    assert_eq!(actor2.locked_state().locked_block_hash, Some([0xAA; 32]));
    assert_eq!(actor2.locked_state().locked_round, Some(0));

    // 恢复后同 target 幂等复用（签名一致）
    let ev2 = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("恢复后同 target 允许");
    assert_eq!(ev_sig(&ev1), ev_sig(&ev2), "clean shutdown 后复用同一签名");
}

// ---------- RT-2 : crash after intent persistence (R2) ----------

#[test]
fn rt_2_crash_after_intent_different_target_rejected_same_allowed() {
    let tmp = TempDir::new("rt2");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    // R2 crash window：仅 durable intent（signature 前 crash）；不经过 actor（直接 store 写入）。
    let store = ValidatorSafetyStore::create(&journal, identity_for(&pk)).unwrap();
    store
        .commit_vote_intent(&key_of(0, 0, VoteType::Prevote), [0xAA; 32], [0u8; 32], 0)
        .unwrap();
    drop(store);

    // restart：同 VoteKey 不同 target ⇒ REJECT（绝不签名）
    let (actor, count) = restart_actor(pk, &journal);
    let err = actor
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap_err();
    assert!(
        matches!(err, ValidatorActorError::DoubleVote { .. }),
        "R2 restart：异 target 必须拒绝"
    );
    assert_eq!(count.get(), 0, "异 target 从不签名");

    // restart：同 target ⇒ 允许完成（补签 + durable signature）
    let (actor, count) = restart_actor(pk, &journal);
    let ev = actor
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("R2 restart：同 target 允许完成");
    assert_eq!(ev_sig(&ev), [0x5A; 64]);
    assert_eq!(count.get(), 1, "仅完成一次签名");
    // signature 已 durable
    let rec = ValidatorSafetyStore::at(&journal, identity_for(&pk))
        .recover()
        .unwrap()
        .ledger
        .lookup(&key_of(0, 0, VoteType::Prevote))
        .unwrap();
    assert_eq!(rec.signature, Some([0x5A; 64]));
}

// ---------- RT-3 : crash after sign, before signature persist (R3) ----------

#[test]
fn rt_3_crash_after_sign_resume_single_signature_no_duplicate() {
    let tmp = TempDir::new("rt3");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    // R3 durable 痕迹 = intent durable、signature 缺席（签名生成于内存但未持久化/未广播）。
    let store = ValidatorSafetyStore::create(&journal, identity_for(&pk)).unwrap();
    store
        .commit_vote_intent(&key_of(0, 0, VoteType::Prevote), [0xAA; 32], [0u8; 32], 0)
        .unwrap();
    drop(store);

    // restart：同 target 完成 signing（允许；signature 可能缺席）
    let (actor, count) = restart_actor(pk, &journal);
    let ev = actor
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("R3 resume 完成签名");
    assert_eq!(count.get(), 1);
    drop(actor);

    // 再 restart：signature 已持久化 ⇒ 复用，不产生第二份签名 / 无重复记录
    let (actor2, count2) = restart_actor(pk, &journal);
    let ev2 = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("复用");
    assert_eq!(count2.get(), 0, "签名已 durable ⇒ restart 不重签");
    assert_eq!(ev_sig(&ev), ev_sig(&ev2), "同一确定性签名，无第二份");
}

// ---------- RT-4 / RT-23 : crash after signature persistence (R4) + reuse ----------

#[test]
fn rt_4_and_23_crash_after_signature_reuse_same_signature_no_resign() {
    let tmp = TempDir::new("rt4");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    // 完整投票（intent + signature 均 durable）
    let (actor1, count1) = fresh_actor(pk, &journal);
    let ev1 = actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次投票");
    assert_eq!(count1.get(), 1);
    drop(actor1); // crash after signature persistence

    // restart：R4 = reuse signature；RT-23 = 同一签名、不重签
    let (actor2, count2) = restart_actor(pk, &journal);
    let rec = actor2
        .vote_ledger()
        .lookup(&key_of(0, 0, VoteType::Prevote))
        .unwrap();
    assert_eq!(rec.signature, Some(ev_sig(&ev1)), "恢复签名 == 原签名");
    let ev2 = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("restart 同 target 允许");
    assert_eq!(count2.get(), 0, "RT-4/RT-23：签名已 durable ⇒ 不重签");
    assert_eq!(ev_sig(&ev1), ev_sig(&ev2), "RT-23：复用同一签名");
}

// ---------- RT-5 : same target after restart ----------

#[test]
fn rt_5_same_target_after_restart_allowed() {
    let tmp = TempDir::new("rt5");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次");
    drop(actor1);

    let (actor2, _c2) = restart_actor(pk, &journal);
    let ev = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap();
    assert!(ev.is_some(), "RT-5：restart 后同 target 必须允许");
}

// ---------- RT-6 : different target after restart ----------

#[test]
fn rt_6_different_target_after_restart_rejected() {
    let tmp = TempDir::new("rt6");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次 AA");
    drop(actor1);

    let (actor2, count) = restart_actor(pk, &journal);
    let err = actor2
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap_err();
    assert!(
        matches!(err, ValidatorActorError::DoubleVote { .. }),
        "RT-6：restart 后异 target 必须拒绝"
    );
    assert_eq!(count.get(), 0, "异 target 不签名");
}

// ---------- RT-7 : different round after restart ----------

#[test]
fn rt_7_different_round_independent_after_restart() {
    let tmp = TempDir::new("rt7");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("round0 AA");
    drop(actor1);

    let (actor2, _c2) = restart_actor(pk, &journal);
    // round1 独立 VoteKey ⇒ 允许（BB）
    let ev = actor2
        .produce_vote(&req(0, 1, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap();
    assert!(ev.is_some(), "RT-7：不同 round 独立，restart 后允许");
    // round0 同 key 异 target ⇒ 仍拒绝
    let err = actor2
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap_err();
    assert!(matches!(err, ValidatorActorError::DoubleVote { .. }));
}

// ---------- RT-8 : different height after restart ----------

#[test]
fn rt_8_different_height_independent_after_restart() {
    let tmp = TempDir::new("rt8");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("height0 AA");
    drop(actor1);

    let (actor2, _c2) = restart_actor(pk, &journal);
    let ev = actor2
        .produce_vote(&req(1, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap();
    assert!(ev.is_some(), "RT-8：不同 height 独立，restart 后允许");
    let err = actor2
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap_err();
    assert!(matches!(err, ValidatorActorError::DoubleVote { .. }));
}

// ---------- RT-9 : Prevote vs Precommit after restart ----------

#[test]
fn rt_9_prevote_precommit_independent_after_restart() {
    let tmp = TempDir::new("rt9");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("prevote AA");
    drop(actor1);

    let (actor2, _c2) = restart_actor(pk, &journal);
    // 同 (h,r) 的 Precommit 是独立 VoteKey ⇒ 允许（type 独立）
    let ev = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Precommit), &set, &dag)
        .unwrap();
    assert!(
        ev.is_some(),
        "RT-9：Precommit 与 Prevote 独立，restart 后允许"
    );
    // 同 (h,r,Prevote) 异 target ⇒ 拒绝
    let err = actor2
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set, &dag)
        .unwrap_err();
    assert!(matches!(err, ValidatorActorError::DoubleVote { .. }));
}

// ---------- RT-10 : Precommit persistence / reuse after restart ----------

#[test]
fn rt_10_precommit_restart_reuse_and_cross_type() {
    let tmp = TempDir::new("rt10");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Precommit), &set, &dag)
        .unwrap()
        .expect("precommit AA");
    drop(actor1);

    let (actor2, count) = restart_actor(pk, &journal);
    let ev = actor2
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Precommit), &set, &dag)
        .unwrap()
        .expect("RT-10：Precommit 同 target 复用");
    assert_eq!(count.get(), 0, "Precommit 签名已 durable ⇒ 不重签");
    assert_eq!(ev_sig(&ev), [0x5A; 64]);
    // 同 key 异 target ⇒ 拒绝
    let err = actor2
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Precommit), &set, &dag)
        .unwrap_err();
    assert!(matches!(err, ValidatorActorError::DoubleVote { .. }));
}

// ---------- RT-11 : persistence failure before sign ----------

#[test]
// 测试需要「恢复可写」来证明 fail-closed 后可重试 —— 合法的 set_readonly(false) 用途。
#[allow(clippy::permissions_set_readonly_false)]
fn rt_11_persistence_failure_before_sign_fails_closed() {
    let tmp = TempDir::new("rt11");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    // 第一次成功投票（journal 可写；key1 = (0,0,Prevote)->AA）
    let (actor1, count1) = fresh_actor(pk, &journal);
    actor1
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("首次成功");
    assert_eq!(count1.get(), 1);
    drop(actor1);

    // 令 journal 只读 ⇒ 后续 append（含 durable intent）失败
    let mut perms = std::fs::metadata(&journal).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&journal, perms).unwrap();

    // RT-11：persistence failure（intent 无法 durable）⇒ fail closed：DO NOT SIGN。
    let (actor2, count2) = restart_actor(pk, &journal);
    let result = actor2.produce_vote(&req(1, 0, [0xAA; 32], VoteType::Prevote), &set, &dag);
    let err = match result {
        Ok(_) => panic!("RT-11：持久化失败必须 Err（fail closed）"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ValidatorActorError::Safety(ValidatorSafetyError::Io)),
        "预期 Safety(Io)，got {err:?}"
    );
    assert_eq!(count2.get(), 0, "RT-11：intent 未 durable ⇒ 绝不签名");
    drop(actor2);

    // 恢复可写后：同 target 可重试完成（intent durable → sign → durable signature）
    let mut perms = std::fs::metadata(&journal).unwrap().permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(&journal, perms).unwrap();

    let (actor3, count3) = restart_actor(pk, &journal);
    let ev = actor3
        .produce_vote(&req(1, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
        .unwrap()
        .expect("恢复可写后同 target 重试成功");
    assert_eq!(count3.get(), 1);
    assert_eq!(ev_sig(&ev), [0x5A; 64]);
}

// ---------- RT-20 : multi-validator isolation ----------

#[test]
fn rt_20_multi_validator_isolation_across_restart() {
    let tmp_a = TempDir::new("rt20a");
    let tmp_b = TempDir::new("rt20b");
    let pk_a = valid_public_key();
    let pk_b = valid_public_key();
    assert_ne!(pk_a, pk_b);
    let set_a = set_for(pk_a);
    let set_b = set_for(pk_b);
    let dag = dag_ab();

    // A 投 (0,0,P)->AA；B 投 (0,0,P)->BB（各自独立 journal）
    let (actor_a, _) = fresh_actor(pk_a, &tmp_a.journal());
    let (actor_b, _) = fresh_actor(pk_b, &tmp_b.journal());
    actor_a
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set_a, &dag)
        .unwrap()
        .expect("A->AA");
    actor_b
        .produce_vote(&req(0, 0, [0xBB; 32], VoteType::Prevote), &set_b, &dag)
        .unwrap()
        .expect("B->BB");
    assert_eq!(
        actor_a
            .vote_ledger()
            .lookup(&key_of(0, 0, VoteType::Prevote))
            .unwrap()
            .target_block_hash,
        [0xAA; 32]
    );
    assert_eq!(
        actor_b
            .vote_ledger()
            .lookup(&key_of(0, 0, VoteType::Prevote))
            .unwrap()
            .target_block_hash,
        [0xBB; 32]
    );
    drop(actor_a);
    drop(actor_b);

    // restart：A 只恢复 A 历史（不含 B 记录）；B 只恢复 B 历史
    let (actor_a2, _) = restart_actor(pk_a, &tmp_a.journal());
    let (actor_b2, _) = restart_actor(pk_b, &tmp_b.journal());
    assert_eq!(
        actor_a2
            .vote_ledger()
            .lookup(&key_of(0, 0, VoteType::Prevote))
            .unwrap()
            .target_block_hash,
        [0xAA; 32],
        "A 只含自身历史"
    );
    assert_eq!(
        actor_b2
            .vote_ledger()
            .lookup(&key_of(0, 0, VoteType::Prevote))
            .unwrap()
            .target_block_hash,
        [0xBB; 32],
        "B 只含自身历史"
    );
    assert_eq!(actor_a2.vote_ledger().len(), 1);
    assert_eq!(actor_b2.vote_ledger().len(), 1);
}

// ---------- RT-21 : remote vote does not pollute local ledger ----------

#[test]
fn rt_21_remote_vote_does_not_pollute_local_durable_ledger() {
    use nova_consensus::vote::{canonical_vote_payload, verify_vote_input};
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::signature::sign_message_hash;

    let (mut kps, set) = make_ctx_real(3);
    let a = kps.remove(0);
    let b = kps.remove(0);
    let c = kps.remove(0);
    let a_pk = a.verifying_key().to_bytes();
    let a_vid = vid_of(&a_pk);
    let tmp = TempDir::new("rt21");
    let journal = tmp.journal();
    // 本地 durable actor A（真实 SoftwareSigner；store 绑定 A）
    let store = ValidatorSafetyStore::create(&journal, identity_for(&a_pk)).unwrap();
    let actor_a = ValidatorActor::restore(a_vid, SoftwareSigner::new(a), CHAIN_ID, store).unwrap();
    let target_x = [0x11; 32];
    let target_y = [0x22; 32];
    let consensus = ConsensusNode::new(0, 0, CHAIN_ID, set, GENESIS_HASH, dag_ab());
    let mut driver = NodeConsensusDriver::new(consensus, vec![actor_a]);

    // 两个 remote（b、c）对同一 (0,0,Prevote) 不同 target 各投一票（不同 validator —— 非本地双投）。
    let build_remote = |kp: &KeyPair, target: [u8; 32], vt: VoteType, set: &ValidatorSet| {
        let vote = nova_consensus::vote::ValidatorVote {
            round: 0,
            height: 0,
            target_block_hash: target,
            vote_type: vt,
            source_block_hash: [0u8; 32],
            validator_id: vid_of(&kp.verifying_key().to_bytes()),
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
        let sig = sign_message_hash(kp.signing_key(), &hash_signing_message(&signed)).to_bytes();
        verify_vote_input(&vote, &sig, CHAIN_ID, set).unwrap();
        (vote, sig)
    };
    {
        let (vx, sx) = build_remote(
            &b,
            target_x,
            VoteType::Prevote,
            driver.consensus().validator_set(),
        );
        driver.submit_remote_vote(vx, sx).unwrap();
        let (vy, sy) = build_remote(
            &c,
            target_y,
            VoteType::Prevote,
            driver.consensus().validator_set(),
        );
        driver.submit_remote_vote(vy, sy).unwrap();
    }

    // remote vote 不得污染本地 VoteLedger / durable store
    assert!(
        driver.actor(0).unwrap().vote_ledger().is_empty(),
        "RT-21：remote vote 不得写入本地 VoteLedger"
    );
    let recovered = ValidatorSafetyStore::at(&journal, identity_for(&a_pk))
        .recover()
        .expect("本地 store 可恢复");
    assert!(
        recovered.ledger.is_empty(),
        "RT-21：remote vote 不得污染本地 durable store"
    );
}

fn make_ctx_real(n: usize) -> (Vec<KeyPair>, ValidatorSet) {
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

// ---------- RT-22 : restored LockedState validation ----------

#[test]
fn rt_22_restored_lock_validation_against_dag() {
    let tmp = TempDir::new("rt22");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (mut actor1, _c) = fresh_actor(pk, &journal);
    actor1
        .on_verified_precommit_qc(&precommit_qc([0xAA; 32], 0), &dag)
        .unwrap();
    assert_eq!(actor1.locked_state().locked_block_hash, Some([0xAA; 32]));
    drop(actor1);

    // restart：lock 恢复 + 对 DAG 校验
    let (actor2, _c2) = restart_actor(pk, &journal);
    let lock = *actor2.locked_state();
    assert_eq!(lock.locked_block_hash, Some([0xAA; 32]));
    assert_eq!(lock.locked_round, Some(0));

    // same block（round0 AA）⇒ 允许
    assert!(
        actor2
            .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set, &dag)
            .unwrap()
            .is_some(),
        "same block ⇒ 允许"
    );
    // descendant（round1 CC, parent AA）⇒ 允许（full transitive）
    assert!(
        actor2
            .produce_vote(&req(0, 1, [0xCC; 32], VoteType::Prevote), &set, &dag)
            .unwrap()
            .is_some(),
        "descendant ⇒ 允许"
    );
    // unrelated（round2 BB）⇒ 拒绝（lock conflict；restored lock 生效）
    assert!(
        actor2
            .produce_vote(&req(0, 2, [0xBB; 32], VoteType::Prevote), &set, &dag)
            .unwrap()
            .is_none(),
        "unrelated ⇒ restored lock 拒绝"
    );
}

#[test]
fn rt_22b_lock_persisted_durable_before_adopt() {
    let tmp = TempDir::new("rt22b");
    let journal = tmp.journal();
    let pk = valid_public_key();
    let set = set_for(pk);
    let dag = dag_ab();

    let (actor1, _c) = fresh_actor(pk, &journal);
    // 锁前 journal 无 lock 记录；锁后 journal 含 lock
    let before = ValidatorSafetyStore::at(&journal, identity_for(&pk))
        .recover()
        .unwrap();
    assert_eq!(before.locked_state, LockedState::new());
    let mut actor1 = actor1;
    actor1
        .on_verified_precommit_qc(&precommit_qc([0xAA; 32], 0), &dag)
        .unwrap();
    assert_eq!(actor1.locked_state().locked_block_hash, Some([0xAA; 32]));
    drop(actor1);

    let after = ValidatorSafetyStore::at(&journal, identity_for(&pk))
        .recover()
        .unwrap();
    assert_eq!(
        after.locked_state.locked_block_hash,
        Some([0xAA; 32]),
        "lock 在采用前已 durable"
    );
    let _ = set;
}

// ---------- RT-25（10-15T-HARDEN / OBS-3B）: missing safety journal fails closed ----------

#[test]
fn rt_25_missing_safety_journal_fails_closed() {
    // ---- Part 1（store 层）：journal 被外部删除后再次 commit ⇒ Err(Io)，且不得重建文件 ----
    let tmp1 = TempDir::new("rt25_store");
    let journal1 = tmp1.journal();
    let pk1 = valid_public_key();
    let store1 = ValidatorSafetyStore::create(&journal1, identity_for(&pk1)).unwrap();
    store1
        .commit_vote_intent(&key_of(0, 0, VoteType::Prevote), [0xAA; 32], [0u8; 32], 0)
        .unwrap();
    assert!(journal1.exists(), "写入合法 record 后 journal 必须存在");
    std::fs::remove_file(&journal1).unwrap(); // 外部删除
    let err = store1
        .commit_vote_intent(&key_of(1, 0, VoteType::Prevote), [0xAA; 32], [0u8; 32], 0)
        .unwrap_err();
    assert_eq!(
        err,
        ValidatorSafetyError::Io,
        "缺失 journal 必须立即 Err(Io) fail closed"
    );
    assert!(
        !journal1.exists(),
        "append_record 绝不自动 create 缺失 journal（不得产生无 header 文件）"
    );

    // ---- Part 2（actor 层）：存活 durable actor 期间删除 journal ⇒ 本地投票不签名、无事件 ----
    let tmp2 = TempDir::new("rt25_actor");
    let journal2 = tmp2.journal();
    let pk2 = valid_public_key();
    let set2 = set_for(pk2);
    let dag2 = dag_ab();
    let (actor, count) = fresh_actor(pk2, &journal2);
    // 首次投票成功（file 存在；header + intent + signature 均 durable）
    actor
        .produce_vote(&req(0, 0, [0xAA; 32], VoteType::Prevote), &set2, &dag2)
        .unwrap()
        .expect("首次投票（journal 存在）");
    assert_eq!(count.get(), 1);
    assert!(journal2.exists());
    // 外部删除 journal（actor 仍存活、仍持 store）
    std::fs::remove_file(&journal2).unwrap();
    // 下一次本地投票：durable intent 失败 ⇒ Err(Safety(Io))，不签名、无 VoteEvent
    let result = actor.produce_vote(&req(1, 0, [0xAA; 32], VoteType::Prevote), &set2, &dag2);
    let err = match result {
        Ok(_) => panic!("RT-25：缺失 journal 时投票必须 Err（fail closed）"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ValidatorActorError::Safety(ValidatorSafetyError::Io)),
        "预期 Safety(Io)，got {err:?}"
    );
    assert_eq!(count.get(), 1, "缺失 journal ⇒ 绝不产生新签名");
    assert!(!journal2.exists(), "actor 路径亦不得重建 journal");
}
