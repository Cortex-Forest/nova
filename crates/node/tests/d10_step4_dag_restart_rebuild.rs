//! D10-C Step 2 — DAG Restart Rebuild（restart 后 Consensus DAG 重建 canonical ancestry）。
//!
//! 证明：restart（D10-B 已 durable-commit canonical 链）后，validator 启动在 `start_inner` 沿
//! canonical head → BlockStore parent 链重建 Consensus DAG（genesis 根 + 每个 committed 块：
//! 真实 `header.height` + parent 边 + `select_proposer` 推导的 proposer），使 safety lock /
//! ancestry 判定在重启后可安全继续 —— **不持久化 consensus**（Round/QC/Finality/DAG 仍不落盘），
//! 只补偿「DAG 不随 storage 恢复」的 gap；head == genesis（首启 / 无 commit）⇒ 空 DAG（与既有
//! fresh-start 语义完全一致）。
//!
//! 禁止：手动 submit_local_vote / state_mut / 手设 finality / head / QC / round；禁止绕过真实
//! 路径手造 Dag 注入 ConsensusNode。canonical 链经真实 `NodeBlockAdapter::apply_block`（D10-B
//! production commit 原语）或真实 runtime auto finality→commit（单验证者）构造；重启经真实
//! `bootstrap::start` / `NodeRuntime::start`（bootstrap 恢复 + rebuild 接缝）。

use std::path::{Path, PathBuf};

use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_network::node_id::NodeId;
use nova_network::transport::MemoryTransport;
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, block_hash, compute_transaction_root,
    encode_block, encode_block_header,
};
use nova_storage::block_store::BlockStore;
use nova_storage::error::StorageError;
use nova_storage::persistent::PersistentBackend;

use nova_node::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::bootstrap::{NodeConfig, NodeStartupError};
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

type FileAdapter = NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>;

// ---------------------------------------------------------------------------
// Fixtures（与 d10_step3 / block_commit_tests 同套路）
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
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d10c2_{}_{}", std::process::id(), n));
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
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// enabled（网络主循环）validator runtime（单验证者 commit 需要 —— finality bridge 在 enabled 分支）。
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

/// step 直至 head 推进到 `want_height` 或步数上限。
fn step_until_head_height(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..10 {
        runtime.step().expect("step ok");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
    }
    panic!("head 未推进到 {want_height}");
}

/// 空 block 的 proposer 块签名（DomainId::Block + chain_id + canonical header）。
fn block_signature(header: &BlockHeader, sk: &SigningKey) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

/// canonical 链上下一个空 block（parent = head；state_root = 当前 store root —— 空执行不变）。
fn next_empty_block(adapter: &FileAdapter, kp: &KeyPair) -> (Block, Vec<u8>) {
    let head = adapter.head();
    let height = head.height + 1;
    let state_root = *adapter.store().state_root().as_bytes();
    empty_block_at(
        &adapter.genesis_hash(),
        head.block_hash,
        height,
        state_root,
        0,
        kp,
    )
}

/// 任意（未必 canonical）空 block：显式 parent/height/state_root/timestamp。
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

/// block 记录文件路径（deterministic：`blocks/block_{hash_hex}.blk`）。
fn block_file_path(chain_dir: &Path, hash: &[u8; 32]) -> PathBuf {
    let mut hex = String::with_capacity(64);
    for b in hash {
        hex.push_str(&format!("{b:02x}"));
    }
    chain_dir.join("blocks").join(format!("block_{hex}.blk"))
}

// ---------------------------------------------------------------------------
// T1 — 单链（Genesis→A）restart 后 DAG 重建
//      真实 runtime（单验证者）commit A → restart → Consensus DAG 含 genesis 根 + A
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t1_single_chain_rebuilds_on_restart() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;

    // ① 单验证者 runtime：produce A → auto prevote/precommit finality → bridge commit A → head=1。
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.last_proposal().expect("A").block_hash;
    assert_eq!(r1.block_production().unwrap().head().block_hash, a_hash);
    r1.shutdown().expect("shutdown ok"); // shutdown 消费 self

    // ② restart：新本地 key + 新 safety dir、同 chain storage —— start_inner 走 rebuild seam。
    let mut cfg2 = config.clone();
    cfg2.safety_dir = cfg2.safety_dir.join("restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r2 = NodeRuntime::start(&cfg2, Some(&provider2)).expect("restart ok");

    // head 恢复 + DAG 重建 = genesis 根 + committed A（ancestry 可判定）。
    assert_eq!(r2.block_production().unwrap().head().height, 1);
    assert_eq!(r2.block_production().unwrap().head().block_hash, a_hash);
    let dag = r2.consensus().dag();
    assert_eq!(dag.len(), 2, "genesis 根 + A");
    assert!(dag.contains(&genesis_hash), "genesis 根在重建 DAG");
    assert!(dag.contains(&a_hash), "committed A 在重建 DAG");
    assert!(
        dag.is_ancestor(&a_hash, &a_hash),
        "self-inclusive（lock 兼容核心）"
    );
    assert!(
        dag.is_ancestor(&genesis_hash, &a_hash),
        "genesis 是 A 的祖先（parent 边重建）"
    );
    assert_eq!(
        dag.parents_of(&a_hash),
        Some(&[genesis_hash][..]),
        "A.parent == genesis"
    );
    drop(r2);
}

// ---------------------------------------------------------------------------
// T2 — 多块 canonical ancestry（Genesis→A→B→C）restart 后完整重建
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t2_multi_block_ancestry_rebuilds() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;

    // ① 真实 bootstrap adapter（NoAccountsKeyResolver）连续 durable-commit A→B→C。
    let a_hash;
    let b_hash;
    let c_hash;
    {
        let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        let (_, wire_a) = next_empty_block(&adapter, &kp);
        a_hash = adapter
            .apply_block(&wire_a, kp.verifying_key())
            .unwrap()
            .block_hash;
        let (_, wire_b) = next_empty_block(&adapter, &kp);
        b_hash = adapter
            .apply_block(&wire_b, kp.verifying_key())
            .unwrap()
            .block_hash;
        let (_, wire_c) = next_empty_block(&adapter, &kp);
        c_hash = adapter
            .apply_block(&wire_c, kp.verifying_key())
            .unwrap()
            .block_hash;
        assert_eq!(adapter.head().height, 3);
    }

    // ② restart：真实 bootstrap 恢复 + rebuild。
    let mut cfg2 = config.clone();
    cfg2.safety_dir = cfg2.safety_dir.join("restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r2 = NodeRuntime::start(&cfg2, Some(&provider2)).expect("restart ok");

    assert_eq!(r2.block_production().unwrap().head().height, 3);
    assert_eq!(r2.block_production().unwrap().head().block_hash, c_hash);
    let dag = r2.consensus().dag();
    assert_eq!(dag.len(), 4, "genesis 根 + A + B + C");
    for h in [genesis_hash, a_hash, b_hash, c_hash] {
        assert!(dag.contains(&h), "DAG 含 canonical 块 {:?}", h);
    }
    // parent 边连续 + 全传递 ancestry + 高度单调（真实 header.height）。
    assert_eq!(dag.parents_of(&a_hash), Some(&[genesis_hash][..]));
    assert_eq!(dag.parents_of(&b_hash), Some(&[a_hash][..]));
    assert_eq!(dag.parents_of(&c_hash), Some(&[b_hash][..]));
    assert!(dag.is_ancestor(&a_hash, &c_hash), "A → … → C ancestry");
    assert!(dag.is_ancestor(&genesis_hash, &c_hash));
    assert!(!dag.is_ancestor(&c_hash, &a_hash), "反向非祖先");
    drop(r2);
}

// ---------------------------------------------------------------------------
// T3 — Fork isolation：BlockStore 存有非 canonical fork 块 ⇒ rebuild 不混入
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t3_fork_isolation_no_mixing() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;

    let a_hash;
    let b_hash;
    {
        // canonical A→B（head = B）。
        let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        let (_, wire_a) = next_empty_block(&adapter, &kp);
        a_hash = adapter
            .apply_block(&wire_a, kp.verifying_key())
            .unwrap()
            .block_hash;
        let (_, wire_b) = next_empty_block(&adapter, &kp);
        b_hash = adapter
            .apply_block(&wire_b, kp.verifying_key())
            .unwrap()
            .block_hash;

        // fork X：height1、parent=genesis、不同 timestamp ⇒ 与 A 分叉；仅直接写入 BlockStore
        //（不经 apply —— 非 canonical，head 仍是 B）。
        let (x_block, _) = empty_block_at(
            &genesis_hash,
            genesis_hash,
            1,
            *adapter.store().state_root().as_bytes(),
            1,
            &kp,
        );
        let x_hash = block_hash(&x_block).unwrap();
        assert_ne!(x_hash, a_hash, "fork 必须与 A 是不同块");
        let x_store = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
        x_store.put(&x_block).expect("fork block 可存储");
    }

    // restart → rebuild 只沿 canonical head(B)→A→genesis；fork X 不混入。
    let mut cfg2 = config.clone();
    cfg2.safety_dir = cfg2.safety_dir.join("restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let r2 = NodeRuntime::start(&cfg2, Some(&provider2)).expect("restart ok");
    assert_eq!(r2.block_production().unwrap().head().block_hash, b_hash);
    let dag = r2.consensus().dag();
    assert!(dag.contains(&a_hash));
    assert!(dag.contains(&b_hash));
    assert_eq!(dag.len(), 3, "只含 genesis + A + B（不混 fork）");
    // fork X 的 hash 需重新计算以断言不在 DAG —— 重放相同 block 再取 hash。
    let state_root = *r2
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    let (x2, _) = empty_block_at(&genesis_hash, genesis_hash, 1, state_root, 1, &kp);
    let x_hash = block_hash(&x2).unwrap();
    assert!(!dag.contains(&x_hash), "非 canonical fork 不进入重建 DAG");
    drop(r2);
}

// ---------------------------------------------------------------------------
// T4 — Missing ancestor ⇒ rebuild fail-closed（不 skip / 不 partial）
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t4_missing_ancestor_fail_closed() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();

    let a_hash;
    let b_hash;
    {
        let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        let (_, wire_a) = next_empty_block(&adapter, &kp);
        a_hash = adapter
            .apply_block(&wire_a, kp.verifying_key())
            .unwrap()
            .block_hash;
        let (_, wire_b) = next_empty_block(&adapter, &kp);
        b_hash = adapter
            .apply_block(&wire_b, kp.verifying_key())
            .unwrap()
            .block_hash;
    }

    // 删除中间祖先 A 的 block 文件（head B 仍在 —— bootstrap 恢复 head 本身通过）。
    std::fs::remove_file(block_file_path(&env.chain_dir, &a_hash)).unwrap();

    let adapter2 = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    assert_eq!(adapter2.head().height, 2, "head 块存在，恢复通过");
    let set = ValidatorSet::from_genesis(&genesis);
    let err = nova_node::bootstrap::rebuild_consensus_dag(&adapter2, &set).unwrap_err();
    assert!(
        matches!(err, NodeStartupError::DagRebuildMissingAncestor(h) if h == a_hash),
        "缺 A ⇒ fail closed（实际: {err:?}）"
    );
    // B 是 head —— 断言用它避免未用
    assert_eq!(adapter2.head().block_hash, b_hash);
}

// ---------------------------------------------------------------------------
// T5 — Corrupted ancestor ⇒ rebuild fail-closed（strict decode 拒）
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t5_corrupt_ancestor_fail_closed() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();

    let a_hash;
    {
        let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        let (_, wire_a) = next_empty_block(&adapter, &kp);
        a_hash = adapter
            .apply_block(&wire_a, kp.verifying_key())
            .unwrap()
            .block_hash;
        let (_, wire_b) = next_empty_block(&adapter, &kp);
        adapter.apply_block(&wire_b, kp.verifying_key()).unwrap();
    }

    // 覆写中间祖先 A 的 block 记录（损坏）。
    std::fs::write(block_file_path(&env.chain_dir, &a_hash), b"corrupted!").unwrap();

    let adapter2 = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    let set = ValidatorSet::from_genesis(&genesis);
    let err = nova_node::bootstrap::rebuild_consensus_dag(&adapter2, &set).unwrap_err();
    assert!(
        matches!(err, NodeStartupError::Storage(StorageError::CorruptedState)),
        "损坏祖先 ⇒ Storage(CorruptedState)（实际: {err:?}）"
    );
}

// ---------------------------------------------------------------------------
// T6 — Rebuild 幂等：每次新建 Dag，同输入 ⇒ 同结果
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t6_rebuild_idempotent() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;
    let set = ValidatorSet::from_genesis(&genesis);

    let mut adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
    let (_, wire_a) = next_empty_block(&adapter, &kp);
    let a_hash = adapter
        .apply_block(&wire_a, kp.verifying_key())
        .unwrap()
        .block_hash;

    let d1 = nova_node::bootstrap::rebuild_consensus_dag(&adapter, &set).unwrap();
    let d2 = nova_node::bootstrap::rebuild_consensus_dag(&adapter, &set).unwrap();
    assert_eq!(d1.len(), 2);
    assert_eq!(d2.len(), d1.len(), "幂等：两次重建成员数一致");
    for h in [genesis_hash, a_hash] {
        assert!(d1.contains(&h) && d2.contains(&h));
        assert_eq!(d1.parents_of(&h), d2.parents_of(&h), "同 parent 结构");
    }
    drop(adapter);

    // fresh（head==genesis，另一独立 genesis）时 rebuild 返回空 DAG —— 兼容既有 fresh-start 语义。
    let g2 = genesis_with(vec![(pk, STAKE)]);
    let e2 = Env::new(&g2);
    let config2 = e2.config();
    let adapter_fresh = nova_node::bootstrap::start(NoAccountsKeyResolver, &config2).unwrap();
    assert_eq!(adapter_fresh.head().height, 0);
    let df = nova_node::bootstrap::rebuild_consensus_dag(&adapter_fresh, &set).unwrap();
    assert!(
        df.is_empty(),
        "无 committed 块 ⇒ 空 DAG（兼容 fresh-start）"
    );
    drop(adapter_fresh);
}

// ---------------------------------------------------------------------------
// T7 — Safety Lock compatibility：restart 后 locked canonical ancestry 可识别
//      单验证者 runtime commit A 并锁定 A → restart（新 key / 新 safety dir）→ 重建 DAG
//      含 locked 块 A；self-inclusive + ancestor ancestry 判定成立（空 DAG 时 is_ancestor(A,A)
//      为 false ⇒ LockConflict —— 本 seam 消除该 gap）。
// ---------------------------------------------------------------------------

#[test]
fn d10_c2_t7_safety_lock_compat_after_restart() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let genesis_hash = env.genesis_hash;

    // ① 单验证者：commit A（bridge）+ validator lock A（precommit QC 达成）。
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.last_proposal().expect("A").block_hash;
    assert_eq!(r1.block_production().unwrap().head().block_hash, a_hash);
    assert_eq!(
        r1.validator()
            .expect("validator")
            .actor()
            .locked_state()
            .locked_block_hash,
        Some(a_hash),
        "validator 锁定 committed block A"
    );
    r1.shutdown().expect("shutdown ok"); // shutdown 消费 self

    // ② restart：rebuild 使 locked ancestry（A 及其祖先）在 DAG 中可判定。
    let mut cfg2 = config.clone();
    cfg2.safety_dir = cfg2.safety_dir.join("restart_safety");
    let provider2 = SoftwareKeyProvider::from_keypair(KeyPair::generate().unwrap());
    let mut r2 = NodeRuntime::start(&cfg2, Some(&provider2)).expect("restart ok");

    let dag = r2.consensus().dag();
    assert!(dag.contains(&a_hash), "locked block A ∈ 重建 DAG");
    assert!(dag.contains(&genesis_hash));
    // 空 DAG 时以下均为 false ⇒ 任何对 A 的 lock/ancestry 检查都会误 LockConflict；
    // rebuild 后 self-inclusive + 全传递 ancestry 成立。
    assert!(
        dag.is_ancestor(&a_hash, &a_hash),
        "self-inclusive lock check"
    );
    assert!(dag.is_ancestor(&genesis_hash, &a_hash), "祖先可判定");
    assert_eq!(dag.len(), 2);

    // head 恢复且无 regression（restart 后不因 DAG 空 / lock 悬空而错误推进或停摆）。
    assert_eq!(r2.block_production().unwrap().head().height, 1);
    assert_eq!(r2.block_production().unwrap().head().block_hash, a_hash);
    r2.step()
        .expect("step ok（无 crash / 无错误 LockConflict 停摆）");
    assert_eq!(r2.block_production().unwrap().head().block_hash, a_hash);
    drop(r2);
}
