//! D10-C Step 7-B — Same-Runtime Height Advancement（真实 Runtime；**不 restart** / 无 mock）。
//!
//! 证明 commit 成功后 Node 以 **durable canonical head** 驱动 consensus 进入下一高度轮，同一
//! `NodeRuntime` 实例内连续产出 `genesis → A → B → C`（不再依赖 restart seam）：
//! - `ConsensusNode::advance_to_height`（node-only；单调 / 幂等；仅重建 `RoundState` +
//!   `IntegrationContext`，**保留** finality / DAG / ValidatorSet / chain_id / genesis_hash）。
//! - `NodeRuntime::step`：`finality → commit → head durable → advance → 下一轮 proposal`。
//!
//! 全部断言基于真实 production 路径（真实 genesis / 真实签名 / 真实 storage commit /
//! 真实 frozen transition），无 stub / 无手设 state / 无 fake head。

use std::path::PathBuf;

use nova_consensus::round::RoundStep;
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::node_id::NodeId;
use nova_network::transport::MemoryTransport;
use nova_runtime::BlockHeader;
use nova_storage::block_store::BlockStore;

use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;
use nova_node::vote_ledger::VoteKey;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

// ---------------------------------------------------------------------------
// Fixtures（与 d10_step2/3/6 同套路：真实 genesis 落盘 + enabled validator runtime）
// ---------------------------------------------------------------------------

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
        let dir = std::env::temp_dir().join(format!("nova_d10c7b_{}_{}", std::process::id(), n));
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

/// 单验证者 enabled runtime（真实 provider / transport / identity）。
fn start_single(config: &NodeConfig, provider: &dyn KeyProvider) -> NodeRuntime {
    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    NodeRuntime::start_with_network(config, Some(provider), Box::new(tx_a), Box::new(identity))
        .expect("validator + network 启动")
}

/// step 直至 `head.height >= want_height`（真实驱动，非手设 head）；每 step 必须 `Ok`。
fn step_until_head_height(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..80 {
        runtime
            .step()
            .expect("step ok（无 DoubleVote / LockConflict / DagRegister 错误）");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
    }
    panic!("head 未推进到 {want_height}");
}

fn head_hash(runtime: &NodeRuntime) -> [u8; 32] {
    runtime.block_production().unwrap().head().block_hash
}

/// durable block header（BlockStore；证明 commit 是真实持久化，不是内存伪造）。
fn durable_header(config: &NodeConfig, hash: &[u8; 32]) -> BlockHeader {
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    bs.get(hash)
        .expect("BlockStore 可读")
        .expect("block durable")
        .header
}

fn single_setup() -> (KeyPair, Env, NodeConfig) {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let env = Env::new(&genesis);
    let config = env.config();
    (kp, env, config)
}

// ---------------------------------------------------------------------------
// T7-B-1 — A commit 后 consensus 进入 height=1 / round=0 / Propose / proposal=None
// ---------------------------------------------------------------------------

#[test]
fn d10_c7b_t1_a_commit_advances_consensus_height() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut runtime = start_single(&config, &provider);

    assert_eq!(runtime.consensus().state().round.height, 0, "启动高度");
    assert_eq!(runtime.consensus().state().round.round, 0);
    assert_eq!(runtime.consensus().state().round.step, RoundStep::Propose);

    step_until_head_height(&mut runtime, 1);
    let a_hash = head_hash(&runtime);
    assert_eq!(runtime.block_production().unwrap().head().height, 1);

    let round = &runtime.consensus().state().round;
    assert_eq!(round.height, 1, "A commit 后 consensus 进入下一高度");
    assert_eq!(round.round, 0, "新高度轮从 round 0 开始");
    assert_eq!(round.step, RoundStep::Propose, "新高度轮阶段 = Propose");
    assert!(round.proposal.is_none(), "新高度轮无 stale proposal");
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        Some(a_hash),
        "finality 保留（A 不被清除）"
    );
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T7-B-2 — 同一 runtime 实例真实产出 B（B.parent = A）
// ---------------------------------------------------------------------------

#[test]
fn d10_c7b_t2_same_runtime_produces_b() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut runtime = start_single(&config, &provider);

    step_until_head_height(&mut runtime, 1);
    let a_hash = head_hash(&runtime);
    assert_eq!(
        runtime.last_proposal().expect("A proposal").block_hash,
        a_hash,
        "A 由本 runtime 产出"
    );

    // 无 restart：同一实例继续推进到 head=2。
    step_until_head_height(&mut runtime, 2);
    let head = runtime.block_production().unwrap().head().clone();
    assert_eq!(head.height, 2, "同进程（无 restart）产出并 commit B");
    let b_hash = head.block_hash;
    assert_ne!(b_hash, a_hash, "B != A");

    let b = durable_header(&config, &b_hash);
    assert_eq!(b.height, 2);
    assert_eq!(b.parent_hash, a_hash, "B.parent == A（真实链）");

    let dag = runtime.consensus().dag();
    assert!(dag.contains(&a_hash), "DAG contains A");
    assert!(dag.contains(&b_hash), "DAG contains B");
    assert!(dag.is_ancestor(&a_hash, &b_hash), "A ancestor of B");

    let round = &runtime.consensus().state().round;
    assert_eq!(round.height, 2, "B commit 后再推进到高度 2");
    assert_eq!(round.step, RoundStep::Propose);
    assert!(round.proposal.is_none());
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T7-B-3 — 同一 runtime 实例真实产出 C（genesis → A → B → C）
// ---------------------------------------------------------------------------

#[test]
fn d10_c7b_t3_same_runtime_produces_c() {
    let (kp, env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut runtime = start_single(&config, &provider);

    step_until_head_height(&mut runtime, 1);
    let a_hash = head_hash(&runtime);
    step_until_head_height(&mut runtime, 2);
    let b_hash = head_hash(&runtime);
    step_until_head_height(&mut runtime, 3);
    let c_hash = head_hash(&runtime);

    let a = durable_header(&config, &a_hash);
    let b = durable_header(&config, &b_hash);
    let c = durable_header(&config, &c_hash);
    assert_eq!((a.height, b.height, c.height), (1, 2, 3));
    assert_eq!(a.parent_hash, env.genesis_hash, "A.parent == genesis");
    assert_eq!(b.parent_hash, a_hash, "B.parent == A");
    assert_eq!(c.parent_hash, b_hash, "C.parent == B");

    let dag = runtime.consensus().dag();
    assert_eq!(dag.parents_of(&a_hash), Some(&[env.genesis_hash][..]));
    assert_eq!(dag.parents_of(&b_hash), Some(&[a_hash][..]));
    assert_eq!(dag.parents_of(&c_hash), Some(&[b_hash][..]));
    assert!(
        dag.is_ancestor(&env.genesis_hash, &c_hash),
        "genesis → C 全传递"
    );

    let round = &runtime.consensus().state().round;
    assert_eq!(round.height, 3, "C commit 后高度 3");
    assert_eq!(round.round, 0);
    assert_eq!(round.step, RoundStep::Propose);
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T7-B-4 — 全过程单一 runtime / 单一 actor 实例（无 drop / 无重建 / 无 restart）
// ---------------------------------------------------------------------------

#[test]
fn d10_c7b_t4_single_runtime_instance_no_reconstruction() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut runtime = start_single(&config, &provider);

    let validator_id = runtime.validator().expect("validator view").validator_id();
    let mut produced = Vec::new();
    let mut committed = Vec::new();

    for want in 1..=3u64 {
        // 同一实例、同一循环内推进（无 shutdown / 无 NodeRuntime::start / 无 driver 重建）。
        step_until_head_height(&mut runtime, want);
        let head = runtime.block_production().unwrap().head().clone();
        assert_eq!(head.height, want);
        // 每个 committed block 均由**本实例**在之前 tick 真实产出（last_proposal 即同一对象）。
        assert_eq!(
            runtime.last_proposal().expect("proposal").block_hash,
            head.block_hash,
            "head 块由本 runtime 实例产出（非外部注入）"
        );
        assert_eq!(
            runtime.validator().expect("validator view").validator_id(),
            validator_id,
            "同一 actor 实例贯穿全程"
        );
        produced.push(runtime.last_proposal().unwrap().block_hash);
        committed.push(head.block_hash);
    }

    assert_eq!(
        produced, committed,
        "produced 顺序 == committed 顺序（同实例链）"
    );
    let mut sorted = committed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 3, "3 个不同 block（无重复 commit）");
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T7-B-5 — Safety：跨高度继续不产生 DoubleVote / LockConflict / 无效 QC / 重复 commit
// ---------------------------------------------------------------------------

#[test]
fn d10_c7b_t5_safety_across_heights() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut runtime = start_single(&config, &provider);

    let mut heights = Vec::new();
    let mut hashes = Vec::new();
    let mut finalized = Vec::new();

    for want in 1..=3u64 {
        step_until_head_height(&mut runtime, want); // 每 step 必须 Ok（无 DoubleVote / LockConflict / DagRegister）
        let head = runtime.block_production().unwrap().head().clone();
        assert_eq!(head.height, want, "严格 +1（无跳过 parent / 无高度跳跃）");
        heights.push(head.height);
        hashes.push(head.block_hash);
        let fr = runtime
            .consensus()
            .state()
            .finality
            .finalized_reference
            .expect("finality 单调存在");
        finalized.push(fr);

        // lock 随 finality 单调推进（descendant ⇒ advance；无 LockConflict 保守 no-op）。
        let view = runtime.validator().expect("validator view");
        assert_eq!(
            view.actor().locked_state().locked_block_hash,
            Some(head.block_hash),
            "lock == 最新 committed block（descendant applicability，无 LockConflict）"
        );
    }

    assert_eq!(heights, vec![1, 2, 3], "高度严格递增");
    assert_eq!(
        finalized, hashes,
        "finality 单调跟随 committed block（无 invalid QC / 无 finality 回退）"
    );

    // 无重复 commit：每 committed block 在 BlockStore 各一份，且三者互异。
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    for h in &hashes {
        assert!(bs.contains(h).expect("blockstore 可读"), "durable");
    }
    let mut uniq = hashes.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), 3, "3 个互异 block（无重复 commit）");

    // 无 double vote：VoteLedger 每个高度各有 Prevote / Precommit 记录（VoteKey 含 height ⇒
    // 跨高度不复用键），target 各自对齐该高度的 block。
    let view = runtime.validator().expect("validator view");
    let ledger = view.actor().vote_ledger();
    for (idx, h) in hashes.iter().enumerate() {
        let height = idx as u64;
        for vt in [VoteType::Prevote, VoteType::Precommit] {
            let key = VoteKey {
                height,
                round: 0,
                vote_type: vt,
            };
            let rec = ledger.lookup(&key).expect("该高度已投票（无跳过）");
            assert_eq!(
                rec.target_block_hash, *h,
                "该高度 vote target == 该高度 block"
            );
        }
    }
    assert_eq!(
        ledger.len(),
        6,
        "3 高度 × (Prevote + Precommit)，无重复签名"
    );
    runtime.shutdown().unwrap();
}
