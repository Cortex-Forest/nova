//! MODE-2 SYNC REGRESSION — "无 sync 任务 / 无 external QC / 未服务任何 QC" 时推进不得停滞。
//!
//! 背景（R1，来自长跑观测）：历史长场景中曾出现 `sync_pending=0 && pending_external_qc=0 &&
//! qc_served=0` 但 `head_height` 不再增长的情形（C2 starvation）。本文件用**确定性、单进程、
//! 无网络**的最小 rig 把"Mode 2 观测三元组全为 0 时仍必须推进"这一行为锁死，防止回归。
//!
//! 断言（全部基于真实 production 路径；无 mock / 无手设 state / 无 fake head）：
//! - M2-1：启动即 `sync_pending=0` / `pending_external_qc=0` / `qc_served=0`；随后 head 仍推进到 3 且
//!   finality 提交（`finalized == head`）。
//! - M2-2：每次 commit 都由**本 runtime 真实产出 proposal**（`last_proposal.block_hash == head`），
//!   block 真实持久化（BlockStore）且 parent 链闭合。
//! - M2-3：逐 step 观测 head / consensus round height / finality 单调推进，且每 step 后 Mode 2 三元组
//!   恒为 0（观测访问器**只读**，不改变控制流）。
//!
//! 边界：本文件**只新增测试**，不修改 `runtime.rs` 或任何生产代码；不修改 consensus 规则 /
//! genesis 算法 / tokenomics / validator 经济模型。

use std::path::PathBuf;

use nova_consensus::round::RoundStep;
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

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// 目标 head 高度（3 次真实 commit）。
const TARGET_HEIGHT: u64 = 3;
/// step 预算（真实驱动；正常远小于此值）。
const STEP_BUDGET: usize = 240;

// ---------------------------------------------------------------------------
// Fixtures（与 d10_step7b 同套路：真实 genesis 落盘 + enabled validator runtime）
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
        let dir = std::env::temp_dir().join(format!("nova_mode2_{}_{}", std::process::id(), n));
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

    /// Mode 2 rig：**无 peer / 无 listener**（不注入任何网络 transport）。
    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            // G5-D.7.2：仅在 safety journal 不存在时声明显式初始化（fresh validator startup）。
            validator_safety_init: !self.safety_dir.join("safety.journal").exists(),
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
            listen_addr: None,
        }
    }
}

fn single_setup() -> (KeyPair, Env, NodeConfig) {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = single_validator_genesis(pk);
    let env = Env::new(&genesis);
    let config = env.config();
    (kp, env, config)
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// Mode 2 rig：**零 configured peer / 无 listener**；仅装配 network seam（与 d10_step7b 同形态，
/// 保证 validator 本地 propose→vote 生产路径可用），对端为无 peer 的 MemoryTransport。
fn start_single(config: &NodeConfig, provider: &dyn KeyProvider) -> NodeRuntime {
    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    NodeRuntime::start_with_network(config, Some(provider), Box::new(tx_a), Box::new(identity))
        .expect("validator runtime 启动（network 装配 / 零 configured peer）")
}

// ---------------------------------------------------------------------------
// Mode 2 观测（只读访问器；不改变控制流）
// ---------------------------------------------------------------------------

/// Mode 2 三元组：`(sync_pending, pending_external_qc, qc_served)`。
fn mode2_witness(rt: &NodeRuntime) -> (usize, usize, u64) {
    (
        rt.sync_pending_requests(),
        rt.pending_external_qc_len(),
        rt.qc_served(),
    )
}

fn assert_mode2(rt: &NodeRuntime, ctx: &str) {
    let (sync_pending, pending_external_qc, qc_served) = mode2_witness(rt);
    assert_eq!(sync_pending, 0, "{ctx}: sync_pending 必须为 0（Mode 2）");
    assert_eq!(
        pending_external_qc, 0,
        "{ctx}: pending_external_qc 必须为 0（Mode 2）"
    );
    assert_eq!(qc_served, 0, "{ctx}: qc_served 必须为 0（Mode 2）");
    assert_eq!(
        rt.block_inbound_skipped(),
        0,
        "{ctx}: 无网络 ⇒ 不可能有 inbound block 被 skip"
    );
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production().unwrap().head().height
}

fn head_hash(rt: &NodeRuntime) -> [u8; 32] {
    rt.block_production().unwrap().head().block_hash
}

fn finalized(rt: &NodeRuntime) -> Option<[u8; 32]> {
    rt.consensus().state().finality.finalized_reference
}

/// durable block header（BlockStore；证明 commit 是真实持久化，而非内存伪造）。
fn durable_header(config: &NodeConfig, hash: &[u8; 32]) -> BlockHeader {
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    bs.get_content(hash)
        .expect("BlockStore 可读")
        .expect("block durable")
        .header
}

// ---------------------------------------------------------------------------
// M2-1 — 三元组为 0 时 head 仍推进且 finality 提交
// ---------------------------------------------------------------------------

#[test]
fn mode2_t1_zero_sync_zero_external_qc_zero_served_head_still_advances() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut rt = start_single(&config, &provider);

    assert_mode2(&rt, "startup");
    assert_eq!(head_height(&rt), 0, "启动 head=0");
    assert_eq!(
        rt.consensus().state().round.height,
        0,
        "启动 consensus height=0"
    );
    assert_eq!(rt.consensus().state().round.step, RoundStep::Propose);

    let mut prev_head = 0u64;
    let mut steps = 0usize;
    for _ in 0..STEP_BUDGET {
        rt.step().expect("step ok");
        steps += 1;
        assert_mode2(&rt, "after step");
        let h = head_height(&rt);
        assert!(h >= prev_head, "head 不得回退（{prev_head} → {h}）");
        prev_head = h;
        if h >= TARGET_HEIGHT {
            break;
        }
    }

    assert_eq!(
        head_height(&rt),
        TARGET_HEIGHT,
        "Mode 2 下 head 必须推进到 {TARGET_HEIGHT}（steps={steps}）"
    );
    assert_eq!(
        finalized(&rt),
        Some(head_hash(&rt)),
        "finality 继续提交：finalized_reference == head.block_hash"
    );
    assert_mode2(&rt, "final");
    rt.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// M2-2 — 无 peer 时 proposer 持续真实出块，且持久化 / parent 链闭合
// ---------------------------------------------------------------------------

#[test]
fn mode2_t2_proposer_keeps_producing_blocks_without_peers() {
    let (kp, env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut rt = start_single(&config, &provider);

    assert_mode2(&rt, "startup");
    assert!(rt.last_proposal().is_none(), "启动时无 stale proposal");

    let mut committed: Vec<([u8; 32], u64)> = Vec::new();
    for _ in 0..STEP_BUDGET {
        rt.step().expect("step ok");
        assert_mode2(&rt, "after step");
        let h = head_height(&rt);
        if h > 0 && committed.last().map(|(_, ph)| *ph) != Some(h) {
            let proposal = rt
                .last_proposal()
                .expect("commit 后必有本 runtime 产出的 proposal");
            assert_eq!(
                proposal.block_hash,
                head_hash(&rt),
                "proposal.block_hash == head.block_hash（真实出块，非继承）"
            );
            committed.push((proposal.block_hash, h));
        }
        if h >= TARGET_HEIGHT {
            break;
        }
    }

    assert_eq!(
        committed.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "每高度均由本 runtime 产出并 commit"
    );

    let hashes: Vec<[u8; 32]> = committed.iter().map(|(hash, _)| *hash).collect();
    assert_eq!(
        hashes.len(),
        hashes
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        "块哈希互不相同"
    );

    // durable + parent 链闭合：A.parent = genesis，B.parent = A，C.parent = B。
    let a = durable_header(&config, &hashes[0]);
    let b = durable_header(&config, &hashes[1]);
    let c = durable_header(&config, &hashes[2]);
    assert_eq!((a.height, b.height, c.height), (1, 2, 3));
    assert_eq!(a.parent_hash, env.genesis_hash, "A.parent == genesis");
    assert_eq!(b.parent_hash, hashes[0], "B.parent == A");
    assert_eq!(c.parent_hash, hashes[1], "C.parent == B");

    // DAG 真实记录全部高度。
    let dag = rt.consensus().dag();
    for hash in &hashes {
        assert!(dag.contains(hash), "DAG contains {hash:?}");
    }
    assert!(dag.is_ancestor(&hashes[0], &hashes[2]), "A ancestor of C");

    assert_eq!(finalized(&rt), Some(head_hash(&rt)));
    assert_mode2(&rt, "final");
    rt.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// M2-3 — 逐 step 单调性：head / consensus round height / finality 只增不减
// ---------------------------------------------------------------------------

#[test]
fn mode2_t3_round_and_finality_progress_monotonically() {
    let (kp, _env, config) = single_setup();
    let provider = SoftwareKeyProvider::from_keypair(kp);
    let mut rt = start_single(&config, &provider);

    let mut prev_head = 0u64;
    let mut prev_round_height = 0u64;
    let mut prev_finalized: Option<[u8; 32]> = None;
    let mut commits = 0u32;

    for _ in 0..STEP_BUDGET {
        rt.step().expect("step ok");
        assert_mode2(&rt, "after step");

        let h = head_height(&rt);
        let round_height = rt.consensus().state().round.height;
        let fin = finalized(&rt);

        assert!(h >= prev_head, "head 单调不减（{prev_head} → {h}）");
        assert!(
            round_height >= prev_round_height,
            "consensus round height 单调不减（{prev_round_height} → {round_height}）"
        );

        if h > prev_head {
            commits += 1;
            assert_eq!(round_height, h, "commit 后 consensus 进入同一高度（轮）");
            assert_eq!(fin, Some(head_hash(&rt)), "commit 后 finality == 新 head");
            assert_eq!(
                rt.consensus().state().round.round,
                0,
                "新高度轮从 round 0 开始（无 round 回退/复用）"
            );
            assert!(
                rt.consensus().state().round.proposal.is_none(),
                "新高度轮无 stale proposal"
            );
            assert!(
                fin != prev_finalized,
                "finality 必须真正推进（不得重复或回退）"
            );
        }

        prev_head = h;
        prev_round_height = round_height;
        prev_finalized = fin;

        if h >= TARGET_HEIGHT {
            break;
        }
    }

    assert_eq!(commits, TARGET_HEIGHT as u32, "所有目标高度均 commit");
    assert_eq!(prev_head, TARGET_HEIGHT);
    assert_eq!(prev_finalized, Some(head_hash(&rt)));
    assert_mode2(&rt, "final");
    rt.shutdown().unwrap();
}
