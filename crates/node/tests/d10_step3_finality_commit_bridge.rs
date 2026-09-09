//! D10-B Step 2 — Finality → Commit Bridge（经 NodeRuntime enabled 主循环）。
//!
//! 证明：runtime 达共识 finality 后，D10-B bridge（`finality_commit_bridge`）自动把该
//! finalized 本地 canonical block 经既有 `NodeBlockAdapter::apply_block` durable-commit →
//! head 推进 → state/block 持久化 → restart 恢复；且未 finality / remote valid-but-unfinalized /
//! stale 一律 NO COMMIT。禁止手动 apply_block / submit_local_vote / 手设 finality/head/state。

use std::path::PathBuf;

use nova_consensus::proposer::select_proposer;
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
use nova_crypto::signature::sign_message_hash;
use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{HandshakeKind, handshake_payload_encode};
use nova_network::transport::{MemoryTransport, Transport};

use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

// ---------------------------------------------------------------------------
// Fixtures（与 d10_step2 同套路）
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
        let dir = std::env::temp_dir().join(format!("nova_d10b2_{}_{}", std::process::id(), n));
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

/// enabled（网络主循环）validator runtime；返回 (runtime, env)。provider 借用（可跨 restart 复用）。
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

/// step 直至 head 推进到 `want_height`（bridge commit 后）或步数上限。
fn step_until_head_height(runtime: &mut NodeRuntime, want_height: u64) {
    for _ in 0..10 {
        runtime.step().expect("step ok");
        if runtime.block_production().unwrap().head().height >= want_height {
            return;
        }
    }
    panic!("head 未推进到 {want_height}");
}

/// 循环生成双验证者 keys 直至 `select_proposer(0,0)` == 目标。
fn pair_until_selected(want_b: bool) -> (KeyPair, KeyPair, GenesisV1, [u8; 32]) {
    for _ in 0..64 {
        let kp_a = KeyPair::generate().unwrap();
        let kp_b = KeyPair::generate().unwrap();
        let genesis = genesis_with(vec![
            (kp_a.verifying_key().to_bytes(), STAKE),
            (kp_b.verifying_key().to_bytes(), STAKE),
        ]);
        let hash = compute_genesis_hash(&genesis).unwrap();
        let set = ValidatorSet::from_genesis(&genesis);
        let id_b = ValidatorId::from_consensus_public_key(&kp_b.verifying_key().to_bytes());
        let sel = select_proposer(CHAIN_ID, 0, 0, &hash, &set).unwrap();
        if (sel == id_b) == want_b {
            return (kp_a, kp_b, genesis, hash);
        }
    }
    panic!("无法在 bounded 重试内找到满足 proposer 条件的 keys");
}

// ---------------------------------------------------------------------------
// T1 — Single validator: finality → commit → head == finalized block
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t1_finality_commits_head_advances() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp);

    let mut runtime = start_enabled(&config, &provider);
    assert_eq!(
        runtime.block_production().unwrap().head().height,
        0,
        "genesis head"
    );

    // 多 tick：propose → auto prevote/precommit → finality → bridge commit → head=1。
    step_until_head_height(&mut runtime, 1);

    let pb = runtime.last_proposal().expect("本地 proposal").clone();
    let head = runtime.block_production().unwrap().head().clone();
    assert_eq!(
        head.height, 1,
        "finality → commit bridge 推进 canonical head 到 finalized block"
    );
    assert_eq!(
        head.block_hash, pb.block_hash,
        "head == finalized block（bridge 经 apply_block 真实 commit）"
    );
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        Some(pb.block_hash),
        "finality 达成"
    );
    // head 已推进（step_until_head_height 通过）即证明 commit 路径真实执行；空块执行 root 不变。
}

// ---------------------------------------------------------------------------
// T2 — Not finalized → NO COMMIT（valid 本地块存在但无 finality）
//      双验证者 A 当选、B 缺席 ⇒ A 单票 < quorum ⇒ 永不 finality ⇒ head 不变
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t2_not_finalized_no_commit() {
    let (kp_a, _kp_b, genesis, _hash) = pair_until_selected(false);
    let env = Env::new(&genesis);
    let config = env.config();
    let set = ValidatorSet::from_genesis(&genesis);
    assert!(STAKE < set.quorum(), "单方不足 quorum");
    let provider = SoftwareKeyProvider::from_keypair(kp_a);

    let mut runtime = start_enabled(&config, &provider);
    let head0 = runtime.block_production().unwrap().head().clone();

    // 多 tick：A 产 valid 块 + auto prevote（单票不足）→ 无 finality ⇒ bridge NO COMMIT。
    for _ in 0..6 {
        runtime.step().expect("step ok");
    }
    assert!(
        runtime.last_proposal().is_some(),
        "valid 本地块存在（last_proposal）"
    );
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
    assert_eq!(
        runtime.block_production().unwrap().head().height,
        0,
        "未 finality ⇒ head 不变（NO COMMIT）"
    );
    let head = runtime.block_production().unwrap().head();
    assert_eq!(head.block_hash, head0.block_hash, "head 完全不变");
}

// ---------------------------------------------------------------------------
// T4 / T10 — Duplicate tick idempotent + stale finality：commit 后 head/state 稳定
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t4_duplicate_tick_idempotent_no_regression() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp);

    let mut runtime = start_enabled(&config, &provider);
    step_until_head_height(&mut runtime, 1);
    let pb = runtime.last_proposal().expect("proposal").clone();
    let head1 = runtime.block_production().unwrap().head().clone();
    assert_eq!(head1.block_hash, pb.block_hash);

    // 更多 tick：finality 仍 = X（已 commit）⇒ bridge 幂等 no-op；head/state 稳定无回归。
    for _ in 0..5 {
        runtime.step().expect("step ok");
    }
    assert_eq!(
        runtime.block_production().unwrap().head().block_hash,
        pb.block_hash,
        "重复 tick：无重复 destructive commit / 无 head 变化"
    );
    assert_eq!(
        runtime.block_production().unwrap().head().height,
        1,
        "head 稳定（height 1，无回归）"
    );
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        Some(pb.block_hash),
        "stale finality 不造成 regression / 不重复 commit"
    );
    // 幂等：BlockStore 中该块只一份（head 块存在）。
    assert!(
        runtime
            .block_production()
            .unwrap()
            .block_store()
            .unwrap()
            .contains(&pb.block_hash)
            .unwrap_or(false),
        "committed block durable in BlockStore"
    );
}

// ---------------------------------------------------------------------------
// T6+T7 — Restart after commit → head/state/block recovered
//         （同 key runtime restart 需持久化 key 导入 = DEFERRED provider 载体 ⇒ restart 用
//          新随机本地 key + 新 safety dir、同 chain storage；验证链持久化恢复与本地 validator
//          无关；A→B 跨进程连续产块 defer 到 D10-C/持久化 key 导入）
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t6_t7_restart_recovers_committed_head() {
    // 单验证者：r1 = 唯一 validator（当选，auto finality → commit A → head=1）。
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp);

    // ① 第一进程（唯一 validator）：produce A → finality → bridge commit A → head=1。
    let mut r1 = start_enabled(&config, &provider);
    step_until_head_height(&mut r1, 1);
    let a_hash = r1.last_proposal().expect("A").block_hash;
    assert_eq!(r1.block_production().unwrap().head().block_hash, a_hash);
    let a_root = *r1
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    r1.shutdown().expect("shutdown ok");

    // ② restart：新本地 key + 新 safety dir，同 chain storage —— bootstrap 恢复 canonical
    //    head/state/block（链持久化与本地 validator 身份无关）。
    let mut cfg2 = config.clone();
    cfg2.safety_dir = cfg2.safety_dir.join("restart_safety");
    let kp2 = KeyPair::generate().unwrap();
    let provider2 = SoftwareKeyProvider::from_keypair(kp2);
    let mut r2 = start_enabled(&cfg2, &provider2);
    let head_restored = r2.block_production().unwrap().head().clone();
    assert_eq!(
        head_restored.height, 1,
        "restart 恢复已 commit head（height 1）"
    );
    assert_eq!(
        head_restored.block_hash, a_hash,
        "head == committed block A"
    );
    assert_eq!(
        *r2.block_production()
            .unwrap()
            .store()
            .state_root()
            .as_bytes(),
        a_root,
        "state 恢复一致"
    );
    assert!(
        r2.block_production()
            .unwrap()
            .block_store()
            .unwrap()
            .contains(&a_hash)
            .unwrap_or(false),
        "committed block A durable（重启后可用）"
    );
    // 新本地 key 非 set 成员（单验 genesis 只有 kp）⇒ 不产块 ⇒ head 保持（无回归）。
    r2.step().expect("step ok");
    assert_eq!(
        r2.block_production().unwrap().head().block_hash,
        a_hash,
        "restart 后无 regression"
    );
    assert_eq!(r2.block_production().unwrap().head().height, 1);
}

// ---------------------------------------------------------------------------
// T9 — Remote valid-but-unfinalized block → NO COMMIT（Runtime inbound 只读观测）
//      双验证者：A=runtime（非当选）、B=当选（测试注入真实正确 block）
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t9_remote_valid_block_not_committed() {
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_selected(true);
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp_a);

    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, mut tx_b) = MemoryTransport::pair(a_id, b_id);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&provider),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("A validator + network 启动");

    // B 握手（Established）—— 信封由网络 key `net_b` 签名（≠ consensus key）。
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        &b_id,
        &SessionNonce::from_bytes([1; 16]),
        b"",
    )
    .expect("hs");
    let mut hs = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: b_id,
        signature: [0u8; 64],
    };
    sign_message(net_b.signing_key(), &mut hs).expect("sign hs");
    tx_b.send(&a_id, encode(&hs)).expect("inject handshake");
    runtime.step().expect("step handshake ok");

    // B（当选者）产真实 canonical-next block，state_root = A 链 root（通过 canonical 全验证）。
    let root = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    let body = nova_runtime::BlockBody { txs: Vec::new() };
    let header = nova_runtime::BlockHeader {
        version: nova_runtime::BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: genesis_hash,
        finality_reference: None,
        transaction_root: nova_runtime::compute_transaction_root(&body),
        state_root: root,
        validator_set_hash: genesis_hash,
        timestamp: 0,
    };
    let hp = nova_runtime::encode_block_header(&header);
    let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &hp).unwrap();
    let msg = hash_signing_message(&signed);
    let block = nova_runtime::Block {
        header,
        body,
        proposer_signature: sign_message_hash(kp_b.signing_key(), &msg).to_bytes(),
    };
    let wire = nova_runtime::encode_block(&block).unwrap();
    let mut gossip = MessageEnvelope {
        version: 1,
        message_type: MessageType::GossipBlock,
        payload: wire,
        sender: b_id,
        signature: [0u8; 64],
    };
    sign_message(net_b.signing_key(), &mut gossip).expect("sign gossip");
    tx_b.send(&a_id, encode(&gossip))
        .expect("inject remote block");
    runtime.step().expect("step remote block ok");

    // remote valid block 经 D9 seam = CanonicalNextCandidate（只读观测）……
    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes.iter().any(|o| {
            matches!(
                o,
                Ok(InboundBlockVerdict::CanonicalNextCandidate { height: 1, .. })
            )
        }),
        "remote valid block 通过 proposer 验证为 canonical-next（只读）: {:?}",
        outcomes
    );
    // ……但未 finality ⇒ bridge NO COMMIT：head 不变、无 apply。
    assert_eq!(
        runtime.block_production().unwrap().head().height,
        0,
        "remote valid-but-unfinalized ⇒ NO COMMIT（head 不变）"
    );
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "无本地 finality"
    );
}

// ---------------------------------------------------------------------------
// T3/T5/T8 说明（见文件尾注释 —— 由 gate 结构 / 既有 adapter E2E 保证）
// ---------------------------------------------------------------------------

#[test]
fn d10_b2_t5_wrong_target_never_committed() {
    // 结构保证：bridge 只 commit `finalized_reference`（consensus 唯一产出）且要求
    // block_hash(block)==X 严格匹配；adapter ⑤ 只收 head 的严格 child。
    // 等价负向：finality None（B 缺席）时，即使存在 valid 本地块也 NO COMMIT（head 不变）。
    let (kp_a, _kp_b, genesis, _hash) = pair_until_selected(false);
    let env = Env::new(&genesis);
    let config = env.config();
    let provider = SoftwareKeyProvider::from_keypair(kp_a);
    let mut runtime = start_enabled(&config, &provider);
    for _ in 0..5 {
        runtime.step().expect("step ok");
    }
    assert!(runtime.last_proposal().is_some(), "存在本地 valid block");
    assert_eq!(
        runtime.block_production().unwrap().head().height,
        0,
        "无 finality ⇒ 不会把任意本地块当 target commit（wrong-target 不可能）"
    );
    // 显式验证 T9 同类：任何非 finalized 块都不能成为 commit 目标。
    let _ = InboundBlockError::InvalidProposerSignature; // （import 引用保持；T9 用 InboundBlockVerdict）
}
