//! NodeRuntime 生命周期装配集成测试（STEP 10-16 Phase 1；RT-26 / RT-27 / RT-28）。
//!
//! - RT-26：full-node（validator_enabled=false）启动 —— genesis + chain storage；跳过 key/safety/validator。
//! - RT-27：validator mode 启动生命周期 —— KeyProvider → derive ValidatorId → SafetyStore → recover →
//!   ValidatorActor；并验证 actor 可经 runtime 装配产出投票。
//! - RT-28：identity mismatch（chain_id / genesis_hash / validator_id）⇒ 启动 fail closed。
//!
//! 不复制 validator/consensus 测试逻辑；只用生产装配 API（`NodeRuntime::start`）。

use std::path::PathBuf;

use nova_consensus::integration::ConsensusEvent;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;

use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::runtime::{NodeRuntime, NodeRuntimeError, derive_validator_id};
use nova_node::safety_store::{SafetyIdentity, ValidatorSafetyStore};
use nova_node::validator::LocalVoteRequest;
use nova_node::wiring::NodeConsensusCommand;

const CHAIN_ID: u64 = 1001;

// ---------- fixtures ----------

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// TEST GENESIS ONLY：通过 `validate_genesis` 的形态（timestamp>0、account 升序、
/// Σliquid==total_supply、validator 账户 liquid ≥ bonded_stake；pubkey = 被测验证者）。
fn genesis_for(pk: [u8; 32]) -> GenesisV1 {
    let mut accounts = vec![
        AccountInit {
            address: addr([0x11; 32]),
            liquid_balance: 1_000_000,
        },
        AccountInit {
            address: addr([0x22; 32]),
            liquid_balance: 500_000,
        },
    ];
    accounts.sort_by_key(|a| a.address.payload().to_bytes()); // canonical 账户序
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: accounts[0].address,
            consensus_public_key: pk,
            bonded_stake: 200_000,
            commission_bps: 0,
        }],
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
    dir: PathBuf,
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
        let dir = std::env::temp_dir().join(format!("nova_rt16_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        Self {
            dir,
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self, validator_enabled: bool, expected_hash: [u8; 32]) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: expected_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn vote_req(target: [u8; 32], h: u64, r: u64) -> LocalVoteRequest {
    LocalVoteRequest {
        height: h,
        round: r,
        target_block_hash: target,
        vote_type: VoteType::Prevote,
        source_block_hash: [0u8; 32],
        timestamp: 0,
    }
}

fn ev_target(ev: &ConsensusEvent) -> [u8; 32] {
    match ev {
        ConsensusEvent::Vote { vote, .. } => vote.target_block_hash,
        other => panic!("必须为 ConsensusEvent::Vote，got {other:?}"),
    }
}

// ---------- RT-26 : full-node startup ----------

#[test]
fn rt_26_full_node_startup_skips_validator_lifecycle() {
    let pk = KeyPair::generate().unwrap().verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let config = env.config(false, env.genesis_hash);

    let runtime = NodeRuntime::start(&config, None).expect("full-node 启动成功");
    // genesis + chain identity
    assert_eq!(runtime.chain_identity().chain_id, CHAIN_ID);
    assert_eq!(runtime.chain_identity().genesis_hash, env.genesis_hash);
    // chain storage 已初始化（目录存在）
    assert!(env.chain_dir.exists(), "chain storage 目录已初始化");
    // consensus handle 存在
    let _ = runtime.consensus().state().round.height;
    // key / safety / validator 全部跳过
    assert!(!runtime.validator_enabled(), "full-node：validator 未启用");
    assert!(runtime.validator().is_none());
    assert!(
        !env.safety_dir.exists(),
        "full-node：不得创建 safety 目录 / journal"
    );
}

// ---------- RT-27 : validator startup lifecycle ----------

#[test]
fn rt_27_validator_startup_lifecycle() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let config = env.config(true, env.genesis_hash);
    let provider = SoftwareKeyProvider::from_keypair(kp);

    let runtime = NodeRuntime::start(&config, Some(&provider)).expect("validator 启动成功");
    assert!(runtime.validator_enabled());
    let v = runtime.validator().expect("validator mode 有运行时");

    // key provider → derive validator id（与 genesis 内公钥一致）
    let expected_id = derive_validator_id(&pk);
    assert_eq!(
        v.validator_id(),
        expected_id,
        "ValidatorId 与 genesis 内公钥一致"
    );
    // safety store open + recover（空首启）→ actor 装配
    assert!(v.actor().vote_ledger().is_empty(), "首启 ledger 为空");
    assert!(
        env.safety_dir.join("safety.journal").exists(),
        "safety journal 已创建（独立目录）"
    );

    // actor 经 runtime 装配可用（produce 走完整 persist-before-sign 管线）
    let set = runtime.consensus().validator_set();
    let dag = runtime.consensus().dag();
    let ev = v
        .actor()
        .produce_vote(&vote_req([0xAA; 32], 0, 0), set, dag)
        .expect("本地投票（runtime 装配）")
        .expect("authorized 产出事件");
    assert_eq!(ev_target(&ev), [0xAA; 32]);
    // 投票已 durable 至 safety journal
    let rec = ValidatorSafetyStore::at(
        &env.safety_dir.join("safety.journal"),
        SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, env.genesis_hash, &expected_id),
    )
    .recover()
    .expect("safety store 可恢复")
    .ledger
    .lookup(&nova_node::vote_ledger::VoteKey {
        height: 0,
        round: 0,
        vote_type: VoteType::Prevote,
    })
    .expect("恢复记录");
    assert_eq!(rec.target_block_hash, [0xAA; 32]);
}

// ---------- RT-28 : identity mismatch fail closed ----------

#[test]
fn rt_28_chain_id_mismatch_startup_fails() {
    let pk = KeyPair::generate().unwrap().verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let mut config = env.config(false, env.genesis_hash);
    config.expected_chain_id = CHAIN_ID + 1; // 期望 chain 与 genesis 不符

    let err = match NodeRuntime::start(&config, None) {
        Err(e) => e,
        Ok(_) => panic!("RT-28：期望 chain_id mismatch 启动失败"),
    };
    assert!(
        matches!(
            err,
            NodeRuntimeError::Startup(nova_node::bootstrap::NodeStartupError::ChainIdMismatch)
        ),
        "chain_id mismatch ⇒ startup fail（got {err:?}）"
    );
}

#[test]
fn rt_28_genesis_hash_mismatch_startup_fails() {
    let pk = KeyPair::generate().unwrap().verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let config = env.config(false, [0x99; 32]); // 错误期望 genesis hash

    let err = match NodeRuntime::start(&config, None) {
        Err(e) => e,
        Ok(_) => panic!("RT-28：期望 genesis_hash mismatch 启动失败"),
    };
    assert!(
        matches!(err, NodeRuntimeError::Startup(_)),
        "genesis_hash mismatch ⇒ startup fail（got {err:?}）"
    );
}

#[test]
fn rt_28_validator_id_mismatch_startup_fails() {
    // key A 写入既有 safety store；用 key B 启动 ⇒ store identity 校验失败 ⇒ fail closed。
    let kp_a = KeyPair::generate().unwrap();
    let pk_a = kp_a.verifying_key().to_bytes();
    let kp_b = KeyPair::generate().unwrap();
    let env = Env::new(&genesis_for(pk_a));
    let config = env.config(true, env.genesis_hash);

    // 预先创建绑定 key A 的 safety store（模拟已有历史 / 换 key 场景）
    let id_a = derive_validator_id(&pk_a);
    let sid_a = SafetyIdentity::new(NetworkId::Mainnet, CHAIN_ID, env.genesis_hash, &id_a);
    let journal = env.safety_dir.join("safety.journal");
    ValidatorSafetyStore::create(&journal, sid_a).unwrap();

    // 用 key B 启动（validator_id 与 store header 不符）
    let provider_b = SoftwareKeyProvider::from_keypair(kp_b);
    let err = match NodeRuntime::start(&config, Some(&provider_b)) {
        Err(e) => e,
        Ok(_) => panic!("RT-28：期望 validator_id mismatch 启动失败"),
    };
    assert!(
        matches!(err, NodeRuntimeError::Validator(_)),
        "validator_id mismatch ⇒ validator 启动 fail closed（got {err:?}）"
    );
}

// ---------- RT-29 : consensus orchestration 入口（10-18I-D-A Option A） ----------

/// RT-29：Runtime 承接 node 层 consensus command → Driver（唯一 mutation owner）。
/// Proposal command（EventLoop/handler 已完成 decode）→ 既有 canonical 门面 Applied；
/// ConsensusNode 是唯一 canonical 状态 owner（command 不停留在任何中间层）。
#[test]
fn rt_29_runtime_processes_consensus_command() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let config = env.config(true, env.genesis_hash);
    let provider = SoftwareKeyProvider::from_keypair(kp);

    let mut runtime = NodeRuntime::start(&config, Some(&provider)).expect("validator 启动成功");
    let proposer = derive_validator_id(&pk);
    let pr = ProposalRef {
        block_hash: [0xAA; 32],
        proposer,
    };

    // 经 Runtime orchestration 入口提交 remote proposal（verify 由 Driver 既有门面完成）
    runtime
        .process_consensus_command(NodeConsensusCommand::Proposal(pr.clone()))
        .expect("proposal orchestration Ok");

    // ConsensusNode canonical 状态已推进（Proposal Applied ⇒ step=Prevote）
    let state = runtime.consensus().state();
    assert_eq!(state.round.proposal, Some(pr));
    assert_eq!(state.round.step, RoundStep::Prevote);
}

// ---------- RT-BP : STEP 10-19-6 OPT-1 block-production seam ----------

/// RT-BP-1：validator `step` ⇒ 自动经真实 BlockBuilder 出块（`ProposalRef.block_hash ==
/// BlockHash(block)`，非 placeholder）；head / store state root 不变（build 只读、不推进 head）。
#[test]
fn rt_bp_proposer_produces_real_block_head_unchanged() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(pk));
    let config = env.config(true, env.genesis_hash);
    let provider = SoftwareKeyProvider::from_keypair(kp);

    let mut runtime = NodeRuntime::start(&config, Some(&provider)).expect("validator 启动");
    let head_before = runtime
        .block_production()
        .expect("validator 装配 block-production adapter")
        .head()
        .clone();
    let root_before = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    assert_eq!(head_before.height, 0, "head = genesis");
    assert_eq!(
        head_before.block_hash, env.genesis_hash,
        "head.block_hash = genesis_hash"
    );

    // step（网络 disabled）⇒ 本地 proposer 自动出块（真实 BlockBuilder；显式 timestamp）。
    runtime.step().expect("step ok");

    let pb = runtime
        .last_proposal()
        .expect("本地 proposer 产出 ProposalBuild")
        .clone();
    // ProposalRef.block_hash == BlockHash(block)（真实；非 proposer_seed placeholder）
    assert_eq!(pb.proposal_ref.block_hash, pb.block_hash);
    assert_eq!(pb.block_hash, nova_runtime::block_hash(&pb.block).unwrap());
    // OPT1-6：canonical encode → decode roundtrip（结构往返一致）
    let wire = nova_runtime::encode_block(&pb.block).unwrap();
    let decoded = nova_runtime::decode_block(&wire).unwrap();
    assert_eq!(decoded, pb.block, "encode → decode roundtrip");
    // 真实 Block 字段：chain / height = head+1 / parent = head / tx_root（空体）/ state_root = parent
    assert_eq!(pb.block.header.chain_id, CHAIN_ID);
    assert_eq!(pb.block.header.height, head_before.height + 1);
    assert_eq!(pb.block.header.parent_hash, head_before.block_hash);
    assert_eq!(pb.block.header.validator_set_hash, env.genesis_hash);
    assert!(pb.block.body.txs.is_empty(), "V0.1 candidate = empty set");
    assert_eq!(
        pb.block.header.state_root, root_before,
        "空候选 ⇒ post-state root == parent root"
    );
    // consensus 已接收（Prevote；proposal 即真实 hash）
    let state = runtime.consensus().state();
    assert_eq!(state.round.step, RoundStep::Prevote);
    assert_eq!(
        state.round.proposal.as_ref().expect("proposal").block_hash,
        pb.block_hash
    );

    // build 只读：head / store state root 不变（不 commit / 不推进 / 不写 WAL）。
    let head_after = runtime.block_production().unwrap().head().clone();
    let root_after = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    assert_eq!(head_after, head_before, "head unchanged（无 head advance）");
    assert_eq!(root_after, root_before, "store unchanged（无 commit）");

    // 幂等：已提案（step=Prevote）⇒ 再次 step 不重复出块。
    runtime.step().expect("step ok");
    let still = runtime.last_proposal().expect("same proposal");
    assert_eq!(still.block_hash, pb.block_hash, "幂等：无第二次 proposal");
}

/// RT-BP-2：timestamp 显式变化 ⇒ BlockHash 变化（无系统时钟；runtime 字段配置）。
#[test]
fn rt_bp_timestamp_changes_block_hash() {
    let kp_a = KeyPair::generate().unwrap();
    let pk_a = kp_a.verifying_key().to_bytes();
    let env_a = Env::new(&genesis_for(pk_a));
    let mut ra = NodeRuntime::start(
        &env_a.config(true, env_a.genesis_hash),
        Some(&SoftwareKeyProvider::from_keypair(kp_a)),
    )
    .expect("validator A 启动");

    let kp_b = KeyPair::generate().unwrap();
    let pk_b = kp_b.verifying_key().to_bytes();
    let env_b = Env::new(&genesis_for(pk_b));
    let mut rb = NodeRuntime::start(
        &env_b.config(true, env_b.genesis_hash),
        Some(&SoftwareKeyProvider::from_keypair(kp_b)),
    )
    .expect("validator B 启动");

    ra.step().expect("A step");
    let ha = ra.last_proposal().expect("A proposal").block_hash;
    rb.set_proposal_timestamp(5);
    rb.step().expect("B step");
    let hb = rb.last_proposal().expect("B proposal").block_hash;
    assert_ne!(ha, hb, "timestamp 显式变化 ⇒ BlockHash 变化");
}
