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
