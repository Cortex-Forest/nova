//! F-3 Node restart / bootstrap 集成测试（PHASE 3 STEP 7-P；ADR-0048 recovery / ADR-0046 / ADR-0010）。
//!
//! - **TEST GENESIS ONLY**：所有 `GenesisV1` 均为测试 fixture（明确注释），非生产 genesis。
//! - 仅使用 `nova_node` / `nova_runtime` / `nova_storage` / `nova_crypto` 既有公开 API；
//!   不触碰 WAL / PersistentBackend internals（Test 11 仅构造损坏的 snapshot 文件以验证
//!   storage 恢复语义被 Node 正确表面为 fail-closed）。

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, VerifyingKey, sign_message_hash};
use nova_crypto::transaction::{TransactionType, TransactionV1, sign_transaction};
use nova_node::bootstrap::{NodeConfig, NodeStartupError, start};
use nova_runtime::{
    AccountChange, BLOCK_VERSION, BlockBody, BlockHeader, KeyResolver, ParentContext,
    TRANSFER_INTRINSIC_GAS, compute_transaction_root, encode_block, encode_block_header,
};
use nova_storage::error::StorageError;
use nova_storage::memory::MemoryBackend;
use nova_storage::node::NodeHash;
use nova_storage::store::StateStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// 单 transfer 固有费用（gas_price=1 ⇒ fee = 21_000）。
const FEE: u128 = TRANSFER_INTRINSIC_GAS as u128;

// ---------------------------------------------------------------------------
// Fixtures（TEST GENESIS ONLY）
// ---------------------------------------------------------------------------

fn addr(key_hash: [u8; 32], net: NetworkId) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: net,
        key_hash,
    })
}

/// TEST GENESIS ONLY：通用 builder；accounts 自动按 payload 升序排序（canonical 要求），
/// validator 取排序后首账户（liquid 须 ≥ bonded_stake）。
fn make_genesis(
    net: NetworkId,
    chain_id: u64,
    max_gas: u64,
    fee_burn: u16,
    mut accounts: Vec<AccountInit>,
) -> GenesisV1 {
    accounts.sort_by_key(|a| a.address.payload().to_bytes());
    let total_supply = accounts.iter().map(|a| a.liquid_balance).sum();
    let validator_account = accounts[0].address;
    GenesisV1 {
        network_id: net,
        chain_id,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: validator_account,
            consensus_public_key: [0xaa; 32],
            bonded_stake: 200_000,
            commission_bps: 0,
        }],
        initial_accounts: accounts,
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: max_gas,
            max_contract_code_bytes: 1024,
            max_contract_storage_bytes: 1024,
            epoch_length_blocks: 1_000,
            snapshot_interval_blocks: 10_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: fee_burn,
        },
    }
}

/// TEST GENESIS ONLY：默认两固定账户（A: 1_000_000 / B: 500_000）。
fn test_genesis(net: NetworkId, chain_id: u64, max_gas: u64, fee_burn: u16) -> GenesisV1 {
    make_genesis(
        net,
        chain_id,
        max_gas,
        fee_burn,
        vec![
            AccountInit {
                address: addr([0x11; 32], net),
                liquid_balance: 1_000_000,
            },
            AccountInit {
                address: addr([0x22; 32], net),
                liquid_balance: 500_000,
            },
        ],
    )
}

/// 测试节点：临时目录 + genesis 文件 + 存储目录。
struct TestNode {
    dir: PathBuf,
    genesis: GenesisV1,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    storage_dir: PathBuf,
}

impl TestNode {
    fn new(net: NetworkId, chain_id: u64) -> Self {
        Self::with_params(net, chain_id, 1_000_000, 0)
    }

    fn with_params(net: NetworkId, chain_id: u64, max_gas: u64, fee_burn: u16) -> Self {
        Self::with_genesis(test_genesis(net, chain_id, max_gas, fee_burn))
    }

    fn with_genesis(genesis: GenesisV1) -> Self {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_f3_{}_{}", std::process::id(), seq));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(&genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(&genesis).unwrap()).unwrap();
        let storage_dir = dir.join("storage");
        TestNode {
            dir,
            genesis,
            genesis_hash,
            genesis_path,
            storage_dir,
        }
    }

    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: self.genesis.chain_id,
            expected_network_id: self.genesis.network_id,
            storage_dir: self.storage_dir.clone(),
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// 最小 KeyResolver（TEST ONLY）：address → verifying key。
#[derive(Clone, Default)]
struct TestKeyRegistry {
    map: HashMap<NovaAddress, VerifyingKey>,
}

impl TestKeyRegistry {
    fn with(entries: impl IntoIterator<Item = (NovaAddress, VerifyingKey)>) -> Self {
        Self {
            map: entries.into_iter().collect(),
        }
    }
}

impl KeyResolver for TestKeyRegistry {
    fn resolve(&self, address: NovaAddress) -> Option<VerifyingKey> {
        self.map.get(&address).copied()
    }
}

/// `GenesisV1.initial_accounts` → AccountChange（created，nonce 0）。
fn genesis_changes(genesis: &GenesisV1) -> Vec<AccountChange> {
    genesis
        .initial_accounts
        .iter()
        .map(|a| AccountChange {
            address: a.address,
            new_balance: a.liquid_balance,
            new_nonce: 0,
            created: true,
        })
        .collect()
}

/// 确定性期望 root：genesis 状态 + 逐轮 changes（probe MemoryBackend；不落盘）。
fn twin_root(genesis: &GenesisV1, rounds: &[&[AccountChange]]) -> NodeHash {
    let mut twin = StateStore::new(MemoryBackend::new());
    twin.apply(&genesis_changes(genesis)).unwrap();
    for round in rounds {
        twin.apply(round).unwrap();
    }
    twin.state_root()
}

// ---------------------------------------------------------------------------
// Block 构建（复用 runtime 冻结语义；TEST ONLY）
// ---------------------------------------------------------------------------

fn signed_tx(
    sender: NovaAddress,
    receiver: NovaAddress,
    nonce: u64,
    amount: u128,
    sk: &SigningKey,
    chain_id: u64,
) -> TransactionV1 {
    let mut tx = TransactionV1 {
        version: 1,
        chain_id,
        nonce,
        sender,
        receiver,
        amount,
        gas_limit: 100_000,
        gas_price: 1,
        transaction_type: TransactionType::Transfer,
        payload: vec![0u8; 140],
        expiration: 1_000_000,
        signature: [0u8; 64],
    };
    sign_transaction(sk, &mut tx).unwrap();
    tx
}

fn block_signature(header: &BlockHeader, sk: &SigningKey, chain_id: u64) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

fn make_valid_block(
    chain_id: u64,
    height: u64,
    parent: &ParentContext,
    tx: TransactionV1,
    state_root: NodeHash,
    proposer_kp: &KeyPair,
) -> nova_runtime::Block {
    let body = BlockBody { txs: vec![tx] };
    let tx_root = compute_transaction_root(&body);
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id,
        height,
        parent_hash: parent.parent_hash,
        finality_reference: None,
        transaction_root: tx_root,
        state_root: *state_root.as_bytes(),
        validator_set_hash: [0x33; 32],
        timestamp: 0,
    };
    nova_runtime::Block {
        header: header.clone(),
        body: body.clone(),
        proposer_signature: block_signature(&header, proposer_kp.signing_key(), chain_id),
    }
}

/// 期望 `start` 失败（fail closed）；成功则 panic。
fn startup_err<R: KeyResolver>(resolver: R, config: &NodeConfig) -> NodeStartupError {
    match start(resolver, config) {
        Err(e) => e,
        Ok(_) => panic!("startup must fail closed"),
    }
}

// ---------------------------------------------------------------------------
// Test 1：fresh directory → bootstrap → 持久化 → reopen → load_with_head
// ---------------------------------------------------------------------------

#[test]
fn test_1_fresh_bootstrap_persist_and_reopen() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    let registry = TestKeyRegistry::default();

    // 首启 bootstrap
    let adapter = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(adapter.head().height, 0, "genesis head height 0");
    assert_eq!(
        adapter.head().block_hash,
        tn.genesis_hash,
        "head.block_hash == genesis_hash"
    );
    drop(adapter);

    // reopen → restart recovery
    let adapter2 = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(adapter2.head().height, 0);
    assert_eq!(
        adapter2.head().block_hash,
        tn.genesis_hash,
        "recovered head == genesis"
    );
    assert_eq!(
        adapter2.head().state_root,
        adapter2.store().state_root(),
        "recovered head.state_root == recovered state_root"
    );
}

// ---------------------------------------------------------------------------
// Test 2/3/4：bootstrap → append block → restart → 恢复 state/head
// ---------------------------------------------------------------------------

#[test]
fn test_2_3_4_restart_preserves_state_and_head() {
    let net = NetworkId::Testnet;
    let kp = KeyPair::generate().unwrap();
    // sender 必须由 kp 派生（7D 签名绑定 key_hash == hash(vk)）。
    let sender =
        NovaAddress::from_verifying_key(kp.verifying_key(), AddressType::UserAccount, net).unwrap();
    let receiver = addr([0x22; 32], net);
    let genesis = make_genesis(
        net,
        1001,
        1_000_000,
        0,
        vec![
            AccountInit {
                address: sender,
                liquid_balance: 1_000_000,
            },
            AccountInit {
                address: receiver,
                liquid_balance: 500_000,
            },
        ],
    );
    let tn = TestNode::with_genesis(genesis);
    let registry = TestKeyRegistry::with([(sender, *kp.verifying_key())]);

    let mut adapter = start(registry.clone(), &tn.config()).unwrap();
    // Block 1: sender→receiver amount 100（fee=FEE，fee_burn=0）
    let ch1 = vec![
        AccountChange {
            address: sender,
            new_balance: 1_000_000 - 100 - FEE,
            new_nonce: 1,
            created: false,
        },
        AccountChange {
            address: receiver,
            new_balance: 500_000 + 100,
            new_nonce: 0,
            created: false,
        },
    ];
    let tx1 = signed_tx(sender, receiver, 0, 100, kp.signing_key(), 1001);
    let parent1 = ParentContext {
        parent_height: 0,
        parent_hash: tn.genesis_hash,
    };
    let root1 = twin_root(&tn.genesis, &[ch1.as_slice()]);
    let block1 = make_valid_block(1001, 1, &parent1, tx1, root1, &kp);
    let head1 = adapter
        .apply_block(&encode_block(&block1).unwrap(), kp.verifying_key())
        .unwrap();
    assert_eq!(head1.height, 1);
    drop(adapter); // 已 flush；模拟关闭

    // restart
    let adapter2 = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(
        adapter2.head(),
        &head1,
        "Test 3: ChainHead preserved across restart"
    );
    assert_eq!(
        adapter2.store().state_root(),
        root1,
        "Test 4: state root preserved"
    );
    assert_eq!(
        adapter2.head().state_root,
        adapter2.store().state_root(),
        "Test 2: recovered state/head consistent"
    );
}

// ---------------------------------------------------------------------------
// Test 5：genesis 修改 ⇒ hash mismatch ⇒ 拒绝
// ---------------------------------------------------------------------------

#[test]
fn test_5_genesis_hash_mismatch_rejected() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    let registry = TestKeyRegistry::default();

    // 首启 bootstrap（原始 genesis）
    let adapter = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(adapter.head().height, 0);
    drop(adapter);

    // 修改 genesis（账户 B 余额 +1 且同步 total_supply ⇒ 合法但 hash 不同）
    let mut modified = tn.genesis.clone();
    modified.initial_accounts[1].liquid_balance += 1;
    modified.economics_parameters.total_supply += 1;
    let new_hash = compute_genesis_hash(&modified).unwrap();
    std::fs::write(
        &tn.genesis_path,
        canonical_genesis_bytes(&modified).unwrap(),
    )
    .unwrap();

    // 用新 hash 的 config 重启 ⇒ recovered head（旧 genesis）≠ 新 hash ⇒ 拒绝
    let mut cfg = tn.config();
    cfg.expected_genesis_hash = new_hash;
    let err = startup_err(registry.clone(), &cfg);
    assert!(
        matches!(err, NodeStartupError::GenesisIdentityMismatch),
        "changed genesis must be rejected on restart, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 6：chain_id mismatch ⇒ 拒绝
// ---------------------------------------------------------------------------

#[test]
fn test_6_chain_id_mismatch_rejected() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    let mut cfg = tn.config();
    cfg.expected_chain_id = 9999;
    let err = startup_err(TestKeyRegistry::default(), &cfg);
    assert!(matches!(err, NodeStartupError::ChainIdMismatch));
}

// ---------------------------------------------------------------------------
// Test 7：network_id mismatch ⇒ 拒绝
// ---------------------------------------------------------------------------

#[test]
fn test_7_network_id_mismatch_rejected() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    let mut cfg = tn.config();
    cfg.expected_network_id = NetworkId::Devnet;
    let err = startup_err(TestKeyRegistry::default(), &cfg);
    assert!(matches!(err, NodeStartupError::NetworkIdMismatch));
}

// ---------------------------------------------------------------------------
// Test 8/9：max_gas / fee_burn 来自 GenesisV1（注入 getter）
// ---------------------------------------------------------------------------

#[test]
fn test_8_9_execution_params_sourced_from_genesis() {
    let tn = TestNode::with_params(NetworkId::Testnet, 1001, 5_000_000, 250);
    let adapter = start(TestKeyRegistry::default(), &tn.config()).unwrap();
    assert_eq!(
        adapter.max_gas_per_block(),
        tn.genesis.protocol_parameters.max_gas_per_block,
        "Test 8: max_gas from GenesisV1"
    );
    assert_eq!(
        adapter.fee_burn_bps(),
        tn.genesis.economics_parameters.fee_burn_bps,
        "Test 9: fee_burn from GenesisV1"
    );
    assert_eq!(adapter.network_id(), NetworkId::Testnet);
    assert_eq!(adapter.chain_id(), 1001);
    assert_eq!(adapter.genesis_hash(), tn.genesis_hash);
}

// ---------------------------------------------------------------------------
// Test 10/12：重启不二次 bootstrap（state root 不变，无第二次 genesis 写入）
// ---------------------------------------------------------------------------

#[test]
fn test_10_12_restart_does_not_second_bootstrap() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    let registry = TestKeyRegistry::default();

    let adapter = start(registry.clone(), &tn.config()).unwrap();
    let root_after_first = adapter.store().state_root();
    let hash_first = adapter.genesis_hash();
    drop(adapter);

    let adapter2 = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(
        adapter2.store().state_root(),
        root_after_first,
        "Test 12: state root unchanged"
    );
    assert_eq!(adapter2.head().height, 0, "no second bootstrap");
    assert_eq!(
        adapter2.head().block_hash,
        hash_first,
        "no second genesis write"
    );
    assert_eq!(adapter2.genesis_hash(), hash_first);
}

// ---------------------------------------------------------------------------
// Test 11：损坏 snapshot ⇒ CorruptedState ⇒ 拒绝启动（fail closed）
// ---------------------------------------------------------------------------

#[test]
fn test_11_corrupted_snapshot_rejected() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    std::fs::create_dir_all(&tn.storage_dir).unwrap();
    std::fs::write(tn.storage_dir.join("snapshot"), [0xffu8; 8]).unwrap();
    let err = startup_err(TestKeyRegistry::default(), &tn.config());
    assert!(
        matches!(err, NodeStartupError::Storage(StorageError::CorruptedState)),
        "corrupted storage must surface as fail-closed startup error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 13：首启 state + head 原子持久化（同一恢复边界）
// ---------------------------------------------------------------------------

#[test]
fn test_13_state_head_atomic_persistence() {
    let tn = TestNode::new(NetworkId::Testnet, 1001);
    // 首启 bootstrap
    start(TestKeyRegistry::default(), &tn.config()).unwrap();
    // 重启后 head 与 state 必须同时存在且一致（load_with_head cross-check 已过）
    let adapter2 = start(TestKeyRegistry::default(), &tn.config()).unwrap();
    assert_eq!(
        adapter2.head().block_hash,
        tn.genesis_hash,
        "head present after bootstrap"
    );
    assert_eq!(
        adapter2.head().state_root,
        adapter2.store().state_root(),
        "state + head recovered at same boundary"
    );
}

// ---------------------------------------------------------------------------
// Test 14：PersistentBackend → StateStore → NodeBlockAdapter 端到端 restart continuation
// ---------------------------------------------------------------------------

#[test]
fn test_14_full_restart_continuation() {
    let net = NetworkId::Testnet;
    let kp = KeyPair::generate().unwrap();
    // sender 由 kp 派生（7D 签名绑定）。
    let sender =
        NovaAddress::from_verifying_key(kp.verifying_key(), AddressType::UserAccount, net).unwrap();
    let receiver = addr([0x22; 32], net);
    let c = addr([0x33; 32], net);
    let genesis = make_genesis(
        net,
        1001,
        1_000_000,
        0,
        vec![
            AccountInit {
                address: sender,
                liquid_balance: 1_000_000,
            },
            AccountInit {
                address: receiver,
                liquid_balance: 500_000,
            },
        ],
    );
    let tn = TestNode::with_genesis(genesis);
    let registry = TestKeyRegistry::with([(sender, *kp.verifying_key())]);

    // ---- 首启 bootstrap ----
    let mut adapter = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(adapter.head().height, 0);
    assert_eq!(adapter.head().block_hash, tn.genesis_hash);

    // Block 1: sender→receiver amount 100
    let ch1 = vec![
        AccountChange {
            address: sender,
            new_balance: 1_000_000 - 100 - FEE,
            new_nonce: 1,
            created: false,
        },
        AccountChange {
            address: receiver,
            new_balance: 500_000 + 100,
            new_nonce: 0,
            created: false,
        },
    ];
    let tx1 = signed_tx(sender, receiver, 0, 100, kp.signing_key(), 1001);
    let parent1 = ParentContext {
        parent_height: 0,
        parent_hash: tn.genesis_hash,
    };
    let root1 = twin_root(&tn.genesis, &[ch1.as_slice()]);
    let block1 = make_valid_block(1001, 1, &parent1, tx1, root1, &kp);
    let head1 = adapter
        .apply_block(&encode_block(&block1).unwrap(), kp.verifying_key())
        .unwrap();
    assert_eq!(head1.height, 1);
    assert_eq!(head1.state_root, root1);
    drop(adapter); // 已 flush；模拟关闭/进程结束

    // ---- 重启：恢复 state + head ----
    let mut adapter2 = start(registry.clone(), &tn.config()).unwrap();
    assert_eq!(adapter2.head(), &head1, "recovered head == committed head");
    assert_eq!(adapter2.store().state_root(), root1, "recovered state root");

    // ---- 继续处理：Block 2（sender→c amount 50，sender nonce=1；c 隐式创建）----
    let ch2 = vec![
        AccountChange {
            address: sender,
            new_balance: 1_000_000 - 100 - FEE - 50 - FEE,
            new_nonce: 2,
            created: false,
        },
        AccountChange {
            address: c,
            new_balance: 50,
            new_nonce: 0,
            created: true,
        },
    ];
    let tx2 = signed_tx(sender, c, 1, 50, kp.signing_key(), 1001);
    let parent2 = ParentContext {
        parent_height: 1,
        parent_hash: head1.block_hash,
    };
    let root2 = twin_root(&tn.genesis, &[ch1.as_slice(), ch2.as_slice()]);
    let block2 = make_valid_block(1001, 2, &parent2, tx2, root2, &kp);
    let head2 = adapter2
        .apply_block(&encode_block(&block2).unwrap(), kp.verifying_key())
        .unwrap();
    assert_eq!(
        head2.height, 2,
        "continuation applies next block after restart"
    );
    assert_eq!(head2.state_root, root2);
    assert_eq!(head2.parent_hash, head1.block_hash);
}
