//! Node 启动 / 重启编排（PHASE 3 STEP 7-P；F-3 —— ADR-0048 recovery / ADR-0046 / ADR-0010）。
//!
//! # 职责（单一）
//! - genesis 文件加载 / decode / validate（既有 `nova-crypto` API；**不重造**编码 / hash / 校验）。
//! - first-start vs restart 判定（durable evidence = recovered head + EMPTY state；非内存 / 非布尔 / 非时间戳）。
//! - first-start bootstrap：`initial_accounts → AccountChange → calculate_state_root → HeadRecord
//!   → enqueue_head → apply_block`（state + head 同一持久化边界，R-10）。
//! - restart recovery：`load_with_head` 恢复 state + head；genesis identity 校验
//!   （hash / chain_id / network_id）；协议参数提取；`NodeBlockAdapter` 构造。
//! - **Fail closed**：任何失败 ⇒ `Err`；无 fallback / 无默认 genesis / 无 Mainnet 默认。
//!
//! # 边界
//! - 不触碰 runtime / execution / consensus / storage backend internals / WAL。
//! - 不修改 runtime ⑥ / `ExecutionContext` 语义 / 协议。

use std::path::PathBuf;

use nova_crypto::address::NetworkId;
use nova_crypto::identity::{
    AccountInit, ChainIdentity, GenesisError, GenesisV1, decode_genesis_bytes,
    validate_genesis_with_expected,
};
use nova_runtime::{AccountChange, KeyResolver};
use nova_storage::error::StorageError;
use nova_storage::head::HeadRecord;
use nova_storage::persistent::PersistentBackend;
use nova_storage::state_root::calculate_state_root;
use nova_storage::store::StateStore;
use nova_storage::trie::EMPTY_STATE_ROOT;

use crate::block_adapter::{ChainHead, NodeBlockAdapter};

/// 节点启动配置（F-3 最小；Node-local，非协议）。
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// genesis 文件路径（canonical genesis bytes；ADR-0015 / genesis-v1.md）。
    pub genesis_path: PathBuf,
    /// 期望 genesis hash（启动校验；ADR-0010 §5 configured hash）。
    pub expected_genesis_hash: [u8; 32],
    /// 期望 chain_id（须 == `GenesisV1.chain_id`；ADR-0010 §5）。
    pub expected_chain_id: u64,
    /// 期望 network_id（须 == `GenesisV1.network_id`；ADR-0010 §5 / genesis-v1.md §15）。
    pub expected_network_id: NetworkId,
    /// 持久化存储目录。
    pub storage_dir: PathBuf,
}

/// Node 启动错误（Node-local；typed，不 String 化 / 不 Box 隐藏）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStartupError {
    /// genesis 文件不可读 / 不存在。
    GenesisRead,
    /// genesis decode 失败。
    GenesisDecode(GenesisError),
    /// genesis 校验失败（含 computed != expected hash；ADR-0010 §5 / genesis-v1.md §13）。
    GenesisValidation(GenesisError),
    /// 存储打开 / 恢复 / 持久化失败（PersistentBackend / StateStore）。
    Storage(StorageError),
    /// 存储目录创建失败。
    StorageIo,
    /// recovered head 与 genesis 不匹配（genesis 改变 / 换链；R-3/R-8）。
    GenesisIdentityMismatch,
    /// `genesis.chain_id != expected_chain_id`（R-4/R-8）。
    ChainIdMismatch,
    /// `genesis.network_id != expected_network_id`（R-5/R-8）。
    NetworkIdMismatch,
    /// head 缺失但 state 非空（legacy / 异常）：不 bootstrap，拒绝启动（R-6）。
    MissingHeadWithState,
}

/// 完整节点启动：first-start bootstrap 或 restart recovery，返回已构造的适配器。
///
/// - genesis 校验先于 execution-critical 参数使用（`load_genesis`）。
/// - 首启（`head == None ∧ state == EMPTY`）⇒ bootstrap；重启（`head == Some`）⇒ recovery；
///   `head == None ∧ state 非空` ⇒ `MissingHeadWithState`（fail closed）。
/// - 重启**不**重新 bootstrap genesis（R-1）；**不**修改 recovered head（R-7）。
pub fn start<R: KeyResolver>(
    resolver: R,
    config: &NodeConfig,
) -> Result<NodeBlockAdapter<PersistentBackend, R>, NodeStartupError> {
    // 1. genesis：load → decode → validate（expected hash / chain_id / network_id）。
    let (genesis, identity) = load_genesis(config)?;

    // 2. storage：创建目录（幂等）→ 打开 → 恢复 state + head。
    std::fs::create_dir_all(&config.storage_dir).map_err(|_| NodeStartupError::StorageIo)?;
    let backend =
        PersistentBackend::open(&config.storage_dir).map_err(NodeStartupError::Storage)?;
    let (mut store, recovered) =
        StateStore::load_with_head(backend).map_err(NodeStartupError::Storage)?;

    // 3. 分支：first-start vs restart。
    let head = match recovered {
        Some(recovered_head) => {
            // 重启：恢复 head；不 bootstrap。
            // genesis 身份：链未推进（height 0）时 recovered head 即 genesis head，其 block_hash
            // 必须 == genesis_hash（storage 起源与 genesis 文件一致；R-8）。链已推进（height > 0）
            // 时 head 为最新块哈希，genesis 身份由 `expected_genesis_hash`（validate_genesis_with_expected）
            // 与 chain_id / network_id 锚定（HeadRecord 仅持久化当前 head，不携带 genesis 锚）。
            if recovered_head.height == 0 && recovered_head.block_hash != identity.genesis_hash {
                return Err(NodeStartupError::GenesisIdentityMismatch);
            }
            ChainHead {
                height: recovered_head.height,
                block_hash: recovered_head.block_hash,
                state_root: recovered_head.state_root,
                parent_hash: recovered_head.parent_hash,
            }
        }
        None if store.state_root().as_bytes() == &EMPTY_STATE_ROOT => {
            // 首启：bootstrap genesis（state + head 同批持久化，R-10）。
            bootstrap(&mut store, &genesis, &identity)?
        }
        None => return Err(NodeStartupError::MissingHeadWithState),
    };

    // 4. 参数提取 + 适配器构造（全部来自 genesis；Node 不自行决定）。
    Ok(NodeBlockAdapter::new(
        store,
        resolver,
        identity.chain_id,
        identity.genesis_hash,
        genesis.protocol_parameters.max_gas_per_block,
        genesis.economics_parameters.fee_burn_bps,
        head,
        identity.network_id,
    ))
}

/// genesis 文件 → decode → validate（expected hash / chain_id / network_id）。任一失败 ⇒ `Err`。
fn load_genesis(config: &NodeConfig) -> Result<(GenesisV1, ChainIdentity), NodeStartupError> {
    let bytes = std::fs::read(&config.genesis_path).map_err(|_| NodeStartupError::GenesisRead)?;
    let genesis = decode_genesis_bytes(&bytes).map_err(NodeStartupError::GenesisDecode)?;
    let identity = validate_genesis_with_expected(&genesis, &config.expected_genesis_hash)
        .map_err(NodeStartupError::GenesisValidation)?;
    if identity.chain_id != config.expected_chain_id {
        return Err(NodeStartupError::ChainIdMismatch);
    }
    if identity.network_id != config.expected_network_id {
        return Err(NodeStartupError::NetworkIdMismatch);
    }
    Ok((genesis, identity))
}

/// 首启 bootstrap：`initial_accounts → changes → root → HeadRecord → enqueue_head → apply_block`。
///
/// `enqueue_head` 在 `apply_block` **之前**调用 ⇒ 单 WAL 批次（state + head）同 checksum 同 fsync（R-10）。
fn bootstrap(
    store: &mut StateStore<PersistentBackend>,
    genesis: &GenesisV1,
    identity: &ChainIdentity,
) -> Result<ChainHead, NodeStartupError> {
    let changes = genesis_changes(&genesis.initial_accounts);
    let tx_refs: Vec<&[AccountChange]> = vec![changes.as_slice()];
    // 确定性 genesis state root（空 store ⇒ 从空推导；ADR-0030 C-3）。
    let genesis_root = calculate_state_root(store, &tx_refs).map_err(NodeStartupError::Storage)?;
    let genesis_head = HeadRecord {
        height: 0,
        block_hash: identity.genesis_hash,
        parent_hash: [0u8; 32],
        state_root: genesis_root,
    };
    store
        .enqueue_head(genesis_head)
        .map_err(NodeStartupError::Storage)?;
    store
        .apply_block(&tx_refs)
        .map_err(NodeStartupError::Storage)?;
    Ok(ChainHead::genesis(identity.genesis_hash, genesis_root))
}

/// `AccountInit`（address + liquid_balance）→ `AccountChange`（created，nonce 0）。
fn genesis_changes(accounts: &[AccountInit]) -> Vec<AccountChange> {
    accounts
        .iter()
        .map(|a| AccountChange {
            address: a.address,
            new_balance: a.liquid_balance,
            new_nonce: 0,
            created: true,
        })
        .collect()
}
