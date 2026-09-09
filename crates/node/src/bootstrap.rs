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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::error::ConsensusError;
use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::NetworkId;
use nova_crypto::identity::{
    AccountInit, ChainIdentity, GenesisError, GenesisV1, decode_genesis_bytes,
    validate_genesis_with_expected,
};
use nova_network::node_id::NodeId;
use nova_network::transport::ConnectionTarget;
use nova_runtime::{AccountChange, BlockPipelineError, KeyResolver};
use nova_storage::block_store::BlockStore;
use nova_storage::error::StorageError;
use nova_storage::head::HeadRecord;
use nova_storage::persistent::PersistentBackend;
use nova_storage::state_root::calculate_state_root;
use nova_storage::store::StateStore;
use nova_storage::trie::EMPTY_STATE_ROOT;

use crate::block_adapter::{
    ChainHead, NoAccountsKeyResolver, NodeBlockAdapter, NodeBlockApplicationError,
};
use crate::key_provider::KeyProviderConfig;

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
    /// 持久化存储目录（canonical chain storage）。
    pub storage_dir: PathBuf,
    /// 是否启用验证者模式（STEP 10-16；默认 false：不初始化 signer / safety / validator）。
    pub validator_enabled: bool,
    /// validator safety journal 目录（STEP 10-16；仅 validator_enabled=true；与 storage_dir 分离）。
    pub safety_dir: PathBuf,
    /// KeyProvider 配置（STEP 10-16 Phase 1：`None` = 由调用方注入 provider 实例）。
    pub key_provider_config: KeyProviderConfig,
    /// 静态 configured connection targets（STEP 10-19-10-B7-A3；`[]` = 无网络 peer，合法）。
    /// 仅 initial connection targets（不 discovery / 不自动连接策略）。
    pub peers: Vec<ConnectionTarget>,
}

/// configured connection target 校验错误（node-local config 域；dial **前**失败，fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTargetError {
    /// `peer_id == self_id`（自我连接；dial 前拒绝）。
    SelfTarget { peer_id: NodeId },
    /// 同一 `peer_id` 配置多次。
    DuplicateNodeId { peer_id: NodeId },
    /// 同一 `address` 配置多次。
    DuplicateAddress { address: SocketAddr },
}

impl NodeConfig {
    /// 校验 configured connection targets（dial **前**；`self_id` 供自我连接检测）。
    ///
    /// 结构级（SocketAddr 由标准类型保证 IP/port）；**不**解析字符串、不新增 address parser。
    /// 允许 loopback / private（测试与 LAN 需要）；生产 policy 另开 STEP。
    pub fn validate_network_targets(&self, self_id: NodeId) -> Result<(), ConnectionTargetError> {
        let mut seen_ids: Vec<NodeId> = Vec::with_capacity(self.peers.len());
        let mut seen_addrs: Vec<SocketAddr> = Vec::with_capacity(self.peers.len());
        for t in &self.peers {
            if t.peer_id == self_id {
                return Err(ConnectionTargetError::SelfTarget { peer_id: t.peer_id });
            }
            if seen_ids.contains(&t.peer_id) {
                return Err(ConnectionTargetError::DuplicateNodeId { peer_id: t.peer_id });
            }
            if seen_addrs.contains(&t.address) {
                return Err(ConnectionTargetError::DuplicateAddress { address: t.address });
            }
            seen_ids.push(t.peer_id);
            seen_addrs.push(t.address);
        }
        Ok(())
    }
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
    /// DAG 重建：canonical head > genesis 但 adapter 无 BlockStore（装配不一致；fail closed）。
    DagRebuildNoBlockStore,
    /// DAG 重建失败（共识规则 / proposer 推导；consensus 错误原样传递；fail closed）。
    DagRebuild(ConsensusError),
    /// DAG 重建：canonical ancestry 中某块缺失（head / 祖先块不在 BlockStore；fail closed）。
    DagRebuildMissingAncestor([u8; 32]),
    /// DAG 重建：parent 链成环（未达 genesis；fail closed）。
    DagRebuildCycle([u8; 32]),
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
    //    同时装配 BlockStore（canonical block commit；chain storage 目录下 blocks/ 子目录）。
    let block_store =
        BlockStore::open(&config.storage_dir.join("blocks")).map_err(NodeStartupError::Storage)?;
    let adapter = NodeBlockAdapter::with_block_store(
        store,
        resolver,
        identity.chain_id,
        identity.genesis_hash,
        genesis.protocol_parameters.max_gas_per_block,
        genesis.economics_parameters.fee_burn_bps,
        head,
        identity.network_id,
        Some(block_store),
    );
    // 恢复一致性（BC-1/R-2..R-4）：重启后 head 指向的 canonical block 必须存在且与 head 一致；
    // 缺失 / 损坏 / mismatch ⇒ fail closed（不自动跳过 / 不静默恢复）。
    adapter.verify_committed_head_block().map_err(|e| {
        NodeStartupError::Storage(match e {
            NodeBlockApplicationError::Pipeline(BlockPipelineError::Storage(s)) => s,
            _ => StorageError::CorruptedState,
        })
    })?;
    Ok(adapter)
}

/// genesis 文件 → decode → validate（expected hash / chain_id / network_id）。任一失败 ⇒ `Err`。
pub(crate) fn load_genesis(
    config: &NodeConfig,
) -> Result<(GenesisV1, ChainIdentity), NodeStartupError> {
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

/// D10-C Step 2 — restart 后 Consensus DAG 重建（canonical ancestry；consensus-not-persisted seam）。
///
/// 从 canonical head 沿 committed BlockStore 的 parent 链回溯至 genesis，重建 frozen `Dag`：
/// genesis 根（height 0；无 block 文件）+ 每个 canonical committed 块的 [`BlockReference`]
/// （真实 `header.height` + 单 parent 边 + `proposer` 由 `select_proposer(chain_id, height-1, 0,
/// genesis_hash, set)` 推导 —— 父高轮，与 vote / QC 轮高语义及 block_adapter V0.1 一致）。
/// reference 按自底向上（genesis → … → head）顺序加入 ⇒ 复用 frozen `Dag::add_block` 校验
/// （parent 已存在 / `parent.height < height`），**不改共识层**。
///
/// - **fail closed**：head / 祖先块缺失 ⇒ `DagRebuildMissingAncestor`；BlockStore 记录损坏
///   （strict decode / hash 重算失败）⇒ `Storage(CorruptedState)`；parent 链成环（未达 genesis）
///   ⇒ `DagRebuildCycle`；高度 / parent 不合法（add_block 拒）或 proposer 推导失败 ⇒
///   `DagRebuild(ConsensusError)`。无 skip / 无 partial / 无 fallback。
/// - **幂等**：每次重建全新 `Dag`（同输入 ⇒ 同结果；构造 `ConsensusNode::new(…, dag)` 前调用）。
/// - 不扫全 BlockStore / 不混 fork：只沿 `head → parent → … → genesis` 单条 canonical 链。
/// - head == genesis（首启 / 无 committed block）⇒ **空 `Dag`**（与既有 fresh-start 语义完全一致）；
///   仅当存在 committed canonical 块时才加 genesis 根 + 回溯链。
pub fn rebuild_consensus_dag(
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    set: &ValidatorSet,
) -> Result<Dag, NodeStartupError> {
    let genesis_hash = adapter.genesis_hash();
    let chain_id = adapter.chain_id();
    let head = adapter.head();

    // 首启 / 无 committed canonical block ⇒ 空 DAG（保持既有行为；无历史可重建）。
    if head.height == 0 {
        return Ok(Dag::new());
    }

    let mut dag = Dag::new();
    // genesis 根：无对应 block 文件（协议初始承诺）；height 0、parent 空。
    // proposer 用占位（genesis 非投票 / lock 目标 —— 仅供 DAG 结构锚，不参与 authorize）。
    dag.add_block(BlockReference {
        block_hash: genesis_hash,
        height: 0,
        parents: Vec::new(),
        proposer: ValidatorId::from_bytes([0u8; 32]),
    })
    .map_err(NodeStartupError::DagRebuild)?;

    let block_store = adapter
        .block_store()
        .ok_or(NodeStartupError::DagRebuildNoBlockStore)?;

    // 1. 沿 parent 链回溯收集 canonical ancestry（head → … → 最低 committed 块）；
    //    祖先缺失 / 成环 ⇒ fail closed（get 本身对损坏记录 strict decode ⇒ CorruptedState）。
    let mut ancestry = vec![head.block_hash];
    let mut visited: HashSet<[u8; 32]> = HashSet::from([head.block_hash]);
    let mut cur = head.block_hash;
    loop {
        let block = match block_store.get(&cur).map_err(NodeStartupError::Storage)? {
            Some(b) => b,
            None => return Err(NodeStartupError::DagRebuildMissingAncestor(cur)),
        };
        // 最低 committed 块：其 parent 即 genesis（回溯终止；genesis 不在 BlockStore）。
        if block.header.parent_hash == genesis_hash {
            break;
        }
        let parent = block.header.parent_hash;
        if !visited.insert(parent) {
            return Err(NodeStartupError::DagRebuildCycle(parent));
        }
        ancestry.push(parent);
        cur = parent;
    }

    // 2. 自底向上（最低 committed → head）逐个登记：parent（更低层）已先入 ⇒
    //    `Dag::add_block` 的 parent 存在 + `parent.height < height` 校验通过
    //    （高度不合法 ⇒ 拒 ⇒ fail closed）。
    for &hash in ancestry.iter().rev() {
        let block = match block_store.get(&hash).map_err(NodeStartupError::Storage)? {
            Some(b) => b,
            None => return Err(NodeStartupError::DagRebuildMissingAncestor(hash)),
        };
        // proposer 推导：该块是 round = header.height - 1 的 canonical-next（V0.1 父高轮语义）。
        let proposer = select_proposer(
            chain_id,
            block.header.height.saturating_sub(1),
            0,
            &genesis_hash,
            set,
        )
        .map_err(NodeStartupError::DagRebuild)?;
        dag.add_block(BlockReference {
            block_hash: hash,
            height: block.header.height,
            parents: vec![block.header.parent_hash],
            proposer,
        })
        .map_err(NodeStartupError::DagRebuild)?;
    }
    Ok(dag)
}
