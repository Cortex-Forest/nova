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
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use nova_consensus::dag::{BlockReference, Dag};
use nova_consensus::error::ConsensusError;
use nova_consensus::finality::{FinalityError, QuorumCertificate, decode_qc, encode_qc, verify_qc};
use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::address::NetworkId;
use nova_crypto::hash::protocol_hash;
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
    /// 入站 listener 绑定地址（D9 Step 7；node-local，非协议）。
    ///
    /// - `None`（默认）⇒ **不启用** listener：节点行为与 D9 Step 7 之前**完全一致**（无 bind /
    ///   无 accept / 注入 transport 原样使用）。
    /// - `Some(addr)` ⇒ 启用 node-only 入站 listener（nonblocking + 每 step 有界 accept）；
    ///   仅在**网络已装配**（`start_with_network`）时生效 —— 无 `NetworkService` 时忽略。
    /// - 绑定失败（地址占用 / 权限）⇒ 启动 fail-closed（`NodeRuntimeError::InboundListener`）。
    pub listen_addr: Option<SocketAddr>,
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
    /// Finality Recovery Fact：文件 / 结构损坏（magic / version / 长度 / checksum / 字段边界）。
    FinalityFactCorrupt,
    /// Finality Recovery Fact：chain identity（network_id / chain_id / genesis_hash）不匹配。
    FinalityFactIdentityMismatch,
    /// Finality Recovery Fact：`finalized_reference != QC.target`。
    FinalityFactTargetMismatch,
    /// Finality Recovery Fact：height 与 QC / block 不一致（canonical-next parent-round 关系）。
    FinalityFactHeightMismatch,
    /// Finality Recovery Fact：QC 结构 / 验证失败（decode_qc / verify_qc / 非 Precommit）。
    FinalityFactQc(FinalityError),
    /// Finality Recovery Fact：finalized_reference 对应 block 缺失于 BlockStore。
    FinalityFactMissingBlock,
    /// Finality Recovery Fact：与 canonical head 关系冲突（同高异 hash / unrelated / 高度异常）。
    FinalityFactHeadConflict,
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

// =========================================================================
// D10-C Step 4 — Finality Recovery Fact（node-local；最小 + fail-closed）
//
// 目标：`Finality(X) 已达成 → commit 前 crash → restart` 时，从 durable fact 恢复
// `X was finalized`，使既有 D10-B bridge 能继续 commit X —— 不持久化完整 ConsensusState、
// 不改 frozen consensus/crypto/core/storage/network、不伪造 finality。
//
// 格式（deterministic，node-only；无第二套协议 wire）：
//   magic(4) ‖ version(1) ‖ network_id(1) ‖ chain_id(8 LE) ‖ genesis_hash(32)
//   ‖ height(8 LE) ‖ finalized_reference(32) ‖ qc_len(4 LE) ‖ qc(encode_qc)
//   ‖ checksum(32 = SHA-256(上述全部))
//
// 语义：`finalized_reference == qc.target` 且 `qc.context.height + 1 == height`
// （V0.1 canonical-next：块在 round.height 的 canonical-next ⇒ 块高 = QC 轮高 + 1）。
// 读取侧任何损坏 / identity 失配 / QC 失败 / block 缺失 / 高度 / head 关系冲突 ⇒ `Err`
// （fail-closed；绝不当「无 fact」、绝不 ignore、绝不自动覆写损坏文件）。
// =========================================================================

/// Finality Recovery Fact 文件名（chain storage 目录下；与 canonical block 文件分离）。
pub const FINALITY_FACT_FILE: &str = "finality_fact.bin";

/// Fact magic（'NVFF'）。
const FINALITY_FACT_MAGIC: [u8; 4] = *b"NVFF";
/// Fact 版本（V0.1）。
const FINALITY_FACT_VERSION: u8 = 1;
/// 定长前缀：magic(4)+version(1)+network(1)+chain(8)+genesis(32)+height(8)+ref(32)+qc_len(4)。
const FACT_FIXED_LEN: usize = 4 + 1 + 1 + 8 + 32 + 8 + 32 + 4;

/// 解析后的 Recovery Fact（结构级；未做 identity / block / QC 语义验证）。
struct ParsedFact {
    network_id: u8,
    chain_id: u64,
    genesis_hash: [u8; 32],
    height: u64,
    reference: [u8; 32],
    qc: QuorumCertificate,
}

/// 原子写（tmp + fsync + rename；仿 storage `atomic_write`；同目录 rename 覆盖既有 fact）。
fn atomic_write_fact(path: &Path, bytes: &[u8]) -> Result<(), NodeStartupError> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp).map_err(|_| NodeStartupError::StorageIo)?;
    file.write_all(bytes)
        .map_err(|_| NodeStartupError::StorageIo)?;
    file.sync_all().map_err(|_| NodeStartupError::StorageIo)?;
    drop(file);
    fs::rename(&tmp, path).map_err(|_| NodeStartupError::StorageIo)?;
    Ok(())
}

/// 编码 Recovery Fact（结构级；`reference == qc.target` 由调用方契约保证，此处防御检查）。
fn encode_fact(
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    height: u64,
    reference: [u8; 32],
    qc: &QuorumCertificate,
) -> Result<Vec<u8>, NodeStartupError> {
    if reference != qc.target {
        return Err(NodeStartupError::FinalityFactTargetMismatch);
    }
    let qc_bytes = encode_qc(qc);
    if qc_bytes.len() > u32::MAX as usize {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    let mut out = Vec::with_capacity(FACT_FIXED_LEN + qc_bytes.len() + 32);
    out.extend_from_slice(&FINALITY_FACT_MAGIC);
    out.push(FINALITY_FACT_VERSION);
    out.push(network_id.as_u8());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&genesis_hash);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&reference);
    out.extend_from_slice(&(qc_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&qc_bytes);
    let checksum = protocol_hash(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// 严格解析（magic → version → 长度边界 → 字段 → checksum → QC decode）；任一失败 ⇒ `Err`。
fn parse_fact(bytes: &[u8]) -> Result<ParsedFact, NodeStartupError> {
    if bytes.len() < FACT_FIXED_LEN + 32 {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    if bytes[0..4] != FINALITY_FACT_MAGIC {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    if bytes[4] != FINALITY_FACT_VERSION {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    let network_id = bytes[5];
    let chain_id = u64::from_le_bytes(
        bytes[6..14]
            .try_into()
            .map_err(|_| NodeStartupError::FinalityFactCorrupt)?,
    );
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&bytes[14..46]);
    let height = u64::from_le_bytes(
        bytes[46..54]
            .try_into()
            .map_err(|_| NodeStartupError::FinalityFactCorrupt)?,
    );
    let mut reference = [0u8; 32];
    reference.copy_from_slice(&bytes[54..86]);
    let qc_len = u32::from_le_bytes(
        bytes[86..90]
            .try_into()
            .map_err(|_| NodeStartupError::FinalityFactCorrupt)?,
    ) as usize;
    let qc_start = FACT_FIXED_LEN;
    let qc_end = qc_start
        .checked_add(qc_len)
        .ok_or(NodeStartupError::FinalityFactCorrupt)?;
    let checksum_start = qc_end
        .checked_add(32)
        .ok_or(NodeStartupError::FinalityFactCorrupt)?;
    if checksum_start != bytes.len() {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    let computed = protocol_hash(&bytes[..qc_end]);
    if computed != bytes[qc_end..checksum_start] {
        return Err(NodeStartupError::FinalityFactCorrupt);
    }
    let qc = decode_qc(&bytes[qc_start..qc_end]).map_err(NodeStartupError::FinalityFactQc)?;
    Ok(ParsedFact {
        network_id,
        chain_id,
        genesis_hash,
        height,
        reference,
        qc,
    })
}

/// D10-C Step 4 — 持久化 Finality Recovery Fact（原子写；durable-before-bridge）。
///
/// - 调用方契约：`reference == qc.target` 且 `qc` 为已验证 PrecommitQC（本函数防御检查
///   `reference == qc.target`）；`height` = finalized block 高度（= `qc.context.height + 1`）。
/// - 幂等由调用方避免重复写（同 reference 重写同内容亦无害）。
/// - 失败 ⇒ `Err`（fail-closed；不影响 canonical commit —— commit 由 bridge 后续执行）。
pub fn persist_finality_fact(
    path: &Path,
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    height: u64,
    reference: [u8; 32],
    qc: &QuorumCertificate,
) -> Result<(), NodeStartupError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| NodeStartupError::StorageIo)?;
    }
    let bytes = encode_fact(network_id, chain_id, genesis_hash, height, reference, qc)?;
    atomic_write_fact(path, &bytes)
}

/// 结构级读取（magic / version / 长度 / checksum / 字段边界 / QC decode；**不**执行
/// identity / block / QC 语义验证）。无 fact 文件 ⇒ `Ok(None)`。测试 / 审计探测。
pub fn read_finality_fact(path: &Path) -> Result<Option<(u64, [u8; 32])>, NodeStartupError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|_| NodeStartupError::StorageIo)?;
    let fact = parse_fact(&bytes)?;
    Ok(Some((fact.height, fact.reference)))
}

/// D10-C Step 4 — restart 时 Finality Recovery Fact 恢复（校验全通过才返回待注入 reference）。
///
/// 校验链（任一步失败 ⇒ `Err`，fail-closed）：
/// 1. identity（network_id / chain_id / genesis_hash）；2. QC 为 Precommit 且
///    `reference == qc.target`；3. `qc.context.height + 1 == height`（canonical-next parent-round）；
/// 4. `reference` 已在 committed DAG ⇒ fact 已满足（**幂等 / stale ignore** —— 不注入、不回退）；
/// 5. `BlockStore.get(reference)` 存在且 `block.header.height == height`；
/// 6. canonical head 关系：未 commit 时要求 X 是 head 的严格 child（`parent == head.block_hash ∧
///    height == head.height + 1`），否则 ⇒ `FinalityFactHeadConflict`（同高异 hash / unrelated /
///    高度异常；**绝不选择 / 绝不猜测**）；
/// 7. 加 genesis 根（若 rebuild 空 DAG 且 head == genesis）→ `Dag::add_block(X)`（真实 parent /
///    height / `select_proposer` 推导 proposer）→ `verify_qc(qc, set, genesis, dag_with_X)`。
///
/// 返回 `(dag, Option<X>)`：`Some(X)` = 恢复注入目标（未 commit 且 QC/block/DAG 全通过）。
pub fn restore_finality_fact(
    path: &Path,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    set: &ValidatorSet,
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    mut dag: Dag,
) -> Result<(Dag, Option<[u8; 32]>), NodeStartupError> {
    // 无 fact ⇒ 正常启动（无恢复）。
    if !path.exists() {
        return Ok((dag, None));
    }
    let bytes = fs::read(path).map_err(|_| NodeStartupError::StorageIo)?;
    let fact = parse_fact(&bytes)?;

    // Check 1 — chain identity（防跨链 / 换链 fact）。
    if fact.network_id != network_id.as_u8()
        || fact.chain_id != chain_id
        || fact.genesis_hash != genesis_hash
    {
        return Err(NodeStartupError::FinalityFactIdentityMismatch);
    }
    // Check 2/3 — QC 语义（Precommit / target == reference / canonical-next parent-round 高度）。
    if fact.qc.context.vote_type != VoteType::Precommit {
        return Err(NodeStartupError::FinalityFactQc(
            FinalityError::NotPrecommitQc,
        ));
    }
    if fact.reference != fact.qc.target {
        return Err(NodeStartupError::FinalityFactTargetMismatch);
    }
    if fact.height != fact.qc.context.height.saturating_add(1) {
        return Err(NodeStartupError::FinalityFactHeightMismatch);
    }

    // 已在 committed canonical ancestry ⇒ fact 已满足（幂等 / stale ignore —— 不回退 head）。
    if dag.contains(&fact.reference) {
        return Ok((dag, None));
    }

    // Check 5 — block 存在 + 高度一致（get 已 strict decode + hash 重算 == key）。
    let block_store = adapter
        .block_store()
        .ok_or(NodeStartupError::FinalityFactCorrupt)?;
    let block = match block_store
        .get(&fact.reference)
        .map_err(NodeStartupError::Storage)?
    {
        Some(b) => b,
        None => return Err(NodeStartupError::FinalityFactMissingBlock),
    };
    if block.header.height != fact.height {
        return Err(NodeStartupError::FinalityFactHeightMismatch);
    }

    // Check 6 — canonical head 关系：未 commit ⇒ X 必须是 head 的严格 child（否则冲突）。
    let head = adapter.head();
    let is_child_of_head = block.header.parent_hash == head.block_hash
        && block.header.height == head.height.saturating_add(1);
    if !is_child_of_head {
        return Err(NodeStartupError::FinalityFactHeadConflict);
    }

    // Check 7 — 加入 recovery DAG（frozen `Dag::add_block`）+ QC 验证。
    //    head == genesis（无 committed 块）时 rebuild 返回空 DAG ⇒ 先加 genesis 根作 X 的 parent。
    if !dag.contains(&genesis_hash) {
        dag.add_block(BlockReference {
            block_hash: genesis_hash,
            height: 0,
            parents: Vec::new(),
            proposer: ValidatorId::from_bytes([0u8; 32]),
        })
        .map_err(|_| NodeStartupError::FinalityFactHeadConflict)?;
    }
    // proposer（V0.1 parent-height 语义；与 D9 / block_adapter / rebuild 同源 —— 不新造规则）。
    let proposer = select_proposer(
        chain_id,
        block.header.height.saturating_sub(1),
        0,
        &genesis_hash,
        set,
    )
    .map_err(|_| NodeStartupError::FinalityFactHeadConflict)?;
    dag.add_block(BlockReference {
        block_hash: fact.reference,
        height: block.header.height,
        parents: vec![block.header.parent_hash],
        proposer,
    })
    .map_err(|_| NodeStartupError::FinalityFactHeadConflict)?;

    // QC 验证（`verify_qc` 要求 target ∈ DAG —— X 已加入）。
    verify_qc(&fact.qc, set, &genesis_hash, &dag).map_err(NodeStartupError::FinalityFactQc)?;

    Ok((dag, Some(fact.reference)))
}
