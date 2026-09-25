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
use nova_crypto::signature::VerifyingKey;
use nova_network::node_id::NodeId;
use nova_network::transport::ConnectionTarget;
use nova_runtime::{
    AccountChange, Block, BlockPipelineError, KeyResolver, validate_block_signature,
};
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
use crate::qc_history::QcHistory;

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
    /// Finality Recovery Fact **写入侧**：同高度但**证据内容不同** ⇒ 拒绝覆盖（fail-closed）。
    ///
    /// D11-25（Owner 冻结，D4）：finality evidence 是**证据对象**（不只是 block reference 一个
    /// 字段）⇒ 同高度**仅**允许**完整编码字节一致**（idempotent no-op）。两种形态均拒绝：
    ///   · 同高度 + 不同 reference；
    ///   · 同高度 + 同 reference + 不同 QC / evidence / 其它编码字节。
    /// 属 **IMPLEMENTATION SAFETY INVARIANT**（**非**协议规则 / **非**共识规则；保护对象 =
    /// durable evidence，**不是** `finalized_reference`，**不是** canonical head）。
    ///
    /// 注意（D11-25 D3）：`new.height < existing.height`（runtime `R` 落到已有 evidence 之下）
    /// **不是**错误 —— 见 [`persist_finality_fact`]：不写 + 非致命继续。
    FinalityFactSameHeightConflict,
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
/// **P1-A.20-C Phase 2** —— 历史块的 proposer 解析（**不再硬编码 round 0**）。
///
/// 顺序（均为**既有** authority / 既有验证；无新授权 / 无 round-0 回退 / 无伪造）：
/// 1. **QC 优先（target-specific）**：`qc_history.get(height)` 且 `qc.target == block_hash` ⇒
///    `round = qc.context.round` ⇒ `select_proposer(chain_id, height-1, round, genesis_hash, set)`
///    ⇒ **再用该 proposer 的 key 验签该块**（QC 与块必须相互印证）；
/// 2. QC 不可得（缺失 / target 不匹配 / 推导后验签失败）⇒ **不猜 round**：改为在**既有
///    ValidatorSet** 内按**签名**枚举（membership-bounded ≤ |set|）：唯一命中者即该块实际
///    签名 proposer（密码学绑定，强于轮次推导）；
/// 3. 无命中或**多命中**（重复 key / 装配不一致）⇒ **fail-closed**
///    （canonical 块无法唯一归属任一成员 ⟹ 状态不一致；`Storage(CorruptedState)`）。
fn resolve_historical_proposer(
    qc_history: Option<&QcHistory>,
    chain_id: u64,
    genesis_hash: &[u8; 32],
    set: &ValidatorSet,
    hash: &[u8; 32],
    block: &Block,
) -> Result<ValidatorId, NodeStartupError> {
    let height = block.header.height;
    if let Some(history) = qc_history
        && let Ok(Some(qc)) = history.get(height)
        && qc.target == *hash
        && let Ok(p) = select_proposer(
            chain_id,
            height.saturating_sub(1),
            qc.context.round,
            genesis_hash,
            set,
        )
        && let Some(info) = set.info(&p)
        && let Ok(vk) = VerifyingKey::from_bytes(&info.consensus_public_key)
        && validate_block_signature(block, &vk, chain_id).is_ok()
    {
        return Ok(p);
    }
    // QC 不可得 ⇒ 不猜 round：按签名在既有集合内枚举（≤ |set|；deterministic 排序）。
    let mut found: Option<ValidatorId> = None;
    for info in set.validators() {
        let Ok(vk) = VerifyingKey::from_bytes(&info.consensus_public_key) else {
            continue;
        };
        if validate_block_signature(block, &vk, chain_id).is_ok() {
            if found.is_some() {
                // 多命中（重复 key / 装配不一致）⇒ fail-closed（不猜）。
                return Err(NodeStartupError::Storage(StorageError::CorruptedState));
            }
            found = Some(info.validator_id);
        }
    }
    found.ok_or(NodeStartupError::Storage(StorageError::CorruptedState))
}

/// 从 canonical head 沿 committed BlockStore 的 parent 链回溯至 genesis，重建 frozen `Dag`：
/// genesis 根（height 0；无 block 文件）+ 每个 canonical committed 块的 [`BlockReference`]
/// （真实 `header.height` + 单 parent 边 + `proposer` 由**历史 QC 的 `context.round`** 推导，
/// 见 [`resolve_historical_proposer`]：**不再硬编码 round 0**；QC 不可得时按**签名**在既有
/// ValidatorSet 内枚举（密码学绑定），仍不可得 ⇒ fail-closed）。
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
    qc_history: Option<&QcHistory>,
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
        let block = match block_store
            .get_content(&cur)
            .map_err(NodeStartupError::Storage)?
        {
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
        let block = match block_store
            .get_content(&hash)
            .map_err(NodeStartupError::Storage)?
        {
            Some(b) => b,
            None => return Err(NodeStartupError::DagRebuildMissingAncestor(hash)),
        };
        // proposer 推导（P1-A.20-C Phase 2）：按**历史 QC 的 context.round** 推导；
        // QC 不可得 ⇒ **不猜 round**，改为按签名在既有 ValidatorSet 内枚举（见 helper）。
        let proposer =
            resolve_historical_proposer(qc_history, chain_id, &genesis_hash, set, &hash, &block)?;
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
// 目标：`Finality(X) 已达成 → commit 前 crash → restart` 时，durable fact 保留 `X was finalized`
// 这一**已验证证据**（供审计 / 服务 / runtime 独立重建），不持久化完整 ConsensusState、
// 不改 frozen consensus/crypto/core/storage/network、不伪造 finality。
//
// 格式（deterministic，node-only；无第二套协议 wire）：
//   magic(4) ‖ version(1) ‖ network_id(1) ‖ chain_id(8 LE) ‖ genesis_hash(32)
//   ‖ height(8 LE) ‖ finalized_reference(32) ‖ qc_len(4 LE) ‖ qc(encode_qc)
//   ‖ checksum(32 = SHA-256(上述全部))
//
// 语义：`finalized_reference == qc.target` 且 `qc.context.height + 1 == height`
// （V0.1 canonical-next：块在 round.height 的 canonical-next ⇒ 块高 = QC 轮高 + 1）。
// 读取侧任何损坏 / identity 失配 / QC 失败 / block 缺失 / 高度不符 ⇒ `Err`
// （fail-closed；绝不当「无 fact」、绝不 ignore、绝不自动覆写损坏文件）。
//
// D11-23 U4-C（Owner 冻结）—— **ahead-of-head 不等于 invalid**：
//   · `verify_qc` 先于 head/canonical 关系判定（IPC-1）⇒ invalid QC **不会**被 ahead 规则静默忽略；
//   · verified valid 且 reference 严格高于 ChainHead 且可证明为 canonical descendant ⇒
//     **不注入** `finalized_reference`（`R = None`）+ **继续启动**（不中止）；
//   · 关系**不可证明**（含同高异 hash / unrelated parent）⇒ 保持既有 `FinalityFactHeadConflict`。
//   ⇒ U4-C 只改变「是否把 fact 的 reference 装载进 runtime」，不改变任何有效性判定。
//
// D11-25（Owner 冻结）—— **FinalityFact = durable finality evidence（Model B）**：
//   · fact **不是** `finalized_reference` 的 runtime mirror；二者生命周期不同：
//     `finalized_reference` 是 runtime consensus object（volatile；按 frozen DAG ancestry 单调），
//     fact 是 durable finality evidence（**永不降级**）；
//   · 因此 `Fact > R` 与 `Fact > ChainHead` 均为**合法状态**（durable-before-bridge 的既有 crash
//     window），**不**代表 corruption / downgrade / startup failure；
//   · 写入侧语义（见 [`persist_finality_fact`]）：runtime `R` 前进到**低于**已有 fact 高度 ⇒
//     **不写、不覆盖、不删除、不报错**（非致命继续）；仅**同高度证据冲突**才 fail-closed。
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

/// D10-C Step 4 / **D11-25** — 持久化 Finality Recovery Fact（原子写；durable-before-bridge）。
///
/// - 调用方契约：`reference == qc.target` 且 `qc` 为已验证 PrecommitQC（本函数防御检查
///   `reference == qc.target`）；`height` = finalized block 高度（= `qc.context.height + 1`）。
/// - **语义（D11-25 D1 = Model B）**：fact = **durable finality evidence snapshot**，
///   **不是** runtime `finalized_reference` 的 mirror；`Fact > R` / `Fact > ChainHead` 为合法状态。
/// - **写入状态机（D11-25 D3/D4）**：
///   ① 无既有 fact ⇒ 写入；
///   ② 完整编码字节一致 ⇒ idempotent no-op（不重复原子写）；
///   ③ `new.height > existing.height` ⇒ 写入（证据前进）；
///   ④ `new.height < existing.height` ⇒ **不写 / 不覆盖 / 不删除 / 不报错**（非致命继续；
///   保留更高 durable evidence —— runtime `R` 落后**不是**错误）；
///   ⑤ `new.height == existing.height` 且证据内容不同（不同 reference，或同 reference 但
///   QC / evidence 字节不同）⇒ `FinalityFactSameHeightConflict`（fail-closed，不覆盖）。
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
    // D11-23 A-1 + **D11-25（Owner 冻结）**：durable evidence 单调保护（Model B）。
    //
    // 属 **IMPLEMENTATION SAFETY INVARIANT**（非协议 / 非共识规则）；保护对象 = durable evidence
    // （`finality_fact.bin`），**不是** `finalized_reference`，**不是** canonical head。
    //   · 无既有 fact ⇒ 写入；
    //   · 完整字节一致 ⇒ idempotent no-op；
    //   · 既有高度**更高** ⇒ **不写 + 非致命继续**（保留更高证据；D11-25 D3 —— runtime `R`
    //     前进到低于已有 evidence 的高度**不是**错误，不得产生 fatal Err / 进程退出）；
    //   · 更高高度 ⇒ 允许覆盖（证据正常前进）；
    //   · 同高度 + 证据不同 ⇒ `FinalityFactSameHeightConflict`（fail-closed，不覆盖）。
    // 身份判据 = `encode_fact` 的字节级比较（**不**把 byte equality 当 consensus validity）。
    // 为**不**静默覆盖损坏文件（与模块头注释既有原则一致），无法解析的既有 fact ⇒ `FinalityFactCorrupt`。
    if path.exists() {
        let existing = fs::read(path).map_err(|_| NodeStartupError::StorageIo)?;
        if existing == bytes {
            // ② 完整编码字节一致（含同高度同内容）⇒ 幂等：不重复原子写。
            return Ok(());
        }
        let old = parse_fact(&existing)?;
        if old.height > height {
            // ④ 既有证据更高 ⇒ 不写 / 不覆盖 / 不删除 / 不报错（D11-25 D3）：
            //    runtime `R` 落在已有 durable evidence 之下是**合法状态**（Model B）
            //    ⇒ 保留更高证据，非致命继续。
            return Ok(());
        }
        if old.height == height {
            // ⑤ 同高度 + 证据内容不同 ⇒ fail-closed（不覆盖）。D11-25 D4：finality evidence 是
            //    证据对象 ⇒ 只有**完整编码字节一致**才算 idempotent。
            return Err(NodeStartupError::FinalityFactSameHeightConflict);
        }
    }
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

/// D10 Recovery C（Phase 1 / D-1）— **已通过恢复校验**的 finality 材料。
///
/// 语义：由 [`restore_finality_fact`] 在 Check 1–7 与 `verify_qc` **全部通过之后**构造 ⇒
/// `qc` 就是原 fact 中的 PrecommitQC（**不重新实现 / 不绕过 / 不放宽任何校验**），
/// `reference == qc.target`、`height == qc.context.height + 1`。
/// 用途：restart 恢复窗口内作为 finality commit bridge 的**第三证据源**（不改共识规则）。
#[derive(Debug, Clone)]
pub struct RestoredFinality {
    /// 已恢复（尚未 commit）的 finalized block hash（= `qc.target`）。
    pub reference: [u8; 32],
    /// 该块高度（= `qc.context.height + 1`）。
    pub height: u64,
    /// 原 fact 中的 PrecommitQC（已通过 Check 1–7 与 `verify_qc`）。
    pub qc: QuorumCertificate,
}

/// D10-C Step 4 / **D11-23 U4-C** — restart 时 Finality Recovery Fact 恢复校验。
///
/// 校验链（**D11-23 R1/R3 顺序**；任一步失败 ⇒ `Err`，fail-closed）：
/// 1. structural（`parse_fact`：magic / version / 长度 / checksum / `decode_qc`）；
/// 2. identity（network_id / chain_id / genesis_hash）；
/// 3. QC **结构性**：Precommit 且 `reference == qc.target` 且 `qc.context.height + 1 == height`；
/// 4. block/reference：`BlockStore.get_content(reference)` 存在且 `block.header.height == height`；
/// 5. **QC validity：`verify_qc`**（IPC-1：**先于** head/canonical 关系判定；
///    用 scratch DAG 克隆携带 `target`，不修改调用方 DAG）
///    ⇒ invalid QC **不会**被 U4-C 的 ahead 规则静默忽略；
/// 6. head / canonical 关系（**D1 保守**；禁止仅以 height 判定 ahead）：
///    (a) reference ∈ canonical ancestry（`head → parent → … → genesis`；含 `== head`）
///    ⇒ 既有语义（幂等 / stale ignore：不注入、不回退 head）；
///    (b) verified valid ∧ `height(reference) > height(head)` ∧ **可证明**为 head 的 canonical
///    descendant（沿 parent 回溯可达 head）⇒ **U4-C**：不恢复 `finalized_reference`（`R = None`）
///    + **继续启动**（不中止）；
///      (c) 其余（同高异 hash / unrelated parent / 关系不可证明）⇒ `FinalityFactHeadConflict`
///      （同高异 hash / unrelated / 高度异常；**绝不选择 / 绝不猜测** / 绝不把 fork block 当 canonical）。
///
/// 返回 `(dag, Option<RestoredFinality>)`：**D11-23 U4-C 后** ahead-of-head fact **不再注入**
/// ⇒ 成功路径恒为 `Ok((dag, None))`；`RestoredFinality` 类型保留（既有 bridge 证据源接线不变，
/// 当前无 production 构造点）。**不**改变任何 validity 判定、**不**新增持久化、**不**触碰 head。
pub fn restore_finality_fact(
    path: &Path,
    adapter: &NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>,
    set: &ValidatorSet,
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
    dag: Dag,
) -> Result<(Dag, Option<RestoredFinality>), NodeStartupError> {
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

    // ---- IPC-1（D11-23 R1/R3）—— QC validity 必须先于 head / canonical 关系判定 ----
    // 顺序（Owner 冻结）：structural → identity → block/reference → **verify_qc** →
    //                   validity → head/canonical relation → U4-C admission。
    // 旧顺序把「head 关系」放在 `verify_qc` 之前 ⇒ `invalid QC + ahead reference` 会被 U4-C 的
    // ahead 规则**静默忽略**（丢失 fail-closed 检测）。此处修正。

    // Check 5 — block 存在 + 高度一致（get 已 strict decode + hash 重算 == key）。
    let block_store = adapter
        .block_store()
        .ok_or(NodeStartupError::FinalityFactCorrupt)?;
    let block = match block_store
        .get_content(&fact.reference)
        .map_err(NodeStartupError::Storage)?
    {
        Some(b) => b,
        None => return Err(NodeStartupError::FinalityFactMissingBlock),
    };
    if block.header.height != fact.height {
        return Err(NodeStartupError::FinalityFactHeightMismatch);
    }

    // QC 验证（validity 判定，F-6a）—— **前移**（原实现位于 head 关系判定之后）。
    // `verify_qc` 对 `dag` 的唯一要求 = `dag.contains(&qc.target)`（consensus `finality.rs`）⇒
    // 使用 **scratch DAG 克隆**（`Dag: Clone`）+ genesis 根 + 候选 X（`parents` 空，与 genesis 根同法）
    // **仅供验证**，用后丢弃：**不**注入、**不**修改调用方持有的 `dag`、**不**新增持久化。
    {
        let mut verify_dag = dag.clone();
        if !verify_dag.contains(&genesis_hash) {
            verify_dag
                .add_block(BlockReference {
                    block_hash: genesis_hash,
                    height: 0,
                    parents: Vec::new(),
                    proposer: ValidatorId::from_bytes([0u8; 32]),
                })
                .map_err(|_| NodeStartupError::FinalityFactHeadConflict)?;
        }
        if !verify_dag.contains(&fact.reference) {
            verify_dag
                .add_block(BlockReference {
                    block_hash: fact.reference,
                    height: block.header.height,
                    parents: Vec::new(),
                    proposer: ValidatorId::from_bytes([0u8; 32]),
                })
                .map_err(|_| NodeStartupError::FinalityFactHeadConflict)?;
        }
        verify_qc(&fact.qc, set, &genesis_hash, &verify_dag)
            .map_err(NodeStartupError::FinalityFactQc)?;
    }
    // ⇒ 至此 fact 已通过**全部** validity checks（structural / identity / reference / block / QC）。

    // ---- head / canonical 关系判定（**D1：保守**；禁止仅以 height 判定 ahead） ----
    let head = adapter.head();
    // (a) reference 已在 canonical ancestry（`head → parent → … → genesis`；含 `== head`）
    //     ⇒ 既有语义：不注入、不回退 head、继续启动（幂等 / stale ignore）。
    if is_canonical_ancestor(block_store, head, &fact.reference)? {
        return Ok((dag, None));
    }
    // (b) verified valid ∧ reference **严格高于** head ∧ **可证明**为 head 的 canonical descendant
    //     ⇒ **U4-C**（Owner 冻结）：`finalized_reference` 不恢复（`R = None`）+ 继续启动（不中止）。
    //     注意：**不**把 X 加入返回的 DAG（不注入 ⇒ 无需 DAG 注册 ⇒ 不污染 canonical DAG）。
    if block.header.height > head.height
        && is_canonical_descendant(block_store, head, &fact.reference, block.header.height)?
    {
        return Ok((dag, None));
    }
    // (c) 其余（同高异 hash / unrelated parent / 关系不可证明）⇒ **既有冲突语义**（fail-closed）。
    //     禁止把 fork block 当作 canonical；禁止把「无法证明关系」当作 ahead。
    Err(NodeStartupError::FinalityFactHeadConflict)
}

/// D1（保守）—— `reference` 是否属于当前 **canonical ancestry**（`head → parent → … → genesis`）。
///
/// - `reference == head.block_hash` ⇒ `true`；`head.height == 0`（仅 genesis）⇒ `false`。
/// - 从 head 沿 `parent_hash` **回溯**（只读 `get_content`）；逐块要求
///   `block.header.height == 期望高度`（严格递减 1）⇒ 任一不符 ⇒ `false`（不可证明）。
/// - 块缺失 / 存储损坏 ⇒ `Err`（与 `rebuild_consensus_dag` 同口径 fail-closed）。
/// - **不**以 fork-only DAG membership 作判据；**不**按 height 猜测。
fn is_canonical_ancestor(
    block_store: &BlockStore,
    head: &ChainHead,
    reference: &[u8; 32],
) -> Result<bool, NodeStartupError> {
    if *reference == head.block_hash {
        return Ok(true);
    }
    let mut cur = head.block_hash;
    let mut height = head.height;
    while height >= 1 {
        if cur == *reference {
            return Ok(true);
        }
        let block = match block_store
            .get_content(&cur)
            .map_err(NodeStartupError::Storage)?
        {
            Some(b) => b,
            None => return Err(NodeStartupError::DagRebuildMissingAncestor(cur)),
        };
        if block.header.height != height {
            // canonical 记录高度不符（结构异常）⇒ 不可证明（不猜）。
            return Ok(false);
        }
        if height == 1 {
            break;
        }
        cur = block.header.parent_hash;
        height -= 1;
    }
    Ok(false)
}

/// D1（保守）—— `reference` 是否**可证明**为 `head` 的 canonical descendant（`head → … → reference`）。
///
/// 方法：从 `reference` 沿 `parent_hash` **回溯**（只读 `get_content`），每步高度**严格递减 1**；
/// 当回溯到 `head.height + 1` 的块时，要求其 `parent_hash == head.block_hash` ⇒ `true`。
/// 任何一步不可判定（块缺失 / 高度异常 / 链底未达 head）⇒ `false`（不可证明 ⇒ **非** ahead）。
/// 约束（Owner D1）：**不**做 forward reconstruction、**不**使用网络、**不**按 height 猜测、
/// **不**把 fork block 当作 canonical。步数上界 = `reference_height - head.height`（严格递减 ⇒ 终止）。
fn is_canonical_descendant(
    block_store: &BlockStore,
    head: &ChainHead,
    reference: &[u8; 32],
    reference_height: u64,
) -> Result<bool, NodeStartupError> {
    let mut cur = *reference;
    let mut height = reference_height;
    while height > head.height {
        let block = match block_store
            .get_content(&cur)
            .map_err(NodeStartupError::Storage)?
        {
            Some(b) => b,
            None => return Ok(false),
        };
        if block.header.height != height {
            return Ok(false);
        }
        if height == head.height.saturating_add(1) {
            return Ok(block.header.parent_hash == head.block_hash);
        }
        cur = block.header.parent_hash;
        height -= 1;
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// P1-A.20-C Phase 2 — T9（历史 round ≥ 1 的 proposer 解析）
//
// 目标（Owner Phase 2 mandate §15-T9）：restart 后重建历史块的 proposer 时，**必须**使用
// 历史 QC 的 `context.round`（`select_proposer(chain, height-1, round, genesis_hash, set)`），
// **不得**硬编码 round 0；QC 不可得 / 不适用 ⇒ 按**签名**在既有 ValidatorSet 内枚举；
// 集合外签名 ⇒ **fail-closed**。
//
// 可观测性说明：frozen `Dag` 不暴露 `BlockReference.proposer` 读取器（`crates/consensus`
// 本阶段禁止改动）⇒ 端到端「DAG 内的 proposer」不可从外部断言；本测试固定在**最近可观测
// 接缝** `resolve_historical_proposer`（`rebuild_consensus_dag` 每个 canonical 块调用的
// 解析器）。QC 键语义（ADR-0064 / `qc_history`）：键 `h` 存的是**该块**的 QC
// （`context.height == h-1` ∧ `target == block_hash(block@h)`）。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::finality::QcContext;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{
        AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
        compute_genesis_hash,
    };
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use nova_runtime::{
        BLOCK_VERSION, BlockBody, BlockHeader, block_hash, compute_transaction_root,
        encode_block_header,
    };

    const T9_CHAIN_ID: u64 = 1001;
    const T9_STAKE: u128 = 200_000;

    /// 独立临时目录（每次调用唯一；测试内自清理）。
    fn t9_dir(tag: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("nova_p1a20c_t9_{tag}_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn t9_addr(i: u8) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: [0x11u8.wrapping_add(i); 32],
        })
    }

    fn t9_genesis(pks: &[[u8; 32]]) -> GenesisV1 {
        let accounts: Vec<AccountInit> = (0..pks.len())
            .map(|i| AccountInit {
                address: t9_addr(i as u8),
                liquid_balance: 1_000_000,
            })
            .collect();
        let mut vs: Vec<ValidatorInit> = pks
            .iter()
            .zip(accounts.iter())
            .map(|(pk, a)| ValidatorInit {
                account_address: a.address,
                consensus_public_key: *pk,
                bonded_stake: T9_STAKE,
                commission_bps: 0,
            })
            .collect();
        vs.sort_by_key(|v| ValidatorId::from_consensus_public_key(&v.consensus_public_key));
        let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: T9_CHAIN_ID,
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

    /// 合成某高度的块（parent = genesis；仅用于 proposer 解析 —— 不执行状态）。
    fn t9_block(genesis_hash: [u8; 32], height: u64, kp: &KeyPair) -> Block {
        let body = BlockBody { txs: Vec::new() };
        let header = BlockHeader {
            version: BLOCK_VERSION,
            chain_id: T9_CHAIN_ID,
            height,
            parent_hash: genesis_hash,
            finality_reference: None,
            transaction_root: compute_transaction_root(&body),
            state_root: [0u8; 32],
            validator_set_hash: genesis_hash,
            timestamp: 0,
        };
        let payload = encode_block_header(&header);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, T9_CHAIN_ID, &payload)
                .unwrap();
        let msg = hash_signing_message(&signed);
        Block {
            header,
            body,
            proposer_signature: sign_message_hash(kp.signing_key(), &msg).to_bytes(),
        }
    }

    /// 合成「某块的 QC」：键 `block_height`、`context.height = block_height - 1`（ADR-0064）。
    fn t9_qc(
        block_height: u64,
        round: u64,
        target: [u8; 32],
        genesis_hash: [u8; 32],
    ) -> QuorumCertificate {
        QuorumCertificate {
            context: QcContext {
                chain_id: T9_CHAIN_ID,
                height: block_height - 1,
                round,
                vote_type: VoteType::Precommit,
            },
            target,
            validator_set_id: genesis_hash,
            evidence: Vec::new(),
        }
    }

    /// 确定性选取「round 0 ≠ round 1 当选者」的候选高度（T9 可区分性的**唯一**前提）。
    ///
    /// 随机 key 下固定高度可能恰好相同（3-validator 每高度 `p0 == p1` 概率 ≈ 1/3）⇒
    /// 在多个高度 × 多组密钥上确定性搜索（64 × 8 组密钥下失败概率可忽略）。
    fn t9_case() -> (
        Vec<KeyPair>,
        [u8; 32],
        ValidatorSet,
        u64,
        ValidatorId,
        ValidatorId,
    ) {
        for _ in 0..8 {
            let kps: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
            let pks: Vec<[u8; 32]> = kps.iter().map(|k| k.verifying_key().to_bytes()).collect();
            let genesis = t9_genesis(&pks);
            let genesis_hash = compute_genesis_hash(&genesis).unwrap();
            let set = ValidatorSet::from_genesis(&genesis);
            for height in 1..=64u64 {
                let Ok(p0) = select_proposer(T9_CHAIN_ID, height - 1, 0, &genesis_hash, &set)
                else {
                    continue;
                };
                let Ok(p1) = select_proposer(T9_CHAIN_ID, height - 1, 1, &genesis_hash, &set)
                else {
                    continue;
                };
                if p0 != p1 {
                    return (kps, genesis_hash, set, height, p0, p1);
                }
            }
        }
        panic!("未找到 round 0 ≠ round 1 的候选高度（3-validator 下概率可忽略）");
    }

    /// T9 — 历史 QC 的 `context.round` 决定历史块 proposer（**不得** round-0 硬编码）；
    /// QC 缺失 / target 不符 / QC 推导后验签失败 ⇒ 签名枚举回退；集合外签名 ⇒ fail-closed。
    #[test]
    fn p1a20c_t9_historical_qc_round_resolves_proposer() {
        let (kps, genesis_hash, set, h, p0, p1) = t9_case();

        let kp_of = |id: &ValidatorId| -> &KeyPair {
            let info = set.info(id).unwrap();
            kps.iter()
                .find(|k| k.verifying_key().to_bytes() == info.consensus_public_key)
                .expect("成员 key 可得")
        };

        // 场景 A：块由 **round 1 当选者**签名 + 历史 QC（round 1，target = 该块）
        //         ⇒ 解析结果必须是 round 1 的 proposer（round-0 硬编码 ⇒ p0 ⇒ FAIL）。
        let block_a = t9_block(genesis_hash, h, kp_of(&p1));
        let hash_a = block_hash(&block_a).unwrap();
        let da = t9_dir("qc_round1");
        let mut history_a = QcHistory::open(&da, NetworkId::Mainnet, T9_CHAIN_ID, genesis_hash);
        history_a
            .put(h, &t9_qc(h, 1, hash_a, genesis_hash))
            .expect("QC 写入（键 = 块高度）");
        assert_eq!(
            resolve_historical_proposer(
                Some(&history_a),
                T9_CHAIN_ID,
                &genesis_hash,
                &set,
                &hash_a,
                &block_a
            )
            .unwrap(),
            p1,
            "T9：历史 QC round=1 ⇒ select_proposer(h-1, 1)（非 round 0）"
        );
        // 场景 B：同一块、无 QC ⇒ 签名枚举回退（密码学绑定 ⇒ 同一结果；不猜 round）。
        assert_eq!(
            resolve_historical_proposer(None, T9_CHAIN_ID, &genesis_hash, &set, &hash_a, &block_a)
                .unwrap(),
            p1,
            "T9：QC 不可得 ⇒ 签名枚举回退（不硬编码 round）"
        );
        let _ = std::fs::remove_dir_all(&da);

        // 场景 C：QC 存在但 **target 不是该块** ⇒ QC 不适用 ⇒ 回退签名枚举（不被误导）。
        let dc = t9_dir("qc_other_target");
        let mut history_c = QcHistory::open(&dc, NetworkId::Mainnet, T9_CHAIN_ID, genesis_hash);
        history_c
            .put(h, &t9_qc(h, 1, [0xABu8; 32], genesis_hash))
            .unwrap();
        assert_eq!(
            resolve_historical_proposer(
                Some(&history_c),
                T9_CHAIN_ID,
                &genesis_hash,
                &set,
                &hash_a,
                &block_a
            )
            .unwrap(),
            p1,
            "T9：QC target 不符 ⇒ 回退签名枚举（不得按 QC 猜 proposer）"
        );
        let _ = std::fs::remove_dir_all(&dc);

        // 场景 D：QC 声称 round 1（⇒ p1），但块**实际由 p0 签名** ⇒ QC 推导的 key 验签失败
        //         ⇒ 回退签名枚举 ⇒ p0（**绝不**盲信 QC / 绝不伪造 proposer）。
        let block_d = t9_block(genesis_hash, h, kp_of(&p0));
        let hash_d = block_hash(&block_d).unwrap();
        let dd = t9_dir("qc_mismatch_signer");
        let mut history_d = QcHistory::open(&dd, NetworkId::Mainnet, T9_CHAIN_ID, genesis_hash);
        history_d
            .put(h, &t9_qc(h, 1, hash_d, genesis_hash))
            .unwrap();
        let resolved_d = resolve_historical_proposer(
            Some(&history_d),
            T9_CHAIN_ID,
            &genesis_hash,
            &set,
            &hash_d,
            &block_d,
        )
        .unwrap();
        assert_eq!(
            resolved_d, p0,
            "T9：QC 与块签名不一致 ⇒ 以签名者为准（不盲信 QC）"
        );
        assert_ne!(resolved_d, p1, "T9：不得返回 QC 推导的 p1");
        let _ = std::fs::remove_dir_all(&dd);

        // 场景 E：块签名者 **不在 ValidatorSet** ⇒ fail-closed（无法唯一归属 ⇒ CorruptedState）。
        let outsider = KeyPair::generate().unwrap();
        let block_e = t9_block(genesis_hash, h, &outsider);
        let hash_e = block_hash(&block_e).unwrap();
        let err =
            resolve_historical_proposer(None, T9_CHAIN_ID, &genesis_hash, &set, &hash_e, &block_e)
                .unwrap_err();
        assert!(
            matches!(err, NodeStartupError::Storage(StorageError::CorruptedState)),
            "T9：集合外 proposer ⇒ fail-closed（实际 {err:?}）"
        );
    }
}
