//! NodeRuntime —— 生产节点生命周期装配层（STEP 10-16；Phase 1 骨架）。
//!
//! # 职责（仅装配 / 生命周期；不实现共识算法）
//! 固定启动顺序：`Config → Genesis → ChainIdentity 校验 → chain storage →（validator mode）
//! KeyProvider → derive ValidatorId → SafetyStore open → strict recover → ValidatorActor →
//! ConsensusNode → NodeConsensusDriver`（STEP 10-18I-C：Runtime 经 [`crate::driver::NodeConsensusDriver`]
//! 持有 ConsensusNode + ValidatorActor）。Stage C（STEP 10-18I-G）：Network / EventLoop /
//! NetworkIdentity 以可选 `NetworkStack` 装配（`start` = 网络 disabled；`start_with_network` = 启用）。
//!
//! # 边界
//! - [`NodeRuntime`] **拥有生命周期**（组件创建顺序 / 注入），但：
//!   - 不持有共识状态（`ConsensusNode` 是 canonical 状态 owner，Runtime 只持 handle 引用层）；
//!   - 不改变 `ConsensusState` / 共识算法 / DAG / finality / fork choice；
//!   - 不替代 [`crate::validator::ValidatorActor`]（安全逻辑仍在 actor 内）；
//!   - **不存储私钥 / vote history / SafetyRecord**（私钥在 SigningCapability 边界内；
//!     vote history 在 ValidatorSafetyStore / actor ledger）。
//! - chain storage（`config.storage_dir`）与 validator safety storage（`config.safety_dir`）
//!   **目录分离**，绝不混用；SafetyStore recover 失败 = validator mode 启动失败（fail closed）。
//! - full-node（`validator_enabled=false`）：跳过 key / safety / validator，不触碰 Provider。

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

use nova_consensus::dag::Dag;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::identity::ChainIdentity;
use nova_network::event_loop::{EventLoop, EventLoopConfig, EventLoopError};
use nova_network::message::{MessageEnvelope, MessageType};
use nova_network::network_service::{NetworkService, NetworkServiceConfig, NetworkServiceError};
use nova_network::node_id::NodeId;
use nova_network::security::{NetworkSecurityError, random_request_id};
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, SessionError, handshake_payload_encode, random_session_nonce,
};
use nova_network::sync::SyncBlockResponse;
use nova_network::transport::{BoxTransport, ConnectionTarget, TcpDialer, Transport};
use nova_storage::error::StorageError;
use nova_storage::persistent::PersistentBackend;

use crate::assembly::ConsensusNode;
use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use crate::block_dispatch::{dispatch_gossip_block, dispatch_sync_block_response};
use crate::block_inbound::{InboundBlockError, InboundBlockVerdict};
use crate::bootstrap::{self, ConnectionTargetError, NodeConfig, NodeStartupError};
use crate::driver::{DriverError, NodeConsensusDriver};
use crate::intent_ledger::{BlockInboundSource, MissingAncestorIntentLedger};
use crate::key_provider::{KeyProvider, KeyProviderError};
use crate::network_identity::{NetworkSigner, NetworkSigningError};
use crate::outbound::OutboundConsensusMessage;
use crate::proposer::{ProposalBuild, ProposerError, build_proposal};
use crate::safety_store::{SafetyIdentity, ValidatorSafetyError, ValidatorSafetyStore};
use crate::signer::SigningCapability;
use crate::sync_correlator::{LogicalTick, SyncRequestCorrelator};
use crate::sync_dispatch::{NetworkSyncDispatcher, dispatch_batch};
use crate::sync_scheduler::{
    PeerCandidate, PeerSelectionPolicy, ScheduleResult, SyncRequestScheduler, select_peer,
};
use crate::validator::{ValidatorActor, ValidatorActorError};
use crate::wiring::{
    BlockInboundMessage, NodeConsensusCommand, NodeConsensusHandler, process_command,
};

/// ValidatorActor 的签名能力类型（Phase 1：trait object）。
type DynSigner = Box<dyn SigningCapability>;

/// block inbound 观测队列有界容量（Node-local；满则丢最早 —— 不累积无限历史）。
const BLOCK_INBOUND_OUTCOME_CAP: usize = 128;

/// missing-ancestor intent ledger 有界容量（Node-local；满 ⇒ FIFO evict —— 不无限增长）。
const MISSING_ANCESTOR_LEDGER_CAP: usize = 256;

/// outbound sync request scheduler 有界容量（D8-2；满 ⇒ 丢弃多余 intent —— bounded）。
const SYNC_SCHEDULER_CAP: usize = 64;

/// outbound sync request correlator 有界容量（D8-2；满 ⇒ register Full 拒 —— bounded）。
const SYNC_CORRELATOR_CAP: usize = 64;

/// 每 step 从 ledger 调度入 scheduler 的最大 intent 数（bounded；防每 step 无限发送）。
const SYNC_SCHEDULE_MAX_PER_STEP: usize = 8;

/// 每 step 从 scheduler 出队并 register/dispatch 的最大条数（bounded dispatch）。
const SYNC_DISPATCH_MAX_PER_STEP: usize = 8;

/// register 用 deadline horizon（D8-3-1：expire release-only —— 悬挂 request 在该 step 数后
/// 被 `expire_at` 释放；无 retry / 无 backoff；correlator capacity 即有界）。
const SYNC_DEADLINE_HORIZON: u64 = 64;

/// 网络 peer-auth 协议版本（与 `PeerAuthConfig.protocol_version` 一致；非 genesis 字段）。
const NETWORK_PROTOCOL_VERSION: u8 = 1;

/// Node-local proposer step（STEP 10-19-6 OPT-1）：本节点为当前 proposer 时经真实 BlockBuilder
/// 产出 Block + ProposalRef → submit ProposalRef。
///
/// - 纯编排：`build_proposal` 只读判定 + build（真实 BlockHash；**非 placeholder**）；签名走
///   `ValidatorActor::sign_block`（不暴露私钥）；提交走 `driver.submit_proposal`。
/// - 高度同步 gate / 阶段守卫 / 幂等由 `build_proposal` 与 consensus 保证（非 proposer /
///   不同步 / 已提案 ⇒ `Ok(None)`，no-op）。
/// - 返回 `Some(ProposalBuild)`（本地保留 Block，**不持久化 / 不推进 head**）；无 adapter /
///   无 actor ⇒ `Ok(None)`。
fn runtime_propose(
    driver: &mut NodeConsensusDriver<DynSigner>,
    block_production: &Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    timestamp: u64,
) -> Result<Option<ProposalBuild>, RuntimeError> {
    let Some(adapter) = block_production.as_ref() else {
        return Ok(None);
    };
    let Some(local_id) = driver.actor(0).map(|a| a.validator_id()) else {
        return Ok(None);
    };
    let proposal = build_proposal(local_id, driver.consensus(), adapter, timestamp)
        .map_err(RuntimeError::Proposer)?;
    let Some(mut pb) = proposal else {
        return Ok(None);
    };
    // 出块签名（ValidatorActor 授权；signature ∉ block_hash —— hash 在签名前已定）。
    if let Some(a) = driver.actor(0) {
        a.sign_block(&mut pb.block)
            .map_err(RuntimeError::Validator)?;
    }
    // 提交共识（ProposalRef 64B；只记 hash，不含 Block）。
    let _ = driver.submit_proposal(pb.proposal_ref.clone());
    Ok(Some(pb))
}

/// NodeRuntime 启动错误（node-local；typed；fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRuntimeError {
    /// genesis / storage / identity 校验失败（复用 bootstrap NodeStartupError）。
    Startup(NodeStartupError),
    /// validator mode 但未提供 KeyProvider（fail closed：不默认生成不稳定密钥）。
    KeyNotProvisioned,
    /// KeyProvider 加载 signer 失败。
    KeyProvider(KeyProviderError),
    /// SafetyStore create / recover / identity 校验失败。
    Safety(ValidatorSafetyError),
    /// ValidatorActor 构造 / 恢复失败（含 identity mismatch）。
    Validator(ValidatorActorError),
    /// configured connection target 校验失败（self / duplicate；dial **前** fail-closed）。
    NetworkTarget(ConnectionTargetError),
}

/// Runtime 运行期错误（Stage C `step`；分层、不吞错、不改底层语义）。
#[derive(Debug)]
pub enum RuntimeError {
    /// EventLoop / Network 错误（poll/dispatch 层；NS 错误经 `EventLoopError::Network` 内嵌）。
    EventLoop(EventLoopError),
    /// Driver 验证 / transition 门面失败（与网络错误分层 —— 不伪装成 NetworkError）。
    Driver(DriverError),
    /// Node Egress 网络签名失败（fail-closed；不吞安全错误）。
    Egress(crate::egress::EgressError),
    /// Node-local Proposer orchestration 失败（selection / block build / head；fail-closed）。
    Proposer(ProposerError),
    /// ValidatorActor 出块签名失败（`sign_block`；fail-closed）。
    Validator(ValidatorActorError),
    /// outbound dial 失败（NetworkServiceError 透传；不自动 retry / 不自动换 peer）。
    NetworkDial(NetworkServiceError),
    /// handshake 构造 / nonce 生成失败（session 域 typed 错误）。
    Session(SessionError),
    /// outbound handshake envelope 签名失败（network identity 域）。
    NetworkSigning(NetworkSigningError),
    /// NetworkService 未装配 peer-auth（handshake 编排前置缺失；fail-closed）。
    PeerAuthMissing,
    /// authenticated remote NodeId ≠ configured peer_id（address 正确 ≠ identity 正确）。
    IdentityMismatch { configured: NodeId },
    /// sync RequestId 生成失败（OS CSPRNG 不可用；fail-closed —— 不退回弱随机）。
    NetworkSecurity(NetworkSecurityError),
}

/// `establish_configured_peer` 单次推进后的握手判定（Node 只编排；session 验证归 NetworkService）。
#[derive(Debug, PartialEq, Eq)]
enum HandshakeOutcome {
    /// configured peer 已认证（Established）且身份匹配。
    Established(NodeId),
    /// 尚未收到对端合法握手（后续 step 再推进；不重发 / 不重 dial）。
    Pending,
    /// 收到其它 peer 的合法握手（identity mismatch；fail-closed 断开）。
    ForeignEstablished(Vec<NodeId>),
}

/// 单个 configured peer 的建立状态（STEP 10-19-10-B7-A1-D7-Implementation-3；每 peer 独立）。
#[derive(Debug)]
pub enum PeerStatus {
    /// 已认证（Established）且身份匹配（不重复 dial / 不重复 Init）。
    Established,
    /// 尚未（已 dial / 已发 Init 或等待对端握手；后续轮再推进）。
    Pending,
    /// 本 peer 建立失败（dial / Init / 签名 typed error；**不阻塞其它 peer**）。
    Failed(RuntimeError),
    /// 网络未启用（无 NetworkStack）。
    Unavailable,
}

/// 单个 configured peer 的建立结果（peer_id + 独立状态；D7-Implementation-3）。
#[derive(Debug)]
pub struct PeerEstablishment {
    pub peer_id: NodeId,
    pub status: PeerStatus,
}

/// Runtime 关闭错误（Stage C `shutdown`；仅 Storage 可失败 ——
/// EventLoop/NetworkService shutdown 均 infallible，Driver 无显式 shutdown）。
#[derive(Debug)]
pub enum ShutdownError {
    /// ChainStorage 关闭失败（`PersistentBackend::close`）。
    Storage(StorageError),
}

/// Stage C 网络子栈（最小 owned container；非 factory / provider / framework）。
///
/// - `ns`：网络状态 owner（own `Transport` / peers / queues；内部经 `Box<dyn Transport>` 注入）。
/// - `el`：dispatch-only（own handler / queue / timer；**不拥有** `ns` —— poll 经注入借用）。
/// - `signer`：网络身份（NodeId + envelope 签名；与 validator identity 分离）。
struct NetworkStack {
    ns: NetworkService<BoxTransport>,
    el: EventLoop<NodeConsensusHandler>,
    signer: Box<dyn NetworkSigner>,
}

impl NetworkStack {
    /// 本网络身份 NodeId（= 网络 key pubkey；≠ ValidatorId）。
    fn node_id(&self) -> NodeId {
        self.signer.node_id()
    }
}

/// 单验证者只读 **compatibility view**（STEP 10-18I-C；非 owning）。
///
/// - ValidatorActor 的真正 ownership 在 [`NodeConsensusDriver`]（`actors: Vec<ValidatorActor<DynSigner>>`）。
/// - [`NodeRuntime::validator`] 在调用时**动态构造**本 view（含对 `driver.actor(0)` 的借用），
///   避免 self-referential ownership；不长期存储 actor 引用字段。
pub struct ValidatorView<'a> {
    validator_id: ValidatorId,
    journal_path: &'a std::path::Path,
    actor: &'a ValidatorActor<DynSigner>,
}

impl ValidatorView<'_> {
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// 本地 ValidatorActor（只读；safety/signing owner 在 actor —— 经 driver 拥有）。
    pub fn actor(&self) -> &ValidatorActor<DynSigner> {
        self.actor
    }

    pub fn journal_path(&self) -> &std::path::Path {
        self.journal_path
    }
}

/// 生产节点生命周期装配根（STEP 10-16 Phase 1 骨架；STEP 10-18I-C ownership migration；
/// STEP 10-18I-G Stage C Full Composition）。
///
/// - **ConsensusNode + ValidatorActor 的实际 ownership 在 [`NodeConsensusDriver`]**（`driver` 字段）；
///   Runtime **不再**独立持有 ConsensusNode / ValidatorActor（避免 duplication，ADR-0057）。
/// - 网络（NetworkService / EventLoop / NetworkSigner）以可选 [`NetworkStack`] 装配：
///   `start()` ⇒ `None`（网络 disabled，不生成网络身份）；`start_with_network()` ⇒ `Some`。
/// - Runtime 只负责 composition / lifecycle / accessor delegation（最终 lifecycle coordinator）。
pub struct NodeRuntime {
    chain_identity: ChainIdentity,
    /// chain storage owner（full-node 形态：Phase 1 裸 PersistentBackend handle）。validator ⇒ `None`。
    chain_storage: Option<PersistentBackend>,
    /// validator-mode 形态：bootstrap 装配的 NodeBlockAdapter（canonical StateStore + ChainHead +
    /// genesis 参数单一 owner；BlockBuilder 只读出块输入）。full-node ⇒ `None`。
    block_production: Option<NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>>,
    driver: NodeConsensusDriver<DynSigner>,
    /// 可选网络子栈（Stage C；`start` ⇒ `None`）。
    network_stack: Option<NetworkStack>,
    /// 静态 configured connection targets（STEP 10-19-10-B7-A3；来自 `config.peers`）。
    configured_targets: Vec<ConnectionTarget>,
    /// 已为各 configured peer 发送过 outbound Handshake Init 的集合（per-peer；防重复发送）。
    /// D7-Implementation-3：每 peer 独立 —— disconnect(A) 只清 A，不影响 B/C。
    handshake_init_sent_for: HashSet<NodeId>,
    /// validator 元数据（safety journal 路径；actor 本体在 driver）。full-node ⇒ `None`。
    validator_journal: Option<PathBuf>,
    /// step-driven proposer 出块的显式 timestamp（默认 0；无系统时钟；调用方可配置）。
    proposal_timestamp: u64,
    /// 最近一次本地出块产物（本地保留；不持久化 / 不推进 head）。
    last_proposal: Option<ProposalBuild>,
    /// 协议最大块字节（来自 genesis `protocol_parameters`；block inbound validation 上限；
    /// 不修改协议参数 —— 只读供 `block_dispatch` context 使用）。
    max_block_bytes: usize,
    /// block inbound dispatch 的 typed 观测（STEP 10-19-10-A；bounded，满则丢最早）。
    /// 只读验证结果；**不 commit / 不写存储 / 不推进 head**。
    block_inbound_outcomes: VecDeque<Result<InboundBlockVerdict, InboundBlockError>>,
    /// 无 canonical 上下文（full-node / 无 adapter）而跳过的 block inbound payload 数。
    block_inbound_skipped: u64,
    /// missing-ancestor intent ledger（STEP 10-19-10-B1；bounded + dedup）。
    /// 仅记录 `FutureMissingAncestor` 观察；**不发送 / 不写存储 / 不触发 finality**。
    missing_ancestor_ledger: MissingAncestorIntentLedger,
    /// outbound sync request scheduler（D8-2；bounded FIFO；不拥有 transport）。
    sync_scheduler: SyncRequestScheduler,
    /// outbound sync request correlator（D8-2；register/resolve/timeout 状态机；不拥有 transport）。
    sync_correlator: SyncRequestCorrelator,
    /// sync 编排确定性逻辑 tick（每网络 step 自增；D8-3-1 驱动 expire_at release-only）。
    sync_tick: LogicalTick,
    /// 收到且 correlation 成功的 SyncBlockResponse 数（request lifecycle 完成；观测）。
    sync_resolved_responses: u64,
    /// 收到但无对应 active request / 结构损坏而被拒的 SyncBlockResponse 数（Unknown；观测）。
    sync_unknown_responses: u64,
}

impl NodeRuntime {
    /// 启动（网络 disabled）：Consensus + Storage（+ validator）正常启动；**不**装配
    /// NetworkStack（不生成网络身份）。行为与 Stage C 前完全兼容。
    pub fn start(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, None)
    }

    /// 启动（Stage C Full Composition）：在 `start` 基础上注入网络 assets ——
    /// `transport: Box<dyn Transport>`（MemoryTransport test/dev；未来 production adapter 注入）
    /// 与 `network_identity: Box<dyn NetworkSigner>`（网络身份；**不得**用 validator key）。
    ///
    /// 顺序保证：`NetworkIdentity → node_id() → NetworkService::new(self_id, transport)`；
    /// `NodeId = NetworkSigner::node_id()`（≠ ValidatorId）。
    pub fn start_with_network(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        transport: Box<dyn Transport>,
        network_identity: Box<dyn NetworkSigner>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, Some((transport, network_identity)))
    }

    /// 内部启动：固定顺序（§模块 doc）。任何安全失败 ⇒ `Err`（fail closed）。
    ///
    /// - `key_provider`：validator mode 时**必须**提供（None ⇒ `KeyNotProvisioned`）；
    ///   full-node 时忽略。
    /// - `network_assets`：`Some((transport, network_identity))` ⇒ 装配 NetworkStack。
    /// - SafetyStore 打开 / recover 仍在 Runtime lifecycle（`build_validator`）；
    ///   Driver 只接收已构造好的 `ConsensusNode` + `ValidatorActor(s)`。
    fn start_inner(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        network_assets: Option<(Box<dyn Transport>, Box<dyn NetworkSigner>)>,
    ) -> Result<Self, NodeRuntimeError> {
        // 2/3. Genesis + ChainIdentity validation（expected hash/chain/network）。
        let (genesis, identity) =
            bootstrap::load_genesis(config).map_err(NodeRuntimeError::Startup)?;

        // 4. chain storage owner：
        //    - validator mode：bootstrap 装配 NodeBlockAdapter（canonical StateStore + ChainHead +
        //      genesis 参数；首启 bootstrap genesis state，单一 backend owner，不另开裸 handle）。
        //    - full-node：Phase 1 裸 PersistentBackend handle（现状；不触碰 Provider / validator）。
        let (chain_storage, block_production, consensus_start_height) = if config.validator_enabled
        {
            let adapter = bootstrap::start(NoAccountsKeyResolver, config)
                .map_err(NodeRuntimeError::Startup)?;
            let head_height = adapter.head().height;
            (None, Some(adapter), head_height)
        } else {
            std::fs::create_dir_all(&config.storage_dir)
                .map_err(|_| NodeRuntimeError::Startup(NodeStartupError::StorageIo))?;
            let backend = PersistentBackend::open(&config.storage_dir)
                .map_err(NodeStartupError::Storage)
                .map_err(NodeRuntimeError::Startup)?;
            (Some(backend), None, 0)
        };

        // 10. ConsensusNode（canonical state owner）——随后装配进 NodeConsensusDriver。
        //     validator：初始共识高度 = canonical head height（ChainHead 单一高度源）；full-node = 0。
        let set = ValidatorSet::from_genesis(&genesis);
        let consensus = ConsensusNode::new(
            consensus_start_height,
            0,
            identity.chain_id,
            set,
            identity.genesis_hash,
            Dag::new(),
        );

        // 5–11. validator mode：KeyProvider → id → SafetyStore → recover → ValidatorActor
        //      （Runtime lifecycle）→ 与 ConsensusNode 一并装配进 NodeConsensusDriver。
        let (driver, validator_journal) = if config.validator_enabled {
            let (actor, journal_path) = Self::build_validator(config, &identity, key_provider)?;
            let driver = NodeConsensusDriver::new(consensus, vec![actor]);
            (driver, Some(journal_path))
        } else {
            // full-node：consensus-only driver（actors = []）；不触碰 Provider。
            let driver = NodeConsensusDriver::<DynSigner>::new(consensus, Vec::new());
            (driver, None)
        };

        // Stage C：网络资产注入 ⇒ NetworkStack（identity → node_id → NetworkService）。
        //   configured peers 校验（self / duplicate）在 dial 前启动时执行（fail-closed）；
        //   NS 注入 TcpDialer（复用 D4 seam；Node 不直调 TcpTransport::dial）。
        let network_stack = match network_assets {
            Some((transport, network_identity)) => {
                let self_id = network_identity.node_id();
                config
                    .validate_network_targets(self_id)
                    .map_err(NodeRuntimeError::NetworkTarget)?;
                // D5：装配 peer-auth（network/chain/genesis/protocol/caps/rate/replay）——
                //   使 inbound process_handshake 能执行认证（session owner = NetworkService）。
                let auth = Self::network_peer_auth(&identity);
                let ns = NetworkService::new(
                    NetworkServiceConfig {
                        peer_auth: Some(auth),
                        ..Default::default()
                    },
                    self_id,
                    BoxTransport::new(transport),
                )
                .with_dialer(Box::new(TcpDialer));
                let el = EventLoop::new(EventLoopConfig::default(), NodeConsensusHandler::new());
                Some(NetworkStack {
                    ns,
                    el,
                    signer: network_identity,
                })
            }
            None => None,
        };

        // 协议参数（block inbound size 上限；来自 genesis；只读）。
        let max_block_bytes = genesis.protocol_parameters.max_block_bytes as usize;

        Ok(Self {
            chain_identity: identity,
            chain_storage,
            block_production,
            driver,
            network_stack,
            configured_targets: config.peers.clone(),
            handshake_init_sent_for: HashSet::new(),
            validator_journal,
            proposal_timestamp: 0,
            last_proposal: None,
            max_block_bytes,
            block_inbound_outcomes: VecDeque::new(),
            block_inbound_skipped: 0,
            missing_ancestor_ledger: MissingAncestorIntentLedger::new(MISSING_ANCESTOR_LEDGER_CAP),
            sync_scheduler: SyncRequestScheduler::new(SYNC_SCHEDULER_CAP),
            sync_correlator: SyncRequestCorrelator::new(SYNC_CORRELATOR_CAP),
            sync_tick: 0,
            sync_resolved_responses: 0,
            sync_unknown_responses: 0,
        })
    }

    /// validator mode 生命周期装配（key provider → derive id → safety store → recover → actor）。
    /// 返回 `(actor, journal_path)`；actor 随后移入 Driver（ownership）。
    fn build_validator(
        config: &NodeConfig,
        identity: &ChainIdentity,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<(ValidatorActor<DynSigner>, PathBuf), NodeRuntimeError> {
        // 5. KeyProvider（validator mode 必填；不默认生成不稳定生产密钥）。
        let provider = key_provider.ok_or(NodeRuntimeError::KeyNotProvisioned)?;
        let signer = provider
            .load_signer()
            .map_err(NodeRuntimeError::KeyProvider)?;
        let public_key = signer.public_key().to_bytes();

        // 6. derive ValidatorId（单一来源）。
        let validator_id = derive_validator_id(&public_key);

        // 7. SafetyIdentity + SafetyStore open（独立 safety_dir；与 chain storage 分离）。
        let safety_identity = SafetyIdentity::new(
            identity.network_id,
            identity.chain_id,
            identity.genesis_hash,
            &validator_id,
        );
        let journal_path = config.safety_dir.join("safety.journal");
        let store = if journal_path.exists() {
            ValidatorSafetyStore::at(&journal_path, safety_identity)
        } else {
            ValidatorSafetyStore::create(&journal_path, safety_identity)
                .map_err(NodeRuntimeError::Safety)?
        };

        // 8/9. strict recover（restore 内部执行）→ 构造 ValidatorActor。
        //      recover / identity mismatch ⇒ Err ⇒ validator mode 启动失败（fail closed）。
        let actor = ValidatorActor::restore(validator_id, signer, identity.chain_id, store)
            .map_err(NodeRuntimeError::Validator)?;

        Ok((actor, journal_path))
    }

    pub fn chain_identity(&self) -> &ChainIdentity {
        &self.chain_identity
    }

    /// chain storage handle（full-node 形态；validator ⇒ `None`）。
    pub fn chain_storage(&self) -> Option<&PersistentBackend> {
        self.chain_storage.as_ref()
    }

    /// validator-mode block-production adapter（canonical store + head + genesis 参数；只读）。
    pub fn block_production(
        &self,
    ) -> Option<&NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>> {
        self.block_production.as_ref()
    }

    /// 最近一次本地出块产物（本地保留；不持久化 / 不推进 head）。
    pub fn last_proposal(&self) -> Option<&ProposalBuild> {
        self.last_proposal.as_ref()
    }

    /// 取走 block inbound dispatch 观测（STEP 10-19-10-A；FIFO；bounded）。
    ///
    /// 每项 = `Ok(verdict)`（含 `CanonicalNextCandidate` 等分类）或 `Err(reason)`
    /// （`Oversized`/`Malformed`/`WrongChain`/…/`UnsupportedValidation`）。
    /// 只读观测：**不 commit / 不写存储 / 不推进 head**。
    pub fn take_block_inbound_outcomes(
        &mut self,
    ) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
        self.block_inbound_outcomes.drain(..).collect()
    }

    /// 当前 block inbound 观测深度。
    pub fn block_inbound_outcome_len(&self) -> usize {
        self.block_inbound_outcomes.len()
    }

    /// 无 canonical 上下文（full-node）而跳过的 block inbound payload 计数。
    pub fn block_inbound_skipped(&self) -> u64 {
        self.block_inbound_skipped
    }

    /// 当前 missing-ancestor intent ledger 深度（STEP 10-19-10-B1）。
    pub fn missing_ancestor_intent_len(&self) -> usize {
        self.missing_ancestor_ledger.len()
    }

    /// 取走全部 missing-ancestor intents（FIFO；consuming）。只读/消费观测；不发送 / 不写存储。
    pub fn take_missing_ancestor_intents(
        &mut self,
    ) -> Vec<crate::intent_ledger::MissingAncestorIntent> {
        self.missing_ancestor_ledger.take_all()
    }

    /// 收到且 correlation 成功的 SyncBlockResponse 数（D8-3-1；request lifecycle resolve）。
    pub fn sync_resolved_responses(&self) -> u64 {
        self.sync_resolved_responses
    }

    /// 收到但 Unknown / 结构损坏而被拒的 SyncBlockResponse 数（D8-3-1；安全拒绝观测）。
    pub fn sync_unknown_responses(&self) -> u64 {
        self.sync_unknown_responses
    }

    /// 当前 outbound sync correlator 中 active（未 resolve / 未 expire）request 数
    /// （D8-3-1 观测：request lifecycle register→resolve→release 的 active 深度）。
    pub fn sync_pending_requests(&self) -> usize {
        self.sync_correlator.len()
    }

    /// 显式设置 step-driven 出块 timestamp（无系统时钟；默认 0；确定性由调用方保证）。
    pub fn set_proposal_timestamp(&mut self, timestamp: u64) {
        self.proposal_timestamp = timestamp;
    }

    /// NodeConsensusDriver（只读；ConsensusNode + ValidatorActor 的 owner）。
    pub fn driver(&self) -> &NodeConsensusDriver<DynSigner> {
        &self.driver
    }

    /// 网络身份 NodeId（`start_with_network` 启用时 `Some`）。
    /// NodeId 来自网络 key pubkey（≠ ValidatorId；Network/Validator identity 分离）。
    pub fn network_node_id(&self) -> Option<NodeId> {
        self.network_stack.as_ref().map(NetworkStack::node_id)
    }

    /// configured peer 当前是否已认证 Established（D7-Implementation-3 观测；只读）。
    pub fn network_peer_established(&self, peer_id: NodeId) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.is_peer_established(peer_id))
            .unwrap_or(false)
    }

    /// configured peer 当前是否 connected（D7-Implementation-3 观测；只读）。
    pub fn network_peer_connected(&self, peer_id: NodeId) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.is_connected(peer_id))
            .unwrap_or(false)
    }

    /// 连接第一个 configured connection target（STEP 10-19-10-B7-A3；single-active）。
    ///
    /// - 无网络栈 / 无 configured peers / 已有 active connection ⇒ `Ok(None)`（幂等）。
    /// - 配置校验（self / duplicate）已在启动（`start_with_network`）时 fail-closed；此处直接
    ///   dial `configured_targets[0]`（ordered；不并发 / 不多连接）。
    /// - 成功 ⇒ `Ok(Some(peer_id))`（仅 `Connected`；**不 handshake / 不 Established**）。
    /// - dial 失败 ⇒ `Err(NetworkDial(..))`（不自动 retry / 不自动换 peer / 不自动 next）。
    pub fn connect_configured_peer(&mut self) -> Result<Option<NodeId>, RuntimeError> {
        if self.configured_targets.is_empty() {
            return Ok(None);
        }
        let max_frame = {
            let Some(stack) = &self.network_stack else {
                return Ok(None);
            };
            if stack.ns.connected_peer_count() > 0 {
                // single-active：已有 active connection（不重连 / 不静默替换）。
                return Ok(None);
            }
            stack.ns.config().max_msg_bytes
        };
        let t = self.configured_targets[0];
        let Some(stack) = &mut self.network_stack else {
            return Ok(None);
        };
        stack
            .ns
            .dial_peer(t.address, t.peer_id, max_frame, None)
            .map_err(RuntimeError::NetworkDial)?;
        Ok(Some(t.peer_id))
    }

    /// 是否已装配 network peer-auth（`start_with_network` 网络启用时为 `true`）。
    pub fn network_peer_auth_enabled(&self) -> bool {
        self.network_stack
            .as_ref()
            .map(|s| s.ns.config().peer_auth.is_some())
            .unwrap_or(false)
    }

    /// 建立 configured peer（STEP 10-19-10-B7-A1-D5；single-active）。
    ///
    /// 只编排（**不实现握手协议** —— 信封签名 / session 验证全归 NetworkSigner 与
    /// NetworkService `process_handshake`）：dial（若未连）→ 发本端 Handshake Init（每目标一次；
    /// 每次新 nonce）→ poll 一次推进 → 判定：
    /// - configured peer `Established` ⇒ `Ok(Some(peer_id))`（authenticated 且 == configured）；
    /// - 尚无对端握手 ⇒ `Ok(None)`（pending；后续 step 再调本方法推进，不重 dial / 不重发）；
    /// - 收到**其它** peer 合法握手（identity mismatch）⇒ 断开 + `Err(IdentityMismatch)`
    ///   （fail-closed：address 正确 ≠ identity 正确）；
    /// - dial / 构造 / 签名 / 发送失败 ⇒ typed error（不自动 retry / 不自动换 peer / 不 sleep）。
    pub fn establish_configured_peer(&mut self) -> Result<Option<NodeId>, RuntimeError> {
        let Some(target) = self.configured_targets.first().copied() else {
            return Ok(None);
        };
        // 0. 已 Established 目标 ⇒ 完成（幂等）。
        let established_now = self
            .network_stack
            .as_ref()
            .map(|s| s.ns.is_peer_established(target.peer_id))
            .unwrap_or(false);
        if established_now {
            self.handshake_init_sent_for.remove(&target.peer_id);
            return Ok(Some(target.peer_id));
        }
        // 1. dial（无 active connection 时）。
        let dial_needed = self
            .network_stack
            .as_ref()
            .map(|s| s.ns.connected_peer_count() == 0)
            .unwrap_or(false);
        if dial_needed {
            let (addr, remote, max_frame) = {
                let Some(stack) = &self.network_stack else {
                    return Ok(None);
                };
                let max_frame = stack.ns.config().max_msg_bytes;
                (target.address, target.peer_id, max_frame)
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .ns
                .dial_peer(addr, remote, max_frame, None)
                .map_err(RuntimeError::NetworkDial)?;
        }
        // 2. 发送本端 Handshake Init（每目标一次；新 nonce）。
        if !self.handshake_init_sent_for.contains(&target.peer_id) {
            let env = {
                let Some(stack) = &self.network_stack else {
                    return Ok(None);
                };
                let auth = stack
                    .ns
                    .config()
                    .peer_auth
                    .ok_or(RuntimeError::PeerAuthMissing)?;
                Self::build_outbound_handshake(stack.signer.as_ref(), &auth)?
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .ns
                .enqueue_outbound(target.peer_id, env)
                .map_err(RuntimeError::NetworkDial)?;
            let _ = stack.ns.flush_outbound();
            self.handshake_init_sent_for.insert(target.peer_id);
        }
        // 3. poll 一次推进（读对端握手；无 while / 无 sleep）。
        let outcome = {
            let Some(stack) = &mut self.network_stack else {
                return Ok(None);
            };
            stack
                .el
                .poll_once(&mut stack.ns)
                .map_err(RuntimeError::EventLoop)?;
            if stack.ns.is_peer_established(target.peer_id) {
                HandshakeOutcome::Established(target.peer_id)
            } else {
                let foreign: Vec<NodeId> = stack.ns.established_peers();
                if foreign.is_empty() {
                    HandshakeOutcome::Pending
                } else {
                    HandshakeOutcome::ForeignEstablished(foreign)
                }
            }
        };
        match outcome {
            HandshakeOutcome::Established(id) => {
                self.handshake_init_sent_for.remove(&id);
                Ok(Some(id))
            }
            HandshakeOutcome::Pending => Ok(None),
            HandshakeOutcome::ForeignEstablished(others) => {
                // address 正确 ≠ identity 正确：收到其它 peer 的合法握手 → fail-closed 断开。
                if let Some(stack) = &mut self.network_stack {
                    for o in &others {
                        let _ = stack.ns.disconnect_peer(*o);
                    }
                    let _ = stack.ns.disconnect_peer(target.peer_id);
                }
                for o in &others {
                    self.handshake_init_sent_for.remove(o);
                }
                self.handshake_init_sent_for.remove(&target.peer_id);
                Err(RuntimeError::IdentityMismatch {
                    configured: target.peer_id,
                })
            }
        }
    }

    /// 断开 first configured peer 并清其握手状态（STEP 10-19-10-B7-A1-D6 生命周期；兼容单 peer）。
    ///
    /// - 调用 `NetworkService::disconnect_peer`（PeerManager connected 清除 + session 清除；
    ///   session owner = NetworkService，此处不手工改 session）。
    /// - 清该 peer 的 `handshake_init_sent_for` ⇒ 之后可重新 dial + 生成 **新 nonce** + 发送
    ///   新 Init（reconnect；L5/L6）。幂等（未连接 / 空 peers ⇒ Ok）。
    pub fn disconnect_configured_peer(&mut self) -> Result<(), RuntimeError> {
        let Some(target) = self.configured_targets.first().copied() else {
            return Ok(());
        };
        self.disconnect_configured_peer_for(target.peer_id)
    }

    /// 断开指定 configured peer 并清其 per-peer Init 状态（D7-Implementation-3）。
    ///
    /// **只影响该 peer**：其它 configured peers 的 connection / session / handshake 状态不受影响
    /// （`NetworkService::disconnect_peer` 本身即单 peer 清理 —— D7-1/2 隔离语义）。非 configured
    /// peer 或未连接 ⇒ 幂等 Ok。不自动 reconnect（之后显式 `establish_configured_peers` 可重建）。
    pub fn disconnect_configured_peer_for(&mut self, peer_id: NodeId) -> Result<(), RuntimeError> {
        if !self.configured_targets.iter().any(|t| t.peer_id == peer_id) {
            return Ok(());
        }
        if let Some(stack) = &mut self.network_stack {
            stack
                .ns
                .disconnect_peer(peer_id)
                .map_err(RuntimeError::NetworkDial)?;
        }
        self.handshake_init_sent_for.remove(&peer_id);
        Ok(())
    }

    /// 建立**全部** configured peers（STEP 10-19-10-B7-A1-D7-Implementation-3；multi-peer）。
    ///
    /// 单次调用 = 一轮受控推进，对每个 configured target（配置顺序，确定性）：
    /// （1）已 Established ⇒ 跳过（不重复 dial / 不重复 Init）；
    /// （2）未 connected ⇒ `dial_peer`（KEEP-FIRST 防同 NodeId 重复连接）；
    /// （3）已 connected 但本 peer 未发过 Init ⇒ 发送一次（per-peer `handshake_init_sent_for`）；
    ///     已发 ⇒ 等待后续 poll。
    /// 随后 **一次 bounded poll**（`EventLoop::poll_once` ⇒ `NetworkService::poll_transport`
    /// 轮询全部 connections —— NS 是 A/B/C connections owner；Runtime 不直连 Transport）。
    ///
    /// 错误隔离：单个 peer 的 dial / Init / 签名失败只进该 peer 的 `PeerStatus::Failed`，
    /// **不阻塞其它 peer**；仅全局 poll（EventLoop/NS 层）失败 ⇒ `Err(RuntimeError)`。
    /// 返回 `Ok(Vec<PeerEstablishment>)`（按 `configured_targets` 顺序，每 peer 独立结果）。
    ///
    /// 幂等 / 显式 reconnect：Established 不重复建立；EOF/断开后的 peer 再次调用本方法
    /// （无自动 reconnect / 无 retry / 无 timer）即可重建。
    pub fn establish_configured_peers(&mut self) -> Result<Vec<PeerEstablishment>, RuntimeError> {
        let targets: Vec<ConnectionTarget> = self.configured_targets.clone();
        if self.network_stack.is_none() {
            return Ok(targets
                .iter()
                .map(|t| PeerEstablishment {
                    peer_id: t.peer_id,
                    status: PeerStatus::Unavailable,
                })
                .collect());
        }
        // A. per-peer 准备（dial / Init）；错误隔离：单 peer 失败记入其 status，继续其它。
        let mut prepare: Vec<Option<RuntimeError>> = Vec::with_capacity(targets.len());
        for t in &targets {
            match self.establish_prepare(t.peer_id, t.address) {
                Ok(()) => prepare.push(None),
                Err(e) => prepare.push(Some(e)),
            }
        }
        // B. 一次 bounded poll（推进全部连接的握手；无 while / 无 sleep / 无 async）。
        if let Some(stack) = &mut self.network_stack {
            stack
                .el
                .poll_once(&mut stack.ns)
                .map_err(RuntimeError::EventLoop)?;
        }
        // C. 观察每 target 状态（Established / Pending / prepare 错误）。
        let mut out = Vec::with_capacity(targets.len());
        for (i, t) in targets.iter().enumerate() {
            if let Some(e) = prepare[i].take() {
                out.push(PeerEstablishment {
                    peer_id: t.peer_id,
                    status: PeerStatus::Failed(e),
                });
                continue;
            }
            let established = self
                .network_stack
                .as_ref()
                .map(|s| s.ns.is_peer_established(t.peer_id))
                .unwrap_or(false);
            let status = if established {
                PeerStatus::Established
            } else {
                PeerStatus::Pending
            };
            out.push(PeerEstablishment {
                peer_id: t.peer_id,
                status,
            });
        }
        Ok(out)
    }

    /// 单 target 的 dial / Init 准备（D7-Implementation-3；per-peer；不 poll）。
    ///
    /// - 已 Established ⇒ 不 dial / 不 Init（返回 Ok）。
    /// - 未 connected ⇒ `dial_peer`（dial 失败 ⇒ Err；由调用方隔离）。
    /// - 已 connected 但本 peer 未发过 Init ⇒ 构造 + 发送一次（每 target 一次；新 nonce）。
    fn establish_prepare(
        &mut self,
        remote: NodeId,
        address: std::net::SocketAddr,
    ) -> Result<(), RuntimeError> {
        let Some(stack) = &self.network_stack else {
            return Ok(());
        };
        if stack.ns.is_peer_established(remote) {
            return Ok(());
        }
        // dial（若未连；per-peer —— NS KEEP-FIRST 保证同 NodeId 不重复连接）。
        if !stack.ns.is_connected(remote) {
            let max_frame = stack.ns.config().max_msg_bytes;
            let Some(stack) = &mut self.network_stack else {
                return Ok(());
            };
            stack
                .ns
                .dial_peer(address, remote, max_frame, None)
                .map_err(RuntimeError::NetworkDial)?;
        }
        // 发送 Init（本 peer 未发过；per-peer 集合）。
        if !self.handshake_init_sent_for.contains(&remote) {
            let env = {
                let Some(stack) = &self.network_stack else {
                    return Ok(());
                };
                let auth = stack
                    .ns
                    .config()
                    .peer_auth
                    .ok_or(RuntimeError::PeerAuthMissing)?;
                Self::build_outbound_handshake(stack.signer.as_ref(), &auth)?
            };
            let Some(stack) = &mut self.network_stack else {
                return Ok(());
            };
            stack
                .ns
                .enqueue_outbound(remote, env)
                .map_err(RuntimeError::NetworkDial)?;
            let _ = stack.ns.flush_outbound();
            self.handshake_init_sent_for.insert(remote);
        }
        Ok(())
    }

    /// outbound sync orchestration（STEP 10-19-10-B7-A1-D8-2；同步、确定性、有界；无 self ——
    /// step 内字段级借用调用，避免与活跃 NetworkStack 借用冲突）。
    ///
    /// 每 step 一轮：
    /// （1）candidate = Established peers（`ns`；D7 建立；无 Established ⇒ 不产生 / 不发送 ——
    ///      不 dial / 不 handshake / 不 reconnect）；
    /// （2）有界消费 `ledger` intents（`SYNC_SCHEDULE_MAX_PER_STEP`/step），每条经
    ///      `schedule_from_missing_ancestor`（ADR-0062：target = { local_head_height + 1,
    ///      block_hash: None }；**不伪造 ancestor hash / 不猜 head+1 的 hash**）入 scheduler
    ///      （deterministic peer selection 用候选 Established peers）；
    /// （3）`dispatch_batch`：correlator.register（**register-before-send**）→ dispatcher
    ///      （`NetworkSyncDispatcher`：Established gate → SyncBlockRequest → 网络签名 →
    ///      `NetworkService::enqueue_outbound`）。
    ///
    /// 边界：同步 / deterministic / bounded（scheduler/correlator/queue 均 bounded）；不 dial /
    /// 不自动 retry / 不 backoff / 不重新选 peer；expire 为 **release-only**（释放 active，不重发）；
    /// SyncBlockResponse → persist/commit 不在此（保持既有 inbound validation / observation）。
    fn sync_orchestrate(
        ns: &mut NetworkService<BoxTransport>,
        signer: &dyn NetworkSigner,
        scheduler: &mut SyncRequestScheduler,
        correlator: &mut SyncRequestCorrelator,
        tick: &mut LogicalTick,
        ledger: &mut MissingAncestorIntentLedger,
        head_height: Option<u64>,
    ) -> Result<(), RuntimeError> {
        // 0. D8-3-1-E：每 step 推进 deterministic tick + expire 到期 active request
        //    （release-only：无 retry / 无 backoff / 无重新选 peer；correlator capacity 即有界）。
        *tick = tick.saturating_add(1);
        let _expired = correlator.expire_at(*tick);
        // 1. candidate = Established peers（SI-6：只向 Established 发送）。
        let candidates: Vec<PeerCandidate> = ns
            .established_peers()
            .into_iter()
            .map(|id| PeerCandidate { peer_id: id })
            .collect();
        if candidates.is_empty() {
            // 无 Established peer ⇒ 不产生 request（不 dial / 不 reconnect —— 属 D7 lifecycle）。
            return Ok(());
        }
        let policy = PeerSelectionPolicy::default();
        // 2. 有界消费 ledger intents（take_all ≤ cap；本 step 上限 SYNC_SCHEDULE_MAX_PER_STEP）。
        let intents = ledger.take_all();
        let mut scheduled = 0usize;
        for intent in intents {
            if scheduled >= SYNC_SCHEDULE_MAX_PER_STEP {
                break;
            }
            // 陈旧过滤：本地 canonical head 已 ≥ observed 高度 ⇒ 该区间不再待补。
            if let Some(hh) = head_height
                && intent.observed_height <= hh
            {
                continue;
            }
            let peer = match select_peer(&policy, &candidates, &[]) {
                Ok(p) => p,
                Err(_) => continue, // 无可用候选（candidates 非空时不发生）
            };
            let request_id = random_request_id().map_err(RuntimeError::NetworkSecurity)?;
            let r = scheduler.schedule_from_missing_ancestor(request_id, peer, &intent);
            if r == ScheduleResult::Scheduled {
                scheduled += 1;
            }
            // Duplicate / Full：bounded 丢弃（不自动重试；同一 intent 只消费一次 —— T10）。
        }
        if scheduler.is_empty() {
            return Ok(());
        }
        // 3. dispatch（register-before-send）：deadline = 当前 tick + horizon（expire 在函数头
        //    已驱动；D8-3-1 不自动 retry）。
        let deadline = tick.saturating_add(SYNC_DEADLINE_HORIZON);
        let mut dispatcher = NetworkSyncDispatcher::new(ns, signer);
        // dispatch_batch：register-before-send；send 失败（Rejected）⇒ release 该 request（D8-3-1-B）。
        let report = dispatch_batch(
            scheduler,
            correlator,
            &mut dispatcher,
            deadline,
            SYNC_DISPATCH_MAX_PER_STEP,
        );
        let _ = report;
        Ok(())
    }

    /// 构造 outbound Handshake Init envelope（本端身份；`claimed = signer.node_id()`，**非**
    /// configured peer）。复用 session `handshake_payload_encode` + `random_session_nonce`
    /// （每次新 nonce）+ 既有 `MessageEnvelope` + `NetworkSigner::sign_envelope`。
    fn build_outbound_handshake(
        signer: &dyn NetworkSigner,
        auth: &PeerAuthConfig,
    ) -> Result<MessageEnvelope, RuntimeError> {
        let nonce = random_session_nonce().map_err(RuntimeError::Session)?;
        let local = signer.node_id();
        let payload = handshake_payload_encode(
            HandshakeKind::Init,
            auth.network_id,
            auth.chain_id,
            auth.genesis_hash,
            auth.protocol_version,
            &local,
            &nonce,
            auth.capabilities,
        )
        .map_err(RuntimeError::Session)?;
        let mut env = MessageEnvelope {
            version: 1,
            message_type: MessageType::Handshake,
            payload,
            sender: local,
            signature: [0u8; 64],
        };
        signer
            .sign_envelope(&mut env)
            .map_err(RuntimeError::NetworkSigning)?;
        Ok(env)
    }

    /// network peer-auth 配置（ChainIdentity 绑定 network/chain/genesis + 协议常量）。
    fn network_peer_auth(identity: &ChainIdentity) -> PeerAuthConfig {
        PeerAuthConfig {
            network_id: identity.network_id,
            chain_id: identity.chain_id,
            genesis_hash: identity.genesis_hash,
            protocol_version: NETWORK_PROTOCOL_VERSION,
            capabilities: b"",
            per_peer_handshake_limit: 8,
            global_handshake_limit: 128,
            replay_cache_capacity: 256,
        }
    }

    /// 取走 Driver 验证 PASS 后待广播的 consensus outbound **semantic**（手动提取 / 测试用；
    /// `step()` 会自行 drain + egress）。网络 disabled 亦可调用（outbound 在 Driver，独立于
    /// NetworkStack）。
    pub fn take_consensus_outbound(&mut self) -> Vec<OutboundConsensusMessage> {
        self.driver.take_outbound()
    }

    /// consensus orchestration 入口（STEP 10-18I-D-A Option A）：把 node 层 consensus command
    /// （EventLoop → Handler decode queue → Runtime 承接）交给 Driver 的既有安全门面。
    /// - verify/decode/transition 门面 FAIL 原样以 `DriverError` 传出（不吞错、不改状态）。
    /// - outbound：验证 PASS 后入 Driver pending（STEP 10-18I-N-IMPL：`step()` 末尾 drain →
    ///   egress adapter 签名 → `NetworkService` broadcast）；本方法仅承接 command。
    /// - 借用生命周期严格限当前调用（不长期借 Driver；无 self-reference）。
    pub fn process_consensus_command(
        &mut self,
        command: NodeConsensusCommand,
    ) -> Result<(), DriverError> {
        process_command(&mut self.driver, command)
    }

    /// canonical consensus node handle（只读）—— **delegate** `driver.consensus()`（不复制）。
    pub fn consensus(&self) -> &ConsensusNode {
        self.driver.consensus()
    }

    /// validator mode 是否启用 —— **delegate** `driver.actor_count()`。
    pub fn validator_enabled(&self) -> bool {
        self.driver.actor_count() > 0
    }

    /// 单验证者只读 view（validator mode 时为 `Some`）—— **delegate** `driver.actor(0)`。
    /// 调用时动态构造（含对 actor 的借用）；不长期存储 actor 引用（无 self-reference）。
    pub fn validator(&self) -> Option<ValidatorView<'_>> {
        let actor = self.driver.actor(0)?;
        let journal = self.validator_journal.as_ref()?;
        Some(ValidatorView {
            validator_id: actor.validator_id(),
            journal_path: journal.as_path(),
            actor,
        })
    }

    /// 一轮运行时驱动（Stage C）：网络 disabled（`start`）⇒ `Ok(())`（不产生网络 identity）；
    /// 启用网络（`start_with_network`）⇒ EventLoop poll NetworkService → dispatch →
    /// Handler 产 **owned** `NodeConsensusCommand` → Runtime drain → `process_command` →
    /// Driver（既有验证门面）→ ConsensusNode / ValidatorActor。
    ///
    /// borrow-safe：`poll_once` 临时借 `stack.el` + `stack.ns`（同栈内 disjoint 字段）；
    /// `take_commands()` 返回 owned commands 后即释放 EventLoop 借用；随后才 `&mut self.driver`。
    /// 无 `Handler → &mut Driver/Runtime`、无 self-reference（无 Rc/RefCell/Arc/unsafe/async）。
    pub fn step(&mut self) -> Result<(), RuntimeError> {
        let Some(stack) = &mut self.network_stack else {
            // 网络 disabled：node-local proposer orchestration（真实 BlockBuilder；显式 timestamp）。
            let proposal = runtime_propose(
                &mut self.driver,
                &self.block_production,
                self.proposal_timestamp,
            )?;
            if let Some(pb) = proposal {
                self.last_proposal = Some(pb);
            }
            return Ok(());
        };
        stack
            .el
            .poll_once(&mut stack.ns)
            .map_err(RuntimeError::EventLoop)?;
        let commands = stack.el.handler_mut().take_commands();
        for command in commands {
            process_command(&mut self.driver, command).map_err(RuntimeError::Driver)?;
        }
        // STEP 10-19-10-A：Node-level block inbound dispatch —— wiring 收集的 GossipBlock /
        // SyncBlockResponse payload → block_inbound validator（只读）→ typed verdict 观测。
        // 不 commit / 不写存储 / 不推进 head（CanonicalNextCandidate 非 finality-authorized）。
        let block_msgs = stack.el.handler_mut().take_block_inbound();
        for msg in block_msgs {
            // D8-3-1-A/C：SyncBlockResponse 先做 request_id correlation —— resolve 匹配的 active
            // request（释放 active capacity；request lifecycle 完成）；Unknown / 结构损坏 ⇒ 安全
            // 拒（不 dispatch 未请求数据 / 不 commit / 不改 canonical / 不创建 request / 不 panic）。
            let msg = match msg {
                BlockInboundMessage::SyncBlockResponse(payload) => {
                    let request_id = match SyncBlockResponse::decode(&payload) {
                        Ok(r) => r.request_id,
                        Err(_) => {
                            // 结构损坏：无法取得 request_id ⇒ 拒（记 unknown；不产生 request）。
                            self.sync_unknown_responses += 1;
                            continue;
                        }
                    };
                    match self.sync_correlator.resolve(request_id) {
                        Ok(_target) => {
                            // resolved：request lifecycle 完成（D8-3-1-C）；block payload 原样交
                            // 后续阶段（本步只 correlation —— 不验证 / 不持久化 / 不 commit）。
                            self.sync_resolved_responses += 1;
                        }
                        Err(_) => {
                            // Unknown request：安全拒绝（不改 correlator / 不创建 / 不 panic）。
                            self.sync_unknown_responses += 1;
                            continue;
                        }
                    }
                    // resolved ⇒ 继续既有 block inbound（adapter 只读验证观测；不 commit）。
                    BlockInboundMessage::SyncBlockResponse(payload)
                }
                other => other,
            };
            let (source, outcomes) = match (&self.block_production, msg) {
                (Some(adapter), BlockInboundMessage::GossipBlock(wire)) => (
                    BlockInboundSource::Gossip,
                    vec![dispatch_gossip_block(adapter, self.max_block_bytes, &wire)],
                ),
                (Some(adapter), BlockInboundMessage::SyncBlockResponse(payload)) => (
                    BlockInboundSource::SyncResponse,
                    dispatch_sync_block_response(adapter, self.max_block_bytes, &payload),
                ),
                (None, _) => {
                    // full-node / 无 canonical adapter：无法验证（无 state/head 上下文）→ 丢弃并计数。
                    self.block_inbound_skipped += 1;
                    continue;
                }
            };
            for outcome in outcomes {
                // observation（bounded outcomes；保留既有语义）
                if self.block_inbound_outcomes.len() >= BLOCK_INBOUND_OUTCOME_CAP {
                    self.block_inbound_outcomes.pop_front();
                }
                // STEP 10-19-10-B1：FutureMissingAncestor → intent ledger（bounded + dedup；
                // 只记录，不发送 / 不写存储 / 不触发 finality）。
                if let Ok(verdict) = &outcome {
                    self.missing_ancestor_ledger.observe(verdict, source);
                }
                self.block_inbound_outcomes.push_back(outcome);
            }
        }
        // STEP 10-19-10-B7-A1-D8-2：outbound sync orchestration —— 消费 bounded missing-ancestor
        // intents → ADR-0062 height-based target（head+1 / hash=None）→ deterministic peer
        // selection → scheduler → correlator.register（register-before-send）→ dispatcher →
        // NetworkService.enqueue_outbound（Established-only）。有界；不 dial / 不 retry / 不
        // timeout 策略（D8-2 边界）；Response→persist/commit 不属本步。
        let sync_head = self.block_production.as_ref().map(|a| a.head().height);
        Self::sync_orchestrate(
            &mut stack.ns,
            stack.signer.as_ref(),
            &mut self.sync_scheduler,
            &mut self.sync_correlator,
            &mut self.sync_tick,
            &mut self.missing_ancestor_ledger,
            sync_head,
        )?;
        // STEP 10-19-6 OPT-1：node-local proposer orchestration —— 仅本节点为当前 proposer 且
        // 阶段 Propose 且本轮未提案时，经 BlockBuilder 产出真实 Block + ProposalRef 并提交；
        // 否则幂等 no-op。不自动投票（vote 仍走既有路径）。
        let proposal = runtime_propose(
            &mut self.driver,
            &self.block_production,
            self.proposal_timestamp,
        )?;
        if let Some(pb) = proposal {
            self.last_proposal = Some(pb);
        }
        // STEP 10-18I-N-IMPL：production egress —— drain Driver semantic outbound →
        // NetworkSigner 编码签名 → NetworkService.broadcast（established-only/queue 由 NS 负责）
        // → flush（TCP send）。sign 失败 fail-closed；NS broadcast/flush 失败（queue full / 无
        // established）按 backpressure drop —— 不 panic、不阻塞共识。
        let outbound = self.driver.take_outbound();
        for msg in outbound {
            let envelope = crate::egress::envelope_for(&msg, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            let _ = stack.ns.broadcast(envelope);
        }
        let _ = stack.ns.flush_outbound();
        Ok(())
    }

    /// 确定性生命周期终止（D2 冻结；**consuming** `self`）。
    ///
    /// 顺序（destructure 一次析构全部字段，显式顺序调用）：
    /// EventLoop stop → NetworkService stop → Driver 生命周期结束（owns ConsensusNode +
    /// ValidatorActor）→ `ChainStorage::close(self)`（最后；consuming）。
    /// - 网络 disabled：跳过 EventLoop/NetworkService；仍 Driver drop + Storage close。
    /// - `PersistentBackend::close` 是唯一可失败子调用 ⇒ `ShutdownError::Storage`。
    /// - 不用 Option 化 Storage / Rc / Arc / Mutex / mem::replace（无绕 ownership workaround）。
    pub fn shutdown(self) -> Result<(), ShutdownError> {
        let Self {
            chain_identity: _,
            chain_storage,
            block_production,
            driver,
            network_stack,
            configured_targets: _,
            handshake_init_sent_for: _,
            validator_journal: _,
            proposal_timestamp: _,
            last_proposal: _,
            max_block_bytes: _,
            block_inbound_outcomes: _,
            block_inbound_skipped: _,
            missing_ancestor_ledger: _,
            sync_scheduler: _,
            sync_correlator: _,
            sync_tick: _,
            sync_resolved_responses: _,
            sync_unknown_responses: _,
        } = self;

        if let Some(mut stack) = network_stack {
            // EventLoop stop → NetworkService stop（独立 owner；EventLoop 不级联 NS）。
            stack.el.shutdown();
            stack.ns.shutdown();
            // signer（Box<dyn NetworkSigner>）随 stack drop（无显式 shutdown）。
        }
        // Driver 生命周期结束（ConsensusNode + ValidatorActor drop；safety 已 durable journal）。
        drop(driver);
        // Storage 最后关闭：
        // - full-node 形态：显式 `PersistentBackend::close`（flush）。
        // - validator 形态：block-production adapter drop（bootstrap/apply 已完成同步 flush，
        //   无待刷写 —— storage crate 无 `StateStore::into_backend` / close seam；BlockStorage STEP
        //   将补正式 close seam）。
        drop(block_production);
        if let Some(storage) = chain_storage {
            storage.close().map_err(ShutdownError::Storage)?;
        }
        Ok(())
    }
}

/// ValidatorId 单一来源（STEP 10-16）：node 装配层统一入口。
///
/// 实现委托 consensus `ValidatorId::from_consensus_public_key`（= SHA-256(pubkey)，crypto 冻结）。
/// 未来把 crypto `identity::validator_id` 与共识实现收敛至此（本步保持值不变，仅统一调用入口）。
pub fn derive_validator_id(public_key: &[u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::identity::validator_id as crypto_validator_id;
    use nova_crypto::key::KeyPair;

    /// 单一来源一致性：derive_validator_id == consensus impl == crypto identity::validator_id。
    #[test]
    fn derive_validator_id_matches_existing_sources() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let derived = derive_validator_id(&pk);
        assert_eq!(
            derived,
            ValidatorId::from_consensus_public_key(&pk),
            "derive == consensus 实现"
        );
        assert_eq!(
            *derived.as_bytes(),
            crypto_validator_id(&pk),
            "derive == crypto identity::validator_id（值不变）"
        );
    }
}
