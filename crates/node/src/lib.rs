//! Nova Chain 节点组装层（PHASE 1 占位 + STEP 11-4 组装）。
//!
//! 未来承载：节点服务、配置系统、模块组装、启动流程。
//! 本阶段建立**配置系统骨架**与 **STEP 11-4 Node 组装层**（Vote + RoundTimeout 路径）。

/// 配置系统骨架（PHASE 1）。
///
/// 未来分节：`network` / `node` / `rpc` / `storage` / `consensus` / `telemetry`。
/// 本阶段**不实现任何具体配置参数**（如共识参数须进 Genesis/Governance Parameters）。
pub mod config {
    /// 节点配置（骨架，暂无字段）。
    ///
    /// 具体配置字段在后续阶段按 Config Spec 定义。
    #[derive(Debug, Default, Clone)]
    pub struct Config;

    /// 配置加载器接口（骨架）。
    ///
    /// 具体实现（文件/环境变量/远端）在后续阶段完成。
    /// 本阶段只约定接口形状，保证未来各配置源可插拔。
    pub trait ConfigLoader {
        /// 加载失败的错误类型（由具体实现定义）。
        type Error;

        /// 加载节点配置。
        fn load(&self) -> Result<Config, Self::Error>;
    }
}

/// Node 组装层（STEP 11-4）：Network envelope → classify → construct `ConsensusEvent` →
/// `transition` → `TransitionResult` 路由。**不执行 Consensus verification**（归 Consensus）。
pub mod assembly;

/// Node 区块应用适配层（STEP 7-D / ADR-0046）：Block wire → runtime 7-step 管线 → StateStore → ChainHead。
pub mod block_adapter;

/// Node 启动 / 重启编排（PHASE 3 STEP 7-P；F-3）：genesis 加载/校验 + first-start bootstrap +
/// restart recovery + 参数注入 + NodeBlockAdapter 构造。
pub mod bootstrap;

/// Node-local 签名边界（STEP 10-15L）：`SigningCapability` + `SoftwareSigner`（validator 本地投票签名）。
pub mod signer;

/// 本地验证者投票边界（STEP 10-15L）：`ValidatorActor` + `LocalVoteContext`（ADR-0053
/// validator-local lock / 本地投票授权 → 标准 `ConsensusEvent::Vote`）。
pub mod validator;

/// Node-local 投票账本（STEP 10-15S；Double-Vote Protection）：`VoteKey`/`VoteRecord`/`VoteLedger`
/// —— 同 `(height, round, vote_type)` 至多一个 target（内存实现；10-15T 持久化）。
pub mod vote_ledger;

/// Node Consensus Driver（STEP 10-15O）：Proposal → Local Vote → 统一 `verify_vote_input` →
/// canonical transition → `TransitionDerived` → `verify_qc` → 路由至各本地 `ValidatorActor` lock。
pub mod driver;

/// Consensus outbound semantic seam（STEP 10-18G-1）：`OutboundConsensusMessage`（what to send）+
/// `NetworkEgress`（抽象 seam，未实现 impl）。Production semantic→envelope egress 由
/// `egress` 模块实现（STEP 10-18I-N-IMPL）。
pub mod outbound;

/// Node Production Egress Adapter（STEP 10-18I-N-IMPL）：Driver semantic outbound →
/// `MessageEnvelope`（canonical）+ `NetworkSigner` 签名 → NetworkService。
pub mod egress;

/// Node-local BlockBuilder（STEP 10-19-5 / ADR-0061）：candidate transactions → ADR-0061 canonical
/// ordering → execution（runtime 只读组合 `execute_and_compute_state_root`）→ post-state root →
/// transaction root → BlockV1 assembly → block_hash。纯确定性：timestamp / height / parent_hash /
/// finality_reference / validator_set_hash 由 caller 显式传入（不碰系统时间 / 网络 / 随机 / 私钥 /
/// 持久化）。签名 seam：`attach_proposer_signature`（`SigningCapability`；signature ∉ block_hash）。
pub mod block_builder;

/// Remote Block Inbound Validation Boundary v1（STEP 10-19-9）：远端 Block wire →
/// Wire + Canonical validation（纯只读，最多到 CANONICAL VALIDATED）。**不 commit / 不推进
/// ChainHead / 不更新 StateStore / 不写 BlockStore**；产物 CanonicalNextCandidate 非
/// finality-authorized（finality→commit 归未来 STEP）。
pub mod block_inbound;

/// Node-level Block Inbound Dispatch（STEP 10-19-10-A）：GossipBlock / SyncBlockResponse
/// payload → adapter 真实只读上下文 → `block_inbound::validate_block_inbound` → typed verdict。
/// **只读观测**：不 commit / 不写 BlockStore / 不推进 ChainHead；CanonicalNextCandidate 非
/// finality-authorized。wire 收集 seam 在 `wiring::NodeConsensusHandler`。
pub mod block_dispatch;

/// Node-local Missing-Ancestor Intent Ledger（STEP 10-19-10-B1）：`FutureMissingAncestor`
/// verdict → bounded + deduplicated 缺失祖先需求记账（FIFO eviction；count saturating）。
/// **≠ Sync / ≠ 存储 / ≠ finality**：不发送请求、不写 BlockStore/StateStore/ChainHead、不触发
/// finality；纯 Node-local 观察状态。
pub mod intent_ledger;

/// Node-local Sync Request/Response Correlator（STEP 10-19-10-B2）：`RequestId`（network
/// `security::RequestId`，canonical 16B）pending correlation —— `register(request_id, target)` /
/// consuming `resolve(response.request_id)`；bounded、无网络 I/O、无 timeout/retry、无 eviction。
/// 匹配只绑定 request，不 imply 块有效/canonical/finality。
pub mod sync_correlator;

/// Node-local Proposer orchestration（STEP 10-19-2）：ProposalRef 装配（ADR-0050 `select_proposer`
/// 判定 + deterministic placeholder commitment）；ProposerService ≠ BlockBuilder / ValidatorActor /
/// NetworkService / Storage / ConsensusState。
pub mod proposer;

/// KeyProvider seam（STEP 10-16）：`load_signer() -> Box<dyn SigningCapability>`；ValidatorActor
/// 不知私钥位置 / 载体（software/HSM/remote/KMS 均为实现）。不修改 `SigningCapability`。
pub mod key_provider;

/// Network Identity seam（STEP 10-18I-A）：`NetworkIdentityProvider` / `NetworkSigner`
/// （NodeId + envelope 签名）；网络身份与 validator 身份分离；生产网络 key DEFERRED。
pub mod network_identity;
/// Validator Safety Store（STEP 10-15T；Restart Safety）：独立 fail-closed 的 validator-local
/// durable journal（VoteIntent / VoteSigned / LockedState + identity header）。Option B —— 与
/// canonical `PersistentBackend` state WAL 分离；不持久化私钥。
pub mod safety_store;

/// NodeRuntime 生命周期装配（STEP 10-16 Phase 1）：Config → Genesis → ChainIdentity → chain
/// storage →（validator mode）KeyProvider → derive ValidatorId → SafetyStore → recover →
/// ValidatorActor → ConsensusNode；Network / EventLoop 为 future 占位。
pub mod runtime;

/// Consensus inbound/outbound wiring adapter（STEP 10-18G-1）：`NodeEvent → Driver` 的 node 层
/// decode seam + outbound semantic egress（NetworkService/EventLoop 不解析 consensus）。
pub mod wiring;
pub use block_adapter::{ChainHead, NodeBlockAdapter, NodeBlockApplicationError};
pub use bootstrap::{NodeConfig, NodeStartupError, start};

// 注意：本阶段禁止实现任何节点/共识业务逻辑（除 STEP 11-4 已冻结的 Vote + RoundTimeout 路径、
// STEP 7-D 已授权的 Block 应用适配路径、STEP 10-15L 已授权的本地验证者投票边界 signer + validator、
// STEP 10-15O 已授权的 Node Consensus Driver 编排接线，以及 STEP 10-15S 已授权的本地 Double-Vote
// Protection（vote_ledger））。
