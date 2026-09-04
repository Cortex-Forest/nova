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

/// Validator Safety Store（STEP 10-15T；Restart Safety）：独立 fail-closed 的 validator-local
/// durable journal（VoteIntent / VoteSigned / LockedState + identity header）。Option B —— 与
/// canonical `PersistentBackend` state WAL 分离；不持久化私钥。
pub mod safety_store;

pub use block_adapter::{ChainHead, NodeBlockAdapter, NodeBlockApplicationError};
pub use bootstrap::{NodeConfig, NodeStartupError, start};

// 注意：本阶段禁止实现任何节点/共识业务逻辑（除 STEP 11-4 已冻结的 Vote + RoundTimeout 路径、
// STEP 7-D 已授权的 Block 应用适配路径、STEP 10-15L 已授权的本地验证者投票边界 signer + validator、
// STEP 10-15O 已授权的 Node Consensus Driver 编排接线，以及 STEP 10-15S 已授权的本地 Double-Vote
// Protection（vote_ledger））。
