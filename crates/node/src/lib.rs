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

pub use block_adapter::{ChainHead, NodeBlockAdapter, NodeBlockApplicationError};

// 注意：本阶段禁止实现任何节点/共识业务逻辑（除 STEP 11-4 已冻结的 Vote + RoundTimeout 路径
// 与 STEP 7-D 已授权的 Block 应用适配路径）。
