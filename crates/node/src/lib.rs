//! Nova Chain 节点组装层（PHASE 1 占位）。
//!
//! 未来承载：节点服务、配置系统、模块组装、启动流程。
//! 本阶段仅建立**配置系统骨架**与 **feature flags 机制**占位。

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

// 注意：本阶段禁止实现任何节点/共识业务逻辑。
