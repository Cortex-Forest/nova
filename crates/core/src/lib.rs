//! Nova Chain 核心协议类型（PHASE 1 占位）。
//!
//! 本 crate 未来承载：交易、状态、区块等核心协议类型。
//! 当前仅定义**协议版本**常量；协议类型的设计需先经 ADR 批准（Master Prompt §9/§23）。
//!
//! # 版本概念
//! 协议版本（Protocol）与软件版本（Software）、数据库版本（Database）、
//! API 版本（API）四者相互独立，禁止混用（Master Prompt §10 / ADR-0001）。

/// Nova Chain 协议版本（Protocol Version）。
///
/// 数据库版本定义于 `nova-storage` crate（`DATABASE_VERSION`），二者相互独立。
pub const PROTOCOL_VERSION: &str = "0.1";

/// Nova Chain 统一错误模型（PHASE 1 骨架）。
///
/// # 设计原则：分层边界式（非集中式大杂烩）
/// - [`NovaError`] 只是**根接口标记**，不承载具体错误数据。
/// - [`ErrorKind`] 仅作**分类标签**（模块边界标识），不是把所有错误塞进一个枚举。
/// - 每个 crate 应拥有**自己的具体错误类型**，通过明确的边界（`From`/映射）向上转换。
/// - 禁止把跨模块错误集中到一个大枚举里（会导致模块强耦合）。
///
/// # 纪律（Master Prompt §54）
/// - 所有生产模块统一使用 `Result<T, E>`。
/// - 错误类型必须可分类；禁止吞掉错误、禁止 catch 后进入未知状态。
/// - 本阶段不实现任何具体业务错误。
pub mod error {
    /// Nova 统一错误根接口。
    ///
    /// 未来各 crate 的具体错误类型（CryptoError / StorageError / ...）应实现
    /// [`std::error::Error`]，并以本 trait 作为 Nova 错误体系的统一入口标记。
    pub trait NovaError: std::error::Error {}

    /// Nova Chain 错误分类（模块边界骨架）。
    ///
    /// 用于标识错误所属模块，便于日志聚合与 API 错误码映射。
    /// 仅定义分类，不携带具体错误数据。
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ErrorKind {
        /// 核心协议层错误（`nova-core`）。
        Core,
        /// 密码学错误（`nova-crypto`）。
        Crypto,
        /// 网络错误（`nova-network`）。
        Network,
        /// 存储错误（`nova-storage`）。
        Storage,
        /// 共识错误（`nova-consensus`）。
        Consensus,
        /// 执行错误（`nova-execution`）。
        Execution,
        /// RPC / API 错误（`nova-rpc`）。
        Rpc,
        /// 钱包错误（`nova-wallet`）。
        Wallet,
    }
}

// 注意：本阶段禁止实现任何核心协议逻辑（交易/状态/区块）。
