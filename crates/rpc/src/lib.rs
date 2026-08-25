//! Nova Chain RPC / API 层（PHASE 1 占位）。
//!
//! 未来承载：公开 RPC、Validator 管理 API、统一接口契约（API Contract First）。
//! 当前仅定义 **API 版本** 常量。
//!
//! # 版本概念
//! API 版本（API）与软件版本 / 协议版本 / 数据库版本相互独立（ADR-0001）。

/// Nova Chain API 版本（API Version）。
///
/// 公共 RPC 与 Validator 管理 API 必须分离；API 版本化策略见 ADR-0011。
pub const API_VERSION: &str = "v1";

// 注意：本阶段禁止实现任何 RPC 逻辑。
