//! Nova Chain 存储层（PHASE 1 占位）。
//!
//! 未来承载：RocksDB schema、状态树、快照、修剪、崩溃恢复。
//! 当前仅定义**数据库版本**常量。
//!
//! # 版本概念
//! 数据库版本（Database）与软件版本 / 协议版本 / API 版本相互独立（ADR-0001）。

/// Nova Chain 数据库版本（Database Version）。
///
/// 首次引入状态存储时确定 schema 版本；存储迁移策略由 ADR-0007 定义。
pub const DATABASE_VERSION: u32 = 1;

// 注意：本阶段禁止实现任何存储逻辑。
