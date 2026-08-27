//! Nova Chain 存储层（PHASE 4 — STEP 8B SMT Node Layer）。
//!
//! # 模块
//! - [`hashing`]：**STEP 8B-2**——域分离哈希（`STATE_EMPTY/LEAF/BRANCH`、`EMPTY_NODE_HASH`）。
//! - [`node`]：**STEP 8B-2**——SMT 节点（`Empty`/`Leaf`/`Branch`）+ encode/decode + `NodeHash`
//!   （ADR-0026 T-3/T-4/T-7）。
//!
//! # 边界（ADR-0025/0026）
//! - 本阶段只实现**节点层**；trie update / StateStore apply / 持久化 / proof / block state root
//!   分别由 8B-3 / 8C / 8E / 8D 冻结。
//! - **不引入数据库依赖**（8E 之前）。
//! - 版本概念：数据库版本与软件/协议/API 版本独立（ADR-0001）。

/// Nova Chain 数据库版本（Database Version）。
///
/// 首次引入状态存储时确定 schema 版本；存储迁移策略由 ADR-0007 定义。
pub const DATABASE_VERSION: u32 = 1;

pub mod hashing;
pub mod node;

// 注意：本阶段不实现 trie update / apply / 持久化。
