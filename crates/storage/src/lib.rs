//! Nova Chain 存储层（PHASE 4 — STEP 8B/8C SMT + StateStore）。
//!
//! # 模块
//! - [`hashing`]：**STEP 8B-2**——域分离哈希（`STATE_EMPTY/LEAF/BRANCH`、`EMPTY_NODE_HASH`）。
//! - [`node`]：**STEP 8B-2**——SMT 节点（`Empty`/`Leaf`/`Branch`）+ encode/decode + `NodeHash`
//!   （ADR-0026 T-3/T-4/T-7）。
//! - [`trie`]：**STEP 8B-3**——`SparseMerkleTree`（insert/update/get/delete/root，ADR-0026 T-6）。
//! - [`proof`]：**STEP 8B-4**——Sparse Merkle Proof（inclusion/exclusion + [`proof::verify_proof`]，ADR-0027）。
//! - [`error`] / [`backend`] / [`memory`] / [`store`]：**STEP 8C**——StateStore + MemoryBackend
//!   （`StorageBackend` / `MemoryBackend` / `StateStore` 骨架，ADR-0028）。
//!
//! # 边界（ADR-0025/0026/0027/0028）
//! - 本阶段实现节点层 / 树算法 / proof / StateStore 骨架；`StateStore::apply`（8C-3）、
//!   持久化后端（8E）、block state root（8D）后续冻结。
//! - **不引入数据库依赖**（8E 之前）。
//! - 版本概念：数据库版本与软件/协议/API 版本独立（ADR-0001）。

/// Nova Chain 数据库版本（Database Version）。
///
/// 首次引入状态存储时确定 schema 版本；存储迁移策略由 ADR-0007 定义。
pub const DATABASE_VERSION: u32 = 1;

pub mod backend;
pub mod error;
pub mod hashing;
pub mod memory;
pub mod node;
pub mod proof;
pub mod state_root;
pub mod store;
pub mod trie;

// 注意：本阶段不实现持久化后端（8E）/ 完整区块格式（PHASE 7）。
