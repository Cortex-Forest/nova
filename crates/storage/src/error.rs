//! Storage 错误（STEP 8C — ADR-0025 S-H / ADR-0028 D-1/D-4）。
//!
//! 错误模型分层：`nova-core`（协议错误）/ `nova-storage`（`StorageError`）/
//! `nova-execution`（`ExecutionError`）各自独立；storage **不复用** ExecutionError（S-H）。

use core::fmt;

/// Storage 错误（ADR-0025 S-H 四类，冻结）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// backend 原语失败（put / delete / snapshot / restore）。
    BackendFailure,
    /// 账户/节点序列化失败（canonical_account_bytes 等）。
    SerializationFailure,
    /// 状态损坏（trie/backend 校验失败、数据长度不符）。
    CorruptedState,
    /// 提交失败（snapshot/commit/rollback 异常）。
    CommitFailed,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailure => write!(f, "backend primitive failure"),
            Self::SerializationFailure => write!(f, "state serialization failure"),
            Self::CorruptedState => write!(f, "corrupted state"),
            Self::CommitFailed => write!(f, "state commit failed"),
        }
    }
}

impl std::error::Error for StorageError {}
