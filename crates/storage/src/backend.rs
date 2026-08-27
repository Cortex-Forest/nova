//! Storage Backend trait（STEP 8C — ADR-0028 D-1）。
//!
//! - **backend = byte storage**；serialization responsibility 在 store 层（D-1）。
//! - backend **不知道** `AccountState`（通用 KV）；8E RocksDB/MDBX 复用同一 trait（S-F）。
//! - **delete primitive boundary**：`delete` 仅为底层存储原语（migration / pruning /
//!   snapshot restore 用）；**协议层 AccountState 删除 V0.1 禁止**（ADR-0017）。两者不可混淆。

use crate::error::StorageError;
use crate::node::TrieKey;

/// 存储后端抽象（ADR-0028 D-1）。
///
/// 通用 KV：key = `TrieKey`（`NovaAddressPayload` raw 35B），value = 账户 canonical bytes。
pub trait StorageBackend {
    /// 快照句柄（8C MemoryBackend = 账户表深拷贝 clone）。
    type Snapshot: Clone;

    /// 读 key（不存在 ⇒ `None`）。
    fn get(&self, key: &TrieKey) -> Option<Vec<u8>>;

    /// 写 key→value（upsert）。
    fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError>;

    /// 底层删除原语（**协议层账户删除 V0.1 禁止**；仅 migration/pruning/snapshot restore 用）。
    fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError>;

    /// 快照当前状态（事务回滚基线；D-5）。
    fn snapshot(&self) -> Self::Snapshot;

    /// 恢复快照（rollback；覆盖当前状态）。
    fn restore(&mut self, snap: &Self::Snapshot);
}
