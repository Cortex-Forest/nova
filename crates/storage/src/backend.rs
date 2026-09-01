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

    /// 确保所有未持久化写入已 durable（WAL fsync；ADR-0031 E-2）。
    /// `MemoryBackend` = `Ok(())`（内存天然 durable）。
    fn flush(&mut self) -> Result<(), StorageError>;

    /// 全量枚举当前键值（**state reload** 用；ADR-0031 E-5）。
    /// `StateStore::load` 借此重建 trie（E-6：trie 不落盘，确定性重建）。
    fn entries(&self) -> Vec<(TrieKey, Vec<u8>)>;

    /// 将不透明 metadata 加入下一次 flush 的**同一持久化批次**（STEP 7-J / ADR-0048 OD-7）。
    ///
    /// - **不落盘、不 fsync、不创建独立批次**；只缓冲，等待下次 `flush` 与 state changes 同批持久化。
    /// - 单 head 约束：同一 pending transaction 内重复 enqueue ⇒ `Err`（防覆盖/防 phantom head）。
    /// - trait 不感知 HeadRecord 语义（backend = 字节存储，E-2）；编码归 `StateStore`。
    /// - 默认实现：不支持 co-meta 的后端**显式失败**（安全默认，防静默丢 head）。
    fn enqueue_meta(&mut self, _meta: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::BackendFailure)
    }

    /// 读取恢复得到的 head metadata（ADR-0031 E-5 amendment / ADR-0048 recovery）。
    ///
    /// `MemoryBackend` = `None`（无持久 head）；`PersistentBackend` = 快照/WAL 重放得到的最后 head。
    /// 默认 `None`（非持久后端无需实现）。
    fn recovered_meta(&self) -> Option<Vec<u8>> {
        None
    }
}
