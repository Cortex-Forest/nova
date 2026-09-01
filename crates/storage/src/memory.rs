//! MemoryBackend（STEP 8C — ADR-0028 D-1/D-5；S-F 先内存后端）。
//!
//! - `HashMap<TrieKey, Vec<u8>>`；快照 = 深拷贝 clone（V0.1 数据量小，正确优先；
//!   COW 优化留 8E 持久化后端）。
//! - 不参与协议状态定义（S-G）；只做字节存储。

use crate::backend::StorageBackend;
use crate::error::StorageError;
use crate::node::TrieKey;
use std::collections::HashMap;

/// 内存快照句柄（账户表深拷贝）。
#[derive(Debug, Clone, Default)]
pub struct MemorySnapshot {
    map: HashMap<TrieKey, Vec<u8>>,
}

/// 一次 flush 的观测记录（STEP 7-J 测试辅助：证明 state + head 同一逻辑 flush 边界）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRecord {
    /// 本次 flush 中的 state change 数量。
    pub changes: usize,
    /// 本次 flush 中的 head metadata（若有）。
    pub head: Option<Vec<u8>>,
}

/// 内存存储后端（V0.1；8E 前唯一后端）。
///
/// STEP 7-J：增加 pending 模型（与 PersistentBackend 对齐），使"enqueue_head + apply_block =
/// 单 flush 批次（head + state 同批生效/同批回滚）"可在内存后端直接验证（E-7 后端等价）。
#[derive(Debug, Clone, Default)]
pub struct MemoryBackend {
    map: HashMap<TrieKey, Vec<u8>>,
    pending: Vec<(TrieKey, Vec<u8>)>,
    pending_meta: Option<Vec<u8>>,
    flushes: Vec<FlushRecord>,
}

impl MemoryBackend {
    /// 空后端。
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前条目数（测试辅助）。
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 读取某 key 的原始 bytes（测试辅助；`get` 的便捷封装）。
    pub fn get_bytes(&self, key: &TrieKey) -> Option<&[u8]> {
        self.map.get(key).map(Vec::as_slice)
    }

    /// flush 观测记录（测试辅助：验证 state+head 同批）。
    pub fn flush_records(&self) -> &[FlushRecord] {
        &self.flushes
    }

    /// flush 次数（测试辅助）。
    pub fn flush_count(&self) -> usize {
        self.flushes.len()
    }
}

impl StorageBackend for MemoryBackend {
    type Snapshot = MemorySnapshot;

    fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError> {
        self.map.insert(key, value.clone());
        self.pending.push((key, value));
        Ok(())
    }

    fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError> {
        self.map.remove(key);
        self.pending.push((*key, Vec::new()));
        Ok(())
    }

    fn snapshot(&self) -> Self::Snapshot {
        MemorySnapshot {
            map: self.map.clone(),
        }
    }

    fn restore(&mut self, snap: &Self::Snapshot) {
        self.map = snap.map.clone();
        self.pending.clear();
        self.pending_meta = None;
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        // 记录本次 flush（state change 数 + head）→ 观测"单批生效"；内存天然 durable，无持久化。
        self.flushes.push(FlushRecord {
            changes: self.pending.len(),
            head: self.pending_meta.take(),
        });
        self.pending.clear();
        Ok(())
    }

    fn enqueue_meta(&mut self, meta: &[u8]) -> Result<(), StorageError> {
        if self.pending_meta.is_some() {
            // 单 head 约束：拒绝重复 enqueue，防覆盖 / 防 phantom head。
            return Err(StorageError::BackendFailure);
        }
        self.pending_meta = Some(meta.to_vec());
        Ok(())
    }

    fn entries(&self) -> Vec<(TrieKey, Vec<u8>)> {
        self.map.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}
