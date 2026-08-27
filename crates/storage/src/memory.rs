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

/// 内存存储后端（V0.1；8E 前唯一后端）。
#[derive(Debug, Clone, Default)]
pub struct MemoryBackend {
    map: HashMap<TrieKey, Vec<u8>>,
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
}

impl StorageBackend for MemoryBackend {
    type Snapshot = MemorySnapshot;

    fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError> {
        self.map.insert(key, value);
        Ok(())
    }

    fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError> {
        self.map.remove(key);
        Ok(())
    }

    fn snapshot(&self) -> Self::Snapshot {
        MemorySnapshot {
            map: self.map.clone(),
        }
    }

    fn restore(&mut self, snap: &Self::Snapshot) {
        self.map = snap.map.clone();
    }
}
