//! PersistentBackend（STEP 8E — ADR-0031）。
//!
//! - 自研文件后端（E-1）：内存 KV + WAL（追加式）+ 全量快照（atomic rename）。
//! - 崩溃安全（E-3）：`put`/`delete` 改内存 + `pending`；`flush()` 把 `pending` 写为一个
//!   WAL 批次（`batch_id + changes + SHA-256 checksum`）并 fsync；`open()` 加载快照 +
//!   重放 WAL 有效批次、**丢弃损坏尾部**。
//! - trie **不落盘**（E-6）：重启由 WAL 重放重建 SMT（固定深度 SMT 确定性，ADR-0026）。
//!
//! 目录结构：
//! ```text
//! <path>/snapshot    # 全量 KV 快照（magic 0x02 + count + entries + checksum）
//! <path>/wal.log     # WAL（magic 0x01 记录序列；value_len=0 表示 delete 原语）
//! ```

use crate::backend::StorageBackend;
use crate::error::StorageError;
use crate::node::TrieKey;
use nova_crypto::hash::protocol_hash;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// WAL 记录 magic（E-3）。
const WAL_MAGIC: u8 = 0x01;
/// 快照文件 magic（E-4）。
const SNAPSHOT_MAGIC: u8 = 0x02;

/// 持久化后端内存快照句柄（rollback 用，非磁盘快照；ADR-0028 D-5）。
#[derive(Debug, Clone, Default)]
pub struct PersistentSnapshot {
    kv: HashMap<TrieKey, Vec<u8>>,
}

/// 自研文件持久化后端（ADR-0031 E-1）。
///
/// - `kv`：当前完整状态（内存缓存；重启后由磁盘重建）。
/// - `pending`：未 flush 的变更（作为**一个 WAL 批次**）。
/// - `next_batch_id`：下一 WAL 批次号（单调递增）。
#[derive(Clone)]
pub struct PersistentBackend {
    dir: PathBuf,
    kv: HashMap<TrieKey, Vec<u8>>,
    pending: Vec<(TrieKey, Vec<u8>)>,
    next_batch_id: u64,
}

impl PersistentBackend {
    /// 创建新持久化库（空状态；ADR-0031 E-5）。
    pub fn create(path: &Path) -> Result<Self, StorageError> {
        if path.exists() && !path.is_dir() {
            return Err(StorageError::BackendFailure);
        }
        fs::create_dir_all(path).map_err(|_| StorageError::BackendFailure)?;
        let wal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.join("wal.log"))
            .map_err(|_| StorageError::BackendFailure)?;
        wal.sync_all().map_err(|_| StorageError::BackendFailure)?;
        Ok(Self {
            dir: path.to_path_buf(),
            kv: HashMap::new(),
            pending: Vec::new(),
            next_batch_id: 0,
        })
    }

    /// 打开既有持久化库：加载快照 → 重放 WAL 有效批次 → 丢弃损坏尾部（ADR-0031 E-5）。
    ///
    /// **幂等**：同一目录多次 `open` ⇒ 同一状态 / 同一 root。
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if !path.is_dir() {
            return Err(StorageError::BackendFailure);
        }
        let mut kv = HashMap::new();
        // 1. 快照
        let snap_path = path.join("snapshot");
        if snap_path.exists() {
            let bytes = fs::read(&snap_path).map_err(|_| StorageError::BackendFailure)?;
            kv = decode_snapshot(&bytes)?;
        }
        // 2. WAL 重放（顺序 = 状态转换顺序；尾部损坏丢弃）
        let wal_path = path.join("wal.log");
        let mut next_batch_id = 0u64;
        if wal_path.exists() {
            let bytes = fs::read(&wal_path).map_err(|_| StorageError::BackendFailure)?;
            let mut pos = 0usize;
            while pos < bytes.len() {
                match decode_wal_record(&bytes[pos..]) {
                    Ok((batch_id, changes, consumed)) => {
                        for (key, value) in changes {
                            if value.is_empty() {
                                kv.remove(&key); // delete 原语
                            } else {
                                kv.insert(key, value);
                            }
                        }
                        next_batch_id = batch_id + 1;
                        pos += consumed;
                    }
                    Err(_) => break, // 损坏/不完整尾部 ⇒ 丢弃
                }
            }
        }
        Ok(Self {
            dir: path.to_path_buf(),
            kv,
            pending: Vec::new(),
            next_batch_id,
        })
    }

    /// 关闭：flush 未持久化写入（ADR-0031 E-5）。
    pub fn close(mut self) -> Result<(), StorageError> {
        self.flush()?;
        Ok(())
    }

    /// 全量快照（ADR-0031 E-4）：flush 后写 `snapshot.tmp → fsync → atomic rename`，再截断 WAL。
    pub fn persist_snapshot(&mut self) -> Result<(), StorageError> {
        self.flush()?;
        let tmp = self.dir.join("snapshot.tmp");
        let mut body = Vec::new();
        body.push(SNAPSHOT_MAGIC);
        body.extend_from_slice(&(self.kv.len() as u32).to_le_bytes());
        for (k, v) in &self.kv {
            body.extend_from_slice(k);
            body.extend_from_slice(&(v.len() as u32).to_le_bytes());
            body.extend_from_slice(v);
        }
        let mut out = body.clone();
        out.extend_from_slice(&protocol_hash(&body));
        let mut file = File::create(&tmp).map_err(|_| StorageError::BackendFailure)?;
        file.write_all(&out)
            .map_err(|_| StorageError::BackendFailure)?;
        file.sync_all().map_err(|_| StorageError::BackendFailure)?;
        drop(file);
        fs::rename(&tmp, self.dir.join("snapshot")).map_err(|_| StorageError::BackendFailure)?;
        // 快照已含全部状态 ⇒ 截断 WAL
        File::create(self.wal_path()).map_err(|_| StorageError::BackendFailure)?;
        Ok(())
    }

    /// 当前 KV 条目数（测试辅助）。
    pub fn len(&self) -> usize {
        self.kv.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.kv.is_empty()
    }

    fn wal_path(&self) -> PathBuf {
        self.dir.join("wal.log")
    }
}

/// WAL 记录编码：`magic ‖ batch_id(8B LE) ‖ count(4B LE) ‖ count×(key35 ‖ vlen(4B LE) ‖ value)
/// ‖ SHA-256(body)`。`value_len=0` 表示 delete 原语（账户 canonical 88B 永不为空）。
fn encode_wal_record(batch_id: u64, changes: &[(TrieKey, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(WAL_MAGIC);
    body.extend_from_slice(&batch_id.to_le_bytes());
    body.extend_from_slice(&(changes.len() as u32).to_le_bytes());
    for (k, v) in changes {
        body.extend_from_slice(k);
        body.extend_from_slice(&(v.len() as u32).to_le_bytes());
        body.extend_from_slice(v);
    }
    let mut out = body.clone();
    out.extend_from_slice(&protocol_hash(&body));
    out
}

/// WAL 解码结果：`(batch_id, changes, consumed_bytes)`。
type WalRecord = (u64, Vec<(TrieKey, Vec<u8>)>, usize);

/// WAL 记录解码：损坏/不完整 ⇒ `Err`。
fn decode_wal_record(bytes: &[u8]) -> Result<WalRecord, StorageError> {
    if bytes.len() < 1 + 8 + 4 + 32 {
        return Err(StorageError::CorruptedState);
    }
    if bytes[0] != WAL_MAGIC {
        return Err(StorageError::CorruptedState);
    }
    let batch_id = u64::from_le_bytes(bytes[1..9].try_into().expect("len checked"));
    let count = u32::from_le_bytes(bytes[9..13].try_into().expect("len checked")) as usize;
    let mut pos = 13usize;
    let mut changes = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 35 + 4 > bytes.len() - 32 {
            return Err(StorageError::CorruptedState);
        }
        let key: TrieKey = bytes[pos..pos + 35].try_into().expect("slice 35");
        pos += 35;
        let vlen = u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("slice 4")) as usize;
        pos += 4;
        if pos + vlen > bytes.len() - 32 {
            return Err(StorageError::CorruptedState);
        }
        changes.push((key, bytes[pos..pos + vlen].to_vec()));
        pos += vlen;
    }
    let body = &bytes[..pos];
    let cksum = &bytes[pos..pos + 32];
    if protocol_hash(body) != cksum {
        return Err(StorageError::CorruptedState);
    }
    Ok((batch_id, changes, pos + 32))
}

/// 快照解码：`magic ‖ count(4B LE) ‖ count×(key35 ‖ vlen ‖ value) ‖ SHA-256(body)`。
fn decode_snapshot(bytes: &[u8]) -> Result<HashMap<TrieKey, Vec<u8>>, StorageError> {
    if bytes.len() < 1 + 4 + 32 || bytes[0] != SNAPSHOT_MAGIC {
        return Err(StorageError::CorruptedState);
    }
    let count = u32::from_le_bytes(bytes[1..5].try_into().expect("len checked")) as usize;
    let mut pos = 5usize;
    let mut kv = HashMap::new();
    for _ in 0..count {
        if pos + 35 + 4 > bytes.len() - 32 {
            return Err(StorageError::CorruptedState);
        }
        let key: TrieKey = bytes[pos..pos + 35].try_into().expect("slice 35");
        pos += 35;
        let vlen = u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("slice 4")) as usize;
        pos += 4;
        if pos + vlen > bytes.len() - 32 {
            return Err(StorageError::CorruptedState);
        }
        kv.insert(key, bytes[pos..pos + vlen].to_vec());
        pos += vlen;
    }
    let body = &bytes[..pos];
    let cksum = &bytes[pos..pos + 32];
    if protocol_hash(body) != cksum {
        return Err(StorageError::CorruptedState);
    }
    Ok(kv)
}

impl StorageBackend for PersistentBackend {
    type Snapshot = PersistentSnapshot;

    fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
        self.kv.get(key).cloned()
    }

    fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError> {
        self.kv.insert(key, value.clone());
        self.pending.push((key, value));
        Ok(())
    }

    fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError> {
        self.kv.remove(key);
        self.pending.push((*key, Vec::new())); // value_len=0 标记 delete 原语
        Ok(())
    }

    fn snapshot(&self) -> Self::Snapshot {
        PersistentSnapshot {
            kv: self.kv.clone(),
        }
    }

    fn restore(&mut self, snap: &Self::Snapshot) {
        self.kv = snap.kv.clone();
        self.pending.clear(); // 恢复后 pending 变更无效（ADR-0031）
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let record = encode_wal_record(self.next_batch_id, &self.pending);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.wal_path())
            .map_err(|_| StorageError::BackendFailure)?;
        file.write_all(&record)
            .map_err(|_| StorageError::BackendFailure)?;
        file.sync_all().map_err(|_| StorageError::BackendFailure)?;
        self.next_batch_id += 1;
        self.pending.clear();
        Ok(())
    }

    fn entries(&self) -> Vec<(TrieKey, Vec<u8>)> {
        self.kv.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}
