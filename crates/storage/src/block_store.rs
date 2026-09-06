//! BlockStorage 最小生产实现（STEP 10-19-7）。
//!
//! # 职责
//! - `BlockHash → canonical BlockV1 bytes` 的可验证、可恢复持久化（单块文件存储）。
//! - `put(block)` / `get(hash)` / `contains(hash)`；get 必须 strict canonical decode +
//!   `block_hash` 重算比对（fail closed：不返回未经验证的 Block）。
//!
//! # 架构边界
//! - **不复制 canonical state**：Block 记录与账户 TrieKey / SMT / head meta / StateStore 完全隔离
//!   （独立子目录文件，key = block hash hex）；`StateStore::load` / state_root 不受影响。
//! - **不扩展账户 key space**：不改 `StorageBackend` / TrieKey / WAL / snapshot 既有格式（旧库
//!   重启兼容）；本模块在 storage crate 内使用文件原语（等同 `persistent.rs` 地位，非绕过）。
//! - **复用冻结编码**：canonical bytes = ADR-0042 `encode_block`；decode = `decode_block`；
//!   hash = `block_hash`（SHA-256(canonical_header‖canonical_body)）。无第二套 Block encoding。
//! - 单 block put 原子：tmp 写 + fsync + `rename`（atomic；仿 `persist_snapshot`）。
//! - 不建第二 WAL：每 block 一原子文件（非追加日志）；无 batch/多记录日志。
//! - 不负责：ConsensusState / ValidatorSafety / VoteLedger / QC / ForkChoice / Proposer /
//!   Mempool / Gossip / BlockSync / Network / Execution / StateRoot / 私钥 / 签名。
//!
//! # 确定性
//! 无 SystemTime / Instant / random / network；存储 key 仅由 canonical BlockHash 决定。
//!
//! # 原子性（记录）
//! 单 block put 原子；`block + state + ChainHead` 全原子 commit = **DEFERRED**（专门 Block Commit
//! step）——本模块不假装已解决全原子性。

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use nova_core::block::{Block, block_hash, decode_block, encode_block};
use nova_crypto::hash::protocol_hash;

use crate::error::StorageError;

/// Block 记录 magic（区分 WAL 0x01/0x05、snapshot 0x02/0x06、HeadRecord 0x03）。
const BLOCK_FILE_MAGIC: u8 = 0x07;
/// Block 记录版本（V0.1；未知版本 ⇒ 拒）。
const BLOCK_FILE_VERSION: u8 = 0x01;
/// 记录头长度：magic(1) + version(1) + canonical_len(4 LE)。
const HEADER_LEN: usize = 1 + 1 + 4;

/// 单 block 文件记录编码：
/// `magic ‖ version ‖ canonical_len(4 LE) ‖ canonical_block(encode_block) ‖
///  SHA-256(magic..canonical_block)`。
fn encode_block_record(canonical: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(HEADER_LEN + canonical.len());
    body.push(BLOCK_FILE_MAGIC);
    body.push(BLOCK_FILE_VERSION);
    body.extend_from_slice(&(canonical.len() as u32).to_le_bytes());
    body.extend_from_slice(canonical);
    let mut out = body.clone();
    out.extend_from_slice(&protocol_hash(&body));
    out
}

/// 严格解码记录：长度下限 / magic / version / checksum / len 与实际一致；返回 canonical bytes。
fn decode_block_record(record: &[u8]) -> Result<Vec<u8>, StorageError> {
    if record.len() < HEADER_LEN + 32 {
        return Err(StorageError::CorruptedState);
    }
    if record[0] != BLOCK_FILE_MAGIC {
        return Err(StorageError::CorruptedState);
    }
    if record[1] != BLOCK_FILE_VERSION {
        return Err(StorageError::CorruptedState);
    }
    let len = u32::from_le_bytes(
        record[2..6]
            .try_into()
            .map_err(|_| StorageError::CorruptedState)?,
    ) as usize;
    let body_end = HEADER_LEN + len;
    if body_end + 32 != record.len() {
        return Err(StorageError::CorruptedState);
    }
    let body = &record[..body_end];
    let checksum = &record[body_end..];
    if protocol_hash(body) != *checksum {
        return Err(StorageError::CorruptedState);
    }
    Ok(record[HEADER_LEN..body_end].to_vec())
}

/// 原子写（tmp + fsync + rename；仿 `persist_snapshot`）。
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let tmp = path.with_extension("blk.tmp");
    let mut file = File::create(&tmp).map_err(|_| StorageError::BackendFailure)?;
    file.write_all(bytes)
        .map_err(|_| StorageError::BackendFailure)?;
    file.sync_all().map_err(|_| StorageError::BackendFailure)?;
    drop(file);
    fs::rename(&tmp, path).map_err(|_| StorageError::BackendFailure)
}

/// BlockStorage：`BlockHash → BlockV1`（canonical bytes + hash 校验）。
///
/// 无内存状态（每次读写即时文件 IO）⇒ `open`（幂等建目录）即视为恢复（restart-safe）。
#[derive(Debug, Clone)]
pub struct BlockStore {
    dir: PathBuf,
}

impl BlockStore {
    /// 打开 / 创建 block 存储目录（幂等；不存在则创建）。
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        fs::create_dir_all(dir).map_err(|_| StorageError::BackendFailure)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// 保存 Block（key = `block_hash(block)`）。
    ///
    /// - 不存在 ⇒ 原子写记录。
    /// - 已存在：记录**逐字节一致** ⇒ `Ok`（幂等，无第二份逻辑记录）；
    ///   不一致（同 hash 不同 bytes）⇒ [`StorageError::CorruptedState`]（**绝不静默覆盖**）。
    pub fn put(&self, block: &Block) -> Result<(), StorageError> {
        let hash = block_hash(block).map_err(|_| StorageError::SerializationFailure)?;
        let canonical = encode_block(block).map_err(|_| StorageError::SerializationFailure)?;
        let record = encode_block_record(&canonical);
        let path = self.block_path(&hash);
        if path.exists() {
            let existing = fs::read(&path).map_err(|_| StorageError::BackendFailure)?;
            if existing != record {
                return Err(StorageError::CorruptedState);
            }
            return Ok(());
        }
        atomic_write(&path, &record)
    }

    /// 读取 Block；不存在 ⇒ `Ok(None)`。
    ///
    /// 校验链：记录 strict decode（magic/version/checksum）→ `decode_block`（结构级 strict）→
    /// `block_hash(block)` 重算 == 请求 hash；任一不匹配 ⇒ [`StorageError::CorruptedState`]。
    pub fn get(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        let path = self.block_path(hash);
        if !path.exists() {
            return Ok(None);
        }
        let record = fs::read(&path).map_err(|_| StorageError::BackendFailure)?;
        let canonical = decode_block_record(&record)?;
        let block = decode_block(&canonical).map_err(|_| StorageError::CorruptedState)?;
        let computed = block_hash(&block).map_err(|_| StorageError::CorruptedState)?;
        if computed != *hash {
            return Err(StorageError::CorruptedState);
        }
        Ok(Some(block))
    }

    /// 是否存在该 BlockHash。
    pub fn contains(&self, hash: &[u8; 32]) -> Result<bool, StorageError> {
        Ok(self.block_path(hash).exists())
    }

    /// 该 hash 对应的记录文件路径（deterministic：block hash hex；无随机 / 时间）。
    fn block_path(&self, hash: &[u8; 32]) -> PathBuf {
        let mut hex = String::with_capacity(64);
        for b in hash {
            hex.push_str(&format!("{b:02x}"));
        }
        self.dir.join(format!("block_{hex}.blk"))
    }

    /// 清空记录（仅测试辅助；返回文件数）。
    #[cfg(test)]
    fn clear(&self) -> usize {
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".blk"))
                .map(|e| {
                    let _ = fs::remove_file(e.path());
                    1usize
                })
                .sum(),
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::block::{BLOCK_VERSION, BlockBody, BlockHeader};

    fn mk_block(tag: u8) -> Block {
        Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                chain_id: 1001,
                height: 1,
                parent_hash: [tag; 32],
                finality_reference: None,
                transaction_root: [0u8; 32],
                state_root: [0u8; 32],
                validator_set_hash: [0u8; 32],
                timestamp: 0,
            },
            body: BlockBody { txs: Vec::new() },
            proposer_signature: [0u8; 64],
        }
    }

    fn hash_of(b: &Block) -> [u8; 32] {
        block_hash(b).unwrap()
    }

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // BS-1：不存在 Block ⇒ get == None
    #[test]
    fn bs_1_missing_block_is_none() {
        let store = BlockStore::open(dir().path()).unwrap();
        assert_eq!(store.get(&[0xAB; 32]).unwrap(), None);
        assert!(!store.contains(&[0xAB; 32]).unwrap());
    }

    // BS-2：保存 Block ⇒ get == block
    #[test]
    fn bs_2_put_get_roundtrip() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(1);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        assert_eq!(store.get(&h).unwrap(), Some(b));
        assert!(store.contains(&h).unwrap());
    }

    // BS-3：BlockHash 正确（get 后重算一致）
    #[test]
    fn bs_3_hash_integrity() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(2);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        let got = store.get(&h).unwrap().unwrap();
        assert_eq!(block_hash(&got).unwrap(), h, "recomputed hash == key");
    }

    // BS-4：canonical roundtrip（decode(encode(block)) == block）
    #[test]
    fn bs_4_canonical_roundtrip() {
        let b = mk_block(3);
        let bytes = encode_block(&b).unwrap();
        assert_eq!(decode_block(&bytes).unwrap(), b);
    }

    // BS-5：duplicate same block ⇒ 幂等成功（无第二份记录）
    #[test]
    fn bs_5_duplicate_put_idempotent() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(4);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        store.put(&b).unwrap(); // idempotent
        assert_eq!(store.get(&h).unwrap(), Some(b.clone()));
        assert_eq!(store.clear(), 1, "只有一份记录");
    }

    // BS-6：same hash / different bytes ⇒ 拒绝（fail closed，不静默覆盖）
    #[test]
    fn bs_6_hash_conflict_rejected() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(5);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        // 人为覆写同 hash 文件为另一 block 的记录 bytes（模拟冲突 / 损坏）
        let other = mk_block(6);
        let other_canonical = encode_block(&other).unwrap();
        let path = store.block_path(&h);
        atomic_write(&path, &encode_block_record(&other_canonical)).unwrap();
        // put 同 hash：现记录 ≠ 本 block 记录 ⇒ CorruptedState（拒绝覆盖）
        assert_eq!(store.put(&b), Err(StorageError::CorruptedState));
    }

    // BS-7：corrupted stored bytes ⇒ fail closed（hash mismatch / 记录校验失败）
    #[test]
    fn bs_7_corruption_fail_closed() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(7);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        // 篡改：翻转 canonical 字节（记录 checksum 不变 ⇒ decode_block / hash 校验将失败）
        let path = store.block_path(&h);
        let mut record = fs::read(&path).unwrap();
        let flip = record.len() - 34; // canonical 区（checksum 前）
        record[flip] ^= 0xFF;
        fs::write(&path, &record).unwrap();
        // 记录 checksum 校验失败（checksum 未更新）⇒ CorruptedState
        assert_eq!(store.get(&h), Err(StorageError::CorruptedState));
    }

    // BS-8：restart recovery —— 保存后重新 open，仍能读取 + 校验
    #[test]
    fn bs_8_restart_recovery() {
        let d = dir();
        {
            let store = BlockStore::open(d.path()).unwrap();
            let b = mk_block(8);
            store.put(&b).unwrap();
        } // drop（模拟关闭；无显式 close —— 每块原子文件已落盘）
        let reopened = BlockStore::open(d.path()).unwrap();
        let b = mk_block(8);
        let h = hash_of(&b);
        assert_eq!(reopened.get(&h).unwrap(), Some(b), "restart 后仍可读");
    }

    // BS-9：multiple blocks（互不干扰；restart 下多块独立取回）
    #[test]
    fn bs_9_multiple_blocks() {
        let d = dir();
        {
            let store = BlockStore::open(d.path()).unwrap();
            for tag in 0..5u8 {
                store.put(&mk_block(tag)).unwrap();
            }
            assert_eq!(store.clear(), 5, "五份记录");
        }
        // 重新写入（restart 场景）后逐个取回
        {
            let store = BlockStore::open(d.path()).unwrap();
            for tag in 0..5u8 {
                store.put(&mk_block(tag)).unwrap();
            }
        }
        let reopened = BlockStore::open(d.path()).unwrap();
        for tag in 0..5u8 {
            let b = mk_block(tag);
            let h = hash_of(&b);
            assert_eq!(reopened.get(&h).unwrap(), Some(b), "多块独立取回");
        }
    }

    // BS-10：deterministic retrieval（多次 get 一致；无随机/时间）
    #[test]
    fn bs_10_deterministic_retrieval() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(9);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        let a = store.get(&h).unwrap();
        let c = store.get(&h).unwrap();
        assert_eq!(a, c, "多次读取一致");
        assert_eq!(a, Some(b.clone()));
        assert_eq!(store.block_path(&h), store.block_path(&h), "路径确定性");
    }
}
