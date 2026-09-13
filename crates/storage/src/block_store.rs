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
//!
//! # P1-A.20-C Phase 1 —— multi-encoding（Layout B′）
//!
//! **根因**：`block_hash = SHA-256(canonical_header‖canonical_body)` **冻结不含 `proposer_signature`**
//! （ADR-0042 FROZEN；`block_hash(A) == block_hash(B)` 即使 signature 不同）⇒ 同一 hash 可**合法**
//! 对应多个 proposer encoding；而 legacy「一 hash 一 record」把第二个合法 encoding 判为
//! [`StorageError::CorruptedState`] ⇒ 上层 fail-closed。
//!
//! **布局（Layout B′）**：
//! ```text
//! blocks/
//!   block_<hash64>.blk          # legacy 单记录：**保留**（不删 / 不改名 / 不自动迁移 / 不覆盖）
//!   <hash64>/                   # 新：同一 hash 多 encoding
//!     p_<proposer64>.blk        #   文件名 = proposer **索引提示**（非权威）
//!     p_<proposer64>.blk.tmp    #   原子写残留（**永不**被当作 encoding）
//! ```
//!
//! **encoding identity = `(block_hash, proposer)`**（**不是** `(block_hash, round)`：round → proposer
//! 是多对一；同一 proposer 对不同 round 的同内容会产生**同一签名** ⇒ 同一 encoding）。
//!
//! **不变式**：
//! - **zero-persistence**：任何未通过 `block_hash` 重算 + 签名验证的输入 ⇒ **不落盘**（连目录都不创建）；
//! - **永不覆盖 / 永不删除**：已存在的 encoding 不被覆盖或删除（同 `(hash, proposer)` 字节不一致 ⇒
//!   `CorruptedState`，因为同一 proposer 对同一内容必产生同一签名）；
//! - **cap 非致命**：[`PutOutcome::CapReached`] 绝不映射为 `CorruptedState`，不删除 / 不覆盖 / 不写盘；
//! - **无 metadata**：不使用 index/manifest（避免 dangling metadata / 两文件原子性窗口）；
//!   重启后由目录发现 encoding（`.tmp` 忽略）；
//! - **文件名不构成权威**：proposer 绑定只能由签名验证建立（[`BlockStore::get_for_proposer_verified`]）；
//! - **storage 不决定权威**：不遍历 ValidatorSet / 不猜 proposer / 不猜 round（均由 caller 提供
//!   `expected_vk` + `chain_id`；storage crate **不**引入 consensus 依赖）。

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use nova_core::block::{Block, block_hash, decode_block, encode_block, verify_block_signature};
use nova_crypto::hash::protocol_hash;
use nova_crypto::signature::VerifyingKey;

use crate::error::StorageError;

/// Block 记录 magic（区分 WAL 0x01/0x05、snapshot 0x02/0x06、HeadRecord 0x03）。
const BLOCK_FILE_MAGIC: u8 = 0x07;
/// Block 记录版本（V0.1；未知版本 ⇒ 拒）。
const BLOCK_FILE_VERSION: u8 = 0x01;
/// 记录头长度：magic(1) + version(1) + canonical_len(4 LE)。
const HEADER_LEN: usize = 1 + 1 + 4;

/// **P1-A.20-C Phase 1 —— encoding 数上界（storage-level 防御常量）**。
///
/// 设计依据（非“拍数字”）：
/// - 合法 encoding 数 ≤ 产生**同一 canonical 内容**的相异 proposer 数（Ed25519 决定性：同一 key +
///   同一 signature message ⇒ 同一 signature ⇒ 每 proposer 至多 1 个 encoding）；
/// - 每个 encoding 必须对集合成员的 key 验签成功，且验证**先于**落盘 ⇒ 恶意 peer **无法**增加上限；
/// - 与 `round` 数量**无关**（同一 proposer 反复重提案不产生新 encoding）。
///
/// 因此实际上界 = `min(caller 传入的 max_encodings, ABSOLUTE_MAX_ENCODINGS)`。
/// 该常量只作防御性硬顶（防病态 caller / 病态目录），**不**依赖 consensus / validator set。
pub const ABSOLUTE_MAX_ENCODINGS: usize = 64;

/// [`BlockStore::put_verified`] 的结果（**非错误**语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// 该 `(block_hash, proposer)` 的 encoding 已存在且记录字节**完全一致**（幂等；非错误）。
    AlreadyPresent,
    /// 新增了一个 encoding。
    Inserted,
    /// 该 `block_hash` 的 encoding 数已达上限：**未写入 / 未删除 / 未覆盖**（非致命）。
    CapReached,
}

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

/// `[u8; 32]` ⇒ 64 位小写 hex（deterministic；无随机 / 无墙钟）。
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 单个 hex 字符 ⇒ 半字节（严格：仅 `0-9a-f`）。
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// 严格读取记录 ⇒ [`Block`]（magic/version/len/checksum + canonical strict decode）。
fn read_record_strict(record: &[u8]) -> Result<Block, StorageError> {
    let canonical = decode_block_record(record)?;
    decode_block(&canonical).map_err(|_| StorageError::CorruptedState)
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

    /// **legacy / compatibility** —— 保存 Block（key = `block_hash(block)`；**单记录路径**）。
    ///
    /// - 不存在 ⇒ 原子写记录。
    /// - 已存在：记录**逐字节一致** ⇒ `Ok`（幂等，无第二份逻辑记录）；
    ///   不一致（同 hash 不同 bytes）⇒ [`StorageError::CorruptedState`]（**绝不静默覆盖**）。
    ///
    /// ⚠️ **P1-A.20-C 状态**：本方法**不**验证签名、**不**支持多 encoding（无 proposer 参数），
    /// 因此「同 hash 不同 proposer 签名」在此仍会 `CorruptedState`。
    /// 生产写入路径应迁移到 [`Self::put_verified`]（Phase 2 / Phase 3）。
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

    // -----------------------------------------------------------------------
    // P1-A.20-C Phase 1 —— multi-encoding（Layout B′；identity = (hash, proposer)）
    // -----------------------------------------------------------------------

    /// **`(block_hash, proposer)` 的 encoding 目录**：`<dir>/<hash64>/`（目录名 = 协议身份）。
    fn encoding_dir(&self, hash: &[u8; 32]) -> PathBuf {
        self.dir.join(hex32(hash))
    }

    /// **`(block_hash, proposer)` 的 encoding 记录路径**：`<dir>/<hash64>/p_<proposer64>.blk`。
    fn encoding_path(&self, hash: &[u8; 32], proposer: &[u8; 32]) -> PathBuf {
        self.encoding_dir(hash)
            .join(format!("p_{}.blk", hex32(proposer)))
    }

    /// 解析 encoding 文件名：严格 `p_<64 hex>.blk` ⇒ proposer bytes；否则 `None`。
    ///
    /// `.blk.tmp`（原子写残留）与任何外来文件**不**被当作 encoding。
    fn parse_encoding_name(name: &str) -> Option<[u8; 32]> {
        let core = name.strip_prefix("p_")?.strip_suffix(".blk")?;
        if core.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in core.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0])?;
            let lo = hex_val(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(out)
    }

    /// 目录内**可寻址** encoding 的 proposer 列表（升序、去重、**有界**）。
    ///
    /// - 目录不存在 ⇒ 空（不报错）；
    /// - 仅 `p_<64hex>.blk` 形态计入（`.tmp` / 外来文件 **忽略**）；
    /// - 排序后截断到 [`ABSOLUTE_MAX_ENCODINGS`]（返回有界、确定性，不依赖遍历顺序）。
    pub fn list_proposers(&self, hash: &[u8; 32]) -> Result<Vec<[u8; 32]>, StorageError> {
        let dir = self.encoding_dir(hash);
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(StorageError::BackendFailure),
        };
        let mut out: Vec<[u8; 32]> = Vec::new();
        for entry in rd {
            let Ok(entry) = entry else {
                return Err(StorageError::BackendFailure);
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(p) = Self::parse_encoding_name(&name) {
                out.push(p);
            }
        }
        out.sort_unstable();
        out.dedup();
        out.truncate(ABSOLUTE_MAX_ENCODINGS);
        Ok(out)
    }

    /// 读取某 `(hash, proposer)` 的 encoding（strict 记录解码 + `block_hash` 重算 == 目录 hash）。
    ///
    /// - 文件不存在 ⇒ `Ok(None)`；
    /// - 记录损坏 / hash 不一致 ⇒ [`StorageError::CorruptedState`]（**不**静默信任文件名）；
    /// - **不**验证签名（storage 无密钥）⇒ 需要权威绑定请用 [`Self::get_for_proposer_verified`]。
    pub fn get_for_proposer(
        &self,
        hash: &[u8; 32],
        proposer: &[u8; 32],
    ) -> Result<Option<Block>, StorageError> {
        let path = self.encoding_path(hash, proposer);
        if !path.exists() {
            return Ok(None);
        }
        let record = fs::read(&path).map_err(|_| StorageError::BackendFailure)?;
        let block = read_record_strict(&record)?;
        if block_hash(&block).map_err(|_| StorageError::CorruptedState)? != *hash {
            return Err(StorageError::CorruptedState);
        }
        Ok(Some(block))
    }

    /// 读取某 `(hash, proposer)` 的 encoding **并验证签名**（`expected_vk` / `chain_id` 由调用方提供）。
    ///
    /// 语义：文件名 proposer 必须与**实际签名者**一致才视为 usable encoding ——
    /// 记录与 hash 校验通过但签名对 `expected_vk` 验证失败 ⇒ [`StorageError::CorruptedState`]
    /// （防「文件名伪造 proposer」；storage 仍不遍历 ValidatorSet）。
    pub fn get_for_proposer_verified(
        &self,
        hash: &[u8; 32],
        proposer: &[u8; 32],
        expected_vk: &VerifyingKey,
        chain_id: u64,
    ) -> Result<Option<Block>, StorageError> {
        let Some(block) = self.get_for_proposer(hash, proposer)? else {
            return Ok(None);
        };
        verify_block_signature(&block, expected_vk, chain_id)
            .map_err(|_| StorageError::CorruptedState)?;
        Ok(Some(block))
    }

    /// **内容型读取**：只保证 block **内容**（同一 hash 的各 encoding 的 header/body 逐字节相同）。
    ///
    /// 确定性选择（**禁止**依赖文件系统遍历顺序）：
    /// 1. legacy 单记录 `block_<hash64>.blk` 存在 ⇒ 返回它（既有链与既有语义不变）；
    /// 2. 否则取**最小 proposer 字节序**的 encoding（`list_proposers` 已排序）。
    pub fn get_content(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        let legacy = self.block_path(hash);
        if legacy.exists() {
            let record = fs::read(&legacy).map_err(|_| StorageError::BackendFailure)?;
            let block = read_record_strict(&record)?;
            if block_hash(&block).map_err(|_| StorageError::CorruptedState)? != *hash {
                return Err(StorageError::CorruptedState);
            }
            return Ok(Some(block));
        }
        let Some(min) = self.list_proposers(hash)?.into_iter().next() else {
            return Ok(None);
        };
        self.get_for_proposer(hash, &min)
    }

    /// **P1-A.20-C Phase 1 —— verified multi-encoding 写入**。
    ///
    /// # 步骤（**验证全部先于任何磁盘写入**）
    /// 1. `block_hash(block)`（= 存储 key；frozen ADR-0042 规则，本模块不改）；
    /// 2. `verify_block_signature(block, expected_vk, chain_id)`（**调用方**提供期望 key；
    ///    storage **不**遍历 ValidatorSet / **不**猜 proposer / **不**猜 round）；
    /// 3. canonical 记录编码；
    /// 4. 同 `(hash, proposer)` 已存在：字节一致 ⇒ [`PutOutcome::AlreadyPresent`]；不一致 ⇒
    ///    `CorruptedState`（**绝不覆盖**：同一 proposer 对同一内容必产生同一签名）；
    /// 5. cap = `min(max_encodings, ABSOLUTE_MAX_ENCODINGS)`；已达 ⇒ [`PutOutcome::CapReached`]
    ///    （**非致命 / 不删除 / 不覆盖 / 不写盘**）；
    /// 6. 目录（如需）创建 + **原子写**（tmp + fsync + rename）。
    ///
    /// # 参数
    /// - `proposer`：调用方断言的 proposer 身份（32B）——仅作**索引标签 / 文件名**，
    ///   storage **不**授权该标签（授权来源 = `expected_vk` 的签名验证）；
    /// - `expected_vk`：该 proposer 的验证公钥（签名验证的唯一权威来源）；
    /// - `chain_id`：签名域分离参数（storage 不自持 chain 配置）。
    pub fn put_verified(
        &self,
        block: &Block,
        proposer: &[u8; 32],
        expected_vk: &VerifyingKey,
        chain_id: u64,
        max_encodings: usize,
    ) -> Result<PutOutcome, StorageError> {
        // 1. 协议身份（frozen：SHA-256(canonical_header‖canonical_body)）。
        let hash = block_hash(block).map_err(|_| StorageError::SerializationFailure)?;
        // 2. 签名验证（invalid ⇒ 在**任何**落盘动作之前返回 ⇒ zero-persistence）。
        verify_block_signature(block, expected_vk, chain_id)
            .map_err(|_| StorageError::CorruptedState)?;
        // 3. canonical 记录（与 legacy 路径同一编码；无第二套 Block encoding）。
        let canonical = encode_block(block).map_err(|_| StorageError::SerializationFailure)?;
        let record = encode_block_record(&canonical);
        let path = self.encoding_path(&hash, proposer);
        // 4. 幂等 / 冲突（同 proposer 不同字节 ⇒ 拒绝覆盖）。
        if path.exists() {
            let existing = fs::read(&path).map_err(|_| StorageError::BackendFailure)?;
            if existing == record {
                return Ok(PutOutcome::AlreadyPresent);
            }
            return Err(StorageError::CorruptedState);
        }
        // 5. cap（写盘前；越界 ⇒ 非致命，不触碰既有文件）。
        let cap = max_encodings.min(ABSOLUTE_MAX_ENCODINGS);
        if self.list_proposers(&hash)?.len() >= cap {
            return Ok(PutOutcome::CapReached);
        }
        // 6. 原子写（目录仅在此处创建 ⇒ 失败路径零持久化）。
        fs::create_dir_all(self.encoding_dir(&hash)).map_err(|_| StorageError::BackendFailure)?;
        atomic_write(&path, &record)?;
        Ok(PutOutcome::Inserted)
    }

    /// **legacy / compatibility** —— 读取 legacy 单记录 Block；不存在 ⇒ `Ok(None)`。
    ///
    /// 校验链：记录 strict decode（magic/version/checksum）→ `decode_block`（结构级 strict）→
    /// `block_hash(block)` 重算 == 请求 hash；任一不匹配 ⇒ [`StorageError::CorruptedState`]。
    ///
    /// ⚠️ 本方法**只看 legacy 路径**（既有语义不变）。需要「legacy 或任一 encoding」的内容读取请用
    /// [`Self::get_content`]；需要按 proposer 精确取用请用 [`Self::get_for_proposer`]。
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

    /// 是否存在该 BlockHash 的**任一** encoding（legacy 记录 **或** 多 encoding 目录中的任一条）。
    ///
    /// 语义（P1-A.20-C Phase 1）：`true` ⟺ legacy 文件存在 ∨ `p_<64hex>.blk`（不含 `.tmp`）存在 ≥ 1。
    pub fn contains(&self, hash: &[u8; 32]) -> Result<bool, StorageError> {
        if self.block_path(hash).exists() {
            return Ok(true);
        }
        Ok(!self.list_proposers(hash)?.is_empty())
    }

    /// 该 hash 的 legacy 记录文件路径（deterministic：block hash hex；无随机 / 时间）。
    fn block_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("block_{}.blk", hex32(hash)))
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

    // =====================================================================
    // P1-A.20-C Phase 1 —— multi-encoding（Layout B′）测试 T1–T12
    // =====================================================================

    use nova_core::block::encode_block_header;
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::signature::{SigningKey, sign_message_hash};

    /// 测试链 ID（与 `mk_block` header 一致）。
    const CHAIN: u64 = 1001;

    /// 确定性测试密钥（`SigningKey::from_seed` = test/dev seam）。
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed([seed; 32])
    }

    /// proposer 索引标签（32B）。storage **不**验证其与 key 的绑定（由调用方保证）⇒
    /// 测试中始终成对使用（同一 seed 的 label + key）。
    fn pid(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// 按**生产同款**签名域签名 block（payload = canonical_header；`DomainId::Block`；chain_id）。
    fn sign_block(block: &mut Block, sk: &SigningKey, chain_id: u64) {
        let payload = encode_block_header(&block.header);
        let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload)
            .expect("signed bytes");
        let msg = hash_signing_message(&signed);
        block.proposer_signature = sign_message_hash(sk, &msg).to_bytes();
    }

    /// 目录内**可寻址** encoding 文件数（仅 `p_<64hex>.blk`；`.tmp` 不计）。
    fn encoding_files(store: &BlockStore, hash: &[u8; 32]) -> usize {
        fs::read_dir(store.encoding_dir(hash))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        BlockStore::parse_encoding_name(&e.file_name().to_string_lossy()).is_some()
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// encoding 目录项总数（含 `.tmp`；用于「零持久化」断言）。
    fn dir_entries(store: &BlockStore, hash: &[u8; 32]) -> usize {
        fs::read_dir(store.encoding_dir(hash))
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }

    /// 同一 canonical 内容（header+body 逐字节相同）+ 两个不同 proposer 的真实签名
    /// ⇒ **同 block_hash / 不同 proposer_signature**（frozen ADR-0042 hash exclusion）。
    fn twin_blocks(tag: u8) -> (Block, Block, [u8; 32]) {
        let base = mk_block(tag);
        let mut a = base.clone();
        let mut b = base;
        sign_block(&mut a, &key(0xA1), CHAIN);
        sign_block(&mut b, &key(0xB2), CHAIN);
        assert_ne!(
            a.proposer_signature, b.proposer_signature,
            "两个 proposer 签名不同"
        );
        let ha = hash_of(&a);
        assert_eq!(ha, hash_of(&b), "signature ∉ block_hash ⇒ 同 hash");
        (a, b, ha)
    }

    // T1 —— legacy 单 encoding：旧 `block_<hash>.blk` 继续可读；不产生目录 encoding。
    #[test]
    fn t1_legacy_single_encoding() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let b = mk_block(11);
        let h = hash_of(&b);
        store.put(&b).unwrap();
        assert_eq!(
            store.get_content(&h).unwrap(),
            Some(b.clone()),
            "get_content 读 legacy"
        );
        assert_eq!(store.get(&h).unwrap(), Some(b), "legacy get 语义不变");
        assert!(store.contains(&h).unwrap());
        assert!(
            store.list_proposers(&h).unwrap().is_empty(),
            "legacy 不产生目录 encoding"
        );
        assert_eq!(encoding_files(&store, &h), 0);
    }

    // T2 —— 同 hash / 两个 proposer encoding 同时存在（**不** KEEP-FIRST / **不** KEEP-LATEST）。
    #[test]
    fn t2_same_hash_two_proposer_encodings() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, b, h) = twin_blocks(12);
        let vk_a = key(0xA1).verifying_key();
        let vk_b = key(0xB2).verifying_key();
        assert_eq!(
            store.put_verified(&a, &pid(0xA1), &vk_a, CHAIN, 8).unwrap(),
            PutOutcome::Inserted
        );
        assert_eq!(
            store.put_verified(&b, &pid(0xB2), &vk_b, CHAIN, 8).unwrap(),
            PutOutcome::Inserted
        );
        assert_eq!(encoding_files(&store, &h), 2, "两个 encoding 文件同时存在");
        assert_eq!(
            store.list_proposers(&h).unwrap(),
            vec![pid(0xA1), pid(0xB2)],
            "升序、确定性"
        );
        assert!(store.contains(&h).unwrap());
        let ga = store.get_for_proposer(&h, &pid(0xA1)).unwrap().unwrap();
        let gb = store.get_for_proposer(&h, &pid(0xB2)).unwrap().unwrap();
        assert_eq!(hash_of(&ga), h);
        assert_eq!(hash_of(&gb), h);
        assert_eq!(ga.header, gb.header, "header 逐字节相同");
        assert_eq!(ga.body, gb.body, "body 逐字节相同");
        assert_ne!(ga.proposer_signature, gb.proposer_signature);
    }

    // T3 —— `get_for_proposer` 精确返回指定 proposer；verified 读取拒绝「文件名 ≠ 实际签名者」。
    #[test]
    fn t3_get_for_proposer_exact() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, b, h) = twin_blocks(13);
        store
            .put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8)
            .unwrap();
        store
            .put_verified(&b, &pid(0xB2), &key(0xB2).verifying_key(), CHAIN, 8)
            .unwrap();
        assert_eq!(
            store
                .get_for_proposer(&h, &pid(0xA1))
                .unwrap()
                .unwrap()
                .proposer_signature,
            a.proposer_signature
        );
        assert_eq!(
            store
                .get_for_proposer(&h, &pid(0xB2))
                .unwrap()
                .unwrap()
                .proposer_signature,
            b.proposer_signature
        );
        assert!(
            store
                .get_for_proposer_verified(&h, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN)
                .unwrap()
                .is_some(),
            "正确 key ⇒ 验证通过"
        );
        assert_eq!(
            store.get_for_proposer_verified(&h, &pid(0xA1), &key(0xB2).verifying_key(), CHAIN),
            Err(StorageError::CorruptedState),
            "文件名 proposer 与实际签名者不一致 ⇒ 拒绝（不静默信任文件名）"
        );
    }

    // T4 —— unknown proposer ⇒ `None`（**不得** fallback 到其它 proposer 的 encoding）。
    #[test]
    fn t4_unknown_proposer_none_no_fallback() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, _, h) = twin_blocks(14);
        store
            .put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8)
            .unwrap();
        assert_eq!(store.get_for_proposer(&h, &pid(0xCC)).unwrap(), None);
        assert_eq!(
            store
                .get_for_proposer_verified(&h, &pid(0xCC), &key(0xCC).verifying_key(), CHAIN)
                .unwrap(),
            None
        );
    }

    // T5 —— duplicate same `(hash, proposer)` ⇒ `AlreadyPresent` 且磁盘字节不变。
    #[test]
    fn t5_duplicate_same_proposer_already_present() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, _, h) = twin_blocks(15);
        let vk_a = key(0xA1).verifying_key();
        assert_eq!(
            store.put_verified(&a, &pid(0xA1), &vk_a, CHAIN, 8).unwrap(),
            PutOutcome::Inserted
        );
        let path = store.encoding_path(&h, &pid(0xA1));
        let before = fs::read(&path).unwrap();
        assert_eq!(
            store.put_verified(&a, &pid(0xA1), &vk_a, CHAIN, 8).unwrap(),
            PutOutcome::AlreadyPresent
        );
        assert_eq!(fs::read(&path).unwrap(), before, "磁盘字节不变（无重写）");
        assert_eq!(encoding_files(&store, &h), 1);
    }

    // T6 —— 第三个 proposer 仍可新增；内容读取确定性（最小 proposer）。
    #[test]
    fn t6_third_proposer_and_deterministic_content_read() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, b, h) = twin_blocks(16);
        let mut c = a.clone();
        sign_block(&mut c, &key(0xC3), CHAIN);
        assert_eq!(hash_of(&c), h, "第三个 proposer 亦同 hash");
        store
            .put_verified(&c, &pid(0xC3), &key(0xC3).verifying_key(), CHAIN, 8)
            .unwrap();
        store
            .put_verified(&b, &pid(0xB2), &key(0xB2).verifying_key(), CHAIN, 8)
            .unwrap();
        store
            .put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8)
            .unwrap();
        assert_eq!(
            store.list_proposers(&h).unwrap(),
            vec![pid(0xA1), pid(0xB2), pid(0xC3)]
        );
        let g1 = store.get_content(&h).unwrap().unwrap();
        let g2 = store.get_content(&h).unwrap().unwrap();
        assert_eq!(g1, g2, "多次内容读取一致（确定性）");
        assert_eq!(
            g1.proposer_signature, a.proposer_signature,
            "内容读取 = 最小 proposer 的 encoding"
        );
    }

    // T7 —— invalid signature ⇒ ERROR + **零持久化**（连目录都不创建）。
    #[test]
    fn t7_invalid_signature_zero_persistence() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        // (a) 未签名（全零签名）⇒ 对任何 key 都不成立。
        let unsigned = mk_block(17);
        let h_u = hash_of(&unsigned);
        assert_eq!(
            store.put_verified(&unsigned, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8),
            Err(StorageError::CorruptedState)
        );
        assert_eq!(dir_entries(&store, &h_u), 0, "零持久化：目录未创建");
        // (b) 由 A 签名但用 B 的 key 验证 ⇒ 拒绝。
        let mut signed = mk_block(18);
        sign_block(&mut signed, &key(0xA1), CHAIN);
        let h_s = hash_of(&signed);
        assert_eq!(
            store.put_verified(&signed, &pid(0xB2), &key(0xB2).verifying_key(), CHAIN, 8),
            Err(StorageError::CorruptedState)
        );
        assert_eq!(dir_entries(&store, &h_s), 0, "零持久化：目录未创建");
    }

    // T8 —— 既有记录 hash 不一致 ⇒ ERROR + 不覆盖 / 不新增；读路径同样检测。
    #[test]
    fn t8_hash_mismatch_rejected_no_overwrite() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, _, h) = twin_blocks(19);
        let other = mk_block(20);
        let path = store.encoding_path(&h, &pid(0xA1));
        fs::create_dir_all(store.encoding_dir(&h)).unwrap();
        atomic_write(&path, &encode_block_record(&encode_block(&other).unwrap())).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            store.put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8),
            Err(StorageError::CorruptedState),
            "hash 不一致 ⇒ 拒绝（绝不覆盖）"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "既有记录未被覆盖");
        assert_eq!(dir_entries(&store, &h), 1, "未新增文件");
        assert_eq!(
            store.get_for_proposer(&h, &pid(0xA1)),
            Err(StorageError::CorruptedState),
            "读路径检测 hash mismatch"
        );
        assert_eq!(store.get_content(&h), Err(StorageError::CorruptedState));
    }

    // T9 —— corrupted record（字节篡改）⇒ fail-closed 检测。
    #[test]
    fn t9_corrupted_record_detected() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, _, h) = twin_blocks(21);
        store
            .put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8)
            .unwrap();
        let path = store.encoding_path(&h, &pid(0xA1));
        let mut record = fs::read(&path).unwrap();
        let flip = record.len() - 34;
        record[flip] ^= 0xFF;
        fs::write(&path, &record).unwrap();
        assert_eq!(
            store.get_for_proposer(&h, &pid(0xA1)),
            Err(StorageError::CorruptedState)
        );
        assert_eq!(store.get_content(&h), Err(StorageError::CorruptedState));
    }

    // T10 —— `.tmp` 残留被忽略（不是 encoding；不参与 list / get / contains）。
    #[test]
    fn t10_tmp_ignored() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, _, h) = twin_blocks(22);
        let final_path = store.encoding_path(&h, &pid(0xA1));
        let tmp_path = final_path.with_extension("blk.tmp");
        assert!(
            tmp_path.to_string_lossy().ends_with(".blk.tmp"),
            "tmp 命名 = <encoding>.blk.tmp"
        );
        fs::create_dir_all(store.encoding_dir(&h)).unwrap();
        fs::write(&tmp_path, encode_block_record(&encode_block(&a).unwrap())).unwrap();
        assert_eq!(dir_entries(&store, &h), 1, "目录内只有 1 个 tmp");
        assert!(
            store.list_proposers(&h).unwrap().is_empty(),
            "tmp 不计为 encoding"
        );
        assert_eq!(store.get_for_proposer(&h, &pid(0xA1)).unwrap(), None);
        assert_eq!(store.get_content(&h).unwrap(), None);
        assert!(!store.contains(&h).unwrap());
        // reopen 后仍然忽略。
        let reopened = BlockStore::open(d.path()).unwrap();
        assert!(reopened.list_proposers(&h).unwrap().is_empty());
        assert!(!reopened.contains(&h).unwrap());
    }

    // T11 —— 无 metadata：reopen 后由目录重建发现（两个 encoding 均可用）。
    #[test]
    fn t11_reopen_rebuild_discovery_without_metadata() {
        let d = dir();
        let (a, b, h) = twin_blocks(23);
        {
            let store = BlockStore::open(d.path()).unwrap();
            store
                .put_verified(&a, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 8)
                .unwrap();
            store
                .put_verified(&b, &pid(0xB2), &key(0xB2).verifying_key(), CHAIN, 8)
                .unwrap();
            assert_eq!(
                dir_entries(&store, &h),
                2,
                "只有两个 .blk（无 metadata/index）"
            );
        }
        let reopened = BlockStore::open(d.path()).unwrap();
        assert_eq!(
            reopened.list_proposers(&h).unwrap(),
            vec![pid(0xA1), pid(0xB2)]
        );
        assert_eq!(reopened.get_for_proposer(&h, &pid(0xA1)).unwrap(), Some(a));
        assert_eq!(reopened.get_for_proposer(&h, &pid(0xB2)).unwrap(), Some(b));
        assert_eq!(encoding_files(&reopened, &h), 2);
    }

    // T12 —— cap reached ⇒ `CapReached`（非致命）：既有 encoding 完整保留（不删除 / 不覆盖 / 不 corruption）。
    #[test]
    fn t12_cap_reached_preserves_existing() {
        let d = dir();
        let store = BlockStore::open(d.path()).unwrap();
        let (a, b, h) = twin_blocks(24);
        let vk_a = key(0xA1).verifying_key();
        assert_eq!(
            store.put_verified(&a, &pid(0xA1), &vk_a, CHAIN, 1).unwrap(),
            PutOutcome::Inserted
        );
        let path_a = store.encoding_path(&h, &pid(0xA1));
        let before = fs::read(&path_a).unwrap();
        // cap=1 ⇒ 第二个 proposer：**非致命**且非 CorruptedState。
        assert_eq!(
            store
                .put_verified(&b, &pid(0xB2), &key(0xB2).verifying_key(), CHAIN, 1)
                .unwrap(),
            PutOutcome::CapReached
        );
        assert_eq!(encoding_files(&store, &h), 1, "既有 encoding 保留，未新增");
        assert_eq!(fs::read(&path_a).unwrap(), before, "既有 encoding 未被覆盖");
        assert_eq!(store.get_for_proposer(&h, &pid(0xB2)).unwrap(), None);
        assert_eq!(store.get_for_proposer(&h, &pid(0xA1)).unwrap(), Some(a));
        // `max_encodings = 0` ⇒ 首个即 CapReached（且不写盘）。
        let (x, _, hx) = twin_blocks(25);
        assert_eq!(
            store
                .put_verified(&x, &pid(0xA1), &key(0xA1).verifying_key(), CHAIN, 0)
                .unwrap(),
            PutOutcome::CapReached
        );
        assert_eq!(dir_entries(&store, &hx), 0, "CapReached 不写盘");
        // caller 传入超大值被 clamp 到 `ABSOLUTE_MAX_ENCODINGS`（不 panic）。
        assert_eq!(
            store
                .put_verified(
                    &x,
                    &pid(0xA1),
                    &key(0xA1).verifying_key(),
                    CHAIN,
                    usize::MAX
                )
                .unwrap(),
            PutOutcome::Inserted
        );
    }
}
