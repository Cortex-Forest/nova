//! Validator Safety Store（STEP 10-15T；Restart Safety — Option B）。
//!
//! # 职责（node-local / validator-local；**非** canonical state）
//! - [`ValidatorSafetyStore`]：独立于 `PersistentBackend` canonical state WAL 的 **fail-closed**
//!   追加式 journal —— 持久化本地投票授权（double-vote）证据、签名证据与 `LockedState`。
//! - 每个 [`crate::validator::ValidatorActor`] 持有自己的 store（validator isolation；无共享）。
//! - **不持久化** private key / seed / mnemonic / secret；只保存 `ValidatorId`（公钥派生）、
//!   vote evidence / signature、`LockedState`、chain identity。
//!
//! # 安全语义（10-15T DESIGN FREEZE）
//! - **Identity header**：`magic + safety_version(=1, 独立于 DATABASE_VERSION) + network_id + chain_id
//!   (u64 LE) + genesis_hash + validator_id`（各字段复用项目既有 canonical representation：
//!   `NetworkId::as_u8()` / `u64::to_le_bytes()` / raw `[u8;32]` —— 不创造新 ChainIdentity
//!   serialization）。加载时 header 任一 mismatch ⇒ [`ValidatorSafetyError::IdentityMismatch`]。
//! - **严格恢复（FAIL CLOSED）**：magic / version / identity / header checksum / 逐条 record
//!   checksum 任何失败（**含最后一条不完整/损坏尾部**）⇒ `Err`，**不**采用
//!   `PersistentBackend::open()` 的「损坏尾部 break 丢弃继续」语义。
//! - **记录模型**：`VoteIntent`（signature 前持久化）→ `VoteSigned`（签名后持久化）→
//!   `LockedState`。恢复时：同 `VoteKey` 不同 target ⇒ [`ValidatorSafetyError::ConflictingRecord`]；
//!   `VoteSigned` 无对应 intent ⇒ `MissingReservation`；结构非法 lock ⇒ `InvalidLockState`。
//! - **Persist-before-sign** 由 actor 编排：`commit_vote_intent` 在签名前调用、`commit_signature`
//!   在签名后、发事件前调用（见 [`crate::validator::ValidatorActor::produce_vote`]）。
//!
//! # 文件格式（append-only journal；单 validator 单文件）
//! ```text
//! header (114B)：magic(8) ‖ safety_version(1) ‖ network_id(1) ‖ chain_id u64LE(8) ‖
//!                genesis_hash(32) ‖ validator_id(32) ‖ SHA-256(header[0..82])(32)
//! record：record_type(1) ‖ body_len u32LE(4) ‖ body ‖ SHA-256(type‖len‖body)(32)
//!   VoteIntent (body 89B)：key(h8‖r8‖type1)=17 ‖ target(32) ‖ source(32) ‖ timestamp u64LE(8)
//!   VoteSigned (body 81B)：key(17) ‖ signature(64)
//!   LockedState(body 1|41B)：presence(1) ‖ [hash(32) ‖ round u64LE(8) if locked]
//! ```
//! Checksum 复用 `nova_crypto::hash::protocol_hash`（SHA-256）——与 storage `PersistentBackend`
//! WAL/snapshot checksum 一致的项目内既有模式（本地完整性原语；非新 consensus 承诺）。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nova_consensus::round::LockedState;
use nova_consensus::validator::ValidatorId;
use nova_consensus::vote::VoteType;
use nova_crypto::address::NetworkId;
use nova_crypto::hash::protocol_hash;

use crate::vote_ledger::{VoteKey, VoteLedger, VoteLedgerError};

/// Safety State 持久化格式版本（独立于 storage `DATABASE_VERSION`）。
pub const SAFETY_STATE_VERSION: u8 = 1;
/// Header 固定长度（82B 前置 + 32B checksum）。
pub const SAFETY_HEADER_LEN: usize = 114;

const MAGIC: [u8; 8] = *b"NOVASAFE";
/// 记录类型：VoteIntent（signature 前持久化的投票意图；signature 缺席）。
const REC_INTENT: u8 = 0x01;
/// 记录类型：VoteSigned（签名证据；对应已持久化的 intent）。
const REC_SIGNED: u8 = 0x02;
/// 记录类型：LockedState（本地 lock 快照；last-wins 恢复）。
const REC_LOCK: u8 = 0x03;

/// VoteKey body 定长（height u64LE + round u64LE + vote_type u8）。
const KEY_LEN: usize = 17;

/// ValidatorSafetyStore 错误（node-local；fail-closed 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorSafetyError {
    /// 文件 I/O 失败（打开/追加/fsync）——fail closed（不签名）。
    Io,
    /// Header magic 不符。
    UnknownMagic,
    /// `safety_version` 未知（≠ `SAFETY_STATE_VERSION`）。
    UnknownVersion,
    /// Header 损坏（长度不足 / header checksum 不符）。
    CorruptHeader,
    /// 未知记录类型 / 记录 framing 非法。
    CorruptRecord,
    /// 单条 record checksum 不符。
    ChecksumMismatch,
    /// 记录不完整（含最后一条截断/损坏尾部）——**不丢弃继续**（fail closed）。
    TruncatedRecord,
    /// 结构非法的 LockedState 记录（presence 非法 / 混合 Option 状态）。
    InvalidLockState,
    /// `VoteSigned` 无对应已持久化 intent。
    MissingReservation,
    /// 同 `VoteKey` 不同 target / 冲突签名（double-vote across restart ⇒ corrupted）。
    ConflictingRecord,
    /// Header identity（network_id / chain_id / genesis_hash / validator_id）与期望不符。
    IdentityMismatch,
    /// `create` 时文件已存在（禁止覆写历史）。
    AlreadyExists,
}

/// Safety identity（复用项目既有 canonical primitives；非 ChainIdentity 新序列化）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyIdentity {
    /// `NetworkId::as_u8()`（0x01/0x02/0x03）。
    pub network_id: u8,
    /// `chain_id`（u64 LE；Genesis canonical 同款编码）。
    pub chain_id: u64,
    /// `genesis_hash`（raw `[u8;32]`；链实例唯一锚）。
    pub genesis_hash: [u8; 32],
    /// `ValidatorId::as_bytes()`（raw 32B）。
    pub validator_id: [u8; 32],
}

impl SafetyIdentity {
    /// 从既有类型构造（network_id / chain_id / genesis_hash / ValidatorId 的 canonical 表示）。
    pub fn new(
        network_id: NetworkId,
        chain_id: u64,
        genesis_hash: [u8; 32],
        validator_id: &ValidatorId,
    ) -> Self {
        Self {
            network_id: network_id.as_u8(),
            chain_id,
            genesis_hash,
            validator_id: *validator_id.as_bytes(),
        }
    }
}

/// 恢复（严格重放）结果：重建的 in-memory [`VoteLedger`] 与 `LockedState`。
#[derive(Debug, Clone)]
pub struct RecoveredSafetyState {
    pub ledger: VoteLedger,
    pub locked_state: LockedState,
}

/// 独立 fail-closed 的 validator safety journal（Option B；与 canonical state WAL 分离）。
///
/// - 单 validator 单文件（隔离由调用方以独立路径/identity 保证；无共享状态）。
/// - 每次写入打开-追加-fsync-关闭（崩溃前返回 ⇒ 该记录已 durable）。
#[derive(Debug)]
pub struct ValidatorSafetyStore {
    path: PathBuf,
    identity: SafetyIdentity,
}

impl ValidatorSafetyStore {
    /// 新建（写 header）。若 journal 文件已存在 ⇒ `AlreadyExists`（禁止覆写既有安全历史）。
    pub fn create(path: &Path, identity: SafetyIdentity) -> Result<Self, ValidatorSafetyError> {
        if path.exists() {
            return Err(ValidatorSafetyError::AlreadyExists);
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|_| ValidatorSafetyError::Io)?;
        }
        let header = build_header(identity);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| ValidatorSafetyError::Io)?;
        file.write_all(&header)
            .map_err(|_| ValidatorSafetyError::Io)?;
        file.sync_all().map_err(|_| ValidatorSafetyError::Io)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
        })
    }

    /// 绑定既有 journal（restart 路径；文件实际校验由 [`Self::recover`] 执行）。
    pub fn at(path: &Path, identity: SafetyIdentity) -> Self {
        Self {
            path: path.to_path_buf(),
            identity,
        }
    }

    /// 严格恢复（FAIL CLOSED）：header 校验 → 逐条重放 → 重建 ledger + lock。
    ///
    /// 任何异常（含最后一条截断/损坏）⇒ `Err`；**绝不丢弃损坏尾部继续**。
    pub fn recover(&self) -> Result<RecoveredSafetyState, ValidatorSafetyError> {
        let bytes = fs::read(&self.path).map_err(|_| ValidatorSafetyError::Io)?;
        parse_header(&bytes, self.identity)?;

        let ledger = VoteLedger::new();
        let mut locked_state = LockedState::new();
        let mut pos = SAFETY_HEADER_LEN;
        while pos < bytes.len() {
            // 完整 record 最少 5B framing + 32B checksum。
            if bytes.len() - pos < 1 + 4 + 32 {
                return Err(ValidatorSafetyError::TruncatedRecord);
            }
            let record_type = bytes[pos];
            let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap()) as usize;
            let body_start = pos + 5;
            let checksum_start = body_start
                .checked_add(len)
                .and_then(|v| v.checked_add(32))
                .ok_or(ValidatorSafetyError::CorruptRecord)?;
            if checksum_start > bytes.len() {
                // body 或 checksum 不完整（含损坏尾部）⇒ fail closed。
                return Err(ValidatorSafetyError::TruncatedRecord);
            }
            let expected = protocol_hash(&bytes[pos..checksum_start - 32]);
            let stored = &bytes[checksum_start - 32..checksum_start];
            if &expected[..] != stored {
                return Err(ValidatorSafetyError::ChecksumMismatch);
            }
            apply_record(
                record_type,
                &bytes[body_start..checksum_start - 32],
                &ledger,
                &mut locked_state,
            )?;
            pos = checksum_start;
        }
        Ok(RecoveredSafetyState {
            ledger,
            locked_state,
        })
    }

    /// 持久化投票意图（**签名前**；RT-INV-2）。幂等：重复 intent 记录重放无害。
    pub fn commit_vote_intent(
        &self,
        key: &VoteKey,
        target_block_hash: [u8; 32],
        source_block_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<(), ValidatorSafetyError> {
        let mut body = Vec::with_capacity(KEY_LEN + 32 + 32 + 8);
        body.extend_from_slice(&key_bytes(key));
        body.extend_from_slice(&target_block_hash);
        body.extend_from_slice(&source_block_hash);
        body.extend_from_slice(&timestamp.to_le_bytes());
        self.append_record(REC_INTENT, &body)
    }

    /// 持久化签名证据（**签名后、发事件前**；R4/R5 复用）。幂等语义由 actor/重放保证。
    pub fn commit_signature(
        &self,
        key: &VoteKey,
        signature: [u8; 64],
    ) -> Result<(), ValidatorSafetyError> {
        let mut body = Vec::with_capacity(KEY_LEN + 64);
        body.extend_from_slice(&key_bytes(key));
        body.extend_from_slice(&signature);
        self.append_record(REC_SIGNED, &body)
    }

    /// 持久化 LockedState（**采用前**；RT-22/28：durable BEFORE relying on new lock）。
    /// 结构约束：`locked_block_hash` 与 `locked_round` 必须同为 `Some` 或同为 `None`。
    pub fn commit_lock(&self, lock: &LockedState) -> Result<(), ValidatorSafetyError> {
        let body = encode_lock_body(lock)?;
        self.append_record(REC_LOCK, &body)
    }

    /// 绑定 identity（只读；actor 构造时一致性校验）。
    pub fn identity(&self) -> SafetyIdentity {
        self.identity
    }

    /// journal 文件路径（只读；测试 / 审计）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一条 record（打开 → 追加 → fsync → 关闭；返回前已 durable）。
    ///
    /// OBS-3B（10-15T-HARDEN）：**Safety Journal 必须已存在才能写入**（不 `create`）。
    /// 文件被外部删除/缺失 ⇒ 立即 `Err(Io)` fail closed —— 绝不静默重建无 header 文件 /
    /// 产生虚假 durable 状态 / 继续签名。
    fn append_record(&self, record_type: u8, body: &[u8]) -> Result<(), ValidatorSafetyError> {
        let record = encode_record(record_type, body);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| ValidatorSafetyError::Io)?;
        file.write_all(&record)
            .map_err(|_| ValidatorSafetyError::Io)?;
        file.sync_all().map_err(|_| ValidatorSafetyError::Io)
    }
}

// =========================================================================
// Encoding / decoding（格式见模块 doc；全定长 + SHA-256 checksum）
// =========================================================================

fn build_header(identity: SafetyIdentity) -> Vec<u8> {
    let mut header = Vec::with_capacity(SAFETY_HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(SAFETY_STATE_VERSION);
    header.push(identity.network_id);
    header.extend_from_slice(&identity.chain_id.to_le_bytes());
    header.extend_from_slice(&identity.genesis_hash);
    header.extend_from_slice(&identity.validator_id);
    let checksum = protocol_hash(&header);
    header.extend_from_slice(&checksum);
    debug_assert_eq!(header.len(), SAFETY_HEADER_LEN);
    header
}

/// Header 校验顺序（magic → version → identity → checksum），以产出精确错误变体。
fn parse_header(bytes: &[u8], expected: SafetyIdentity) -> Result<(), ValidatorSafetyError> {
    if bytes.len() < SAFETY_HEADER_LEN {
        return Err(ValidatorSafetyError::CorruptHeader);
    }
    if bytes[0..8] != MAGIC {
        return Err(ValidatorSafetyError::UnknownMagic);
    }
    if bytes[8] != SAFETY_STATE_VERSION {
        return Err(ValidatorSafetyError::UnknownVersion);
    }
    let network_id = bytes[9];
    let chain_id = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&bytes[18..50]);
    let mut validator_id = [0u8; 32];
    validator_id.copy_from_slice(&bytes[50..82]);
    if network_id != expected.network_id
        || chain_id != expected.chain_id
        || genesis_hash != expected.genesis_hash
        || validator_id != expected.validator_id
    {
        return Err(ValidatorSafetyError::IdentityMismatch);
    }
    let mut stored = [0u8; 32];
    stored.copy_from_slice(&bytes[82..SAFETY_HEADER_LEN]);
    let computed = protocol_hash(&bytes[0..82]);
    if computed != stored {
        return Err(ValidatorSafetyError::CorruptHeader);
    }
    Ok(())
}

fn encode_record(record_type: u8, body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(1 + 4 + body.len() + 32);
    record.push(record_type);
    record.extend_from_slice(&(body.len() as u32).to_le_bytes());
    record.extend_from_slice(body);
    let checksum = protocol_hash(&record);
    record.extend_from_slice(&checksum);
    record
}

/// 重放单条记录（VoteIntent / VoteSigned / LockedState）。
fn apply_record(
    record_type: u8,
    body: &[u8],
    ledger: &VoteLedger,
    locked_state: &mut LockedState,
) -> Result<(), ValidatorSafetyError> {
    match record_type {
        REC_INTENT => {
            let (key, target, source, timestamp) = decode_intent_body(body)?;
            match ledger.prepare(&key, target, source, timestamp) {
                Ok(_) => Ok(()), // New 或 Existing（幂等重放）
                Err(VoteLedgerError::DoubleVote { .. }) => {
                    Err(ValidatorSafetyError::ConflictingRecord)
                }
                // prepare 不产生 MissingReservation。
                Err(VoteLedgerError::MissingReservation) => {
                    Err(ValidatorSafetyError::CorruptRecord)
                }
            }
        }
        REC_SIGNED => {
            let (key, signature) = decode_signed_body(body)?;
            match ledger.lookup(&key) {
                None => Err(ValidatorSafetyError::MissingReservation),
                Some(record) => {
                    if record.signature == Some(signature) {
                        Ok(()) // 幂等（同签名重放）
                    } else if record.signature.is_none() {
                        ledger
                            .finalize_signature(&key, signature)
                            .map_err(|_| ValidatorSafetyError::CorruptRecord)
                    } else {
                        // 已有不同签名 ⇒ 冲突（corrupted safety state）。
                        Err(ValidatorSafetyError::ConflictingRecord)
                    }
                }
            }
        }
        REC_LOCK => {
            *locked_state = decode_lock_body(body)?;
            Ok(())
        }
        _ => Err(ValidatorSafetyError::CorruptRecord),
    }
}

fn key_bytes(key: &VoteKey) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out[0..8].copy_from_slice(&key.height.to_le_bytes());
    out[8..16].copy_from_slice(&key.round.to_le_bytes());
    out[16] = vote_type_u8(key.vote_type);
    out
}

fn decode_key(bytes: &[u8]) -> Result<VoteKey, ValidatorSafetyError> {
    if bytes.len() != KEY_LEN {
        return Err(ValidatorSafetyError::CorruptRecord);
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let round = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let vote_type = vote_type_from_u8(bytes[16]).ok_or(ValidatorSafetyError::CorruptRecord)?;
    Ok(VoteKey {
        height,
        round,
        vote_type,
    })
}

fn vote_type_u8(vote_type: VoteType) -> u8 {
    match vote_type {
        VoteType::Prevote => 0x01,
        VoteType::Precommit => 0x02,
    }
}

fn vote_type_from_u8(v: u8) -> Option<VoteType> {
    match v {
        0x01 => Some(VoteType::Prevote),
        0x02 => Some(VoteType::Precommit),
        _ => None,
    }
}

/// VoteIntent body：key(17) ‖ target(32) ‖ source(32) ‖ timestamp u64LE(8) = 89B。
fn decode_intent_body(
    body: &[u8],
) -> Result<(VoteKey, [u8; 32], [u8; 32], u64), ValidatorSafetyError> {
    const LEN: usize = KEY_LEN + 32 + 32 + 8;
    if body.len() != LEN {
        return Err(ValidatorSafetyError::CorruptRecord);
    }
    let key = decode_key(&body[0..KEY_LEN])?;
    let mut target = [0u8; 32];
    target.copy_from_slice(&body[KEY_LEN..KEY_LEN + 32]);
    let mut source = [0u8; 32];
    source.copy_from_slice(&body[KEY_LEN + 32..KEY_LEN + 64]);
    let timestamp = u64::from_le_bytes(body[KEY_LEN + 64..].try_into().unwrap());
    Ok((key, target, source, timestamp))
}

/// VoteSigned body：key(17) ‖ signature(64) = 81B。
fn decode_signed_body(body: &[u8]) -> Result<(VoteKey, [u8; 64]), ValidatorSafetyError> {
    const LEN: usize = KEY_LEN + 64;
    if body.len() != LEN {
        return Err(ValidatorSafetyError::CorruptRecord);
    }
    let key = decode_key(&body[0..KEY_LEN])?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&body[KEY_LEN..]);
    Ok((key, signature))
}

fn encode_lock_body(lock: &LockedState) -> Result<Vec<u8>, ValidatorSafetyError> {
    // 结构约束：hash 与 round 必须同为 Some / None（合法 LockedState 永不混合）。
    match (lock.locked_block_hash, lock.locked_round) {
        (None, None) => Ok(vec![0u8]),
        (Some(hash), Some(round)) => {
            let mut body = Vec::with_capacity(1 + 32 + 8);
            body.push(1u8);
            body.extend_from_slice(&hash);
            body.extend_from_slice(&round.to_le_bytes());
            Ok(body)
        }
        _ => Err(ValidatorSafetyError::InvalidLockState),
    }
}

fn decode_lock_body(body: &[u8]) -> Result<LockedState, ValidatorSafetyError> {
    match body {
        [0] => Ok(LockedState::new()),
        [1, rest @ ..] if rest.len() == 40 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&rest[0..32]);
            let round = u64::from_le_bytes(rest[32..40].try_into().unwrap());
            Ok(LockedState {
                locked_block_hash: Some(hash),
                locked_round: Some(round),
            })
        }
        _ => Err(ValidatorSafetyError::InvalidLockState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use nova_consensus::round::LockedState;
    use nova_consensus::validator::ValidatorId;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// 唯一临时 journal 文件路径（无 tempfile 依赖；进程内计数保证并行测试唯一）。
    fn tmp_journal(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nova_safety_unit_{}_{}_{}",
            std::process::id(),
            n,
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("safety.journal")
    }

    fn identity(vid: [u8; 32]) -> SafetyIdentity {
        SafetyIdentity {
            network_id: NetworkId::Mainnet.as_u8(),
            chain_id: 1001,
            genesis_hash: [0x42; 32],
            validator_id: vid,
        }
    }

    fn key(h: u64, r: u64, vt: VoteType) -> VoteKey {
        VoteKey {
            height: h,
            round: r,
            vote_type: vt,
        }
    }

    /// 直接追加一条**编码正确**的 record（测试合成 corrupted / 冲突 journal 用）。
    fn append_raw(path: &Path, record_type: u8, body: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(&encode_record(record_type, body)).unwrap();
    }

    fn append_raw_bytes(path: &Path, bytes: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn s0_empty_journal_roundtrip() {
        let path = tmp_journal("s0");
        let id = identity([0x11; 32]);
        ValidatorSafetyStore::create(&path, id).unwrap();
        let store = ValidatorSafetyStore::at(&path, id);
        let recovered = store.recover().unwrap();
        assert!(recovered.ledger.is_empty());
        assert_eq!(recovered.locked_state, LockedState::new());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn s1_intent_signature_lock_roundtrip() {
        let path = tmp_journal("s1");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        store
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 7)
            .unwrap();
        store.commit_signature(&k, [0x55; 64]).unwrap();
        let lock = LockedState {
            locked_block_hash: Some([0xAA; 32]),
            locked_round: Some(0),
        };
        store.commit_lock(&lock).unwrap();

        // 重新打开（restart）⇒ 重建 ledger + lock
        let recovered = ValidatorSafetyStore::at(&path, id).recover().unwrap();
        let rec = recovered.ledger.lookup(&k).expect("恢复记录");
        assert_eq!(rec.target_block_hash, [0xAA; 32]);
        assert_eq!(rec.source_block_hash, [0u8; 32]);
        assert_eq!(rec.timestamp, 7);
        assert_eq!(rec.signature, Some([0x55; 64]));
        assert_eq!(recovered.locked_state, lock);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn s2_intent_only_recover_signature_absent() {
        // R2/R3 crash window：intent 已 durable、signature 缺席 ⇒ 恢复后 signature=None。
        let path = tmp_journal("s2");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(3, 4, VoteType::Precommit);
        store
            .commit_vote_intent(&k, [0xBB; 32], [0u8; 32], 9)
            .unwrap();
        let recovered = ValidatorSafetyStore::at(&path, id).recover().unwrap();
        let rec = recovered.ledger.lookup(&k).expect("intent 恢复");
        assert_eq!(rec.signature, None, "intent 已 durable、signature 缺席");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_12_corrupted_checksum_fails_closed() {
        let path = tmp_journal("rt12");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        store
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 0)
            .unwrap();
        // 翻转 record body 一个字节 ⇒ record checksum 失效
        let mut bytes = std::fs::read(&path).unwrap();
        let idx = SAFETY_HEADER_LEN + 1 + 4; // body[0]（key.height 首字节）
        bytes[idx] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::ChecksumMismatch);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_13_truncated_record_fails_closed_not_discarded() {
        let path = tmp_journal("rt13");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        store
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 0)
            .unwrap();
        // 追加半条 record（模拟 torn write）⇒ 恢复必须 FAIL（不得丢弃尾部继续）
        let mut partial = encode_record(REC_INTENT, &[0u8; 89]);
        partial.truncate(partial.len() / 2);
        append_raw_bytes(&path, &partial);
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::TruncatedRecord);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_14_unknown_version_fails_closed() {
        let path = tmp_journal("rt14");
        let id = identity([0x11; 32]);
        ValidatorSafetyStore::create(&path, id).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] = 0xFF; // version 篡改
        std::fs::write(&path, &bytes).unwrap();
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::UnknownVersion);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_15_wrong_genesis_hash_fails_closed() {
        let path = tmp_journal("rt15");
        let id_a = identity([0x11; 32]);
        let mut id_b = id_a;
        id_b.genesis_hash = [0x99; 32];
        ValidatorSafetyStore::create(&path, id_a).unwrap();
        let err = ValidatorSafetyStore::at(&path, id_b).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::IdentityMismatch);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_16_wrong_chain_id_fails_closed() {
        let path = tmp_journal("rt16");
        let id_a = identity([0x11; 32]);
        let mut id_b = id_a;
        id_b.chain_id = 999;
        ValidatorSafetyStore::create(&path, id_a).unwrap();
        let err = ValidatorSafetyStore::at(&path, id_b).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::IdentityMismatch);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_17_wrong_network_id_fails_closed() {
        let path = tmp_journal("rt17");
        let id_a = identity([0x11; 32]);
        let mut id_b = id_a;
        id_b.network_id = NetworkId::Testnet.as_u8();
        ValidatorSafetyStore::create(&path, id_a).unwrap();
        let err = ValidatorSafetyStore::at(&path, id_b).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::IdentityMismatch);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_18_wrong_validator_id_fails_closed() {
        let path = tmp_journal("rt18");
        let id_a = identity([0x11; 32]);
        let id_b = identity([0x22; 32]);
        ValidatorSafetyStore::create(&path, id_a).unwrap();
        let err = ValidatorSafetyStore::at(&path, id_b).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::IdentityMismatch);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_19_conflicting_vote_records_fails_closed() {
        // 同 VoteKey 不同 target（§31：corrupted/conflicting ⇒ FAIL CLOSED，不择一继续）
        let path = tmp_journal("rt19a");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        store
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 0)
            .unwrap();
        // 直接追加冲突 intent（绕过 actor guard；模拟 corrupted journal）
        append_raw(
            &path,
            REC_INTENT,
            &encode_intent_body(&k, [0xBB; 32], [0u8; 32], 0),
        );
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::ConflictingRecord);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());

        // 同 VoteKey 两个不同签名（冲突签名）
        let path2 = tmp_journal("rt19b");
        let store2 = ValidatorSafetyStore::create(&path2, id).unwrap();
        store2
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 0)
            .unwrap();
        store2.commit_signature(&k, [0x55; 64]).unwrap();
        append_raw(&path2, REC_SIGNED, &encode_signed_body(&k, [0x77; 64]));
        let err2 = ValidatorSafetyStore::at(&path2, id).recover().unwrap_err();
        assert_eq!(err2, ValidatorSafetyError::ConflictingRecord);
        let _ = std::fs::remove_dir_all(path2.parent().unwrap());
    }

    #[test]
    fn rt_24_corrupted_lock_state_fails_closed() {
        // 结构非法 lock（presence=0x02，非 0/1）＋ checksum 有效 ⇒ InvalidLockState
        let path = tmp_journal("rt24");
        let id = identity([0x11; 32]);
        ValidatorSafetyStore::create(&path, id).unwrap();
        append_raw(&path, REC_LOCK, &[0x02u8]);
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::InvalidLockState);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rt_24b_mixed_lock_state_rejected_on_commit() {
        // hash Some / round None（混合）⇒ commit_lock 拒绝（结构约束）
        let path = tmp_journal("rt24b");
        let id = identity([0x11; 32]);
        let store = ValidatorSafetyStore::create(&path, id).unwrap();
        let mixed = LockedState {
            locked_block_hash: Some([0xAA; 32]),
            locked_round: None,
        };
        let err = store.commit_lock(&mixed).unwrap_err();
        assert_eq!(err, ValidatorSafetyError::InvalidLockState);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn create_never_overwrites_existing_history() {
        let path = tmp_journal("exists");
        let id = identity([0x11; 32]);
        ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        ValidatorSafetyStore::at(&path, id)
            .commit_vote_intent(&k, [0xAA; 32], [0u8; 32], 0)
            .unwrap();
        // 再次 create ⇒ AlreadyExists（绝不覆写历史）
        let err = ValidatorSafetyStore::create(&path, id).unwrap_err();
        assert_eq!(err, ValidatorSafetyError::AlreadyExists);
        // 历史完好
        let rec = ValidatorSafetyStore::at(&path, id)
            .recover()
            .unwrap()
            .ledger
            .lookup(&k)
            .unwrap();
        assert_eq!(rec.target_block_hash, [0xAA; 32]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn signed_without_intent_is_missing_reservation() {
        let path = tmp_journal("nosig");
        let id = identity([0x11; 32]);
        ValidatorSafetyStore::create(&path, id).unwrap();
        let k = key(0, 0, VoteType::Prevote);
        append_raw(&path, REC_SIGNED, &encode_signed_body(&k, [0x55; 64]));
        let err = ValidatorSafetyStore::at(&path, id).recover().unwrap_err();
        assert_eq!(err, ValidatorSafetyError::MissingReservation);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// 测试内重复 encoder（独立实现，验证格式确定性；不依赖生产 encoder 内部状态）。
    fn encode_intent_body(k: &VoteKey, target: [u8; 32], source: [u8; 32], ts: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&k.height.to_le_bytes());
        body.extend_from_slice(&k.round.to_le_bytes());
        body.push(vote_type_u8(k.vote_type));
        body.extend_from_slice(&target);
        body.extend_from_slice(&source);
        body.extend_from_slice(&ts.to_le_bytes());
        body
    }

    fn encode_signed_body(k: &VoteKey, sig: [u8; 64]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&k.height.to_le_bytes());
        body.extend_from_slice(&k.round.to_le_bytes());
        body.push(vote_type_u8(k.vote_type));
        body.extend_from_slice(&sig);
        body
    }

    #[test]
    fn validator_id_new_uses_canonical_bytes() {
        let vid = ValidatorId::from_bytes([0x99; 32]);
        let si = SafetyIdentity::new(NetworkId::Devnet, 42, [0x77; 32], &vid);
        assert_eq!(si.network_id, 0x03);
        assert_eq!(si.chain_id, 42);
        assert_eq!(si.genesis_hash, [0x77; 32]);
        assert_eq!(si.validator_id, [0x99; 32]);
    }
}
