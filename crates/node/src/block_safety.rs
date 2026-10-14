//! Signer-owned Block signing safety layer（D-5.2 / D-5.3 **B2-B**；Owner 授权 D-5.3.3）。
//!
//! # 职责
//! 为 **Block（proposer）签名**提供 signer-owned 的 durable 安全层：
//! 在同一 `Block Safety Slot` 内**只允许一个 signing target**，并提供幂等返回、
//! 冲突拒绝、崩溃恢复与 fail-closed 语义。
//!
//! # 冻结语义（不得在本模块内重新解释）
//!
//! ```text
//! Safety Namespace  = (network_id, chain_id, genesis_hash, validator_id)
//! Block Safety Slot = Safety Namespace + height
//! exact target      = SigningMessageHash
//!                     = SHA-256(build_signed_bytes(Ed25519, DomainId::Block, chain_id,
//!                                                  encode_block_header(header)))
//! ```
//!
//! - `round` 与 `proposer` **不是** slot 维度，**也不进入** signed bytes。
//! - `block_hash` **不是** signing target（且 signer 不持有 body，无法计算 `block_hash`）。
//! - 本模块**不产生** cryptographic round binding / cryptographic proposer binding，
//!   亦**不**要求 `B3`（无任何对 signed bytes / Block header / `block_hash` / consensus / genesis 的修改）。
//! - 本模块为 **signer-local safety policy**，不得被描述为密码学绑定。
//!
//! # F1 / F2 / F3 / F4
//!
//! | 规则 | 条件 | 行为 |
//! | --- | --- | --- |
//! | `F1` | 同 namespace + 同 height + **同 exact target** | **IDEMPOTENT RETURN**（`F1-B = SEMANTIC-EQUIVALENT`：**不要求**签名字节相等；**要求**签名对 exact target 验证通过） |
//! | `F2` | 同 namespace + 同 height + **不同 target** | **REJECT / CONFLICT**（不覆盖、不替换 target、不再签名） |
//! | `F3` | 不同 round + 同 height | **REJECT**（round 不构成新 slot；同 height 的新 round 仍是同一 slot） |
//! | `F4` | 不同 proposer + 同 height/round | **REJECT**（proposer 不构成新 slot；signer 拒绝为**非自身身份**的 proposer 出签） |
//!
//! # 崩溃次序（`C1 = FAIL-CLOSED`）
//!
//! ```text
//! record intent → fsync → sign → record signature → fsync
//! ```
//!
//! `sign → record` **不得**作为生产安全路径（本模块不接受该次序）。
//! 任何缺失 / 截断 / checksum 不符 / identity 不符 / 冲突 / 未恢复状态 ⇒ 拒绝签名。
//!
//! # Journal（signer-owned；`P-B = independent signer-owned block-safety.journal`）
//!
//! ```text
//! header (114B) = magic(8, "NOVABLKS") ‖ journal_version(1) ‖ network_id(1)
//!               ‖ chain_id u64LE(8) ‖ genesis_hash(32) ‖ validator_id(32)
//!               ‖ SHA-256(header[0..82])(32)
//!
//! record = record_type(1) ‖ body_len u32LE(4) ‖ body ‖ SHA-256(type‖len‖body)(32)
//!   INTENT (0x11) = height u64LE(8) ‖ target(32) ‖ payload_len u32LE(4) ‖ payload
//!   SIGNED (0x12) = height u64LE(8) ‖ target(32)          （仅记录“已签名”事实）
//! ```
//!
//! - **`S3 = intent + target`**：journal **不持久化 64 字节签名**（`D-5.2-D`）。
//!   `SIGNED` 记录的是**签名事实**（供恢复时判定状态），不是签名字节。
//! - INTENT 记录含 canonical payload ⇒ 可**确定性重建** exact target（恢复时逐条校验），
//!   满足 `D-5.2-D` 对 intent 的 MUST 要求。
//! - `requestId` **不持久化**：它只是请求追踪上下文，**不得**被当成安全身份。
//!
//! # 内部状态（最小集）
//!
//! ```text
//! EMPTY     : slot 未占用
//! INTENT    : slot 已被 target 占用，尚未记录签名事实
//! SIGNED    : slot 已被 target 占用，且已记录签名事实
//! CONFLICT  : 同 slot 出现不同 target（⇒ Err；不写入、不签名）
//! CORRUPTED : framing / checksum / 内容不一致（⇒ Err；fail-closed）
//! ```
//!
//! # No pruning（`P1`）
//!
//! 本模块**不实现** pruning / compaction / finality-based deletion / retention policy。
//! 历史 slot 永久保留；恢复时全部重放。
//!
//! # Scope（本次实现）
//!
//! 本模块**仅**实现 signer-owned Block safety；**未**接入生产出块调用点
//! （`block_builder::attach_proposer_signature` 的替换属独立集成步骤，需另行 Owner 授权）。

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nova_consensus::validator::ValidatorId;
use nova_crypto::address::NetworkId;
use nova_crypto::domain::{
    AlgorithmId, DomainId, SigningMessageHash, build_signed_bytes, hash_signing_message,
};
use nova_crypto::hash::protocol_hash;
use nova_crypto::signature::verify_message_hash;
use nova_runtime::BLOCK_VERSION;

use crate::signer::SigningCapability;

/// Block safety journal 格式版本（独立于 storage `DATABASE_VERSION` 与 `safety_store` 版本）。
pub const BLOCK_SAFETY_JOURNAL_VERSION: u8 = 1;

/// Header 固定长度（82B 前置 + 32B checksum）。
pub const BLOCK_SAFETY_HEADER_LEN: usize = 114;

const MAGIC: [u8; 8] = *b"NOVABLKS";

/// 记录类型：BlockSigningIntent（签名前持久化的槽位占用；不含签名字节）。
const REC_INTENT: u8 = 0x11;
/// 记录类型：BlockSigned（签名事实；对应已持久化的 intent）。
const REC_SIGNED: u8 = 0x12;

/// INTENT body 固定前缀：`height(8) ‖ target(32) ‖ payload_len(4)`。
const INTENT_PREFIX_LEN: usize = 44;
/// SIGNED body 定长：`height(8) ‖ target(32)`。
const SIGNED_BODY_LEN: usize = 40;

// --- Canonical BlockHeader 前缀偏移（ADR-0042 冻结布局；仅读取签名与槽位校验所需字段）---
/// `version` 偏移。
const HEADER_OFF_VERSION: usize = 0;
/// `chain_id`（u64 LE）偏移。
const HEADER_OFF_CHAIN_ID: usize = 1;
/// `height`（u64 LE）偏移。
const HEADER_OFF_HEIGHT: usize = 9;
/// `finality_reference` Option tag 偏移（v2：`version ‖ chain_id ‖ height ‖ round(8) ‖ parent(32)`）。
const HEADER_OFF_FINALITY_TAG: usize = 57;
/// `finality_reference = None` 时的 header 长度（v2）。
const HEADER_LEN_NO_REF: usize = 162;
/// `finality_reference = Some(..)` 时的 header 长度（v2）。
const HEADER_LEN_WITH_REF: usize = 194;

/// Block signing safety identity（= D-5.2.4 冻结的 Safety Namespace）。
///
/// 字段复用项目既有 canonical representation（`NetworkId::as_u8()` / `u64` LE /
/// raw `[u8;32]` / `ValidatorId::as_bytes()`）；本类型**不**持久化任何密钥材料。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSafetyIdentity {
    /// `NetworkId::as_u8()`（0x01/0x02/0x03）。
    pub network_id: u8,
    /// `chain_id`（u64 LE）。
    pub chain_id: u64,
    /// `genesis_hash`（链实例唯一锚）。
    pub genesis_hash: [u8; 32],
    /// `ValidatorId::as_bytes()`。
    pub validator_id: [u8; 32],
}

impl BlockSafetyIdentity {
    /// 从既有类型构造（`network_id` / `chain_id` / `genesis_hash` / `ValidatorId`）。
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

/// Block Safety Slot = Safety Namespace + height（`round` / `proposer` **不在**其中）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSafetySlot {
    /// Safety Namespace。
    pub identity: BlockSafetyIdentity,
    /// Block 高度（slot 的唯一变化维度）。
    pub height: u64,
}

impl BlockSafetySlot {
    /// 由 namespace + height 构造 slot。
    pub const fn new(identity: BlockSafetyIdentity, height: u64) -> Self {
        Self { identity, height }
    }
}

/// C3-B canonical Block signing request（signer 侧自行重建 exact target）。
///
/// 字段语义：
/// - `identity` / `declared_height` / `canonical_header_payload` 参与**槽位与 target 判定**；
/// - `declared_round` / `declared_proposer` 仅为**上下文**（不是 slot 维度，也不进入摘要）；
/// - `request_id` 仅为**请求追踪**（不是安全身份、不参与判定、不参与摘要）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSigningRequest {
    /// 请求声明的 Safety Namespace（必须与 journal identity 一致）。
    pub identity: BlockSafetyIdentity,
    /// 请求声明的 Block 高度（必须与 canonical header 内 `height` 一致）。
    pub declared_height: u64,
    /// `encode_block_header(header)` 的字节（signer 侧重建 signed bytes 的唯一输入）。
    pub canonical_header_payload: Vec<u8>,
    /// 请求上下文：声明的 round（**不是** slot 维度；`F3` 依赖该事实）。
    pub declared_round: u64,
    /// 请求上下文：声明的 proposer（**不是** slot 维度；必须是 signer 自身身份）。
    pub declared_proposer: ValidatorId,
    /// 请求追踪标识（**不得**作为安全身份或幂等判据）。
    pub request_id: u64,
}

impl BlockSigningRequest {
    /// 构造请求（`declared_round` / `request_id` 默认 0；`declared_proposer` = 自身身份）。
    pub fn new(
        identity: BlockSafetyIdentity,
        declared_height: u64,
        canonical_header_payload: Vec<u8>,
        declared_proposer: ValidatorId,
    ) -> Self {
        Self {
            identity,
            declared_height,
            canonical_header_payload,
            declared_round: 0,
            declared_proposer,
            request_id: 0,
        }
    }
}

/// 授权+签名结果（两种情况返回的签名**必定**对 exact target 验证通过）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSigningOutcome {
    /// 该 slot 首次占用：已写入 INTENT 与 SIGNED 记录。
    New {
        /// exact signing target。
        target: [u8; 32],
        /// 对 exact target 的签名（已验证）。
        signature: [u8; 64],
    },
    /// 同 slot 同 exact target 的重复请求（`F1` 幂等；语义等价，不要求字节相等）。
    Idempotent {
        /// exact signing target。
        target: [u8; 32],
        /// 对同一 exact target 重新产生的签名（已验证）。
        signature: [u8; 64],
    },
}

impl BlockSigningOutcome {
    /// exact signing target。
    pub fn target(&self) -> [u8; 32] {
        match self {
            Self::New { target, .. } | Self::Idempotent { target, .. } => *target,
        }
    }

    /// 签名（64B）。
    pub fn signature(&self) -> [u8; 64] {
        match self {
            Self::New { signature, .. } | Self::Idempotent { signature, .. } => *signature,
        }
    }

    /// 是否为幂等命中（`F1`）。
    pub fn is_idempotent(&self) -> bool {
        matches!(self, Self::Idempotent { .. })
    }
}

/// Block safety 错误（signer-local；**全部** fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSafetyError {
    /// 文件 I/O 失败（打开 / 追加 / fsync / 读取）——fail closed（不签名）。
    Io,
    /// Header magic 不符。
    UnknownMagic,
    /// `journal_version` 未知（≠ [`BLOCK_SAFETY_JOURNAL_VERSION`]）。
    UnknownVersion,
    /// Header 损坏（长度不足 / checksum 不符）。
    CorruptHeader,
    /// Header identity（四字段）与期望不符（fail-closed）。
    IdentityMismatch,
    /// 记录 framing / 内容非法（未知类型 / 长度非法 / intent 与 payload 不一致）。
    CorruptRecord,
    /// 单条 record checksum 不符。
    ChecksumMismatch,
    /// 记录不完整（含最后一条截断）——**不丢弃继续**（fail-closed）。
    TruncatedRecord,
    /// `SIGNED` 记录没有对应的已持久化 `INTENT`。
    MissingReservation,
    /// 同 slot 已有不同 target（`F2` / `F3` / `F4` 统一冲突出口；**绝不签名**）。
    ConflictingTarget {
        /// 已记录的 target（**保持权威**）。
        existing_target: [u8; 32],
        /// 本次请求的 target（被拒绝）。
        requested_target: [u8; 32],
    },
    /// `create` 时文件已存在（禁止覆写既有安全历史）。
    AlreadyExists,
    /// journal 尚未 `recover()`（状态未知 ⇒ 拒绝签名）。
    NotRecovered,
    /// 请求声明的 namespace 与 journal identity 不一致。
    RequestIdentityMismatch,
    /// 签名者公钥派生的 `ValidatorId` 与 journal identity 不一致。
    SignerIdentityMismatch,
    /// 请求声明的 proposer 不是 signer 自身身份（`F4`）。
    ProposerIdentityMismatch,
    /// canonical payload 内 `chain_id` 与 namespace 不一致。
    ChainIdMismatch,
    /// canonical payload 内 `height` 与 `declared_height` 不一致。
    DeclaredHeightMismatch,
    /// canonical payload 不是合法的 canonical BlockHeader（长度 / version / tag 非法）。
    PayloadInvalid,
    /// 无法重建 exact target（canonical 构造失败）。
    TargetReconstruction,
    /// 底层签名失败。
    SigningFailed,
    /// 产生的签名未通过自检（fail-closed；**不得**把未验证签名交给调用方）。
    SignatureInvalid,
}

impl core::fmt::Display for BlockSafetyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => write!(f, "block safety journal I/O failure"),
            Self::UnknownMagic => write!(f, "block safety journal magic mismatch"),
            Self::UnknownVersion => write!(f, "unknown block safety journal version"),
            Self::CorruptHeader => write!(f, "corrupt block safety journal header"),
            Self::IdentityMismatch => write!(f, "block safety identity mismatch"),
            Self::CorruptRecord => write!(f, "corrupt block safety record"),
            Self::ChecksumMismatch => write!(f, "block safety record checksum mismatch"),
            Self::TruncatedRecord => write!(f, "truncated block safety record"),
            Self::MissingReservation => write!(f, "signed record without persisted intent"),
            Self::ConflictingTarget { .. } => write!(f, "block safety slot target conflict"),
            Self::AlreadyExists => write!(f, "block safety journal already exists"),
            Self::NotRecovered => write!(f, "block safety journal not recovered"),
            Self::RequestIdentityMismatch => write!(f, "request namespace mismatch"),
            Self::SignerIdentityMismatch => write!(f, "signer identity mismatch"),
            Self::ProposerIdentityMismatch => write!(f, "declared proposer is not own identity"),
            Self::ChainIdMismatch => write!(f, "payload chain_id mismatch"),
            Self::DeclaredHeightMismatch => write!(f, "declared height mismatch"),
            Self::PayloadInvalid => write!(f, "invalid canonical block header payload"),
            Self::TargetReconstruction => write!(f, "cannot reconstruct signing target"),
            Self::SigningFailed => write!(f, "signer failed"),
            Self::SignatureInvalid => write!(f, "produced signature failed self-check"),
        }
    }
}

impl std::error::Error for BlockSafetyError {}

/// 单 slot 的 in-memory 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotState {
    target: [u8; 32],
    signed: bool,
}

/// Signer-owned Block signing safety journal（`P-B`；独立文件；fail-closed）。
///
/// - 单 identity 单文件（隔离由 identity header 强制；不匹配即拒绝）。
/// - 每次写入打开-追加-fsync-关闭（返回前已 durable）。
/// - **必须**先 `recover()` 才能签名（[`BlockSafetyError::NotRecovered`]）。
#[derive(Debug)]
pub struct BlockSafetyJournal {
    path: PathBuf,
    identity: BlockSafetyIdentity,
    slots: RefCell<BTreeMap<u64, SlotState>>,
    recovered: Cell<bool>,
}

impl BlockSafetyJournal {
    /// 新建 journal（写 header）。文件已存在 ⇒ [`BlockSafetyError::AlreadyExists`]（禁止覆写历史）。
    pub fn create(path: &Path, identity: BlockSafetyIdentity) -> Result<Self, BlockSafetyError> {
        if path.exists() {
            return Err(BlockSafetyError::AlreadyExists);
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|_| BlockSafetyError::Io)?;
        }
        let header = build_header(identity);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| BlockSafetyError::Io)?;
        file.write_all(&header).map_err(|_| BlockSafetyError::Io)?;
        file.sync_all().map_err(|_| BlockSafetyError::Io)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            slots: RefCell::new(BTreeMap::new()),
            recovered: Cell::new(true),
        })
    }

    /// 绑定既有 journal（**不**读取文件；须随后调用 [`Self::recover`]）。
    pub fn at(path: &Path, identity: BlockSafetyIdentity) -> Self {
        Self {
            path: path.to_path_buf(),
            identity,
            slots: RefCell::new(BTreeMap::new()),
            recovered: Cell::new(false),
        }
    }

    /// journal path。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 本 journal 的 Safety Namespace。
    pub fn identity(&self) -> &BlockSafetyIdentity {
        &self.identity
    }

    /// 是否已完成严格恢复。
    pub fn is_recovered(&self) -> bool {
        self.recovered.get()
    }

    /// 严格恢复（FAIL CLOSED）：header 校验 → 逐条重放 → 重建 slot 状态。
    ///
    /// 任何异常（含最后一条截断 / checksum 不符 / identity 不符 / 冲突）⇒ `Err`；
    /// **绝不丢弃损坏尾部继续**，**绝不覆盖既有 target**。
    pub fn recover(&self) -> Result<(), BlockSafetyError> {
        let bytes = fs::read(&self.path).map_err(|_| BlockSafetyError::Io)?;
        parse_header(&bytes, self.identity)?;
        let mut slots: BTreeMap<u64, SlotState> = BTreeMap::new();
        let mut offset = BLOCK_SAFETY_HEADER_LEN;
        while offset < bytes.len() {
            if bytes.len() - offset < 5 {
                return Err(BlockSafetyError::TruncatedRecord);
            }
            let record_type = bytes[offset];
            let body_len = u32::from_le_bytes(
                bytes[offset + 1..offset + 5]
                    .try_into()
                    .map_err(|_| BlockSafetyError::TruncatedRecord)?,
            ) as usize;
            let body_start = offset + 5;
            let body_end = body_start
                .checked_add(body_len)
                .ok_or(BlockSafetyError::TruncatedRecord)?;
            let checksum_end = body_end
                .checked_add(32)
                .ok_or(BlockSafetyError::TruncatedRecord)?;
            if checksum_end > bytes.len() {
                return Err(BlockSafetyError::TruncatedRecord);
            }
            let expected = protocol_hash(&bytes[offset..body_end]);
            if bytes[body_end..checksum_end] != expected {
                return Err(BlockSafetyError::ChecksumMismatch);
            }
            let body = &bytes[body_start..body_end];
            match record_type {
                REC_INTENT => {
                    let (height, target, payload) = decode_intent_body(body)?;
                    let rebuilt = reconstruct_target(self.identity.chain_id, payload)?;
                    if *rebuilt.as_bytes() != target {
                        return Err(BlockSafetyError::CorruptRecord);
                    }
                    validate_payload_prefix(payload, self.identity.chain_id, height)?;
                    match slots.get(&height) {
                        None => {
                            slots.insert(
                                height,
                                SlotState {
                                    target,
                                    signed: false,
                                },
                            );
                        }
                        Some(existing) if existing.target == target => {}
                        Some(existing) => {
                            return Err(BlockSafetyError::ConflictingTarget {
                                existing_target: existing.target,
                                requested_target: target,
                            });
                        }
                    }
                }
                REC_SIGNED => {
                    let (height, target) = decode_signed_body(body)?;
                    match slots.get_mut(&height) {
                        Some(state) if state.target == target => state.signed = true,
                        Some(_) | None => return Err(BlockSafetyError::MissingReservation),
                    }
                }
                _ => return Err(BlockSafetyError::CorruptRecord),
            }
            offset = checksum_end;
        }
        *self.slots.borrow_mut() = slots;
        self.recovered.set(true);
        Ok(())
    }

    /// 已记录的 target（须在 `recover()` 之后读取；未占用 ⇒ `None`）。
    pub fn recorded_target(&self, height: u64) -> Option<[u8; 32]> {
        self.slots.borrow().get(&height).map(|s| s.target)
    }

    /// 是否已记录签名事实（`None` = slot 未占用）。
    pub fn is_signed(&self, height: u64) -> Option<bool> {
        self.slots.borrow().get(&height).map(|s| s.signed)
    }

    /// 已占用的 slot 数（**无 pruning**：仅增长）。
    pub fn occupied_slots(&self) -> usize {
        self.slots.borrow().len()
    }

    /// 授权并对 exact target 签名（`C1` 次序：intent → fsync → sign → signature → fsync）。
    ///
    /// 流程（任一前置校验失败 ⇒ fail-closed，**不签名**）：
    /// 1. journal 已恢复；2. 请求 namespace == journal identity；
    /// 3. 声明 proposer == 自身 `ValidatorId`（`F4`）；4. signer 公钥派生身份 == journal identity；
    /// 5. canonical payload 合法且 `chain_id` / `height` 一致；6. 重建 exact target；
    /// 7. slot 判定（`F1` 幂等 / `F2` 冲突）。
    pub fn authorize_and_sign(
        &self,
        signer: &dyn SigningCapability,
        request: &BlockSigningRequest,
    ) -> Result<BlockSigningOutcome, BlockSafetyError> {
        if !self.recovered.get() {
            return Err(BlockSafetyError::NotRecovered);
        }
        if request.identity != self.identity {
            return Err(BlockSafetyError::RequestIdentityMismatch);
        }
        if request.declared_proposer.as_bytes() != &self.identity.validator_id {
            return Err(BlockSafetyError::ProposerIdentityMismatch);
        }
        let derived = ValidatorId::from_consensus_public_key(&signer.public_key().to_bytes());
        if derived.as_bytes() != &self.identity.validator_id {
            return Err(BlockSafetyError::SignerIdentityMismatch);
        }
        let payload = request.canonical_header_payload.as_slice();
        validate_payload_prefix(payload, self.identity.chain_id, request.declared_height)?;
        let target = reconstruct_target(self.identity.chain_id, payload)?;
        let target_bytes = *target.as_bytes();

        let existing = self.slots.borrow().get(&request.declared_height).copied();
        match existing {
            Some(state) if state.target != target_bytes => {
                // F2 / F3 / F4：同 slot 不同 target ⇒ 拒绝（不覆盖、不签名）。
                // 本 `match` 即函数尾表达式 ⇒ 该臂直接产出 `Err(..)`（与其余臂的 `Ok(..)` 同型；
                // 无早退 `return` 亦无任何行为差异 —— clippy::needless_return 最小修复）。
                Err(BlockSafetyError::ConflictingTarget {
                    existing_target: state.target,
                    requested_target: target_bytes,
                })
            }
            Some(state) => {
                // F1：同 slot 同 exact target ⇒ 幂等返回（语义等价；不要求字节相等）
                let signature = self.sign_and_verify(signer, &target)?;
                if !state.signed {
                    self.append_record(
                        REC_SIGNED,
                        &encode_signed_body(request.declared_height, &target_bytes),
                    )?;
                    if let Some(entry) = self.slots.borrow_mut().get_mut(&request.declared_height) {
                        entry.signed = true;
                    }
                }
                Ok(BlockSigningOutcome::Idempotent {
                    target: target_bytes,
                    signature,
                })
            }
            None => {
                // 新 slot：**先** durable 记录 intent（fsync），**再**签名
                self.append_record(
                    REC_INTENT,
                    &encode_intent_body(request.declared_height, &target_bytes, payload),
                )?;
                self.slots.borrow_mut().insert(
                    request.declared_height,
                    SlotState {
                        target: target_bytes,
                        signed: false,
                    },
                );
                let signature = self.sign_and_verify(signer, &target)?;
                self.append_record(
                    REC_SIGNED,
                    &encode_signed_body(request.declared_height, &target_bytes),
                )?;
                if let Some(entry) = self.slots.borrow_mut().get_mut(&request.declared_height) {
                    entry.signed = true;
                }
                Ok(BlockSigningOutcome::New {
                    target: target_bytes,
                    signature,
                })
            }
        }
    }

    /// 签名 + **自检**（`signature validity` 为 `F1-B` 的必要条件；失败 ⇒ fail-closed）。
    fn sign_and_verify(
        &self,
        signer: &dyn SigningCapability,
        target: &SigningMessageHash,
    ) -> Result<[u8; 64], BlockSafetyError> {
        let signature = signer
            .sign(target)
            .map_err(|_| BlockSafetyError::SigningFailed)?;
        verify_message_hash(&signer.public_key(), target, &signature)
            .map_err(|_| BlockSafetyError::SignatureInvalid)?;
        Ok(signature.to_bytes())
    }

    /// 追加一条 record（打开 → 追加 → fsync → 关闭；返回前已 durable）。
    ///
    /// Journal **必须已存在**（不 `create`）：文件缺失 ⇒ `Err(Io)` fail-closed。
    fn append_record(&self, record_type: u8, body: &[u8]) -> Result<(), BlockSafetyError> {
        let record = encode_record(record_type, body);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| BlockSafetyError::Io)?;
        file.write_all(&record).map_err(|_| BlockSafetyError::Io)?;
        file.sync_all().map_err(|_| BlockSafetyError::Io)
    }
}

// =========================================================================
// Encoding / decoding（全定长 + SHA-256 checksum；格式见模块 doc）
// =========================================================================

fn build_header(identity: BlockSafetyIdentity) -> Vec<u8> {
    let mut header = Vec::with_capacity(BLOCK_SAFETY_HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(BLOCK_SAFETY_JOURNAL_VERSION);
    header.push(identity.network_id);
    header.extend_from_slice(&identity.chain_id.to_le_bytes());
    header.extend_from_slice(&identity.genesis_hash);
    header.extend_from_slice(&identity.validator_id);
    let checksum = protocol_hash(&header);
    header.extend_from_slice(&checksum);
    debug_assert_eq!(header.len(), BLOCK_SAFETY_HEADER_LEN);
    header
}

/// Header 校验顺序（magic → version → identity → checksum），以产出精确错误变体。
fn parse_header(bytes: &[u8], expected: BlockSafetyIdentity) -> Result<(), BlockSafetyError> {
    if bytes.len() < BLOCK_SAFETY_HEADER_LEN {
        return Err(BlockSafetyError::CorruptHeader);
    }
    if bytes[0..8] != MAGIC {
        return Err(BlockSafetyError::UnknownMagic);
    }
    if bytes[8] != BLOCK_SAFETY_JOURNAL_VERSION {
        return Err(BlockSafetyError::UnknownVersion);
    }
    let network_id = bytes[9];
    let chain_id = u64::from_le_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| BlockSafetyError::CorruptHeader)?,
    );
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&bytes[18..50]);
    let mut validator_id = [0u8; 32];
    validator_id.copy_from_slice(&bytes[50..82]);
    let expected_checksum = protocol_hash(&bytes[0..82]);
    if bytes[82..114] != expected_checksum {
        return Err(BlockSafetyError::CorruptHeader);
    }
    if network_id != expected.network_id
        || chain_id != expected.chain_id
        || genesis_hash != expected.genesis_hash
        || validator_id != expected.validator_id
    {
        return Err(BlockSafetyError::IdentityMismatch);
    }
    Ok(())
}

fn encode_record(record_type: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(1 + 4 + body.len() + 32);
    out.push(record_type);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    let checksum = protocol_hash(&out);
    out.extend_from_slice(&checksum);
    out
}

fn encode_intent_body(height: u64, target: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(INTENT_PREFIX_LEN + payload.len());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(target);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_intent_body(body: &[u8]) -> Result<(u64, [u8; 32], &[u8]), BlockSafetyError> {
    if body.len() < INTENT_PREFIX_LEN {
        return Err(BlockSafetyError::CorruptRecord);
    }
    let height = u64::from_le_bytes(
        body[0..8]
            .try_into()
            .map_err(|_| BlockSafetyError::CorruptRecord)?,
    );
    let mut target = [0u8; 32];
    target.copy_from_slice(&body[8..40]);
    let payload_len = u32::from_le_bytes(
        body[40..44]
            .try_into()
            .map_err(|_| BlockSafetyError::CorruptRecord)?,
    ) as usize;
    let payload = &body[INTENT_PREFIX_LEN..];
    if payload.len() != payload_len {
        return Err(BlockSafetyError::CorruptRecord);
    }
    Ok((height, target, payload))
}

fn encode_signed_body(height: u64, target: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNED_BODY_LEN);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(target);
    out
}

fn decode_signed_body(body: &[u8]) -> Result<(u64, [u8; 32]), BlockSafetyError> {
    if body.len() != SIGNED_BODY_LEN {
        return Err(BlockSafetyError::CorruptRecord);
    }
    let height = u64::from_le_bytes(
        body[0..8]
            .try_into()
            .map_err(|_| BlockSafetyError::CorruptRecord)?,
    );
    let mut target = [0u8; 32];
    target.copy_from_slice(&body[8..40]);
    Ok((height, target))
}

/// 由 canonical payload 重建 exact target（`C3-B`；不修改任何被签字节）。
fn reconstruct_target(
    chain_id: u64,
    payload: &[u8],
) -> Result<SigningMessageHash, BlockSafetyError> {
    let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, payload)
        .map_err(|_| BlockSafetyError::TargetReconstruction)?;
    Ok(hash_signing_message(&signed))
}

/// 校验 canonical payload 冻结前缀：长度 / `version` / `finality` tag / `chain_id` / `height`。
///
/// 说明：仅读取**冻结布局**中的前三个字段（ADR-0042），不复制完整 header 解码逻辑；
/// 任何不符合冻结布局的输入 ⇒ [`BlockSafetyError::PayloadInvalid`]（fail-closed）。
fn validate_payload_prefix(
    payload: &[u8],
    expected_chain_id: u64,
    expected_height: u64,
) -> Result<(), BlockSafetyError> {
    if payload.len() != HEADER_LEN_NO_REF && payload.len() != HEADER_LEN_WITH_REF {
        return Err(BlockSafetyError::PayloadInvalid);
    }
    if payload[HEADER_OFF_VERSION] != BLOCK_VERSION {
        return Err(BlockSafetyError::PayloadInvalid);
    }
    let tag = payload[HEADER_OFF_FINALITY_TAG];
    match (tag, payload.len()) {
        (0, HEADER_LEN_NO_REF) | (1, HEADER_LEN_WITH_REF) => {}
        _ => return Err(BlockSafetyError::PayloadInvalid),
    }
    let chain_id = u64::from_le_bytes(
        payload[HEADER_OFF_CHAIN_ID..HEADER_OFF_CHAIN_ID + 8]
            .try_into()
            .map_err(|_| BlockSafetyError::PayloadInvalid)?,
    );
    if chain_id != expected_chain_id {
        return Err(BlockSafetyError::ChainIdMismatch);
    }
    let height = u64::from_le_bytes(
        payload[HEADER_OFF_HEIGHT..HEADER_OFF_HEIGHT + 8]
            .try_into()
            .map_err(|_| BlockSafetyError::PayloadInvalid)?,
    );
    if height != expected_height {
        return Err(BlockSafetyError::DeclaredHeightMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::{Signature, VerifyingKey};
    use nova_runtime::{Block, BlockBody, BlockHeader, block_hash, encode_block_header};

    use crate::signer::SoftwareSigner;

    const CHAIN_ID: u64 = 1001;

    fn tmp_journal(n: u32, tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nova_blocksafety_unit_{}_{}_{}",
            std::process::id(),
            n,
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("block-safety.journal")
    }

    fn identity_with(vid: [u8; 32]) -> BlockSafetyIdentity {
        BlockSafetyIdentity {
            network_id: NetworkId::Mainnet.as_u8(),
            chain_id: CHAIN_ID,
            genesis_hash: [0x42; 32],
            validator_id: vid,
        }
    }

    fn header(height: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            version: BLOCK_VERSION,
            chain_id: CHAIN_ID,
            height,
            round: 0,
            parent_hash: [0x11; 32],
            finality_reference: None,
            transaction_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_hash: [0x44; 32],
            timestamp,
        }
    }

    fn payload(height: u64, timestamp: u64) -> Vec<u8> {
        encode_block_header(&header(height, timestamp))
    }

    fn signer_and_identity() -> (SoftwareSigner, BlockSafetyIdentity) {
        let kp = KeyPair::generate().unwrap();
        let vk: VerifyingKey = *kp.verifying_key();
        let vid = ValidatorId::from_consensus_public_key(&vk.to_bytes());
        (SoftwareSigner::new(kp), identity_with(*vid.as_bytes()))
    }

    fn request(id: BlockSafetyIdentity, height: u64, ts: u64) -> BlockSigningRequest {
        BlockSigningRequest::new(
            id,
            height,
            payload(height, ts),
            ValidatorId::from_bytes(id.validator_id),
        )
    }

    /// 直接追加一条**编码正确**的 record（测试合成 corrupted / 冲突 journal 用）。
    fn append_raw(path: &Path, record_type: u8, body: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(&encode_record(record_type, body)).unwrap();
        f.sync_all().unwrap();
    }

    fn append_raw_bytes(path: &Path, bytes: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    fn target_of(height: u64, ts: u64) -> [u8; 32] {
        *reconstruct_target(CHAIN_ID, &payload(height, ts))
            .unwrap()
            .as_bytes()
    }

    // ------------------------------------------------------------------
    // Header / codec
    // ------------------------------------------------------------------
    #[test]
    fn b0_header_layout_and_offsets() {
        let (_, id) = signer_and_identity();
        let h = build_header(id);
        assert_eq!(h.len(), BLOCK_SAFETY_HEADER_LEN);
        assert_eq!(&h[0..8], b"NOVABLKS");
        assert_eq!(h[8], BLOCK_SAFETY_JOURNAL_VERSION);
        assert_eq!(h[9], id.network_id);
        assert_eq!(parse_header(&h, id), Ok(()));
    }

    #[test]
    fn b1_payload_prefix_reads_frozen_offsets() {
        let p = payload(7, 1);
        assert_eq!(p.len(), HEADER_LEN_NO_REF);
        assert_eq!(validate_payload_prefix(&p, CHAIN_ID, 7), Ok(()));
        assert_eq!(
            validate_payload_prefix(&p, CHAIN_ID, 8),
            Err(BlockSafetyError::DeclaredHeightMismatch)
        );
        assert_eq!(
            validate_payload_prefix(&p, CHAIN_ID + 1, 7),
            Err(BlockSafetyError::ChainIdMismatch)
        );
    }

    #[test]
    fn b2_payload_invalid_shapes_are_rejected() {
        let mut bad = payload(1, 0);
        bad.push(0x00); // trailing byte
        assert_eq!(
            validate_payload_prefix(&bad, CHAIN_ID, 1),
            Err(BlockSafetyError::PayloadInvalid)
        );
        let mut bad_version = payload(1, 0);
        bad_version[HEADER_OFF_VERSION] = 0xFF;
        assert_eq!(
            validate_payload_prefix(&bad_version, CHAIN_ID, 1),
            Err(BlockSafetyError::PayloadInvalid)
        );
        let mut bad_tag = payload(1, 0);
        bad_tag[HEADER_OFF_FINALITY_TAG] = 0x02;
        assert_eq!(
            validate_payload_prefix(&bad_tag, CHAIN_ID, 1),
            Err(BlockSafetyError::PayloadInvalid)
        );
        let short = vec![0u8; 10];
        assert_eq!(
            validate_payload_prefix(&short, CHAIN_ID, 1),
            Err(BlockSafetyError::PayloadInvalid)
        );
    }

    #[test]
    fn b3_target_is_not_block_hash() {
        let h = header(5, 9);
        let target = *reconstruct_target(CHAIN_ID, &encode_block_header(&h))
            .unwrap()
            .as_bytes();
        let block = Block {
            header: h,
            body: BlockBody { txs: Vec::new() },
            proposer_signature: [0u8; 64],
        };
        let bh = block_hash(&block).unwrap();
        assert_ne!(target, bh, "block_hash 不得是 signer safety target");
    }

    // ------------------------------------------------------------------
    // F1（含 semantic equivalence）
    // ------------------------------------------------------------------
    #[test]
    fn f1_same_request_is_idempotent_and_signature_verifies() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(1, "f1");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let r = request(id, 10, 1);

        let first = j.authorize_and_sign(&signer, &r).unwrap();
        assert!(!first.is_idempotent());
        let second = j.authorize_and_sign(&signer, &r).unwrap();
        assert!(second.is_idempotent());
        assert_eq!(first.target(), second.target());

        // F1-B：**不**断言签名字节相等；只断言“对 exact target 验证通过”。
        let target = SigningMessageHash::from_bytes(first.target());
        let vk = signer.public_key();
        assert_eq!(
            verify_message_hash(
                &vk,
                &target,
                &Signature::from_bytes(&first.signature()).unwrap()
            ),
            Ok(())
        );
        assert_eq!(
            verify_message_hash(
                &vk,
                &target,
                &Signature::from_bytes(&second.signature()).unwrap()
            ),
            Ok(())
        );
        assert_eq!(j.recorded_target(10), Some(first.target()));
        assert_eq!(j.is_signed(10), Some(true));
        assert_eq!(j.occupied_slots(), 1);
    }

    #[test]
    fn f1_idempotent_retry_does_not_create_second_slot_or_new_target() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(2, "f1b");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let r = request(id, 11, 3);
        let a = j.authorize_and_sign(&signer, &r).unwrap();
        for _ in 0..3 {
            let again = j.authorize_and_sign(&signer, &r).unwrap();
            assert!(again.is_idempotent());
            assert_eq!(again.target(), a.target());
        }
        assert_eq!(j.occupied_slots(), 1);
        assert_eq!(j.recorded_target(11), Some(a.target()));
    }

    // ------------------------------------------------------------------
    // F2
    // ------------------------------------------------------------------
    #[test]
    fn f2_different_target_same_height_conflicts_and_old_target_authoritative() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(3, "f2");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let a = j.authorize_and_sign(&signer, &request(id, 20, 1)).unwrap();
        // 同 height、不同 timestamp ⇒ 不同 target
        let other = j.authorize_and_sign(&signer, &request(id, 20, 2));
        assert_eq!(
            other,
            Err(BlockSafetyError::ConflictingTarget {
                existing_target: a.target(),
                requested_target: target_of(20, 2),
            })
        );
        assert_eq!(
            j.recorded_target(20),
            Some(a.target()),
            "旧 target 保持权威（不覆盖）"
        );
        assert_eq!(j.occupied_slots(), 1);
        // 冲突后同 target 仍可幂等
        let again = j.authorize_and_sign(&signer, &request(id, 20, 1)).unwrap();
        assert!(again.is_idempotent());
        assert_eq!(again.target(), a.target());
    }

    // ------------------------------------------------------------------
    // F3 / F4
    // ------------------------------------------------------------------
    #[test]
    fn f3_different_round_same_height_is_rejected() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(4, "f3");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let a = j.authorize_and_sign(&signer, &request(id, 30, 1)).unwrap();

        // 同 height、round=1、不同 target ⇒ 仍属同一 slot ⇒ REJECT
        let mut later_round = request(id, 30, 2);
        later_round.declared_round = 1;
        assert!(matches!(
            j.authorize_and_sign(&signer, &later_round),
            Err(BlockSafetyError::ConflictingTarget { .. })
        ));
        assert_eq!(j.occupied_slots(), 1);
        assert_eq!(j.recorded_target(30), Some(a.target()));

        // 同 height、round=1、同 target ⇒ F1 幂等（round 不构成新 slot）
        let mut same_target = request(id, 30, 1);
        same_target.declared_round = 1;
        let out = j.authorize_and_sign(&signer, &same_target).unwrap();
        assert!(out.is_idempotent());
        assert_eq!(out.target(), a.target());
    }

    #[test]
    fn f4_different_proposer_same_height_round_is_rejected() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(5, "f4");
        let j = BlockSafetyJournal::create(&path, id).unwrap();

        // 不同 proposer（非自身身份）⇒ REJECT（不创建新 slot、不签名）
        let mut foreign = request(id, 40, 1);
        foreign.declared_proposer = ValidatorId::from_bytes([0xEE; 32]);
        assert_eq!(
            j.authorize_and_sign(&signer, &foreign),
            Err(BlockSafetyError::ProposerIdentityMismatch)
        );
        assert_eq!(j.occupied_slots(), 0, "不得创建 slot");

        // 自身身份首次可签
        let a = j.authorize_and_sign(&signer, &request(id, 40, 1)).unwrap();
        assert!(!a.is_idempotent());

        // 同 height/round、不同 proposer、不同 target ⇒ 仍 REJECT
        let mut other = request(id, 40, 2);
        other.declared_proposer = ValidatorId::from_bytes([0xEE; 32]);
        assert_eq!(
            j.authorize_and_sign(&signer, &other),
            Err(BlockSafetyError::ProposerIdentityMismatch)
        );
        assert_eq!(j.recorded_target(40), Some(a.target()));
        assert_eq!(j.occupied_slots(), 1);
    }

    // ------------------------------------------------------------------
    // Safety Namespace isolation
    // ------------------------------------------------------------------
    #[test]
    fn ns_identity_mismatch_fails_closed_on_recover() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(6, "ns1");
        BlockSafetyJournal::create(&path, id).unwrap();

        let mut wrong_network = id;
        wrong_network.network_id = NetworkId::Testnet.as_u8();
        assert_eq!(
            BlockSafetyJournal::at(&path, wrong_network).recover(),
            Err(BlockSafetyError::IdentityMismatch)
        );

        let mut wrong_chain = id;
        wrong_chain.chain_id = CHAIN_ID + 7;
        assert_eq!(
            BlockSafetyJournal::at(&path, wrong_chain).recover(),
            Err(BlockSafetyError::IdentityMismatch)
        );

        let mut wrong_genesis = id;
        wrong_genesis.genesis_hash = [0x99; 32];
        assert_eq!(
            BlockSafetyJournal::at(&path, wrong_genesis).recover(),
            Err(BlockSafetyError::IdentityMismatch)
        );

        let mut wrong_validator = id;
        wrong_validator.validator_id = [0x77; 32];
        assert_eq!(
            BlockSafetyJournal::at(&path, wrong_validator).recover(),
            Err(BlockSafetyError::IdentityMismatch)
        );

        // 正确 identity 可恢复
        assert_eq!(BlockSafetyJournal::at(&path, id).recover(), Ok(()));
    }

    #[test]
    fn ns_request_namespace_mismatch_is_rejected_without_state_change() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(7, "ns2");
        let j = BlockSafetyJournal::create(&path, id).unwrap();

        let mut other_chain = id;
        other_chain.chain_id = CHAIN_ID + 1;
        let r = request(other_chain, 50, 1);
        assert_eq!(
            j.authorize_and_sign(&signer, &r),
            Err(BlockSafetyError::RequestIdentityMismatch)
        );
        let mut other_genesis = id;
        other_genesis.genesis_hash = [0xAA; 32];
        assert_eq!(
            j.authorize_and_sign(&signer, &request(other_genesis, 50, 1)),
            Err(BlockSafetyError::RequestIdentityMismatch)
        );
        let mut other_validator = id;
        other_validator.validator_id = [0xBB; 32];
        assert_eq!(
            j.authorize_and_sign(&signer, &request(other_validator, 50, 1)),
            Err(BlockSafetyError::RequestIdentityMismatch)
        );
        // 另一 network 的 journal 需用另一文件（identity 不符即拒绝）
        assert_eq!(j.occupied_slots(), 0);
        assert_eq!(j.recorded_target(50), None);
    }

    #[test]
    fn ns_payload_chain_id_must_match_namespace() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(8, "ns3");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let mut h = header(60, 1);
        h.chain_id = CHAIN_ID + 5;
        let r = BlockSigningRequest::new(
            id,
            60,
            encode_block_header(&h),
            ValidatorId::from_bytes(id.validator_id),
        );
        assert_eq!(
            j.authorize_and_sign(&signer, &r),
            Err(BlockSafetyError::ChainIdMismatch)
        );
        assert_eq!(j.occupied_slots(), 0);
    }

    #[test]
    fn ns_wrong_signer_identity_is_rejected() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(9, "ns4");
        let j = BlockSafetyJournal::create(&path, id).unwrap();

        // journal identity 声称另一个 validator，但传入的 signer 是自身 ⇒ SignerIdentityMismatch
        let kp = KeyPair::generate().unwrap();
        let vk = *kp.verifying_key();
        let other_vid = ValidatorId::from_consensus_public_key(&vk.to_bytes());
        let mut foreign_identity = id;
        foreign_identity.validator_id = *other_vid.as_bytes();
        let j2_path = tmp_journal(10, "ns5");
        let j2 = BlockSafetyJournal::create(&j2_path, foreign_identity).unwrap();
        assert_eq!(
            j2.authorize_and_sign(&signer, &request(foreign_identity, 1, 1)),
            Err(BlockSafetyError::SignerIdentityMismatch)
        );
        assert_eq!(j2.occupied_slots(), 0);

        // 正确 signer 可签
        let mine = request(id, 2, 1);
        assert!(j.authorize_and_sign(&signer, &mine).is_ok());
    }

    // ------------------------------------------------------------------
    // Crash recovery（intent / signature 次序）
    // ------------------------------------------------------------------
    #[test]
    fn crash_before_intent_fsync_slot_is_free() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(11, "crash1");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        // 无任何记录 ⇒ 视为未占用 ⇒ 首次签名允许
        assert_eq!(j.recorded_target(70), None);
        let out = j.authorize_and_sign(&signer, &request(id, 70, 1)).unwrap();
        assert!(!out.is_idempotent());
    }

    #[test]
    fn crash_after_intent_before_sign_same_target_allowed_other_target_conflict() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(12, "crash2");
        let _j = BlockSafetyJournal::create(&path, id).unwrap();
        let p = payload(80, 1);
        let target = target_of(80, 1);
        // 模拟“intent 已 fsync、尚未签名”
        append_raw(&path, REC_INTENT, &encode_intent_body(80, &target, &p));

        let j2 = BlockSafetyJournal::at(&path, id);
        assert!(!j2.is_recovered());
        assert_eq!(
            j2.authorize_and_sign(&signer, &request(id, 80, 1)),
            Err(BlockSafetyError::NotRecovered)
        );
        j2.recover().unwrap();
        assert_eq!(j2.is_signed(80), Some(false));

        // 同 target ⇒ 允许（补写 SIGNED）
        let out = j2.authorize_and_sign(&signer, &request(id, 80, 1)).unwrap();
        assert!(out.is_idempotent());
        assert_eq!(out.target(), target);
        assert_eq!(j2.is_signed(80), Some(true));

        // 不同 target ⇒ CONFLICT（不覆盖、不签名）
        assert!(matches!(
            j2.authorize_and_sign(&signer, &request(id, 80, 2)),
            Err(BlockSafetyError::ConflictingTarget { .. })
        ));
        assert_eq!(j2.recorded_target(80), Some(target));
    }

    #[test]
    fn crash_after_sign_before_signature_record_is_recoverable_same_target() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(13, "crash3");
        let j = BlockSafetyJournal::create(&path, id).unwrap();
        let a = j.authorize_and_sign(&signer, &request(id, 90, 1)).unwrap();

        // 重开并恢复（等价于“签后崩溃 ⇒ 重启”）
        let j2 = BlockSafetyJournal::at(&path, id);
        j2.recover().unwrap();
        assert_eq!(j2.recorded_target(90), Some(a.target()));
        assert_eq!(j2.is_signed(90), Some(true));
        let again = j2.authorize_and_sign(&signer, &request(id, 90, 1)).unwrap();
        assert!(again.is_idempotent());
        assert_eq!(again.target(), a.target());
    }

    #[test]
    fn restart_restores_state_f1_idempotent_and_f2_conflict() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(14, "restart");
        let a = {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.authorize_and_sign(&signer, &request(id, 100, 1)).unwrap()
        };
        let j = BlockSafetyJournal::at(&path, id);
        j.recover().unwrap();
        let same = j.authorize_and_sign(&signer, &request(id, 100, 1)).unwrap();
        assert!(same.is_idempotent());
        assert_eq!(same.target(), a.target());
        assert!(matches!(
            j.authorize_and_sign(&signer, &request(id, 100, 2)),
            Err(BlockSafetyError::ConflictingTarget { .. })
        ));
    }

    #[test]
    fn truncated_tail_and_bad_checksum_fail_closed() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(15, "corrupt1");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.recover().unwrap();
        }
        let target = target_of(110, 1);
        let full = encode_record(
            REC_INTENT,
            &encode_intent_body(110, &target, &payload(110, 1)),
        );
        append_raw_bytes(&path, &full[..full.len() - 3]); // 截断尾部
        assert_eq!(
            BlockSafetyJournal::at(&path, id).recover(),
            Err(BlockSafetyError::TruncatedRecord)
        );

        let path2 = tmp_journal(16, "corrupt2");
        {
            let j = BlockSafetyJournal::create(&path2, id).unwrap();
            j.recover().unwrap();
        }
        let mut bad = full.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF; // 破坏 checksum
        append_raw_bytes(&path2, &bad);
        assert_eq!(
            BlockSafetyJournal::at(&path2, id).recover(),
            Err(BlockSafetyError::ChecksumMismatch)
        );
    }

    #[test]
    fn conflicting_target_in_journal_fails_closed_on_recovery() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(17, "corrupt3");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.recover().unwrap();
        }
        append_raw(
            &path,
            REC_INTENT,
            &encode_intent_body(120, &target_of(120, 1), &payload(120, 1)),
        );
        append_raw(
            &path,
            REC_INTENT,
            &encode_intent_body(120, &target_of(120, 2), &payload(120, 2)),
        );
        assert!(matches!(
            BlockSafetyJournal::at(&path, id).recover(),
            Err(BlockSafetyError::ConflictingTarget { .. })
        ));
    }

    #[test]
    fn signed_record_without_intent_fails_closed_on_recovery() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(18, "corrupt4");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.recover().unwrap();
        }
        append_raw(
            &path,
            REC_SIGNED,
            &encode_signed_body(130, &target_of(130, 1)),
        );
        assert_eq!(
            BlockSafetyJournal::at(&path, id).recover(),
            Err(BlockSafetyError::MissingReservation)
        );
    }

    #[test]
    fn intent_with_inconsistent_target_fails_closed_on_recovery() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(19, "corrupt5");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.recover().unwrap();
        }
        // 记录中的 target 与 payload 重建结果不一致 ⇒ CORRUPTED
        append_raw(
            &path,
            REC_INTENT,
            &encode_intent_body(140, &[0xAB; 32], &payload(140, 1)),
        );
        assert_eq!(
            BlockSafetyJournal::at(&path, id).recover(),
            Err(BlockSafetyError::CorruptRecord)
        );
    }

    #[test]
    fn unknown_record_type_and_missing_journal_fail_closed() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(20, "corrupt6");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            j.recover().unwrap();
        }
        append_raw(&path, 0x7F, &[0x00; 4]);
        assert_eq!(
            BlockSafetyJournal::at(&path, id).recover(),
            Err(BlockSafetyError::CorruptRecord)
        );

        let missing = tmp_journal(21, "missing").join("absent.journal");
        assert_eq!(
            BlockSafetyJournal::at(&missing, id).recover(),
            Err(BlockSafetyError::Io)
        );
    }

    #[test]
    fn create_never_overwrites_existing_journal() {
        let (_, id) = signer_and_identity();
        let path = tmp_journal(22, "exists");
        BlockSafetyJournal::create(&path, id).unwrap();
        assert!(matches!(
            BlockSafetyJournal::create(&path, id),
            Err(BlockSafetyError::AlreadyExists)
        ));
    }

    // ------------------------------------------------------------------
    // No pruning
    // ------------------------------------------------------------------
    #[test]
    fn no_pruning_history_is_retained_across_recovery() {
        let (signer, id) = signer_and_identity();
        let path = tmp_journal(23, "nopruning");
        {
            let j = BlockSafetyJournal::create(&path, id).unwrap();
            for h in 1..=25u64 {
                j.authorize_and_sign(&signer, &request(id, h, h)).unwrap();
            }
            assert_eq!(j.occupied_slots(), 25);
        }
        let j = BlockSafetyJournal::at(&path, id);
        j.recover().unwrap();
        assert_eq!(j.occupied_slots(), 25, "历史 slot 全部保留（无 pruning）");
        for h in 1..=25u64 {
            assert_eq!(j.recorded_target(h), Some(target_of(h, h)));
            assert_eq!(j.is_signed(h), Some(true));
        }
    }
}
