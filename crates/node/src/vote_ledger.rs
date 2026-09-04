//! Node-local 投票账本（STEP 10-15S；Double-Vote Protection）。
//!
//! # 职责（node-local；**非** consensus state）
//! - [`VoteLedger`]：记录「本 validator 对某个 `(height, round, vote_type)` 已签 / 已授权 的 target」，
//!   保证同一 [`VoteKey`] 至多一个 target —— 同 target 幂等复用既有签名，不同 target 拒绝（不签）。
//! - 每个 [`crate::validator::ValidatorActor`] 持有自己的 `VoteLedger`（validator isolation；
//!   无全局 ledger）。
//! - **当前为内存实现**（10-15S；Owner Decision 4）：为未来 10-15T durable 实现保留 API seam
//!   （`prepare` = 签名前持久化意图；`finalize_signature` = 签名后记录签名）。
//!
//! # 安全语义
//! - `prepare` **先于签名**（reserve-before-sign）；不同 target ⇒ [`VoteLedgerError::DoubleVote`]
//!   （拒绝、绝不签名）。
//! - `finalize_signature` 于签名之后记录；若失败则不产出无记录的签名（fail-safe）。
//! - 不持久化 private key；`VoteRecord.signature: Option<[u8;64]>` 仅为已签证据（Decision 1）。
//! - 本地 ledger 只记录「本 validator 自签」；remote vote 不写 ledger（remote 证据归 consensus）。

use std::cell::RefCell;
use std::collections::BTreeMap;

use nova_consensus::vote::VoteType;

/// 本地双投键：同一 `(height, round, vote_type)` 只允许一个 target。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteKey {
    pub height: u64,
    pub round: u64,
    pub vote_type: VoteType,
}

impl VoteKey {
    /// BTreeMap 内部有序键（VoteType 无 Ord ⇒ 映射为类型字节）。
    fn ordinal(&self) -> (u64, u64, u8) {
        let ty = match self.vote_type {
            VoteType::Prevote => 0x01,
            VoteType::Precommit => 0x02,
        };
        (self.height, self.round, ty)
    }
}

/// 一次本地投票记录（node-local；不含私钥）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRecord {
    pub target_block_hash: [u8; 32],
    pub source_block_hash: [u8; 32],
    pub timestamp: u64,
    /// 已签证据（Decision 1；可选 —— `prepare` 阶段为 `None`，`finalize_signature` 后为 `Some`）。
    pub signature: Option<[u8; 64]>,
}

/// `prepare` 结果：`New`（已 reserve，待签名）或 `Existing`（同 key 同 target 已存在）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotePrepare {
    New,
    Existing { record: VoteRecord },
}

/// VoteLedger 错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteLedgerError {
    /// 同一 `VoteKey` 已有不同 target（双投：拒绝，绝不签名）。
    DoubleVote {
        existing_target: [u8; 32],
        requested_target: [u8; 32],
    },
    /// 内部不变量：`finalize_signature` 时无对应 reservation（不应发生）。
    MissingReservation,
}

/// Node-local 投票账本（内存实现；10-15S —— 10-15T 由 `safety_store` durable journal 支撑恢复）。
///
/// 确定性：`BTreeMap`（键有序）。单线程同步：`RefCell` interior mutability 使
/// `produce_vote` 保持 `&self`，与既有 actor 借用结构一致。
#[derive(Debug, Clone)]
pub struct VoteLedger {
    entries: RefCell<BTreeMap<(u64, u64, u8), VoteRecord>>,
}

impl VoteLedger {
    /// 空账本。
    pub fn new() -> Self {
        Self {
            entries: RefCell::new(BTreeMap::new()),
        }
    }

    /// 签名前授权（reserve-before-sign）：
    /// - 同 key 无记录 ⇒ reserve（`Ok(New)`，signature=None，待签名）；
    /// - 同 key 同 target ⇒ `Ok(Existing)`（若已有 signature ⇒ 幂等复用，不重签）；
    /// - 同 key 不同 target ⇒ `Err(DoubleVote)`（不签名）。
    pub fn prepare(
        &self,
        key: &VoteKey,
        target_block_hash: [u8; 32],
        source_block_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<VotePrepare, VoteLedgerError> {
        let mut entries = self.entries.borrow_mut();
        match entries.get(&key.ordinal()) {
            None => {
                entries.insert(
                    key.ordinal(),
                    VoteRecord {
                        target_block_hash,
                        source_block_hash,
                        timestamp,
                        signature: None,
                    },
                );
                Ok(VotePrepare::New)
            }
            Some(record) if record.target_block_hash == target_block_hash => {
                Ok(VotePrepare::Existing {
                    record: record.clone(),
                })
            }
            Some(record) => Err(VoteLedgerError::DoubleVote {
                existing_target: record.target_block_hash,
                requested_target: target_block_hash,
            }),
        }
    }

    /// 签名后记录（幂等：已存在签名则 no-op）。
    pub fn finalize_signature(
        &self,
        key: &VoteKey,
        signature: [u8; 64],
    ) -> Result<(), VoteLedgerError> {
        let mut entries = self.entries.borrow_mut();
        let record = entries
            .get_mut(&key.ordinal())
            .ok_or(VoteLedgerError::MissingReservation)?;
        if record.signature.is_none() {
            record.signature = Some(signature);
        }
        Ok(())
    }

    /// 查询（只读；测试 / 审计）。
    pub fn lookup(&self, key: &VoteKey) -> Option<VoteRecord> {
        self.entries.borrow().get(&key.ordinal()).cloned()
    }

    /// 当前记录数（测试）。
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }
}

impl Default for VoteLedger {
    fn default() -> Self {
        Self::new()
    }
}
