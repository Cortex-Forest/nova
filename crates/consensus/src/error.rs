//! Consensus 错误（STEP 10 — ADR-0034 V-5 / ADR-0035 D-2）。
//!
//! 独立错误类型（nova-consensus 自有）；不混用 ExecutionError/NetworkError/StorageError。

use core::fmt;

/// 共识错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusError {
    /// V-5 ①：非 ValidatorSet 成员。
    UnknownValidator,
    /// V-5 ②：validator_id 与公钥派生不符。
    ValidatorIdentityMismatch,
    /// V-5 ⑤：签名验证失败。
    InvalidSignature,
    /// V-5：canonical 编码错误。
    InvalidVoteEncoding,
    /// ADR-0041 PR-5：ProposalRef canonical 编码错误（长度非 64B）。
    InvalidProposalEncoding,
    /// V-5：域分离错误。
    InvalidDomain,
    /// V-5：chain_id 不匹配。
    InvalidChainId,
    /// D-2：DAG 引用非法（parent 缺失 / height 不合法）。
    InvalidDagReference,
    /// D-2：block_hash 重复。
    DuplicateBlock,
    /// ADR-0050 §30：proposer 输入 ValidatorSet 为空 / total_weight == 0 ⇒ 无 proposer。
    EmptyValidatorSet,
    /// ADR-0050 §30：proposer 输入 ValidatorSet 非法（duplicate ValidatorId / 权重算术溢出）。
    InvalidValidatorSet,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownValidator => write!(f, "unknown validator"),
            Self::ValidatorIdentityMismatch => write!(f, "validator identity mismatch"),
            Self::InvalidSignature => write!(f, "invalid vote signature"),
            Self::InvalidVoteEncoding => write!(f, "invalid vote encoding"),
            Self::InvalidProposalEncoding => write!(f, "invalid proposal ref encoding"),
            Self::InvalidDomain => write!(f, "invalid signing domain"),
            Self::InvalidChainId => write!(f, "invalid chain_id"),
            Self::InvalidDagReference => write!(f, "invalid DAG reference"),
            Self::DuplicateBlock => write!(f, "duplicate block hash"),
            Self::EmptyValidatorSet => {
                write!(f, "empty validator set / zero total weight: no proposer")
            }
            Self::InvalidValidatorSet => write!(f, "invalid validator set for proposer selection"),
        }
    }
}

impl std::error::Error for ConsensusError {}
