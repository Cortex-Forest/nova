//! Canonical 输入整理：**排序 + 重排报告**（策略：`AUTO SORT + REPORT`，绝不静默）。
//!
//! - validator 排序键：`validator_id = SHA-256(consensus_public_key)`（委托
//!   [`nova_crypto::identity::validator_id`]，本 crate 不实现 SHA-256）。
//! - account 排序键：地址 35B payload raw bytes（`YazimaoAddressPayload::to_bytes`）。
//! - 排序**稳定**（`sort_by_key` 保持同键元素的相对次序）⇒ 输出可复现。
//! - 报告包含 `reordered=true/false` 与 **`original_index → canonical_index`** 全量映射。
//! - 额外提供 **地址 ↔ 公钥派生一致性检查**：`account_address` 必须等于
//!   `derive(consensus_public_key, UserAccount, network_id)`。该关系**不在**协议校验内
//!   （`validate_semantic` 只检查网络一致与唯一性），因此必须由 Builder 显式保证。

use core::fmt;
use nova_crypto::address::{AddressType, YazimaoAddress};
use nova_crypto::identity::{GenesisV1, validator_id};
use nova_crypto::signature::VerifyingKey;

use crate::hex;

/// 单条重排映射。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorderEntry {
    /// 输入中的原始下标。
    pub original_index: usize,
    /// canonical（排序后）下标。
    pub canonical_index: usize,
    /// 排序键（validator：`validator_id` hex；account：35B payload hex）。
    pub key_hex: String,
}

/// 重排报告（写入 `genesis_summary.json`，供人工核对）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorderReport {
    /// validator 列表是否发生重排。
    pub validators_reordered: bool,
    /// account 列表是否发生重排。
    pub accounts_reordered: bool,
    /// validator 映射（按 `canonical_index` 升序）。
    pub validators: Vec<ReorderEntry>,
    /// account 映射（按 `canonical_index` 升序）。
    pub accounts: Vec<ReorderEntry>,
}

impl ReorderReport {
    /// 任一列表发生重排。
    pub fn any_reordered(&self) -> bool {
        self.validators_reordered || self.accounts_reordered
    }
}

/// 派生一致性检查失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationError {
    /// 公钥不是合法 Ed25519 点（解析阶段应已拦截）。
    InvalidPublicKey { index: usize },
    /// 地址与公钥派生结果不一致。
    Mismatch {
        index: usize,
        expected: String,
        found: String,
    },
}

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey { index } => {
                write!(
                    f,
                    "validators[{index}].consensus_public_key: 非法 Ed25519 公钥"
                )
            }
            Self::Mismatch {
                index,
                expected,
                found,
            } => write!(
                f,
                "validators[{index}].account_address: 与 consensus_public_key 派生结果不一致（应为 {expected}，给定 {found}）"
            ),
        }
    }
}

impl std::error::Error for DerivationError {}

/// 地址 ↔ 公钥派生一致性检查（全部 validator）。
pub fn check_derivation_consistency(genesis: &GenesisV1) -> Result<(), DerivationError> {
    for (index, v) in genesis.initial_validator_set.iter().enumerate() {
        let Ok(vk) = VerifyingKey::from_bytes(&v.consensus_public_key) else {
            return Err(DerivationError::InvalidPublicKey { index });
        };
        let derived =
            YazimaoAddress::from_verifying_key(&vk, AddressType::UserAccount, genesis.network_id)
                .map_err(|_| DerivationError::InvalidPublicKey { index })?;
        if derived != v.account_address {
            return Err(DerivationError::Mismatch {
                index,
                expected: encode_or_placeholder(&derived),
                found: encode_or_placeholder(&v.account_address),
            });
        }
    }
    Ok(())
}

fn encode_or_placeholder(addr: &YazimaoAddress) -> String {
    addr.encode()
        .unwrap_or_else(|_| "<encode-error>".to_string())
}

/// 对两个列表执行 canonical 排序，并返回重排报告。
///
/// 若列表已是有序，则**不改变**其内容（保持输入等价）。
pub fn normalize_lists(genesis: &mut GenesisV1) -> ReorderReport {
    // ---- validators：按 validator_id 升序 ----
    let mut v_pairs: Vec<(usize, [u8; 32])> = genesis
        .initial_validator_set
        .iter()
        .enumerate()
        .map(|(i, v)| (i, validator_id(&v.consensus_public_key)))
        .collect();
    v_pairs.sort_by_key(|(_, key)| *key);
    let validators_reordered = v_pairs
        .iter()
        .enumerate()
        .any(|(canonical, (original, _))| canonical != *original);
    let validators: Vec<ReorderEntry> = v_pairs
        .iter()
        .enumerate()
        .map(|(canonical, (original, key))| ReorderEntry {
            original_index: *original,
            canonical_index: canonical,
            key_hex: hex(key),
        })
        .collect();
    if validators_reordered {
        genesis.initial_validator_set = v_pairs
            .iter()
            .map(|(original, _)| genesis.initial_validator_set[*original].clone())
            .collect();
    }

    // ---- accounts：按 35B payload raw bytes 升序 ----
    let mut a_pairs: Vec<(usize, [u8; 35])> = genesis
        .initial_accounts
        .iter()
        .enumerate()
        .map(|(i, a)| (i, a.address.payload().to_bytes()))
        .collect();
    a_pairs.sort_by_key(|(_, key)| *key);
    let accounts_reordered = a_pairs
        .iter()
        .enumerate()
        .any(|(canonical, (original, _))| canonical != *original);
    let accounts: Vec<ReorderEntry> = a_pairs
        .iter()
        .enumerate()
        .map(|(canonical, (original, key))| ReorderEntry {
            original_index: *original,
            canonical_index: canonical,
            key_hex: hex(key),
        })
        .collect();
    if accounts_reordered {
        genesis.initial_accounts = a_pairs
            .iter()
            .map(|(original, _)| genesis.initial_accounts[*original].clone())
            .collect();
    }

    ReorderReport {
        validators_reordered,
        accounts_reordered,
        validators,
        accounts,
    }
}
