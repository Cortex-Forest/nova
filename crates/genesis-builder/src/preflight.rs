//! Genesis 预检（preflight）：在生成 canonical bytes / hash **之前**给出**带路径**的人可读错误。
//!
//! 检查项（Owner 指定）：
//! 0. **ADR-0051 冻结经济政策**（FINAL FREEZE，不可变 cap）：`economics_parameters.total_supply`
//!    必须 `== 1,000,000,000`（固定供应），且 `fee_burn_bps` 必须 `== 0`（no-burn；ADR-0022
//!    burn 公式在本版本「参数禁用」）。二者均为**已冻结的协议决定**，非本工具新增政策。
//!    分配桶（Community/Public 500M · Ecosystem 200M · Team 120M · Foundation 80M ·
//!    Genesis Validator 100M）属**链外 provenance 分类**、不进 Genesis schema（ADR-0051 §11
//!    禁止 `allocation_type` 等字段）⇒ **不由本模块校验**（见 Owner data template GATE-3/GATE-8）。
//! 1. `total_supply` 与账户 liquid 合计一致（协议供应不变量）。
//! 2. **allocation 求和一致性**：每 validator 的 liquid 可覆盖其 `bonded_stake`，
//!    且 `Σ bonded_stake ≤ Σ validator liquid`（本模块**不**硬编码任何分配政策数值）。
//! 3. validator stake：账户必须存在、`bonded_stake > 0`、`bonded ≤ liquid`、`≥ min_validator_stake`。
//! 4. `commission_bps ≤ 10000`。
//! 5. 唯一性：account 地址、validator 账户地址、`consensus_public_key`、`validator_id`。
//! 6. **地址 ↔ 公钥派生一致性**（委托 [`crate::normalize::check_derivation_consistency`]）。
//! 7. 占位值（`TBD`/`PENDING`/空串）在**解析阶段**已被拒绝（此处不做字符串检查）。
//!
//! 最后**委托** [`nova_crypto::identity::validate_genesis`]：协议级规则（canonical 顺序 / 重复 /
//! 资源上限 / protocol·economics 边界）**不在本 crate 重新实现**，fail-closed。

use core::fmt;
use std::collections::HashMap;

use nova_crypto::address::YazimaoAddress;
use nova_crypto::identity::{GenesisError, GenesisV1, validate_genesis};

use crate::normalize::{DerivationError, check_derivation_consistency};

/// ADR-0051（FINAL FREEZE）固定的 Genesis 供应总量：`1,000,000,000 NOVA`。
///
/// 依据：ADR-0051 §4「MAX_SUPPLY = 1,000,000,000 NOVA（不可变 cap）」+「Genesis 时
/// Σ(initial_accounts.liquid_balance) == 1,000,000,000 NOVA」+ §5 Allocation 合计 100%。
/// 该数值是**已冻结的协议决定**（不是本工具新增的政策）⇒ 在本预检中显式执行；
/// 任何**小于**该值的 total_supply 同样违反「fixed supply」⇒ 一并拒绝。
pub const ADR_0051_FIXED_SUPPLY: u128 = 1_000_000_000;

/// 预检统计（写入 `genesis_summary.json`，供人工核对分配）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    /// validator 数量。
    pub validator_count: usize,
    /// account 数量。
    pub account_count: usize,
    /// `economics_params.total_supply`。
    pub total_supply: u128,
    /// `Σ accounts[].liquid_balance`（必须等于 `total_supply`）。
    pub account_liquid_sum: u128,
    /// validator 账户 liquid 合计。
    pub validator_liquid_sum: u128,
    /// 非 validator 账户 liquid 合计（= `account_liquid_sum - validator_liquid_sum`）。
    pub non_validator_liquid_sum: u128,
    /// `Σ validators[].bonded_stake`。
    pub validator_bonded_sum: u128,
}

/// 预检错误（结构化；禁止笼统单一错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    /// validator 列表为空（协议要求非空）。
    EmptyValidators,
    /// account 列表为空（协议要求非空）。
    EmptyAccounts,
    /// `chain_id == 0`。
    ZeroChainId,
    /// `genesis_timestamp == 0`。
    ZeroTimestamp,
    /// `total_supply == 0`。
    ZeroTotalSupply,
    /// `min_validator_stake == 0`。
    ZeroMinValidatorStake,
    /// `unbonding_period_seconds == 0`。
    ZeroUnbondingPeriod,
    /// `fee_burn_bps > 10000`。
    FeeBurnOutOfRange { value: u16 },
    /// `commission_bps > 10000`。
    CommissionOutOfRange { index: usize, value: u16 },
    /// `bonded_stake == 0`。
    ZeroStake { index: usize },
    /// validator 账户不在 `initial_accounts` 中。
    ValidatorAccountMissing { index: usize, address: String },
    /// `bonded_stake > 该账户 liquid`。
    StakeExceedsBalance {
        index: usize,
        bonded: u128,
        liquid: u128,
    },
    /// `bonded_stake < min_validator_stake`。
    StakeBelowMinimum {
        index: usize,
        bonded: u128,
        min: u128,
    },
    /// account 地址重复。
    DuplicateAccountAddress { index: usize, address: String },
    /// validator 账户地址重复。
    DuplicateValidatorAccount { index: usize, address: String },
    /// `consensus_public_key` 重复。
    DuplicateConsensusPublicKey { index: usize, key: String },
    /// `validator_id` 重复（派生自公钥）。
    DuplicateValidatorId { index: usize, id: String },
    /// `Σ bonded_stake > Σ validator liquid`。
    BondedSumExceedsValidatorLiquid { bonded: u128, liquid: u128 },
    /// `Σ accounts liquid != total_supply`。
    SupplyMismatch { computed: u128, declared: u128 },
    /// `total_supply != ADR_0051_FIXED_SUPPLY`（固定供应 = 不可变 cap；ADR-0051 §4/§5/§12）。
    FixedSupplyMismatch { declared: u128 },
    /// `fee_burn_bps != 0`（ADR-0051 §11：no-burn；ADR-0022 burn 公式参数禁用）。
    BurnPolicyViolation { value: u16 },
    /// 求和溢出 u128。
    SupplyOverflow,
    /// 地址 ↔ 公钥派生一致性失败。
    Derivation(DerivationError),
    /// 协议级校验失败（委托 `nova-crypto`）。
    Genesis(GenesisError),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValidators => {
                write!(f, "validators: 不得为空（协议要求至少 1 个 validator）")
            }
            Self::EmptyAccounts => write!(f, "accounts: 不得为空（协议要求至少 1 个 account）"),
            Self::ZeroChainId => write!(f, "chain_id: 必须 > 0（0 为「未配置」保留值）"),
            Self::ZeroTimestamp => write!(
                f,
                "genesis_timestamp: 必须 > 0（Builder 不会自动生成时间戳）"
            ),
            Self::ZeroTotalSupply => write!(f, "economics_params.total_supply: 必须 > 0"),
            Self::ZeroMinValidatorStake => {
                write!(f, "economics_params.min_validator_stake: 必须 > 0")
            }
            Self::ZeroUnbondingPeriod => {
                write!(f, "economics_params.unbonding_period_seconds: 必须 > 0")
            }
            Self::FeeBurnOutOfRange { value } => {
                write!(
                    f,
                    "economics_params.fee_burn_bps: 必须 ≤ 10000（实际 {value}）"
                )
            }
            Self::CommissionOutOfRange { index, value } => write!(
                f,
                "validators[{index}].commission_bps: 必须 ≤ 10000（实际 {value}）"
            ),
            Self::ZeroStake { index } => {
                write!(f, "validators[{index}].bonded_stake: 必须 > 0")
            }
            Self::ValidatorAccountMissing { index, address } => write!(
                f,
                "validators[{index}].account_address: 账户 {address} 不在 accounts 中"
            ),
            Self::StakeExceedsBalance {
                index,
                bonded,
                liquid,
            } => write!(
                f,
                "validators[{index}].bonded_stake: {bonded} 超过该账户 liquid {liquid}"
            ),
            Self::StakeBelowMinimum { index, bonded, min } => write!(
                f,
                "validators[{index}].bonded_stake: {bonded} 低于 min_validator_stake {min}"
            ),
            Self::DuplicateAccountAddress { index, address } => {
                write!(f, "accounts[{index}].address: 地址重复（{address}）")
            }
            Self::DuplicateValidatorAccount { index, address } => write!(
                f,
                "validators[{index}].account_address: 地址重复（{address}）"
            ),
            Self::DuplicateConsensusPublicKey { index, key } => write!(
                f,
                "validators[{index}].consensus_public_key: 公钥重复（{key}）"
            ),
            Self::DuplicateValidatorId { index, id } => {
                write!(f, "validators[{index}]: validator_id 重复（{id}）")
            }
            Self::BondedSumExceedsValidatorLiquid { bonded, liquid } => write!(
                f,
                "allocation: Σ bonded_stake ({bonded}) 超过 validator 账户 liquid 合计 ({liquid})"
            ),
            Self::SupplyMismatch { computed, declared } => write!(
                f,
                "supply: Σ accounts liquid ({computed}) != total_supply ({declared})"
            ),
            Self::FixedSupplyMismatch { declared } => write!(
                f,
                "economics_params.total_supply: 必须 == {ADR_0051_FIXED_SUPPLY}（ADR-0051 固定供应不可变 cap；\
                 实际 {declared}）"
            ),
            Self::BurnPolicyViolation { value } => write!(
                f,
                "economics_params.fee_burn_bps: 必须 == 0（ADR-0051 §11 no-burn；实际 {value}）"
            ),
            Self::SupplyOverflow => write!(f, "supply: Σ liquid 求和溢出 u128"),
            Self::Derivation(e) => write!(f, "{e}"),
            Self::Genesis(e) => write!(f, "协议校验失败：{e}"),
        }
    }
}

impl std::error::Error for PreflightError {}

/// 执行预检（不写任何文件、不改动输入）。
pub fn check_preconditions(genesis: &GenesisV1) -> Result<PreflightReport, PreflightError> {
    if genesis.initial_validator_set.is_empty() {
        return Err(PreflightError::EmptyValidators);
    }
    if genesis.initial_accounts.is_empty() {
        return Err(PreflightError::EmptyAccounts);
    }
    if genesis.chain_id == 0 {
        return Err(PreflightError::ZeroChainId);
    }
    if genesis.genesis_timestamp == 0 {
        return Err(PreflightError::ZeroTimestamp);
    }

    let ep = &genesis.economics_parameters;
    if ep.total_supply == 0 {
        return Err(PreflightError::ZeroTotalSupply);
    }
    if ep.min_validator_stake == 0 {
        return Err(PreflightError::ZeroMinValidatorStake);
    }
    if ep.unbonding_period_seconds == 0 {
        return Err(PreflightError::ZeroUnbondingPeriod);
    }
    if ep.fee_burn_bps > 10_000 {
        return Err(PreflightError::FeeBurnOutOfRange {
            value: ep.fee_burn_bps,
        });
    }
    // ADR-0051 §11（FINAL）：no-burn ⇒ `fee_burn_bps == 0`（ADR-0022 burn 公式参数禁用）。
    // 置于既有「≤ 10000 范围」检查**之后** ⇒ 既有越界用例的错误变体保持不变。
    if ep.fee_burn_bps != 0 {
        return Err(PreflightError::BurnPolicyViolation {
            value: ep.fee_burn_bps,
        });
    }

    // ---- account 表 + 重复检测 ----
    let mut balances: HashMap<YazimaoAddress, u128> =
        HashMap::with_capacity(genesis.initial_accounts.len());
    let mut account_liquid_sum: u128 = 0;
    for (index, a) in genesis.initial_accounts.iter().enumerate() {
        if balances.contains_key(&a.address) {
            return Err(PreflightError::DuplicateAccountAddress {
                index,
                address: display_address(&a.address),
            });
        }
        account_liquid_sum = account_liquid_sum
            .checked_add(a.liquid_balance)
            .ok_or(PreflightError::SupplyOverflow)?;
        balances.insert(a.address, a.liquid_balance);
    }
    if account_liquid_sum != ep.total_supply {
        return Err(PreflightError::SupplyMismatch {
            computed: account_liquid_sum,
            declared: ep.total_supply,
        });
    }

    // ---- validator 逐条 + 唯一性 ----
    let mut seen_validator_accounts: HashMap<YazimaoAddress, usize> = HashMap::new();
    let mut seen_pubkeys: HashMap<[u8; 32], usize> = HashMap::new();
    let mut seen_validator_ids: HashMap<[u8; 32], usize> = HashMap::new();
    let mut validator_liquid_sum: u128 = 0;
    let mut validator_bonded_sum: u128 = 0;

    for (index, v) in genesis.initial_validator_set.iter().enumerate() {
        if v.commission_bps > 10_000 {
            return Err(PreflightError::CommissionOutOfRange {
                index,
                value: v.commission_bps,
            });
        }
        if v.bonded_stake == 0 {
            return Err(PreflightError::ZeroStake { index });
        }
        let Some(liquid) = balances.get(&v.account_address).copied() else {
            return Err(PreflightError::ValidatorAccountMissing {
                index,
                address: display_address(&v.account_address),
            });
        };
        if v.bonded_stake > liquid {
            return Err(PreflightError::StakeExceedsBalance {
                index,
                bonded: v.bonded_stake,
                liquid,
            });
        }
        if v.bonded_stake < ep.min_validator_stake {
            return Err(PreflightError::StakeBelowMinimum {
                index,
                bonded: v.bonded_stake,
                min: ep.min_validator_stake,
            });
        }
        if seen_validator_accounts
            .insert(v.account_address, index)
            .is_some()
        {
            return Err(PreflightError::DuplicateValidatorAccount {
                index,
                address: display_address(&v.account_address),
            });
        }
        if seen_pubkeys.insert(v.consensus_public_key, index).is_some() {
            return Err(PreflightError::DuplicateConsensusPublicKey {
                index,
                key: crate::hex(&v.consensus_public_key),
            });
        }
        let vid = nova_crypto::identity::validator_id(&v.consensus_public_key);
        if seen_validator_ids.insert(vid, index).is_some() {
            return Err(PreflightError::DuplicateValidatorId {
                index,
                id: crate::hex(&vid),
            });
        }
        validator_liquid_sum = validator_liquid_sum
            .checked_add(liquid)
            .ok_or(PreflightError::SupplyOverflow)?;
        validator_bonded_sum = validator_bonded_sum
            .checked_add(v.bonded_stake)
            .ok_or(PreflightError::SupplyOverflow)?;
    }

    if validator_bonded_sum > validator_liquid_sum {
        return Err(PreflightError::BondedSumExceedsValidatorLiquid {
            bonded: validator_bonded_sum,
            liquid: validator_liquid_sum,
        });
    }

    // ---- ADR-0051 §4/§5（FINAL FREEZE）固定供应 = 不可变 cap ----
    // 位置：**结构性 / 逐条**错误（供应不变量、validator stake、唯一性）之后 ⇒ 既有以
    // 非 1e9 供应隔离「单一错误」的 fixture（如 `rejects_validator_account_missing_from_accounts`
    // 用 total_supply = 980_000_000 把缺失账户错误与其供应不变量分开）保持其**具体**错误变体；
    // 本检查只负责捕获「Σ liquid == total_supply（自洽）但 ≠ 1e9」这一在修复前**可以通过**
    // 并产出 genesis.bin 的、违反 ADR-0051 不可变 cap 的输入。仍在**写任何产物之前** fail-closed。
    if ep.total_supply != ADR_0051_FIXED_SUPPLY {
        return Err(PreflightError::FixedSupplyMismatch {
            declared: ep.total_supply,
        });
    }

    // ---- 地址 ↔ 公钥派生一致性（生产缺口，Builder 必须补上）----
    check_derivation_consistency(genesis).map_err(PreflightError::Derivation)?;

    // ---- 委托协议级校验（canonical 顺序 / 重复 / 上限 / protocol·economics 边界）----
    validate_genesis(genesis).map_err(PreflightError::Genesis)?;

    let non_validator_liquid_sum = account_liquid_sum
        .checked_sub(validator_liquid_sum)
        .ok_or(PreflightError::SupplyOverflow)?;

    Ok(PreflightReport {
        validator_count: genesis.initial_validator_set.len(),
        account_count: genesis.initial_accounts.len(),
        total_supply: ep.total_supply,
        account_liquid_sum,
        validator_liquid_sum,
        non_validator_liquid_sum,
        validator_bonded_sum,
    })
}

fn display_address(addr: &YazimaoAddress) -> String {
    addr.encode()
        .unwrap_or_else(|_| "<encode-error>".to_string())
}
