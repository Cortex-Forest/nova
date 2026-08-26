//! Nova Chain 链身份与 Genesis Canonical Encoding（STEP 6A）。
//!
//! 严格依据冻结规范：**ADR-0014**（Genesis Schema V1）、**ADR-0015**（Canonical Encoding）、
//! **ADR-0016**（Accounting Invariants）、`genesis-v1.md`（§9–§10）、
//! `crypto-serialization-v1.md`（§1–§8）。
//!
//! # 本模块实现（STEP 6A）
//! - `GenesisV1` 及嵌套类型（`ValidatorInit`/`AccountInit`/`ProtocolParamsV1`/`EconomicsParamsV1`）
//! - `canonical_genesis_bytes`：字节级确定性编码（LE、`u32` LE 长度、定长 bytes 无前缀）
//! - `compute_genesis_hash`：`SHA-256(canonical_genesis_bytes)`（hash-over-preimage）
//! - 编码期校验：资源上限、canonical 顺序、明显重复项（§7/§8/§19）
//!
//! # 职责边界
//! - 本阶段**不实现完整 `validate_genesis`**（结构/网络/链/时间戳/质押/供给等语义校验 → STEP 6B）。
//! - 地址在 canonical bytes 中为 **35B payload raw bytes**（非 bech32m 文本，ADR-0015）。
//! - `validator_id = SHA-256(consensus_public_key)` 为**派生值，不编码进 Genesis**。
//! - 禁止把 `genesis_hash` 放入被 hash 的内容（hash-over-preimage）。

use crate::address::{NetworkId, NovaAddress};
use crate::hash::protocol_hash;
use core::fmt;
use std::collections::HashSet;

/// V0.1 资源上限（ADR-0014 §Resource Limits）。
pub const MAX_VALIDATORS: usize = 10_000;
pub const MAX_ACCOUNTS: usize = 1_000_000;

/// Genesis 编码错误（与 ADR-0014 §14 一致；本阶段使用 canonical 相关分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisError {
    /// `network_id` 未注册（0x00 / 0x04+）。
    InvalidNetwork,
    /// `chain_id == 0`。
    InvalidChainId,
    /// `genesis_timestamp == 0`。
    InvalidTimestamp,
    /// validator 单条不合法（stake/commission/key/address）。
    InvalidValidator,
    /// validator 的 account_address / consensus_public_key / validator_id 重复。
    DuplicateValidator,
    /// account address 重复。
    DuplicateAccount,
    /// `bonded_stake > 对应 liquid`；或 validator 账户缺失。
    InvalidStake,
    /// account 不合法。
    InvalidInitialState,
    /// protocol 参数不合法/超上限。
    InvalidProtocolParams,
    /// economics 参数不合法。
    InvalidEconomicsParams,
    /// 列表非 canonical 顺序（validator/account）。
    NonCanonicalOrdering,
    /// 编码非 canonical（多余字节/非 minimal 前缀等）。
    NonCanonicalEncoding,
    /// computed != configured genesis_hash。
    GenesisHashMismatch,
    /// `total_supply != Σ liquid` 或溢出。
    SupplyInvariantViolation,
    /// 地址无效。
    InvalidAddress,
    /// 公钥无效。
    InvalidPublicKey,
    /// 编码长度溢出（u32 长度前缀等）。
    EncodingOverflow,
    /// 集合超上限。
    CollectionTooLarge,
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidNetwork => "invalid network_id",
            Self::InvalidChainId => "invalid chain_id",
            Self::InvalidTimestamp => "invalid genesis_timestamp",
            Self::InvalidValidator => "invalid validator",
            Self::DuplicateValidator => "duplicate validator",
            Self::DuplicateAccount => "duplicate account",
            Self::InvalidStake => "invalid stake accounting",
            Self::InvalidInitialState => "invalid initial state",
            Self::InvalidProtocolParams => "invalid protocol parameters",
            Self::InvalidEconomicsParams => "invalid economics parameters",
            Self::NonCanonicalOrdering => "non-canonical ordering",
            Self::NonCanonicalEncoding => "non-canonical encoding",
            Self::GenesisHashMismatch => "genesis hash mismatch",
            Self::SupplyInvariantViolation => "supply invariant violation",
            Self::InvalidAddress => "invalid address",
            Self::InvalidPublicKey => "invalid public key",
            Self::EncodingOverflow => "encoding overflow",
            Self::CollectionTooLarge => "collection too large",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for GenesisError {}

/// 初始验证者（ADR-0014 §2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInit {
    /// 验证者账户地址（bech32m；canonical 编码为 35B payload）。
    pub account_address: NovaAddress,
    /// Ed25519 公钥（压缩点 32B；不保存 `voting_power`）。
    pub consensus_public_key: [u8; 32],
    /// 从对应账户 liquid 划转的质押（u128 LE）。
    pub bonded_stake: u128,
    /// 佣金基点（≤ 10_000）。
    pub commission_bps: u16,
}

/// 初始账户（ADR-0014 §3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInit {
    /// 账户地址（bech32m；canonical 编码为 35B payload）。
    pub address: NovaAddress,
    /// Genesis 初始化前的 liquid balance（u128 LE）。
    pub liquid_balance: u128,
}

/// 协议参数（ADR-0014 §4；字段顺序固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolParamsV1 {
    pub max_tx_bytes: u32,
    pub max_block_bytes: u32,
    pub max_gas_per_block: u64,
    pub max_contract_code_bytes: u32,
    pub max_contract_storage_bytes: u32,
    pub epoch_length_blocks: u64,
    pub snapshot_interval_blocks: u64,
}

/// 经济参数（ADR-0014 §5；字段顺序固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicsParamsV1 {
    pub total_supply: u128,
    pub min_validator_stake: u128,
    pub unbonding_period_seconds: u64,
    pub fee_burn_bps: u16,
}

/// GenesisV1（ADR-0014 §1；字段顺序固定，禁止重排）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisV1 {
    pub network_id: NetworkId,
    pub chain_id: u64,
    pub genesis_timestamp: u64,
    pub initial_validator_set: Vec<ValidatorInit>,
    pub initial_accounts: Vec<AccountInit>,
    pub protocol_parameters: ProtocolParamsV1,
    pub economics_parameters: EconomicsParamsV1,
}

/// validator 派生身份：`validator_id = SHA-256(consensus_public_key)`（不存储）。
pub fn validator_id(consensus_public_key: &[u8; 32]) -> [u8; 32] {
    protocol_hash(consensus_public_key)
}

/// 地址的 35B canonical payload bytes（ADR-0015 §2）。
pub fn address_payload_bytes(addr: &NovaAddress) -> [u8; 35] {
    let p = addr.payload();
    let mut b = [0u8; 35];
    b[0] = p.address_version;
    b[1] = p.address_type as u8;
    b[2] = p.network_id as u8;
    b[3..35].copy_from_slice(&p.key_hash);
    b
}

/// 生成 canonical Genesis 字节（ADR-0015 §4）。
///
/// 编码前校验（§7/§8/§19）：资源上限 → 明显重复 → canonical 顺序；任一失败返回结构化错误，
/// **不自动排序 / 不静默接受重复**。
pub fn canonical_genesis_bytes(genesis: &GenesisV1) -> Result<Vec<u8>, GenesisError> {
    // ---- 1. 资源上限（§19）----
    let n_val = genesis.initial_validator_set.len();
    let n_acc = genesis.initial_accounts.len();
    if n_val > MAX_VALIDATORS {
        return Err(GenesisError::CollectionTooLarge);
    }
    if n_acc > MAX_ACCOUNTS {
        return Err(GenesisError::CollectionTooLarge);
    }

    // ---- 2. 明显重复检测（§8：不得静默接受）----
    let mut seen_acc = HashSet::new();
    let mut seen_pk = HashSet::new();
    let mut seen_vid = HashSet::new();
    for v in &genesis.initial_validator_set {
        if !seen_acc.insert(address_payload_bytes(&v.account_address)) {
            return Err(GenesisError::DuplicateValidator);
        }
        if !seen_pk.insert(v.consensus_public_key) {
            return Err(GenesisError::DuplicateValidator);
        }
        if !seen_vid.insert(validator_id(&v.consensus_public_key)) {
            return Err(GenesisError::DuplicateValidator);
        }
    }
    let mut seen_addr = HashSet::new();
    for a in &genesis.initial_accounts {
        if !seen_addr.insert(address_payload_bytes(&a.address)) {
            return Err(GenesisError::DuplicateAccount);
        }
    }

    // ---- 3. canonical 顺序（§7：非序 ⇒ REJECT，不自动排序）----
    for w in genesis.initial_validator_set.windows(2) {
        if validator_id(&w[0].consensus_public_key) >= validator_id(&w[1].consensus_public_key) {
            return Err(GenesisError::NonCanonicalOrdering);
        }
    }
    for w in genesis.initial_accounts.windows(2) {
        if address_payload_bytes(&w[0].address) >= address_payload_bytes(&w[1].address) {
            return Err(GenesisError::NonCanonicalOrdering);
        }
    }

    // ---- 4. 编码（ADR-0015 §4 字节布局）----
    let cap = 1 + 8 + 8 + 4 + n_val * 85 + 4 + n_acc * 51 + 40 + 42;
    let mut out = Vec::with_capacity(cap);
    out.push(genesis.network_id.as_u8());
    out.extend_from_slice(&genesis.chain_id.to_le_bytes());
    out.extend_from_slice(&genesis.genesis_timestamp.to_le_bytes());

    let count_val = u32::try_from(n_val).map_err(|_| GenesisError::EncodingOverflow)?;
    out.extend_from_slice(&count_val.to_le_bytes());
    for v in &genesis.initial_validator_set {
        out.extend_from_slice(&address_payload_bytes(&v.account_address));
        out.extend_from_slice(&v.consensus_public_key);
        out.extend_from_slice(&v.bonded_stake.to_le_bytes());
        out.extend_from_slice(&v.commission_bps.to_le_bytes());
    }

    let count_acc = u32::try_from(n_acc).map_err(|_| GenesisError::EncodingOverflow)?;
    out.extend_from_slice(&count_acc.to_le_bytes());
    for a in &genesis.initial_accounts {
        out.extend_from_slice(&address_payload_bytes(&a.address));
        out.extend_from_slice(&a.liquid_balance.to_le_bytes());
    }

    let pp = &genesis.protocol_parameters;
    out.extend_from_slice(&pp.max_tx_bytes.to_le_bytes());
    out.extend_from_slice(&pp.max_block_bytes.to_le_bytes());
    out.extend_from_slice(&pp.max_gas_per_block.to_le_bytes());
    out.extend_from_slice(&pp.max_contract_code_bytes.to_le_bytes());
    out.extend_from_slice(&pp.max_contract_storage_bytes.to_le_bytes());
    out.extend_from_slice(&pp.epoch_length_blocks.to_le_bytes());
    out.extend_from_slice(&pp.snapshot_interval_blocks.to_le_bytes());

    let ep = &genesis.economics_parameters;
    out.extend_from_slice(&ep.total_supply.to_le_bytes());
    out.extend_from_slice(&ep.min_validator_stake.to_le_bytes());
    out.extend_from_slice(&ep.unbonding_period_seconds.to_le_bytes());
    out.extend_from_slice(&ep.fee_burn_bps.to_le_bytes());

    debug_assert_eq!(out.len(), cap, "canonical length must match layout");
    Ok(out)
}

/// 计算 genesis_hash：`SHA-256(canonical_genesis_bytes)`（ADR-0015 §6）。
///
/// 禁止 hash(JSON) / hash(Debug) / hash(非 canonical)；`genesis_hash` 不进入被 hash 的内容。
pub fn compute_genesis_hash(genesis: &GenesisV1) -> Result<[u8; 32], GenesisError> {
    let bytes = canonical_genesis_bytes(genesis)?;
    Ok(protocol_hash(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{AddressType, NovaAddressPayload};

    fn addr(kh: [u8; 32], net: NetworkId) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: 1,
            address_type: AddressType::UserAccount,
            network_id: net,
            key_hash: kh,
        })
    }

    fn proto() -> ProtocolParamsV1 {
        ProtocolParamsV1 {
            max_tx_bytes: 65_536,
            max_block_bytes: 1_048_576,
            max_gas_per_block: 1_000_000_000,
            max_contract_code_bytes: 32_768,
            max_contract_storage_bytes: 1_048_576,
            epoch_length_blocks: 100,
            snapshot_interval_blocks: 1_000,
        }
    }

    fn econ() -> EconomicsParamsV1 {
        EconomicsParamsV1 {
            total_supply: 6_500_000,
            min_validator_stake: 100_000,
            unbonding_period_seconds: 1_209_600,
            fee_burn_bps: 500,
        }
    }

    /// 构造一个 canonical 有序的 sample Genesis（2 validator + 3 account，mainnet）。
    fn sample() -> GenesisV1 {
        // 用固定 key_hash 派生地址；validator 按 validator_id 升序。
        let mut vals = vec![
            ValidatorInit {
                account_address: addr([0x11; 32], NetworkId::Mainnet),
                consensus_public_key: [0x01; 32],
                bonded_stake: 1_000_000,
                commission_bps: 1000,
            },
            ValidatorInit {
                account_address: addr([0x22; 32], NetworkId::Mainnet),
                consensus_public_key: [0x02; 32],
                bonded_stake: 800_000,
                commission_bps: 800,
            },
        ];
        // 按 validator_id 排序（保证 canonical）
        vals.sort_by_key(|v| validator_id(&v.consensus_public_key));
        let mut accs = vec![
            AccountInit {
                address: addr([0x11; 32], NetworkId::Mainnet),
                liquid_balance: 2_000_000,
            },
            AccountInit {
                address: addr([0x22; 32], NetworkId::Mainnet),
                liquid_balance: 1_500_000,
            },
            AccountInit {
                address: addr([0x33; 32], NetworkId::Mainnet),
                liquid_balance: 3_000_000,
            },
        ];
        accs.sort_by_key(|a| address_payload_bytes(&a.address));
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 1_750_000_000,
            initial_validator_set: vals,
            initial_accounts: accs,
            protocol_parameters: proto(),
            economics_parameters: econ(),
        }
    }

    // ---- Canonical determinism / length ----
    #[test]
    fn canonical_encoding_deterministic() {
        let g = sample();
        let a = canonical_genesis_bytes(&g).unwrap();
        let b = canonical_genesis_bytes(&g).unwrap();
        assert_eq!(a, b);
        // 1+8+8+4 + 2×85 + 4 + 3×51 + 40 + 42 = 430
        assert_eq!(a.len(), 430, "canonical layout length");
    }

    #[test]
    fn hash_deterministic() {
        let g = sample();
        let h1 = compute_genesis_hash(&g).unwrap();
        let h2 = compute_genesis_hash(&g).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    // ---- Mutation changes hash (§14) ----
    #[test]
    fn mutation_changes_hash() {
        let base = sample();
        let h0 = compute_genesis_hash(&base).unwrap();
        let mut m;

        m = base.clone();
        m.network_id = NetworkId::Testnet;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "network_id");

        m = base.clone();
        m.chain_id = 9999;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "chain_id");

        m = base.clone();
        m.genesis_timestamp = 9_999_999_999;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "timestamp");

        m = base.clone();
        m.initial_validator_set[0].consensus_public_key[0] ^= 0xFF;
        // 换 key 后需重新排序（key 改变可能破坏顺序 → 先尝试，若 NonCanonicalOrdering 则重新排序）
        m.initial_validator_set
            .sort_by_key(|v| validator_id(&v.consensus_public_key));
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "validator key");

        m = base.clone();
        m.initial_validator_set[0].bonded_stake += 1;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "validator stake");

        m = base.clone();
        m.initial_validator_set[0].commission_bps = 999;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "commission");

        m = base.clone();
        m.initial_accounts[0].address = addr([0x44; 32], NetworkId::Mainnet);
        m.initial_accounts
            .sort_by_key(|a| address_payload_bytes(&a.address));
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "account");

        m = base.clone();
        m.initial_accounts[0].liquid_balance += 1;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "balance");

        m = base.clone();
        m.protocol_parameters.max_tx_bytes = 99_999;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "protocol param");

        m = base.clone();
        m.economics_parameters.fee_burn_bps = 1234;
        assert_ne!(compute_genesis_hash(&m).unwrap(), h0, "economics param");
    }

    // ---- Ordering rejection (§15) ----
    #[test]
    fn wrong_validator_order_rejected() {
        let g = sample();
        let mut wrong = g.clone();
        wrong.initial_validator_set.swap(0, 1);
        assert_eq!(
            canonical_genesis_bytes(&wrong),
            Err(GenesisError::NonCanonicalOrdering)
        );
    }

    #[test]
    fn wrong_account_order_rejected() {
        let g = sample();
        let mut wrong = g.clone();
        wrong.initial_accounts.swap(0, 1);
        assert_eq!(
            canonical_genesis_bytes(&wrong),
            Err(GenesisError::NonCanonicalOrdering)
        );
    }

    // ---- Duplicate detection (§8) ----
    #[test]
    fn duplicate_validator_pubkey_rejected() {
        let g = sample();
        let mut d = g.clone();
        d.initial_validator_set
            .push(d.initial_validator_set[0].clone());
        assert_eq!(
            canonical_genesis_bytes(&d),
            Err(GenesisError::DuplicateValidator)
        );
    }

    #[test]
    fn duplicate_account_rejected() {
        let g = sample();
        let mut d = g.clone();
        d.initial_accounts.push(d.initial_accounts[0].clone());
        assert_eq!(
            canonical_genesis_bytes(&d),
            Err(GenesisError::DuplicateAccount)
        );
    }

    // ---- Resource limits (§19) ----
    #[test]
    fn too_many_validators_rejected() {
        let g = sample();
        let mut big = g.clone();
        for i in 0..(MAX_VALIDATORS + 1 - 2) {
            let mut kh = [0u8; 32];
            kh[0..16].copy_from_slice(&(i as u128).to_le_bytes());
            let mut pk = [0u8; 32];
            pk[0..16].copy_from_slice(&((i + 1) as u128).to_le_bytes());
            big.initial_validator_set.push(ValidatorInit {
                account_address: addr(kh, NetworkId::Mainnet),
                consensus_public_key: pk,
                bonded_stake: 1,
                commission_bps: 0,
            });
        }
        big.initial_validator_set
            .sort_by_key(|v| validator_id(&v.consensus_public_key));
        assert_eq!(
            canonical_genesis_bytes(&big),
            Err(GenesisError::CollectionTooLarge)
        );
    }

    // ---- validator_id is derived, not encoded ----
    #[test]
    fn validator_id_derived() {
        let pk = [0x42; 32];
        assert_eq!(validator_id(&pk), protocol_hash(&pk));
        // 不同 key ⇒ 不同 id
        let mut pk2 = pk;
        pk2[0] ^= 1;
        assert_ne!(validator_id(&pk), validator_id(&pk2));
    }

    // ---- hash-over-preimage: genesis_hash not in content ----
    #[test]
    fn genesis_hash_not_in_preimage() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        let h = protocol_hash(&bytes);
        // canonical bytes 中不含 h（hash-over-preimage）
        let h_bytes = h.as_slice();
        assert!(
            !bytes.windows(h_bytes.len()).any(|w| w == h_bytes),
            "genesis_hash must not appear in preimage"
        );
    }
}
