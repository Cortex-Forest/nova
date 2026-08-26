//! Nova Chain 链身份与 Genesis Canonical Encoding / Validation（STEP 6A + 6B）。
//!
//! 严格依据冻结规范：**ADR-0014**（Genesis Schema V1）、**ADR-0015**（Canonical Encoding）、
//! **ADR-0016**（Accounting Invariants）、`genesis-v1.md`（§9–§13）、
//! `crypto-serialization-v1.md`（§1–§8）。
//!
//! # 本模块实现
//! - **STEP 6A**：`GenesisV1` 及嵌套类型、`canonical_genesis_bytes`（字节级确定性编码）、
//!   `compute_genesis_hash`（SHA-256(canonical)）；编码期校验（上限/顺序/重复）。
//! - **STEP 6B**：`decode_genesis_bytes`（字节解析 + structural + canonical）、
//!   `validate_genesis`（semantic 校验 + hash + `ChainIdentity`）、
//!   `validate_genesis_with_expected`（configured hash 对比）。
//!
//! # Decode Pipeline（用户评审 §1）
//! ```text
//! raw bytes → decode → structural validation → canonical validation
//!           → semantic validation → genesis hash → ChainIdentity
//! ```
//!
//! # 职责边界
//! - 地址在 canonical bytes 中为 **35B payload raw bytes**（非 bech32m 文本，ADR-0015）。
//! - `validator_id = SHA-256(consensus_public_key)` 为**派生值，不编码进 Genesis**。
//! - 禁止把 `genesis_hash` 放入被 hash 的内容（hash-over-preimage）。
//! - **不实现**：节点启动 / 共识 / validator/staking/economics runtime / P2P / wallet / RPC。

use crate::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use crate::hash::protocol_hash;
use crate::signature::VerifyingKey;
use core::fmt;
use std::collections::HashSet;

/// V0.1 资源上限（ADR-0014 §Resource Limits）。
pub const MAX_VALIDATORS: usize = 10_000;
pub const MAX_ACCOUNTS: usize = 1_000_000;

/// V0.1 参数上限（ADR-0014 §4；防启动资源耗尽）。
pub const MAX_TX_BYTES: u32 = 1_048_576;
pub const MAX_BLOCK_BYTES: u32 = 8_388_608;
pub const MAX_GAS_PER_BLOCK: u64 = 100_000_000_000;
pub const MAX_CONTRACT_CODE_BYTES: u32 = 524_288;
pub const MAX_CONTRACT_STORAGE_BYTES: u32 = 16_777_216;
pub const MAX_EPOCH_LENGTH: u64 = 1_000_000;
pub const MAX_SNAPSHOT_INTERVAL: u64 = 10_000_000;
pub const MAX_COMMISSION_BPS: u16 = 10_000;
pub const MAX_FEE_BURN_BPS: u16 = 10_000;

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
    /// 解码失败（truncated / 非法字段编码 / 非法长度 / 未知 enum/tag）。
    DecodeError,
    /// 解码后存在尾随字节（trailing bytes）。
    TrailingBytes,
    /// `bonded_stake > 对应账户 liquid_balance`（质押超出余额）。
    StakeExceedsBalance,
    /// `Σ liquid_balance` 溢出 u128（checked_add 失败）。
    SupplyOverflow,
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
            Self::DecodeError => "decode error",
            Self::TrailingBytes => "trailing bytes",
            Self::StakeExceedsBalance => "stake exceeds balance",
            Self::SupplyOverflow => "supply overflow",
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

// =========================================================================
// STEP 6B：decode / semantic validation / ChainIdentity
// =========================================================================

/// 链身份（ADR-0010/0011）：`network_id + chain_id + genesis_hash` 三元组。
/// `chain_id` 来自 Genesis 显式配置，**不得从 genesis_hash 派生**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainIdentity {
    pub network_id: NetworkId,
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
}

/// 地址 35B payload → NovaAddress（校验 version/type/network 注册；未知 tag ⇒ 拒绝）。
/// `pub(crate)`：供 transaction 模块复用（单一来源，ADR-0004）。
pub(crate) fn decode_addr_payload(b: &[u8; 35]) -> Result<NovaAddress, GenesisError> {
    let version = b[0];
    if version != crate::address::ADDRESS_VERSION {
        return Err(GenesisError::InvalidAddress);
    }
    let address_type = AddressType::try_from(b[1]).map_err(|_| GenesisError::InvalidAddress)?;
    let network_id = NetworkId::try_from(b[2]).map_err(|_| GenesisError::InvalidAddress)?;
    let mut key_hash = [0u8; 32];
    key_hash.copy_from_slice(&b[3..35]);
    Ok(NovaAddress::from_payload(NovaAddressPayload {
        address_version: version,
        address_type,
        network_id,
        key_hash,
    }))
}

/// Ed25519 压缩点严格 canonical 校验（`crypto-serialization-v1.md` §7）。
///
/// ed25519-dalek 3.0 的 `from_bytes` 宽松解码（字段运算自动 mod p），会接受 `Y >= p`
/// 的非 canonical 编码。这里按冻结规范额外拒绝非 canonical 压缩点（`Y >= 2^255 - 19`）。
/// 这是**编码格式检查**（非算法实现），防止同一公钥多字节表示（T15）。
fn is_canonical_ed25519_pubkey(pk: &[u8; 32]) -> bool {
    // p = 2^255 - 19（LE）
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    let mut y = *pk;
    y[31] &= 0x7f; // 去掉符号位（高位 bit 255）
    // Y < p 才为 canonical（Y == p 亦无效）。
    for i in (0..32).rev() {
        if y[i] < P[i] {
            return true;
        }
        if y[i] > P[i] {
            return false;
        }
    }
    false // y == p
}

/// 从 canonical bytes 解码 Genesis（ADR-0015 §4）。
///
/// 拒绝（用户 §2）：truncated input、trailing bytes、非法字段/长度、未知 enum/tag、
/// overflow、集合超上限、地址/公钥非法、地址网络与 Genesis 不一致。
/// **不静默忽略 trailing bytes**。
///
/// 本函数执行 **structural + 部分 canonical**（地址/公钥有效、网络一致、上限、trailing）；
/// 排序/重复由 `canonical_genesis_bytes`（validate 内）执行；语义由 `validate_genesis` 执行。
pub fn decode_genesis_bytes(bytes: &[u8]) -> Result<GenesisV1, GenesisError> {
    fn take<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], GenesisError> {
        if bytes.len() < *pos + n {
            return Err(GenesisError::DecodeError);
        }
        let s = &bytes[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }

    let mut pos = 0usize;
    let arr8 = |b: &[u8]| -> [u8; 8] { b.try_into().expect("len 8") };

    let net_byte = take(bytes, &mut pos, 1)?[0];
    let network_id = NetworkId::try_from(net_byte).map_err(|_| GenesisError::InvalidNetwork)?;
    let chain_id = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));
    let genesis_timestamp = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));

    let n_val = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().expect("len 4")) as usize;
    if n_val > MAX_VALIDATORS {
        return Err(GenesisError::CollectionTooLarge);
    }
    let mut initial_validator_set = Vec::with_capacity(n_val);
    for _ in 0..n_val {
        let a35: [u8; 35] = take(bytes, &mut pos, 35)?.try_into().expect("len 35");
        let pk: [u8; 32] = take(bytes, &mut pos, 32)?.try_into().expect("len 32");
        let bonded_stake =
            u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().expect("len 16"));
        let commission_bps =
            u16::from_le_bytes(take(bytes, &mut pos, 2)?.try_into().expect("len 2"));
        let account_address = decode_addr_payload(&a35)?;
        if account_address.payload().network_id != network_id {
            return Err(GenesisError::InvalidValidator);
        }
        // 严格 canonical 压缩点（§7：拒绝 Y >= p 的非 canonical 编码）+ 曲线有效性。
        if !is_canonical_ed25519_pubkey(&pk) || VerifyingKey::from_bytes(&pk).is_err() {
            return Err(GenesisError::InvalidPublicKey);
        }
        initial_validator_set.push(ValidatorInit {
            account_address,
            consensus_public_key: pk,
            bonded_stake,
            commission_bps,
        });
    }

    let n_acc = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().expect("len 4")) as usize;
    if n_acc > MAX_ACCOUNTS {
        return Err(GenesisError::CollectionTooLarge);
    }
    let mut initial_accounts = Vec::with_capacity(n_acc);
    for _ in 0..n_acc {
        let a35: [u8; 35] = take(bytes, &mut pos, 35)?.try_into().expect("len 35");
        let liquid_balance =
            u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().expect("len 16"));
        let address = decode_addr_payload(&a35)?;
        if address.payload().network_id != network_id {
            return Err(GenesisError::InvalidInitialState);
        }
        initial_accounts.push(AccountInit {
            address,
            liquid_balance,
        });
    }

    let protocol_parameters = ProtocolParamsV1 {
        max_tx_bytes: u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().expect("len 4")),
        max_block_bytes: u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().expect("len 4")),
        max_gas_per_block: u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?)),
        max_contract_code_bytes: u32::from_le_bytes(
            take(bytes, &mut pos, 4)?.try_into().expect("len 4"),
        ),
        max_contract_storage_bytes: u32::from_le_bytes(
            take(bytes, &mut pos, 4)?.try_into().expect("len 4"),
        ),
        epoch_length_blocks: u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?)),
        snapshot_interval_blocks: u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?)),
    };
    let economics_parameters = EconomicsParamsV1 {
        total_supply: u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().expect("len 16")),
        min_validator_stake: u128::from_le_bytes(
            take(bytes, &mut pos, 16)?.try_into().expect("len 16"),
        ),
        unbonding_period_seconds: u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?)),
        fee_burn_bps: u16::from_le_bytes(take(bytes, &mut pos, 2)?.try_into().expect("len 2")),
    };

    // trailing bytes：不得静默忽略（用户 §2）。
    if pos != bytes.len() {
        return Err(GenesisError::TrailingBytes);
    }

    Ok(GenesisV1 {
        network_id,
        chain_id,
        genesis_timestamp,
        initial_validator_set,
        initial_accounts,
        protocol_parameters,
        economics_parameters,
    })
}

/// Protocol 参数校验（§10：> 0 且不超 ADR-0014 上限）。
fn validate_protocol_params(pp: &ProtocolParamsV1) -> Result<(), GenesisError> {
    if pp.max_tx_bytes == 0 || pp.max_tx_bytes > MAX_TX_BYTES {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.max_block_bytes < pp.max_tx_bytes || pp.max_block_bytes > MAX_BLOCK_BYTES {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.max_gas_per_block == 0 || pp.max_gas_per_block > MAX_GAS_PER_BLOCK {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.max_contract_code_bytes == 0 || pp.max_contract_code_bytes > MAX_CONTRACT_CODE_BYTES {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.max_contract_storage_bytes == 0
        || pp.max_contract_storage_bytes > MAX_CONTRACT_STORAGE_BYTES
    {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.epoch_length_blocks == 0 || pp.epoch_length_blocks > MAX_EPOCH_LENGTH {
        return Err(GenesisError::InvalidProtocolParams);
    }
    if pp.snapshot_interval_blocks == 0 || pp.snapshot_interval_blocks > MAX_SNAPSHOT_INTERVAL {
        return Err(GenesisError::InvalidProtocolParams);
    }
    Ok(())
}

/// Economics 参数校验（§11）。
fn validate_economics_params(ep: &EconomicsParamsV1) -> Result<(), GenesisError> {
    if ep.total_supply == 0 {
        return Err(GenesisError::InvalidEconomicsParams);
    }
    if ep.min_validator_stake == 0 {
        return Err(GenesisError::InvalidEconomicsParams);
    }
    if ep.unbonding_period_seconds == 0 {
        return Err(GenesisError::InvalidEconomicsParams);
    }
    if ep.fee_burn_bps > MAX_FEE_BURN_BPS {
        return Err(GenesisError::InvalidEconomicsParams);
    }
    Ok(())
}

/// Semantic 校验（用户 §3–§12）。canonical（排序/重复/上限）由 `canonical_genesis_bytes` 保证。
fn validate_semantic(genesis: &GenesisV1) -> Result<(), GenesisError> {
    if genesis.chain_id == 0 {
        return Err(GenesisError::InvalidChainId);
    }
    if genesis.genesis_timestamp == 0 {
        return Err(GenesisError::InvalidTimestamp);
    }
    if genesis.initial_validator_set.is_empty() {
        return Err(GenesisError::InvalidValidator);
    }
    if genesis.initial_accounts.is_empty() {
        return Err(GenesisError::InvalidInitialState);
    }
    for v in &genesis.initial_validator_set {
        if v.bonded_stake == 0 {
            return Err(GenesisError::InvalidValidator);
        }
        if v.commission_bps > MAX_COMMISSION_BPS {
            return Err(GenesisError::InvalidValidator);
        }
        if v.account_address.payload().network_id != genesis.network_id {
            return Err(GenesisError::InvalidValidator);
        }
    }
    for a in &genesis.initial_accounts {
        if a.address.payload().network_id != genesis.network_id {
            return Err(GenesisError::InvalidInitialState);
        }
    }
    // stake accounting（§4/§7/§9）：账户存在、stake <= liquid（无 underflow）、min stake。
    for v in &genesis.initial_validator_set {
        let liquid = genesis
            .initial_accounts
            .iter()
            .find(|a| a.address == v.account_address)
            .map(|a| a.liquid_balance);
        let Some(liquid) = liquid else {
            return Err(GenesisError::InvalidStake);
        };
        if v.bonded_stake > liquid {
            return Err(GenesisError::StakeExceedsBalance);
        }
        if v.bonded_stake < genesis.economics_parameters.min_validator_stake {
            return Err(GenesisError::InvalidStake);
        }
        // final_liquid = liquid - stake（无 underflow）；bonded 进入 staking state，非新增供应。
        let _final_liquid = liquid - v.bonded_stake;
    }
    validate_protocol_params(&genesis.protocol_parameters)?;
    validate_economics_params(&genesis.economics_parameters)?;
    // total supply invariant（§8/§9）：total_supply == Σ liquid，checked。
    let mut sum: u128 = 0;
    for a in &genesis.initial_accounts {
        sum = sum
            .checked_add(a.liquid_balance)
            .ok_or(GenesisError::SupplyOverflow)?;
    }
    if sum != genesis.economics_parameters.total_supply {
        return Err(GenesisError::SupplyInvariantViolation);
    }
    Ok(())
}

/// 完整校验管线（用户 §1）：canonical → semantic → hash → ChainIdentity。
///
/// `chain_id` 来自 Genesis 显式配置；`genesis_hash` 为 `SHA-256(canonical)`。
pub fn validate_genesis(genesis: &GenesisV1) -> Result<ChainIdentity, GenesisError> {
    let bytes = canonical_genesis_bytes(genesis)?; // 排序/重复/上限
    let genesis_hash = protocol_hash(&bytes);
    validate_semantic(genesis)?;
    Ok(ChainIdentity {
        network_id: genesis.network_id,
        chain_id: genesis.chain_id,
        genesis_hash,
    })
}

/// 完整校验 + configured hash 对比（用户 §16）：computed == expected，否则 `GenesisHashMismatch`。
pub fn validate_genesis_with_expected(
    genesis: &GenesisV1,
    expected_hash: &[u8; 32],
) -> Result<ChainIdentity, GenesisError> {
    let identity = validate_genesis(genesis)?;
    if identity.genesis_hash != *expected_hash {
        return Err(GenesisError::GenesisHashMismatch);
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

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
        // 用真实 Ed25519 公钥（decode 会校验 pubkey 有效性）；地址从固定 key_hash 构造。
        let pk1 = KeyPair::generate().expect("kp1").verifying_key().to_bytes();
        let pk2 = KeyPair::generate().expect("kp2").verifying_key().to_bytes();
        // validator 按 validator_id 排序（保证 canonical）。
        let mut vals = vec![
            ValidatorInit {
                account_address: addr([0x11; 32], NetworkId::Mainnet),
                consensus_public_key: pk1,
                bonded_stake: 1_000_000,
                commission_bps: 1000,
            },
            ValidatorInit {
                account_address: addr([0x22; 32], NetworkId::Mainnet),
                consensus_public_key: pk2,
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

    // ---- STEP 6B：decode ----
    #[test]
    fn decode_roundtrip() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        let d = decode_genesis_bytes(&bytes).unwrap();
        assert_eq!(d, g, "decode mismatch:\nd={d:#?}\ng={g:#?}");
        assert_eq!(
            canonical_genesis_bytes(&d).unwrap(),
            bytes,
            "re-encode stable"
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        // truncated
        let r1 = decode_genesis_bytes(&bytes[..bytes.len() - 1]);
        assert_eq!(
            r1,
            Err(GenesisError::DecodeError),
            "truncated result: {r1:?}"
        );
        let r2 = decode_genesis_bytes(&bytes[..3]);
        assert_eq!(r2, Err(GenesisError::DecodeError), "short result: {r2:?}");
        // trailing：不得静默忽略
        let mut t = bytes.clone();
        t.push(0x00);
        assert_eq!(decode_genesis_bytes(&t), Err(GenesisError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_bad_network_address() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        // 布局：header 21B；validator0 地址 payload [21..56]，network 字节在 +2 = 23
        let mut m = bytes.clone();
        m[23] = 0x02; // testnet（Genesis 是 mainnet）
        assert_eq!(
            decode_genesis_bytes(&m),
            Err(GenesisError::InvalidValidator)
        );
    }

    #[test]
    fn decode_rejects_bad_pubkey() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        let mut m = bytes.clone();
        // 第一个 validator pubkey [56..88]；0xff×32 的 y 值超出曲线域 ⇒ 非法压缩点
        for b in m[56..88].iter_mut() {
            *b = 0xff;
        }
        let r = decode_genesis_bytes(&m);
        assert_eq!(
            r,
            Err(GenesisError::InvalidPublicKey),
            "bad pubkey result: {r:?}"
        );
    }

    #[test]
    fn decode_rejects_unknown_network_id() {
        let g = sample();
        let bytes = canonical_genesis_bytes(&g).unwrap();
        let mut m = bytes.clone();
        m[0] = 0x04; // 未注册 network_id
        assert_eq!(decode_genesis_bytes(&m), Err(GenesisError::InvalidNetwork));
    }

    // ---- STEP 6B：validate_genesis ----
    #[test]
    fn validate_ok_chain_identity() {
        let g = sample();
        let ci = validate_genesis(&g).unwrap();
        assert_eq!(ci.network_id, g.network_id);
        assert_eq!(ci.chain_id, g.chain_id);
        assert_eq!(ci.genesis_hash, compute_genesis_hash(&g).unwrap());
    }

    #[test]
    fn validate_with_expected() {
        let g = sample();
        let ci = validate_genesis(&g).unwrap();
        assert!(validate_genesis_with_expected(&g, &ci.genesis_hash).is_ok());
        let wrong = [0xab; 32];
        assert_eq!(
            validate_genesis_with_expected(&g, &wrong),
            Err(GenesisError::GenesisHashMismatch)
        );
    }

    #[test]
    fn validate_rejects_chain_id_zero() {
        let mut g = sample();
        g.chain_id = 0;
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidChainId));
    }

    #[test]
    fn validate_rejects_timestamp_zero() {
        let mut g = sample();
        g.genesis_timestamp = 0;
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidTimestamp));
    }

    #[test]
    fn validate_rejects_empty_sets() {
        let mut g = sample();
        g.initial_validator_set.clear();
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidValidator));
        let mut g = sample();
        g.initial_accounts.clear();
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidInitialState));
    }

    #[test]
    fn validate_rejects_stake_exceeds_balance() {
        let mut g = sample();
        g.initial_validator_set[0].bonded_stake = u128::MAX;
        assert_eq!(validate_genesis(&g), Err(GenesisError::StakeExceedsBalance));
    }

    #[test]
    fn validate_rejects_validator_account_missing() {
        let mut g = sample();
        let addr = g.initial_validator_set[0].account_address;
        g.initial_accounts.retain(|a| a.address != addr);
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidStake));
    }

    #[test]
    fn validate_rejects_below_min_stake() {
        let mut g = sample();
        g.initial_validator_set[0].bonded_stake = 1;
        assert_eq!(validate_genesis(&g), Err(GenesisError::InvalidStake));
    }

    #[test]
    fn validate_rejects_supply_invariant() {
        let mut g = sample();
        g.economics_parameters.total_supply += 1;
        assert_eq!(
            validate_genesis(&g),
            Err(GenesisError::SupplyInvariantViolation)
        );
    }

    #[test]
    fn validate_rejects_supply_overflow() {
        let mut g = sample();
        g.initial_accounts[0].liquid_balance = u128::MAX;
        g.initial_accounts[1].liquid_balance = u128::MAX;
        g.economics_parameters.total_supply = 1;
        assert_eq!(validate_genesis(&g), Err(GenesisError::SupplyOverflow));
    }

    #[test]
    fn validate_rejects_bad_protocol_and_economics() {
        let mut g = sample();
        g.protocol_parameters.max_tx_bytes = 0;
        assert_eq!(
            validate_genesis(&g),
            Err(GenesisError::InvalidProtocolParams)
        );
        let mut g = sample();
        g.protocol_parameters.max_block_bytes = 1; // < max_tx_bytes
        assert_eq!(
            validate_genesis(&g),
            Err(GenesisError::InvalidProtocolParams)
        );
        let mut g = sample();
        g.economics_parameters.fee_burn_bps = 10_001;
        assert_eq!(
            validate_genesis(&g),
            Err(GenesisError::InvalidEconomicsParams)
        );
    }

    #[test]
    fn network_separation() {
        let a = sample();
        let mut b = sample();
        b.network_id = NetworkId::Testnet;
        let ha = compute_genesis_hash(&a).unwrap();
        let hb = compute_genesis_hash(&b).unwrap();
        assert_ne!(ha, hb, "不同 network_id ⇒ 不同 hash");
        // b 的地址仍是 mainnet ⇒ 语义校验拒绝（地址网络不一致）
        assert_eq!(validate_genesis(&b), Err(GenesisError::InvalidValidator));
    }

    #[test]
    fn chain_id_not_derived_from_hash() {
        let g = sample();
        let ci = validate_genesis(&g).unwrap();
        let h = ci.genesis_hash;
        let from_hash = u64::from_le_bytes(h[0..8].try_into().unwrap());
        assert_ne!(g.chain_id, from_hash, "chain_id 非 genesis_hash 截断派生");
    }
}
