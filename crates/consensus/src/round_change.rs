//! O2 Round-Change Certificate（**PHASE 6H-Y**；治理依据 ADR-0066 / ADR-0070 / ADR-0072 / ADR-0073）。
//!
//! # 范围（严格限于冻结设计；**不重新解释、不改进协议**）
//! - [`RoundChangeCertificate`]：`validator_set_id ‖ height ‖ from_round ‖ evidence[]`。
//! - [`RoundChangeEvidence`]：`validator_id(32B) ‖ signature(64B)`（定长 96B）。
//! - canonical 编码：**ADR-0070 §6**（`len = 50 + 96·n`）。
//! - 签名陈述：`Abandon(chain_id, height, from_round)`（ADR-0066 RC-4 / §5.1；域 = `0x10`）。
//! - `to_round := checked_successor(from_round)`（**派生，不编码、不签名**；ADR-0066 RC-2）。
//! - 上界：`MAX_EVIDENCE_COUNT = 21`、`MAX_CERTIFICATE_BYTES = 2066`（ADR-0070 §8）。
//! - 有界内存：`MAX_CERTIFICATES_PER_HEIGHT = 64` + 确定性淘汰（Owner implementation policy D4）。
//!
//! # Safety 边界（**绝对**；ADR-0066 §7.2 / §9、ADR-0072 §7）
//! 本模块 **绝不**：进入 `VoteAccumulator` / `RoundEvidence` / `QcRegistry`；调用 `assemble_qc` /
//! `verify_qc`；触发 finality；修改 `finalized_reference` / QC history / `LockedState` / lock 语义。
//! 证书 **不是** QC / PrevoteQC / PrecommitQC / Vote / finality 证据 / lock 证据。
//!
//! # 非目标（本阶段不实现；Owner 另行授权）
//! 检索协议（D6 = A：none）· protocol-version 协商（D5 = A）· journal / 持久化（S1：none）·
//! node runtime 循环接线（见 PHASE 6H-Y 报告，标记 PARTIAL）。

use core::fmt;

use crate::integration::checked_successor;
use crate::validator::{ValidatorId, ValidatorSet};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};

/// 证书 evidence 项数上界（**ADR-0070 §8 / PHASE 6H-J Owner 批准**；非本模块自选）。
pub const MAX_EVIDENCE_COUNT: usize = 21;
/// 证书字节数上界（**ADR-0070 §8**；`= 50 + 96 × 21`）。
pub const MAX_CERTIFICATE_BYTES: usize = 2066;
/// 证书固定头长度：`validator_set_id(32) ‖ height(8) ‖ from_round(8) ‖ evidence_count(2)`。
pub const CERTIFICATE_HEADER_BYTES: usize = 50;
/// 单项 evidence 定长：`validator_id(32) ‖ signature(64)`。
pub const EVIDENCE_BYTES: usize = 96;
/// 每个 height 的最大在内存证书数（**Owner implementation policy D4**；非 consensus 安全参数）。
pub const MAX_CERTIFICATES_PER_HEIGHT: usize = 64;
/// 默认跟踪的最大 height 数（有界内存；确定性淘汰见 [`RoundChangeStore`]）。
pub const DEFAULT_MAX_TRACKED_HEIGHTS: usize = 256;

/// `len(certificate) = 50 + 96·n`（ADR-0070 §6 派生式）。
pub const fn certificate_len(evidence_count: usize) -> usize {
    CERTIFICATE_HEADER_BYTES + EVIDENCE_BYTES * evidence_count
}

/// O2 证书错误（**独立错误域**；不复用也不改写既有错误类型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundChangeError {
    /// evidence 项数超过 [`MAX_EVIDENCE_COUNT`]。
    TooManyEvidence,
    /// evidence 为空。
    EmptyEvidence,
    /// 编码后字节数超过 [`MAX_CERTIFICATE_BYTES`]。
    CertificateTooLarge,
    /// 字节数 < [`CERTIFICATE_HEADER_BYTES`]（截断）。
    Truncated,
    /// 长度 ≠ `50 + 96·count`（含 trailing bytes）。
    InvalidLength,
    /// evidence_count 与实际内容不一致。
    InvalidEvidenceCount,
    /// `validator_id` 非**严格升序**（非 canonical 排序）。
    EvidenceNotAscending,
    /// 重复 `validator_id`。
    DuplicateValidator,
    /// `validator_set_id` 与期望不符。
    ValidatorSetMismatch,
    /// 证书 `height` 与本地当前高度不符（ADR-0066 §6.2「wrong height」）。
    ///
    /// 冻结验证器 [`verify_certificate`] 无本地高度参数 ⇒ 该项由**节点层适用性前置**实现。
    WrongHeight,
    /// `to_round <= local_round`（**无 round 回退**；ADR-0066 §7.1/§9.1）。
    StaleCertificate,
    /// `checked_successor` 溢出（`from_round == u64::MAX`）。
    RoundOverflow,
    /// 非验证者集合成员。
    UnknownValidator,
    /// 公钥畸形或 `validator_id` 与公钥不一致。
    ValidatorIdentityMismatch,
    /// 签名无效（含域 / 链绑定不符时验签失败）。
    InvalidSignature,
    /// 签名域构造失败（不应发生：`0x10` 为已注册域）。
    InvalidDomain,
    /// 累计权重未达 `ceil(2T/3)`。
    InsufficientQuorum,
}

impl fmt::Display for RoundChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TooManyEvidence => "too many evidence entries",
            Self::EmptyEvidence => "empty evidence",
            Self::CertificateTooLarge => "certificate too large",
            Self::Truncated => "truncated certificate",
            Self::InvalidLength => "invalid certificate length",
            Self::InvalidEvidenceCount => "evidence count mismatch",
            Self::EvidenceNotAscending => "evidence not in ascending validator_id order",
            Self::DuplicateValidator => "duplicate validator_id",
            Self::ValidatorSetMismatch => "validator_set_id mismatch",
            Self::WrongHeight => "wrong height (certificate height != local height)",
            Self::StaleCertificate => "stale certificate (to_round <= local_round)",
            Self::RoundOverflow => "round overflow",
            Self::UnknownValidator => "unknown validator",
            Self::ValidatorIdentityMismatch => "validator identity mismatch",
            Self::InvalidSignature => "invalid signature",
            Self::InvalidDomain => "invalid signing domain",
            Self::InsufficientQuorum => "insufficient quorum weight",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RoundChangeError {}

/// 单条 Abandon attestation（ADR-0066 §3 RC-1 / §4.1；ADR-0070 §6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundChangeEvidence {
    /// `SHA-256(consensus_public_key)`。
    pub validator_id: ValidatorId,
    /// Ed25519 原始签名（64B）。
    pub signature: [u8; 64],
}

/// `Abandon(chain_id, height, from_round)` 的 canonical payload（ADR-0066 §5.1；ADR-0070 §5）。
///
/// `payload = height(8B LE) ‖ from_round(8B LE)` —— **精确 16B**。
/// **MUST NOT** 含 `to_round` / `target` / `vote_type` / `source_block_hash` / `timestamp`。
pub fn canonical_abandon_payload(height: u64, from_round: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&height.to_le_bytes());
    out[8..16].copy_from_slice(&from_round.to_le_bytes());
    out
}

/// Abandon 签名的 `signed_bytes`（**复用既有 `build_signed_bytes`；不建立第二套序列化**）。
///
/// `algorithm_id(1B) ‖ domain_id(1B) ‖ chain_id(8B LE) ‖ payload_length(4B LE) ‖ payload`
/// 且 `domain_id = 0x10`、`payload_length = 16`。
pub fn abandon_signed_bytes(
    chain_id: u64,
    height: u64,
    from_round: u64,
) -> Result<Vec<u8>, RoundChangeError> {
    let payload = canonical_abandon_payload(height, from_round);
    build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::RoundChangeCertificate,
        chain_id,
        &payload,
    )
    .map_err(|_| RoundChangeError::InvalidDomain)
}

/// Abandon 签名消息哈希（`SHA-256(signed_bytes)`）。
pub fn abandon_message_hash(
    chain_id: u64,
    height: u64,
    from_round: u64,
) -> Result<nova_crypto::domain::SigningMessageHash, RoundChangeError> {
    Ok(hash_signing_message(&abandon_signed_bytes(
        chain_id, height, from_round,
    )?))
}

/// O2 Round-Change Certificate（ADR-0066 §3 RC-1）。
///
/// `to_round` **不存在于结构体中** —— 它由 `from_round` 派生（ADR-0066 RC-2：不编码、不签名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundChangeCertificate {
    /// `= genesis_hash`（ADR-0038 F-11 口径）。
    pub validator_set_id: [u8; 32],
    /// 证书针对的高度。
    pub height: u64,
    /// 该证书聚合的 round（**不是**目标 round）。
    pub from_round: u64,
    /// 已按 `validator_id` **严格升序**排列的 evidence。
    pub evidence: Vec<RoundChangeEvidence>,
}

impl RoundChangeCertificate {
    /// `to_round := checked_successor(from_round) = from_round + 1`（ADR-0066 RC-2；唯一后继原语）。
    pub fn to_round(&self) -> Result<u64, RoundChangeError> {
        checked_successor(self.from_round).ok_or(RoundChangeError::RoundOverflow)
    }

    /// 编码后的字节数（派生）。
    pub fn encoded_len(&self) -> usize {
        certificate_len(self.evidence.len())
    }
}

/// 证书被接受后产生的**唯一**语义结果：`round` 恰好 `+1`。
///
/// 该结果**不**携带 QC / finality / lock 语义（ADR-0066 §7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundChangeTransition {
    /// 证书聚合的 round。
    pub from_round: u64,
    /// 派生目标 round（`= from_round + 1`）。
    pub to_round: u64,
}

/// Canonical 编码（ADR-0070 §6）：`validator_set_id(32) ‖ height(8 LE) ‖ from_round(8 LE) ‖
/// evidence_count(2 LE) ‖ evidence[96×n]`。
pub fn encode_certificate(cert: &RoundChangeCertificate) -> Result<Vec<u8>, RoundChangeError> {
    let n = cert.evidence.len();
    if n == 0 {
        return Err(RoundChangeError::EmptyEvidence);
    }
    if n > MAX_EVIDENCE_COUNT {
        return Err(RoundChangeError::TooManyEvidence);
    }
    let len = certificate_len(n);
    if len > MAX_CERTIFICATE_BYTES {
        return Err(RoundChangeError::CertificateTooLarge);
    }
    if u16::try_from(n).is_err() {
        return Err(RoundChangeError::TooManyEvidence);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&cert.validator_set_id);
    out.extend_from_slice(&cert.height.to_le_bytes());
    out.extend_from_slice(&cert.from_round.to_le_bytes());
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for e in &cert.evidence {
        out.extend_from_slice(e.validator_id.as_bytes());
        out.extend_from_slice(&e.signature);
    }
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

/// Canonical 解码（**仅结构解析**；不做 membership / 签名 / 阈值等语义校验）。
///
/// **严格**：拒绝截断、trailing bytes、长度 ≠ `50 + 96·count`、count > 上限、
/// 非严格升序、重复 `validator_id`。
pub fn decode_certificate(bytes: &[u8]) -> Result<RoundChangeCertificate, RoundChangeError> {
    if bytes.len() < CERTIFICATE_HEADER_BYTES {
        return Err(RoundChangeError::Truncated);
    }
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(RoundChangeError::CertificateTooLarge);
    }
    let mut set_id = [0u8; 32];
    set_id.copy_from_slice(&bytes[0..32]);
    let height = u64::from_le_bytes(bytes[32..40].try_into().expect("8B slice"));
    let from_round = u64::from_le_bytes(bytes[40..48].try_into().expect("8B slice"));
    let count = u16::from_le_bytes(bytes[48..50].try_into().expect("2B slice")) as usize;

    if count == 0 {
        return Err(RoundChangeError::EmptyEvidence);
    }
    if count > MAX_EVIDENCE_COUNT {
        return Err(RoundChangeError::TooManyEvidence);
    }
    let expected = certificate_len(count);
    if bytes.len() != expected {
        return Err(RoundChangeError::InvalidLength);
    }

    let mut evidence = Vec::with_capacity(count);
    let mut prev: Option<ValidatorId> = None;
    for i in 0..count {
        let off = CERTIFICATE_HEADER_BYTES + i * EVIDENCE_BYTES;
        let mut vid = [0u8; 32];
        vid.copy_from_slice(&bytes[off..off + 32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[off + 32..off + EVIDENCE_BYTES]);
        let validator_id = ValidatorId::from_bytes(vid);
        if let Some(p) = prev {
            if validator_id == p {
                return Err(RoundChangeError::DuplicateValidator);
            }
            if validator_id < p {
                return Err(RoundChangeError::EvidenceNotAscending);
            }
        }
        prev = Some(validator_id);
        evidence.push(RoundChangeEvidence {
            validator_id,
            signature: sig,
        });
    }

    Ok(RoundChangeCertificate {
        validator_set_id: set_id,
        height,
        from_round,
        evidence,
    })
}

/// 逐项验签（**V-5 同构五步**：membership → identity → signed_bytes(`0x10`) → hash → verify_strict）。
///
/// PHASE 6H-Z：改为 `pub` —— 节点层**有界 attestation 累积**（`round_change_pool`）必须复用
/// 本**冻结**验证器逐条验证（MUST NOT 建立第二套验签实现）。返回该 attestation 的权重。
pub fn verify_evidence(
    evidence: &RoundChangeEvidence,
    chain_id: u64,
    height: u64,
    from_round: u64,
    set: &ValidatorSet,
) -> Result<u128, RoundChangeError> {
    // ① membership（不信任 envelope sender；仅信任 validator set）
    let info = set
        .info(&evidence.validator_id)
        .ok_or(RoundChangeError::UnknownValidator)?;
    // ② identity：validator_id == SHA-256(canonical pubkey)
    let vk = VerifyingKey::from_bytes(&info.consensus_public_key)
        .map_err(|_| RoundChangeError::ValidatorIdentityMismatch)?;
    if ValidatorId::from_consensus_public_key(&vk.to_bytes()) != evidence.validator_id {
        return Err(RoundChangeError::ValidatorIdentityMismatch);
    }
    // ③ signed_bytes（专用域 0x10 —— 不得复用 ValidatorVote / 其它域）
    let signed = abandon_signed_bytes(chain_id, height, from_round)?;
    // ④ hash
    let h = hash_signing_message(&signed);
    // ⑤ verify_strict
    let sig = Signature::from_bytes(&evidence.signature)
        .map_err(|_| RoundChangeError::InvalidSignature)?;
    verify_message_hash(&vk, &h, &sig).map_err(|_| RoundChangeError::InvalidSignature)?;
    Ok(info.voting_weight)
}

/// 校验并派生存取转移（**ADR-0066 §6 / §7.1；ADR-0070 §7**）。
///
/// ACCEPT 当且仅当全部成立：
/// ① 结构有效 ② `evidence.len() <= 21` ③ 编码字节数 `<= 2066`
/// ④ `validator_set_id == expected_validator_set_id` ⑤ 成员 ⑥ 域 `0x10` 验签通过
/// ⑦ 严格升序 ⑧ 无重复 ⑨ 权重 `>= ceil(2T/3)` ⑩ `to_round = from_round + 1`
/// ⑪ `to_round > local_round`。
///
/// **绝不**产生 QC / finality / lock 语义；结果只有 [`RoundChangeTransition`]。
pub fn verify_certificate(
    cert: &RoundChangeCertificate,
    chain_id: u64,
    expected_validator_set_id: &[u8; 32],
    set: &ValidatorSet,
    local_round: u64,
) -> Result<RoundChangeTransition, RoundChangeError> {
    // ① / ② 结构 + 项数上界
    let n = cert.evidence.len();
    if n == 0 {
        return Err(RoundChangeError::EmptyEvidence);
    }
    if n > MAX_EVIDENCE_COUNT {
        return Err(RoundChangeError::TooManyEvidence);
    }
    // ③ 字节上界（由 n 派生）
    if certificate_len(n) > MAX_CERTIFICATE_BYTES {
        return Err(RoundChangeError::CertificateTooLarge);
    }
    // ④ validator_set_id
    if &cert.validator_set_id != expected_validator_set_id {
        return Err(RoundChangeError::ValidatorSetMismatch);
    }
    // ⑩ 派生 to_round（唯一后继原语）
    let to_round = cert.to_round()?;
    // ⑪ 无 round 回退
    if to_round <= local_round {
        return Err(RoundChangeError::StaleCertificate);
    }
    // ⑦ / ⑧ 严格升序 + 无重复（先于昂贵验签）
    let mut prev: Option<ValidatorId> = None;
    for e in &cert.evidence {
        if let Some(p) = prev {
            if e.validator_id == p {
                return Err(RoundChangeError::DuplicateValidator);
            }
            if e.validator_id < p {
                return Err(RoundChangeError::EvidenceNotAscending);
            }
        }
        prev = Some(e.validator_id);
    }
    // ⑤ / ⑥ / ⑨ 逐项验签 + 权重累计
    let mut weight: u128 = 0;
    for e in &cert.evidence {
        weight = weight.saturating_add(verify_evidence(
            e,
            chain_id,
            cert.height,
            cert.from_round,
            set,
        )?);
    }
    if !set.is_quorum(weight) {
        return Err(RoundChangeError::InsufficientQuorum);
    }
    Ok(RoundChangeTransition {
        from_round: cert.from_round,
        to_round,
    })
}

/// 证书准入结果（`RoundChangeStore::admit` 的返回值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// 新证书已存入。
    Admitted {
        /// 因 height 容量上限而被淘汰的最低 height（若有）。
        evicted_height: Option<u64>,
        /// 因 height 内容量上限而被 FIFO 淘汰的证书（若有）。
        evicted_certificate: bool,
    },
    /// 同一 `(height, from_round)` 已存在 ⇒ **幂等**（不增长、不改变内容）。
    Duplicate,
}

/// 有界的证书内存存储（**Owner policy D4**；S1：无 journal / 无持久化 / 无迁移）。
///
/// 确定性淘汰规则（**显式、可测**）：
/// 1. **height 维度**：当跟踪的 height 数达到 `max_heights` 且新 height 未跟踪时，
///    淘汰**最低 height**（`BTreeMap::pop_first`；与插入顺序无关）。
/// 2. **height 内部**：当该 height 的证书数达到 `max_per_height` 时，淘汰**最早插入**的一项
///    （FIFO）；随后追加新项。
/// 3. **幂等**：同一 `(height, from_round)` 再次准入 ⇒ [`AdmitOutcome::Duplicate`]。
///
/// **重启会丢失全部已接收证书 —— 这是有意设计**（R-2 pure on-demand；S1）。
#[derive(Debug, Clone)]
pub struct RoundChangeStore {
    max_heights: usize,
    max_per_height: usize,
    heights: std::collections::BTreeMap<u64, Vec<RoundChangeCertificate>>,
}

impl RoundChangeStore {
    /// 以 `max_per_height = MAX_CERTIFICATES_PER_HEIGHT` 构造。
    pub fn new(max_heights: usize) -> Self {
        Self {
            max_heights: max_heights.max(1),
            max_per_height: MAX_CERTIFICATES_PER_HEIGHT,
            heights: std::collections::BTreeMap::new(),
        }
    }

    /// 以显式容量构造（仅供测试；生产用 [`Self::new`]）。
    pub fn with_caps(max_heights: usize, max_per_height: usize) -> Self {
        Self {
            max_heights: max_heights.max(1),
            max_per_height: max_per_height.max(1),
            heights: std::collections::BTreeMap::new(),
        }
    }

    /// 准入一张证书（不修改任何共识状态）。
    pub fn admit(&mut self, cert: RoundChangeCertificate) -> AdmitOutcome {
        let mut evicted_height = None;
        if !self.heights.contains_key(&cert.height) && self.heights.len() >= self.max_heights {
            // 确定性淘汰：始终移除最低高度（BTreeMap 首元素），与插入顺序无关。
            let evicted = self.heights.pop_first().map(|(height, _)| height);
            evicted_height = evicted;
        }
        let slot = self.heights.entry(cert.height).or_default();
        if slot.iter().any(|c| c.from_round == cert.from_round) {
            return AdmitOutcome::Duplicate;
        }
        let mut evicted_certificate = false;
        if slot.len() >= self.max_per_height {
            slot.remove(0);
            evicted_certificate = true;
        }
        slot.push(cert);
        AdmitOutcome::Admitted {
            evicted_height,
            evicted_certificate,
        }
    }

    /// 按 `(height, from_round)` 查询。
    pub fn get(&self, height: u64, from_round: u64) -> Option<&RoundChangeCertificate> {
        self.heights
            .get(&height)
            .and_then(|v| v.iter().find(|c| c.from_round == from_round))
    }

    /// 跟踪的 height 数。
    pub fn tracked_heights(&self) -> usize {
        self.heights.len()
    }

    /// 某个 height 的证书数。
    pub fn certificates_at(&self, height: u64) -> usize {
        self.heights.get(&height).map_or(0, Vec::len)
    }

    /// 证书总数（有界）。
    pub fn total(&self) -> usize {
        self.heights.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;

    const CHAIN_ID: u64 = 1001;
    const VSET_ID: [u8; 32] = [0x42; 32];

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn vin(pk: [u8; 32], stake: u128, kh: [u8; 32]) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: stake,
            commission_bps: 100,
        }
    }

    fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_timestamp: 0,
            initial_validator_set: vals,
            initial_accounts: Vec::new(),
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 64 * 1024,
                max_block_bytes: 8 * 1024 * 1024,
                max_gas_per_block: 100_000_000_000,
                max_contract_code_bytes: 0,
                max_contract_storage_bytes: 0,
                epoch_length_blocks: 1_000_000,
                snapshot_interval_blocks: 10_000_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 1_000_000_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 100,
            },
        }
    }

    struct Ctx {
        set: ValidatorSet,
        kps: Vec<KeyPair>,
    }

    fn ctx(n: usize, stake: u128) -> Ctx {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().unwrap();
            vals.push(vin(
                kp.verifying_key().to_bytes(),
                stake,
                [i as u8 + 0x10; 32],
            ));
            kps.push(kp);
        }
        Ctx {
            set: ValidatorSet::from_genesis(&genesis_with(vals)),
            kps,
        }
    }

    fn sign_abandon(kp: &KeyPair, chain_id: u64, height: u64, from_round: u64) -> [u8; 64] {
        let h = abandon_message_hash(chain_id, height, from_round).unwrap();
        sign_message_hash(kp.signing_key(), &h).to_bytes()
    }

    fn cert_from(
        c: &Ctx,
        chain_id: u64,
        height: u64,
        from_round: u64,
        signers: &[usize],
    ) -> RoundChangeCertificate {
        let mut evidence: Vec<RoundChangeEvidence> = signers
            .iter()
            .map(|&i| RoundChangeEvidence {
                validator_id: ValidatorId::from_consensus_public_key(
                    &c.kps[i].verifying_key().to_bytes(),
                ),
                signature: sign_abandon(&c.kps[i], chain_id, height, from_round),
            })
            .collect();
        evidence.sort_by_key(|e| e.validator_id);
        RoundChangeCertificate {
            validator_set_id: VSET_ID,
            height,
            from_round,
            evidence,
        }
    }

    #[test]
    fn abandon_payload_is_exactly_16_bytes() {
        let p = canonical_abandon_payload(7, 3);
        assert_eq!(p.len(), 16);
        assert_eq!(&p[0..8], &7u64.to_le_bytes());
        assert_eq!(&p[8..16], &3u64.to_le_bytes());
    }

    #[test]
    fn signed_bytes_use_domain_0x10_and_length_16() {
        let sb = abandon_signed_bytes(CHAIN_ID, 9, 4).unwrap();
        assert_eq!(sb[0], AlgorithmId::Ed25519.as_u8());
        assert_eq!(sb[1], DomainId::RoundChangeCertificate.as_u8());
        assert_eq!(sb[1], 0x10);
        assert_eq!(&sb[2..10], &CHAIN_ID.to_le_bytes());
        assert_eq!(u32::from_le_bytes(sb[10..14].try_into().unwrap()), 16);
        assert_eq!(sb.len(), 14 + 16);
    }

    #[test]
    fn certificate_len_matches_derivation() {
        assert_eq!(certificate_len(0), 50);
        assert_eq!(certificate_len(1), 146);
        assert_eq!(certificate_len(21), 2066);
        assert_eq!(certificate_len(21), MAX_CERTIFICATE_BYTES);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = ctx(1, 100);
        let cert = cert_from(&c, CHAIN_ID, 5, 2, &[0]);
        let bytes = encode_certificate(&cert).unwrap();
        assert_eq!(bytes.len(), 146);
        let back = decode_certificate(&bytes).unwrap();
        assert_eq!(back, cert);
    }

    #[test]
    fn decode_rejects_truncated_trailing_and_bad_length() {
        let c = ctx(1, 100);
        let cert = cert_from(&c, CHAIN_ID, 5, 2, &[0]);
        let bytes = encode_certificate(&cert).unwrap();

        assert_eq!(
            decode_certificate(&bytes[..49]),
            Err(RoundChangeError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_certificate(&trailing),
            Err(RoundChangeError::InvalidLength)
        );
        let mut short = bytes.clone();
        short.pop();
        assert_eq!(
            decode_certificate(&short),
            Err(RoundChangeError::InvalidLength)
        );
    }

    #[test]
    fn decode_rejects_zero_count() {
        let mut b = vec![0u8; CERTIFICATE_HEADER_BYTES];
        b[48..50].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_certificate(&b), Err(RoundChangeError::EmptyEvidence));
    }

    #[test]
    fn decode_rejects_count_above_max() {
        let mut b = vec![0u8; CERTIFICATE_HEADER_BYTES];
        b[48..50].copy_from_slice(&22u16.to_le_bytes());
        assert_eq!(
            decode_certificate(&b),
            Err(RoundChangeError::TooManyEvidence)
        );
    }

    #[test]
    fn encode_rejects_empty_and_too_many() {
        let empty = RoundChangeCertificate {
            validator_set_id: VSET_ID,
            height: 1,
            from_round: 0,
            evidence: Vec::new(),
        };
        assert_eq!(
            encode_certificate(&empty),
            Err(RoundChangeError::EmptyEvidence)
        );

        let c = ctx(22, 100);
        let big = cert_from(&c, CHAIN_ID, 1, 0, &(0..22).collect::<Vec<_>>());
        assert_eq!(
            encode_certificate(&big),
            Err(RoundChangeError::TooManyEvidence)
        );
    }

    #[test]
    fn decode_rejects_non_ascending_and_duplicate() {
        // 手工构造：两项 validator_id 逆序
        let mut b = vec![0u8; certificate_len(2)];
        b[48..50].copy_from_slice(&2u16.to_le_bytes());
        b[50..82].copy_from_slice(&[0xFF; 32]);
        b[146..178].copy_from_slice(&[0x01; 32]);
        assert_eq!(
            decode_certificate(&b),
            Err(RoundChangeError::EvidenceNotAscending)
        );
        // 重复
        let mut d = vec![0u8; certificate_len(2)];
        d[48..50].copy_from_slice(&2u16.to_le_bytes());
        d[50..82].copy_from_slice(&[0x07; 32]);
        d[146..178].copy_from_slice(&[0x07; 32]);
        assert_eq!(
            decode_certificate(&d),
            Err(RoundChangeError::DuplicateValidator)
        );
    }

    #[test]
    fn to_round_is_derived_plus_one() {
        let c = ctx(1, 100);
        let cert = cert_from(&c, CHAIN_ID, 5, 7, &[0]);
        assert_eq!(cert.to_round().unwrap(), 8);
        // 结构上不存在 to_round 字段 ⇒ 无法编码任意未来 round
        let bytes = encode_certificate(&cert).unwrap();
        assert_eq!(bytes.len(), certificate_len(cert.evidence.len()));
    }

    #[test]
    fn to_round_overflow_rejected() {
        let cert = RoundChangeCertificate {
            validator_set_id: VSET_ID,
            height: 1,
            from_round: u64::MAX,
            evidence: vec![RoundChangeEvidence {
                validator_id: ValidatorId::from_bytes([1u8; 32]),
                signature: [0u8; 64],
            }],
        };
        assert_eq!(cert.to_round(), Err(RoundChangeError::RoundOverflow));
    }

    #[test]
    fn verify_accepts_valid_certificate() {
        let c = ctx(3, 100); // quorum = ceil(300*2/3) = 200 ⇒ 2 validators
        let cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        let t = verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 2).unwrap();
        assert_eq!(t.from_round, 2);
        assert_eq!(t.to_round, 3);
    }

    #[test]
    fn verify_exact_quorum_and_over_quorum() {
        let c = ctx(3, 100);
        // 恰好 2/3（200/300）
        let exact = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        assert!(verify_certificate(&exact, CHAIN_ID, &VSET_ID, &c.set, 2).is_ok());
        // 3/3
        let over = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1, 2]);
        assert!(verify_certificate(&over, CHAIN_ID, &VSET_ID, &c.set, 2).is_ok());
    }

    #[test]
    fn verify_rejects_insufficient_quorum() {
        let c = ctx(3, 100);
        let cert = cert_from(&c, CHAIN_ID, 11, 2, &[0]);
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::InsufficientQuorum)
        );
    }

    /// P1-A.30 **S5-1**：**非等权**集合的 quorum 由**权重**（非节点数）决定。
    ///
    /// 集合 `[100, 50, 50]` ⇒ `T = 200`、`Q = ceil(2T/3) = 134`：
    /// - `{50, 50}`（= 2/3 节点数）权重 100 < 134 ⇒ **拒绝** —— 若实现按“节点数 2/3”判 quorum
    ///   则会**误接受**（本用例为决定性反例）；
    /// - `{100, 50}` = 150 ≥ 134 ⇒ 接受，且仍为 `to_round = from_round + 1`；
    /// - `{100, 50, 50}` = 200 ⇒ 接受。
    #[test]
    fn s5_quorum_uses_weight_not_validator_count() {
        let stakes = [100u128, 50, 50];
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for (i, stake) in stakes.iter().enumerate() {
            let kp = KeyPair::generate().unwrap();
            vals.push(vin(
                kp.verifying_key().to_bytes(),
                *stake,
                [0x30 + i as u8; 32],
            ));
            kps.push(kp);
        }
        let c = Ctx {
            set: ValidatorSet::from_genesis(&genesis_with(vals)),
            kps,
        };
        assert_eq!(c.set.total_weight(), 200);
        assert_eq!(c.set.quorum(), 134);

        // ① 节点数 2/3 但权重不足 ⇒ 拒绝（权重语义 ≠ 计数语义）。
        let weak = cert_from(&c, CHAIN_ID, 11, 2, &[1, 2]);
        assert_eq!(weak.evidence.len(), 2);
        assert_eq!(
            verify_certificate(&weak, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::InsufficientQuorum)
        );
        // ② 恰好达到加权 quorum（150 ≥ 134）⇒ 接受，且仍为单步 +1。
        let exact = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        let t = verify_certificate(&exact, CHAIN_ID, &VSET_ID, &c.set, 2).expect("weighted quorum");
        assert_eq!(t.to_round, 3);
        // ③ 全体 ⇒ 接受。
        let all = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1, 2]);
        assert!(verify_certificate(&all, CHAIN_ID, &VSET_ID, &c.set, 2).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_chain_id() {
        let c = ctx(3, 100);
        let cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID + 1, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_validator_set_id() {
        let c = ctx(3, 100);
        let cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &[0x99; 32], &c.set, 2),
            Err(RoundChangeError::ValidatorSetMismatch)
        );
    }

    #[test]
    fn verify_rejects_unknown_validator() {
        let a = ctx(3, 100);
        let b = ctx(3, 100);
        // 用 b 的成员签名构造证书，却以 a 的 set 校验
        let mut evidence: Vec<RoundChangeEvidence> = (0..2)
            .map(|i| RoundChangeEvidence {
                validator_id: ValidatorId::from_consensus_public_key(
                    &b.kps[i].verifying_key().to_bytes(),
                ),
                signature: sign_abandon(&b.kps[i], CHAIN_ID, 11, 2),
            })
            .collect();
        evidence.sort_by_key(|e| e.validator_id);
        let cert = RoundChangeCertificate {
            validator_set_id: VSET_ID,
            height: 11,
            from_round: 2,
            evidence,
        };
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &a.set, 2),
            Err(RoundChangeError::UnknownValidator)
        );
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let c = ctx(3, 100);
        let mut cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        cert.evidence[0].signature[0] ^= 0xFF;
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_height_binding() {
        let c = ctx(3, 100);
        let mut cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        cert.height = 12; // 签名覆盖 height ⇒ 失效
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_duplicate_and_non_ascending_before_crypto() {
        let c = ctx(3, 100);
        let good = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        // 重复
        let mut dup = good.clone();
        dup.evidence[1].validator_id = dup.evidence[0].validator_id;
        assert_eq!(
            verify_certificate(&dup, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::DuplicateValidator)
        );
        // 逆序
        let mut rev = good.clone();
        rev.evidence.reverse();
        assert_eq!(
            verify_certificate(&rev, CHAIN_ID, &VSET_ID, &c.set, 2),
            Err(RoundChangeError::EvidenceNotAscending)
        );
    }

    #[test]
    fn verify_rejects_stale_certificate() {
        let c = ctx(3, 100);
        let cert = cert_from(&c, CHAIN_ID, 11, 2, &[0, 1]);
        // local_round = 3 ⇒ to_round(3) <= 3 ⇒ REJECT（无 round 回退）
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 3),
            Err(RoundChangeError::StaleCertificate)
        );
        // local_round = 4 ⇒ 同样 REJECT
        assert_eq!(
            verify_certificate(&cert, CHAIN_ID, &VSET_ID, &c.set, 4),
            Err(RoundChangeError::StaleCertificate)
        );
    }

    #[test]
    fn verify_rejects_empty_and_oversized_evidence() {
        let c = ctx(22, 100);
        let empty = RoundChangeCertificate {
            validator_set_id: VSET_ID,
            height: 1,
            from_round: 0,
            evidence: Vec::new(),
        };
        assert_eq!(
            verify_certificate(&empty, CHAIN_ID, &VSET_ID, &c.set, 0),
            Err(RoundChangeError::EmptyEvidence)
        );
        let big = cert_from(&c, CHAIN_ID, 1, 0, &(0..22).collect::<Vec<_>>());
        assert_eq!(
            verify_certificate(&big, CHAIN_ID, &VSET_ID, &c.set, 0),
            Err(RoundChangeError::TooManyEvidence)
        );
    }

    #[test]
    fn store_is_bounded_and_idempotent() {
        let c = ctx(3, 100);
        let mut store = RoundChangeStore::with_caps(2, 3);
        for r in 0..3u64 {
            let cert = cert_from(&c, CHAIN_ID, 10, r, &[0, 1]);
            store.admit(cert);
        }
        assert_eq!(store.certificates_at(10), 3);
        // 第 4 张 ⇒ FIFO 淘汰最早（from_round = 0）
        let cert4 = cert_from(&c, CHAIN_ID, 10, 3, &[0, 1]);
        match store.admit(cert4) {
            AdmitOutcome::Admitted {
                evicted_certificate,
                ..
            } => assert!(evicted_certificate),
            other => panic!("expected Admitted, got {other:?}"),
        }
        assert_eq!(store.certificates_at(10), 3);
        assert!(store.get(10, 0).is_none(), "FIFO 淘汰最早插入项");
        assert!(store.get(10, 3).is_some());
        // 幂等：同一 (height, from_round) 再次准入 ⇒ Duplicate（不增长）
        let dup = cert_from(&c, CHAIN_ID, 10, 1, &[0, 1]);
        assert_eq!(store.admit(dup), AdmitOutcome::Duplicate);
        assert_eq!(store.certificates_at(10), 3);
    }

    #[test]
    fn store_evicts_lowest_height_deterministically() {
        let c = ctx(3, 100);
        let mut store = RoundChangeStore::with_caps(2, 64);
        for h in [5u64, 6] {
            store.admit(cert_from(&c, CHAIN_ID, h, 0, &[0, 1]));
        }
        assert_eq!(store.tracked_heights(), 2);
        // 新 height 7 ⇒ 淘汰最低 height（5），与插入顺序无关
        match store.admit(cert_from(&c, CHAIN_ID, 7, 0, &[0, 1])) {
            AdmitOutcome::Admitted { evicted_height, .. } => assert_eq!(evicted_height, Some(5)),
            other => panic!("expected Admitted, got {other:?}"),
        }
        assert_eq!(store.tracked_heights(), 2);
        assert!(store.get(5, 0).is_none());
        assert!(store.get(7, 0).is_some());
    }

    #[test]
    fn store_default_capacity_is_64_per_height() {
        let store = RoundChangeStore::new(DEFAULT_MAX_TRACKED_HEIGHTS);
        assert_eq!(store.max_per_height, MAX_CERTIFICATES_PER_HEIGHT);
        assert_eq!(MAX_CERTIFICATES_PER_HEIGHT, 64);
        assert_eq!(store.total(), 0);
    }

    #[test]
    fn golden_vector_exact_bytes_and_hash() {
        // **implementation-stage vector**（D1-V = V2）：由本实现的 codec / 签名路径产生。
        let sb = abandon_signed_bytes(1, 2, 3).unwrap();
        assert_eq!(
            sb,
            vec![
                0x01, // algorithm_id = Ed25519
                0x10, // domain_id = RoundChangeCertificate
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // chain_id = 1 (LE)
                0x10, 0x00, 0x00, 0x00, // payload_length = 16 (LE)
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // height = 2 (LE)
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // from_round = 3 (LE)
            ]
        );
        let h = abandon_message_hash(1, 2, 3).unwrap();
        assert_eq!(h.as_bytes().len(), 32);

        // 证书容器 golden：count = 1 ⇒ 146B；header 精确可验
        let cert = RoundChangeCertificate {
            validator_set_id: [0xAB; 32],
            height: 2,
            from_round: 3,
            evidence: vec![RoundChangeEvidence {
                validator_id: ValidatorId::from_bytes([0xCD; 32]),
                signature: [0xEF; 64],
            }],
        };
        let bytes = encode_certificate(&cert).unwrap();
        assert_eq!(bytes.len(), 146);
        assert_eq!(&bytes[0..32], &[0xAB; 32]);
        assert_eq!(&bytes[32..40], &2u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &3u64.to_le_bytes());
        assert_eq!(&bytes[48..50], &1u16.to_le_bytes());
        assert_eq!(&bytes[50..82], &[0xCD; 32]);
        assert_eq!(&bytes[82..146], &[0xEF; 64]);
        assert_eq!(decode_certificate(&bytes).unwrap(), cert);
    }

    #[test]
    fn restart_loses_certificates_no_persistence() {
        let c = ctx(3, 100);
        let mut store = RoundChangeStore::new(8);
        store.admit(cert_from(&c, CHAIN_ID, 4, 0, &[0, 1]));
        assert_eq!(store.total(), 1);
        // "重启" = 新 store（无 journal / 无持久化；R-2 / S1）
        let store2 = RoundChangeStore::new(8);
        assert_eq!(store2.total(), 0);
    }
}
