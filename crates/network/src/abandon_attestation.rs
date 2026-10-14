//! **ADR-0074（FROZEN）** — Individual Abandon Attestation canonical wire container。
//!
//! # 冻结规格（ADR-0074 §6；Owner PHASE 6H-AE D-5）
//!
//! ```text
//! byte offset   field           type        width
//! 0..8          height          u64 LE      8
//! 8..16         from_round      u64 LE      8
//! 16..48        validator_id    [u8;32]     32
//! 48..112       signature       [u8;64]     64
//! TOTAL                                    112 bytes（精确）
//! ```
//!
//! # 边界（MUST）
//! - **精确 112 字节**：短 / 长 / trailing bytes ⇒ 一律拒绝（fail-closed）。
//! - 定长；**禁止**变长 / 可选字段 / 备用编码 / 字段重排 / unknown fields。
//! - `chain_id` / `validator_set_id` / `algorithm_id` / `domain_id` **不进 body**（ADR-0074 §7/§8；
//!   `chain_id` 由 envelope/framework 承载并进入 `build_signed_bytes`；签署域固定 `Ed25519 0x01` / `0x10`）。
//! - 本模块**只**做 canonical 字节（无语义 / 无验签）；验证必须复用
//!   `nova_consensus::round_change::verify_evidence`（ADR-0074 §9；**禁止**第二套验签实现）。
//! - 本模块**不**触碰：Vote / QC / finality / lock / VoteLedger / 任何 journal。

/// 容器精确长度（ADR-0074 §6.1）。
pub const ABANDON_ATTESTATION_LEN: usize = 112;
/// `validator_id` 字段偏移。
pub const VALIDATOR_ID_OFFSET: usize = 16;
/// `signature` 字段偏移。
pub const SIGNATURE_OFFSET: usize = 48;

/// 解码错误（**可区分**；ADR-0074 §17 要求拒因可审计）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonAttestationError {
    /// 长度 ≠ 112（含截断 / 超长 / trailing bytes）。
    InvalidLength {
        /// 期望长度（恒为 112）。
        expected: usize,
        /// 实际长度。
        actual: usize,
    },
}

impl core::fmt::Display for AbandonAttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid attestation length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl core::error::Error for AbandonAttestationError {}

/// 单条 Abandon Attestation 的 canonical wire container（ADR-0074 §6.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbandonAttestation {
    /// 语句高度（∈ 签名范围）。
    pub height: u64,
    /// 被放弃的 round（∈ 签名范围；**无** target round）。
    pub from_round: u64,
    /// `SHA-256(consensus_public_key)`（不进签名 payload；由验签期 identity 检查绑定）。
    pub validator_id: [u8; 32],
    /// Ed25519 `R ‖ S`（64B）。
    pub signature: [u8; 64],
}

/// Canonical 编码（精确 112B；确定性 ⇒ 同输入同字节）。
pub fn encode(attestation: &AbandonAttestation) -> Vec<u8> {
    let mut out = Vec::with_capacity(ABANDON_ATTESTATION_LEN);
    out.extend_from_slice(&attestation.height.to_le_bytes());
    out.extend_from_slice(&attestation.from_round.to_le_bytes());
    out.extend_from_slice(&attestation.validator_id);
    out.extend_from_slice(&attestation.signature);
    debug_assert_eq!(out.len(), ABANDON_ATTESTATION_LEN);
    out
}

/// Canonical 解码（**严格**：长度 ≠ 112 ⇒ 拒绝；无 fallback / 无 trailing 容忍）。
pub fn decode(bytes: &[u8]) -> Result<AbandonAttestation, AbandonAttestationError> {
    if bytes.len() != ABANDON_ATTESTATION_LEN {
        return Err(AbandonAttestationError::InvalidLength {
            expected: ABANDON_ATTESTATION_LEN,
            actual: bytes.len(),
        });
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().expect("len checked"));
    let from_round = u64::from_le_bytes(bytes[8..16].try_into().expect("len checked"));
    let mut validator_id = [0u8; 32];
    validator_id.copy_from_slice(&bytes[VALIDATOR_ID_OFFSET..VALIDATOR_ID_OFFSET + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 64]);
    Ok(AbandonAttestation {
        height,
        from_round,
        validator_id,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AbandonAttestation {
        AbandonAttestation {
            height: 7,
            from_round: 3,
            validator_id: [0xAB; 32],
            signature: [0xCD; 64],
        }
    }

    #[test]
    fn valid_112_byte_canonical_encoding() {
        let bytes = encode(&sample());
        assert_eq!(bytes.len(), ABANDON_ATTESTATION_LEN);
        assert_eq!(bytes.len(), 112);
        // 逐字段偏移（ADR-0074 §6.1）。
        assert_eq!(&bytes[0..8], &7u64.to_le_bytes());
        assert_eq!(&bytes[8..16], &3u64.to_le_bytes());
        assert_eq!(
            &bytes[VALIDATOR_ID_OFFSET..VALIDATOR_ID_OFFSET + 32],
            &[0xAB; 32]
        );
        assert_eq!(&bytes[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 64], &[0xCD; 64]);
        // body 不含 chain_id / validator_set_id / algorithm_id / domain_id（§7/§8）。
        assert_eq!(bytes.len(), 8 + 8 + 32 + 64);
    }

    #[test]
    fn decode_encode_roundtrip_is_exact() {
        let att = sample();
        let bytes = encode(&att);
        assert_eq!(decode(&bytes).expect("decode"), att);
        assert_eq!(encode(&decode(&bytes).expect("decode")), bytes);
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(encode(&sample()), encode(&sample()));
    }

    #[test]
    fn wrong_length_short_rejected() {
        let bytes = encode(&sample());
        for len in [0usize, 1, 8, 16, 48, 111] {
            assert_eq!(
                decode(&bytes[..len]).expect_err("short rejected"),
                AbandonAttestationError::InvalidLength {
                    expected: ABANDON_ATTESTATION_LEN,
                    actual: len
                },
                "len={len}"
            );
        }
    }

    #[test]
    fn wrong_length_long_and_trailing_rejected() {
        let mut bytes = encode(&sample());
        bytes.push(0x00); // 单个 trailing byte
        assert_eq!(
            decode(&bytes).expect_err("trailing rejected"),
            AbandonAttestationError::InvalidLength {
                expected: ABANDON_ATTESTATION_LEN,
                actual: 113
            }
        );
        // 更长输入同样拒绝（无 fallback 截断）。
        let long = vec![0u8; ABANDON_ATTESTATION_LEN + 96];
        assert!(decode(&long).is_err());
    }

    #[test]
    fn extreme_values_roundtrip() {
        let att = AbandonAttestation {
            height: u64::MAX,
            from_round: u64::MAX,
            validator_id: [0xFF; 32],
            signature: [0xFF; 64],
        };
        assert_eq!(decode(&encode(&att)).expect("decode"), att);
    }
}
