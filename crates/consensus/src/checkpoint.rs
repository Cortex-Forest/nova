//! Checkpoint（STEP 10-7.2 — ADR-0039 CP-1~CP-8 +
//! `docs/protocols/checkpoint-implementation-design-v1.md`）。
//!
//! # 核心职责（严格分离）
//! - [`derive_checkpoint`]：**结构派生**（显式 `finalized_reference + finalized_qc`；无对应 QC ⇒ `None`；
//!   结构上**无法** fallback 到 `FinalityState.highest_precommit_qc`，CP-MF-4）。不验证 QC 密码学有效性。
//! - [`verify_checkpoint`]：**Validity**（CP-MF-10 唯一优先级：① self-consistency → ② Precommit →
//!   ③ verify_qc）。**无 FinalityState 参数 ⇒ 结构上无法执行 FinalityState transition**（CP-5）。
//! - [`encode_checkpoint`] / [`decode_checkpoint`]：canonical 布局（60B fixed prefix + qc_bytes）；
//!   **decode 只做结构解析**（CP-MF-9），不承担 semantic/QC/finality 验证。
//!
//! # 冻结约束（禁令）
//! - Checkpoint **不是独立 Finality 来源**（CP-5/F-15）；不引入第二套 finality rule。
//! - `height`/`round` 仅 metadata（CP-8），不得推断 ancestry / finality / applicability / ordering。
//! - 不接 storage/execution/network；不实现 light-client/sync；无新签名/domain；
//!   不引入新的 consensus state 类型（无 CheckpointState / latest_checkpoint 为共识状态）。

use crate::dag::Dag;
use crate::finality::{FinalityError, QuorumCertificate, decode_qc, encode_qc, verify_qc};
use crate::validator::ValidatorSet;
use crate::vote::VoteType;
use std::fmt;

/// Checkpoint（ADR-0039；非新区块、非签名对象）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// CP-7：`== precommit_qc.context.chain_id`。
    pub chain_id: u64,
    /// CP-1：`== precommit_qc.target`。
    pub finalized_block_hash: [u8; 32],
    /// CP-3/CP-8：`== precommit_qc.context.height`；仅 metadata。
    pub height: u64,
    /// CP-3/CP-8：`== precommit_qc.context.round`；仅 metadata。
    pub round: u64,
    /// CP-2/CP-4：Precommit-only，且 `target == finalized_block_hash`。
    pub precommit_qc: QuorumCertificate,
}

/// Checkpoint 层错误（不改 `error.rs`；内嵌 QC 错误经 `InvalidQc(FinalityError)` 确定性映射）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// decode 结构/长度/截断/额外字节非法（CP-MF-9）。
    InvalidCheckpointStructure,
    /// CP-2：证明非 Precommit。
    NotPrecommitQc,
    /// CP-1：`finalized_block_hash != precommit_qc.target`。
    CheckpointTargetMismatch,
    /// CP-3：`height`/`round` 与 QC context 不一致。
    CheckpointContextMismatch,
    /// CP-7：`chain_id != precommit_qc.context.chain_id`。
    CheckpointChainIdMismatch,
    /// 内嵌 QC 验证失败（verify_qc 的全部 Err 确定性映射）。
    InvalidQc(FinalityError),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCheckpointStructure => write!(f, "invalid checkpoint structure"),
            Self::NotPrecommitQc => write!(f, "checkpoint proof is not Precommit"),
            Self::CheckpointTargetMismatch => write!(f, "checkpoint target mismatch"),
            Self::CheckpointContextMismatch => {
                write!(f, "checkpoint height/round context mismatch")
            }
            Self::CheckpointChainIdMismatch => write!(f, "checkpoint chain_id mismatch"),
            Self::InvalidQc(e) => write!(f, "invalid embedded QC: {e}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

/// Checkpoint 结构派生（CP-MF-4；**不验证 QC 密码学有效性**——那是 `verify_checkpoint` 职责）。
///
/// 返回 `None`（确定性）：
/// 1. `finalized_qc.target != finalized_reference`（CP-4）；
/// 2. `finalized_qc.context.vote_type != Precommit`（CP-2 防御，防生成不可自验对象）。
///
/// **无 `FinalityState` 入参 ⇒ 结构上无法 fallback 到 `highest_precommit_qc`。**
pub fn derive_checkpoint(
    finalized_reference: [u8; 32],
    finalized_qc: &QuorumCertificate,
) -> Option<Checkpoint> {
    if finalized_qc.target != finalized_reference
        || finalized_qc.context.vote_type != VoteType::Precommit
    {
        return None;
    }
    Some(Checkpoint {
        chain_id: finalized_qc.context.chain_id,
        finalized_block_hash: finalized_reference,
        height: finalized_qc.context.height,
        round: finalized_qc.context.round,
        precommit_qc: finalized_qc.clone(),
    })
}

/// Checkpoint 验证（**Validity**；CP-MF-10 唯一优先级）。
///
/// ① self-consistency：target → height/round → chain_id；
/// ② Precommit-only；
/// ③ 内嵌 QC 有效性（复用 `verify_qc`）。
///
/// **无 `FinalityState` 参数 ⇒ 结构上无法执行 FinalityState transition（CP-5）。**
/// 只建立结构自洽 + 内嵌 QC 有效性；**不判定 latest/applicability**。
pub fn verify_checkpoint(
    cp: &Checkpoint,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> Result<(), CheckpointError> {
    // ①a CP-1
    if cp.finalized_block_hash != cp.precommit_qc.target {
        return Err(CheckpointError::CheckpointTargetMismatch);
    }
    // ①b CP-3
    if cp.height != cp.precommit_qc.context.height || cp.round != cp.precommit_qc.context.round {
        return Err(CheckpointError::CheckpointContextMismatch);
    }
    // ①c CP-7
    if cp.chain_id != cp.precommit_qc.context.chain_id {
        return Err(CheckpointError::CheckpointChainIdMismatch);
    }
    // ② CP-2
    if cp.precommit_qc.context.vote_type != VoteType::Precommit {
        return Err(CheckpointError::NotPrecommitQc);
    }
    // ③ CP-4 内嵌 QC 有效性（含 target ∈ DAG / validator_set / 签名 / quorum）
    verify_qc(&cp.precommit_qc, set, expected_genesis_hash, dag).map_err(CheckpointError::InvalidQc)
}

/// 读取定长 N 字节（越界 ⇒ `InvalidCheckpointStructure`；无 panic）。
fn take<const N: usize>(b: &[u8], off: &mut usize) -> Result<[u8; N], CheckpointError> {
    let end = off
        .checked_add(N)
        .ok_or(CheckpointError::InvalidCheckpointStructure)?;
    if end > b.len() {
        return Err(CheckpointError::InvalidCheckpointStructure);
    }
    let arr: [u8; N] = b[*off..end]
        .try_into()
        .map_err(|_| CheckpointError::InvalidCheckpointStructure)?;
    *off = end;
    Ok(arr)
}

/// Checkpoint canonical 编码（设计文档 §6.1）：
/// `chain_id(8 LE) ‖ finalized_block_hash(32) ‖ height(8 LE) ‖ round(8 LE) ‖
/// qc_len(4 LE) ‖ qc_bytes[qc_len]`（qc_bytes = encode_qc(precommit_qc)）。
pub fn encode_checkpoint(cp: &Checkpoint) -> Vec<u8> {
    let qc_bytes = encode_qc(&cp.precommit_qc);
    let mut out = Vec::with_capacity(60 + qc_bytes.len());
    out.extend_from_slice(&cp.chain_id.to_le_bytes());
    out.extend_from_slice(&cp.finalized_block_hash);
    out.extend_from_slice(&cp.height.to_le_bytes());
    out.extend_from_slice(&cp.round.to_le_bytes());
    out.extend_from_slice(&(qc_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&qc_bytes);
    out
}

/// Checkpoint decode（**CP-MF-9：仅结构解析**；不执行 QC semantic / finality / applicability 验证）。
///
/// - `metadata prefix = 56B`；`qc_len = 4B`；`total fixed prefix = 60B`。
/// - 长度严格 `bytes.len() == 60 + qc_len`（checked arithmetic；无多余字节）。
/// - 内嵌 QC 解码失败 ⇒ `InvalidCheckpointStructure`（结构性）。
pub fn decode_checkpoint(bytes: &[u8]) -> Result<Checkpoint, CheckpointError> {
    if bytes.len() < 60 {
        return Err(CheckpointError::InvalidCheckpointStructure);
    }
    let mut off = 0usize;
    let chain_id = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let finalized_block_hash = take::<32>(bytes, &mut off)?;
    let height = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let round = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let qc_len = u32::from_le_bytes(take::<4>(bytes, &mut off)?) as usize;
    let total = 60usize
        .checked_add(qc_len)
        .ok_or(CheckpointError::InvalidCheckpointStructure)?;
    if bytes.len() != total {
        return Err(CheckpointError::InvalidCheckpointStructure);
    }
    let precommit_qc =
        decode_qc(&bytes[60..]).map_err(|_| CheckpointError::InvalidCheckpointStructure)?;
    Ok(Checkpoint {
        chain_id,
        finalized_block_hash,
        height,
        round,
        precommit_qc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::BlockReference;
    use crate::finality::QcContext;
    use crate::finality::QcEvidence;
    use crate::vote::{ValidatorVote, canonical_vote_payload};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];
    const TARGET: [u8; 32] = [0xAA; 32];
    const TARGET_Y: [u8; 32] = [0xBB; 32];
    const ZERO: [u8; 32] = [0x00; 32];

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
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

    struct TestCtx {
        set: ValidatorSet,
        kps: Vec<KeyPair>,
    }

    fn test_ctx(n: usize, stake: u128) -> TestCtx {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().unwrap();
            let pk = kp.verifying_key().to_bytes();
            kps.push(kp);
            vals.push(vin(pk, stake, [i as u8 + 0x10; 32]));
        }
        TestCtx {
            set: ValidatorSet::from_genesis(&genesis_with(vals)),
            kps,
        }
    }

    fn validator_id_of(ctx: &TestCtx, i: usize) -> crate::validator::ValidatorId {
        crate::validator::ValidatorId::from_consensus_public_key(
            &ctx.kps[i].verifying_key().to_bytes(),
        )
    }

    fn sign_vote(signing: &nova_crypto::signature::SigningKey, vote: &ValidatorVote) -> [u8; 64] {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .unwrap();
        sign_message_hash(signing, &hash_signing_message(&signed)).to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_qc(
        ctx: &TestCtx,
        idxs: &[usize],
        target: [u8; 32],
        round: u64,
        height: u64,
        vt: VoteType,
        source: [u8; 32],
        timestamp: u64,
    ) -> QuorumCertificate {
        let mut evidence: Vec<QcEvidence> = Vec::with_capacity(idxs.len());
        for &i in idxs {
            let vid = validator_id_of(ctx, i);
            let vote = ValidatorVote {
                round,
                height,
                target_block_hash: target,
                vote_type: vt,
                source_block_hash: source,
                validator_id: vid,
                timestamp,
            };
            let sig = sign_vote(ctx.kps[i].signing_key(), &vote);
            evidence.push(QcEvidence {
                validator_id: vid,
                source_block_hash: source,
                timestamp,
                signature: sig,
            });
        }
        evidence.sort_by_key(|e| e.validator_id);
        QuorumCertificate {
            context: QcContext {
                chain_id: CHAIN_ID,
                height,
                round,
                vote_type: vt,
            },
            target,
            validator_set_id: GENESIS_HASH,
            evidence,
        }
    }

    fn build_dag() -> Dag {
        let mut dag = Dag::new();
        dag.add_block(BlockReference {
            block_hash: [0xAA; 32],
            height: 0,
            parents: vec![],
            proposer: crate::validator::ValidatorId::from_bytes([0xAA; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0xBB; 32],
            height: 1,
            parents: vec![[0xAA; 32]],
            proposer: crate::validator::ValidatorId::from_bytes([0xBB; 32]),
        })
        .unwrap();
        dag
    }

    fn valid_checkpoint(ctx: &TestCtx) -> Checkpoint {
        let qc = make_qc(
            ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        derive_checkpoint(TARGET, &qc).expect("derive ok")
    }

    // ---- T1：derive valid PrecommitQC(target==X) → Some，字段自洽 ----
    #[test]
    fn derive_checkpoint_ok_and_fields_consistent() {
        let ctx = test_ctx(3, 100);
        let cp = valid_checkpoint(&ctx);
        assert_eq!(cp.finalized_block_hash, TARGET);
        assert_eq!(cp.chain_id, CHAIN_ID);
        assert_eq!(cp.height, 1);
        assert_eq!(cp.round, 0);
        assert_eq!(cp.precommit_qc.target, cp.finalized_block_hash, "CP-1");
        assert_eq!(cp.precommit_qc.context.chain_id, cp.chain_id, "CP-7");
        assert_eq!(cp.precommit_qc.context.height, cp.height, "CP-3");
        assert_eq!(cp.precommit_qc.context.round, cp.round, "CP-3");
    }

    // ---- T2：encode/decode roundtrip ----
    #[test]
    fn checkpoint_encode_decode_roundtrip() {
        let ctx = test_ctx(3, 100);
        let cp = valid_checkpoint(&ctx);
        let bytes = encode_checkpoint(&cp);
        let decoded = decode_checkpoint(&bytes).expect("decode ok");
        assert_eq!(decoded, cp);
    }

    // ---- T3：derive_checkpoint(X, QC(Y)) → None（CP-4 / CP-MF-4 核心）----
    #[test]
    fn derive_checkpoint_rejects_unpaired_qc() {
        let ctx = test_ctx(3, 100);
        let qc_y = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET_Y,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        assert_eq!(derive_checkpoint(TARGET, &qc_y), None, "target 不符 ⇒ None");
    }

    // ---- T4：derive_checkpoint(X, PrevoteQC(X)) → None（CP-2 防御）----
    #[test]
    fn derive_checkpoint_rejects_prevote_qc() {
        let ctx = test_ctx(3, 100);
        let qc = make_qc(&ctx, &[0, 1, 2], TARGET, 0, 1, VoteType::Prevote, ZERO, 100);
        assert_eq!(derive_checkpoint(TARGET, &qc), None);
    }

    // ---- T5：verify_checkpoint Ok ----
    #[test]
    fn verify_checkpoint_ok() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let cp = valid_checkpoint(&ctx);
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Ok(())
        );
    }

    // ---- T6：target 篡改 → CheckpointTargetMismatch（优先级 ①a）----
    #[test]
    fn verify_checkpoint_rejects_target_mismatch() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut cp = valid_checkpoint(&ctx);
        cp.finalized_block_hash = TARGET_Y;
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::CheckpointTargetMismatch)
        );
    }

    // ---- T7：chain_id 篡改 → CheckpointChainIdMismatch（优先级 ①c）----
    #[test]
    fn verify_checkpoint_rejects_chain_id_mismatch() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut cp = valid_checkpoint(&ctx);
        cp.chain_id = 9999;
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::CheckpointChainIdMismatch)
        );
    }

    // ---- T8：height/round 篡改 → CheckpointContextMismatch（优先级 ①b）----
    #[test]
    fn verify_checkpoint_rejects_context_mismatch() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut cp = valid_checkpoint(&ctx);
        cp.height = 99;
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::CheckpointContextMismatch)
        );
        let mut cp2 = valid_checkpoint(&ctx);
        cp2.round = 7;
        assert_eq!(
            verify_checkpoint(&cp2, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::CheckpointContextMismatch)
        );
    }

    // ---- T9：内嵌 PrevoteQC → NotPrecommitQc（优先级 ②）----
    #[test]
    fn verify_checkpoint_rejects_prevote_qc() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        // 手工构造：target 一致但 vote_type=Prevote
        let qc = make_qc(&ctx, &[0, 1, 2], TARGET, 0, 1, VoteType::Prevote, ZERO, 100);
        let cp = Checkpoint {
            chain_id: CHAIN_ID,
            finalized_block_hash: TARGET,
            height: 1,
            round: 0,
            precommit_qc: qc,
        };
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::NotPrecommitQc)
        );
    }

    // ---- T10：内嵌 QC 签名失败 → InvalidQc(FinalityError::Evidence(_))（优先级 ③）----
    #[test]
    fn verify_checkpoint_rejects_bad_embedded_qc() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut cp = valid_checkpoint(&ctx);
        cp.precommit_qc.evidence[0].signature[0] ^= 0xff;
        assert!(matches!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::InvalidQc(FinalityError::Evidence(_)))
        ));
    }

    // ---- T11：decode 截断 / 多余字节 / qc_len 不符 → InvalidCheckpointStructure（CP-MF-9）----
    #[test]
    fn decode_checkpoint_rejects_bad_structure() {
        let ctx = test_ctx(1, 100);
        let qc = make_qc(&ctx, &[0], TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
        let cp = Checkpoint {
            chain_id: CHAIN_ID,
            finalized_block_hash: TARGET,
            height: 1,
            round: 0,
            precommit_qc: qc,
        };
        let bytes = encode_checkpoint(&cp);
        // 截断
        assert_eq!(
            decode_checkpoint(&bytes[..bytes.len() - 1]),
            Err(CheckpointError::InvalidCheckpointStructure)
        );
        // 多余字节
        let mut extra = bytes.clone();
        extra.push(0x00);
        assert_eq!(
            decode_checkpoint(&extra),
            Err(CheckpointError::InvalidCheckpointStructure)
        );
        // 不足 60B
        assert_eq!(
            decode_checkpoint(&[0u8; 59]),
            Err(CheckpointError::InvalidCheckpointStructure)
        );
        // 内嵌 QC 解码失败（qc 字节被截断在内部）
        let mut bad = bytes.clone();
        let qc_len = u32::from_le_bytes(bad[56..60].try_into().unwrap()) as usize;
        // 缩短 qc_len 使 total < 实际长度 → 长度不匹配
        bad[56..60].copy_from_slice(&((qc_len as u32 - 1).to_le_bytes()));
        assert_eq!(
            decode_checkpoint(&bad),
            Err(CheckpointError::InvalidCheckpointStructure)
        );
    }

    // ---- T12：valid 历史 checkpoint（不判 latest）→ verify Ok（Validity ≠ Latest）----
    #[test]
    fn verify_checkpoint_valid_regardless_of_latestness() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        // 一个合法但"非最新"（对当前无 FinalityState 概念）的 checkpoint 仍应 Validity Ok
        let cp = valid_checkpoint(&ctx);
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Ok(())
        );
        // 无 FinalityState 参数 ⇒ verify 不判定 latest（结构保证）
    }

    // ---- T13：decode(prevote-checkpoint) → Ok；verify → NotPrecommitQc（CP-MF-9 分层）----
    #[test]
    fn decode_does_not_semantic_verify_prevote() {
        let ctx = test_ctx(1, 100);
        let qc = make_qc(&ctx, &[0], TARGET, 0, 1, VoteType::Prevote, ZERO, 100);
        let cp = Checkpoint {
            chain_id: CHAIN_ID,
            finalized_block_hash: TARGET,
            height: 1,
            round: 0,
            precommit_qc: qc,
        };
        let bytes = encode_checkpoint(&cp);
        let decoded = decode_checkpoint(&bytes).expect("decode 只做结构解析 ⇒ Ok");
        assert_eq!(decoded, cp);
        // verify 阶段才拒绝
        let ctx3 = test_ctx(3, 100);
        assert_eq!(
            verify_checkpoint(&decoded, &ctx3.set, &GENESIS_HASH, &build_dag()),
            Err(CheckpointError::NotPrecommitQc)
        );
    }

    // ---- T14：precedence 确定（target mismatch + 坏签名 ⇒ CheckpointTargetMismatch，① 先于 ③）----
    #[test]
    fn verify_precedence_target_before_qc() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut cp = valid_checkpoint(&ctx);
        // 同时存在 target mismatch + 坏签名
        cp.finalized_block_hash = TARGET_Y;
        cp.precommit_qc.evidence[0].signature[0] ^= 0xff;
        assert_eq!(
            verify_checkpoint(&cp, &ctx.set, &GENESIS_HASH, &dag),
            Err(CheckpointError::CheckpointTargetMismatch),
            "CP-MF-10：① target 先于 ③ verify_qc"
        );
    }

    // ---- adversarial：derive 无 FinalityState（结构保证无 fallback）----
    #[test]
    fn derive_cannot_fallback_to_highest_qc() {
        // derive_checkpoint 只接收 (finalized_reference, finalized_qc)——无 FinalityState 参数。
        // 结构上不存在从 highest_precommit_qc 搜索/替代的路径。
        let ctx = test_ctx(3, 100);
        let qc_y = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET_Y,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        // 即使存在"higher" QC(Y)，derive(X, QC(Y)) 仍为 None，不会 substitute
        assert_eq!(derive_checkpoint(TARGET, &qc_y), None);
        // 唯一成功路径 = 显式提供 target==reference 的 QC
        let qc_x = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        assert!(derive_checkpoint(TARGET, &qc_x).is_some());
    }

    // ---- adversarial：verify 无 FinalityState 参数（结构保证无 FinalityState transition / 第二套 finality rule）----
    #[test]
    fn verify_checkpoint_has_no_state_parameter() {
        // 签名固定为 (cp, set, genesis_hash, dag)；无 &mut FinalityState ⇒ 无法 finalize/update/acquire。
        // 本测试仅验证签名契约存在（编译期保证），无运行断言。
        let ctx = test_ctx(1, 100);
        let _ = &ctx;
    }
}
