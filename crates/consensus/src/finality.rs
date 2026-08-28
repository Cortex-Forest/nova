//! Finality / Quorum Certificate（STEP 10-6.2 — ADR-0038 F-1~F-18 +
//! `docs/protocols/finality-implementation-design-v1.md`）。
//!
//! # 核心职责（严格分离）
//! - [`decode_qc`]：bytes → 结构化 [`QuorumCertificate`]（结构 + evidence 升序；**不**承担验证）。
//! - [`verify_qc`]：**QC Validity**（context / target / validator_set / evidence / quorum）；**不 finalize**。
//! - [`check_finality_applicability`]：**DAG Relation**（same / descendant / ancestor / unrelated）；
//!   仅用 DAG parent relation，**禁止** height/round 推导 ancestry。
//! - [`acquire_lock`]：**Lock transition**（valid PrecommitQC → `LockedState::lock`；不重复完整验证）。
//! - [`update_finalized_reference`]：**Finality state transition**（Advance 更新 / 其余不变；Conflict 非错误）。
//!
//! # 冻结约束（禁令）
//! - `canonical_vote_payload` **不变**；evidence 重建 vote 时 `block_hash = QC.target`（唯一 target）。
//! - `source_block_hash` 仅是签名时 `ValidatorVote.source`，**不**代表 target parent。
//! - Valid-but-inapplicable **≠ Invalid**（返回 `Applicability::Inapplicable{Conflict}`，非 Err）。
//! - 不接入 execution/storage/network；不做 cross-round lock enforcement；不宣称实现层 cross-round safety。

use crate::dag::Dag;
use crate::error::ConsensusError;
use crate::round::LockedState;
use crate::validator::{ValidatorId, ValidatorSet};
use crate::vote::{ValidatorVote, VoteType, verify_vote};
use nova_crypto::signature::VerifyingKey;
use std::collections::HashSet;
use std::fmt;

/// QC 上下文（ADR-0038 F-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QcContext {
    pub chain_id: u64,
    pub height: u64,
    pub round: u64,
    pub vote_type: VoteType,
}

/// QC 投票证据（ADR-0038 F-10；`source_block_hash`/`timestamp`/`validator_id` 为签名内字段，必须携带）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QcEvidence {
    pub validator_id: ValidatorId,
    pub source_block_hash: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
}

/// Quorum Certificate（ADR-0038 F-2；非签名对象，有效性由每条 evidence 的独立签名决定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub context: QcContext,
    /// 唯一投票目标（F-1：Finalized Block = QC.target；evidence 无独立 target）。
    pub target: [u8; 32],
    /// = genesis_hash（F-11）。
    pub validator_set_id: [u8; 32],
    /// 按 `validator_id` 字节升序（F-12；duplicate ⇒ invalid）。
    pub evidence: Vec<QcEvidence>,
}

/// Finality 状态（F-1；`finalized_reference` 非密码学证明——证明由 PrecommitQC 承载）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalityState {
    /// 最新已 final block（仅追踪引用）。
    pub finalized_reference: Option<[u8; 32]>,
    /// 最高 Precommit QC（F-14 恢复事实；node 层维护）。
    pub highest_precommit_qc: Option<QuorumCertificate>,
}

/// Finality 层错误（F-16；不改 `error.rs` 既有 `ConsensusError`——evidence 层经 `Evidence` 包装）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityError {
    /// decode / 结构非法 / evidence 未按 validator_id 升序。
    InvalidQcStructure,
    /// evidence 含重复 validator_id。
    DuplicateValidator,
    /// `validator_set_id` 与期望 `genesis_hash` 不符。
    ValidatorSetMismatch,
    /// `target` 不在 DAG。
    UnknownTarget,
    /// 累计权重 < quorum。
    InsufficientQuorum,
    /// evidence 层错误（映射现有 `ConsensusError`）。
    Evidence(ConsensusError),
}

impl fmt::Display for FinalityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQcStructure => write!(f, "invalid QC structure"),
            Self::DuplicateValidator => write!(f, "duplicate validator in QC evidence"),
            Self::ValidatorSetMismatch => write!(f, "QC validator_set_id mismatch"),
            Self::UnknownTarget => write!(f, "QC target not in DAG"),
            Self::InsufficientQuorum => write!(f, "insufficient quorum weight"),
            Self::Evidence(e) => write!(f, "QC evidence error: {e}"),
        }
    }
}

impl std::error::Error for FinalityError {}

/// Finality 更新模式（F-8）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// `Y == X`：幂等。
    Idempotent,
    /// `Y` descendant of `X`（或初始 finality）：前进。
    Advance,
}

/// 不适用原因（F-8）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InapplicableReason {
    /// `Y` ancestor of `X`：过时。
    Stale,
    /// `Y` unrelated to `X`：冲突（**非错误**，evidence 保留）。
    Conflict,
}

/// Finality applicability（F-6b；`QC valid` ≠ `QC applicable`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    Applicable { mode: UpdateMode },
    Inapplicable { reason: InapplicableReason },
}

/// QC canonical 编码（设计文档 §1.2）：
/// `context(chain_id 8LE ‖ height 8LE ‖ round 8LE ‖ vote_type 1B) ‖ target 32B ‖
/// validator_set_id 32B ‖ count 4LE ‖ count×(validator_id 32B ‖ source 32B ‖ timestamp 8LE ‖ signature 64B)`。
pub fn encode_qc(qc: &QuorumCertificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(93 + qc.evidence.len() * 136);
    out.extend_from_slice(&qc.context.chain_id.to_le_bytes());
    out.extend_from_slice(&qc.context.height.to_le_bytes());
    out.extend_from_slice(&qc.context.round.to_le_bytes());
    out.push(qc.context.vote_type.as_u8());
    out.extend_from_slice(&qc.target);
    out.extend_from_slice(&qc.validator_set_id);
    out.extend_from_slice(&(qc.evidence.len() as u32).to_le_bytes());
    for ev in &qc.evidence {
        out.extend_from_slice(ev.validator_id.as_bytes());
        out.extend_from_slice(&ev.source_block_hash);
        out.extend_from_slice(&ev.timestamp.to_le_bytes());
        out.extend_from_slice(&ev.signature);
    }
    out
}

/// 读取定长 N 字节（越界 ⇒ `InvalidQcStructure`；无 panic）。
fn take<const N: usize>(b: &[u8], off: &mut usize) -> Result<[u8; N], FinalityError> {
    let end = off
        .checked_add(N)
        .ok_or(FinalityError::InvalidQcStructure)?;
    if end > b.len() {
        return Err(FinalityError::InvalidQcStructure);
    }
    let arr: [u8; N] = b[*off..end]
        .try_into()
        .map_err(|_| FinalityError::InvalidQcStructure)?;
    *off = end;
    Ok(arr)
}

/// bytes → 结构化 `QuorumCertificate`（MF-10-6.1-1：`decode_qc` 负责结构 + evidence 升序；
/// **不**执行签名/quorum 验证——由 [`verify_qc`] 负责）。
pub fn decode_qc(bytes: &[u8]) -> Result<QuorumCertificate, FinalityError> {
    let mut off = 0usize;
    let chain_id = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let height = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let round = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
    let vt = take::<1>(bytes, &mut off)?[0];
    let vote_type = VoteType::try_from(vt).map_err(|_| FinalityError::InvalidQcStructure)?;
    let target = take::<32>(bytes, &mut off)?;
    let validator_set_id = take::<32>(bytes, &mut off)?;
    let count = u32::from_le_bytes(take::<4>(bytes, &mut off)?) as usize;
    let ev_bytes = count
        .checked_mul(136)
        .ok_or(FinalityError::InvalidQcStructure)?;
    if bytes.len() != off + ev_bytes {
        return Err(FinalityError::InvalidQcStructure);
    }
    let mut evidence = Vec::with_capacity(count);
    for _ in 0..count {
        let validator_id = ValidatorId::from_bytes(take::<32>(bytes, &mut off)?);
        let source_block_hash = take::<32>(bytes, &mut off)?;
        let timestamp = u64::from_le_bytes(take::<8>(bytes, &mut off)?);
        let signature = take::<64>(bytes, &mut off)?;
        evidence.push(QcEvidence {
            validator_id,
            source_block_hash,
            timestamp,
            signature,
        });
    }
    // F-12：evidence 必须按 validator_id 升序。
    if evidence
        .windows(2)
        .any(|w| w[0].validator_id > w[1].validator_id)
    {
        return Err(FinalityError::InvalidQcStructure);
    }
    Ok(QuorumCertificate {
        context: QcContext {
            chain_id,
            height,
            round,
            vote_type,
        },
        target,
        validator_set_id,
        evidence,
    })
}

/// QC 验证（**Validity，F-6a**；不依赖 current proposal、不 finalize）。
///
/// 步骤：target ∈ DAG → validator_set_id == genesis_hash → evidence 升序 → duplicate ⇒ Err →
/// 逐条重建 `ValidatorVote`（`block_hash = QC.target`，唯一 target）并经 `verify_vote`（V-5 五步）
/// → 累计权重 → quorum。
pub fn verify_qc(
    qc: &QuorumCertificate,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> Result<(), FinalityError> {
    // ① target ∈ DAG（F-6a）
    if !dag.contains(&qc.target) {
        return Err(FinalityError::UnknownTarget);
    }
    // ② validator_set_id（F-11）
    if qc.validator_set_id != *expected_genesis_hash {
        return Err(FinalityError::ValidatorSetMismatch);
    }
    // ③ evidence 升序（F-12）
    if qc
        .evidence
        .windows(2)
        .any(|w| w[0].validator_id > w[1].validator_id)
    {
        return Err(FinalityError::InvalidQcStructure);
    }
    // ④ duplicate validator（F-12）
    if qc
        .evidence
        .windows(2)
        .any(|w| w[0].validator_id == w[1].validator_id)
    {
        return Err(FinalityError::DuplicateValidator);
    }
    // ⑤ 逐条验证 + 权重（F-10 / V-5）
    let mut weight = 0u128;
    for ev in &qc.evidence {
        let info = set
            .info(&ev.validator_id)
            .ok_or(FinalityError::Evidence(ConsensusError::UnknownValidator))?;
        let vk = VerifyingKey::from_bytes(&info.consensus_public_key)
            .map_err(|_| FinalityError::Evidence(ConsensusError::ValidatorIdentityMismatch))?;
        // 重建 vote：`block_hash = QC.target`（唯一 target；evidence 无独立 target）。
        let vote = ValidatorVote {
            round: qc.context.round,
            height: qc.context.height,
            target_block_hash: qc.target,
            vote_type: qc.context.vote_type,
            source_block_hash: ev.source_block_hash,
            validator_id: ev.validator_id,
            timestamp: ev.timestamp,
        };
        verify_vote(&vote, &ev.signature, &vk, qc.context.chain_id, set)
            .map_err(FinalityError::Evidence)?;
        weight = weight.saturating_add(info.voting_weight);
    }
    // ⑥ quorum（V-3：>= ceil(T*2/3)）
    if weight < set.quorum() {
        return Err(FinalityError::InsufficientQuorum);
    }
    Ok(())
}

/// `ancestor` 是否为 `node` 的祖先（沿 DAG parent 边；**仅用 DAG relation**，禁 height/round 推导）。
fn dag_is_ancestor(dag: &Dag, ancestor: &[u8; 32], node: &[u8; 32]) -> bool {
    if node == ancestor {
        return true;
    }
    let mut visited = HashSet::new();
    let mut stack = vec![*node];
    while let Some(cur) = stack.pop() {
        if cur == *ancestor {
            return true;
        }
        if !visited.insert(cur) {
            continue;
        }
        if let Some(parents) = dag.parents_of(&cur) {
            stack.extend(parents.iter().copied());
        }
    }
    false
}

/// Finality applicability（**DAG Relation，F-6b/F-8**；MF-10-6.1-5：仅 DAG ancestry 决定前进）。
///
/// - `finalized == None` → Advance（初始 finality）。
/// - `Y == X` → Idempotent。
/// - `Y` descendant of `X` → Advance。
/// - `Y` ancestor of `X` → Stale。
/// - unrelated → Conflict（**非错误**）。
pub fn check_finality_applicability(
    qc: &QuorumCertificate,
    finalized: Option<&[u8; 32]>,
    dag: &Dag,
) -> Applicability {
    let y = qc.target;
    match finalized {
        None => Applicability::Applicable {
            mode: UpdateMode::Advance,
        },
        Some(x) => {
            if y == *x {
                Applicability::Applicable {
                    mode: UpdateMode::Idempotent,
                }
            } else if dag_is_ancestor(dag, x, &y) {
                // X 是 Y 的祖先 ⇒ Y descendant of X
                Applicability::Applicable {
                    mode: UpdateMode::Advance,
                }
            } else if dag_is_ancestor(dag, &y, x) {
                // Y 是 X 的祖先 ⇒ 过时
                Applicability::Inapplicable {
                    reason: InapplicableReason::Stale,
                }
            } else {
                Applicability::Inapplicable {
                    reason: InapplicableReason::Conflict,
                }
            }
        }
    }
}

/// Lock transition（MF-10-6.1-4/F-7）：**valid PrecommitQC → Lock**。
///
/// 前置契约：调用方已 `verify_qc` Ok 且 `qc.context.vote_type == Precommit`；
/// **本函数不重复执行完整 QC 验证**，只做 `LockedState::lock(qc.target, qc.context.round)`。
pub fn acquire_lock(lock: &mut LockedState, qc: &QuorumCertificate) {
    lock.lock(qc.target, qc.context.round);
}

/// Finality state transition（F-6c/MF-10-6.1-6）。
///
/// - `Advance`：更新 `state.finalized_reference = Some(qc.target)`。
/// - `Idempotent` / `Stale` / `Conflict`：**不改变状态**。
/// - **`Conflict` 不是错误**：返回 `Ok(())`，evidence 由调用方保留。
pub fn update_finalized_reference(
    state: &mut FinalityState,
    qc: &QuorumCertificate,
    applicability: Applicability,
) -> Result<(), FinalityError> {
    match applicability {
        Applicability::Applicable {
            mode: UpdateMode::Advance,
        } => {
            state.finalized_reference = Some(qc.target);
            Ok(())
        }
        Applicability::Applicable {
            mode: UpdateMode::Idempotent,
        }
        | Applicability::Inapplicable { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::BlockReference;
    use crate::vote::canonical_vote_payload;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use proptest::prelude::*;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];
    const TARGET: [u8; 32] = [0xAA; 32];
    const TARGET_B: [u8; 32] = [0xBB; 32];
    const TARGET_C: [u8; 32] = [0xCC; 32];
    const TARGET_X: [u8; 32] = [0x11; 32];
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

    fn validator_id_of(ctx: &TestCtx, i: usize) -> ValidatorId {
        ValidatorId::from_consensus_public_key(&ctx.kps[i].verifying_key().to_bytes())
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

    /// DAG：A(0) → B(1) → C(2)；X(0) 独立分支。
    fn build_dag() -> Dag {
        let mut dag = Dag::new();
        dag.add_block(BlockReference {
            block_hash: [0xAA; 32],
            height: 0,
            parents: vec![],
            proposer: ValidatorId::from_bytes([0xAA; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0xBB; 32],
            height: 1,
            parents: vec![[0xAA; 32]],
            proposer: ValidatorId::from_bytes([0xBB; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0xCC; 32],
            height: 2,
            parents: vec![[0xBB; 32]],
            proposer: ValidatorId::from_bytes([0xCC; 32]),
        })
        .unwrap();
        dag.add_block(BlockReference {
            block_hash: [0x11; 32],
            height: 0,
            parents: vec![],
            proposer: ValidatorId::from_bytes([0x11; 32]),
        })
        .unwrap();
        dag
    }

    // ---- T1：verify_qc Ok（多 validator 达 quorum）----
    #[test]
    fn verify_qc_ok_with_quorum() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Ok(()),
            "3×100 → total 300 → quorum 200，应通过"
        );
    }

    // ---- T2：仅凭 QC 独立验证（BLOCKER 1 回归）+ decode/encode roundtrip ----
    #[test]
    fn qc_independent_verify_and_roundtrip() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        let bytes = encode_qc(&qc);
        let decoded = decode_qc(&bytes).expect("decode ok");
        assert_eq!(decoded, qc, "roundtrip 还原");
        assert_eq!(
            verify_qc(&decoded, &ctx.set, &GENESIS_HASH, &dag),
            Ok(()),
            "无原始 Vote 对象仍可独立验证"
        );
    }

    // ---- T3：篡改 evidence ⇒ 签名失效 ----
    #[test]
    fn verify_qc_rejects_tampered_evidence() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let base = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );

        // signature 篡改
        let mut qc = base.clone();
        qc.evidence[0].signature[0] ^= 0xff;
        assert!(matches!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::Evidence(_))
        ));

        // source_block_hash 篡改（仅签名元数据，不代表 target parent）
        let mut qc = base.clone();
        qc.evidence[0].source_block_hash[0] ^= 0xff;
        assert!(matches!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::Evidence(_))
        ));

        // timestamp 篡改
        let mut qc = base.clone();
        qc.evidence[0].timestamp += 1;
        assert!(matches!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::Evidence(_))
        ));

        // target 篡改为 DAG 中另一块 ⇒ evidence 签名针对新 target 失效
        let mut qc = base.clone();
        qc.target = TARGET_B;
        assert!(matches!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::Evidence(_))
        ));
    }

    // ---- T4：evidence 乱序 ⇒ InvalidQcStructure ----
    #[test]
    fn verify_qc_rejects_unordered_evidence() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        qc.evidence.reverse();
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::InvalidQcStructure)
        );
    }

    // ---- T5：duplicate validator ⇒ DuplicateValidator ----
    #[test]
    fn verify_qc_rejects_duplicate_validator() {
        let ctx = test_ctx(2, 100);
        let dag = build_dag();
        // 两个 validator 构造证据，然后复制 validator[0] 的证据造成重复
        let mut qc = make_qc(&ctx, &[0, 1], TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
        let dup = qc.evidence[0];
        qc.evidence.push(dup);
        qc.evidence.sort_by_key(|e| e.validator_id);
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::DuplicateValidator)
        );
    }

    // ---- T6：权重差一 ⇒ InsufficientQuorum ----
    #[test]
    fn verify_qc_rejects_insufficient_quorum() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        // 单 validator 100 < quorum 200
        let qc = make_qc(&ctx, &[0], TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::InsufficientQuorum)
        );
    }

    // ---- T7：validator_set_id 不符 ⇒ ValidatorSetMismatch ----
    #[test]
    fn verify_qc_rejects_validator_set_mismatch() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        qc.validator_set_id = [0x43; 32];
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::ValidatorSetMismatch)
        );
    }

    // ---- T8：target 不在 DAG ⇒ UnknownTarget ----
    #[test]
    fn verify_qc_rejects_unknown_target() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let qc = make_qc(
            &ctx,
            &[0, 1, 2],
            [0x99; 32],
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::UnknownTarget)
        );
    }

    // ---- T9：跨 chain_id ⇒ 签名失效 ----
    #[test]
    fn verify_qc_rejects_wrong_chain_id() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let mut qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        qc.context.chain_id = 9999; // 签名是针对 1001 的
        assert_eq!(
            verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag),
            Err(FinalityError::Evidence(ConsensusError::InvalidSignature))
        );
    }

    // ---- T10：applicability 四态（仅 DAG relation）----
    #[test]
    fn applicability_uses_dag_relation_only() {
        let dag = build_dag();
        let precommit = VoteType::Precommit;

        // same → Idempotent
        let qc = make_qc(&test_ctx(1, 100), &[0], TARGET, 0, 1, precommit, ZERO, 100);
        assert_eq!(
            check_finality_applicability(&qc, Some(&TARGET), &dag),
            Applicability::Applicable {
                mode: UpdateMode::Idempotent
            }
        );

        // descendant（B descendant of A）→ Advance
        let qc_b = make_qc(
            &test_ctx(1, 100),
            &[0],
            TARGET_B,
            0,
            1,
            precommit,
            ZERO,
            100,
        );
        assert_eq!(
            check_finality_applicability(&qc_b, Some(&TARGET), &dag),
            Applicability::Applicable {
                mode: UpdateMode::Advance
            }
        );

        // ancestor（A ancestor of B）→ Stale
        assert_eq!(
            check_finality_applicability(&qc, Some(&TARGET_B), &dag),
            Applicability::Inapplicable {
                reason: InapplicableReason::Stale
            }
        );

        // unrelated（X vs A）→ Conflict
        let qc_x = make_qc(
            &test_ctx(1, 100),
            &[0],
            TARGET_X,
            0,
            1,
            precommit,
            ZERO,
            100,
        );
        assert_eq!(
            check_finality_applicability(&qc_x, Some(&TARGET), &dag),
            Applicability::Inapplicable {
                reason: InapplicableReason::Conflict
            }
        );

        // 无 finalized → Advance（初始）
        assert_eq!(
            check_finality_applicability(&qc, None, &dag),
            Applicability::Applicable {
                mode: UpdateMode::Advance
            }
        );
    }

    // ---- T11：valid-but-inapplicable 非错误；evidence 保留；finalized 不变 ----
    #[test]
    fn valid_but_inapplicable_is_not_error() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        // X 与 A 无关，但 QC 完全有效
        let qc_x = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET_X,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        assert_eq!(verify_qc(&qc_x, &ctx.set, &GENESIS_HASH, &dag), Ok(()));

        let mut fs = FinalityState {
            finalized_reference: Some(TARGET),
            highest_precommit_qc: None,
        };
        let app = check_finality_applicability(&qc_x, fs.finalized_reference.as_ref(), &dag);
        assert_eq!(
            app,
            Applicability::Inapplicable {
                reason: InapplicableReason::Conflict
            }
        );
        // Conflict → Ok（非 Err），finalized 不变
        assert_eq!(update_finalized_reference(&mut fs, &qc_x, app), Ok(()));
        assert_eq!(fs.finalized_reference, Some(TARGET), "不得更新");
        // evidence 保留：QC 仍可被验证（历史证据）
        assert_eq!(verify_qc(&qc_x, &ctx.set, &GENESIS_HASH, &dag), Ok(()));
    }

    // ---- T12：acquire_lock（唯一来源 valid PrecommitQC）----
    #[test]
    fn acquire_lock_from_precommit_qc() {
        let ctx = test_ctx(3, 100);
        let qc = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET_B,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        let mut lock = LockedState::new();
        acquire_lock(&mut lock, &qc);
        assert!(lock.is_locked());
        assert_eq!(lock.locked_block_hash, Some(TARGET_B));
        assert_eq!(lock.locked_round, Some(0));
        // is_compatible：same / descendant OK；unrelated reject（B-5）
        assert!(lock.is_compatible(&TARGET_B, &[]), "same ⇒ OK");
        assert!(
            lock.is_compatible(&TARGET_C, &[[0xBB; 32]]),
            "descendant（parents 含 locked）⇒ OK"
        );
        assert!(
            !lock.is_compatible(&TARGET_X, &[[0xAA; 32]]),
            "unrelated ⇒ reject"
        );
    }

    // ---- T13：equivocation evidence 保留（同 validator 两 target）----
    #[test]
    fn equivocation_evidence_retained_across_targets() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag();
        let qc_a = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        let qc_b = make_qc(
            &ctx,
            &[0, 1, 2],
            TARGET_B,
            0,
            1,
            VoteType::Precommit,
            ZERO,
            100,
        );
        // validator[0] 同时出现在两个不同 target 的 QC evidence（equivocation 证据）
        let v0 = validator_id_of(&ctx, 0);
        assert!(qc_a.evidence.iter().any(|e| e.validator_id == v0));
        assert!(qc_b.evidence.iter().any(|e| e.validator_id == v0));
        // 两个 QC 各自独立合法（不因 equivocation 丢弃）
        assert_eq!(verify_qc(&qc_a, &ctx.set, &GENESIS_HASH, &dag), Ok(()));
        assert_eq!(verify_qc(&qc_b, &ctx.set, &GENESIS_HASH, &dag), Ok(()));
    }

    // ---- T15：decode 拒坏结构 ----
    #[test]
    fn decode_qc_rejects_bad_structure() {
        // 空
        assert_eq!(decode_qc(&[]), Err(FinalityError::InvalidQcStructure));
        // 截断（只有头）
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(decode_qc(&bytes), Err(FinalityError::InvalidQcStructure));
        // 未知 vote_type
        let ctx = test_ctx(1, 100);
        let qc = make_qc(&ctx, &[0], TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
        let mut b = encode_qc(&qc);
        // vote_type 位于 chain_id(8)+height(8)+round(8) 之后
        b[24] = 0x00;
        assert_eq!(decode_qc(&b), Err(FinalityError::InvalidQcStructure));
        b[24] = 0x03;
        assert_eq!(decode_qc(&b), Err(FinalityError::InvalidQcStructure));
        // 乱序 evidence（交换两个不同 validator 的证据）
        let ctx2 = test_ctx(2, 100);
        let mut qc2 = make_qc(&ctx2, &[0, 1], TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
        qc2.evidence.swap(0, 1);
        assert_eq!(
            decode_qc(&encode_qc(&qc2)),
            Err(FinalityError::InvalidQcStructure)
        );
    }

    // ---- T14：proptest ----
    proptest! {
        // decode 成功 ⟹ encode 精确还原（canonical 唯一性）
        #[test]
        fn decode_ok_implies_canonical_roundtrip(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            if let Ok(qc) = decode_qc(&bytes) {
                prop_assert_eq!(encode_qc(&qc), bytes);
            }
        }

        // quorum 边界：随机子集 verify Ok ⟺ 权重 >= quorum
        #[test]
        fn quorum_boundary(
            subset in prop::collection::vec(0..3usize, 0..3),
        ) {
            let ctx = test_ctx(3, 100);
            let dag = build_dag();
            let mut idxs: Vec<usize> = subset;
            idxs.sort_unstable();
            idxs.dedup();
            let qc = make_qc(&ctx, &idxs, TARGET, 0, 1, VoteType::Precommit, ZERO, 100);
            let weight: u128 = idxs.iter().map(|&i| ctx.set.weight_of(&validator_id_of(&ctx, i)).unwrap()).sum();
            let res = verify_qc(&qc, &ctx.set, &GENESIS_HASH, &dag);
            if weight >= ctx.set.quorum() {
                prop_assert!(res.is_ok(), "weight {weight} >= quorum {} 应通过", ctx.set.quorum());
            } else {
                prop_assert_eq!(res, Err(FinalityError::InsufficientQuorum));
            }
        }
    }
}
