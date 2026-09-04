//! ValidatorActor / LocalVoteContext（STEP 10-15L；ADR-0053 validator-local vote production）。
//!
//! - [`LocalVoteContext`]：**validator-local** 授权上下文 —— 拥有 `ValidatorId` + `LockedState`；
//!   只回答「本 validator 当前是否允许产生该 vote」（authorize）。
//! - [`ValidatorActor`]：orchestration 层 —— 拥有 / 协调 `LocalVoteContext` 与 `SigningCapability`；
//!   标准流程：authorize → construct `ValidatorVote` → canonical payload → domain separation →
//!   `SigningMessageHash` → sign → 标准 [`ConsensusEvent::Vote`]。
//!
//! # 安全边界（ADR-0053 / STEP 10-15G）
//! - 本地 lock **只约束本 validator 自己的投票**；绝不用作远程 Vote 拒收。
//! - `LocalVoteContext` 不持有 SigningCapability / KeyPair / 私钥字节 / FinalityState /
//!   VoteAccumulator / QC registry / global DAG / ValidatorSet mutation（非第二个 ConsensusState）。
//! - signer 身份（`public_key`）在 [`ValidatorActor::new`] 与 configured `ValidatorId` 比对：
//!   失配 ⇒ `Err(IdentityMismatch)`（NO VOTE / NO SIGN / NO EVENT）。
//! - 依赖方向：node → consensus / crypto；不新增第二套 consensus event。

use nova_consensus::dag::Dag;
use nova_consensus::finality::{FinalityError, QuorumCertificate, acquire_lock};
use nova_consensus::integration::ConsensusEvent;
use nova_consensus::round::LockedState;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};

use crate::signer::SigningCapability;

/// ValidatorActor 构造错误（node operational）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorActorError {
    /// configured `ValidatorId` 与 signer 公钥派生身份不一致（wrong-key：禁止投票/签名/发事件）。
    IdentityMismatch,
}

/// 本地投票授权决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalVoteDecision {
    Authorized,
    Rejected(LocalRejectReason),
}

/// 本地授权拒绝原因（仅本地投票授权；非 remote consensus rejection）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRejectReason {
    /// validator 不在 `ValidatorSet`（成员校验）。
    NotMember,
    /// `vote.validator_id` 与本地 validator 不一致。
    IdentityMismatch,
    /// 与本地 `LockedState` 冲突（unrelated / ancestor / unknown；ADR-0053 L-4）。
    LockConflict,
}

/// 一次本地投票的输入（不含 validator_id —— actor 以自身身份填充）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalVoteRequest {
    pub height: u64,
    pub round: u64,
    pub target_block_hash: [u8; 32],
    pub vote_type: VoteType,
    pub source_block_hash: [u8; 32],
    pub timestamp: u64,
}

/// 本地投票授权上下文（validator-local；MUST OWN = ValidatorId + LockedState）。
pub struct LocalVoteContext {
    validator_id: ValidatorId,
    locked_state: LockedState,
}

impl LocalVoteContext {
    pub fn new(validator_id: ValidatorId) -> Self {
        Self {
            validator_id,
            locked_state: LockedState::new(),
        }
    }

    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub fn locked_state(&self) -> &LockedState {
        &self.locked_state
    }

    /// 判断本 validator 是否允许产生该 vote：
    /// ① membership（`set.contains`）→ ② identity（`vote.validator_id == self`）→
    /// ③ lock compatibility（unlocked ⇒ OK；same ⇒ OK；full transitive DAG descendant ⇒ OK；
    ///    unrelated / ancestor / unknown ⇒ `LockConflict`；ADR-0053 L-4 / dag::is_ancestor）。
    pub fn authorize_vote(
        &self,
        vote: &ValidatorVote,
        set: &ValidatorSet,
        dag: &Dag,
    ) -> LocalVoteDecision {
        if !set.contains(&self.validator_id) {
            return LocalVoteDecision::Rejected(LocalRejectReason::NotMember);
        }
        if vote.validator_id != self.validator_id {
            return LocalVoteDecision::Rejected(LocalRejectReason::IdentityMismatch);
        }
        match self.locked_state.locked_block_hash {
            None => LocalVoteDecision::Authorized,
            Some(locked) => {
                // 兼容：same block（L-5）或 locked 的 full-transitive DAG descendant（L-6，
                // dag.is_ancestor 自包含 ⇒ same block 亦为 Authorized）。
                let lock_compatible = dag.is_ancestor(&locked, &vote.target_block_hash);
                if lock_compatible {
                    LocalVoteDecision::Authorized
                } else {
                    LocalVoteDecision::Rejected(LocalRejectReason::LockConflict)
                }
            }
        }
    }
}

/// 验证者参与者：validator-local 投票的编排层（owns LocalVoteContext + SigningCapability）。
pub struct ValidatorActor<S: SigningCapability> {
    context: LocalVoteContext,
    signer: S,
    chain_id: u64,
}

impl<S: SigningCapability> ValidatorActor<S> {
    /// 构造：校验 signer 公钥派生的 `ValidatorId` 与 configured id 一致（wrong-key 保护，sign 前）。
    pub fn new(
        validator_id: ValidatorId,
        signer: S,
        chain_id: u64,
    ) -> Result<Self, ValidatorActorError> {
        let derived = ValidatorId::from_consensus_public_key(&signer.public_key().to_bytes());
        if derived != validator_id {
            return Err(ValidatorActorError::IdentityMismatch);
        }
        Ok(Self {
            context: LocalVoteContext::new(validator_id),
            signer,
            chain_id,
        })
    }

    pub fn validator_id(&self) -> ValidatorId {
        self.context.validator_id()
    }

    pub fn locked_state(&self) -> &LockedState {
        self.context.locked_state()
    }

    /// 收到并验证 valid `PrecommitQC` 时推进本地 lock（validator-local；经 consensus `acquire_lock`
    /// L-8 guard；**不改** FinalityState —— global finality 由 Finality pipeline 管理）。
    pub fn on_verified_precommit_qc(
        &mut self,
        qc: &QuorumCertificate,
        dag: &Dag,
    ) -> Result<(), FinalityError> {
        acquire_lock(&mut self.context.locked_state, qc, dag)
    }

    /// 组装并签名一条本地投票（authorize → construct → canonical → domain → hash → sign）。
    /// 任一授权 / 签名失败 ⇒ `None`（不产生 `ConsensusEvent`，无旁路 event path）。
    pub fn produce_vote(
        &self,
        request: &LocalVoteRequest,
        set: &ValidatorSet,
        dag: &Dag,
    ) -> Option<ConsensusEvent> {
        let vote = ValidatorVote {
            round: request.round,
            height: request.height,
            target_block_hash: request.target_block_hash,
            vote_type: request.vote_type,
            source_block_hash: request.source_block_hash,
            validator_id: self.context.validator_id,
            timestamp: request.timestamp,
        };
        if self.context.authorize_vote(&vote, set, dag) != LocalVoteDecision::Authorized {
            return None;
        }
        // domain separation（ADR-0009/0010/0013）：canonical_vote_payload → build_signed_bytes →
        // hash_signing_message → sign（绝不签 raw bytes / Debug / JSON）。
        let payload = canonical_vote_payload(&vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            self.chain_id,
            &payload,
        )
        .ok()?;
        let message_hash = hash_signing_message(&signed);
        let signature = self.signer.sign(&message_hash).ok()?;
        Some(ConsensusEvent::Vote {
            vote,
            signature: signature.to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::dag::BlockReference;
    use nova_consensus::finality::QcContext;
    use nova_consensus::vote::canonical_vote_payload;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::SigningMessageHash;
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};

    use crate::signer::SoftwareSigner;

    const CHAIN_ID: u64 = 1001;

    // ---------- fixtures ----------

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
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

    fn vid_of(kp: &KeyPair) -> ValidatorId {
        ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
    }

    /// 生成 n 个等 stake 验证者的 (KeyPair, ValidatorSet)。
    fn make_ctx(n: usize) -> (Vec<KeyPair>, ValidatorSet) {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().unwrap();
            let pk = kp.verifying_key().to_bytes();
            kps.push(kp);
            vals.push(ValidatorInit {
                account_address: addr([i as u8 + 0x10; 32]),
                consensus_public_key: pk,
                bonded_stake: 100,
                commission_bps: 100,
            });
        }
        let set = ValidatorSet::from_genesis(&genesis_with(vals));
        (kps, set)
    }

    /// DAG：A(0xAA,h0) → B(0xBB,h1) → C(0xCC,h2)；X(0x11,h0) 独立 root。
    fn build_dag() -> Dag {
        let mut dag = Dag::new();
        let blocks: &[(u8, u64, Vec<u8>)] = &[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
            (0x11, 0, vec![]),
        ];
        for (hash, height, parents) in blocks {
            dag.add_block(BlockReference {
                block_hash: [*hash; 32],
                height: *height,
                parents: parents.iter().map(|p| [*p; 32]).collect(),
                proposer: ValidatorId::from_bytes([*hash; 32]),
            })
            .unwrap();
        }
        dag
    }

    /// 构造 **结构为** Precommit 的 QC（dummy evidence：`acquire_lock` 只依赖 target / round /
    /// vote_type / dag —— evidence 验证由 caller 的 verify_qc 负责，本测试不伪造真签名）。
    fn make_precommit_qc(target: [u8; 32], round: u64, height: u64) -> QuorumCertificate {
        QuorumCertificate {
            context: QcContext {
                chain_id: CHAIN_ID,
                height,
                round,
                vote_type: VoteType::Precommit,
            },
            target,
            validator_set_id: [0x42; 32],
            evidence: Vec::new(),
        }
    }

    fn vote_req(target: [u8; 32], vt: VoteType) -> LocalVoteRequest {
        LocalVoteRequest {
            height: 0,
            round: 0,
            target_block_hash: target,
            vote_type: vt,
            source_block_hash: [0u8; 32],
            timestamp: 0,
        }
    }

    fn msg_hash_of(vote: &ValidatorVote) -> SigningMessageHash {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .unwrap();
        hash_signing_message(&signed)
    }

    /// 构造身份与 kp 匹配的 actor（move kp 进 SoftwareSigner；KeyPair 无 Clone）；返回公钥供验证。
    fn actor_of(kp: KeyPair) -> (ValidatorActor<SoftwareSigner>, VerifyingKey) {
        let vk = *kp.verifying_key();
        let id = ValidatorId::from_consensus_public_key(&vk.to_bytes());
        let actor = ValidatorActor::new(id, SoftwareSigner::new(kp), CHAIN_ID).unwrap();
        (actor, vk)
    }

    // ---------- identity ----------

    #[test]
    fn actor_accepts_matching_signer_identity() {
        let (mut kps, _set) = make_ctx(1);
        let (_actor, vk) = actor_of(kps.remove(0));
        assert_eq!(
            vk.to_bytes().len(),
            32,
            "signer 公钥有效；身份匹配 ⇒ 构造成功"
        );
    }

    #[test]
    fn actor_rejects_mismatched_signer_identity() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        // configured id = a，signer = b ⇒ IdentityMismatch（NO VOTE / NO SIGN / NO EVENT）
        let id_a = vid_of(&a);
        let signer_b = SoftwareSigner::new(b);
        assert!(
            matches!(
                ValidatorActor::new(id_a, signer_b, CHAIN_ID),
                Err(ValidatorActorError::IdentityMismatch)
            ),
            "wrong-key ⇒ 构造拒绝"
        );
    }

    // ---------- LocalVoteContext lock rules ----------

    fn auth_ctx(
        ctx: &LocalVoteContext,
        target: [u8; 32],
        set: &ValidatorSet,
        dag: &Dag,
    ) -> LocalVoteDecision {
        let vote = ValidatorVote {
            round: 0,
            height: 0,
            target_block_hash: target,
            vote_type: VoteType::Prevote,
            source_block_hash: [0u8; 32],
            validator_id: ctx.validator_id(),
            timestamp: 0,
        };
        ctx.authorize_vote(&vote, set, dag)
    }

    #[test]
    fn unlocked_allows_valid_local_vote() {
        let (kps, set) = make_ctx(1);
        let dag = build_dag();
        let ctx = LocalVoteContext::new(vid_of(&kps[0]));
        assert_eq!(
            auth_ctx(&ctx, [0xAA; 32], &set, &dag),
            LocalVoteDecision::Authorized
        );
    }

    #[test]
    fn locked_same_block_allowed() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor, _vk) = actor_of(kps.remove(0));
        let qc = make_precommit_qc([0xAA; 32], 0, 0);
        actor.on_verified_precommit_qc(&qc, &dag).unwrap();
        assert_eq!(actor.locked_state().locked_block_hash, Some([0xAA; 32]));
        let ev = actor.produce_vote(&vote_req([0xAA; 32], VoteType::Prevote), &set, &dag);
        assert!(ev.is_some(), "same block ⇒ allowed");
    }

    #[test]
    fn locked_descendant_allowed() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor, _vk) = actor_of(kps.remove(0));
        let qc = make_precommit_qc([0xAA; 32], 0, 0);
        actor.on_verified_precommit_qc(&qc, &dag).unwrap();
        // full transitive descendant C(0xCC) of A(0xAA)：A→B→C
        let ev = actor.produce_vote(&vote_req([0xCC; 32], VoteType::Prevote), &set, &dag);
        assert!(ev.is_some(), "full transitive descendant ⇒ allowed");
    }

    #[test]
    fn locked_unrelated_branch_rejected() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor, _vk) = actor_of(kps.remove(0));
        let qc = make_precommit_qc([0xAA; 32], 0, 0);
        actor.on_verified_precommit_qc(&qc, &dag).unwrap();
        let ev = actor.produce_vote(&vote_req([0x11; 32], VoteType::Prevote), &set, &dag);
        assert!(ev.is_none(), "unrelated branch ⇒ 本地不授权（无 event）");
    }

    #[test]
    fn locked_ancestor_branch_rejected() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor, _vk) = actor_of(kps.remove(0));
        // lock B(0xBB,h1)；target A(0xAA) 是 B 的 ancestor ⇒ is_ancestor(B,A)=false ⇒ reject
        let qc = make_precommit_qc([0xBB; 32], 0, 1);
        actor.on_verified_precommit_qc(&qc, &dag).unwrap();
        assert_eq!(actor.locked_state().locked_block_hash, Some([0xBB; 32]));
        let ev = actor.produce_vote(&vote_req([0xAA; 32], VoteType::Prevote), &set, &dag);
        assert!(ev.is_none(), "ancestor ⇒ 本地不授权");
    }

    #[test]
    fn not_member_rejected() {
        let (_kps, set) = make_ctx(1);
        let outsider_kp = KeyPair::generate().unwrap();
        let dag = build_dag();
        let outsider = vid_of(&outsider_kp);
        assert!(!set.contains(&outsider));
        let ctx = LocalVoteContext::new(outsider);
        assert_eq!(
            auth_ctx(&ctx, [0xAA; 32], &set, &dag),
            LocalVoteDecision::Rejected(LocalRejectReason::NotMember)
        );
    }

    #[test]
    fn authorize_rejects_foreign_validator_id() {
        let (kps, set) = make_ctx(2);
        let dag = build_dag();
        let ctx = LocalVoteContext::new(vid_of(&kps[0]));
        let vote = ValidatorVote {
            round: 0,
            height: 0,
            target_block_hash: [0xAA; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0u8; 32],
            validator_id: vid_of(&kps[1]), // 不同 validator
            timestamp: 0,
        };
        assert_eq!(
            ctx.authorize_vote(&vote, &set, &dag),
            LocalVoteDecision::Rejected(LocalRejectReason::IdentityMismatch)
        );
    }

    // ---------- actor signing + event equivalence ----------

    #[test]
    fn actor_signed_vote_verifies_and_is_standard_event() {
        let (mut kps, set) = make_ctx(1);
        let dag = build_dag();
        let (actor, vk) = actor_of(kps.remove(0));
        let ev = actor
            .produce_vote(&vote_req([0xAA; 32], VoteType::Prevote), &set, &dag)
            .expect("unlocked 应授权");
        match ev {
            ConsensusEvent::Vote { vote, signature } => {
                assert_eq!(vote.validator_id, actor.validator_id());
                // 签名可被 signer 公钥验证（domain separation 保留：msg = msg_hash_of(vote)）
                let sig = Signature::from_bytes(&signature).unwrap();
                let msg = msg_hash_of(&vote);
                assert_eq!(verify_message_hash(&vk, &msg, &sig), Ok(()));
            }
            other => panic!("produce_vote 必须产出标准 ConsensusEvent::Vote，got {other:?}"),
        }
    }

    #[test]
    fn rejection_produces_no_event() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor, _vk) = actor_of(kps.remove(0));
        let qc = make_precommit_qc([0xAA; 32], 0, 0);
        actor.on_verified_precommit_qc(&qc, &dag).unwrap();
        // 与本地 lock 冲突的 target ⇒ None（无 event）
        assert!(
            actor
                .produce_vote(&vote_req([0x11; 32], VoteType::Prevote), &set, &dag)
                .is_none()
        );
    }

    // ---------- multi-validator isolation ----------

    #[test]
    fn multi_validator_lock_isolation() {
        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (mut actor_a, _) = actor_of(kps.remove(0));
        let (actor_b, _) = actor_of(kps.remove(0));
        assert_ne!(actor_a.validator_id(), actor_b.validator_id());
        // A 锁 AA；B lock 不受影响
        let qc_a = make_precommit_qc([0xAA; 32], 0, 0);
        actor_a.on_verified_precommit_qc(&qc_a, &dag).unwrap();
        assert_eq!(actor_a.locked_state().locked_block_hash, Some([0xAA; 32]));
        assert_eq!(
            actor_b.locked_state().locked_block_hash,
            None,
            "B lock 不受 A 影响"
        );
        // B（unlocked）可投其它有效分支（A lock 不影响 B 授权）
        let ev_b = actor_b.produce_vote(&vote_req([0xBB; 32], VoteType::Prevote), &set, &dag);
        assert!(
            ev_b.is_some(),
            "B 自身 unlocked ⇒ 可授权（A lock 不影响 B）"
        );
    }

    // ---------- canonical event equivalence ----------

    #[test]
    fn actor_event_flows_through_canonical_transition() {
        use nova_consensus::finality::FinalityState;
        use nova_consensus::integration::{ConsensusState, IntegrationContext, TransitionResult};
        use nova_consensus::round::RoundState;

        let (mut kps, set) = make_ctx(3);
        let dag = build_dag();
        let (actor, _vk) = actor_of(kps.remove(0));
        // 目标 = 当前 height=0/round=0 的 DAG 内区块 AA
        let ev = actor
            .produce_vote(&vote_req([0xAA; 32], VoteType::Prevote), &set, &dag)
            .expect("unlocked 授权");
        // 同一标准 ConsensusEvent::Vote 进入既有 canonical transition（无需知道"本机产生"）
        let state = ConsensusState {
            round: RoundState::new(0, 0),
            finality: FinalityState::default(),
        };
        let mut ctx = IntegrationContext::new(0, 0);
        let genesis_hash = [0x42; 32];
        let result = nova_consensus::integration::transition(
            &state,
            ev,
            &mut ctx,
            CHAIN_ID,
            &set,
            &genesis_hash,
            &dag,
        );
        assert!(
            matches!(result, TransitionResult::Applied { .. }),
            "actor 产出的标准 ConsensusEvent::Vote 必须被 canonical transition 以 Applied 消费"
        );
    }
}
