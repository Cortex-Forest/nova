//! Node-local Proposer orchestration（STEP 10-19-2 — Proposer Assembly）。
//!
//! # 职责（Node-local；非 canonical ConsensusState）
//! - 判定本节点是否为当前 `(height, round)` proposer（复用 ADR-0050 `select_proposer`，
//!   **不重新设计** proposer selection）。
//! - 生成确定性 `ProposalRef`（block_hash = deterministic placeholder commitment）。
//! - 不接触 ValidatorActor 私钥 / VoteLedger / LockedState / SafetyStore；不做 block 构造 /
//!   tx 选择 / 存储 / 网络 / execution（ProposerService ≠ BlockBuilder / ValidatorActor /
//!   NetworkService / Storage / ConsensusState）。
//!
//! # 边界（STEP 10-19-2）
//! - `ProposalRef ≠ Block`：仍为 `{ block_hash: [u8;32], proposer: ValidatorId }`（64B wire，
//!   ADR-0041）；不改变 ProposalRef canonical encoding。
//! - block_hash 为 **placeholder commitment**：`= proposer_seed(chain,height,round,set_id)`
//!   （ADR-0050 既有协议 hash；deterministic）。**仅装配/测试用**，不伪装为真实完整 block hash；
//!   未来 BlockBuilder 在该 adapter 处替换（不改 canonical consensus 语义）。
//! - 不可变触发（idempotent）：`step == Propose` 且本轮尚无 proposal 且本地为 proposer ⇒
//!   `Some`；否则 `None`（no-op）。stale / future / 其它 proposer 不产生 proposal、不改 state。
//!
//! # 调用方
//! - `NodeRuntime::step`（node-local step-driven trigger；同步，无 async/timer）。
//! - 测试：`proposer_decision` + `NodeConsensusDriver::submit_proposal`（真实装配）。

use nova_consensus::error::ConsensusError;
use nova_consensus::proposer::{proposer_seed, select_proposer};
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::ValidatorId;

use crate::assembly::ConsensusNode;

/// 判定本节点是否应对当前 `(height, round)` 出 proposal（**纯只读**；不修改 state）。
///
/// 返回 `Some(ProposalRef)` 当且仅当：
/// - `round.step == Propose`（阶段守卫；已进 Prevote/之后 ⇒ no-op）；
/// - `round.proposal.is_none()`（同轮已提案 ⇒ idempotent no-op）；
/// - `select_proposer(chain, height, round, set_id=genesis_hash, set) == local_id`
///   （本节点为 proposer；非 proposer ⇒ `None`，不 panic / 不改 state / 不改 lock）。
///
/// 错误仅来自 `select_proposer` 的非法 ValidatorSet（空 / duplicate / 权重溢出）——fail-closed。
pub fn proposer_decision(
    local_id: ValidatorId,
    consensus: &ConsensusNode,
) -> Result<Option<ProposalRef>, ConsensusError> {
    let rs = &consensus.state().round;
    if rs.step != RoundStep::Propose || rs.proposal.is_some() {
        return Ok(None);
    }
    let set_id = consensus.genesis_hash(); // V0.1：validator_set_id = genesis_hash（ADR-0038 F-11）
    let selected = select_proposer(
        consensus.chain_id(),
        rs.height,
        rs.round,
        &set_id,
        consensus.validator_set(),
    )?;
    if selected != local_id {
        return Ok(None);
    }
    // 确定性 placeholder commitment（仅装配；勿伪装为真实完整 block hash）。
    let block_hash = proposer_seed(consensus.chain_id(), rs.height, rs.round, &set_id);
    Ok(Some(ProposalRef {
        block_hash,
        proposer: local_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::ConsensusNode;
    use nova_consensus::dag::{BlockReference, Dag};
    use nova_consensus::validator::ValidatorSet;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];

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

    fn dag1() -> Dag {
        let mut dag = Dag::new();
        dag.add_block(BlockReference {
            block_hash: [0xAA; 32],
            height: 0,
            parents: vec![],
            proposer: ValidatorId::from_bytes([0xAA; 32]),
        })
        .unwrap();
        dag
    }

    /// n 个等权重验证者的 ConsensusNode（本地 actor 不绑定；consensus 仅只读视图）。
    fn node_n(n: usize) -> (ConsensusNode, Vec<ValidatorId>, ValidatorSet) {
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
        let ids: Vec<ValidatorId> = set.validators().iter().map(|v| v.validator_id).collect();
        let node = ConsensusNode::new(0, 0, CHAIN_ID, set.clone(), GENESIS_HASH, dag1());
        (node, ids, set)
    }

    #[test]
    fn p1_local_proposer_detected() {
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let decision = proposer_decision(local, &node).expect("select ok");
        assert!(decision.is_some(), "单验证者必为 (0,0) proposer");
        let pr = decision.unwrap();
        assert_eq!(pr.proposer, local);
        assert_eq!(pr.block_hash.len(), 32);
        // block_hash = proposer_seed（deterministic placeholder）
        assert_eq!(pr.block_hash, proposer_seed(CHAIN_ID, 0, 0, &GENESIS_HASH));
    }

    #[test]
    fn p2_non_proposer_no_proposal() {
        let (node, ids, _) = node_n(2);
        // 确定 (0,0) proposer；另一成员 ⇒ None
        let selected =
            select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, node.validator_set()).unwrap();
        let local_other = ids.iter().copied().find(|i| *i != selected).unwrap();
        let decision = proposer_decision(local_other, &node).expect("select ok");
        assert!(decision.is_none(), "非当前 proposer 不产生 ProposalRef");
        // 当前 proposer ⇒ Some
        let decision_sel = proposer_decision(selected, &node).expect("ok");
        assert!(decision_sel.is_some());
    }

    #[test]
    fn p3_deterministic_proposal_commitment() {
        let (node_a, ids, _) = node_n(1);
        let local = ids[0];
        let a = proposer_decision(local, &node_a).unwrap().unwrap();
        let b = proposer_decision(local, &node_a).unwrap().unwrap();
        assert_eq!(a.block_hash, b.block_hash, "同输入 ⇒ 同 commitment");
        assert_eq!(a.proposer, b.proposer);
    }

    #[test]
    fn p5_duplicate_proposal_noop_after_submit() {
        // 提交后 step → Prevote 且 proposal 已设置 ⇒ 再次 decision None（不重复提案）。
        let (mut node, ids, _) = node_n(1);
        let local = ids[0];
        let pr = proposer_decision(local, &node).unwrap().unwrap();
        let first = node.submit_proposal(pr.clone());
        assert!(matches!(
            first,
            nova_consensus::integration::TransitionResult::Applied { .. }
        ));
        assert_eq!(node.state().round.step, RoundStep::Prevote);
        // 同轮再次触发（即使人为）⇒ 阶段守卫（consensus set_proposal 拒绝）+ decision no-op
        assert!(proposer_decision(local, &node).unwrap().is_none());
        let again = node.submit_proposal(pr);
        assert!(matches!(
            again,
            nova_consensus::integration::TransitionResult::Ignored { .. }
        ));
    }

    #[test]
    fn p6_stale_proposal_ignored() {
        // 已进 Prevote（非 Propose 阶段）⇒ decision None（stale/阶段不符 no-op，不改 state）
        let (mut node, ids, _) = node_n(1);
        let local = ids[0];
        let pr = proposer_decision(local, &node).unwrap().unwrap();
        node.submit_proposal(pr);
        let before_step = node.state().round.step;
        let before_has = node.state().round.proposal.is_some();
        assert!(proposer_decision(local, &node).unwrap().is_none());
        assert_eq!(node.state().round.step, before_step);
        assert_eq!(node.state().round.proposal.is_some(), before_has);
    }

    #[test]
    fn p10_canonical_state_isolation_and_readonly() {
        // decision 是纯只读：调用前后 state 不变；不触碰 validator/lock/safety（无此类输入）。
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let (h, r, step, has) = (
            node.state().round.height,
            node.state().round.round,
            node.state().round.step,
            node.state().round.proposal.is_some(),
        );
        let _ = proposer_decision(local, &node).unwrap();
        assert_eq!(node.state().round.height, h);
        assert_eq!(node.state().round.round, r);
        assert_eq!(node.state().round.step, step);
        assert_eq!(node.state().round.proposal.is_some(), has);
    }
}
