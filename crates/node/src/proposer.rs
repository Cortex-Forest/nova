//! Node-local Proposer orchestration（STEP 10-19-6 OPT-1 — Proposer → Real BlockBuilder）。
//!
//! # 职责（Node-local；非 canonical ConsensusState）
//! - 判定本节点是否为当前 `(height, round)` proposer（复用 ADR-0050 `select_proposer`，
//!   **不重新设计** proposer selection）。
//! - 是 proposer 时经真实 [`crate::block_builder::build_block`] 构造 `BlockV1`：
//!   `ProposalRef.block_hash` 来自真实 `BlockHash`（ADR-0042；**不再使用 proposer_seed 占位**）。
//!
//! # 边界（ProposerService = WHEN + WHO；BlockBuilder = WHAT；Consensus = ACCEPT / VOTE / FINALIZE）
//! - `ProposalRef` 仍为 `{ block_hash, proposer }`（64B wire，ADR-0041）；不含 Block。
//! - 出块所需输入全部显式：parent `ChainHead`（canonical）+ 交易候选（V0.1 = **空集**；
//!   Mempool integration DEFERRED）+ `timestamp`（显式；**禁止系统时钟**）。
//! - build **只读**：不 commit state / 不推进 ChainHead / 不写 WAL / 不广播（head 推进归未来
//!   block commit path，本轮不推进）。
//! - 不接触私钥（block 签名归 [`crate::validator::ValidatorActor::sign_block`]；本模块不签名）。
//!
//! # V0.1 DEV BLOCK SEMANTICS（STEP 10-19-6 OPT-1）
//! - 链高单一来源 = `ChainHead`（`NodeBlockAdapter`）；`parent_hash = head.block_hash`；
//!   `height = head.height + 1`（首块 parent = genesis head）。
//! - **高度同步 gate**：仅当 `consensus.round.height == head.height`（共识与链高同步）时出块；
//!   不同步 ⇒ `Ok(None)`（no-op；不猜 / 不伪造 parent）。
//! - `validator_set_hash = genesis_hash`（V0.1 validator_set_id = genesis_hash；ADR-0038 F-11）。
//! - `finality_reference = None`（本轮无已应用 finalized block 可引用；head 不推进）。
//! - head **不因** proposer build 自动推进（Owner 授权；正式 block commit path 为未来 STEP）。
//!
//! # 调用方
//! - [`crate::runtime::NodeRuntime`]（step-driven；显式 `timestamp` 输入）。

use nova_consensus::error::ConsensusError;
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep};
use nova_consensus::validator::ValidatorId;
use nova_crypto::identity::ChainIdentity;
use nova_runtime::{Block, ExecutionContext};
use nova_storage::backend::StorageBackend;

use crate::assembly::ConsensusNode;
use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use crate::block_builder::{BlockBuilderError, BlockContext, build_block};

/// Proposer orchestration 错误（node-local；区分选择 / block 构建 / head 边界）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposerError {
    /// `select_proposer` 非法 ValidatorSet（空 / duplicate / 权重溢出）——fail-closed。
    Selection(ConsensusError),
    /// BlockBuilder 构建失败（execution / state root / assembly / duplicate 等）。
    Block(BlockBuilderError),
    /// `head.height + 1` 溢出（u64::MAX）。
    HeadOverflow,
}

impl From<ConsensusError> for ProposerError {
    fn from(e: ConsensusError) -> Self {
        Self::Selection(e)
    }
}

impl From<BlockBuilderError> for ProposerError {
    fn from(e: BlockBuilderError) -> Self {
        Self::Block(e)
    }
}

impl core::fmt::Display for ProposerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Selection(e) => write!(f, "proposer selection: {e}"),
            Self::Block(e) => write!(f, "proposer block build: {e}"),
            Self::HeadOverflow => write!(f, "proposer head height overflow"),
        }
    }
}

impl std::error::Error for ProposerError {}

/// 本地出块产物：真实 `BlockV1` + 其 `BlockHash` + 对应 `ProposalRef`。
///
/// - `block` 初始 `proposer_signature = [0u8; 64]`（签名由 runtime 经
///   [`crate::validator::ValidatorActor::sign_block`] 回填；signature ∉ block_hash，hash 不变）。
/// - `block_hash == proposal_ref.block_hash == BlockHash(block)`（ADR-0042 §6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalBuild {
    /// 组装的真实 Block（未签 / 占位 signature）。
    pub block: Block,
    /// `SHA-256(canonical_header ‖ canonical_body)`（ADR-0042 §6）。
    pub block_hash: [u8; 32],
    /// 提交共识的 ProposalRef（`block_hash` 即真实 BlockHash；64B wire）。
    pub proposal_ref: ProposalRef,
}

/// 判定本节点是否应对当前 `(height, round)` 出 proposal；是则经 BlockBuilder 产出真实 Block。
///
/// 返回 `Some(ProposalBuild)` 当且仅当：
/// - `round.step == Propose` 且 `round.proposal.is_none()`（阶段 / 幂等守卫）；
/// - **高度同步 gate**：`consensus.round.height == head.height`（共识与链高同步）；
/// - `select_proposer(chain, height, round, set_id=genesis_hash, set) == local_id`；
/// - build 成功（V0.1 candidate = 空集；post-state root = parent root）。
///
/// 否则 `Ok(None)`（no-op：非 proposer / 阶段不符 / 高度不同步 / 已提案）——不改任何 state。
pub fn build_proposal<B: StorageBackend + Clone>(
    local_id: ValidatorId,
    consensus: &ConsensusNode,
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    timestamp: u64,
) -> Result<Option<ProposalBuild>, ProposerError> {
    let rs = &consensus.state().round;
    if rs.step != RoundStep::Propose || rs.proposal.is_some() {
        return Ok(None);
    }
    // 高度同步 gate：consensus 当前高度必须 == canonical 链高（head）；否则无真实 parent ⇒ no-op。
    let head = adapter.head();
    if rs.height != head.height {
        return Ok(None);
    }
    let set_id = consensus.genesis_hash(); // V0.1：validator_set_id = genesis_hash（ADR-0038 F-11）
    let selected = select_proposer(
        consensus.chain_id(),
        rs.height,
        rs.round,
        &set_id,
        consensus.validator_set(),
    )
    .map_err(ProposerError::Selection)?;
    if selected != local_id {
        return Ok(None);
    }
    let next_height = head
        .height
        .checked_add(1)
        .ok_or(ProposerError::HeadOverflow)?;
    // BlockContext（全部来自 canonical head / genesis / 显式输入；无系统时钟 / 无伪造 parent）。
    let context = BlockContext {
        height: next_height,
        parent_hash: head.block_hash,
        finality_reference: None, // 本轮无已应用 finalized block 可引用（head 不推进）
        validator_set_hash: set_id,
        timestamp,
    };
    let exec_ctx = ExecutionContext {
        chain: ChainIdentity {
            network_id: adapter.network_id(),
            chain_id: adapter.chain_id(),
            genesis_hash: adapter.genesis_hash(),
        },
        current_height: head.height,
        fee_burn_bps: adapter.fee_burn_bps(),
    };
    // V0.1 proposer candidate source = empty set（Mempool integration DEFERRED）。
    let result = build_block(
        adapter.store(),
        &context,
        &exec_ctx,
        adapter.max_gas_per_block(),
        &[],
    )
    .map_err(ProposerError::Block)?;
    let proposal_ref = ProposalRef {
        block_hash: result.block_hash,
        proposer: local_id,
    };
    Ok(Some(ProposalBuild {
        block: result.block,
        block_hash: result.block_hash,
        proposal_ref,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::ConsensusNode;
    use crate::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
    use nova_consensus::dag::{BlockReference, Dag};
    use nova_consensus::validator::ValidatorSet;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_storage::memory::MemoryBackend;
    use nova_storage::store::StateStore;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
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

    /// 空 genesis-head adapter（MemoryBackend；测试用）：head.height=0、block_hash=GENESIS_HASH。
    fn adapter() -> NodeBlockAdapter<MemoryBackend, NoAccountsKeyResolver> {
        let store = StateStore::new(MemoryBackend::new());
        let root = store.state_root();
        NodeBlockAdapter::new(
            store,
            NoAccountsKeyResolver,
            CHAIN_ID,
            GENESIS_HASH,
            100_000_000_000,
            100,
            ChainHead::genesis(GENESIS_HASH, root),
            NetworkId::Mainnet,
        )
    }

    /// build_proposal（本地 proposer 路径；adapter 只读新建）。
    fn propose_for(node: &ConsensusNode, local: ValidatorId, ts: u64) -> Option<ProposalBuild> {
        build_proposal(local, node, &adapter(), ts).unwrap()
    }

    #[test]
    fn p1_local_proposer_builds_real_block() {
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let pb = propose_for(&node, local, 0).expect("单验证者 (0,0) 必为 proposer");
        assert_eq!(pb.proposal_ref.proposer, local);
        // ProposalRef.block_hash == BlockHash(block)（真实；非 placeholder）
        assert_eq!(pb.block_hash, pb.proposal_ref.block_hash);
        assert_eq!(pb.block_hash, nova_runtime::block_hash(&pb.block).unwrap());
        // 真实 Block 字段：空体 / height = head+1 = 1 / parent = genesis / chain / vs_hash
        assert!(pb.block.body.txs.is_empty(), "V0.1 candidate = empty");
        assert_eq!(pb.block.header.height, 1);
        assert_eq!(pb.block.header.parent_hash, GENESIS_HASH);
        assert_eq!(pb.block.header.chain_id, CHAIN_ID);
        assert_eq!(pb.block.header.validator_set_hash, GENESIS_HASH);
        assert_eq!(pb.block.header.finality_reference, None);
    }

    #[test]
    fn p2_non_proposer_no_build() {
        let (node, ids, _) = node_n(2);
        // 确定 (0,0) proposer；另一成员 ⇒ None（不 build）
        let selected =
            select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, node.validator_set()).unwrap();
        let local_other = ids.iter().copied().find(|i| *i != selected).unwrap();
        assert!(
            propose_for(&node, local_other, 0).is_none(),
            "非 proposer 不 build"
        );
        // 当前 proposer ⇒ Some
        assert!(propose_for(&node, selected, 0).is_some());
    }

    #[test]
    fn p3_real_proposal_deterministic() {
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let a = propose_for(&node, local, 0).unwrap();
        let b = propose_for(&node, local, 0).unwrap();
        assert_eq!(a.block, b.block, "同输入 ⇒ 同 Block");
        assert_eq!(a.block_hash, b.block_hash, "同输入 ⇒ 同 BlockHash");
        assert_eq!(a.proposal_ref.proposer, b.proposal_ref.proposer);
    }

    #[test]
    fn p5_duplicate_proposal_noop_after_submit() {
        // 提交后 step → Prevote 且 proposal 已设置 ⇒ 再次 build None（不重复提案）。
        let (mut node, ids, _) = node_n(1);
        let local = ids[0];
        let pb = propose_for(&node, local, 0).unwrap();
        let first = node.submit_proposal(pb.proposal_ref.clone());
        assert!(matches!(
            first,
            nova_consensus::integration::TransitionResult::Applied { .. }
        ));
        assert_eq!(node.state().round.step, RoundStep::Prevote);
        // 同轮再次触发 ⇒ 阶段守卫 + decision no-op
        assert!(propose_for(&node, local, 0).is_none());
        let again = node.submit_proposal(pb.proposal_ref);
        assert!(matches!(
            again,
            nova_consensus::integration::TransitionResult::Ignored { .. }
        ));
    }

    #[test]
    fn p6_stale_noop_after_prevote() {
        // 已进 Prevote（非 Propose 阶段）⇒ build None（stale/阶段不符 no-op，不改 state）
        let (mut node, ids, _) = node_n(1);
        let local = ids[0];
        let pb = propose_for(&node, local, 0).unwrap();
        node.submit_proposal(pb.proposal_ref);
        let before_step = node.state().round.step;
        let before_has = node.state().round.proposal.is_some();
        assert!(propose_for(&node, local, 0).is_none());
        assert_eq!(node.state().round.step, before_step);
        assert_eq!(node.state().round.proposal.is_some(), before_has);
    }

    #[test]
    fn p10_canonical_state_isolation_and_readonly() {
        // build_proposal 纯只读：调用前后 consensus state 不变；不触碰 validator/lock/safety。
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let (h, r, step, has) = (
            node.state().round.height,
            node.state().round.round,
            node.state().round.step,
            node.state().round.proposal.is_some(),
        );
        let _ = propose_for(&node, local, 0);
        assert_eq!(node.state().round.height, h);
        assert_eq!(node.state().round.round, r);
        assert_eq!(node.state().round.step, step);
        assert_eq!(node.state().round.proposal.is_some(), has);
    }

    #[test]
    fn opt_timestamp_changes_block_hash() {
        // OPT1-17：timestamp 显式变化 ⇒ BlockHash 变化（且无系统时钟）。
        let (node, ids, _) = node_n(1);
        let local = ids[0];
        let a = propose_for(&node, local, 0).unwrap();
        let b = propose_for(&node, local, 7).unwrap();
        assert_ne!(a.block_hash, b.block_hash, "timestamp 变 ⇒ BlockHash 变");
    }

    #[test]
    fn opt_height_sync_gate_noop_when_desynced() {
        // consensus round.height=1 而 head.height=0（不同步）⇒ 无真实 parent ⇒ None（不猜/不伪造）。
        let (_, ids, set) = node_n(1);
        let local = ids[0];
        let node = ConsensusNode::new(1, 0, CHAIN_ID, set, GENESIS_HASH, dag1());
        assert!(propose_for(&node, local, 0).is_none(), "高度不同步不出块");
    }
}
