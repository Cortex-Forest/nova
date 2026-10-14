//! Node-level Block Inbound Dispatch（STEP 10-19-10-A）。
//!
//! 把网络入站 block payload（`GossipBlock` / `SyncBlockResponse`，经 wiring seam 收集的
//! `NodeConsensusHandler`）接到既有 **`block_inbound::validate_block_inbound`**（STEP 10-19-9）
//! 验证 seam，产出 typed verdict —— **只读观测，到此为止**。
//!
//! ```text
//! Network inbound
//!     ↓ wiring seam（NodeConsensusHandler.take_block_inbound）
//! dispatch_gossip_block / dispatch_sync_block_response（本模块）
//!     ↓ validate_block_inbound（10-19-9；纯只读）
//! typed verdict（CanonicalNextCandidate / AlreadyKnown / Stale / FutureMissingAncestor /
//!               ConflictingParent / Invalid… / UnsupportedValidation）
//!     ↓ diagnostic / bounded observation（Runtime）
//!     ↓ STOP
//! ```
//!
//! # 边界（硬性）
//! - **不 commit**：不调 `apply_block` / `commit_block` / `enqueue_head`。
//! - **不写存储**：不调 `BlockStore.put` / `StateStore.apply` / 不改 ChainHead。
//! - **不把 GossipBlock / SyncBlockResponse 当 finality proof**：`CanonicalNextCandidate` 仅是
//!   commit 候选；finality authorization / canonical commit 未实现且不在本模块。
//! - **不伪造验证能力**：无 ValidatorSet 的观测入口（[`dispatch_gossip_block`] /
//!   [`dispatch_sync_block_response`]）保持 `expected_proposer_vk = None` ⇒ canonical-next 返回
//!   `UnsupportedValidation(ProposerSignature)`（绝不 None→accept）。A11 桥接入口
//!   [`dispatch_gossip_block_with_validator_set`] 及 Sync 对称入口
//!   [`dispatch_sync_block_response_with_validator_set`] 由调用方提供 `ValidatorSet`，Node 独立计算
//!   期望 proposer（select_proposer，父高轮 head.height / round 0 / validator_set_id = genesis_hash），
//!   经 `ValidatorId → ValidatorInfo.consensus_public_key → VerifyingKey` 注入 `expected_proposer_vk`；
//!   **Sync ≠ trusted input**：同步块同样必须经本地 ValidatorSet 验 proposer，不得绕过。
//! - 远端 input 处理**无 panic / unwrap / expect**；Malformed 远端 payload ⇒ typed error。

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::ValidatorSet;
use nova_crypto::signature::VerifyingKey;
use nova_network::sync::SyncBlockResponse;
use nova_storage::backend::StorageBackend;

use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use crate::block_inbound::{
    InboundBlockContext, InboundBlockError, InboundBlockVerdict, UnverifiableItem,
    validate_block_inbound,
};

/// 从 adapter 的**真实只读** canonical 状态构造 inbound context（STEP 10-19-9）。
///
/// - 链身份 / 执行参数全部来自 adapter（bootstrap 装配的 genesis 派生值）；不伪造。
/// - `expected_proposer_vk` 由调用方决定：`None` = 不执行 proposer 验证（诚实能力边界，validator
///   对 canonical-next 返回 `UnsupportedValidation(ProposerSignature)`）；`Some(vk)` = 执行验签。
///   **None 永不等于“跳过验证放行”。**
/// - `expected_hash = None`（无 correlation；validator 内部仍重算 BlockHash）。
fn inbound_context_with_proposer<'a, B: StorageBackend + Clone>(
    adapter: &'a NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    expected_proposer_vk: Option<&'a VerifyingKey>,
    dag: Option<&'a nova_consensus::dag::Dag>,
) -> InboundBlockContext<'a, B> {
    InboundBlockContext {
        network_id: adapter.network_id(),
        chain_id: adapter.chain_id(),
        genesis_hash: adapter.genesis_hash(),
        fee_burn_bps: adapter.fee_burn_bps(),
        max_gas_per_block: adapter.max_gas_per_block(),
        max_block_bytes,
        state_store: adapter.store(),
        head: adapter.head(),
        block_store: adapter.block_store(),
        sender_resolver: &NoAccountsKeyResolver,
        expected_proposer_vk,
        expected_hash: None,
        dag,
    }
}

/// 解析 canonical-next（父高轮 `head.height` / round 0）的期望 proposer 验证公钥（A11 bridge）。
///
/// `ValidatorSet → select_proposer(chain_id, head.height, 0, genesis_hash, set) → ValidatorId
/// → ValidatorInfo.consensus_public_key → VerifyingKey`。
///
/// - `validator_set_id` = `genesis_hash`（ADR-0038 F-11；与 block_inbound 链身份一致）。
/// - 块本身**不携带** proposer 自证；期望 proposer 完全由本地 ValidatorSet 独立推导。
/// - 空集合 / 成员缺失 / 成员 consensus key 无法构成 Ed25519 点 ⇒ `Err(UnsupportedValidation(
///   ProposerSignature))`（缺失 proposer identity = 验证失败；不放行、不跳过）。
///
/// P1-A.18 RC-1 —— **绑定轮证据**：`(round, bound_block_hash)`。
///
/// 绑定键 = `bound_block_hash`：**仅当**它与待验证块的 canonical hash **严格相等**时，`round`
/// 才被使用；否则该证据不可用（**回退 round 0**，绝不猜测轮次）。
pub type ProposerRoundEvidence = (u64, [u8; 32]);

/// P1-A.18 RC-1 —— 解析该块可用的**绑定轮证据**（至多两个来源：proposal-bound / QC-bound）。
///
/// - 来源 A（proposal-bound，gossip）：本地已接受的 proposal `(round, proposal.block_hash)`；
///   调用方须额外保证 `round.height == head.height`（父高轮语义）。
/// - 来源 B（QC-bound，commit / 同步证据）：`(qc.context.round, qc.target)`；调用方须额外保证
///   高度绑定（`qc.context.height + 1 == block.height`）。
///
/// 契约（P1-A.18 §5/§6）：
/// - `Ok(0)` = 无可用证据 ⇒ 调用方**回退既有 round 0 行为**（不猜、不放宽）；
/// - `Ok(r)` = 恰有一个绑定来源 ⇒ 用 `r`（r 可为 0）；
/// - `Err(())` = **两个绑定来源给出不同轮** ⇒ 调用方必须**拒绝**（不得静默择一、不得遍历其它轮）。
// `Err(())` 是**协议语义**（“绑定证据矛盾”单一信号），不是错误信息载体；
// 调用方按契约 `Err(()) => 拒绝该块` 处理，本提交不改变该契约 / 不改公开签名。
#[allow(clippy::result_unit_err)]
pub fn resolve_proposer_round_evidence(
    block_hash: [u8; 32],
    proposal: Option<ProposerRoundEvidence>,
    qc: Option<ProposerRoundEvidence>,
) -> Result<u64, ()> {
    let a = proposal.filter(|(_, h)| *h == block_hash).map(|(r, _)| r);
    let b = qc.filter(|(_, t)| *t == block_hash).map(|(r, _)| r);
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(()),
        (Some(x), _) => Ok(x),
        (None, Some(y)) => Ok(y),
        (None, None) => Ok(0),
    }
}

/// **M3（Owner 授权）** —— 入站 canonical block 的**统一轮次派生**（gossip / sync / registration
/// **共用同一 helper**；禁止两套不一致规则）。
///
/// 规则（按优先级）：
/// 1. **绑定证据优先**：`proposal` / `qc` 中**恰一**项绑定 `block_hash`（严格相等）⇒ 用其轮
///    （轮 `0` 是合法证据，与“无证据”严格区分）；
/// 2. **冲突拒绝**：两项均绑定但轮不同 ⇒ `Err(())`（调用方必须拒绝 / 保守 no-op；不静默择一）；
/// 3. **无绑定证据 ⇒ `header_round`**：即 `BlockHeader.round` —— 它**由 proposer 签名绑定**
///    （`crates/core/src/block.rs::verify_block_signature` 的 payload = 整 `canonical_header`）
///    且**已被 block hash 承诺覆盖**（`block_hash = SHA-256(canonical_header‖canonical_body)`），
///    取代旧的**隐式 `round 0` 回退**（后者使 round>0 的诚实提案无法通过入站验证）。
///
/// 安全边界（**逐条保持**）：候选轮**至多 2 个**（`{证据轮, header.round}`）；
/// **不**遍历轮 / **不**遍历 validator / **不**接受任意成员签名 / **不**做 membership-only 接受；
/// 仍只注入**单个** `expected_proposer_vk`（签名必须与该轮当选 proposer 匹配，见
/// `resolve_expected_proposer_vk_at`）；`block_inbound` seam 与其单钥验签**逐字不变**。
///
/// 边界（不使用 `header.round` 的场合）：
/// - `header.round` **不**进入投票 / QC / lock / finality 授权（`Guard C` / `auto_drive` 仍只用**本地**
///   共识轮）；
/// - 结构损坏（无法解码）时调用方**不**调用本函数（以 `Malformed` 拒绝，**不进入登记路径**）。
// `Err(())` = “绑定证据矛盾”单一信号（与 `resolve_proposer_round_evidence` 同约定）。
#[allow(clippy::result_unit_err)]
pub fn resolve_inbound_block_round(
    block_hash: [u8; 32],
    header_round: u64,
    proposal: Option<ProposerRoundEvidence>,
    qc: Option<ProposerRoundEvidence>,
) -> Result<u64, ()> {
    let a = proposal.filter(|(_, h)| *h == block_hash).map(|(r, _)| r);
    let b = qc.filter(|(_, t)| *t == block_hash).map(|(r, _)| r);
    match (a, b) {
        // 2. 冲突：两源绑定同一 hash 但轮不同 ⇒ 拒绝（不静默择一）。
        (Some(x), Some(y)) if x != y => Err(()),
        // 1. 恰一源绑定（或两源同轮）⇒ 用该轮（可为 0）。
        (Some(x), _) => Ok(x),
        (None, Some(y)) => Ok(y),
        // 3. 无绑定证据 ⇒ 用块自身（已签名 / 已被 hash 承诺）的 `header.round`。
        (None, None) => Ok(header_round),
    }
}

/// 待验证 wire 的 canonical block hash（结构损坏 ⇒ `None`；此时轮不可用，由 validator 自身以
/// `Malformed` 拒绝，不在此处猜测）。
pub(crate) fn wire_block_hash(wire: &[u8]) -> Option<[u8; 32]> {
    wire_block_hash_and_round(wire).map(|(h, _)| h)
}

/// 待验证 wire 的 `(canonical block hash, BlockHeader.round)`（**单次解码**；结构损坏 ⇒ `None`）。
///
/// `round` 取自**解码后**的 header（= 签名 payload / hash 承诺内的同一字段）——单一来源，
/// 不重新计算 / 不猜轮。
pub(crate) fn wire_block_hash_and_round(wire: &[u8]) -> Option<([u8; 32], u64)> {
    let block = nova_runtime::decode_block(wire).ok()?;
    let hash = nova_runtime::block_hash(&block).ok()?;
    Some((hash, block.header.round))
}

/// 期望 proposer 验证公钥（**显式父高轮高度 + 轮**；`pub(crate)` 供 node 层**单一来源**复用）。
///
/// `ValidatorSet → select_proposer(chain_id, height, round, genesis_hash, set) → ValidatorId
/// → ValidatorInfo.consensus_public_key → VerifyingKey`。
///
/// - `height` = **父高轮高度**（ADR-0076 OD-11：A11 Guard C 传 `block.header.height - 1`；
///   block 入站路径传 `adapter.head().height`）；本函数**不**自行推导高度。
/// - 块本身**不携带** proposer 自证；期望 proposer 完全由本地 ValidatorSet 独立推导。
/// - 空集合 / 成员缺失 / 成员 consensus key 无法构成 Ed25519 点 ⇒ `Err(UnsupportedValidation(
///   ProposerSignature))`（缺失 proposer identity = 验证失败；不放行、不跳过）。
pub(crate) fn resolve_expected_proposer_vk_at<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    set: &ValidatorSet,
    height: u64,
    round: u64,
) -> Result<VerifyingKey, InboundBlockError> {
    let id = select_proposer(
        adapter.chain_id(),
        height,
        round,
        &adapter.genesis_hash(),
        set,
    )
    .map_err(|_| InboundBlockError::UnsupportedValidation(UnverifiableItem::ProposerSignature))?;
    let info = set
        .info(&id)
        .ok_or(InboundBlockError::UnsupportedValidation(
            UnverifiableItem::ProposerSignature,
        ))?;
    VerifyingKey::from_bytes(&info.consensus_public_key)
        .map_err(|_| InboundBlockError::UnsupportedValidation(UnverifiableItem::ProposerSignature))
}

/// 期望 proposer 验证公钥（指定**父高轮次**）。
///
/// 与 [`resolve_expected_proposer_vk_at`] **同一来源**：`height = adapter.head().height`
/// （canonical-next 块（height == head.height + 1）由「父高度轮」的 proposer 产出；
/// `build_proposal` 高度同步 gate `rs.height == head.height`）。
///
/// P1-A.18 RC-1：`round` 来自**严格绑定**证据（见 [`resolve_proposer_round_evidence`]）；
/// 无证据 ⇒ `0`（与 P1-A.18 之前行为逐字一致）。
pub(crate) fn resolve_expected_proposer_vk_at_round<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    set: &ValidatorSet,
    round: u64,
) -> Result<VerifyingKey, InboundBlockError> {
    resolve_expected_proposer_vk_at(adapter, set, adapter.head().height, round)
}

/// 期望 proposer 验证公钥（**round 0 兼容入口**；行为与 P1-A.18 之前逐字一致）。
fn resolve_expected_proposer_vk<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    set: &ValidatorSet,
) -> Result<VerifyingKey, InboundBlockError> {
    resolve_expected_proposer_vk_at_round(adapter, set, 0)
}

/// dispatch 一条 `GossipBlock` payload（= 单个 BlockV1 wire）→ validator verdict。
///
/// 只读：不 commit / 不写存储 / 不推进 head。结果供观测；`CanonicalNextCandidate` 非
/// finality-authorized（调用方不得据此 commit）。
pub fn dispatch_gossip_block<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    wire: &[u8],
) -> Result<InboundBlockVerdict, InboundBlockError> {
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, None, None);
    validate_block_inbound(wire, &ctx)
}

/// dispatch 一条 `GossipBlock` payload，并以本地 `ValidatorSet` 注入期望 proposer 公钥
/// （A11 桥接：canonical-next 可执行真实 proposer 签名验证，解除
/// `UnsupportedValidation(ProposerSignature)` 假阻塞）。
///
/// 期望 proposer = `select_proposer(chain_id, head.height(父高轮), round 0, genesis_hash, set)`；
/// 块内不携带 proposer 自证；非成员 / 空集 ⇒ `Err(UnsupportedValidation(ProposerSignature))`。
/// 只读：不 commit / 不写存储 / 不推进 head（`CanonicalNextCandidate` 仍非 finality-authorized）。
pub fn dispatch_gossip_block_with_validator_set<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    wire: &[u8],
    set: &ValidatorSet,
) -> Result<InboundBlockVerdict, InboundBlockError> {
    dispatch_gossip_block_with_validator_set_and_dag(adapter, max_block_bytes, wire, set, None)
}

/// 同 [`dispatch_gossip_block_with_validator_set`]，并注入**本地 DAG**（D9 Step 8A G1）。
///
/// `dag = Some(&local_dag)` ⇒ 已落盘但不在 DAG 的块**不**短路为 `AlreadyKnown`，而是走完
/// ⑥/⑦ 全验证后给出 `CanonicalNextCandidate`，使调用方可幂等补登记（**不** commit / **不**
/// 推进 head / **不**产生 finality）。`dag = None` ⇒ 与既有 4 参版本完全等价。
pub fn dispatch_gossip_block_with_validator_set_and_dag<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    wire: &[u8],
    set: &ValidatorSet,
    dag: Option<&nova_consensus::dag::Dag>,
) -> Result<InboundBlockVerdict, InboundBlockError> {
    dispatch_gossip_block_round_aware(adapter, max_block_bytes, wire, set, dag, None, None)
}

/// **P1-A.18 RC-1（Stage 1）** —— gossip 块的**证据绑定 round-aware** 期望 proposer 解析 + 验证。
///
/// 与 [`dispatch_gossip_block_with_validator_set_and_dag`] 的唯一差异：期望 proposer 的**父高轮次**
/// 可由**严格绑定**的既有证据给出（见 [`resolve_proposer_round_evidence`]）：
///
/// - `proposal_evidence = Some((round, proposal.block_hash))`：本地**已接受**的 proposal（该
///   proposal 已经过 driver 的 round-aware 授权校验）；
/// - `qc_evidence = Some((qc.context.round, qc.target))`：本地 `last_precommit_qc()`。
///
/// 安全边界（P1-A.18 §4 + M3）：候选轮**至多 2 个**（`{evidence_round, header.round}`，去重后实际仍只
/// 注入**单个** `expected_proposer_vk`）；**不**遍历轮 / **不**遍历 validator / **不**接受任意成员
/// 签名 / **不**做 membership-only 接受；无绑定证据 ⇒ **用 `header.round`**（M3；**不再**隐式回退
/// round 0）；两个绑定证据冲突 ⇒ 拒绝（`InvalidProposerSignature`）。
/// `block_inbound` seam 与其单钥验签**逐字不变**。
pub fn dispatch_gossip_block_round_aware<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    wire: &[u8],
    set: &ValidatorSet,
    dag: Option<&nova_consensus::dag::Dag>,
    proposal_evidence: Option<ProposerRoundEvidence>,
    qc_evidence: Option<ProposerRoundEvidence>,
) -> Result<InboundBlockVerdict, InboundBlockError> {
    // PHASE 6H-A30-ROOTFIX-M3（Owner 授权）—— **统一轮次派生**（gossip 路径）。
    //
    // 历史（保留为记录）：M1 曾把“无绑定证据”一律判为 `UnsupportedValidation(ProposerSignature)` ⇒
    // 造成 proposal ⇄ block 证据死锁（round-0 全线 stall）；M2 恢复 round-0 回退 ⇒ 修复 round 0，
    // 但 **round>0 的诚实提案**（`header.round = r`）仍被按 round 0 判定 ⇒ `InvalidProposerSignature`
    // ⇒ 块不登记 ⇒ U3 recovery 不可达 ⇒ round≥1 无法闭合（A30 `t7_3` 5/7 实测 `head=0`）。
    //
    // M3：改用 [`resolve_inbound_block_round`]（**证据优先 / 冲突拒绝 / `header.round` 兜底**），
    // 与 sync 路径、registration 共用唯一规则；不再有隐式 round 0 回退。
    let round = match wire_block_hash_and_round(wire) {
        Some((h, header_round)) => {
            resolve_inbound_block_round(h, header_round, proposal_evidence, qc_evidence)
                .map_err(|_| InboundBlockError::InvalidProposerSignature)?
        }
        // 结构损坏：轮不可用（不猜轮）；validator 自身以 `Malformed` 拒绝 ⇒ **不进入登记路径**。
        None => 0,
    };
    let expected_vk = resolve_expected_proposer_vk_at_round(adapter, set, round)?;
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, Some(&expected_vk), dag);
    validate_block_inbound(wire, &ctx)
}

/// **P1-A.18 RC-1（Stage 2）** —— 从**绑定** QC 证据切片解析轮次（sync / catch-up 路径）。
///
/// 绑定规则与 Stage 1 **同一语义**：仅统计 `target == block_hash` 的条目。
/// - 0 个绑定条目 ⇒ `Ok(None)`（调用方**回退 round 0**：与 Stage 2 之前逐字一致，不猜轮）；
/// - 1 个（或多个但全为同一轮）⇒ `Ok(Some(r))`；
/// - **两个不同轮都绑定同一 block hash** ⇒ `Err(())`（调用方必须**拒绝**；不得静默择一）。
///
/// 有界性：扫描上界 = 调用方切片长度（= 既有 `PENDING_EXTERNAL_QC_CAP`，**有界**）；
/// 本函数**只做等值匹配**——不做「逐轮试签名」，不遍历 validator，不做 membership-only 接受。
// `Err(())` 与 Stage 1 同一协议语义（“绑定证据矛盾”单一信号）；契约不变。
#[allow(clippy::result_unit_err)]
pub fn resolve_proposer_round_from_evidences(
    block_hash: [u8; 32],
    evidences: &[ProposerRoundEvidence],
) -> Result<Option<u64>, ()> {
    let mut bound: Option<u64> = None;
    for (round, target) in evidences {
        if *target != block_hash {
            continue;
        }
        match bound {
            None => bound = Some(*round),
            Some(prev) if prev == *round => {}
            Some(_) => return Err(()),
        }
    }
    Ok(bound)
}

/// **P1-A.18 RC-1（Stage 2）** —— sync 批次的**证据绑定 round-aware** 期望 proposer 解析 + 验证。
///
/// 与 [`dispatch_sync_block_response_with_validator_set_and_dag`] 的唯一差异：期望 proposer 的**父高
/// 轮次**可由 `qc_evidences` 中**严格绑定**（`target == 本块 canonical hash`）的 QC 证据给出。
/// `qc_history` 的键不变式（`height == qc.context.height + 1`）保证该 QC 正是**该块**的 QC；本函数
/// 仍以 **hash 严格相等**作为唯一绑定判据（多余条件一律不用该轮）。
///
/// 安全边界（与 Stage 1 完全一致 + M3）：候选轮**至多 2 个**（`{bound_round, header.round}`，去重后
/// 仍只注入**单个** `expected_proposer_vk`）；**不**遍历轮 / **不**遍历 validator / **不**做
/// membership-only 接受；无绑定证据 ⇒ **用 `header.round`**（M3；**不再**隐式回退 round 0）；
/// 两个绑定条目轮不同 ⇒ **拒绝**（`InvalidProposerSignature`）。`block_inbound` seam 与其单钥验签
/// **逐字不变**；`qc_evidences = &[]` 且 `header.round = 0` ⇒ 与既有 round-0 入口**逐字等价**
/// （`p1a18_t1` / `p1a18_t1_sync_round0_no_evidence_is_identical` 以断言固化）。
pub fn dispatch_sync_block_response_round_aware<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    payload: &[u8],
    set: &ValidatorSet,
    dag: Option<&nova_consensus::dag::Dag>,
    qc_evidences: &[ProposerRoundEvidence],
) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
    let response = match SyncBlockResponse::decode(payload) {
        Ok(r) => r,
        Err(_) => return vec![Err(InboundBlockError::Malformed)],
    };
    response
        .blocks
        .iter()
        .map(|block_payload| {
            // PHASE 6H-A30-ROOTFIX-M3（Owner 授权）—— 与 gossip 路径**同一 helper / 同一规则**：
            // 证据（此路径只有 QC 证据）优先；冲突 ⇒ 拒绝；**无绑定证据 ⇒ `header.round`**
            // （替代旧的隐式 round 0 回退）。
            let round = match wire_block_hash_and_round(&block_payload.0) {
                Some((h, header_round)) => {
                    // 切片内“同 hash 两个不同轮” ⇒ 冲突（既有语义，保持拒绝）。
                    let bound = match resolve_proposer_round_from_evidences(h, qc_evidences) {
                        Ok(b) => b,
                        Err(()) => return Err(InboundBlockError::InvalidProposerSignature),
                    };
                    resolve_inbound_block_round(h, header_round, None, bound.map(|r| (r, h)))
                        .map_err(|_| InboundBlockError::InvalidProposerSignature)?
                }
                // 结构损坏：轮不可用（不猜轮）；validator 自身以 `Malformed` 拒绝。
                None => 0,
            };
            let expected_vk = match resolve_expected_proposer_vk_at_round(adapter, set, round) {
                Ok(vk) => vk,
                Err(e) => return Err(e),
            };
            let ctx =
                inbound_context_with_proposer(adapter, max_block_bytes, Some(&expected_vk), dag);
            validate_block_inbound(&block_payload.0, &ctx)
        })
        .collect()
}

/// dispatch 一条 `SyncBlockResponse` payload（codec：count + len-prefixed block wires）。
///
/// 解码失败（结构损坏）⇒ `vec![Err(Malformed)]`；每块经**同一** validator seam 逐条验证。
/// 只读；不 commit / 不写存储 / 不推进 head。
pub fn dispatch_sync_block_response<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    payload: &[u8],
) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
    let response = match SyncBlockResponse::decode(payload) {
        Ok(r) => r,
        Err(_) => return vec![Err(InboundBlockError::Malformed)],
    };
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, None, None);
    response
        .blocks
        .iter()
        .map(|block_payload| validate_block_inbound(&block_payload.0, &ctx))
        .collect()
}

/// dispatch 一条 `SyncBlockResponse` payload，并以本地 `ValidatorSet` 注入期望 proposer 公钥
/// （Sync 对称 A11 桥接，与 gossip [`dispatch_gossip_block_with_validator_set`] 一致）。
///
/// **Sync ≠ trusted input**：远端同步块不携带 proposer 自证；每块仍须由本地 `ValidatorSet`
/// 独立推导期望 proposer（`select_proposer(chain_id, head.height, 0, genesis_hash, set)`）→
/// `ValidatorInfo.consensus_public_key → VerifyingKey` 后执行真实验签 —— 验证通过才
/// `CanonicalNextCandidate`；非当选 / 篡改 / 非成员签名 ⇒ `InvalidProposerSignature`。
///
/// 解码失败 ⇒ `vec![Err(Malformed)]`；单块无合法 proposer / 验签失败 ⇒ 该块 `Err`。
/// 只读：不 commit / 不写存储 / 不推进 head（`CanonicalNextCandidate` 非 finality-authorized）。
pub fn dispatch_sync_block_response_with_validator_set<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    payload: &[u8],
    set: &ValidatorSet,
) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
    dispatch_sync_block_response_with_validator_set_and_dag(
        adapter,
        max_block_bytes,
        payload,
        set,
        None,
    )
}

/// 同 [`dispatch_sync_block_response_with_validator_set`]，并注入**本地 DAG**（D9 Step 8A G1）。
///
/// 语义与 gossip 侧 `_and_dag` 完全对称：已落盘但不在 DAG 的块走完 ⑥/⑦ 全验证（**不**短路），
/// 使调用方可幂等补登记；`dag = None` ⇒ 与既有 4 参版本完全等价。
pub fn dispatch_sync_block_response_with_validator_set_and_dag<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    payload: &[u8],
    set: &ValidatorSet,
    dag: Option<&nova_consensus::dag::Dag>,
) -> Vec<Result<InboundBlockVerdict, InboundBlockError>> {
    let response = match SyncBlockResponse::decode(payload) {
        Ok(r) => r,
        Err(_) => return vec![Err(InboundBlockError::Malformed)],
    };
    response
        .blocks
        .iter()
        .map(|block_payload| {
            let expected_vk = match resolve_expected_proposer_vk(adapter, set) {
                Ok(vk) => vk,
                Err(e) => return Err(e),
            };
            let ctx =
                inbound_context_with_proposer(adapter, max_block_bytes, Some(&expected_vk), dag);
            validate_block_inbound(&block_payload.0, &ctx)
        })
        .collect()
}
