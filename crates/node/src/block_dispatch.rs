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
fn resolve_expected_proposer_vk<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    set: &ValidatorSet,
) -> Result<VerifyingKey, InboundBlockError> {
    // canonical-next 块（height == head.height + 1）由「父高度轮」的 proposer 产出：
    // node build_proposal 高度同步 gate（rs.height == head.height）⇒ 产块轮高 = head.height；
    // proposer = select(chain, head.height, round 0, genesis_hash, set)。用父高度轮而非块高，
    // 与产块方 / vote / QC 的轮高语义一致（双验证者下 (head) 与 (head+1) 选择可能不同）。
    let height = adapter.head().height;
    let id = select_proposer(
        adapter.chain_id(),
        height,
        0u64,
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

/// dispatch 一条 `GossipBlock` payload（= 单个 BlockV1 wire）→ validator verdict。
///
/// 只读：不 commit / 不写存储 / 不推进 head。结果供观测；`CanonicalNextCandidate` 非
/// finality-authorized（调用方不得据此 commit）。
pub fn dispatch_gossip_block<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
    wire: &[u8],
) -> Result<InboundBlockVerdict, InboundBlockError> {
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, None);
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
    let expected_vk = resolve_expected_proposer_vk(adapter, set)?;
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, Some(&expected_vk));
    validate_block_inbound(wire, &ctx)
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
    let ctx = inbound_context_with_proposer(adapter, max_block_bytes, None);
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
            let ctx = inbound_context_with_proposer(adapter, max_block_bytes, Some(&expected_vk));
            validate_block_inbound(&block_payload.0, &ctx)
        })
        .collect()
}
