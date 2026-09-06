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
//! - **不伪造验证能力**：`expected_proposer_vk = None`（BlockV1 header 无 proposer identity，
//!   Node 当前不能可靠确定远端 block 的 proposer key ⇒ validator 返回
//!   `UnsupportedValidation(ProposerSignature)`，绝不 None→accept）；`expected_hash = None`
//!   （无 request correlation，且 payload 无可信 claimed hash；validator 内部仍重算 BlockHash）。
//! - 远端 input 处理**无 panic / unwrap / expect**；Malformed 远端 payload ⇒ typed error。

use nova_network::sync::SyncBlockResponse;
use nova_storage::backend::StorageBackend;

use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use crate::block_inbound::{
    InboundBlockContext, InboundBlockError, InboundBlockVerdict, validate_block_inbound,
};

/// 从 adapter 的**真实只读** canonical 状态构造 inbound context（STEP 10-19-9）。
///
/// - 链身份 / 执行参数全部来自 adapter（bootstrap 装配的 genesis 派生值）；不伪造。
/// - `expected_proposer_vk = None`（Node 不能确定远端 proposer key；诚实能力边界）。
/// - `expected_hash = None`（无 correlation；validator 内部仍重算 BlockHash）。
fn inbound_context<'a, B: StorageBackend + Clone>(
    adapter: &'a NodeBlockAdapter<B, NoAccountsKeyResolver>,
    max_block_bytes: usize,
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
        expected_proposer_vk: None,
        expected_hash: None,
    }
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
    let ctx = inbound_context(adapter, max_block_bytes);
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
    let ctx = inbound_context(adapter, max_block_bytes);
    response
        .blocks
        .iter()
        .map(|block_payload| validate_block_inbound(&block_payload.0, &ctx))
        .collect()
}
