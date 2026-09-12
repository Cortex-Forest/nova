//! D9 Step 8A — Production Sync Responder（node-only；复用既有 wire / codec / Established 通道）。
//!
//! # 路径（production）
//! ```text
//! Established peer（既有 handshake/auth；非 Established 已被 NetworkService fail-closed 丢弃）
//!     → SyncBlockRequest（既有 envelope / 既有 codec；handler 只搬 payload）
//!     → wiring 有界队列（满 ⇒ drop + 计数）
//!     → NodeRuntime::step 每 step 有界 serve（≤ MAX_SYNC_RESPONSES_PER_STEP）
//!     → BlockStore **只读**查找（hash 优先；无 hash ⇒ 从 canonical head 沿 parent_hash 回走，
//!        步数 ≤ MAX_SYNC_WALK）
//!     → 既有 `SyncBlockResponse` codec（单块；request_id 原样回带）
//!     → 既有 `NetworkSigner`（网络身份签名；非 validator key）
//!     → 既有 `NetworkService::enqueue_outbound` → 既有 outbound 队列 → 既有 transport/flush
//! ```
//!
//! # 边界（严格遵守）
//! - **不新增协议**：`MessageType` / wire field / codec / 认证语义全部复用（本轮零 network 改动）。
//! - **不直接写 socket**、**不绕过 NetworkService**、**不建第二套 send path**。
//! - **绝不**产生 finality / commit / head 推进：本模块只把**本地已持久化**的块读出来回送，
//!   不修改任何 consensus / storage 状态（`BlockStore` 只读）。
//! - **不伪造**：本地没有请求的块（hash 未命中 / 高度不在 canonical 链 / 回走超限）⇒ **不响应**
//!   （不回其它高度 / 不用 head 冒充 / 不截断），只计数。
//! - 单块响应（`MAX_SYNC_BLOCKS_PER_RESPONSE = 1`）；若单块响应超出 `max_msg_bytes` ⇒ fail-closed
//!   （不发、计数），**不截断**。

use nova_consensus::finality::QuorumCertificate;
use nova_network::message::{MessageEnvelope, MessageType};
use nova_network::network_service::NetworkService;
use nova_network::node_id::NodeId;
use nova_network::sync::{BlockPayload, SyncBlockRequest, SyncBlockResponse};
use nova_network::transport::BoxTransport;
use nova_runtime::Block;

use crate::block_adapter::{NoAccountsKeyResolver, NodeBlockAdapter};
use crate::network_identity::NetworkSigner;
use crate::outbound::OutboundConsensusMessage;
use crate::qc_history::QcHistory;
use nova_storage::backend::StorageBackend;

/// 单条 `SyncBlockResponse` 最多携带块数（本轮最小实现：**只支持单块**）。
pub const MAX_SYNC_BLOCKS_PER_RESPONSE: usize = 1;

/// 无 hash 请求的 parent 回走上限（防无限 ancestor traversal）。
///
/// 超过 ⇒ `WalkExceeded`（不响应）；walk = 0 时只允许命中 head 自身。
pub const MAX_SYNC_WALK: u64 = 64;

/// 每 step 最多 serve 的请求数（bounded work；其余留在 wiring 队列，下一 step 继续）。
pub const MAX_SYNC_RESPONSES_PER_STEP: usize = 4;

/// wiring 侧入站 `SyncBlockRequest` 队列容量（bounded；满 ⇒ drop + 计数）。
pub const MAX_PENDING_SYNC_REQUESTS: usize = 64;

/// serve 单条请求的结果（全部为"不响应"的显式原因；无 panic / 无 fake）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncServeOutcome {
    /// 已构造响应并交给既有 outbound 队列。
    Served,
    /// 本地不存在（hash 未命中 / 高度不在 canonical 链 / 高度=0 无 block 实体）。
    Missing,
    /// parent 回走超过 `MAX_SYNC_WALK`。
    WalkExceeded,
    /// 单块响应 > `max_msg_bytes`（fail-closed；不截断）。
    Oversized,
    /// 无 canonical adapter / BlockStore（full-node 形态）。
    NoBlockStore,
    /// 防御性：peer 非 Established（正常已由 NetworkService gate 拦截）。
    NotEstablished,
    /// 入站 payload 无法 decode 为 `SyncBlockRequest`（结构损坏）。
    Malformed,
    /// `enqueue_outbound` 拒绝（队列满 / 未知 peer 等）。
    SendRejected,
    /// 信封签名失败（网络身份）。
    SigningFailed,
}

/// 只读查找结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncLookup {
    /// `Box<Block>`：避免 variant 尺寸失衡（Block ≈ 280B；clippy `large_enum_variant`）。
    Found(Box<Block>),
    Missing,
    WalkExceeded,
    NoBlockStore,
}

/// responder 观测（node-local；只读计数，非协议字段）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncRespondDiagnostics {
    /// 入站请求被 serve 的次数（含所有 outcome）。
    pub attempts: u64,
    pub served: u64,
    pub missing: u64,
    pub walk_exceeded: u64,
    pub oversized: u64,
    pub no_block_store: u64,
    pub not_established: u64,
    pub malformed: u64,
    pub send_rejected: u64,
    pub signing_failed: u64,
    /// P1-A.7：已附发的历史 PrecommitQC 数（既有 `ConsensusQc` 消息；含对应高度 QC 与 tip hint）。
    pub qc_served: u64,
    /// P1-A.7：QC 附发被跳过数（超 `max_msg_bytes` / 签名失败 / artifact 损坏 / 本地无该高度）。
    ///
    /// 注：本地**无**该高度历史 QC（超出 retention / 未持久化）不计入 skipped（无可用证据）；
    /// 结构损坏 / checksum 不符 / 同高度冲突 ⇒ 计入（fail-closed 拒绝服务）。
    pub qc_serve_skipped: u64,
}

impl SyncRespondDiagnostics {
    fn record(&mut self, outcome: SyncServeOutcome) {
        self.attempts += 1;
        match outcome {
            SyncServeOutcome::Served => self.served += 1,
            SyncServeOutcome::Missing => self.missing += 1,
            SyncServeOutcome::WalkExceeded => self.walk_exceeded += 1,
            SyncServeOutcome::Oversized => self.oversized += 1,
            SyncServeOutcome::NoBlockStore => self.no_block_store += 1,
            SyncServeOutcome::NotEstablished => self.not_established += 1,
            SyncServeOutcome::Malformed => self.malformed += 1,
            SyncServeOutcome::SendRejected => self.send_rejected += 1,
            SyncServeOutcome::SigningFailed => self.signing_failed += 1,
        }
    }

    fn record_qc(&mut self, tally: QcServeTally) {
        self.qc_served = self.qc_served.saturating_add(tally.served);
        self.qc_serve_skipped = self.qc_serve_skipped.saturating_add(tally.skipped);
    }
}

/// P1-A.7 — 单次请求的 QC 附发统计（node-local；非协议字段）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QcServeTally {
    served: u64,
    skipped: u64,
}

/// 构造一条**已签名**的 `ConsensusQc` 信封（复用既有 `egress::envelope_for`；**零 wire 变更**）。
///
/// - payload = `encode_qc(qc)`（既有 codec）；超出 `max_msg_bytes` ⇒ `Err`（**不截断**）。
/// - 签名失败 ⇒ `Err`（fail-closed；不发不完整消息）。
fn build_qc_envelope(
    signer: &dyn NetworkSigner,
    qc: &QuorumCertificate,
    max_msg_bytes: usize,
) -> Result<MessageEnvelope, ()> {
    let envelope =
        crate::egress::envelope_for(&OutboundConsensusMessage::VerifiedQc(qc.clone()), signer)
            .map_err(|_| ())?;
    if envelope.payload.len() > max_msg_bytes {
        return Err(());
    }
    Ok(envelope)
}

/// P1-A.7 — 在 block 响应之后附发历史 QC（**既有** `MessageType::ConsensusQc`；不新增消息）。
///
/// 顺序与上限：
/// 1. **请求高度对应 QC**（追赶必需；来源 `qc_history.get(requested_height)`）；
/// 2. **tip hint ≤ 1 条**（来源 `qc_history.tip_height()` 的**直接** `get`；**不扫描目录** /
///    不遍历历史）；仅当与已发高度不同。
///
/// 边界：只发本地**已持久化**的 QC；缺失 ⇒ 不发（fail-closed 由对端自行验证）；
/// 超尺寸 / 签名失败 / artifact 损坏 ⇒ 不发 + 计数（不截断 / 不猜测 / 不跨高度借）。
fn serve_qc(
    ns: &mut NetworkService<BoxTransport>,
    signer: &dyn NetworkSigner,
    peer: NodeId,
    max_msg_bytes: usize,
    qc_history: Option<&QcHistory>,
    requested_height: u64,
) -> QcServeTally {
    let mut tally = QcServeTally::default();
    let Some(store) = qc_history else {
        return tally;
    };
    let mut sent_height: Option<u64> = None;
    match store.get(requested_height) {
        Ok(Some(qc)) => match build_qc_envelope(signer, &qc, max_msg_bytes) {
            Ok(envelope) => match ns.enqueue_outbound(peer, envelope) {
                Ok(()) => {
                    tally.served += 1;
                    sent_height = Some(requested_height);
                }
                Err(_) => tally.skipped += 1,
            },
            Err(()) => tally.skipped += 1,
        },
        Ok(None) => {}
        Err(_) => tally.skipped += 1,
    }
    // tip hint：≤ 1；**直接路径**查询（不扫描 / 不遍历）。
    if let Some(tip) = store.tip_height()
        && sent_height != Some(tip)
    {
        match store.get(tip) {
            Ok(Some(qc)) => match build_qc_envelope(signer, &qc, max_msg_bytes) {
                Ok(envelope) => {
                    if ns.enqueue_outbound(peer, envelope).is_ok() {
                        tally.served += 1;
                    } else {
                        tally.skipped += 1;
                    }
                }
                Err(()) => tally.skipped += 1,
            },
            Ok(None) => {}
            Err(_) => tally.skipped += 1,
        }
    }
    tally
}

/// **只读**块查找（不写存储 / 不改 head / 不产生 finality）。
///
/// - `request.block_hash = Some(h)`：`BlockStore::get(h)`；并要求块高度 == `request.height`
///   （否则 `Missing` —— 绝不回送与请求高度不符的块）。
/// - `request.block_hash = None`：从 **canonical head** 沿 `parent_hash` 回走到 `request.height`；
///   步数 ≤ `MAX_SYNC_WALK`（超限 ⇒ `WalkExceeded`）。高度 0（genesis）无 BlockV1 实体 ⇒ `Missing`。
/// - 存储损坏（`get` 返回 `Err`）⇒ `Missing`（fail-closed；不 panic）。
pub fn lookup_block<B: StorageBackend + Clone>(
    adapter: &NodeBlockAdapter<B, NoAccountsKeyResolver>,
    request: &SyncBlockRequest,
) -> SyncLookup {
    let Some(block_store) = adapter.block_store() else {
        return SyncLookup::NoBlockStore;
    };
    if let Some(hash) = request.block_hash {
        return match block_store.get(&hash) {
            Ok(Some(block)) if block.header.height == request.height => {
                SyncLookup::Found(Box::new(block))
            }
            _ => SyncLookup::Missing,
        };
    }
    let head = adapter.head();
    if request.height == 0 || request.height > head.height {
        // 高度 0 = genesis（无 block 实体）；高于 head = 尚未 canonical（不猜 / 不回其它块）。
        return SyncLookup::Missing;
    }
    let mut hash = head.block_hash;
    let mut height = head.height;
    let mut steps = 0u64;
    loop {
        let block = match block_store.get(&hash) {
            Ok(Some(b)) => b,
            _ => return SyncLookup::Missing,
        };
        if block.header.height != height {
            // 存储内容与预期高度不一致 ⇒ fail-closed（不沿不一致链继续）。
            return SyncLookup::Missing;
        }
        if height == request.height {
            return SyncLookup::Found(Box::new(block));
        }
        if height == 0 || steps >= MAX_SYNC_WALK {
            return SyncLookup::WalkExceeded;
        }
        hash = block.header.parent_hash;
        height -= 1;
        steps += 1;
    }
}

/// 构造单块 `SyncBlockResponse` 信封（复用既有 codec + 既有 `NetworkSigner`）。
///
/// - `request_id` **原样回带**（不生成新 id）。
/// - 单块；`payload.len() > max_msg_bytes` ⇒ `Oversized`（**不截断**）。
/// - 签名失败 ⇒ `SigningFailed`。
pub fn build_response_envelope(
    signer: &dyn NetworkSigner,
    request_id: nova_network::security::RequestId,
    block: &Block,
    max_msg_bytes: usize,
) -> Result<MessageEnvelope, SyncServeOutcome> {
    debug_assert_eq!(MAX_SYNC_BLOCKS_PER_RESPONSE, 1, "本轮仅支持单块响应");
    let payload = BlockPayload::from_block(block).map_err(|_| SyncServeOutcome::Missing)?;
    let response = SyncBlockResponse {
        request_id,
        blocks: vec![payload],
    };
    let encoded = response.encode();
    if encoded.len() > max_msg_bytes {
        return Err(SyncServeOutcome::Oversized);
    }
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type: MessageType::SyncBlockResponse,
        payload: encoded,
        sender: signer.node_id(),
        signature: [0u8; 64],
    };
    signer
        .sign_envelope(&mut envelope)
        .map_err(|_| SyncServeOutcome::SigningFailed)?;
    Ok(envelope)
}

/// 有界 serve 一批入站请求（每 step 调用一次；≤ `MAX_SYNC_RESPONSES_PER_STEP` 条）。
///
/// 返回本 step 实际处理的请求数（调用方用于观测；不返回 `Err` —— 单条失败只计数，不中断 step）。
pub fn serve_requests<B: StorageBackend + Clone>(
    adapter: Option<&NodeBlockAdapter<B, NoAccountsKeyResolver>>,
    ns: &mut NetworkService<BoxTransport>,
    signer: &dyn NetworkSigner,
    requests: Vec<(NodeId, Vec<u8>)>,
    diagnostics: &mut SyncRespondDiagnostics,
    qc_history: Option<&QcHistory>,
) -> usize {
    let max_msg_bytes = ns.config().max_msg_bytes;
    let mut handled = 0usize;
    for (peer, payload) in requests.into_iter().take(MAX_SYNC_RESPONSES_PER_STEP) {
        handled += 1;
        let (outcome, qc_tally) = serve_one(
            adapter,
            ns,
            signer,
            peer,
            &payload,
            max_msg_bytes,
            qc_history,
        );
        diagnostics.record(outcome);
        diagnostics.record_qc(qc_tally);
    }
    handled
}

fn serve_one<B: StorageBackend + Clone>(
    adapter: Option<&NodeBlockAdapter<B, NoAccountsKeyResolver>>,
    ns: &mut NetworkService<BoxTransport>,
    signer: &dyn NetworkSigner,
    peer: NodeId,
    payload: &[u8],
    max_msg_bytes: usize,
    qc_history: Option<&QcHistory>,
) -> (SyncServeOutcome, QcServeTally) {
    // ① 结构：既有 codec 解码（失败 ⇒ 不响应；不 panic）。
    let Ok(request) = SyncBlockRequest::decode(payload) else {
        return (SyncServeOutcome::Malformed, QcServeTally::default());
    };
    // ② 防御性 Established 检查（NetworkService 已对非 Established 的**非 Handshake** 消息
    //    fail-closed 丢弃；此处再确认一次，保证 responder 自身不依赖上游隐含条件）。
    if !ns.is_peer_established(peer) {
        return (SyncServeOutcome::NotEstablished, QcServeTally::default());
    }
    // ③ 只读查找（无 adapter / 无 BlockStore ⇒ 明确不响应）。
    let Some(adapter) = adapter else {
        return (SyncServeOutcome::NoBlockStore, QcServeTally::default());
    };
    let block = match lookup_block(adapter, &request) {
        SyncLookup::Found(block) => block,
        SyncLookup::Missing => return (SyncServeOutcome::Missing, QcServeTally::default()),
        SyncLookup::WalkExceeded => {
            return (SyncServeOutcome::WalkExceeded, QcServeTally::default());
        }
        SyncLookup::NoBlockStore => {
            return (SyncServeOutcome::NoBlockStore, QcServeTally::default());
        }
    };
    // ④ 既有 codec + 既有签名构造响应（request_id 原样回带；超限 fail-closed）。
    let envelope = match build_response_envelope(signer, request.request_id, &block, max_msg_bytes)
    {
        Ok(env) => env,
        Err(outcome) => return (outcome, QcServeTally::default()),
    };
    // ⑤ 既有 outbound 路径（Established-only 队列；不直接写 socket）。
    match ns.enqueue_outbound(peer, envelope) {
        Ok(()) => {
            // ⑥ P1-A.7：block 已入队 ⇒ 附发历史 QC（请求高度 + ≤1 tip hint；既有 ConsensusQc）。
            let tally = serve_qc(ns, signer, peer, max_msg_bytes, qc_history, request.height);
            (SyncServeOutcome::Served, tally)
        }
        Err(_) => (SyncServeOutcome::SendRejected, QcServeTally::default()),
    }
}
