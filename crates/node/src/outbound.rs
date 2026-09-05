//! Consensus outbound **semantic** seam（STEP 10-18G-1；Owner Option 1）。
//!
//! # 定位
//! - 只表达「**应该发送什么**」的 consensus-domain intent（semantic）；**不含** Transport /
//!   NetworkService / MessageEnvelope / private key（`what to send`，不是 `how to send`）。
//! - 字段直接复用既有 consensus wire 类型（`ValidatorVote` / `QuorumCertificate` /
//!   `ProposalRef`）——不重新发明 consensus encoding。
//! - **只有**通过既有验证门面（`verify_vote_input` / `verify_qc`）的消息才会被
//!   [`crate::driver::NodeConsensusDriver`] 放入 outbound（unverified never outbound）。
//!
//! # NetworkEgress seam
//! - 把 Driver 产出的 outbound intent 接出的最小接口；生产网络身份签名
//!   （NodeId key → pre-signed `MessageEnvelope` → `NetworkService`）**DEFERRED（GAP-A）**。
//! - 测试实现可用 test KeyPair + `MemoryTransport` 证明整条网络发送路径（见 node tests）。
//!
//! # 边界
//! - Driver 不拥有 Transport / NetworkService / EventLoop；只产出 semantic output。
//! - 本模块不引用 network crate；network crate 亦不引用本模块（依赖方向 node → network）。

use nova_consensus::finality::QuorumCertificate;
use nova_consensus::round::ProposalRef;
use nova_consensus::vote::ValidatorVote;

/// Driver 产出的、需要广播给网络对端的 consensus outbound **语义**消息。
///
/// 只含既有 consensus wire 类型；不携带网络/传输/签名 key 句柄。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundConsensusMessage {
    /// 本地已签名 vote（validator 已 durable intent → sign → durable signature；随后经
    /// `verify_vote_input` PASS 才被 Driver record）。
    Vote {
        vote: ValidatorVote,
        signature: [u8; 64],
    },
    /// 已验证 precommit QC（`derived.precommit_qc` 经 `verify_qc` PASS 后才被 Driver record）。
    VerifiedQc(QuorumCertificate),
    /// 本地 proposal（`ProposalRef`；本 STEP 无 ProposerService ⇒ **无自动 source**，仅保留
    /// semantic seam 供未来 proposer 使用；不人为构造）。
    Proposal(ProposalRef),
}

/// 出站 egress seam：把 Driver 产出的 consensus semantic output 接出。
///
/// - 生产实现（未来，GAP-A 解除后）：`intent → network identity signing → MessageEnvelope →
///   NetworkService.broadcast`。
/// - 测试实现：test KeyPair + `MemoryTransport`（真实 sign + 发送路径）。
pub trait NetworkEgress {
    /// 发送一批 consensus outbound semantic 消息。
    fn send_outbound(&mut self, messages: Vec<OutboundConsensusMessage>);
}
