//! Consensus inbound/outbound **wiring adapter**（STEP 10-18G-1；Owner Option 1）。
//!
//! 把已由 NetworkService 完成 envelope 验签/分类的 `NetworkEvent`（payload **opaque**）经
//! EventLoop dispatch 到本 adapter，在 **node 层**做唯一 decode → 交给既有验证门面 →
//! Driver orchestration；Driver 产出的 outbound semantic 经 [`crate::outbound::NetworkEgress`]
//! seam 接出。
//!
//! # 数据流
//! ```text
//! Transport → NetworkService → NetworkEvent → EventLoop → NodeConsensusHandler
//!     → decode（node 层唯一 decode 点）→ Driver（verify_vote_input / verify_qc /
//!       submit_verified_vote / submit_proposal / submit_inbound_qc / process_transition_derived）
//!     → ConsensusNode canonical transition
//!     → driver.take_outbound()（仅验证 PASS 后）→ NetworkEgress（测试实现可证明网络路径）
//! ```
//!
//! # 边界
//! - NetworkService / EventLoop **不** decode consensus payload、**不** verify、**不** lock；
//!   decode/验证全部在本 node-layer adapter（G-11/G-12 对应：NS/EL 不调用 consensus 门面）。
//! - ConsensusVote / ConsensusProposal / ConsensusQc → consensus 路径；
//!   Gossip / Sync / Status / Handshake / Ping / Pong / Timer / Internal / Block →
//!   非 consensus seam（不塞入 Driver；仅计数）。
//! - 无效 payload / 门面 FAIL ⇒ `Err(InvalidEvent)`（EventLoop 计 handler_errors 并继续，
//!   fail-safe；不 panic、不 mutate）。
//! - **禁止** recursive dispatch：本 handler 不 push 事件回 EventLoop；outbound 直接经 egress
//!   （semantic intent，非回环事件）。

use nova_consensus::finality::decode_qc;
use nova_consensus::integration::TransitionResult;
use nova_consensus::round::decode_proposal_ref;
use nova_consensus::vote::{ValidatorVote, decode_validator_vote};
use nova_network::event_loop::{EventHandler, EventLoopError, NodeEvent};
use nova_network::network_service::NetworkEvent;

use crate::driver::{DriverError, NodeConsensusDriver};
use crate::outbound::NetworkEgress;
use crate::signer::SigningCapability;

/// 远程 vote wire payload（11-1 §3；与 assembly 同布局）：`canonical_vote_payload(121B) ‖ sig(64B)`。
const VOTE_PAYLOAD_LEN: usize = 121;
const VOTE_WIRE_LEN: usize = VOTE_PAYLOAD_LEN + 64;

/// 拆分并解码 vote wire payload（node adapter 层唯一 decode；不重复实现 consensus 验证）。
fn decode_vote_payload(payload: &[u8]) -> Result<(ValidatorVote, [u8; 64]), EventLoopError> {
    if payload.len() != VOTE_WIRE_LEN {
        return Err(EventLoopError::InvalidEvent);
    }
    let vote = decode_validator_vote(&payload[..VOTE_PAYLOAD_LEN])
        .map_err(|_| EventLoopError::InvalidEvent)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload[VOTE_PAYLOAD_LEN..]);
    Ok((vote, signature))
}

/// Node 层 EventLoop handler：`NodeEvent → Driver`（consensus 三类）+ outbound semantic egress。
///
/// - `S`：driver 的本地签名能力类型（与 `NodeConsensusDriver<S>` 一致）。
/// - `E`：outbound egress seam（测试注入 recording / 真实 test-key egress）。
pub struct NodeConsensusHandler<S: SigningCapability, E: NetworkEgress> {
    driver: NodeConsensusDriver<S>,
    egress: E,
    /// 非 consensus 事件计数（Ping/gossip/sync/status/timer/block…；future handler seam）。
    non_consensus_seen: u64,
}

impl<S: SigningCapability, E: NetworkEgress> NodeConsensusHandler<S, E> {
    pub fn new(driver: NodeConsensusDriver<S>, egress: E) -> Self {
        Self {
            driver,
            egress,
            non_consensus_seen: 0,
        }
    }

    pub fn driver(&self) -> &NodeConsensusDriver<S> {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut NodeConsensusDriver<S> {
        &mut self.driver
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    /// 已见但未塞入 Driver 的事件数（非 consensus seam）。
    pub fn non_consensus_seen(&self) -> u64 {
        self.non_consensus_seen
    }

    // ---------- ingress（node 层 decode → driver 既有门面） ----------

    /// Remote vote：decode → `submit_remote_vote`（verify_vote_input）→ 单一 choke
    /// `process_transition_derived` → outbound semantic egress。
    fn handle_vote(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let (vote, signature) = decode_vote_payload(payload)?;
        let result = self
            .driver
            .submit_remote_vote(vote, signature)
            .map_err(driver_error_to_event_loop)?;
        self.process_and_egress(&result)
    }

    /// Remote proposal：decode → `submit_proposal`（canonical transition 守卫）。
    fn handle_proposal(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let proposal = decode_proposal_ref(payload).map_err(|_| EventLoopError::InvalidEvent)?;
        let result = self.driver.submit_proposal(proposal);
        self.process_and_egress(&result)
    }

    /// Remote QC：decode → `submit_inbound_qc`（verify_qc → 每本地 actor acquire_lock）。
    /// Inbound QC 不 record outbound（外部证据，不重广播）。
    fn handle_qc(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let qc = decode_qc(payload).map_err(|_| EventLoopError::InvalidEvent)?;
        self.driver
            .submit_inbound_qc(qc)
            .map_err(driver_error_to_event_loop)
    }

    /// 单一 derived choke：verify_qc → 本地 actor lock → drain outbound → egress（无递归）。
    fn process_and_egress(&mut self, result: &TransitionResult) -> Result<(), EventLoopError> {
        self.driver
            .process_transition_derived(result)
            .map_err(driver_error_to_event_loop)?;
        let outbound = self.driver.take_outbound();
        if !outbound.is_empty() {
            self.egress.send_outbound(outbound);
        }
        Ok(())
    }
}

/// Driver 编排错误 → EventLoop 事件错误（fail-safe；不改状态）。
fn driver_error_to_event_loop(_err: DriverError) -> EventLoopError {
    EventLoopError::InvalidEvent
}

impl<S: SigningCapability, E: NetworkEgress> EventHandler for NodeConsensusHandler<S, E> {
    fn handle(&mut self, event: &NodeEvent) -> Result<(), EventLoopError> {
        match event {
            NodeEvent::Network(NetworkEvent::ConsensusVote { payload, .. }) => {
                self.handle_vote(payload)
            }
            NodeEvent::Network(NetworkEvent::ConsensusProposal { payload, .. }) => {
                self.handle_proposal(payload)
            }
            NodeEvent::Network(NetworkEvent::ConsensusQc { payload, .. }) => {
                self.handle_qc(payload)
            }
            // 非 consensus：gossip/sync/status/handshake/ping/pong/timer/internal/block ——
            // future handler seam；不塞入 Driver（尤其 Block Sync 不得借 ConsensusNode 伪装）。
            _ => {
                self.non_consensus_seen += 1;
                Ok(())
            }
        }
    }
}
