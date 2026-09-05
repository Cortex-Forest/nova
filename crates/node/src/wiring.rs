//! Consensus inbound **decode-queue adapter + 单一 orchestration**（STEP 10-18I-D-A；Option A）。
//!
//! # 定位
//! - [`NodeConsensusHandler`]：node 层 EventLoop handler —— **无 Driver / 无 egress / 无网络**。
//!   只把 NetworkService 已完成验签/分类的 `NetworkEvent`（payload opaque）decode/classify 成
//!   owned [`NodeConsensusCommand`] 入 FIFO 队列；**不**做任何 consensus mutation / verify / lock。
//! - [`process_command`]：node 层**单一 consensus orchestration**（Runtime / 测试复用）——command →
//!   Driver 既有安全门面（`submit_remote_vote` / `submit_proposal` / `submit_inbound_qc` /
//!   `process_transition_derived`）→ ConsensusNode / ValidatorActor。Driver 仍为唯一
//!   consensus mutation owner。
//! - outbound：不在此处理；Driver `take_outbound()`（仅验证 PASS 后）由 Runtime / 调用方
//!   取走 → NetworkEgress adapter（生产 future；测试层注入）。
//!
//! # 数据流
//! ```text
//! Transport → NetworkService → NetworkEvent → EventLoop → NodeConsensusHandler
//!     → decode/classify → NodeConsensusCommand → queue
//!     → NodeRuntime / 调用方 process_command(&mut Driver, cmd)
//!     → Driver（verify_vote_input / verify_qc / submit_* / process_transition_derived）
//!     → ConsensusNode canonical transition / ValidatorActor acquire_lock
//! ```
//!
//! # 边界
//! - NetworkService / EventLoop **不** decode consensus payload、**不** verify、**不** lock。
//! - Handler **不**拥有 / 引用：NodeConsensusDriver / ConsensusNode / ValidatorActor / SafetyStore /
//!   VoteLedger / SigningCapability / NetworkService / Transport / NetworkSigner / NodeRuntime。
//! - ConsensusVote / ConsensusProposal / ConsensusQc → consensus command；
//!   Gossip / Sync / Status / Handshake / Ping / Pong / Timer / Internal / Block → 非共识 seam
//!   （不产生 command；仅计数）。
//! - decode 失败 ⇒ handler 返回 `Err(InvalidEvent)`（EventLoop 计 handler_errors；不 panic）。
//! - `decode 成功 ≠ verify 成功`（尤其 QC）：verify 仅在 Driver 既有 choke 完成（Handler 绝不
//!   broadcast / lock / finality）。

use nova_consensus::finality::{QuorumCertificate, decode_qc};
use nova_consensus::round::{ProposalRef, decode_proposal_ref};
use nova_consensus::vote::{ValidatorVote, decode_validator_vote};
use nova_network::event_loop::{EventHandler, EventLoopError, NodeEvent};
use nova_network::network_service::NetworkEvent;
use std::collections::VecDeque;

use crate::driver::{DriverError, NodeConsensusDriver};
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

/// Node 层 semantic command（owned；无引用 / 无 driver / 无 runtime / 无网络）。
///
/// 目的：把 EventLoop/Network 层已收到的 consensus wire 转成 node 层 semantic input，
/// 供 [`process_command`]（Runtime / 测试）交给 Driver 的既有验证门面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeConsensusCommand {
    /// Remote vote（网络证据；`verify_vote_input` 在 Driver；不进本地 VoteLedger）。
    RemoteVote {
        vote: ValidatorVote,
        signature: [u8; 64],
    },
    /// Remote proposal（ProposalRef；canonical 守卫在 Driver/transition）。
    Proposal(ProposalRef),
    /// Remote QC（decode 成功 ≠ verify 成功；`verify_qc` 在 Driver）。
    InboundQc(QuorumCertificate),
}

/// Node 层 EventLoop handler（Option A）：decode/classify → command queue。
///
/// **不拥有 / 不引用** Driver / Runtime / NetworkService / Transport / NetworkSigner /
/// ValidatorActor / ConsensusNode / SafetyStore / VoteLedger / SigningCapability（见模块 doc）。
pub struct NodeConsensusHandler {
    commands: VecDeque<NodeConsensusCommand>,
    /// 非 consensus 事件计数（Ping/gossip/sync/status/timer/block…；future handler seam）。
    non_consensus_seen: u64,
}

impl NodeConsensusHandler {
    /// 构造（空 command 队列）。
    pub fn new() -> Self {
        Self {
            commands: VecDeque::new(),
            non_consensus_seen: 0,
        }
    }

    /// 已见但未产生 command 的事件数（非 consensus seam）。
    pub fn non_consensus_seen(&self) -> u64 {
        self.non_consensus_seen
    }

    /// 当前待处理 command 数（FIFO 深度）。
    pub fn pending_commands(&self) -> usize {
        self.commands.len()
    }

    /// 取走全部待处理 command（FIFO；owned；同步；deterministic）。
    pub fn take_commands(&mut self) -> Vec<NodeConsensusCommand> {
        self.commands.drain(..).collect()
    }

    // ---------- decode/classify（无 driver / 无 verify） ----------

    fn decode_vote(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let (vote, signature) = decode_vote_payload(payload)?;
        self.commands
            .push_back(NodeConsensusCommand::RemoteVote { vote, signature });
        Ok(())
    }

    fn decode_proposal(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let proposal = decode_proposal_ref(payload).map_err(|_| EventLoopError::InvalidEvent)?;
        self.commands
            .push_back(NodeConsensusCommand::Proposal(proposal));
        Ok(())
    }

    fn decode_qc(&mut self, payload: &[u8]) -> Result<(), EventLoopError> {
        let qc = decode_qc(payload).map_err(|_| EventLoopError::InvalidEvent)?;
        self.commands.push_back(NodeConsensusCommand::InboundQc(qc));
        Ok(())
    }
}

impl Default for NodeConsensusHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHandler for NodeConsensusHandler {
    fn handle(&mut self, event: &NodeEvent) -> Result<(), EventLoopError> {
        match event {
            NodeEvent::Network(NetworkEvent::ConsensusVote { payload, .. }) => {
                self.decode_vote(payload)
            }
            NodeEvent::Network(NetworkEvent::ConsensusProposal { payload, .. }) => {
                self.decode_proposal(payload)
            }
            NodeEvent::Network(NetworkEvent::ConsensusQc { payload, .. }) => {
                self.decode_qc(payload)
            }
            // 非 consensus：gossip/sync/status/handshake/ping/pong/timer/internal/block ——
            // future handler seam；不产生 command（尤其 Block Sync 不得借 ConsensusNode 伪装）。
            _ => {
                self.non_consensus_seen += 1;
                Ok(())
            }
        }
    }
}

/// Node 层**单一 consensus orchestration**（Option A）：command → Driver 既有安全门面。
///
/// - `RemoteVote` → `driver.submit_remote_vote`（`verify_vote_input`）→ `process_transition_derived`。
/// - `Proposal` → `driver.submit_proposal`（canonical 守卫）→ `process_transition_derived`。
/// - `InboundQc` → `driver.submit_inbound_qc`（`verify_qc` → 每本地 actor `acquire_lock`；不进 canonical）。
///
/// outbound 不在此：Driver `take_outbound()`（仅验证 PASS 后）由调用方（Runtime/egress）取走。
///
/// `S` = Driver 本地签名能力类型（测试 `SoftwareSigner`；Runtime `Box<dyn SigningCapability>`）。
pub fn process_command<S: SigningCapability>(
    driver: &mut NodeConsensusDriver<S>,
    command: NodeConsensusCommand,
) -> Result<(), DriverError> {
    match command {
        NodeConsensusCommand::RemoteVote { vote, signature } => {
            let result = driver.submit_remote_vote(vote, signature)?;
            driver.process_transition_derived(&result)
        }
        NodeConsensusCommand::Proposal(proposal) => {
            let result = driver.submit_proposal(proposal);
            driver.process_transition_derived(&result)
        }
        NodeConsensusCommand::InboundQc(qc) => driver.submit_inbound_qc(qc),
    }
}
