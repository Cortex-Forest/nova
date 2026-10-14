//! PHASE 6H-AK — D3（Owner 授权）O2 专属 **per-peer 入站限流** 集成测试。
//!
//! # 被验证的政策（Owner，逐字冻结；本测试**不**重新定义）
//! | 消息 | wire | 速率 | burst | 超限 | BAN / 断连 |
//! |---|---|---|---|---|---|
//! | `ConsensusRoundChange` | `0x0D` | 4/s/peer | 8 | **DROP** | **无** |
//! | `ConsensusAbandonAttestation` | `0x0E` | 4/s/peer | 8 | **DROP** | **无** |
//!
//! - 两个 **独立** `RoundChangeRateLimiter` 实例（**不**共享 bucket、**不**共享额度）。
//! - 唯一 gate 位置：`NetworkService::handle_inbound_frame`，**分类之后、`NetworkEvent` 入队之前**。
//! - DROP 为**完整动作**：不产生 `NetworkEvent`、不 BAN、不断开、不改任何 session / 共识状态。
//!
//! # 测试手法（无真实 TCP —— 与 Owner §7 一致）
//! 使用注入 transport（`MultiPeerTransport`，内存 inbox）直接投递 **已签名 envelope**：
//! `handle_inbound_frame` 的既有步骤 1–4（decode / `sender == raw_sender` / 信封 Ed25519 验签 /
//! payload 大小 /（auth 关闭时无 session gate））全部照常执行 ⇒ 限流 gate 之前的路径**未被绕过**。
//! 同一注入 transport 可承载多个 sender（`envelope.sender == raw_sender` 由既有步骤 2 保证），
//! 因此可在**一个** `NetworkService` 上验证 per-peer 隔离。
//!
//! 时间基准：限流器按**整秒**补充 token；全部帧在毫秒内投递 ⇒ 测试窗口内**无补充** ⇒ 确定性。

use std::collections::VecDeque;

use nova_crypto::key::KeyPair;
use nova_network::abandon_attestation::{AbandonAttestation, encode as encode_attestation};
use nova_network::message::{MessageEnvelope, MessageType, NetworkError, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::transport::Transport;

/// 注入型多 peer 内存 transport：`try_recv` 依序返回 `(sender, envelope_bytes)`。
struct MultiPeerTransport {
    inbox: VecDeque<(NodeId, Vec<u8>)>,
}

impl MultiPeerTransport {
    fn new() -> Self {
        Self {
            inbox: VecDeque::new(),
        }
    }

    fn push(&mut self, sender: NodeId, bytes: Vec<u8>) {
        self.inbox.push_back((sender, bytes));
    }
}

impl Transport for MultiPeerTransport {
    fn send(&mut self, _peer: &NodeId, _message: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        Ok(self.inbox.pop_front())
    }
}

fn cfg() -> NetworkServiceConfig {
    NetworkServiceConfig {
        max_msg_bytes: 4096,
        inbound_capacity: 1024,
        outbound_capacity: 1024,
        peer_auth: None,
    }
}

fn node_id(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// 构造 + 签名一条 envelope（sender = NodeId(pubkey)）。
fn signed(kp: &KeyPair, mt: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    let mut e = MessageEnvelope {
        version: 1,
        message_type: mt,
        payload,
        sender: node_id(kp),
        signature: [0u8; 64],
    };
    sign_message(kp.signing_key(), &mut e).expect("sign envelope");
    e
}

/// 真实 112B `0x0E` 容器（复用冻结 ADR-0074 codec；network 层不解析其语义）。
fn attestation_payload() -> Vec<u8> {
    encode_attestation(&AbandonAttestation {
        height: 0,
        from_round: 0,
        validator_id: [0xAB; 32],
        signature: [0xCD; 64],
    })
}

/// 一条 `0x0D` 帧的 payload（network 层 opaque；长度取真实证书量级以下）。
fn certificate_payload() -> Vec<u8> {
    vec![0xC0; 64]
}

/// 预构造 `count` 条同类型帧（同一 sender）。
fn frames(
    kp: &KeyPair,
    mt: MessageType,
    payload: impl Fn() -> Vec<u8>,
    count: usize,
) -> Vec<(NodeId, Vec<u8>)> {
    (0..count)
        .map(|_| {
            let env = signed(kp, mt, payload());
            (node_id(kp), encode(&env))
        })
        .collect()
}

/// 以**预装载**帧构造 service（注入 transport，顺序保持）；随后由调用方 `poll_transport()`。
/// 不添加任何生产侧 accessor。
fn service_with(frames: Vec<(NodeId, Vec<u8>)>) -> NetworkService<MultiPeerTransport> {
    let mut t = MultiPeerTransport::new();
    for (sender, bytes) in frames {
        t.push(sender, bytes);
    }
    NetworkService::new(cfg(), NodeId::from_bytes([0x01; 32]), t)
}

#[test]
fn round_change_burst_8_then_drop() {
    let kp = KeyPair::generate().unwrap();
    let mut svc = service_with(frames(
        &kp,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        9,
    ));

    let accepted = svc.poll_transport().expect("poll");

    assert_eq!(accepted, 8, "burst 8 ⇒ 前 8 条入站");
    let events = svc.drain_inbound();
    assert_eq!(events.len(), 8);
    assert!(
        events
            .iter()
            .all(|e| e.message_type() == MessageType::ConsensusRoundChange)
    );
    assert_eq!(
        svc.diagnostics().round_change_rate_limited,
        1,
        "第 9 条被 DROP"
    );
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 0);
    assert_eq!(
        svc.diagnostics().dropped_invalid,
        0,
        "限流不得混入 dropped_invalid"
    );
    assert_eq!(
        svc.diagnostics().dropped_overflow,
        0,
        "限流不得混入 dropped_overflow"
    );
    assert_eq!(
        svc.diagnostics().frames_received,
        9,
        "九帧均经既有 decode/验签（未被绕过）"
    );
}

#[test]
fn abandon_attestation_burst_8_then_drop() {
    let kp = KeyPair::generate().unwrap();
    let mut svc = service_with(frames(
        &kp,
        MessageType::ConsensusAbandonAttestation,
        attestation_payload,
        9,
    ));

    let accepted = svc.poll_transport().expect("poll");

    assert_eq!(accepted, 8);
    let events = svc.drain_inbound();
    assert_eq!(events.len(), 8);
    assert!(
        events
            .iter()
            .all(|e| e.message_type() == MessageType::ConsensusAbandonAttestation)
    );
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 1);
    assert_eq!(svc.diagnostics().round_change_rate_limited, 0);
    assert_eq!(svc.diagnostics().dropped_invalid, 0);
    assert_eq!(svc.diagnostics().dropped_overflow, 0);
    assert_eq!(svc.diagnostics().frames_received, 9);
}

/// **关键**：证明 `0x0D` 与 `0x0E` **不共享** bucket。
#[test]
fn buckets_are_independent_across_message_types() {
    let kp = KeyPair::generate().unwrap();
    // 预装载：[9 × 0x0E] 然后 [1 × 0x0D]（顺序保持 ⇒ 0x0D 在 0x0E 配额耗尽**之后**处理）。
    let mut all = frames(
        &kp,
        MessageType::ConsensusAbandonAttestation,
        attestation_payload,
        9,
    );
    all.extend(frames(
        &kp,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        1,
    ));
    let mut svc = service_with(all);

    let accepted = svc.poll_transport().expect("poll");
    assert_eq!(
        accepted, 9,
        "0x0E × 8 + 0x0D × 1（独立 bucket ⇒ 0x0D 未被拦）"
    );
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 1);
    assert_eq!(
        svc.diagnostics().round_change_rate_limited,
        0,
        "0x0E 耗尽不得影响 0x0D 配额"
    );

    // 事件顺序：前 8 条 0x0E，然后（配额耗尽之后）第 9 条 0x0D 仍被投递。
    let events = svc.drain_inbound();
    assert_eq!(events.len(), 9);
    assert!(
        events[..8]
            .iter()
            .all(|e| e.message_type() == MessageType::ConsensusAbandonAttestation)
    );
    assert_eq!(events[8].message_type(), MessageType::ConsensusRoundChange);
}

#[test]
fn peers_have_independent_buckets() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    // 预装载：[A: 9 × 0x0D] → [B: 1 × 0x0D, 1 × 0x0E]（顺序保持）。
    let mut all = frames(
        &kp_a,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        9,
    );
    all.extend(frames(
        &kp_b,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        1,
    ));
    all.extend(frames(
        &kp_b,
        MessageType::ConsensusAbandonAttestation,
        attestation_payload,
        1,
    ));
    let mut svc = service_with(all);

    let accepted = svc.poll_transport().expect("poll");
    assert_eq!(accepted, 10, "A: 8 条 + B: 2 条（B 不继承 A 的消耗）");
    assert_eq!(
        svc.diagnostics().round_change_rate_limited,
        1,
        "仅 A 的第 9 条被限"
    );
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 0);

    let events = svc.drain_inbound();
    assert_eq!(events.len(), 10);
    assert_eq!(
        events[8].message_type(),
        MessageType::ConsensusRoundChange,
        "B 的 0x0D"
    );
    assert_eq!(
        events[9].message_type(),
        MessageType::ConsensusAbandonAttestation,
        "B 的 0x0E"
    );
}

#[test]
fn rate_limit_drop_has_no_side_effects() {
    let kp = KeyPair::generate().unwrap();
    // 预装载：[9 × 0x0D] → [1 × Ping]（DROP 后服务必须继续工作）。
    let mut all = frames(
        &kp,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        9,
    );
    all.extend(frames(&kp, MessageType::Ping, || vec![0x01], 1));
    let mut svc = service_with(all);

    let accepted = svc.poll_transport().expect("poll");
    assert_eq!(accepted, 9, "8 条 0x0D + 1 条 Ping（DROP 后服务仍可用）");
    assert_eq!(svc.diagnostics().round_change_rate_limited, 1);

    // DROP 完整动作：不 BAN / 不断开 / 不改其它任何计数。
    let d = svc.diagnostics();
    assert_eq!(d.dropped_invalid, 0);
    assert_eq!(d.dropped_overflow, 0);
    assert_eq!(d.unauthenticated_drops, 0);
    assert_eq!(d.replay_drops, 0);
    assert_eq!(d.handshake_attempts, 0, "限流不得触发握手/关闭路径");
    assert_eq!(d.handshake_success, 0);
    assert_eq!(d.handshake_failures, 0);
    assert_eq!(d.sent, 0, "限流不得产生出站");
    assert_eq!(
        svc.state(),
        nova_network::network_service::NetworkServiceState::Running
    );

    // 服务未进入 Stopped / 未断开：普通消息照常入站。
    let events = svc.drain_inbound();
    assert_eq!(events.len(), 9);
    assert_eq!(events[8].message_type(), MessageType::Ping);
    assert_eq!(
        svc.diagnostics().round_change_rate_limited,
        1,
        "计数不因后续消息变化"
    );
}

#[test]
fn legitimate_traffic_is_not_rate_limited() {
    let kp = KeyPair::generate().unwrap();
    // 真实停滞轮量级：≤2 张证书 + ≤2 条 attestation（远低于 burst 8）。
    let mut all = frames(
        &kp,
        MessageType::ConsensusRoundChange,
        certificate_payload,
        2,
    );
    all.extend(frames(
        &kp,
        MessageType::ConsensusAbandonAttestation,
        attestation_payload,
        2,
    ));
    let mut svc = service_with(all);

    let accepted = svc.poll_transport().expect("poll");
    assert_eq!(accepted, 4, "全部投递");
    assert_eq!(svc.drain_inbound().len(), 4);
    assert_eq!(svc.diagnostics().round_change_rate_limited, 0);
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 0);
    assert_eq!(svc.diagnostics().dropped_invalid, 0);
    assert_eq!(svc.diagnostics().dropped_overflow, 0);
}

#[test]
fn other_message_types_are_unaffected() {
    let kp = KeyPair::generate().unwrap();
    // 12 条 Ping（> burst 8）必须**全部**入站 —— 限流只作用于 0x0D / 0x0E。
    let mut svc = service_with(frames(&kp, MessageType::Ping, || vec![0x7f], 12));
    let accepted = svc.poll_transport().expect("poll");
    assert_eq!(accepted, 12, "普通消息不受 O2 配额影响");
    assert_eq!(svc.drain_inbound().len(), 12);
    assert_eq!(svc.diagnostics().round_change_rate_limited, 0);
    assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 0);

    // 其它共识 wire（Vote / QC / GossipBlock）同样不受影响（每类 10 条 > burst 8）。
    for mt in [
        MessageType::ConsensusVote,
        MessageType::ConsensusQc,
        MessageType::GossipBlock,
    ] {
        let mut svc = service_with(frames(&kp, mt, || vec![0x11; 8], 10));
        let accepted = svc.poll_transport().expect("poll");
        assert_eq!(accepted, 10, "{mt:?} 不受影响");
        assert_eq!(svc.drain_inbound().len(), 10);
        assert_eq!(svc.diagnostics().round_change_rate_limited, 0);
        assert_eq!(svc.diagnostics().abandon_attestation_rate_limited, 0);
    }
}
