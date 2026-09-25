//! P1-A.26 — **Non-validator follower as sync responder**（test-only；零生产改动）。
//!
//! # 目标（补齐 G1）
//! P1-A.24 使 `validator_enabled = false` 的 full-node 具备 canonical `NodeBlockAdapter` +
//! per-height QC history；P1-A.25 证明其可 restart/恢复。本测试补最后一项**未被覆盖的能力**：
//! 非验证者 follower 作为 **sync responder** —— 向第三个节点提供 block **与历史 QC**，
//! 使 requester 能真实追平。
//!
//! # 拓扑（真实 TCP，非 mock）
//! ```text
//! A (validator；genesis {SEED_V1} 单验证者 ⇒ quorum 1/1；listener)
//!   ↑ dial
//! B (non-validator full-node follower；listener)
//!   ↑ dial
//! C (non-validator requester；**仅**连 B ⇒ 收不到 A 的 gossip ⇒ 必须经 sync 追平)
//! ```
//! C 的追平机制（P1-A.7 / P1-A.17 既有通路，本测试不改任何实现）：
//! 1. B 将**已验证**的远端派生 QC 转发给 C（Owner option (i)：forwarded verified QC）；
//! 2. C 收到 target ∉ 自身 DAG 的 QC ⇒ `UnknownTarget` 被容忍（deferred + 有界缓冲）
//!    ⇒ 以更高高度证据记录 `head + 1` 的 missing-ancestor intent；
//! 3. C 向 B 发 `SyncBlockRequest`（`request_id` correlation）；B 以 `BlockStore` **只读**响应
//!    并**附发对应高度的历史 QC**（`serve_qc`）⇒ C 逐高度 finalize/commit，head 前进。
//!
//! # 语义边界（不得夸大）
//! - 本测试 == **VERIFIED: 3-node（1 validator + 1 follower responder + 1 requester）**；
//!   **不是** "3-node mixed validator testnet verified"，**不是** testnet / production ready。
//! - gap ≪ `MAX_SYNC_WALK = 512` ⇒ 走**正常窗口**路径；P1-A.23 exact（verified-history）路径
//!   需 >512 的真实离线窗口（由 `d10_p1_a23a` / `d10_p1_a23` 独立覆盖）⇒ 本测试**仅在被触发时**
//!   断言 `served_via_verified_hash >= 1 ∧ walk_exceeded == 0`，否则只打印观测值。
//! - **不**断言 QC 转发次数上界（option (i) 允许 ≥ 1）。
//! - 本文件不修改任何生产代码 / 共享 rig（`d10_p1_a10_common`）。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::key_provider::KeyProviderConfig;
use nova_node::runtime::NodeRuntime;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_N3, SEED_V1, finalized_ref, free_port, head_height, net_node_id,
    start_node, target,
};

/// C 需要追平到的高度（≥ 该值时停止驱动）。
const TARGET_HEIGHT: u64 = 8;
/// 驱动 step 预算（纯计数 ⇒ 与机器速度无关）。
const STEP_BUDGET: usize = 20_000;
/// 建连 step 预算（纯计数）。
const CONNECT_STEP_BUDGET: usize = 400;

/// 单步驱动（错误只记录为诊断，不 panic —— 与共享 rig 一致的 fail-soft 观测策略）。
fn drive(node: &mut rig::Node) {
    if let Err(e) = node.rt.step() {
        node.last_err = Some(format!("{e:?}"));
    }
}

/// 构造 **非验证者** full-node（`validator_enabled = false`，**无** validator key / actor）。
///
/// 与共享 rig `start_node` 的唯一差异：`validator_enabled = false` +
/// `key_provider_config = None` + `start_with_network(.., None, ..)`（不注入 validator provider）。
fn start_non_validator(
    env: &Env,
    label: &'static str,
    net_seed: [u8; 32],
    listen: Option<SocketAddr>,
    peers: Vec<ConnectionTarget>,
) -> rig::Node {
    let mut cfg = env.config(label, listen, peers.clone());
    cfg.validator_enabled = false;
    cfg.key_provider_config = KeyProviderConfig::None;

    let self_id = net_node_id(net_seed);
    let (tx_self, _tx_other) = MemoryTransport::pair(self_id, NodeId::from_bytes([0x99; 32]));
    let rt = NodeRuntime::start_with_network(
        &cfg,
        None, // ← 无 validator key / 无 KeyProvider
        Box::new(tx_self),
        Box::new(rig::SeedNetworkIdentity::from_seed(net_seed)),
    )
    .expect("非验证者（full-node）runtime 启动");
    let listen = rt.network_listen_addr();
    rig::Node {
        label,
        val_seed: [0u8; 32],
        net_seed,
        listen,
        rt,
        last_err: None,
        peer_ids: peers.into_iter().map(|p| p.peer_id).collect(),
    }
}

/// 有界建连：`near`（主动 dial）↔ `far` 双向 Established（必须同时驱动两侧）。
fn connect_to(near: &mut rig::Node, far: &mut rig::Node, far_id: NodeId) -> bool {
    for _ in 0..CONNECT_STEP_BUDGET {
        let _ = near.rt.establish_configured_peers();
        drive(near);
        drive(far);
        if near.rt.network_peer_established(far_id) {
            return true;
        }
        thread::yield_now();
    }
    false
}

#[test]
fn d10_p1_a26_follower_as_sync_responder() {
    // -----------------------------------------------------------------------
    // 固定装置：genesis = {V1}（唯一 validator ⇒ quorum 1/1；B/C 均为非成员）
    // -----------------------------------------------------------------------
    let env = Env::new("a26", &[SEED_V1]);

    // ---------- A：validator（listener）----------
    let a_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut a = start_node(&env, "a", SEED_V1, SEED_N1, Some(a_listen), Vec::new());
    let a_id = net_node_id(SEED_N1);
    let a_addr = a.listen.expect("A 必须绑定真实 listener");
    assert!(a.rt.validator_enabled(), "A 必须是 validator");
    assert!(a.rt.validator().is_some(), "A 必须有 validator actor");

    // ---------- B：non-validator follower（dial A；自带 listener 供 C dial）----------
    let b_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut b = start_non_validator(
        &env,
        "b",
        SEED_N2,
        Some(b_listen),
        vec![target(a_id, a_addr)],
    );
    let b_id = net_node_id(SEED_N2);
    let b_addr = b.listen.expect("B 必须绑定 listener（C 需要 dial B）");
    assert!(!b.rt.validator_enabled(), "B 必须是 full-node / observer");
    assert!(
        b.rt.validator().is_none(),
        "B 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        b.rt.block_production().is_some(),
        "P1-A.24：B 必须有 canonical adapter（可验证 / 登记 / 采纳 / commit / serve sync）"
    );

    assert!(
        connect_to(&mut b, &mut a, a_id),
        "B 未与 A 建立 Established（B.last_err={:?} A.last_err={:?}）",
        b.last_err,
        a.last_err
    );

    // A 产块 → B 跟随至 TARGET_HEIGHT（此间 C 尚未加入 ⇒ C 天然落后）
    let mut steps_ab: usize = 0;
    while steps_ab < STEP_BUDGET && head_height(&b.rt) < TARGET_HEIGHT {
        let _ = b.rt.establish_configured_peers();
        drive(&mut b);
        drive(&mut a);
        steps_ab += 1;
        thread::yield_now();
    }
    assert!(
        head_height(&b.rt) >= TARGET_HEIGHT,
        "B 未跟随到目标高度（head={} < {TARGET_HEIGHT}；steps={steps_ab}）",
        head_height(&b.rt)
    );

    // ---------- C：non-validator requester（**仅** dial B；无 listener）----------
    let b_head_at_c_start = head_height(&b.rt);
    let a_head_at_c_start = head_height(&a.rt);
    let mut c = start_non_validator(&env, "c", SEED_N3, None, vec![target(b_id, b_addr)]);
    assert!(
        !c.rt.validator_enabled() && c.rt.validator().is_none(),
        "C 亦必须是非验证者（无 actor）"
    );
    assert!(
        c.rt.block_production().is_some(),
        "C 必须有 canonical adapter（否则无法验证 / 登记 / commit 追平）"
    );
    let c_head_at_start = head_height(&c.rt);
    assert_eq!(c_head_at_start, 0, "C 应从 genesis head 起步（尚未同步）");

    assert!(
        connect_to(&mut c, &mut b, b_id),
        "C 未与 B 建立 Established（C.last_err={:?} B.last_err={:?}）",
        c.last_err,
        b.last_err
    );

    // ---------- 追平：C 经 B 的 sync 响应前进（持续驱动 A ⇒ B 持续转发 QC 作为 C 的证据）----------
    let mut steps_catchup: usize = 0;
    while steps_catchup < STEP_BUDGET && head_height(&c.rt) < b_head_at_c_start {
        let _ = c.rt.establish_configured_peers();
        drive(&mut c);
        drive(&mut b);
        drive(&mut a);
        steps_catchup += 1;
        thread::yield_now();
    }

    // ---------- 证据读数 ----------
    let b_head_after = head_height(&b.rt);
    let a_head_after = head_height(&a.rt);
    let c_head_after = head_height(&c.rt);
    let b_diag = b.rt.sync_respond_diagnostics();
    let c_finalized = finalized_ref(&c.rt);
    let b_finalized = finalized_ref(&b.rt);
    let c_qc_tip_after = c.rt.qc_history_tip_height();
    let c_resolved = c.rt.sync_resolved_responses();
    let c_unknown = c.rt.sync_unknown_responses();
    let c_skipped = c.rt.block_inbound_skipped();
    let b_skipped = b.rt.block_inbound_skipped();
    let b_qc_write_failed = b.rt.qc_history_write_failed();
    let a_rejected = a.rt.inbound_consensus_rejected();
    let steps = steps_ab + steps_catchup;

    println!(
        "P1-A.26 EVIDENCE (real TCP; A=validator, B=non-validator follower/responder, C=non-validator requester)\n\
         \x20 a_head_at_c_start               = {a_head_at_c_start}\n\
         \x20 b_head_at_c_start               = {b_head_at_c_start}\n\
         \x20 c_head_at_start                 = {c_head_at_start}\n\
         \x20 a_head_after                    = {a_head_after}\n\
         \x20 b_head_after                    = {b_head_after}\n\
         \x20 c_head_after                    = {c_head_after}\n\
         \x20 b_responder_attempts            = {}\n\
         \x20 b_responder_served              = {}\n\
         \x20 b_responder_missing             = {}\n\
         \x20 b_responder_walk_exceeded       = {}\n\
         \x20 b_responder_no_block_store      = {}\n\
         \x20 b_responder_not_established     = {}\n\
         \x20 b_responder_malformed           = {}\n\
         \x20 b_responder_send_rejected       = {}\n\
         \x20 b_responder_signing_failed      = {}\n\
         \x20 b_responder_oversized           = {}\n\
         \x20 b_served_via_verified_hash      = {}   （P1-A.23 exact 路径；需 >512 gap 才触发）\n\
         \x20 b_qc_served                     = {}   （非验证者附发**历史 QC** ⇒ C 能逐高度 finalize）\n\
         \x20 b_qc_serve_skipped              = {}\n\
         \x20 b_qc_history_write_failed       = {b_qc_write_failed}\n\
         \x20 c_qc_history_tip_after          = {c_qc_tip_after:?}\n\
         \x20 c_sync_resolved_responses       = {c_resolved}\n\
         \x20 c_sync_unknown_responses        = {c_unknown}\n\
         \x20 c_finalized_reference           = {c_finalized:?}\n\
         \x20 b_finalized_reference           = {b_finalized:?}\n\
         \x20 b_validator_enabled             = {}\n\
         \x20 b_has_validator_actor           = {}\n\
         \x20 b_has_canonical_adapter         = {}\n\
         \x20 c_validator_enabled             = {}\n\
         \x20 c_has_validator_actor           = {}\n\
         \x20 c_has_canonical_adapter         = {}\n\
         \x20 b_block_inbound_skipped         = {b_skipped}\n\
         \x20 c_block_inbound_skipped         = {c_skipped}\n\
         \x20 a_inbound_consensus_rejected    = {a_rejected}   （B/C 若发送 vote/proposal ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 steps                           = {steps}   （ab={steps_ab} catchup={steps_catchup}）\n\
         \x20 target_height                   = {TARGET_HEIGHT}",
        b_diag.attempts,
        b_diag.served,
        b_diag.missing,
        b_diag.walk_exceeded,
        b_diag.no_block_store,
        b_diag.not_established,
        b_diag.malformed,
        b_diag.send_rejected,
        b_diag.signing_failed,
        b_diag.oversized,
        b_diag.served_via_verified_hash,
        b_diag.qc_served,
        b_diag.qc_serve_skipped,
        b.rt.validator_enabled(),
        b.rt.validator().is_some(),
        b.rt.block_production().is_some(),
        c.rt.validator_enabled(),
        c.rt.validator().is_some(),
        c.rt.block_production().is_some(),
    );

    // -----------------------------------------------------------------------
    // 断言 1：B（非验证者）确实作为 **sync responder** 工作
    // -----------------------------------------------------------------------
    assert!(
        b_diag.attempts >= 1,
        "B 必须收到过 sync 请求（attempts={}）",
        b_diag.attempts
    );
    assert!(
        b_diag.served >= 1,
        "B（非验证者）必须成功响应 sync 请求（served={}；C head={c_head_after}）",
        b_diag.served
    );
    assert_eq!(
        b_diag.no_block_store, 0,
        "B 不得以 NoBlockStore 拒答（P1-A.24 后 B 必有 adapter/BlockStore；实测 {}）",
        b_diag.no_block_store
    );
    assert_eq!(
        b_diag.not_established, 0,
        "B 不得对非 Established 请求作出响应判定（实测 {}）",
        b_diag.not_established
    );
    assert_eq!(
        b_diag.malformed, 0,
        "B 不得收到畸形请求（实测 {}）",
        b_diag.malformed
    );
    assert_eq!(
        b_diag.send_rejected, 0,
        "B 的响应不得被发送层拒绝（实测 {}）",
        b_diag.send_rejected
    );
    assert_eq!(
        b_diag.signing_failed, 0,
        "B 的响应签名不得失败（实测 {}）",
        b_diag.signing_failed
    );

    // -----------------------------------------------------------------------
    // 断言 2：B 附发了**历史 QC**（G1 的核心：非验证者提供 verified history）
    //   —— C 逐高度 finalize/commit 依赖该 QC 证据（否则 head 无法前进）
    // -----------------------------------------------------------------------
    assert!(
        b_diag.qc_served >= 1,
        "B 必须向 requester 附发历史 QC（qc_served={}）；这是 C 能 finalize/commit 的前提",
        b_diag.qc_served
    );

    // -----------------------------------------------------------------------
    // 断言 3：窗口路径不被误判；P1-A.23 exact 路径按"**如果触发**"口径条件断言
    //   （gap ≪ MAX_SYNC_WALK ⇒ 正常窗口；exact 路径由 a23a/a23 独立覆盖）
    // -----------------------------------------------------------------------
    assert_eq!(
        b_diag.walk_exceeded, 0,
        "本拓扑 gap ≪ MAX_SYNC_WALK=512 ⇒ 不得出现 WalkExceeded（实测 {}）",
        b_diag.walk_exceeded
    );
    if b_diag.served_via_verified_hash > 0 {
        assert_eq!(
            b_diag.walk_exceeded, 0,
            "P1-A.23 exact 路径被触发时 WalkExceeded 必须为 0（实测 {}）",
            b_diag.walk_exceeded
        );
        println!(
            "P1-A.26 NOTE: served_via_verified_hash = {} ⇒ P1-A.23 exact 路径在**非验证者** \
             responder 上被触发（unexpected for this gap; recorded as evidence）",
            b_diag.served_via_verified_hash
        );
    }

    // -----------------------------------------------------------------------
    // 断言 4：C（requester）真实追平（head 前进 ⇒ 必然已 finalize + commit）
    // -----------------------------------------------------------------------
    assert!(
        c_head_after >= b_head_at_c_start,
        "C 未追平 B 在 C 启动时的 head（c={c_head_after} < b={b_head_at_c_start}；steps={steps_catchup}）"
    );
    assert!(
        c_head_after >= TARGET_HEIGHT,
        "C 未达到目标高度（c={c_head_after} < {TARGET_HEIGHT}）"
    );
    assert!(
        c_finalized.is_some(),
        "C 必须经**采纳**外部已验证 finality 才能 commit（finalized_reference=None）"
    );
    assert!(
        b_finalized.is_some(),
        "B 必须已具备 finality（否则无法提供 verified QC / 无法持续跟随）"
    );
    assert!(
        c_resolved >= 1,
        "C 必须成功 correlate 至少一次 sync 响应（resolved={c_resolved}）"
    );

    // -----------------------------------------------------------------------
    // 断言 5：健康 + 角色隔离（B/C 全程非验证者；A 未收到任何非法共识命令）
    // -----------------------------------------------------------------------
    assert_eq!(c_skipped, 0, "C 不得跳过任何块（实测 {c_skipped}）");
    assert_eq!(b_skipped, 0, "B 不得跳过任何块（实测 {b_skipped}）");
    assert_eq!(
        b_qc_write_failed, 0,
        "B 的 QC history 写入不得失败（实测 {b_qc_write_failed}）"
    );
    assert!(!b.rt.validator_enabled(), "B 不得变成 validator");
    assert!(
        b.rt.validator().is_none(),
        "B 不得持有 actor（无 lock 获取 / 无签名能力）"
    );
    assert!(!c.rt.validator_enabled(), "C 不得变成 validator");
    assert!(
        c.rt.validator().is_none(),
        "C 不得持有 actor（无 lock 获取 / 无签名能力）"
    );
    assert_eq!(
        a_rejected, 0,
        "A 不得收到 B/C 的任何非法/不可应用 consensus command（实测 {a_rejected}）\
         ⇒ B/C 未发送 vote / proposal"
    );

    // A 保持 validator 形态
    assert!(a.rt.validator_enabled(), "A 必须保持 validator");
    assert!(a.rt.validator().is_some(), "A 必须保持 validator actor");
}
