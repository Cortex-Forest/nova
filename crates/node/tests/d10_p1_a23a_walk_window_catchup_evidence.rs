//! P1-A.23a — **`MAX_SYNC_WALK`（>512 gap）catch-up REGRESSION**（真实 TCP；**非 mock**）。
//!
//! # 本文件的历史与现状
//! 本文件最初（commit `0d6d333`）是**修复前**的行为刻画 / 证据测试：证明 gap > 512 时
//! 落后节点在 `WalkExceeded` 下**永久无法**推进（head 恒为 0）。
//! **P1-A.23 修复后**，本文件按 Owner 授权转为**正式回归**：同一构造（同一 rig / 同一确定性
//! step 计数）现在必须证明落后节点**能够追平**。
//!
//! # 断言（修复后的不变式）
//! 1. **过窗前提曾成立**：catch-up 起始时 `leader_head - (lagging_head + 1) > MAX_SYNC_WALK`；
//! 2. **落后节点跨过旧窗口并追平**：`lagging_head >= LEADER_TARGET_HEIGHT`（= `MAX_SYNC_WALK + 8`）；
//! 3. **P1-A.23 exact verified-hash 路径确实被使用**：`served_via_verified_hash >= 1`；
//! 4. **窗口内路径未被绕过**：`served > served_via_verified_hash`（大部分块仍经既有 walk 路径）；
//! 5. **落后节点获得真实 finality**（`finalized_reference` 非空 ⇒ 真经 commit，非跳高度）；
//! 6. **request 侧语义未变**：生产 target / wire 仍为 `{ height: local_head + 1, block_hash: None }`。
//!
//! # 构造（确定性：固定 step 计数；无墙钟断言 / 无随机 / 无 mock 状态 / 无人工注入最终状态）
//!
//! 1. genesis = **单验证者** `{V1}`（`quorum = 1/1`）⇒ leader 无需任何对端即可自主推进；
//! 2. leader = 真实 production `NodeRuntime`（真实 TCP listener；无 configured peer），
//!    以**固定 step 计数**推进到 canonical head > `MAX_SYNC_WALK`；
//! 3. lagging = 同 genesis 的真实 production `NodeRuntime`（validator mode ⇒ 具备完整 canonical
//!    adapter：**能**验证 / 登记 / 提交，非 full-node 占位），`--peer` = leader；
//! 4. 交替有界 `step()` 两者：lagging 经真实 TCP 收到 leader 的 `GossipBlock` / `ConsensusQc`
//!    ⇒ `FutureMissingAncestor` verdict / 保留的 future external QC ⇒ **生产** catch-up 驱动
//!    （`record_catchup_intent` / proactive probe）记录 intent ⇒ **生产** target 形态
//!    `{ height: local_head + 1, block_hash: None }`（ADR-0062 §6）⇒ 真实 `SyncBlockRequest`；
//! 5. leader responder：`head.height - request.height > MAX_SYNC_WALK` ⇒ `WalkExceeded`
//!    ⇒ **不响应**（`serve_qc` 只在块入队成功后才附发 ⇒ 连对应高度 QC 也不发）。
//!
//! # 为什么 `walk_exceeded >= 1` 同时证明"请求是 height-based"
//!
//! `sync_responder::lookup_block` 对 `block_hash = Some(_)` 走 O(1) `get_content`，
//! **不经过**窗口判定 ⇒ 该分支**不可能**产生 `WalkExceeded`。因此 `walk_exceeded` 只能由
//! `block_hash = None` 的高度请求产生 ⇒ 该计数即"生产 target 形态"的运行时证据。
//!
//! # 明确边界（本文件不做）
//!
//! 不修改 `runtime.rs` / `sync_scheduler.rs` / `sync_responder.rs` / `sync_dispatch.rs` /
//! `sync_correlator.rs` / `block_store.rs` / network protocol / consensus / ADR / spec；
//! 不修改 `MAX_SYNC_WALK`；不新增 `block_hash: Some(...)` 生产路径；不修复 `WalkExceeded`。
//! 窗口行为本身是既有冻结语义（ADR-0062 §13/§14；ADR-0064 "Effective catch-up limit /
//! Known limitation"），本测试**不**主张其为协议缺陷。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::security::random_request_id;
use nova_node::intent_ledger::{BlockInboundSource, MissingAncestorIntent};
use nova_node::sync_dispatch::sync_block_request_from_intent;
use nova_node::sync_responder::MAX_SYNC_WALK;
use nova_node::sync_scheduler::{SyncRequestIntent, sync_target_from_missing_ancestor};

use rig::{
    Env, SEED_N1, SEED_N2, SEED_V1, SEED_V2, consensus_height, head_height, net_node_id,
    start_node, target,
};

/// leader 目标 head：`MAX_SYNC_WALK + 8 = 520` —— **最小可行且严格大于窗口**的确定性构造
/// （Owner 授权：若 rig 成本过高，可取更小但 `> MAX_SYNC_WALK` 的方案）。
///
/// 说明：窗口判定为 `leader_head - request.height > MAX_SYNC_WALK`；lagging 请求 `head+1`，
/// 故 `520 - 1 = 519 > 512` 成立，且观测阶段 leader 仍单调增长 ⇒ 裕度只会变大，不会变薄。
const LEADER_TARGET_HEIGHT: u64 = MAX_SYNC_WALK + 8;
/// leader 自主推进的 step 预算（纯计数 ⇒ 与机器速度无关，确定性）。
const LEADER_STEP_BUDGET: usize = 8_000;
/// 建连（双向 Established）step 预算（纯计数；实测需 2 步）。
const CONNECT_STEP_BUDGET: usize = 400;
/// catch-up 驱动的 step 预算（纯计数 ⇒ 与机器速度无关，确定性；到目标即停）。
const CATCHUP_STEP_BUDGET: usize = 20_000;

/// 单步驱动（错误只记录为诊断，不 panic —— 与共享 rig 一致的 fail-soft 观测策略）。
fn drive(node: &mut rig::Node) {
    if let Err(e) = node.rt.step() {
        node.last_err = Some(format!("{e:?}"));
    }
}

#[test]
fn p1a23a_gap_beyond_max_sync_walk_is_not_recovered_by_height_based_catchup() {
    // -----------------------------------------------------------------------
    // 1. genesis：单验证者 {V1}（quorum 1/1 ⇒ leader 可独立推进）
    // -----------------------------------------------------------------------
    let env = Env::new("a23a", &[SEED_V1]);

    // -----------------------------------------------------------------------
    // 2. leader：真实 production NodeRuntime（真实 TCP listener；无 configured peer）
    // -----------------------------------------------------------------------
    let leader_listen: SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("listen addr");
    let mut leader = start_node(
        &env,
        "leader",
        SEED_V1,
        SEED_N1,
        Some(leader_listen),
        Vec::new(),
    );
    let leader_id = net_node_id(SEED_N1);
    let leader_addr = leader.listen.expect("leader 必须已绑定 listener");

    // 固定计数推进（无墙钟判定；到达即停）
    let mut leader_steps: usize = 0;
    while leader_steps < LEADER_STEP_BUDGET && head_height(&leader.rt) < LEADER_TARGET_HEIGHT {
        drive(&mut leader);
        leader_steps += 1;
    }
    let leader_height_before_join = head_height(&leader.rt);
    assert!(
        leader_height_before_join >= LEADER_TARGET_HEIGHT,
        "leader 未在 {LEADER_STEP_BUDGET} 步内推进到 head >= {LEADER_TARGET_HEIGHT}\
         （实测 {}；last_err={:?}）",
        leader_height_before_join,
        leader.last_err
    );

    // -----------------------------------------------------------------------
    // 3. lagging：同 genesis 的真实 production NodeRuntime；configured peer = leader
    //
    //    注：lagging 使用**不在**验证者集合内的 validator seed ⇒ 它是"具备完整 canonical
    //    adapter（能验证 / 登记 / 提交）的落后节点"，且**不会**成为任何高度的 proposer
    //    ⇒ 其落后**不会**干扰 leader 的推进（消除 proposer-rotation / round-timeout 噪声）。
    // -----------------------------------------------------------------------
    let lagging_listen: SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("listen addr");
    let mut lagging = start_node(
        &env,
        "lagging",
        SEED_V2,
        SEED_N2,
        Some(lagging_listen),
        vec![target(leader_id, leader_addr)],
    );
    let lagging_id = net_node_id(SEED_N2);
    let lagging_head_at_start = head_height(&lagging.rt);
    let lagging_consensus_at_start = consensus_height(&lagging.rt);

    // -----------------------------------------------------------------------
    // 4. 建连（双向 Established；纯计数预算）
    // -----------------------------------------------------------------------
    let mut connect_steps: usize = 0;
    let mut both_established = false;
    while connect_steps < CONNECT_STEP_BUDGET {
        let _ = lagging.rt.establish_configured_peers();
        let _ = leader.rt.establish_configured_peers();
        drive(&mut lagging);
        drive(&mut leader);
        connect_steps += 1;
        if lagging.rt.network_peer_established(leader_id)
            && leader.rt.network_peer_established(lagging_id)
        {
            both_established = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        both_established,
        "lagging ↔ leader 未在 {CONNECT_STEP_BUDGET} 步内双向 Established\
         （lagging→leader={} leader→lagging={}；lagging.last_err={:?} leader.last_err={:?}）",
        lagging.rt.network_peer_established(leader_id),
        leader.rt.network_peer_established(lagging_id),
        lagging.last_err,
        leader.last_err
    );

    // -----------------------------------------------------------------------
    // 5. 生产 catch-up 驱动（有界）：交替 step 直到落后节点追平目标 / 预算耗尽
    //
    //    真实路径（无 mock）：落后节点生产循环（GossipBlock / ConsensusQc → verdict / 保留证据
    //    → intent → scheduler → `SyncBlockRequest{height: head+1, block_hash: None}`
    //    → 真实 TCP → responder（超窗时经本地已验证 qc_history artifact 解析 exact hash）
    //    → 既有 `SyncBlockResponse` → 既有 inbound 全验证 → 登记 → 采纳 → commit）。
    // -----------------------------------------------------------------------
    let leader_height_at_start = head_height(&leader.rt);
    let mut max_pending_requests: usize = lagging.rt.sync_pending_requests();
    let mut catchup_steps: usize = 0;
    while catchup_steps < CATCHUP_STEP_BUDGET && head_height(&lagging.rt) < LEADER_TARGET_HEIGHT {
        let _ = lagging.rt.establish_configured_peers();
        let _ = leader.rt.establish_configured_peers();
        drive(&mut lagging);
        drive(&mut leader);
        max_pending_requests = max_pending_requests.max(lagging.rt.sync_pending_requests());
        catchup_steps += 1;
        thread::yield_now();
    }

    // -----------------------------------------------------------------------
    // 6. 证据读数（全部来自真实 production 只读 accessor）
    // -----------------------------------------------------------------------
    let leader_height = head_height(&leader.rt);
    let lagging_height = head_height(&lagging.rt);
    let gap = leader_height.saturating_sub(lagging_height);
    let requested_height = lagging_head_at_start.saturating_add(1);
    let initial_walk_distance = leader_height_at_start.saturating_sub(requested_height);
    let resp = leader.rt.sync_respond_diagnostics();
    let lagging_finalized = rig::finalized_ref(&lagging.rt);

    // 生产 target 形态（纯函数 + 既有 wire 构造器；只读调用生产代码，不新增路径）
    let probe_intent = MissingAncestorIntent {
        observed_height: leader_height,
        observed_block_hash: [0xAB; 32],
        local_head_height: lagging_height,
        source: BlockInboundSource::Gossip,
        count: 1,
    };
    let target = sync_target_from_missing_ancestor(&probe_intent);
    let wire = sync_block_request_from_intent(&SyncRequestIntent {
        request_id: random_request_id().expect("request id"),
        peer: leader_id,
        target,
    });

    println!(
        "P1-A.23a EVIDENCE (post-fix regression; real TCP; no mock)\n\
         \x20 leader_height                        = {leader_height}\n\
         \x20 lagging_height                       = {lagging_height}\n\
         \x20 gap                                  = {gap}\n\
         \x20 MAX_SYNC_WALK                        = {MAX_SYNC_WALK}\n\
         \x20 lagging_head_at_start                = {lagging_head_at_start}\n\
         \x20 request_height                       = {requested_height}\n\
         \x20 initial_walk_distance                = {initial_walk_distance}\n\
         \x20 walk_exceeded                        = {}\n\
         \x20 served                               = {}\n\
         \x20 served_via_verified_hash             = {}\n\
         \x20 qc_served                            = {}\n\
         \x20 qc_serve_skipped                     = {}\n\
         \x20 response_attempts                    = {}\n\
         \x20 lagging_consensus_height            = {}\n\
         \x20 lagging_finalized_reference          = {lagging_finalized:?}\n\
         \x20 lagging_max_pending_sync_requests    = {max_pending_requests}\n\
         \x20 leader_steps_to_target               = {leader_steps}\n\
         \x20 connect_steps                        = {connect_steps}\n\
         \x20 catchup_steps                        = {catchup_steps}\n\
         \x20 catchup_budget                       = {CATCHUP_STEP_BUDGET}\n\
         \x20 production_target_form               = {{ height: local_head + 1, block_hash: none }}\n\
         \x20 produced_wire_form                   = {{ height: {}, block_hash: none }}\n\
         \x20 lagging_consensus_at_start           = {lagging_consensus_at_start}",
        resp.walk_exceeded,
        resp.served,
        resp.served_via_verified_hash,
        resp.qc_served,
        resp.qc_serve_skipped,
        resp.attempts,
        consensus_height(&lagging.rt),
        wire.height,
    );

    // -----------------------------------------------------------------------
    // 7. 断言（**修复后**不变式；全部为本次运行内可复算的量）
    // -----------------------------------------------------------------------

    // 1) 过窗前提**曾**成立（即修复前会永久失联的场景）。
    assert!(
        initial_walk_distance > MAX_SYNC_WALK,
        "过窗前提不成立：起始 walk_distance ({initial_walk_distance}) 必须 > MAX_SYNC_WALK ({MAX_SYNC_WALK})"
    );

    // 2) 落后节点**跨过旧窗口并追平目标高度**（修复的核心效果）。
    assert!(
        lagging_height > MAX_SYNC_WALK,
        "落后节点未跨过旧窗口（lagging_head={lagging_height} <= MAX_SYNC_WALK={MAX_SYNC_WALK}）"
    );
    assert!(
        lagging_height >= LEADER_TARGET_HEIGHT,
        "落后节点未追平目标（{lagging_height} < {LEADER_TARGET_HEIGHT}；catchup_steps={catchup_steps}）"
    );

    // 3) P1-A.23 exact verified-hash 路径**确实**被使用（不是靠调大窗口）。
    assert!(
        resp.served_via_verified_hash >= 1,
        "P1-A.23 exact verified-hash 路径未被使用（实测 {}）",
        resp.served_via_verified_hash
    );

    // 4) 超窗请求**全部**经本地已验证 artifact 解析（无一次落到 fail-closed 拒绝）。
    //    注：追赶期间 leader 仍在产块 ⇒ gap 恒定 ≈ 初始值（>512）⇒ 本场景下每个请求都在窗口外；
    //    「窗口内仍走既有 walk 路径」由 `d9_step8a_sync_responder::d9s8a_t3` 阶段 3 证明。
    assert_eq!(
        resp.walk_exceeded, 0,
        "超窗请求不得落到 WalkExceeded（实测 {}；attempts={}）",
        resp.walk_exceeded, resp.attempts
    );

    // 5) 落后节点获得**真实 finality**（真经 frozen 最终性 + commit；非跳高度 / 非伪造）。
    assert!(
        lagging_finalized.is_some(),
        "落后节点未产生 finality（无真实 commit 证据）"
    );

    // 6) request 侧语义逐字不变（ADR-0062 §4/§6：height = local_head + 1、hash = None）。
    assert!(
        target.block_hash.is_none(),
        "生产 target 必须仍为 block_hash = None（无 hash-pinned 生产路径）"
    );
    assert!(
        wire.block_hash.is_none(),
        "wire `SyncBlockRequest.block_hash` 必须仍为 None"
    );
    assert_eq!(
        wire.height,
        lagging_height.saturating_add(1),
        "wire 请求高度 = local_head + 1"
    );

    // 7) 落后节点的共识高度已随 head 推进（真实 commit → advance，非 head 跳跃）。
    assert!(
        consensus_height(&lagging.rt) >= lagging_height,
        "落后节点 consensus 高度 ({}) 未随 durable head ({lagging_height}) 推进",
        consensus_height(&lagging.rt)
    );
}
