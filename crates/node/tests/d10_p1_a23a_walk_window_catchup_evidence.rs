//! P1-A.23a — **`MAX_SYNC_WALK`（>512 gap）catch-up stall EVIDENCE test**（**tests-only**）。
//!
//! # 本测试是**行为刻画 / 证据测试**（characterization），**不是**修复
//!
//! 它断言**当前实现**的既有行为，不修改任何生产代码、不改任何 wire / 语义 / 常量。
//! 其唯一目的是提供确定性证据：
//!
//! > 当一个节点落后超过 `MAX_SYNC_WALK = 512` 高度时，当前生产同步路径进入 `WalkExceeded`，
//! > 落后节点**无法**通过现有 height-based catch-up 自动追平。
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
/// 建连完成后的观测 step 预算（实测首步即产生请求 ⇒ 120 步已有充足裕度）。
const OBSERVE_STEP_BUDGET: usize = 120;

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
    // 5. 观测窗口：继续有界交替 step（真实 TCP gossip / sync 往返 + 生产 catch-up 驱动）
    // -----------------------------------------------------------------------
    let mut max_pending_requests: usize = lagging.rt.sync_pending_requests();
    let mut lagging_head_max = head_height(&lagging.rt);
    for _ in 0..OBSERVE_STEP_BUDGET {
        let _ = lagging.rt.establish_configured_peers();
        let _ = leader.rt.establish_configured_peers();
        drive(&mut lagging);
        drive(&mut leader);
        max_pending_requests = max_pending_requests.max(lagging.rt.sync_pending_requests());
        lagging_head_max = lagging_head_max.max(head_height(&lagging.rt));
        thread::yield_now();
    }

    // -----------------------------------------------------------------------
    // 6. 证据读数（全部来自真实 production 只读 accessor）
    // -----------------------------------------------------------------------
    let leader_height = head_height(&leader.rt);
    let lagging_height = head_height(&lagging.rt);
    let gap = leader_height.saturating_sub(lagging_height);
    let requested_height = lagging_height.saturating_add(1);
    let walk_distance = leader_height.saturating_sub(requested_height);
    let resp = leader.rt.sync_respond_diagnostics();

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
        "P1-A.23a EVIDENCE (tests-only; production code unchanged)\n\
         \x20 leader_height                        = {leader_height}\n\
         \x20 lagging_height                       = {lagging_height}\n\
         \x20 gap                                  = {gap}\n\
         \x20 MAX_SYNC_WALK                        = {MAX_SYNC_WALK}\n\
         \x20 lagging_requested_height             = {requested_height}\n\
         \x20 walk_distance (leader - requested)   = {walk_distance}\n\
         \x20 walk_exceeded                        = {}\n\
         \x20 served                               = {}\n\
         \x20 qc_served                            = {}\n\
         \x20 response_attempts                    = {}\n\
         \x20 lagging_head_after_wait              = {lagging_head_max}\n\
         \x20 lagging_consensus_height_after_wait  = {}\n\
         \x20 lagging_head_at_start                = {lagging_head_at_start}\n\
         \x20 lagging_consensus_height_at_start    = {lagging_consensus_at_start}\n\
         \x20 lagging_max_pending_sync_requests    = {max_pending_requests}\n\
         \x20 lagging_finalized_reference          = {:?}\n\
         \x20 production_target_form               = {{ height: lagging_head + 1 = {}, block_hash: none }}\n\
         \x20 produced_wire_form                   = {{ height: {}, block_hash: none }}\n\
         \x20 leader_steps_to_target               = {leader_steps}\n\
         \x20 connect_steps                        = {connect_steps}\n\
         \x20 observe_steps                        = {OBSERVE_STEP_BUDGET}",
        resp.walk_exceeded,
        resp.served,
        resp.qc_served,
        resp.attempts,
        consensus_height(&lagging.rt),
        rig::finalized_ref(&lagging.rt),
        target.height,
        wire.height,
    );

    // -----------------------------------------------------------------------
    // 7. 断言（刻画**当前**行为；全部为本次运行内可复算的不变量）
    // -----------------------------------------------------------------------

    // 1) survivor/leader 高度已明显高于落后节点。
    assert!(
        gap > MAX_SYNC_WALK,
        "证据前提不成立：gap ({gap}) 必须 > MAX_SYNC_WALK ({MAX_SYNC_WALK})\
         （leader={leader_height} lagging={lagging_height}）"
    );

    // 2) 过窗条件成立：leader responder 侧 `head - request.height > MAX_SYNC_WALK`。
    assert!(
        walk_distance > MAX_SYNC_WALK,
        "证据前提不成立：walk_distance ({walk_distance}) 必须 > MAX_SYNC_WALK ({MAX_SYNC_WALK})"
    );

    // 3) 落后节点的请求目标仍是**当前生产**的 height-based target（`block_hash = None`）。
    assert_eq!(
        target.height, requested_height,
        "生产 target 高度必须是 local_head + 1（ADR-0062 §4/§6）"
    );
    assert!(
        target.block_hash.is_none(),
        "生产 target 必须为 block_hash = None（无 hash-pinned 生产路径）"
    );
    assert!(
        wire.block_hash.is_none(),
        "wire `SyncBlockRequest.block_hash` 必须为 None（生产路径不携带 hash）"
    );
    assert_eq!(
        wire.height, requested_height,
        "wire 请求高度 = local_head + 1"
    );

    // 4) responder 对超窗请求返回 `WalkExceeded`（且该计数**只能**由 None-hash 请求产生）。
    assert!(
        resp.walk_exceeded >= 1,
        "leader responder 必须观测到 >= 1 次 WalkExceeded（实测 {}；attempts={}）",
        resp.walk_exceeded,
        resp.attempts
    );

    // 5) 落后节点**没有**因为该请求获得任何块（served = 0 ⇒ 无 sync 块路径可用）。
    assert_eq!(
        resp.served, 0,
        "超窗场景下 responder 不得 serve 任何块（实测 {}）",
        resp.served
    );

    // 6) 落后节点**没有** commit 越级 block、head **没有**自动跳跃
    //    （head 与 consensus 高度在整个观测窗口内保持不变）。
    assert_eq!(
        lagging_height, lagging_head_at_start,
        "落后节点 head 不得因超窗请求推进（观测窗口内 {} → {}）",
        lagging_head_at_start, lagging_height
    );
    assert_eq!(
        lagging_head_max, lagging_head_at_start,
        "落后节点 head 不得跳跃（观测窗口内最大 head = {}，起始 = {}）",
        lagging_head_max, lagging_head_at_start
    );
    assert_eq!(
        consensus_height(&lagging.rt),
        lagging_consensus_at_start,
        "落后节点 consensus 高度不得推进（越级 commit 的排除证据）"
    );

    // 7) 落后节点**没有**获得任何 finality（无块入 DAG ⇒ 无可采纳的 finality 证据）。
    assert!(
        rig::finalized_ref(&lagging.rt).is_none(),
        "落后节点不得产生 finality（实测 {:?}）",
        rig::finalized_ref(&lagging.rt)
    );
}
