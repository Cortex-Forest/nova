//! P1-A.23 — **`MAX_SYNC_WALK` 之外的 catch-up：精确验证过的 height → hash 取块**（真实 TCP）。
//!
//! # 被验证的行为（修复后）
//!
//! 请求侧**语义不变**（ADR-0062 §4/§6）：`SyncBlockRequest { height: local_head + 1,
//! block_hash: None }`。responder 在 `head - request.height > MAX_SYNC_WALK`（即既有
//! `WalkExceeded` 早退条件）时，改为尝试用**本地已验证**的 `qc_history` artifact 解析
//! `height → hash`，再以 exact hash 取块；无 artifact / artifact 损坏 / 块缺失 / 高度不符 ⇒
//! **仍** `WalkExceeded`（fail-closed 安全边界保留）。
//!
//! # Case 覆盖与分工（全部**真实 TCP**，无 mock）
//!
//! | Case | 内容 | 位置 |
//! |---|---|---|
//! | **A** | `gap ≤ MAX_SYNC_WALK` 行为逐字不变（窗口内仍走 parent walk） | `d9_step8a_sync_responder::d9s8a_t3` 阶段 3（**窗口内真实 TCP 请求**经 walk 服务；`served_via_verified_hash` **不**增加） |
//! | **B** | `gap > MAX_SYNC_WALK` 经 **exact verified-hash** 路径成功推进 | 本文件 Case B（机制激活 + 进度）+ `d10_p1_a23a_walk_window_catchup_evidence`（**完整追平**证据） |
//! | **C** | `gap > MAX_SYNC_WALK` 且**无**可信 artifact ⇒ 仍 `WalkExceeded`（不得无限扩大同步窗口） | 本文件 Case C |
//! | **D** | `block_hash = Some(不存在/错误 hash)` ⇒ `Missing`（**不响应**，不任意接受块、不回其它高度） | `d9_step8a_sync_responder::d9s8a_t3` 阶段 1（生产代码**从不**产生 `Some(hash)`，该场景只能由 wire 级 fixture 构造） |
//!
//! Case B 的**完整追平**（落后节点 head 追到目标高度）由 `d10_p1_a23a` 证明；本文件按
//! Owner 指示避免重复构造第二个 520 高度的完整追平长链 fixture，改为证明**同一固定装置**上的
//! 「exact 路径确实被激活 + 落后节点**确实推进**」与 Case C 的负向边界。
//!
//! # 安全性（本文件断言的范围）
//!
//! - `hash` **不来自网络**：由 responder 本地 `qc_history`（写入侧只在 `qc.target ==` 本地
//!   `finalized_reference` 时写、QC 已经既有 driver 门面 `verify_qc`；读取侧 `QcHistory::get`
//!   全验证）解析；
//! - 返回块仍走**请求侧**既有完整 inbound 验证（decode / 版本 / chain_id / canonical hash
//!   本地重算 / parent linkage / proposer 签名）与既有 finality → commit 桥；
//! - 本文件不修改任何 production 语义，只做只读观测。

mod d10_p1_a10_common;

use std::thread;

use d10_p1_a10_common as rig;

use nova_node::sync_responder::MAX_SYNC_WALK;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_N3, SEED_V1, SEED_V2, SEED_V3, consensus_height, head_height,
    net_node_id, start_node, target,
};

/// leader 目标 head：`MAX_SYNC_WALK + 8 = 520`（严格大于窗口；最小可行确定性构造）。
const LEADER_TARGET_HEIGHT: u64 = MAX_SYNC_WALK + 8;
/// leader 自主推进 step 预算（纯计数 ⇒ 与机器速度无关）。
const LEADER_STEP_BUDGET: usize = 8_000;
/// 建连 step 预算（纯计数）。
const CONNECT_STEP_BUDGET: usize = 400;
/// Case B（跟随者推进）step 预算。
const CASE_B_STEP_BUDGET: usize = 2_000;
/// Case B：等待 f1 完成一次真实 commit 的额外有界 step 预算。
const CASE_B_COMMIT_WAIT_BUDGET: usize = 600;
/// Case C（无 artifact 边界）step 预算。
const CASE_C_STEP_BUDGET: usize = 240;

/// 单步驱动（错误只记录为诊断，不 panic —— 与共享 rig 一致的 fail-soft 观测策略）。
fn drive(node: &mut rig::Node) {
    if let Err(e) = node.rt.step() {
        node.last_err = Some(format!("{e:?}"));
    }
}

/// 有界建连：follower ↔ leader **双向** Established（纯计数）。
///
/// 必须**同时**驱动两侧：被 dial 的 leader 只在 `step()` 内 accept / 完成握手 / flush。
fn connect(
    follower: &mut rig::Node,
    leader: &mut rig::Node,
    leader_id: nova_network::node_id::NodeId,
) -> bool {
    for _ in 0..CONNECT_STEP_BUDGET {
        let _ = follower.rt.establish_configured_peers();
        drive(follower);
        drive(leader);
        if follower.rt.network_peer_established(leader_id) {
            return true;
        }
        thread::yield_now();
    }
    false
}

#[test]
fn p1a23_exact_verified_hash_catchup_and_missing_artifact_boundary() {
    // -----------------------------------------------------------------------
    // 0. 固定装置：单验证者 genesis（quorum 1/1）⇒ leader 可独立推进到 > MAX_SYNC_WALK
    // -----------------------------------------------------------------------
    let env = Env::new("a23", &[SEED_V1]);
    let leader_listen: std::net::SocketAddr = format!("127.0.0.1:{}", rig::free_port())
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
    let leader_addr = leader.listen.expect("leader listener");

    let mut leader_steps: usize = 0;
    while leader_steps < LEADER_STEP_BUDGET && head_height(&leader.rt) < LEADER_TARGET_HEIGHT {
        drive(&mut leader);
        leader_steps += 1;
    }
    assert!(
        head_height(&leader.rt) >= LEADER_TARGET_HEIGHT,
        "leader 未达目标（实测 {}；last_err={:?}）",
        head_height(&leader.rt),
        leader.last_err
    );

    // =======================================================================
    // Case B —— gap > MAX_SYNC_WALK：exact verified-hash 路径被激活且落后节点**确实推进**
    // =======================================================================
    let f1_listen: std::net::SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("listen addr");
    let mut f1 = start_node(
        &env,
        "f1",
        SEED_V2,
        SEED_N2,
        Some(f1_listen),
        vec![target(leader_id, leader_addr)],
    );
    let f1_start_height = head_height(&f1.rt);
    let leader_height_at_f1_start = head_height(&leader.rt);
    let initial_gap = leader_height_at_f1_start.saturating_sub(f1_start_height);
    assert!(
        initial_gap > MAX_SYNC_WALK,
        "Case B 前提不成立：初始 gap ({initial_gap}) 必须 > MAX_SYNC_WALK ({MAX_SYNC_WALK})"
    );
    assert!(
        connect(&mut f1, &mut leader, leader_id),
        "Case B：f1 未与 leader 建立 Established（last_err={:?}）",
        f1.last_err
    );

    let mut case_b_steps: usize = 0;
    while case_b_steps < CASE_B_STEP_BUDGET
        && head_height(&f1.rt) <= f1_start_height
        && leader
            .rt
            .sync_respond_diagnostics()
            .served_via_verified_hash
            == 0
    {
        let _ = f1.rt.establish_configured_peers();
        drive(&mut f1);
        drive(&mut leader);
        case_b_steps += 1;
        thread::yield_now();
    }
    // 再给一段有界窗口：让 f1 完成至少一次真实 commit（head 推进）。
    for _ in 0..CASE_B_COMMIT_WAIT_BUDGET {
        if head_height(&f1.rt) > f1_start_height {
            break;
        }
        drive(&mut f1);
        drive(&mut leader);
        thread::yield_now();
    }

    let leader_height_after_b = head_height(&leader.rt);
    let f1_height_after_b = head_height(&f1.rt);
    let resp_after_b = leader.rt.sync_respond_diagnostics();
    println!(
        "P1-A.23 CASE B EVIDENCE (real TCP)\n\
         \x20 leader_height_at_f1_start            = {leader_height_at_f1_start}\n\
         \x20 f1_start_height                     = {f1_start_height}\n\
         \x20 initial_gap                         = {initial_gap}\n\
         \x20 MAX_SYNC_WALK                       = {MAX_SYNC_WALK}\n\
         \x20 request_height                      = {}\n\
         \x20 walk_exceeded                       = {}\n\
         \x20 served                              = {}\n\
         \x20 served_via_verified_hash            = {}\n\
         \x20 qc_served                           = {}\n\
         \x20 response_attempts                   = {}\n\
         \x20 f1_height_after                     = {f1_height_after_b}\n\
         \x20 leader_height_after                 = {leader_height_after_b}\n\
         \x20 f1_consensus_height_after           = {}\n\
         \x20 f1_finalized_reference              = {:?}\n\
         \x20 case_b_steps                        = {case_b_steps}\n\
         \x20 leader_steps_to_target              = {leader_steps}",
        f1_start_height.saturating_add(1),
        resp_after_b.walk_exceeded,
        resp_after_b.served,
        resp_after_b.served_via_verified_hash,
        resp_after_b.qc_served,
        resp_after_b.attempts,
        consensus_height(&f1.rt),
        rig::finalized_ref(&f1.rt),
    );

    // Case B 断言：
    // ① exact verified-hash 路径**确实**被使用（修复前该计数恒为 0 且落后节点永不推进）；
    assert!(
        resp_after_b.served_via_verified_hash >= 1,
        "Case B：exact verified-hash 路径未被激活（served_via_verified_hash={}）",
        resp_after_b.served_via_verified_hash
    );
    // ② 落后节点**确实推进**（修复前 head 恒为起始值）。
    assert!(
        f1_height_after_b > f1_start_height,
        "Case B：落后节点未推进（{} → {}）",
        f1_start_height,
        f1_height_after_b
    );
    // ③ 推进来自真实的「验证 → 登记 → 采纳 → commit」链（finality 非空）。
    assert!(
        rig::finalized_ref(&f1.rt).is_some(),
        "Case B：落后节点无 finality 证据（非真实 commit 路径）"
    );
    // ④ 超窗请求**全部**经本地已验证 artifact 解析（无一次落到 fail-closed 拒绝）。
    assert_eq!(
        resp_after_b.walk_exceeded, 0,
        "Case B：超窗请求不得落到 WalkExceeded（实测 {}；attempts={}）",
        resp_after_b.walk_exceeded, resp_after_b.attempts
    );

    // =======================================================================
    // Case C —— gap > MAX_SYNC_WALK 且**无**可信 artifact ⇒ 仍 WalkExceeded（fail-closed）
    //
    // 构造：删除 leader 的本地 `qc_history` 目录（模拟 retention 淘汰 / 服务目录缺失）。
    // 仅影响 node-local **服务提示**artifact，不触碰 consensus / storage schema / head；
    // leader 继续运行但不再有低高度 artifact（写入锚点 ⇒ 不会重复写已处理的高度）。
    // =======================================================================
    let qc_dir = env
        .root("leader")
        .join("chain")
        .join(nova_node::qc_history::QC_HISTORY_DIR);
    let _ = std::fs::remove_dir_all(&qc_dir);
    assert!(!qc_dir.exists(), "Case C 前置：qc_history 目录必须已移除");

    let walk_before = leader.rt.sync_respond_diagnostics();
    let f2_listen: std::net::SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("listen addr");
    let mut f2 = start_node(
        &env,
        "f2",
        SEED_V3,
        SEED_N3,
        Some(f2_listen),
        vec![target(leader_id, leader_addr)],
    );
    let f2_start_height = head_height(&f2.rt);
    assert!(
        head_height(&leader.rt).saturating_sub(f2_start_height) > MAX_SYNC_WALK,
        "Case C 前提不成立（leader={} f2={}）",
        head_height(&leader.rt),
        f2_start_height
    );
    assert!(
        connect(&mut f2, &mut leader, leader_id),
        "Case C：f2 未与 leader 建立 Established（last_err={:?}）",
        f2.last_err
    );

    for _ in 0..CASE_C_STEP_BUDGET {
        let _ = f2.rt.establish_configured_peers();
        drive(&mut f2);
        drive(&mut leader);
        thread::yield_now();
    }

    let walk_after = leader.rt.sync_respond_diagnostics();
    let f2_height_after = head_height(&f2.rt);
    println!(
        "P1-A.23 CASE C EVIDENCE (real TCP; no verified artifact)\n\
         \x20 qc_history_removed                 = true\n\
         \x20 leader_height                      = {}\n\
         \x20 f2_start_height                   = {f2_start_height}\n\
         \x20 f2_height_after                   = {f2_height_after}\n\
         \x20 request_height                    = {}\n\
         \x20 walk_exceeded_before               = {}\n\
         \x20 walk_exceeded_after                = {}\n\
         \x20 served                          = {}\n\
         \x20 served_via_verified_hash           = {}\n\
         \x20 qc_served                         = {}\n\
         \x20 f2_finalized_reference             = {:?}",
        head_height(&leader.rt),
        f2_start_height.saturating_add(1),
        walk_before.walk_exceeded,
        walk_after.walk_exceeded,
        walk_after.served,
        walk_after.served_via_verified_hash,
        walk_after.qc_served,
        rig::finalized_ref(&f2.rt),
    );

    // Case C 断言：无 artifact ⇒ 安全边界逐字保留。
    assert!(
        walk_after.walk_exceeded > walk_before.walk_exceeded,
        "Case C：无 artifact 的超窗请求必须仍计 WalkExceeded（{} → {}）",
        walk_before.walk_exceeded,
        walk_after.walk_exceeded
    );
    assert_eq!(
        walk_after.served_via_verified_hash, walk_before.served_via_verified_hash,
        "Case C：无 artifact ⇒ 不得进入 exact 路径"
    );
    assert_eq!(
        f2_height_after, f2_start_height,
        "Case C：无 artifact ⇒ 落后节点 head 不得推进（{} → {}）",
        f2_start_height, f2_height_after
    );
    assert!(
        rig::finalized_ref(&f2.rt).is_none(),
        "Case C：无 artifact ⇒ 落后节点不得产生 finality"
    );
}
