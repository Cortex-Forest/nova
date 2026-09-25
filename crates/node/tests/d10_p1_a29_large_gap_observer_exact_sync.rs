//! P1-A.29 — **large-gap observer（non-validator）exact sync regression**（test-only；零生产改动）。
//!
//! # 目标（闭合 G3-b / G3-c）
//! - **G3-b**：follower/observer 的 **large-gap** catch-up（gap > `MAX_SYNC_WALK`）；
//! - **G3-c**：**非验证者 requester** 触发 responder 的 P1-A.23 **exact verified-history** 路径。
//!
//! 既有证据的缺口：`d10_p1_a23a` / `d10_p1_a23` 的落后节点为 **validator-mode**（带 validator
//! identity，仅不在集合内）；`d10_p1_a26` 的 requester 是真正的 non-validator，但 gap = 8（≪ 512）
//! ⇒ `served_via_verified_hash = 0`（exact 路径**未触发**）。本测试补二者的组合。
//!
//! ```text
//! A = validator 1（genesis {SEED_V1, SEED_V2}；listener；peers = []）
//! B = validator 2（dial A；listener）         ← A/B 共同构成 quorum 2/2 的生产者
//! C = observer / non-validator（**仅** dial A ⇒ responder 确定性为 A；无 listener）
//! ```
//!
//! # Gap 构造与"越窗"论证
//! 1. 先驱动 A/B 至 `head == MAX_SYNC_WALK + 8`（= 520），**再**启动 C（head = 0）
//!    ⇒ `sync_gap = 520 > MAX_SYNC_WALK = 512`（断言此不等式）；
//! 2. `sync_responder` 的 `WalkExceeded` 条件为 `head - request.height > MAX_SYNC_WALK`
//!    ⇒ C 请求高度 `1..7` **必然越窗** ⇒ 走 P1-A.23 exact 路径（本地已验证 height→hash）；
//!    高度 `8..16` 自动回落到窗口内 `parent` 回走 ⇒ **两条路径都被覆盖**；
//! 3. C 目标高度取 **16**（有界；不要求追平 520），使本测试在可接受时长内完成。
//!
//! # 断言边界（诚实声明）
//! - `served_via_verified_hash >= 1`（exact 路径**确实**被使用）且 `walk_exceeded == 0`
//!   （越窗请求被 exact 路径**成功解析**，未被判定为不可服务 —— 与 a23a 同口径）；
//! - C 必须 `finalized_reference.is_some()`（逐高度 commit 依赖 finality ⇒ 证明附发历史 QC 生效）；
//! - 角色隔离：C `validator_enabled == false` ∧ `validator().is_none()`；A/B 侧
//!   `inbound_consensus_rejected == 0`（C 若发送 vote/proposal ⇒ 非成员 ⇒ 必被拒并计数）。
//! - 语义上限：仅 **`VERIFIED: 3-node large-gap observer sync`**；**不得**声称
//!   testnet ready / production ready / mainnet ready。
//! - 本文件不修改任何生产代码 / 共享 rig（`d10_p1_a10_common`），且**直接引用生产常量**
//!   `nova_node::sync_responder::MAX_SYNC_WALK`（`lib.rs:140` / `sync_responder.rs:59`）以避免口径漂移。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::key_provider::KeyProviderConfig;
use nova_node::runtime::NodeRuntime;
use nova_node::sync_responder::MAX_SYNC_WALK;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_N3, SEED_V1, SEED_V2, STAKE, finalized_ref, free_port, head_height,
    net_node_id, quorum_for, start_node, target,
};

/// A/B 需先推进到的高度（= 越窗 gap 的构造高度）。
const LEADER_TARGET_HEIGHT: u64 = MAX_SYNC_WALK + 8;
/// C（observer）在 restart-free catch-up 中需达到的高度（有界；> 8 ⇒ 同时覆盖 exact 与窗口两条路径）。
const OBSERVER_TARGET_HEIGHT: u64 = 16;
/// A/B 生产阶段的 step 预算（纯计数）。
const LEADER_STEP_BUDGET: usize = 8_000;
/// C 追平阶段的 step 预算（纯计数）。
const CATCHUP_STEP_BUDGET: usize = 20_000;
/// 建连 step 预算（纯计数）。
const CONNECT_STEP_BUDGET: usize = 400;

/// 单步驱动（错误只记录为诊断，不 panic —— 与共享 rig 一致的 fail-soft 观测策略）。
fn drive(node: &mut rig::Node) {
    if let Err(e) = node.rt.step() {
        node.last_err = Some(format!("{e:?}"));
    }
}

/// 构造 **observer**（`validator_enabled = false`，**无** validator key / actor）。
fn start_observer(
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
    .expect("observer（full-node）runtime 启动");
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

#[test]
fn d10_p1_a29_large_gap_observer_exact_sync() {
    // -----------------------------------------------------------------------
    // quorum 语义：2 个验证者 ⇒ 单验证者权重不足 ⇒ 有效 2/2
    // -----------------------------------------------------------------------
    let quorum = quorum_for(2 * STAKE);
    assert!(
        quorum > STAKE,
        "单验证者权重（{STAKE}）不得足以构成 quorum（{quorum}）⇒ 必须 2/2"
    );

    // -----------------------------------------------------------------------
    // 固定装置：genesis = {SEED_V1, SEED_V2}
    // -----------------------------------------------------------------------
    let env = Env::new("a29", &[SEED_V1, SEED_V2]);

    // ---------- A：validator 1 ----------
    let a_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut a = start_node(&env, "a", SEED_V1, SEED_N1, Some(a_listen), Vec::new());
    let a_id = net_node_id(SEED_N1);
    let a_addr = a.listen.expect("A 必须绑定真实 listener");

    // ---------- B：validator 2（dial A）----------
    let b_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut b = start_node(
        &env,
        "b",
        SEED_V2,
        SEED_N2,
        Some(b_listen),
        vec![target(a_id, a_addr)],
    );
    let validator_set_len = a.rt.driver().consensus().validator_set().len();
    assert_eq!(validator_set_len, 2, "genesis 必须恰有 2 个验证者");

    // A/B 建连（B dial A）
    let mut connect_ab: usize = 0;
    let mut ab_connected = false;
    while connect_ab < CONNECT_STEP_BUDGET {
        let _ = b.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        connect_ab += 1;
        if b.rt.network_peer_established(a_id) {
            ab_connected = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        ab_connected,
        "B 未与 A 建连（a.last_err={:?} b.last_err={:?}）",
        a.last_err, b.last_err
    );

    // ---------- 生产：A/B 推进到越窗高度（C 尚未加入）----------
    let mut leader_steps: usize = 0;
    while leader_steps < LEADER_STEP_BUDGET
        && (head_height(&a.rt) < LEADER_TARGET_HEIGHT || head_height(&b.rt) < LEADER_TARGET_HEIGHT)
    {
        let _ = b.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        leader_steps += 1;
        thread::yield_now();
    }
    let a_head_before_c = head_height(&a.rt);
    let b_head_before_c = head_height(&b.rt);
    assert!(
        a_head_before_c >= LEADER_TARGET_HEIGHT && b_head_before_c >= LEADER_TARGET_HEIGHT,
        "A/B 未在 {LEADER_STEP_BUDGET} 步内推进到 head >= {LEADER_TARGET_HEIGHT}\
         （a={a_head_before_c} b={b_head_before_c}）"
    );

    // ---------- C：observer（仅 dial A ⇒ responder 确定性为 A）----------
    let mut c = start_observer(&env, "c", SEED_N3, None, vec![target(a_id, a_addr)]);
    assert!(!c.rt.validator_enabled(), "C 必须是 observer / full-node");
    assert!(
        c.rt.validator().is_none(),
        "C 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        c.rt.block_production().is_some(),
        "P1-A.24：C 必须有 canonical adapter"
    );
    let c_head_before = head_height(&c.rt);
    let sync_gap = a_head_before_c.saturating_sub(c_head_before);
    assert!(
        sync_gap > MAX_SYNC_WALK,
        "gap 必须**越窗**（sync_gap={sync_gap} 必须 > MAX_SYNC_WALK={MAX_SYNC_WALK}）"
    );

    // C ↔ A 建连
    let mut connect_c: usize = 0;
    let mut c_connected = false;
    while connect_c < CONNECT_STEP_BUDGET {
        let _ = c.rt.establish_configured_peers();
        let _ = b.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c);
        connect_c += 1;
        if c.rt.network_peer_established(a_id) {
            c_connected = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        c_connected,
        "C 未与 A 建连（a.last_err={:?} c.last_err={:?}）",
        a.last_err, c.last_err
    );

    // ---------- 追平：C 经 A 的 sync 响应前进（exact 路径 + 窗口路径）----------
    let mut catchup_steps: usize = 0;
    while catchup_steps < CATCHUP_STEP_BUDGET && head_height(&c.rt) < OBSERVER_TARGET_HEIGHT {
        let _ = c.rt.establish_configured_peers();
        let _ = b.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c);
        catchup_steps += 1;
        thread::yield_now();
    }

    // ---------- 证据读数 ----------
    let a_head_after = head_height(&a.rt);
    let b_head_after = head_height(&b.rt);
    let c_head_after = head_height(&c.rt);
    let a_diag = a.rt.sync_respond_diagnostics();
    let c_fin = finalized_ref(&c.rt);
    let c_tip = c.rt.qc_history_tip_height();
    let c_skipped = c.rt.block_inbound_skipped();
    let a_rejected = a.rt.inbound_consensus_rejected();
    let b_rejected = b.rt.inbound_consensus_rejected();
    let steps = connect_ab + leader_steps + connect_c + catchup_steps;

    println!(
        "P1-A.29 EVIDENCE\n\
         \x20 topology                     = 3-node（2 validator + 1 observer；real TCP；C 仅 dial A）\n\
         \x20 validator_set_len            = {validator_set_len}\n\
         \x20 target_height                = {LEADER_TARGET_HEIGHT}（A/B 生产）/ {OBSERVER_TARGET_HEIGHT}（C 追平）\n\
         \x20 max_sync_walk                = {MAX_SYNC_WALK}\n\
         \x20 a_head                       = {a_head_after}\n\
         \x20 b_head                       = {b_head_after}\n\
         \x20 c_head_before                = {c_head_before}\n\
         \x20 c_head_after                 = {c_head_after}\n\
         \x20 sync_gap                     = {sync_gap}   （越窗：{sync_gap} > {MAX_SYNC_WALK}）\n\
         \x20 c_validator_enabled          = {}\n\
         \x20 c_has_validator_actor        = {}\n\
         \x20 c_has_canonical_adapter      = {}\n\
         \x20 served_via_verified_hash     = {}   （P1-A.23 exact 路径命中次数）\n\
         \x20 responder_served             = {}\n\
         \x20 responder_attempts           = {}\n\
         \x20 responder_walk_exceeded      = {}\n\
         \x20 responder_no_block_store     = {}\n\
         \x20 responder_malformed          = {}\n\
         \x20 responder_send_rejected      = {}\n\
         \x20 responder_signing_failed     = {}\n\
         \x20 qc_served                    = {}   （附发历史 QC = C 逐高度 finalize 的前提）\n\
         \x20 c_qc_history_tip             = {c_tip:?}\n\
         \x20 finalized_reference          = {c_fin:?}\n\
         \x20 c_block_inbound_skipped      = {c_skipped}\n\
         \x20 a_inbound_consensus_rejected = {a_rejected}   （C 若发送 vote/proposal ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 b_inbound_consensus_rejected = {b_rejected}\n\
         \x20 steps                        = {steps}   （leader={leader_steps} catchup={catchup_steps}）",
        c.rt.validator_enabled(),
        c.rt.validator().is_some(),
        c.rt.block_production().is_some(),
        a_diag.served_via_verified_hash,
        a_diag.served,
        a_diag.attempts,
        a_diag.walk_exceeded,
        a_diag.no_block_store,
        a_diag.malformed,
        a_diag.send_rejected,
        a_diag.signing_failed,
        a_diag.qc_served,
    );

    // -----------------------------------------------------------------------
    // 断言 1：越窗请求经 **exact verified-history** 路径被成功服务
    // -----------------------------------------------------------------------
    assert!(
        a_diag.served_via_verified_hash >= 1,
        "P1-A.23 exact 路径必须被使用（served_via_verified_hash={}；sync_gap={sync_gap}）",
        a_diag.served_via_verified_hash
    );
    assert_eq!(
        a_diag.walk_exceeded, 0,
        "越窗请求必须被 exact 路径解析（不得落到 WalkExceeded；实测 {}）",
        a_diag.walk_exceeded
    );
    assert!(
        a_diag.served >= 1,
        "responder 必须成功响应（served={}）",
        a_diag.served
    );
    assert_eq!(
        a_diag.no_block_store, 0,
        "responder 不得以 NoBlockStore 拒答（实测 {}）",
        a_diag.no_block_store
    );
    assert_eq!(a_diag.malformed, 0, "不得出现畸形请求");
    assert_eq!(a_diag.send_rejected, 0, "响应不得被发送层拒绝");
    assert_eq!(a_diag.signing_failed, 0, "响应签名不得失败");
    assert!(
        a_diag.qc_served >= 1,
        "responder 必须附发历史 QC（qc_served={}）",
        a_diag.qc_served
    );

    // -----------------------------------------------------------------------
    // 断言 2：observer 真实追平（含 exact 与窗口两条路径）
    // -----------------------------------------------------------------------
    assert!(
        c_head_after >= OBSERVER_TARGET_HEIGHT,
        "C 未追平到目标（head={c_head_after} < {OBSERVER_TARGET_HEIGHT}；catchup_steps={catchup_steps}）"
    );
    assert!(
        c_head_after > c_head_before,
        "C 的 head 必须前进（{c_head_before} → {c_head_after}）"
    );
    assert!(
        c_fin.is_some(),
        "C 必须逐高度 finalize 才能 commit（finalized_reference=None ⇒ 附发 QC 未生效）"
    );
    assert_eq!(c_skipped, 0, "C 不得跳过任何远端 block（实测 {c_skipped}）");

    // -----------------------------------------------------------------------
    // 断言 3：角色隔离（C 为非验证者；A/B 未收到 C 的非法共识命令）
    // -----------------------------------------------------------------------
    assert!(!c.rt.validator_enabled(), "C 不得变成 validator");
    assert!(
        c.rt.validator().is_none(),
        "C 不得持有 actor（无 lock 获取 / 无签名能力）"
    );
    assert_eq!(
        a_rejected, 0,
        "A 不得收到 C 的任何非法/不可应用 consensus command（实测 {a_rejected}）\
         ⇒ C 未发送 vote / proposal"
    );
    assert_eq!(
        b_rejected, 0,
        "B 不得收到 C 的任何非法/不可应用 consensus command（实测 {b_rejected}）"
    );

    // 验证者保持形态
    assert!(a.rt.validator_enabled() && a.rt.validator().is_some());
    assert!(b.rt.validator_enabled() && b.rt.validator().is_some());
}
