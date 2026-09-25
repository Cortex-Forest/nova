//! P1-A.25 — **Full-node follower restart & recovery regression**（test-only；零生产改动）。
//!
//! # 背景
//! P1-A.24（`35c203e`）使 `validator_enabled = false` 的 full-node 也装配 canonical
//! `NodeBlockAdapter`（`runtime.rs:1596-1601`），由此首次获得：
//! - restart 时 DAG 重建（`runtime.rs:1644 rebuild_consensus_dag`）、
//! - finality fact 恢复（`runtime.rs:1647 restore_finality_fact`）、
//! - QC history 装配 + tip 播种（`runtime.rs:1619-1633`）、
//! - `consensus_start_height = canonical head`（`runtime.rs:1599`）。
//!
//! 此前**没有测试**验证「非验证者 follower 重启后恢复并继续跟随」：既有 restart fixture 要么是
//! adapter 层（`restart_tests.rs`）、要么是 validator-mode 的 `NodeRuntime`
//! （`d10_p1_a7_rejoin_catchup.rs`、`d10_p1_a21_five_validator_devnet.rs`）。本测试补齐该证据。
//!
//! # 拓扑与流程（真实 TCP，非 mock）
//! A = validator（genesis `{SEED_V1}` 单验证者 ⇒ quorum 1/1，A 可单独推进）；B = 非验证者 follower（dial A）。
//! 1. B 跟随 A 到 `TARGET_HEIGHT`；
//! 2. `rt.shutdown()`（**保留同一 label / 同一 `storage_dir`**，不删目录、不重新 genesis）；
//! 3. A 单独再推进 `CONTINUE_K` 高度（制造真实离线 gap；同时让 A 通过多步 poll 完成 B 的 EOF 清理，
//!    避免 A 侧 KEEP-FIRST 丢弃 B2 的新连接）；
//! 4. 用**同一 label**（`Env::config` 以 label 定位目录 ⇒ 同 `storage_dir`）重启 B2；
//! 5. **不 step** 立即断言恢复（head / head_hash / finality / DAG / qc_history / 无 safety journal）；
//! 6. 继续 step，断言 B2 真正恢复 follower 生命周期（继续增长并追平 A）。
//!
//! # 断言边界（诚实声明）
//! - 角色隔离：B/B2 全程 `validator_enabled() == false`、`validator().is_none()`、`actors = 0` 语义；
//!   运行时反证 = A 侧 `inbound_consensus_rejected() == 0`（B 若发送 vote / proposal，A 作为唯一
//!   验证者必然拒绝并计数）。
//! - **不**断言 QC 转发次数（Owner option (i) 允许 forwarded verified QC ≥ 1）；**不**断言
//!   `pending_external_qc_len`。
//! - `qc_history_written()` 是**进程内观测计数**（restart 归零）⇒ 仅打印，不作跨重启大小比较；
//!   改断言 `qc_history_write_failed() == 0`（真实健康检查）。
//! - 本文件不修改任何生产代码 / 共享 rig（`d10_p1_a10_common`）。
//! - **finality 恢复语义（frozen，本测试如实记录）**：`bootstrap::restore_finality_fact` 对
//!   canonical-ancestry 的 fact 返回 `Ok((dag, None))` —— **刻意不注入** `finalized_reference`
//!   （`RestoredFinality` 无生产构造点；D11-23 U4-C / IPC-1 顺序冻结）。因此 restart 瞬间
//!   `finalized_reference == None` 属**预期行为**，其"恢复"体现为：head/hash/DAG/qc_history 由
//!   durable 状态恢复，而 finality 由 restart 后的正常路径**重新取得**（Phase 6 断言）。
//!   本测试因此**不**断言 restart 后 finality 等值恢复（该断言与 frozen 语义冲突）。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::key_provider::KeyProviderConfig;
use nova_node::runtime::NodeRuntime;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_V1, consensus_height, finalized_ref, free_port, head_hash,
    head_height, hex32, net_node_id, start_node, target,
};

/// B 首次跟随需达到的高度。
const TARGET_HEIGHT: u64 = 8;
/// B 停机期间 A 单独推进的高度数（制造真实离线 gap；远小于 `MAX_SYNC_WALK = 512`）。
const CONTINUE_K: u64 = 8;
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

/// 构造 **canonical follower**（`validator_enabled = false`，**无** validator key / actor）。
///
/// 与共享 rig `start_node` 的唯一差异：`validator_enabled = false` +
/// `key_provider_config = None` + `start_with_network(.., None, ..)`；其余（真实 TCP listener /
/// 网络身份 / **同一 label ⇒ 同一 `storage_dir`**）完全一致 —— 这正是 restart 复用目录的前提。
fn start_follower(
    env: &Env,
    label: &'static str,
    net_seed: [u8; 32],
    listen: Option<SocketAddr>,
    peers: Vec<ConnectionTarget>,
) -> rig::Node {
    let mut cfg = env.config(label, listen, peers.clone());
    cfg.validator_enabled = false; // ← 等价于 CLI 不传 `--validator`
    cfg.key_provider_config = KeyProviderConfig::None;

    let self_id = net_node_id(net_seed);
    let (tx_self, _tx_other) = MemoryTransport::pair(self_id, NodeId::from_bytes([0x99; 32]));
    let rt = NodeRuntime::start_with_network(
        &cfg,
        None, // ← 无 validator key / 无 KeyProvider
        Box::new(tx_self),
        Box::new(rig::SeedNetworkIdentity::from_seed(net_seed)),
    )
    .expect("full-node（canonical follower）runtime 启动");
    let listen = rt.network_listen_addr();
    rig::Node {
        label,
        val_seed: [0u8; 32], // follower 无 validator 身份
        net_seed,
        listen,
        rt,
        last_err: None,
        peer_ids: peers.into_iter().map(|p| p.peer_id).collect(),
    }
}

/// 有界建连：follower ↔ validator 双向 Established（必须同时驱动两侧）。
fn connect(follower: &mut rig::Node, validator: &mut rig::Node, validator_id: NodeId) -> bool {
    for _ in 0..CONNECT_STEP_BUDGET {
        let _ = follower.rt.establish_configured_peers();
        drive(follower);
        drive(validator);
        if follower.rt.network_peer_established(validator_id) {
            return true;
        }
        thread::yield_now();
    }
    false
}

/// 停止节点（consuming `shutdown`）；**不删除** `storage_dir`（restart 复用）。
fn stop(node: rig::Node) {
    let rig::Node { rt, .. } = node;
    rt.shutdown().expect("follower shutdown 必须成功");
}

#[test]
fn p1a25_full_node_follower_restart_recovers_and_continues() {
    // -----------------------------------------------------------------------
    // 固定装置：genesis = {V1}（唯一 validator ⇒ quorum 1/1；B 为非成员 follower）
    // -----------------------------------------------------------------------
    let env = Env::new("a25", &[SEED_V1]);

    // ---------- Phase 1：A（validator）+ B（non-validator follower）----------
    let a_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut a = start_node(&env, "a", SEED_V1, SEED_N1, Some(a_listen), Vec::new());
    let a_id = net_node_id(SEED_N1);
    let a_addr = a.listen.expect("A 必须绑定真实 listener");
    assert!(a.rt.validator_enabled(), "A 必须是 validator");
    assert!(a.rt.validator().is_some(), "A 必须有 validator actor");

    let b_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut b1 = start_follower(
        &env,
        "b",
        SEED_N2,
        Some(b_listen),
        vec![target(a_id, a_addr)],
    );

    // 启动形态：canonical adapter 与 actor 解耦（P1-A.24 语义）
    assert!(!b1.rt.validator_enabled(), "B 必须是 full-node / observer");
    assert!(
        b1.rt.validator().is_none(),
        "B 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        b1.rt.block_production().is_some(),
        "P1-A.24：B 必须有 canonical adapter（可验证 / 登记 / 采纳 / commit / serve sync）"
    );

    assert!(
        connect(&mut b1, &mut a, a_id),
        "B 未与 A 建立 Established（B.last_err={:?} A.last_err={:?}）",
        b1.last_err,
        a.last_err
    );
    assert!(
        a.rt.network_peer_established(net_node_id(SEED_N2)),
        "A 未与 B 建立 Established"
    );

    // 有界驱动：A 产块，B 跟随至 TARGET_HEIGHT
    let mut steps_initial: usize = 0;
    while steps_initial < STEP_BUDGET && head_height(&b1.rt) < TARGET_HEIGHT {
        let _ = b1.rt.establish_configured_peers();
        drive(&mut b1);
        drive(&mut a);
        steps_initial += 1;
        thread::yield_now();
    }

    // ---------- Phase 1 证据 + 断言 ----------
    let a_head_before = head_height(&a.rt);
    let b_head_before = head_height(&b1.rt);
    let b_hash_before = head_hash(&b1.rt);
    let b_finality_before = finalized_ref(&b1.rt);
    let b_tip_before = b1.rt.qc_history_tip_height();
    let b_qcw_before = b1.rt.qc_history_written();

    assert!(
        b_head_before >= TARGET_HEIGHT,
        "B 未跟随到目标高度（head={b_head_before} < {TARGET_HEIGHT}；steps={steps_initial}）"
    );
    assert!(
        b_finality_before.is_some(),
        "B 必须采纳经 frozen `verify_qc` 验证的外部 finality（finalized_reference=None）"
    );
    assert_eq!(
        b1.rt.block_inbound_skipped(),
        0,
        "B 不得跳过任何远端 block（实测 {}）",
        b1.rt.block_inbound_skipped()
    );

    // ---------- Phase 2：停止 B（保留同 label / 同 storage_dir）----------
    stop(b1);

    // ---------- Phase 3：A 单独推进（制造离线 gap + 让 A 完成 B 的 EOF 清理）----------
    let a_target_while_b_down = a_head_before + CONTINUE_K;
    let mut steps_a_alone: usize = 0;
    while steps_a_alone < STEP_BUDGET && head_height(&a.rt) < a_target_while_b_down {
        drive(&mut a);
        steps_a_alone += 1;
        thread::yield_now();
    }
    assert!(
        head_height(&a.rt) >= a_target_while_b_down,
        "A 未在 B 停机期间推进到 {}（head={}）",
        a_target_while_b_down,
        head_height(&a.rt)
    );

    // ---------- Phase 4：同 label（⇒ 同 storage_dir）重启 B2 ----------
    let b2_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut b2 = start_follower(
        &env,
        "b",
        SEED_N2,
        Some(b2_listen),
        vec![target(a_id, a_addr)],
    );

    // ---------- Phase 5：恢复断言（**不 step**，立即检查）----------
    let b2_head_after_restart = head_height(&b2.rt);
    let b2_hash_after_restart = head_hash(&b2.rt);
    let b2_finality_after_restart = finalized_ref(&b2.rt);
    let b2_tip_after_restart = b2.rt.qc_history_tip_height();
    let b2_dag_len = b2.rt.driver().consensus().dag().len();
    let b2_consensus_height_after_restart = consensus_height(&b2.rt);
    let b2_safety_journal_exists = env.root("b").join("safety").join("safety.journal").exists();

    assert!(!b2.rt.validator_enabled(), "B2 不得变成 validator");
    assert!(
        b2.rt.validator().is_none(),
        "B2 不得持有 actor（无 lock 获取 / 无签名能力 / 无 safety journal）"
    );
    assert!(
        b2.rt.block_production().is_some(),
        "B2 必须有 canonical adapter（restart 后仍具备 canonical 能力）"
    );
    assert!(
        b2.rt
            .block_production()
            .is_some_and(|adapter| adapter.block_store().is_some()),
        "B2 的 BlockStore 必须可用（编码布局可读）"
    );
    assert_eq!(
        b2_head_after_restart, b_head_before,
        "restart 后 committed head 必须与 shutdown 前一致（shutdown={b_head_before} restart={b2_head_after_restart}）"
    );
    assert_eq!(
        b2_hash_after_restart, b_hash_before,
        "restart 后 canonical head hash 必须保留"
    );
    // **frozen 语义（D11-23 U4-C / IPC-1）**：`bootstrap::restore_finality_fact` 对
    // canonical-ancestry fact 返回 `Ok((dag, None))` —— **不注入** `finalized_reference`
    // （`RestoredFinality` 无生产构造点）⇒ restart 瞬间为 `None`，随后由正常路径重新取得
    // （Phase 6 断言）。此处锁定该冻结行为，而非断言"等值恢复"。
    assert!(
        b2_finality_after_restart.is_none(),
        "restart 瞬间 finalized_reference 不得由 canonical-ancestry fact 注入（frozen D11-23 U4-C）；\
         实测 {:?}（shutdown 前 = {b_finality_before:?}）",
        b2_finality_after_restart
    );
    assert!(
        b2_tip_after_restart.is_some(),
        "restart 后 qc_history tip 必须已播种（QcHistory::open + seed_tip_from_store）"
    );
    assert!(
        b2_dag_len >= 2,
        "restart 后 DAG 必须已由 canonical ancestry 重建（len={b2_dag_len}）"
    );
    assert!(
        b2.rt.driver().consensus().dag().contains(&b_hash_before),
        "restart 后 DAG 必须包含恢复出的 canonical head"
    );
    assert!(
        b2_consensus_height_after_restart >= b_head_before,
        "P1-A.24：共识高度必须锚定 durable head（consensus={b2_consensus_height_after_restart} \
         head={b_head_before}）"
    );
    assert!(
        !b2_safety_journal_exists,
        "non-validator 不得产生 safety journal（实测存在）"
    );

    // ---------- Phase 6：继续跟随 ----------
    assert!(
        connect(&mut b2, &mut a, a_id),
        "B2 未能与 A 重新建立 Established（B2.last_err={:?} A.last_err={:?}）",
        b2.last_err,
        a.last_err
    );
    let a_head_at_b2_start = head_height(&a.rt);
    let mut steps_continue: usize = 0;
    while steps_continue < STEP_BUDGET && head_height(&b2.rt) < a_head_at_b2_start {
        let _ = b2.rt.establish_configured_peers();
        drive(&mut b2);
        drive(&mut a);
        steps_continue += 1;
        thread::yield_now();
    }

    let b2_head_after_continue = head_height(&b2.rt);
    let b2_qcw_after_continue = b2.rt.qc_history_written();
    let b2_write_failed = b2.rt.qc_history_write_failed();
    let a_rejected = a.rt.inbound_consensus_rejected();
    let b2_inbound_skipped = b2.rt.block_inbound_skipped();
    // Phase 6 结束后的 finality（用于证据打印 + 断言；restart 后应由正常路径重新取得）。
    let b2_finalized_after_continue = finalized_ref(&b2.rt);

    // ---------- Evidence ----------
    let steps = steps_initial + steps_a_alone + steps_continue;
    println!(
        "P1-A.25 EVIDENCE (real TCP; A=validator, B=non-validator full-node follower; restart 同 label / 同 storage_dir)\n\
         \x20 a_head_1                            = {a_head_before}\n\
         \x20 b_head_1                            = {b_head_before}\n\
         \x20 b_hash_1                            = {}\n\
         \x20 b2_head_after_restart               = {b2_head_after_restart}\n\
         \x20 b2_head_after_continue              = {b2_head_after_continue}\n\
         \x20 b_finalized_reference               = {b_finality_before:?}\n\
         \x20 b2_finalized_reference              = after_restart={b2_finality_after_restart:?} after_continue={b2_finalized_after_continue:?}\n\
         \x20 b_qc_tip_before                     = {b_tip_before:?}\n\
         \x20 b_qc_tip_after                      = {b2_tip_after_restart:?}\n\
         \x20 b_qc_written_before                 = {b_qcw_before}\n\
         \x20 b_qc_written_after                  = {b2_qcw_after_continue}\n\
         \x20 b2_dag_len                          = {b2_dag_len}\n\
         \x20 b2_validator_enabled                = {}\n\
         \x20 b2_has_validator_actor              = {}\n\
         \x20 b2_has_canonical_adapter            = {}\n\
         \x20 safety_journal_exists               = {b2_safety_journal_exists}\n\
         \x20 a_inbound_consensus_rejected        = {a_rejected}   （B 若发送 vote/proposal ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 steps                               = {steps}   （initial={steps_initial} a_alone={steps_a_alone} continue={steps_continue}）\n\
         \x20 -- extra --\n\
         \x20 b2_hash_after_restart               = {}\n\
         \x20 a_head_while_b_down                 = {a_target_while_b_down}\n\
         \x20 a_head_at_b2_start                  = {a_head_at_b2_start}\n\
         \x20 b2_consensus_height_after_restart   = {b2_consensus_height_after_restart}\n\
         \x20 b2_consensus_height_after_continue  = {}\n\
         \x20 b2_qc_write_failed                  = {b2_write_failed}\n\
         \x20 b2_block_inbound_skipped            = {b2_inbound_skipped}\n\
         \x20 target_height                       = {TARGET_HEIGHT}   continue_k = {CONTINUE_K}",
        hex32(&b_hash_before),
        b2.rt.validator_enabled(),
        b2.rt.validator().is_some(),
        b2.rt.block_production().is_some(),
        hex32(&b2_hash_after_restart),
        consensus_height(&b2.rt),
    );

    // ---------- Phase 6 断言 ----------
    assert!(
        b2_head_after_continue > b_head_before,
        "P1-A.25：restart 后 B2 必须继续前进（{b_head_before} → {b2_head_after_continue}；steps={steps_continue}）"
    );
    assert!(
        b2_head_after_continue >= a_head_at_b2_start,
        "restart 后 B2 未追平 A 在 B2 启动时的 head（b2={b2_head_after_continue} < a={a_head_at_b2_start}）"
    );
    assert!(
        b2_head_after_continue >= a_head_before + CONTINUE_K,
        "P1-A.25 Phase 7：B2 必须达到 A 初始 head + K（b2={b2_head_after_continue} < {}）",
        a_head_before + CONTINUE_K
    );
    assert!(
        b2_finalized_after_continue.is_some(),
        "B2 继续跟随期间必须**重新取得** finality（restart 后由正常路径派生/采纳；\
         finalized_reference=None ⇒ 无法 commit 任何新高度，head 不可能前进）"
    );
    assert_eq!(
        b2_inbound_skipped, 0,
        "B2 不得跳过任何远端 block（实测 {b2_inbound_skipped}）"
    );
    assert_eq!(
        b2_write_failed, 0,
        "B2 的 QC history 写入不得失败（实测 {b2_write_failed}）"
    );
    assert!(
        b2_qcw_after_continue > 0,
        "P1-A.25 Phase 7：restart 后 qc_history 必须继续增长（restart 后本进程写入 = {b2_qcw_after_continue}）"
    );

    // ---------- 角色隔离（restart 后仍成立）----------
    assert!(!b2.rt.validator_enabled(), "B2 不得变成 validator");
    assert!(
        b2.rt.validator().is_none(),
        "B2 不得持有 actor（无 lock 获取 / 无签名能力）"
    );
    assert_eq!(
        a_rejected, 0,
        "A 不得收到 B 的任何非法/不可应用 consensus command（实测 {a_rejected}）\
         ⇒ B 未发送 vote / proposal"
    );

    // A 保持 validator 形态（不受 B restart 影响）
    assert!(a.rt.validator_enabled(), "A 必须保持 validator");
    assert!(a.rt.validator().is_some(), "A 必须保持 validator actor");
}
