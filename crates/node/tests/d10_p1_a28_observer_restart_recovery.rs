//! P1-A.28 — **observer restart/recovery（2 validator + 1 observer）**（test-only；零生产改动）。
//!
//! # 目标（闭合 G3-a）
//! P1-A.25 证明 **2-node**（validator + follower）restart 恢复；P1-A.27 证明 **混合拓扑**
//! （2 validator + 1 observer）但不重启。本测试补齐二者之**组合**：runbook §4 精确拓扑下的
//! observer restart/recovery。
//!
//! ```text
//! A = validator 1（genesis {SEED_V1, SEED_V2}；listener；peers = []）
//! B = validator 2（dial A；listener）
//! C = observer / non-validator（dial A 与 B；无 validator key / 无 actor）
//! ```
//! quorum = `ceil(2T/3)`，`T = 2 × STAKE` ⇒ **单个验证者权重不足 ⇒ 有效 2/2**（本测试断言该算术）。
//!
//! # 流程
//! 1. 起 A/B/C，三向建连；驱动至 `head >= 8`（三节点）；
//! 2. 记录 C 的 head / head_hash / finalized_reference / qc_history tip；
//! 3. `rt.shutdown()` **仅** C（保留同 label / 同 `storage_dir`；A/B 继续运行并推进到 `>= 12`，
//!    既制造真实离线窗口，也让 A/B 完成对 C 的 EOF 清理）；
//! 4. 以同一 label 重启 C（**不重新 genesis / 不换目录**）；
//! 5. 重启后**未 step 即断言**恢复（head/hash/DAG/qc_history/无 safety journal）；
//! 6. 重连并驱动至 `head >= 12`，断言 finality **重新取得**且与验证者一致。
//!
//! # finality 恢复语义（frozen，如实记录 —— 与 P1-A.25 同）
//! `bootstrap::restore_finality_fact` 对 canonical-ancestry 的 fact 返回 `Ok((dag, None))`
//! ⇒ **刻意不注入** `finalized_reference`（D11-23 U4-C / IPC-1）。因此 restart **瞬间**
//! `finalized_reference == None` 属**预期行为**；其"恢复"体现为：head/hash/DAG/qc_history 由
//! durable 状态恢复，而 finality 由 restart 后的正常路径**重新取得**（Step 6 断言，且要求与
//! 验证者一致）。本测试**不**断言 restart 瞬间的 finality 等值恢复（该断言与 frozen 语义冲突）。
//!
//! # 语义边界（不得夸大）
//! 仅 **`VERIFIED: 3-node（2 validator + 1 observer）restart recovery`**。
//! **不是** "testnet ready" / "production ready" / "mainnet ready"。
//! 本文件不修改任何生产代码 / 共享 rig（`d10_p1_a10_common`）。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::key_provider::KeyProviderConfig;
use nova_node::runtime::NodeRuntime;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_N3, SEED_V1, SEED_V2, STAKE, finalized_ref, free_port, head_hash,
    head_height, hex32, net_node_id, quorum_for, start_node, target,
};

/// restart 前要求三节点达到的高度。
const TARGET_BEFORE_RESTART: u64 = 8;
/// restart 后要求 observer 达到的高度（同时验证 A/B 在 C 停机期间继续推进）。
const TARGET_AFTER_RESTART: u64 = 12;
/// 驱动 step 预算（纯计数 ⇒ 与机器速度无关）。
const STEP_BUDGET: usize = 20_000;
/// 建连 step 预算（纯计数）。
const CONNECT_STEP_BUDGET: usize = 800;

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

/// 停止节点（consuming `shutdown`）；**不删除** `storage_dir`（restart 复用）。
fn stop(node: rig::Node) {
    let rig::Node { rt, .. } = node;
    rt.shutdown().expect("observer shutdown 必须成功");
}

/// 有界三向建连：B→A、C→A、C→B（每 step 同时驱动三节点）。
fn connect_three(a: &mut rig::Node, b: &mut rig::Node, c: &mut rig::Node) -> (bool, usize) {
    let a_id = net_node_id(SEED_N1);
    let b_id = net_node_id(SEED_N2);
    let mut steps = 0usize;
    while steps < CONNECT_STEP_BUDGET {
        let _ = b.rt.establish_configured_peers();
        let _ = c.rt.establish_configured_peers();
        drive(a);
        drive(b);
        drive(c);
        steps += 1;
        if b.rt.network_peer_established(a_id)
            && c.rt.network_peer_established(a_id)
            && c.rt.network_peer_established(b_id)
        {
            return (true, steps);
        }
        thread::yield_now();
    }
    (false, steps)
}

#[test]
fn d10_p1_a28_observer_restart_recovery() {
    // -----------------------------------------------------------------------
    // quorum 语义：2 个验证者 ⇒ 单验证者权重不足 ⇒ 有效 2/2
    // -----------------------------------------------------------------------
    let quorum = quorum_for(2 * STAKE);
    assert!(
        quorum > STAKE,
        "单验证者权重（{STAKE}）不得足以构成 quorum（{quorum}）⇒ 必须 2/2"
    );
    assert!(quorum <= 2 * STAKE, "quorum 不得超过总权重");

    // -----------------------------------------------------------------------
    // 固定装置：genesis = {SEED_V1, SEED_V2}（两个真实验证者）
    // -----------------------------------------------------------------------
    let env = Env::new("a28", &[SEED_V1, SEED_V2]);

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
    let b_id = net_node_id(SEED_N2);
    let b_addr = b.listen.expect("B 必须绑定真实 listener");

    assert_eq!(
        a.rt.driver().consensus().validator_set().len(),
        2,
        "genesis 必须恰有 2 个验证者"
    );
    assert!(a.rt.validator().is_some() && b.rt.validator().is_some());

    // ---------- C：observer（label "c" ⇒ restart 复用同一 storage_dir）----------
    let mut c1 = start_observer(
        &env,
        "c",
        SEED_N3,
        None,
        vec![target(a_id, a_addr), target(b_id, b_addr)],
    );
    assert!(!c1.rt.validator_enabled(), "C 必须是 observer / full-node");
    assert!(
        c1.rt.validator().is_none(),
        "C 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        c1.rt.block_production().is_some(),
        "P1-A.24：C 必须有 canonical adapter"
    );

    // ---------- Step 1/2：三向建连 + 推进至 TARGET_BEFORE_RESTART ----------
    let (connected, connect_steps) = connect_three(&mut a, &mut b, &mut c1);
    assert!(
        connected,
        "三向建连未完成（a.last_err={:?} b.last_err={:?} c.last_err={:?}）",
        a.last_err, b.last_err, c1.last_err
    );

    let mut steps_before: usize = 0;
    while steps_before < STEP_BUDGET
        && (head_height(&a.rt) < TARGET_BEFORE_RESTART
            || head_height(&b.rt) < TARGET_BEFORE_RESTART
            || head_height(&c1.rt) < TARGET_BEFORE_RESTART)
    {
        let _ = b.rt.establish_configured_peers();
        let _ = c1.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c1);
        steps_before += 1;
        thread::yield_now();
    }

    // ---------- Step 3：restart 前记录 + 断言 ----------
    let c_head_before = head_height(&c1.rt);
    let c_hash_before = head_hash(&c1.rt);
    let c_fin_before = finalized_ref(&c1.rt);
    let c_tip_before = c1.rt.qc_history_tip_height();

    assert!(
        c_head_before >= TARGET_BEFORE_RESTART,
        "C 未达到 restart 前目标高度（head={c_head_before} < {TARGET_BEFORE_RESTART}）"
    );
    assert!(
        c_fin_before.is_some(),
        "C 必须已取得 finality（finalized_reference=None）"
    );

    // ---------- Step 4：仅停机 C（保留同 label / 同 storage_dir）----------
    stop(c1);

    // A/B 在 C 停机期间继续推进（真实离线窗口；同时让 A/B 完成 EOF 清理）
    let mut steps_while_down: usize = 0;
    while steps_while_down < STEP_BUDGET
        && (head_height(&a.rt) < TARGET_AFTER_RESTART || head_height(&b.rt) < TARGET_AFTER_RESTART)
    {
        let _ = b.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        steps_while_down += 1;
        thread::yield_now();
    }
    assert!(
        head_height(&a.rt) >= TARGET_AFTER_RESTART && head_height(&b.rt) >= TARGET_AFTER_RESTART,
        "A/B 未在 C 停机期间推进到 {}（a={} b={}）",
        TARGET_AFTER_RESTART,
        head_height(&a.rt),
        head_height(&b.rt)
    );

    // ---------- Step 5：同 label 重启 C（不重新 genesis / 不换目录）----------
    let mut c2 = start_observer(
        &env,
        "c",
        SEED_N3,
        None,
        vec![target(a_id, a_addr), target(b_id, b_addr)],
    );
    let c_restart_success = true; // 能走到此处即 `start_with_network` 成功（否则上方会 panic）

    // ---------- Step 5b：重启后**未 step** 立即断言恢复 ----------
    let c_head_at_restart = head_height(&c2.rt);
    let c_hash_at_restart = head_hash(&c2.rt);
    let c_fin_at_restart = finalized_ref(&c2.rt);
    let c_tip_at_restart = c2.rt.qc_history_tip_height();
    let c_dag_len = c2.rt.driver().consensus().dag().len();
    let c_safety_journal_exists = env.root("c").join("safety").join("safety.journal").exists();

    assert!(!c2.rt.validator_enabled(), "C2 不得变成 validator");
    assert!(
        c2.rt.validator().is_none(),
        "C2 不得持有 actor（无 lock 获取 / 无签名能力 / 无 safety journal）"
    );
    assert!(
        c2.rt.block_production().is_some(),
        "P1-A.24：C2 必须仍有 canonical adapter"
    );
    assert!(
        c2.rt
            .block_production()
            .is_some_and(|adapter| adapter.block_store().is_some()),
        "C2 的 BlockStore 必须可用"
    );
    assert_eq!(
        c_head_at_restart, c_head_before,
        "restart 后 committed head 不得回退（before={c_head_before} after={c_head_at_restart}）"
    );
    assert_eq!(
        c_hash_at_restart, c_hash_before,
        "restart 后 canonical head hash 必须保留"
    );
    assert!(
        c2.rt.driver().consensus().dag().contains(&c_hash_before),
        "restart 后 DAG 必须包含恢复出的 canonical head"
    );
    assert!(
        c_dag_len >= 2,
        "restart 后 DAG 必须已由 canonical ancestry 重建（len={c_dag_len}）"
    );
    assert!(
        c_tip_at_restart.is_some(),
        "restart 后 qc_history tip 必须已播种（QcHistory::open + seed_tip_from_store）"
    );
    assert!(!c_safety_journal_exists, "observer 不得产生 safety journal");
    // frozen 语义（D11-23 U4-C / IPC-1）：canonical-ancestry fact **不注入** finalized_reference
    assert!(
        c_fin_at_restart.is_none(),
        "restart 瞬间 finalized_reference 不得由 canonical-ancestry fact 注入（frozen D11-23 U4-C）；\
         实测 {:?}（restart 前 = {c_fin_before:?}）",
        c_fin_at_restart
    );

    // ---------- Step 5c/6：重连 + 继续推进至 TARGET_AFTER_RESTART ----------
    let (reconnected, reconnect_steps) = connect_three(&mut a, &mut b, &mut c2);
    assert!(
        reconnected,
        "C2 未能重新建连（a.last_err={:?} b.last_err={:?} c2.last_err={:?}）",
        a.last_err, b.last_err, c2.last_err
    );

    let mut steps_after: usize = 0;
    while steps_after < STEP_BUDGET && head_height(&c2.rt) < TARGET_AFTER_RESTART {
        let _ = b.rt.establish_configured_peers();
        let _ = c2.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c2);
        steps_after += 1;
        thread::yield_now();
    }

    // ---------- 证据读数 ----------
    let a_head_after = head_height(&a.rt);
    let b_head_after = head_height(&b.rt);
    let c_head_after = head_height(&c2.rt);
    let a_fin_after = finalized_ref(&a.rt);
    let b_fin_after = finalized_ref(&b.rt);
    let c_fin_after = finalized_ref(&c2.rt);
    let c_skipped = c2.rt.block_inbound_skipped();
    let c_qc_write_failed = c2.rt.qc_history_write_failed();
    let a_rejected = a.rt.inbound_consensus_rejected();
    let b_rejected = b.rt.inbound_consensus_rejected();
    let steps = connect_steps + steps_before + steps_while_down + reconnect_steps + steps_after;

    println!(
        "P1-A.28 EVIDENCE\n\
         \x20 topology = 2 validator + 1 observer（real TCP）\n\
         \x20 before_restart_height = {c_head_before}\n\
         \x20 after_restart_height = {c_head_after}\n\
         \x20 before_restart_hash = {}\n\
         \x20 after_restart_hash = {}\n\
         \x20 a_finalized_reference = {a_fin_after:?}\n\
         \x20 b_finalized_reference = {b_fin_after:?}\n\
         \x20 c_finalized_reference = {c_fin_after:?}\n\
         \x20 c_validator_enabled = {}\n\
         \x20 c_has_validator_actor = {}\n\
         \x20 c_qc_history_tip_before = {c_tip_before:?}\n\
         \x20 c_qc_history_tip_after = {c_tip_at_restart:?}\n\
         \x20 c_restart_success = {c_restart_success}\n\
         \x20 steps = {steps}   （connect={connect_steps} before={steps_before} while_down={steps_while_down} reconnect={reconnect_steps} after={steps_after}）\n\
         \x20 -- extra --\n\
         \x20 c_head_at_restart = {c_head_at_restart}   （durable head 恢复，未 step）\n\
         \x20 c_hash_at_restart = {}\n\
         \x20 c_finalized_at_restart = {c_fin_at_restart:?}   （frozen：不注入）\n\
         \x20 a_head_after = {a_head_after}\n\
         \x20 b_head_after = {b_head_after}\n\
         \x20 c_head_after = {c_head_after}\n\
         \x20 c_dag_len = {c_dag_len}\n\
         \x20 c_safety_journal_exists = {c_safety_journal_exists}\n\
         \x20 c_block_inbound_skipped = {c_skipped}\n\
         \x20 c_qc_history_write_failed = {c_qc_write_failed}\n\
         \x20 a_inbound_consensus_rejected = {a_rejected}   （C 若发送 vote/proposal ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 b_inbound_consensus_rejected = {b_rejected}",
        hex32(&c_hash_before),
        hex32(&c_hash_at_restart),
        c2.rt.validator_enabled(),
        c2.rt.validator().is_some(),
        hex32(&c_hash_at_restart),
    );

    // -----------------------------------------------------------------------
    // 断言：restart 后 observer 恢复并继续跟随
    // -----------------------------------------------------------------------
    assert!(
        c_head_after >= TARGET_AFTER_RESTART,
        "C 未在 restart 后达到目标高度（head={c_head_after} < {TARGET_AFTER_RESTART}；steps={steps_after}）"
    );
    assert!(
        c_head_after >= c_head_before,
        "C 的 head 不得回退（before={c_head_before} after={c_head_after}）"
    );
    assert!(
        c_fin_after.is_some(),
        "C 必须在 restart 后**重新取得** finality（finalized_reference=None ⇒ 无法 commit 新高度）"
    );
    assert_eq!(c_skipped, 0, "C 不得跳过任何远端 block（实测 {c_skipped}）");
    assert_eq!(
        c_qc_write_failed, 0,
        "C 的 QC history 写入不得失败（实测 {c_qc_write_failed}）"
    );

    // 与 validator finality 一致（同一高度下必须同值）
    if c_head_after == a_head_after {
        assert_eq!(
            c_fin_after, a_fin_after,
            "C 与 A 在同一高度上的 finalized_reference 必须一致"
        );
    }
    if c_head_after == b_head_after {
        assert_eq!(
            c_fin_after, b_fin_after,
            "C 与 B 在同一高度上的 finalized_reference 必须一致"
        );
    }
    if a_head_after == b_head_after {
        assert_eq!(
            a_fin_after, b_fin_after,
            "A/B 在同一高度上的 finalized_reference 必须一致（同链无分歧）"
        );
    }

    // -----------------------------------------------------------------------
    // 安全 / 隔离断言
    // -----------------------------------------------------------------------
    assert!(!c2.rt.validator_enabled(), "C2 不得变成 validator");
    assert!(
        c2.rt.validator().is_none(),
        "C2 不得持有 actor（无 lock 获取 / 无签名能力）"
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
