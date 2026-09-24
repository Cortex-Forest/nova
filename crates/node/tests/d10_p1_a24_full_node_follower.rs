//! P1-A.24 — **Canonical follower（非验证者节点跟随链）**：真实 TCP 回归。
//!
//! # 背景（P1-A.24 前）
//! 未启用 `--validator` 的节点（"full-node"）在 `NodeRuntime::start_inner` 中只得到**裸**
//! `PersistentBackend`（`block_production = None`）⇒ 远端区块被跳过（`block_inbound_skipped`），
//! 无法登记 DAG / 无法采纳外部 finality / 无法 commit / 不能作为 sync responder（`NoBlockStore`）。
//! 结果：文档拓扑中的 observer 节点 head 永远停在 genesis。
//!
//! # P1-A.24（本文件验证）
//! `runtime.rs` 的 full-node 分支改为**复用** `bootstrap::start(NoAccountsKeyResolver, config)`
//! —— 与 validator 分支**同一** canonical adapter 构造，但 actors 保持 `Vec::new()`。
//!
//! 因此本测试要求（A = validator，B = 无 `--validator` 的 follower，真实 TCP）：
//!
//! **B 必须跟随链**
//! - `validator_enabled() == false`、`validator().is_none()`（actors = 0）
//! - `head_height() >= N`（真实 commit 远端 canonical block）
//! - `block_inbound_skipped() == 0`（不再丢块）
//! - `finality.finalized_reference.is_some()`（经 frozen `verify_qc` 采纳外部 finality）
//! - `consensus.round.height >= head`（commit → advance 真实发生）
//!
//! **B 必须保持角色隔离**
//! - **不 proposal**：`runtime_propose` 的 `driver.actor(0)` gate 恒为 `None`（结构性）
//! - **不 vote / 不签名**：唯一 `Vote` outbound push 点在 `submit_local_vote`，只由 `auto_drive`
//!   的 actor 循环调用；actors = [] ⇒ 循环体不执行（结构性）；亦无 safety journal / signer
//! - **不产生自己的 QC**：无投票 ⇒ 不贡献 quorum
//! - **允许转发已验证 QC**（Owner 裁定选项 (i)）：`process_transition_derived` 对**由远端已验证
//!   证据**派生的 PrecommitQC 先做 `verify_qc`，通过后才 push outbound ⇒ 属
//!   **forwarded verified QC**，不是 locally produced QC。本测试把该行为作为**可观测证据**打印，
//!   不断言其必须为 0。
//!
//! # 可观测性（不新增生产代码）
//! - B 转发 QC ⇒ A 会收到 `ConsensusQc`（A 侧 `pending_external_qc_len() >= 1` 即"确实收到了
//!   来自 B 的 QC"的直接证据）；
//! - 反证：若 B 曾发送 Vote / 非法命令，A（genesis 唯一 validator，B 为非成员）必然
//!   `inbound_consensus_rejected > 0` ⇒ 断言其为 0 即"B 从未发送投票"的运行时反证。
//!
//! # 边界
//! 不修改 production 语义；不重复 P1-A.23 的 520 高度长链（>512 catch-up 已由
//! `d10_p1_a23a` / `d10_p1_a23` / `d9_step8a` 独立证明）。本测试目标高度 `N = 8`。

mod d10_p1_a10_common;

use std::net::SocketAddr;
use std::thread;

use d10_p1_a10_common as rig;

use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::key_provider::KeyProviderConfig;
use nova_node::runtime::NodeRuntime;

use rig::{
    Env, SEED_N1, SEED_N2, SEED_V1, consensus_height, head_height, net_node_id, start_node, target,
};

/// A（validator）需推进到的目标高度（最小可验证；**不**重复 P1-A.23 长链）。
const TARGET_HEIGHT: u64 = 8;
/// leader 推进 + follower 跟随的 step 预算（纯计数 ⇒ 与机器速度无关）。
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
/// 与共享 rig 的 `start_node` 唯一差异：`validator_enabled = false` +
/// `key_provider_config = None` + `start_with_network(.., None, ..)`。
/// 其余（真实 TCP listener / 真实网络身份 / 目录规划）与 validator 节点完全一致
/// —— 这正是 P1-A.24 要验证的"同一装配、不同权威"。
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

/// 有界建连：follower ↔ validator 双向 Established（纯计数；必须同时驱动两侧）。
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

#[test]
fn p1a24_full_node_follows_chain_without_validator_authority() {
    // -----------------------------------------------------------------------
    // 固定装置：genesis = {V1}（唯一 validator ⇒ quorum 1/1；B 为非成员 follower）
    // -----------------------------------------------------------------------
    let env = Env::new("a24", &[SEED_V1]);

    // ---------- A：validator（真实 TCP listener）----------
    let a_listen: SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("addr");
    let mut a = start_node(&env, "a", SEED_V1, SEED_N1, Some(a_listen), Vec::new());
    let a_id = net_node_id(SEED_N1);
    let a_addr = a.listen.expect("A 必须绑定真实 listener");
    assert!(a.rt.validator_enabled(), "A 必须是 validator");
    assert!(a.rt.validator().is_some(), "A 必须有 validator actor");

    // ---------- B：canonical follower（无 --validator；dial A）----------
    let b_listen: SocketAddr = format!("127.0.0.1:{}", rig::free_port())
        .parse()
        .expect("addr");
    let mut b = start_follower(
        &env,
        "b",
        SEED_N2,
        Some(b_listen),
        vec![target(a_id, a_addr)],
    );

    // ---------- B 启动形态（P1-A.24 核心：adapter 与 actor 解耦）----------
    assert!(!b.rt.validator_enabled(), "B 必须是 full-node / observer");
    assert!(
        b.rt.validator().is_none(),
        "B 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        b.rt.block_production().is_some(),
        "P1-A.24：B 必须有 canonical adapter（可验证 / 登记 / 采纳 / commit / serve sync）"
    );
    let b_head_at_start = head_height(&b.rt);

    // ---------- 建连（真实 TCP）----------
    assert!(
        connect(&mut b, &mut a, a_id),
        "B 未与 A 建立 Established（B.last_err={:?} A.last_err={:?}）",
        b.last_err,
        a.last_err
    );
    assert!(
        a.rt.network_peer_established(net_node_id(SEED_N2)),
        "A 未与 B 建立 Established"
    );

    // ---------- 有界驱动：A 产块，B 跟随 ----------
    let mut steps: usize = 0;
    while steps < STEP_BUDGET && head_height(&b.rt) < TARGET_HEIGHT {
        let _ = b.rt.establish_configured_peers();
        drive(&mut b);
        drive(&mut a);
        steps += 1;
        thread::yield_now();
    }

    // ---------- 证据读数 ----------
    let a_head = head_height(&a.rt);
    let b_head = head_height(&b.rt);
    let b_finalized = rig::finalized_ref(&b.rt);
    let b_rejected = b.rt.inbound_consensus_rejected();
    let a_rejected = a.rt.inbound_consensus_rejected();
    let a_pending_external_qc = a.rt.pending_external_qc_len();

    println!(
        "P1-A.24 EVIDENCE (real TCP; A=validator, B=full-node follower)\n\
         \x20 a_head_height                  = {a_head}\n\
         \x20 b_head_height                  = {b_head}\n\
         \x20 b_head_at_start                = {b_head_at_start}\n\
         \x20 b_validator_enabled            = {}\n\
         \x20 b_has_validator_actor          = {}\n\
         \x20 b_has_canonical_adapter        = {}\n\
         \x20 b_block_inbound_skipped        = {}\n\
         \x20 b_consensus_height             = {}\n\
         \x20 b_finalized_reference          = {b_finalized:?}\n\
         \x20 b_inbound_consensus_rejected   = {b_rejected}\n\
         \x20 a_inbound_consensus_rejected   = {a_rejected}   （B 若发送 vote ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 a_pending_external_qc_len      = {a_pending_external_qc}   （B 转发 QC 的收侧证据）\n\
         \x20 steps                          = {steps}\n\
         \x20 target_height                  = {TARGET_HEIGHT}",
        b.rt.validator_enabled(),
        b.rt.validator().is_some(),
        b.rt.block_production().is_some(),
        b.rt.block_inbound_skipped(),
        consensus_height(&b.rt),
    );

    // -----------------------------------------------------------------------
    // 断言 1：B 与 A 都必须推进（follower 真实跟随）
    // -----------------------------------------------------------------------
    assert!(
        a_head >= TARGET_HEIGHT,
        "A（validator）未达目标高度（head={a_head}）"
    );
    assert!(
        b_head >= TARGET_HEIGHT,
        "P1-A.24：B（canonical follower）未跟随到目标高度（head={b_head} < {TARGET_HEIGHT}；steps={steps}）"
    );

    // -----------------------------------------------------------------------
    // 断言 2：B 的跟随路径是**真实 commit**（非 head 跳跃）
    // -----------------------------------------------------------------------
    assert_eq!(
        b.rt.block_inbound_skipped(),
        0,
        "B 不得跳过任何远端 block（实测 {}）",
        b.rt.block_inbound_skipped()
    );
    assert!(
        b_finalized.is_some(),
        "B 必须采纳经 frozen `verify_qc` 验证的外部 finality（finalized_reference=None）"
    );
    assert!(
        consensus_height(&b.rt) >= b_head,
        "B 的 consensus 高度必须随 durable head 推进（consensus={} head={b_head}）",
        consensus_height(&b.rt)
    );

    // -----------------------------------------------------------------------
    // 断言 3：角色隔离（结构性；见文件头"可观测性"与 PRECHECK 的代码证据）
    //   · 不 proposal：`runtime_propose` 的 `driver.actor(0)` gate 恒 None
    //   · 不 vote / 不签名：唯一 Vote push 点在 `submit_local_vote`，只由 actor 循环调用
    //   · 不产生自己的 QC：无投票 ⇒ 不贡献 quorum
    // -----------------------------------------------------------------------
    assert!(!b.rt.validator_enabled(), "B 不得变成 validator");
    assert!(
        b.rt.validator().is_none(),
        "B 不得持有 actor（无 lock 获取 / 无签名能力）"
    );
    // 运行时反证：B 若发送过 Vote（非成员签名）⇒ A 必然拒绝并计数。
    assert_eq!(
        a_rejected, 0,
        "A 不得收到 B 的任何非法/不可应用 consensus command（实测 {a_rejected}）\
         ⇒ B 未发送 vote / proposal"
    );
    // 允许"转发已验证 QC"（Owner 选项 (i)）：若 A 侧观测到来自 B 的 QC，则其为 forwarded verified QC。
    if a_pending_external_qc >= 1 {
        println!(
            "P1-A.24 NOTE: A 观测到 {a_pending_external_qc} 条来自 B 的 ConsensusQc \
             ⇒ provenance = process_transition_derived → verify_qc → **forwarded verified QC**\
             （非 locally produced QC）"
        );
    }

    // -----------------------------------------------------------------------
    // 断言 4：validator 路径不受影响
    // -----------------------------------------------------------------------
    assert!(a.rt.validator_enabled(), "A 必须保持 validator");
    assert!(a.rt.validator().is_some(), "A 必须保持 validator actor");
}
