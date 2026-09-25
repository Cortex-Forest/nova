//! P1-A.27 — **2 validator + 1 observer 混合拓扑回归**（test-only；零生产改动）。
//!
//! # 目标（闭合 G2）
//! 既有 3-node 测试（`d10_p1_a10` / `a12` / `a21`）**全部为 validator**；非验证者仅由
//! `a24` / `a25` / `a26` 以 **2-node**（或 A←B←C 链）覆盖。本测试补 runbook §4 的**精确拓扑**：
//! ```text
//! A = validator 1（genesis {SEED_V1, SEED_V2} 之一；listener；peers = []）
//! B = validator 2（dial A；listener）
//! C = observer / non-validator（dial A 与 B；无 validator key / 无 actor）
//! ```
//! quorum：`total = 2 × STAKE` ⇒ `quorum = ceil(2T/3)`，**单个验证者权重不足以成 quorum**
//! ⇒ 有效的 **2/2**（本测试断言该算术，避免口径含糊）。
//!
//! # 断言范围
//! - A/B：`head >= TARGET` 且 `finalized_reference.is_some()`（双验证者真实 finality）；
//! - C（observer）：`validator_enabled == false`、`validator().is_none()`、`block_production().is_some()`、
//!   `head >= TARGET`、`finalized_reference.is_some()`、`block_inbound_skipped == 0`；
//! - **角色隔离**：C 不产生 proposal / vote / QC ⇒ 运行时反证 = A、B 两侧
//!   `inbound_consensus_rejected() == 0`（C 为非成员，若发送任何 vote/proposal 必被拒绝并计数）；
//! - 健康：`C.qc_history_write_failed() == 0`。
//!
//! # 语义边界（不得夸大）
//! 本测试 == **VERIFIED: 3-node（2 validator + 1 observer）**。
//! **不是** "testnet ready" / "production ready" / "mainnet ready"，也**不**等价于真实 Testnet 演练。
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
    Env, SEED_N1, SEED_N2, SEED_N3, SEED_V1, SEED_V2, STAKE, finalized_ref, free_port, head_height,
    hex32, net_node_id, quorum_for, start_node, target,
};

/// 三个节点都需达到的高度。
const TARGET_HEIGHT: u64 = 8;
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
///
/// 与共享 rig `start_node` 的唯一差异：`validator_enabled = false` +
/// `key_provider_config = None` + `start_with_network(.., None, ..)`（不注入 validator provider）。
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
fn d10_p1_a27_two_validators_one_observer() {
    // -----------------------------------------------------------------------
    // quorum 语义：2 个验证者 ⇒ 单验证者权重不足 ⇒ 有效 2/2
    // -----------------------------------------------------------------------
    let quorum = quorum_for(2 * STAKE);
    assert!(
        quorum > STAKE,
        "单验证者权重（{STAKE}）不得足以构成 quorum（{quorum}）⇒ 必须 2/2"
    );
    assert!(
        quorum <= 2 * STAKE,
        "quorum（{quorum}）不得超过总权重（{}）",
        2 * STAKE
    );

    // -----------------------------------------------------------------------
    // 固定装置：genesis = {SEED_V1, SEED_V2}（两个真实验证者）
    // -----------------------------------------------------------------------
    let env = Env::new("a27", &[SEED_V1, SEED_V2]);

    // ---------- A：validator 1（listener；peers = []）----------
    let a_listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut a = start_node(&env, "a", SEED_V1, SEED_N1, Some(a_listen), Vec::new());
    let a_id = net_node_id(SEED_N1);
    let a_addr = a.listen.expect("A 必须绑定真实 listener");
    assert!(a.rt.validator_enabled(), "A 必须是 validator");
    assert!(a.rt.validator().is_some(), "A 必须有 validator actor");
    assert_eq!(
        a.rt.driver().consensus().validator_set().len(),
        2,
        "genesis 必须恰有 2 个验证者"
    );

    // ---------- B：validator 2（dial A；listener）----------
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
    assert!(b.rt.validator_enabled(), "B 必须是 validator");
    assert!(b.rt.validator().is_some(), "B 必须有 validator actor");
    assert_ne!(a_id, b_id, "两个验证者必须身份不同");

    // ---------- C：observer（non-validator；dial A 与 B）----------
    let mut c = start_observer(
        &env,
        "c",
        SEED_N3,
        None, // observer 无需 listener（无人 dial 它）
        vec![target(a_id, a_addr), target(b_id, b_addr)],
    );
    assert!(!c.rt.validator_enabled(), "C 必须是 observer / full-node");
    assert!(
        c.rt.validator().is_none(),
        "C 不得持有任何 actor（无 key / 无 signer / 无 safety journal）"
    );
    assert!(
        c.rt.block_production().is_some(),
        "P1-A.24：C 必须有 canonical adapter（可验证 / 登记 / 采纳 / commit）"
    );

    // ---------- 建连：B→A、C→A、C→B（三向全互联）----------
    let mut connect_steps: usize = 0;
    let mut connected = false;
    while connect_steps < CONNECT_STEP_BUDGET {
        let _ = b.rt.establish_configured_peers();
        let _ = c.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c);
        connect_steps += 1;
        if b.rt.network_peer_established(a_id)
            && c.rt.network_peer_established(a_id)
            && c.rt.network_peer_established(b_id)
        {
            connected = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        connected,
        "三向建连未完成（B↔A={} C↔A={} C↔B={}；a.last_err={:?} b.last_err={:?} c.last_err={:?}）",
        b.rt.network_peer_established(a_id),
        c.rt.network_peer_established(a_id),
        c.rt.network_peer_established(b_id),
        a.last_err,
        b.last_err,
        c.last_err
    );

    // ---------- 推进：双验证者出块/finalize，observer 跟随 ----------
    let mut steps: usize = 0;
    while steps < STEP_BUDGET
        && (head_height(&a.rt) < TARGET_HEIGHT
            || head_height(&b.rt) < TARGET_HEIGHT
            || head_height(&c.rt) < TARGET_HEIGHT)
    {
        let _ = b.rt.establish_configured_peers();
        let _ = c.rt.establish_configured_peers();
        drive(&mut a);
        drive(&mut b);
        drive(&mut c);
        steps += 1;
        thread::yield_now();
    }

    // ---------- 证据读数 ----------
    let a_head = head_height(&a.rt);
    let b_head = head_height(&b.rt);
    let c_head = head_height(&c.rt);
    let a_fin = finalized_ref(&a.rt);
    let b_fin = finalized_ref(&b.rt);
    let c_fin = finalized_ref(&c.rt);
    let a_rejected = a.rt.inbound_consensus_rejected();
    let b_rejected = b.rt.inbound_consensus_rejected();
    let c_skipped = c.rt.block_inbound_skipped();
    let c_qc_tip = c.rt.qc_history_tip_height();
    let c_qc_write_failed = c.rt.qc_history_write_failed();
    let validator_set_len = a.rt.driver().consensus().validator_set().len();

    println!(
        "P1-A.27 EVIDENCE (real TCP; A=validator1, B=validator2, C=observer/non-validator)\n\
         \x20 validator_set_len              = {validator_set_len}   （quorum = {quorum} / total = {} ⇒ 2/2）\n\
         \x20 a_head                         = {a_head}\n\
         \x20 b_head                         = {b_head}\n\
         \x20 c_head                         = {c_head}\n\
         \x20 a_finalized_reference          = {a_fin:?}\n\
         \x20 b_finalized_reference          = {b_fin:?}\n\
         \x20 c_finalized_reference          = {c_fin:?}\n\
         \x20 c_validator_enabled            = {}\n\
         \x20 c_has_validator_actor          = {}\n\
         \x20 c_has_canonical_adapter        = {}\n\
         \x20 c_block_inbound_skipped        = {c_skipped}\n\
         \x20 c_qc_history_tip               = {c_qc_tip:?}\n\
         \x20 c_qc_history_write_failed      = {c_qc_write_failed}\n\
         \x20 a_inbound_consensus_rejected   = {a_rejected}   （C 若发送 vote/proposal ⇒ 非成员 ⇒ 必 >0）\n\
         \x20 b_inbound_consensus_rejected   = {b_rejected}\n\
         \x20 connect_steps                  = {connect_steps}\n\
         \x20 steps                          = {steps}\n\
         \x20 target_height                  = {TARGET_HEIGHT}",
        2 * STAKE,
        c.rt.validator_enabled(),
        c.rt.validator().is_some(),
        c.rt.block_production().is_some(),
    );

    // -----------------------------------------------------------------------
    // 断言 1：双验证者真实 finality
    // -----------------------------------------------------------------------
    assert!(
        a_head >= TARGET_HEIGHT,
        "A（validator 1）未达目标高度（head={a_head}；steps={steps}）"
    );
    assert!(
        b_head >= TARGET_HEIGHT,
        "B（validator 2）未达目标高度（head={b_head}；steps={steps}）"
    );
    assert!(
        a_fin.is_some(),
        "A 必须形成 finality（finalized_reference=None ⇒ 2/2 quorum 未达成）"
    );
    assert!(
        b_fin.is_some(),
        "B 必须形成 finality（finalized_reference=None ⇒ 2/2 quorum 未达成）"
    );

    // -----------------------------------------------------------------------
    // 断言 2：observer 真实跟随（含 finality 采纳）
    // -----------------------------------------------------------------------
    assert!(
        c_head >= TARGET_HEIGHT,
        "C（observer）未跟随到目标高度（head={c_head} < {TARGET_HEIGHT}；steps={steps}）"
    );
    assert!(
        c_fin.is_some(),
        "C 必须采纳/派生出已 finality 的引用（finalized_reference=None）"
    );
    assert_eq!(c_skipped, 0, "C 不得跳过任何远端 block（实测 {c_skipped}）");
    assert_eq!(
        c_qc_write_failed, 0,
        "C 的 QC history 写入不得失败（实测 {c_qc_write_failed}）"
    );

    // -----------------------------------------------------------------------
    // 断言 3：角色隔离（C 非验证者；A/B 未收到 C 的任何非法共识命令）
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

    // -----------------------------------------------------------------------
    // 断言 4：双验证者仍保持 validator 形态（observer 未影响其角色）
    // -----------------------------------------------------------------------
    assert!(a.rt.validator_enabled() && a.rt.validator().is_some());
    assert!(b.rt.validator_enabled() && b.rt.validator().is_some());
    assert_eq!(validator_set_len, 2, "验证者集合必须仍为 2");

    // 附带证据：两验证者在同一高度上不应出现 hash 分歧（若高度相同）。
    if a_head == b_head {
        let a_hash = rig::head_hash(&a.rt);
        let b_hash = rig::head_hash(&b.rt);
        assert_eq!(
            a_hash,
            b_hash,
            "同一高度上两验证者的 canonical head 必须一致（a={} b={}）",
            hex32(&a_hash),
            hex32(&b_hash)
        );
    }
}
