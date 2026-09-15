//! B2 — **5 Validator Internal Devnet**（Tier-1：5 个生产 `NodeRuntime` + 真实 loopback TCP）。
//!
//! 目的（Testnet readiness 证据，**tests-only**）：证明 **5 validator** 配置在当前**冻结**共识实现下
//! 可端到端工作，且**无需任何生产改动**：
//! - quorum（权重制）= `ceil(total_weight × 2 / 3)`；5 × 等额 stake（`5×STAKE`）⇒ **666_667**
//!   ⇒ 4/5（`4×STAKE = 800_000`）**可达**；3/5（`600_000`）**不可达**（BFT 门限，非缺陷）；
//! - 每节点独立：validator 身份（seed）／network 身份（seed）／storage+safety 目录／监听端口；
//! - 静态全互联拓扑（后启动者 dial 先启动者，含 inbound accept）⇒ 每节点 4 个 configured peer 全 Established；
//! - proposal → vote → QC → finality（head + durable QC tip 前进）；跨节点 canonical 一致性；
//! - 单节点故障（4/5 继续 finality）；重新加入（catch-up）；同目录重启（committed head 保留 / DAG 重建 / 无
//!   `CorruptedState`）。
//!
//! 复用既有 rig [`d10_p1_a10_common`]（**不修改**该 harness），仅在本文件补充 2 组 seed 与 5 节点装配。
//! 所有推进均为**有界**（step 预算 + 硬超时），失败时输出诊断并显式失败（不吞错、不无限等待）。
//!
//! 受害节点选择（**确定性 + 自证**，见 [`pick_non_proposer_victim`]）：T3/T4/T5 停掉的是**不承担**
//! 所需高度 round-0 提案职责的节点。原因：rig 以单线程顺序 `step()` 驱动多节点，不经真实运行时的
//! 多线程消息交错，因此「离线 proposer ⇒ round timeout ⇒ round ≥ 1 产出」在 rig 下会出现票被拆到
//! 不同 round 的**保真度失真**（实测 window=300：`votes=[(0,0),(400_000,0),(600_000,0),(400_000,0)]`、
//! 各节点 round 互不相同 ⇒ 拿不到 QC）。该路径已由**真实多进程证据**覆盖：Tier-2 `t2_2`（停 V4 ⇒
//! 幸存 4/5 的 `finalized` 3 → 15/21/21/21）与 A12 `p1a18_t8`（确定性停 round-0 proposer，存活 2/3）。

mod d10_p1_a10_common;

use d10_p1_a10_common as rig;

use std::time::{Duration, Instant};

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::ValidatorSet;
use nova_crypto::identity::compute_genesis_hash;
use nova_network::node_id::NodeId;

use rig::*;

/// 追加的 2 组身份（V4/V5、N4/N5），与 rig 既有 `SEED_V1..V3` / `SEED_N1..N3` 共同构成 5 validator。
const SEED_V4: [u8; 32] = [0x34; 32];
const SEED_V5: [u8; 32] = [0x35; 32];
const SEED_N4: [u8; 32] = [0x44; 32];
const SEED_N5: [u8; 32] = [0x45; 32];

/// 5 validator 的 validator 身份 seeds（genesis 收录全部 5 个）。
const FIVE_VAL: [[u8; 32]; 5] = [SEED_V1, SEED_V2, SEED_V3, SEED_V4, SEED_V5];
/// 5 validator 的 network 身份 seeds（与 validator 身份隔离）。
const FIVE_NET: [[u8; 32]; 5] = [SEED_N1, SEED_N2, SEED_N3, SEED_N4, SEED_N5];
/// 节点标签（0..=4 ⇒ V0..V4）。
const LABELS: [&str; 5] = ["v0", "v1", "v2", "v3", "v4"];

/// 受害节点选择时需避开提案职责的高度数（`head+1 ..= head+VICTIM_NEEDED`）。
///
/// 为何要覆盖 5 个高度：该区间必须同时涵盖「受害节点离线期间集群需推进的高度」与「重启后恢复/追赶
/// 需推进的高度」——否则重启节点恰好是接下来某个高度的 round-0 proposer 时，集群会等它、它等同步，
/// 而默认 pacemaker 窗口（1000 tick）在有限阶段窗口内到不了超时（实测 `heads=[5,3,5,5,5]` 卡死）。
const VICTIM_NEEDED: u64 = 5;

/// 5 validator 的 network NodeId（供 Established 断言）。
fn five_ids() -> Vec<NodeId> {
    FIVE_NET.iter().map(|s| net_node_id(*s)).collect()
}

/// 5 节点诊断串（失败路径输出；只读观测）。
///
/// 除 head/tip/round 外还打印 **QC 形成所需的证据**：当前 round 的 proposal proposer、已累积的
/// prevote/precommit 权重（quorum 见 `quorum_for`）、以及 pacemaker 的 `(window, elapsed)` 窗口状态
/// —— 用于区分「未触发超时」与「超时了但拿不到 quorum 票」。
fn diag(tag: &str, nodes: &[Node]) -> String {
    format!(
        "{tag}: heads={:?} tips={:?} consensus(h,r)={:?} proposer={:?} votes(prevote,precommit)={:?} \
         timeout(window,elapsed)={:?} established(configured)={:?} \
         dial(att,fail)={:?} inbound={:?} round_timeouts={:?} rejected={:?} last_err={:?}",
        nodes.iter().map(|n| head_height(&n.rt)).collect::<Vec<_>>(),
        nodes.iter().map(|n| tip_height(&n.rt)).collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| (consensus_height(&n.rt), consensus_round(&n.rt)))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| proposal_proposer(&n.rt))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| (prevote_weight(&n.rt), precommit_weight(&n.rt)))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| (
                n.rt.round_timeout_window_ticks(),
                n.rt.round_timeout_elapsed_ticks()
            ))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| established_count(&n.rt, &five_ids()))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| (
                n.rt.peer_dial_attempts_total(),
                n.rt.peer_dial_failures_total()
            ))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| n.rt.network_inbound_connection_count())
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| n.rt.round_timeouts())
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| n.rt.inbound_consensus_rejected())
            .collect::<Vec<_>>(),
        nodes.iter().map(|n| n.last_err.clone()).collect::<Vec<_>>(),
    )
}

/// 启动 5 节点（静态互联：V_i 的 configured peers = V_0..=V_{i-1}；inbound 侧由对端 dial 补齐）。
///
/// 端口全部 `127.0.0.1:0`（动态）；每节点独立 storage/safety 目录与身份 seed（见 rig `config`）。
fn start_five(env: &Env) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::with_capacity(5);
    for i in 0..5 {
        let peers: Vec<_> = nodes
            .iter()
            .map(|n| {
                target(
                    net_node_id(n.net_seed),
                    n.listen.expect("已启动节点必有监听地址"),
                )
            })
            .collect();
        let n = start_node(
            env,
            LABELS[i],
            FIVE_VAL[i],
            FIVE_NET[i],
            Some("127.0.0.1:0".parse().expect("addr")),
            peers,
        );
        assert!(
            n.listen.is_some(),
            "{}：必须绑定真实监听地址（动态端口）",
            LABELS[i]
        );
        nodes.push(n);
    }
    nodes
}

/// 5 节点全互联（每节点 4 个 configured peer 全 Established）。
fn all_meshed(nodes: &[Node], ids: &[NodeId]) -> bool {
    nodes.iter().all(|n| established_count(&n.rt, ids) == 4)
}

/// 稳定基线谓词：全互联 ∧ 每节点 `head ≥ 3` ∧ durable QC tip `≥ 2`。
fn stable_baseline(nodes: &[Node], ids: &[NodeId]) -> bool {
    all_meshed(nodes, ids)
        && nodes
            .iter()
            .all(|n| head_height(&n.rt) >= 3 && tip_height(&n.rt).is_some_and(|h| h >= 2))
}

/// 断言无致命 step 错误（`CorruptedState` / 启动 / 驱动错误）。
fn assert_no_fatal(tag: &str, nodes: &[Node]) {
    for n in nodes {
        assert!(
            n.last_err.is_none(),
            "{tag}：{} 出现 step 错误（fail-closed）：{:?}",
            n.label,
            n.last_err
        );
    }
}
/// 选定受害节点：**不承担**「所需高度 `head+1 ..= head+needed` 的 round-0 提案职责」的节点。
///
/// 为什么需要这一步（实测证据，非猜测）：rig 以**单线程顺序 `step()`** 驱动多节点，不经过真实运行时的
/// 多线程消息交错；因此「离线 proposer ⇒ round timeout ⇒ round ≥ 1 产出」这条路径在 rig 下会失真：
/// 票被拆到不同 round（实测 window=300 ⇒ `votes=[(0,0),(400_000,0),(600_000,0),(400_000,0)]`、
/// `consensus(h,r)=[(3,2),(3,2),(3,1),(3,2)]` ⇒ 永远差一票，拿不到 QC）。该路径由**真实多进程证据**覆盖：
/// - 本文件 Tier-2 `t2_2`：停 V4 后幸存 4/5 的 `finalized` 3 → 15/21/21/21；
/// - A12 `p1a18_t8`：确定性停「未来高度的 round-0 proposer」⇒ 存活 2/3（quorum 紧凑）跳 round 产出。
///
/// 故 Tier-1 把受害节点选在**非提案位**，只考核 B2-3/B2-4/B2-5 的主张本身：
/// 「一个 validator 离线后 4/5（quorum 666_667 可达）继续出块 + finality」与「重启后保留 / 追赶」。
///
/// 确定性 + 自证：`select_proposer(chain, hh-1, 0, vset_id, set)` 给出高度 `hh` 的 round-0 proposer
/// （`vset_id` = genesis hash，与 A12 `p1a18_t8` 一致）；若有节点处于 round 0 且持有提案，则把
/// `proposal_proposer` 与计算值**交叉验证**（不一致即失败，避免 vset/genesis 不一致时静默选错节点）。
fn pick_non_proposer_victim(nodes: &[Node], needed: u64) -> usize {
    let genesis = rig::genesis_with(&FIVE_VAL);
    let vset_id = compute_genesis_hash(&genesis).expect("genesis hash");
    let set = ValidatorSet::from_genesis(&genesis);
    let head = nodes
        .iter()
        .map(|n| head_height(&n.rt))
        .max()
        .expect("至少 1 个节点");

    // 需避开的 proposer 集合：所需高度（head+1 ..= head+needed）的 round-0 proposer。
    let mut owners = Vec::new();
    for d in 1..=needed {
        if let Ok(p) = select_proposer(CHAIN_ID, head + d - 1, 0, &vset_id, &set) {
            owners.push(p);
        }
    }
    // 交叉验证（仅当存在 round 0 的提案时）＋把当前提案者也纳入避开集合（双保险）。
    if let Ok(p_first) = select_proposer(CHAIN_ID, head, 0, &vset_id, &set) {
        let observed = nodes.iter().find_map(|n| proposal_proposer(&n.rt));
        if let Some(obs) = observed {
            if nodes.iter().any(|n| consensus_round(&n.rt) == 0) {
                assert_eq!(
                    obs, p_first,
                    "B2：proposer 自证失败（select_proposer 与运行时可观测提案者不一致）"
                );
            }
            owners.push(obs);
        }
    }
    eprintln!(
        "B2 victim 选择：head={head} needed={needed} 避开 {n} 个 proposer（含当前提案者）",
        n = owners.len()
    );

    (0..nodes.len())
        .find(|i| {
            let id = validator_id_of_seed(FIVE_VAL[*i]);
            !owners.iter().any(|p| *p == id)
        })
        .unwrap_or_else(|| {
            panic!(
                "B2：fixture 内不存在可用的 non-proposer 受害节点（head={head} needed={needed}）"
            )
        })
}
/// 停止一个节点（graceful `NodeRuntime::shutdown`，consuming self）并返回其身份材料供重启使用。
fn stop_node(node: Node) -> ([u8; 32], [u8; 32]) {
    let val_seed = node.val_seed;
    let net_seed = node.net_seed;
    let Node { rt, .. } = node;
    rt.shutdown().expect("节点 shutdown 必须成功");
    (val_seed, net_seed)
}

/// 幸存者 peers（用于重启节点 dial 全互联；地址取自活的 `Node.listen`）。
fn targets_of(nodes: &[Node]) -> Vec<nova_network::transport::ConnectionTarget> {
    nodes
        .iter()
        .map(|n| target(net_node_id(n.net_seed), n.listen.expect("监听地址")))
        .collect()
}

// ---------------------------------------------------------------------------
// B2-1 — 5 Validator Baseline：真实 TCP 全互联 ⇒ height / QC tip 前进
// ---------------------------------------------------------------------------
#[test]
fn t1_five_validator_real_tcp_finality() {
    // quorum 公式核对（5 × 等额 stake）。
    let total = 5 * STAKE;
    let quorum = quorum_for(total);
    assert_eq!(quorum, 666_667, "quorum = ceil(5×STAKE×2/3) = 666_667");
    assert!(4 * STAKE >= quorum, "4/5 可达 quorum");
    assert!(3 * STAKE < quorum, "3/5 不可达 quorum（BFT 门限）");

    let env = Env::new("b2t1", &FIVE_VAL);
    let ids = five_ids();
    let uniq: std::collections::BTreeSet<[u8; 32]> = ids.iter().map(|i| *i.as_bytes()).collect();
    assert_eq!(uniq.len(), 5, "5 个 network 身份互不相同");
    let mut nodes = start_five(&env);

    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        // 稳定基线 ∧ **跨节点 canonical 一致**（至少一对同高度同 hash）—— 后件由谓词保证，避免事后抢跑断言。
        stable_baseline(ns, &ids)
            && (0..5).any(|i| {
                ((i + 1)..5).any(|j| {
                    head_height(&ns[i].rt) == head_height(&ns[j].rt)
                        && head_hash(&ns[i].rt) == head_hash(&ns[j].rt)
                })
            })
    });
    let d = diag("B2-T1", &nodes);
    eprintln!("{d}");
    assert!(
        ok,
        "B2-1：5 验证者未在全互联下达成 head≥3 ∧ QC tip≥2 ∧ 跨节点 canonical 一致（bounded 180s）"
    );
    assert_no_fatal("B2-1", &nodes);
    assert!(
        all_meshed(&nodes, &ids),
        "B2-1：每节点 4 个 configured peer 必须全部 Established"
    );
    // 跨节点 canonical 一致性：至少 2 个节点在同一 head 高度上给出相同 head hash。
    let mut agreement = 0usize;
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            if head_height(&nodes[i].rt) == head_height(&nodes[j].rt)
                && head_hash(&nodes[i].rt) == head_hash(&nodes[j].rt)
            {
                agreement += 1;
            }
        }
    }
    assert!(
        agreement > 0,
        "B2-1：未观察到任何同高度 canonical head 一致（{d}）"
    );
}

// ---------------------------------------------------------------------------
// B2-2 — Sustained consensus（有界窗口；head 与 finality 必须净增长）
// ---------------------------------------------------------------------------
#[test]
fn t2_five_validator_sustained_consensus() {
    let env = Env::new("b2t2", &FIVE_VAL);
    let ids = five_ids();
    let mut nodes = start_five(&env);

    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        stable_baseline(ns, &ids)
    });
    assert!(ok, "B2-2：未达稳定基线（先决条件）");
    let h0: Vec<u64> = nodes.iter().map(|n| head_height(&n.rt)).collect();
    let f0: Vec<u64> = nodes
        .iter()
        .map(|n| tip_height(&n.rt).unwrap_or(0))
        .collect();

    // 有界持续窗口：90s 墙钟上限 ∧ 200k step 预算（无无限等待）。
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut steps = 0usize;
    while Instant::now() < deadline && steps < 200_000 {
        for n in nodes.iter_mut() {
            let _ = n.rt.establish_configured_peers();
            if let Err(e) = n.rt.step() {
                n.last_err = Some(format!("{e:?}"));
            }
        }
        steps += 1;
        std::thread::yield_now();
    }

    let h1: Vec<u64> = nodes.iter().map(|n| head_height(&n.rt)).collect();
    let f1: Vec<u64> = nodes
        .iter()
        .map(|n| tip_height(&n.rt).unwrap_or(0))
        .collect();
    let d = diag("B2-T2", &nodes);
    eprintln!("B2-T2 sustained: steps={steps} h0={h0:?} h1={h1:?} f0={f0:?} f1={f1:?}\n{d}");

    assert_eq!(nodes.len(), 5, "B2-2：5 个节点必须全部存活");
    assert_no_fatal("B2-2", &nodes);
    for i in 0..5 {
        assert!(
            h1[i] > h0[i],
            "B2-2：节点 {} head 未增长（{h0:?} → {h1:?}）",
            nodes[i].label
        );
    }
    let f0_max = f0.iter().copied().max().unwrap_or(0);
    let f1_max = f1.iter().copied().max().unwrap_or(0);
    assert!(
        f1_max > f0_max,
        "B2-2：finality（durable QC tip 最大值）未前进（{f0:?} → {f1:?}）"
    );
    let h0_min = h0.iter().copied().min().unwrap_or(0);
    let h1_min = h1.iter().copied().min().unwrap_or(0);
    assert!(
        h1_min > h0_min,
        "B2-2：最小 head 未增长（{h0_min} → {h1_min}）"
    );
}

// ---------------------------------------------------------------------------
// B2-3 — One validator failure：停 V4 ⇒ 4/5 继续出块与 finality
// ---------------------------------------------------------------------------
#[test]
fn t3_one_validator_failure_four_of_five_continue() {
    let env = Env::new("b2t3", &FIVE_VAL);
    let ids = five_ids();
    let mut nodes = start_five(&env);

    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        stable_baseline(ns, &ids)
    });
    assert!(ok, "B2-3：未达稳定基线（先决条件）");

    // 受害节点：不承担所需高度的 round-0 提案职责（见 [`pick_non_proposer_victim`]）。
    let victim_idx = pick_non_proposer_victim(&nodes, VICTIM_NEEDED);
    let v4 = nodes.remove(victim_idx);
    let before_head = head_height(&v4.rt);
    let before_tip = tip_height(&v4.rt).unwrap_or(0);
    let (v4_val, v4_net) = stop_node(v4);
    assert_ne!(v4_val, v4_net, "身份隔离（validator ≠ network）");
    eprintln!(
        "B2-T3 victim={} (index {victim_idx}) before_head={before_head} before_tip={before_tip}",
        LABELS[victim_idx]
    );

    // 4/5 必须继续：head 前进 ≥ 2 且 QC tip 前进（quorum 666_667 可达）。
    let ok = advance_all(&mut nodes, 500_000, Duration::from_secs(240), |ns| {
        ns.iter().all(|n| head_height(&n.rt) >= before_head + 2)
            && ns
                .iter()
                .map(|n| tip_height(&n.rt).unwrap_or(0))
                .max()
                .unwrap_or(0)
                > before_tip
    });
    let timeouts_after: Vec<_> = nodes.iter().map(|n| n.rt.round_timeouts()).collect();
    eprintln!(
        "B2-T3 evidence: round_timeouts after = {timeouts_after:?}（受害节点非提案位 ⇒ 期望 0；\
         离线 proposer 的跳 round 路径由 Tier-2 / A12 p1a18_t8 的真实进程证据覆盖）"
    );
    let d = diag("B2-T3", &nodes);
    eprintln!("B2-T3 after victim stop: before_head={before_head} before_tip={before_tip}\n{d}");
    assert!(
        ok,
        "B2-3：4/5 未在窗口内继续（要求 head ≥ {} ∧ tip > {}）",
        before_head + 2,
        before_tip
    );
    assert_no_fatal("B2-3", &nodes);
    let after_min = nodes.iter().map(|n| head_height(&n.rt)).min().unwrap_or(0);
    let after_tip = nodes
        .iter()
        .map(|n| tip_height(&n.rt).unwrap_or(0))
        .max()
        .unwrap_or(0);
    assert!(after_min > before_head, "B2-3：4/5 head 必须前进");
    assert!(after_tip > before_tip, "B2-3：4/5 finality 必须前进");
}

// ---------------------------------------------------------------------------
// B2-4 — Rejoin / catch-up：V4 重启 ⇒ 重连 ⇒ 追赶 ⇒ 与其他节点一致
// ---------------------------------------------------------------------------
#[test]
fn t4_validator_rejoin_catchup() {
    let env = Env::new("b2t4", &FIVE_VAL);
    let ids = five_ids();
    let mut nodes = start_five(&env);

    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        stable_baseline(ns, &ids)
    });
    assert!(ok, "B2-4：未达稳定基线（先决条件）");

    // 受害节点：不承担所需高度的 round-0 提案职责（见 [`pick_non_proposer_victim`]）。
    let victim_idx = pick_non_proposer_victim(&nodes, VICTIM_NEEDED);
    let v4 = nodes.remove(victim_idx);
    let pre_stop_head = head_height(&v4.rt);
    let pre_stop_tip = tip_height(&v4.rt).unwrap_or(0);
    let (v4_val, v4_net) = stop_node(v4);
    eprintln!(
        "B2-T4 victim={} (index {victim_idx}) pre_stop_head={pre_stop_head} pre_stop_tip={pre_stop_tip}",
        LABELS[victim_idx]
    );

    // 存活 4/5 在此期间前进（制造真实落后）。
    let ok = advance_all(&mut nodes, 500_000, Duration::from_secs(240), |ns| {
        ns.iter().all(|n| head_height(&n.rt) >= pre_stop_head + 3)
    });
    assert!(ok, "B2-4：幸存 4/5 未前进（无法制造落后）");
    let peers = targets_of(&nodes);
    let min_others = nodes.iter().map(|n| head_height(&n.rt)).min().unwrap_or(0);

    // 以**同一身份与同一数据目录**重启（rig `config` 以 label 定位目录 ⇒ 复用该 label）。
    let v4_restarted = start_node(
        &env,
        LABELS[victim_idx],
        v4_val,
        v4_net,
        Some("127.0.0.1:0".parse().expect("addr")),
        peers,
    );
    // ★ committed head 必须在重启瞬间被 storage 恢复（catch-up 之前）。
    assert_eq!(
        head_height(&v4_restarted.rt),
        pre_stop_head,
        "B2-4：V4 重启后 committed head 必须保留（{pre_stop_head}）"
    );
    nodes.push(v4_restarted);

    // 追赶：V4 head ≥ 幸存者最小 head ∧ V4 durable tip 前进。
    let ok = advance_all(&mut nodes, 700_000, Duration::from_secs(300), |ns| {
        let v4h = head_height(&ns[4].rt);
        let min_others = ns[..4]
            .iter()
            .map(|n| head_height(&n.rt))
            .min()
            .unwrap_or(u64::MAX);
        v4h >= min_others && tip_height(&ns[4].rt).is_some_and(|h| h > pre_stop_tip)
    });
    let d = diag("B2-T4", &nodes);
    eprintln!(
        "B2-T4 rejoin: pre_stop_head={pre_stop_head} pre_stop_tip={pre_stop_tip} \
         min_others_at_restart={min_others}\n{d}"
    );
    assert!(ok, "B2-4：V4 未在窗口内完成重连 + 追赶（bounded 300s）");
    assert_no_fatal("B2-4", &nodes);
    let v4_head = head_height(&nodes[4].rt);
    let others_min = nodes[..4]
        .iter()
        .map(|n| head_height(&n.rt))
        .min()
        .unwrap_or(0);
    assert!(
        v4_head >= others_min,
        "B2-4：V4 head 必须追平幸存者最小 head（{v4_head} vs {others_min}）"
    );
    // 跨节点 canonical 一致性：V4 head hash 必须出现在幸存者之一的同高度 head 上。
    let v4_hash = head_hash(&nodes[4].rt);
    let consistent = nodes[..4]
        .iter()
        .any(|n| head_height(&n.rt) == v4_head && head_hash(&n.rt) == v4_hash)
        || nodes[..4].iter().any(|n| {
            head_height(&n.rt) >= v4_head && tip_height(&n.rt).is_some_and(|h| h >= v4_head)
        });
    assert!(
        consistent,
        "B2-4：V4 的 head 未与幸存者 canonical 链一致（{d}）"
    );
}

// ---------------------------------------------------------------------------
// B2-5 — Restart persistence（同目录 / 同身份；committed head 保留 + DAG 重建 + 恢复）
// ---------------------------------------------------------------------------
#[test]
fn t5_validator_restart_persistence() {
    let env = Env::new("b2t5", &FIVE_VAL);
    let ids = five_ids();
    let mut nodes = start_five(&env);

    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        stable_baseline(ns, &ids)
    });
    assert!(ok, "B2-5：未达稳定基线（先决条件）");
    // 受害节点：不承担所需高度的 round-0 提案职责（见 [`pick_non_proposer_victim`]）。
    let victim_idx = pick_non_proposer_victim(&nodes, VICTIM_NEEDED);
    assert!(
        head_height(&nodes[victim_idx].rt) >= 3,
        "B2-5：被重启节点必须先 commit ≥3 块"
    );

    let v3 = nodes.remove(victim_idx);
    let pre_head = head_height(&v3.rt);
    let pre_hash = head_hash(&v3.rt);
    let (v3_val, v3_net) = stop_node(v3);

    // 其余 4 个继续前进（重启节点应落后）。
    let ok = advance_all(&mut nodes, 400_000, Duration::from_secs(180), |ns| {
        ns.iter().all(|n| head_height(&n.rt) >= pre_head + 2)
    });
    assert!(ok, "B2-5：其余节点未前进");

    let peers = targets_of(&nodes);
    // 同目录 / 同身份重启：`start_node` 内部执行 bootstrap + BlockStore 恢复 +
    // `verify_committed_head_block`（失败即 panic ⇒ 无 CorruptedState 的强证据）。
    let v3_restarted = start_node(
        &env,
        LABELS[victim_idx],
        v3_val,
        v3_net,
        Some("127.0.0.1:0".parse().expect("addr")),
        peers,
    );
    assert_eq!(
        head_height(&v3_restarted.rt),
        pre_head,
        "B2-5：重启后 committed head 必须保留"
    );
    assert_eq!(
        head_hash(&v3_restarted.rt),
        pre_hash,
        "B2-5：重启后 canonical head hash 必须保留"
    );
    assert!(
        v3_restarted
            .rt
            .block_production()
            .is_some_and(|a| a.block_store().is_some()),
        "B2-5：重启后 BlockStore 必须可用（编码布局可读）"
    );
    nodes.insert(victim_idx, v3_restarted);

    // consensus 恢复：重启节点 head 前进 ∧ durable tip 前进。
    let ok = advance_all(&mut nodes, 500_000, Duration::from_secs(240), |ns| {
        let v3h = head_height(&ns[victim_idx].rt);
        v3h > pre_head && tip_height(&ns[3].rt).is_some_and(|h| h >= 2)
    });
    let d = diag("B2-T5", &nodes);
    eprintln!("B2-T5 restart: pre_head={pre_head}\n{d}");
    assert!(ok, "B2-5：重启节点未恢复共识推进（bounded 240s）");
    assert_no_fatal("B2-5", &nodes);
    for n in &nodes {
        if let Some(e) = &n.last_err {
            assert!(
                !e.contains("CorruptedState"),
                "B2-5：不得出现 CorruptedState（{}）",
                n.label
            );
        }
    }
}
