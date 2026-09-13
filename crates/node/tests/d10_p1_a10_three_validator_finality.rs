//! T1 — **3 Validator Real TCP Finality**（P1-A.10 Testnet Evidence；tests-only）。
//!
//! 证据目标（真实 TCP + 真实 runtime + 真实 consensus 路径）：
//! - 3 个 validator 身份（genesis 等额 stake ⇒ `total = 3×STAKE`、`quorum = 2×STAKE`）；
//! - proposal 产出 + 提案者轮转；
//! - **远端投票聚合**：单节点自身权重 = 1×STAKE **< quorum** ⇒ prevote/precommit 聚合权重达 quorum
//!   即证明收到并验证了远端投票；
//! - QC / finality：`finalized_reference` 三节点一致、`qc_history_tip_height ≥ 2`、head 前进。
//!
//! 拓扑（顺序 dial ⇒ 3 条真实 TCP 连接构成全互联；动态端口 `127.0.0.1:0`）：
//! ```text
//! A(listen, 无 peer)  ←  B(listen, peer=A)  ←  C(listen, peer=A,B)
//! ```

mod d10_p1_a10_common;

use d10_p1_a10_common as rig;

use std::collections::BTreeSet;
use std::time::Duration;

use rig::*;

#[test]
fn t1_three_validator_real_tcp_finality() {
    // quorum 公式核对：3 × STAKE ⇒ ceil(2T/3) = 2 × STAKE。
    let total = 3 * STAKE;
    let quorum = quorum_for(total);
    assert_eq!(quorum, 2 * STAKE, "quorum = ceil(3×STAKE×2/3) = 2×STAKE");

    let env = Env::new("t1", &[SEED_V1, SEED_V2, SEED_V3]);
    let a_id = net_node_id(SEED_N1);
    let b_id = net_node_id(SEED_N2);
    let c_id = net_node_id(SEED_N3);
    assert_ne!(a_id, b_id);
    assert_ne!(b_id, c_id);

    let a = start_node(
        &env,
        "a",
        SEED_V1,
        SEED_N1,
        Some("127.0.0.1:0".parse().expect("addr")),
        Vec::new(),
    );
    let a_addr = a.listen.expect("A 已绑定真实监听");
    let b = start_node(
        &env,
        "b",
        SEED_V2,
        SEED_N2,
        Some("127.0.0.1:0".parse().expect("addr")),
        vec![target(a_id, a_addr)],
    );
    let b_addr = b.listen.expect("B 已绑定真实监听");
    let c = start_node(
        &env,
        "c",
        SEED_V3,
        SEED_N3,
        Some("127.0.0.1:0".parse().expect("addr")),
        vec![target(a_id, a_addr), target(b_id, b_addr)],
    );
    assert_ne!(a_addr, b_addr, "动态端口互不相同");

    let mut nodes = vec![a, b, c];

    // ---- 证据采样（在推进过程中跟踪，禁止 sleep-only 判定）----
    let mut proposers: BTreeSet<nova_consensus::validator::ValidatorId> = BTreeSet::new();
    let mut max_prevote = [0u128; 3];
    let mut max_precommit = [0u128; 3];
    let mut meshed = false;

    let ok = advance_all(&mut nodes, 120_000, Duration::from_secs(30), |ns| {
        collect_proposers(ns, &mut proposers);
        for (i, n) in ns.iter().enumerate() {
            max_prevote[i] = max_prevote[i].max(prevote_weight(&n.rt));
            max_precommit[i] = max_precommit[i].max(precommit_weight(&n.rt));
        }
        // 全互联（每节点 2 个 configured peer 均 Established）。
        if !meshed {
            meshed = ns
                .iter()
                .enumerate()
                .all(|(i, n)| established_count(&n.rt, &[a_id, b_id, c_id][..]) == 2 && i < 3);
        }
        meshed
            && ns
                .iter()
                .all(|n| head_height(&n.rt) >= 3 && tip_height(&n.rt).is_some_and(|h| h >= 2))
    });
    let diag = format!(
        "heads={:?} tips={:?} consensus={:?} established={:?} dial(att/fail)={:?} inbound={:?} \
         round_timeouts={:?} inbound_rejected={:?} last_err={:?}",
        nodes.iter().map(|n| head_height(&n.rt)).collect::<Vec<_>>(),
        nodes.iter().map(|n| tip_height(&n.rt)).collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| (consensus_height(&n.rt), consensus_round(&n.rt)))
            .collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| established_count(&n.rt, &[a_id, b_id, c_id][..]))
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
    );
    eprintln!("T1 diagnostics: {diag}");
    // proposer 选择诊断（只读；用于定位为何无提案）。
    {
        use nova_consensus::proposer::select_proposer;
        use nova_consensus::validator::ValidatorSet;
        let g = genesis_with(&[SEED_V1, SEED_V2, SEED_V3]);
        let set = ValidatorSet::from_genesis(&g);
        let set_id = nova_crypto::identity::compute_genesis_hash(&g).expect("hash");
        let sel: Vec<String> = (0..4)
            .map(|h| match select_proposer(CHAIN_ID, h, 0, &set_id, &set) {
                Ok(v) => hex32(v.as_bytes()),
                Err(_) => "ERR".to_string(),
            })
            .collect();
        let local: Vec<String> = [SEED_V1, SEED_V2, SEED_V3]
            .iter()
            .map(|s| hex32(validator_id_of_seed(*s).as_bytes()))
            .collect();
        let steps: Vec<String> = nodes
            .iter()
            .map(|n| format!("{:?}", n.rt.driver().consensus().state().round.step))
            .collect();
        eprintln!(
            "T1 proposer-selection: selected(h=0..3)={sel:?} local={local:?} round_steps={steps:?}"
        );
    }
    assert!(ok, "T1 未在预算内达成: {diag}");

    // ---- 1. proposal production + 提案者轮转 ----
    assert!(
        !proposers.is_empty(),
        "必须观察到 proposal（proposer 集合不应为空）"
    );
    assert!(
        proposers.len() >= 2,
        "高度 ≥3 应观察到提案者轮转（observed={}）",
        proposers.len()
    );

    // ---- 2. 远端投票证明 ----
    // (a) 瞬时累加器采样（仅上界 + 报告；累加器随 round 推进 reset ⇒ 逐节点瞬态值不可靠）。
    for i in 0..3 {
        assert!(
            max_prevote[i] <= total && max_precommit[i] <= total,
            "节点{i} 聚合权重不得超总权重（prevote={} precommit={} total={total}）",
            max_prevote[i],
            max_precommit[i]
        );
    }
    let sampled_prevote = max_prevote.iter().copied().max().unwrap_or(0);
    let sampled_precommit = max_precommit.iter().copied().max().unwrap_or(0);
    assert!(
        sampled_prevote > 0,
        "至少应采样到非零 prevote 权重（observed={sampled_prevote}）"
    );
    // precommit 采样不可靠：precommit quorum ⇒ Finalized 与 round 推进在**同一 step 内**完成
    // ⇒ `step()` 返回后累加器已被 reset。故只报告，并以 (b) 结构性证明作为 quorum 证据。
    eprintln!(
        "T1 sampled weights (best-effort): prevote_max={sampled_prevote} precommit_max={sampled_precommit} quorum={quorum}"
    );
    // (b) 结构性证明（强于采样）：durable QC **只在** `verify_qc`（evidence 逐条签名 + weight ≥ quorum）
    //     通过后才会落盘（`qc_history` / finality fact）⇒ `tip ≥ 2` ∧ `write_failed == 0` ∧ 三节点
    //     `finalized_reference` 一致 ⇒ quorum 必然由**远端投票**达成（单节点自身 1×STAKE < quorum=2×STAKE）。
    // (c) 无 QC 校验失败：任何 `Driver(QcVerification(..))` 都必须缺席（P1-A.11 回归核心）。

    // ---- 3. QC / finality 收敛 ----
    let refs: Vec<Option<[u8; 32]>> = nodes.iter().map(|n| finalized_ref(&n.rt)).collect();
    assert!(
        refs.iter().all(|r| r.is_some()),
        "三节点都必须有 finalized reference：{refs:?}"
    );
    assert!(
        refs[0] == refs[1] && refs[1] == refs[2],
        "三节点 finalized reference 必须一致：{refs:?}"
    );
    for n in &nodes {
        assert!(
            tip_height(&n.rt).is_some_and(|h| h >= 2),
            "{} 的 durable QC tip 必须 ≥2：{:?}",
            n.label,
            tip_height(&n.rt)
        );
        assert!(
            tip_height(&n.rt) == Some(head_height(&n.rt)),
            "{} durable QC tip 必须与 head 一致（tip={:?} head={}）",
            n.label,
            tip_height(&n.rt),
            head_height(&n.rt)
        );
        // 注：`external_finality_rejected` 是**聚合计数**（含正常幂等/过时 与 异常冲突 两类）⇒
        // 不能作为严格 `== 0` 断言；安全性由下方三节点 reference 收敛 + 无 `last_err` 断言。
        eprintln!(
            "T1 node {} external_finality: adopted={} rejected={}",
            n.label,
            n.rt.external_finality_adopted(),
            n.rt.external_finality_rejected()
        );
        assert!(
            n.rt.qc_history_write_failed() == 0,
            "{} QC 历史写入不得失败",
            n.label
        );
        // P1-A.11 回归核心：不得出现任何 QC 证据校验失败。
        assert!(
            n.last_err.is_none(),
            "{} step 不得报错（含 QcVerification/InvalidSignature）：{:?}",
            n.label,
            n.last_err
        );
    }

    // ---- 4. 观测输出（非敏感）----
    eprintln!(
        "T1: heads={:?} tips={:?} refs_equal={} proposers={} prevote_max={:?} precommit_max={:?} quorum={}",
        nodes.iter().map(|n| head_height(&n.rt)).collect::<Vec<_>>(),
        nodes.iter().map(|n| tip_height(&n.rt)).collect::<Vec<_>>(),
        refs[0] == refs[1] && refs[1] == refs[2],
        proposers.len(),
        max_prevote,
        max_precommit,
        quorum,
    );
}
