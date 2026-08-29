//! Fork Choice（STEP 10-8.2 — ADR-0040 FC-1~FC-14 +
//! `docs/protocols/fork-choice-implementation-design-v1.md`）。
//!
//! # 核心职责（纯计算、无状态）
//! - [`fork_choice`]：最终性优先选择 DAG 候选 head。
//!   - **FC-12 Finality Dominance**：`finalized` 存在（∈ DAG）⇒ 绝对短路返回，不比较非 final 候选。
//!   - **FC-13**：justified anchor = `verify_qc`（authoritative）+ `vote_type == Prevote` +
//!     `target ∈ DAG`（applicability guard）。
//!   - **FC-MF-10**：`highest justified` = DAG causal 偏序下 **maximal justified anchors**；
//!     incomparable ⇒ `block_hash` 最小（**结果不依赖 `prevote_qcs` 输入顺序**）。
//!   - **FC-14**：head = selected anchor 的 **causal-descendant frontier**（subtree 的 maximal
//!     elements）；`head = min_hash(Frontier(anchor))`。
//!   - **O-3**：无 justified ⇒ DAG root（zero-parent；多 root ⇒ hash 最小）；空 DAG ⇒ `None`。
//!
//! # 冻结约束（禁令）
//! - 不引入 ForkChoiceError / Result（保持 `Option<[u8;32]>`）；无 witness；无 serialization；
//!   无新 consensus state；不接 storage/execution/network。
//! - 禁 height/round/block_count/insertion/iteration order 参与任何选择。
//! - 不改 `dag.rs` / `finality.rs` / `vote.rs` / `validator.rs` / `error.rs` / 冻结 ADR。

use crate::dag::Dag;
use crate::finality::{QuorumCertificate, verify_qc};
use crate::validator::ValidatorSet;
use crate::vote::VoteType;
use std::collections::HashSet;

/// Fork Choice（ADR-0040）。
///
/// `None` 语义（契约层）：① `finalized=Some(f)` 且 `f ∉ DAG`（FC-10 invalid-input）；
/// ② 空 DAG + 无 finalized + 无 justified（O-3）；③ 其他无 head。
pub fn fork_choice(
    dag: &Dag,
    finalized: Option<&[u8; 32]>,
    prevote_qcs: &[QuorumCertificate],
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    // ① FC-12 Finality Dominance（绝对短路）：不比较任何非 final 候选。
    if let Some(f) = finalized {
        if !dag.contains(f) {
            return None; // FC-10：deterministic invalid-input
        }
        return Some(*f);
    }
    // ② FC-13：收集 justified anchors（verify_qc → Prevote → target∈DAG）。
    let anchors = collect_justified_anchors(dag, prevote_qcs, set, expected_genesis_hash);
    // ③ O-3：无 anchor ⇒ root fallback（空 DAG ⇒ None）。
    if anchors.is_empty() {
        if dag.is_empty() {
            return None;
        }
        return Some(select_root(dag));
    }
    // ④ FC-MF-10：maximal justified anchors（输入顺序无关），选 block_hash 最小者。
    let maximal = maximal_anchors(dag, &anchors);
    let selected = match maximal.iter().min() {
        Some(m) => *m,
        None => return None, // 不可达（anchors 非空 ⇒ maximal 非空）；防御
    };
    // ⑤ FC-14：selected anchor 的 causal-descendant frontier 中 min_hash。
    frontier_head(dag, &selected)
}

/// FC-13 三层判定（严格分离）：Layer 1 `verify_qc`（authoritative QC validation boundary）→
/// Layer 2 `vote_type == Prevote` + `dag.contains(target)`（Fork Choice applicability guard）。
/// 任一失败 ⇒ 过滤（不作 anchor，不影响其他 QC）。
fn collect_justified_anchors(
    dag: &Dag,
    prevote_qcs: &[QuorumCertificate],
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
) -> Vec<[u8; 32]> {
    let mut anchors = Vec::new();
    let mut seen = HashSet::new();
    for qc in prevote_qcs {
        // Layer 1（FC-MF-9）：verify_qc 为 authoritative QC validation boundary。
        if verify_qc(qc, set, expected_genesis_hash, dag).is_err() {
            continue;
        }
        // Layer 2a：vote_type == Prevote（FC-2/FC-4）。
        if qc.context.vote_type != VoteType::Prevote {
            continue;
        }
        // Layer 2b：target ∈ DAG（显式 applicability guard，FC-13）。
        if !dag.contains(&qc.target) {
            continue;
        }
        if seen.insert(qc.target) {
            anchors.push(qc.target);
        }
    }
    anchors
}

/// `ancestor` 是否为 `node` 的祖先（沿 DAG parent 边；仅 DAG relation，禁 height/round 推导）。
fn dag_reaches(dag: &Dag, ancestor: &[u8; 32], node: &[u8; 32]) -> bool {
    if node == ancestor {
        return true;
    }
    let mut visited = HashSet::new();
    let mut stack = vec![*node];
    while let Some(cur) = stack.pop() {
        if cur == *ancestor {
            return true;
        }
        if !visited.insert(cur) {
            continue;
        }
        if let Some(parents) = dag.parents_of(&cur) {
            stack.extend(parents.iter().copied());
        }
    }
    false
}

/// FC-MF-10：maximal justified anchors（DAG causal 偏序下的极大元）。
/// `{ A ∈ anchors : 无 B ∈ anchors（B≠A）使 B 是 A 的 proper causal ancestor }`。
/// 结果与输入顺序无关（集合运算）。
fn maximal_anchors(dag: &Dag, anchors: &[[u8; 32]]) -> Vec<[u8; 32]> {
    anchors
        .iter()
        .copied()
        .filter(|&a| !anchors.iter().any(|&b| b != a && dag_reaches(dag, &b, &a)))
        .collect()
}

/// O-3 root fallback：zero-parent block 中 `block_hash` 字典序最小者。
/// 调用前提：DAG 非空。
fn select_root(dag: &Dag) -> [u8; 32] {
    let mut best: Option<[u8; 32]> = None;
    // 遍历全部 blocks（DAG 中每块都是某 tip 的祖先；causal_order(tip) 覆盖全部 reachable）。
    for tip in dag.tips() {
        for h in dag.causal_order(tip) {
            let is_root = dag.parents_of(&h).is_none_or(|p| p.is_empty());
            if is_root {
                best = Some(match best {
                    None => h,
                    Some(b) => b.min(h),
                });
            }
        }
    }
    best.expect("non-empty DAG has at least one root")
}

/// FC-14：selected anchor 的 causal-descendant frontier 中 `block_hash` 最小者。
/// Frontier = { tip ∈ dag.tips() : anchor 是 tip 的祖先（或 tip == anchor）}。
/// 禁退化：不用 height/round/descendants 数/全 DAG tips/insertion/iteration order。
fn frontier_head(dag: &Dag, anchor: &[u8; 32]) -> Option<[u8; 32]> {
    let mut best: Option<[u8; 32]> = None;
    for tip in dag.tips() {
        if dag_reaches(dag, anchor, tip) {
            best = Some(match best {
                None => *tip,
                Some(b) => b.min(*tip),
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::BlockReference;
    use crate::finality::{QcContext, QcEvidence};
    use crate::validator::ValidatorId;
    use crate::vote::{ValidatorVote, canonical_vote_payload};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use proptest::prelude::*;

    const CHAIN_ID: u64 = 1001;
    const GENESIS_HASH: [u8; 32] = [0x42; 32];

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn vin(pk: [u8; 32], stake: u128, kh: [u8; 32]) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: stake,
            commission_bps: 100,
        }
    }

    fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_timestamp: 0,
            initial_validator_set: vals,
            initial_accounts: Vec::new(),
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 64 * 1024,
                max_block_bytes: 8 * 1024 * 1024,
                max_gas_per_block: 100_000_000_000,
                max_contract_code_bytes: 0,
                max_contract_storage_bytes: 0,
                epoch_length_blocks: 1_000_000,
                snapshot_interval_blocks: 10_000_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 1_000_000_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 100,
            },
        }
    }

    struct TestCtx {
        set: ValidatorSet,
        kps: Vec<KeyPair>,
    }

    fn test_ctx(n: usize, stake: u128) -> TestCtx {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().unwrap();
            let pk = kp.verifying_key().to_bytes();
            kps.push(kp);
            vals.push(vin(pk, stake, [i as u8 + 0x10; 32]));
        }
        TestCtx {
            set: ValidatorSet::from_genesis(&genesis_with(vals)),
            kps,
        }
    }

    fn validator_id_of(ctx: &TestCtx, i: usize) -> ValidatorId {
        ValidatorId::from_consensus_public_key(&ctx.kps[i].verifying_key().to_bytes())
    }

    fn sign_vote(signing: &nova_crypto::signature::SigningKey, vote: &ValidatorVote) -> [u8; 64] {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .unwrap();
        sign_message_hash(signing, &hash_signing_message(&signed)).to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_qc(
        ctx: &TestCtx,
        idxs: &[usize],
        target: [u8; 32],
        round: u64,
        height: u64,
        vt: VoteType,
        source: [u8; 32],
        timestamp: u64,
    ) -> QuorumCertificate {
        let mut evidence: Vec<QcEvidence> = Vec::with_capacity(idxs.len());
        for &i in idxs {
            let vid = validator_id_of(ctx, i);
            let vote = ValidatorVote {
                round,
                height,
                target_block_hash: target,
                vote_type: vt,
                source_block_hash: source,
                validator_id: vid,
                timestamp,
            };
            let sig = sign_vote(ctx.kps[i].signing_key(), &vote);
            evidence.push(QcEvidence {
                validator_id: vid,
                source_block_hash: source,
                timestamp,
                signature: sig,
            });
        }
        evidence.sort_by_key(|e| e.validator_id);
        QuorumCertificate {
            context: QcContext {
                chain_id: CHAIN_ID,
                height,
                round,
                vote_type: vt,
            },
            target,
            validator_set_id: GENESIS_HASH,
            evidence,
        }
    }

    /// 构造 DAG：`(block_byte, height, parents_bytes)`。调用方保证 parent.height < block.height。
    fn build_dag(blocks: &[(u8, u64, Vec<u8>)]) -> Dag {
        let mut dag = Dag::new();
        for (h, height, parents) in blocks {
            dag.add_block(BlockReference {
                block_hash: [*h; 32],
                height: *height,
                parents: parents.iter().map(|p| [*p; 32]).collect(),
                proposer: ValidatorId::from_bytes([*h; 32]),
            })
            .unwrap();
        }
        dag
    }

    fn prevote(ctx: &TestCtx, target: [u8; 32]) -> QuorumCertificate {
        make_qc(
            ctx,
            &[0, 1, 2],
            target,
            0,
            1,
            VoteType::Prevote,
            [0x00; 32],
            100,
        )
    }

    // ---- T1：finalized ∈ DAG ⇒ 返回 finalized（FC-1/FC-12）----
    #[test]
    fn t1_finality_first() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let qc = prevote(&ctx, [0xBB; 32]);
        assert_eq!(
            fork_choice(&dag, Some(&[0xAA; 32]), &[qc], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- T2：finalized ∉ DAG ⇒ None（FC-10 invalid-input）----
    #[test]
    fn t2_finalized_not_in_dag() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![])]);
        assert_eq!(
            fork_choice(&dag, Some(&[0x99; 32]), &[], &ctx.set, &GENESIS_HASH),
            None
        );
    }

    // ---- T3：QC(B)，A←B←C ⇒ anchor=B，head=C（FC-9/FC-MF-3）----
    #[test]
    fn t3_anchor_head_separation() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
        ]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        assert_eq!(
            fork_choice(&dag, None, &[qc_b], &ctx.set, &GENESIS_HASH),
            Some([0xCC; 32]),
            "anchor=B，head=C"
        );
    }

    // ---- T4：无 justified ⇒ DAG root（多 root ⇒ block_hash 最小，O-3/A）----
    #[test]
    fn t4_root_fallback_multi_root() {
        let ctx = test_ctx(3, 100);
        // 两个 root：0xAA 与 0xBB（0xAA < 0xBB）
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 0, vec![])]);
        assert_eq!(
            fork_choice(&dag, None, &[], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32]),
            "root = min hash"
        );
    }

    // ---- T5：多 justified，descendant 更高 ⇒ 选 descendant（FC-5）----
    #[test]
    fn t5_descendant_anchor_higher() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
        ]);
        let qc_a = prevote(&ctx, [0xAA; 32]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        // anchors={A,B}；B 支配 A ⇒ maximal={B}；head = frontier(B) = {C}
        assert_eq!(
            fork_choice(&dag, None, &[qc_a, qc_b], &ctx.set, &GENESIS_HASH),
            Some([0xCC; 32])
        );
    }

    // ---- T6：incomparable justified ⇒ hash tie-break（FC-8）----
    #[test]
    fn t6_incomparable_hash_tiebreak() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 1, vec![0xAA]),
        ]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        let qc_c = prevote(&ctx, [0xCC; 32]);
        // B ∥ C，均为 tip ⇒ maximal={B,C}；选 min(B,C)=0xBB；head=frontier(0xBB)={0xBB}
        assert_eq!(
            fork_choice(&dag, None, &[qc_b, qc_c], &ctx.set, &GENESIS_HASH),
            Some([0xBB; 32])
        );
    }

    // ---- T7：伪 PrevoteQC（签名失败）⇒ 不作 anchor（FC-13 Layer 1）----
    #[test]
    fn t7_invalid_qc_not_anchor() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let mut qc = prevote(&ctx, [0xBB; 32]);
        qc.evidence[0].signature[0] ^= 0xff;
        // 无 justified ⇒ root fallback
        assert_eq!(
            fork_choice(&dag, None, &[qc], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- T8：height 反例：高 height 非 descendant ⇒ 不选（FC-3）----
    #[test]
    fn t8_height_not_ancestry() {
        let ctx = test_ctx(3, 100);
        // 两个独立分支：root A 和 root B（B 有更高后裔但无关）
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 0, vec![]),
            (0xCC, 1, vec![0xBB]), // CC 更高 height 但 unrelated to AA-branch
        ]);
        // QC(AA) justified；选 AA 分支 head（frontier of AA = {AA}，因 AA 无后裔且是 tip）
        let qc_a = prevote(&ctx, [0xAA; 32]);
        assert_eq!(
            fork_choice(&dag, None, &[qc_a], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32]),
            "height 更大的 CC 不因 height 入选"
        );
    }

    // ---- T9：确定性：同输入同输出（FC-2）----
    #[test]
    fn t9_deterministic() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let qc = prevote(&ctx, [0xBB; 32]);
        let r1 = fork_choice(
            &dag,
            None,
            std::slice::from_ref(&qc),
            &ctx.set,
            &GENESIS_HASH,
        );
        let r2 = fork_choice(&dag, None, &[qc], &ctx.set, &GENESIS_HASH);
        assert_eq!(r1, r2);
    }

    // ---- T10：返回值 ∈ DAG（FC-7）----
    #[test]
    fn t10_output_in_dag() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let qc = prevote(&ctx, [0xBB; 32]);
        let r = fork_choice(&dag, None, &[qc], &ctx.set, &GENESIS_HASH);
        assert!(r.is_some_and(|h| dag.contains(&h)));
    }

    // ---- T11：Witness 不参与（API 无 witness 参数，结构保证）----
    #[test]
    fn t11_no_witness_parameter() {
        // 编译期保证：fork_choice 签名无 witness；本测试仅调用一次确认。
        let ctx = test_ctx(1, 100);
        let dag = build_dag(&[(0xAA, 0, vec![])]);
        assert_eq!(
            fork_choice(&dag, None, &[], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- T13：Finality Dominance：finalized 覆盖更深 QC（FC-12/FC-MF-6）----
    #[test]
    fn t13_finality_dominance() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
        ]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        let qc_c = prevote(&ctx, [0xCC; 32]);
        assert_eq!(
            fork_choice(
                &dag,
                Some(&[0xAA; 32]),
                &[qc_b, qc_c],
                &ctx.set,
                &GENESIS_HASH
            ),
            Some([0xAA; 32]),
            "finalized=A 绝对短路，B/C 更深 QC 不覆盖"
        );
    }

    // ---- T14：QC target ∉ DAG ⇒ 不作 anchor（FC-MF-7/FC-13）----
    #[test]
    fn t14_qc_target_not_in_dag() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![])]);
        let qc_unknown = prevote(&ctx, [0x99; 32]); // target ∉ DAG
        // verify_qc → UnknownTarget ⇒ 过滤 ⇒ 无 justified ⇒ root fallback
        assert_eq!(
            fork_choice(&dag, None, &[qc_unknown], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- T15：Anchor-scoped head（FC-MF-8/FC-14 核心 adversarial）----
    #[test]
    fn t15_anchor_scoped_frontier() {
        let ctx = test_ctx(3, 100);
        // A←B←C；B↘D；QC(B) ⇒ 仅 C/D/B 竞争；A 或无关 branch 不得入选
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
            (0xDD, 2, vec![0xBB]),
        ]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        let head = fork_choice(&dag, None, &[qc_b], &ctx.set, &GENESIS_HASH);
        assert!(
            head == Some([0xCC; 32]) || head == Some([0xDD; 32]),
            "head 必须在 C/D 中，实际 {head:?}"
        );
        assert_ne!(head, Some([0xAA; 32]), "A 不得入选（非 frontier）");
    }

    // ---- T16：empty DAG ⇒ None（O-3，不 panic）----
    #[test]
    fn t16_empty_dag() {
        let ctx = test_ctx(3, 100);
        let dag = Dag::new();
        assert_eq!(fork_choice(&dag, None, &[], &ctx.set, &GENESIS_HASH), None);
    }

    // ---- T17：QC validity / applicability boundary（FC-MF-9）----
    #[test]
    fn t17_qc_validity_vs_applicability() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        // (a) invalid QC（签名坏）→ ignored
        let mut bad = prevote(&ctx, [0xBB; 32]);
        bad.evidence[0].signature[0] ^= 0xff;
        // (b) valid QC + target ∉ DAG → ignored（verify_qc → UnknownTarget）
        let unknown = prevote(&ctx, [0x99; 32]);
        // (c) valid + Prevote + ∈DAG → justified
        let good = prevote(&ctx, [0xBB; 32]);
        // 只有 good 构成 anchor ⇒ head = frontier(BB) = {BB}
        assert_eq!(
            fork_choice(
                &dag,
                None,
                &[bad.clone(), unknown.clone(), good.clone()],
                &ctx.set,
                &GENESIS_HASH
            ),
            Some([0xBB; 32])
        );
        // invalid/unknown 单独 ⇒ 无 anchor ⇒ root fallback
        assert_eq!(
            fork_choice(&dag, None, &[bad, unknown], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- T18：Input-order determinism（FC-MF-10，攻击输入顺序）----
    #[test]
    fn t18_input_order_determinism() {
        let ctx = test_ctx(3, 100);
        // A├C └D；QC(C)、QC(D)；C ∥ D
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xCC, 1, vec![0xAA]),
            (0xDD, 1, vec![0xAA]),
        ]);
        let qc_c = prevote(&ctx, [0xCC; 32]);
        let qc_d = prevote(&ctx, [0xDD; 32]);
        let expected = [0xCC; 32]; // min hash（0xCC < 0xDD）
        let r1 = fork_choice(
            &dag,
            None,
            &[qc_c.clone(), qc_d.clone()],
            &ctx.set,
            &GENESIS_HASH,
        );
        let r2 = fork_choice(&dag, None, &[qc_d, qc_c], &ctx.set, &GENESIS_HASH);
        assert_eq!(r1, Some(expected), "[C,D] 顺序");
        assert_eq!(r2, Some(expected), "[D,C] 顺序，输入顺序不得影响结果");
    }

    // ---- A1：finality 绝对短路（更深 justified 也不覆盖）----
    #[test]
    fn a1_finality_absolute_short_circuit() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        assert_eq!(
            fork_choice(&dag, Some(&[0xAA; 32]), &[qc_b], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    // ---- A2：frontier 禁退化（subtree 外更高/更多 branch 不入选）----
    #[test]
    fn a2_frontier_no_height_or_count_degredation() {
        let ctx = test_ctx(3, 100);
        // A ← B ← C；无关分支 R0 ← R1 ← R2（更高 height、更多 blocks）
        let dag = build_dag(&[
            (0xAA, 0, vec![]),
            (0xBB, 1, vec![0xAA]),
            (0xCC, 2, vec![0xBB]),
            (0xEE, 0, vec![]),
            (0xEF, 1, vec![0xEE]),
            (0xF0, 2, vec![0xEF]),
        ]);
        let qc_b = prevote(&ctx, [0xBB; 32]);
        let head = fork_choice(&dag, None, &[qc_b], &ctx.set, &GENESIS_HASH);
        assert_eq!(head, Some([0xCC; 32]), "仅 anchor subtree 内 CC 入选");
    }

    // ---- A3：多 QC 过滤（无效不影响有效）----
    #[test]
    fn a3_invalid_qc_does_not_affect_valid() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        let mut bad = prevote(&ctx, [0xBB; 32]);
        bad.evidence[0].signature[0] ^= 0xff;
        let good = prevote(&ctx, [0xBB; 32]);
        assert_eq!(
            fork_choice(&dag, None, &[bad, good], &ctx.set, &GENESIS_HASH),
            Some([0xBB; 32])
        );
    }

    // ---- A4：空 prevote_qcs + 非空 DAG ⇒ root ----
    #[test]
    fn a4_empty_qcs_root_fallback() {
        let ctx = test_ctx(3, 100);
        let dag = build_dag(&[(0xAA, 0, vec![]), (0xBB, 1, vec![0xAA])]);
        assert_eq!(
            fork_choice(&dag, None, &[], &ctx.set, &GENESIS_HASH),
            Some([0xAA; 32])
        );
    }

    /// 从字节序列构造线性链 DAG（sorted unique，height=index ⇒ parent.height < child.height）。
    fn build_linear_dag(bytes: &[u8]) -> Dag {
        let mut sorted = bytes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut dag = Dag::new();
        for (i, &b) in sorted.iter().enumerate() {
            let parents = if i == 0 {
                vec![]
            } else {
                vec![[sorted[i - 1]; 32]]
            };
            dag.add_block(BlockReference {
                block_hash: [b; 32],
                height: i as u64,
                parents,
                proposer: ValidatorId::from_bytes([b; 32]),
            })
            .unwrap();
        }
        dag
    }

    // ---- T12 / A5：proptest 确定性 + ∈DAG ----
    proptest! {
        #[test]
        fn fc_deterministic_and_in_dag(
            blocks in prop::collection::vec(any::<u8>(), 0..8),
            finalized_present in any::<bool>(),
        ) {
            let ctx = test_ctx(3, 100);
            let dag = build_linear_dag(&blocks);
            let finalized: Option<[u8; 32]> = if finalized_present && !dag.is_empty() {
                Some(dag.tips()[0])  // 任取一个已知块
            } else {
                None
            };
            let r1 = fork_choice(&dag, finalized.as_ref(), &[], &ctx.set, &GENESIS_HASH);
            let r2 = fork_choice(&dag, finalized.as_ref(), &[], &ctx.set, &GENESIS_HASH);
            prop_assert_eq!(r1, r2, "确定性");
            if let Some(h) = r1 {
                prop_assert!(dag.contains(&h), "返回值 ∈ DAG");
            }
            if let Some(f) = finalized {
                prop_assert_eq!(r1, Some(f), "finality-first");
            }
        }
    }
}
