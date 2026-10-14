# Nova PHASE 2 STEP 6-R4 — EXPERIMENT EXECUTION & VALIDATION (E-GLID-1/2/3, E-EPOCH-1,
#   C-Discrimination, Cap Stress, alpha/beta Sensitivity, Decay Stress,
#   Remainder Long Horizon, Citation Attack)
# CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
# NO PARAMETER FREEZE. Simulation Result != Protocol Proof. AI Recommendation != Owner Decision.
# Integer-only; canonical ordering; fixed seed; no float/wall-clock/oracle in computation
# (floats used ONLY as read-only metrics, matching prior toy experiments).
import json, random, hashlib
from collections import defaultdict, deque
import toy_econ_sim as T
from remediation_experiments import mk, gkey, compute_weights, run_variant, \
    distribute, top1, topk, sumsh

gini = T.gini


# ---------------- E-GLID-1 group splitting resistance ----------------
def e_glid_1(p):
    TOTAL = 60
    single = run_variant([mk("G", i, 100, group="G0") for i in range(TOTAL)], p, "I2", E=0)
    base = sumsh(single["shares"], p["B"])
    out, gains = {}, []
    for K in [1, 2, 4, 8, 16]:
        cs = []
        idx = 0
        bn = TOTAL // K
        extra = TOTAL % K
        for k in range(K):  # attacker splits total activity into K groups
            n = bn + (1 if k < extra else 0)
            for _ in range(n):
                cs.append(mk(f"s{k}", idx, 100, group=f"G{k}"))
                idx += 1
        r = run_variant(cs, p, "I2", E=0)
        sp = sumsh(r["shares"], p["B"])
        gain = round(sp / base, 4) if base > 0 else float("inf")
        gains.append(gain)
        out[f"K={K}"] = dict(baseline_reward=base, split_reward=round(sp, 4),
                             gain_ratio=gain, total_weight=r["tw"],
                             top1=round(top1(r["shares"], p["B"]), 4))
    return dict(cases=out, max_gain=max(gains), avg_gain=round(sum(gains) / len(gains), 4),
                scaling_curve=[dict(K=K, gain=g) for K, g in zip([1, 2, 4, 8, 16], gains)],
                gain_gt_1_detected=any(g > 1.0 for g in gains),
                note="per-group independent cap: reward scales ~linearly with attacker-created group count. "
                     "RECORDS ONLY; no G1/G2/G3 selection.")


# ---------------- E-GLID-2 canonical serialization / reconstruction ----------------
def canonical_serial(cs):
    members = sorted(cs, key=lambda c: (gkey(c), c["ident"], c["domain"], c["epoch"], c["cid"]))
    blob = "|".join(f"{m['ident']}:{m['cid']}:{m['domain']}:{m['epoch']}:{m['q']}" for m in members)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def e_glid_2(p):
    members = [mk(f"u{c}", c, 60, ep=c % 3, dom=f"d{c % 2}", group="G1") for c in range(40)]
    id_orig = canonical_serial(members)
    shuf = list(members); random.Random(7).shuffle(shuf)
    id_shuf = canonical_serial(shuf)
    id_replay = canonical_serial(members)
    other = [mk(f"v{c}", c, 60, ep=c % 3, dom=f"d{c % 2}", group="G2") for c in range(40)]
    id_other = canonical_serial(other)
    return dict(same_group_same_id=(id_orig == id_shuf),
                replay_same_id=(id_orig == id_replay),
                different_group_diff_id=(id_orig != id_other),
                determinism=(id_orig == id_shuf == id_replay),
                note="canonical serialization simulation (sha256 of canonical-sorted member set); "
                     "NOT a GLID protocol implementation")


# ---------------- E-GLID-3 cross-domain aggregation ----------------
def e_glid_3(p):
    base = run_variant([mk("G", i, 100, group="G1", dom="a") for i in range(60)], p, "I2", E=0)
    base_r = sumsh(base["shares"], p["B"])
    out = {}
    for D in [1, 2, 4]:
        cs = []
        idx = 0
        bn = 60 // D
        extra = 60 % D
        for d in range(D):
            n = bn + (1 if d < extra else 0)
            for _ in range(n):
                cs.append(mk("G", idx, 100, group="G1", dom=f"d{d}"))
                idx += 1
        r = run_variant(cs, p, "I2", E=0)
        sp = sumsh(r["shares"], p["B"])
        out[f"D={D}"] = dict(reward=round(sp, 6), gain_ratio=round(sp / base_r, 4) if base_r > 0 else float("inf"))
    gains = [v["gain_ratio"] for v in out.values() if v["gain_ratio"] != float("inf")]
    return dict(cases=out, amplification_detected=any(g > 1.0 for g in gains),
                note="cross-domain aggregation under I2 group aggregation; RECORDS ONLY")


# ---------------- E-EPOCH-1 created / finalized / late finalization ----------------
def dedup(cs):
    seen, out = set(), []
    for c in cs:
        k = (c["ident"], c["cid"], c["domain"], c["epoch"])
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def e_epoch_1(p):
    pp = dict(p, reward_cap=False)  # isolate duplicate effect from reward-share cap masking
    once = run_variant([mk("A", 0, 100, ep=0), mk("B", 0, 100, ep=0)], pp, "baseline", E=0)
    late = run_variant([mk("A", 0, 100, ep=0), mk("B", 0, 100, ep=0)], pp, "baseline", E=3)  # created ep0, late finalize
    twice_raw = run_variant([mk("A", 0, 100, ep=0), mk("A", 0, 100, ep=0), mk("B", 0, 100, ep=0)],
                            pp, "baseline", E=0)
    twice_dedup = run_variant(dedup([mk("A", 0, 100, ep=0), mk("A", 0, 100, ep=0), mk("B", 0, 100, ep=0)]),
                              pp, "baseline", E=0)
    share_once_a = once["shares"].get("A", 0)
    share_twice_a = twice_raw["shares"].get("A", 0)
    cons = (once["total_alloc"] + once["remainder"] == p["B"])
    return dict(
        created_finalized_same_epoch=dict(alloc=once["total_alloc"], share_A=share_once_a,
                                          share_B=once["shares"].get("B", 0)),
        late_finalized_eval3=dict(alloc=late["total_alloc"], note="counted at eval E=3; created ep0"),
        replay_idempotent_after_dedup=(twice_dedup == once),
        raw_engine_duplicate_inflates_share=(share_twice_a != share_once_a),
        duplicate_allocation_detected_raw=dict(share_A_once=share_once_a, share_A_twice_raw=share_twice_a),
        accounting_consistency=dict(conservation=cons, alloc_nonneg=(once["total_alloc"] >= 0)),
        note="epoch attribution/replay/accounting checks; reward_cap disabled to isolate duplicate effect; "
             "no E-a/E-b/E-c selection")


# ---------------- C-Discrimination (C1/C2/C5 vs C3/C4 controls) ----------------
def c_discrimination(p):
    sc = {
        "heavy_tail": ([mk("W", 0, 30)] + [mk(f"t{i}", 0, 2) for i in range(15)], [mk("W", 0, 60)]),
        "whale": ([mk(f"s{i}", 0, 100) for i in range(30)], [mk("W", c, 100) for c in range(30)]),
        "many_small": ([mk(f"m{i}", 0, 2) for i in range(50)], [mk("M", 0, 100)]),
        "burst": ([mk(f"b{i}", 0, 60) for i in range(20)], [mk("B", c, 60) for c in range(20)]),
        "long_horizon": ([mk(f"h{i}", 0, 100, ep=i % 4) for i in range(10)], [mk("L", 0, 100, ep=0)]),
    }
    out = {}
    for name, (sm, lg) in sc.items():
        row = {}
        for v in ["C1", "C2", "C5", "C3", "C4"]:
            rl = run_variant(lg, p, v, E=3)
            rs = run_variant(sm, p, v, E=3)
            g = round(rs["tw"] / max(1, rl["tw"]), 4)
            row[v] = dict(split_gain=g, top1=round(top1(rs["shares"], p["B"]), 4),
                          total_share=round(sumsh(rs["shares"], p["B"]), 4),
                          gini=round(gini(rs["shares"], p["B"]), 4))
        out[name] = row
    out["note"] = ("C1/C2/C5 are IDENTICAL in the current toy engine (single aggregate-before-diminishing branch); "
                   "C3/C4 differ. Discrimination among C1/C2/C5 requires Owner-defined variant semantics. No winner declared.")
    return out


# ---------------- Cap Stress (HYPOTHETICAL toy cap-ordering) ----------------
def cap_order_allocate(w, p, pipeline):
    ids = sorted(w.keys())
    tw = sum(w[i] for i in ids)
    cap_r = p["B"] * p["C_reward"] // 10000  # per-share reward cap (absolute)
    if tw == 0:
        return {}, 0, p["B"]
    shares = {}
    if pipeline == "A":  # normalize -> cap
        for i in ids:
            sh = w[i] * p["B"] // tw
            sh = min(sh, cap_r)
            shares[i] = sh
    elif pipeline == "B":  # cap (weight-level ceiling) -> normalize
        ceiling = cap_r * tw // p["B"]
        w2 = {i: min(w[i], ceiling) for i in ids}
        tw2 = sum(w2.values()) or 1
        for i in ids:
            shares[i] = w2[i] * p["B"] // tw2
    else:  # C: MaxScore before cap -> normalize -> cap
        w2 = {i: min(w[i], p["M"]) for i in ids}
        tw2 = sum(w2.values()) or 1
        for i in ids:
            sh = w2[i] * p["B"] // tw2
            sh = min(sh, cap_r)
            shares[i] = sh
    total = sum(shares.values())
    return shares, total, p["B"] - total


def cap_stress(p):
    scenarios = {
        "extreme_whale": [mk("W", c, 100) for c in range(200)] + [mk(f"n{i}", 0, 50) for i in range(20)],
        "many_contributors": [mk(f"u{i}", 0, 60) for i in range(80)],
        "multi_domain": [mk(f"u{i}", 0, 60, dom=f"d{i % 4}") for i in range(80)],
        "cross_epoch": [mk(f"u{i}", 0, 60, ep=i % 4) for i in range(80)],
    }
    out = {}
    for name, cs in scenarios.items():
        w = compute_weights(cs, p, "baseline", "D2", E=3)
        row = {}
        for pl in ["A", "B", "C"]:
            sh, tot, rem = cap_order_allocate(w, p, pl)
            row[pl] = dict(top1=round(top1(sh, p["B"]), 4), topk=round(topk(sh, p["B"]), 4),
                           total_share=round(sumsh(sh, p["B"]), 4),
                           gini=round(gini(sh, p["B"]), 4),
                           conservation=(tot + rem == p["B"]))
        out[name] = row
    out["note"] = ("HYPOTHETICAL toy cap-ordering semantics (A=normalize->cap, B=cap->normalize via weight ceiling, "
                   "C=MaxScore-before-cap); engine pipelines otherwise unmodeled (Q4 masking). No cap ordering frozen.")
    return out


# ---------------- alpha x beta sensitivity ----------------
def ab_sensitivity(p):
    out = {}
    for a in [1, 2, 3, 4, 5]:
        for b in [1, 2, 3, 4, 5]:
            pp = dict(p, alpha=a, beta=b)
            large = run_variant([mk("L", 0, 100)], pp, "C1", E=0)
            small = run_variant([mk("S", i, 10) for i in range(10)], pp, "C1", E=0)
            split_gain = round(small["tw"] / max(1, large["tw"]), 4)
            mix = run_variant([mk("W", c, 100) for c in range(20)] + [mk(f"n{i}", 0, 40) for i in range(20)],
                              pp, "C1", E=0)
            pers = run_variant([mk("P", e, 60, ep=e) for e in range(5)], pp, "C1", mode="D2", E=4)
            w_p = pers["weights"].get("P", 0)
            pers_early = run_variant([mk("P", 0, 60, ep=0)], pp, "C1", mode="D2", E=4)
            w_early = pers_early["weights"].get("P", 0)
            retention = round(w_p / max(1, w_early), 4) if w_early > 0 else None
            out[f"a={a},b={b}"] = dict(split_gain=split_gain,
                                       gini=round(gini(mix["shares"], pp["B"]), 4),
                                       top1=round(top1(mix["shares"], pp["B"]), 4),
                                       total_share=round(sumsh(mix["shares"], pp["B"]), 4),
                                       retention=retention)
    return dict(grid=out, note="2D alpha x beta sweep under C1; direction only; NO final parameters, NO freeze")


# ---------------- Decay Stress (D2 vs D4) ----------------
def decay_stress(p):
    out = {}
    for mode in ["D2", "D4"]:
        early = run_variant([mk("E", 0, 80, ep=1)], p, "baseline", mode, E=9)
        persistent = run_variant([mk("P", e, 70, ep=e) for e in range(0, 10)], p, "baseline", mode, E=9)
        late = run_variant([mk("L", 0, 80, ep=9)], p, "baseline", mode, E=9)
        b_in = run_variant([mk("B", 0, 80, ep=8)], p, "baseline", mode, E=9)
        b_out = run_variant([mk("B", 0, 80, ep=10)], p, "baseline", mode, E=9)
        latefin = run_variant([mk("A", 0, 80, ep=0)], p, "baseline", mode, E=9)
        out[mode] = dict(
            early_weight=early["weights"].get("E", 0),
            persistent_weight=persistent["weights"].get("P", 0),
            late_weight=late["weights"].get("L", 0),
            boundary_inside_weight=b_in["weights"].get("B", 0),
            boundary_outside_weight=b_out["weights"].get("B", 0),
            late_finalized_weight=latefin["weights"].get("A", 0),
            floor_effect="floor NOT invented; early weights can decay toward 0 at long horizon",
            boundary_gaming_flag=(b_in["weights"].get("B", 0) > 0 and b_out["weights"].get("B", 0) == 0),
        )
    out["note"] = "records only; no D2/D4 selection; floor/duration OPEN"
    return out


# ---------------- Remainder Long Horizon (toy integer accounting) ----------------
def remainder_long_horizon(p):
    out = {}
    for H in [100, 1000, 10000, 100000]:
        row = {}
        for pol in ["R-a", "R-b", "R-c"]:
            budget = 0; pool = 0; alloc_total = 0; starved = 0
            for e in range(H):
                budget += 1_000_000  # toy fixed per-epoch inflow (NON-PROTOCOL)
                alloc = budget * 90 // 100
                rem = budget - alloc
                if alloc == 0:
                    starved += 1
                alloc_total += alloc
                if pol == "R-a":
                    budget = rem  # carry forward remainder into next epoch budget
                elif pol == "R-b":
                    pool += rem; budget = 0  # remainder retained in pool, not reused
                else:  # R-c pro-rata redistribution (toy: immediate full reuse)
                    alloc_total += rem
                    rem = 0; budget = 0
            overflow = ((budget + pool) > 1_000_000_000)
            row[pol] = dict(final_budget=budget, pool=pool, alloc_total=alloc_total,
                            starved_epochs=starved, overflow_risk=overflow,
                            starvation_detected=(starved > 0))
        out[f"H={H}"] = row
    out["note"] = ("toy integer accounting model (fixed per-epoch inflow, 90% alloc); NOT the engine pipeline; "
                   "R-a/R-b accumulate reserve -> long-horizon overflow risk (cf. Q8 saturation). No remainder policy selected.")
    return out


# ---------------- Citation Attack (N1/N2/N3) ----------------
def has_cycle_back(edges, src, dst):
    adj = defaultdict(list)
    for s, ds in edges.items():
        for d in ds:
            adj[s].append(d)
    seen = {dst}; q = deque([dst])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v == src:
                return True
            if v not in seen:
                seen.add(v); q.append(v)
    return False


def citation_attack(p):
    base = {"A": 100, "B": 80, "C": 60}
    CW = 20  # toy citation weight (NON-PROTOCOL)
    attacks = {
        "self": {"A": ["A"]},
        "circular": {"A": ["B"], "B": ["A"]},
        "farming": {"A": ["B", "C"], "B": ["A", "C"], "C": ["A", "B"]},
        "amplification": {"A": ["B"], "B": ["C"], "C": ["A"]},
    }
    out = {}
    for name, edges in attacks.items():
        row = {}
        for N in ["N1", "N2", "N3"]:
            scores = dict(base)
            if N == "N2":
                for src, dsts in edges.items():
                    for d in dsts:
                        scores[d] = scores.get(d, 0) + CW
            elif N == "N3":
                for src, dsts in edges.items():
                    for d in dsts:
                        if src == d:  # self-citation rejected
                            continue
                        if has_cycle_back(edges, src, d):  # any citation lying on a cycle rejected
                            continue
                        scores[d] = scores.get(d, 0) + CW
            n1_total = sum(base.values())
            row[N] = dict(total_score=sum(scores.values()),
                          amplification=round(sum(scores.values()) / n1_total, 4))
        out[name] = row
    return dict(cases=out,
                note="integer graph toy; no oracle; N1 no effect, N2 accepts all citations, "
                     "N3 verified-only rejects self/cyclic. No citation model selected.")


# ---------------- main ----------------
def main():
    p = T.base_params()
    results = {
        "E_GLID_1_group_splitting": e_glid_1(p),
        "E_GLID_2_canonical_serialization": e_glid_2(p),
        "E_GLID_3_cross_domain": e_glid_3(p),
        "E_EPOCH_1": e_epoch_1(p),
        "C_discrimination": c_discrimination(p),
        "Cap_Stress": cap_stress(p),
        "ab_sensitivity": ab_sensitivity(p),
        "Decay_Stress": decay_stress(p),
        "Remainder_Long_Horizon": remainder_long_horizon(p),
        "Citation_Attack": citation_attack(p),
    }
    with open("step6r4_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    # summary print
    print("== STEP 6-R4 EXECUTION SUMMARY (TOY / NON-PROTOCOL) ==")
    print("GLID-1 gain_gt_1_detected =", results["E_GLID_1_group_splitting"]["gain_gt_1_detected"],
          "max_gain =", results["E_GLID_1_group_splitting"]["max_gain"])
    print("GLID-2 determinism =", results["E_GLID_2_canonical_serialization"]["determinism"])
    print("GLID-3 amplification_detected =", results["E_GLID_3_cross_domain"]["amplification_detected"])
    print("EPOCH-1 replay_idempotent_after_dedup =", results["E_EPOCH_1"]["replay_idempotent_after_dedup"])
    print("C-discrimination note =", results["C_discrimination"]["note"])
    print("Cap_Stress note =", results["Cap_Stress"]["note"])
    print("ab_sensitivity note =", results["ab_sensitivity"]["note"])
    print("Decay_Stress note =", results["Decay_Stress"]["note"])
    print("Remainder note =", results["Remainder_Long_Horizon"]["note"])
    print("Citation note =", results["Citation_Attack"]["note"])
    print("results written to step6r4_results.json")


if __name__ == "__main__":
    main()
