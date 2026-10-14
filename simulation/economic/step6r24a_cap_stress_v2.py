# Nova PHASE 2 STEP 6-R24-A — CAP STRESS v2 VALIDATION
# CLASSIFICATION: TOY MODEL / NON-PROTOCOL / VALIDATION ONLY
# Goal: discriminate SR-P3 Cap Ordering: Option A (score->cap->rounding) vs Option B (score->rounding->cap)
# NO PARAMETER FREEZE. Simulation Result != Protocol Proof. AI Recommendation != Owner Decision.
# Integer-only; canonical ordering; fixed seed; no float/wall-clock/oracle in computation.
import json, random
import toy_econ_sim as T
from remediation_experiments import mk, compute_weights, run_variant, top1, topk, sumsh

gini = T.gini


def allocate_v2(w, p, option):
    """Toy cap-ordering allocation under SR-P3.
    A: score -> cap -> rounding   (cap weights first via share-equivalent ceiling, then floor-allocate)
    B: score -> rounding -> cap   (floor-allocate first, then cap each share)
    Returns (shares, total, remainder). Conservation: total + remainder == B.
    """
    ids = sorted(w.keys())
    tw = sum(w[i] for i in ids)
    cap_r = p["B"] * p["C_reward"] // 10000  # per-share reward cap (absolute)
    if tw == 0:
        return {}, 0, p["B"]
    shares = {}
    if option == "A":
        ceiling = cap_r * tw // p["B"] if p["B"] > 0 else 0  # weight-level cap equiv.
        w2 = {i: min(w[i], ceiling) for i in ids}
        tw2 = sum(w2.values()) or 1
        for i in ids:
            shares[i] = w2[i] * p["B"] // tw2
    else:  # B
        for i in ids:
            sh = w[i] * p["B"] // tw   # rounding (floor) first
            sh = min(sh, cap_r)        # then cap
            shares[i] = sh
    total = sum(shares.values())
    return shares, total, p["B"] - total


def run_scenario(name, cs, p, variant="baseline", mode="D2", E=3):
    w = compute_weights(cs, p, variant, mode, E)
    out = {}
    for opt in ["A", "B"]:
        sh, tot, rem = allocate_v2(w, p, opt)
        out[opt] = dict(top1=round(top1(sh, p["B"]), 4), topk=round(topk(sh, p["B"]), 4),
                        total_share=round(sumsh(sh, p["B"]), 4),
                        gini=round(gini(sh, p["B"]), 4),
                        remainder=rem,
                        conservation=(tot + rem == p["B"]),
                        replay=(allocate_v2(w, p, opt) == (sh, tot, rem)))
    out["weights_total"] = sum(w.values())
    return out


def main():
    p = T.base_params()
    scenarios = {}

    # 1 Extreme Whale: single dominant contributor
    scenarios["extreme_whale"] = run_scenario(
        "extreme_whale", [mk("W", c, 100) for c in range(200)] + [mk(f"n{i}", 0, 50) for i in range(20)], p)

    # 2 Identity Split: one entity's activity as one identity vs K identities (I2 group = not split)
    single_id = run_scenario("identity_split_unified",
                             [mk("S", c, 100, group="G1") for c in range(60)], p, variant="I2", E=0)
    split_id = run_scenario("identity_split_K4",
                            [mk(f"s{k}", i, 100, group=f"G{k}") for k in range(4) for i in range(15)], p,
                            variant="I2", E=0)
    scenarios["identity_split"] = dict(unified=single_id, split_K4=split_id)
    for opt in ["A", "B"]:
        base_sh = sumsh(single_id[opt], p["B"])
        sp_sh = sumsh(split_id[opt], p["B"])
        scenarios["identity_split"][f"split_gain_{opt}"] = round(sp_sh / base_sh, 4) if base_sh > 0 else float("inf")

    # 3 Contribution Split: one big contribution vs N split (aggregate-first C1 resistance)
    big = run_scenario("contrib_split_big", [mk("L", 0, 100)], p, variant="C1", E=0)
    small = run_scenario("contrib_split_N", [mk("S", i, 100 // 8) for i in range(8)], p, variant="C1", E=0)
    scenarios["contribution_split"] = dict(big=big, small_N8=small)
    for opt in ["A", "B"]:
        tw_big = big["weights_total"]
        tw_small = small["weights_total"]
        scenarios["contribution_split"][f"split_gain_{opt}"] = round(tw_small / max(1, tw_big), 4)

    # 4 Many Small Contributors
    scenarios["many_small"] = run_scenario("many_small",
                                           [mk(f"u{i}", 0, 60) for i in range(80)], p, E=3)

    # 5 Decay Interaction: early vs late vs persistent (D2)
    scenarios["decay_early"] = run_scenario("decay_early", [mk("E", 0, 100, ep=0)], p, mode="D2", E=9)
    scenarios["decay_late"] = run_scenario("decay_late", [mk("L", 0, 100, ep=9)], p, mode="D2", E=9)
    scenarios["decay_persistent"] = run_scenario("decay_persistent",
                                                 [mk("P", e, 80, ep=e) for e in range(10)], p, mode="D2", E=9)

    # 6 Cap Boundary: weight just below/above cap-activation threshold
    #   scale many contributors so per-identity weight sits near the share-cap ceiling
    below = run_scenario("cap_boundary_below",
                         [mk(f"b{i}", 0, 2) for i in range(5)] + [mk("W", 0, 100)],
                         dict(p, reward_cap=True), E=0)
    above = run_scenario("cap_boundary_above",
                         [mk(f"b{i}", 0, 2) for i in range(5)] + [mk("W", c, 100) for c in range(40)],
                         dict(p, reward_cap=True), E=0)
    scenarios["cap_boundary"] = dict(below=below, above=above)

    results = dict(scenarios=scenarios,
                   note="TOY cap-ordering semantics (A=cap-then-round, B=round-then-cap); "
                        "distinguishes SR-P3 under cap-activated stress; NO parameter freeze; "
                        "no cap ordering selected.")
    with open("step6r24a_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("== STEP 6-R24-A CAP STRESS v2 SUMMARY (TOY / NON-PROTOCOL) ==")
    for sc in ["extreme_whale", "many_small"]:
        r = scenarios[sc]
        print(f"{sc}: A(top1={r['A']['top1']},consv={r['A']['conservation']}) "
              f"B(top1={r['B']['top1']},consv={r['B']['conservation']}) "
              f"diff_top1={round(abs(r['A']['top1']-r['B']['top1']),4)}")
    print("identity_split split_gain:", {o: scenarios['identity_split'][f'split_gain_{o}'] for o in ['A', 'B']})
    print("contribution_split split_gain:", {o: scenarios['contribution_split'][f'split_gain_{o}'] for o in ['A', 'B']})
    for sc in ["decay_early", "decay_late", "decay_persistent"]:
        r = scenarios[sc]
        print(f"{sc}: A(top1={r['A']['top1']}) B(top1={r['B']['top1']}) diff={round(abs(r['A']['top1']-r['B']['top1']),4)}")
    print("cap_boundary below A top1:", scenarios['cap_boundary']['below']['A']['top1'],
          "above A top1:", scenarios['cap_boundary']['above']['A']['top1'])
    print("results written to step6r24a_results.json")


if __name__ == "__main__":
    main()
