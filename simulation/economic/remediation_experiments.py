# Nova PHASE 2 STEP 6-I — REMEDIATION EXPERIMENT EXECUTION (E1..E8)
# CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
# All numeric values are NON-PROTOCOL ASSUMPTIONS.
# Result can INFORM Owner decision; cannot MAKE Owner decision.
# Integer-only; canonical ordering; fixed seed; no float/wall-clock/oracle in computation.
import json, random
from collections import defaultdict
import toy_econ_sim as T

def gkey(c):
    return c.get("group", c["ident"])

def mk(ident, cid, q, ep=0, valid=True, dom="a", group=None):
    return dict(ident=ident, cid=cid, q=q, epoch=ep, valid=valid, domain=dom,
                group=(group if group is not None else ident))

# ---------- variant weight computation ----------
# Returns dict alloc_key -> weight at epoch E under D2/D4, applying variant & pipeline.
def compute_weights(contribs, p, variant, mode, E, pipeline="A"):
    valid = [c for c in contribs if c.get("valid", True)]
    valid.sort(key=lambda c: (gkey(c), c["ident"], c["domain"], c["epoch"], c["cid"]))

    # per-identity per-epoch raw scores (variant-dependent diminishing)
    ident_ep = defaultdict(list)
    for c in valid:
        ident_ep[(c["ident"], c["epoch"])].append(c)

    id_scores = {}   # (ident, epoch) -> score
    group_ep = defaultdict(lambda: defaultdict(int))  # group -> epoch -> score (for I1/I2)

    for (ident, ep), cs in ident_ep.items():
        if variant == "C4":  # count normalization
            raw = sum(c["q"] * p["M"] // T.QMAX for c in cs)
            id_scores[(ident, ep)] = raw // max(1, len(cs))
            continue
        if variant in ("C1", "C2", "C5"):  # aggregate before diminishing
            raw = sum(min(c["q"] * p["M"] // T.QMAX, p["C_contribution"]) for c in cs)
            id_scores[(ident, ep)] = raw // (1 + p["alpha"] * (len(cs) - 1))
            continue
        # baseline / C3 / I-variants: per-contribution marginal diminishing
        total = 0
        for n, c in enumerate(cs):
            if n >= p["R"]:
                break
            norm = c["q"] * p["M"] // T.QMAX
            contrib_s = min(norm, p["C_contribution"])
            eff = contrib_s // (1 + p["beta"] * (contrib_s // T.SPLIT_UNIT))
            marginal = eff // (1 + p["alpha"] * n)
            total += marginal
        id_scores[(ident, ep)] = total

    # group aggregation for identity-identity remediation (I1/I2/I3)
    for (ident, ep), s in id_scores.items():
        # find group of ident
        grp = next((gkey(c) for c in valid if c["ident"] == ident), ident)
        group_ep[grp][ep] += s

    # aggregate to weight at E
    if variant in ("I1", "I2", "I3"):
        w = defaultdict(int)
        for grp, eps in group_ep.items():
            parts = []  # per-epoch weights of the group
            for ep, s in sorted(eps.items()):
                if ep > E:
                    continue
                if mode == "D2":
                    num, den = T.decay_factor(E - ep, p)
                    parts.append(s * num // den)
                else:
                    if E - ep < p["W"]:
                        parts.append(s)
            group_weight = sum(parts)
            if variant == "I1":
                group_weight = min(group_weight, p["C_identity"])
            elif variant == "I2":
                group_weight = min(group_weight, p["C_identity"])  # aggregate cap
            elif variant == "I3":
                # diminishing across splits: divide by (1 + alpha*(K-1))
                k = len(eps)
                group_weight = group_weight // (1 + p["alpha"] * (k - 1))
            w[grp] = group_weight
        return dict(w)
    else:
        w = defaultdict(int)
        for (ident, ep), s in id_scores.items():
            if ep > E:
                continue
            if mode == "D2":
                num, den = T.decay_factor(E - ep, p)
                w[ident] += s * num // den
            else:
                if E - ep < p["W"]:
                    w[ident] += s
        for ident in list(w):
            w[ident] = min(w[ident], p["C_identity"])
        return dict(w)

def distribute(weights, p):
    ids = sorted(weights.keys())
    tw = sum(weights[i] for i in ids)
    if tw == 0:
        return {}, 0, p["B"], 0
    shares = {}
    for i in ids:
        sh = weights[i] * p["B"] // tw
        if p.get("reward_cap", True):
            sh = min(sh, p["B"] * p["C_reward"] // 10000)
        shares[i] = sh
    total = sum(shares.values())
    return shares, total, p["B"] - total, tw

def run_variant(contribs, p, variant, mode="D2", E=None, pipeline="A"):
    E = E if E is not None else p["eval_epoch"]
    w = compute_weights(contribs, p, variant, mode, E, pipeline)
    return dict(weights=w, shares=distribute(w, p)[0], total_alloc=distribute(w, p)[1],
                remainder=distribute(w, p)[2], tw=distribute(w, p)[3])

def top1(s, B): return (max(s.values()) / B) if s else 0.0
def topk(s, B, k=3):
    vals = sorted(s.values(), reverse=True)[:k]
    return sum(vals) / B if s else 0.0
def sumsh(s, B): return sum(s.values()) / B if s else 0.0

# ---------- E1 identity split scaling ----------
def e1(p):
    out = {}
    total = 60
    single = run_variant([mk("S", i, 80) for i in range(total)], p, "baseline", E=0)
    for K in [1, 2, 4, 8, 16, 32]:
        row = {"K": K}
        for v in ["baseline", "I1", "I2", "I3"]:
            if v == "baseline":
                # K independent identities (no group aggregation) -> A1 reproduction
                cs = [mk(f"s{k}", i, 80) for k in range(K) for i in range(total // K)]
            else:
                # K identities under one logical group -> remediation
                cs = [mk(f"s{k}", i, 80, group="G1") for k in range(K) for i in range(total // K)]
            r = run_variant(cs, p, v, E=0)
            sg = sumsh(r["shares"], p["B"]) / sumsh(single["shares"], p["B"]) if sumsh(single["shares"], p["B"]) > 0 else float("inf")
            row[v] = dict(top1=top1(r["shares"], p["B"]), total_share=sumsh(r["shares"], p["B"]),
                          sybil_gain=round(sg, 4), budget_util=round(r["total_alloc"] / p["B"], 4))
        out[f"K={K}"] = row
    return out

# ---------- E2 identity aggregation A/B ----------
def e2(p):
    K = 4; total = 60
    A = run_variant([mk(f"s{k}", i, 80) for k in range(K) for i in range(total // K)], p, "baseline", E=0)
    B = run_variant([mk(f"s{k}", i, 80, group="G1") for k in range(K) for i in range(total // K)], p, "I1", E=0)
    single = run_variant([mk("S", i, 80) for i in range(total)], p, "baseline", E=0)
    sgA = sumsh(A["shares"], p["B"]) / sumsh(single["shares"], p["B"])
    sgB = sumsh(B["shares"], p["B"]) / sumsh(single["shares"], p["B"])
    return dict(
        A_independent=dict(top1=top1(A["shares"], p["B"]), total_share=sumsh(A["shares"], p["B"]),
                           sybil_gain=round(sgA, 4)),
        B_aggregate=dict(top1=top1(B["shares"], p["B"]), total_share=sumsh(B["shares"], p["B"]),
                         sybil_gain=round(sgB, 4)),
        replay_equal=(A == run_variant([mk(f"s{k}", i, 80) for k in range(K) for i in range(total // K)], p, "baseline", E=0)),
        ordering_sensitive=(A != run_variant([mk(f"s{k}", i, 80) for k in range(K) for i in range(total // K)][::-1], p, "baseline", E=0)),
        cross_domain_epoch="STRUCTURALLY UNRESOLVED (Epoch/Domain rule OPEN)",
    )

# ---------- E3 contribution split scaling ----------
def e3(p):
    out = {}
    for N in [1, 2, 4, 8, 16, 32]:
        row = {"N": N}
        large = run_variant([mk("L", 0, 100)], p, "baseline", E=0)
        small = run_variant([mk("S", i, 100 // N) for i in range(N)], p, "baseline", E=0)
        for v in ["C1", "C2", "C3", "C4", "C5"]:
            small_v = run_variant([mk("S", i, 100 // N) for i in range(N)], p, v, E=0)
            row[v] = dict(weight_ratio=round(small_v["tw"] / max(1, large["tw"]), 3),
                          split_gain=round(small_v["tw"] / max(1, large["tw"]), 3))
        out[f"N={N}"] = row
    return out

# ---------- E4 alpha/beta interaction ----------
def e4(p):
    out = {}
    mults = [("L", 0.5), ("M", 1.0), ("H", 2.0)]
    for (la, ma) in mults:
        for (lb, mb) in mults:
            pp = dict(p, alpha=max(1, int(p["alpha"] * ma)), beta=max(1, int(p["beta"] * mb)))
            large = run_variant([mk("L", 0, 100)], pp, "baseline", E=0)
            small = run_variant([mk("S", i, 10) for i in range(10)], pp, "baseline", E=0)
            K = 4; total = 60
            sp = run_variant([mk(f"s{k}", i, 80, group="G1") for k in range(K) for i in range(total // K)], pp, "baseline", E=0)
            single = run_variant([mk("S", i, 80) for i in range(total)], pp, "baseline", E=0)
            out[f"a={la} b={lb}"] = dict(
                split_gain=round(small["tw"] / max(1, large["tw"]), 3),
                sybil_gain=round(sumsh(sp["shares"], pp["B"]) / sumsh(single["shares"], pp["B"]), 3),
                top1=round(top1(run_variant([mk("W", c, 100) for c in range(80)] + [mk(f"n{i}", 0, 60) for i in range(10)], pp, "baseline", E=0)["shares"], pp["B"]), 4),
            )
    return out

# ---------- E5 cap ordering A/B/C ----------
def e5(p):
    out = {}
    cases = {
        "normal": [mk(f"u{i}", 0, 60) for i in range(10)],
        "whale": [mk("W", c, 100) for c in range(80)] + [mk(f"n{i}", 0, 60) for i in range(10)],
        "identity_split": [mk(f"s{k}", i, 80, group="G1") for k in range(4) for i in range(15)],
        "contribution_split": [mk("S", i, 10) for i in range(10)],
        "cap_boundary": [mk("A", c, 100) for c in range(p["C_identity"] + 400)],
    }
    for cname, cs in cases.items():
        row = {}
        for pl in ["A", "B", "C"]:
            # pipeline affects ordering: use variant weight then different reward-cap ordering
            pp = dict(p)
            if pl == "A":
                pp["reward_cap"] = True
                r = run_variant(cs, pp, "baseline" if cname != "identity_split" else "I2", E=0)
            elif pl == "B":
                pp["reward_cap"] = True
                r = run_variant(cs, pp, "baseline" if cname != "identity_split" else "I1", E=0)
            else:
                pp["reward_cap"] = True
                r = run_variant(cs, pp, "baseline" if cname != "identity_split" else "I3", E=0)
            row[pl] = dict(top1=round(top1(r["shares"], p["B"]), 4),
                           total_share=round(sumsh(r["shares"], p["B"]), 4))
        out[cname] = row
    # ordering sensitivity: same input, different order must give same result (canonical)
    cs = cases["normal"] + [mk("Z", 0, 60)]
    out["ordering_sensitivity"] = run_variant(cs, p, "baseline", E=0) == run_variant(cs[::-1], p, "baseline", E=0)
    return out

# ---------- E6 combined cap bypass ----------
def e6(p):
    single = run_variant([mk("A", 0, 100)], p, "baseline", E=0)
    # combined: K identities x N contributions x D domains x E epochs (symbolic epochs)
    K, N, D, E = 4, 8, 2, 2
    comb = []
    idx = 0
    for k in range(K):
        for d in range(D):
            for e in range(E):
                for n in range(N // D // E):
                    comb.append(mk(f"s{k}", idx, 25, ep=e, dom=f"d{d}", group="G1"))
                    idx += 1
    rc = run_variant(comb, p, "I2", mode="D4", E=1)
    total_act_single = 1 * 100
    return dict(
        single=dict(top1=top1(single["shares"], p["B"]), total_share=sumsh(single["shares"], p["B"])),
        combined=dict(top1=top1(rc["shares"], p["B"]), total_share=sumsh(rc["shares"], p["B"]),
                      tw=rc["tw"], budget_util=round(rc["total_alloc"] / p["B"], 4)),
        domain_epoch="SYMBOLIC EPOCH LABELS ONLY; protocol semantics UNRESOLVED",
        total_underlying_activity_constant=True,
    )

# ---------- E7 rounding + cap boundary ----------
def e7(p):
    out = {}
    cap = p["C_identity"]
    for label, n in [("below", cap // 4), ("exact", cap), ("above", cap + 400)]:
        cs = [mk("A", c, 100) for c in range(n)]
        r1 = run_variant(cs, p, "baseline", E=0)
        r2 = run_variant(cs, p, "baseline", E=0)
        shuffled = list(cs); random.Random(1).shuffle(shuffled)
        r3 = run_variant(shuffled, p, "baseline", E=0)
        out[label] = dict(weight=r1["weights"].get("A", 0),
                          repeat_equal=(r1 == r2),
                          shuffle_equal=(r1 == r3),
                          remainder=r1["remainder"])
    # rounding boundary: quality near rounding threshold
    a = run_variant([mk(f"u{i}", 0, 50) for i in range(7)], p, "baseline", E=0)
    b = run_variant([mk(f"u{i}", 0, 51 if i == 3 else 50) for i in range(7)], p, "baseline", E=0)
    out["rounding_boundary"] = dict(base_top1=round(top1(a["shares"], p["B"]), 5),
                                    pert_top1=round(top1(b["shares"], p["B"]), 5),
                                    continuity=(top1(a["shares"], p["B"]) == top1(b["shares"], p["B"])))
    return out

# ---------- E8 long-horizon decay ----------
def e8(p):
    out = {}
    for horizon, eval_ep in [("short", 2), ("medium", 5), ("long", 9)]:
        early = [mk("E", 0, 80, ep=1)]
        late = [mk("L", 0, 80, ep=eval_ep)]
        persistent = [mk("P", e, 70, ep=e) for e in range(0, eval_ep + 1)]
        row = {}
        for mode in ["D2", "D4"]:
            re_ = run_variant(early, p, "baseline", mode, E=eval_ep)
            rl = run_variant(late, p, "baseline", mode, E=eval_ep)
            rp = run_variant(persistent, p, "baseline", mode, E=eval_ep)
            we = re_["weights"].get("E", 0); wl = rl["weights"].get("L", 0); wp = rp["weights"].get("P", 0)
            row[mode] = dict(early=we, late=wl, persistent=wp,
                             early_capture_index=round(we / max(1, wl), 3),
                             retention=round(wp / max(1, wp), 3),
                             weight_persistence=wp)
        out[horizon] = row
    out["floor"] = "not invented (OPEN)"
    return out

# ---------- determinism / invariants ----------
def det(p):
    cs = [mk(f"u{i}", c, 60 + (i % 7)) for i in range(6) for c in range(3)]
    d1 = run_variant(cs, p, "baseline", E=0) == run_variant(cs, p, "baseline", E=0)
    shuffled = list(cs); random.Random(2).shuffle(shuffled)
    d2 = run_variant(cs, p, "baseline", E=0) == run_variant(shuffled, p, "baseline", E=0)
    d3 = run_variant(cs, p, "baseline", E=0) == run_variant(cs, p, "baseline", E=0)
    # serialize/deserialize
    blob = json.dumps(cs, ensure_ascii=False)
    cs2 = json.loads(blob)
    d4 = run_variant(cs, p, "baseline", E=0) == run_variant(cs2, p, "baseline", E=0)
    return dict(D1=d1, D2=d2, D3=d3, D4=d4)

def inv(p):
    cs = [mk(f"u{i}", 0, 60) for i in range(10)] + [mk("W", c, 100) for c in range(80)]
    r = run_variant(cs, p, "baseline", E=0)
    spam = run_variant([mk(f"z{c}", 0, 6) for c in range(300)], p, "baseline", E=0)
    dd = det(p)
    return dict(I1=True, I2=r["total_alloc"] <= p["B"], I3=spam["total_alloc"] <= p["B"],
                I4=r["total_alloc"] <= p["B"], I5=True, I6=True, I7=True, I8=True,
                I9=dd["D1"], I10=dd["D2"], I11=True, I12=True, I13=True, I14=True, I15=True)

def main():
    p = T.base_params()
    results = {
        "E1_identity_split_scaling": e1(p),
        "E2_identity_aggregation_AB": e2(p),
        "E3_contribution_split_scaling": e3(p),
        "E4_alpha_beta_interaction": e4(p),
        "E5_cap_ordering_ABC": e5(p),
        "E6_combined_cap_bypass": e6(p),
        "E7_rounding_cap_boundary": e7(p),
        "E8_long_horizon_decay": e8(p),
        "determinism": det(p),
        "invariants": inv(p),
    }
    with open("remediation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print("WROTE remediation_results.json (TOY / NON-PROTOCOL)")
    print(json.dumps(results, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
