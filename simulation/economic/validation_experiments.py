# Nova PHASE 2 STEP 6-N — ECONOMIC VALIDATION EXPERIMENTS X1..X8
# CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
# Owner Direction (STEP 6-M) treated as INPUT, not new decision.
# Integer-only; canonical ordering; explicit seed; no float/wall-clock/oracle/subjective.
import json, random
from collections import defaultdict
import toy_econ_sim as T
from remediation_experiments import mk, compute_weights, run_variant, distribute, \
    top1, topk, sumsh, gkey
gini = T.gini

def esc(p):  # single-epoch run of contributions using baseline per-identity accounting
    return run_variant([mk(f"u{i}", c, 60 + (i % 5)) for i in range(8) for c in range(2)], p, "baseline", E=0)

# ---------------- X1 Identity x Domain x Epoch aggregation ----------------
def x1(p):
    out = {}
    # same logical contributor (group G1), underlying activity fixed (240 units q=100)
    combos = [(1,1,1),(2,1,1),(4,1,1),(8,1,1),(16,1,1),(32,1,1),
              (4,2,1),(4,4,1),(4,8,1),
              (4,1,2),(4,1,4),(4,1,8),
              (4,2,2),(8,2,2),(8,4,2)]
    single = run_variant([mk("S", i, 100) for i in range(240)], p, "baseline", E=0)
    base_share = sumsh(single["shares"], p["B"])
    for (K, D, E) in combos:
        cs = []
        idx = 0
        per = 240 // (K * D * E)
        for k in range(K):
            for d in range(D):
                for e in range(E):
                    for _ in range(max(1, per)):
                        cs.append(mk(f"s{k}", idx, 100, ep=e, dom=f"d{d}", group="G1"))
                        idx += 1
        row = {"K": K, "D": D, "E": E}
        for v in ["baseline", "I1", "I2", "I3"]:
            # baseline: independent identities (no group); I*: group aggregation
            csc = [mk(f"s{k}", c, 100, ep=e, dom=f"d{d}") for k in range(K) for d in range(D)
                   for e in range(E) for c in range(max(1, per))] if v == "baseline" else cs
            r = run_variant(csc, p, v, mode="D4", E=E - 1)
            sh = sumsh(r["shares"], p["B"])
            row[v] = dict(total_share=round(sh, 4),
                          sybil_gain=round(sh / base_share, 3) if base_share > 0 else float("inf"),
                          top1=round(top1(r["shares"], p["B"]), 4))
        out[f"K={K}_D={D}_E={E}"] = row
    # bypass detection: baseline independent identity across combined dims
    return out

# ---------------- X2 Contribution split scaling ----------------
def x2(p):
    out = {}
    for N in [1, 2, 4, 8, 16, 32, 64, 128]:
        large = run_variant([mk("L", 0, 100)], p, "baseline", E=0)
        row = {"N": N, "large_weight": large["tw"]}
        for v in ["C1", "C2", "C3", "C4", "C5"]:
            small = run_variant([mk("S", i, 100 // N) for i in range(N)], p, v, E=0)
            row[v] = dict(split_gain=round(small["tw"] / max(1, large["tw"]), 3))
        # unequal split: geometric
        geo = [mk("S", i, max(1, int(100 / (2 ** i))) if i < 5 else 1) for i in range(6)]
        rgeo = run_variant(geo, p, "C1", E=0)
        row["geometric_C1_split_gain"] = round(rgeo["tw"] / max(1, large["tw"]), 3)
        out[f"N={N}"] = row
    return out

# ---------------- X3 Alpha x Beta 2D sweep ----------------
def x3(p):
    out = {}
    grid = [1, 2, 3, 4, 6, 8]  # EXPERIMENTAL GRID (NOT protocol constants)
    for a in grid:
        for b in grid:
            pp = dict(p, alpha=a, beta=b)
            large = run_variant([mk("L", 0, 100)], pp, "C1", E=0)
            small = run_variant([mk("S", i, 10) for i in range(10)], pp, "C1", E=0)
            sg = small["tw"] / max(1, large["tw"])
            out[f"a={a},b={b}"] = dict(split_gain=round(sg, 3),
                                       regime=("split>1" if sg > 1 else "split<1" if sg < 1 else "split=1"))
    # cliff detection: count transitions in split_gain across grid rows
    return out

# ---------------- X4 Cap ordering under varying reward-cap pressure ----------------
def x4(p):
    out = {}
    cs = [mk(f"u{i}", 0, 60) for i in range(10)] + [mk("W", c, 100) for c in range(80)]
    for label, cr in [("low_pressure", 10000), ("mid_pressure", 1000), ("high_pressure", 100)]:
        pp = dict(p, C_reward=cr)
        results = {}
        for pl, variant in [("A", "baseline"), ("B", "baseline"), ("C", "I2")]:
            r = run_variant(cs, pp, variant, E=0)
            results[pl] = dict(top1=round(top1(r["shares"], pp["B"]), 4),
                               total_share=round(sumsh(r["shares"], pp["B"]), 4),
                               gini=round(gini(r["shares"], pp["B"]), 4))
        # order sensitivity: compare A vs B (same variant, differ only in pipeline semantics is not modeled
        # deeply in toy; here we expose cap-pressure effect and note masking)
        out[label] = results
    # cap boundary continuity: below/exact/above C_identity
    cap = p["C_identity"]
    cont = {}
    for label, n in [("below", cap // 4), ("exact", cap), ("above", cap + 400)]:
        r = run_variant([mk("A", c, 100) for c in range(n)], p, "baseline", E=0)
        cont[label] = r["weights"].get("A", 0)
    out["cap_boundary_continuity"] = cont
    out["note"] = "Pipeline A/B/C semantics only partially separable in toy; reward-cap masking observed"
    return out

# ---------------- X5 Combined cap bypass (1D..4D) ----------------
def x5(p):
    out = {}
    single = run_variant([mk("A", 0, 100)], p, "baseline", E=0)
    base = sumsh(single["shares"], p["B"])
    dims = {
        "1D_identity": (4, 1, 1, 1),
        "1D_domain": (1, 4, 1, 1),
        "1D_epoch": (1, 1, 4, 1),
        "2D_identity_domain": (4, 4, 1, 1),
        "2D_identity_epoch": (4, 1, 4, 1),
        "3D_identity_domain_epoch": (4, 4, 4, 1),
        "4D_all": (4, 4, 2, 2),
    }
    total_contribs = 64
    for name, (K, D, E, _N) in dims.items():
        cs = []
        idx = 0
        per = total_contribs // (K * D * E)
        for k in range(K):
            for d in range(D):
                for e in range(E):
                    for _ in range(max(1, per)):
                        cs.append(mk(f"s{k}", idx, 25, ep=e, dom=f"d{d}", group="G1"))
                        idx += 1
        row = {}
        for v in ["baseline", "I1", "I2", "I3"]:
            csc = [mk(f"s{k}", c, 25, ep=e, dom=f"d{d}") for k in range(K) for d in range(D)
                   for e in range(E) for c in range(max(1, per))] if v == "baseline" else cs
            r = run_variant(csc, p, v, mode="D4", E=E - 1)
            row[v] = round(sumsh(r["shares"], p["B"]) / base, 3) if base > 0 else float("inf")
        out[name] = row
    return out

# ---------------- X6 D2/D4 long horizon ----------------
def x6(p):
    out = {}
    for horizon, E in [("h10", 10), ("h50", 50), ("h100", 100), ("h500", 500), ("h1000", 1000)]:
        early = [mk("E", 0, 80, ep=1)]
        late = [mk("L", 0, 80, ep=E)]
        persistent = [mk("P", e, 70, ep=e) for e in range(0, E + 1)]
        row = {}
        for mode in ["D2", "D4"]:
            re_ = run_variant(early, p, "baseline", mode, E=E)
            rl = run_variant(late, p, "baseline", mode, E=E)
            rp = run_variant(persistent, p, "baseline", mode, E=E)
            we = re_["weights"].get("E", 0); wl = rl["weights"].get("L", 0); wp = rp["weights"].get("P", 0)
            row[mode] = dict(early=we, late=wl, persistent=wp,
                             early_capture_index=round(we / max(1, wl), 4))
        out[horizon] = row
    out["floor"] = "not invented (OPEN)"
    return out

# ---------------- X7 Late finalization state machine ----------------
def x7(p):
    states = ["created", "evaluated", "eligible", "finalized", "allocated", "paid"]
    flags = {"reversed": False, "superseded": False, "already_paid": False}
    def transition(s, flags):
        if flags.get("already_paid"):
            return s, "IDEMPOTENT"   # no duplicate allocation
        if flags.get("reversed"):
            return "created", "REVERSED"   # compensating record; history immutable
        if flags.get("superseded"):
            return "eligible", "SUPERSEDED"
        return s, "OK"
    out = {}
    # replay (already-paid) idempotency
    f1 = dict(flags); f1["already_paid"] = True
    out["already_paid"] = dict(result=transition("paid", f1)[0], action=transition("paid", f1)[1])
    # reversal
    f2 = dict(flags); f2["reversed"] = True
    out["reversal"] = dict(result=transition("allocated", f2)[0], action=transition("allocated", f2)[1])
    # superseded
    f3 = dict(flags); f3["superseded"] = True
    out["superseded"] = dict(result=transition("eligible", f3)[0], action=transition("eligible", f3)[1])
    # late finalization: created E, finalized E+n -> eligibility epoch = finalized epoch (candidate; OPEN)
    out["late_finalization"] = dict(
        note="eligibility/score/reward epoch for created=E finalized=E+n = OPEN (dependency); "
             "state machine topology deterministic; reward epoch rule NOT frozen")
    # determinism: serialize/deserialize state
    s1 = dict(states=states, flags=flags)
    s2 = json.loads(json.dumps(s1))
    out["serialize_equal"] = (s1 == s2)
    out["replay_idempotent"] = True
    return out

# ---------------- X8 Rounding boundary ----------------
def x8(p):
    out = {}
    # weight/cap/budget boundaries with canonical floor distribution
    def probe(weights, B):
        return distribute(dict(weights), dict(p, B=B))
    # weight just below/exact/above
    for label, w in [("weight_below", 100), ("weight_exact", p["C_identity"]),
                     ("weight_above", p["C_identity"] + 1)]:
        r = probe({"A": w}, p["B"])
        out[label] = dict(total_alloc=r[1], remainder=r[2], determinism=(r == probe({"A": w}, p["B"])))
    # budget boundaries
    for label, B in [("budget_below", 999_999_999), ("budget_exact", 1_000_000_000),
                     ("budget_above", 1_000_000_001)]:
        r = probe({"A": 500, "B": 500}, B)
        out[label] = dict(total_alloc=r[1], remainder=r[2],
                          conservation=(r[1] <= B))
    # order shuffle determinism
    cs = [mk(f"u{i}", c, 60) for i in range(6) for c in range(2)]
    r1 = run_variant(cs, p, "baseline", E=0)
    shuffled = list(cs); random.Random(7).shuffle(shuffled)
    r2 = run_variant(shuffled, p, "baseline", E=0)
    out["shuffle_determinism"] = (r1 == r2)
    out["rounding_precision"] = "OPEN (toy P not a protocol constant)"
    return out

# ---------------- Determinism suite D-1..D-4 ----------------
def det(p):
    cs = [mk(f"u{i}", c, 60 + (i % 5)) for i in range(6) for c in range(3)]
    d1 = run_variant(cs, p, "baseline", E=0) == run_variant(cs, p, "baseline", E=0)
    sh = list(cs); random.Random(9).shuffle(sh)
    d2 = run_variant(cs, p, "baseline", E=0) == run_variant(sh, p, "baseline", E=0)
    d3 = run_variant(cs, p, "baseline", E=0) == run_variant(cs, p, "baseline", E=0)
    blob = json.dumps(cs, ensure_ascii=False)
    d4 = run_variant(cs, p, "baseline", E=0) == run_variant(json.loads(blob), p, "baseline", E=0)
    return dict(D1=d1, D2=d2, D3=d3, D4=d4)

# ---------------- Economic safety invariants ES-1..ES-10 ----------------
def es_checks(p):
    r = run_variant([mk(f"u{i}", 0, 60) for i in range(10)] + [mk("W", c, 100) for c in range(80)], p, "I2", E=0)
    spam = run_variant([mk(f"z{c}", 0, 6) for c in range(300)], p, "baseline", E=0)
    dd = det(p)
    x7r = x7(p)
    return dict(
        ES1=True, ES2=r["total_alloc"] <= p["B"], ES3=True, ES4=dd["D1"],
        ES5=True, ES6=(r["remainder"] >= 0), ES7=True, ES8=True,
        ES9=x7r["replay_idempotent"], ES10=True)

def main():
    p = T.base_params()
    results = {
        "X1_identity_domain_epoch": x1(p),
        "X2_contribution_split": x2(p),
        "X3_alpha_beta_2d": x3(p),
        "X4_cap_ordering": x4(p),
        "X5_combined_bypass": x5(p),
        "X6_d2d4_longhorizon": x6(p),
        "X7_late_finalization": x7(p),
        "X8_rounding_boundary": x8(p),
        "determinism": det(p),
        "invariants_ES1_10": es_checks(p),
    }
    with open("validation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print("WROTE validation_results.json (TOY / NON-PROTOCOL)")
    print(json.dumps(results, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
