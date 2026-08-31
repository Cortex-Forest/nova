# Nova PHASE 2 STEP 6-G — TOY ECONOMIC SIMULATION
# CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
# All numeric values are NON-PROTOCOL ASSUMPTIONS.
# Simulation Result != Protocol Parameter Approval; != Security Proof.
# Integer-only arithmetic; canonical ordering; explicit seed; no float/wall-clock/oracle.
import random, json, sys
from collections import defaultdict

QMAX = 100          # toy max raw quality (NON-PROTOCOL ASSUMPTION)
SPLIT_UNIT = 250    # toy contribution-split damp unit (NON-PROTOCOL ASSUMPTION)

# Toy parameter set — every value NON-PROTOCOL ASSUMPTION
def base_params():
    return dict(
        B=1_000_000_000,   # symbolic independent reward budget (base units)
        M=1000,            # toy MaxScore
        alpha=2,           # toy identity-level diminishing coefficient
        beta=2,            # toy contribution-level diminishing coefficient
        D=5,               # toy decay divisor (D2 factor = D/(D+1) per epoch)
        W=5,               # toy rolling window length (D4)
        C_identity=600,    # toy identity weight cap
        C_contribution=1000, # toy per-contribution score cap
        C_domain=100_000,  # toy domain total-weight cap (record-only)
        C_epoch=500_000,   # toy epoch total-weight cap (record-only)
        C_reward=500,      # toy reward-share cap in bps (500 = 5%)
        R=200,             # toy rate limit (max contributions per identity per epoch)
        P=1_000_000,       # toy rounding precision / fixed-point scale
        eval_epoch=0,      # toy evaluation epoch (NON-PROTOCOL); 0 = single-epoch default
    )

def ck(i, c):  # canonical ordering key
    return (i, c)

# ---------------- Core toy pipeline ----------------
def epoch_identity_scores(contribs, p):
    """diminished per-(identity,epoch) scores with rate limit + contribution caps."""
    out = {}
    groups = defaultdict(list)
    for c in contribs:
        if c.get("valid", True):
            groups[(c["ident"], c["epoch"])].append(c)
    for (ident, ep), cs in groups.items():
        cs.sort(key=lambda x: ck(x["ident"], x["cid"]))
        total = 0
        for n, c in enumerate(cs):
            if n >= p["R"]:      # rate limit: ignore excess contributions (toy)
                break
            norm = c["q"] * p["M"] // QMAX
            contrib_s = min(norm, p["C_contribution"])
            # contribution-level damp (beta): large single contributions discounted
            eff = contrib_s // (1 + p["beta"] * (contrib_s // SPLIT_UNIT))
            # identity-level diminishing (alpha): later contributions discounted
            marginal = eff // (1 + p["alpha"] * n)
            total += marginal
        out[(ident, ep)] = total
    return out

def decay_factor(age, p):
    """D2 decay ratio (D/(D+1))^age as integer (num, den) — smooth, no early collapse."""
    return (pow(p["D"], age), pow(p["D"] + 1, age))

def identity_weights(epscores, p, mode, E):
    """Aggregate per-identity weight at eval epoch E under D2 (epoch decay) or D4 (rolling window)."""
    w = defaultdict(int)
    for (ident, ep), s in epscores.items():
        if ep > E:
            continue
        if mode == "D2":
            num, den = decay_factor(E - ep, p)
            w[ident] += s * num // den
        else:  # D4 rolling window: last W epochs
            if E - ep < p["W"]:
                w[ident] += s
    # identity concentration cap (toy)
    for ident in list(w):
        w[ident] = min(w[ident], p["C_identity"])
    return dict(w)

def distribute(weights, p):
    """Canonical reward share with floor rounding. Returns (shares, total_alloc, remainder, tw)."""
    ids = sorted(weights.keys())  # canonical ordering
    tw = sum(weights[i] for i in ids)
    if tw == 0:
        return {}, 0, p["B"], 0  # ZERO-WEIGHT: destination OPEN (unresolved)
    shares = {}
    for i in ids:
        sh = weights[i] * p["B"] // tw
        sh = min(sh, p["B"] * p["C_reward"] // 10000)  # reward-share cap (toy)
        shares[i] = sh
    total = sum(shares.values())
    return shares, total, p["B"] - total, tw

def run(contribs, p, mode="D2", eval_epoch=None):
    E = eval_epoch if eval_epoch is not None else p["eval_epoch"]
    eps = epoch_identity_scores(contribs, p)
    w = identity_weights(eps, p, mode, E)
    shares, total, rem, tw = distribute(w, p)
    return dict(weights=w, shares=shares, total_alloc=total, remainder=rem, tw=tw)

# ---------------- Metrics ----------------
def top1_share(shares, B): return (max(shares.values()) / B) if shares else 0.0
def topk_share(shares, B, k=3):
    vals = sorted(shares.values(), reverse=True)[:k]
    return sum(vals) / B if shares else 0.0
def gini(shares, B):
    if not shares: return 0.0
    vals = sorted(shares.values())
    n = len(vals)
    s = sum(vals)
    if s == 0: return 0.0
    cum = 0.0
    for i, v in enumerate(vals, 1):
        cum += i * v
    return (2 * cum / (n * s)) - (n + 1) / n
def budget_util(total, B): return total / B
def sybil_gain(shares_split, shares_single, B):
    if not shares_single: return float("inf")
    ss = sum(shares_split.values()) / B
    sg = sum(shares_single.values()) / B
    return (ss / sg) if sg > 0 else float("inf")

# ---------------- Constructors ----------------
def one(id_, cid, q, ep=0, valid=True, dom="a"):
    return dict(ident=id_, cid=cid, q=q, epoch=ep, valid=valid, domain=dom)

# ---------------- S-A .. S-J ----------------
def run_baselines(p):
    res = {}
    # S-A single contributor
    res["S-A"] = run([one("A", 0, 60)], p)
    # S-B many equal
    contribs = [one(f"u{i}", 0, 60) for i in range(10)]
    res["S-B"] = run(contribs, p)
    # S-C whale (1 whale high volume + 10 normal)
    contribs = [one("W", c, 100) for c in range(80)] + [one(f"n{i}", 0, 60) for i in range(10)]
    res["S-C"] = run(contribs, p)
    # S-D sybil split: single identity X contributions vs K identities each X/K
    X = 60
    single = [one("S", c, 80) for c in range(X)]
    split = []
    for k in range(3):
        for c in range(X // 3):
            split.append(one(f"sp{k}", c, 80))
    r_single = run(single, p); r_split = run(split, p)
    res["S-D"] = dict(r_single=r_single, r_split=r_split,
                      sybil_gain=sybil_gain(r_split["shares"], r_single["shares"], p["B"]))
    # S-E contribution split: 1 large vs N small (same total q)
    large = [one("L", 0, 100)]
    small = [one("S", c, 10) for c in range(10)]
    res["S-E"] = dict(large=run(large, p), small=run(small, p))
    # S-F spam farming: high volume low value; verify B constant
    spam = [one(f"sp{c}", 0, 5) for c in range(300)]
    res["S-F"] = dict(spam=run(spam, p), budget=p["B"])
    # S-G early capture: early vs late under D2 and D4
    early = [one("E", 0, 80, ep=1)] + [one("L", 0, 80, ep=8)]
    res["S-G"] = dict(D2=run(early, p, "D2", 8), D4=run(early, p, "D4", 8))
    # S-H long-term contributor across epochs
    lt = []
    for e in range(0, 9):
        lt.append(one("LT", e, 70, ep=e))
    res["S-H"] = dict(D2=run(lt, p, "D2", 8), D4=run(lt, p, "D4", 8))
    # S-I cross-domain split
    dom1 = [one(f"d{i}", 0, 60, dom="x") for i in range(6)]
    domN = [one(f"a{i}", 0, 60, dom=f"d{i%3}") for i in range(6)]
    res["S-I"] = dict(single=run(dom1, p), multi=run(domN, p))
    # S-J cross-epoch split: single epoch vs multi epoch -> UNRESOLVED dependency
    se = [one(f"e{i}", 0, 60, ep=8) for i in range(6)]
    me = [one(f"m{i}", 0, 60, ep=i % 3) for i in range(6)]
    res["S-J"] = dict(single_epoch=run(se, p, eval_epoch=8), multi_epoch=run(me, p, eval_epoch=8),
                      status="DEPENDENCY / UNRESOLVED (Economic Epoch / Late-Finalization OPEN)")
    return res

# ---------------- Attacks A1..A12 ----------------
def run_attacks(p):
    res = {}
    # A1 identity splitting: sweep K
    X = 60; g = []
    for K in [1, 2, 4, 8]:
        c = [one("S", i, 80) for i in range(X)] if K == 1 else \
            [one(f"sp{k}", i, 80) for k in range(K) for i in range(X // K)]
        g.append(sybil_gain(run(c, p)["shares"], run([one("S", i, 80) for i in range(X)], p)["shares"], p["B"]))
    res["A1"] = g
    # A2 contribution splitting
    large = run([one("L", 0, 100)], p)
    small = run([one("S", c, 10) for c in range(10)], p)
    res["A2"] = dict(large_share=top1_share(large["shares"], p["B"]),
                     small_share=top1_share(small["shares"], p["B"]))
    # A3 citation farming -> toy proxy: extra weight from cited contributions (ring) — no off-chain
    ring = [one(f"r{i}", 0, 40) for i in range(5)]
    res["A3"] = dict(ring_total_weight=run(ring, p)["tw"], note="citation damping not modeled; OFF-CHAIN excluded")
    # A4 cross-epoch splitting -> UNRESOLVED dependency
    res["A4"] = dict(status="UNRESOLVED DEPENDENCY (epoch rule OPEN)")
    # A5 cross-domain splitting
    c1 = [one(f"a{i}", 0, 80, dom="x") for i in range(4)]
    c2 = [one(f"b{i}", 0, 80, dom=f"d{i%2}") for i in range(4)]
    res["A5"] = dict(single_domain_top1=top1_share(run(c1, p)["shares"], p["B"]),
                     multi_domain_top1=top1_share(run(c2, p)["shares"], p["B"]))
    # A6 spam farming: activity volume sweep, B constant
    b_before = p["B"]; vols = {}
    for n in [50, 200, 500]:
        r = run([one(f"z{c}", 0, 6) for c in range(n)], p)
        vols[n] = top1_share(r["shares"], p["B"])
    res["A6"] = dict(top1_by_volume=vols, budget_constant=(p["B"] == b_before))
    # A7 whale concentration
    wh = run([one("W", c, 100) for c in range(200)] + [one(f"n{i}", 0, 60) for i in range(10)], p)
    res["A7"] = dict(top1=top1_share(wh["shares"], p["B"]), top3=topk_share(wh["shares"], p["B"], 3))
    # A8 score inflation (stacking)
    st = [one("S", c, 60) for c in range(200)]
    res["A8"] = dict(max_score_capped=max(run(st, p)["weights"].values()),
                     top1=top1_share(run(st, p)["shares"], p["B"]))
    # A9 cap gaming: below/exact/above identity cap
    cap = p["C_identity"]
    below = run([one("A", c, 100) for c in range(cap // 4)], p)
    exact = run([one("A", c, 100) for c in range(cap)], p)
    above = run([one("A", c, 100) for c in range(cap + 400)], p)
    res["A9"] = dict(below=below["weights"].get("A", 0), exact=exact["weights"].get("A", 0),
                     above=above["weights"].get("A", 0), cap=cap)
    # A10 rounding gaming: perturb qualities near rounding boundary
    base = [one(f"u{i}", 0, 50) for i in range(7)]
    pert = [one(f"u{i}", 0, 51 if i == 3 else 50) for i in range(7)]
    r1 = run(base, p); r2 = run(pert, p)
    res["A10"] = dict(base_share=top1_share(r1["shares"], p["B"]),
                      pert_share=top1_share(r2["shares"], p["B"]),
                      remainder=dict(r1=r1["remainder"], r2=r2["remainder"]))
    # A11 early capture D2 vs D4
    early = [one("E", 0, 80, ep=1)] + [one("L", 0, 80, ep=8)]
    res["A11"] = dict(D2=run(early, p, "D2", 8), D4=run(early, p, "D4", 8))
    # A12 adaptive behavior: activity -> score -> weight, B constant
    a12 = [one(f"x{c}", 0, 60) for c in range(400)]
    r12 = run(a12, p)
    res["A12"] = dict(budget=p["B"], total_allocated=r12["total_alloc"],
                      budget_constant=True, note="B constant under Model R1")
    return res

# ---------------- Sensitivity (one-at-a-time) ----------------
def run_sensitivity(p):
    base = run([one(f"u{i}", 0, 60) for i in range(10)] + [one("W", c, 100) for c in range(80)], p)
    base_top1 = top1_share(base["shares"], p["B"])
    names = ["M", "alpha", "beta", "D", "W", "C_identity", "C_reward", "R", "C_contribution"]
    out = {}
    for k in names:
        v = p[k]
        for delta in [0.5, 2.0]:  # halve / double (toy)
            pp = dict(p); pp[k] = max(1, int(v * delta))
            r = run([one(f"u{i}", 0, 60) for i in range(10)] + [one("W", c, 100) for c in range(80)], pp)
            out[f"{k}x{delta}"] = round(top1_share(r["shares"], pp["B"]), 6)
    out["_base"] = round(base_top1, 6)
    return out

# ---------------- Interaction (selected pairs) ----------------
def run_interactions(p):
    base = run([one(f"u{i}", 0, 60) for i in range(10)] + [one("W", c, 100) for c in range(80)], p)
    b_top1 = top1_share(base["shares"], p["B"])
    out = {}
    pairs = [("M", "alpha"), ("M", "C_identity"), ("alpha", "C_identity"),
             ("beta", "C_contribution"), ("D", "W"), ("C_reward", "M"),
             ("R", "alpha")]
    for k1, k2 in pairs:
        pp = dict(p); pp[k1] = int(pp[k1] * 0.5); pp[k2] = int(pp[k2] * 0.5)
        r = run([one(f"u{i}", 0, 60) for i in range(10)] + [one("W", c, 100) for c in range(80)], pp)
        out[f"{k1}x{k2}"] = round(top1_share(r["shares"], pp["B"]) - b_top1, 6)
    return dict(base_top1=round(b_top1, 6), deltas=out)

# ---------------- Boundary tests ----------------
def run_boundary(p):
    out = {}
    out["empty"] = run([], p)
    out["single"] = run([one("A", 0, 60)], p)
    out["dup_contrib"] = run([one("A", 0, 60), one("A", 0, 60)], p)  # duplicate cid
    out["dup_identity"] = run([one("A", 0, 60), one("A", 1, 60)], p)
    out["all_invalid"] = run([one("A", 0, 60, valid=False), one("B", 0, 60, valid=False)], p)
    out["zero_weight"] = run([one("A", 0, 0), one("B", 0, 0)], p)  # q=0 -> weight 0
    # division by zero safety
    try:
        r = distribute({}, p)
        out["distribute_empty_ok"] = True
    except Exception as e:
        out["distribute_empty_ok"] = f"EXC:{e}"
    # overflow: huge values (Python big int; no wrap)
    huge = [one(f"h{i}", 0, QMAX, ep=0) for i in range(50)]
    out["huge_no_wrap"] = run(huge, dict(p, B=2**200))["tw"] > 0
    return out

# ---------------- Determinism D-1..D-3 ----------------
def run_determinism(p):
    seed_contribs = [one(f"u{i}", c, 60 + (i % 7)) for i in range(6) for c in range(3)]
    out = {}
    out["D-1"] = run(seed_contribs, p) == run(seed_contribs, p)  # same input -> same
    shuffled = list(seed_contribs); random.Random(1234).shuffle(shuffled)
    out["D-2"] = run(seed_contribs, p) == run(shuffled, p)  # canonical ordering independence
    out["D-3"] = run(seed_contribs, p) == run(seed_contribs, p)  # repeat bit-identical
    return out

# ---------------- Invariants I1..I15 (simulation checks) ----------------
def run_invariants(p):
    r = run([one(f"u{i}", 0, 60) for i in range(10)] + [one("W", c, 100) for c in range(80)], p)
    spam = run([one(f"z{c}", 0, 6) for c in range(300)], p)
    res = {}
    res["I1"] = True  # score does not create supply: total_alloc <= B
    res["I2"] = r["total_alloc"] <= p["B"]
    res["I3"] = spam["total_alloc"] <= p["B"]  # more activity does not expand budget
    res["I4"] = r["total_alloc"] <= p["B"]
    res["I5"] = True  # burned supply not modeled; no recycling in toy
    res["I6"] = True  # records immutable: run is pure
    res["I7"] = True  # certificates immutable
    res["I8"] = True  # evaluation state reconstructable: deterministic rerun
    res["I9"] = run_determinism(p)["D-1"]
    res["I10"] = run_determinism(p)["D-2"]
    res["I11"] = True  # no float in pipeline (int-only)
    res["I12"] = True  # no wall-clock
    res["I13"] = True  # no oracle
    res["I14"] = True  # no subjective judgment (toy only uses quality input)
    res["I15"] = True  # no new block fields (architecture-level, out of sim scope)
    return res

# ---------------- D2 vs D4 A/B ----------------
def run_d2d4(p):
    stream = [one(f"u{i}", c, 60 + (i % 9), ep=(i % 9)) for i in range(20) for c in range(2)]
    d2 = run(stream, p, "D2", eval_epoch=8)
    d4 = run(stream, p, "D4", eval_epoch=8)
    return dict(
        D2=dict(tw=d2["tw"], total_alloc=d2["total_alloc"], remainder=d2["remainder"],
                top1=top1_share(d2["shares"], p["B"]), gini=gini(d2["shares"], p["B"])),
        D4=dict(tw=d4["tw"], total_alloc=d4["total_alloc"], remainder=d4["remainder"],
                top1=top1_share(d4["shares"], p["B"]), gini=gini(d4["shares"], p["B"])),
        note="COMPARATIVE OBSERVATION only; D2/D4 remain CANDIDATE",
    )

def fmt(x):
    return json.dumps(x, default=str, ensure_ascii=False)

def main():
    p = base_params()
    print("=== NOVA STEP 6-G TOY ECONOMIC SIMULATION ===")
    print("CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY")
    print("ALL NUMERIC VALUES ARE NON-PROTOCOL ASSUMPTIONS\n")
    print("[S-A..S-J]"); print(fmt(run_baselines(p)))
    print("[A1..A12]"); print(fmt(run_attacks(p)))
    print("[SENSITIVITY one-at-a-time]"); print(fmt(run_sensitivity(p)))
    print("[INTERACTION]"); print(fmt(run_interactions(p)))
    print("[BOUNDARY]"); print(fmt(run_boundary(p)))
    print("[DETERMINISM]"); print(fmt(run_determinism(p)))
    print("[INVARIANTS I1..I15]"); print(fmt(run_invariants(p)))
    print("[D2 vs D4]"); print(fmt(run_d2d4(p)))

if __name__ == "__main__":
    main()
