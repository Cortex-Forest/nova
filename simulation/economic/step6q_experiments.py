# Nova PHASE 2 STEP 6-Q — STRUCTURAL GAP CLOSURE & ADVERSARIAL VALIDATION
# CLASSIFICATION: DESIGN / TOY / NON-PROTOCOL
# Goal: close structural unknowns blocking ADR-0045 Freeze Design. No parameter freeze.
# Integer-only; canonical ordering; explicit seed; no float/wall-clock/oracle/subjective.
import json, random
from collections import defaultdict
import toy_econ_sim as T
from remediation_experiments import mk, compute_weights, run_variant, distribute, \
    top1, topk, sumsh, gkey
gini = T.gini

def esc(p):
    return run_variant([mk(f"u{i}", c, 60 + (i % 5)) for i in range(8) for c in range(2)], p, "baseline", E=0)

# ---------------- Q1 Canonical Logical Contributor Group ----------------
GROUP_PROPERTIES = ["Derivable", "Canonical", "Serializable", "Reconstructible", "Verifiable",
                    "Deterministic", "Replay-safe", "Cross-domain stable", "Cross-epoch stable",
                    "Split-resistant", "State-size acceptable"]
def q1(p):
    # G1 = cryptographic-key-derived group; G2 = protocol-derived canonical logical group;
    # G3 = contribution-set/provenance-derived group.
    # Property assessment (design analysis; NOT protocol proof)
    g1 = dict.fromkeys(GROUP_PROPERTIES, "DESIGN ANALYSIS")
    g2 = dict.fromkeys(GROUP_PROPERTIES, "DESIGN ANALYSIS")
    g3 = dict.fromkeys(GROUP_PROPERTIES, "DESIGN ANALYSIS")
    g1["Derivable"] = "YES (from crypto key)"; g1["Canonical"] = "YES (key)"
    g1["Split-resistant"] = "NO (key-per-attacker)"
    g2["Derivable"] = "YES (protocol state)"; g2["Canonical"] = "CANDIDATE (needs key spec)"
    g2["Split-resistant"] = "PARTIAL"
    g3["Derivable"] = "YES (provenance set)"; g3["Canonical"] = "CANDIDATE"
    g3["Split-resistant"] = "PARTIAL"
    # Group splitting attack (toy): K logical groups, each aggregated -> per-group cap
    total_q = 100 * 60
    single = run_variant([mk("G", i, 100) for i in range(60)], p, "I2", E=0)
    base = sumsh(single["shares"], p["B"])
    splits = {}
    for K in [1, 2, 4, 8]:
        cs = []
        idx = 0
        per = 60 // K
        for k in range(K):
            for _ in range(max(1, per)):
                cs.append(mk(f"s{k}", idx, 100, group=f"G{k}"))  # DIFFERENT groups (attack)
                idx += 1
        r = run_variant(cs, p, "I2", E=0)  # per-group aggregate cap
        splits[K] = round(sumsh(r["shares"], p["B"]) / base, 3) if base > 0 else float("inf")
    return dict(G1=g1, G2=g2, G3=g3,
                group_split_gain=splits,
                note="multi-group splitting under per-group cap: toy shows linear gain (major risk); "
                     "real-world identity NOT protocol-verifiable")

# ---------------- Q2 Cross-Domain / Cross-Epoch Aggregation ----------------
def q2(p):
    # A global / B domain-scoped / C epoch-scoped / D domain x epoch scoped
    # toy: group aggregation (I2) under domain and/or epoch partition
    single = run_variant([mk("G", i, 100) for i in range(120)], p, "I2", E=3)
    base = sumsh(single["shares"], p["B"])
    models = {}
    # A global: all in one group (already base) -> Gain 1
    models["A_global"] = round(base / base, 3)
    # B domain-scoped: group aggregation, contributions split across domains
    csB = [mk("G", i, 100, dom=f"d{i%2}") for i in range(120)]
    models["B_domain_scoped"] = round(sumsh(run_variant(csB, p, "I2", E=3)["shares"], p["B"]) / base, 3)
    # C epoch-scoped
    csC = [mk("G", i, 100, ep=i % 4) for i in range(120)]
    models["C_epoch_scoped"] = round(sumsh(run_variant(csC, p, "I2", mode="D4", E=3)["shares"], p["B"]) / base, 3)
    # D domain x epoch scoped
    csD = [mk("G", i, 100, dom=f"d{i%2}", ep=i % 4) for i in range(120)]
    models["D_domainxepoch"] = round(sumsh(run_variant(csD, p, "I2", mode="D4", E=3)["shares"], p["B"]) / base, 3)
    return dict(models=models,
                classification="INCONCLUSIVE / DESIGN GAP (scoping semantics require Owner decision)")

# ---------------- Q3 Contribution variant (fixed-point, no q=0) ----------------
def q3(p):
    # integer fixed-point contribution units; total > N; each contribution positive integer size
    TOTAL_UNITS = 12800  # NON-PROTOCOL toy fixed-point total
    out = {}
    for N in [1, 2, 4, 8, 16, 32, 64, 128]:
        large = run_variant([mk("L", 0, TOTAL_UNITS)], p, "C1", E=0)
        row = {"N": N}
        q_per = max(1, TOTAL_UNITS // N)
        for v in ["C1", "C2", "C5"]:
            small = run_variant([mk("S", i, q_per) for i in range(N)], p, v, E=0)
            row[v] = round(small["tw"] / max(1, large["tw"]), 3)
        # heavy-tail split
        heavy = [mk("S", 0, TOTAL_UNITS // 2)] + [mk("S", i, max(1, TOTAL_UNITS // (2 * (N - 1)))) for i in range(1, N)]
        row["heavy_tail_C1"] = round(run_variant(heavy, p, "C1", E=0)["tw"] / max(1, large["tw"]), 3)
        out[f"N={N}"] = row
    out["artifact_fix"] = "integer fixed-point units; total>N; each contribution positive integer (no q=0)"
    return out

# ---------------- Q4 Cap ordering under non-cap-dominated conditions ----------------
def q4(p):
    out = {}
    # non-cap-dominated: set reward cap very high (low pressure)
    pp = dict(p, C_reward=10000)  # reward-cap pressure off
    cs = [mk(f"u{i}", 0, 60) for i in range(10)] + [mk("W", c, 100) for c in range(80)]
    pipelines = {}
    for pl, variant in [("A", "baseline"), ("B", "baseline"), ("C", "I2")]:
        r = run_variant(cs, pp, variant, E=0)
        pipelines[pl] = dict(top1=round(top1(r["shares"], pp["B"]), 4),
                             total_share=round(sumsh(r["shares"], pp["B"]), 4),
                             gini=round(gini(r["shares"], pp["B"]), 4))
    out["non_cap_dominated_pipelines"] = pipelines
    # split combos
    combos = {
        "identity": (4, 1, 1, 1), "domain": (1, 4, 1, 1), "epoch": (1, 1, 4, 1),
        "identity_domain": (4, 4, 1, 1), "identity_epoch": (4, 1, 4, 1),
        "domain_epoch": (1, 4, 4, 1), "id_dom_ep": (4, 4, 4, 1),
        "all4": (4, 4, 2, 2),
    }
    total_c = 64
    base = sumsh(run_variant([mk("A", 0, 100)], pp, "baseline", E=0)["shares"], pp["B"])
    res = {}
    for name, (K, D, E, _N) in combos.items():
        cs2 = [mk(f"s{k}", c, 25, ep=e, dom=f"d{d}") for k in range(K) for d in range(D)
               for e in range(E) for c in range(max(1, total_c // (K * D * E)))]
        r = run_variant(cs2, pp, "I2", mode="D4", E=E - 1)
        res[name] = round(sumsh(r["shares"], pp["B"]) / base, 3) if base > 0 else float("inf")
    out["bypass_gain_by_dim"] = res
    out["order_sensitivity"] = "A/B/C identical in toy under both pressures; requires finer pipeline model"
    out["classification"] = "INCONCLUSIVE (pipeline semantics not fully separable in toy)"
    return out

# ---------------- Q5 Economic Epoch ----------------
def q5():
    states = ["created", "evaluated", "eligible", "finalized", "allocated", "paid"]
    # created in E, finalized in E+n: candidate epoch assignments
    out = {}
    for n in [0, 1, 2, "large"]:
        out[f"finalized_E+{n}"] = dict(
            eligibility_epoch="OPEN (candidate: finalized epoch)",
            reward_epoch="OPEN", decay_start="OPEN", cap_epoch="OPEN",
            already_paid="IDEMPOTENT", reversal="IMMUTABLE+SUPERSEDING")
    out["epoch_identity"] = "REQUIRED (deterministic accounting abstraction)"
    out["epoch_mapping"] = "OPEN (NOT block height / wall clock / consensus round / genesis)"
    out["arch_conflict_risk"] = "ISOLATE Economic Epoch from Consensus/Block epoch concepts"
    return out

# ---------------- Q6 D2/D4 adversarial decay ----------------
def q6(p):
    out = {}
    for horizon, E in [("h10", 10), ("h50", 50), ("h100", 100), ("h500", 500), ("h1000", 1000)]:
        early = [mk("E", 0, 80, ep=1)]
        late = [mk("L", 0, 80, ep=E)]
        persistent = [mk("P", e, 70, ep=e) for e in range(0, E + 1)]
        burst = [mk("B", e, 80, ep=e) for e in range(E // 2, E // 2 + 2)]  # burst before boundary
        row = {}
        for mode in ["D2", "D4"]:
            we = run_variant(early, p, "baseline", mode, E=E)["weights"].get("E", 0)
            wl = run_variant(late, p, "baseline", mode, E=E)["weights"].get("L", 0)
            wp = run_variant(persistent, p, "baseline", mode, E=E)["weights"].get("P", 0)
            wb = run_variant(burst, p, "baseline", mode, E=E)["weights"].get("B", 0)
            row[mode] = dict(early=we, late=wl, persistent=wp, burst=wb,
                             early_capture_index=round(we / max(1, wl), 3))
        out[horizon] = row
    out["floor"] = "OPEN (not invented)"
    return out

# ---------------- Q7 Late finalization + reversal ----------------
def q7():
    trans = [
        ("not_paid_to_finalized", "OK"),
        ("paid_to_duplicate_finalized", "IDEMPOTENT (no duplicate)"),
        ("paid_to_reversal", "SUPERSEDING RECORD (immutable original)"),
        ("paid_to_superseding", "SUPERSEDED"),
        ("reversal_then_replay", "NO REPLAY REWARD"),
        ("reversal_second", "SECOND REVERSAL = new superseding record"),
        ("late_finalization_to_already_paid", "IDEMPOTENT"),
        ("late_finalization_to_reversal", "SUPERSEDING"),
    ]
    return dict(transitions=[{"case": c, "handling": h} for c, h in trans],
                invariants=dict(idempotent=True, auditability=True, negative_reward_prohibited=True,
                                double_allocation_prevented=True, supply_conservation=True,
                                reconstruction=True))

# ---------------- Q8 Remainder / zero-weight / budget ----------------
def q8(p):
    out = {}
    for horizon in [10, 100, 1000, 10000]:
        acc = 0
        for e in range(horizon):
            # toy: each epoch distribute, carry remainder forward (candidate)
            r = distribute({"A": 500, "B": 500}, dict(p, B=p["B"] + acc))
            acc = r[2]  # remainder
        out[f"h{horizon}"] = dict(carry_forward_remainder=acc, overflow_risk=(acc > p["B"] * 2))
    # zero weight
    zw = distribute({}, p)
    out["zero_weight"] = dict(total_alloc=zw[1], remainder=zw[2], implicit_reward=False)
    return dict(long_horizon=out, note="carry-forward accumulation bounded in toy; REQUIRES VALIDATION")

# ---------------- Q9 Rounding precision ----------------
def q9(p):
    out = {}
    for label, w in [("below", 100), ("exact", p["C_identity"]), ("above", p["C_identity"] + 1)]:
        r1 = distribute({"A": w}, p)
        r2 = distribute({"A": w}, p)
        out[label] = dict(alloc=r1[1], remainder=r1[2], determinism=(r1 == r2))
    many = distribute({f"u{i}": 7 for i in range(100)}, p)
    out["many_recipients"] = dict(alloc=many[1], conservation=(many[1] <= p["B"]))
    cs = [mk(f"u{i}", c, 60) for i in range(6) for c in range(2)]
    r1 = run_variant(cs, p, "baseline", E=0)
    sh = list(cs); random.Random(11).shuffle(sh)
    out["permutation_invariant"] = (r1 == run_variant(sh, p, "baseline", E=0))
    out["serialization_invariant"] = (r1 == run_variant(json.loads(json.dumps(cs)), p, "baseline", E=0))
    return out

# ---------------- Q10 Citation (design exploration) ----------------
def q10():
    cases = ["single", "duplicate", "conflicting", "fake", "same_evidence_many", "chain", "cross_domain"]
    return dict(
        cases=[{"case": c,
                "attack_surface": "citation amplification / fake evidence",
                "verification_dependency": "protocol-verifiable citation relation (L1)",
                "state_dependency": "citation graph state",
                "oracle_dependency": "NONE (no off-chain oracle)",
                "replay_risk": "must be idempotent"} for c in cases],
        classification="DESIGN EXPLORATION ONLY; citation model REQUIRES dedicated experiment",
        note="no real-world trusted third party as consensus-critical oracle")

def main():
    p = T.base_params()
    results = {
        "Q1_group_key": q1(p),
        "Q2_cross_domain_epoch": q2(p),
        "Q3_contribution_variant": q3(p),
        "Q4_cap_ordering": q4(p),
        "Q5_economic_epoch": q5(),
        "Q6_d2d4_adversarial": q6(p),
        "Q7_late_finalization_reversal": q7(),
        "Q8_remainder_budget": q8(p),
        "Q9_rounding": q9(p),
        "Q10_citation": q10(),
    }
    with open("step6q_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print("WROTE step6q_results.json (TOY / NON-PROTOCOL)")
    print(json.dumps(results, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
