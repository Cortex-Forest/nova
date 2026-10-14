# PHASE 2 STEP 6-R4 — Experiment Execution & Validation — Summary Report

CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
NO PARAMETER FREEZE. All numeric values are NON-PROTOCOL ASSUMPTIONS.
Results INFORM Owner decisions; they do NOT MAKE them. Simulation pass != Protocol proof.

## 1. E-GLID-1 Group Splitting Resistance
- Attacker splits total activity across K groups; per-group independent cap (I2).
- Scaling: K=1→gain 1.0, K=2→2.0, K=4→4.0, K=8→8.0, K=16→16.0 (LINEAR).
- max_gain = 16.0; avg_gain = 6.2; **gain_gt_1_detected = TRUE**.
- CONFIRMS STEP 6-Q Q1 MAJOR RISK: if attacker can create arbitrary groups, per-group cap is bypassed ~linearly.
- RECORDS ONLY; no G1/G2/G3 selection.

## 2. E-GLID-2 Canonical Serialization / Reconstruction
- Same logical group (canonical-sorted member set, sha256): permutation -> same id; replay -> same id;
  different group -> different id. **determinism = TRUE**.
- NOTE: canonical serialization simulation; NOT a GLID protocol implementation.

## 3. E-GLID-3 Cross-Domain Aggregation
- Same group activity spread across D=1/2/4 domains: gain_ratio = 1.0 for all D.
- **amplification_detected = FALSE** (cross-domain does not amplify under I2 group aggregation, toy).
- RECORDS ONLY.

## 4. E-EPOCH-1 Epoch Attribution / Replay / Accounting
- created+finalized same epoch: allocated (reward_cap disabled to isolate duplicate effect).
- late finalized (created ep0, eval E=3): counted at eval E; decay reduces weight over horizon (toy).
- **replay_idempotent_after_dedup = TRUE** (dedup restores single-submission allocation).
- **raw_engine_duplicate_inflates_share = TRUE** (A share 5e8 -> 5.7e8 when duplicate left raw) —
  confirms engine counts duplicates at weight layer; protocol needs explicit idempotency/dedup (already-paid rule).
- accounting_consistency: conservation TRUE, alloc non-negative TRUE.
- no E-a/E-b/E-c selection.

## 5. C-Discrimination (C1/C2/C5, controls C3/C4)
- C1/C2/C5 are **IDENTICAL** in the current toy engine (single aggregate-before-diminishing branch).
- Across 5 scenarios (heavy_tail / whale / many_small / burst / long_horizon):
  - C1/C2/C5 identical everywhere; C3 and C4 differ (C3 heavy_tail split_gain 3.22, C4 whale 30.0).
  - C-family suppresses contribution-split in heavy_tail/many_small (split_gain < 1) BUT
    **whale/burst show split_gain 59.2 / 39.2** — splitting one identity's dense contributions into many
    identities evades the per-identity alpha diminishing. C-family does NOT resist identity-split by itself;
    it must be paired with group aggregation (I2) — reinforcing the canonical-group (GLID) requirement.
- No winner declared; C1/C2/C5 discrimination requires Owner-defined variant semantics.

## 6. Cap Stress (HYPOTHETICAL toy cap-ordering A/B/C)
- A=normalize->cap, B=cap->normalize (weight-ceiling), C=MaxScore-before-cap.
- extreme_whale: A==C (total_share 0.9143, gini 0.0071); B differs (total_share 1.0, gini 0.0063).
- many_contributors / multi_domain / cross_epoch: A/B/C identical (cap not activated) — confirms Q4 masking.
- All scenarios conservation TRUE.
- HYPOTHETICAL toy semantics; engine pipelines otherwise unmodeled. No cap ordering frozen.

## 7. Alpha x Beta Sensitivity (C1)
- alpha 1..5: split_gain 0.1667 -> 0.035 (alpha drives split suppression); gini 0.0034 -> 0.0223;
  total_share rises to 1.0 at higher alpha.
- **beta has NO effect under C1** (identical across beta=1..5) — the C1 branch does not apply beta.
  Beta's role must be evaluated under a variant that uses contribution-level diminishing (e.g. baseline/C3 path).
- retention (persistent vs early, D2) = 2.0761 constant across grid (decay-driven).
- Direction only; NO final parameters; NO freeze.

## 8. Decay Stress (D2 vs D4)
- D2: early 26, persistent 600, late 114, boundary_inside 95, boundary_outside 0, late_finalized 22.
- D4: early 0, persistent 600, late 114, boundary_inside 114, boundary_outside 0, late_finalized 0.
- floor_effect: floor NOT invented; early weights decay toward 0 at long horizon (D4 reaches 0 via window; D2 retains residue).
- boundary_gaming_flag TRUE for both (inside counted, outside excluded).
- Records only; no D2/D4 selection; floor/duration OPEN.

## 9. Remainder Long Horizon (toy integer accounting: fixed per-epoch inflow, 90% alloc)
- R-a carry-forward: converges to steady-state budget ~111112 (no overflow in this model; NOT the Q8 engine model).
- R-b pool-retention: pool grows linearly 10^7 -> 10^10 over 100..100000 epochs; **overflow_risk TRUE at H=100000**.
- R-c redistribution: no reserve, full utilization, no overflow, no starvation.
- No starvation in any policy; conservation holds in model.
- Toy accounting model, NOT the engine pipeline; no remainder policy selected.

## 10. Citation Attack (N1/N2/N3; no oracle)
- N1 (no citation): all attacks amplification = 1.0.
- N2 (citation weight): self 1.0833, circular 1.1667, farming 1.5, amplification 1.25 — ALL amplified.
- N3 (verified-only, rejects self/cyclic): all attacks amplification = 1.0 (amplification suppressed).
- Toy graph model; no citation model selected.

## Key TOY Findings (INFORM ONLY)
1. E-GLID-1 re-confirms Q1: arbitrary-group creation linearly bypasses per-group cap (16x) -> canonical group commitment required.
2. C-family does not resist identity-split (whale 59x); relies on I2 group aggregation -> GLID is a structural prerequisite.
3. C1/C2/C5 identical in engine -> no discrimination possible until Owner defines variant semantics.
4. Cap ordering only separable under cap-activated (extreme whale) scenarios; A==C in this toy semantics.
5. alpha drives split suppression; beta unused under C1 (needs contribution-level diminishing variant to matter).
6. D2 retains early residue; D4 zeroes window-external early contributions (floor question).
7. R-b pool retention unboundedly accumulates (overflow at long horizon); R-a converges under this model.
8. N2 citation amplifies all attacks; N3 verified-only suppresses to 1.0 (if citation enters score, N3 form is the candidate; no selection).

## NO PARAMETER FREEZE. NO DECISION MADE. OWNER DECISION REQUIRED.
