# PHASE 2 STEP 6-R24-A — CAP STRESS v2 VALIDATION — Summary Report

CLASSIFICATION: TOY MODEL / NON-PROTOCOL / VALIDATION ONLY
NO PARAMETER FREEZE. All numeric values NON-PROTOCOL ASSUMPTIONS.
Results INFORM Owner decision; they do NOT make it.

## 1. Test Design
- Option A: score -> cap -> rounding (cap applied at weight level via share-equivalent ceiling, then floor-allocate)
- Option B: score -> rounding -> cap (floor-allocate first, then cap each share to absolute cap_r)
- cap_r = B * C_reward // 10000 (per-share reward cap, 5% of budget)
- Metrics: conservation (allocated+remainder==B), replay (same input -> same output), split gain, top1/topk/gini (distortion/fairness), boundary safety.

## 2. Scenario Matrix (6 scenarios)
1. Extreme Whale  2. Identity Split  3. Contribution Split  4. Many Small
5. Decay Interaction (early/late/persistent)  6. Cap Boundary (below/above)

## 3. Observation Result
- extreme_whale: A top1=0.0539 (> cap_r=0.05, remainder 12) ; B top1=0.05 (= cap_r, remainder 8.57e7). Both conservation=True, replay=True.
- identity_split (unified single group): A top1=1.0 (single unit dominates whole budget); B top1=0.05 (strict per-share cap). split_K4: A top1=0.25, B top1=0.05. split_gain: A=0.8, B=0.8421 (both <1 -> split not rewarded).
- contribution_split: split_gain A=B=0.1067 (aggregate-first resistance at weight layer; A/B same here).
- many_small: A=B (top1 0.0125, no cap activation -> no difference).
- decay_early/late/persistent: A top1=1.0 vs B top1=0.05 (single-contributor scenarios: A weight-level cap diluted by normalization -> full budget; B strictly capped).
- cap_boundary: A top1=0.1667 for below & above (no step arbitrage observed in A under this toy).

## 4. Option A vs Option B Comparison (TOY)
| Dimension | A (score->cap->rounding) | B (score->rounding->cap) |
|---|---|---|
| Determinism/Replay | PASS | PASS |
| Conservation | PASS | PASS |
| Per-share absolute cap | WEAK: whale 0.0539>0.05; single unit 1.0 (normalize dilutes) | STRONG: top1 == 0.05 constant |
| Whale resistance | partial (can exceed absolute cap) | strong (strict <= cap_r) |
| Remainder | small (near-full allocation) | larger (cap truncation) |
| Masking | only separable under cap activation | same |
| Boundary safety | no step observed (toy) | n/a (strict cap) |

KEY TOY FINDING: Option B provides a STRONGER absolute per-share cap guarantee (whale/single contributor cannot exceed cap_r); Option A's weight-level cap is diluted by normalization and can let a single aggregation unit dominate the whole budget. B aligns better with the ADR-0044 reward-share cap semantics (absolute share ceiling in bps).

## 5. SR-P3 Recommendation (AI, not Owner decision)
- Recommend Option B (score -> rounding -> cap) as candidate: strict per-share cap, consistent with reward-share cap absolute semantics, conservation holds, replay deterministic.
- Note: toy semantics are implementation assumptions; cap stress v2 is INFORM ONLY.

## 6. Owner Decision Record Draft
| Decision ID | Decision Item | Evidence | AI Recommendation | Owner Decision |
|---|---|---|---|---|
| SR-P3 | Cap Ordering (A score->cap->rounding / B score->rounding->cap) | Cap stress v2: A diluted (0.0539>cap; single-unit 1.0); B strict (top1=0.05) | B (score->rounding->cap) as candidate; strong per-share cap | (empty - Owner) |

## NO PARAMETER FREEZE. NO CAP ORDERING SELECTED. OWNER DECISION REQUIRED.
