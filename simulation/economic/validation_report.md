# STEP 6-N — Economic Validation Experiments X1~X8 — Summary Report

CLASSIFICATION: TOY MODEL / NON-PROTOCOL / EXPLORATORY ONLY
All numeric values are NON-PROTOCOL ASSUMPTIONS. Results INFORM, they do NOT MAKE Owner decisions.

## X1 Identity × Domain × Epoch aggregation
- Baseline (independent identities): Sybil Gain ∝ K (K=8 → 8.0) across D/E dims (identity split dominates).
- I-1/I-2/I-3 (group aggregation): Sybil Gain = 1.0 for all K/D/E combos tested.
- Toy observation: group aggregation kept Gain ≈ 1 under identity×domain×epoch partitions; no combined bypass observed under remediation variants (toy).

## X2 Contribution split scaling
- Aggregate-first family (C1/C2/C5): split_gain < 1 for large N (N=32 → 0.135) — splitting not rewarded.
- C3 (marginal-independent): N=4 → 1.234 (split>1 region), N=32 → 0.595.
- C4 (count normalization): intermediate (N=4 → 2.252).
- Geometric/unequal split under C1: 1.586 (unequal split can exploit) — residual risk.
- Note: N=128 toy artifact (100//N=0 → q=0) yields 0.0.

## X3 Alpha × Beta 2D sweep
- Under aggregate-first (C1): all grid cells split<1 (0.022~0.167); α higher → more suppression; β minor under C1.
- No incentive inversion observed in the tested grid under C1 (toy). α/β remain OPEN.

## X4 Cap ordering
- Reward-cap pressure dominates: low pressure → total_share 1.0 (top1 0.2058); high pressure → total_share 0.11.
- Pipeline A/B/C identical in toy (pipeline semantics only partially separable); cap boundary continuous (below/exact/above = 311).
- Cap Ordering remains OPEN; masking observed.

## X5 Combined cap bypass
- Baseline: bypass gain = 4.0 (K=4) regardless of added domain/epoch dims.
- I-1/I-2/I-3: gain = 1.0 (aggregation suppresses). No combined bypass observed under remediation (toy).

## X6 D2/D4 long horizon
- h100/h1000: D2 early weight → 0 (asymptotic decay); D4 early → 0 (window exclusion); persistent → 600 (C_identity cap).
- D2 and D4 converge to 0 for early-only contribution at very long horizon (toy). Floor not invented (OPEN).

## X7 Late finalization state machine
- already-paid → IDEMPOTENT (no duplicate allocation); reversal → compensating REVERSED; superseded → SUPERSEDED.
- serialize_equal = True; replay_idempotent = True.
- Reward epoch for created=E finalized=E+n remains OPEN (dependency).

## X8 Rounding boundary
- Canonical floor: weight/budget boundaries conservative; determinism True; budget conservation True; shuffle determinism True.
- Rounding precision OPEN.

## Determinism D1~D4: all True. Invariants ES1~ES10: all True.
