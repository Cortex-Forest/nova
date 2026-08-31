# STEP 6-Q — Structural Gap Closure & Adversarial Validation — Summary Report

CLASSIFICATION: DESIGN / TOY / NON-PROTOCOL

## Q1 Canonical Logical Contributor Group
- G1 (crypto-key-derived): derivable/canonical YES; split-resistant NO (key-per-attacker).
- G2/G3: derivable YES; canonical CANDIDATE (key spec needed); split-resistant PARTIAL.
- Group splitting attack (toy): group_split_gain = K (per-group cap linear amplification) -> MAJOR RISK.
- DESIGN GAP: group-key derivability/serialization/reconstruction/verification spec missing; real-world identity NOT protocol-verifiable.

## Q2 Cross-Domain / Cross-Epoch Aggregation
- A global / B domain-scoped / C epoch-scoped / D domain×epoch: all Gain ≈ 1.0 (toy, under group aggregation).
- Classification: INCONCLUSIVE / DESIGN GAP (scoping semantics require Owner decision).

## Q3 Contribution Variant (fixed-point; no q=0 artifact)
- C1/C2/C5 (aggregate-first): split_gain monotonically < 1 (N=4 0.952, N=8 0.888, N=32 0.845, N=128 0.835).
- Heavy-tail C1: 0.888 (N=8) ... 0.42 (N=128) — heavier split penalized.
- No partition produced split_gain > 1 in tested grid -> no >1 amplification under aggregate-first (toy).
- Structural risk largely converged for aggregate-first family; variant selection (C1/C2/C5) still OPEN.

## Q4 Cap Ordering (non-cap-dominated)
- A/B/C identical in toy even under low reward-cap pressure -> pipeline semantics not fully separable (INCONCLUSIVE).
- Bypass gain by dimension (identity/domain/epoch/combined): all 1.0 under I2 aggregation (toy).

## Q5 Economic Epoch
- existence REQUIRED; length/mapping/boundary OPEN (candidate: finalized epoch).
- already-paid idempotent; reversal immutable+superseding.
- ARCHITECTURAL CONFLICT RISK: isolate Economic Epoch from Consensus/Block epoch concepts.

## Q6 D2/D4 Adversarial Decay
- Long horizon (h100/h1000): D2/D4 early → 0; late 114; persistent 600 (cap); burst → 0.
- Floor OPEN (not invented).

## Q7 Late Finalization + Reversal
- 8 transition cases all OK / IDEMPOTENT / SUPERSEDING; invariants (idempotent, auditability, no negative reward, no double allocation, supply conservation, reconstruction) True.

## Q8 Remainder / Budget
- Carry-forward remainder accumulates to ~9e9 (toy saturation) -> REQUIRES VALIDATION (long-term accumulation/overflow).
- Zero-weight: no implicit reward True.

## Q9 Rounding
- below/exact/above: deterministic; many recipients conservation True; permutation & serialization invariant True.

## Q10 Citation
- DESIGN EXPLORATION ONLY; requires dedicated experiment; no off-chain oracle as consensus-critical.
