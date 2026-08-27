# ADR-0036: Random Witness V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（Random Witness，10-4）
- 关联：ADR-0033（C-4 Deterministic Random Witness）、ADR-0034（ValidatorSet/ValidatorId）、
  ADR-0005（DomainId——新增 `Witness`）、ADR-0012（Ed25519）、ADR-0013（签名消息哈希）

## Context

ADR-0033 C-4 冻结 Deterministic Random Witness（WitnessSeed / DeterministicSelect / Witness ≠ finality
authority）。本 ADR 冻结 **W-1~W-6**：身份来源、随机算法、seed、数量、proof、BFT 边界。

## Decision（冻结）

### W-1 — Witness 身份来源

- **`WitnessId = ValidatorId`**；来源 = `ValidatorSet`（DeterministicSelect）。
- **禁止**：NodeId → Witness / Account → Witness / External observer → Witness（Witness 属共识观察层，
  必须受 ValidatorSet 管理）。

### W-2 — Deterministic Selection Algorithm

```rust
rank = SHA-256(witness_seed ‖ validator_id)
// 按 rank 升序取前 witness_count
```

- 同 `ValidatorSet + WitnessSeed + witness_count` ⇒ 同 `WitnessSet`（任何节点可验证；无中心随机源、
  无 VRF 依赖）。

### W-3 — WitnessSeed

- `WitnessSeed = protocol_hash(previous_finality_reference ‖ height)`（C-4）。
- 不依赖 timestamp / random() / network order / peer input（防节点间不一致 / 随机可操纵）。

### W-4 — Witness 数量

- **`witness_count` = protocol constant**（V0.1 固定值；简单、共识可验证、无动态治理变量）。
- 动态（ratio-based）留后续 ADR（`Dynamic Witness Scaling`）——不污染当前协议。

### W-5 — WitnessProof（新增 DomainId）

- **新增 `DomainId::Witness`**（不采用 `ValidatorVote`——Vote 决定 finality，Witness 提供
  availability signal，语义不同必须隔离）。
  ```rust
  pub struct WitnessProof {
      pub block_hash: [u8; 32],
      pub witness_id: ValidatorId,
      pub signature: [u8; 64],   // Ed25519
  }
  ```
- 签名覆盖：`DomainId::Witness + chain_id + canonical payload`（ADR-0005/0013 体系）。

### W-6 — Witness / BFT Boundary

- Witness 提供：**availability signal** + **DAG confidence**。
- Witness **不是**：voting power / finality authority / block ordering authority / quorum participant。
- 权力链：`DAG（candidate organization）→ Witness（availability confidence）→ BFT（weighted quorum
  ≥2/3）→ Finality`。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| W-1 | WitnessId = ValidatorId（ValidatorSet 管理） | 冻结 |
| W-2 | `deterministic_select`：`rank=SHA-256(seed‖validator_id)` 升序 | 冻结 |
| W-3 | `WitnessSeed = Hash(prev_finality_ref ‖ height)` | 冻结 |
| W-4 | `witness_count` protocol constant（V0.1 固定） | 冻结 |
| W-5 | `WitnessProof` + **`DomainId::Witness`**（新增） | 冻结 |
| W-6 | Witness ≠ finality authority（边界） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| NodeId/External → Witness | 不受 ValidatorSet 管理；越权（W-1） |
| VRF / 中心随机源 | 复杂度；Nova 确定性优先（W-2） |
| ratio-based witness count | 动态治理变量污染 V0.1（W-4） |
| 复用 ValidatorVote domain | Vote/Witness 语义不同须隔离（W-5） |
| Witness 参与 finality | 破坏 BFT ≥2/3 quorum 安全（W-6） |

## Consequences

- **正面**：确定性、可验证、与 BFT 边界清晰。
- **成本**：`DomainId::Witness` 扩展 ADR-0005 注册表。
- **可迁移**：动态 witness 数量未来 ADR。

## Security Impact

- 防随机操纵：确定性 seed/算法（W-2/W-3）。
- 防越权：Witness 受 ValidatorSet 管理 + 独立域签名（W-1/W-5）。
- 防 finality 污染：Witness 不参与 quorum（W-6）。
