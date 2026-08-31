# ADR-0045 — Economic Protocol V1

- **Status**: **DRAFT**（PHASE 2 STEP 6-R32 初稿 + STEP 6-R36 M1 Micro-Fix 整合；**非 FROZEN**）
- **Type**: HOW — Economic Protocol Specification（经济状态机结构定义）
- **Freeze**: NONE · **Implementation**: NONE · **Commit**: NONE
- **依据**: STEP 6-A~6-E（ADR-0044 集成）+ 6-F~6-Q（toy 实验）+ 6-R1~6-R36（Closure 链 + Owner 签署 + M1 Micro-Fix）
- **前置**: ADR-0044（Sustainable Economy Model V1，DRAFT 边界层）· ADR-0043（PoC，FROZEN）· ADR-0042（Block Format，FROZEN）
- **References**: ADR-0014（Genesis Schema）· ADR-0016（Genesis Accounting）· ADR-0022（Gas/Fee）· ADR-0041（ProposalRef canonical serialization）

---

## 1. Context

- **为什么需要 Economic Protocol V1**：ADR-0044 建立了经济边界（Model A 独立 Reward Budget / Model R1 / Frozen Economic Boundary / Deterministic Math），但 HOW 层（GLID / Economic Epoch / Decay / Contribution / Pipeline / Remainder / Citation / Funding / Reward Source / Redistribution）的**协议结构定义**需要独立 ADR 承载。ADR-0044 保持 DRAFT 边界层；ADR-0045 定义经济状态机的可执行结构。
- **与 ADR-0044 的关系**：ADR-0045 继承 ADR-0044 的 Frozen Economic Boundary（total_supply cap 不可变 / burned_supply 不重入 reward / 无 Genesis unissued bucket / non-burn fee ownership UNDEFINED / Founder Allocation = 0）与已批准架构（Model A / Model R1 / Deterministic Math），并将经济设计链（STEP 6-R19~R36 Owner 签署）的结构决策固化。
- **当前问题边界**：定义抗 Sybil 的可验证经济状态机（GLID → Epoch → Decay → Contribution → Pipeline → Remainder → Citation），与共识层隔离；所有数值参数保持 OPEN。

## 2. Scope

**本 ADR 定义**：
```
· Economic Epoch（E-a state counter）语义边界
· GLID（G2 creator + lineage commitment）结构边界（含 Creation Boundary / Sybil Boundary / Cap Identity Binding）
· Decay（D2，GLID 聚合层）规则边界
· Contribution（aggregate-first + GLID 聚合 + unique id + dedup）
· Pipeline（Contribution → GLID Aggregation → Transformation → Decay → Rounding → Cap → Allocation → Remainder）
· Cap Ordering（SR-P3 = Score → Rounding → Cap）
· Remainder（R-c redistribution，RCB-C cap adjusted weight）
· Citation（B auxiliary + N3 verified + L1-only + epoch-scoped + bounded）
· Funding（F-B no reserve）与 Reward Source（R-C Hybrid Bounded）边界
· Redistribution Semantics（RCB-C）
· 经济不变量（E1~E6 / S1~S6 / B1~B5）
```

**本 ADR 不定义**：
```
· 任何数值参数（epoch length / reward amount / emission rate / cap value / decay constants /
  rounding precision / α / β / rate limit / citation weight —— 全部 OPEN，见 §9）
· GLID 最终字节布局 / hash domain 参数 / implementation details
· Consensus / Block / Transaction / State 格式修改
· Validator / Treasury 完整奖励定义（FUTURE ADR）
```

## 3. Design Principles

```
P1  Determinism        same economic state → same economic result（可重放）
P2  No hidden inflation    不创造 supply · 不突破 total_supply cap · burned 不重入（EBI-4）
P3  No team reserve    Founder Allocation = 0 · Funding = F-B no reserve
P4  Mobile verification    状态有界 · 验证成本有限 · 可重建
P5  Replayability      same state → same weight → same allocation → same remainder
P6  L1-only            经济评估仅依赖 protocol-verifiable facts（ADR-0043）
P7  Economic Epoch ≠ Consensus Epoch（禁绑 block/round/wall-clock）
P8  No oracle / off-chain / subjective（Deterministic Math）
```

## 4. Economic Pipeline Specification

```
Contribution
   ↓ (unique contribution_id · dedup / already-paid · aggregate-first)
GLID Aggregation
   ↓ (G2 creator + lineage commitment · immutable snapshot · GCB-B 创建约束)
Transformation
   ↓ (canonical ordering · integer/fixed-point · checked)
Decay
   ↓ (D2 epoch decay · age = Economic Epoch distance · 作用于 GLID 聚合权重
      · floor / duration 机制存在，数值 OPEN)
Rounding
   ↓ (canonical rounding last · deterministic · conserving)
Cap
   ↓ (SR-P3: Score → Rounding → Cap · per-share cap 严格 ≤ cap_r
      · cap-induced remainder 不回流 · Cap 绑定 verified GLID identity)
Allocation
   ↓
Remainder Redistribution
   ↓ (R-c redistribution · RCB-C cap adjusted weight · epoch-scoped eligible set
      · cap-induced remainder 不回流)
```

**关键顺序约束（不可交换）**：
- GLID Aggregation 在 Transformation 前（aggregate-first）
- Decay 在 GLID Aggregation 后（GLID 层衰减）
- Rounding 在 Cap 前（SR-P3：Score → Rounding → Cap）
- Cap 在 Allocation 前
- Remainder Redistribution 在 Allocation 后
- Conservation：`allocated + remainder = budget`

## 5. GLID Specification Boundary

```
· Identity model:          creator + lineage commitment（SR-G1 = B）
· Lineage commitment:      L1 可验证贡献溯源链（membership = contribution lineage）
· Canonical serialization: creator + lineage + membership commitment；canonical ordering；L1-only
                           （排除 metadata / subjective / oracle）
· Mutation policy:         immutable forever（SR-G3 = A；cross-epoch 稳定）
· Mobile verification:     bounded state · reconstructable · deterministic replay（SR-G4）
· GLID Creation Boundary（SR-G5 = GCB-B — Verified Lineage Creation）：
      GLID 创建必须以 L1 verifiable lineage 为前提；
      禁止任意 GLID 创建（设计依据：E-GLID-1 per-GLID cap 线性放大 16× 风险）
· GLID Sybil Boundary（SR-G6）：GLID 数量增长不得产生额外经济权重
      （identity 数量 ≠ economic power；防 K-GLID 分裂攻击）
· Cap Identity Binding（SR-G7）：cap 绑定 verified GLID economic identity
      （cap 不绑定 arbitrary identifier；对真实经济主体生效）
· 暂不包含：最终字节布局 · hash domain 参数 · implementation details
```

## 6. Reward Source Boundary

```
· Reward ≠ Funding（SR-RS2；Model A 独立预算）
· Reward Source（SR-RS1 = R-C Hybrid Bounded）：
      bounded emission + fee source separation + reward accounting independent + no hidden reserve
· Funding（SR-F1 = F-B No Funding Reserve）：
      Funding ≠ Reward · No hidden inflation · Immutable/bounded · No genesis bucket
· Supply Boundary（SR-RS3）：不突破 total_supply cap · no hidden inflation · burned 不重入
· Emission Authority（SR-RS4）：Immutable/bounded · 禁治理动态 mint
· Genesis Relation（SR-RS5）：不形成 Genesis 新供应桶
· 禁止：hidden reserve · discretionary mint · genesis unissued bucket
```

## 7. Redistribution Specification

```
· Base（SR-RC1 = RCB-C）：cap adjusted weight
· Eligible set（SR-RC2）：本 Economic Epoch 内有有效分配权重的 GLID participant（epoch-scoped；不跨 epoch）
· Cap interaction（SR-RC3）：cap-induced remainder 不回流；仅 rounding-induced remainder 进入 redistribution
· Sybil resistance（SR-RC4）：GLID aggregated weight；不使用 participant count
· Determinism（SR-RC5）：canonical ordering + deterministic integer accounting；same input → same redistribution
```

## 8. Security Analysis

| 攻击 | 防御（已锁） | 状态 |
|---|---|---|
| Sybil（identity split / GLID 创建滥用 / contribution fragmentation） | GLID 聚合（G2）+ **GCB-B Verified Lineage Creation（M1）** + Contribution ID + dedup + aggregate-first | PASS |
| Whale（extreme contributor / cap bypass / normalization dilution） | SR-P3（Score→Rounding→Cap）严格 per-share cap | PASS |
| Citation Farming（self / circular / mutual） | Citation = B auxiliary + N3 verified + L1-only（N3 压回放大 1.0） | PASS |
| Funding Capture（hidden reserve / team allocation） | F-B no reserve + F3 no hidden inflation | PASS |
| Governance Capture（discretionary mint / mutable rules） | F4 Immutable/bounded + reward rule-based deterministic | PASS |
| Replay Attack | canonical ordering + integer accounting + rounding rule（same state → same result） | PASS |

## 9. Open Parameters（全部 OPEN，AI 不得决定）

```
epoch length · epoch mapping · reward amount · emission rate · cap value(s)
· decay constants · decay floor · decay duration · α · β
· rounding precision · rate limit · citation weight
· GLID serialization 字节布局 / hash domain 参数（后续实现设计阶段）
—— 全部为 Open Parameters（占位），由 Owner 在参数化阶段裁决
```

## 10. Compatibility

```
· 不修改 ADR-0001 ~ ADR-0044（含 ADR-0042 Block FROZEN / ADR-0043 L1-only / ADR-0044 边界）
· 不新增 Block / Transaction / State 字段（经济状态为评估层派生）
· 不修改 consensus / block / state / transaction
· 仅引用已有结构（ADR-0041 canonical serialization · ADR-0022 fee · ADR-0016 accounting · ADR-0014 Genesis）
```

## References

- ADR-0044（Sustainable Economy Model V1，DRAFT 边界层）· ADR-0043（PoC，FROZEN）· ADR-0042（Block，FROZEN）
- ADR-0014（Genesis Schema）· ADR-0016（Genesis Accounting）· ADR-0022（Gas/Fee）· ADR-0041（Canonical Serialization）

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿 Draft：基于 STEP 6-R31 Creation Gate READY + 全部 Owner 签署结构（6-R19~R30） | STEP 6-R32（CONTROLLED DESIGN） |
| 2026-08-31 | **M1 Micro-Fix 整合**：GLID Creation Boundary（SR-G5 = GCB-B Verified Lineage Creation · SR-G6 GLID 数量不增权重 · SR-G7 Cap 绑定 verified GLID identity）纳入 §5/§8 | STEP 6-R36（Micro-Fix Integration Review） |

**Status 保持 DRAFT（非 FROZEN）** · 不定义数值参数 · 不修改 consensus/block/state/transaction。
