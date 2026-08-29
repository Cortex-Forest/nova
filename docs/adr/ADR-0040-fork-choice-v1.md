# ADR-0040: Fork Choice V1（Draft）

- **Status**: Draft（STEP 10-8；待 Review 后冻结）
- **Date**: 2026-08-29
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（Fork Choice，10-8）
- 关联：ADR-0033（C-6 Finality-first fork choice）、ADR-0035（D-1~D-4 DAG）、ADR-0038（F-1 FinalityState /
  F-4 PrevoteQC=justification）、ADR-0036（W-6 Witness ≠ finality authority）、ADR-0039（CP-1~CP-8 Checkpoint）
- 前置：STEP 10-8 Design Review **APPROVED WITH REQUIRED MICRO-FREEZES**（FC-MF-1~FC-MF-5；
  O-1/O-2/O-3 裁决）
- **本 ADR 不修改**任何既有冻结 ADR 或代码。

## Context

10-1~10-7 已冻结 ValidatorSet / Vote / DAG / Witness / BFT Round / Finality / Checkpoint。C-6 冻结
finality-first fork choice 原则，但**具体算法从未冻结**。10-8 冻结 **Fork Choice**：未 final 时，在 DAG
候选中选择 canonical head；final 时返回 finalized reference。**必须消除「justified」「highest justified」
「fork-choice head」「DAG tip」「DAG root」的语义歧义**（本次 Review 核心）。

## Decision（冻结候选）

### FC-MF-1 — Justification Definition（冻结候选）

> **`Valid PrevoteQC(target = X)` ⇒ `X` is justified**（仅当 `X` 对应 DAG 中的 block reference）。

- **验证责任（方案 A 自验证）**：`fork_choice` 对每个提供的 `prevote_qc` 调用 `verify_qc`（Validity，
  ADR-0038 F-6a），仅接受 `Ok` 者作为 justification evidence。**不得**将仅结构上像 PrevoteQC 的未验证
  QC 当作 justification（方案 A/B 二选一，本 ADR 冻结 A——set/genesis_hash 入参因此必需）。
- `PrevoteQC` 仍为 justification evidence only（F-4），不产生 finality。

### FC-MF-2 — Highest Justified Ordering（冻结候选）

> **`higher(A, B)` iff `A` is a causal descendant of `B`**（仅用 DAG parent relation，FC-3）。
> **禁止**用 `height(A) > height(B)` 或 `round(A) > round(B)` 推导 higher。

- 若两个 justified blocks 互不为 descendant/ancestor ⇒ **incomparable**。
- incomparable justified candidates ⇒ FC-8（`block_hash` 字典序）tie-break。

### FC-MF-3 — Anchor vs Head Separation（冻结候选）

**两阶段模型**：
```
PrevoteQC(target=X) → justified anchor（X）
X 的 DAG descendants / tips → fork-choice head
```

- **QC 不要求直接存在于最终 selected tip**：例如 `A ← B ← C` 且 `QC(B)` ⇒
  `justified anchor = B`，`fork-choice head = C`。
- **FC-9（新）**：Fork-choice candidate head MUST be a DAG tip that is a **descendant** of the
  selected justified anchor（anchor 自身若是 tip 亦算），**除非**不存在 justified anchor。

### FC-MF-4 — Finalized Reference Integrity（冻结候选）

> `fork_choice` treats supplied `finalized_reference` as **trusted FinalityState output**, but
> requires it to exist in the supplied DAG（FC-7）。**Absence is deterministic invalid-input
> behavior（`None`）。**

- **FC-10（新）**：`finalized != None` ⇒ supplied reference MUST 对应 DAG block；否则返回 `None`。
- **不得让 Fork Choice 自己创造 Finality**（无第二套 finality rule；CP-5/F-15 原则延伸）。

### FC-MF-5 — Witness Exclusion（冻结候选）

> **Witness availability MUST NOT affect fork-choice output（V0.1）。**

- **从 API / consensus logic 删除 `witness_signal`**（O-2 裁决 B）。
- 更严格于"confidence"：`Witness ≠ confidence signal 进入排序`；它完全不参与 `fork_choice`（W-6）。

### O-1 / O-2 / O-3 裁决（冻结候选）

| OPEN | 裁决 |
|---|---|
| O-1 | **A，但重新定义**：`Valid PrevoteQC(target=X) ⇒ X justified`；"highest" 只按 DAG causal ancestry（FC-MF-2）；incomparable ⇒ hash tie-break（FC-8） |
| O-2 | **B**：Witness 完全不参与 Fork Choice；删除 `witness_signal` API（FC-MF-5） |
| O-3 | **A，但严格定义**：无 justified 时选择 DAG root；`root = zero-parent block`；多个 root ⇒ `block_hash` 字典序最小者（**禁 height 最小**） |

### FC 不变量集（冻结候选）

| # | 不变量 |
|---|---|
| FC-1 | finality-first：`finalized` 存在（且 ∈ DAG）⇒ 返回该 reference |
| FC-2 | 确定性：同输入 ⇒ 同输出 |
| FC-3 | 仅 DAG relation：ancestry 只用 `parents_of` 边；禁 height/round 推导 |
| FC-4 | Justified Definition（FC-MF-1） |
| FC-5 | Highest Justified = DAG causal relation（FC-MF-2） |
| FC-6 | 禁 longest-chain / highest-block-count（C-6.3） |
| FC-7 | 返回值 ∈ DAG（含 finalized 与 head 与 fallback） |
| FC-8 | 确定性 tie-break：`block_hash` 字典序 |
| FC-9 | Head = selected justified anchor 的 descendant DAG tip（FC-MF-3） |
| FC-10 | Finalized Reference Integrity（FC-MF-4） |
| FC-11 | Witness MUST NOT affect output（FC-MF-5） |

## Fork Choice 规则（冻结候选）

**API**：
```rust
pub fn fork_choice(
    dag: &Dag,
    finalized: Option<&[u8; 32]>,       // 信任的 FinalityState 输出（FC-10）
    prevote_qcs: &[QuorumCertificate],  // 逐条自验证（方案 A，FC-MF-1）
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
) -> Option<[u8; 32]>;
```

**规则流**：
```
① finalized 存在：
     ├─ finalized ∈ DAG ⇒ Some(finalized)（FC-1）
     └─ 否则 ⇒ None（deterministic invalid-input，FC-10；不创造 Finality）
② 收集 justified anchors：对每个 prevote_qc，verify_qc Ok 且 target ∈ DAG ⇒ anchor（FC-4）
③ 无 anchor ⇒ Some(DAG root)（root = zero-parent block；多 root ⇒ block_hash 字典序最小，O-3/A）
④ 选最高 anchor：higher(A,B) iff A causal descendant of B（FC-5）；incomparable ⇒ FC-8 tie-break
⑤ candidate heads = 该 anchor 的 descendant DAG tips（含 anchor 自身若为 tip）（FC-9）
⑥ 返回 head：多个 ⇒ FC-8 tie-break（block_hash 字典序最小）
```

## 边界

- 新模块 `crates/consensus/src/fork_choice.rs`（`nova-consensus`，纯计算）。
- 单向依赖 `fork_choice → {dag, finality, validator}`；无循环；不依赖 witness（FC-11）。
- 不接 storage/execution/network；不实现 GHOST 全量 / longest-chain / 跨节点传播 / node 层排序。

## 测试计划（候选）

| # | 用例 |
|---|---|
| T1 | finalized ∈ DAG ⇒ 返回 finalized（FC-1） |
| T2 | finalized ∉ DAG ⇒ None（FC-10，不创造 Finality） |
| T3 | `QC(B)`，`A←B←C` ⇒ anchor=B，head=C（FC-9，FC-MF-3 核心） |
| T4 | 无 justified ⇒ DAG root（多 root ⇒ block_hash 最小，O-3/A） |
| T5 | 多 justified：descendant 更高 ⇒ 选 descendant（FC-5） |
| T6 | incomparable justified ⇒ hash tie-break（FC-8） |
| T7 | 仅结构像 PrevoteQC 但 verify_qc 失败 ⇒ 不作 justified（FC-4，方案 A） |
| T8 | 构造 height 反例：高 height 非 descendant ⇒ 不选（FC-3/FC-MF-2） |
| T9 | 确定性：同输入同输出（FC-2） |
| T10 | 返回值 ∈ DAG（FC-7） |
| T11 | Witness 不改变输出（FC-11；API 无 witness 参数，结构保证） |
| T12 | proptest：随机 DAG + QC ⇒ 确定性 + ∈ DAG |

## Decision Log

| # | 决策 | 状态 |
|---|------|------|
| FC-1 | finality-first（final wins） | Draft 冻结候选 |
| FC-2 | 确定性 | Draft 冻结候选 |
| FC-3 | 仅 DAG relation | Draft 冻结候选 |
| FC-4 | Justified Definition + 方案 A 自验证（FC-MF-1） | Draft 冻结候选 |
| FC-5 | Highest = DAG causal（FC-MF-2） | Draft 冻结候选 |
| FC-6 | 禁 longest-chain/highest-block-count | Draft 冻结候选 |
| FC-7 | 返回值 ∈ DAG | Draft 冻结候选 |
| FC-8 | block_hash 字典序 tie-break | Draft 冻结候选 |
| FC-9 | Head = anchor descendant tip（FC-MF-3） | Draft 冻结候选 |
| FC-10 | Finalized Reference Integrity（FC-MF-4） | Draft 冻结候选 |
| FC-11 | Witness Exclusion（FC-MF-5） | Draft 冻结候选 |
| O-1/O-2/O-3 | 按裁决表冻结 | Draft 冻结候选 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| `height`/`round` 定义 highest | 违反 DAG relation 原则（FC-MF-2） |
| 仅返回 justified block（非 head） | 混淆 justification 与 fork-choice head（FC-MF-3） |
| Witness confidence 进入排序 | 共识语义被 availability 污染（FC-MF-5/O-2） |
| 无 justified 时选最小 height root | height 非 ancestry；DAG 多 root 需 hash tie-break（O-3） |
| 调用方预验证 QC（方案 B） | 验证责任模糊；方案 A 自验证更自包含（FC-MF-1） |

## Consequences

- **正面**：justified / highest / head / root 语义全部由 DAG relation + hash tie-break 定义，跨实现确定性；无 Witness 污染。
- **成本**：V0.1 简化（存在性 justification + causal 比较）；深度/权重累计比较延后。
- **可迁移**：未来 justified 权重/深度模型可经新 ADR 扩展，不破坏 head 选择结构。

## Security Impact

- 防实现分歧：FC-MF-1~5 + O-1~O-3 消除语义歧义。
- 防第二套 Finality：FC-10 不创造 Finality。
- 防 Witness 污染共识：FC-11。
- 防 height 冒充 ancestry：FC-3/FC-MF-2。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-29 | 初稿：10-8 Fork Choice 设计 + FC-MF-1~5 + O-1/O-2/O-3 裁决 + FC-1~FC-11 不变量 | STEP 10-8 Review APPROVED WITH REQUIRED MICRO-FREEZES |
