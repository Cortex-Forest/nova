# Nova Chain — Fork Choice Implementation Design V1（10-8.1）

- **Status**: **Frozen**（STEP 10-8.1 DESIGN FREEZE；**STEP 10-8.2 IMPLEMENTATION FINAL FREEZE**，2026-08-29）
- **Date**: 2026-08-29
- **Scope**: Fork Choice 的**实现设计**（API、语义分层、maximal anchor、frontier、测试计划）。
- **依据**：ADR-0040 FC-1~FC-14（FROZEN）、ADR-0038 F-2/F-6a（verify_qc/QC Validity）、
  ADR-0035 D-1~D-4（DAG）。
- 前置：10-8.1 Review APPROVED WITH 2 REQUIRED MICRO-FREEZES（FC-MF-9/FC-MF-10 + T17/T18 + Frontier 数学化）→
  **FINAL REVIEW APPROVED / READY TO FREEZE**
- **本文件是设计契约，不是代码实现**。实现（10-8.2）必须严格遵循本契约。

---

## 0. 核心不变量（FC-1~FC-14 总纲）

| # | 不变量 |
|---|---|
| FC-1 | finality-first（final wins） |
| FC-2 | 确定性（同输入同输出，**不依赖输入顺序**） |
| FC-3 | 仅 DAG relation（禁 height/round 推导 ancestry） |
| FC-4 | Justified Definition + 方案 A 自验证 |
| FC-5 | Highest = DAG causal relation |
| FC-6 | 禁 longest-chain / highest-block-count |
| FC-7 | 返回值 ∈ DAG |
| FC-8 | `block_hash` 字典序 tie-break |
| FC-9 | Head = selected anchor 的 descendant DAG tip |
| FC-10 | Finalized Reference Integrity（invalid-input ⇒ `None`） |
| FC-11 | Witness MUST NOT affect output |
| FC-12 | Finality Dominance（绝对短路） |
| FC-13 | Justification DAG Membership（QC validity ≠ DAG applicability） |
| FC-14 | Anchor-Scoped Head Selection（causal-descendant frontier） |

---

## 1. API Contract

```rust
pub fn fork_choice(
    dag: &Dag,
    finalized: Option<&[u8; 32]>,       // 信任的 FinalityState 输出（FC-10）
    prevote_qcs: &[QuorumCertificate],  // 逐条自验证（方案 A，FC-13）
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
) -> Option<[u8; 32]>;
```

- 新模块 `crates/consensus/src/fork_choice.rs`（`nova-consensus`，纯计算、无状态）。
- **无 witness 参数**（FC-11）、**无 canonical serialization**（纯计算结果，无独立协议对象）。

## 2. Input Validity / Error Semantics

**决策：不引入 `ForkChoiceError`，保持 `Option<[u8;32]>`**（ADR-0040 冻结；`verify_qc` 失败 / target∉DAG 是**过滤**非错误）。

**`None` 三语义（契约层明确）**：

| 情形 | 语义 |
|---|---|
| `finalized = Some(f)` 且 `f ∉ DAG` | deterministic invalid-input（FC-10；调用方契约违规） |
| DAG 空 + 无 finalized + 无 justified | 正常无候选（O-3 边界） |
| 其他无 head | 正常无候选 |

- 不 panic、不构造 synthetic genesis、不返回哨兵 hash。

## 3. Finality Dominance（FC-12 绝对短路）

```rust
if let Some(f) = finalized {
    if !dag.contains(f) { return None; }   // FC-10 invalid-input
    return Some(*f);                        // FC-12：不比较任何非 final 候选
}
```

## 4. FC-MF-9 — QC Validity / DAG Applicability Boundary（必须冻结）

**两层严格分离（不得绑定成单一"重复检查"）**：

```
Layer 1 — QC Validity = verify_qc(...)
    （签名 / quorum / context / genesis / structural；authoritative QC validation boundary）

Layer 2 — Fork-Choice Applicability =
    qc.context.vote_type == Prevote
        && dag.contains(qc.target)
    ⇒ Justified Anchor
```

- **`fork_choice` treats `verify_qc` as the authoritative QC validation boundary；`dag.contains(target)`
  is retained as an explicit applicability guard, even if currently redundant, and does NOT introduce
  a new QC validity rule.**（不修改 ADR-0038 / `verify_qc`。）
- **不得**把这两层重新定义成新的 finality rule；QC invalid 与 valid-but-not-applicable 都必须
  **过滤**（不作 anchor），且互不影响。

## 5. Justified Anchor Collection（FC-13 + MF-9）

```rust
// 对每个 prevote_qc（顺序无关，结果与输入顺序无关，见 §6）：
fn is_justified_anchor(qc, set, genesis_hash, dag) -> Option<[u8;32]> {
    // Layer 1（MF-9）：QC Validity（verify_qc 内含 target∈DAG 检查——authoritative boundary）
    verify_qc(qc, set, genesis_hash, dag).ok()?;
    // Layer 2（MF-9）：Applicability guard（显式，即使与 verify_qc ① 重叠）
    if qc.context.vote_type != VoteType::Prevote { return None; }   // FC-2/FC-4
    if !dag.contains(&qc.target) { return None; }                    // FC-13
    Some(qc.target)
}
```

## 6. FC-MF-10 — Maximal Justified Anchor Determinism（必须冻结）

> **`highest justified` 必须定义为 DAG causal partial order 下的 maximal justified anchors**：
> ```
> MaximalJustifiedAnchors =
> { A ∈ justified : there exists no B ∈ justified
>   such that A is a proper causal descendant of B }
> ```

- `len == 1` ⇒ 选择该 anchor；
- `len > 1`（incomparable）⇒ **`block_hash` 字典序最小**（FC-8）；
- **结果不得依赖 `prevote_qcs` 输入顺序**：
  - **禁止**"遍历替换"式 `for qc { if higher(candidate, selected) { selected = candidate } }`（会因输入顺序产生 first/last wins）；
  - **禁止** iteration order / insertion order 参与选择（FC-2）。

**示例**：`A├C └D`，`QC(A),QC(C),QC(D)` ⇒ `Justified={A,C,D}`，`Maximal={C,D}`（C∥D），`select min_hash(C,D)`。

## 7. Causal-Descendant Frontier（FC-14 数学化定义）

```
Frontier(A) =
{ x ∈ DAG |
    (x == A  OR  A is a proper causal ancestor of x)
  AND
    x has no causal descendant y satisfying (A is ancestor of y) }
```
即 **A 的 causal-descendant subtree 的 maximal elements**（A 自身若为该 subtree 的叶子也纳入）。

```
head = min_hash(Frontier(A))          // FC-8
```

- **实现**：对 `dag.tips()` 中每个 tip，用 DFS（`dag.parents_of` 回溯）判断 `A` 是否可达；`A` 自身若为 tip 也纳入。
- **禁退化**：不得用最高 height / 最大 round / 最多 descendants / 全 DAG tips / insertion / iteration（FC-14）。
- **subtree 外 block 不得竞争**（FC-14）。

## 8. Root Fallback / Empty DAG（O-3）

| 边界 | 行为 |
|---|---|
| 无 justified + DAG 非空 | `root = zero-parent block`（`parents_of(h) == []`）；多 root ⇒ `block_hash` 最小 |
| 无 justified + DAG 空 | `None`（不 panic） |
| 空 `prevote_qcs` | 无 anchor ⇒ root fallback（或 `None` if 空 DAG） |

## 9. Module Dependency Boundary

- `fork_choice → { dag（Dag/parents_of/tips/contains）, finality（verify_qc/QuorumCertificate）, validator（ValidatorSet）, vote（VoteType） }`——**单向，无循环**。
- 本地实现 causality DFS（不复用 `finality.rs` 私有函数；**不改 finality.rs**）。
- 不依赖 witness / checkpoint / storage / execution / network；不引入新 consensus state（不保存 head、不改 FinalityState、不产生 finality/QC）。

## 10. Test Plan（T1~T18 + adversarial）

**T1~T16（ADR-0040）**：finality-first / finalized∉DAG→None / anchor-head（`QC(B), A←B←C` ⇒ anchor=B head=C）/ root 多 root hash 最小 / descendant 更高 / incomparable hash tie-break / 伪 PrevoteQC verify 失败 / height 反例 / 确定性 / ∈DAG / witness 无参数 / proptest / T13 finality dominance / T14 target∉DAG / **T15 anchor-scoped frontier** / T16 empty DAG→None。

**T17 — QC validity / applicability boundary（FC-MF-9）**：
```
QC invalid                → ignored（不作 anchor）
QC valid + target ∉ DAG   → ignored（applicability guard）
QC valid + Prevote + target ∈ DAG → justified
```
（验证 `verify_qc` 失败与 valid-but-not-applicable 均被过滤，且不混成新 finality rule。）

**T18 — Input-order determinism（FC-MF-10，攻击输入顺序）**：
```
        C
       /
A ----
       \
        D
QC(C), QC(D)，C ∥ D
输入 [C,D] 与 [D,C]
⇒ fork_choice(...) == 相同结果 == min(hash(C), hash(D))
```
（直接捕获 first-wins / last-wins / iteration-order 类漏洞。）

**Adversarial（补充）**：
- A1 finality 绝对短路：更深 justified 不覆盖 finalized。
- A2 frontier 禁退化：height 更大 / descendants 更多的 subtree 外 branch 不入选。
- A3 多 QC 过滤：一个 anchor 无效不影响另一有效 anchor。
- A4 空 prevote_qcs + 非空 DAG ⇒ root。
- A5 proptest：随机 DAG + QC 集 ⇒ 确定性 + ∈DAG + frontier ⊆ anchor subtree。

## 11. Implementation Prohibitions

```
FORBIDDEN:
1. Do not introduce ForkChoiceError / Result (keep Option; ADR-0040).      (§2)
2. Do not use height/round/block_count/insertion/iteration order in any
   selection (anchor, maximal, frontier, head, root).                      (FC-3/FC-8/FC-14)
3. Do not let QC/anchor override finalized (FC-12 absolute short-circuit).  (FC-12)
4. Do not bind QC validity and DAG applicability into a single check that
   creates a new QC validity rule; verify_qc is authoritative, dag.contains
   is an applicability guard.                                             (FC-MF-9)
5. Do not select "highest justified" by iteration-order replacement;
   use MaximalJustifiedAnchors + hash tie-break (input-order independent).  (FC-MF-10)
6. Do not use a QC as anchor unless verify_qc Ok AND vote_type==Prevote
   AND target∈DAG.                                                        (FC-13)
7. Do not let non-anchor-subtree blocks compete for head.                   (FC-14)
8. Do not introduce new consensus state / modify FinalityState / create
   finality or QC.                                                        (§9)
9. Do not add witness to API/logic.                                        (FC-11)
10. Do not add canonical serialization.                                    (§1)
11. Do not connect storage/execution/network.
12. Do not modify dag.rs / finality.rs / vote.rs / validator.rs / error.rs
    / any frozen ADR (incl. ADR-0038 / ADR-0040).
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-29 | 初稿：10-8.1 Fork Choice 实现设计 + FC-MF-9（QC validity/applicability boundary）+ FC-MF-10（Maximal Justified Anchor determinism）+ T17/T18 + frontier 数学化 | 10-8.1 Review APPROVED WITH 2 REQUIRED MICRO-FREEZES |
| 2026-08-29 | **DESIGN FREEZE**：Status → Frozen（10-8.1） | FINAL REVIEW APPROVED / READY TO FREEZE |
| 2026-08-29 | **IMPLEMENTATION FINAL FREEZE（10-8.2）**：`crates/consensus/src/fork_choice.rs`（commit `30bf98c`）+ `lib.rs` 注册；T1~T18 + A1~A4 + proptest 全 PASS；四项 Gate PASS；源码级 Security Review APPROVED（0 BLOCKER / 0 MUST-FIX） | Security / Protocol Review 最终裁决 APPROVED |
