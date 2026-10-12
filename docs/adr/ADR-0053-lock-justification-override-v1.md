# ADR-0053: Lock Justification & Override Semantics V1

- **Status**: FROZEN（STEP 10-15D-F FINAL FREEZE，2026-09-04；经 STEP 10-15D-R1 Semantic Review PASS，处理观察项 O1~O5。本 ADR 兑现 ADR-0037 B-5 预留 deferred 的 Lock Justification & Override 语义）
- **Date**: 2026-09-04
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（Lock Justification & Override Semantics）
- 关联：ADR-0033（C-5 weighted ≥2/3 quorum）、ADR-0035（D-1~D-3 DAG ancestry）、ADR-0037（B-5
  LockedState + Lock 兼容 + override 延后授权）、ADR-0038（F-4 PrevoteQC=justification /
  PrecommitQC=finality；F-7 Lock Acquisition；F-8 Applicability；F-9 valid-but-inapplicable；
  F-11 ValidatorSet identity；F-17 Safety）、ADR-0040（FC-MF-1 Fork Choice justification；
  FC-13/FC-14）、ADR-0041（ProposalRef canonical serialization）、ADR-0049（Liveness /
  Pacemaker；timeout MUST NOT unlock）、ADR-0050（Proposer Selection ≠ Lock Override Authority）、
  `docs/protocols/consensus-spec-v1.md`
- 前置：STEP 10-15B-DESIGN（BLOCKED：Local Vote Boundary Missing + Justified Descendant
  unresolved）、STEP 10-15C-DESIGN（BLOCKED：Lock justification / higher-round override
  unresolved）、STEP 10-15C-ADR-DESIGN（READY FOR OWNER REVIEW）、STEP 10-15C-ADR-SEMANTIC-REVIEW
  （READY WITH OWNER DECISION）→ Owner 发布 STEP 10-15D，批准 DECISION A/B/C/D 并授权创建本 ADR
- **本 ADR 不修改**任何既有冻结 ADR / consensus-spec / Rust 源码 / 测试 / Node / Network /
  Genesis。仅作为 ADR-0037 B-5 预留但未定义的 Lock semantics 的**补充协议权威**（兑现 B-5
  行 74 的 deferred 授权）。

## Context

ADR-0037 B-5 冻结 `LockedState` 基本安全语义：precommit quorum 触发 `lock(block_hash, round)`；
之后只投 same block / descendant；unrelated branch reject；"higher justified override 归 10-6 +
Consensus spec"。ADR-0038（10-6）只冻结了 **Finality**（PrecommitQC → Finalized）与 **Lock
Acquisition**（F-7：valid PrecommitQC → Lock），未定义 lock compatibility 粒度、justified
descendant 谓词与 higher-round override；consensus-spec §1.4/§13 将 lock 标 ASSUMPTION（GAP D）、
enforcement DEFERRED。本 ADR 冻结这些语义，为后续 Lock Enforcement 提供协议依据，并严格保持
**FinalityState 与 LockedState 的语义分离**。

## Problem

- ADR-0037 已定义 `LockedState` 的基本安全语义，但：
  - `descendant` 的精确定义（immediate parent vs full transitive DAG ancestry）未明确；
  - `justified descendant` 的语义未冻结（B-5 行 71「justified extension」vs 行 73「descendant」
    内部张力）；
  - `higher-round override` 未冻结（B-5 行 74 承诺未兑现）；
  - `PrevoteQC` / `PrecommitQC` 在 Lock 中的职责需明确（F-7 只覆盖 acquisition）；
  - **Lock 与 FinalityState 必须保持语义分离**（lock 是 validator-local 投票约束，不是全局
    finality 的别名）。

## Decision

### Core Principle — FinalityState ≠ LockedState（MUST BE EXPLICIT）

```text
FinalityState != LockedState
```

```text
Valid PrecommitQC
        |
        +----> FinalityState（consensus state，共享、可观察、可重放）
        |
        +----> validator-local LockedState（本节点未来投票约束）
```

**FinalityState**：属于共识状态（`ConsensusState{round, finality}`，MF-1；integration.rs）。由
**有效且适用**的 PrecommitQC 推进（F-8 Advance/Idempotent；unrelated ⇒ Conflict 不更新）。网络
可观察、可验证、可重放。

**LockedState**：属于 **validator-local state**（B-5/F-7/integration 设计 v1 O-4；不在
ConsensusState / Integration pipeline）。只约束 **当前 validator 自己未来产生的 vote**。
LockedState **绝对不能用于拒绝其他 validator 的远程 Vote**——这是本 ADR 的安全性核心。

### L-1 — Lock Is Validator-Local

```text
L-1:
LockedState is validator-local.

A validator's local lock constrains only that validator's
future vote production.

A remote Vote MUST NOT be rejected merely because it conflicts
with the receiving node's local LockedState.
```

```text
Remote Vote:
authentication
→ validator membership
→ duplicate/conflict detection
→ accumulator
→ QC processing

Local Vote:
local lock compatibility
→ vote construction
→ signing
→ broadcast
```

> The remote Vote processing sequence is descriptive context only.
> This ADR does not define or implement a new double-vote detection,
> equivocation, or slashing mechanism.（O4：Non-Goals 保持 double-vote detection / slashing
> 不属本 ADR。）

本 ADR 不负责定义 Local Vote Actor / Node architecture（Non-Scope，见 L-12）。

### L-2 — FinalityState and LockedState Are Separate

```text
L-2:
FinalityState and LockedState are distinct state machines.

A valid AND applicable PrecommitQC may simultaneously:

1. advance global FinalityState (only when applicable per
   ADR-0038 F-8; an unrelated PrecommitQC is Conflict and does
   NOT advance FinalityState), and
2. provide the evidence from which the local validator may
   acquire/advance its LockedState.

This does not make FinalityState and LockedState equivalent.
This MUST NOT be read as "every valid PrecommitQC automatically
advances every node's lock".
```

**禁止**写成：

```text
lock == finality
```

或：

```text
LockedState is global finality
```

### L-3 — Lock Acquisition Source

```text
L-3:
A validator may acquire or advance its local lock only from
a valid PrecommitQC satisfying the applicable height,
round, validator-set, domain, signature and quorum requirements.
```

```text
PrevoteQC does NOT acquire a lock.
```

（Lock Acquisition 唯一协议证据 = valid PrecommitQC，ADR-0038 F-7。）

### L-4 — Full DAG Ancestry

```text
L-4:
Lock compatibility uses full transitive DAG ancestry.

For locked block L and candidate C:

Compatible(L,C)
    iff
C == L
OR
L is an ancestor of C in the DAG.
```

即：

```text
L
|
A
|
B
|
C
```

则：

```text
L -> A = compatible
L -> B = compatible
L -> C = compatible
```

**不能只检查**：

```text
parents(C) contains L
```

（round.rs `LockedState::is_compatible` 的 immediate-parent 检查是 V0.1 简化，**不升格为协议**；
完整闭包 `is_dag_ancestor(L, C)` 与 ADR-0038 F-8 Finality applicability 使用同一 DAG ancestry
关系。确定性边界：unknown hash / missing parent ⇒ not-ancestor ⇒ not compatible；DAG 无环由
`dag.rs add_block` 的 `parent.height < height` 保证，helper 仍以 visited 集防御。）

### L-5 — JustifiedDescendant V1

```text
L-5:
For V1:

JustifiedDescendant(L,C)
    iff
C == L
OR
L is an ancestor of C in the DAG.
```

明确：**"justified" 在此处不是指 Fork Choice 的 PrevoteQC justification。V1 不要求额外
PrevoteQC。** justification 由 L 自身的 valid PrecommitQC（L-3/F-7）继承传递；不引入 per-C QC；
Fork Choice justification 不自动成为 Lock justification。

### L-6 — PrevoteQC Role

```text
L-6:
PrevoteQC is fork-choice justification only in V1.

PrevoteQC MUST NOT:

- acquire a local lock;
- advance a local lock;
- unlock a validator;
- override an unrelated local lock;
- establish finality.
```

必须保持：

```text
Fork Choice justification
!= 
Lock acquisition
!= 
Finality
```

（PrevoteQC = justification evidence only，ADR-0038 F-4 / ADR-0040 FC-MF-1；不产生 finality。）

### L-7 — PrecommitQC Role

```text
L-7:
PrecommitQC is the finality evidence defined by ADR-0038.

A valid applicable PrecommitQC may:

1. advance FinalityState, and
2. serve as the evidence for local lock acquisition/advance.
```

但：

```text
PrecommitQC does NOT automatically grant unrelated-lock override authority.
```

（Finality evidence：ADR-0038 F-4/F-5。Lock Acquisition evidence：F-7。两 effect 语义分离，L-2。
仅 valid AND applicable 的 PrecommitQC 推进 FinalityState——validity 不自动等于 applicability，
F-8/F-9；不得读作 "every valid PrecommitQC automatically advances every node's lock"，O2。）

### L-8 — Lock Advance Rule

```text
L-8:
A local lock may advance only when the PrecommitQC target is:

1. the same block as the current lock; or
2. a descendant of the current locked block under full DAG ancestry.
```

因此：

```text
same block       => ALLOW
descendant       => ALLOW
unrelated branch => NO LOCK ADVANCE
```

如果 QC 在密码学/协议层面有效，但与本地 Lock 不兼容：

必须称为：

```text
valid but inapplicable to local lock advancement
```

而不是：

```text
invalid QC
```

证据必须保留（ADR-0038 F-9/F-13：valid-but-inapplicable ≠ invalid；保留供 equivocation /
slashing / safety analysis）。

### L-9 — Higher-Round Override

```text
L-9:
V1 defines no unrelated higher-round lock override.

A higher round alone does not invalidate or clear a local lock.

A higher-round PrevoteQC does not override the lock.

A higher-round PrecommitQC does not override an unrelated lock.

A future higher-round override mechanism requires a separate ADR.
```

（round 本身无 unlock/override authority：ADR-0049 round change MUST NOT unlock。Tendermint 式
PrevoteQC-based higher-round release 需新 ADR + F-17 延后的 A-sync-before-conflicting-vote
同步边界，V1 不引入。）

### L-10 — Timeout / Round Change / Proposer Change

```text
L-10:
Timeout MUST NOT unlock a validator.

Round change MUST NOT unlock a validator.

Proposer change MUST NOT unlock a validator.

LockedState survives timeout and round transitions.
```

明确：

```text
Pacemaker != Lock Override
Proposer Selection != Lock Override
```

ADR-0049 与 ADR-0050 不获得 Lock override authority。

### L-11 — Isolation

```text
L-11:
Lock semantics are isolated by:

- height;
- validator set;
- vote domain;
- vote type;
- applicable protocol context.
```

必须确保：

```text
lock at height H
```

不能影响：

```text
height H+1
```

并且 foreign validator-set evidence 不能推进本地 lock（validator_set_id == genesis_hash，
ADR-0038 F-11；vote context guard 10-5.1 绑定 (height, round)；vote_type 在 canonical payload +
QC context，F-3——PrevoteQC 不可伪装 PrecommitQC 或反之）。

### L-12 — Safety Boundary

```text
L-12:
Lock enforcement is a local vote-production safety rule.

It MUST NOT be implemented as a blanket rejection rule
for remote Vote ingestion.
```

本 ADR 不定义：

- Local Validator Actor architecture；
- SigningKey ownership；
- SelfVote event；
- double-vote detection；
- slashing；
- node orchestration；
- network transport。

这些属于后续独立 STEP。

## Safety Invariants（FL）

| # | Invariant | 来源 |
|---|-----------|------|
| FL-1 | FinalityState 不因某 validator 的 local lock 改变 | L-2 / MF-1 |
| FL-2 | LockedState 不因 timeout 自动解除 | L-10 / ADR-0049 |
| FL-3 | LockedState 不因 proposer change 自动解除 | L-10 / ADR-0050 |
| FL-4 | Remote Vote ingestion 不使用本节点 LockedState 作为拒收条件 | L-1 / L-12（P0） |
| FL-5 | PrecommitQC 可作为 Lock Acquisition evidence | L-3 / F-7 |
| FL-6 | PrecommitQC 可作为 Finality evidence | L-7 / F-4 |
| FL-7 | 两 effect（Finality vs Lock）语义分离 | L-2 |
| FL-8 | unrelated PrecommitQC 不得自动成为 local lock override | L-8 / L-9 |

**Local Lock Safety（论证）**：由 L-8 直接保证——本地 LockedState 只能推进到 same block 或 full
transitive DAG descendant；unrelated valid PrecommitQC 不能替换本地 lock（L-8/L-9/FL-8）。该保证由
本地 lock 状态机规则自身成立，即使存在 byzantine 行为也成立；它只约束本 validator 自己。

**Global Finality Safety（论证）**：由 ADR-0038 治理——valid PrecommitQC 的 quorum / signature 假设
（F-17）：同 context 两个 conflicting ≥2/3 证据集交集 ≥1/3 含 ≥1 honest，其双投违反 H2 ⇒ 矛盾；
跨 round unrelated finality 由 honest lock 遵守（H3）封死。它**独立于任何单个 validator 的本地
LockedState 是否存在**。

**QC Safety（论证）**：同 context 两个 conflicting PrecommitQC 需 2/3+2/3 > total，honest 单投
（H2）约束下矛盾（ADR-0038 F-17）；跨 round unrelated finality 由 H3（honest 只投 lock/descendant）
封死。

**Override Safety（论证）**：V1 无 unrelated override（L-9）⇒ honest 永不投 unrelated ⇒ 永不成为
conflicting PrecommitQC 的 2/3 之一。FinalityState 层对 unrelated PrecommitQC 返回
valid-but-inapplicable（F-9，不更新）；LockedState 层保持本节点承诺（L-8/L-9）。两层分离，互不
以对方为权威，亦不把 local state 当作 global consensus state。

**禁止的两种误读（O5）**：
- Local lock safety 不得被读作 "proves global finality safety"；
- LockedState 不是 finality 的来源（finality 来源 = valid AND applicable PrecommitQC，
  ADR-0038 F-4/F-5）。

## Decision Matrix（REQUIRED）

Scope note:

All ALLOW / REJECT / NO UNLOCK / NO ADVANCE results in this matrix
describe the effect on the local validator's LockedState or the
local validator's own vote production.

They do NOT define a blanket rejection rule for remote Vote ingestion.
（O3：与 L-1 / L-12 一致。）

| Situation | Result |
|---|---|
| same block | ALLOW |
| direct descendant | ALLOW |
| deep DAG descendant | ALLOW |
| unrelated block | REJECT for local lock advancement |
| unrelated + PrevoteQC | REJECT for local lock advancement |
| unrelated + PrecommitQC | REJECT for local lock advancement |
| higher round only | NO UNLOCK |
| higher-round PrevoteQC | NO UNLOCK |
| higher-round unrelated PrecommitQC | NO UNRELATED OVERRIDE |
| timeout | NO UNLOCK |
| proposer change | NO UNLOCK |
| foreign validator set | REJECT |
| cross-height evidence | REJECT |
| invalid QC | REJECT |
| valid but locally inapplicable QC | preserve evidence; no local lock advancement |

## Non-Goals

```text
This ADR does NOT implement:

- LockedState wiring;
- ConsensusState modification;
- local validator identity;
- local vote actor boundary;
- Vote signing;
- double-vote detection;
- slashing;
- DAG helper implementation;
- network behavior;
- timeout implementation;
- proposer implementation;
- fork-choice changes;
- finality algorithm changes;
- Genesis changes.
```

## Implementation Consequences

The existing `acquire_lock` helper MUST NOT be wired directly into
production lock enforcement without implementing the L-8 advance guard.

Before production wiring:

1. the PrecommitQC MUST be valid;
2. the target MUST satisfy the applicable height / validator-set /
   protocol-context requirements;
3. if a local lock already exists, the target MUST be the same block
   or a full transitive DAG descendant of the currently locked block;
4. an unrelated valid PrecommitQC MUST NOT advance or replace the
   local LockedState;
5. a valid but locally inapplicable PrecommitQC remains valid evidence
   and MUST NOT be relabeled as an invalid QC.

（O1：本约束为 ADR 设计约束；本 ADR 不修改 `finality.rs` / `acquire_lock()`。LockedState wiring
属后续独立实现 STEP。）

## Dependencies

```text
ADR-0037 — Round & Lock Semantics
ADR-0038 — Finality / PrecommitQC
ADR-0040 — Fork Choice
ADR-0049 — Liveness / Pacemaker
ADR-0050 — Proposer Selection
```

> **ADR-0053 does not redefine those ADRs.** 本 ADR 作为 ADR-0037 B-5 预留 deferred 语义的兑现
> 权威；不改写冻结文本。

## Important Semantic Warning（P0 Safety Boundary）

```text
A receiving validator MUST NOT use its own LockedState
to reject a remote validator's Vote.

LockedState is an authorization constraint on local vote
production, not a remote vote validation rule.
```

## Compatibility

- ADR-0037：NO CHANGE。B-5「higher justified override 归 10-6 + Consensus spec」的 deferred
  授权由本 ADR 兑现为「V1 无 unrelated higher-round override（仅 descendant advance）」——是
  兑现 deferred 语义，非改写 B-5；B-5 行 71 vs 行 73 张力由 L-5（Model 1）显式消解。
- ADR-0038：一致（F-4/F-7/F-8/F-9/F-11/F-17）。`FinalityState != LockedState` 由 L-2 显式成文。
- ADR-0040：一致（PrevoteQC 保持 fork-choice justification only，L-6）。
- ADR-0049 / ADR-0050：一致（timeout / round change / proposer change 不解锁，L-10）。
- ADR-0041：一致（ProposalRef{block_hash, proposer} 不变；V1 lock 兼容无需 per-C QC）。
- consensus-spec：一致（语义来源；freeze 后按跟进流程将 §1.4 lock 由 ASSUMPTION 的语义依据指向
  本 ADR，不改 consensus-spec 文件）。

## Consequences

- **正面**：Lock vs Finality 语义分离（P0）；justified descendant / higher-round override /
  PrevoteQC / PrecommitQC 职责全部精确定义；为 Lock Enforcement 提供协议依据。
- **成本**：V1 无 unrelated higher-round override —— 极端 partition / equivocation 场景下可能
  暂停 liveness；符合 ADR-0049「Safety takes precedence over temporary Liveness」。
- **可迁移**：未来 higher-round release 机制经独立新 ADR 引入，不破坏本 ADR 语义。

## Security Impact

- 防 Lock==Finality 混淆（把 local state 当 global consensus state）。
- 防 remote Vote 被 local lock 拒收（P0）。
- 防 PrevoteQC 越权为 lock/finality authority。
- 防 unrelated higher-round override 造成 conflicting finality。
- 防 timeout / proposer / round 篡改 lock。

## Decision Log

| # | 决策 | 状态 |
|---|------|------|
| L-1 | LockedState = validator-local；远程 Vote 不得以 local lock 拒收 | FROZEN |
| L-2 | FinalityState ≠ LockedState（同源 PrecommitQC 双 effect，语义分离） | FROZEN |
| L-3 | Lock Acquisition 唯一来源 = valid PrecommitQC（PrevoteQC 不 acquire） | FROZEN |
| L-4 | Full transitive DAG ancestry（非 immediate parent） | FROZEN（DECISION A） |
| L-5 | JustifiedDescendant V1 = Model 1（C==L ∨ L ancestor of C；无额外 PrevoteQC） | FROZEN（DECISION B） |
| L-6 | PrevoteQC = fork-choice justification only | FROZEN |
| L-7 | PrecommitQC = finality + lock acquisition evidence；无 unrelated override authority | FROZEN |
| L-8 | Lock Advance：same / descendant ALLOW；unrelated NO ADVANCE；valid-but-inapplicable 保留证据 | FROZEN |
| L-9 | V1 无 unrelated higher-round override（future 需独立 ADR） | FROZEN（DECISION C） |
| L-10 | Timeout / round change / proposer change MUST NOT unlock | FROZEN |
| L-11 | Isolation：height / validator set / vote domain / vote type / context | FROZEN |
| L-12 | Lock enforcement = local vote-production 安全规则；非远程拒收规则 | FROZEN |

## 变更记录

| 日期 | 变更 | 依据 |
|------|------|------|
| 2026-09-04 | ADR-0053 PROPOSED 创建（L-1~L-12 + Finality≠Lock 核心原则 + Decision Matrix + Non-Goals + Dependencies + P0 Warning） | Owner STEP 10-15D（DECISION A/B/C/D APPROVED；ADR Creation Only；不自动 FROZEN） |
| 2026-09-04 | **FINAL FREEZE**：Status → FROZEN；Decision Log 全部 FROZEN；处理 R1 观察项 O1（Implementation Consequences：acquire_lock 必须实现 L-8 advance guard 才可 wiring）/ O2（L-2/L-7：valid AND applicable；不得读作自动推进每节点 lock）/ O3（Decision Matrix Scope note：仅本地 lock/vote 效果，非远程拒收）/ O4（L-1 remote pipeline = descriptive context only；不定义 double-vote）/ O5（Local Lock Safety 与 Global Finality Safety 论证分离） | Owner STEP 10-15D-F（ADR-0053 Freeze；R1 PASS；不 commit） |
