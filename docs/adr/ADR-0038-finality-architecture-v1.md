# ADR-0038: Finality Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（Finality Architecture，10-6）
- 关联：ADR-0033（C-5 ≥2/3 quorum / C-6 finality-first fork choice / C-7 Checkpoint=Finalized Reference）、
  ADR-0034（V-3 quorum / V-4 ValidatorVote / V-5 verify_vote）、ADR-0035（D-1~D-4 DAG）、
  ADR-0036（W-6 Witness ≠ finality authority）、ADR-0037（B-1~B-6 BFT Round）、
  ADR-0005（DomainId::ValidatorVote）、ADR-0009（canonical_vote_payload）、ADR-0010（chain_id）、
  ADR-0012（Ed25519）、`docs/protocols/consensus-spec-v1.md`
- 前置：STEP 10-6 Revision-2 审查 **APPROVED WITH 4 MICRO-FREEZES（MF-1~MF-4）**

## Context

STEP 10-5/10-5.1 冻结 BFT Round 状态机（`process_vote`/`RoundState`/`LockedState`）。10-6 冻结
**Finality Architecture**：什么条件下一个 block/reference 被判定为 finalized、节点如何证明该结果合法。
本 ADR 基于 Revision-2 设计 + 4 个 Micro-Freeze 成文冻结；**不修改**任何既有冻结 ADR / Crypto /
vote / round 实现。**Checkpoint（10-7）、slashing、epoch、validator rotation 不在本 ADR 范围。**

## Decision（冻结）

### F-1 — Finality Object（冻结；**措辞修订——三概念严格分离**）

**（10-6.1 前锁死：`Finalized Reference` 不是密码学证明对象）**

| 概念 | 定义 | 角色 |
|---|---|---|
| **Cryptographic Finality Proof** | **`PrecommitQC`**（vote 签名集合） | **唯一密码学证明** |
| **Finalized Block** | **`QC.target`**（被证明的单个 block hash） | 证明对象 |
| **Finalized Reference** | consensus state 追踪的 **latest finalized block** | 状态对象（非证明） |

- **`Finalized Reference` IS NOT a cryptographic proof**：它只是最新已 final block 的追踪引用，
  不携带/替代 `PrecommitQC` 证明（证明由 QC 单独承载）。
- **Finality ≠ Execution ≠ Storage Commit ≠ Snapshot ≠ Checkpoint**（C-7 五者分离）。
- `PrecommitQC → FinalizedReference` **不自动推导** `StateStore::commit_changes`（storage commit 是
  node 协调层行为，非共识推导）。

### F-2 — QC 结构（冻结）

```rust
pub struct QuorumCertificate {
    context: QcContext,          // chain_id / height / round / vote_type
    target:  [u8; 32],           // block hash
    validator_set_id: [u8; 32],  // = genesis_hash（F-11）
    evidence: Vec<QcEvidence>,   // 有序（F-12）
}
pub struct QcEvidence {
    validator_id: [u8; 32],      // 必须随 evidence 携带
    source_block_hash: [u8; 32], // 签名内字段，必须携带（不可丢失）
    timestamp: u64,              // 签名内字段，必须携带（不可丢失）
    signature: [u8; 64],         // Ed25519
}
```

- **QC 不是签名对象**：自身无签名；有效性由每条 evidence 的独立签名决定（V-5 冻结管线）。
- **QC 是聚合/证明层**：把已验证 vote 组装成可传递、可独立验证的最终性证据。

### F-3 — QC Context 绑定（冻结）

| 维度 | 状态 | 说明 |
|---|---|---|
| `chain_id` | **REQUIRED** | 每 evidence 经 `verify_vote` 绑定 chain_id（ADR-0005/0010） |
| `height` | **REQUIRED** | vote 签名覆盖内（ADR-0009 §2）+ 10-5.1 context guard |
| `round` | **REQUIRED** | 同上 |
| `vote_type` | **REQUIRED** | PrevoteQC / PrecommitQC（F-4） |
| `epoch` | **NOT USED / FOLLOW-UP** | 当前无 epoch 协议 |
| `protocol version` | **FOLLOW-UP** | 不进 signed_bytes（当前冻结） |

### F-4 — PrevoteQC / PrecommitQC 语义（冻结）

- **`PrevoteQC` = justification evidence only**（C-6 fork choice / justified state；**不产生 finality**）。
- **`PrecommitQC` = finality evidence**（**唯一产生 Finalized 的 QC 类型**）。
- **不采用**"PrevoteQC → PrecommitQC → Finality"链式要求（QC validity 层不要求 PrevoteQC 存在）。

### F-5 — PrecommitQC 独立充分（冻结）

> **PrecommitQC is independently sufficient as finality evidence; a separate PrevoteQC is not
> required for QC validity or finality acceptance.**

- precommit vote 是完整签名对象（121B 自包含）；`process_vote` precommit 分支允许 precommit
  独立到达（无"必须先有 prevote"的 QC 前提）。
- 与 B-2（Prevote→Precommit 为 validator 行为顺序）不冲突——行为顺序 ≠ QC 前提。

### F-6 — 三层分离（冻结；**MF-2**）

```rust
QC Validity（F-6a）≠ Finality Applicability（F-6b）≠ Finalized Update（F-6c）
```

**F-6a — QC Validity（Layer 1）**：`ValidQC = structural valid + context valid + target valid +
validator_set valid + evidence valid + quorum valid`（+ evidence canonical ordering / duplicate
detection，F-12）。**不依赖 current proposal。**

**F-6b — Finality Applicability（Layer 2）**：`Finalizable(PrecommitQC(Y)) = ValidQC + Y compatible
with latest_finalized`（F-8）。**`QC valid` ≠ `QC applicable`。**

**F-6c — Finalized Update（Layer 3）**：见 F-8。

- **强制流程**（禁止 `verify_qc() → 自动 finalize()`）：
  ```
  verify_qc() → ValidQC → check_finality_applicability() → update_finalized_reference()
  ```

### F-7 — Lock Acquisition（冻结；**MF-1**）

- **Lock 的权威证明来源 = Valid PrecommitQC**（统一单一规则，非"自己投票 + 本地 accumulator"）：
  > **A validator acquires `Lock(X, r)` when it locally establishes or verifies a valid
  > `PrecommitQC(X, r)`.**

- 流程统一：
  ```
  local quorum observation（或收到 QC）
        ↓
  construct / verify PrecommitQC(X, r)
        ↓
  Lock(X, r)  ∧  Finalized(X)
  ```
- `LockedState{ locked_block_hash, locked_round }`（B-5）足以表达 V0.1；lock 之后只投
  `X` 或其 descendant（B-5 `is_compatible`：same / descendant ⇒ OK；unrelated ⇒ reject）。
- **Lock propagation**：QC 自包含可验证（F-2/F-3）⇒ 新 round validator 收到 PrecommitQC(X) 即可
  更新本地 lock（node 层转发；consensus 状态机不含跨 round 传播）。
- **Lock enforcement**：状态机拒绝 lock 违规投票——**未实现**（GAP D，future hardening；
  safety 依赖 (A-lock) ASSUMPTION，见 F-17）。

### F-8 — Finality Applicability / Update（冻结；**MF-4**）

- **适用关系仅用 DAG relation**（DAG parent/descendant，D-1/D-3）；**禁止用 `(height, round)`
  推导 ancestry**（DAG 非简单线性链，height/round/ancestor/descendant 不等价）：

| `Y` 与 latest_finalized `X` 关系 | Applicable | Finalized Update |
|---|---|---|
| `Y == X` | Applicable | **idempotent**（不更新） |
| `Y` descendant of `X` | Applicable | **advance**（更新） |
| `Y` ancestor of `X` | Not applicable | **stale / ignore** |
| `Y` unrelated to `X` | Not applicable | **conflict / retain evidence / no finalize**（F-9） |

### F-9 — Valid-but-inapplicable QC（冻结；**MF-3**）

> **Valid-but-inapplicable QC MUST NOT be relabeled as InvalidQC.**

| 情形 | QC 状态 | 是否 finalize |
|---|---|---|
| signature 错误 | Invalid | ❌ |
| validator 不属于 set | Invalid | ❌ |
| quorum 不够 | Invalid / insufficient | ❌ |
| 重复 validator | Invalid | ❌ |
| target 不存在 | Invalid | ❌ |
| QC 完全有效但与 finalized 冲突 | **Valid / Inapplicable** | ❌ |
| QC 完全有效且 same | Valid / Applicable | ✅ |
| QC 完全有效且 descendant | Valid / Applicable | ✅ |

- **必须保留 evidence**：Valid-but-inapplicable QC 是真实历史证据（可能为 equivocation /
  slashing 输入，F-13 语义），不得因"不适用"而丢弃或改标 Invalid。

### F-10 — QC Evidence 可独立验证（冻结）

- evidence 携带 `{validator_id, source_block_hash, timestamp, signature}`；context/target 提供
  `round/height/vote_type/target/chain_id`（F-2/F-3）。字段来源矩阵：
  - `round/height/vote_type` ← QC.context；`target` ← QC.target；`chain_id` ← 验证上下文；
  - `source_block_hash/timestamp/validator_id` ← evidence（**签名内字段，不可丢失、不可派生**）。
- 独立验证（无原始网络 Vote 对象）：
  ```
  重建 ValidatorVote{ ctx.height, ctx.round, QC.target, ctx.vote_type,
                      ev.source_block_hash, ev.validator_id, ev.timestamp }
  → canonical_vote_payload（121B，ADR-0009 冻结，一字不改）
  → build_signed_bytes(Ed25519, DomainId::ValidatorVote, chain_id, payload)
  → hash → verify_strict(ev.signature, vk)
  → membership + weight（validator_set）
  ```
- **不修改 Vote 签名覆盖 / canonical_vote_payload / verify_vote 五步**。

### F-11 — ValidatorSet Identity（冻结）

- **`validator_set_id = genesis_hash`（[u8;32]，V0.1 唯一确定，无 OR）**。
- 论证：V0.1 单一 ValidatorSet 由 `GenesisV1.initial_validator_set` 完全决定（V-1/V-2），
  `genesis_hash = SHA-256(canonical_genesis)` 覆盖全部 genesis 字段（ADR-0010 §3）
  ⇒ 同 `genesis_hash` ⟺ 同 validator set（含权重）。
- **未来迁移**：epoch / validator rotation 引入时，validator_set_id 迁移到独立 `validator_set_hash`
  （FOLLOW-UP，新 ADR）；V0.1 不使用 `validator_set_hash`（当前 consensus 无此概念）。

### F-12 — QC Canonical Ordering（冻结；**NEW FREEZE**）

- **evidence 按 `validator_id` 字节升序**（与 genesis validator 排序一致，canonical）。
- **duplicate validator_id ⇒ `InvalidQC`**（防重复计权歧义）。
- 本项为 **NEW FREEZE CANDIDATE 成文**（QC 类型此前不存在），随本 ADR 冻结。

### F-13 — Timestamp & Equivocation（冻结）

- **Timestamp**：signed metadata（ADR-0009 §2 签名覆盖内），**非 QC validity 条件**。
  > **Timestamp is part of the signed vote payload but is not independently used as a QC
  > validity condition in V0.1.**
  - V0.1 不引入 clock drift / freshness / window。
- **Equivocation 语义**（`duplicate ≠ equivocation`）：
  - `duplicate`：same validator + same (height, round, vote_type) + same target ⇒ **去重不重复计权**；
  - `equivocation`：same validator + same (height, round, vote_type) + different target ⇒
    各 target 独立计权；V0.1 不 reject；**保留 evidence**。
- **不因无 slashing 而丢失证据**：所有 QC（含 Valid-but-inapplicable）必须保留；individual
  signatures 即未来 equivocation/slashing 证据载体（检测/惩罚归 PHASE 7+，FOLLOW-UP）。

### F-14 — Recovery Boundary（冻结）

> **A validator MUST NOT resume voting until it has restored: local voting state, lock state,
> finalized reference, and highest relevant QC.**

- 恢复顺序（先恢复、后参与；**禁止**"先参与 consensus 再恢复"）：
  ```
  Node restart → restore local voting state → restore lock → restore finalized
  → restore highest QC → ONLY THEN resume voting
  ```
- 目的：防 `restart → forgotten vote → conflicting vote`（重启双投）。
- Consensus-owned facts = local lock + latest_finalized + highest QC + 已投记录；
  **不设计 storage API**（C-1 禁 consensus→storage）；持久化实现归 node 协调层。

### F-15 — Finality / Storage / Checkpoint Hard Boundary（冻结）

- **五者分离**：`Finality ≠ Execution ≠ Storage Commit ≠ Snapshot ≠ Checkpoint`（C-7）。
- **Checkpoint 不能反过来证明 Finality**：只能 `Finality → Checkpoint`。
- Checkpoint（STEP 10-7）消费 Finalized Reference + PrecommitQC 证明；本 ADR 不实现 checkpoint。

### F-16 — Error Boundary（需求，不改 error.rs）

QC/Finality 层需要的逻辑错误类别（**不修改 `ConsensusError`**，实现时按需扩展并经 ADR）：
```
InvalidQC                 —— QC 结构/编码非法
WrongHeight / WrongRound  —— context 不符（已有 10-5.1 guard 语义）
WrongTarget               —— target 非 DAG 已知 / 非期望
InsufficientQuorum        —— 累计权重 < ceil(T*2/3)
InvalidValidatorEvidence  —— 非成员 / 签名无效 / 重复 validator（F-12）
ConflictingQC             —— 检测到冲突 QC（equivocation 输入，FOLLOW-UP）
```

### F-17 — Safety Argument（冻结；Protocol vs Implementation）

**Protocol Safety Model**（在下列 ASSUMPTION 下）：
- (H1) `Byzantine < 1/3`，`Honest ≥ 2/3`（C-5/V-3 派生）；
- (H2) honest single-vote（同 (height, round, vote_type) 不投冲突 target）；
- (H3) honest 遵守 lock（B-5）——**ASSUMPTION，状态机未强制**；
- (A-prop) honest **最终**接收并验证 PrecommitQC —— **liveness / propagation 假设**（ASSUMPTION，未实现）；
  注意：`eventually` 对 safety **不足**；cross-round safety 需"在投与 X 冲突的后续 vote 之前已获知并验证
  X 的 finality 信息"的**同步边界**（`A-sync-before-conflicting-vote`），该边界属 **10-6.1 SAFETY
  BOUNDARY**（本 ADR 不新增规则）。

*Same-context QC*：`QC(X)`+`QC(Y)`（同 context，X≠Y）各需 ≥2/3 ⇒ 权重和 ≥4/3；但 honest 单投
（H2）使 `h_X+h_Y ≤ H ≤ 1`，byzantine `b_X+b_Y ≤ B < 1/3` ⇒ 和 ≤ H+B = 1 < 4/3。**矛盾 ⇒ 不可能。** ∎

*Cross-round finality*：`Finalized(X)`（PrecommitQC(X)）。对 unrelated `Y` 达成 Finalized(Y) 需某
context PrecommitQC(Y) ≥2/3；honest（≥2/3）由 (A-prop) 已知 X、由 (H3) 只投 X/descendant ⇒
Y 的 precommit 仅来自 byzantine + 未收敛 honest < 2/3。**无法达成。** ∎（依赖 (A-prop)+(H3)）

**Current Implementation Safety**：当前代码只保证状态机确定性 + context guard + 终态 guard
（10-5.1）；**不强制** H2/H3。**不得宣称实现已保证 safety**；仅"协议语义已定义、实现安全尚未闭环"。

### F-18 — Liveness Boundary（冻结）

- 已确定：`RoundTimeoutConfig`（B-3，本地事件，非共识输入；禁止 timeout 直接 finalize）。
- **OPEN / FOLLOW-UP（不凭空设定）**：网络模型、leader rotation / proposer selection、
  timeout protocol、网络传递保证、validator 活性。

## Decision Log

| # | 决策 | 状态 |
|---|------|------|
| F-1 | Finality Object = Finalized Reference（五者分离） | 冻结 |
| F-2 | QC 结构（context/target/validator_set_id/ordered evidence） | 冻结 |
| F-3 | QC Context 绑定（chain_id/height/round/vote_type REQUIRED） | 冻结 |
| F-4 | PrevoteQC=justification only；PrecommitQC=finality evidence | 冻结 |
| F-5 | PrecommitQC 独立充分（不需 PrevoteQC） | 冻结 |
| F-6 | QC Validity ≠ Finality Applicability ≠ Finalized Update（MF-2） | 冻结 |
| F-7 | Lock 唯一来源 = Valid PrecommitQC（MF-1） | 冻结 |
| F-8 | Applicability 用 DAG relation（same/descendant/ancestor/unrelated；MF-4） | 冻结 |
| F-9 | Valid-but-inapplicable ≠ InvalidQC；保留 evidence（MF-3） | 冻结 |
| F-10 | evidence={validator_id, source, timestamp, signature}；canonical 121B 不变 | 冻结 |
| F-11 | validator_set_id = genesis_hash | 冻结 |
| F-12 | evidence 有序（validator_id 升序；duplicate ⇒ InvalidQC）——NEW FREEZE | 冻结 |
| F-13 | timestamp=signed metadata；equivocation 保留 evidence | 冻结 |
| F-14 | Recovery MUST restore before participation | 冻结 |
| F-15 | Finality/Storage/Checkpoint 硬边界（Checkpoint 不能证明 Finality） | 冻结 |
| F-16 | Error boundary 需求（不改 error.rs） | 冻结 |
| F-17 | Safety（同 context QC + cross-round）在 ASSUMPTION 下 | 冻结 |
| F-18 | Liveness 边界（RoundTimeoutConfig；其余 OPEN） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| PrevoteQC → PrecommitQC → Finality 链式 | QC validity 层不要求 PrevoteQC；precommit vote 自包含（F-5） |
| QC 自身签名（QC-level signature） | 循环问题（谁签 QC）；QC 是投票集合凭证，非签名对象（F-2） |
| aggregate signature（BLS） | Ed25519 仅（C-2/ADR-0012）；DEPENDENCY/FOLLOW-UP |
| validator_set_id = validator_set_hash | 当前 consensus 无此概念；V0.1 用 genesis_hash（F-11） |
| lock 由本地 accumulator 触发 | 与 propagation 不统一；权威来源应为 Valid PrecommitQC（MF-1/F-7） |
| applicability 用 (height, round) 推导 | DAG 非线性链；必须用 DAG relation（MF-4/F-8） |
| valid-but-inapplicable 标 Invalid | 丢弃 equivocation/slashing 证据（MF-3/F-9） |

## Consequences

- **正面**：Finality 语义唯一确定；三层分离防实现偷换；evidence 可独立验证；safety 论证成文。
- **成本**：V0.1 individual signatures（O(n) 验证）；lock enforcement / slashing 未闭环（明示）。
- **可迁移**：BLS 聚合、validator_set_hash、epoch 均可未来 ADR 迁移（不破坏 QC 结构）。

## Security Impact

- 防跨链/跨 context 重放：chain_id + domain + height/round + validator_set（F-3/F-10/F-11）。
- 防重复计权：evidence canonical ordering + duplicate ⇒ InvalidQC（F-12）。
- 防安全证明伪装：Protocol vs Implementation 二分（F-17）。
- 防证据丢失：Valid-but-inapplicable 保留（F-9/F-13）。
- 防重启双投：Recovery MUST restore before participation（F-14）。
