# ADR-0039: Checkpoint Architecture V1（FINAL）

- **Status**: **Frozen**（STEP 10-7；ADR-0039 FINAL FREEZE，2026-08-28）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（Checkpoint，10-7）
- 关联：ADR-0033（C-1 纯计算边界 / C-7 Checkpoint=Finalized Reference）、ADR-0038（F-1/F-6/F-15，
  Finality/QC）、ADR-0036（W-3 WitnessSeed 用 previous_finality_reference）、ADR-0035（DAG relation）、
  `docs/protocols/finality-implementation-design-v1.md`
- 前置：STEP 10-7 Design Review **APPROVED**（D5 裁决 = 选项 A；CP-MF-1 / CP-MF-2 必须冻结）；
  ADR-0039 Review **APPROVED WITH 3 MICRO-FREEZES**（CP-MF-3/4/5）；最终裁决 **READY TO FREEZE**
- **本 ADR 不修改** ADR-0038 / ADR-0033 / 任何既有冻结 ADR 或代码；仅定义 checkpoint 层不变量。

## Context

10-6（ADR-0038）冻结 Finality/QC：`Finalized Reference` = 共识状态追踪的最新 final block（非密码学证明），
证明由 PrecommitQC 承载。10-7 冻结 **Checkpoint**：把 Finalized Reference + 其对应 PrecommitQC 证明组织成
可验证、可传递的锚点。**Checkpoint 是 Finality 的下游消费**（F-15：`Finality → Checkpoint`），不是独立
共识权威。

## Decision（Draft 冻结候选）

### D5 — Checkpoint 生成策略（裁决：**选项 A**）

- **V1 Checkpoint generation is not interval-gated. Every finalized-reference advancement MAY derive
  the latest Checkpoint.**
- **`snapshot_interval_blocks` is not a consensus requirement and MUST NOT determine Checkpoint
  validity or Finality.**（仅供未来 snapshot / checkpoint density optimization，在 node/storage 层做，
  不污染 consensus。）
- **禁止** `height % snapshot_interval_blocks == 0` 作为 checkpoint 生成/有效性条件。

### CP-1 — Reference Identity（不变量）

```
checkpoint.finalized_block_hash
        ==
checkpoint.precommit_qc.target
```

### CP-2 — QC Type（不变量）

```
checkpoint.precommit_qc.context.vote_type
        ==
VoteType::Precommit
```

### CP-3 — Context Consistency（不变量）

```
checkpoint.height == checkpoint.precommit_qc.context.height
checkpoint.round  == checkpoint.precommit_qc.context.round
```

### CP-4 — Proof Correspondence（不变量；**CP-MF-1**）

> **Checkpoint 使用的 QC 必须是 `QC.target == finalized_reference` 的 Valid PrecommitQC。**
> **不得**把 `FinalityState.highest_precommit_qc` 当作默认 checkpoint proof——
> `highest_precommit_qc` 是 **recovery fact**，其 `target` **未必等于** `finalized_reference`
> （例如 `QC(Y)` 合法但 `Y unrelated to X` 时，`finalized_reference = X` 而 `highest_precommit_qc.target = Y`）。

- **生成 API 语义（冻结候选）**：显式传入对应 QC，禁止函数内猜测：
  ```rust
  derive_checkpoint(
      finalized_reference: [u8; 32],
      finalized_qc: &QuorumCertificate,   // 前置：finalized_qc.target == finalized_reference（CP-4）
  ) -> Option<Checkpoint>
  ```
- **绝对不变量（CP-MF-4）**：
  > **`derive_checkpoint()` MUST NOT select, search, substitute, or infer a QC from
  > `FinalityState.highest_precommit_qc` when the supplied finalized-reference proof is absent.**
- 没有对应 QC（`target == finalized_reference` 的 Valid PrecommitQC 不存在）：**`derive_checkpoint` 必须
  返回 `None`**；**绝不能**拿 `target != finalized_reference` 的 QC 凑 checkpoint（含**禁止 fallback** 到
  `highest_precommit_qc`——ADR-0038 已明确其 ≠ finalized_reference 对应 QC）。
- `FinalityState.highest_precommit_qc` 的恢复语义**保持 ADR-0038 不变**（本 ADR 不修改，仅声明其
  **MUST NOT** 被假定为对应 `finalized_reference` 的 proof）。

### CP-5 — No Independent Finality（不变量；**CP-MF-2 —— F-15 措辞精确化**）

> **A Checkpoint is not an independent source of Finality. Its embedded PrecommitQC may be validated
> as evidence, but Checkpoint verification MUST NOT itself perform a FinalityState transition or
> introduce a separate finality rule.**
>
> 中文：**Checkpoint 不是独立的 Finality 来源。Checkpoint 可以携带并验证对应的 PrecommitQC 证据，
> 但 Checkpoint 验证不得自行执行 FinalityState 转换，也不得引入独立于 Finality/QC 的最终性规则。**

- 语义澄清：`Checkpoint` 内含有效 `PrecommitQC(target=X)` ⇒ 该 QC 本身**是**可验证的 finality 证据
  （继承 10-6）；但 **Checkpoint 对象 / `verify_checkpoint()` 不是 FinalityState transition 的触发源**，
  也不定义第二套 finality rule。
- `verify_checkpoint()` 只验证：结构 + `target == reference`（CP-1）+ Precommit（CP-2）+ height/round
  一致（CP-3）+ 内嵌 QC 有效性（复用 `verify_qc`）。**绝不修改 FinalityState。**

### CP-6 — Interval Independence（不变量）

```
snapshot_interval_blocks 不得决定：
  - checkpoint validity
  - finality
  - QC validity
  - checkpoint applicability
```
（D5 的延伸：无 interval gating。）

### CP-7 — Chain Identity Consistency（不变量；**CP-MF-3 新增冻结**）

```
Checkpoint.chain_id
        ==
Checkpoint.precommit_qc.context.chain_id
```

- `verify_checkpoint()` 必须拒绝不一致对象（`Checkpoint.chain_id != QC.context.chain_id` ⇒ Err）。
- `chain_id` **仍不能**通过 `genesis_hash` 推导（遵守 ADR-0010 冻结规则）。
- 防对象自洽性缺口：`Checkpoint.chain_id = A` 但 `QC.context.chain_id = B` 的错配对象必须拒绝。

### CP-8 — Height/Round Metadata-Only（不变量；**CP-MF-5 新增冻结**）

```
Checkpoint.height / Checkpoint.round
MUST NOT be used to infer:
  - finality
  - ancestry
  - checkpoint applicability
  - checkpoint ordering
```

- 与 10-6 原则一致：**DAG ancestry = parent relation，不能通过 height/round 推导**；
  Checkpoint 不得成为绕过该禁令的新入口。
- 禁止：`cp.height > current.height ⇒ descendant`；`cp.round > old.round ⇒ newer finality`。
- `height`/`round` 仅作 metadata（CP-3 自洽性），不承载语义推断。

---

## Checkpoint Object（冻结候选）

```rust
pub struct Checkpoint {
    pub chain_id: u64,                  // 链绑定（与 QC 一致）
    pub finalized_block_hash: [u8; 32], // = Finalized Reference（C-7）
    pub height: u64,                    // finalized block 高度
    pub round: u64,                     // 达成 finality 的 round
    pub precommit_qc: QuorumCertificate, // 对应 proof（CP-4：target == finalized_block_hash）
}
```

- **不是新区块 / 不是签名对象**；无新密码算法、无新签名域。
- 不引入 checkpoint_index（V0.1；FOLLOW-UP）。

## Checkpoint Verification（分层，镜像 ADR-0038 F-6）

- **Layer 1 — Validity（自洽性，纯函数，不依赖当前状态）**：
  ```
  verify_checkpoint(cp, set, genesis_hash, dag) -> Result<(), CheckpointError>
    ① verify_qc(cp.precommit_qc, ...)                    // 复用 10-6（含 Precommit evidence）
    ② CP-2（Precommit-only）
    ③ CP-1（target == finalized_block_hash）
    ④ CP-3（height/round 与 QC context 一致）
    ⑤ CP-7（chain_id == QC.context.chain_id）
  ```
  **`verify_checkpoint` 不得执行 FinalityState transition（CP-5）。**
- **Layer 2 — Applicability（与当前 Finality 关系，node/状态层）**：
  - `cp.finalized_block_hash == latest finalized_reference` ⇒ 最新锚点；
  - 历史 checkpoint 判定**只用 DAG relation**（CP-10-6 原则：`height/round ≠ ancestry`）；
  - `checkpoint valid` ≠ `checkpoint latest/applicable`（镜像 F-6 分层）。

## Checkpoint / Witness / Storage 边界

| 关系 | 语义 |
|---|---|
| `Finality → Checkpoint` | Checkpoint 消费 Finalized Reference + 对应 PrecommitQC（CP-4）；反向不成立（CP-5） |
| Checkpoint vs Storage Snapshot | **不同**（C-7；`snapshot_interval_blocks` 仅参考，CP-6） |
| Checkpoint vs Storage Commit | **不同**（F-15） |
| Checkpoint vs Witness | Checkpoint 锚定的 `finalized_block_hash` = `previous_finality_reference`（W-3 WitnessSeed 输入）；不改变 Witness 协议 |

## Error Boundary（不改 error.rs）

新增 `CheckpointError`（finality.rs 或独立，实现时经实现 ADR 定）：
```
InvalidCheckpointStructure      —— 结构/编码非法
NotPrecommitQc                  —— 证明非 Precommit（CP-2）
CheckpointTargetMismatch        —— precommit_qc.target != finalized_block_hash（CP-1）
CheckpointContextMismatch       —— height/round 与 QC context 不一致（CP-3）
CheckpointChainIdMismatch       —— checkpoint.chain_id != QC.context.chain_id（CP-7）
（evidence 层复用 FinalityError::Evidence / ConsensusError）
```

## Scope Boundary（10-7 不实现）

- ❌ storage 持久化 / 落盘（checkpoint 持久化归 node 层）
- ❌ light client verification（FOLLOW-UP）
- ❌ checkpoint sync / 跨节点传播（ADR-0032 N-6 已排除，归 node 层）
- ❌ 用 Checkpoint 证明 Finality / 独立 FinalityState transition（CP-5）
- ❌ interval gating / `snapshot_interval_blocks` 参与共识判定（D5/CP-6）

## Safety / Consistency

- Checkpoint **不新增安全假设**：合法性完全由 PrecommitQC 继承（verify_qc + Precommit-only + CP-1/CP-3）。
- **无新重放面**：Checkpoint 无签名、无域；重放由 QC 的 chain_id/height/round/validator_set 绑定继承。
- **单调性**：latest finalized 单调前进（10-6 MF-5），Checkpoint 随之单调。
- **边界声明**：cross-round lock enforcement / A-sync-before-conflicting-vote 仍为 **ASSUMPTION /
  未实现**（10-6.2 FINAL 声明保留，**不得**在 checkpoint 语境升级为"已证明 cross-round safety"）。

## Decision Log

| # | 决策 | 状态 |
|---|------|------|
| D5 | 每次 finalized-reference advancement MAY 派生最新 Checkpoint；无 interval gating（选项 A） | **冻结** |
| CP-1 | `finalized_block_hash == precommit_qc.target` | **冻结** |
| CP-2 | `precommit_qc.vote_type == Precommit` | **冻结** |
| CP-3 | `height/round` 与 QC context 一致 | **冻结** |
| CP-4 | proof 必须精确对应 finalized_reference；不得用 highest_precommit_qc 充当（CP-MF-1） | **冻结** |
| CP-5 | Checkpoint 非独立 Finality 来源；验证不得执行 FinalityState transition（CP-MF-2） | **冻结** |
| CP-6 | `snapshot_interval_blocks` 不参与 checkpoint/finality/QC validity | **冻结** |
| CP-7 | `checkpoint.chain_id == QC.context.chain_id`（CP-MF-3） | **冻结** |
| CP-8 | `height`/`round` 仅 metadata，不得推断 finality/ancestry/applicability/ordering（CP-MF-5） | **冻结** |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 用 `snapshot_interval_blocks` 做 interval gating | 语义耦合 finality/checkpoint/snapshot；C-7 分离原则（D5） |
| 默认以 `highest_precommit_qc` 作为 checkpoint proof | `target` 未必 == finalized_reference ⇒ 生成不可自验对象（CP-MF-1/CP-4） |
| `verify_checkpoint` 允许推进 FinalityState | 制造第二套 finality rule；违反 F-15/CP-5 |

## Consequences

- **正面**：Checkpoint 完全继承 10-6 安全模型；proof 对应关系明确；无独立 finality 权威。
- **成本**：derive_checkpoint 需显式提供对应 QC（无对应则 None）；调用方/node 层负责持有
  `target == finalized_reference` 的 QC。
- **可迁移**：未来持久化 / light client / checkpoint sync 在 node/storage 层扩展，不污染 consensus。

## Security Impact

- 防 proof 错配：CP-1/CP-4 强制 proof 精确对应 finalized_reference。
- 防第二套最终性规则：CP-5 禁止 checkpoint 独立推进 FinalityState。
- 防 finality/checkpoint/snapshot 耦合：D5/CP-6 interval independence。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-28 | 初稿：10-7 Checkpoint 设计 + D5（选项 A）+ CP-MF-1/CP-MF-2 + CP-1~CP-6 不变量 | STEP 10-7 Design Review APPROVED（D5 裁决 A；CP-MF-1/CP-MF-2 冻结） |
| 2026-08-28 | 落实 CP-MF-3（CP-7 chain_id 一致性）/ CP-MF-4（derive_checkpoint 禁 fallback）/ CP-MF-5（CP-8 height/round metadata-only）+ `CheckpointChainIdMismatch` | ADR-0039 Review APPROVED WITH 3 MICRO-FREEZES |
| 2026-08-28 | **FINAL FREEZE**：Status → Frozen；Decision Log 全部冻结 | 最终裁决 READY TO FREEZE |
