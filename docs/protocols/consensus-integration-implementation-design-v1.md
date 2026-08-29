# Nova Chain — Consensus Integration Implementation Design V1（10-9.1）

- **Status**: Draft（STEP 10-9.1；**APPROVED WITH 5 REQUIRED MICRO-FREEZES**，待最终 Review）
- **Date**: 2026-08-29
- **Scope**: Consensus State Machine Integration 的**实现设计**（ConsensusState / ConsensusEvent /
  Atomic Transition / Snapshot / Timeout / 边界）。
- **依据**：ADR-0033 C-1~C-9、ADR-0037 B-1~B-6（RoundState/process_vote）、ADR-0038 F-1~F-18
  （FinalityState/verify_qc）、ADR-0039 CP-1~CP-8（Checkpoint）、ADR-0040 FC-1~FC-14（ForkChoice）。
- **本文件是设计契约，不是代码实现**。实现（10-9.2）必须严格遵循本契约。

---

## 0. 核心边界（用户 6 条）

1. 不重新设计 10-1~10-8（只消费冻结 API）。
2. 不扩大成 node（无网络/调度/storage/persistence/execution/mempool/P2P）。
3. 不做 Epoch / 4. 不做 Slashing。
5. Lock enforcement 谨慎：**Integration 不引入 `LockedState`/`acquire_lock`**（保持现有模块内部语义）。
6. Fork Choice 仅下游：`FinalityState → finalized_reference → ForkChoice`；禁止反向产生 Finality。

## 1. ConsensusState（MF-1：协议状态 vs 派生缓存）

```rust
pub struct ConsensusState {
    pub round: RoundState,        // canonical consensus state（B-1）
    pub finality: FinalityState,  // canonical consensus state（F-1）
}
```

- **`ConsensusState` 仅含 `round + finality`（可持久化、可 replay 比对）**。
- **QC Registry 不是 `ConsensusState` 字段**（MF-1 冻结）：
  > **`QcRegistry` is bounded, deterministic integration context, not an independent protocol
  > state machine.** 它：
  > - 不产生新的协议权威；不拥有 finality；不决定 vote validity；
  > - **不无限增长**（retention/pruning 边界为未来设计，本 ADR 只明确"非无限永久状态"）。
- **实现**：transition 产生的 PrevoteQC/PrecommitQC 作为 **derived output** 交调用方（node 层）
  维护 **bounded** 已验证 QC 集，并作为后续 `fork_choice` 的 `prevote_qcs` 输入传回。
- 不含 `LockedState`（validator-local voting constraint/context，B-5/F-7，非共识状态；Integration
  不拥有、不凭空创造 cross-round lock enforcement）。

## 2. ConsensusEvent / Verified Vote 边界（MF-2）

```rust
pub enum ConsensusEvent {
    Vote(VerifiedVote),          // MF-2：已验证 Vote
    SetProposal(ProposalRef),
    RoundTimeout,                // 本地事件（MF-5）
}
```

- **MF-2 冻结（方案 A + 硬 precondition）**：
  - `ConsensusEvent::Vote` 接受 **`VerifiedVote`**（概念边界：`raw Vote → verify_vote（V-5）→ VerifiedVote → ConsensusEvent`）。
  - 若现有类型体系暂不新增 wrapper，则 API contract 写死硬 precondition：
    > **`ConsensusEvent::Vote` MUST contain a vote whose V-5 verification has already succeeded.**
  - **Integration 不重新验证签名**，但**绝不把未经验证的 Vote 视为协议有效 Vote**（安全边界不依赖调用者自觉）。
  - Integration 仍执行**上下文守卫**（`height/round` 与 `RoundState` 匹配，10-5.1 语义）。

## 3. Atomic Transition（MF-3）

> **任何一个 consensus transition 要么产生完整的新状态，要么保持旧状态不变。无部分更新。**

```rust
pub struct ConsensusTransition {
    pub next_state: Option<ConsensusState>,  // None = 拒绝/忽略（状态不变）
    pub disposition: Disposition,            // Applied / Ignored{ContextMismatch} / Ignored{Terminal} / Rejected{RoundOverflow}
    pub prevote_quorum: bool,                // observation（派生结果，非长期状态）
    pub precommit_quorum: bool,
    pub finalized_advance: Option<[u8; 32]>,
    pub prevote_qc: Option<QuorumCertificate>,   // derived（交调用方维护 bounded registry）
    pub checkpoint: Option<Checkpoint>,          // derived（非状态）
    pub fork_choice_head: Option<[u8; 32]>,      // 消费 next_state snapshot（MF-4）
}
```

- **实现模式**：`transition(state, event, context) -> ConsensusTransition` 为**不可变纯计算**——
  基于 `state` 计算完整 `next_state`；**任何一步失败/拒绝 ⇒ 返回 `next_state = None`（状态不变）**；
  成功才产出完整 `next_state`。**禁止** `mutate round / mutate registry / mutate finality` 顺序变更。
- `prevote_quorum`/`precommit_quorum` 是**本次 transition 的 observation**，不是长期 consensus state。

## 4. ForkChoice 同 Snapshot 消费（MF-4）

- **Fork Choice 必须消费本次 transition 完成后的同一逻辑快照**：
  ```
  NextState（round+finality）
     ↓
  Checkpoint derivation（基于 NextState.finality）
     ↓
  ForkChoice(snapshot = NextState + 调用方 bounded prevote_qcs + 外部 dag)
  ```
- **禁止** `old finality + new qc_registry` 或 `new finality + old qc_registry` 混合（时间错位）。
- **Fork Choice 仍不能反向修改 NextState**（边界 6）。
- `fork_choice_head` 与 `next_state`/`checkpoint` 同 snapshot。

## 5. RoundTimeout（MF-5）

- **Timeout 只能 advance local consensus round state**：
  ```
  next_round = checked_successor(current_round)   // None ⇒ Rejected{RoundOverflow}
  ```
- **`timeout ≠ vote / QC / finality evidence / checkpoint`**：Timeout 事件**不得**产生
  PrevoteQC / PrecommitQC / 修改 FinalityState / 派生 Checkpoint / 改变 finalized reference。
- **`MAX_ROUND + timeout` ⇒ 确定性拒绝（`Rejected{RoundOverflow}`，`next_state = None`）**——不 wrap、
  不 panic、debug/release 行为一致。

## 6. O-1 ~ O-4 裁决（冻结）

| OPEN | 裁决 |
|---|---|
| O-1 qc_registry | **A + MF-1**：保存当前 transition 上下文可见的已验证 QC，但**非无限 canonical consensus state**；retention/pruning 未来设计 |
| O-2 verified vote | **A + MF-2**：`verify_vote → VerifiedVote → ConsensusEvent`（或硬 precondition）；Integration 不重验签名 |
| O-3 timeout | **A + MF-5**：确定性 round advancement；timeout ≠ evidence；overflow 确定性拒绝 |
| O-4 LockedState | **不纳入 ConsensusState / Integration pipeline**（validator-local context） |

## 7. 严格 Transition 顺序

```
ConsensusEvent
  → VerifiedVote 边界 + 上下文守卫（不符 ⇒ Ignored）
  → process_vote(RoundState) → RoundTransition
      ├─ prevote_quorum ⇒ 构造 PrevoteQC（derived output，交调用方 bounded registry）
      └─ precommit_quorum ⇒ 构造 PrecommitQC → verify_qc（Validity）→ update_finalized_reference
  → 计算完整 NextState（原子，MF-3）
  → Checkpoint derivation（仅 finality Advance，CP-MF-4：显式对应 QC）
  → ForkChoice（消费 NextState 同一 snapshot，MF-4）
  → 输出 ConsensusTransition（含 next_state / disposition / derived outputs）
```

## 8. 状态持久化边界

- 可持久化（node 层候选，GAP G）：`ConsensusState{ round, finality }`。
- Integration 不新增 consensus state 类型、不创造 finality/QC、不把 checkpoint/head 存为状态。

## 9. Test Plan（T1~T16）

| # | 用例 |
|---|---|
| T1 | 完整生命周期：Vote→prevote quorum→PrecommitQC→finality advance→checkpoint→fork_choice head |
| T2 | 上下文不符 ⇒ Ignored（状态不变） |
| T3 | 幂等：重复 vote 不改变状态（VoteAccumulator 去重 + 终态守卫） |
| T4 | replay：同事件序列同最终状态 |
| T5 | finalized 后 vote ⇒ Ignored{Terminal} |
| T6 | fork_choice 下游：finality 变化 ⇒ head 更新；反向不成立 |
| T7 | checkpoint 仅 finality Advance 时派生；无对应 QC ⇒ None（CP-MF-4） |
| T8 | timeout 推进 round（round+1，finality/qc 保留） |
| T9 | determinism：同输入同输出（proptest 随机事件序列） |
| T10 | 不引入新 consensus state / 不改冻结 API / 无 height-round 推导 / 无输入顺序依赖 |
| T11 | **Atomic（MF-3）**：round 更新路径 + finality 拒绝 ⇒ `state_after == state_before`（无半更新） |
| T12 | **Snapshot consistency（MF-4）**：fork_choice 输入 = 同一 transition snapshot（无 old/new 混合） |
| T13 | **Verified Vote boundary（MF-2）**：unverified vote 不能进入 transition；verified 可进入 |
| T14 | **Timeout 不产生证据（MF-5）**：round 前进；PrevoteQC=None / PrecommitQC=None / Finality 不变 / Checkpoint=None |
| T15 | **Round overflow（MF-5）**：MAX_ROUND + timeout ⇒ 确定性 Rejected{RoundOverflow}，不 wrap |
| T16 | **QC registry bounded（MF-1）**：同 QC 同逻辑 identity ⇒ 无重复累积；不造成 fork_choice input-order dependency |

## 10. 边界 / 延期（10-9 不做）

Epoch / validator rotation、Slashing、Network/P2P 收发、Storage/Persistence/Recovery、Execution、
Mempool、完整 Block 格式、**cross-round lock enforcement（无新协议授权不创造）**、consensus 消息的
P2P 类型、node 协调层。**`acquire_lock`/`LockedState` 不进入 Integration pipeline**（范围修正）。

## 11. Implementation Prohibitions

```
FORBIDDEN:
1. Do not re-design 10-1~10-8 (consume frozen APIs only).
2. Do not put QcRegistry into ConsensusState as unbounded canonical state.   (MF-1)
3. Do not treat an unverified vote as valid (VerifiedVote boundary / hard precondition). (MF-2)
4. Do not partially update state; transition must be atomic (full next_state or None).  (MF-3)
5. Do not let ForkChoice consume mixed old/new snapshots.                     (MF-4)
6. Do not let RoundTimeout create QC/finality/checkpoint; do not wrap round overflow.    (MF-5)
7. Do not introduce LockedState/acquire_lock into ConsensusState or pipeline.
8. Do not create new consensus state types / new finality rule.
9. Do not add witness / serialization / storage / network / execution.
10. Do not modify round.rs / finality.rs / checkpoint.rs / fork_choice.rs / vote.rs
    / dag.rs / validator.rs / error.rs / any frozen ADR.
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-29 | 初稿：10-9.1 Consensus Integration 实现设计 + MF-1~MF-5（QC registry 有界/VerifiedVote/原子 transition/snapshot/timeout）+ O-1~O-4 裁决 + T11~T16 + acquire_lock 范围修正 | 10-9.1 Review APPROVED WITH 5 REQUIRED MICRO-FREEZES |
