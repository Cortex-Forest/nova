# Nova Chain — Consensus Integration Implementation Design V2（10-9.2）

- **Status**: Draft（STEP 10-9.2；**实现级设计核对**，待 Review → Micro-Freeze → Design Freeze）
- **Date**: 2026-08-29
- **Scope**: 将 10-9.1（FROZEN，`consensus-integration-implementation-design-v1.md`）冻结契约落实为
  **可直接编码的层面**：精确类型签名、`QcRegistry` canonical rank 计算、N 冻结值、`encode_qc`
  identity 复用、`transition` 原子 pipeline、T1~T19 落点、现有冻结 API 签名兼容性核对。
- **本文件不改变 10-9.1 契约、不修改任何冻结 ADR/代码**；只补充 10-9.2 需要的实现级细节。
- **依据**：10-9.1（FROZEN）MF-1~MF-9、ADR-0033~0040（FROZEN）、既有实现
  `round.rs`/`finality.rs`/`checkpoint.rs`/`fork_choice.rs`/`vote.rs`/`dag.rs`/`validator.rs`。

---

## 0. 方法（实现级核对，非新协议设计）

- **不新增 consensus primitive**：只组装冻结类型（`ValidatorVote`/`QuorumCertificate`/
  `Checkpoint`/`RoundState`/`FinalityState`）。
- **不修改 10-1~10-8 冻结文件**（禁令 12）：新模块 `integration.rs` 只消费其 pub API；
  所需辅助类型/常量（`QcRegistry`/`RoundEvidence`/`MAX_ROUND`/`checked_successor`）全部
  定义在 integration 模块内，**不改** `round.rs` 等任何冻结文件。
- 本文给出的是**可编码规格**：Rust 签名 + 算法伪代码。10-9.2 实现照此直写。

## 1. 模块边界 / 依赖方向

```
crates/consensus/src/integration.rs   （新模块，STEP 10-9.2）
lib.rs 新增： pub mod integration;

依赖方向（单向，同 crate 内 application → protocol）：
integration ──▶ round / finality / checkpoint / fork_choice
          └──▶ vote / validator / dag
禁止：integration ─✗─▶ network / storage / execution / witness / error 新增变体
```

- `integration` 是共识应用层（最上层），只消费冻结 pub API；不导出协议权威类型以外的类型。
- 不修改：`round.rs`/`finality.rs`/`checkpoint.rs`/`fork_choice.rs`/`vote.rs`/`dag.rs`/
  `validator.rs`/`error.rs`/`witness.rs`/冻结 ADR。

## 2. 类型落点（10-9.1 → 可编码）

### 2.1 ConsensusState（MF-1）

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusState {
    pub round: RoundState,       // B-1 canonical state
    pub finality: FinalityState, // F-1 canonical state
}
```

- `PartialEq` 用于 **replay 比对（T4）**。仅含 round+finality；**无 QcRegistry / RoundEvidence /
  LockedState 字段**（MF-1）。

### 2.2 ConsensusEvent + VerifiedVote 概念落点（MF-2）

```rust
pub enum ConsensusEvent {
    /// VerifiedVote 概念落点（MF-2）：**不创建新 primitive**。
    /// `vote` 的 V-5 验证 MUST 已由调用方完成（硬 precondition）；integration 不重新验证签名，
    /// 但绝不把未经验证 Vote 视为协议有效。`signature` 仅用于 MF-8 QC 组装（evidence.signature）。
    Vote { vote: ValidatorVote, signature: [u8; 64] },
    SetProposal(ProposalRef),
    RoundTimeout, // 本地事件（MF-5）
}
```

- `VerifiedVote ≙ (ValidatorVote, [u8;64])`，**不是新类型**（API audit：仓库无 `VerifiedVote`）。
- `signature` 必须保留：`QuorumCertificate.evidence[].signature` 需要它（MF-8 组装）。

### 2.3 TransitionResult 家族（MF-3 / MF-7）

```rust
pub enum TransitionResult {
    Applied {
        next_state: ConsensusState,
        observation: TransitionObservation, // 派生结果（非长期状态）
        derived: TransitionDerived,         // 同 snapshot 派生输出
    },
    Ignored { reason: IgnoreReason },       // state unchanged
    Rejected { reason: RejectReason },      // state unchanged
}

pub struct TransitionObservation {
    pub prevote_quorum: bool,   // 本次是否达成 prevote quorum（B-2）
    pub precommit_quorum: bool, // 本次是否达成 precommit quorum（B-2）
    pub finalized_advance: bool,// 本次 Finality 是否 Advance（F-8）
}

pub struct TransitionDerived {
    pub prevote_qc: Option<QuorumCertificate>,  // 仅 prevote quorum 时 Some（MF-8 组装）
    pub precommit_qc: Option<QuorumCertificate>,// 仅 precommit quorum 时 Some（MF-8 组装）
    pub checkpoint: Option<Checkpoint>,         // 仅 finality Advance 时 Some（CP-MF-4）
    pub fork_choice_head: Option<[u8; 32]>,     // 同 snapshot（MF-4）
}

pub enum IgnoreReason { ContextMismatch, Terminal }
pub enum RejectReason { RoundOverflow }
```

- **`state unchanged` 是 `Ignored`/`Rejected` 的硬语义**；且 **context 也不变**（T18）：
  Ignored/Rejected 路径不 record evidence、不更新 registry、不 reset。
- `prevote_qc`/`precommit_qc` 交调用方：`context.qc_registry.admit(...)` 由 integration 在
  Applied 路径内完成（registry 是 context，由调用方持有、integration 更新）。

### 2.4 IntegrationContext（派生累积器，非 ConsensusState）

```rust
pub struct IntegrationContext {
    pub qc_registry: QcRegistry,        // bounded canonical set（MF-6/MF-9；见 §3）
    pub round_evidence: RoundEvidence,  // 当前 (height, round) 已验证证据（MF-2/MF-8；见 §4）
}
```

- **不是 ConsensusState 字段**（MF-1）：`ConsensusState = { round, finality }` 可持久化 replay 比对；
  context 是调用方维护的派生缓存。
- `transition` 以 `&mut IntegrationContext` 传入；`ConsensusState` 以 `&` 只读（纯计算，无部分更新）。

## 3. QcRegistry — 可编码规格（MF-6 / **MF-9** ★ 重点）

### 3.1 冻结常量：N 的具体值（10-9.2 定值，待 Review）

```rust
/// 冻结协议常量（V0.1）。bounded integration context 容量。
/// 理由：单个 (height, round) 最多产生 1 个 PrevoteQC + 1 个 PrecommitQC；
/// 64 覆盖多 height 的 justified 窗口且保持内存有界、审计可读。
/// 不随验证者数量推导（冻结常量，非运行时函数）。必须 >= 1。
pub const MAX_QC_REGISTRY_ENTRIES: usize = 64;
```

- **N = 64（建议冻结值）**。候选备选（若 Review 否决）：32 / 128；原则是**冻结常量、非推导**。

### 3.2 QC identity = canonical bytes（复用冻结 `encode_qc`）

```rust
/// QC identity（MF-6/MF-9）：直接复用冻结 `finality::encode_qc`（evidence 按
/// validator_id 升序 F-12 ⇒ 确定性）。**不新写编码**。
fn qc_identity(qc: &QuorumCertificate) -> Vec<u8> {
    encode_qc(qc)   // 93B header + n×136B；same logical QC ⇒ same bytes（T17）
}
```

- **同一逻辑 QC（same context/target/validator_set_id/evidence 集）⇒ 同一 identity**（确定性）。
- identity 不依赖 insertion index / Vec position / arrival time / pointer（MF-6 禁用）。

### 3.3 canonical rank = identity 字典序

```rust
/// canonical rank：`qc_identity` 的**字典序**（`Vec<u8>` 的 Ord；total order，输入顺序无关）。
/// registry 最终 = 见过 unique QC 中按该全序取最低 N 个。
```

- 用 `BTreeMap<Vec<u8>, QuorumCertificate>` 承载：key = identity（全序），value = QC。
  - lowest-N 维护：插入后 `len() > N` ⇒ `pop_last()`（移除最大 key）。
  - **permutation invariant（T17）**：BTreeMap 是全序集合，插入顺序不影响最终 key 集。

### 3.4 QcRegistry 结构 + admit 算法

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QcRegistry {
    inner: BTreeMap<Vec<u8>, QuorumCertificate>, // key = qc_identity
}

/// admit 结果（对 registry content 的净效果）。
pub enum QcAdmission {
    Noop,      // same identity 已在 registry（去重）；content 不变
    Inserted,  // 未满插入，或满时按 canonical rank 替换 worst；content 增加候选
    Rejected,  // 满且候选不优于 worst；content 不变
}

impl QcRegistry {
    pub fn new() -> Self { Self { inner: BTreeMap::new() } }

    /// 不变式：inner.len() <= MAX_QC_REGISTRY_ENTRIES（构造即成立，admit 维持）。
    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_full(&self) -> bool { self.inner.len() >= MAX_QC_REGISTRY_ENTRIES }
    pub fn contains(&self, qc: &QuorumCertificate) -> bool {
        self.inner.contains_key(&qc_identity(qc))
    }

    /// canonical bounded set admission（MF-9 方案 A）：
    /// ① same identity ⇒ Noop（去重）；
    /// ② 未满 ⇒ 插入；
    /// ③ 满 ⇒ 候选 rank 优于当前 worst（最大 key）⇒ 替换 worst；否则 ⇒ Rejected。
    /// 结果 = lowest-N（permutation invariant / input-order independent）。
    pub fn admit(&mut self, qc: QuorumCertificate) -> QcAdmission {
        let k = qc_identity(&qc);
        if self.inner.contains_key(&k) {
            return QcAdmission::Noop;
        }
        if self.inner.len() >= MAX_QC_REGISTRY_ENTRIES {
            // 非空（MAX >= 1 且 len >= MAX >= 1）
            let worst = self.inner.keys().next_back().expect("non-empty");
            if k < *worst {
                self.inner.pop_last(); // 确定性替换 worst
            } else {
                return QcAdmission::Rejected;
            }
        }
        self.inner.insert(k, qc);
        QcAdmission::Inserted
    }

    /// 供 fork_choice 消费的 prevote_qcs（FC-13 过滤在 fork_choice 内部完成；此处全量给）。
    /// 迭代顺序 = BTreeMap key 序（确定性）。
    pub fn prevote_qcs(&self) -> Vec<QuorumCertificate> {
        self.inner.values().cloned().collect()
    }
}
```

### 3.5 禁例（MF-6/MF-9）

- **禁止** arrival-order eviction / evict-oldest / evict-newest / truncate Vec / 按到达时间淘汰。
- **禁止** 把 identity 建立在 insertion index / Vec position / arrival time / pointer 上。
- **禁止** registry 无界增长；`len()` 恒 ≤ N。

## 4. RoundEvidence — QC 组装证据（MF-2 / MF-8）

- `VoteAccumulator`（RoundState 内）只存权重 + voter id（**不存 signature**）。QC 组装
  （evidence.signature / source_block_hash / timestamp）需要每票详情 ⇒ integration 维护伴随证据。

```rust
/// 当前 (height, round) 已见**已验证**票（hard precondition：V-5 已通过）。
/// 派生缓存（非 ConsensusState 字段）；round 推进时 reset。
#[derive(Debug, Clone, Default)]
pub struct RoundEvidence {
    /// target → 按 validator_id 升序的 (vote, signature)
    by_target: HashMap<[u8; 32], BTreeMap<ValidatorId, (ValidatorVote, [u8; 64])>>,
    bound: (u64, u64), // (height, round)；绑定守卫
}

impl RoundEvidence {
    pub fn new(height: u64, round: u64) -> Self { Self { by_target: HashMap::new(), bound: (height, round) } }

    /// 记录已验证票（同 validator 同 target 覆盖/幂等）。
    /// 调用方保证 V-5 已通过（MF-2 hard precondition）。
    pub fn record(&mut self, vote: &ValidatorVote, signature: &[u8; 64]) {
        self.by_target
            .entry(vote.target_block_hash)
            .or_default()
            .insert(vote.validator_id, (vote.clone(), *signature));
    }

    /// round 推进时 reset（timeout 路径，§6）；绑定新 (height, round)。
    pub fn reset(&mut self, height: u64, round: u64) {
        self.by_target.clear();
        self.bound = (height, round);
    }

    /// 组装 QC（MF-8：只组装冻结 QuorumCertificate 结构；evidence 升序 = BTreeMap 迭代序）。
    /// 空 evidence（target 无票）⇒ None。
    pub fn assemble_qc(
        &self,
        chain_id: u64,
        validator_set_id: &[u8; 32], // = genesis_hash（F-11）
        target: [u8; 32],
        vote_type: VoteType,
        height: u64,
        round: u64,
    ) -> Option<QuorumCertificate> {
        let entries = self.by_target.get(&target)?;
        let evidence: Vec<QcEvidence> = entries
            .iter()
            .map(|(vid, (v, sig))| QcEvidence {
                validator_id: *vid,
                source_block_hash: v.source_block_hash,
                timestamp: v.timestamp,
                signature: *sig,
            })
            .collect();
        if evidence.is_empty() {
            return None;
        }
        Some(QuorumCertificate {
            context: QcContext { chain_id, height, round, vote_type },
            target,
            validator_set_id: *validator_set_id,
            evidence, // BTreeMap 升序 ⇒ F-12 满足
        })
    }
}
```

- **F-12 升序由构造保证**（BTreeMap<ValidatorId,..> 迭代天然升序），无运行时排序、无排序依赖。
- **bound 守卫**：`record`/`assemble_qc` 隐含绑定 (height,round)；timeout reset 保持确定性。

## 5. transition — 原子 pipeline（MF-3 / MF-4 / MF-7 / MF-8）

### 5.1 签名

```rust
/// 原子 consensus transition（纯计算，无部分更新）。
/// `state` 只读；成功 ⇒ 完整 `next_state`；Ignored/Rejected ⇒ 原状态不变 **且 context 不变**。
/// `chain_id` = 域绑定（QC context / vote 域分离），由调用方传入（冻结不变）。
pub fn transition(
    state: &ConsensusState,
    event: ConsensusEvent,
    context: &mut IntegrationContext,
    chain_id: u64,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> TransitionResult
```

### 5.2 Pipeline（严格顺序；任何 early-return 均不改 state/context）

```
ConsensusEvent
  ├─ SetProposal(p):
  │    round 副本 set_proposal(p)；false（step != Propose）⇒ Ignored{ContextMismatch}
  │    next = ConsensusState { round', finality 不变 }；derived 全 None；observation 全 false
  │    （finality/qc/registry 不变；T6 反向不成立）
  ├─ RoundTimeout:
  │    checked_successor(state.round.round)  ⇒ None ⇒ Rejected{RoundOverflow}（T15；不 wrap）
  │    round' = RoundState::new(height, next_round)；context.round_evidence.reset(height, next_round)
  │    next = ConsensusState { round', finality 不变 }；derived 全 None（timeout≠证据，T14）
  └─ Vote { vote, signature }:
       ① 上下文守卫：vote.height/round ≠ state.round.height/round ⇒ Ignored{ContextMismatch}（T2）
       ② 终态守卫：state.round.step == Finalized ⇒ Ignored{Terminal}（T5）
       ③ record 证据：context.round_evidence.record(vote, signature)
       ④ round 副本 process_vote(vote, weight=set.weight_of(vid), quorum=set.quorum()) → RoundTransition t
       ⑤ if t.prevote_quorum:
             derived.prevote_qc = round_evidence.assemble_qc(chain_id, genesis, target, Prevote, h, r)
             if Some(qc): context.qc_registry.admit(qc)（bounded，MF-9）
       ⑥ if t.precommit_quorum:
             derived.precommit_qc = round_evidence.assemble_qc(chain_id, genesis,
                                                               t.finalized_target, Precommit, h, r)
             if Some(qc):
                if verify_qc(qc, set, genesis, dag).is_ok():      // Validity（F-6a）
                   app = check_finality_applicability(qc, finality.finalized_reference, dag)
                   update_finalized_reference(&mut finality', qc, app)   // Advance 才更新
                   finalized_advance = matches!(app, Applicable{Advance})
                   context.qc_registry.admit(qc)
                   if finalized_advance:                            // checkpoint 仅 Advance（CP-MF-4）
                      derived.checkpoint = derive_checkpoint(finality'.finalized_reference?, qc)
       ⑦ next_state = ConsensusState { round', finality' }
       ⑧ derived.fork_choice_head = fork_choice(                    // 同 snapshot（MF-4）
              dag, next_state.finality.finalized_reference.as_ref(),
              &context.qc_registry.prevote_qcs(), set, genesis)
       ⑨ Applied { next_state, observation, derived }
```

- **原子性**（T11/T18）：所有拒绝路径在 mutate 前 return；Applied 路径一次性产出完整 next_state；
  `qc_registry`/`round_evidence` 只在 Applied 路径更新。
- **QC construction boundary（MF-8）**：`assemble_qc` 只组装冻结 `QuorumCertificate`；integration
  不重新决定 quorum 阈值（用 `set.quorum()`）、vote context（用 vote 数据）、target（用
  `t.finalized_target`）、signer set（BTreeMap 升序全票）、signature coverage（evidence 原样）、
  genesis binding（`expected_genesis_hash`）。
- **ForkChoice 单向下游**（边界 6）：`fork_choice` 返回值不反向影响 next_state。

## 6. timeout / MAX_ROUND / checked_successor（MF-5）

```rust
/// 协议冻结上限（10-9.2 定值）：类型上界，`checked_add(1)` 语义 ⇒ 不 wrap、不 panic。
/// 不引入武断协议数值；到达即 RoundOverflow（确定性拒绝）。
pub const MAX_ROUND: u64 = u64::MAX;

pub fn checked_successor(r: u64) -> Option<u64> { r.checked_add(1) }
```

- RoundTimeout 路径：`checked_successor(state.round.round)`；`None`（r == u64::MAX）⇒
  `Rejected{RoundOverflow}`（T15）。debug/release 行为一致（`checked_add` 无溢出行为差异）。
- timeout **不**产生 PrevoteQC / PrecommitQC / finality 变更 / checkpoint / finalized reference
  变化（T14）。

## 7. 现有冻结 API 签名兼容性核对（10-9.2 实测）

| 冻结 API（实际签名） | 10-9.2 使用点 | 兼容 |
|---|---|---|
| `process_vote(&mut RoundState, &ValidatorVote, u128, u128) -> RoundTransition` | §5.2 ④ | ✅ |
| `RoundTransition { new_step, prevote_quorum, precommit_quorum, finalized_target }` | §5.2 ⑤⑥ | ✅ |
| `RoundState::new(height, round)` / `set_proposal(p) -> bool` / `step` | §5.2 SetProposal/timeout | ✅ |
| `RoundStep::Finalized`（终态守卫） | §5.2 ② | ✅ |
| `verify_qc(qc, set, genesis, dag) -> Result<(), FinalityError>` | §5.2 ⑥ Validity | ✅ |
| `check_finality_applicability(qc, Option<&[u8;32]>, dag) -> Applicability` | §5.2 ⑥ | ✅ |
| `update_finalized_reference(&mut FinalityState, qc, Applicability) -> Result<(),FinalityError>`（Precommit-only 代码强制） | §5.2 ⑥ | ✅ |
| `FinalityState { finalized_reference: Option<[u8;32]>, highest_precommit_qc }` | ConsensusState 字段 / ⑦ | ✅ |
| `encode_qc(&QuorumCertificate) -> Vec<u8>` | §3.2 identity | ✅ 直接复用 |
| `derive_checkpoint([u8;32], &QuorumCertificate) -> Option<Checkpoint>` | §5.2 ⑥ | ✅ |
| `fork_choice(&Dag, Option<&[u8;32]>, &[QuorumCertificate], &ValidatorSet, &[u8;32]) -> Option<[u8;32]>` | §5.2 ⑧ | ✅ |
| `ValidatorSet::quorum() -> u128` / `weight_of(id) -> Option<u128>` | §5.2 ④ | ✅ |
| `ValidatorId: Ord`（字节序）/ `from_bytes` / `as_bytes` | §4 BTreeMap 升序 | ✅ |
| `Dag::contains/parents_of/tips/causal_order` | fork_choice 输入 | ✅ |
| `VoteType { Prevote, Precommit }` / `ValidatorVote` 字段 | §4 组装 | ✅ |

- **无签名冲突、无缺失依赖**。10-9.2 需要新增的仅：`MAX_QC_REGISTRY_ENTRIES` / `MAX_ROUND` /
  `checked_successor` / `QcRegistry` / `RoundEvidence` / `ConsensusState` / `ConsensusEvent` /
  `TransitionResult` 家族 / `IntegrationContext` / `transition` —— 全部在 `integration.rs` 内。

## 8. 冻结常量表（10-9.2 定值，待 Review）

| 常量 | 值 | 依据 |
|---|---|---|
| `MAX_QC_REGISTRY_ENTRIES` | **64** | 单 (height,round) 最多 2 QC；覆盖多 height justified 窗口；内存有界；≥1 |
| `MAX_ROUND` | `u64::MAX` | 类型上界；`checked_add` 语义；不 wrap（MF-5） |

## 9. T1~T19 落点（integration.rs `#[cfg(test)]`）

| # | 落点/断言 |
|---|---|
| T1 | 完整生命周期：SetProposal(A)→prevote quorum→`derived.prevote_qc=Some`→precommit quorum→`precommit_qc=Some`+`finalized_advance=true`+`checkpoint=Some`+`fork_choice_head=Some(A)` |
| T2 | Vote 的 height/round ≠ state ⇒ `Ignored{ContextMismatch}`；state 与 context 均不变 |
| T3 | 同 validator 同 target 重复 vote ⇒ 状态不变（VoteAccumulator 去重） |
| T4 | replay：同事件序列作用于两个独立 (state,context) ⇒ `ConsensusState` `PartialEq` 相等 |
| T5 | `step==Finalized` 后 vote ⇒ `Ignored{Terminal}` |
| T6 | finality Advance ⇒ head==finalized_reference（FC-12 短路）；仅 prevote_qcs 变化不反向改 finality |
| T7 | checkpoint 仅 finality Advance：Idempotent/无对应 QC ⇒ `checkpoint=None` |
| T8 | timeout ⇒ round+1、finality 保留、derived 全 None |
| T9 | proptest：随机事件序列 ⇒ 同输入同输出（determinism） |
| T10 | API 审查/编译断言：无新 quorum/signature/target/QC-validity 规则；只消费冻结类型 |
| T11 | Atomic：所有拒绝路径 ⇒ `state_after == state_before` 且 context 无 partial mutation |
| T12 | Snapshot：`fork_choice_head` 与 `next_state.finality` 同 snapshot（MF-4） |
| T13 | VerifiedVote 边界：integration 不调用 `verify_vote`（审查断言）；已验证票可进入 |
| T14 | timeout：round 前进；PrevoteQC/PrecommitQC=None、Finality 不变、Checkpoint=None |
| T15 | `state.round.round == u64::MAX` + RoundTimeout ⇒ `Rejected{RoundOverflow}`；不 wrap（round 保持 u64::MAX） |
| T16 | registry bounded：admit >N unique QC ⇒ `len() <= N`；same QC 重复 ⇒ 单条目（`Noop`） |
| T17 | **permutation invariance**：MAX=N；S 与 permutations(S) ⇒ registry content 相等；duplicate ⇒ one identity；capacity exceeded ⇒ lowest-N（deterministic replacement/rejection）；`encode_qc` 集合字段确定性 |
| T18 | Rejection semantics：height/round mismatch / Finalized 违例 / MAX_ROUND timeout ⇒ state 不变 + `round_evidence` 无记录 + registry 无变化 |
| T19 | Frozen QC construction：same RoundTransition ⇒ same QC；不改 quorum 阈值/vote context/target/signer set/signature coverage/genesis binding |

## 10. 边界确认

- **不新增 consensus primitive**：`QcRegistry`/`RoundEvidence`/`TransitionResult` 是 integration
  层派生结构，非协议权威类型；不产生新 finality/quorum/QC-validity 规则（MF-8）。
- **QcRegistry 不升级为 ConsensusState**（MF-1/MF-9）：仍是 bounded integration context。
- **不扩大成 node**：无 network/storage/persistence/execution/mempool/P2P/调度。
- **LockedState / acquire_lock 不进入 pipeline**（O-4 / 范围修正）。
- **不改冻结文件 / ADR**；依赖方向单向。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-29 | 初稿：10-9.2 实现级设计（类型落点 / QcRegistry canonical rank+N=64+encode_qc identity / RoundEvidence / transition pipeline / MAX_ROUND / API 签名核对 / T1~T19 落点） | 10-9.1 Design Freeze（aa433d3）后进入 10-9.2 |
