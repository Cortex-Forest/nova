# Nova Chain — Consensus Integration Implementation Design V2（10-9.2）

- **Status**: **FROZEN**（STEP 10-9.2 DESIGN FREEZE + **STEP 10-9.3 IMPLEMENTATION
  FINAL FREEZE**，2026-08-29；MF-10/MF-11/MF-12 CLOSED，T20~T23 PASS，N=64 FREEZE）
- **Date**: 2026-08-29
- **Scope**: 将 10-9.1（FROZEN，`consensus-integration-implementation-design-v1.md`）冻结契约落实为
  **可直接编码的层面**：精确类型签名、`QcRegistry` canonical rank 计算、N 冻结值、`encode_qc`
  identity 复用、`transition` 原子 pipeline、T1~T23 落点、现有冻结 API 签名兼容性核对。
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
- `prevote_qc` 交调用方：`context.qc_registry.admit(...)` 由 integration 在 Applied 路径内完成
  （registry 是 context，Prevote-only，§3.0）；`precommit_qc` 作为 derived output 交调用方
  （F-14 恢复事实等），**不经 registry**（MF-10 S1）。

### 2.4 IntegrationContext（派生累积器，非 ConsensusState）

```rust
pub struct IntegrationContext {
    pub qc_registry: QcRegistry,        // bounded **Prevote**-QC canonical set（MF-6/MF-9/MF-10；§3）
    pub round_evidence: RoundEvidence,  // 当前 (height, round) 已验证证据（MF-2/MF-8/MF-11；§4）
}
```

- **不是 ConsensusState 字段**（MF-1）：`ConsensusState = { round, finality }` 可持久化 replay 比对；
  context 是调用方维护的派生缓存。
- `transition` 以 `&mut IntegrationContext` 传入；`ConsensusState` 以 `&` 只读（纯计算，无部分更新）。

## 3. QcRegistry — 可编码规格（MF-6 / **MF-9** / **MF-10** ★ 重点）

### 3.0 类型范围（Review-4 冻结）：registry = **PrevoteQC-only**

- **QcRegistry 只保存 PrevoteQC**（ForkChoice 的 justified-anchor 输入）。
- **PrecommitQC 不进 registry**：pipeline ⑥ 直接组装 → `verify_qc` → finality/checkpoint，并作为
  `derived.precommit_qc` 交付调用方（F-14 恢复事实等）；**与 registry 无数据流**（MF-10 S1）。
- **ForkChoice 只消费 `registry.prevote_qcs()`（全为 Prevote）**；`fork_choice` 不重新解释 QC type
  （FC-13 的 `vote_type==Prevote` 是防御性 guard；输入侧已保证 Prevote-only）。
- pipeline 只在 prevote quorum 分支（⑤）调用 `admit`；precommit 分支（⑥）不调用 ⇒ 结构上
  registry 恒为 Prevote-only。

### 3.1 冻结常量：N 的具体值（10-9.2 定值，待 Review）

```rust
/// 冻结协议常量（V0.1）。bounded **Prevote**-QC registry 容量（MF-10）。
/// 语义理由（MF-10）：registry 只保存 PrevoteQC（§3.0）；无 finality 推进阶段
/// 单 (height, round) 至多 1 个 PrevoteQC（B-2 quorum 语义）；正常 justified 窗口 ≪ 64；
/// 64 提供该窗口内工程余量，使正常协议运行下 justified anchors 不被截断。
/// 极端超限下的截断语义由 MF-10（§3.6 S1/S2/S3）保证不丢失冻结语义。
/// 不随验证者数量推导（冻结常量，非运行时函数）。必须 >= 1。
pub const MAX_QC_REGISTRY_ENTRIES: usize = 64;
```

- **N = 64（Review-4 H-4 ACCEPT，可冻结）**。候选备选 32/128 已放弃；原则是**冻结常量、非推导**。

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

    /// canonical bounded set admission（MF-9 方案 A；**Prevote-only，§3.0**）：
    /// 调用方保证只对 PrevoteQC 调用（pipeline ⑤ 仅 prevote 分支调 admit）。
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

### 3.6 MF-10 — Bounded Registry Semantic Safety

> **冻结**：`QcRegistry` 的 bounded retention **不得改变任何在其输入语义要求下必须可观察的
> ForkChoice/Finality 结果**。registry 的截断只是 deterministic 的输入子集变化，不是语义变化。

**可观察范围**：registry 的唯一协议可观察输出 = `prevote_qcs()`（ForkChoice justified-anchor 输入）
+ `contains/len`（调试/断言）。**Finality/Checkpoint 不经 registry**（pipeline ⑥ 直接消费 transition
内组装的 PrecommitQC）——registry 与 finality/checkpoint **无数据流**。

**生命周期**：registry 由调用方持有；内容**不进入 `ConsensusState`**（replay 比对仅针对
`ConsensusState{round, finality}`）；registry = "当前可见 justified 上下文的 bounded 摘要"。

**语义安全不变量**：
- **S1 — Finality/Checkpoint 截断无关**：PrecommitQC 永不进入 registry（§3.0）⇒ registry 截断
  **不可能**改变 finality 或 checkpoint 结果（数据流分离）。**T22 验证**。
- **S2 — 有 finality 时 head 截断无关**：一旦 `finalized_reference ∈ DAG`，FC-12 绝对短路 ⇒
  `fork_choice_head ≡ finalized_reference`，**与 registry 内容无关**。**T22 验证**。
- **S3 — 无 finality 时 head 是确定性建议**：无 finality 时 head 由 justified anchors（registry 的
  PrevoteQC ∩ FC-13）或 root fallback 决定。registry 截断（canonical lowest-N）只改变**输入集**，
  不改 `fork_choice` 函数行为；head 变化 = 确定性建议变化（同输入 ⇒ 同 registry ⇒ 同 head；
  replay 可复现），**不构成最终性/安全承诺丢失**（无 finality 时 head 非共识安全状态）。

**为什么 64 / 不足时会发生什么 / 截断后 ForkChoice 仍符合冻结语义**：
1. **为什么 64**：registry 只含 PrevoteQC；无 finality 推进阶段单 (height,round) 至多 1 个
   PrevoteQC（B-2）；正常 justified 窗口 ≪ 64 ⇒ 正常协议运行下 anchors 不被截断。
2. **64 不足时**：按 canonical rank 淘汰 worst；`prevote_qcs()` 少一些 anchor；无 finality 时 head
   变为剩余 maximal anchor 的 frontier 或 root fallback——**确定性**（同输入同输出），且
   S1/S2 保证 finality/checkpoint 与有 finality 时的 head 不受影响。
3. **截断后仍符合冻结语义**：10-8 冻结的 "ForkChoice 语义" = **函数行为**（deterministic、
   finality-dominant、input-order-independent），非特定 head 值；对任何 registry 输入子集，
   `fork_choice` 均产生确定性、finality-dominant、input-order-independent 的结果（T21/T22 验证）。

## 4. RoundEvidence — QC 组装证据（MF-2 / MF-8 / **MF-11**）

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

### 4.1 MF-11 — RoundEvidence Ephemeral Boundary

> **冻结**：`RoundEvidence` 仅用于当前 round 上下文的 **QC construction**；**不得成为
> `ConsensusState`、不得参与 replay 之外的隐式状态、不得通过 arrival order 或历史事件累积
> 产生协议语义。**

1. **非 ConsensusState**：`RoundEvidence` 是 integration context 派生缓存，不是 `ConsensusState`
   字段；**replay 比对仅针对 `ConsensusState{round, finality}`**（T4 排除 evidence）。
2. **绑定 + reset**：`RoundEvidence` 绑定当前 (height, round)；timeout 推进时确定性 `reset` 为空 ⇒
   **不跨 round 累积、不无限增长**。
3. **唯一协议用途 = QC construction**（MF-8 组装冻结 `QuorumCertificate`）；不参与 vote validity
   判定（V-5 硬 precondition 由调用方）、不改 quorum、不改 finality、不改 checkpoint。
4. **arrival-order independence**：QC 组装按 `validator_id` 升序（BTreeMap 迭代），与提交顺序无关
   ⇒ **不通过 arrival order / 历史事件累积产生非确定性协议语义**。
5. **实现约束**：transition Vote 分支**仅在 Applied 路径** `record`（T18）；`RoundEvidence` 存活
   范围 = 当前 round 的 transitions 序列，round 推进即消亡（reset）。

## 5. transition — 原子 pipeline（MF-3 / MF-4 / MF-7 / MF-8）

### 5.1 签名

```rust
/// 原子 consensus transition（纯计算，无部分更新；**MF-12 三元组契约**）。
/// `state` 只读；成功 ⇒ 完整 `next_state` + 确定性 `context` 更新；Ignored/Rejected ⇒
/// 原状态不变 **且 context 不变**（MF-12 契约 3）。
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
             if Some(qc): context.qc_registry.admit(qc)（仅 Prevote 入 registry，§3.0/MF-10 S1）
       ⑥ if t.precommit_quorum:
             derived.precommit_qc = round_evidence.assemble_qc(chain_id, genesis,
                                                               t.finalized_target, Precommit, h, r)
             if Some(qc):
                // PrecommitQC 不经 registry（§3.0/MF-10 S1）：直接驱动 finality/checkpoint。
                if verify_qc(qc, set, genesis, dag).is_ok():      // Validity（F-6a）
                   app = check_finality_applicability(qc, finality.finalized_reference, dag)
                   update_finalized_reference(&mut finality', qc, app)   // Advance 才更新
                   finalized_advance = matches!(app, Applicable{Advance})
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

### 5.3 MF-12 — IntegrationContext Determinism（Review-5 冻结）

> **冻结**：consensus transition 的完整契约是**三元组映射**：
> ```
> (ConsensusState, IntegrationContext, ConsensusEvent)
>     → (ConsensusState', IntegrationContext', TransitionResult)
> ```
> 必须满足六条确定性契约。

1. **同输入同输出**：相同 `state + context + event` ⇒ 相同 `(next_state, next_context, result)`。
2. **容器/顺序无关**：相同**逻辑** context（不同内部容器/insertion order）⇒ 相同结果
   （QcRegistry 用 BTreeMap 全序 key、RoundEvidence 用 BTreeMap 升序 evidence ⇒ 结构性保证）。
3. **Ignored/Rejected ⇒ state 与 context 均不变**（T18/T23）。
4. **Applied ⇒ context 变化完全由 canonical admission / evidence rules 决定**
   （PrevoteQC → canonical lowest-N admit；evidence → 按 validator_id 升序 record），无任意/顺序依赖。
5. **QcRegistry 不依赖 arrival order**（MF-9 禁例 + BTreeMap 全序）。
6. **replay 语义**：`ConsensusState{round, finality}` 是 replay 比对对象；`IntegrationContext` 为
   **可重建 derived cache（H-3）**——replay 必须**同时重建 context**（由同一事件流按相同规则
   record/admit），或 context 被定义为可由事件流重放的 derived cache；两者等价。

**H-3（非阻塞建议，已并入 MF-12 契约 6）**：
> `QcRegistry` is a bounded, **rebuildable** integration context/cache; it is **not** canonical
> consensus state. **丢失 `QcRegistry` ≠ consensus-state corruption**；恢复节点若缺历史
> PrevoteQC，必须通过 replay/rebuild 路径重新获得相同 context（由事件流按 canonical rules 重建）。

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
| `MAX_QC_REGISTRY_ENTRIES` | **64** | PrevoteQC-only registry（§3.0）；无 finality 阶段单 (h,r) 至多 1 PrevoteQC；正常 justified 窗口 ≪64；截断语义安全由 MF-10 S1/S2/S3 保证；≥1；Review-4 H-4 ACCEPT |
| `MAX_ROUND` | `u64::MAX` | 类型上界；`checked_add` 语义；不 wrap（MF-5） |

## 9. T1~T23 落点（integration.rs `#[cfg(test)]`）

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
| T16 | registry bounded（Prevote-only）：admit >N unique PrevoteQC ⇒ `len() <= N`；same QC 重复 ⇒ 单条目（`Noop`） |
| T17 | **permutation invariance**：MAX=N；S（全部 PrevoteQC）与 permutations(S) ⇒ registry content 相等；duplicate ⇒ one identity；capacity exceeded ⇒ lowest-N（deterministic replacement/rejection）；`encode_qc` 集合字段确定性 |
| T18 | Rejection semantics：height/round mismatch / Finalized 违例 / MAX_ROUND timeout ⇒ state 不变 + `round_evidence` 无记录 + registry 无变化 |
| T19 | Frozen QC construction：same RoundTransition ⇒ same QC；不改 quorum 阈值/vote context/target/signer set/signature coverage/genesis binding |
| T20 | **QC Identity Completeness（Review-4）**：对影响 QC validity/semantic 的每个字段 mutate ⇒ `encode_qc` 不同（injective canonical coverage）。字段：`vote_type`/`target`/`height`/`round`/`genesis_hash(validator_set_id)`/`evidence`（`validator_id`/`source_block_hash`/`timestamp`/`signature`）。依据：ADR-0038 冻结 `encode_qc`（QuorumCertificate{context{chain_id,height,round,vote_type},target,validator_set_id,evidence[]}，evidence=QcEvidence{validator_id,source_block_hash,timestamp,signature} 全字段无遗漏） |
| T21 | **Registry adversarial（Review-4）**：N unique QCs（混合 Prevote + Precommit）+ 不同 permutation ⇒ registry canonical content 相同；PrecommitQC **不进入** registry（§3.0）⇒ ForkChoice 只消费 PrevoteQC（`precommit_qcs` 不构成 anchor）；Finality 只消费对应 PrecommitQC（不经 registry） |
| T22 | **MF-10 截断安全**：`finalized_reference ∈ DAG` 时 registry 截断（含极端超 N）不改变 `fork_choice_head`（恒 == finalized_reference，FC-12 S2）；registry 截断不改变 finality/checkpoint 结果（S1） |
| T23 | **Context Determinism / Replay（MF-12）**：同一 logical history 以不同 insertion/事件顺序构造 context（C1+E1,E2,E3 vs C2+E3,E1,E2）⇒ `ConsensusState'1==ConsensusState'2`、`IntegrationContext'1==IntegrationContext'2`（QcRegistry + RoundEvidence 一致）、`Derived'1==Derived'2`（含 fork_choice_head）；Ignored/Rejected ⇒ state **且 context** 均不变 |

## 10. 边界确认

- **不新增 consensus primitive**：`QcRegistry`/`RoundEvidence`/`TransitionResult` 是 integration
  层派生结构，非协议权威类型；不产生新 finality/quorum/QC-validity 规则（MF-8）。
- **QcRegistry 不升级为 ConsensusState**（MF-1/MF-9/MF-10）：仍是 bounded integration context；
  截断只改变 ForkChoice 输入子集，不改变 finality/checkpoint 或已 final 的 head（MF-10 S1/S2）。
- **RoundEvidence 不升级为隐式 consensus state**（MF-11）：绑定 (height,round)、round 推进即
  reset；唯一用途 QC construction；arrival-order independent。
- **IntegrationContext 是 rebuildable derived cache（MF-12/H-3）**：transition 契约 =
  (state, context, event) → (state', context', result)；丢失 context ≠ consensus-state corruption；
  replay 必须同时重建 context（canonical rules）。
- **不扩大成 node**：无 network/storage/persistence/execution/mempool/P2P/调度。
- **LockedState / acquire_lock 不进入 pipeline**（O-4 / 范围修正）。
- **不改冻结文件 / ADR**；依赖方向单向。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-29 | 初稿：10-9.2 实现级设计（类型落点 / QcRegistry canonical rank+N=64+encode_qc identity / RoundEvidence / transition pipeline / MAX_ROUND / API 签名核对 / T1~T19 落点） | 10-9.1 Design Freeze（aa433d3）后进入 10-9.2 |
| 2026-08-29 | 落实 MF-10（registry 截断语义安全 S1/S2/S3 + N=64 语义理由）/ MF-11（RoundEvidence ephemeral boundary）/ Review-4：registry=PrevoteQC-only、PrecommitQC 不经 registry / T20（identity completeness）/ T21（registry adversarial 混合类型+permutation）/ T22（截断安全） | 10-9.2 Review 🟡 APPROVED WITH REQUIRED MF-10/MF-11/T20 |
| 2026-08-29 | 落实 **MF-12**（IntegrationContext Determinism：三元组契约 + 六条确定性规则 + replay 重建语义）/ T23（Context Determinism / Replay）/ 并入 H-3（QcRegistry rebuildable derived cache）与 H-4（N=64 ACCEPT） | 10-9.2 Final Review 🟡 APPROVED WITH 1 REQUIRED MICRO-FREEZE — MF-12 |
| 2026-08-29 | **DESIGN FREEZE（10-9.2）**：Status Draft→FROZEN。Final Review 🟢 APPROVED：MF-10/11/12 CLOSED、T20~T23 PASS、N=64 ACCEPT/FREEZE、PrevoteQC-only registry、QcRegistry rebuildable non-canonical、Ignored/Rejected 原子性、新增 consensus primitive 0、protocol violation 0、blocker 0。10-9.3 Implementation 未启动（HARD STOP） | 用户最终裁决 🟢 APPROVED FOR DESIGN FREEZE |
| 2026-08-29 | **IMPLEMENTATION FINAL FREEZE（10-9.3）**：`crates/consensus/src/integration.rs`（commit `92ef8c5`）+ `lib.rs` 模块注册；T1~T23（含 T7/T11/T13/T15/T17/T18/T20/T21/T22/T23）全 PASS；四项 Gate（fmt/check/test/clippy -D warnings）PASS；源码级 Security/Protocol Review APPROVED（无 verify_vote/acquire_lock/LockedState；PrevoteQC-only registry；finalized_advance 仅 Advance；原子性；无新 primitive；0 BLOCKER / 0 MUST-FIX）；工作区 clean | 用户授权 STEP 10-9 FINAL FREEZE — **STEP 10-9 CLOSED** |
