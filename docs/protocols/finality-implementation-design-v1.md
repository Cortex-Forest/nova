# Nova Chain — Finality/QC Implementation Design V1（10-6.1）

- **Status**: Draft（STEP 10-6.1；**APPROVED WITH 6 MICRO-FREEZES**，待 10-6.2 实现）
- **Date**: 2026-08-28
- **Scope**: QC / Finality 的**实现设计**（模块边界、API 契约、集成流程、测试计划）。
- **依据**：ADR-0038 F-1~F-18（含 MF-1~MF-4、F-1 三概念分离、A-prop 精确化）、ADR-0034 V-3/V-4/V-5、
  ADR-0035 D-1~D-4、ADR-0037 B-1~B-6、consensus-spec-v1.md。
- **本文件是设计契约，不是代码实现**。实现（10-6.2）必须严格遵循本契约。

---

## 0. 核心状态机（冻结总纲）

```
                    ┌──────────────────────┐
                    │      ValidatorVote   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   collect evidence   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Construct Precommit│
                    │          QC          │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      verify_qc()     │
                    │      VALIDITY        │
                    └──────────┬───────────┘
                               │
                         Valid QC
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
      acquire_lock()             check_finality_applicability()
              │                                 │
              │                    ┌────────────┼────────────┐
              │                    ▼            ▼            ▼
              │                 Advance     Idempotent    Conflict
              │                    │            │            │
              └────────────────────┴────────────┴────────────┘
                                           │
                                           ▼
                              update_finalized_reference()
                                           │
                                           ▼
                                  FinalityState
```

**硬约束**：`verify_qc()` **永不**直接修改 `FinalityState`；四层职责独立（见 MF-10-6.1-4）。

---

## 1. 模块边界（10-6.1-A）

- 新模块 `crates/consensus/src/finality.rs`（QC 类型 + FinalityState + 四 API）。
- 依赖保持 `consensus → core/crypto`；禁 `→ execution/storage/network`（C-1）。
- 可访问同 crate `dag.rs`（F-8 需 DAG parent relation）。

### 1.1 类型（API 设计，非实现）

```rust
pub struct QcContext {
    pub chain_id: u64,
    pub height: u64,
    pub round: u64,
    pub vote_type: VoteType,          // F-3
}

pub struct QcEvidence {
    pub validator_id: ValidatorId,
    pub source_block_hash: [u8; 32],  // F-10：签名内字段
    pub timestamp: u64,               // F-10：签名内字段
    pub signature: [u8; 64],          // Ed25519
}

pub struct QuorumCertificate {
    pub context: QcContext,           // F-2
    pub target: [u8; 32],             // F-2 / F-1（Finalized Block = QC.target）
    pub validator_set_id: [u8; 32],   // = genesis_hash（F-11）
    pub evidence: Vec<QcEvidence>,    // F-12 validator_id 字节升序
}

pub struct FinalityState {
    pub finalized_reference: Option<[u8; 32]>,        // F-1：latest finalized block（非证明）
    pub highest_precommit_qc: Option<QuorumCertificate>, // F-14 恢复事实（node 层消费）
}
```

### 1.2 QC canonical 编码（NEW FREEZE 延续）

按 `crypto-serialization-v1.md` 规则：
`context(chain_id 8LE ‖ height 8LE ‖ round 8LE ‖ vote_type 1B) ‖ target 32B ‖ validator_set_id 32B ‖
count 4LE ‖ count×(validator_id 32B ‖ source 32B ‖ timestamp 8LE ‖ signature 64B)`。

**编码/解码职责分离（MF-10-6.1-1）**：`decode_qc(bytes)` 负责 bytes → 结构化 QC（含结构/有序性验证）；
`verify_qc()` **不承担**任何序列化/反序列化职责。

---

## 2. API 契约

### 2.1 `decode_qc`（bytes → QC；MF-10-6.1-1）

```rust
pub fn decode_qc(bytes: &[u8]) -> Result<QuorumCertificate, FinalityError>;
```
- 验证结构合法 + evidence 已按 `validator_id` 升序（F-12）。
- 产出结构化 `QuorumCertificate` 后**才**可进入 `verify_qc`。

### 2.2 `verify_qc`（Layer 1 — Validity；MF-10-6.1-1/2/3）

```rust
pub fn verify_qc(
    qc: &QuorumCertificate,            // 已结构化（decode_qc 产物）
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> Result<(), FinalityError>;
```
- **输入已是结构化对象**；不负责 decode（MF-10-6.1-1）。
- 检查：context 自洽 → target ∈ DAG → validator_set_id == genesis_hash → evidence 有序 / duplicate ⇒ Err
  → 逐条重建 `ValidatorVote` 并经 `verify_vote`（V-5 五步复用）→ 权重 → quorum。
- **唯一 canonical target = `QC.target`（MF-10-6.1-2）**：`QcEvidence` **不存在**独立 block hash；
  重建 `ValidatorVote.block_hash = QC.target`。**禁止** `QC.target / Evidence.target / Vote.block_hash`
  三个潜在不一致来源。
- **禁止推导 `source == parent(target)`（MF-10-6.1-3）**：`source_block_hash` 仅是签名时
  ValidatorVote 的 `source` 字段，**不代表 QC target，不自动代表 target 的 parent**；除非未来冻结协议
  明确规定该关系，否则不得在验证中额外推导。
- **不检查 `QC.target == current proposal.target`**（禁令 2：仅属 formation 层）。
- **不 finalize**（禁令 3）。

### 2.3 `check_finality_applicability`（Layer 2 — Relation）

```rust
pub enum UpdateMode { Idempotent, Advance }
pub enum InapplicableReason { Stale, Conflict }
pub enum Applicability {
    Applicable { mode: UpdateMode },
    Inapplicable { reason: InapplicableReason },
}

pub fn check_finality_applicability(
    qc: &QuorumCertificate,            // 调用方保证 verify_qc Ok（PrecommitQC）
    finalized: Option<&[u8; 32]>,
    dag: &Dag,
) -> Applicability;
```
- 仅对 PrecommitQC 调用（F-4）。
- **关系只用 DAG parent relation**（禁令 5）：`finalized==None → Advance`；`Y==X → Idempotent`；
  descendant → Advance；ancestor → Stale；unrelated → Conflict。
- **Valid-but-inapplicable ≠ Invalid**（F-9/MF-3）：返回枚举值而非 Err。

### 2.4 `acquire_lock`（Lock transition；MF-10-6.1-4 + **MF-10-6.2-1**）

```rust
pub fn acquire_lock(lock: &mut LockedState, qc: &QuorumCertificate) -> Result<(), FinalityError>;
```
- **Precommit-only 强制（代码级）**：`qc.context.vote_type != Precommit` ⇒ `Err(NotPrecommitQc)`，lock **不改变**。
- **不重复执行完整 QC verification**（MF-10-6.1-4）：`acquire_lock` 只做 Lock transition
  （`lock.lock(qc.target, qc.context.round)`，B-5）。
- **禁止**把 `verify QC + check Precommit + lock + finalize` 揉进 `acquire_lock`。

### 2.5 `update_finalized_reference`（Finality state transition；MF-10-6.1-6 + **MF-10-6.2-1**）

```rust
pub fn update_finalized_reference(
    state: &mut FinalityState,
    qc: &QuorumCertificate,
    applicability: Applicability,
) -> Result<(), FinalityError>;
```
**行为冻结**：

| Applicability | 行为 |
|---|---|
| `Advance` | **更新** `state.finalized_reference = Some(qc.target)` |
| `Idempotent` | 不改变状态 |
| `Stale` | 不改变状态 |
| `Conflict` | **不改变状态**（evidence 保留） |

- **Precommit-only 强制（代码级）**：`qc.context.vote_type != Precommit` ⇒ `Err(NotPrecommitQc)`，
  FinalityState **不改变**。
- **`Conflict ≠ Error`**（MF-3/F-9）：`Conflict` 对 **Valid PrecommitQC** 不产生 Err，仅不更新。
- **单调不变量（MF-10-6.1-5）**：
  > **`finalized_reference` only advances according to verified DAG ancestry; numeric height/round
  > MUST NOT determine advancement.**
  - 一旦从 X 更新为 Y，后续不得回退到 X 的 ancestor；
  - **禁止** `if qc.height > finalized_height` 式判断（禁令 5）。

### 2.6 四职责分离（MF-10-6.1-4 总纲）

```
verify_qc                     = Validity
check_finality_applicability  = Relation
acquire_lock                  = Lock transition
update_finalized_reference    = Finality state transition
```

---

## 3. LockedState / RoundState Integration（10-6.1-D/E）

- **LockedState 不新增字段**（`{locked_block_hash, locked_round}` 足够）。
- `acquire_lock` 复用 `LockedState::lock`；后续投票约束复用 `is_compatible`（B-5）——validator 本地使用；
  **状态机强制未实现（GAP D），不得偷塞**。
- **RoundState 保持现状**（B-1 纯计算）；`FinalityState` 独立维护（F-6c）。
- 集成驱动流程（本地事件流）：
  ```
  process_vote → RoundTransition{precommit_quorum, finalized_target: Some(X)}
    → Construct PrecommitQC(X, r)
    → verify_qc            （Validity）
    → acquire_lock         （Lock(X,r)）
    → check_finality_applicability（Relation）
    → update_finalized_reference  （Layer 3；Conflict 时保留 evidence 不更新）
  ```

---

## 4. Error Mapping（10-6.1-F；不改 error.rs）

新增 `FinalityError`（归属实现时经 ADR 决定）：

| 场景 | 错误 |
|---|---|
| decode / 结构非法 / evidence 未有序 | `InvalidQcStructure` |
| duplicate validator_id | `DuplicateValidator` |
| `validator_set_id ≠ genesis_hash` | `ValidatorSetMismatch` |
| target 不在 DAG | `UnknownTarget` |
| evidence 签名/身份失败 | 映射现有 `ConsensusError::{UnknownValidator, ValidatorIdentityMismatch, InvalidSignature}` |
| 权重 < quorum | `InsufficientQuorum` |
| **Valid 但与 finalized 冲突** | **非错误** → `Applicability::Inapplicable{Conflict}` |

---

## 5. Test Plan（10-6.1-G）

| # | 用例 | 期望 |
|---|---|---|
| 1 | 多 validator 达 quorum 的 PrecommitQC → verify Ok | Valid |
| 2 | 仅凭 QC（无原始 Vote 对象）重建 vote → verify（BLOCKER 1 回归） | Ok |
| 3 | 篡改单条 signature / source / timestamp / target | Invalid |
| 4 | evidence 乱序 | InvalidQcStructure |
| 5 | duplicate validator_id | DuplicateValidator |
| 6 | 权重恰好差 1（quorum−1） | InsufficientQuorum |
| 7 | `validator_set_id` 不符 | ValidatorSetMismatch |
| 8 | target 不在 DAG | UnknownTarget |
| 9 | 跨 chain_id | 签名失败（InvalidSignature） |
| 10 | applicability：same→Idempotent；descendant→Advance；ancestor→Stale；unrelated→Conflict | 各枚举值 |
| 11 | **valid-but-inapplicable 返回 `Inapplicable{Conflict}` 而非 Err**，evidence 保留 | 非错误 |
| 12 | valid PrecommitQC → acquire_lock(X,r)；is_compatible（same/descendant/unrelated） | lock 正确 |
| 13 | equivocation：同 validator 两 target 的 QC evidence 均保留 | 证据完整 |
| 14 | proptest：随机 evidence 子集 quorum 边界；QC 编码 roundtrip（decode_qc ↔ 编码） | 属性保持 |
| 15 | decode_qc 拒坏结构（截断 / 未知 vote_type / 未排序） | Err |

---

## 6. SAFETY BOUNDARY（10-6.1-H）

- **A-prop（eventually）≠ safety**：`eventually receives QC` 是 liveness/propagation 假设；cross-round
  safety 需 `A-sync-before-conflicting-vote`（投冲突 vote 前已获知 X finality）——**未实现、未证明**，
  不得将 `eventually` 当作 safety 充分条件。
- **Protocol vs Implementation**：本设计只实现状态机内确定性 + 四层分离；**不宣称 implementation-level
  cross-round safety**（lock enforcement 未实现）。
- **verify_qc 永不 finalize**；四层职责独立。

---

## 7. 实现阶段禁令（10-6.2 写死）

```
FORBIDDEN:
1. Do not change canonical_vote_payload.
2. Do not make QC.target == current proposal.target a QC verification requirement.
3. Do not automatically finalize inside verify_qc().
4. Do not claim implementation-level cross-round safety while lock enforcement
   remains unimplemented.
5. Do not infer DAG ancestry from height or round.
6. Do not put serialization/deserialization inside verify_qc().      (MF-10-6.1-1)
7. Do not add a per-evidence target; QC.target is the only target.   (MF-10-6.1-2)
8. Do not derive source == parent(target) in QC verification.        (MF-10-6.1-3)
9. Do not re-verify full QC inside acquire_lock().                   (MF-10-6.1-4)
10. Do not let numeric height/round drive finalized advancement.     (MF-10-6.1-5)
11. Do not treat Conflict as an error.                                (MF-10-6.1-6)
12. acquire_lock / update_finalized_reference MUST reject non-PrecommitQC
    (NotPrecommitQc; lock/FinalityState unchanged).                   (MF-10-6.2-1)
13. decode_qc MUST use checked arithmetic for all attacker-controlled
    offset/length (off + ev_bytes → checked_add).                    (MF-10-6.2-2)
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-28 | 初稿：10-6.1 实现设计 + 6 Micro-Freeze（MF-10-6.1-1~6）成文 | 10-6.1 Design Review APPROVED WITH 6 MICRO-FREEZES |
| 2026-08-28 | 补充 Precommit-only transition 代码强制（acquire_lock/update 拒绝非 PrecommitQC）+ decode checked arithmetic | MF-10-6.2-1/2（Security Review PASS WITH MICRO-FIXES） |
