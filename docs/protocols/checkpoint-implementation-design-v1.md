# Nova Chain — Checkpoint Implementation Design V1（10-7.1）

- **Status**: Draft（STEP 10-7.1；**APPROVED WITH 2 MICRO-FREEZES**，待最终 Review）
- **Date**: 2026-08-28
- **Scope**: Checkpoint 的**实现设计**（模块边界、API 契约、canonical 布局、测试计划）。
- **依据**：ADR-0039 CP-1~CP-8（FROZEN）、ADR-0038 F-1~F-18、
  `docs/protocols/finality-implementation-design-v1.md`。
- **本文件是设计契约，不是代码实现**。实现（10-7.2）必须严格遵循本契约。

---

## 0. 核心不变式（CP-1~CP-8 总纲）

| # | 不变量 |
|---|---|
| CP-1 | `checkpoint.finalized_block_hash == checkpoint.precommit_qc.target` |
| CP-2 | `checkpoint.precommit_qc.context.vote_type == Precommit` |
| CP-3 | `checkpoint.height == QC.context.height` ∧ `checkpoint.round == QC.context.round` |
| CP-4 | proof 必须精确对应 finalized_reference；**不得**用 `highest_precommit_qc` 充当 / fallback |
| CP-5 | Checkpoint 非独立 Finality 来源；验证不得执行 FinalityState transition |
| CP-6 | `snapshot_interval_blocks` 不参与 checkpoint/finality/QC validity |
| CP-7 | `checkpoint.chain_id == QC.context.chain_id` |
| CP-8 | `height`/`round` 仅 metadata，不得推断 finality/ancestry/applicability/ordering |

---

## 1. 模块边界（10-7.1-A）

- 新模块 `crates/consensus/src/checkpoint.rs`（`nova-consensus`）。
- **依赖方向（单向，无循环）**：`checkpoint → finality`（`QuorumCertificate` / `verify_qc` /
  `FinalityError` / `encode_qc` / `decode_qc`）。**无反向依赖**。
- 不接 storage / execution / network（C-1）；不实现 light-client / sync / 跨节点传播 / 持久化
  （归 node 层或 FOLLOW-UP）。
- **不引入新的 consensus state 类型**（无 `CheckpointState` / `latest_checkpoint` 作为共识状态；
  latest 判定归 node 层）。

## 2. `Checkpoint` 类型（CP-1~CP-8）

```rust
pub struct Checkpoint {
    pub chain_id: u64,                   // CP-7
    pub finalized_block_hash: [u8; 32],  // CP-1
    pub height: u64,                     // CP-3 / CP-8（仅 metadata）
    pub round: u64,                      // CP-3 / CP-8（仅 metadata）
    pub precommit_qc: QuorumCertificate, // CP-2 / CP-4
}
```

- 非新区块、非签名对象、无新密码算法 / domain。

## 3. `derive_checkpoint`（生成；CP-MF-4）

```rust
pub fn derive_checkpoint(
    finalized_reference: [u8; 32],
    finalized_qc: &QuorumCertificate,
) -> Option<Checkpoint>;
```

- **显式接收对应 `finalized_qc`**；**无 `FinalityState` 参数 ⇒ 结构上无法 fallback 到
  `highest_precommit_qc`**（CP-MF-4 绝对不变量）。
- 返回 `None`（确定性）：
  1. `finalized_qc.target != finalized_reference`（CP-4）→ `None`；
  2. `finalized_qc.context.vote_type != Precommit`（CP-2 防御）→ `None`。
- 命中时：打包 `Checkpoint`（`chain_id`/`height`/`round` 取自 `finalized_qc.context`）。
- **职责边界**：`derive = structural derivation`；**不负责 QC 密码学有效性**（那是 `verify_checkpoint`
  / 调用方 `verify_qc` 职责）。**不得**把 `derive_checkpoint` 变成第二个 `verify_qc`。
- **不修改任何 consensus state**（纯派生，CP-5）。

## 4. `verify_checkpoint`（验证；CP-MF-10 唯一优先级）

```rust
pub fn verify_checkpoint(
    cp: &Checkpoint,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
) -> Result<(), CheckpointError>;
```

**CP-MF-10 — Deterministic Verification Precedence（唯一冻结顺序）**：

```
① Checkpoint structural invariants（self-consistency）
     a. finalized_block_hash == precommit_qc.target          → CheckpointTargetMismatch
     b. height == QC.context.height && round == QC.context.round → CheckpointContextMismatch
     c. chain_id == QC.context.chain_id                      → CheckpointChainIdMismatch
② Precommit-only
     vote_type == Precommit                                  → NotPrecommitQc
③ QC cryptographic/semantic validity
     verify_qc(&precommit_qc, set, genesis_hash, dag)        → InvalidQc(FinalityError)
```

- **唯一顺序（CP-MF-10）**：先自洽性（明显损坏的 Checkpoint 不进入完整 QC 验证）→ Precommit 约束
  → QC 有效性。**任何实现不得改变此顺序**（避免同一恶意对象在不同实现得到不同 `CheckpointError`）。
- **无 `FinalityState` 参数** ⇒ 结构上无法 finalize / update finalized reference / acquire lock /
  建立第二套 finality rule（CP-5）。
- `verify_checkpoint` **only establishes Checkpoint structural/self-consistency and embedded QC
  validity**; it MUST NOT establish current-state applicability/latestness（Validity ≠ Latest
  Applicability）。

## 5. `CheckpointError`（与 `FinalityError` 边界）

```rust
pub enum CheckpointError {
    InvalidCheckpointStructure,      // decode 结构/长度/截断/额外字节（CP-MF-9）
    NotPrecommitQc,                  // CP-2
    CheckpointTargetMismatch,        // CP-1
    CheckpointContextMismatch,       // CP-3
    CheckpointChainIdMismatch,       // CP-7
    InvalidQc(FinalityError),        // 内嵌 QC 验证失败（确定性映射 verify_qc 的全部 Err）
}
```

- **不改 `error.rs`**；与 `FinalityError` 单向包装（`InvalidQc(FinalityError)`），避免错误定义漂移。
- **确定性映射**：`verify_qc` 任一 `Err(e)` ⇒ `CheckpointError::InvalidQc(e)`。

## 6. Canonical Serialization（CP-MF-9）

### 6.1 Byte layout（冻结）

```
encode_checkpoint(cp):
  chain_id(8 LE) ‖ finalized_block_hash(32) ‖ height(8 LE) ‖ round(8 LE)
  ‖ qc_len(4 LE) ‖ qc_bytes[qc_len]          // qc_bytes = encode_qc(cp.precommit_qc)

decode_checkpoint(bytes):
  → metadata prefix = 56B（8+32+8+8）
  → qc_len = 4B
  → total fixed prefix = 60B（56B metadata + 4B qc_len）
  → 总长度校验：bytes.len() == 60 + qc_len（无多余字节）
  → 截取 qc_bytes[qc_len] → decode_qc（复用 10-6）
  → 组装 Checkpoint
```

- **命名澄清**：`metadata prefix = 56B`；`qc_len = 4B`；`total fixed prefix = 60B`。不得称整个
  prefix 为 56B（防实现混淆）。
- **checked arithmetic（MF-10-6.2 延续）**：`qc_len` 读取、`60 + qc_len`（`checked_add`）、
  `bytes.len() == 60 + qc_len` 严格相等（`valid + 0 bytes → Ok`；`valid + 1 byte → Err`）。
- 无新签名 / 无新 domain；QC 签名继承。

### 6.2 CP-MF-9 — Checkpoint Decode Is Structural Only

> **`decode_checkpoint()` MUST NOT perform QC semantic validation, Finality validation,
> applicability validation, or FinalityState transition.**

```
decode_checkpoint(bytes)
        ↓
结构解析（layout / 长度 / qc_len / 内嵌 decode_qc 结构）
        ↓
Checkpoint
```

- 允许：`decode_checkpoint(valid-encoding-of-prevote-checkpoint) → Ok(Checkpoint)`，
  随后 `verify_checkpoint(...) → Err(NotPrecommitQc)`（与 10-6 `decode_qc` 分层一致）。
- **禁止** decode 阶段执行 semantic / QC / finality / applicability 验证。

## 7. 测试计划（10-7.1-G）

| # | 用例 | 期望 |
|---|---|---|
| T1 | valid PrecommitQC(target==X) → derive_checkpoint → Checkpoint | Some，字段自洽（CP-1/3/7） |
| T2 | encode/decode roundtrip | 还原一致 |
| T3 | `derive_checkpoint(X, QC(Y))`（target 不符） | `None`（CP-4 / CP-MF-4 核心） |
| T4 | `derive_checkpoint(X, PrevoteQC(X))` | `None`（CP-2 防御） |
| T5 | verify_checkpoint Ok（valid，多 validator quorum） | Ok |
| T6 | target 篡改 | `CheckpointTargetMismatch`（优先级 ①a） |
| T7 | chain_id 篡改 | `CheckpointChainIdMismatch`（优先级 ①c） |
| T8 | height/round 篡改 | `CheckpointContextMismatch`（优先级 ①b） |
| T9 | 内嵌 PrevoteQC | `NotPrecommitQc`（优先级 ②） |
| T10 | 内嵌 QC 签名/quorum 失败 | `InvalidQc(FinalityError::…)`（优先级 ③） |
| T11 | decode 截断 / 多余字节 / qc_len 不符 | `InvalidCheckpointStructure`（CP-MF-9） |
| T12 | valid 历史 checkpoint | verify_checkpoint = Ok（Validity ≠ Latest，§4） |
| T13 | decode(prevote-checkpoint) → Ok；verify → NotPrecommitQc | 分层成立（CP-MF-9） |
| T14 | **Precedence 确定**：target mismatch + 坏签名 ⇒ 返回 `CheckpointTargetMismatch`（① 先于 ③） | 唯一错误 |

## 8. Adversarial / Safety 断言

- **CP-MF-9**：decode 不做 semantic；断言 decode 不触发 verify。
- **CP-MF-10**：precedence 唯一（T14 覆盖）；无两实现歧义。
- **CP-MF-4**：`derive_checkpoint` 无 `FinalityState` 入参（结构保证无 fallback）。
- **CP-5**：`verify_checkpoint` 无 state 参数（结构保证无 FinalityState transition）。
- **CP-8**：无 height/round 推断 ancestry / ordering / applicability。
- **F-15 / CP-5**：不得由 Checkpoint 反向"证明"Finality。

## 9. 实现阶段禁令（10-7.2 写死）

```
FORBIDDEN:
1. Do not create a new consensus state type (no CheckpointState/latest_checkpoint as consensus state).
2. decode_checkpoint MUST NOT perform semantic/QC/finality/applicability validation.  (CP-MF-9)
3. verify_checkpoint MUST NOT execute FinalityState transition.                      (CP-5)
4. derive_checkpoint MUST NOT fallback to / search FinalityState.highest_precommit_qc.(CP-MF-4)
5. Do not use height/round to infer ancestry/finality/applicability/ordering.        (CP-8)
6. Do not introduce a second finality rule; do not let Checkpoint prove Finality.    (CP-5/F-15)
7. Do not change canonical_vote_payload / vote signature semantics / error.rs.
8. Do not connect storage/execution/network.
9. Do not claim implementation-level cross-round safety.
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-28 | 初稿：10-7.1 Checkpoint 实现设计 + CP-MF-9（decode structural-only）+ CP-MF-10（唯一 verification precedence）+ 60B prefix 澄清 | STEP 10-7.1 Review APPROVED WITH 2 MICRO-FREEZES |
