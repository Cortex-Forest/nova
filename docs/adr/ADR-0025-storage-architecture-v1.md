# ADR-0025: Storage Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（架构冻结）
- 关联：ADR-0017（AccountState）、ADR-0018（账户承诺 / State Root DEFERRED）、ADR-0023（State Transition）、
  ADR-0001（版本概念，Database）、`crypto-serialization-v1.md` §12

## Context

Nova 从 "Transaction Processor" 进入 "L1 Blockchain State Machine"。本 ADR 冻结 **Storage 架构
（8A）**：分层、依赖方向、`AccountStateView` 归属、`StateStore` 边界、原子提交模型。
**Trie / State Root（8B）与持久化后端（8E）DEFERRED**，不在此提前固化。

**冻结边界（STEP 8 不得回改）**：Transaction（7B–7C）、Execution（7G）、Gas（7F）语义零变化；
7G/7H 行为必须保持。

## Decision（建议，待批准）

### 1. Storage Responsibility（冻结）

Storage = **state persistence layer**：`serialize` / `store` / `retrieve` / `commit`。
Storage **不拥有协议状态定义**（S-G）：`AccountState` / `AccountChange` / `TransactionReceipt`
属于 `nova-core`；storage 只序列化/存储/读取/提交。

### 2. Dependency Direction（冻结）

```
             nova-core（协议类型 + 状态视图接口）
                 |
       --------------------
       |                  |
nova-execution       nova-storage
   (consume)          (implement)
```

- 依赖方向：`nova-storage → nova-core`；`nova-execution → nova-core`。
- **禁止**：`nova-storage → nova-execution`（反向依赖）。
- 分层：`nova-storage` 三层（backend / trie / store）＋ `error.rs`（S-B）。

### 3. AccountStateView Ownership（S-A，迁移冻结）

- `AccountStateView` trait **上移至 `nova-core`**（协议层状态视图接口）。
- 现状：`nova-execution::state_transition` 定义 → **迁移**至 `nova-core::state`。
- 结果：core 定义接口；execution 消费；storage 实现。
- **纯接口迁移**：`apply_transaction` 行为完全不变；7G / 7H 无任何行为变化。
- `nova-execution` re-export 保持对外路径兼容。

### 4. StateStore Boundary（S-C，冻结）

```rust
pub trait AccountStateView {          // nova-core（迁移后）
    fn account(&self, addr: &NovaAddress) -> Option<AccountState>;
}
```

- `StateStore`（nova-storage）实现 `AccountStateView`。
- **唯一写入入口**：`StateStore::apply(&[AccountChange]) -> Result<(), StorageError>`。
- 流程冻结：
  ```
  Transaction → apply_transaction（execution，纯函数）→ StateTransition
              → AccountChange[] → StateStore.apply（storage，commit）→ State Root
  ```
- **禁止**：execution 直接写数据库 / 修改 `AccountState` / 调用 trie。
  **Execution = calculate；Storage = commit**。

### 5. Atomic Commit Model（S-D，冻结）

```
Block execution:
  begin snapshot
      tx1, tx2, tx3, ...
  commit       或      rollback
```

- `StorageBackend` 提供 `snapshot` / `commit` / `rollback`。
- 任何异常 ⇒ 回滚到区块前状态（`state before block == rollback result`）。
- 禁止部分提交（`tx1 committed, tx2 failed, tx3 missing`）。

### 6. Trie Deferred（S-E，候选冻结）

- **Trie abstraction 存在**（nova-storage 三层含 `trie.rs`）。
- **不冻结**：node encoding / empty root / hash path / proof format / SMT 细节。
- 候选：**Sparse Merkle Tree**（8B 默认候选）；Node encoding / empty root / key derivation 等
  全部由 **STEP 8B（ADR-0026）** 决定。
- `EMPTY_STORAGE_ROOT` 数值、StateRoot hash、Empty Root → **STEP 8B+**。

### 7. Database Deferred（S-F，冻结）

- **先 MemoryBackend**（8C），全部测试通过后接 **Persistent Backend**（8E，RocksDB / MDBX）。
- **不一开始绑定数据库**：防数据库 schema 提前污染 State / Trie / Protocol 模型。
- 持久化选型 / schema / 崩溃恢复 → **STEP 8E（后续 ADR）**。

### 8. Storage Error 独立（S-H，冻结）

- `nova-storage` 使用自有 `StorageError`（**不复用 `ExecutionError`**，防错误模型污染）。
  ```rust
  pub enum StorageError {
      BackendFailure,       // backend 原语失败
      SerializationFailure, // 账户/节点序列化失败
      CorruptedState,       // 状态损坏（trie 校验失败）
      CommitFailed,         // 提交失败（snapshot/commit）
  }
  ```
- 错误模型分层：`nova-core`（协议错误）/ `nova-storage`（`StorageError`）/
  `nova-execution`（`ExecutionError`）各自独立。

### 9. Decision Log

| # | 决策 | 状态 |
|---|------|------|
| S-A | `AccountStateView` 上移 nova-core（纯接口迁移） | 冻结 |
| S-B | storage 三层：backend / trie / store + error | 冻结 |
| S-C | `apply(AccountChange[])` 唯一写入入口 | 冻结 |
| S-D | 区块级事务 snapshot / commit / rollback | 冻结 |
| S-E | SMT 为 8B 默认候选（细节 DEFERRED 8B） | 候选冻结 |
| S-F | 先 MemoryBackend，DB 留 8E | 冻结 |
| S-G | storage 不拥有协议状态定义 | 冻结 |
| S-H | `StorageError` 独立（不混用 ExecutionError） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| storage → execution 依赖 | 反向依赖；接口归属错误 |
| `AccountStateView` 留在 execution | storage 无法实现（依赖反向） |
| execution 直接写 storage | 破坏 "Execution=calculate, Storage=commit" |
| 每笔 tx 单独 commit | 无法保证区块原子性（S-D） |
| 一开始绑定 RocksDB | 数据库 schema 提前污染状态/trie/协议模型 |
| 复用 ExecutionError | 错误模型污染；storage 错误语义独立 |

## Consequences

- **正面**：分层清晰；接口归属正确；执行与提交解耦；原子性可验证。
- **成本**：8A 仅冻结架构（无 trie / 无 DB）；8B/8C/8E 逐项 ADR。
- **可迁移**：trie 类型 / DB 后端可替换，不影响协议。

## Security Impact

- 防部分提交：区块级原子事务（S-D）。
- 防状态损坏：`StorageError::CorruptedState` + trie 校验（8B）。
- 防接口污染：execution 不接触存储原语（S-C）。
