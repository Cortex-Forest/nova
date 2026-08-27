# ADR-0030: StateRootCalculator V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（StateRootCalculator，STEP 8D-2）
- 关联：ADR-0029（Block State Root Verification D-4）、ADR-0028（StateStore / apply / snapshot）、
  ADR-0026（SMT State Root）、ADR-0023（StateTransition 顺序 G-J）

## Context

ADR-0029 D-4 冻结 `StateStore::apply_block`（提交）与 StateRootCalculator（只读重算）。本 ADR 细化冻结
StateRootCalculator：归属、snapshot 模型、`commit_changes` 抽象、排序语义、空区块语义、错误边界、测试要求。

## Decision（冻结）

### C-1 — Calculator Ownership（冻结）

- **归属 `nova_storage::state_root`**，无状态纯函数：
  ```rust
  pub fn calculate_state_root<B: StorageBackend>(
      store: &StateStore<B>,
      tx_changes: &[&[AccountChange]],
  ) -> Result<NodeHash, StorageError>;
  ```
- state root 属**状态承诺层（storage）**，非交易执行层（execution）。
- **禁止** execution 做 state root calculation（ADR-0029 D-2 边界）。

### C-2 — Snapshot Calculation Model（冻结）

- **只读重算**：临时状态 = `store.clone()`（trie 深拷贝 + backend 快照）→ 应用 tx_changes → root → drop。
- 调用前后 store **完全一致**（root / account / backend / trie 均不变）。
- V0.1 深拷贝可接受（无生产规模 / 无持久化 backend / 正确性优先）；8E 后允许 immutable view +
  incremental trie（**不提前设计**）。

### C-3 — commit_changes Abstraction（冻结，核心）

- 内部共享核心：
  ```rust
  fn commit_changes(&mut self, tx_changes: &[&[AccountChange]]) -> Result<(), StorageError>;
  ```
- `apply_block` = `snapshot` → `commit_changes` → `root()` → 成功保留（失败 rollback）。
- `calculate_state_root` = 临时 clone → `commit_changes` → `root()` → drop。
- **同一核心** ⇒ 杜绝 apply 与 calculate 分叉（主网 state root mismatch 风险）。

### C-4 — Ordering Semantics（冻结）

- `tx_changes` 外层 = block 内成功 tx 顺序；内层 = 单 tx 的 changes（sender→receiver）。
- **不排序**（禁 `sort(address)`）、**不合并**（禁 merge same-address）。
- `tx1: A+10; tx2: A-5` ⇒ `A = old +10 -5`（顺序语义；破坏会损坏 nonce / gas / future proof / trace）。

### C-5 — Empty Block Semantics（冻结）

- 空 `tx_changes`（`[]`）⇒ root = 区块前 root（初始空 = `EMPTY_STATE_ROOT`）。

### C-6 — Error Boundary（冻结）

- 统一 `Result<NodeHash, StorageError>`（MemoryBackend 无失败路径；8E 持久化/远程后端可能失败，提前统一）。
- `apply_block` 失败：`commit_changes` Err ⇒ `rollback` ⇒ Err（状态 = 区块前）。
- `calculate_state_root`：只读，不落盘。

### C-7 — Test Requirements（冻结）

1. **Root equivalence**：`calculate_state_root` == `apply_block`（同输入）。
2. **Read-only**：calculate 前后 store 不变（root/account）。
3. **Empty block**：`[]` ⇒ root 不变。
4. **Atomic rollback**：backend 注入失败 ⇒ root/account 不变。
5. **Execution integration**：`execute_block → apply_block` root == `calculate_state_root`。
6. **Golden vector**：`block-state-root-v1`（ADR-0029 D-6）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| C-1 | `state_root` 模块 + 无状态 `calculate_state_root` | 冻结 |
| C-2 | snapshot 深拷贝只读重算（不污染 store） | 冻结 |
| C-3 | `commit_changes` 共享核心 | 冻结 |
| C-4 | 排序/合并禁止（顺序语义） | 冻结 |
| C-5 | 空区块 root 不变 | 冻结 |
| C-6 | `Result` 统一 + apply_block 整块回滚 | 冻结 |
| C-7 | 测试要求（6 项） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| execution 计算 state root | 破坏归属；状态承诺属 storage（C-1） |
| calculate 直接改 store | 污染正式状态（C-2） |
| apply_block 与 calculate 独立实现 | 主网 state root mismatch 风险（C-3） |
| 排序/合并优化 | 破坏 nonce / gas / proof / trace（C-4） |

## Consequences

- **正面**：apply 与 calculate 单一实现来源；只读校验安全；区块级原子。
- **成本**：V0.1 深拷贝（正确性优先，8E 优化）。
- **可迁移**：`block-state-root-v1` 向量跨语言复刻；PHASE 7 接入 header。

## Security Impact

- **防 root mismatch**：commit_changes 单源（C-3）。
- **防污染**：calculate 只读（C-2）。
- **防状态歧义**：区块级原子回滚 + 顺序语义（C-4/C-6）。
