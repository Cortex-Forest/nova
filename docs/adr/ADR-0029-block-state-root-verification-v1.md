# ADR-0029: Block State Root Verification V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage/Execution（Block State Root，STEP 8D）
- 关联：ADR-0021（block 内 `(sender,nonce)` 严格递增 §7）、ADR-0023（StateTransition / G6 / G-B）、
  ADR-0026（SMT State Root）、ADR-0027（Proof）、ADR-0028（StateStore / snapshot-commit-rollback）、
  ADR-0009（block_hash 归 PHASE 7）

## Context

8C 冻结 `StateStore`（单 tx `apply`）。本 ADR 冻结 **区块级执行与 state root 校验（8D）**：
`BlockExecutionResult`、`execute_block`（纯计算）、Block Validity 模型（两阶段 + tx skip）、
`apply_block`（区块级原子）、`verify_block_state_root`、向量集成。

**8D 范围**：BlockExecutionResult + execute_block + validate_block + apply_block/StateRootCalculator +
verify_block_state_root + block 向量。
**不做**：完整 `BlockHeader`/`Block` 格式与 `block_hash`（ADR-0009 PHASE 7）、mempool、block production、
共识（PoS/BFT/DAG）、P2P。

## Decision（冻结）

### D-1 — BlockExecutionResult（nova-core，冻结）

```rust
pub struct BlockExecutionResult {
    pub tx_transitions: Vec<StateTransition>,   // 成功 tx（顺序 = block 内顺序）
    pub gas_used_total: u64,
}
```

- **不含** `final_state_root`（由 storage `apply_block` 计算——execution 无 SMT）。
- **不含** receipt root / block_hash（PHASE 7 聚合）。

### D-2 — execute_block boundary（nova-execution，冻结）

```rust
pub fn execute_block<S: AccountStateView>(
    state: &S,
    txs: &[TransactionV1],
    ctx: &ExecutionContext,
    max_gas_per_block: u64,
) -> Result<BlockExecutionResult, BlockError>;
```

- **纯计算**：内部**影子状态**（`overlay: HashMap<NovaAddress, AccountState>` + fallback 到 `&S`，
  实现 `AccountStateView`），逐 tx `apply_transaction` → 成功则把 changes 应用回 overlay → 记录 transition。
- **execution 禁止**：Storage write / Trie mutation / Backend access / State root calculation。
- **execution 允许**：overlay state / transaction execution / gas accounting / transition generation。
- `BlockError`（nova-execution，独立错误类型）：`NonceConflict` / `GasLimitExceeded` /
  `InvalidTransaction(ExecutionError)`。

### D-3 — Block Validity Model（两阶段，Model A，冻结）

1. **validate_block（block validity 预检）**：block 内 `(sender, nonce)` 唯一（ADR-0021 §7）、
   累计 gas ≤ `max_gas_per_block`（G6）、tx 结构合法。任一违反 ⇒ `BlockError` ⇒ **整块回滚
   （Block Invalid，无状态变更）**。
2. **执行期 tx 失败（skip）**：单 tx 执行错误（signature/replay/nonce/gas/balance）⇒ **跳过**
   （无 change、无 receipt，G-B），**区块继续**；`state_root` = 成功 tx 的承诺（与 7H
   `failed-no-mutation` 一致）。

- **防 DoS**：坏 tx **不**使整块无效（Ethereum 式 skip 是 L1 主流）。
- 否决 Model B（任一 tx 失败 ⇒ 整块回滚）：与 G-B/7H 失败无副作用矛盾；坏 tx ⇒ 整块无效 = DoS。

### D-4 — apply_block & StateRootCalculator（nova-storage，冻结）

```rust
pub fn apply_block(
    &mut self,
    tx_changes: &[&[AccountChange]],      // 每成功 tx 的 changes（顺序 = block 顺序）
) -> Result<NodeHash, StorageError>;      // 返回 final state_root
```

- **区块级原子**：`snapshot()` → 逐 tx 提交（复用两阶段 prepare/commit 逻辑）→ 成功返回 final root；
  任一失败 ⇒ `rollback` → `Err`（状态 = 区块前）。
- **StateRootCalculator**（8D-2 细化架构）：`calculate_state_root` **只读重算**（基于 store 快照的临时
  状态，不落盘，校验用）。

### D-5 — verify_block_state_root（冻结）

```rust
pub fn verify_block_state_root(expected: &NodeHash, computed: &NodeHash) -> Result<(), BlockStateRootError>;
// BlockStateRootError::Mismatch（nova-storage）
```

- **边界**：只做 `state_root` 校验；**不包含** block_hash / header validation / timestamp / prev_hash /
  producer / consensus（全部 PHASE 7，ADR-0009）。

### D-6 — 向量集成（冻结）

- 协调在 `tests/vectors`（已依赖 nova-storage + nova-execution，避免 execution↔storage 循环依赖）。
- **schema**：`block-state-root-v1`。
- 链：`execute_block → StateTransition[] → apply_block → state_root → verify`。

### D-7 — 测试策略（冻结）

- **execution**：multi tx / gas 累计 / tx skip / nonce 序列。
- **storage**：block atomic rollback / trie-backend consistency。
- **validation**：duplicate nonce / gas overflow / invalid block。
- **vector**：block fixtures 生成 + loader 校验。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| D-1 | `BlockExecutionResult` 归属 nova-core | 冻结 |
| D-2 | `execute_block` 纯计算 + 影子状态 + `BlockError` | 冻结 |
| D-3 | Block validity 两阶段 + tx skip（Model A） | 冻结 |
| D-4 | `apply_block` 区块级原子 + StateRootCalculator | 冻结 |
| D-5 | `verify_block_state_root` 边界（PHASE 7 外延） | 冻结 |
| D-6 | tests/vectors 协调 + `block-state-root-v1` | 冻结 |
| D-7 | 测试策略 | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| Model B：任一 tx 失败整块回滚 | 与 G-B/7H 失败无副作用矛盾；坏 tx ⇒ 整块无效 = DoS（D-3） |
| `execute_block` 直接写 storage | 破坏依赖方向；execution 不持有 SMT/backend（D-2） |
| `BlockExecutionResult` 含 final root | execution 无 SMT 无法计算（D-1） |
| 冻结完整 BlockHeader | block_hash/共识字段属 PHASE 7（D-5） |

## Consequences

- **正面**：区块级原子、失败隔离、状态承诺链路（tx→block→root→verify）闭合。
- **成本**：execute_block 影子状态与 storage apply 为"双写计算"（execution 算、storage 落）。
- **可迁移**：`block-state-root-v1` 向量跨语言可复刻；PHASE 7 接入 block_hash/header。

## Security Impact

- **防 DoS**：坏 tx skip 不使整块无效（D-3）。
- **防状态歧义**：block nonce 严格递增 + 区块级原子回滚（D-3/D-4）。
- **防越权**：`execute_block` 纯计算，无持久写入（D-2）。
