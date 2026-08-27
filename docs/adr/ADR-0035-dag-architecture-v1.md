# ADR-0035: DAG Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（DAG Architecture，10-3）
- 关联：ADR-0033（C-3 DAG≠Finality / C-6 fork choice）、ADR-0034（ValidatorId/ValidatorSet）、
  ADR-0009（block_hash 承诺，PHASE 7）

## Context

ADR-0033 C-3 冻结 **DAG ≠ Finality**（传播/因果/候选排序）；C-6 未 final 区块选 highest justified DAG
branch。本 ADR 冻结 **DAG 数据结构（10-3）**：BlockReference、Dag、确定性因果排序、候选排序边界。

## Decision（冻结）

### D-1 — BlockReference（DAG 节点）

```rust
pub struct BlockReference {
    pub block_hash: [u8; 32],       // 区块承诺（仅引用，不解析完整 Block；PHASE 7）
    pub height: u64,                // 提议高度
    pub parents: Vec<[u8; 32]>,     // DAG 边（≥1，多父 = 因果/并行）
    pub proposer: ValidatorId,      // 提议者（Consensus identity，非 NodeId/Account）
}
```

- `block_hash` 仅引用承诺；`proposer` 用 `ValidatorId`（非 NodeId/Account Address——身份隔离）。

### D-2 — Dag 存储与验证

```rust
pub struct Dag {
    blocks: HashMap<[u8; 32], BlockReference>,
    tips: Vec<[u8; 32]>,            // 无后代叶子（候选）
}
impl Dag {
    pub fn add_block(&mut self, r: BlockReference) -> Result<(), ConsensusError>;
    pub fn contains(&self, hash: &[u8; 32]) -> bool;
    pub fn parents_of(&self, hash: &[u8; 32]) -> Option<&[[u8; 32]]>;
    pub fn tips(&self) -> &[[u8; 32]];
}
```

- **节点唯一性**：`block_hash` 唯一；重复 ⇒ 拒绝。
- **add_block 验证**：① hash 不存在 ② parents 全部存在 ③ height 合法（`parent.height < block.height`）；
  违反 ⇒ `ConsensusError::InvalidDagReference`。

### D-3 — Deterministic Causal Ordering

```rust
pub fn causal_order(&self, from: &[u8; 32]) -> Vec<[u8; 32]>;
```

- 语义：`parents → ancestors → child`（**parent 先于 child**）。
- 要求：deterministic、无随机遍历、同 DAG ⇒ 同结果。
- 多 parent 可选时：**`block_hash` 字典序**（跨节点一致）。

### D-4 — Candidate Ordering 输入契约

- 10-3 **不决定** which block wins；只提供 `DAG{tips, causal_order, proposer, references}` 供
  10-5 BFT / 10-6 Finality 计算 justified branch。
- DAG 负责：availability / causal relation / parallel block organization。
- DAG 不负责：finality / canonical chain / validator agreement。

### D-5 — Implementation Boundary

- 本 STEP 只实现：`BlockReference` + `Dag` + `causal_order`（纯函数）。
- 不实现：network propagation / Witness（10-4）/ BFT Round（10-5）/ Finality（10-6）/ Checkpoint（10-7）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| D-1 | `BlockReference`（hash/height/parents/proposer:ValidatorId） | 冻结 |
| D-2 | `Dag`（唯一 hash + add 验证 ①②③） | 冻结 |
| D-3 | `causal_order` 确定性（parent 先于 child；hash 字典序） | 冻结 |
| D-4 | Candidate ordering 输入契约（justified 归 10-5/10-6） | 冻结 |
| D-5 | 边界（只 DAG 数据结构 + 因果序） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| proposer 用 NodeId/Account | 身份隔离破坏（D-1） |
| 非确定性遍历 | 跨节点不一致（D-3） |
| DAG 决定 canonical chain | 违反 C-3 DAG≠Finality（D-4） |

## Consequences

- **正面**：DAG 纯函数、确定性因果序、与 BFT 边界清晰。
- **成本**：完整 Block 格式延后（PHASE 7）；DAG 只持引用。
- **可迁移**：BFT/finality 消费 DAG 输入契约。

## Security Impact

- 防循环/坏引用：add_block 验证 parents/height（D-2）。
- 防跨节点分叉：确定性因果序（D-3）。
- 防越权：proposer 强制 ValidatorId（D-1）。
