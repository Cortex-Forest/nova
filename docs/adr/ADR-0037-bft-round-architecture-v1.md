# ADR-0037: BFT Round Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（BFT Round，10-5）
- 关联：ADR-0033（C-5 ≥2/3 quorum / Prevote→Precommit）、ADR-0034（V-4/V-5 ValidatorVote）、
  ADR-0035（DAG 候选）、ADR-0036（Witness availability）

## Context

10-5 是 Nova 共识安全核心。冻结 **BFT Round 状态机**（B-1~B-6），确保 `DAG（候选）→ Witness
（availability）→ BFT（weighted quorum ≥2/3）→ Finality` 分层，**DAG/Witness 不得越权**。

## Decision（冻结）

### B-1 — Round 模型

```rust
pub struct RoundState {
    pub height: u64,
    pub round: u64,
    pub proposal: Option<ProposalRef>,     // 当前 proposal（BlockReference 引用）
    pub prevotes: VoteAccumulator,
    pub precommits: VoteAccumulator,
    pub step: RoundStep,
}
pub enum RoundStep { Propose, Prevote, Precommit, Finalized }
```

- `(height, round)` 唯一确定 consensus context；round 单调递增。
- **禁止** execution/storage/network 进入 `RoundState`（纯计算）。

### B-2 — Prevote / Precommit 状态机

```
Propose → [≥2/3 weighted prevote] → Precommit → [≥2/3 weighted precommit] → Finalized
```

- `process_vote(state, vote) -> RoundTransition`：接收**已验证** vote → 聚合权重 → quorum 判定 →
  推进 step。
- **禁止** process_vote 验证交易 / 执行 block / 修改 state root。

### B-3 — Round Timeout 边界

```rust
pub struct RoundTimeoutConfig { initial_timeout: u64, max_timeout: u64, backoff_factor: u64 }
// timeout(round) = initial × backoff(round)，capped at max_timeout
```

- **timeout 不是共识输入**：是本地节点事件 → 状态机事件；不同节点可能不同时触发。
- 最终状态由 vote / quorum / lock 决定。**禁止** timeout 直接 finalize / 改变 block validity。

### B-4 — Proposal / Vote 生命周期

- `DAG Candidate → Availability Check（Witness signal，只影响 confidence）→ Proposal →
  Prevote → Precommit → Finality`。
- Witness **不能**决定 candidate accepted；最终接受由 **≥2/3 weighted precommit** 决定。
- Proposal 只引用 `BlockReference`（完整 Block PHASE 7）。

### B-5 — Locked Block Rule（**Lock Object = 单 Block**）

```rust
pub struct LockedState {
    pub locked_block_hash: Option<[u8; 32]>,
    pub locked_round: Option<u64>,
}
```

- 触发：`precommit quorum ≥ 2/3` 产生 `lock(block_hash, round)`。
- 之后只投：① 同一 block ② 包含该 block 的 **justified extension**（descendant）。
- **禁止**：平级 DAG fork 投票 / 回退旧 branch。
- 兼容：`same block → OK`；`descendant of locked → OK`；`unrelated DAG branch → reject`。
- **higher justified override 归 10-6 + Consensus spec**（10-5 不实现，避免 lock 提前复杂化）。

### B-6 — Safety Boundary

- **代码**：deterministic state transition / vote aggregation / quorum checking / lock enforcement。
- **Spec 文档**（后续 `docs/protocols/consensus-spec-v1.md`）：Safety proof（无两个冲突 block 同时
  finalized）、Liveness assumptions、Byzantine model、≥2/3 honest weight。
- **代码禁止承载数学证明**。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| B-1 | `RoundState`/`RoundStep`（纯计算） | 冻结 |
| B-2 | Prevote→Precommit→Finalize（`process_vote`） | 冻结 |
| B-3 | `RoundTimeoutConfig`（本地事件；禁直接 finalize） | 冻结 |
| B-4 | Proposal/Vote 生命周期（Witness 只影响 confidence） | 冻结 |
| B-5 | 单 Block lock + DAG 兼容规则（override 归 10-6） | 冻结 |
| B-6 | 代码/spec 分离（consensus-spec-v1.md 后续） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| timeout 作为共识输入 | 节点间不一致 ⇒ 状态歧义（B-3） |
| Witness 决定 candidate accepted | 越权；finality 唯一由 BFT（B-4） |
| DAG 分支 lock | 锁对象必须明确（单 block）；分支 lock 复杂（B-5） |
| 代码承载安全证明 | 证明属 spec 文档（B-6） |

## Consequences

- **正面**：BFT 状态机纯函数、分层清晰、防双投/回滚（lock）。
- **成本**：higher justified override 延后 10-6。
- **可迁移**：10-6 Finality 消费 RoundState 输出。

## Security Impact

- 防双投/回滚：lock 规则（B-5）。
- 防越权：DAG/Witness 不进入 RoundState（B-1/B-4）。
- 防 timeout 滥用：非共识输入（B-3）。
