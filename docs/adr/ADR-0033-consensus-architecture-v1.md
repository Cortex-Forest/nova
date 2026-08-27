# ADR-0033: Consensus Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（架构冻结，10-1）
- 关联：ADR-0005（DomainId::ValidatorVote/Block）、ADR-0009（Vote/Block 签名覆盖）、
  ADR-0012（Algorithm Registry）、ADR-0014/0015（genesis validator set）、
  ADR-0003（BLS 候选——延后）、ADR-0031（storage snapshot——与 consensus checkpoint 分离）

## Context

8C-9 完成执行/持久化/网络。STEP 10 冻结**共识架构**：谁决定哪个 block 被接受、何时最终确定。
nova-consensus 占位方向：**PoS Validator Set + DAG 传播 + BFT Finality**。

**10 范围**：共识**纯计算**（ValidatorSet / Vote / Finality / Checkpoint / Fork choice）。
**不做**：完整 Block 格式（PHASE 7）、reward 发放（C-8 边界）、node 协调层、完整共识消息收发调度。

## Decision（冻结）

### C-1 — Consensus Boundary

- 依赖：`consensus → core`（协议类型）、`consensus → crypto`（签名/哈希/validator_id）。
- **禁止** `consensus → execution` / `consensus → storage` / `consensus → network`。
- **Consensus Input**：Block metadata + Votes + ValidatorSet。
- **Consensus Output**：Accepted ordering + Finality proof/reference。

### C-2 — Validator Model

- `ValidatorId = SHA-256(consensus_public_key)`（32B；已冻结 genesis-v1.md）。
- **签名体系：Ed25519（V0.1）**（`AlgorithmId::Ed25519`；与 STEP 9 identity / ADR-0012 一致）。
- **BLS（ADR-0003 blst 聚合）延后**——不得提前绑定；未来 ADR（ValidatorSignatureV2）迁移。

### C-3 — DAG Boundary

- **DAG ≠ Finality**：DAG 负责并行传播 / 因果关系 / 候选排序；**不负责** finality / canonical chain。
- 流程：`Transaction → DAG Layer（parent refs / causal ordering）→ BFT Layer（final ordering）→
  Final Block Sequence`。

### C-4 — Deterministic Random Witness

- **Deterministic**（任何节点可复算，防不可验证随机 / Sybil / 权重操纵）：
  ```
  WitnessSeed = Hash(previous_finality_reference ‖ height)
  WitnessSet  = DeterministicSelect(ValidatorSet, WitnessSeed, witness_count)
  ```
- **Witness ≠ finality authority**：Witness = 快速验证层（availability/validity signal），
  最终性由 BFT 决定。

### C-5 — BFT Finality（Weighted）

- **Quorum：≥ 2/3 total voting weight**（经典 BFT 安全条件）。
- **VoteType 两阶段**：
  ```rust
  enum VoteType { Prevote, Precommit }
  ```
- **Round 流程**：`height → round → proposal → prevote → precommit → finalize`。

### C-6 — Finality-first Fork Choice

- **规则**：
  1. 已 final 的 block ⇒ **final block wins**。
  2. 未 final ⇒ 选 **highest justified DAG branch**（依据 validator vote weight + witness availability）。
- **禁止**：longest chain / highest block count（Nova 是 DAG + BFT，非 Nakamoto chain）。

### C-7 — Consensus Checkpoint

- **`Checkpoint = Finalized Block Reference`**（finality anchor）。
- 间隔参考 `snapshot_interval_blocks`（genesis）但**不绑定 storage snapshot**。
- **禁止**：`storage snapshot = consensus checkpoint`（8E 快照 = 快速恢复；consensus checkpoint = 最终性锚点）。

### C-8 — Reward Boundary

- **Consensus 负责**：`who finalized`。
- **Consensus 不负责**：`how reward changes state`（reward 由未来 Execution + Economic Module）。
- 奖励不改变状态转换确定性（共识不影响 execution 纯函数性）。

### C-9 — ValidatorVote

```rust
pub struct ValidatorVote {
    pub round: u64,
    pub height: u64,
    pub target_block_hash: [u8; 32],
    pub vote_type: VoteType,
    pub source_block_hash: [u8; 32],
    pub validator_id: ValidatorId,
    pub timestamp: u64,
}
```

- 签名：`DomainId::ValidatorVote`（ADR-0005 0x02；签名覆盖见 ADR-0009）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| C-1 | consensus 纯计算边界（禁→execution/storage/network） | 冻结 |
| C-2 | ValidatorId（已冻结）+ **Ed25519 V0.1**（BLS 延后） | 冻结 |
| C-3 | DAG ≠ Finality（传播/因果/候选排序） | 冻结 |
| C-4 | Deterministic Random Witness（`Hash(prev_finality‖height)`）；Witness ≠ finality authority | 冻结 |
| C-5 | BFT Weighted **≥2/3** quorum；Prevote→Precommit | 冻结 |
| C-6 | Finality-first fork choice（final wins / highest justified DAG） | 冻结 |
| C-7 | Consensus Checkpoint = Finalized Reference（≠ storage snapshot） | 冻结 |
| C-8 | Reward 边界（consensus 只管 who finalized） | 冻结 |
| C-9 | `ValidatorVote` 结构 + `DomainId::ValidatorVote` | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| BLS validator 签名（V0.1） | 密码学复杂度；与 ADR-0012/STEP 9 不一致；V0.1 简洁优先（C-2） |
| Witness 直接决定 finality | 快速验证层 ≠ 共识权威；防 Sybil/权重操纵（C-4） |
| longest-chain / highest-block-count | DAG+BFT 非 Nakamoto；finality-first（C-6） |
| storage snapshot = consensus checkpoint | 混淆恢复与最终性（C-7） |

## Consequences

- **正面**：共识纯计算（不碰状态/网络）；确定性强；安全模型数学化（≥2/3、deterministic witness）。
- **成本**：DAG+BFT 复杂度高于单链；完整实现分 STEP 10-2+。
- **可迁移**：BLS 聚合签名可未来 ADR 迁移（不破坏 Vote 结构）。

## Security Impact

- **防 Sybil/随机操纵**：deterministic witness 可复算（C-4）。
- **防分叉歧义**：≥2/3 weighted quorum + finality-first（C-5/C-6）。
- **防恢复/最终性混淆**：consensus checkpoint 与 storage snapshot 分离（C-7）。
