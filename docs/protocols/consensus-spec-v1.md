# Nova Chain — Consensus Specification V1（BFT Round 安全模型）

- **Status**: Draft（STEP 10-5.1；基于已冻结 ADR-0033 C-1~C-9 / ADR-0034 V-1~V-6 /
  ADR-0035 D-1~D-5 / ADR-0036 W-1~W-6 / ADR-0037 B-1~B-6）
- **Date**: 2026-08-28
- **Scope**: BFT Round 的当前实际规则 + 安全论证边界。
- **本文件是协议说明文档，不是代码实现**。任何与本文件不符的代码行为均属实现缺陷。

---

## 1. Scope

本 spec 定义以下 consensus context 的**当前已确定**规则（对应 `nova-consensus` 已冻结设计）：

| 概念 | 定义 | 冻结来源 |
|------|------|----------|
| `height` | 区块提议高度（DAG `BlockReference.height` 同源；BFT context 的一部分） | ADR-0035 D-1 / ADR-0037 B-1 |
| `round` | BFT 轮次，`(height, round)` **唯一确定 consensus context**；round 单调递增 | ADR-0037 B-1 |
| `proposal` | 当前 round 的候选区块引用（`ProposalRef{block_hash, proposer}`；完整 Block PHASE 7） | ADR-0037 B-1/B-4 |
| `prevote` | 第一阶段投票（`VoteType::Prevote = 0x01`；`canonical_vote_payload` 121B） | ADR-0034 V-4 / ADR-0009 §2 |
| `precommit` | 第二阶段投票（`VoteType::Precommit = 0x02`） | ADR-0034 V-4 |
| `quorum` | **`ceil(total_weight * 2 / 3)`**（加权 ≥2/3；`3Q >= 2T`） | ADR-0034 V-3 / ADR-0033 C-5 |
| `finalization boundary` | **precommit quorum**（≥2/3 weighted，且 target 匹配当前 proposal）触发 `RoundStep::Finalized` | ADR-0037 B-2 / B-5 |

**finalization boundary 精确规则**（10-5.1 修复后，`process_vote` 实际强制执行）：

1. **上下文守卫**：vote 必须满足 `vote.height == state.height && vote.round == state.round`，
   否则**忽略**（不进 accumulator / 不计 quorum / 不改状态）。
2. **终态守卫**：`RoundStep::Finalized` 之后任何 vote **忽略**（状态稳定，无重复推进事件）。
3. **推进规则**：
   - `Propose → [≥2/3 weighted prevote，target 匹配 proposal] → Precommit`
   - `Precommit → [≥2/3 weighted precommit，target 匹配 proposal] → Finalized`
   - 只推进**匹配当前 proposal.target** 的 quorum（不匹配的 quorum 不推进）。
4. **lock 规则（B-5，validator 本地规则）**：precommit quorum 触发 `lock(block_hash, round)`；
   之后只投同一 block 或其 justified descendant；`LockedState::is_compatible` 判定
   （same / descendant ⇒ OK；unrelated ⇒ reject）。**该规则当前是协议假设，状态机未强制**（见 §3）。

---

## 2. Byzantine Model

当前协议采用的假设（源自冻结的加权 ≥2/3 quorum 设计，ADR-0033 C-5 / ADR-0034 V-3）：

```
Byzantine weight  <  1/3 · total_weight
Honest weight     >= 2/3 · total_weight
```

- 该数值**派生自**冻结的 `quorum = ceil(T*2/3)` 与安全论证需求，**本 spec 不修改**。
- 若未来修改 quorum 阈值，必须先修改冻结 ADR，再更新本 spec。

---

## 3. Honest Validator Assumption

**协议假设（标记 `ASSUMPTION`，非当前状态机 enforcement）：**

> 同一 consensus context `(height, round)` 下，honest validator **不会**对冲突 target
> 同时进行违反协议的投票（不双投 / 不 equivocate）。

- **当前状态机没有强制执行该假设**：`VoteAccumulator` 按 target 独立去重，
  同一 validator 对多个不同 target 的 prevote/precommit 均会被记录，无 double-vote /
  conflicting-vote 检测（10-5.1 GAP C，slashing 归后续设计）。
- 同理，lock 规则（§1.4）当前**未**在 `process_vote` 中强制（10-5.1 GAP D）。
- **不得**将上述 `ASSUMPTION` 描述为代码已强制执行。

---

## 4. Safety Argument

当前协议模型下的 safety reasoning（**论证，非代码证明**）：

> 若两个冲突 target 各自达到 ≥2/3 权重形成 finalized result，则两集合权重之和
> `2/3 + 2/3 > 1`，两集合**必然重叠**。因此在假设
> （a）`honest weight >= 2/3`（§2）且
> （b）honest validator 不对冲突 target 双投（§3）
> 成立时，**两个 conflicting finalized result 不能同时合法产生**。

**限制声明**：
- 这是当前协议模型下的 safety argument；
- **不得**声称"代码已经完整证明安全"；
- 论证依赖 §2/§3 假设；若任一假设被破坏（如双投未检测、honest weight 跌破 2/3），
  结论不成立。

---

## 5. Liveness Assumptions

当前**已确定**的条件：

- `RoundTimeoutConfig`（B-3）：本地节点超时事件，**非共识输入**；`timeout(round) = initial × backoff^round`，
  cap at `max_timeout`。最终状态由 vote / quorum / lock 决定。
- **禁止** timeout 直接 finalize / 改变 block validity（B-3）。

以下**未正式定义**（标记 `OPEN / FOLLOW-UP`，不得凭空设定）：

```
- 网络模型（部分同步 / 异步 / 同步假设）
- timeout protocol（超时后如何进入下一 round 的节点本地行为）
- leader rotation / proposer selection
- synchrony assumptions
```

---

## 6. Scope Boundary

以下内容**不属于本 spec 当前版本**，进入后续设计（对应各 ADR / STEP）：

| 排除项 | 归属 |
|--------|------|
| QC 完整结构（quorum certificate 类型 / 存储） | STEP 10-6 Finality |
| Finality architecture（higher justified override / fork choice 判定） | STEP 10-6 |
| Checkpoint finalization integration | STEP 10-7 |
| Validator lifecycle（加入 / 退出 / 权重变化） | PHASE 7+ |
| Slashing（double-vote / equivocation 证据与惩罚） | PHASE 7+ / 未来 ADR |
| Epoch transition（`epoch_length_blocks` 消费） | 未来 ADR |
| Network message transport（vote/proposal 在 P2P 的封装） | node 协调层 |
| Persistent recovery（RoundState 持久化 / 重启重放防护） | node 协调层 |

---

## 变更记录

| 日期 | 变更 | 依据 |
|------|------|------|
| 2026-08-28 | 初稿：记录 BFT Round 当前规则 + safety argument + scope 边界 | STEP 10-5.1（修复 A/B + GAP H） |
