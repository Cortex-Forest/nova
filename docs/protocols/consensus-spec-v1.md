# Nova Chain — Consensus Protocol Specification V1

- **Status**: **FROZEN**（STEP 10-10；Consensus Protocol Specification V1 FINAL FREEZE，2026-08-30；
  整合 ADR-0033~0040 + STEP 10-9 已冻结规则为唯一权威共识规范）
- **Date**: 2026-08-30
- **Scope**: 唯一权威共识规范。整合 validator/vote/dag/witness/bft-round/finality/checkpoint/
  fork-choice/integration 的**已冻结**规则；严格区分 ENFORCED / ASSUMPTION / DEFERRED。
- **依据**：ADR-0033 C-1~C-9 / ADR-0034 V-1~V-6 / ADR-0035 D-1~D-5 / ADR-0036 W-1~W-6 /
  ADR-0037 B-1~B-6 / ADR-0038 F-1~F-18 / ADR-0039 CP-1~CP-8 / ADR-0040 FC-1~FC-14（均 FROZEN）+
  STEP 10-9.1 / 10-9.2（FROZEN）+ 既有实现（validator/vote/dag/witness/round/finality/checkpoint/
  fork_choice/integration）。
- **本文件是协议说明文档，不是代码实现**。任何与本文件不符的代码行为均属实现缺陷。
- **三态原则**：`ENFORCED`（状态机已强制执行）≠ `ASSUMPTION`（依赖但未强制）≠
  `DEFERRED`（后续阶段）；禁止将 ASSUMPTION 写成 ENFORCED、将 DEFERRED 写成已实现。

---

## 0. 规范原则与三态分类

本规范只整合已冻结规则（ADR-0033~0040 + STEP 10-9），**不新增协议**。每条规则标注：

| 标记 | 含义 | 举例 |
|------|------|------|
| **ENFORCED** | 已由 ADR + implementation 强制执行的规则 | 上下文/终态守卫、`verify_qc`、`checked_successor`、PrevoteQC-only registry |
| **ASSUMPTION** | 协议依赖但当前状态机未强制 | honest validator 不双投（§3）；lock 规则（§1.4）未在 `process_vote` 强制 |
| **DEFERRED** | 明确留给后续阶段 | Epoch / validator rotation / Slashing / P2P / storage / recovery / execution / mempool / node orchestration（§6/§13） |

**禁止**：把 ASSUMPTION 描述为代码已强制；把 DEFERRED 描述为已实现。

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

> **注**：§6 表格中标注 `STEP 10-6 / STEP 10-7` 的项（QC/Finality/Checkpoint）已在 STEP 10-6/10-7
> 冻结实现，现整合为本规范 §7/§10；其余项仍为 **DEFERRED**（§13）。

---

## 7. Data Model

引用已冻结定义（**不重新定义字段语义**）：

| 概念 | 冻结来源（实现） | 要点 |
|------|------|------|
| `ValidatorId` = SHA-256(consensus_public_key) | ADR-0034 V-1（validator.rs） | 32B；Ord 字节序 |
| `ValidatorInfo`（weight = bonded_stake） | ADR-0034 V-2（validator.rs） | 静态权重 |
| `ValidatorSet`（quorum = ceil(T*2/3)） | ADR-0034 V-3（validator.rs） | `3Q >= 2T`；`from_genesis` |
| `ValidatorVote`（121B canonical，ADR-0009） | ADR-0034 V-4（vote.rs） | round/height/target/vote_type/source/validator_id/timestamp |
| `VoteType`（Prevote=0x01, Precommit=0x02） | ADR-0034 V-4（vote.rs） | C-5 两阶段 |
| `BlockReference`（hash/height/parents/proposer:ValidatorId） | ADR-0035 D-1（dag.rs） | DAG 节点 |
| `Dag`（唯一 hash + add 验证 + causal_order） | ADR-0035 D-2/D-3（dag.rs） | **DAG ≠ Finality**（C-3） |
| `WitnessSeed`/`WitnessProof`（DomainId::Witness） | ADR-0036 W-1~W-6（witness.rs） | **Witness ≠ finality authority**（W-6） |
| `QuorumCertificate`（context/target/validator_set_id/evidence） | ADR-0038 F-2/F-3/F-11/F-12（finality.rs） | evidence 升序 |
| `FinalityState`（finalized_reference/highest_precommit_qc） | ADR-0038 F-1/F-14（finality.rs） | F-14 恢复事实 |
| `Checkpoint`（chain_id/finalized_block_hash/height/round/precommit_qc） | ADR-0039 CP-1~CP-8（checkpoint.rs） | 非新区块/非签名对象 |
| `ConsensusState`（round + finality） | STEP 10-9 MF-1（integration.rs） | **canonical consensus state** |
| `IntegrationContext`（qc_registry + round_evidence） | STEP 10-9 MF-10/11/12（integration.rs） | **bounded + rebuildable derived cache**（非 canonical） |

---

## 8. Consensus Inputs

**consensus logical input（本规范）**：
- `ValidatorVote` + signature（V-5 已验证，**硬 precondition**；integration 不重验签名，MF-2）。
- `ProposalRef`（block_hash + proposer；完整 Block 属 PHASE 7，DEFERRED）。
- 已验证 `QuorumCertificate`（供 registry / fork_choice 消费）。
- `RoundTimeout`（本地事件，非共识输入，B-3）。

**P2P / network transport（不属于本规范）**：vote/proposal/QC 在网络上的封装、消息
ID/版本/编码/大小/超时——归 node 协调层 / 网络协议（DEFERRED，§13）。

---

## 9. State Model

严格体现 STEP 10-9（MF-12 三元组）：

```
(ConsensusState, IntegrationContext, ConsensusEvent)
        ↓
(ConsensusState', IntegrationContext', TransitionResult)
```

- `ConsensusState` = **canonical consensus state**（replay 比对对象；可持久化，node 层候选 GAP G）。
- `IntegrationContext` = **bounded + rebuildable derived cache**（MF-12/H-3）。
  - **丢失 QcRegistry ≠ consensus-state corruption**；恢复必须通过 replay/rebuild 重建
    deterministic context（同一事件流按 canonical rules）。
  - 不是 `ConsensusState` 字段（MF-1）。
- **新增 canonical state：无**。本规范**不纳入 ConsensusState canonical encoding 协议**（Q2 裁决 NO；
  未来 storage/persistence 阶段再系统解决）。

---

## 10. Transition Pipeline

引用 10-9 §5.2 冻结 pipeline，**不重新设计**：

```
Round → QC → Finality → Checkpoint → ForkChoice
```

### QcRegistry（ENFORCED）
- **PrevoteQC-only**（10-9 §3.0）；`MAX_QC_REGISTRY_ENTRIES = 64`（MF-10/H-4）。
- identity = `encode_qc(qc)`（MF-9；evidence 升序 F-12 ⇒ 确定性）。
- canonical rank = identity 字典序（`Vec<u8>` Ord）。
- 承载 = `BTreeMap<Vec<u8>, QuorumCertificate>`；lowest-N 由 `pop_last` 维持。
- **permutation invariant** / input-order independent / deterministic replacement（MF-9 方案 A）。
- **禁止** arrival-order eviction / evict-oldest / evict-newest / truncate（MF-6/MF-9）。
- PrecommitQC **不进入 registry**（MF-10 S1）：pipeline ⑥ 直接驱动 finality/checkpoint。

### RoundEvidence（ENFORCED，ephemeral）
- 绑定 `(height, round)`；timeout reset；**不跨 round 累积**（MF-11）。
- 唯一用途 = QC construction（MF-8 只组装冻结 `QuorumCertificate`）。
- 不属于 canonical `ConsensusState`（MF-1/MF-11）。

### 原子性（ENFORCED）
- `Applied` ⇒ 完整 next_state + 确定性 context 更新；`Ignored`/`Rejected` ⇒ state 与 context 均不变
  （MF-7/MF-12 契约 3）。无隐式状态修改。

### Finality / Checkpoint（ENFORCED；F-8 / CP-MF-4 文字化，不改协议语义）
- **F-8（Finality Applicability / Update）**：
  - `Advance`（Y descendant of X，或初始 finality）⇒ `FinalityState.finalized_reference` 更新为
    `qc.target`（finality 改变）。
  - `Idempotent`（Y == X）⇒ **Finality 不变**。
  - `Conflict`（unrelated）⇒ **非 protocol error**（valid-but-inapplicable，evidence 保留，F-9）。
- **CP-MF-4（Checkpoint 派生条件）**：Checkpoint 仅在 `Finality Advance` 时派生/更新；
  `Idempotent` **不产生** checkpoint advance（`derived.checkpoint = None`）。

---

## 11. Determinism（MF-12 规范语言化）

```
same state + same context + same event
        ⇒ same next_state + same next_context + same result
```

1. 同输入同输出（契约 1）。
2. insertion order / 内部容器不影响结果（契约 2）。
3. QC admission 不依赖 arrival order（契约 5）。
4. permutations ⇒ 相同 registry（T17 验证）。
5. `Ignored` ⇒ state/context 均不变（契约 3）。
6. `Rejected` ⇒ state/context 均不变（契约 3）。
7. `Applied` ⇒ context 变化只能由 canonical admission / evidence rules 决定（契约 4）。

---

## 12. Replay

- `ConsensusState` = replay comparison object（10-9 T4/T23）。
- `IntegrationContext` = rebuildable derived cache（MF-12 契约 6 / H-3）。
- Replay 不得依赖：HashMap insertion order、网络到达顺序、本地缓存偶然状态。
- 重建路径：`event stream → rebuild context（canonical record/admit）→ replay transition
  → deterministic result`。

---

## 13. Security Boundary

### ENFORCED（状态机已强制）
- round monotonicity（`checked_successor`，MF-5；不 wrap）。
- terminal-state protection（终态守卫，10-5.1 修复 B）。
- replay/context guards（上下文守卫，10-5.1 修复 A）。
- QC validation boundary（`verify_qc`，F-6a 三层）。
- deterministic ordering（`causal_order` D-3；maximal anchor FC-MF-10）。
- permutation invariance（T17）；PrevoteQC-only registry（T21）。
- finality-dominant fork choice（FC-12）；原子 transition（MF-7）。

### ASSUMPTION（依赖但未强制）
- honest validator 不双投（§3；GAP C，slashing 归 DEFERRED）。
- lock 规则（§1.4，GAP D）未在 `process_vote` 强制。

### DEFERRED（不伪装为已存在）
- slashing / equivocation punishment、validator rotation、epoch、lock enforcement、P2P、
  storage/persistence/recovery、execution、mempool、node orchestration、完整 Block 格式、
  网络协议、经济模型、主网部署（边界表见 §6/§13）。

---

## 14. Traceability Matrix

| 协议规则 | ADR | 实现 | 测试 |
|---|---|---|---|
| ValidatorSet / quorum | ADR-0034 V-1~V-3 | validator.rs | `validator::tests::*` |
| ValidatorVote / verify_vote | ADR-0034 V-4/V-5 | vote.rs | `vote::tests::*` |
| DAG / causal_order | ADR-0035 D-1~D-5 | dag.rs | `dag::tests::*` |
| Witness | ADR-0036 W-1~W-6 | witness.rs | `witness::tests::*` |
| BFT Round / process_vote | ADR-0037 B-1~B-6 | round.rs | `round::tests::*` |
| QC / Finality | ADR-0038 F-1~F-18 | finality.rs | `finality::tests::*` |
| Checkpoint | ADR-0039 CP-1~CP-8 | checkpoint.rs | `checkpoint::tests::*` |
| ForkChoice | ADR-0040 FC-1~FC-14 | fork_choice.rs | `fork_choice::tests::*` |
| Consensus Integration | STEP 10-9.1/10-9.2 | integration.rs | `integration::tests::t1..t23` |

> 覆盖：nova-consensus lib **108 tests** + smoke 1（`cargo test --workspace` 全 PASS）。
> 本矩阵只引用**已存在**的实现与测试；禁止凭空编写不存在的测试/实现。

---

## 变更记录

| 日期 | 变更 | 依据 |
|------|------|------|
| 2026-08-28 | 初稿：记录 BFT Round 当前规则 + safety argument + scope 边界 | STEP 10-5.1（修复 A/B + GAP H） |
| 2026-08-29 | **DESIGN DRAFT（10-10）**：整合 ADR-0033~0040 + STEP 10-9 为唯一权威 Consensus Protocol Spec V1；新增 §0 三态原则、§7~§14（Data Model / Inputs / State Model / Pipeline / Determinism / Replay / Security Boundary / Traceability）；原 §1~§6（10-5.1 BFT Round）文本原样保留 | STEP 10-10 Design Draft（用户批准；**未 commit / 未 freeze**） |
| 2026-08-30 | **MF-S-1 CLOSED**（§0 引用 §9→§3）/ **MF-S-2 CLOSED**（§10 补述 F-8 Advance/Idempotent/Conflict + CP-MF-4，仅已冻结规则文字化） | STEP 10-10 DESIGN DRAFT REVIEW 🟡 APPROVED WITH MICRO-FREEZE |
| 2026-08-30 | **DESIGN FREEZE（10-10）**：Status DRAFT→FROZEN。Consensus Protocol Specification V1 冻结，作为 ADR-0033~0040 + STEP 10-9 已冻结规则的权威整合（**不重新解释/不修改任何已冻结协议规则**）；MF-S-1/MF-S-2 CLOSED、原 §1~§6 语义未变、0 协议/primitive/ADR 变化、无 encoding 偷渡 | 用户最终裁决 🟢 APPROVED FOR DESIGN FREEZE |
