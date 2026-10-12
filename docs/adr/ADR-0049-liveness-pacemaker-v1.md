# ADR-0049: Liveness / Pacemaker Protocol V1

- **Status**: **FROZEN**（2026-09-03 Freeze Execution；STEP 10-12E —— Owner 授权。Liveness / Pacemaker Protocol V1 正式冻结；仅协议文档冻结，未实现任何设计）
  - **2026-10-07 文档修正（PHASE 6G-C；Owner 授权 D4）**：仅将已失效的 `DomainId::Proposer` 历史引用
    改为指向 **ADR-0068** 的 **HashDomain** 命名空间。**未**改变任何 pacemaker / timer / round transition /
    §5 liveness conditions / LIV-1~14 / lock / network 语义。
- **Date**: 2026-09-03
- **Deciders**: Nova Chain 架构组（Owner 决策）
- **Scope**: Nova Consensus 层 Liveness / Pacemaker 协议（Network Model · Pacemaker · Timeout · Proposer
  Selection · Round Change · LockedState 交互 · Partition · Recovery Boundary · Timeout Certificate）
- **前置**: ADR-0033（Consensus Architecture，C-5/C-6）、ADR-0036（Random Witness，W-6）、
  ADR-0037（BFT Round，B-3/B-5）、ADR-0038（Finality / PrecommitQC，F-1~F-18）、ADR-0039（Checkpoint，
  CP-4/CP-5）、ADR-0040（Fork Choice，FC-1~FC-14）、ADR-0041（**ProposalRef Canonical Serialization**，
  FROZEN）、consensus-spec-v1.md（FROZEN，§5 Liveness Assumptions = OPEN）
- 说明：**ADR-0041 = ProposalRef Canonical Serialization V1**（FROZEN）—— 本 ADR 正确引用之，绝不将
  0041 当作 Liveness ADR。编号 0049 经全仓库核验（file/title/content reference 全空）确认为空闲。

---

## 1. Context

STEP 10-9/10-10 已确认：Consensus Safety / Finality / Fork Choice / Checkpoint / Integration 全部
FROZEN 且已实现；Round 状态机（RoundState/RoundStep/RoundTimeout/checked_successor/timeout_for）
已 IMPLEMENTED。但 **Liveness / Pacemaker 协议层**（网络模型、timeout 触发/重置语义、proposer
selection、partition 声明、recovery 边界）在 consensus-spec-v1.md §5 明示 **OPEN / FOLLOW-UP**。

本 ADR 在**不破坏任何已冻结 Safety/Finality/Fork Choice/Checkpoint/Integration 边界**的前提下，正式
设计并冻结 Nova 的 Liveness / Pacemaker 协议语义。**本 ADR 为协议文档（FROZEN），只定义协议，不承载实现。**

## 2. Problem

- Safety 已闭环，但"协议如何持续运行、如何从超时中恢复、如何切换 proposer、如何推进 round、如何处理
  锁状态、网络分区与 eventual synchrony"尚无正式协议定义。
- 现有 timeout 仅是实现机制（B-3 本地事件），不得把"代码中存在 timeout state transition"误认为完整
  Liveness Protocol。
- 需把 Pacemaker 从 implementation 提升为冻结协议层，同时保持：
  ```
  Safety 不依赖 synchrony / timeout correctness / proposer availability / network availability
  ```

## 3. Decision（FROZEN；每项末尾标注 FROZEN / OPEN / DEFERRED）

### 3.1 Network Model — Eventual Synchrony 【FROZEN】
- Nova 采用 **Eventual Synchrony**（候选冻结）：存在未知 **GST**（Global Stabilization Time）之后，
  消息传播/处理延迟最终有界（未知有限 **Δ**）。
- 定义（分析模型值，**非链上 protocol constant**，不写死毫秒）：
  ```
  GST = Global Stabilization Time（分析模型中的未知时间点）
  Δ   = GST 后未知但有限的最大消息传播/处理延迟
  ```
- 理由：与 Nova BFT ≥2/3 weighted quorum + 本地指数 backoff timeout 天然兼容；Safety 数学
  （2/3+2/3>1 重叠 + honest 不双投）在该模型下成立；不选纯同步（不现实）/纯异步（FLP 下无 Liveness）。

### 3.2 Pacemaker Model — Local Timeout Pacemaker 【FROZEN】
- Nova V1 采用 **Local Timeout Pacemaker**：
  ```
  Timeout ≠ Vote
  Timeout ≠ QC
  Timeout ≠ Finality
  Timeout ≠ Certificate
  Timeout ≠ Evidence
  ```
- timeout 的唯一协议效果：
  ```
  (height, round) → checked_successor(round) → next round → step=Propose
  ```
- 不得因 timeout 而：finalize / create QC / unlock / 改变 DAG validity / 绕过 vote validation。

### 3.3 Timer Start 【FROZEN】
- **timer 在 validator 进入 `(height, round, Propose)` 时启动**（本地机制）：
  ```
  enter (height, round, Propose) → start timer
  ```
- 约束（FROZEN）：
  ```
  old round timer MUST NOT remain active
  new round MUST have its own timer
  round transition MUST NOT inherit stale deadline
  ```
- timer 是本地机制：不属于 consensus proof；不改变 Safety rules。

### 3.4 Timer Reset 【FROZEN】
**Timer Reset Rule（FROZEN —— 安全/反滥用边界，使用 MUST / MUST NOT）**：
```
A timer is reset only by a valid, current-context, protocol-progress-relevant event that can
advance the validator's state toward completion of the current round.

The following MUST NOT reset the timer:
- invalid messages
- stale messages
- irrelevant messages
- duplicates with no new progress
- spam
- malformed messages
- messages failing authentication or domain validation
```
- **Timer Reset Deadline Semantics（FROZEN）**：
  ```
  reset → restart the current round's timeout window（用当前 round 配置的 timeout deadline 重新计时）
  不是 extend 剩余时间 · 不是 increase timeout · 不是 change round · 不是 modify quorum
  Timer reset MUST NOT alter: height · round · quorum · LockedState · DAG validity · FinalityState
  ```
- 事件级语义见 §3.4.1 Timer Event Matrix（FROZEN）。

### 3.4.1 Timer Event Matrix 【FROZEN】
> Nova V1 状态机事件模型：verified votes → quorum → derived QC → state progression。QC 是**派生输出**
> （非 network input event）；**不创建新的 QC ingestion architecture**。timer 信号 = 状态推进。

| Event | Timer | 说明（FROZEN） |
|---|---|---|
| Valid current-round Proposal | **RESET** | 有效 + 当前 (height,round) + 正确 proposer + 有效结构；推进当前 round |
| Valid current-round Justification / actual progress | **RESET** | 产生实际协议推进的 valid justification |
| Valid PrevoteQC / verified quorum-progress transition | **RESET** | PrevoteQC = protocol progress（→可向 Precommit 推进）；**≠ Finality / ≠ unlock / ≠ quorum change**（保持 ADR-0038 F-4） |
| Valid PrecommitQC leading to Finality | **STOP** | PrecommitQC → Finality → 当前 height pacemaker STOP；**不 reset / 不进入新 round**（V1 语义；未来需独立协议设计） |
| Finality | **STOP** | finalized height 不再 pacemaking；Finality MUST be monotonic / NOT reverted / 不受 timer reset·timeout·proposer rotation 影响（ADR-0038/0039） |
| Duplicate with no new progress | **NO-OP** | 确认已知状态 ≠ progress；仅首次完成未完成 transition 的推进事件可 reset |
| Old-round message | **NO-OP** | old proposal/vote/justification/QC/timeout MUST NOT reset current timer（stale ≠ progress） |
| Future-round message（无 valid round-change authority） | **NO-OP** | 无 timeout cert（§3.13）；不得凭其自身构造 round-change authority |
| Invalid message | **NO-OP** | bad sig/domain/height/round/proposer/ProposalRef/QC/quorum/malformed —— MUST NOT reset |
| Authentication / domain failure | **NO-OP** | 签名/域校验失败不能成为 timer reset 事件 |
| Spam / adversarial irrelevant traffic | **NO-OP** | anti-liveness-attack：junk/duplicate/invalid/stale/irrelevant 不得阻止 honest timeout |
| RoundTimeout | **EXPIRE → ROUND CHANGE** | → checked_successor(round) → 下一 round → 新 Propose timer |

- **Lock Boundary（FROZEN）**：Timer reset / expiration / round change / proposer change **MUST NOT unlock**
  LockedState；ADR-0037 override/descendant 语义是唯一 lock override authority；本 ADR 不重新定义 lock override。
- **Timeout Boundary（FROZEN）**：timeout MUST NOT count as vote / contribute voting weight / create QC /
  create Finality / reduce quorum / unlock LockedState / mutate DAG validity。

### 3.5 Timeout Backoff 【FROZEN（语义）+ 数值 OPEN】
- 现有实现（round.rs `RoundTimeoutConfig` Default）：
  ```
  initial = 1000, max = 60_000, backoff_factor = 2
  timeout_for(round) = initial × backoff^round，saturating_mul，cap at max_timeout
  ```
- **协议要求（冻结候选）**：timeout 必须具有**最终增长能力**，使 eventual synchrony 下最终能覆盖实际
  网络/处理延迟（支持 liveness）。
- **实现配置（不冻结为 protocol constant）**：`1000 / 60000 / 2` 属 implementation / node configuration
  defaults，**不自动升级为 protocol constants**。
- 明确：timeout 参数影响 Liveness；**不产生 Safety authority**（不创建 vote/QC/finality/锁权）。

### 3.6 Proposer / Leader Selection 【FROZEN（设计）+ 精确算法 DEFERRED】
- Nova V1 采用 **Deterministic ValidatorSet-bound proposer selection**（只定义协议，不实现）：
  1. deterministic；2. 所有 honest validator 可独立复算；3. 绑定 active ValidatorSet；
  4. 绑定 height；5. 绑定 round；6. 不依赖本地随机数；
  7. proposer offline → 本地 timeout → 下一 round；8. round+1 → 新的 deterministic proposer。
- **proposer selection 不得改变 quorum 语义**（Selection MUST be deterministic / derived from active
  ValidatorSet / MUST NOT alter quorum semantics）。
- 精确加权/选择算法 = **DEFERRED（implementation design）**（未来独立实现 STEP；见 §10/§13）。

### 3.7 Proposer Seed Domain Separation 【FROZEN（设计）；命名空间 = ADR-0068】
- **WitnessSeed ≠ ProposerSeed**：Witness selection 与 proposer selection 是不同协议用途；
  不得直接复用 ADR-0036 的 WitnessSeed。
- 本节的「独立 domain」是**哈希域**（hash domain），**不是**签名域 `DomainId`：

  ```
  Proposer hash-domain is governed by the HashDomain namespace defined by ADR-0068.

  HashDomain::Proposer = 0x07          （哈希域前缀；不是 signing DomainId）
  ProposerSeed = H(proposer_domain ‖ chain_id ‖ height ‖ round ‖ validator_set_reference)
  ```

- **`0x07` 的 signing-domain 分配仍为 `Contribution`**（ADR-0005 Nova Domain Registry + ADR-0043，FROZEN；
  经 ADR-0067 修复）。
- `HashDomain` 与 `DomainId` 是**不同命名空间 / 不同 Rust 类型**，二者**无隐式转换**（ADR-0068）。
- 这是协议设计表达，**不写 Rust**（实现见 ADR-0068 与 `crates/crypto/src/hash_domain.rs`）。

### 3.8 Validator Weight 兼容性 【FROZEN】
- 现有 ValidatorSet/quorum 为 **weighted**（`quorum = ceil(total_weight × 2/3)`，weight=bonded_stake，
  ADR-0034 V-2/V-3）。proposer selection 必须与既有 ValidatorSet weight 语义**兼容**。
- 本 ADR **禁止**引入：新 stake model / token weight / economic weight / validator economics /
  validator rotation / epoch。

### 3.9 Round Change 【FROZEN（沿用已实现语义）】
- Round change ≠ height change。候选冻结矩阵：
  | State | Round Change | Reason |
  |---|---|---|
  | DAG | **Preserve** | DAG 跨 round/height 持续（D-2） |
  | FinalityState | **Preserve** | `finality.clone()`；finality 不因 round 改变 |
  | Valid historical QC | **Preserve** | 历史合法证明不因 round 过期失效（F-9） |
  | PrevoteQC registry | **Preserve** | admitted PrevoteQC（bounded 64，canonical）保留供 fork choice |
  | PrecommitQC proof | **Preserve** | finality/checkpoint 依赖 |
  | RoundState | **Reset** | `RoundState::new(height, round+1)`：proposal=None、step=Propose |
  | proposal | Reset | 新 round 从 Propose 开始（须重新 SetProposal） |
  | prevotes | Reset | 新 accumulator |
  | precommits | Reset | 新 accumulator |
  | round_evidence | Reset | `RoundEvidence::reset`（per-round，MF-11） |
  | LockedState | **Preserve** | 见 §3.10 |
- 旧 round 消息 `(height, old_round)` 不得修改当前 `(height, current_round)`（context guard）。

### 3.10 LockedState Interaction 【FROZEN（协议规则）+ enforcement IMPLEMENTATION DEFERRED】
- 核心安全原则（冻结候选）：
  ```
  timeout MUST NOT unlock
  round change MUST NOT unlock
  proposer change MUST NOT unlock
  ```
- LockedState 跨 round 保留；**不绑定 proposer identity**；应绑定 `block identity + protocol
  justification / lock context`（B-5：same → OK；justified descendant → OK；unrelated → reject）。
- validator 在 lock 后 **不得投票到 incompatible conflicting branch**。
- 引用 ADR-0037 B-5 override/descendant 语义；无充分依据处不擅自发明 unlock 规则 —— 本 ADR 不新增
  unlock/override 规则（higher-justified override 归 ADR-0038/Finality 语义）。
- lock enforcement（在 process_vote/集成状态机中强制）= **IMPLEMENTATION DEFERRED**（consensus-spec §3
  ASSUMPTION；现有 LockedState 为 validator-local，不在 ConsensusState/IntegrationContext）。
  **协议规则已冻结：timeout / round change / proposer change MUST NOT unlock LockedState。**

### 3.11 Partition Behavior 【FROZEN（显式声明）】
- 少数 partition：Safety = preserved；Liveness = may stop。
- >1/3 unavailable：无 2/3 quorum ⇒ 无 finality；**禁止降低 quorum**。
- proposer isolated：no proposal → 本地 timeout → next round → next deterministic proposer。
- long partition：允许 Liveness temporarily or indefinitely unavailable；**绝不为恢复 Liveness 降 quorum**。
- Nova 原则：**Safety takes precedence over temporary Liveness.**（显式声明；partition 不得产生
  conflicting finality —— quorum 重叠数学保证）。

### 3.12 Recovery Boundary 【DEFERRED】
- Node/Network recovery（P2P / block sync / state sync / restart / persistence / peer discovery）=
  **DEFERRED**（node 层；不在本 ADR）。
- 协议边界（只定义，不实现）：recovered validator 必须从 valid protocol state 恢复并遵守当前 consensus
  validation rules。具体 recovery mechanism = DEFERRED（Node/Network Integration）。

### 3.13 Timeout Certificate 【FROZEN：NO】
- Nova V1 **不需要** TimeoutCertificate / RoundChangeCertificate / PacemakerCertificate。理由：
  1. timeout 是 local event；2. timeout 非 finality proof；3. finality 必须继续依赖 valid PrecommitQC；
  4. local round progression（checked_successor）已足够；5. 避免额外 consensus proof complexity。
- 未来若需要 ⇒ 独立 ADR。

---

## 4. Safety Guarantees（不受 Liveness 影响）
```
Safety 不依赖 synchrony / timeout correctness / proposer availability / temporary partition / delay。
即使网络长期延迟、partition、proposer offline、timeout 错误、stale message，也不得：
  降低 quorum · 产生无 QC 的 finality · 绕过 vote validation · 绕过 lock ·
  修改 finalized reference 回退 · 产生 conflicting finality
```

## 5. Liveness Conditions
```
在以下条件下共识最终继续推进：
  honest validator weight 足够（≥ 2/3）
  network eventually recovers（存在 GST）
  post-GST message delay eventually bounded（未知有限 Δ）
  timeout eventually exceeds effective network/processing delay（backoff 最终增长）
```

## 6. Invariants（LIV；如与既有编号冲突则以既有为准并重编号报告）
```
LIV-1  Timeout cannot create finality.                             = 已有实现验证（PASS）
LIV-2  Finality cannot decrease.                                   = 已有实现验证（PASS）
LIV-3  Round number is monotonic.                                  = 已有实现验证（checked_successor）
LIV-4  Round overflow is rejected.                                 = 已有实现验证（Rejected{RoundOverflow}）
LIV-5  Round may advance without QC.                               = 已有实现验证（RoundTimeout 独立）
LIV-6  Finality requires valid PrecommitQC.                        = 已有实现验证
LIV-7  Timeout cannot bypass LockedState.                          = 实现保持（timeout 不触 lock）；enforcement OPEN
LIV-8  Late old-round messages cannot mutate current state.        = 已有实现验证（context/终态 guard）
LIV-9  Partition may stop liveness but cannot create conflicting finality. = 设计保证（quorum 数学）；validation 待
LIV-10 Timeout cannot modify DAG validity.                         = 已有实现验证
LIV-11 Proposer selection is deterministic.                        = 设计（未实现）→ 未来验证
LIV-12 Proposer failure can be bypassed by round progression.      = 设计（timeout→next round）；proposer 未实现
LIV-13 Timeout parameters cannot create Safety violations.         = 设计论证；validation 待
LIV-14 Finality remains final across round changes.                = 已有实现验证（finality clone 保留）
```

## 7. Non-Goals
```
slashing · equivocation implementation · validator rotation · epoch ·
P2P transport · state synchronization · storage persistence · restart persistence ·
execution layer · economic incentives · tokenomics
（均不在本 ADR；validator rotation/epoch = future ADR）
```

## 8. Compatibility / Dependencies
```
ADR-0033 — Consensus Architecture（C-5/C-6）
ADR-0036 — Random Witness（W-6；WitnessSeed ≠ ProposerSeed）
ADR-0037 — BFT Round（B-3 timeout / B-5 lock）
ADR-0038 — Finality / PrecommitQC（F-1~F-18）
ADR-0039 — Checkpoint（CP-4/CP-5）
ADR-0040 — Fork Choice（FC-1~FC-14）
ADR-0041 — ProposalRef Canonical Serialization（FROZEN；ProposalRef wire 编码）
consensus-spec-v1.md（FROZEN；§5 Liveness Assumptions 本 ADR 之开放点来源）
```

## 9. Implementation Boundary
- 已存在（不属本 ADR 交付）：RoundState / RoundStep / RoundTimeout / checked_successor / timeout_for /
  Round transition / RoundEvidence / QcRegistry / Finality / Fork Choice / Checkpoint。
- **已存在 ≠ 完整 Liveness Protocol**。仍待未来实现（**不在本 STEP**）：
  proposer selection · timer lifecycle（start/reset 落地）· LockedState enforcement ·
  network integration · recovery · persistence。

## 10. Open Questions
```
协议级 Timer Reset 已 FROZEN（§3.4/§3.4.1）；其余 OPEN/DEFERRED（不伪装完成）：
  · exact timeout numeric values = OPEN（implementation / node configuration，非 consensus constant）
  · exact proposer weighting algorithm = DEFERRED（implementation design）
  · validator rotation / epoch = future ADR
  · proposer seed 的**哈希域**命名空间 = 已由 ADR-0068 定义并冻结（`HashDomain::Proposer = 0x07`；
    非 signing DomainId；`0x07` 的 signing 分配 = `Contribution`）
DEFERRED（implementation / node / network layer）：
  · timer 内部结构 / clock / OS timer / scheduler / event loop / monotonic clock
  · recovery implementation · persistence · network transport · state sync
  · LockedState enforcement（GAP D；协议规则 MUST NOT unlock 已冻结）
```

## 11. Validation Requirements（未来）
```
Timeout Safety：timeout cannot create QC · create finality · unlock · alter DAG validity
Round：round monotonicity · round overflow rejection · old-round message rejection
Proposer（未来）：same protocol state ⇒ same proposer
Partition：partition may halt liveness；partition cannot produce conflicting finality
```

## 12. Consequences
- **正面**：Pacemaker 从 implementation 提升为协议层；Safety/Liveness 严格分离；为 Node/Network
  Integration 与 proposer/timer 实现提供冻结语义输入；NO timeout certificate 保持协议简洁。
- **成本**：proposer exact weighting algorithm（DEFERRED，implementation design）与 proposer **哈希域**命名空间
  （**ADR-0068 已定义并冻结**：`HashDomain::Proposer = 0x07`，非 signing DomainId）待后续**实现**；
  LockedState enforcement 仍需独立关闭（GAP D，implementation）。Timer Reset 协议语义已 FROZEN。
- **可迁移**：数值参数为 node config，可调不破坏 Safety；未来需 timeout cert / rotation ⇒ 独立 ADR。

---

## 变更记录
| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-09-03 | ADR-0049 初稿（PROPOSED Design Draft）：Liveness / Pacemaker Protocol V1；11 决策项 + Safety/Liveness 分离 + LIV-1~14 + Non-Goals + 依赖 + Open/Deferred | STEP 10-12B（Owner 授权 ADR-0049；DESIGN DRAFT ONLY，未 freeze / 未实现） |
| 2026-09-03 | **FROZEN（Freeze Execution）**：Status PROPOSED→FROZEN；§3.3 Timer Start 约束 · §3.4 Timer Reset Rule + Deadline Semantics · §3.4.1 Timer Event Matrix（FROZEN）写入；§10/§12 Open/Deferred 清理（Timer Reset 不再 protocol-OPEN；proposer 算法 / lock enforcement = implementation DEFERRED；NO timeout cert 保持）。仅 ADR 文档变更，0 代码 / 0 其他文件 | STEP 10-12C（FG-6 OPEN）→ STEP 10-12D（FG-6 READY FOR FREEZE）→ Owner 授权 STEP 10-12E Freeze Execution |
| 2026-10-07 | **文档修正（PHASE 6G-C；Owner 授权 D4）**：§3.7 / §10 / §12 中已失效的 `DomainId::Proposer` 引用改为指向 **ADR-0068 的 HashDomain 命名空间**（`HashDomain::Proposer = 0x07`，非 signing DomainId；`0x07` 的 signing 分配仍为 `Contribution`）。**未**改变 pacemaker / timer semantics / round transition / §5 liveness conditions / LIV-1~14 / lock / network / 任何代码 | Owner 授权 PHASE 6G-C — D4 documentation correction |
