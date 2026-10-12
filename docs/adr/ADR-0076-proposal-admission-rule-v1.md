# ADR-0076: Proposal Admission Rule V1

## Metadata

| 字段 | 值 |
|---|---|
| ADR | ADR-0076 |
| Title | Proposal Admission Rule V1 |
| Status | **Proposed / Approved for implementation planning**（**不是** Implemented；实现尚未授权） |
| Type | Protocol-adjacent（Node admission rule；**不改变**共识语义） |
| Depends on | ADR-0041（ProposalRef wire，**FROZEN**）· ADR-0042（Block Format）· ADR-0049（Liveness/Pacemaker，**FROZEN**）· ADR-0050（Proposer Selection） |
| Related | ADR-0066 / ADR-0070–0075（O2 / RoundChangeCertificate；本 ADR **不修改**） |
| Owner Decisions | OD-1..OD-9（见 §8；PHASE 6H-OWNER-DECISION-FINAL）+ OD-10..OD-14（见 §8；PHASE 6H-ADR-0076-CORRECTION-APPLY）+ OD-15..OD-19（见 §8；PHASE 6H-A11-DESIGN-CORRECTION）+ **OD-20..OD-21（见 §8；PHASE 6H-A11-OWNER-DECISION-APPLY-V1.4）** |
| Approval basis | PHASE 6H-AR（一致性审查）· 6H-AS（设计预检）· 6H-APD（草案 V1.0）· 6H-OWNER-REVIEW（CHANGES REQUIRED）· 6H-ADR-REVISE-PRECHECK（V1.1）· 6H-A11-PRECHECK（依赖事实复核）· 6H-ADR-0076-CORRECTION-PRECHECK（事实偏差定位）· **6H-ADR-0076-CORRECTION-APPLY（OD-A..OD-E 文本修正）** · **6H-A11-PRECHECK（区链/提案时序阻塞）** · **6H-A11-DESIGN-CORRECTION（OD-15..OD-19）** · **6H-A11-OWNER-DECISION-APPLY-V1.4（OD-20/OD-21：pending evidence + 参数冻结）** |

---

## 1. Context

ADR-0049 §3.4 / §3.4.1 **定义何时允许 pacemaker RESET**：

```
Valid current-round Proposal（有效 + 当前 (height,round) + 正确 proposer + 有效结构） => RESET
Old-round message / Future-round message / Invalid message（bad height/round/proposer/ProposalRef） => NO-OP
```

ADR-0041 **冻结了 `ProposalRef` 的 canonical wire**，并明确 `proposer` 的 authority 判定**不属于 serialization 层**
（A11 proposer authority validation = **DEFERRED**）：

```
canonical_proposal_ref = block_hash(32B) ‖ proposer(32B)      // total 64B，定长（PR-1，FROZEN）
```

当前实现事实（可复核）：

- 提案准入只检查 `step == Propose`（`crates/consensus/src/round.rs:128-136`、`crates/consensus/src/integration.rs:336-350`）；
- 节点入站提案路径仅做 decode + submit（`crates/node/src/assembly.rs:371-374`）；
- consensus envelope 由 **NetworkSigner（网络身份 key）** 签名，`sender = network NodeId`，
  与 `ValidatorId` / validator key **刻意分离**（`crates/node/src/egress.rs:5-12, 29, 96-107`）；
- 对照：**vote 有内层 validator 签名**并经验证（`crates/node/src/assembly.rs:401`、`crates/consensus/src/vote.rs:107`）。

⇒ **`ProposalRef.proposer` 是"未认证声明"**：任何已认证 peer 均可声明任意 proposer。
⇒ 一条越界（old/future-round）或伪造 proposer 的提案，只要本地处于 `Propose`，就会被接受
（`step` 由 `Propose→Prevote`、`proposal_hash` 由 `None→Some`），从而使 pacemaker 的
**RESET 判据（状态差分 `observed != entry`，`crates/node/src/runtime.rs:786`）被触发**——
这正是 ADR-0049 §3.4.1 明确列为 **NO-OP** 的一类事件。

**实测后果（PHASE 6H-AQ / 6H-AQ FOLLOW-UP）**：5/7 场景单节点 `timer_elapsed 893 → 9`（同轮 RESET）
⇒ 该节点停留 `(height=2, round=0)`，其余 4 节点进入 `round=1` ⇒ 任一 round 均 < quorum 5/7
⇒ finality 无法恢复（240s 与 360s 两次实验均 FAIL）。

**Problem Statement（GAP）**

| # | 缺口 | 后果 |
|---|---|---|
| GAP-1 | 提案 wire 不携带 `(height, round)`（ADR-0041 PR-1）⇒ 无法判定 "current-context" | ADR-0049 的 Old/Future-round ⇒ NO-OP 在提案路径**不可执行** |
| GAP-2 | `ProposalRef.proposer` 无 validator 认证 ⇒ 无法判定 "correct proposer" | 伪造 proposer 的提案可被接受 |
| GAP-3 | RESET 判据为**状态差分**而非**事件分类** | 任何非进度的状态变化都可能被误判为 progress |
| GAP-4 | ADR-0049 §6 LIV-8 的 context guard 仅覆盖 **vote** 路径 | 提案路径无上下文绑定 ⇒ LIV-8 的验证陈述不完整 |
| **GAP-5** | proposal 与其区块**同批**到达时，区块在同一 `step()` 内**晚于**提案被处理（`driver.rs:266-272` 先 `Proposal(ref)` 后 `GossipBlock(wire)`；`runtime.rs:3267` commands 早于 `:3298` block inbound） | Guard A 的"区块本地可用"在首送达 step **恒不成立** ⇒ 若照字面实现 Mode-2 ⇒ 几乎全部远程提案被拒（新活性故障） |
| **GAP-6** | 区块登记需要"提案已被接受"提供的轮证据（`runtime.rs:198-207` `proposal_round_evidence` ⇒ `:1355-1358` `register_remote_canonical_block`） | 与 Guard A 形成**循环依赖**；靠调 pipeline 顺序规避会触发 `Ok(0)` 回退 round 0 ⇒ `put_verified` 签名复验失败 ⇒ `step()` 错误 |

> **定性**：这不是 ADR-0049 错误，而是 **HOW 层规则缺失**：ADR-0049 定义 **WHEN**（何种事件允许 RESET），
> 但从未定义 **HOW**（提案何时才算 valid / current-context / correct proposer，以及由谁认证）。
> 本 ADR 补 HOW；WHEN 仍完全归 ADR-0049。

---

## 2. Decision（本 ADR 的规范内容）

### PADR-1 — `ProposalRef.proposer` 的定位（MUST）

```
ProposalRef.proposer = declared metadata（发送者在 payload 内的声明）
                     ≠ cryptographic authorization（NOT an authorization credential）
```

- **MUST NOT** 以该字段作为任何授权判定来源。
- **MUST NOT** 在准入失败时 fallback（回退）到该字段。
- 理由：consensus envelope 仅受 `NetworkSigner`（网络身份 key）保护；vote 有内层 validator 签名而提案没有。

### PADR-2 — Admission Authority 与其前置条件（MUST）

提案准入的**唯一健全锚点** = 被引用区块（内容寻址 `block_hash` ⇒ 内容不可替换）上的
**validator 签名与身份判定**，而非发送者声明。

```
完整准入（Mode-2）PRECONDITION（A11 prerequisite）:
  proposal admission authorization path 已建立
  （Guard A / Guard C 接线 + expected proposer 绑定 + (height_now, round_now) 语义）
```

**Production proposer signature path already exists.
A11 scope is proposal admission authorization integration.**
（A11 的剩余工作**不是**新增签名能力：`build_block` 的 zero signature 是**设计 seam**，
生产出块路径 `runtime_propose` 已附加 proposer 签名；详见下表。）

当前状态（可复核）：

| 事实 | 证据 |
|---|---|
| Block 结构存在 `proposer_signature` 字段 | `crates/core/src/block.rs:121-130`（`block_hash` 只覆盖 header+body，**不含**签名；ADR-0042 Option B Amendment） |
| `build_block` 保留 zero signature = **设计 seam** | `crates/node/src/block_builder.rs:184`（注释："签名由签名 seam 提供；∉ block_hash"）· `:199`（`proposer_signature: [0u8; 64]`）· `:126`（doc） |
| **生产已附加 proposer signature** | `crates/node/src/runtime.rs:282-284`（`a.sign_block(&mut pb.block)`）→ `crates/node/src/validator.rs:267-271`（`sign_block` → `attach_proposer_signature`）→ `crates/node/src/block_builder.rs:229/245` |
| 生产**强制**经 B2-B 签名安全闸（无 journal ⇒ fail-closed；**无** bypass） | `crates/node/src/runtime.rs:2152-2158`（journal 创建/恢复）· `:2167`（`.with_block_safety(…)`）· `crates/node/src/validator.rs:248-252/268-270` |
| 落盘前复验（hash 重算 + 签名复验） | `crates/node/src/runtime.rs:306`（`put_verified`）· `crates/node/src/block_adapter.rs:295` |
| `attach_proposer_signature` 生产可达 | 生产调用点 `crates/node/src/validator.rs:271`；`#[cfg(test)]` 起于 `crates/node/src/block_builder.rs:249`（**非** `:187`）；测试调用点 ≥ 11 处（`:762/:809/:822/:824/:840/:848/:871/:877/:893/:916/:923/:937/:951/:971`） |
| （历史注记，**已过时**）`crates/node/src/block_safety.rs:78` | 模块 doc 仍写"未接入生产出块调用点…需另行 Owner 授权" ⇒ 与上述事实**矛盾**；该 source comment 的修正属**独立 follow-up**（改源码需单独授权），**不**得再作为"生产未接入"的证据 |

⇒ **A11 不负责签名生成**。Mode-2 的前置条件 = 准入授权 path 完成（见 §3）；
**在前置条件满足前，Mode-2 MUST NOT 被启用、MUST NOT 被声明为已达成。**

### PADR-3 — Guard A：Height Context Guard（MUST）

收到 `ConsensusProposal` 时：

```
(A0) height 语义（OD-B = B，**父高轮**）：
       block.header.height        = canonical next block height（被提案区块自身的高度）
       proposer selection height  = parent round height = block.header.height - 1
       ⇒ consensus.state().round.height == block.header.height - 1
(A1) 被引用区块 **MUST become locally available before proposal admission transition**
       —— 判定口径：`BlockStore.contains(block_hash)`（可选 `DAG.contains(block_hash)` 强化）；
       未满足时 **MUST NOT** immediate discard，而按 **PADR-5.2** 进入**有界 pending**（OD-15/OD-16）
(A2) consensus.state().round.height == block.header.height - 1
```

- **高度语义 MUST 冻结**：`select_proposer` 的 `height` 输入**不是**被提案区块高度，而是**父高轮**
  （= `consensus.state().round.height`）。该约定与既有实现一致：`build_proposal` 高度同步 gate
  `rs.height == head.height`；`block_dispatch` 的父高轮证据约定；QC 绑定 `qc.context.height + 1 == block.height`。
- 任一项不满足 ⇒ 按 PADR-6 处理（discard + 零状态变更 + **NO RESET**）。
- 作用：阻断跨高度 replay 与旧/未来高度提案（对齐 ADR-0049 §3.4.1 的 `Old-round` / `Future-round` ⇒ NO-OP）。

### PADR-4 — Guard C：Proposer Authentication Guard（MUST；PRECONDITION = PADR-2）

```
height_now = block.header.height - 1                      // OD-B = B（父高轮）
round_now  = resolve_proposer_round_evidence(             // OD-C = B（严格绑定证据）
                 block_hash, proposal_evidence, qc_evidence)
               · Ok(r)   ⇒ 使用 r（r 可为 0）
               · Ok(0)   ⇒ 无可用证据 ⇒ 回退 round 0（**不猜、不放宽**）
               · Err(()) ⇒ 绑定证据矛盾 ⇒ **拒绝**（fail-closed）

expected = select_proposer(chain_id, height_now, round_now,
                           validator_set_id, active_set)          // ADR-0050
验证: 区块 proposer 签名 必须以 expected 的 consensus public key 验证通过
```

- **复用（MUST）**：`block_dispatch::resolve_expected_proposer_vk_at_round`
  （`crates/node/src/block_dispatch.rs:136`）已支持 `(height, round)` 入参 ⇒ A11 MUST 新增
  `(height_now, round_now)` 的调用点；**MUST NOT** 新造第二套 proposer 派生规则；
  **MUST NOT** 把 `assembly.rs` 作为主要准入位置。
- **延迟准入（PADR-5.2）时的 `round_now` MUST 重新解析**：仍为
  `round_now = resolve_proposer_round_evidence(block_hash, …)`；
  **MUST NOT** 改为直接读取 `consensus.state().round.round`（OD-17 明确禁止）。
- `round_now` 的语义与既有 block ingress round-aware 路径**逐字一致**（OD-C = B）。
- 不满足 ⇒ 按 PADR-6 处理（discard + 零状态变更 + **NO RESET**）。
- 在 A11 前置条件未满足时 **MUST NOT** 启用 Guard C；**MUST NOT** 以"零签名视为有效"作为替代。

### PADR-5 — 轮绑定：隐式绑定（MUST；**仅在 Guard C 可用时成立**）

- **不新增 wire round 字段**（保持 ADR-0041 FROZEN）。轮绑定通过
  `block proposer identity == select_proposer(height_now, round_now)` 达成，其中
  `height_now = block.header.height - 1`（OD-B）· `round_now` 由 `resolve_proposer_round_evidence`
  给出（OD-C）：`select_proposer` 是 `(height, round)` 的确定性函数 ⇒ 为其它轮构造的提案
  必然落到其它 expected ⇒ 被拒。
- **已知取舍（MUST 记录）**：绑定证据不可用（`Ok(0)`）时 Guard C 以 round 0 计算 expected ⇒
  可能**误拒**当前轮 `r > 0` 的合法提案（活性代价，与 RISK-3 同类），**或**在
  `proposer(h, 0) == proposer(h, r)` 时无法区分轮。该取舍由 OD-C 明确接受；Mode-2 测试 MUST 覆盖。
- **限制声明（MUST 记录）**：该绑定**完全依赖 Guard C**。在 Guard C 不可用期间
  **MUST NOT** 声称轮绑定已生效；`future-round` 提案在该期间**不会被拒**。

### PADR-5.1 — Pipeline Ordering Independence（MUST；OD-15 / OD-19）

```
Admission guard MUST NOT depend on changing consensus pipeline ordering.
```

- **MUST NOT** 把 block inbound 阶段提前到 inbound consensus commands 之前（OD-15 明确**拒绝**）。
- **MUST NOT** 修改 `step()` 的既有阶段顺序（commands → block inbound → 采纳检查点 → sync →
  round timeout → 提案 → 本地 consensus → finality fact → QC history → commit bridge → advance → egress）。
- 理由（GAP-5 / GAP-6）：调序会让区块登记所需的轮证据（来自已接受提案）缺失 ⇒ `Ok(0)` 回退 round 0
  ⇒ `put_verified` 签名复验失败 ⇒ `step()` 错误。
- ⇒ 正确解法是**准入侧的等待**（PADR-5.2），而非移动 pipeline 阶段。

### PADR-5.2 — Bounded Pending Admission（MUST；OD-15 / OD-16）

Guard A 的定义修订为：

```
referenced block MUST become locally available before proposal admission transition
```

机制（MUST 全部满足）：

1. **入待定（不丢弃、不 reset）**：收到 `ConsensusProposal` 且区块尚未本地可用（`BlockStore.contains == false`）
   ⇒ 将该 `ProposalRef` 放入**有界** pending 集合（`zero consensus state mutation`、**NO RESET**、**不计为 progress**）。
2. **有界容量（参数已冻结，OD-21）**：条目数 MUST 有硬上限 **`MAX_PENDING_PROPOSALS = 64`**；达上限 ⇒
   按**确定性**策略（FIFO 淘汰最旧）丢弃 + 计数。**MUST NOT 无限缓存**。
3. **超时淘汰（参数已冻结，OD-21）**：每条目 MUST 带有界生命周期 **`MAX_PENDING_TICKS = 2 rounds`**
   （**确定性 tick 计数**，非 wall clock）；到期 ⇒ 淘汰 + 计数 + **NO RESET**。
4. **重评与准入**：被引用区块变为本地可用（`BlockStore.contains`；可选 `DAG.contains` 强化）⇒ 重新执行
   Guard A（含 A2 当前上下文）与 Guard C；**仅当全部通过**才调用 `set_proposal`（此时才算 progress，允许 RESET）。
5. **上下文失效 ⇒ 丢弃（MUST）**：重评时若当前 `(height, round)` 已不同于条目记录的上下文，MUST **丢弃**
   该条目（MUST NOT 以旧上下文准入 ⇒ 防止迟到提案在新轮触发假 RESET）。
6. **幂等 / 去重**：同一 `block_hash` 的重复提案 MUST NOT 产生第二个条目。
7. **禁止**：重试发送 / 主动请求区块 / 修改 wire / 新增计时器语义 / 修改 round / 无限缓存 /
   跨 step 持有可变 consensus 状态。

**Q10 裁定（OD-20 = APPROVED(A)）**：pending 条目记录的 `(arrival_round, block_hash)` **MAY** 作为
**同类** proposal-bound 证据来源（与 `runtime.rs:198-207` 的 `proposal_round_evidence` 同类型、同绑定键（= `block_hash`），
仅记录时机提前至"提案到达"）；适用范围与禁令见 **PADR-5.3**。

### PADR-5.3 — Pending Evidence Rule（MUST；OD-20）

当被引用区块**变为本地可用**时，MUST 按以下**固定顺序**执行：

```
1. recover pending proposal-bound evidence
     —— 取回该 pending 条目的 (arrival_round, block_hash)
2. resolve proposer round evidence
     —— round_now = resolve_proposer_round_evidence(block_hash, pending_evidence, qc_evidence)
        （仍为 OD-17 的来源函数；MUST NOT 读 consensus.state().round.round）
3. execute Guard A / Guard C
     —— 含 A2 当前上下文校验（上下文不符 ⇒ 丢弃条目，MUST NOT 准入）
4. only successful admission may call set_proposal
     —— 仅第 3 步**全部通过**才调用 set_proposal（此时才算 progress，允许 RESET）
```

**约束（MUST；OD-20）**

- `arrival_round` **仅**绑定**本** pending 提案（绑定键 = `block_hash`；hash 不匹配 ⇒ 证据不可用，不得回退到其它来源凑合）。
- **MUST NOT** 变更 consensus round（不得写 / 推进 `RoundState.round`）。
- **MUST NOT** 替代 / 覆盖 finality evidence（不得写 `finalized_reference` / lock / QC）。
- **MUST NOT** 绕过 Guard A / Guard C（证据恢复**不**等于准入；第 3 步不可省略）。
- pending 自身：**MUST NOT** 计为 progress · **MUST NOT** 触发 RESET · **MUST NOT** 改变 round state。

### PADR-6 — Admission Failure Semantics（MUST；模式无关的不变量）

```
准入失败 ⇒ discard + 可选有界计数 + zero consensus state mutation + NO timer reset
```

**MUST NOT**：`set_proposal()` · step transition（`Propose→Prevote`）· `proposal_hash` 更新 ·
QC 更新 · lock 更新 · DAG 变更。

不变量（实现必须保持）：**准入失败路径不得产生任何会改变 `RoundObservation`
（`height` / `round` / `step` / `proposal_hash` / `finalized_reference`）的效果。**

⇒ 未通过准入 ⇒ 非 progress event ⇒ `progressed = false` ⇒ **NO RESET**（对齐 ADR-0049 §3.4 / §3.4.1）。

- **deferral ≠ progress（MUST）**：进入 / 停留 / 超时淘汰 pending 条目（PADR-5.2）**MUST NOT** 改变
  `RoundObservation`（`height` / `round` / `step` / `proposal_hash` / `finalized_reference`）⇒ **NO RESET**；
  只有**真正准入成功**（`set_proposal` 被调用）才构成 progress（对齐 ADR-0049 §3.4.1）。

### PADR-7 — 模式定义（MUST）

| Mode | Guard 集合 | 阻断 | 未闭环 | 安全完备性 | 状态 |
|---|---|---|---|---|---|
| **Mode-0**（当前状态） | 无（仅 `step == Propose`） | — | 跨高度 replay · same-height fake proposer · future-round | **NOT SECURITY COMPLETE** | 当前生效（临时） |
| **Mode-1**（Partial Admission） | 仅 Guard A | 跨高度 replay / 旧高度 / 未来高度 | **GAP-2 remains open**（same-height wrong-proposer 与 future-round 仍可触发假 RESET） | NOT SECURITY COMPLETE | **不采用**（OD-3 = B） |
| **Mode-2**（Full Admission） | Guard A + Guard C（+ PADR-5 隐式轮绑定） | GAP-1/2/3/4 全闭环 | — | 达到 ADR-0049 §3.4.1 `Valid current-round Proposal` 要求 | **目标状态**（A11 完成后启用） |

- **Mode-0 MUST 被标注为 NOT SECURITY COMPLETE**，直至 Mode-2 生效。
- Mode-1 **不采用**（理由：无法闭环 GAP-2；实施面与 Mode-2 主体重叠；存在"部分缓解被误读为已修复"的治理风险）。

### PADR-8 — Zero signature 处理（MUST / MUST NOT）

```
zero signature（[0u8;64]）:
  MUST NOT 视为有效身份
  MUST NOT 作为 proposer authorization
  MUST NOT fallback 到 ProposalRef.proposer
Mode-2 下零签名区块提案 ⇒ reject + NO RESET
```

### PADR-9 — ADR 边界（MUST）

| 对象 | 关系 |
|---|---|
| ADR-0041 | PR-1~PR-4 **保持 FROZEN**；本 ADR **MUST NOT** 修改 `ProposalRef` wire / canonical encoding；**不新增 height、不新增 round** |
| ADR-0049 | 本 ADR 只定义 **HOW**（validity）；**WHEN**（reset policy、timer / window / backoff / ARM / EXPIRE / DISARM）全部归 ADR-0049；**MUST NOT** 修改 |
| `finalized_reference ⇒ STOP/DISARM` 收紧 | **不纳入本 ADR**（独立 ADR / 独立阶段；OD-5 = A） |
| ADR-0066 / 0070–0075（O2 / RC 证书） | **不受影响、不得修改** |
| ADR-0050（proposer selection） | 复用其确定性选择函数，**不修改**算法或 quorum 语义 |

### PADR-10 — Non-Goals（MUST NOT）

**MUST NOT** 修改：consensus transition 语义 · quorum · QC · finality · `LockedState` · vote path ·
O2（RC 证书）· `ProposalRef` wire · envelope canonical encoding · timeout 参数 ·
ValidatorSet 语义 · 引入运营者输入 / 白名单 / 运行时开关。

---

## 3. A11 Dependency Boundary

```
A11 = proposal admission authorization integration（提案准入授权接线）
  是**独立阶段**：PHASE 6H-A11
  · 不属于 ADR-0076 的实现范围
  · 需**单独 PRECHECK**（设计审查）与**单独实现授权**

范围（A11 IS）:
  ① proposal admission guard（Guard A / Guard C）
  ② expected proposer binding（含 (height_now, round_now) 语义；OD-11/OD-12）
  ③ reject-before-consensus-transition（失败 ⇒ 零状态变更 ⇒ NO RESET）
  ④ rollback 方案
  ⑤ Mode-2 tests
  ⑥ bounded pending admission（PADR-5.2；区块缺失时的**有界**等待 + 超时淘汰）

非范围（A11 NOT）:
  · 不新建签名能力 / 不新增密码学（生产 proposer 签名路径**已存在**）
  · 不改 `block_hash` / 不改 wire / 不改 `ProposalRef` canonical encoding
```

- **ADR-0076 Mode-2 MUST NOT be enabled before: A11 admission authorization path complete.**
- 生产 proposer 签名路径**已存在**（`crates/node/src/runtime.rs:282-284` → `crates/node/src/validator.rs:267-271`
  → `crates/node/src/block_builder.rs:229`；生产强制经 B2-B journal：`runtime.rs:2152-2158/2167`；
  落盘 `put_verified` 复验：`runtime.rs:306`）⇒ A11 的工作**不是**"接入签名"，
  而是"把准入授权接到 runtime 入站提案路径"。
- **已核实（PASS，不再作为 A11 未决项）**：签名覆盖范围与 `block_hash` 的关系（ADR-0042：hash 不含签名）、
  malleability、重放边界（6H-A11-PRECHECK §4）。
- **仍需 A11 覆盖**：① Guard C 的 `(height_now, round_now)` 调用点（复用 `block_dispatch.rs:136`）；
  ② PADR-6 失败语义接线；③ rollback 方案；④ Mode-2 测试（§6）。
- 在 A11 未完成期间，Mode-0 继续生效，且 MUST 保持 `NOT SECURITY COMPLETE` 标注（见 §6 风险登记）。

---

## 4. Implementation Boundary

**主入口（MUST）**

```
runtime inbound consensus path
（crates/node/src/runtime.rs 处理入站 consensus command 处）
```

- 原因（已核实）：`pub struct ConsensusNode { state, context, chain_id, set, genesis_hash, dag, last_precommit_qc }`
  （`crates/node/src/assembly.rs:74-87`）**不持有 block store / adapter**；
  `Dag` 仅提供 `contains(&hash)`（`crates/consensus/src/dag.rs:65`）与 `len()`（`:115`），**无按 hash 的高度查询**
  ⇒ Guard A 无法在 `assembly.rs` 内完成。

**允许**

- runtime admission check（Guard A / Guard C 判定 + 有界计数）
- block store lookup（按 `block_hash` 取区块）
- bounded pending proposal set（PADR-5.2 / PADR-5.3：`MAX_PENDING_PROPOSALS = 64`、`MAX_PENDING_TICKS = 2 rounds`；
  确定性 tick 淘汰；零共识状态变更）
- `crates/node/src/block_dispatch.rs` **仅作复用来源**（expected proposer resolution + 签名验证）
- `crates/node/src/assembly.rs`：**只接收 admission result**，并调用**既有** consensus transition
- 可选：只读计数 / 观测接线（`runtime.rs` / `wiring.rs` / bin status）

**禁止**

- 把 `assembly.rs` 作为主要准入位置
- 修改 consensus transition / `round.rs` / QC / finality / lock / DAG / O2 / wire / envelope encoding / 参数

---

## 5. Compatibility & Security

**不影响**：quorum · QC formation · finality proof · lock rule · vote path · O2 / RC 证书 ·
round 单调性 · timeout 参数 · ValidatorSet 语义。

**可能影响**：① 提案接受时机（Mode-2 需本地持有对应区块）；
② expected proposer 绑定依赖 `(height_now, round_now)` 语义（PADR-3/PADR-4；OD-B/OD-C）。

**显式风险声明（MUST）**

| 风险 | 状态 |
|---|---|
| **RISK-1**：Mode-0 生效期间，越界 / 伪造 proposer 提案仍可能触发假 RESET（anti-liveness） | **已接受（临时）**，跟踪至 Mode-2 生效 |
| **RISK-2**：Mode-2 依赖 A11；签名相关安全面（validator key 对区块签名、签名不入 `block_hash`、malleability / 重放边界） | **PASS**（6H-A11-PRECHECK §3/§4）；**剩余风险 = Mode-0 admission guard missing** |
| **RISK-3**：OD-7 = discard ⇒ 若"提案先到、区块后到"，节点放弃该提案，代价上界 = **一个轮次窗口**（由 ADR-0049 backoff 保证最终覆盖） | 已接受；**MUST NOT** 因此新增重试/保留责任 |
| **RISK-4**：OD-6 = 一次性升级 ⇒ **不允许 Mode 混用**（同网络内节点必须同 Mode） | 升级原子性要求 |
| **RISK-5（R-A）**：proposal / block arrival ordering —— 同批到达时区块在同一 step 内**晚于**提案被处理（`driver.rs:266-272`；`runtime.rs:3267` vs `:3298`） | **由 PADR-5.2 有界 pending 承接**；参数与 T7 验收见 §6；**MUST NOT** 通过改动 pipeline 顺序规避（PADR-5.1） |
| **RISK-6（R-B）**：proposal evidence 与 block registration 的依赖关系（区块登记需要"提案已被接受"的轮证据，`runtime.rs:198-207` ⇒ `:1355-1358`） | **CLOSED（OD-20 + PADR-5.3）**：pending arrival evidence 作同类 proposal-bound 来源；**不**绕过 Guard A/C，**不**改 round / finality |

**安全论证（健全性）**：授权锚点为"内容寻址区块 + validator 签名"，而非发送者声明；
被拒路径不产生任何状态变化 ⇒ 不构成 progress ⇒ 不触发 RESET；
本 ADR 不引入新的 safety 面（不产生 vote / QC / finality / lock 变更）。

---

## 6. Test Design

**Mode-2（准入验收；MUST）**

| 用例 | 期望 |
|---|---|
| valid signed proposer block（期望 proposer + 有效签名 + 高度一致） | **accept** · `set_proposal` 生效 · `Propose→Prevote` · reset 允许 |
| wrong proposer signature | **reject** · NO RESET |
| **zero signature block**（`[0u8;64]`） | **reject** · NO RESET（PADR-8） |
| future-round proposal（expected proposer = `select_proposer(height_now, r+1)`） | **reject** · NO RESET |
| replay proposal（重复投递） | 无额外 progress · NO RESET |
| **height 语义回归**（误用 `select_proposer(block.header.height)` 而非 `height_now = block.header.height - 1`） | 用例 MUST 锁定 `height_now = block.header.height - 1`（OD-B）；字面高度用法必须失败 |
| **round evidence 缺失**（`resolve_proposer_round_evidence` ⇒ `Ok(0)`） | 按 OD-C 使用 round 0；MUST NOT 猜测其它轮 |
| **round evidence 矛盾**（⇒ `Err(())`） | **reject** · NO RESET（fail-closed；MUST NOT 静默择一） |
| **T7**（OD-19 新增）proposal 与 `GossipBlock` **同批**到达（按 `driver.rs:266-272` 顺序） | 按 PADR-5.2：入 pending → 区块到齐后在同一 step 内重评并准入（或按超时淘汰）；**MUST NOT** 出现"永久丢弃 ⇒ 本轮永久无提案" |
| **T8**（OD-19 新增）任一 reject / pending / 超时淘汰路径 | `RoundObservation{height,round,step,proposal_hash,finalized_reference}` 逐字段**不变** ⇒ **NO RESET** |
| **T9**（OD-20 新增）pending proposal → 区块到达 → 证据恢复 → Guard 通过 → `set_proposal` | 完整路径成功；**验证 `set_proposal` 之前** `RoundObservation` **逐字段不变**（含证据恢复 / Guard 执行两个中间态） |
| **360s regression**（同 `t7_3` 参数、`A30_WINDOW_E1=360`、5/7） | 无人工计时器重启（不出现 `893→9` 形态）· 无准入引起的轮次分裂 · eventual finality（head ≥ 5） |

**360s regression 仅作为 Mode-2 的验收项**（在 A11 完成前不可执行）。

**回归对照（两模式共用）**：`d10_p1_a6_*`（pacemaker 语义不变）· assembly 提案单测 ·
`d10_p1_a30` `t7_0`/`t7_1` · O2 两条真实 TCP e2e。

**Mode-1 相关**：因 OD-3 = B（不采用），**不设计** Mode-1 验收；`same-height wrong proposer`
在 Mode-1 下无法被证明为安全，故仅作为**已知缺口记录**。

---

## 7. Open Questions

| # | 问题 | 状态 |
|---|---|---|
| Q1 | A11（proposal admission authorization integration）是否**单独授权**？ | OD-2 = A（已授权为独立阶段） |
| Q2 | Mode-1 是否允许短期上线？ | OD-3 = B（**不采用**） |
| Q3 | A11 完成后是否**立即启用 Mode-2**？ | OD-4 = A（含验收门槛，见 §8） |
| Q4 | `finalized_reference ⇒ STOP/DISARM` 是否独立 ADR？ | OD-5 = A（独立，**不纳入本 ADR**） |
| Q5 | Mode 切换策略（升级方式）？ | OD-6 = A（一次性协议升级；不新增运行时开关） |
| Q6 | 区块缺失策略？ | OD-7 = A（立即 discard；保持不 reset / 不改 `RoundObservation` / 不无限缓存） |
| **Q7** | Guard A(A2) / Guard C 的 `height_now` 语义？ | **RESOLVED — OD-B = B**：`height_now = block.header.height - 1`（父高轮；= PADR-3 A0/A2 与 PADR-4） |
| **Q8** | Guard C 的 `round_now` 来源？ | **RESOLVED — OD-C = B**：`resolve_proposer_round_evidence`（与既有 block_dispatch round-aware 路径一致；`Ok(0)`=无证据⇒回退 0，`Err(())`=矛盾⇒拒绝） |
| Q9 | Mode-2 启用后的观测面（拒收计数如何暴露到 status/诊断）？ | **OPEN**（待 Mode-2 实现 PRECHECK 决定） |
| **Q10** | pending 条目记录的 `(arrival_round, block_hash)` 是否可作为**同类** proposal-bound 证据来源（供区块校验 / 登记使用）？ | **RESOLVED — OD-20 = A（APPROVED）**：MAY 作为同类 proposal-bound 证据来源；约束见 **PADR-5.3** |
| **Q11** | `MAX_PENDING_PROPOSALS` 与 pending 生命周期的具体取值？ | **RESOLVED — OD-21（APPROVED）**：**`MAX_PENDING_PROPOSALS = 64`** · **`MAX_PENDING_TICKS = 2 rounds`**（确定性 tick；非 wall clock） |

---

## 8. Owner Decision Record（6H-OWNER-DECISION-FINAL · 6H-ADR-0076-CORRECTION-APPLY · 6H-A11-DESIGN-CORRECTION · 6H-A11-OWNER-DECISION-APPLY-V1.4）

| OD | 决定 | 要点 |
|---|---|---|
| OD-1 | **A** | 批准 ADR-0076 V1.1 作为定稿基础；确认 ADR-0041 PR-1~PR-4 FROZEN、不改 wire、不改 consensus transition、不改 QC/finality/O2 |
| OD-2 | **A** | 单独授权 A11 为**独立阶段**（PHASE 6H-A11），**不属于** ADR-0076 实现；需单独 PRECHECK |
| OD-3 | **B** | **不采用 Mode-1**；保持 Mode-0 并标注 NOT SECURITY COMPLETE；接受并跟踪 RISK-1 |
| OD-4 | **A** | A11 完成后**立即启用 Mode-2**；门槛 = A11 PRECHECK 验收 ∧ Mode-2 验收用例 ∧ 360s 回归通过 |
| OD-5 | **A** | `finalized_reference ⇒ STOP/DISARM` 为**独立 ADR / 独立阶段**，不纳入本 ADR |
| OD-6 | **A** | **一次性协议升级**切换；不允许 Mode 混用；不新增运行时开关 |
| OD-7 | **A**（**部分被 OD-15 取代**） | 区块缺失**不再** immediate discard ⇒ 改按 PADR-5.2 进入**有界** pending（有界容量 + 超时淘汰）；仍始终不 reset / 不改 `RoundObservation` / **不无限缓存** |
| OD-8 | **A** | 授权创建本 ADR 文件（`docs/adr/ADR-0076-proposal-admission-rule-v1.md`） |
| OD-9 | **B** | **暂不进入 IMPLEMENT**；待 ADR 落盘后重新 PRECHECK（五项条件见下） |
| OD-10 | **A** | 批准 C-1..C-8 **纯文本**修正（PHASE 6H-ADR-0076-CORRECTION-APPLY；仅 `docs/adr/ADR-0076-proposal-admission-rule-v1.md`，无源码/测试/其他 docs 改动） |
| OD-11 | **B** | Guard `height_now` = `block.header.height - 1`（**父高轮**语义；见 PADR-3 A0/A2、PADR-4） |
| OD-12 | **B** | Guard `round_now` = `resolve_proposer_round_evidence`（与既有 block_dispatch round-aware 路径一致） |
| OD-13 | **A** | 先裁定 Q1/Q2（即 OD-11/OD-12）后**一次性**落盘 ADR |
| OD-14 | **A** | 授权执行 ADR-0076 文档修正（不进入 IMPLEMENT） |
| OD-15 | **D-1** | **拒绝**调整 runtime step 阶段顺序（MUST NOT 把 block inbound 提前到 commands 之前）；**批准** bounded pending proposal 设计方向（PADR-5.2） |
| OD-16 | **D-2** | Guard A 定义修订：`referenced block MUST become locally available before proposal admission transition`；要求 `BlockStore.contains` + DAG availability + 有界等待 + 超时淘汰；**禁止无限缓存** |
| OD-17 | **D-3** | round 语义**保持**：`height_now = block.header.height - 1` · `round_now = resolve_proposer_round_evidence()`；**禁止**改为 `consensus.state().round.round` |
| OD-18 | **D-4** | 批准 `resolve_expected_proposer_vk_at_round` 于后续 IMPLEMENT 调整为 `pub(crate)`（仅 crate 内可见） |
| OD-19 | **D-5** | Mode-2 测试矩阵新增 **T7**（proposal + gossip block 同批到达）与 **T8**（reject 后 consensus observation 不变）；新增风险 **R-A / R-B**；新增设计原则 "Admission guard 不得依赖改变 consensus pipeline 顺序"（PADR-5.1） |
| OD-20 | **Q10 = APPROVED(A)** | pending proposal 到达证据 **MAY** 用作 proposal-bound 证据来源（PADR-5.3）；约束：`arrival_round` 仅绑定本 pending 提案 · **MUST NOT** 变更 consensus round · **MUST NOT** 替代 finality evidence · **MUST NOT** 绕过 Guard A/C |
| OD-21 | **Q11 = APPROVED** | 冻结 pending 参数：**`MAX_PENDING_PROPOSALS = 64`** · **`MAX_PENDING_TICKS = 2 rounds`**（确定性 tick；非 wall clock；MUST 有界） |

**OD-9 前置条件核对（IMPLEMENT 门槛）**

```
[✓] ADR-0076 定稿                 —— 本阶段完成
[✓] A11 准入授权方案确定            —— 6H-A11-PRECHECK + OD-11（height_now）/ OD-12（round_now）
[✓] Mode 策略确定                  —— OD-3/OD-4/OD-6/OD-7
[✓] runtime inbound boundary 确认  —— 本 ADR §4
[✗] PRECHECK 通过                  —— Mode-2 实现 PRECHECK 尚未启动
⇒ 1 项未满足 ⇒ IMPLEMENT 继续冻结
```

---

## 9. Consequences

- **正面**：ADR-0049 §3.4.1 的 NO-OP 类别在提案路径上**首次可执行**（Mode-2）；
  消除"越界/伪造提案重启他人计时器"的 anti-liveness 向量；补齐 ADR-0041 PR-4 预留的 authority 层规则。
- **成本**：准入需本地持有对应区块 ⇒ 提案接受时机可能后移（RISK-3）；
  需要新增拒收计数与分模式测试；Mode-2 依赖 A11 前置。
- **治理收益**：协议规则先冻结、再实现；A11 与准入实现相互独立、各自可审计。

---

## 10. Evidence Index（审计锚点）

| 主题 | 位置 |
|---|---|
| ADR-0049 §3.4 / §3.4.1（RESET 规则与事件矩阵） | `docs/adr/ADR-0049-liveness-pacemaker-v1.md:82-128` |
| ADR-0049 §6 LIV-8 | `docs/adr/ADR-0049-liveness-pacemaker-v1.md:245-259` |
| ADR-0041 PR-1（64B 定长）/ PR-4（authority 不在 serialization 层） | `docs/adr/ADR-0041-proposalref-canonical-serialization.md:20-30, 41-45, 81-88` |
| 提案准入现状（仅 `step == Propose`） | `crates/consensus/src/round.rs:128-136`；`crates/consensus/src/integration.rs:336-350` |
| 节点入站提案路径 | `crates/node/src/assembly.rs:371-374` |
| RESET 判据（状态差分） | `crates/node/src/runtime.rs:786`（`observed != entry`）；`:470-475`（Reset 分支）；`:502-512`（快照字段） |
| envelope 签名主体（NetworkSigner） | `crates/node/src/egress.rs:5-12, 29, 96-107` |
| vote 的内层 validator 签名（对照） | `crates/node/src/assembly.rs:401`；`crates/consensus/src/vote.rs:107` |
| 区块 proposer 签名（**生产已附加**） | `crates/node/src/runtime.rs:282-284`（签名）· `:306`（`put_verified` 复验）· `:2152-2158` / `:2167`（B2-B journal 装配）；`crates/node/src/validator.rs:267-271`；`crates/node/src/block_builder.rs:199`（seam 留零签名）/ `:229` / `:249`（`cfg(test)`）；`crates/core/src/block.rs:121-130`；`crates/node/src/block_adapter.rs:295` |
| 期望 proposer 绑定 + 轮证据（Guard C 复用来源） | `crates/node/src/block_dispatch.rs:105-118`（`resolve_proposer_round_evidence`）· `:136`（`resolve_expected_proposer_vk_at_round`，父高轮）· `:167`（round 0 兼容入口）· `:231` / `:293`（round-aware dispatch） |
| runtime 入站区块路径已使用 round-aware 入口 | `crates/node/src/runtime.rs:62`（import）· `:3355` · `:3382`（调用） |
| 实测证据（假 RESET ⇒ 轮次分裂） | PHASE 6H-AQ（240s）与 6H-AQ FOLLOW-UP（360s）报告；`timer_elapsed 893→9` |
| proposal/block egress 顺序（R-A 证据） | `crates/node/src/driver.rs:266-272`（`record_local_proposal`：`Proposal(ref)` → `GossipBlock(wire)`） |
| `step()` 阶段顺序（R-A / R-B 证据） | `crates/node/src/runtime.rs:3258`（`round_entry`）· `:3267`（`take_commands`）· `:3281`（`process_inbound_consensus_command`）· `:3298`（`take_block_inbound`）· `:3419`（`CanonicalNextCandidate` ⇒ 登记）· `:3444`（`?` 上抛） |
| 区块登记所需的轮证据（R-B 证据） | `crates/node/src/runtime.rs:198-207`（`proposal_round_evidence` 读 `state.round.proposal`）· `:1355-1358`（登记侧消费）· `:1386`（`put_verified` 复验） |
| A11 接入点（Guard A/C 前置位置） | `crates/node/src/runtime.rs:3267` / `:3281`（`set_proposal` 之前、pacemaker `:3532` 之前） |
| ADR-0076 V1.3 设计修订依据 | PHASE 6H-A11-PRECHECK（R-A/R-B 阻塞发现）· PHASE 6H-A11-DESIGN-CORRECTION（OD-15..OD-19） |

---

## 11. 变更记录

| 版本 | 变更 |
|---|---|
| V1.0（PHASE 6H-APD） | 初稿：PADR-1..PADR-9，档 1 / 档 2 定义，block-anchored admission（默认假设签名可用） |
| V1.1（PHASE 6H-ADR-REVISE-PRECHECK） | 依 6H-OWNER-REVIEW 的 CHANGES REQUIRED：① Guard C 前置条件化（A11）；② 新增 zero-signature 规则（PADR-8）；③ 档位改为 Mode-0/1/2 并加 NOT SECURITY COMPLETE / GAP-2 remains open 标注；④ 隐式轮绑定的成立条件显式化（PADR-5）；⑤ 实现边界更正为 runtime inbound path；⑥ 风险声明显式化；⑦ 测试按 Mode 分类（360s = Mode-2 验收） |
| **定稿（PHASE 6H-ADR-FINALIZE）** | 依 OD-1..OD-9 落盘：Mode-1 标注"**不采用**"；新增 §3 A11 Dependency Boundary 与 §8 Owner Decision Record；Status = Proposed / Approved for implementation planning |
| **V1.2（PHASE 6H-ADR-0076-CORRECTION-APPLY）** | 依 OD-10..OD-14 应用 C-1..C-8 **纯文本**修正：① 删除"生产 proposer 签名未接入"错误前提（PADR-2 / §3 / §10），改为"生产签名路径已存在；A11 = proposal admission authorization integration"；② PADR-2 状态表更正（`build_block` 零签名=设计 seam；`runtime_propose` 已附加签名；`validator.rs:271` 为生产调用点；`cfg(test)` 起点 `:249`）；③ §3 重写 A11 范围（IS/NOT 两栏）；④ 依 **OD-11** 冻结 `height_now = block.header.height - 1`（PADR-3 A0/A2、PADR-4、PADR-5）；⑤ 依 **OD-12** 冻结 `round_now = resolve_proposer_round_evidence`（含 `Ok(0)` 回退与 `Err(())` fail-closed）；⑥ RISK-2 更正（签名安全面 PASS；剩余风险 = Mode-0 admission guard missing）；⑦ §7 新增 Q7/Q8（RESOLVED）并将原 Q7 重编号为 Q9；⑧ §10 Evidence Index 更正并补充 runtime/validator/block_dispatch 行；⑨ §8 新增 OD-10..OD-14；§8 门槛核对由 2 项未满足降为 1 项。**仅修改本文件**；未改源码/测试/wire/O2/配置/其他 docs |
| **V1.3（PHASE 6H-A11-DESIGN-CORRECTION）** | 依 OD-15..OD-19 修订 A11 设计边界：① 新增 **PADR-5.1 Pipeline Ordering Independence**（Admission guard MUST NOT 依赖改变 consensus pipeline 顺序；**拒绝**将 block inbound 提前）；② 新增 **PADR-5.2 Bounded Pending Admission**（Guard A 定义修订为 "referenced block MUST become locally available before proposal admission transition"；`BlockStore.contains` + DAG availability + 有界容量 `MAX_PENDING_PROPOSALS` + 超时淘汰 + 上下文失效即丢弃 + 幂等去重 + 禁止无限缓存）；③ PADR-3 (A1) 改写；PADR-4 新增"延迟准入 MUST 重新解析 `round_now`，MUST NOT 读 `state().round.round`"；PADR-6 新增"**deferral ≠ progress**"；④ §1 GAP 表新增 **GAP-5 / GAP-6**；⑤ §5 新增 **RISK-5（R-A）** / **RISK-6（R-B）**；⑥ §6 Mode-2 矩阵新增 **T7 / T8**；⑦ §7 新增 **Q10**（OWNER DECISION REQUIRED，R-B 未闭合）/ **Q11**；⑧ §8 新增 **OD-15..OD-19** 并标注 **OD-7 部分被 OD-15 取代**；⑨ §10 新增顺序与证据锚点。**仅修改本文件**；未改源码/测试/wire/O2/配置/其他 docs |
| **V1.4（PHASE 6H-A11-OWNER-DECISION-APPLY-V1.4）** | 依 **OD-20**（Q10 = APPROVED(A)）与 **OD-21**（Q11 = APPROVED）：① 新增 **PADR-5.3 Pending Evidence Rule**（区块本地可用后的**固定 4 步**：recover pending proposal-bound evidence → resolve proposer round evidence → execute Guard A/C → only successful admission may call `set_proposal`；约束：`arrival_round` 仅绑定本 pending 提案 / 不变更 consensus round / 不替代 finality evidence / 不绕过 Guard A/C / pending 不计 progress·不触发 RESET·不改 round state）；② PADR-5.2 第 2/3 条冻结参数 **`MAX_PENDING_PROPOSALS = 64`** · **`MAX_PENDING_TICKS = 2 rounds`**；③ PADR-5.2 末尾"已知设计缺口"段落改为 Q10 裁定（OD-20）指向 PADR-5.3；④ §4 允许项新增 bounded pending proposal set；⑤ §5 **RISK-6（R-B）→ CLOSED（OD-20 + PADR-5.3）**；⑥ §6 Mode-2 矩阵新增 **T9**（pending → 区块到达 → 证据恢复 → Guard 通过 → `set_proposal`；验证 `set_proposal` 之前 `RoundObservation` 逐字段不变）；⑦ §7 **Q10 / Q11 → RESOLVED**；⑧ §8 新增 **OD-20 / OD-21**；⑨ Metadata 与本节更新。**仅修改本文件**；未改源码/测试/wire/O2/配置/其他 docs |
