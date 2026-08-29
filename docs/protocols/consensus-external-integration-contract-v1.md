# Nova Chain — Consensus External Integration Contract V1（10-11）

- **Status**: **FROZEN**（STEP 10-11；Consensus External Integration Contract V1 FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 把**已冻结**的 Consensus 输入与跨层边界整理为**可验证的外部集成契约**（逻辑消息语义 + L1~L5 跨层边界 + 验证边界 + replay/duplicate/malformed 期望 + 确定性 + 依赖方向）。**只定义逻辑契约，不实现任何外部模块。**
- **依据**（全部 READ-ONLY）：ADR-0033 C-1~C-9 / 0034 V-1~V-6 / 0035 D-1~D-5 / 0036 W-1~W-6 / 0037 B-1~B-6 / 0038 F-1~F-18 / 0039 CP-1~CP-8 / 0040 FC-1~FC-14（FROZEN）+ `consensus-spec-v1.md`（FROZEN）§8/§13/§14 + STEP 10-9（FROZEN）MF-1~MF-12。
- **本文件是契约文档，不是代码实现**；不改动任何冻结文件、不改任何 Cargo 依赖。

---

## 0. 目的与边界

- **目的**：明确 Consensus 对外部的"接法"——逻辑消息语义、所有权、验证边界、确定性期望、依赖方向——使 Network / Storage / Execution / Node 未来能正确消费，且**不与冻结共识语义冲突**。
- **契约 ≠ 实现**：本文件只定义逻辑边界契约；transport / wire / gossip / persistence / node runtime / block spec 均属各自 Phase。
- **三态原则**（沿用 spec §0）：ENFORCED / ASSUMPTION / DEFERRED 严格区分。

---

## 1. L1 — Consensus ↔ Network（Logical Message Contract）

### 1.1 逻辑消息载体（Frozen Type → 1:1 Logical Wrapper）

| 逻辑消息 | 内容（冻结类型，**不新增字段语义**） | 验证边界（冻结） |
|---|---|---|
| `VoteMessage` | `ValidatorVote` + `signature: [u8;64]` | V-5（`verify_vote` 五步）；硬 precondition：调用方保证已验证（MF-2） |
| `ProposalMessage` | `ProposalRef{block_hash, proposer}` | 上下文/阶段守卫（B-4 / integration `SetProposal`） |
| `QcMessage` | `QuorumCertificate` | `verify_qc`（F-6a：结构/升序/duplicate/signature/quorum） |

- **1:1 逻辑包装**：不得新增协议字段语义、不得新增 canonicalization、不得定义 wire encoding、不得定义 message size limit。
- **N-4 硬约束**：逻辑消息沿用已有链上 DomainId（Vote → `DomainId::ValidatorVote`）；**不得因本契约新增 DomainId**。
- **Network owns**：transport / delivery / peer communication / wire framing / envelope / gossip / connection / retry / topology。
- **Consensus owns**：logical verification（V-5 / `verify_qc` / context+terminal guards）/ transition admission / finality semantics。
- **Network ≠ Consensus**：Network 不得进入 Consensus 内部状态；Consensus 不得依赖 Network crate。

### 1.2 RoundTimeout 定位（冻结事实，非本契约新定义）

> **`RoundTimeout` 是 Node-local event（B-3 / spec §8 / §5），由 Node 本地构造 `ConsensusEvent::RoundTimeout`，不是 Network Consensus Message。**

- 依据：ADR-0037 B-3（`RoundTimeoutConfig` 本地事件；禁直接 finalize；timeout 作为共识输入 = 禁例）；spec §8 L175（本地事件，非共识输入，B-3）。
- 本契约**不**把 RoundTimeout 设计成网络消息。

---

## 2. L2 — Consensus ↔ Proposal / Block（Logical Boundary）

- Consensus 只消费**已冻结**：`ProposalRef{block_hash, proposer}`（B-1/B-4）与 `BlockReference{block_hash, height, parents, proposer}`（D-1）。
- Consensus 需要从 Block 获取的语义：`block_hash`（引用）、`height`、`parents`（DAG relation）、`proposer`（ValidatorId）、`witness`（W-1~W-6，仅影响 confidence，B-4）。
- **完整 Block Spec = PHASE 7**：本契约**不定义** BlockHeader、block_hash 算法、receipt root、state root、block body、block production、block canonical encoding。
- Block 与 Consensus 的关系（C-3）：**DAG ≠ Finality**；Consensus 只对 block reference 做最终性判定，不判定 block 内容。

---

## 3. L3 — Consensus ↔ Execution（Logical Boundary）

- **Consensus 不执行 / 不拥有**：transaction execution、transaction validity、WASM、receipt generation、state transition、mempool。
- **Execution** 负责：block/transaction 语义执行（`apply_transaction` 7G / `execute_block` 8D，产出 `BlockExecutionResult`）。
- 执行结果与 Consensus **无数据流**（C-1）；执行层为独立上层消费者。
- 本契约只定义 ownership + input/output boundary + dependency direction；**不创造任何 Execution API**。

---

## 4. L4 — Consensus ↔ Storage（Semantic Boundary）

- **Consensus 提供**：
  - `ConsensusState{round, finality}` 的**语义**（canonical consensus state，MF-1）；
  - replay object semantics（ConsensusState 为 replay 比对对象；IntegrationContext 为 rebuildable derived cache，MF-12/H-3）；
  - deterministic transition semantics（MF-12）。
- **Storage 负责**（= Storage/Persistence Phase，Q1/Q4 裁决）：encoding、serialization、persistence、recovery、crash consistency、schema、migration、durability。
- **本契约绝对不定义**：`ConsensusState` canonical encoding、serialization format、schema、migration、snapshot format、crash recovery algorithm。
- **丢失 QcRegistry ≠ consensus-state corruption**（H-3）；恢复必须经 replay/rebuild 重建 deterministic context。

---

## 5. L5 — Consensus ↔ Node（Logical Lifecycle）

```
External Input
    ↓
Node constructs logical Consensus input（ValidatorVote+signature / ProposalRef / 本地 RoundTimeout）
    ↓
Consensus verification boundary（V-5 / verify_qc / context+terminal guards）
    ↓
transition（MF-12 三元组）
    ↓
TransitionResult（Applied{next_state, observation, derived} / Ignored / Rejected）
    ↓
Node routes result
```

- 定义：ownership（输入构造=Node；验证=Consensus）、invocation boundary、error/result boundary（TransitionResult 三态）、deterministic expectations。
- **不实现 Node runtime、不修改 Node orchestration、不新增 orchestration code。**

---

## 6. Verification Boundary

```
External Message → Network Delivery → Logical Consensus Message → Consensus Verification Boundary → transition
```

验证责任 = **冻结规则**（只读引用）：
- V-5（`verify_vote` 五步：membership → identity → signed_bytes → hash → verify_strict）。
- `verify_qc`（F-6a：target∈DAG → validator_set_id → evidence 升序 → duplicate → 逐条签名 → quorum）。
- context guards（10-5.1 修复 A：height/round 绑定）。
- terminal-state guards（10-5.1 修复 B：Finalized 后忽略）。
- round monotonicity（`checked_successor`，MF-5）。
- atomic transition（MF-7）。
- deterministic behavior（MF-12）。

**不新增**任何验证规则。

---

## 7. Replay / Duplicate / Malformed Contract

只映射**冻结语义**（不新增规则；若无法表达 ⇒ HARD STOP → Protocol Defect Candidate）：

| 场景 | 冻结语义 | 来源 |
|---|---|---|
| duplicate vote（同 validator 同 target） | VoteAccumulator 去重；不重复计权/不重复推进 | B-2 / T3 |
| replay（旧 height/round） | context guard ⇒ `Ignored{ContextMismatch}` | 10-5.1 修复 A / T2/T18 |
| malformed vote | `verify_vote` 拒绝（五步任一失败） | V-5 |
| malformed QC | `verify_qc` 拒绝（结构/升序/duplicate/signature/quorum） | F-6a |
| out-of-order | context guards（height/round 不符）⇒ Ignored | 10-5.1 / T2 |
| irrelevant input（非 proposal target） | `process_vote` 不推进 quorum | B-2 |
| already-finalized | terminal-state guard ⇒ `Ignored{Terminal}` | 10-5.1 修复 B / T5 |
| finality conflict | **Conflict ≠ protocol error**（valid-but-inapplicable，evidence 保留） | F-8/F-9 / T7 |
| duplicate delivery / permutation | 顺序无关；permutation invariant | MF-12 / T17/T21/T23 |

---

## 8. Determinism Contract

```
same logical input + same canonical state + same relevant context ⇒ same deterministic result
```

- 继承 MF-12（六条契约）。
- **禁止**把以下内容作为 Consensus deterministic input：peer identity、network arrival order、transport timing、retry timing、connection state、gossip order。
- 逻辑消息以**内容**（而非到达顺序/来源）参与 transition；`Ignored`/`Rejected` ⇒ state 与 context 均不变（MF-12 契约 3）。

---

## 9. Dependency Direction

```
Consensus → core / crypto        （C-1 单向）
Network / Storage / Execution / Node → Consensus   （上层消费者）
```

- **禁止**：`Consensus → Network`、`Consensus → Storage backend`、`Consensus → Node`、`Consensus → Execution implementation`。
- 本契约**不修改任何 Cargo dependency**。

---

## 10. Security Boundary（沿用 spec §13）

### ENFORCED（已冻结，状态机强制）
V-5 / `verify_qc` / context+terminal guards / round monotonicity（checked_successor）/ atomic transition / deterministic ordering（causal_order / maximal anchor）/ permutation invariance（T17）/ PrevoteQC-only registry（T21）/ finality-dominant fork choice（FC-12）。

### ASSUMPTION（依赖但未强制，如实标注）
honest validator 不双投（spec §3；GAP C，slashing 归 DEFERRED）；lock 规则（spec §1.4，GAP D）未在 `process_vote` 强制。

### DEFERRED（不伪装为已存在）
slashing、equivocation punishment、epoch、validator rotation、complete Block Spec（PHASE 7）、persistent ConsensusState encoding（Storage）、network transport（Network）、Node runtime（Node）、execution semantics / mempool / WASM（Execution）、P2P / gossip。

---

## 11. Traceability（契约 → 冻结来源）

| 契约项 | ADR / Spec | 实现 | 测试 |
|---|---|---|---|
| 逻辑消息 = 1:1 冻结类型 | spec §8 / V-4/V-5 / F-2 | vote.rs / finality.rs | vote::tests::* / finality::tests::* |
| Timeout = local event | ADR-0037 B-3 / spec §8 | integration.rs | integration::tests::t8/t14/t15 |
| Proposal/Block 消费 | D-1 / B-1/B-4 / W-1~W-6 | dag.rs / round.rs | dag::tests::* / round::tests::* |
| Execution 边界 | C-1 / ADR-0023/0029 | （执行层自有） | （执行层自有） |
| Storage 语义边界 | MF-1/MF-12 / H-3 | integration.rs | integration::tests::t4/t9/t23 |
| Node 生命周期 | MF-12 / spec §9（= State Model 三元组，Node 驱动核心） | integration.rs | integration::tests::* |
| Determinism | MF-12 | integration.rs | T9/T17/T23 |

> 本矩阵只引用**已存在**的实现与测试；不虚构。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Consensus External Integration Contract V1（L1~L5 逻辑边界 + 逻辑消息 1:1 包装 + 验证/确定性/依赖方向 + 安全三态 + traceability） | STEP 10-11 Design Proposal APPROVED（Repository Audit PASS；RoundTimeout=B-3 local；N-4/C-1/Storage/PHASE7 边界尊重；ADR-0041 NOT REQUIRED） |
| 2026-08-30 | **DESIGN FREEZE（10-11）**：Status Draft→FROZEN。Review APPROVED；Micro-Fix（§3 表述 / §11 注）PASS；协议语义 0 / 冻结契约 0 / scope 0；ADR-0041 NOT REQUIRED；external.rs 不创建 | 用户裁决 🟢 APPROVED → DESIGN FREEZE |
