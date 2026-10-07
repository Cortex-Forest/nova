# ADR-0077: Round-Advance Liveness Boundary & Evidence Record V1

## Metadata

| 字段 | 值 |
|---|---|
| ID | **ADR-0077** |
| Title | Round-Advance Liveness Boundary & Evidence Record V1 |
| Type | **Record / Evidence Record**（**非规范性 / Non-Normative**） |
| Status | **Accepted-as-Record** · **Not Implemented** |
| Mode-2 | **Mode-2 remains disabled** |
| 对既有规范的影响 | **Does not modify ADR-0076**；亦不修改 ADR-0041 / ADR-0049 / ADR-0050 / ADR-0066 / ADR-0070 / ADR-0072 |
| Owner Decisions | **D1 = ACCEPT** · **D2 = ACCEPT** · **D3 = ACCEPT** · **D4 = HOLD** · **D5 = HOLD**（见 §9） |
| 相关 ADR | ADR-0041（wire FROZEN）· ADR-0049（round timeout / pacemaker 语义）· ADR-0050（proposer selection V1 FROZEN）· ADR-0066 / ADR-0070 / ADR-0072（RC 证书与权威）· **ADR-0076（proposal admission rule）** |
| 证据基线 | 工作树 HEAD `fb06d617126c067bbfc82f2cc0b97809a1a7992f`（实测 + 只读审查；日志留存于 OS 临时目录，不入库） |
| 冻结值引用 | ADR-0076 SHA256 `914CA8C12E437430A7F9C6532E78E9FF8CADC4822B79BC05874457BBED92C4D2`（**创建本 ADR 时未变更**） |

---

## 0. Status & Non-Normative Statement（MUST READ）

1. 本 ADR 为 **Record / Evidence Record**：**不引入任何新的协议保证**（no new liveness guarantee），不产生新的 MUST/MUST NOT 规范条款。
2. **Accepted-as-Record**：本 ADR 仅记录"已观测到的 round-advance liveness 边界 + 证据 + 待决问题"，作为后续裁定的引用基线。
3. **Not Implemented**：本 ADR 不要求、也不授权任何实现改动；其全部内容的实现状态为"未实现"。
4. **Mode-2 remains disabled**：Mode-2 维持禁用，直至新的 liveness 判据由 Owner 单独裁定建立（见 §5 OD-X5）。
5. **Does not modify ADR-0076**：本 ADR 不修改 ADR-0076 的任何文本；对 **D1 裁定**（ADR-0076 §6 T7 适用范围收窄）的引用仅为**解释性前提**，用于消除阅读歧义（见 §4.4 / §7）。
6. 本 ADR 不修改 ADR-0041（wire FROZEN）、ADR-0049（round timeout 语义）、ADR-0050（proposer selection）、ADR-0066 / ADR-0070 / ADR-0072（RC）。

### 0.1 Background（为何需要本 Record）

Nova 的 **safety / admission / wire** 面已冻结（ADR-0041 / ADR-0049 / ADR-0050 / ADR-0066 / ADR-0070 / ADR-0072 / ADR-0076），但 **round advancement 缺少明确的 liveness 期望**。A30 阶段以真实多进程（真 loopback TCP + 真验证者进程）实测到：在

> **加权确定性 proposer 选择（无轮转保证） + offline proposer + 指数退避 + 提案单发不重传**

四者组合下，网络可以在有限窗口内**不推进最终性**。Owner 已就该结果作出 **D3 = ACCEPT** 的定性：**protocol liveness boundary discovery，非实现回归**。本 Record 即为该发现的证据与边界固化，并列出后续需要 Owner 裁定的问题。

调查链（只读报告，均在同一冻结 HEAD 上完成）：
`PHASE 6H-A11-U5`（`get_content` 修复，a10 PASS）→ `A30-A1`（t7_3 FAIL）→ `X1`（t7_1 PASS）→ `X5`（a12 `p1a18_t8` FAIL）→ `V1`（t7_2 FAIL）→ `Y3 / Y3-b`（RC 权威与 vote/QC 只读审查）→ `W1 / W1-b / W2 / W2-b`（proposer 口径、投递链、ADR-0076 对照）。

---

## 1. Scope

本 ADR 仅覆盖以下内容（**描述性与记录性**）：

1. **proposer availability 的风险描述**：`select_proposer` 为确定性加权哈希、**无轮转保证**，同一高度不同 round 可重复命中同一验证者；当命中的验证者离线时，该 round 可能**不存在任何 proposer**。
2. **round transition 的计时参数记录**（只记录现值，不修改）：`initial_timeout = 1000`、`max_timeout = 60_000`、`backoff_factor = 2`（tick 基）。
3. **tick / wall-clock 映射风险记录**：计时以 tick 计，墙钟厚度随负载漂移（实测 implied tick rate 约 3.5–6.7 ticks/s）⇒ 单轮墙钟上限可达约 2.5–3.3 小时。
4. **liveness 期望的判定口径（记录性）**：作为"需要定义什么"的清单，而非定义值本身。
5. **停滞形态分类学**（观测得到的三种形态，见 §4.4）。
6. **Observability 缺口记录**：判定 liveness 所必需但目前不可得（CLI 不可见）的观测项。
7. **测试验收判据的候选清单**（候选，**不批准、不设阈值**）。
8. **待决问题（OD-X1..OD-X10）** 与 **后续 Amendment 拆分路径**。

---

## 2. Non-Scope

以下内容**明确不属于**本 ADR（保持 out-of-scope；任何改动均需独立 ADR / Amendment 与单独授权）：

1. **wire format**：`ProposalRef` 结构、是否新增 round 字段、envelope / codec / 消息类型分配（归 ADR-0041 FROZEN 与 ADR-0073/0074/0075 系列）。
2. **proposal admission rule**：Guard A / Guard C、bounded pending、pending arrival evidence（**归 ADR-0076**）。
3. **safety 面**：quorum、QC 形成、finality 判定、lock、checkpoint（不改）。
4. **O2 / RoundChangeCertificate 语义与权威**（归 ADR-0066 / ADR-0070 / ADR-0072）。
5. **任何参数取值变更**：`initial_timeout` / `max_timeout` / `backoff_factor` / 各测试窗口常量。
6. **Mode-2 状态变更**（D5 = HOLD）。
7. **任何实现改动**（源码 / 测试 / 配置 / 运行时行为）。

---

## 3. Evidence

> 全部证据来自同一冻结 HEAD 的**真实多进程实测**与**只读代码/ADR 审查**；日志留存于 OS 临时目录（`%TEMP%\nova_u6v1_t72.log` 等），**不入库**。

### 3.1 A30 V1 —— `t7_2_six_of_seven_finality`（6/7 在线，V6 离线）

| 项 | 值 |
|---|---|
| 命令 | `cargo test -p nova-node --test d10_p1_a30_seven_validator_devnet t7_2_six_of_seven_finality -- --nocapture --test-threads=1`（默认窗口） |
| 结果 | **FAIL**；`finished in 3000.16s`（跑满窗口）；断言位置 `d10_p1_a30_seven_validator_devnet.rs:1141` |
| quorum | 933_334；6/7 在线权重 = 1_200_000（票冗余 = 1） |
| 5/6 节点末态 | **head=7 / finalized=7 / consensus=7 / round=3**；`qc_served` 介于 1528–2032 |
| 停滞形态 | **`round_step=Propose` + `proposal_present=false`**；计时窗口 **8000 ticks**（elapsed 3177 / 4564） |
| 末态分裂 | **V2（当选 proposer）· V3 · V5 = `Prevote` + `proposal_present=true`**；**V0 · V4 = `Propose` + `proposal_present=false`** |
| 异常节点 | V1：`steps=4200`（同伴 11200–13700 的约 1/3）、`head=4`、`round=0`、`qc_served=0`、`pending_external_qc=4→3`、`rc_authority=1`（全场唯一非零） |
| Tracer 指标 | `samples=100`、`divergence_samples=15`、`max_distinct_rounds_same_height=2`、`max_stall_secs=1470.6`、`height_advance_events=7`、`timeouts_by_round=[6,5,5,0,…]` |
| 计时观测 | round0 窗口 150.1–180.1 s（1000 ticks，`implied_tick_rate=6.25/s`）；round1 窗口 510.2–630.3 s（2000 ticks） |

**关键事实**：网络**并非**"计票失败"——5/6 节点完成了 round 0→1→2 的推进并达到 head=7（`qc_served` > 1500），停滞发生在 **round=3 且无提案可投** 的状态；且提案只在 6 个节点中的 3 个上出现（`proposal_present=true`）。

### 3.2 W1-b —— `select_proposer` 与 Tracer `prop@` 口径一致性（只读）

| 项 | 结论 |
|---|---|
| 同源性 | Tracer `prop@(h,r)` 与生产路径 `select_proposer(chain_id, h, r, genesis_hash, validator_set)` **同一函数、同一实参**（生产：`crates/consensus/src/proposer.rs:78`；Tracer：`crates/node/tests/d10_p1_a30_seven_validator_devnet.rs:734`，实参取自被采样节点的 `consensus_height` / `round`，`:822-830`） |
| height 语义 | 二者均为 **consensus / parent height**（`consensus_height = round.height`）；不存在 `height+1` 或 round offset |
| 实测映射（h=7） | `prop@(7,0)=V6(OFF)`、`prop@(7,1)=V2`、`prop@(7,2)=V6(OFF)`、`prop@(7,3)=V2` |
| 算法性质 | `x = LE_u128(H(seed)[0..16]) mod total_weight`，取首个累计权重 > x 的验证者（`proposer.rs:90-115`），验证者按 `ValidatorId` ascending 排序 ⇒ **加权哈希、无轮转保证** |

**关键事实**：同一高度上**不同 round 可重复命中同一验证者**（V6 命中 0 与 2）；当该验证者离线时，**这两轮不存在任何 proposer**。

### 3.3 W2 —— proposal 投递面（只读）

| 环节 | 结论 | 引用 |
|---|---|---|
| 出站 | 每次产提案仅登记一次；**单发**、**无 retry**、**无 ack**；`broadcast` 在"无 Established / 队列满"时**静默丢弃** | `crates/node/src/runtime.rs:4525`、`:4598-4604` |
| 中继 | **远端到达的 proposal 不重播** | `crates/node/src/outbound.rs:47-48` |
| 入站 | 解码后入 `commands` 队列（无上限）；准入判定在 guard 前置 | `crates/node/src/wiring.rs:118/167/280-285`、`runtime.rs:1765-1780` |
| 拒绝 | Guard A2 / Guard C 失败 ⇒ **Rejected 且丢弃**（无 pending、无重放） | `runtime.rs:1518-1534`、`:1555+`、`:1777-1780` |
| 区块缺失 | ⇒ 入有界 pending；恢复**仅在区块登记成功之后**触发 | `runtime.rs:1494-1512`、`:1636-1700` |

### 3.4 W2-b —— ADR-0076 对照（只读）

| 项 | 结论 |
|---|---|
| proposal 是否携带 round | **不携带**（`ProposalRef = {block_hash, proposer}` 64B）—— 符合 **ADR-0076 PADR-5:161**（"不新增 wire round 字段"） |
| admission 是否允许跨轮 | **不允许** —— 符合 **PADR-5:165-166**（"为其它轮构造的提案必然落到其它 expected ⇒ 被拒"） |
| rejected 后是否恢复 | **不恢复** —— 符合 **PADR-6**、**PADR-5.2 ⑦**、**RISK-3:374** |
| ADR 明文承认的取舍 | ADR-0076 **PADR-5「已知取舍」:167-169** 明确记录：证据不可用（`Ok(0)`）时可能**误拒** `r > 0` 的合法提案（活性代价） |
| D1 裁定 | ADR-0076 §6 **T7:399** 的适用范围收窄为 **same-round pending ordering**；跨轮拒绝属 PADR-5 既定行为 |
| 残留缺口 | **RISK-3:374** 所依赖的 "eventual coverage（代价上界 = 一个轮次窗口，由 backoff 保证最终覆盖）" 假设，在 §3.2 的"非轮转 selector"证据下**未被分析、需重新审视**（= D2） |

### 3.5 参数记录（现值，**不修改**）

| 参数 | 值 | 位置 |
|---|---|---|
| `initial_timeout` | **1000** ticks | `crates/consensus/src/round.rs:230-241`（`RoundTimeoutConfig` Default） |
| `max_timeout` | **60_000** ticks | 同上 |
| `backoff_factor` | **2** | 同上 |
| 窗口公式 | `timeout_for(r) = min(initial × backoff^r, max_timeout)` ⇒ r0..r6 = 1000 / 2000 / 4000 / 8000 / 16000 / 32000 / **60000（cap）** | `round.rs:247-251` |
| 墙钟含义（实测） | implied tick rate ≈ 3.5–6.7 ticks/s ⇒ cap 60_000 ticks ≈ **2.5–3.3 小时/轮** | §3.1 Tracer |

### 3.6 其它同批证据（同一冻结 HEAD）

| 运行 | 拓扑 | 结果 |
|---|---|---|
| a10 `d10_p1_a10_three_validator_finality` | 3/3 在线，round 恒 0 | **PASS**（`heads=[3,3,3]`、`round_timeouts=[0,0,0]`） |
| X1 `t7_1_seven_of_seven_finality` | 7/7 在线，round 恒 0 | **PASS**（144.71 s，head 44–67，`max_stall_secs=0.0`） |
| A1 `t7_3_five_of_seven_finality`（`A30_WINDOW_E1=360`） | 5/7 在线 | **FAIL**（360.34 s，head 恒 2，round 1 停滞） |
| X5 `d10_p1_a12_binary_three_validator::p1a18_t8_…` | 3 验证者 / 2 在线 | **FAIL**（261.31 s，head 恒 23，round 1→2 无 QC） |

---

## 4. Known Boundary

### 4.1 Proposer availability（结构性）

- `select_proposer` 为**加权哈希**，**不保证**同一高度连续 round 命中不同验证者（实测 h=7 命中 V6 / V2 / V6 / V2）。
- 当选验证者离线时，该 round **不存在 proposer**：既不会产出提案，也不会有任何节点投出该轮的票；网络只能等待该轮计时器到期（并进入下一轮）。
- 由于退避 ×2（§3.5），**每次"命中离线者"的代价随轮次指数增长**；若离线者被反复命中，等待时间在实用意义上无上界。
- 该现象**独立于** admission / wire / safety：它发生在 proposer 生成之前。

### 4.2 tick / wall-clock 映射（环境相关）

- 计时为 **tick**（非墙钟）；实测 tick 墙钟厚度随进程数/负载漂移（3.5–6.7 ticks/s）。
- ⇒ **任何"固定墙钟保证"都不可由当前参数推导**；跨环境比较必须以 tick 为基准，并同时记录实测 tick rate。
- ⇒ 测试窗口若以墙钟设定，可能与退避窗口（tick 基）数量级错配（本阶段即出现此现象）。

### 4.3 停滞形态分类（观测得到）

| 形态 | 现场签名 | 已观测实例 |
|---|---|---|
| **S1 — 无 proposer 型** | `round_step=Propose` + `proposal_present=false`，计时器运行中，无提案可投 | V1（t7_2）V0/V4；A1 的 round-1 起点 |
| **S2 — 计票型** | `round_step=Prevote` + `proposal_present=true`，无 QC 形成 | A1（5/7）；X5（部分阶段） |
| **S3 — 单节点滞后型** | 个别节点 `steps` 显著偏低、`round` 落后、`qc_served=0`、持有未消耗的 `pending_external_qc` | V1（t7_2） |
| 对照（正常） | `round` 恒 0、head 持续增长、`round_timeouts=0` | a10、X1 |

### 4.4 Observability 缺口（判定性风险）

当前**真实进程 CLI status 行**不包含以下判定必需项（部分仅存在于 in-process A11 DIAG）：

| 缺口 | 现状 | 影响的判定 |
|---|---|---|
| proposal **rejected** 分因 | in-process DIAG（`rej[…]`）有，CLI 无 | S1 无法归因（"未到达 / 被拒 / pending 未恢复"不可区分） |
| proposal **dropped** 分因（解码 / 重复 / 队列） | 部分计数存在，CLI 无 | 投递面无法归因 |
| `build_proposal ⇒ Ok(None)` 分因（非当选 / 高度不同步 / 已提案） | 无计数 | 无法区分"我不是 proposer"与"我漏了提案" |
| **proposer unavailable**（本轮当选者离线且无提案） | 无 | S1 的核心成因不可观测 |
| round timeout 来源（本地 pacemaker vs RC 证书） | `round_timeouts` / `rc_*` 分开有，但**无因果标注** | S1/S2 边界模糊 |
| `rc_deferred`（G-1 暂存） | 存取器存在，CLI **未打印** | RC 路径不可观测 |

---

## 5. Open Decisions（待 Owner 裁定；本 ADR 不自行裁定）

| ID | 问题 | 本 Record 的建议分类 |
|---|---|---|
| **OD-X1** | 是否要求 **bounded proposer availability**（同高度连续 k 轮覆盖 ≥ m 个不同验证者）？ | **建议 A：接受现状、只记录风险**；B（要求）⇒ 触及 **ADR-0050 FROZEN**，需独立 Amendment，且会把 A30 类失败**重分类**为"违反新要求"（改变 D3 语义） |
| **OD-X2** | `max_timeout = 60_000` ticks 是否需要**墙钟约束**？ | **建议 A：保持冻结、只记录风险**；B ⇒ 需 **ADR-0049 Amendment**（且与 OD-X1 强耦合，宜在 X1 之后评估） |
| **OD-X3** | 是否允许 **RC 证书（ADR-0072）** 承担"跳过离线 proposer 轮"的活性手段？ | **建议：延期**。只读审查已显示 `rc_authority` **不在活性关键路径**（实测恒 0 或仅 1 次；`Stored` 条目结构性不可应用），可行性未知 |
| **OD-X4** | **eventual finality 的前提 A** 如何定义（validator online 条件 / offline 容忍 / network 假设 / tick 与墙钟假设）？ | **建议 B：本阶段只记录形式（schema）与实测区间，不固定取值**（定值属规范性，触发 D4 冲突） |
| **OD-X5** | **Mode-2 启用条件**如何重定义？（ADR-0076 OD-4 门槛含 360s regression，当前 **FAIL**） | **建议 A：保持禁用**；门槛替换须由 Owner 以独立裁定/未来 Amendment 生效（**不得**由本 Record 替换，**不得**修改 ADR-0076 文本） |
| **OD-X6** | proposal **单发无重传**是否继续冻结？ | **建议：维持冻结**（ADR-0076 `:208` / `:374` 已明令禁止新增重试）；本 Record 仅记账 |
| **OD-X7** | 是否先补齐 **observability**（§4.4）？ | **建议：作为"设计性前置"纳入**（本 Record 仅定义必要观测集）；**实现**属独立授权（D4 禁止） |
| **OD-X8** | §5.1 候选用例的取舍与阈值 | 见 §5.1 |
| **OD-X9** | 编号与标题确认 | 本文即 **ADR-0077 — Round-Advance Liveness Boundary & Evidence Record V1**（Record） |
| **OD-X10** | 正式创建授权流程 | 本文为**授权后创建**；后续任何 Amendment 各自单独授权 |

### 5.1 验收判据候选（**候选，不批准、不设阈值**）

| ID | 候选用例 | 目的 |
|---|---|---|
| C1 | offline proposer 场景（构造某高度 round-0 proposer 离线）⇒ 预算内必须推进 | 覆盖 S1 |
| C2 | repeated proposer 场景（同高度连续 round 命中同一离线者） | 覆盖 §4.1 |
| C3 | 可用性矩阵（7/7、6/7、5/7、4/7-no-finality） | 覆盖 quorum 边界与 slack |
| C4 | 最大 round-advance 延迟测量（`(height,round)` → 下一高度墙钟） | 量化前提 A |
| C5 | 同高度同轮"提案存在性"一致性（不得出现部分节点永久无提案） | 覆盖 V0/V4 形态 |
| C6 | 停滞可归因（超阈值停滞必须可由既有计数归因） | 依赖 OD-X7 |
| C7 | 窗口预算与 `RoundTimeoutConfig`（含 cap）可推导 | 防"窗口太短"型伪失败 |
| C8 | 回归对照（`t7_0`/`t7_1`、`d10_p1_a6_*`、O2 real-TCP e2e 不变） | 不改变 safety 语义 |
| C9 | N 验证者矩阵（N ∈ {3,5,7}，离线 1..2） | 跨拓扑一致性 |

---

## 6. Future Amendment Path

本 Record **不**授权任何改动；若 Owner 后续裁定需要规范性变更，建议拆分如下（**各自独立授权、独立 PRECHECK**）：

| 路径 | 目标 | 触及的冻结面 | 前置条件 |
|---|---|---|---|
| **A-0049** | `max_timeout` / 退避的墙钟约束 | ADR-0049（round timeout 语义/参数） | 先裁定 OD-X1（availability），再评估 cap |
| **A-0050** | proposer availability 保证（若选 B） | **ADR-0050 FROZEN**（算法/向量） | OD-X1 = B；并接受 D3 语义迁移 |
| **A-0076-OD4** | Mode-2 启用门槛（替换 360s regression） | ADR-0076 `:439`（OD-4） | OD-X4（前提 A）+ OD-X7（观测）；**以效力声明覆盖，不修改 0076 文本** |
| **A-OBS** | Observability 实现（§4.4 各项上 CLI） | 源码（node/CLI/DTO） | OD-X7 立项；解除 D4 |
| **A-RC** | RC 证书承担活性 skip（若需要） | ADR-0066 / 0070 / 0072 | OD-X3；需先证明 `rc_authority` 路径可达 |

**升级条件（建议）**：仅当 (a) 前提 A 已定值、(b) §4.4 观测缺口已闭合、(c) Owner 明确授权对应 Amendment 时，本 Record 才可被其后续 Amendment 引用为规范依据。

---

## 7. References（引用，不修改）

**ADR**
- ADR-0041 — wire FROZEN（`ProposalRef` 64B）
- ADR-0049 — round timeout / pacemaker 语义（本 Record 仅记录其参数现值）
- ADR-0050 — proposer selection V1 FROZEN
- ADR-0066 / ADR-0070 / ADR-0072 — RoundChangeCertificate / 序列化 / RC authority amendment
- **ADR-0076 — Proposal Admission Rule V1**（本 Record **不修改**；引用 PADR-5:161/165-169、PADR-5.2 ⑦、PADR-6、RISK-3:374、§6 T7:399、OD-4:439）

**代码（只读引用）**
- `crates/consensus/src/proposer.rs:78-115`（`select_proposer`）
- `crates/consensus/src/round.rs:230-251`（`RoundTimeoutConfig` / `timeout_for`）
- `crates/node/src/runtime.rs:711`（`runtime_propose`）、`:1478/1555`（Guard A/C）、`:4525`（proposal 出站登记）、`:4598-4604`（egress 单发）
- `crates/node/src/outbound.rs:47-48`（远端 proposal 不重播）
- `crates/node/src/wiring.rs:118/167/280-285`（入站 proposal 队列）
- `crates/node/tests/d10_p1_a30_seven_validator_devnet.rs:734/822-830/1141/1197`
- `crates/node/tests/d10_p1_a12_binary_three_validator.rs:1828/1983`

**证据日志（OS 临时目录，不入库）**
- `%TEMP%\nova_u6v1_t72.log`（t7_2）
- `%TEMP%\nova_u6a1_t73.log`（t7_3 / A30-A1）
- `%TEMP%\nova_u6x1_t71.log`（t7_1 / X1）
- `%TEMP%\nova_u6x5_p1a18t8.log`（a12 p1a18_t8 / X5）

---

## 8. Owner Decision Record（本 Record 的前置裁定，逐条引用）

| ID | 裁定 | 内容 |
|---|---|---|
| **D1** | **ACCEPT** | ADR-0076 §6 T7 **仅适用于 same-round pending ordering**；**跨轮 proposal 被拒属 PADR-5 既定行为** |
| **D2** | **ACCEPT** | ADR-0076 **RISK-3 的 eventual coverage 假设需要修订/重新审视**；新建覆盖 round-advance liveness 边界的 ADR（**即本文**） |
| **D3** | **ACCEPT** | A30 FAIL 定性为 **protocol liveness boundary discovery**，**非实现回归** |
| **D4** | **HOLD** | 不改代码、不改 ADR-0076、不改 wire |
| **D5** | **HOLD** | **Mode-2 保持禁用**，等待新的 liveness 判据建立 |

---

**Status recap**：**Accepted-as-Record** · **Not Implemented** · **Mode-2 remains disabled** · **Does not modify ADR-0076**。
本 ADR 不引入任何新的协议保证；任何规范性变更须经 §6 的独立 Amendment 路径与 Owner 单独授权。
