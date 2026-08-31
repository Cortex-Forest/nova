# ADR-0044: Sustainable Economy Model V1

- **Status**: **DRAFT**（PHASE 2 STEP 6-A + STEP 6-A.1 — Reward Budget & Emission Architecture +
  Reward Funding Architecture Decision（Model A 已批准）；**非 FROZEN**——funding source / score / weight /
  decay / reward amount / epoch length / emission model 均未定义）
- **Deciders**: Nova Chain 架构组
- **Date**: 2026-08-31
- **Scope**: HOW CONTRIBUTION BECOMES ECONOMIC REWARD（ADR-0043 边界内）。STEP 6-A 设计
  **Reward Budget + Emission Architecture**；STEP 6-A.1 批准 **Independent Reward Budget（Model A）** 为
  **Funding Architecture（经济 accounting 架构；非代码实现）**。Score / Decay / Citation / Rate Limit /
  Min Artifact Size / 最终 Reward 公式留后续 STEP。

## Context

ADR-0043（FROZEN）冻结了 WHAT COUNTS AS CONTRIBUTION（Score 维度 / 边界 / 抗刷 / 衰减原则）。
ADR-0044 负责 HOW CONTRIBUTION BECOMES ECONOMIC REWARD。本 ADR 首先必须回答：
**"Contribution Reward 的 token 从哪里来？"** —— 即 Reward Budget 与 Emission Architecture。

核心约束（Frozen Economic Boundary）：
- `total_supply` = **不可变 cap**（不因 burn 递减；Genesis 承诺；ADR-0022/0016）。
- 持续不变量：`Σ liquid + Σ bonded + burned_supply ≤ total_supply`（ADR-0022）。
- `fee_burn_bps` 已冻结（burn = actual_fee × bps/10000）。
- validator reward / treasury **尚无 ADR**（归 Economics/PoS Phase，ADR-0022 声明可迁移）。
- ADR-0033 C-1：consensus 纯计算；reward 状态变化归 Execution + Economic Module。
- ADR-0042（Block FROZEN）：不得新增 Block 字段（含 Contribution Root）——若需 ⇒ 新 ADR。

## Frozen Dependencies

| ADR | 冻结内容 | 本 ADR 关系 |
|---|---|---|
| ADR-0043 | Contribution Object/Proof/Verification/Score 维度/抗刷/衰减原则；DomainId::Contribution=0x07 | 输入：Eligibility 前提（已验证/Finalized） |
| ADR-0005 | DomainId 0x07 | 引用（不修改） |
| ADR-0021 | 交易 nonce 语义 | 不触碰（contribution_sequence 独立） |
| ADR-0022 | fee_burn_bps / total_supply cap / burned_supply 累计 | **边界**：reward 不得违反 cap；非 burn fee 归属 UNDEFINED |
| ADR-0033 | C-1 consensus 纯计算 | reward 状态变化归 Execution+Economic Module |
| ADR-0036 | Witness（0x06）复用 | 引用 |
| ADR-0042 | Block Format FROZEN | 不新增 Block 字段 |

## Scope

**本 STEP 6-A 设计**：
- Reward Budget（按 epoch 的确定性预算 + ceiling）
- Funding Sources（token 从哪来）
- Emission Models（候选，NOT FROZEN）
- Budget Constraints（total_supply cap / fee-derived 边界）
- Economic Invariants（EBI-1~EBI-10+）
- Budget Attack Analysis

**不设计（后续 STEP）**：Score Formula / Decay Formula / Citation Formula / Rate Limit /
Minimum Artifact Size / 最终 Reward Formula。

## Economic Architecture（预留接口）

```
Contribution Score        ← ADR-0044 后续 STEP（维度 ADR-0043 已冻结）
        ↓
Eligibility               ← 前提 = 已验证/Finalized（ADR-0043）；阈值 = 后续 STEP
        ↓
Reward Weight             ← 后续 STEP（Score → Weight 映射，非恒等）
        ↓
Epoch Reward Pool         ← 本 STEP：Reward Budget（确定性 epoch budget + ceiling）
        ↓
Reward Allocation         ← 后续 STEP（Weight / ΣWeight × Epoch Pool 或等价，须满足 EBI-1/2）
```

本 STEP 只冻结 **Epoch Reward Pool（Budget）层** 及其约束；与 Score/Weight/Allocation 的接口
以上下箭头预留，不实现公式。

## Approved Architecture: Independent Reward Budget（STEP 6-A.1 已批准）

**正式状态：APPROVED ARCHITECTURE（项目所有者 2026-08-31 授权）**

Contribution Reward 使用 **Independent Reward Budget**：

```
Contribution
      │
      ▼
Independent Reward Budget
      │
      ├── Contributor Rewards
      │
      └── Accounting / Audit Boundary
```

**Independent Reward Budget 是经济 accounting architecture**。它**不是**：
- Genesis reward pool
- Treasury
- Validator reward pool
- Burn pool
- automatically funded mint bucket
- already-funded token reserve

**必须明确：Independent Budget ≠ Existing Funds**。当前 **funding source 尚未定义**。

```
Reward Budget Architecture = APPROVED
Reward Budget Funding       = NOT YET DEFINED
Reward Amount               = NOT YET DEFINED
```

## Enforced Constraints（STEP 6-A.1 已批准；FOUR ENFORCED NOs）

**NO-1 — Cap-Breaking Issuance（FORBIDDEN）**

```
Reward issuance MUST NOT increase supply beyond total_supply.
```

- 任何突破当前 `total_supply` cap 的发行 ⇒ **FORBIDDEN**。
- 未来若需 inflation / additional issuance ⇒ **必须建立独立经济 ADR**，不得通过本 ADR 偷渡。

**NO-2 — Burned Fee Reuse（FORBIDDEN）**

```
burned_supply MUST NOT be reused as contributor reward funding.
```

```
burned_supply ──✗──► Reward Budget
```

- Burn 是不可逆的 supply destruction；不得因 reward budget 不足而重新利用 burned supply（EBI-4）。

**NO-3 — Non-Burn Fee Ownership（UNDEFINED）**

```
non_burn_fee ownership = UNDEFINED
```

- 本 ADR 不得定义 `non_burn_fee → Contributor Reward` / `→ Treasury` / `→ Validator`。
- 归属留给未来 Economic ADR（FUTURE）。

**NO-4 — Genesis Unissued Bucket（DOES NOT EXIST IN V0.1）**

```
Genesis unissued reward bucket = DOES NOT EXIST IN V0.1
```

- 本 ADR 不得：添加 unissued balance / 假设 Genesis reserve / 从 Genesis 余额凭空创建 reward reserve /
  修改 Genesis allocation semantics。
- 未来重新设计 Genesis allocation ⇒ **必须通过独立 ADR 修订 ADR-0016**。

## Reward Budget

- Reward Budget 按 **epoch** 计算（epoch 为抽象经济周期，**epoch_id ≠ block height**；epoch duration 未冻结，除非现有 ADR 已定义——当前无）。
- 每个 epoch 的预算必须：**deterministic**（可重现）且具备 **budget ceiling**（上限）。
- 预算由 **Funding Source** 与 **Emission Schedule** 两个独立维度共同决定（见下）。

## Funding Sources（Funding Source ≠ Emission Schedule；两维度独立）

| F | Funding Source | 是否需要 mint | 消耗未分配 supply | 影响 total_supply | 与 fee burn 冲突 | 需改 ADR-0022 | 需未来 ADR | 通胀风险 | 耗竭风险 | 攻击面 |
|---|---|---|---|---|---|---|---|---|---|---|
| F-A | Genesis / preallocated **unissued** supply | 否（消耗已有未分配） | 是 | 否（在 cap 内） | 否 | 否 | 需 ADR-0016 明确未分配去向 | 低 | 受未分配量限制 | 未分配滥用 |
| F-B | **New issuance** | 是（mint） | 否 | **是（增加 liquid）** | 否 | **否（不改 0022）** | **是：超 cap ⇒ INCOMPATIBLE；cap 内 ⇒ 需明确 cap 语义** | 中-高 | 若无限发行 | emission 操纵 |
| F-C | **Fee-derived**（非 burn 部分） | 否 | 否 | 否 | **部分：burn 部分不可用；非 burn 部分归属 UNDEFINED** | 否 | **是：非 burn 归属 FUTURE ECONOMIC ADR** | 低 | 依赖网络活动 | fee/活动操纵 |
| F-D | **Treasury** | 否 | 是（消耗 treasury） | 否 | 否 | 否 | **是：treasury 需 ADR 明确（ADR-0016）** | 低 | 受 treasury 限制 | treasury 捕获 |
| F-E | Hybrid | 视组成 | 视组成 | 视组成 | 视组成 | 视组成 | 视组成 | 视组成 | 视组成 | 视组成 |

**关键约束**：
- **F-B（new issuance）**：必须满足 `Σliquid+Σbonded+burned ≤ total_supply`。若 mint 突破 cap ⇒
  **INCOMPATIBLE WITH CURRENT FROZEN ECONOMIC BOUNDARY**（禁改 ADR-0022；需新 ADR 修订 cap 语义）。
- **F-C（fee-derived）**：burn 部分被销毁（EBI-4：不得重新当作可分配 supply）；**非 burn 部分现有协议归属
  UNDEFINED**——不得自行创建资金流；其归属 = FUTURE ECONOMIC ADR。
- **F-D（treasury）**：ADR-0016 要求未分配/treasury 去向必须明确；treasury 定义 = FUTURE ADR。

### Funding Source Matrix（Status；STEP 6-A.1 已批准）

| Funding Source | Status |
|---|---|
| Genesis unissued allocation | **FORBIDDEN / DOES NOT EXIST**（ADR-0016 §3：V0.1 全量分配） |
| New issuance beyond cap | **FORBIDDEN**（NO-1；cap 不可变） |
| Burned fee | **FORBIDDEN**（NO-2；EBI-4 不可逆销毁） |
| Non-burn fee | **UNDEFINED / FUTURE**（NO-3；归属留未来 Economic ADR） |
| Treasury | **FUTURE / UNDEFINED**（无 balance/owner/inflow/spending/accounting 定义） |
| Validator budget | **SEPARATE / FUTURE**（validator economics 独立，未来 ADR） |
| Hybrid | **FUTURE / requires explicit ADR**（各组成未就绪，不因"灵活"自动接受） |

> **FUTURE ≠ 允许本 ADR 自行实现**。仅表示未来可能通过独立经济设计定义。
> **当前协议没有可立即用于 Contributor Reward 的合法 funding source。**

## Emission Models（候选；NOT FROZEN，仅 RECOMMENDED CANDIDATE）

| E | Emission Schedule | 特性 |
|---|---|---|
| E-A | **Fixed** | 每 epoch 固定 budget；确定性高；可预测；不随活动变化 |
| E-B | **Declining** | budget 随时间下降；早期激励；长期收敛；早期 reward 波动 |
| E-C | **Activity-Adaptive** | 按协议定义活动调整；需防"刷活动膨胀 emission"（EBI-7） |
| E-D | **Supply-aware / Bounded** | 受剩余可分配量约束；与 total_supply cap 对齐 |
| E-E | **Hybrid** | 固定基础 + 有界调整 |

> **本 STEP 不选择最终模型**。以上均为候选，须经项目所有者裁决（OD）。
> 组合规则：任意 Funding Source × Emission Schedule 均须满足 §Budget Constraints 与 §Economic Invariants。

## Adaptive Emission（BOUNDED CANDIDATE；NOT FROZEN）

- **Adaptive Emission = BOUNDED CANDIDATE**（STEP 6-A.1 确认；本 ADR 不冻结公式或参数）。
- 未来若采用 adaptive emission，**至少必须满足**：
  ```
  bounded + deterministic + L1-only + oracle-free + subjective-metric-free
  ```
- **必须防止正反馈环**：
  ```
  more activity → larger reward pool → larger incentive → more spam/activity → larger reward pool
  ```
- `adaptive emission formula / upper bound / lower bound / activity metric` = **全部 OPEN**。

## Economic Epoch（STEP 6-A.1 确认）

- **只冻结**：Economic Epoch 是 **Reward Accounting 所需的机制边界**。
- **暂不冻结**：epoch length / block count / block-height mapping / finality mapping / exact snapshot point。
- **特别禁止**：`EconomicEpochLength = epoch_length_blocks`（除非未来正式 ADR 明确建立该映射）。
- `ProtocolParamsV1.epoch_length_blocks`（ADR-0014）当前**不能被自动解释为 contribution economic epoch length**。

## Validator / Treasury Separation（STEP 6-A.1 冻结）

```
Contributor Reward ≠ Validator Reward ≠ Treasury
```

- Contribution Reward 不得自动：占用 validator budget / 占用 treasury / 与 validator reward 竞争未定义池 /
  假设 treasury 是 reward source。
- Validator economics = **FUTURE**；Treasury economics = **FUTURE**。

## Supply Accounting Framework（STEP 6-A.1 冻结）

必须保持：

```
liquid_supply + bonded_supply + burned_supply ≤ total_supply
```

定义：

```
available_supply = total_supply − liquid_supply − bonded_supply − burned_supply
```

**但不得把 `available_supply` 自动定义为 Contributor Reward Budget**：

```
available_supply ≠ automatically spendable reward budget
```

- Reward Budget 必须拥有正式 funding semantics。
- 当前：`RewardBudget = not quantitatively funded` ⇒ `RewardBudget_quantification = BLOCKED`。

## Accounting Identity（STEP 6-A.1 冻结框架）

```
ContributorReward_e
    ≤
EpochRewardBudget_e
    ≤
LegallyFundedRewardBudget_e
    ≤
total_supply
```

- `LegallyFundedRewardBudget_e` 的 **funding semantics 当前仍 OPEN**——**不填写数值**。
- 当前事实下无合法 funding source ⇒ `AvailableEconomicSupply_for_new_reward = 0`
  （如实记录，不伪造正数 reward budget）。

## Score Architecture（STEP 6-B 已批准；Layer 1 Architecture）

### Decision A — Score Architecture = W2 + W4 + W5（OWNER 已批准）

```
Score = deterministic + L1-verifiable + integer/fixed-point
Score architecture direction:
  Σ weighted normalized components
    → bounded by global MaxScore
    → subject to per-identity diminishing returns
```

- **仅冻结 Layer 1 Architecture**。`weights / normalization coefficients / MaxScore 数值 /
  diminishing-return curve / 任何具体经济参数` = **不冻结（OPEN）**。
- W1（Fixed Weighted）/ W3（Multiplicative）已评估但**未采用**（记录）。

### Decision B — Model R1（Score-to-Budget Decoupling；OWNER 已批准；强制经济架构约束）

```
Score → Distribution
NOT
Score → Budget Expansion
```

1. Score 不创造 supply。
2. Score 不扩大 Independent Reward Budget。
3. 活跃度增加不得自动产生更大的 reward pool。
4. Score 仅决定已存在 reward budget 内的 distribution。
5. 不得形成：
   ```
   more activity → more score → larger reward pool → more incentive → more spam → larger reward pool
   ```
6. 与 **EBI-7** 对齐（EBI-7 = PASS under Model R1）。

### Decision C — Score → Weight → Reward Pipeline（OWNER 已批准；Layer 1 pipeline）

```
Contribution
    ↓
Eligibility
    ↓
Canonical Score
    ↓
Bounded Normalization
    ↓
Weight
    ↓
Epoch Total Weight
    ↓
Reward Share
    ↓
Independent Reward Budget
```

- **Score ≠ Reward；Weight ≠ Reward**；`Score → Weight`；`Weight → Distribution`。
- **Architectural Equation / Non-Final Formula**（非冻结公式；不冻结 budget 数值；不定义 funding source；
  不定义 rounding 数值；不定义 zero-total-weight 的最终经济处理；不得伪造 reward amount）：
  ```
  reward_i = epoch_reward_budget_e × weight_i / Σ(weight_j)
  ```

### Decision D — Deterministic Math（OWNER 已批准；consensus-critical 强制架构）

```
integer / fixed-point + checked arithmetic + canonical rounding
```

- **禁止**：floating-point consensus calculation / wall clock / locale-dependent / platform-dependent /
  unordered map iteration / randomness / oracle / subjective metric。
- **架构要求**：
  ```
  overflow         → checked arithmetic
  underflow        → checked arithmetic
  division by zero → explicit handling
  rounding         → canonical deterministic rule
  ordering         → canonical ordering
  serialization    → canonical serialization
  empty input      → explicit handling
  duplicate input  → explicit handling
  invalid input    → explicit handling
  large input      → bounded / checked handling
  ```
- **不冻结**：整数位宽 / scale / rounding mode / MaxScore（本 STEP 只冻结架构要求）。

### Decision E — Decay（OWNER 已批准；D2 / D4 后续候选机制）

- **D2（Epoch Decay）/ D4（Rolling Window）= 后续候选机制**；**不得直接冻结为最终机制**。
- decay 只影响未来 Score / Weight；**不修改历史 contribution record / certificate**；
  **不改变 ADR-0043 已冻结事实**。
- `coefficient / interval / window length / floor` = **OPEN**。

### Decision F — Anti-Concentration（OWNER 已批准；architectural boundary）

```
Anti-Concentration ≠ Reward Budget
```

- 架构层可包含：per-identity cap / per-domain cap / per-epoch cap / reward-share cap / global MaxScore /
  diminishing returns。
- **所有 numeric limits = OPEN**（不填伪精确数字）。

### Decision G — 全部经济参数保持 OPEN（OWNER 已批准确认）

```
weights / MaxScore / normalization parameters / decay coefficient / decay interval /
rolling window length / concentration limits / per-identity limits / per-domain limits /
per-epoch limits / reward-share cap / rate limits / citation parameters / economic epoch length /
economic epoch mapping / late-finalization rule / emission bounds / funding source / reward amount
```
= **全部 OPEN**。禁止填写无经济模拟和正式裁决依据的数字（如 0.1 / 0.2 / 10% / 20% / 100 / 1000 / 1e6 等）。

### Score Components（引用 ADR-0043 已冻结的可验证维度）

- **Protocol-verifiable dimensions**（可进入 consensus-critical reward formula）：uniqueness（artifact_hash 唯一）/
  verification / witness 确认 / protocol-verifiable impact（引用、协议级使用、存储/计算占用）/
  historical reliability / contribution sequence / resource cost（Gas/大小）——均来自 ADR-0043 §9.2 可协议化集合。
- **Subjective / oracle-dependent dimensions**（**不得**进入当前 consensus-critical reward formula）：
  human rating / editor rating / AI subjective quality / social popularity / market popularity / external
  engagement / off-chain reputation / artist prestige / community sentiment。
  - 需要 oracle / off-chain reputation / human judgment / subjective quality / centralized curator /
    external popularity score 的因素 ⇒ **FUTURE / SEPARATE ADR**。

### Score Architecture Boundary（STEP 6-B 强制）

```
Contribution → Eligibility → Score → Weight → Distribution
```

**不得**是：

```
Contribution → Score → Mint / expand budget
```

> **Score is a distribution signal, not a monetary issuance mechanism.**

### Cross-Epoch Boundary（STEP 6-B 架构原则）

```
contribution_id is unique
finalized contribution is immutable
same contribution cannot receive duplicate reward allocation
```

- `created in epoch e / finalized in epoch e+1` 的最终经济归属规则：**不得自行冻结** ⇒
  `late-finalization rule = OPEN`。
- Economic Epoch 长度 / mapping = **OPEN**（禁止假设 `economic_epoch_length == epoch_length_blocks`）。

## Decay / Concentration / Sybil-Resistance Architecture（STEP 6-C 已批准；Layer 1 Architecture）

### Decay Architecture（STEP 6-C）

**D2 — Epoch Decay（CANDIDATE）**

- 架构含义：旧 contribution 的 score/weight 可随 economic epoch，通过确定性衰减机制影响未来 distribution。
- 必须明确：
  ```
  deterministic replay = REQUIRED
  historical Contribution record = IMMUTABLE
  Contribution certificate = IMMUTABLE
  decay only affects evaluation/distribution layer
  decay does not rewrite historical records
  decay does not alter certificates
  ```
- 保持 OPEN：`decay coefficient / decay interval / decay timing / floor value /
  late-finalization interaction / epoch mapping`。

**D4 — Rolling Window（CANDIDATE）**

- 架构含义：仅统计最近若干 economic epochs 的贡献评估状态。
- 必须记录：
  ```
  deterministic replay = REQUIRED
  bounded evaluation window = candidate
  historical Contribution record = IMMUTABLE
  window exclusion ≠ deletion of historical record
  ```
- 残余风险：`window edge discontinuity / long-term contributor fairness / late-finalization interaction`。
- 保持 OPEN：`window length / window boundary semantics / late-finalization handling / floor semantics`。

**D2 / D4 最终边界**：
```
D2 and D4 remain CANDIDATE mechanisms.
Neither is frozen as the final decay mechanism.
No decay parameter is frozen in this step.
```

### Concentration Control Architecture（STEP 6-C）

- ADR-0044 建立 anti-concentration architecture，**独立于 Reward Budget 本身**。
- 候选控制层：`per-identity cap / per-domain cap / per-epoch cap / per-contribution cap /
  reward-share cap / global MaxScore`——这些是 architecture / candidate mechanisms；**数值全部 OPEN**。
- 特别强调：
  ```
  Concentration control does NOT create funding.
  Concentration control does NOT expand Reward Budget.
  Concentration control only constrains score/weight/distribution.
  ```

### Cap Ordering（STEP 6-C）

- cap ordering is **consensus-critical**（transformation order 可影响 deterministic output）。
- `canonical ordering = REQUIRED ARCHITECTURAL PROPERTY`。
- **具体 cap ordering = OPEN**：不得擅自冻结 normalize-before-cap / cap-before-normalize /
  identity-aggregation-before-diminishing / diminishing-before-cap / reward-share-cap-before-or-after-another-cap
  ——除非现有 ADR 已明确规定（本 STEP 不存在此类最终冻结）。

### Sybil-Resistance Architecture（STEP 6-C）

以下为 **Layer-1-verifiable architecture**（**DESIGN DEFENSE**；非 IMPLEMENTED / PROVEN / GUARANTEED）：
```
identity-level diminishing returns
contribution-level diminishing returns
per-identity concentration control
per-domain concentration control
per-epoch concentration control
verification cost
contribution uniqueness
canonical aggregation
```

### Sybil / Spam Boundary（STEP 6-C）

**L1-verifiable**：`artifact uniqueness / contribution_id / contribution_sequence / verification cost /
epoch aggregation / domain aggregation / canonical state`。

**NOT consensus-critical / FUTURE**：`reputation / social graph / human judgment / AI judgment /
oracle / off-chain trust`。

> 主观判断、社会关系图谱、oracle 或 off-chain trust **不得成为当前 consensus-critical reward dependency**。

### Candidate Canonical Transformation Pipeline（STEP 6-C）

**CANDIDATE CANONICAL TRANSFORMATION ORDER**（非 Frozen final formula）：
```
Contribution
↓ Eligibility
↓ Canonical Components
↓ Normalization
↓ Weighted Score
↓ Global MaxScore
↓ Identity Aggregation
↓ Diminishing Return
↓ Weight
↓ Concentration Control
↓ Epoch Total Weight
↓ Reward Share
↓ Independent Reward Budget
```

- 主拓扑 `Eligibility → Score → Weight → Reward` 已由 **STEP 6-B 批准**。
- 仍 **OPEN**：exact cap order / exact aggregation order / exact diminishing order /
  exact normalization-cap interaction / exact rounding placement。

### Cross-Epoch Architecture（STEP 6-C）

```
Contribution records remain immutable.
Economic evaluation may be epoch-derived.
Decay affects future distribution/evaluation only.
```

- `created=e, finalized=e+1` 与 `created=e, finalized=e+n`：**不得冻结最终 reward epoch** ⇒ `OPEN`。
- `late-finalization rule = OPEN` · `reversal rule = OPEN` · `already-paid reward handling = OPEN` ·
  `decay start epoch = OPEN`——不得自行发明任何规则。

### Zero-Weight / Empty Epoch Boundary（STEP 6-C）

- `Σweight = 0` 的具体经济处理 = **OPEN**。
- 不得自行定义：`remainder → Treasury / Validators / next epoch / Burn / any other pool`
  （除非现有 Frozen ADR 明确规定）。
- `empty epoch = OPEN` · `all contributions rejected = budget consumption 0` ·
  `remainder destination = OPEN`。

### Cap Remainder Boundary（STEP 6-C）

- cap 可能产生 distribution remainder。
- `remainder handling = OPEN`。
- 绝对禁止 inventing：Treasury destination / Validator destination / burn destination / rollover destination。

### Deterministic Edge Conditions（STEP 6-C）

架构要求（**不要把"需要规则"写成"规则已确定"**）：
```
zero contribution        → explicit deterministic handling required
empty epoch              → explicit deterministic handling required
Σweight = 0              → explicit rule required, currently OPEN
one contributor          → deterministic share calculation
many contributors       → deterministic aggregation
all rejected             → no reward consumption by rejected contributions
overflow                 → checked arithmetic
underflow                → checked arithmetic
division by zero         → explicit rejection/handling
rounding                 → canonical rounding
duplicate                → explicit deterministic handling
invalid contribution     → score/reward = 0 according to EBI boundary
late finalization        → OPEN
budget exhaustion        → OPEN
budget < calculated reward → OPEN
```

### Security Matrix（STEP 6-C）

| Threat | Severity | DESIGN DEFENSE | Residual Risk | Parameter Dependency | Status |
|---|---|---|---|---|---|
| Sybil splitting | HIGH | identity/contribution-level diminishing + caps + 验证成本 | 高资源女巫低效奖励 | OPEN | Candidate |
| Contribution splitting | HIGH | contribution-level diminishing | 拆单绕过 | OPEN | Candidate |
| Spam farming | MEDIUM | 验证成本 + rate limit + Model R1 | 付费刷量（稀释） | OPEN | Candidate |
| Whale concentration | HIGH | concentration caps + MaxScore | 合法高分 | OPEN | Candidate |
| Cross-domain bypass | MEDIUM | domain caps | 多类型分散 | OPEN | Candidate |
| Cross-epoch bypass | MEDIUM | epoch caps + contribution_id 唯一 | 跨 epoch 分散 | OPEN | Candidate |
| Self-citation | LOW | self-citation exclusion（ADR-0043 原则） | 无 | — | 原则已批 |
| Citation rings | MEDIUM | circular detection（ADR-0043 原则） | 合规环 | OPEN | Candidate |
| Early capture | MEDIUM | decay（D2/D4 candidate） | floor 需保护 | OPEN | Candidate |
| Late finalization | MEDIUM | finalized-only | reorg/延迟 | OPEN | Open |
| Score inflation | MEDIUM | MaxScore cap | cap 内集中 | OPEN | Candidate |
| Cap gaming | MEDIUM | cap 边界确定性 | cap 附近集中 | OPEN | Candidate |
| Rounding gaming | MEDIUM | canonical rounding | 边界偏差 | OPEN | 架构已冻结 |
| Order dependence | HIGH | canonical ordering（candidate） | 顺序不一致 | OPEN | Candidate |
| Zero-weight epoch | MEDIUM | — | remainder 去向 | OPEN | Open |
| Budget exhaustion | MEDIUM | budget ceiling | 政策/参数 | OPEN | Candidate |
| Adaptive feedback | HIGH | Model R1（已冻结） | 无 | — | 已冻结 |

> 全部为 **DESIGN DEFENSE**（≠ IMPLEMENTED DEFENSE）；理论防御不写成已实现保证。

### Parameter Boundary（STEP 6-C）

以下全部 **OPEN**（不得填具体数字）：
```
w_i · MaxScore · diminishing-return coefficient · decay coefficient · decay interval · rolling window length ·
per-identity cap · per-domain cap · per-epoch cap · per-contribution cap · reward-share cap · rate limit ·
citation weight · citation cap · rounding precision · economic epoch length · emission bounds ·
reward amount · funding source
```
允许 symbolic notation（α / β / γ / M / D / C_identity / C_domain / W）；**不得赋予未经 Owner 批准的数字**。

## Economic Parameter / Funding / Finalization Boundary（STEP 6-D 已批准；Layer 1 Architecture）

### Funding Boundary（STEP 6-D）

- **Model A = APPROVED ARCHITECTURE** · **Funding Source = UNDEFINED / BLOCKED** · **Reward Amount = NOT DEFINED**。
- 本 ADR **不自行选择** funding source：transaction fee / inflation / treasury / foundation allocation /
  validator subsidy / burned fee / Genesis reserve / Genesis unissued supply / external funding / protocol tax
  ——除非已有 Frozen/Approved ADR 明确规定；候选仅标 CANDIDATE/OPEN，不批准。

### Economic Epoch（STEP 6-D）

- **Economic Epoch = REQUIRED ARCHITECTURAL CONCEPT**（Reward Accounting 机制边界）。
- 以下全部 **OPEN**：epoch length / epoch-to-block mapping / epoch boundary semantics / finalization boundary /
  cross-epoch mapping / late-finalization mapping。
- **禁止填写具体数字**（如 N blocks / 7 epochs / 24 hours / 固定 block 数），除非原有 Frozen ADR 已明确规定。

### Late-Finalization Boundary（STEP 6-D）

```
late-finalization rule = OPEN
created=e, finalized=e+n 的 reward epoch = OPEN · decay start = OPEN
eligibility epoch mapping = OPEN · score epoch mapping = OPEN
weight epoch mapping = OPEN · reward epoch mapping = OPEN
reversal rule = OPEN · already-paid reward handling = OPEN
post-finalization invalidation handling = OPEN
```

- 绝对禁止自行决定：clawback / negative balance / future deduction / treasury transfer / burn /
  redistribution / reward reversal。

### Zero-Weight Epoch Boundary（STEP 6-D）

- `Σweight = 0 handling = OPEN`。
- 该情况属于 **consensus-critical economic edge case**，最终资金处理规则尚未冻结。
- 绝对禁止自行指定：treasury / validators / burn / next epoch rollover / redistribution / permanent lock。

### Remainder Handling Boundary（STEP 6-D）

- `Remainder destination = OPEN`。
- 覆盖至少：Σweight=0 remainder / rounding remainder / cap-induced remainder / budget exhaustion remainder。
- 必须区分：`canonical rounding architecture = APPROVED` · `rounding precision = OPEN` ·
  `remainder destination = OPEN`——**不把 canonical rounding 误写成 remainder destination 已确定**。

### Budget Exhaustion Boundary（STEP 6-D）

- `Reward Budget = independent budget ceiling`。
- 以下全部 **OPEN**：calculated distribution > / = / < budget · exact exhaustion · truncation · scaling ·
  remainder。
- 禁止自行选择：pro-rata scaling / priority ordering / carry-forward / burn / treasury /
  validator distribution / redistribution。

### Economic Parameter Boundary（STEP 6-D）

以下全部 **OPEN**（不得填具体数字）：
```
w_i · normalization parameters · MaxScore · diminishing-return coefficient · diminishing-return curve ·
decay coefficient · decay interval · decay floor · rolling window length · per-identity cap ·
per-domain cap · per-epoch cap · per-contribution cap · reward-share cap · rate limit · citation weight ·
citation cap · rounding precision · economic epoch length · emission bounds · reward amount
```
允许 symbolic notation（α / β / γ / M / D / W / C_identity / C_domain）；**禁止伪精确参数**（0.1 / 10% / 100 / 1000 / 7 epochs 等）。

### Decay Status（STEP 6-D）

```
D2 Epoch Decay = CANDIDATE · D4 Rolling Window = CANDIDATE
```

- 不得选择其中一个成为最终机制。
- **OPEN**：具体 decay mechanism / decay coefficient / decay interval / floor / window length /
  late-finalization interaction。
- 保持：`Contribution record = IMMUTABLE` · `Certificate = IMMUTABLE` ·
  `Economic evaluation state = MUTABLE / RECONSTRUCTABLE`；Decay 不修改历史事实。

### Concentration / Sybil Boundary（STEP 6-D）

- `Anti-Concentration Architecture = APPROVED AS ARCHITECTURAL EXISTENCE`（机制细节与数值 OPEN）。
- 候选控制维度：per-identity / per-domain / per-epoch / per-contribution / reward-share / global MaxScore
  ——**不得冻结具体 cap**。
- `Identity diminishing = CANDIDATE` · `Contribution diminishing = CANDIDATE`；曲线/阈值 OPEN。

### Canonical Transformation Order（STEP 6-D）

- `canonical ordering = REQUIRED architectural property`。
- 候选 pipeline（保留；非最终冻结算法）：
  ```
  Contribution → Eligibility → Canonical Components → Normalization → Weighted Score → Global MaxScore
  → Identity Aggregation → Diminishing Return → Weight → Concentration Control → Epoch Total Weight
  → Reward Share → Independent Reward Budget
  ```
- **OPEN**：具体 cap ordering / normalization-cap interaction / diminishing-cap ordering / MaxScore placement。

### Deterministic Math（STEP 6-D）

保持已批准架构：`integer / fixed-point + checked arithmetic + canonical rounding + canonical ordering`。
**禁止**：floating point / wall clock / locale-dependent / platform-dependent / unordered map iteration /
oracle / randomness / subjective metric。

### Security Status（STEP 6-D）

- 所有经济防御继续标记为 **DESIGN DEFENSE**（非 IMPLEMENTED / PROVEN / GUARANTEED / SECURE）。
- 必须保留 residual risk；理论架构防御不写成已实现保证。

## Budget Constraints

- **total_supply 是 CAP（非 initial allocation）**：任何 Contribution Reward 必须满足
  `Σ liquid + Σ bonded + burned_supply ≤ total_supply`。
- 若 reward 来自未分配 supply：须说明分布不突破 cap。
- 若 reward 来自 new issuance：new issuance 仍不得突破 cap。
- 若某模型需突破 cap：标记 **INCOMPATIBLE WITH CURRENT FROZEN ECONOMIC BOUNDARY**；禁改 ADR-0022。
- 非 burn fee 部分归属 UNDEFINED；不得自行创建资金流。
- Validator / Treasury / Contribution 的预算竞争：候选 Model 1 独立预算池 / Model 2 共享 Economic Budget /
  Model 3 分层预算 / Model 4 动态预算——**NOT FROZEN**；且 ADR-0022 未完整定义 validator/treasury reward ⇒
  边界冲突处标记 **FUTURE ADR REQUIRED**（不得在 0044 中偷完整定义）。

## Economic Invariants（Budget / Emission 层）

```
EBI-1  Contribution reward ≤ Contribution epoch budget
EBI-2  Contribution reward + other allocations ≤ available economic budget
EBI-3  任何 reward distribution 不得突破 total_supply cap
EBI-4  burned supply 不得重新被当作可分配 supply
EBI-5  同一 supply unit 不得被重复分配
EBI-6  Reward calculation deterministic
EBI-7  Reward pool 不得因 contribution count 增加而无限膨胀（除非明确采用有界 adaptive model）
EBI-8  Invalid / rejected contribution 不得消耗 finalized reward budget
EBI-9  Finalized reward allocation 必须可审计
EBI-10 不同 epoch 的预算边界必须确定性可重现
```

### EBI Status（STEP 6-A.1 + STEP 6-B 审查结果）

| EBI | Status |
|---|---|
| EBI-1 | **PASS — framework** |
| EBI-2 | **QUANTIFICATION BLOCKED**（funding source 未定义；不得写成 PASS） |
| EBI-3 | **PASS** |
| EBI-4 | **PASS** |
| EBI-5 | **PASS** |
| EBI-6 | **PASS**（same canonical inputs → same score → same weight → same reward） |
| EBI-7 | **PASS（Model R1）**（score count 不得自动扩大 reward budget） |
| EBI-8 | **PASS**（invalid/rejected → score=0 / reward=0 / budget=0） |
| EBI-9 | **PASS** |
| EBI-10 | **PASS WITH EPOCH DEPENDENCY**（economic epoch length/mapping OPEN） |

> **EBI-2 不是失败**——它是 **QUANTIFICATION BLOCKED BY FUNDING SOURCE**（funding source 未定义）。
> **EBI-10 不是失败**——它是 **DEPENDENT ON ECONOMIC EPOCH DEFINITION**（economic epoch length/mapping OPEN）。

## Attack Analysis（Budget 层）

| # | Attack | Likelihood | Impact | Candidate Defense | Requires Parameter? | Residual Risk |
|---|---|---|---|---|---|---|
| 1 | Reward pool exhaustion | 中 | 高 | budget ceiling + supply-aware（EBI-7） | 是 | 政策/参数风险 |
| 2 | Contribution spam → dilute rewards | 高 | 中 | 固定/有界 budget（稀释有限） | 是 | 低效贡献摊薄 |
| 3 | Contribution spam → inflate adaptive emission | 中 | 高 | 有界 adaptive（EBI-7 上限） | 是 | 若无界则高危 |
| 4 | Sybil splitting | 高 | 高 | per-identity 递减+caps（后续 STEP）+验证成本 | 是 | 无法完美 Sybil 检测 |
| 5 | Whale concentration | 中 | 高 | concentration caps（后续 STEP） | 是 | 合法高分贡献 |
| 6 | Early contributor capture | 中 | 中 | decay（后续 STEP） | 是 | 关键贡献 floor |
| 7 | Fee manipulation | 中 | 中 | fee 归属未定（FUTURE ADR）；burn 不可逆 | 部分 | 非 burn 部分 |
| 8 | Validator/Contributor collusion | 中 | 高 | Witness 确定性（0036）+finality | 否 | ≥1/3 共谋 |
| 9 | Treasury competition | 低-中 | 中 | treasury 边界 FUTURE ADR | 是 | 预算竞争 |
| 10 | Cross-epoch farming | 中 | 中 | epoch 快照+finalization（EBI-10） | 是 | 晚期 finalize |
| 11 | Late-finalization budget abuse | 中 | 中 | reward 仅对 Finalized（I-11 原则） | 是 | reorg/延迟 |
| 12 | Reward double allocation | 低 | 高 | EBI-5（supply unit 不重复分配） | 否 | 协议内消除 |

## Founder Neutrality

- **Founder Allocation = 0**。不得出现：Founder pool / Founder multiplier / Founder reward /
  Founder reserve / Founder guaranteed allocation。
- Contribution Reward 必须 **permissionless / rule-based / deterministic / founder-neutral**。

## Mobile Node Constraint

- Reward Budget 设计不得要求手机节点：长期高频在线 / 保存全部内容 / 高成本内容分析。
- 经济奖励必须基于 **protocol-verifiable facts**（ADR-0043 Impact 边界；L1-only）。

## Out of Scope（STEP 6-A + STEP 6-A.1）

- Score Formula / Decay Formula / Citation Formula / Rate Limit / Minimum Artifact Size / 最终 Reward Formula
  （后续 STEP）。
- 新 Transaction semantics / Block fields / Witness algorithm / DomainId / cryptographic primitive /
  canonical encoding / consensus mechanism（FUTURE ADR）。
- Validator reward / Treasury reward 完整定义（ADR-0022/0016 边界；FUTURE ADR）。
- Genesis Distribution / Public Sale（ADR-0045）。

## Open Questions（STEP 6-A.1 更新；未裁决项须项目所有者裁决）

```
OD1  Reward Budget / Funding Architecture：**架构已批准 = Independent Reward Budget（Model A）**；
     **Funding Source 仍 UNDEFINED / BLOCKED**（需正式 ADR：ADR-0016 修订 / ADR-0045 / FUTURE Economic ADR）
OD2  total_supply cap 语义：cap 内未分配部分是否可用于 reward（需 ADR-0016 对齐/修订）——**保持 OPEN**
OD3  Fee 非 burn 部分归属（UNDEFINED → FUTURE ECONOMIC ADR）——**保持 OPEN / MUST NOT ASSUME**
OD4  Treasury / Validator 预算边界（FUTURE ADR；本 ADR 冻结 Contributor ≠ Validator ≠ Treasury 分离）——**保持 OPEN**
OD5  Epoch 时长与边界（机制 REQUIRED；length / mapping OPEN）——**保持 OPEN**
OD6  Adaptive emission 的有界机制（BOUNDED CANDIDATE；formula/bounds OPEN）——**保持 OPEN**
OD7  Reward Budget 与 total_supply cap 的衔接（Accounting Identity 框架已冻结；
     LegallyFundedRewardBudget funding semantics OPEN）——**量化 BLOCKED**
```

## Do Not Overclaim（STEP 6-A.1）

本 ADR **不得**出现以下表述（除非未来独立 ADR 正式定义）：
- "Reward pool is funded"
- "Genesis provides reward reserve"
- "burned fees fund rewards"
- "non-burn fees fund rewards"
- "Treasury funds rewards"
- "Validators share the contributor reward pool"
- "Rewards are newly minted"

## Owner Decision Integration — STEP 6-E

> 以下为 **STEP 6-E Owner Decision Gate 的决策状态映射**（记录当前分类）；**不代表这些项目已经冻结**。

| Item | Decision State |
|---|---|
| Funding Source | **BLOCKED** |
| Reward Amount | **NOT DEFINED** |
| Economic Epoch | **OPEN** |
| D2 Epoch Decay | **CANDIDATE** |
| D4 Rolling Window | **CANDIDATE** |
| MaxScore | **OPEN / CANDIDATE** |
| Diminishing | **OPEN / CANDIDATE** |
| Identity Cap | **OPEN** |
| Contribution Cap | **OPEN** |
| Domain Cap | **OPEN** |
| Epoch Cap | **OPEN** |
| Reward-Share Cap | **OPEN** |
| Cap Ordering | **OPEN** |
| Decay Parameters | **OPEN** |
| Rounding Precision | **OPEN** |
| Late Finalization | **OPEN** |
| Reversal | **OPEN** |
| Already-Paid Handling | **OPEN** |
| Σweight = 0 | **OPEN** |
| Remainder Destination | **OPEN** |
| Budget Exhaustion | **OPEN** |
| Rate Limit | **OPEN** |
| Citation Parameters | **OPEN** |

## Decision Boundary（STEP 6-E）

```
Owner Decision Integration does not constitute protocol finalization.

No economic parameter is frozen by STEP 6-E unless explicitly designated as FROZEN
by a later Owner Decision Gate.

Funding remains BLOCKED.
Reward Amount remains NOT DEFINED.
Economic Epoch remains OPEN.
Late Finalization remains OPEN.
Zero-Weight handling remains OPEN.
Remainder Destination remains OPEN.
Budget Exhaustion remains OPEN.
Cap Ordering remains OPEN.
```

## References

- ADR-0043（PoC，FROZEN）· ADR-0005（DomainId）· ADR-0021（nonce）· ADR-0022（gas/fee/cap）·
  ADR-0016（genesis accounting）· ADR-0033（C-1）· ADR-0036（Witness）· ADR-0042（Block FROZEN）·
  ADR-0014（Genesis Schema：epoch_length_blocks / EconomicsParamsV1）

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：ADR-0044 Sustainable Economy Model V1（DRAFT——STEP 6-A 只设计 Reward Budget + Emission Architecture；Funding Source × Emission Schedule 两维度；total_supply cap 约束；EBI-1~EBI-10；Budget 攻击分析；Founder Neutrality；Mobile Node；OD1~OD7；未冻结最终模型/公式） | 项目所有者授权 PHASE 2 STEP 6-A（FORMAL ECONOMIC DESIGN — DESIGN ONLY） |
| 2026-08-31 | **STEP 6-A.1 架构落地**：批准 **Independent Reward Budget（Model A）** 为正式架构方向；写入 Four ENFORCED NOs（cap-breaking issuance / burned fee reuse / non-burn fee ownership / Genesis unissued bucket）；Funding Source Matrix（FORBIDDEN / UNDEFINED / FUTURE / SEPARATE）；Validator/Treasury Separation（Contributor ≠ Validator ≠ Treasury）；Supply Accounting Framework（available_supply ≠ spendable budget）；Accounting Identity（ContributorReward ≤ EpochRewardBudget ≤ LegallyFundedRewardBudget ≤ total_supply）；Economic Epoch（机制 REQUIRED；length/mapping OPEN；禁止自动 = epoch_length_blocks）；Adaptive Emission（BOUNDED CANDIDATE）；EBI Status 表；Do Not Overclaim。**Status 保持 DRAFT（非 FROZEN）** | 项目所有者批准 PHASE 2 STEP 6-A.1（Reward Funding Architecture Decision — Model A APPROVED；DESIGN ONLY / NO CODE） |
| 2026-08-31 | **STEP 6-B Score/Weight 架构落地（OWNER DECISION GATE 已批准）**：Decision A Score Architecture = W2 + W4 + W5（Layer 1；W1/W3 未采用）；Decision B Model R1（Score → Distribution，NOT Budget Expansion；与 EBI-7 对齐）；Decision C Score → Weight → Reward Pipeline（architectural equation，非冻结公式）；Decision D Deterministic Math（integer/fixed-point + checked + canonical rounding；禁浮点/oracle/主观）；Decision E Decay = D2/D4 候选（不冻结）；Decision F Anti-Concentration 架构边界（≠ Reward Budget）；Decision G 全部参数 OPEN；Score Components（protocol-verifiable vs subjective/FUTURE）；Score Architecture Boundary（Score = distribution signal，非 issuance）；Cross-Epoch Boundary（contribution_id unique / finalized immutable / 禁重复 allocation；late-finalization OPEN）。**Status 保持 DRAFT（非 FROZEN）** | 项目所有者批准 PHASE 2 STEP 6-B（Score Formula / Weight Architecture — OWNER DECISION GATE；DESIGN / ADR INTEGRATION ONLY / NO CODE） |
| 2026-08-31 | **STEP 6-C Decay / Concentration / Sybil-Resistance 架构落地（OWNER DECISION GATE 已批准）**：D2/D4 decay 候选（均不冻结；deterministic replay REQUIRED；record/certificate IMMUTABLE；decay 只影响评估层）；Concentration Control 架构（anti-concentration ≠ Reward Budget；per-identity/domain/epoch/contribution/reward-share/MaxScore 候选层；数值 OPEN）；Cap Ordering（consensus-critical；canonical ordering = REQUIRED；具体顺序 OPEN）；Sybil-Resistance 架构（identity/contribution-level diminishing 等 = DESIGN DEFENSE）；Sybil/Spam Boundary（L1-verifiable vs 主观/oracle/off-chain = FUTURE）；Candidate Canonical Transformation Pipeline（非 Frozen）；Cross-Epoch 边界（record 不可变；late-finalization/reversal/already-paid/decay start = OPEN）；Zero-Weight/Empty Epoch 边界（Σweight=0 经济处理 OPEN；禁止发明 remainder 去向）；Cap Remainder 边界（handling OPEN）；Deterministic Edge Conditions（架构要求）；Security Matrix（17 项，DESIGN DEFENSE）；Parameter Boundary（全部 OPEN）。**无经济参数冻结；Funding 保持 UNDEFINED/BLOCKED；ADR 保持 DRAFT** | 项目所有者批准 PHASE 2 STEP 6-C（Decay / Concentration / Sybil-Resistance Architecture — OWNER DECISION GATE；DESIGN / ADR INTEGRATION ONLY / NO CODE） |
| 2026-08-31 | **STEP 6-D Integration — Economic Parameter / Funding / Finalization boundaries**。integrated Economic Parameter / Funding / Finalization boundaries：Economic Epoch（REQUIRED concept；length/mapping OPEN）；Late-Finalization Boundary（rule OPEN；reversal / already-paid / post-finalization invalidation OPEN；禁止 clawback/burn/redistribution 等）；Zero-Weight Epoch（Σweight=0 handling OPEN；禁止指定资金去向）；Remainder Handling（destination OPEN；canonical rounding APPROVED vs precision OPEN）；Budget Exhaustion（budget = independent ceiling；exhaustion/truncation/scaling OPEN；禁止 pro-rata/carry-forward 等）；Economic Parameter Boundary（全部 OPEN；仅 symbolic）；Decay Status（D2/D4 CANDIDATE；不选最终机制）；Concentration/Sybil Boundary（Anti-Concentration APPROVED AS EXISTENCE；机制/数值 OPEN）；Canonical Transformation Order（canonical ordering REQUIRED；具体顺序 OPEN）；Deterministic Math（保持已批准架构）；Security Status（DESIGN DEFENSE）。**Funding and Reward Amount remain undefined/blocked; economic parameters remain open; late-finalization, zero-weight, remainder, budget-exhaustion, and cap-ordering rules remain open. No numeric economic parameters were frozen. No funding source was selected. No code or protocol-state changes were made. ADR 保持 DRAFT** | 项目所有者批准 PHASE 2 STEP 6-D（Economic Parameter / Funding / Finalization Decision Gate — DESIGN / ADR INTEGRATION ONLY / NO CODE） |
| 2026-08-31 | **STEP 6-E — Owner Decision Integration**：Owner Decision Gate integrated into ADR-0044（新增 Owner Decision Integration 23 项决策状态映射 + Decision Boundary）。**No code changes. No funding source selected. No reward amount defined. No economic parameter frozen. No finalization rule frozen. No zero-weight destination selected. No remainder destination selected. No ADR-0045 created. ADR 保持 DRAFT** | 项目所有者批准 PHASE 2 STEP 6-E（Economic Simulation / Parameter Sensitivity — OWNER DECISION GATE → INTEGRATION；DESIGN / ADR INTEGRATION ONLY / NO CODE） |
