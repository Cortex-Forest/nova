# ADR-0043: Nova Proof of Contribution Protocol V1

- **Status**: **FROZEN（ACCEPTED）**（PHASE 1.5 STEP 3 FINAL FREEZE；2026-08-31）
- **Deciders**: Nova Chain 架构组
- **Date**: 2026-08-31
- **Scope**: Proof of Contribution（PoC）——定义 Contribution 类型 / Contribution Object / Proof /
  Verification / Eligibility。**不定义** Reward 经济模型（归 ADR-0044）、Genesis Distribution（归 ADR-0045）。
- **前置**: PHASE 0 ADR Registry Audit 通过；ADR-0043 编号已批准。

---

## 0. Freeze Decision（PHASE 1.5 STEP 3 FINAL FREEZE）

```
FINAL DECISION: FROZEN（ACCEPTED）

Freeze basis:
  - PHASE 1.5 STEP 1 Micro-Fixes completed（Q-A~Q-I 落地）
  - PHASE 1.5 STEP 2 Final Consistency + Security Review completed
    （结论：PASS WITH NON-BLOCKING OPEN QUESTIONS）
  - No BLOCKER · No CRITICAL · No HIGH
  - Core security boundaries passed（domain separation / object identity / replay protection /
    chain+domain binding / sequence separation / duplicate handling / originality / conditional Witness /
    L1-only Impact / consensus-execution boundary / citation anti-farming / founder neutrality / ADR-0042 compatibility）

本 Freeze 是 PROTOCOL SCOPE FREEZE：
  不是 IMPLEMENTATION COMPLETE（未实现 Contribution protocol）
  不是 MAINNET READY
  不是 ECONOMIC MODEL COMPLETE（经济归 ADR-0044）

Frozen Scope（A~J）:
  A. Contribution Object（独立协议对象；contribution_id / contribution_sequence / 与交易 nonce 分离）
  B. Domain Separation（DomainId::Contribution = 0x07；签名域含 algorithm‖domain‖chain_id‖len‖payload）
  C. Verification（Model B 基线 + Model C 条件 Witness；复用 ADR-0036）
  D. Replay Protection（contribution_id / contribution_sequence / chain binding / domain binding / finalization）
  E. Impact Boundary（仅 L1 可验证事实影响协议级 Impact）
  F. Score Boundary（ADR-0043 = WHAT COUNTS；ADR-0044 = HOW BECOMES REWARD）
  G. Payload Principle（最小有效载荷原则；不冻结具体经济参数）
  H. Parent Reference（Conditional：原创 None / 衍生必填）
  I. Originality（四态：First Submission / Original / Derivative / Citation；重复 artifact 不得第二 Original）
  J. Citation Anti-Farming（原则冻结：depth cap / decay / inheritance cap / circular detection /
     self-citation exclusion；具体数值不冻结）

Non-Blocking Follow-ups（已记录，不在本 Freeze 解决）:
  M1  Original 共识排序机制（"首验证通过"的确定性排序）→ Future consensus/protocol spec
  M2  状态机形式化（Invalid/Rejected/Duplicate 终态）→ Future protocol/implementation spec
  M3  parent_reference 完整性（self-reference/missing parent/parent not verified）→ Future protocol spec
  M4  canonical_contribution_payload 具体编码（field ordering/integer/length）→ Future canonical encoding spec
  L1  §19 遗留 Open Q-B/Q-H 措辞 → 本次已做 STATUS WORDING CLEANUP（不改安全语义）

NOT FROZEN by ADR-0043（归 ADR-0044）:
  score formula / score coefficients / decay numerical parameters / min artifact size /
  contribution rate limit / citation depth value / citation decay value / inheritance cap value /
  emission weight / reward amount

Domain Registry: DomainId::Contribution = 0x07 已冻结；ADR-0005 Registry 同步 = 独立后续文档任务
  （本 ADR 不修改 ADR-0005）。

ADR-0042 Boundary: 本 ADR 不修改 ADR-0042（无新增 Block field / 无 Contribution Root in Block /
  无 canonical encoding 变更）；若未来需 Contribution Root ⇒ 新 ADR。
```

---

## 1. Context

Nova 面向 AI / 数字创作生态。早期通过有限、透明的 Bootstrap 启动；长期依靠真实网络收入维持贡献奖励。
需要一种**协议可验证**的贡献证明机制，奖励"对网络产生有效贡献"而非"提交数量"。

本 ADR 只解决：**什么算贡献、如何证明、如何验证、谁有资格获得奖励**。
**给多少、从哪来、何时发** 由 ADR-0044（Sustainable Economy）与 ADR-0045（Genesis Distribution）定义。

### 核心命题

> Nova 不奖励：Upload Count / PR Count / Transaction Count / Like Count / Raw Output。
> Nova 奖励：**对网络产生、并且可以被协议验证的有效贡献**。

### 三个概念的严格区分（本 ADR 的基石）

```
Contribution            贡献本身（行为/产物，可被证明存在）
Contribution Verification   证明与验证（协议可验证的事实）
Reward                  奖励（归 ADR-0044；本 ADR 只定义 Eligibility）
```

不得混为一谈。**验证 ≠ 价值判断**；**Eligibility ≠ 奖励数额**。

---

## 2. Goals

- G1 定义统一 Contribution 抽象（类型 / 对象 / 生命周期）。
- G2 建立**协议可验证**的证明与验证模型（签名 / 哈希承诺 / 确定性选择 / 防重放）。
- G3 严格划分 Consensus / Execution / Application / Off-chain 职责。
- G4 使贡献评分可验证、可审计、抗刷、边际递减、必要时衰减。
- G5 明确 Sybil Resistance 与 Anti-Spam 边界（不依赖可操纵指标）。
- G6 定义 Reward Eligibility（奖励资格），把奖励数额边界交给 ADR-0044。
- G7 形式化 Founder / Core Developer 边界（Founder Allocation = 0；Founder 可按统一规则作为普通贡献者）。

## 3. Non-Goals

- 不定义 Token 分配比例 / Reward Pool 比例 / Genesis Sale 比例 / Token 价格 / Treasury 比例（ADR-0044/0045）。
- 不实现任何代码 / Token / Reward / Genesis / Block 字段修改。
- 不引入未经审计的"真人证明（Proof of Humanity）"强制。
- 不定义治理投票规则（仅明确治理边界，规则归 Governance ADR）。
- 不把主观价值（内容质量/审美/社区热度）写入 consensus。

## 4. Terminology

| 术语 | 定义 |
|---|---|
| Contribution | 对网络产生、可被证明存在并验证的有效贡献行为/产物 |
| Contributor | 提出贡献的主体（以 NovaAddress 账户标识） |
| Contribution Object | 协议层贡献记录（§6） |
| Artifact | 贡献的产物（代码、内容、报告等），以哈希承诺标识 |
| Contribution Proof | 证明贡献者确实做出该贡献的密码学证据（签名） |
| Verification | 协议对贡献的**事实性**验证（非价值判断） |
| Impact | 贡献对网络产生的**可协议验证**影响（非主观评分） |
| Contribution Score | 协议可验证维度聚合的贡献度量（§9；不直接等于奖励） |
| Reward Eligibility | 是否具备获得奖励的资格（ADR-0044 定义数额） |
| Witness | 确定性选出的验证者/见证者（ADR-0036 模式复用，§8.4） |

---

## 5. Contribution Types

统一 `ContributionType`（协议枚举，5 类；`0x01`~`0x05`；未知 ⇒ 拒）：

| Type | 值 | 覆盖 | 示例 |
|---|---|---|---|
| `CONTENT` | 0x01 | 音乐 / 视频 / 图片 / 游戏内容 / 文章 / AI 辅助创作 | 数字作品、内容资产 |
| `APPLICATION` | 0x02 | DApp / Wallet / Explorer / SDK / 游戏 / 娱乐 / 工具 | 应用、开发者工具 |
| `PROTOCOL` | 0x03 | Consensus / Network / Runtime / Crypto / Storage / Testing / Performance | 协议开发、修复、测试 |
| `SECURITY` | 0x04 | 漏洞披露 / 安全研究 / 审计贡献 / 关键 Bug 修复 | 安全贡献 |
| `COMMUNITY` | 0x05 | 文档 / 翻译 / 教育 / 开发者支持 | 社区贡献 |

- **DApp 开发、协议 Bug 修复、Network 优化、SDK、测试、安全漏洞提交**——原则上均可成为贡献（用户确认）。
- 但必须满足 §7 Proof + §8 Verification + §9 Impact；**绝不** `提交数量 = 奖励数量`。
- `ContributionType` 是**协议枚举**（与 ADR-0020 TransactionType 同为 Registry 模式）；
  新增类型须经 Registry 扩展（禁止 fallback）。

---

## 6. Contribution Object

设计统一 `Contribution` 对象（协议层）。**不照抄候选字段**——先对照现有协议事实筛选：

| 候选字段 | 是否协议层 | 依据 |
|---|---|---|
| `contributor_id` | ✅ `NovaAddress`（账户） | ADR-0017/0004；账户即贡献者标识 |
| `contribution_type` | ✅ `ContributionType` | §5 |
| `artifact_hash` | ✅ `[u8;32]`（SHA-256） | 内容/产物承诺；`protocol_hash`（ADR-0006） |
| `proof` | ✅ 签名（`[u8;64]` Ed25519） | 证明贡献者确实做出（§7） |
| `timestamp` | ✅ `u64`（LE） | 时间（ADR-0042 BlockHeader 同款） |
| `parent_reference` | ⚠️ `Option<[u8;32]>` | 衍生/复刻链（fork/二次创作）；唯一性相关（Open Q-F） |
| `verification_status` | ✅ 状态机 | 生命周期（§8.1） |
| `impact_score` | ✅ 协议可验证指标聚合 | §9（**非主观评分**） |
| `reward_state` | ⚠️ 归 ADR-0044 | 本 ADR 只定义 eligibility，reward_state 字段由 ADR-0044 定义 |

**`Contribution`（协议对象，Draft 形态）**：
```
contributor_id: NovaAddress
contribution_type: ContributionType
artifact_hash: [u8;32]
proof_signature: [u8;64]       // DomainId::Contribution = 0x07（§7）
timestamp: u64
parent_reference: Option<[u8;32]>   // Conditional（§12；原创=None，衍生=必填）
verification_status: VerificationStatus
impact_score: ImpactScore       // 协议可验证指标（§9）
contribution_id: [u8;32]        // SHA-256(canonical_contribution_payload)；对象承诺/标识（§8.5）
contribution_sequence: u64      // per-contributor 单调递增；独立于交易 nonce（§8.5）
```

- `artifact_hash` 承诺**内容本身**（防篡改）；`proof_signature` 承诺 **contributor + artifact + 元数据**。
- `VerificationStatus` 状态机：`Submitted → Verified → Finalized`（§8.1）。
- `impact_score` 只含**协议可验证**指标，不含 likes/views/followers（§7 视为可操纵）。
- **`contribution_id` = `SHA-256(canonical_contribution_payload)`**——这是 **OBJECT COMMITMENT /
  OBJECT IDENTIFIER**（对象承诺/标识），**不是 transaction hash**。`Contribution` 与 `Transaction`
  是**不同协议对象**；贡献的签名/承诺/生命周期与交易独立。
- **`contribution_sequence`**：per-contributor **单调递增序列**；**独立于 Account Transaction Nonce**
  （ADR-0021 的 (sender,nonce) 交易唯一性）。**不得把 contribution_sequence 与 transaction nonce 合并**。
- **`reward_state`**：由 **ADR-0044** 定义。本 ADR **不冻结**：reward amount / emission weight /
  score formula / economic parameters（§9/§23）。

---

## 7. Proof Model

### 7.1 证明目标
证明三件**事实**（非价值）：
1. **存在**：`artifact_hash` 对应一个真实产物（哈希承诺）。
2. **归属**：该贡献由 `contributor_id` 做出（签名绑定）。
3. **时效**：在 `timestamp` 提交（时间承诺）。

### 7.2 签名（DomainId::Contribution = 0x07，已批准）
- `signed_bytes = alg(Ed25519=0x01) ‖ dom(0x07) ‖ chain_id(8LE) ‖ len(4LE) ‖ canonical_contribution_payload`
- `message_hash = SHA-256(signed_bytes)`；`verify_strict`（ADR-0005/0012/0013 模式）。
- **DomainId::Contribution = `0x07`**（已批准）：
  - `0x01~0x06` 已被现有协议注册（Transaction=0x01 / ValidatorVote=0x02 / Block=0x03 /
    Governance=0x04 / Address=0x05 / Witness=0x06，ADR-0005 + ADR-0036 W-5）。
  - `0x07` 用于 Contribution；`0x08+` 保留未来扩展。
  - **必须避免与 Transaction / ValidatorVote / Block / Governance / Address / Witness 混域**
    （不同 domain_id ⇒ 不同 signed_bytes ⇒ 不同 message_hash ⇒ 防 cross-domain replay）。
- **ADR-0005 Registry 登记**：`DomainId::Contribution = 0x07` 的 Registry 文档登记须作为**独立文档同步工作**
  （经 ADR-0005 修订或 Registry ADR）；**本 ADR 不直接修改 ADR-0005**。

### 7.3 承诺
- `artifact_hash = SHA-256(canonical artifact bytes)`——但"什么算 artifact 的 canonical bytes"：
  - PROTOCOL/SECURITY：Git commit hash / patch hash / 文档 hash（可协议化）。
  - CONTENT/APPLICATION：内容文件 hash（**可协议化**）；但**内容是否原创**需 §12（Originality）辅助。
- `parent_reference`：复刻/衍生需显式声明父贡献（构成原创性图谱，§12）。

---

## 8. Verification Model

### 8.1 生命周期（职责归属）

```
Contribution Submission        → Application / Execution（构造 + 结构）
        ↓
Syntax Validation              → Execution（结构 / 枚举 / 长度）
        ↓
Authenticity Verification      → Execution / Crypto（proof_signature 验证，DomainId::Contribution）
        ↓
Duplicate / Similarity Check   → Execution（精确哈希去重，协议内）；Off-chain（相似度，§12）
        ↓
Replay Protection Check        → Execution（contribution_id + sequence + chain/domain 绑定；§8.5）
        ↓
Witness Verification           → Consensus（**条件性**：仅高 impact / 关键类型；§8.4 Model C）
        ↓
Impact Evaluation              → Execution（协议可验证指标，§9）
        ↓
Consensus Finality             → Consensus（finality 链，ADR-0038）
        ↓
Contribution Certificate       → Execution / State（状态记录，不可变承诺）
        ↓
Reward Eligibility             → ADR-0044（本 ADR 只定义"已验证"为资格前提）
```

### 8.2 职责边界（核心）

**Consensus 负责（C-1：consensus pure computation，ADR-0033）**：
- 验证**可验证事实**：签名、哈希承诺、确定性 Witness 选择、防重放（nonce/timestamp）。
- 为已验证贡献的证书提供 **Finality**（经现有 finality 链）。
- **绝不**承担：内容审美、主观价值判断、AI 内容质量判断、任意外部数据判断。

**Execution 负责**：
- `Contribution` 的语法/结构验证；`proof_signature` 验证（委托 crypto）。
- `impact_score` 中**协议可验证**指标的计算（如：贡献引用的存储量、协议级使用量、唯一性）。
- 状态写入（`Contribution` 记录 + `VerificationStatus` 推进）。

**Application 负责**：
- 用户界面、贡献提交入口、artifact 上传（生成 artifact_hash 之前的内容处理）。
- **off-chain 主观指标**（likes/views/followers/社区热度）——**可展示，但不得进入 consensus/impact_score**。

**Off-chain 辅助**：
- 相似度检测（内容指纹/查重）、举报、人工审核辅助（作为影响/原创性的**辅助证据**，非 consensus 输入）。

### 8.3 防重放（完整见 §8.5）
- 采用**独立 contribution_sequence**（per-contributor 单调递增），**不沿用 ADR-0021 交易 nonce 模式**
  （贡献是独立协议对象）。完整防重放设计见 §8.5。

### 8.4 Verification Model：Model B（基线）+ Model C（条件 Witness）

**Model B — BASELINE（所有 Contribution 强制）**：协议确定性验证，至少包括：
1. `contribution` 结构有效性（structure validity）
2. canonical encoding 有效性
3. `artifact_hash` 有效性（哈希承诺合法）
4. 签名有效性（`proof_signature`，DomainId::Contribution=0x07，verify_strict）
5. 贡献唯一性（`contribution_id` 全局唯一）
6. 防重放（§8.5）
7. 协议定义的 eligibility 检查（类型/身份/时序）

- **Model B 不要求 L1 consensus 解析内容本身的主观质量**（C-1）。

**Model C — CONDITIONAL WITNESS（仅高 impact / 关键类型）**：
- 仅当 Contribution 满足**协议定义的高 impact / critical type**（如 SECURITY 关键贡献、高引用贡献）
  条件时，才需要 Witness Confirmation。
- Witness 选择**必须复用 ADR-0036 已冻结的确定性机制**（`witness_seed` + `deterministic_select`，
  W-2/W-3）；**不得重新设计 witness selection**。
- **不是所有 Contribution 都必须 Witness**。原因：mobile node compatibility / liveness / bandwidth /
  CPU / consensus complexity。

### 8.5 Replay Protection（MUST-FIX，已批准）

**目标**：同一 Contribution Proof 被重放（重广播 / 不同交易引用 / 不同账户提交 / 跨 epoch / 跨 network）
时，**不得**重复获得原创/奖励资格。

**`contribution_id`**（对象承诺 / 对象标识）：
- `contribution_id = SHA-256(canonical_contribution_payload)`。
- 用于：对象身份（object identity）、重复检测（duplicate detection）、防重放（replay protection）。
- **不是 transaction hash**；贡献是独立协议对象。

**`contribution_sequence`**（per-contributor 单调递增）：
- 每个 contributor 独立递增（如 A: 0,1,2,3…；B: 0,1,2,3…）。
- 具体起始值（0 或 1）遵循"protocol-defined sequence rule"——现有 ADR 未定义，故本 ADR 不规定起始值。
- **`transaction nonce ≠ contribution_sequence`**：贡献是独立协议对象，不是普通 Transaction nonce 的替代品；
  **不得合并**（不改变 ADR-0021 交易 nonce 语义）。

**Chain binding**：
- `chain_id` 必须参与 `signed_bytes`。不同 `chain_id` ⇒ 不同 `signed_bytes` ⇒ 不同 `message_hash`
  ⇒ proof **跨链无效**（防 cross-network replay）。

**Domain binding**：
- `DomainId = 0x07` 必须参与 `signed_bytes`。Contribution proof **不能被解释为**：
  Transaction / Block / Witness / ValidatorVote / Governance / Address（防 cross-domain replay）。

**Finalization**：
- Contribution 一旦达到协议定义的 finalized state：其 `contribution_id` / originality result /
  verification result **不可通过普通重复提交改变**。
- 再次提交相同 `contribution_id` ⇒ **不得再次获得 Original Contribution eligibility**。

---

## 9. Contribution Score

### 9.1 原则
- **不采用** `Reward = Contribution Count`。
- Score 只聚合**协议可验证**维度；主观维度**不进协议**。
- 单一指标**不得**决定奖励；边际递减；必要时衰减（§10）。

### 9.2 维度分析（哪些可协议化）

| 维度 | 可协议化？ | 说明 |
|---|---|---|
| Quality | ❌ 应用层 | 内容/代码质量本质主观 → 不协议化（可作 off-chain 参考） |
| Uniqueness | ✅ 协议 | `artifact_hash` 全局唯一 + 原创性图谱（§12） |
| Impact | ⚠️ 部分协议 | 协议可验证的影响（如被引用、协议级使用、存储/计算占用）可协议化；"社会影响"不协议化（Open Q-C） |
| Utility | ⚠️ 部分协议 | 可验证的生态复用（被其他贡献引用次数）可协议化；主观"有用性"不协议化 |
| Verification | ✅ 协议 | 验证状态（Submitted/Verified/Finalized）+ witness 确认 |
| Historical Reliability | ✅ 协议 | 贡献者历史贡献的有效率（已验证占比、被否占比） |

### 9.3 Score 边界（WHAT vs HOW，已批准）
- **ADR-0043 定义 WHAT COUNTS AS CONTRIBUTION**：score dimensions / measurable contribution
  boundaries / anti-abuse principles / decay principle。
- **ADR-0044 定义 HOW CONTRIBUTION BECOMES ECONOMIC REWARD**：score formula / coefficients /
  weights / emission formula / reward amount / economic parameters。
- **本 ADR 不写具体经济数值**（公式 / 系数 / 权重 / 衰减参数 / 奖励量归 ADR-0044）。

```
ImpactScore = f( uniqueness_factor, impact_factor, verification_factor, reliability_factor, decay(t) )
```
- 每个 factor 都是**协议可验证**（哈希唯一 / 引用计数 / 验证状态 / 历史效率 / 时间衰减）。
- 精确聚合公式**不**在本 ADR 冻结（归 ADR-0044）——本 ADR 只冻结"维度集合 + 可协议化边界"。

---

## 10. Contribution Decay

### 10.1 问题
- 早期贡献巨大 → 永久高权重 → 奖励垄断（须防）。
- 历史核心安全贡献 → 时间后完全归零（须避免）。

### 10.2 设计建议（Draft）
- **时间衰减**：贡献权重随时间递减（如半衰期线性/指数衰减），防止"一次贡献永久占权重"。
- **安全/关键贡献保护**：SECURITY/PROTOCOL 关键贡献设**最低保留下限（floor）**，防止被错误归零
  （如历史关键漏洞修复保留最小有效权重）。
- **类型差异化**：不同贡献类型的衰减常数可不同（实现/经济层参数，归 ADR-0044 冻结）。
- **衰减 ≠ 删除**：衰减只影响 Score 权重；贡献记录与证书**不可变**（历史仍可审计）。

---

## 11. Sybil Resistance

### 11.1 目标
一个人创建 100 万个账户并提交 100 万个贡献时，**不得**获得 100 万倍奖励。

### 11.2 原则
```
Contribution Quality > Contribution Count
```
- **边际递减**：同 contributor（或其关联账户）的新增贡献，边际 Score 递减（防刷量）。
- **验证成本**：每贡献需密码学验证 +（可选）witness 确认；提交有成本（Gas，经 ADR-0022）。
- **唯一性**：重复/近似内容被唯一性检查拒绝或降权（§12）。
- **账户历史**：新账户低可靠性（reliability factor 低）。
- **不引入未经审计的"真人证明"**强制（Non-Goal）。
- **关联账户检测**：Off-chain 辅助识别 Sybil 集群（**辅助**，非 consensus 输入）。

### 11.3 边界
- identity 不强绑定链上单一账户（尊重匿名）；通过**经济/验证成本 + 递减 + 唯一性**自然抗 Sybil。

---

## 12. Originality（原创性）

### 12.1 目标
防复制内容 / AI 批量垃圾 / 重复 Git 提交。

### 12.2 四态（已批准 Q-H）

**1. First Submission**：第一次提交某 `artifact_hash` 的候选对象。
- **First Submission ≠ 自动 Original**（需通过验证才成为 Original）。

**2. Original Contribution**：第一个**通过协议验证**并获得原创资格的有效贡献。
- **不得依据裸 timestamp 判断所有权**（timestamp 可伪造/不可靠；以验证通过序为准）。

**3. Derivative Contribution**：明确声明 `parent_reference` 的衍生、Remix、Fork。
- `parent_reference` **必须存在**（§12.3 Conditional）。

**4. Citation**：明确表达对其他 Contribution 的引用关系。
- Citation **不等于复制**，也**不自动改变**被引用对象的 Original status。

### 12.3 parent_reference（Conditional，已批准 Q-F）
- **原创贡献**：`parent_reference = None`（允许 Genesis Contribution——首个原创无父可提交）。
- **Derivative / Remix / Fork**：`parent_reference = 必须`（指向已存在贡献）。
- 防"声明原创实为复制"：靠 `artifact_hash` 全局唯一 + off-chain 相似度辅助（非 consensus 强制）。

### 12.4 Duplicate Artifact 规则（已批准 Q-H）
- 若 `artifact_hash` 已存在（已有 Original）：**不得产生第二个 Original Contribution**。
- 允许显式：**Citation** 或 **Derivative Contribution**。
- **原始贡献者保持其 Original 状态**（不被重复提交覆盖）。

### 12.5 精确去重 / 图谱 / 相似度
- **精确去重（协议内）**：`artifact_hash` 全局唯一——完全相同 artifact 只能有一次 Original 贡献
  （Execution 强制）。
- **原创性图谱（协议内）**：`parent_reference` 声明衍生关系；纯复刻（parent 相同、无增量）⇒ 拒绝或降权。
- **相似度检测（Off-chain 辅助）**：内容指纹/模糊查重，输出辅助报告；不作为 consensus 输入。
- **AI 批量垃圾**：靠唯一性 + 验证成本 + 递减 + 最小有效载荷原则（§11/§12.6）。

### 12.6 Citation Anti-Farming（已批准 Q-I；具体数值归 ADR-0044）
1. **citation depth cap principle**：引用链深度上限（A→B→C→D 不能无限继承权重）。
2. **citation weight decay principle**：深层引用权重递减。
3. **maximum inheritance principle**：单贡献可继承的引用权重上限。
4. **circular citation detection**：A→B→A 属 circular citation，环内引用不得无限产生新权重。
5. **self-citation exclusion**：同 contributor 引用自己不计。
- **本 ADR 不冻结具体数值**（depth / decay / inheritance cap 归 ADR-0044）。

---

## 13. Impact（Impact Evaluation 边界）

- **协议可验证 Impact**（Execution 计算）：
  - 被引用/复用次数（其他贡献声明 `parent_reference` 指向它）。
  - 协议级使用（如贡献为 DApp/Protocol，其在链上的可验证活跃）。
  - 存储/计算资源占用（经存储/费用层可验证）。
- **不可协议化 Impact**（Application/Off-chain）：社会影响、社区热度、内容质量评价。
- **禁止**：likes / views / followers / transaction count 直接进入 Impact（§7 视为可操纵）。

---

## 14. Contribution Decay（见 §10 完整性；本节约束）
- 衰减仅作用于 Score 权重；`Contribution` 记录与证书不可变。
- 安全贡献 floor 保护；衰减参数（半衰期/floor）归 ADR-0044 冻结。

---

## 15. Founder / Contributor Boundary

- **Founder Allocation = 0**：不设置 Founder Premine / Founder Reserve / Hidden Allocation / Guaranteed Reward。
- Founder 可作为**普通贡献者**参与 `PROTOCOL` / `SECURITY` 等贡献；若符合统一规则，可获得
  **Protocol Contributor Reward**（与所有贡献者同一套规则）。
- 不得因 Founder 身份获得额外隐藏权限 / 隐藏参数。
- 核心维护者 / 长期开发者 / 安全研究者：可研究**公开透明**的参数（如可靠性权重、关键贡献保护），
  但必须公开、同规则、经 ADR 冻结（归 ADR-0044）。

---

## 16. Consensus Boundary（C-1 落实）

- Consensus 只验证**可验证事实**（签名 / 哈希 / 确定性选择 / 防重放 / finality）。
- **禁止** Consensus 承担：内容审美、AI 质量、主观价值、任意外部数据判断（ADR-0033 C-1）。
- Consensus 不持有主观指标；`impact_score` 由 Execution 计算，Consensus 只对贡献证书提供 finality。
- **禁止** 验证者投票"这个音乐好听所以奖励 1000"（主观价值不入 consensus）。

## 17. Execution Boundary

- Execution 负责：结构/语法验证、`proof_signature` 验证委托、协议可验证 impact 计算、状态写入。
- Execution **不**做主观价值判断；**不**实现 Token/Reward（归 ADR-0044 实现）。

## 18. Security Considerations

- 防重放（nonce/timestamp 唯一）。
- 签名严格 `verify_strict` + DomainId 域分离（防跨域重放）。
- `artifact_hash` 防篡改（内容承诺）。
- 贡献证书经 finality 链（防双花贡献/回滚）。
- 拒绝服务：贡献提交有大小上限 + 验证成本（Gas）。
- 错误模型：本 ADR 不新增协议错误；错误分类归实现层（触发 ADR 评估先例：P7-3 D5）。

---

## 19. Attack Analysis（12 类）

| # | Attack | Threat Model | Impact | Mitigation | Residual Risk |
|---|---|---|---|---|---|
| 1 | **Sybil Attack**（百万账户刷贡献） | 女巫账户批量 | 稀释奖励 / 刷分 | 边际递减 + 验证成本 + 唯一性 + 账户历史可靠性 | 高资源女巫仍可获部分低效奖励（受递减限制） |
| 2 | **AI Spam Attack**（批量垃圾内容） | AI 生成海量 | 污染贡献池 | artifact 唯一性 + 最小有效载荷 + 验证成本 + 相似度 off-chain | 高仿内容相似度绕过后仍需唯一性/成本 |
| 3 | **Duplicate Content Attack**（复制热门） | 复制他人内容 | 冒领贡献 | artifact_hash 全局唯一 + 原创性图谱（parent_reference） | 重复 hash 拒第二 Original；原创以验证通过序为准（Q-H 已批准，§12.2/§12.4） |
| 4 | **Fake Engagement Attack**（机器人互刷） | 刷使用量/引用 | 虚增 Impact | 协议可验证引用计数 + 防自引用（同 contributor 引用不计/降权） | 跨账户串谋引用（off-chain 检测辅助） |
| 5 | **Fake Contribution Attack**（虚假提交） | 无效/伪造贡献 | 浪费验证资源 | 结构 + 签名 + 唯一性 + Model C 条件 Witness（Q-B 已批准，§8.4） | 恶意有效签名贡献（受验证成本限制） |
| 6 | **Git Spam Attack**（大量低价值提交） | 刷 PROTOCOL 提交 | 刷 PROTOCOL 分 | 提交需 artifact_hash + 有效载荷下限 + 引用图谱 + 验证成本 | 大量小提交仍可累积（受递减限制） |
| 7 | **Self-Transaction Farming**（自交易刷贡献） | 自己制造交易 | 虚增网络活动指标 | Impact 不使用 transaction count；引用计数防自引用 | 间接刷量（off-chain 辅助） |
| 8 | **Whale Manipulation**（大户操纵评分） | 大户操纵 Impact | 垄断 | 边际递减 + 单一指标不决定 + 引用权重上限（Open Q-I） | 大户可通过高价值贡献合法获高分 |
| 9 | **Validator-Contributor Collusion**（验证者-贡献者串谋） | 验证者包庇贡献 | 伪验证 | Witness 确定性选择（ADR-0036，不可预选）+ 多见证者 + finality 链 | 共谋 ≥1/3 验证者（同共识 Byzantine 边界） |
| 10 | **Governance Capture**（通过贡献获得治理权） | 刷贡献获取治理权 | 治理捕获 | 治理边界独立（ADR-0043 不授予治理权；Governance ADR 定义）；贡献 Score ≠ 治理权重 | 治理规则未冻结前边界依赖 Governance ADR |
| 11 | **Reward Farming**（只盯奖励刷分） | 为奖励优化刷量 | 经济效率下降 | 衰减 + 递减 + 质量>数量 + 关键贡献保护 | 合规刷分者仍可获部分奖励 |
| 12 | **Resource Exhaustion**（恶意提交耗尽验证资源） | 大量提交 DoS | 验证者资源耗尽 | 提交大小上限 + Gas 成本 + 每区块贡献数上限（ADR-0022/0042 边界） | 高费用攻击者仍可施压（受费用限制） |

每个 Attack：Attack / Threat Model / Impact / Mitigation / Residual Risk —— 见上表。

### 19.1 补充攻击分析（12 项，Micro-Fixes 后）

| # | Attack | Threat | Impact | Protocol Defense | Remaining Risk |
|---|---|---|---|---|---|
| 13 | **Contribution Replay**（同一 proof 重放） | 重广播/不同交易引用 | 重复获资格 | `contribution_id` 唯一 + 最终化不可变（§8.5） | 无（协议内消除） |
| 14 | **Cross-Network Replay**（跨链重放） | 跨 network 提交 | 跨链重复资格 | `chain_id` 绑定 signed_bytes（§8.5 Chain binding） | 无（不同 chain_id ⇒ 无效） |
| 15 | **Cross-Domain Replay**（跨域重放） | 复用其他域签名 | 混淆为交易/投票 | `DomainId=0x07` 绑定（§8.5 Domain binding） | 无（不同 domain_id ⇒ 无效） |
| 16 | **Duplicate Artifact Submission** | 重复提交相同 hash | 第二 Original | 唯一 Original + 仅 Citation/Derivative（§12.4） | 无（协议内消除） |
| 17 | **Contribution Sequence Reuse** | 复用 sequence | 顺序重放 | per-contributor 单调递增 + 唯一（§8.5） | 无（协议内消除） |
| 18 | **Citation Farming** | 刷引用链 | 虚增继承权重 | depth cap + decay + inheritance cap（§12.6） | 合规刷引用可获部分分（受上限/递减限制） |
| 19 | **Circular Citation** | 引用环 | 无限权重 | circular detection + 环内不计分（§12.6） | 无（协议内消除） |
| 20 | **Self Citation** | 自引用 | 虚增自身 | self-citation exclusion（§12.6） | 无（协议内消除） |
| 21 | **AI-Generated Contribution Spam** | AI 批量内容 | 污染贡献池 | 唯一性 + 验证成本 + 最小有效载荷原则（§11/§12.6） | 高仿唯一内容仍可提交（受成本/递减限制） |
| 22 | **Large Useless Artifact Spam** | 大文件垃圾 | 存储/验证资源 | 最小有效载荷原则 + 大小上限 + Gas（§11；数值归 ADR-0044） | 付费大文件可提交（受成本限制） |
| 23 | **Sybil Contribution Farming** | 女巫批量贡献 | 稀释奖励 | 边际递减 + 验证成本 + 唯一性 + 账户历史（§11） | 高资源女巫低效奖励（受递减限制） |
| 24 | **Validator / Contributor Collusion** | 验证者包庇 | 伪验证 | Witness 确定性选择（ADR-0036 不可预选）+ 多见证 + finality（§8.4） | 共谋 ≥1/3 验证者（同共识 Byzantine 边界） |

**注**：上述攻击的**数值性防御**（大小上限 / 速率限制 / 深度值 / 衰减值 / 上限值）属 ADR-0044 经济参数，
本 ADR 不写无协议依据的数字（§21.2 ADR-0044 TODO）。

---

## 20. Compatibility（现有 ADR 兼容性审查）

| ADR | 兼容性 | 说明 |
|---|---|---|
| ADR-0016 Genesis Accounting Invariants | ✅ | PoC 不改变 genesis 账务；若需未分配供应/treasury，归 ADR-0044/0045 并遵守其"未分配去向必须明确"约束 |
| ADR-0020 Transaction Type Registry | ✅ | 新增 TransactionType（如 Contribution 提交交易）须经 Registry 扩展（本 ADR 不冻结新交易类型） |
| ADR-0022 Gas & Fee Accounting | ✅ | 贡献提交消耗 Gas（提交成本）；validator reward/treasury 归 ADR-0044 |
| ADR-0023 State Transition | ✅ | Contribution 状态写入经 AccountStateView/StateTransition 模式；不改变现有账户语义 |
| ADR-0033 Consensus Architecture | ✅ | C-1 严格保持：consensus pure computation，不承担主观判断（§16） |
| ADR-0034 Validator Set & Vote | ✅ | Witness/验证者复用 ValidatorSet；PoC 不改变投票/权重语义 |
| ADR-0035 DAG | ✅ | Contribution 不引入 DAG 语义（parent_reference 是原创性图谱，非共识 DAG） |
| ADR-0036 Random Witness | ✅ | 复用 witness_seed / deterministic_select（§8.4） |
| ADR-0037 BFT Round / 0038 Finality | ✅ | 贡献证书经现有 finality 链 |
| ADR-0039 Checkpoint / 0040 Fork Choice | ✅ | PoC 不改变 checkpoint/fork-choice |
| ADR-0041 ProposalRef Serialization | ✅ | 不冲突 |
| **ADR-0042 Block Format（FROZEN）** | ⚠️ | 见下 |

### ADR-0042 Block Format FROZEN — 冲突分析

- **Conflict**：若 PoC 需在 Block 内新增贡献相关字段（如贡献 root / 每区块贡献数）。
- **Why**：ADR-0042 已 FROZEN（Block field / order / encoding 不得改变）。
- **Alternative**：
  1. 贡献作为**独立状态/对象**（经账户状态或独立 Contribution Store），Block 只含其承诺（复用
     state_root 承诺机制，无需改 Block 字段）。
  2. 若必须新增 Block 字段 ⇒ **新 ADR**（如 ADR-0046 Block Format Amendment / Contribution Root）。
- **Potential New ADR**：ADR-0046（若需要 Block 贡献承诺字段；**不在本 ADR 决定**）。

---

## 21. 决策状态（Q-A ~ Q-I 已批准 / MICRO-FROZEN）与经济参数（OPEN → ADR-0044）

### 21.1 已批准（MICRO-FROZEN）

| # | 决策 | 状态 | 落地章节 |
|---|---|---|---|
| Q-A | `DomainId::Contribution = 0x07`（0x07 空闲；0x08+ 保留） | **APPROVED / MICRO-FROZEN** | §7.2 |
| Q-B | Model B 基线 + Model C 条件 Witness（仅高 impact/关键类型；复用 ADR-0036） | **APPROVED / MICRO-FROZEN** | §8.4 |
| Q-C | Impact 仅 L1 可验证；Application 辅助；Off-chain 不入 consensus | **APPROVED / MICRO-FROZEN** | §9/§13 |
| Q-D | 0043 冻结维度/边界；公式/参数归 ADR-0044 | **APPROVED / MICRO-FROZEN** | §9.3 |
| Q-E | 0043 冻结最小有效载荷原则；数值归 ADR-0044 | **APPROVED / MICRO-FROZEN** | §11/§12.6 |
| Q-F | `parent_reference` = Conditional（原创 None / 衍生必填） | **APPROVED / MICRO-FROZEN** | §12.3 |
| Q-G | 防重放：contribution_id + 独立 sequence + chain/domain 绑定 | **APPROVED / MICRO-FROZEN** | §8.5 |
| Q-H | 四态；原创 = 首验证通过；重复 hash 拒第二 Original | **APPROVED / MICRO-FROZEN** | §12.2/§12.4 |
| Q-I | Citation anti-farming 原则（depth/decay/cap/环检测/自引用排除）；数值归 ADR-0044 | **APPROVED / MICRO-FROZEN** | §12.6 |

### 21.2 ADR-0044 TODO（经济参数，**本 ADR 保持 OPEN，不得猜测数值**）
- score formula（公式）
- score coefficients（系数）
- decay parameters（衰减参数：半衰期 / floor）
- min artifact size（最小有效载荷数值）
- contribution rate limit（速率限制数值）
- citation depth value（引用深度数值）
- citation decay value（引用衰减数值）
- inheritance cap（继承上限数值）
- emission weight（排放权重）
- reward amount（奖励数额）

---

## 22. Rejected Alternatives

| 方案 | 否决原因 |
|---|---|
| `Reward = Contribution Count` | 直接奖励数量 ⇒ 刷量无边界（本 ADR 基石） |
| Consensus 投票评判内容质量（"好听给 1000"） | 主观价值入 consensus ⇒ 违反 C-1，可操纵 |
| 强制 Proof of Humanity（真人证明） | 未审计、隐私侵入、门槛高（Non-Goal） |
| likes/views/followers 入 Impact | 全可操纵（§7/§13） |
| 修改 ADR-0042 增加 Block 字段 | FROZEN 禁改；用独立状态/承诺 + 新 ADR 方案 |

---

## 23. Dependency on ADR-0044 / ADR-0045

```
Proof of Contribution（ADR-0043）
        │
        ↓
Contribution Score（ADR-0043，维度冻结）
        │
        ↓
Reward Eligibility（ADR-0043）
        │
        ↓
Sustainable Economy（ADR-0044）→ Reward Pools / 奖励来源 / 衰减参数
        │
        ↓
Genesis Distribution & Bootstrap（ADR-0045）→ Bootstrap 期奖励来源
```

- ADR-0043 只定义 **Eligibility**（已验证贡献 + Score 维度 + 衰减/抗刷原则）。
- **Reward 数额 / Pool 比例 / 衰减参数值 / 奖励来源** 由 ADR-0044 定义。
- **Bootstrap 期奖励来源 / Genesis Sale / Treasury** 由 ADR-0045 定义。
- 依赖方向：`0043 ← 0044 ← 0045`（经济模型依赖 PoC 的 eligibility 定义）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：ADR-0043 Nova Proof of Contribution Protocol V1（Draft——Context/Goals/Non-Goals/Terminology/Types/Object/Proof/Verification/Score/Decay/Sybil/Originality/Impact/Founder 边界/Consensus+Execution 边界/Security/Attack Analysis/Compatibility/Open Questions/Rejected Alternatives/依赖） | 项目所有者授权 PHASE 1 ADR-0043 设计（Design Only / No Code） |
| 2026-08-31 | **Micro-Fixes 落地（PHASE 1.5 STEP 1，DOCUMENT REVISION ONLY）**：Q-A~Q-I 批准裁决应用——§6 增 contribution_id/contribution_sequence（对象承诺≠交易 hash；独立于交易 nonce）；§7 明确 DomainId::Contribution=0x07（ADR-0005 登记待独立文档同步）；§8 明确 Model B 基线（7 项验证）+ Model C 条件 Witness（复用 ADR-0036，不重设计）；§8.5 新增 Replay Protection（contribution_id/sequence/chain binding/domain binding/finalization）；§9 明确 WHAT vs HOW 边界；§12 四态 + Duplicate Artifact 规则 + Citation Anti-Farming 原则；§19 补充 12 项攻击；§21 Q-A~Q-I → APPROVED/MICRO-FROZEN，经济参数 → ADR-0044 TODO | 项目所有者批准 PHASE 1.5 Micro-Fixes |
| 2026-08-31 | **PHASE 1.5 STEP 3 — ADR-0043 FINAL FREEZE（DOCUMENT FREEZE）**：Status → **FROZEN（ACCEPTED）**；新增 §0 Freeze Decision（Protocol Scope Freeze；非 implementation / mainnet / economic complete）；Frozen Scope A~J 冻结；Non-Blocking Follow-ups M1~M4 记录并归属（Original 排序 / 状态机形式化 / parent_reference 完整性 / canonical payload 编码）；L1 §19 遗留 Open Q-B/Q-H 措辞清理（不改安全语义）；明确 ADR-0044 经济参数 NOT FROZEN、ADR-0005 Registry 同步为独立任务、ADR-0042 边界保持。**未实现任何代码 / 未创建 ADR-0044/0045 / 未改 Frozen ADR / 未 commit** | 项目所有者批准 PHASE 1.5 STEP 3 ADR-0043 FINAL FREEZE |
