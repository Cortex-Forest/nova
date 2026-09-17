# ADR-0052: Genesis Allocation & Account Provenance Design

- **Status**: **PROPOSED**（2026-09-02 设计稿；**非 FINAL**——等待 Owner 真实数据与 Genesis 参数后定稿）
- **Date**: 2026-09-02
- **Deciders**: Nova Chain 架构组（Owner 决策）
- **Scope**: Genesis Allocation → Provenance → Account → Balance 映射框架（off-chain provenance /
  文档层设计；不改变 GenesisV1 schema）
- **前置**: ADR-0014（GenesisV1 schema）、ADR-0015（canonical encoding）、ADR-0016（accounting
  invariants）、ADR-0051（fixed supply tokenomics，FINAL）、genesis-v1.md（协议冻结）
- 关联：ADR-0050（draft，未落盘）、ADR-0044（historical exploration）

> **设计定位**：本 ADR 是 **off-chain provenance / documentation 设计**。
> `Allocation Category` 不是 GenesisV1 字段；Genesis 仍只保存 `address + liquid_balance`。
> 本 ADR **不**冻结 chain_id / network_id / genesis_timestamp / 真实 validator identity /
> 真实 allocation address——它们属于 Genesis Finalization 阶段。

---

## 1. Motivation

Genesis 需要 provenance，因为：

- **资产来源可追踪**：每一枚 NOVA 从哪个 allocation category 流向哪个账户必须可回溯。
- **分配透明**：社区 / 生态 / 团队 / 基金会 / 验证者可独立核验分配承诺。
- **防止隐藏供应**：供应不变量要求 `Σ initial_accounts.liquid_balance == MAX_SUPPLY`；
  provenance 使"是否全部 1B 都已分配到已知账户"可审计，杜绝隐藏 / 未声明的供应。
- **支持审计**：为后续 public distribution、生态资助、基金会运营提供外部审计基准。

**核心原则**：

```
Provenance ≠ Genesis schema 字段
```

Genesis（链上）仍只保存：

```
address
liquid_balance
```

Allocation category / custody / purpose 全部属于 **off-chain provenance / documentation**
（本 ADR 记录层），与 ADR-0051 §10 冻结语义一致。

---

## 2. Allocation Model Reference

来自 ADR-0051（FINAL，数字不可修改）：

| Category | Amount | % |
|---|---|---|
| Community/Public | 500,000,000 | 50% |
| Ecosystem | 200,000,000 | 20% |
| Team | 120,000,000 | 12% |
| Foundation | 80,000,000 | 8% |
| Genesis Validator | 100,000,000 | 10% |
| **TOTAL** | **1,000,000,000** | 100% |

验证：

```
500M + 200M + 120M + 80M + 100M = 1,000,000,000 NOVA = PASS
```

规则（ADR-0051 冻结）：Founder = 0% · Mint = FORBIDDEN · Burn = FORBIDDEN ·
Supply Cap Change = FORBIDDEN · fee_burn_bps = 0 · Unissued = 0（V0.1 全量分配）。

---

## 3. Genesis Account Representation

### 链上（GenesisV1 AccountInit）

```
AccountInit {
    address:        NovaAddress   // bech32m；canonical 35B payload
    liquid_balance: u128          // 整数 NOVA；u128 LE
}
```

### 链外 provenance 记录（本 ADR 维护；不进入 Genesis）

```
ProvenanceRecord {
    address:         NovaAddress
    category:        Community | Ecosystem | Team | Foundation | Validator
    amount:          u128          // liquid_balance 归属量
    custody_type:    single | multisig | legal | future-distribution
    owner_reference: string        // 实体/托管标识（真实数据到位后填写）
    notes:           string        // 可选：multisig 门限 / legal 安排 / distribution 备注
}
```

**强调**：provenance **不进入 Genesis**。禁止在 Genesis/account schema 中添加
`allocation_type` / `purpose` / `team` / `foundation` / `ecosystem` / `community` /
`vesting` / `unlock` / `release_schedule` / `treasury` / `presale`（ADR-0051 §10 禁止列表）。

---

## 4. Custody Mapping Design

Owner A-G 决策已于 2026-09-02 锁定（记录于 STEP 8-G.5 Owner Decision Review）。

### Community/Public — Target 500M
```
Category:    Community/Public
Target:      500,000,000
Custody:     A3 = multisig custody（Owner LOCKED）—— Genesis 由 1+ 指定 holder
             （链外 multisig 控制）持有；未来经正式 distribution process 分发
Distribution: Future mechanism（distribution ≠ additional supply；无新增供应）
地址/金额:    TBD（PENDING Owner）
```

### Ecosystem — Target 200M
```
Category:    Ecosystem
Target:      200,000,000
Custody:     Dedicated multisig（Owner LOCKED）—— 单一专用 multisig 账户
地址/金额:    TBD（PENDING Owner）
注意:        Ecosystem ≠ Treasury
```

### Foundation — Target 80M
```
Category:    Foundation
Target:      80,000,000
Custody:     Multisig（Owner LOCKED）
地址/金额:    TBD（PENDING Owner）
注意:        Foundation ≠ Protocol Treasury；Genesis 不记录用途
```

### Team — Target 120M
```
Category:    Team
Target:      120,000,000
Vesting:     60 months linear（intent）
Genesis unlock: 0（intent）
Custody:     Multisig + legal vesting（Owner LOCKED）
⚠ Protocol-enforced vesting = NO
  （GenesisV1 无 vesting 字段；链无法阻止全额立即转移；
   60mo/unlock=0 由 multisig + off-chain legal/托管安排承载）
地址/金额:    TBD（PENDING Owner）
```

### Genesis Validator — Target 100M
```
Category:    Genesis Validator
Target:      100,000,000
Validator accounts: V1 - V7
Allocation:  E3 = Owner explicit integer allocation（Owner LOCKED）
             Σ(V1..V7) = 100,000,000 NOVA（整数；无小数 denomination）
bonded stake: 见 §6（F = allocation ≠ bonded，允许 liquid 保留）
地址/公钥/stake: TBD（PENDING 节点运营者/Owner）
```

---

## 5. Validator Genesis Mapping

映射模板（对应 GenesisV1 `ValidatorInit`）：

```
ValidatorEntry {
    account_address:      NovaAddress
    consensus_public_key: [u8; 32]     // Ed25519 压缩点
    bonded_stake:         u128
    commission_bps:       u16          // ≤ 10_000
}
```

约束（来自 `validate_genesis` 冻结语义）：

1. **validator account 必须存在于 `initial_accounts`**（否则 `InvalidStake`）。
2. **`bonded_stake <= liquid_balance`**（validator 账户 liquid 须覆盖 bonded；`StakeExceedsBalance`）。
3. **`bonded_stake >= min_validator_stake`**（`min_validator_stake` 来自 economics_parameters）。
4. **`Σ(initial_accounts.liquid_balance) == MAX_SUPPLY`**（`SupplyInvariantViolation`）。

**禁止虚拟 Validator Pool**：

```
✗ Validator Pool Account（脱离账户的虚拟池）
+   Validator bonded stake

✓ Validator Account { liquid_balance, bonded_stake }
  —— 100M 经由 validator 账户的 liquid_balance 承载；
     bonded_stake 从该 liquid 扣除（状态转换，非新增供应）
```

---

## 6. Bond Allocation Rule

```
Genesis Validator Allocation = 100,000,000 NOVA（ADR-0051 冻结）
```

**明确**：

```
allocation ≠ bonded stake
```

原因：**Genesis account balance**（liquid，账户状态）与 **consensus bonded state**
（bonded，权益/出块权重）是两个不同概念。bonded 是 liquid → bonded 的状态转换
（`ValidatorSet::from_genesis`，weight = bonded_stake），不新增供应。

Owner F 决策（LOCKED 2026-09-02）：

```
方案2 形态：allocation ≠ bonded —— 允许 validator 账户 liquid > bonded_stake
（账户 liquid_balance ≥ bonded_stake 且可大于；超出部分保留为 liquid）
```

各 validator 的 bonded stake 具体值：**TBD**（Owner 在 E3 显式分配后给出；须满足
§5 约束 2/3，即各验 bonded ≤ 其 liquid）。

---

## 7. Address Provenance Rules

默认规则：

```
One Address, One Category
```

默认**禁止**同地址承担多个 allocation category，包括但不限于：

```
Team + Foundation
Foundation + Validator
Community + Ecosystem
Team + Validator
Community + Foundation
```

例外：

```
Owner explicit authorization required（G 决策 = Default deny）
```

一旦 Owner 授权 category overlap，必须记录（写入本 ADR provenance 层）：

```
category overlap exception {
    address
    categories[]        // 每类金额
    custody relationship
    provenance rationale
    owner_authorization_ref
}
```

> 复用风险：同一地址跨分类 → provenance 混淆、单钥跨类风险、审计退化。
> 默认隔离；任何复用皆须 Owner 显式授权，不自行判断。

---

## 8. Reconciliation Table

Category-level（TBD，待真实数据；**禁止填假数据**）：

| Category | Target | Actual | Difference |
|---|---|---|---|
| Community/Public | 500,000,000 | TBD | TBD |
| Ecosystem | 200,000,000 | TBD | TBD |
| Team | 120,000,000 | TBD | TBD |
| Foundation | 80,000,000 | TBD | TBD |
| Genesis Validator | 100,000,000 | TBD | TBD |
| **TOTAL** | **1,000,000,000** | **TBD** | **TBD** |

Genesis 编撰前必须达到：

```
TOTAL Difference = 0
Σ(initial_accounts.liquid_balance) == 1,000,000,000
```

Address-level reconciliation 将在真实地址到位后建立（Address / Category / Liquid /
Validator Stake / Public Key / Provenance 六列）。

---

## 9. Genesis Parameters Pending List

以下参数 **不属于 ADR-0052 决定范围**——它们属于 Genesis Finalization 阶段：

```
chain_id:          PENDING（Owner；Genesis 阶段）
network_id:        PENDING（Owner；Genesis 阶段）
genesis_timestamp: PENDING（Owner；上线前人工确定）
```

原因：这些是确定性网络身份 / 防重放 / 时间锚点常量，须由 Owner 在 Genesis
定稿时按真实规划指定；ADR-0052 不猜测、不生成、不冻结。

---

## 10. Real Identity Requirements

真实数据必须由 Owner / 节点运营者提供；**禁止 placeholder / random / AI generated**。

### Validator（V1-V7，每项）
```
account_address
consensus_public_key[32]
bonded_stake（整数；Σ validator liquid allocation = 100M 约束内）
commission_bps
```
另须保证每个 validator 账户在 `initial_accounts` 中存在且 liquid ≥ bonded（§5）。

### Allocation Accounts
```
Community/Public address（es） + liquid_balance
Ecosystem address + liquid_balance
Foundation address + liquid_balance
Team address + liquid_balance
```

**为何必须真实来源**：这些地址将真实持有资金，是保管入口；公钥/地址必须由真实
自持私钥的实体离线生成。虚构地址 = 无人持钥的"黑洞"或需事后迁移，破坏
provenance 与分配承诺。

---

## 11. Security Review

对最终账户结构（真实数据到位后）执行；此处先立分析框架：

- **custody risk**：Community 500M / Ecosystem 200M 等大桶 custody 单点化风险；
  multisig 门限与托管安排缓解（Owner A-C 已选 multisig）。
- **key compromise risk**：单账户密钥失窃 = 该分类全额暴露；一址多类会放大影响
  （§7 default deny 缓解）。
- **provenance ambiguity**：类别归属 / 金额 / 保管关系不清晰 → 审计退化
  （reconciliation + overlap exception 记录缓解）。
- **concentration risk**：最大桶（Community 50%）与 top allocations 集中面；
  验证者 100M/7 若有余额倾斜需在 E3 显式分配时标注并评估。

> ⚠ allocation % ≠ governance voting power；本 ADR 不设计 token governance / voting。

---

## 12. Decision Status

```
ADR-0052: PROPOSED（2026-09-02；非 FINAL）
```

等待 Owner：

```
A-G custody 决策     → 已 LOCKED（2026-09-02；记录于 §4/§5/§6/§7）
真实地址            → PENDING（Community/Ecosystem/Foundation/Team/Validator V1-V7）
validator identity  → PENDING（address + pubkey + stake + commission）
Genesis parameters  → PENDING（chain_id / network_id / genesis_timestamp）
```

**未决 / 禁止**：不生成 wallet / key / address；不填 chain_id / network_id /
timestamp；不生成 Genesis；不改 schema / Rust / consensus / identity.rs。

---

## 变更记录

| Date | Change | Ref |
|---|---|---|
| 2026-09-02 | ADR-0052 初稿（PROPOSED）：Genesis Allocation & Account Provenance 设计；记录 Owner A-G 决策（A3 / dedicated multisig / multisig / multisig+legal / E3 explicit / F allocation≠bonded / G default deny）；H-L 保持 PENDING | STEP 8-G.5 Owner Decision → STEP 8-H |
