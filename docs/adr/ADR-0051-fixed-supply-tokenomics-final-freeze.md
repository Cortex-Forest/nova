# ADR-0051: Nova Fixed Supply Tokenomics Final Freeze

- **Status**: **FINAL**（2026-09-02 Owner Freeze；固定供应经济模型正式冻结）
- **Date**: 2026-09-02
- **Deciders**: Nova Chain 架构组（Owner 决策）
- **Scope**: Nova 固定供应经济模型（MAX_SUPPLY / Allocation / 无 mint-inflation-burn / Team 政策 /
  Genesis Validator bootstrap / 参与分层 / 未来 reward 边界）
- **前置**: ADR-0014（GenesisV1）、ADR-0015（canonical encoding）、ADR-0016（accounting invariants）、
  ADR-0022（gas/fee）、ADR-0044（sustainable economy，DRAFT，历史探索）、ADR-0048（persistence）、
  genesis-v1.md（协议冻结）
- 关联：ADR-0050（draft，未落盘——本 ADR 为其演进收敛）

## 1. Status
```
FINAL —— 固定供应与分配已冻结（2026-09-02）。
Genesis 所需的真实身份参数（chain_id / network_id / genesis_timestamp）与真实 validator / account
数据未在本 ADR 内定义（留 Genesis 编撰阶段）。
```

## 2. Context
- Nova 为固定供应、量子安全（后量子）、娱乐/创作者公链。
- 冻结目的：把供应上限与分配承诺固化为**共识级经济不变量**，为社区、生态、验证者、创作者提供长期可预期性。
- STEP 8-E.5 冻结前审查：20/20 Hard Gates PASS、无 blocking conflict、Verdict=READY FOR OWNER FREEZE
  DECISION → Owner 授权本 ADR 落盘并冻结。

## 3. Decision
```
Nova adopts a fixed maximum supply of 1,000,000,000 NOVA.

The allocation is:
  Community/Public 50%
  Ecosystem       20%
  Team            12%
  Foundation       8%
  Genesis Validator 10%

Founder allocation = 0%.

No minting.
No inflation.
No burn.
No supply-cap increase.

Any future reward mechanism must operate within the existing
fixed supply and requires a separate ADR.
```

## 4. Supply Invariant
```
MAX_SUPPLY = 1,000,000,000 NOVA（不可变 cap；Genesis 承诺；ADR-0016/0044 语义）
Genesis 时：Σ(initial_accounts.liquid_balance) == 1,000,000,000 NOVA
Bonding = liquid → bonded（状态转换，**非 mint**）
bonded stake 不增加 total supply（防 double counting / supply inflation，ADR-0016）
注：当前代码/GenesisV1 无 protocol_locked_balance / locked_balance / circulating_balance 等字段；
    本 ADR 不把它们写成 Genesis/account schema 字段（不虚构 accounting fields）。
```

## 5. Allocation（合计 100% = 1,000,000,000）
| Category | % | NOVA |
|---|---|---|
| Community/Public | 50% | 500,000,000 |
| Ecosystem | 20% | 200,000,000 |
| Team | 12% | 120,000,000 |
| Foundation | 8% | 80,000,000 |
| Genesis Validator | 10% | 100,000,000 |
| **Total** | **100%** | **1,000,000,000** |
```
Founder = 0% · Unissued = 0% · Hidden = 0%
```

## 6. Founder / Team Policy
```
Founder allocation = 0%（不等于 Team = 0 —— Founder 与 Team 是不同概念）
Team allocation = 12% = 120,000,000 NOVA（独立于 Founder 的项目团队分配）
禁止创建：Founder wallet / Founder reserve / Founder hidden allocation / Founder bonus
```

## 7. Team Vesting
```
Team = 120,000,000 NOVA · 60 months linear release · Genesis liquid unlock = 0
GenesisV1 无 vesting 字段 ⇒ Protocol-enforced vesting = NO
当前方案 = off-chain custody / legal commitment
禁止声称 "The blockchain automatically enforces the 5-year vesting"
未来如需链上强制 vesting ⇒ 须独立 ADR + 新 schema/version
```

## 8. Genesis Validator Bootstrap
```
Genesis Validator Bootstrap Allocation = 100,000,000 NOVA = 10% of MAX_SUPPLY
这是已发行 NOVA 的 allocation，不是新 minted reward。
validator stake 来源于分配账户 liquid 的 bond（liquid → bonded）。
7-validator 等权模型：quorum = ceil(2/3 × 7) = 5 · BFT fault tolerance = 2
real validator addresses/stakes = NOT YET DEFINED（不得生成）
```

## 9. Validator / Community Node / Creator Participation
```
Layer 1 — Validator：BFT consensus（weight = bonded_stake）
Layer 2 — Community Node：Future non-BFT participation（storage / AI compute / content verification / network contribution）
Layer 3 — Creator：Future entertainment/content participation

min_validator_stake = 5,000,000 NOVA 是 Validator 共识门槛，不是 Nova 全体参与门槛：
普通用户无需 5M 即可使用钱包 / 成为 Creator / 参与社区 / 运行未来 Community Node。
Layer 2 / Layer 3 为未来设计（当前未实现），不得写成已实现。
```

## 10. Genesis Expressibility
```
保持 GenesisV1 不变。Genesis 只表达实际账户：{ address, liquid_balance }
Community/Ecosystem/Team/Foundation/Validator 分类 = allocation provenance / off-chain classification
（协议不感知余额归属类别）
禁止加入：allocation_type · vesting · unlock · purpose · team · foundation · ecosystem · treasury ·
          presale · witness_count
```

## 11. Fee Policy
```
fee_burn_bps = 0
⇒ V0.x burn mechanism 不销毁交易手续费（burn = actual_fee × 0 / 10_000 = 0）
Fee destination = NOT DEFINED IN ADR-0051
禁止把手续费定义为：validator reward / treasury / foundation / ecosystem / burn
```

## 12. Mint / Inflation / Burn Policy（HARD NO-MINT RULE）
```
Nova V0.x supply is fixed at 1,000,000,000 NOVA.

No protocol path may create additional NOVA.
No validator reward may mint additional NOVA.
No governance mechanism may increase MAX_SUPPLY.
No emergency authority may increase MAX_SUPPLY.
No inflation schedule exists.
No burn mechanism exists.

表述限定：The protocol design contains no authorized mint path, and MAX_SUPPLY is a
consensus-level economic invariant.（不主张"数学上未来任何软件不可能出 bug"的绝对断言）
```

## 13. Public Sale Policy
```
正式删除 Public Sale 独立 allocation bucket。
未来若开展 public sale（法律与运营可行时），必须作为使用既有 Community/Public allocation 的
distribution mechanism，不得新增供应。
本 ADR 不设计 ICO / 价格 / 融资金额 / sale contract。
```

## 14. Foundation Allocation
```
Foundation = 80,000,000 NOVA（8%）
Foundation allocation ≠ protocol treasury mechanism
Treasury mechanism = NOT DEFINED（不自行创造 Treasury）
```

## 15. Ecosystem Allocation
```
Ecosystem = 200,000,000 NOVA（20%）
Ecosystem allocation ≠ inflation pool
Ecosystem allocation ≠ automatic reward emission
Ecosystem allocation ≠ protocol treasury
```

## 16. Security / Concentration Considerations
```
Validator concentration（真实 validator stake 提供后评估：largest>1/3 阻挠 / ≥2/3 控制 · top2/top3）
Team off-chain vesting trust（依赖托管/法律）
Foundation custody · Ecosystem custody
Genesis allocation provenance（off-chain 记录）
Actual validator concentration cannot be evaluated until real Genesis validator stakes are supplied.
（禁止虚构 validator distribution）
```

## 17. Future Reward Boundary
```
ADR-0051 supersedes ADR-0044 的 mint-based funding/reward 方向（固定供应经济模型）。
ADR-0044 保留为历史设计探索（不删除）。
Future reward mechanisms MUST NOT introduce new NOVA through minting or inflation.
Any future reward mechanism must source value from already-issued NOVA and/or protocol-defined fee
flows, subject to a separate future ADR.
（本 ADR 不设计 reward rate / reward pool / treasury emission / validator APR —— 留未来独立 ADR）
```

## 18. Risks
```
P1 供应集中（Community 500M / Ecosystem 200M 大户 = 保管/治理/抛压，off-protocol）
P1 Team off-chain vesting trust（120M 全 liquid 入 Genesis 依赖托管/法律）
P1 Validator 集中（待真实 stake 评估）
P2 Foundation / Ecosystem custody（80M / 200M 账户控制权，off-protocol）
P3 Community Node / Creator 未实现（方向性）
```

## 19. Compatibility
```
GenesisV1 schema = UNCHANGED · canonical encoding（ADR-0015）= unchanged
ADR-0016（全量分配 Σliquid==cap）= 一致（本分配 100% 全量）
ADR-0022（fee burn 公式；fee_burn_bps=0 参数禁用）= 一致
ADR-0048（persistence）= 无影响
Consensus / crypto / network / witness mechanism = 无修改（witness_count=3 为协议常量，非 Genesis 字段）
```

## 20. Consequences
```
- Genesis 编撰必须使 Σ(initial_accounts.liquid_balance) == 1,000,000,000（Community/Ecosystem/Team/
  Foundation/Genesis Validator 账户以 final liquid 表达）
- 未来 reward 机制不得 mint/inflation；须在固定供应内寻源并经独立 ADR
- 链上 vesting / treasury / reward 若未来需要 ⇒ 新 schema/version + 独立 ADR
- 真实 validator/account/identity 参数留 Genesis 编撰阶段（STEP 8-G+）
```

## 21. Final Decision
```
Nova adopts a fixed maximum supply of 1,000,000,000 NOVA.

The allocation is:
  Community/Public 50%
  Ecosystem       20%
  Team            12%
  Foundation       8%
  Genesis Validator 10%

Founder allocation = 0%.

No minting.
No inflation.
No burn.
No supply-cap increase.

Any future reward mechanism must operate within the existing
fixed supply and requires a separate ADR.

Status: FINAL
```

## 变更记录
| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-09-02 | ADR-0051 正式落盘与冻结：固定供应 1e9 · Allocation 50/20/12/8/10 · 无 mint/inflation/burn/cap 变更 · Team 120M/60mo/off-chain · Validator bootstrap 100M · ADR-0044 mint 方向 superseded | STEP 8-E.5（20/20 gates PASS）→ Owner Freeze 授权 → STEP 8-F 落盘（FINAL） |
