# Nova — Genesis Owner Data Template

> **用途**：STEP 8-J Genesis Finalization Input Preparation 的 Owner 数据输入模板。
> **性质**：**非生产、无私钥** 的文档模板——仅含 字段/用途/格式/是否必填/Owner 提供状态/验证规则。
>
> **禁止**：本文件**不得**包含任何真实私钥、seed、mnemonic、keystore password、硬件钱包秘密。
> Validator 私钥必须由 Owner 在受控环境离线生成并保存，**绝不允许进入本仓库**。
>
> **状态标记**：`PENDING`（Owner 未提供）· `CONFIRMED`（Owner 已提供并核验）· `BLOCKED`（冲突/非法）。
> 不得用 placeholder / random / AI-generated 填充任何生产字段。

设计基准（ADR-0051 FINAL，不可修改）：
```
MAX_SUPPLY = 1,000,000,000 NOVA
Community/Public 500,000,000 · Ecosystem 200,000,000 · Team 120,000,000
Foundation 80,000,000 · Genesis Validator 100,000,000
fee_burn_bps = 0 · No Mint
Validator count = 7 · Validator allocation = 100,000,000
allocation ≠ bonded（bonded = liquid → bonded 状态转换，非新增发行）
```

---

## A. Network Identity

| 字段 | 用途 | 格式 | 必填 | Owner 状态 | 验证规则 |
|---|---|---|---|---|---|
| `chain_id` | 网络标识；防重放/隔离 | `u64` 正整数 | ✅ | PENDING | 明确、稳定、Owner 确认；非 0 |
| `network_id` | 网络身份；防测试/主网混淆；**必须在所有生产地址派生前冻结** | `NetworkId`（协议类型） | ✅ | PENDING | 明确、稳定、Owner 确认；与全部地址 payload 一致 |
| `genesis_timestamp` | 创世时间锚点；Genesis hash 输入 | `u64`（协议 timestamp） | ✅ | PENDING | Owner 明确确认；不得使用当前时间自填 |

## B. Allocation Accounts（Community/Ecosystem/Team/Foundation）

| 字段 | 用途 | 格式 | 必填 | Owner 状态 | 验证规则 |
|---|---|---|---|---|---|
| `address` | Genesis 账户地址 | bech32m NovaAddress | ✅ | PENDING | network_id 匹配；编码/校验和/长度；canonical 表示 |
| `category` | 分配类别 | `Community/Public` `Ecosystem` `Team` `Foundation` | ✅ | PENDING | One Address One Category |
| `liquid_balance` | 账户初始余额 | `u128` 整数 NOVA | ✅ | PENDING | 参与 §E reconciliation |
| `owner approval` | Owner 授权记录 | 引用/批注 | ✅ | PENDING | 必须存在 |
| `custody classification` | 保管类别 | multisig / single / legal / future-distribution | ✅ | PENDING | 不得猜测具体实现 |
| `provenance record reference` | provenance 引用 | ADR-0052 记录标识 | ✅ | PENDING | 链外记录；不进 schema |
| ⛔ `private_key` / `seed` / `mnemonic` | — | — | **NEVER** | — | **绝不允许进入本文件/仓库** |

### 模板（4 行，每行对应一个账户）
```
Category | Address | Liquid Balance | Custody | Owner Approval | Provenance Ref | Status
```

## C. Validator V1-V7

| 字段 | 用途 | 格式 | 必填 | Owner 状态 | 验证规则 |
|---|---|---|---|---|---|
| `validator_id` | 标识 | V1..V7 | ✅ | PENDING | 唯一 |
| `account_address` | 验证者账户 | bech32m NovaAddress | ✅ | PENDING | 必须存在于 initial_accounts；network_id 匹配 |
| `consensus_public_key` | Ed25519 公钥 | `[u8;32]` hex | ✅ | PENDING | **公钥**可入 Genesis；私钥由 Owner 受控生成 |
| `liquid_allocation` | 账户 liquid（V 分配） | `u128` | ✅ | PENDING | Σ(V1..V7)=100,000,000 |
| `bonded_stake` | 质押（liquid→bonded） | `u128` | ✅ | PENDING | `bonded_stake ≤ liquid_allocation`；≥ min_validator_stake |
| `commission_bps` | 佣金 | `u16` ≤ 10_000 | ✅ | PENDING | 协议上限 |
| `identity/provenance reference` | 运营者身份引用 | 记录标识 | ✅ | PENDING | 链外记录 |
| `custody classification` | 运营者保管分类 | 描述 | ✅ | PENDING | — |
| `owner/operator approval` | 授权 | 引用/批注 | ✅ | PENDING | 必须存在 |
| ⛔ `private key` / `seed` / `mnemonic` | — | — | **NEVER** | — | 受控环境生成，绝不入库 |

### 模板（7 行）
```
ID | Account Address | Consensus PubKey | Liquid Allocation | Bonded Stake | Commission Bps | Provenance Ref | Status
```

## D. Custody Mapping（对应 ADR-0052 A-G LOCKED）

| Category | Address | Custody Type（Owner 提供） | Owner Approval | Provenance Ref | Status |
|---|---|---|---|---|---|
| Community/Public | TBD | A3 = multisig + future distribution | PENDING | PENDING | PENDING |
| Ecosystem | TBD | dedicated multisig | PENDING | PENDING | PENDING |
| Team | TBD | multisig + legal vesting | PENDING | PENDING | PENDING |
| Foundation | TBD | multisig | PENDING | PENDING | PENDING |
| Genesis Validator (V1-V7) | TBD | 运营者 | PENDING | PENDING | PENDING |

> 不自行猜测 multisig / single-sig / foundation-controlled / exchange-controlled 等具体实现。

## E. Allocation Reconciliation（填 Actual 后核验）

| Category | Target | Actual | Difference |
|---|---|---|---|
| Community/Public | 500,000,000 | TBD | TBD |
| Ecosystem | 200,000,000 | TBD | TBD |
| Team | 120,000,000 | TBD | TBD |
| Foundation | 80,000,000 | TBD | TBD |
| Genesis Validator | 100,000,000 | TBD | TBD |
| **TOTAL** | **1,000,000,000** | **TBD** | **TBD** |

```
Validator: Σ(V1..V7) = 100,000,000；Difference = 0
必须满足：TOTAL = 1,000,000,000 且 TOTAL Difference = 0
```

## F. Genesis Readiness Gate（填完数据后逐项）

| Gate | Requirement | Status |
|---|---|---|
| GATE-1 | chain/network/timestamp FINAL | BLOCKED |
| GATE-2 | ∀ validator liquid ≥ bonded | BLOCKED |
| GATE-3 | total = 1,000,000,000 | BLOCKED |
| GATE-3V | Σ validators = 100,000,000 | BLOCKED |
| GATE-4 | schema frozen（UNCHANGED） | PASS |
| GATE-5 | all production addresses confirmed | BLOCKED |
| GATE-6 | validator public keys confirmed | BLOCKED |
| GATE-7 | custody mapping approved | BLOCKED |
| GATE-8 | provenance records complete | BLOCKED |

全部 GATE-1..8 = PASS 后方可进入 Genesis Generation（未来，需 Owner 明确批准）。

---

*本模板不含任何真实密钥/地址/经济数值。完成数据收集后，Owner 将基于本模板提供 CONFIRMED 数据。*
