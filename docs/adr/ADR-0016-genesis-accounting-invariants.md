# ADR-0016: Genesis Accounting Invariants

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography（Genesis canonical data）
- 关联：ADR-0014（Genesis Schema V1）、ADR-0015（canonical 编码）、`genesis-v1.md`

## Context

Genesis 初始化必须明确账户与质押的账务语义，防止：stake double counting、supply inflation、
未追踪供应缺口（"总量 81M 但 Genesis 只出现 60M"）。

## Decision（建议，待批准）

### 1. 术语

- `AccountInit.liquid_balance`：Genesis 初始化**之前**该账户拥有的 liquid balance。
- `ValidatorInit.bonded_stake`：从对应 validator 账户的 liquid balance 中**转入 staking state**
  的金额。

### 2. Stake 划转语义

- 每个 validator 的 `account_address` **必须**出现在 `initial_accounts` 中
  （否则 `GenesisError::InvalidStake`）。
- 必须验证：

  ```
  bonded_stake <= corresponding AccountInit.liquid_balance
  ```

  （违反 ⇒ `GenesisError::InvalidStake`）
- Genesis 初始化后：

  ```
  final_liquid_balance = initial_liquid_balance - bonded_stake
  ```

- bonded stake **进入 staking state**，**不得再次计入 total supply**。

### 3. 总量不变量（Total Supply Invariant）

```
total_initial_account_balances = Σ AccountInit.liquid_balance
```

- **Validator bonded stake 不是额外 supply**。
- **V0.1 决策：全部供应量在 Genesis 分配**，即：

  ```
  total_supply == total_initial_account_balances
  ```

- 若未来引入未分配供应（treasury/unallocated），**必须**经 ADR 修订并**明确剩余供应去向**；
  绝对不允许"总量已定但 Genesis 未出现、去向不明"。

### 4. 无通胀 / 无销毁

- Genesis 初始化**不创造、不销毁**供应量。
- `total_supply` 是协议承诺的供应上限；Genesis 后状态必须满足：
  `Σ final_liquid_balance + Σ bonded_stake == total_supply`。

### 5. 溢出防护

- 所有求和（`Σ liquid_balance`、stake 划转差）使用 **checked arithmetic**；
  溢出 ⇒ `GenesisError::SupplyInvariantViolation`（禁止 panic / 回绕）。

### 6. 校验归属（ValidateGenesis 步骤 8）

- stake accounting 校验在 validator/account 校验之后、economics 校验之前执行
  （顺序见 `genesis-v1.md` §10）。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| bonded stake 另计为 supply | 双重计入 ⇒ supply inflation（T：stake double counting） |
| 允许未分配供应且不追踪去向 | 供应缺口不可审计，违反"去向明确"原则 |
| 使用 unchecked 加法 | 溢出回绕 ⇒ 供应破坏（禁止 panic/fallback 纪律） |

## Consequences

- **正面**：Genesis 账务完全可审计；`total_supply` 与 Genesis 内部分配严格一致。
- **成本**：validator 账户必须显式出现在 `initial_accounts`（配置必须完整）。
- **可迁移**：未来 treasury 分配需 ADR 修订 + 明确去向。

## Security Impact

- 防 stake double counting / supply inflation（T：经济攻击）。
- 防溢出回绕导致供应破坏。
- 防"丢失供应"配置错误（总量必须等于 Genesis 内部分配之和）。
