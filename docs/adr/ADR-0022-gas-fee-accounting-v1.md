# ADR-0022: Gas & Fee Accounting V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（Gas / Fee Accounting）
- 关联：ADR-0009（签名覆盖，gas_limit/gas_price 被签）、ADR-0014（fee_burn_bps）、ADR-0016（供应不变量）、
  ADR-0017（账户模型）、ADR-0019（交易 Schema §8/§9）、ADR-0021（流水线边界）、`crypto-serialization-v1.md`

## Context

Transaction 的 gas / fee 计算与校验必须一次冻结，且保持 **Consensus 规则** 与 **本地 Mempool Policy**
严格分离。7E 已把 `balance sufficiency` 划归 7F；7G 负责状态落账。本 ADR 冻结 **F1–F10**。

**职责流水线（硬边界）**：

```
7C Encoding → 7D Signature/Identity → 7E Nonce/Replay → 7F Gas/Fee → 7G State Transition
```

**7F 只做（纯计算 + admission 预检）**：`fee_max` / `required` / `actual_fee` / `burn` 的 checked 计算、
`gas_limit>0` / `gas_price>0` / `gas_used<=gas_limit` 校验、**balance sufficiency**。
**7F 不做**：nonce 写入 / 扣费落账 / revert（7G）、区块 `max_gas_per_block` 聚合（7G/Block STEP）、
Mempool 本地策略（Mempool STEP）、验证者奖励 / treasury（Economics/PoS Phase）。

## Decision（建议，待批准）

### 1. F1 — fee_max 计算（Consensus，已冻结 ADR-0019 §8）

```rust
compute_fee_max(gas_limit: u64, gas_price: u128) -> Result<u128, GasFeeError::FeeMaxOverflow>
```

- `checked_mul`；溢出 ⇒ `FeeMaxOverflow`（Reject）。**禁** wrap / panic。

### 2. F2 — required 计算（Consensus，已冻结 ADR-0019 §8）

```rust
compute_required(amount: u128, fee_max: u128) -> Result<u128, GasFeeError::RequiredOverflow>
```

- `checked_add(amount, fee_max)`；溢出 ⇒ `RequiredOverflow`（Reject）。

### 3. F3 — balance sufficiency（Consensus，7F 职责）

```rust
check_balance_sufficient(balance: u128, required: u128) -> Result<(), GasFeeError::InsufficientBalance>
```

- `balance >= required` 否则 `InsufficientBalance`（Reject）。
- 纯判断（不扣款）；7G 执行时用真实 state 调用（**Admission snapshot 非执行保证**，ADR-0019 §15）。

### 4. F4 — V0.1 Transfer intrinsic gas（Consensus）

```rust
pub const TRANSFER_INTRINSIC_GAS: u64 = 21_000;   // core 常量，非 genesis 字段
```

- V0.1 Transfer 无 WASM 执行，`gas_used = TRANSFER_INTRINSIC_GAS`（与 payload 无关，payload 恒空）。
- **位置**：`nova-core` 常量（**非** ProtocolParamsV1 —— 不改 genesis hash）。
- 数值 `21_000`（对齐 EVM 生态惯例）。未来交易类型 / WASM 引入时经新 ADR。

### 5. F5 — actual_fee 与 gas_used 约束（Consensus，已冻结 ADR-0019 §9）

```rust
check_gas_used(gas_used: u64, gas_limit: u64) -> Result<(), GasFeeError::GasExceedsLimit>
compute_actual_fee(gas_used: u64, gas_price: u128) -> Result<u128, GasFeeError::ActualFeeOverflow>
```

- `gas_used <= gas_limit` 必须（否则 `GasExceedsLimit`）。
- `actual_fee = checked_mul(gas_used, gas_price)`（因 `gas_used <= gas_limit` 且 `fee_max` 不溢出，
  故不溢出；仍 checked 防御）。
- V0.1 下 `actual_fee = TRANSFER_INTRINSIC_GAS × gas_price`（恒 ≤ `fee_max`）。

### 6. F6 — fee settlement 方式（Consensus）

- **只扣 `actual_fee`**（非 `fee_max`）；gas 未用部分**不扣、不退**（Mempool 不预扣，ADR-0019 P3）。
- 成功执行扣款 = `amount + actual_fee`（7G 应用 checked_sub）；admission 已保证
  `balance >= amount + fee_max >= amount + actual_fee`（7G 仍重新 checked，防同区块前序消耗）。

### 7. F7 — fee burn 语义（Consensus；关联 ADR-0016 修订）

```rust
compute_burn(actual_fee: u128, fee_burn_bps: u16) -> Result<u128, GasFeeError::BurnOverflow>
// burn = actual_fee * fee_burn_bps / 10_000（整数除法向下取整）
```

- 前置：`fee_burn_bps <= 10_000`（Genesis 已保证）；`burn <= actual_fee`。
- **`total_supply` 为供应上限（cap）**，不因 burn 递减（Genesis 承诺不可变）；销毁量计入
  `burned_supply` 累计（STEP 7G state），持续不变量：
  `Σ liquid + Σ bonded + burned_supply <= total_supply`（ADR-0016 §4 修订，**不改 genesis hash**）。
- 7F 冻结计算规则；`burned_supply` 落账由 7G 实现。

### 8. F8 — revert / failure charging（Consensus）

- V0.1 Transfer 唯一执行失败场景 = 执行时 balance insufficient（同区块前序消耗后不足）。
- **valid-but-failed ⇒ 不扣费、不增长 nonce、无状态改变**（与 invalid 一致；V0.1 无复杂 revert）。
- nonce 语义由 7G 最终落账（本 ADR 只冻结 gas 侧：失败不扣费）。

### 9. F9 — overflow 防护与错误分类（Consensus）

```rust
pub enum GasFeeError {
    FeeMaxOverflow,      // F1
    RequiredOverflow,    // F2
    ActualFeeOverflow,   // F5（防御）
    BurnOverflow,        // F7
    InsufficientBalance, // F3
    InvalidGasParams,    // gas_limit==0 / gas_price==0（F10）
    GasExceedsLimit,     // gas_used > gas_limit（F5）
}
```

- 所有运算 checked；**禁** panic / 回绕 / silent saturation。
- 未来 admission 组合 `TransactionValidityError::Fee(GasFeeError)`（7F 起）。

### 10. F10 — gas 参数校验与 consensus/policy 边界

- `gas_limit > 0` / `gas_price > 0` ⇒ **Consensus** 字段约束（`InvalidGasParams`；7B 已冻结字段存在）。
- `max_gas_per_block`（ProtocolParamsV1）：区块级 **Consensus** 上限，7G/Block STEP 应用，**7F 不聚合**。
- **min gas price**：ProtocolParamsV1 **无**此字段 ⇒ **无共识 min gas price**；Mempool 本地可配置
  （**Policy**，防 spam，非 consensus）。
- **7F 不向 ProtocolParamsV1 / EconomicsParamsV1 / consensus state 加入任何字段**（Genesis 已冻结）。

### 11. Decision Log（F1–F10）

| # | 决策 | 层 | 状态 |
|---|------|-----|------|
| F1 | `fee_max = gas_limit×gas_price`（checked，溢出 Reject） | Consensus | 冻结 |
| F2 | `required = amount + fee_max`（checked，溢出 Reject） | Consensus | 冻结 |
| F3 | 执行时 `balance >= required` | Consensus | 冻结 |
| F4 | `TRANSFER_INTRINSIC_GAS = 21_000`（core 常量） | Consensus | 冻结 |
| F5 | `gas_used <= gas_limit`；`actual_fee = gas_used×gas_price`（checked） | Consensus | 冻结 |
| F6 | 只扣 `actual_fee`（不预扣、不退） | Consensus | 冻结 |
| F7 | burn = `actual_fee×bps/10000`；`total_supply` 为 cap，burned 累计 | Consensus | 冻结 |
| F8 | valid-but-failed ⇒ 不扣费、不改 nonce、无状态改变 | Consensus | 冻结 |
| F9 | 全部 checked；GasFeeError 分类 | Consensus | 冻结 |
| F10 | gas>0 约束 Consensus；min gas price 为 Mempool Policy；max_gas_per_block 归 7G/Block | Consensus+Policy | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 扣 `fee_max`（预扣） | 与 P3 "Mempool 不预扣费"冲突；gas 未用部分语义复杂 |
| intrinsic gas 进 ProtocolParamsV1 | 改动 genesis 字段 ⇒ 破坏已冻结 genesis hash |
| V0.1 burn 改变 `total_supply` 常量 | Genesis 承诺不可变；cap 语义更稳（ADR-0016 §4 修订） |
| failure 扣部分费 | V0.1 无计算；balance 可能连 fee 都不足 ⇒ 语义复杂；无副作用最简 |
| 共识 min gas price | ProtocolParamsV1 无此字段；防 spam 属 Mempool 本地策略 |

## Consequences

- **正面**：gas/fee 计算与错误分类一次冻结；Consensus/Policy 边界清晰；7G 获得无歧义前置。
- **成本**：`TRANSFER_INTRINSIC_GAS` 为 V0.1 常量，未来交易类型需新 ADR。
- **可迁移**：WASM / 新交易类型 / treasury / validator reward 经对应 Phase + 新 ADR。

## Security Impact

- 防溢出：fee_max/required/actual_fee/burn 全部 checked（F9）。
- 防余额破坏：balance sufficiency + 7G checked_sub（F3/F6）。
- 防供应破坏：burn 不改变 total_supply cap，burned 累计（F7/ADR-0016）。
- 防区块 gas 超限：max_gas_per_block 由 7G/Block STEP 应用（F10）。
- 防 spam：无共识 min gas price；Mempool 本地 policy（F10）。
