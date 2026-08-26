# ADR-0020: Transaction Type Registry

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（设计冻结）
- 关联：ADR-0005（域）、ADR-0008（address_type）、ADR-0019（Transaction Schema）、
  `crypto-serialization-v1.md`（enum 编码）

## Context

`transaction_type`（TransactionV1 字段）必须由统一注册表管理；**未注册类型必须拒绝、禁止 fallback**。
与 `address_type` / `algorithm_id` 语义分离（各自独立注册表）。

## Decision（建议，待批准）

### Transaction Type Registry（`transaction_type: u8`）

| `transaction_type` | 交易类型 | 状态 |
|--------------------|----------|------|
| `0x00` | — | **无效 / 必须拒绝** |
| `0x01` | **Transfer**（转账） | **已批准**（V0.1 唯一） |
| `0x02` – `0xFF` | — | **Reserved（未分配，拒绝）** |

- **未知 / Reserved `transaction_type` ⇒ 解码/校验拒绝**（`UnknownTransactionType`），
  **禁止 fallback / 猜测**。
- 规则：
  1. 每个 `transaction_type` 定义自己的 `payload` 语义（V0.1 Transfer：`payload = empty`）。
  2. 新增交易类型必须经 ADR + 向量 + 实现评审（同 ADR-0012 注册流程）。
  3. `transaction_type` 与 `algorithm_id` / `address_type` 为**独立注册表**，禁止混用。

### V0.1 唯一组合

```
transaction_type = 0x01 Transfer
payload          = empty
receiver         = UserAccount only（Contract Reserved，ADR-0019 §13）
```

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 用 `payload` 区分交易类型 | 隐式、无注册表约束；无法静态拒绝未知类型 |
| 复用 `algorithm_id` 作为交易类型 | 语义混淆（算法 ≠ 交易类型） |

## Consequences

- **正面**：交易类型受控；未知类型静态拒绝；未来新类型经注册流程。
- **成本**：新增交易类型须升级 Transaction Version + 新 ADR（ADR-0019 §2 修订）。
- **可迁移**：Contract 调用 / Governance 等未来类型按序分配（`0x02+`）。

## Security Impact

- 防未知类型 fallback / 猜测（类型混淆）。
- 防 payload 语义漂移（每类型显式 payload 定义）。
