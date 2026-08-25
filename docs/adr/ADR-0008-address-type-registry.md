# ADR-0008: Address Type Registry

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（修订：address_type 语义与 algorithm_id 分离）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0002（签名方案）、ADR-0004（地址格式）、ADR-0012（algorithm_id 分离）、Threat Model（algorithm confusion / address type confusion）

## Context

地址中的 `address_type` 字段必须由**统一注册表**管理，防止地址类型误用。**未注册的类型必须被拒绝**。
**关键区分**（用户评审要求）：
- **`address_type` = 账户/地址语义**（Account semantics），如 User Account / Contract；
- **`algorithm_id` = 密码学签名算法**（Cryptographic algorithm），见 **ADR-0012**；
- **两者不是同一概念，禁止隐式映射**：验证算法必须来自签名上下文中的 `algorithm_id`，
  不允许从 `address_type` 隐式推断。二者允许的组合由**显式映射表**约束。

## Decision（建议，待批准）

### AddressType Registry（账户/地址语义）

| `address_type` | 语义 | 状态 |
|----------------|------|------|
| `0x00` | 未定义/无效 | **必须拒绝**（解码错误） |
| `0x01` | **User Account**（个人账户） | **已批准**（V0.1） |
| `0x02` | Contract（合约账户） | **Reserved**（PHASE 12 WASM 合约） |
| `0x03` – `0xFF` | 未分配 | **Reserved**；必须拒绝（解码错误） |

### 与 `algorithm_id` 的分离（ADR-0012）

- `address_type`（本 ADR）= 账户/地址语义；
- `algorithm_id`（ADR-0012）= 密码学签名算法（Ed25519 / secp256k1 / future PQ）；
- **禁止隐式映射**：签名验证必须显式使用签名上下文中的 `algorithm_id`（ADR-0005）选择算法，
  **不允许**从 `address_type` 隐式推断算法而不校验。

**显式映射表（允许组合）**：

| `address_type` | 允许的 `algorithm_id` | 说明 |
|----------------|------------------------|------|
| `0x01` User Account | `0x01` Ed25519 | V0.1 唯一组合 |
| `0x02` Contract（Reserved） | 未来定义 | PHASE 12 定稿 |

### 规则

1. **未注册 `address_type` 必须拒绝**：解码失败，禁止猜测、禁止 fallback 到默认类型。
2. **注册流程**：新地址语义须提交 ADR + 评审；地址派生域（ADR-0005 `domain_id=0x05`）与
   签名覆盖（ADR-0009）必须同步扩展；算法组合须更新映射表。
3. **校验顺序**：地址解码（`address_type` 注册表）→ 签名验证（`algorithm_id` 注册表，
   ADR-0012）→ 组合校验（映射表）。任何一步失败即拒绝。

### 无效类型行为（Address Decoding Rules 补充，见 ADR-0004）

- `address_type = 0x00` 或未注册值 → **解码失败**（`InvalidAddressType`）。
- 解码失败不产生地址对象，不触发任何验证路径。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 用 `u8` 裸值不做注册表 | 地址类型混淆风险、无演进约束 |
| 用版本号代替类型 | 类型与版本混淆；无法区分账户语义 |
| `address_type` 兼任算法 | 语义混淆（账户类型 ≠ 算法）；无法支持"同账户类型换算法" ❌ |
| 解码时自动探测算法 | 无法可靠探测、扩大攻击面 ❌ |

## Consequences

- **正面**：`address_type` 演进受控；与 `algorithm_id` 分离支持"同账户语义换算法"（如未来 PQ）。
- **成本**：新增地址语义/算法须走完整注册流程（预期内的治理成本）。
- **可迁移**：地址格式不变，仅扩展注册表；算法迁移只影响 `algorithm_id`（ADR-0012）。

## Security Impact

- 未注册 `address_type` 拒绝 ⇒ 防 address type confusion（T17）。
- `algorithm_id` 显式进入 signed bytes + 映射表校验 ⇒ 防 algorithm confusion（T16）。
- `address_type` ↔ `algorithm_id` 显式分离 ⇒ 防"把 Ed25519 公钥当 secp256k1 验证"类攻击。
- 详细威胁见 `docs/security/crypto-threat-model.md`（T-can-en / T-addr-conf / T-alg-conf）。
