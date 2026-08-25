# ADR-0012: Cryptographic Algorithm Registry

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography（冻结）
- 关联：ADR-0002（账户签名）、ADR-0005（签名上下文）、ADR-0008（address_type 分离）

## Context

必须定义 **`algorithm_id`** 注册表（密码学签名算法），并明确：**未注册算法必须拒绝、禁止 fallback**。
同时必须与 **`address_type`**（账户/地址语义）**分离**——两者不是同一概念（用户评审要求）。

## Decision（建议，待批准）

### Algorithm Registry（`algorithm_id: u8`）

| `algorithm_id` | 算法 | 状态 |
|----------------|------|------|
| `0x00` | — | **无效 / 必须拒绝** |
| `0x01` | **Ed25519**（RFC 8032） | **已批准**（默认账户签名，ADR-0002） |
| `0x02` | secp256k1 | **Reserved**——具体方案（ECDSA vs BIP-340 Schnorr）**未定**；实现前必须重新批准 |
| `0x03` | Post-Quantum（TBD） | **Reserved future** |
| `0x04` – `0xFF` | — | **Reserved**（必须拒绝） |

### 规则

1. **未注册算法必须拒绝**（`InvalidAlgorithmId`），禁止 fallback、禁止猜测。
2. **`algorithm_id` 进入 signed bytes**（签名上下文，ADR-0005）：
   - 签名上下文 = `algorithm_id + domain_id + chain_id + canonical_payload`；
   - `algorithm_id` 作为定长 `u8` 前缀进入签名消息 ⇒ 签名自包含算法信息，验证者无需猜测算法，
     从根本上防 algorithm confusion（T16）。
3. **与 `address_type` 分离**（ADR-0008）：
   - `address_type` = **账户/地址语义**（如 User Account / Contract）；
   - `algorithm_id` = **密码学签名算法**；
   - **禁止隐式映射**：签名验证必须显式使用签名上下文中的 `algorithm_id` 选择算法，
     不允许从 `address_type` 隐式推断算法而不校验。
   - 二者允许的**组合**由显式映射表约束（ADR-0008），但映射**不构成隐式强制**——校验仍以
     `algorithm_id` 为准。

### 注册流程（新增算法）

1. 提交 ADR + 独立密码学评审 + 测试向量 + 实现审查。
2. 明确：公钥/签名编码、canonical 验证规则、域注册（ADR-0005）、签名覆盖（ADR-0009）、
   地址映射（ADR-0008）。
3. 未完成全套评审前，`algorithm_id` 一律保持 Reserved。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 用 `address_type` 兼任算法 | 语义混淆（账户类型 ≠ 算法）；无法支持"同账户类型换算法" |
| 算法不进 signed bytes | 验证者需外部推断算法，algorithm confusion 风险 |
| 用版本字符串做算法标识 | 长度不定、易歧义（冻结要求定长） |

## Consequences

- **正面**：算法演进受控；签名自包含算法信息（防混淆）；未来 PQ 算法经注册流程加入。
- **成本**：签名消息 +1 字节（`algorithm_id`）；新增算法须走完整注册流程。
- **可迁移**：PQ 迁移仅新增 `algorithm_id`（如 `0x03`）+ 地址/签名覆盖扩展，不改地址格式。

## Security Impact

- 未注册拒绝 ⇒ 防 algorithm confusion / key-hash substitution（T16/T22）。
- `algorithm_id` 进入 signed bytes ⇒ 防"替换算法重签"。
- 与 `address_type` 显式分离 ⇒ 防 address type confusion（T17）。
