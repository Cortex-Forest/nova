# ADR-0005: Domain Separation

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（修订：DST 字符串 → domain_id 注册表）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0009（签名覆盖）、ADR-0010/0011（链身份）、ADR-0012（algorithm_id）、crypto-serialization-v1.md

## Context

不同对象（交易、验证者投票、区块、地址派生、治理）**不得直接签名相同的裸哈希**，
否则可发生跨域重放（例如：把交易签名重放到投票上）。必须引入域分离 + chain_id。

## Decision（建议，待批准）

**统一签名消息结构（canonical，无拼接歧义）**：

```
signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE)
               || payload_length(4B LE) || payload(canonical)

message_hash = SHA-256(signed_bytes)
```

其中 `H` = SHA-256（ADR-0006），`||` 为拼接。**各段编码（冻结于 `crypto-serialization-v1.md`）**：

| 段 | 编码 |
|----|------|
| `algorithm_id` | `u8`（ADR-0012 Algorithm Registry）；**进入 signed bytes**（显式算法绑定，防 algorithm confusion） |
| `domain_id` | `u8`（Nova Domain Registry，见下） |
| `chain_id` | `u64` **little-endian**（8 字节，ADR-0010/0011） |
| `payload_length` | `u32` **little-endian**（4 字节，payload 字节数） |
| `payload` | 签名覆盖字段的 canonical 编码（ADR-0009） |
| 字段顺序 | **固定**：`algorithm_id \|\| domain_id \|\| chain_id \|\| payload_length \|\| payload`，禁止重排 |

> 说明：以定长 `u8` 的 `domain_id` 替代字符串 DST；**不假设任意 ASCII DST 等长**；
> **禁止使用未定义长度的字符串直接拼接**。

**无歧义证明**：
- `algorithm_id`（1B）、`domain_id`（1B）、`chain_id`（8B）长度固定 ⇒ 边界固定，不依赖内容；
- `payload_length` 显式前缀 ⇒ 与后续数据边界明确；
- 不存在两种不同 `(algorithm_id, domain_id, chain_id, payload)` 产生相同 `signed_bytes` 的情况
  （canonical，防 domain collision）。

**Nova Domain Registry（domain_id: u8）**：

| `domain_id` | 域 | 用途（签名覆盖见 ADR-0009） |
|-------------|-----|------------------------------|
| `0x01` | Transaction | 交易签名（ADR-0009 §1） |
| `0x02` | ValidatorVote | 共识投票签名（ADR-0009 §2） |
| `0x03` | Block | 区块承诺签名（ADR-0009 §3） |
| `0x04` | Governance | 治理提案/投票（ADR-0009 §4） |
| `0x05` | Address | 地址派生（key_hash 计算，ADR-0004） |
| `0x00` / `0x06+` | — | **Reserved / 未注册 ⇒ 必须拒绝** |

**约束**：
- 每个域都必须绑定 `chain_id`（ADR-0010/0011；防跨链重放，Master Prompt §10）。
- **签名上下文 = `algorithm_id + domain_id + chain_id + canonical_payload`**（ADR-0012；
  与上表字段顺序一致：`algorithm_id` 在前，进入 signed bytes——显式算法绑定；
  即使 domain separation 已足够，显式纳入提供纵深防御，且签名自包含算法信息）。
- Ed25519 统一采用"前置域哈希"方案（对 `signed_bytes` 做 SHA-256 后签名），
  不依赖 RFC 8032 context 扩展（跨方案一致、避免实现差异）。
- 未来新增任何签名域必须先在本 ADR 登记 `domain_id`，禁止临时编码。
- `chain_id` 与 `network_id` 的关系见 ADR-0010/0011（签名只绑定 `chain_id`）。

## Alternatives（已评估）

| 方案 | 评估 |
|------|------|
| 直接签名裸 payload hash | 跨域重放风险 ❌ |
| 仅 chain_id 前缀、无 DST | 同链内跨域（交易↔投票）无法区分 ❌ |
| Ed25519 context（RFC 8032 §5.2） | 依赖实现支持，跨库行为不一致；统一走前置 domain_id 签名上下文更稳 ✅ |

## Consequences

- **正面**：跨域/跨链重放被 domain_id + chain_id 双重阻止；单一规范化消息构造。
- **成本**：所有签名路径必须先构造带 domain_id/algorithm_id 的签名上下文（实现约定统一）。
- **可迁移**：新增域只需登记新 domain_id，不影响已有签名。

## Security Impact

- DST + chain_id 构成**双因子**域分离，是防重放的核心防线（配合 nonce，见 PHASE 4）。
- 定长 `u8` domain_id 消除长度歧义（与 SHA-256 的 Merkle-Damgård 结构配合时尤为重要）。
- `algorithm_id` 进入 signed bytes ⇒ 防 algorithm confusion（T16）。
- 禁止把 domain_id 拼进用户可控 payload（防止域注入）。
