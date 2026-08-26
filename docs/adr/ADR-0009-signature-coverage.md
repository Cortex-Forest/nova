# ADR-0009: Signature Coverage Specification

- **Status**: Proposed（待批准）
- **Date**: 2026-08-25
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0005（域分离）、`docs/protocols/crypto-serialization-v1.md`（canonical 编码）

## Context

每个被签名对象必须**显式定义签名覆盖的字段**（Signature Coverage），防止签名覆盖 bug
（例如：改了一个未签名字段，签名仍然有效；或签名覆盖了本不该覆盖的字段）。

**禁止**："整个 struct 序列化后直接 hash"——除非 canonical serialization 已完全定义
（见 `docs/protocols/crypto-serialization-v1.md`）。V0.1 统一采用**显式字段级签名覆盖**。

## 原则

1. 每个签名对象有**显式的签名字段清单**（field order 固定，与 canonical 编码一致）。
2. 签名不覆盖：signature 字段自身、执行后派生数据（receipt/gas_used）、元数据。
3. 签名字段在对象定义中标注（如 `#[signed]`），由规范强制而非靠实现自觉。
4. 覆盖清单变化 = 协议版本变更（须新 ADR）。

## 各对象签名覆盖（待对应 Phase 规范最终定稿）

### 1. Transaction（PHASE 3 交易模型 ADR-0019 定稿）

**签名字段**（顺序固定，canonical 编码）：

```
version || chain_id || nonce || sender || receiver || amount
|| gas_limit || gas_price || transaction_type || payload || expiration
```

- **V0.1 `fee_payer = sender`**：不设置独立 `fee_payer` 字段（ADR-0019 §1）。
  未来引入 fee delegation ⇒ **必须升级 Transaction Version + 新 ADR**（不得向后兼容新增）。

**不签名**：`signature` 自身；`txid`（= SHA-256(canonical_tx_payload ‖ signature)，
完整交易承诺）；执行后派生数据（`gas_used`/`receipt`/`events`）。

### 2. Validator Vote（PHASE 9/10 共识规范定稿）

**签名字段**：

```
round || height || target_block_hash || vote_type
|| source_block_hash (如可) || validator_id || timestamp
```

**不签名**：`signature` 自身；聚合/转发元数据。

### 3. Block（PHASE 7 区块规范定稿）

**Proposer 签名字段**（header 承诺字段）：

```
version || chain_id || height || parent_hash || finality_reference
|| transaction_root || state_root || validator_set_hash || timestamp
```

**不签名**：`block_hash`（自身 hash 不纳入计算，Master Prompt §23）、`signature` 自身、
交易列表（由 `transaction_root` 承诺，无需逐笔签名）。

### 4. Governance（PHASE 后续治理 ADR 定稿）

**签名字段**：

```
proposal_id || action || params_hash || timelock || nonce
```

**不签名**：投票计数、执行结果（链上派生）。

## 一致性要求

- 所有签名消息必须先构造 `SHA-256(dst || chain_id || 签名覆盖字段的 canonical 编码)`（ADR-0005/0010）。
- 签名覆盖字段的编码顺序必须与 `crypto-serialization-v1.md` 的 canonical 规则一致，保证跨实现一致验证结果
  （Strict Verification，ADR-0002 §4）。
- 每类对象的覆盖清单是**规范的一部分**，实现必须逐字段核对；fuzz/property 测试须覆盖字段级
  篡改检测（改任意签名字段 ⇒ 验签失败；改任意非签名字段 ⇒ 不影响验签）。

## Security Impact

- 显式覆盖清单 ⇒ 消除 signature coverage bug。
- 防"签名剥离"：非签名字段不可被攻击者用于改变语义而不被检测。
- 覆盖清单变更走协议版本化，防止悄悄扩大/缩小签名范围。
