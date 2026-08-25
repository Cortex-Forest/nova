# Nova Chain Crypto Test Vectors v1（协议冻结）

- **Status**: Frozen（待批准）
- **Date**: 2026-08-26
- **Scope**: PHASE 2 — Cryptography
- **用途**：跨实现一致性验证；所有向量为**确定性断言**（相同输入 ⇒ 相同接受/拒绝结果）。
- 关联：`crypto-serialization-v1.md`、ADR-0004/0005/0008/0009/0010/0011/0012

## 1. Address 向量

| 类别 | 断言 |
|------|------|
| valid | 合法地址可解码，字段正确 |
| invalid checksum | 校验码错误 ⇒ 拒绝 |
| invalid HRP | HRP 非注册值（非 `nova`/`novat`/`novad`）⇒ 拒绝 |
| invalid version | `address_version` 不支持 ⇒ 拒绝 |
| invalid address type | `address_type` 未注册 ⇒ 拒绝（`InvalidAddressType`） |
| invalid network | `network_id` 与当前网络不匹配 ⇒ 拒绝 |
| corrupt payload | 数据损坏 ⇒ 拒绝 |
| roundtrip | `encode(decode(a)) == a_canonical`；`decode(encode(p)) == p` |

补充：uppercase / mixed case / truncated address / altered character / malformed data
（见 ADR-0004 测试要求）。

## 2. Domain 向量

| 类别 | 断言 |
|------|------|
| each domain ID | 每个注册 `domain_id` 产生确定且不同的签名消息前缀 |
| each chain ID | 每个 `chain_id` 产生确定且不同的签名消息 |
| same payload across domains | 相同 payload 在不同 `domain_id` 下 ⇒ 消息哈希**不同** |
| same payload across chains | 相同 payload 在不同 `chain_id` 下 ⇒ 消息哈希**不同** |
| domain collision check | 不存在两个不同 `(domain_id, chain_id, payload)` 产生相同 `signed_bytes` |

## 3. Signature 向量

| 类别 | 断言 |
|------|------|
| valid | 正确签名可验证通过 |
| malformed | 畸形签名 ⇒ 拒绝 |
| truncated | 截断签名 ⇒ 拒绝 |
| oversized | 超长/额外字节 ⇒ 拒绝 |
| wrong public key | 错误公钥验证 ⇒ 失败 |
| wrong chain | 使用错误 `chain_id` 构造 ⇒ 验签失败 |
| wrong domain | 使用错误 `domain_id` 构造 ⇒ 验签失败 |
| wrong algorithm | 使用错误 `algorithm_id` 构造 ⇒ 验签失败 |
| canonical | 非 canonical 公钥/签名编码 ⇒ 拒绝（Strict Verification，ADR-0002） |

### 3b. Signature 向量完整链路 Schema（评审 §16）

每个签名测试向量必须包含以下字段，以验证**完整协议链路**：

```
{
  "algorithm_id": u8,
  "domain_id":    u8,
  "chain_id":     u64,
  "canonical_payload": hex,
  "signed_bytes":      hex,      // 由上下文构造（测试器独立重算比对）
  "message_hash":      hex(32B), // SHA-256(signed_bytes)
  "public_key":        hex(32B),
  "signature":         hex(64B),
  "expected": "valid" | "invalid" | "malformed" | ...
}
```

- 测试器必须**独立重算** `signed_bytes` 与 `message_hash` 并与向量比对（防向量内部不一致）。
- 覆盖：valid / malformed / truncated / oversized / wrong key / wrong chain / wrong domain /
  wrong algorithm / canonical 拒绝。

## 4. 来源

- 地址编码：官方 Bech32m test vectors + Nova 自定义 vectors（ADR-0004）。
- Ed25519：RFC 8032 测试向量 + Nova 自定义（ADR-0002）。
- 签名消息：Nova 自定义（本文件 §2/§3）。
