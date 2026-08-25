# Nova Chain Crypto Serialization Specification v1（协议冻结）

- **Status**: Frozen（待批准）
- **Date**: 2026-08-26
- **Scope**: PHASE 2 — Cryptography
- **权威性**：以后协议代码必须**严格依赖本文件**；任何偏离须经 ADR。
- 关联：ADR-0004（地址）、ADR-0005（域分离）、ADR-0009（签名覆盖）、ADR-0010/0011（链身份）、ADR-0012（算法注册表）

## 1. 字节序（Integer Endian）

- 所有多字节整数（`u16`/`u32`/`u64`/`u128`）统一 **little-endian（LE）**。
- `u8` 为单字节，直接编码。

## 2. 长度编码（Length Encoding）

- 变长字节数据使用 **`u32` LE 长度前缀**（值为字节数）。
- 固定长度数据**不带**长度前缀（长度由类型决定）。

## 3. 定长字节（Fixed Bytes）

- 定长字节数组按声明顺序原样编码（无长度前缀）。

## 4. Option 编码（Option Encoding）

- 1 字节 tag：`0x00` = `None`，`0x01` = `Some`；`Some` 后跟值（长度/编码由类型决定）。
- 其他 tag 为 **forbidden**。

## 5. Enum 编码（Enum Encoding）

- `u8` discriminant（注册表值：`domain_id` / `algorithm_id` / `address_type` / `network_id`）。
- **未注册 discriminant ⇒ 解码失败**（不猜测、不 fallback）。

## 6. 字段顺序（Field Ordering）

- 固定顺序，**禁止重排**；顺序由对象规范（transaction/block/vote）逐字段定义（ADR-0009）。

## 7. 禁止表示（Forbidden Representations）

以下非 canonical 表示**必须拒绝**：
- 多余/尾随填充字节；
- 非压缩或畸形椭圆曲线点编码；
- 非规范标量（≥ 群阶）；
- 非规范签名（非规范 `S`、额外尾随字节、非 canonical 点编码）；
- 未知 enum discriminant / option tag；
- 非 minimal 长度前缀（如用 5 字节前缀表达 4 字节数据）。

## 8. Canonical 规则

- 每个对象**唯一可解码**（唯一字节表示）。
- Roundtrip 性质（必须满足并被测试）：
  - `encode(decode(address)) == address_canonical`
  - `decode(encode(payload)) == payload`

## 9. 密码学对象编码

| 对象 | 编码 | 大小 |
|------|------|------|
| 协议哈希（SHA-256） | 原始字节 | 32 B |
| Ed25519 公钥 | 压缩点（RFC 8032） | 32 B |
| Ed25519 签名 | `R(32) \|\| S(32)` | 64 B |
| secp256k1 公钥（Reserved） | 压缩点 `0x02/0x03 \|\| x` | 33 B |
| secp256k1 签名（Reserved） | `r(32) \|\| s(32)`（归一化 `s`） | 64 B |
| 地址 | Bech32m-derived 文本（ADR-0004） | 文本 |
| `domain_id` | `u8`（ADR-0005） | 1 B |
| `algorithm_id` | `u8`（ADR-0012） | 1 B |
| `chain_id` | `u64` LE（Genesis 明确配置固定值，非派生；ADR-0010、`genesis-v1.md`） | 8 B |
| `network_id` | `u8`（ADR-0011） | 1 B |

## 10. 签名流水线（冻结）

**术语澄清（消除混淆）**：

| 术语 | 定义 |
|------|------|
| `canonical_payload` | 签名覆盖字段的 canonical 编码（ADR-0009） |
| `signature context` | `algorithm_id \|\| domain_id \|\| chain_id \|\| payload_length`（含 payload） |
| `signed_bytes` | 完整上下文 + payload 的字节串（见下） |
| `message_hash` | `SHA-256(signed_bytes)`（32B）——**Ed25519 签名的输入** |

```
canonical_payload
      ↓
signature context（algorithm_id ‖ domain_id ‖ chain_id ‖ payload_length ‖ canonical_payload）
      ↓
signed_bytes
      ↓
SHA-256
      ↓
message_hash [32 bytes]
      ↓
Ed25519 signing / verification
```

```
signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE)
               || payload_length(4B LE) || payload(canonical)
message_hash = SHA-256(signed_bytes)
```

**Nova V0.1 Ed25519 签名的输入是 `SHA-256(signed_bytes)`（即 `message_hash`）**，
**不是**：raw transaction bytes / canonical payload / 任意用户消息。

**API（防 bypass）**：
```
build_signed_bytes(...)        -> Vec<u8>                        // 构造 signed_bytes
hash_signing_message(...)      -> SigningMessageHash([u8; 32])    // message_hash newtype
sign_message_hash(...)         -> Signature
verify_message_hash(...)       -> Result<(), CryptoError>
```
- 普通 `[u8;32]` 不能直接作为协议签名消息（`SigningMessageHash` newtype 强制，ADR-0013）。
- **唯一验证路径**：`canonical payload → context → signed_bytes → SHA-256 → SigningMessageHash → verify_strict`。
- 字段顺序固定，禁止重排（`algorithm_id` 在最前，进入 signed bytes，ADR-0012）。
- `payload` 为签名覆盖字段的 canonical 编码（ADR-0009）。
- **`chain_id` 必须来自 Genesis 明确配置的固定值**（`genesis-v1.md`）；**不得从**
  `genesis_hash` / `block_hash` / `address` / `network_id` **派生**。
- 禁止使用未定义长度的字符串直接拼接。
