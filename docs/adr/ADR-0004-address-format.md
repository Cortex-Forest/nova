# ADR-0004: Address Format

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（修订：地址长度定义、address_type 语义分离、roundtrip）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0008（address_type 语义）、ADR-0011（网络/HRP）、ADR-0012（algorithm_id）、crypto-serialization-v1.md

## Context

Nova 地址必须：唯一、可校验、有 network 前缀、有 checksum、可扩展（支持未来账户类型）。
不得把地址硬编码成单一公钥格式（Master Prompt §17）。

## Decision（建议，待批准）

采用 **Nova Custom Address Format using Bech32m-derived encoding**。

> **重要澄清**：Nova 使用 Bech32m 的**编码与校验机制**，但**不是 Bitcoin SegWit 地址**，
> **不声称 BIP-350 兼容**。HRP（human-readable part）**网络特定**（ADR-0011）：
> `nova`（mainnet）、`novat`（testnet）、`novad`（devnet）。

**解码后的数据部分（NovaAddressPayload，固定 35 字节）**：

```
NovaAddressPayload {
    address_version: u8,    // 地址格式版本（当前 0x01）
    address_type:    u8,    // 账户/地址语义（ADR-0008；非算法）
    network_id:      u8,    // 网络标识（ADR-0011）
    key_hash:        [u8; 32],  // SHA-256(public_key)
}
```
> **`address_type` 是账户语义，不是签名算法**；算法由签名上下文 `algorithm_id` 显式指定
> （ADR-0008 与 ADR-0012 分离，禁止隐式映射）。

- **`key_hash` 使用 32 字节（SHA-256 全输出，非截断）**：
  - 理由 1：SHA-256 完整 32B 输出，避免截断带来的额外碰撞概率与实现变体；
  - 理由 2：128 位碰撞安全（生日界）保持全额；20B 仅 80 位碰撞安全（偏弱）；
  - 理由 3：消除"截断长度"歧义（各实现必须一致用完整哈希）。
- **地址长度**：由 **HRP + 5-bit conversion + checksum** 共同确定（不预先声明"约 N 字符"）：
  - HRP 网络特定（ADR-0011）；
  - 35B payload 经 bech32 5-bit 转换（数据部分 56 个 5-bit 字符）+ 固定 6 字符校验码；
  - 最终长度由上述构成唯一确定，**必须通过 canonical vectors 验证**（`crypto-test-vectors-v1.md`）。
- **checksum**：复用 Bech32m 的 BCH 校验机制（固定 6 字符强校验），**不引入自定义校验算法**。

### 地址解码规则（Address Decoding Rules）

1. 文本 HRP 必须为当前网络注册的 HRP（ADR-0011；实现接受大小写但必须标准化后校验，规范统一为小写）。
2. Bech32m 校验码必须通过（复用 Bech32m 校验算法，官方 test vectors 验证）。
3. 解码出 35B payload，解析 4 个字段。
4. `address_version` ≠ 当前支持版本 → 拒绝（`UnsupportedAddressVersion`）。
5. `address_type` 必须命中 **ADR-0008 注册表**；**未注册类型必须拒绝**（`InvalidAddressType`）。
6. `network_id` 必须与节点网络参数匹配 → 否则拒绝（`NetworkMismatch`，ADR-0010）。
7. 任何步骤失败 ⇒ **解码失败**，不产生地址对象，不触发任何验证路径。

### 无效类型行为

- `address_type = 0x00` / 未注册值 ⇒ 解码错误（`InvalidAddressType`），**不猜测、不 fallback**。
- 完整规则由 ADR-0008 定义。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 自定 base32 + CRC32 | 无成熟校验实现、易错、生态工具缺失 |
| 以太坊式 `0x` hex + EIP-55 校验和 | 无 network 前缀、大小写校验易误用、无 address_type 显式字段 |
| 自称"BIP-350 地址" | 会造成"Bitcoin SegWit 兼容"误解，事实不符 ❌ |
| 直接 hex 公钥 | 长度长、无校验、无网络前缀 |
| 20 字节 key_hash | 碰撞安全偏弱（80 位）、有截断歧义 ❌（采用 32B） |

## Consequences

- **正面**：可读、可校验、防误输入、network 前缀防跨网混淆；`address_type`（ADR-0008 注册表）
  支持未来新签名算法（crypto agility，无需迁移地址）；32B key_hash 提供全哈希碰撞安全。
- **成本**：地址文本较长（长度由 HRP+5-bit+checksum 确定）；需要成熟 Bech32m 编码/解码库；地址不直接可推导公钥
  （需链上/签名验证）。
- **可迁移**：`address_version` 允许格式演进；后量子迁移仅需新增 `address_type`，地址不变。

## Security Impact

- Bech32m-derived 强校验码（防字符替换/截断/篡改）。
- `network_id`（地址）+ `chain_id`（签名域分离，ADR-0010）共同防跨网/跨链重放。
- 地址只含 pubkey hash，不暴露公钥 ⇒ 对后量子迁移友好（换签名不影响地址）。
- 地址派生必须使用 ADR-0005 Domain Registry 的 `domain_id = 0x05 (Address)`，防跨域复用。
- 未注册 `address_type` 拒绝（ADR-0008）⇒ 防 address type confusion / algorithm confusion。

## 测试要求（未来实现必须满足）

地址实现必须通过：
1. **官方 Bech32m test vectors**（验证复用 Bech32m 编码/校验机制的正确性）。
2. **Nova 自定义 test vectors**（覆盖 NovaAddressPayload 特有逻辑）。

**必须测试的用例**：
- uppercase（全大写地址）
- mixed case（混合大小写）
- invalid checksum（校验码错误）
- invalid HRP（HRP 非 `nova`）
- invalid address type（未注册 `address_type`）
- invalid version（`address_version` 不支持）
- corrupted payload（数据损坏）
- truncated address（截断）
- altered character（字符被篡改）
- invalid network（`network_id` 不匹配）
- malformed data（畸形数据）

所有用例必须为**确定性断言**（相同输入 ⇒ 相同接受/拒绝结果）。

**Roundtrip 性质（必测）**：
- `encode(decode(address)) == address_canonical`
- `decode(encode(payload)) == payload`

详见 `docs/protocols/crypto-test-vectors-v1.md`。
