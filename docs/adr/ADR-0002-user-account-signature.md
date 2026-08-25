# ADR-0002: User Account Signature Scheme

- **Status**: Proposed（待批准）
- **Date**: 2026-08-25
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography

## Context

Nova 用户账户需要一个默认签名方案，用于交易签名与账户所有权证明。选择须同时满足：
安全（抗 malleability / nonce 偏置）、移动优先性能、生态兼容、未来密码学灵活性
（crypto agility，支持未来新增签名算法 / 后量子迁移）。

候选：**Ed25519**（RFC 8032）与 **secp256k1**（具体方案**未定**：ECDSA vs BIP-340 Schnorr，详见 ADR-0008）。

## Decision（建议，待批准）

1. **默认账户签名：Ed25519（RFC 8032）**。
2. **兼容账户：secp256k1**：`address_type = 0x02` 登记为 **Reserved**（ADR-0008）。
   具体签名方案（ECDSA vs BIP-340 Schnorr）**未定**；**未来实现前必须重新批准具体 signature scheme**（新 ADR）。
3. 地址体系用 `address_type` 支持多方案（ADR-0008 注册表）⇒ 未来可增加新算法（含后量子），即 crypto agility。

**Ed25519 作为默认的理由**：
- **确定性签名**：无 nonce 偏置/重放风险——移动设备 CSPRNG 不可靠场景下显著降低一类严重漏洞（如 PS3/Android nonce 泄露）。
- **规范化与严格验证**：Nova 要求 Canonical Public Key Encoding + Canonical Signature Encoding + Strict Verification + Malformed Input Rejection（见下"Ed25519 安全要求"）。
- **性能**：验证极快（比 secp256k1 快数倍），适合移动端与节点。
- **签名大小**：固定 64 字节。
- **库成熟**：`ed25519-dalek`（曾审计，维护活跃）。

**secp256k1 保留为兼容账户**（`Reserved`，ADR-0008）：硬件钱包/Web3 生态支持最广；Nova 虽非 EVM 兼容链，但保留互操作路径（实现前须重新批准具体方案）。

**Ed25519 安全要求（取代泛化安全声明）**：
- 删除"Ed25519 天然消除 malleability"这类泛化描述；
- Nova 要求：**Canonical Public Key Encoding**（压缩 32B）+ **Canonical Signature Encoding**（R‖S 各 32B）
  + **Strict Verification** + **Malformed Input Rejection**；
- **所有 Nova 实现必须对同一签名得到一致的验证结果**：拒绝非 canonical 编码、拒绝畸形输入、
  拒绝任何边界变体（如非规范 S / 非规范点编码）；具体编码规则见 `docs/protocols/crypto-serialization-v1.md`。

**Ed25519 Specification（冻结，`algorithm_id = 0x01`，ADR-0012）**：

| 项 | 值 |
|----|-----|
| 标准 | RFC 8032（Ed25519） |
| 私钥 | 32 B 种子 |
| 公钥长度 | 32 B（压缩点编码） |
| 签名长度 | 64 B（`R(32) \|\| S(32)`） |
| 编码 | canonical：压缩公钥、`R‖S` 签名（crypto-serialization-v1.md §9） |
| canonical verification | 拒绝非 canonical 点/标量；拒绝非规范 `S`；`S < group order` 检查 |
| invalid point 行为 | 解码到非曲线点 ⇒ 拒绝 |
| invalid scalar 行为 | 标量 ≥ 群阶 ⇒ 拒绝 |
| malformed signature 行为 | 长度错误/畸形 ⇒ 拒绝 |
| test vectors | RFC 8032 官方向量 + Nova 自定义（crypto-test-vectors-v1.md） |
| 域注册 | `algorithm_id = 0x01`（ADR-0012）；签名上下文含 algorithm_id（ADR-0005） |

**实现约束**：实现阶段**必须使用成熟密码库**（候选 `ed25519-dalek`，经六项审查后引入）；
**禁止自行实现 Ed25519**（Master Prompt §16）。

## Alternatives（已评估）

| 方案 | 优势 | 劣势 / 否决原因 |
|------|------|----------------|
| 默认 secp256k1 | 生态/硬件钱包支持最广 | 非确定性签名（nonce 风险）、malleability、移动端性能较弱 |
| 仅 Ed25519 | 最简 | 无 EVM/硬件钱包互操作路径 |
| 双默认并重 | 灵活 | 增加 V0.1 范围与测试面；`address_type` 已支持多方案，无需双"默认" |
| SRP256r1 / Schnorr | — | 生态不匹配、工具链不成熟 |

## Consequences

- **正面**：默认 Ed25519 消除 nonce 偏置风险；配合 canonical 编码 + strict verification 提供确定性一致验证；移动端性能好。
- **成本**：硬件钱包对 Ed25519 的支持较 secp256k1 少（中期生态注意）；需定义兼容账户路径与派生规范。
- **可迁移**：地址用 pubkey hash（ADR-0004），未来换签名方案不影响地址，仅新增 `address_type`。

## Security Impact

- 确定性签名缓解移动端随机数风险；密钥生成仍必须使用 CSPRNG（ADR-0007）。
- 兼容账户 secp256k1 为 `Reserved`（ADR-0008），实现前须重新批准具体方案（ECDSA 则强制 RFC 6979 / BIP-340 则走 Schnorr 规范）。
- **不声称**"量子安全 / 不可破解"——定位为成熟密码学优先 + 未来密码学灵活性（Security Claims）。
- 签名域分离见 ADR-0005/0010；地址类型注册表见 ADR-0008；算法注册表见 ADR-0012；签名覆盖见 ADR-0009；序列化见 `docs/protocols/crypto-serialization-v1.md`。
