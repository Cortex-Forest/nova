# ADR-0013: Crypto / Protocol Boundary

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Implementation
- 关联：ADR-0005（域分离）、ADR-0006（哈希策略）、ADR-0008/0011/0012（注册表）、crypto-serialization-v1.md

## Context

必须明确 **Crypto crate 与 Protocol/Core 的所有权边界**，防止 `nova_crypto` 成为所有协议常量的容器
（架构腐化），并**防止签名路径被绕过**（调用方直接对任意字节签名）。

## Decision（建议，待批准）

### 1. 所有权边界

| 归属 | 内容 |
|------|------|
| **Crypto owns** | `AlgorithmId`、哈希算法、签名原语、密钥原语 |
| **Protocol/Core owns**（目标） | `DomainId`、`NetworkId`、`AddressType`、`ChainIdentity`、协议序列化规则 |

### 2. 当前阶段（PHASE 2）与迁移边界

- 因 `core` 尚未建立协议类型层（PHASE 4/7 的交易/区块类型），本阶段**由 `crypto` 暂存**
  `DomainId`/`NetworkId`/`AddressType`/`ChainIdentity`。
- **必须建立明确迁移边界 `CRYPTO → PROTOCOL`**：当 `core` 建立协议类型层时，
  将这些注册表与链身份**迁移**到 protocol/core；`crypto` 只保留算法/哈希/签名/密钥原语。
- 迁移经新 ADR 触发；**不得长期让 crypto 成为所有协议常量的容器**。

### 3. 签名路径边界（防 Bypass）

- **低层原语**（如 Ed25519 库的 `sign`）仅作为**内部原语**存在，**不公开**为"对任意字节签名"的协议 API。
- **协议面向 API 强制经过固定流水线**：
  ```
  build_signed_bytes(...) → Vec<u8>
  hash_signing_message(...) → SigningMessageHash([u8;32])
  sign_message_hash(...) → Signature
  verify_message_hash(...) → Result<(), CryptoError>
  ```
- **类型强制**：`SigningMessageHash([u8;32])` 为 **newtype**，普通 `[u8;32]` 不能直接作为协议签名消息
  （防误用/防绕过 domain separation 与 chain_id）。
- **唯一验证路径**：`canonical payload → context → signed bytes → SHA-256 → SigningMessageHash → verify_strict`。
  禁止一处验证 hash、另一处验证 raw bytes。

### 4. 严格验证（Ed25519）

- 使用 ed25519-dalek 3.x 的**严格验证**能力：拒绝 malformed pubkey/signature、weak key、
  small-order point；强制 canonical encoding。
- **禁止启用** legacy compatibility；**禁止启用** hazmat（除非单独 ADR 批准）。

### 5. 哈希边界

- `protocol_hash()`（SHA-256）只用于 ADR-0006 注册的共识协议位置；**不公开**"通用 SHA-256 wrapper"
  供任意模块随意使用。
- `content_hash()`（BLAKE3）**不得进入** transaction consensus hash / block hash / state root /
  validator vote / finality proof（除非未来 ADR 批准）。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| crypto 永久持有全部注册表 | 架构腐化；crypto 变为协议常量容器 |
| 立即迁移到 core | core 尚无协议类型层，过早抽象 |
| 公开 `sign(message)` | 允许绕过 domain separation/chain_id，攻击面扩大 ❌ |

## Consequences

- **正面**：签名路径被类型系统强制（`SigningMessageHash`）；边界清晰、可迁移。
- **成本**：本阶段 crypto 暂存协议注册表（有明确迁移计划）。
- **可迁移**：经 ADR 迁移至 protocol/core。

## Security Impact

- 防 signing-path bypass（调用方无法对任意字节签名）。
- 防一处 hash 验证、一处 raw 验证的不一致。
- 严格验证杜绝 weak-key / small-order / non-canonical 接受。
- 哈希边界阻止 content hash 混入共识承诺。
