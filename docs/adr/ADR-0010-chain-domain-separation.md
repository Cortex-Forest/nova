# ADR-0010: Chain Identity & Domain Separation

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（修订：chain_id 改为 Genesis 配置值，禁止从 genesis_hash 派生）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0004（地址 network_id/HRP）、ADR-0005（域分离）、ADR-0009（签名覆盖）、ADR-0011（网络注册表）、ADR-0012（算法注册表）、`genesis-v1.md`（Genesis 规范）

## Context

必须明确 **`chain_id`、`network_id`、域分离（domain separation）** 三者的关系，
并保证跨网络隔离：

- Testnet 的交易**不得**被 Mainnet 接受；
- Mainnet 的交易**不得**被其他 Nova network 接受。

## Decision（建议，待批准）

### 1. 概念定义与 ChainIdentity

| 概念 | 定义 | 作用域 |
|------|------|--------|
| **`network_id`** | 网络类别**标签**（mainnet/testnet/devnet，ADR-0011），**不是唯一链身份**。 | 地址/人类可读层 |
| **`chain_id`** | 唯一标识**一条链实例**：Genesis 中**明确配置的固定 `u64`**（非派生）。在生态注册表中保持唯一。 | 协议/签名层 |
| **`genesis_hash`** | 完整 Genesis 承诺（SHA-256 canonical genesis，32B），**不参与生成 chain_id**。 | 链身份验证 |
| **`domain_id`** | 签名消息中的对象域标识（`u8`，ADR-0005 Domain Registry）。 | 签名消息构造 |

**最终链身份（ChainIdentity，冻结）**：

```
ChainIdentity {
    network_id:   u8,        // 网络类别/注册标识（ADR-0011）
    chain_id:     u64,       // Genesis 明确配置的固定值（LE 编码）
    genesis_hash: [u8; 32],  // SHA-256(canonical_genesis)
}
```

**三职责严格分离**：`network_id` = 网络类别；`chain_id` = Genesis 配置固定值；
`genesis_hash` = 完整 Genesis 承诺。三者不可互相替代或推导。

### 2. 权威规则

```
chain_id     = Genesis 明确配置的固定 u64（非派生）
genesis_hash = SHA-256(canonical_genesis)            // 完整 Genesis 承诺
network_id   = 链身份的分类属性（地址/展示/路由）

signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE)
               || payload_length(4B LE) || payload(canonical)
message_hash = SHA-256(signed_bytes)
```

- **签名只绑定 `chain_id`**（唯一、防重放），**不绑定** `network_id`（分类标签，非唯一）。
- **所有 Transaction / Vote / Block / Governance 必须绑定 `chain_id`**（经签名上下文，ADR-0005）。
- `chain_id` **必须来自 Genesis 明确配置的固定值**；**不得从** `genesis_hash` / `block_hash` /
  `address` / `network_id` **派生**。
- **真正用于安全绑定的是**：`chain_id + genesis_hash + domain separation`。
- `network_id` 用于地址（ADR-0004，HRP 网络特定，ADR-0011）与展示层，防人类误用。
- **双重检查**：地址解码出的 `network_id`/HRP 与节点自身匹配（防跨网地址混淆）；
  签名的 `chain_id` 与节点 `ChainIdentity.chain_id` 匹配（防跨链重放）。

### 3. `chain_id` / `genesis_hash` 规则（PHASE 7 定稿）

```
chain_id     = Genesis 配置字段（固定 u64，由 Nova 网络配置/Genesis 管理规则分配）
genesis_hash = SHA-256(canonical_genesis)   // 覆盖全部 Genesis 字段（含 chain_id）
```

- **已删除**旧设计（从 `genesis_hash` 截断前 8 字节作为 `chain_id`）：64-bit 截断不是完整链身份、
  不应依赖概率碰撞安全；`chain_id` 应为明确配置的协议参数。
- **`genesis_hash` 不参与生成 `chain_id`**（`chain_id` 是输入，`genesis_hash` 是对含 `chain_id` 的完整
  canonical Genesis 的输出承诺）。
- 具体字段见 `docs/protocols/genesis-v1.md`。

### 4. 跨网重放 / Fork 防护证明

- **Testnet → Mainnet**：tx 签名的 `chain_id` = testnet 配置值 ≠ mainnet 配置值 ⇒
  `SHA-256(algorithm_id || domain_id || mainnet_chain_id || ...)` ≠ 签名消息 ⇒ **验签失败**。
- **Mainnet → 独立 Fork**：即使 `chain_id` 意外相同，`genesis_hash` 不同 ⇒ 链身份验证必须拒绝
  （`ValidateGenesis()` 第 3 步，`genesis-v1.md`）。
- **地址跨网**：`network_id`/HRP 不匹配 ⇒ 解码/展示层直接拒绝（防地址混淆，ADR-0011）。

### 5. 节点启动校验（防 fork / 跨网，`genesis-v1.md` §6）

```
configured_chain_id   == genesis.chain_id        // 否则拒绝启动
computed_genesis_hash == configured_genesis_hash // 否则拒绝启动
```

节点启动必须执行 `ValidateGenesis()`（8 步，`genesis-v1.md` §5）；任何失败 ⇒ **节点不得启动**。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 用 `network_id` 作签名绑定 | 非唯一（多个 testnet 可同 id），无法防跨 testnet 重放 |
| 仅 `chain_id`、无地址 `network_id` | 人类可读层无网络提示，易误用 |
| 不校验地址 `network_id` | 跨网地址混淆风险（攻击者可发 testnet 地址骗 mainnet 用户） |

## Consequences

- **正面**：跨网/跨链重放被 `chain_id` 签名绑定 + `network_id`/HRP 地址校验**双重**阻止；`ChainIdentity` 三元组提供可验证链身份；`genesis_hash` 防 fork。
- **成本**：所有签名消息必须携带 canonical `chain_id`；地址解码需网络参数注入；genesis 必须可复现且经 `ValidateGenesis()` 校验。
- **可迁移**：`chain_id` 由 Genesis 配置分配；`genesis_hash` 由 canonical Genesis 承诺；不同网络天然隔离。

## Security Impact

- 防 cross-network replay（T18）与跨链重放（T7，见威胁模型）。
- `chain_id` canonical 编码（`u64` LE）须与 `crypto-serialization-v1.md` 一致（防编码歧义）。
- `genesis_hash` 可复现验证 + 启动校验 ⇒ 防"伪造同 chain_id 假链"（即使 chain_id 相同，genesis_hash 不同仍拒绝）。
- 任何"复用他链签名"都必须经过 `chain_id` 校验，从根本上阻断。
