# ADR-0011: Network Registry & Chain Identity

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（修订：registry 只维护网络分类，不负责生成 chain_id）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography（冻结）
- 关联：ADR-0004（地址 HRP）、ADR-0010（chain identity / 域分离）、`genesis-v1.md`（Genesis 规范）

## Context

必须定义 **`network_id`、`network_name`、`HRP`、`environment`** 的网络分类关系，
并明确：**`network_id` 不是唯一的链身份**；真正的链身份由 `ChainIdentity` 三元组
（`network_id + chain_id + genesis_hash`，ADR-0010）提供。

**Network Registry 只负责网络分类**，**不负责从 Genesis Hash 生成 Chain ID**。

## Decision（建议，待批准）

### Nova Network Registry（初始）

| `network_id` | `network_name` | HRP（地址前缀） | `environment` | 状态 |
|--------------|----------------|------------------|----------------|------|
| `0x00` | — | — | — | **无效 / 必须拒绝** |
| `0x01` | `mainnet` | `nova` | production | Planned（未上线） |
| `0x02` | `testnet` | `novat` | staging | Planned |
| `0x03` | `devnet` | `novad` | development | Planned |
| `0x04` – `0xFF` | — | — | — | Reserved（未分配，拒绝） |

Network Registry 维护字段：**`network_id`、`network_name`、`HRP`、`environment`**。
**不维护也不生成 `chain_id` / `genesis_hash`**（二者由 Genesis 配置/承诺，见 `genesis-v1.md`）。

### 关系定义

```
ChainIdentity {
    network_id:  u8,     // 网络类别/注册标识（本 ADR）
    chain_id:    u64,    // Genesis 明确配置的固定值（LE 编码，genesis-v1.md）
    genesis_hash: [u8; 32], // SHA-256(canonical_genesis)
}
```

- **`network_id`**：网络类别**标签**（mainnet/testnet/devnet），**不是**唯一链身份。
- **`chain_id`**：唯一标识一条链实例——Genesis 中**明确配置的固定 `u64`**（**非派生**，`genesis-v1.md`）；
  **签名只绑定 `chain_id`**。
- **`genesis_hash`**：完整 Genesis 承诺（`SHA-256(canonical_genesis)`），**不参与生成 chain_id**。
- **HRP**：地址 human-readable part，**网络特定**（`nova`/`novat`/`novad`），地址文本直接区分网络，防人类误用。

### 规则

1. 真正链身份 = `ChainIdentity { network_id, chain_id, genesis_hash }` 三元组（ADR-0010）。
2. `chain_id` 由 Nova 网络配置 / Genesis 管理规则分配，并在对应生态注册表保持唯一；
   **不声称 u64 数学绝对唯一**。
3. 两个网络若 `genesis_hash` 不同（不同 canonical Genesis）⇒ 链身份不同（即使 `chain_id` 相同）。
4. 同一 `network_id`（如两个 testnet 实例）可有不同 `chain_id` ⇒ 仍为**不同链**。
5. 地址解码：HRP 必须与当前网络登记一致；`network_id` 必须匹配（ADR-0004 解码规则）。
6. 签名验证：`chain_id` 必须与当前 `ChainIdentity.chain_id` 一致（ADR-0010）。

### genesis_hash（不参与生成 chain_id）

```
genesis_hash = SHA-256(canonical_genesis)
```
`canonical_genesis` 字段见 `docs/protocols/genesis-v1.md`；**本注册表不生成 chain_id/genesis_hash**。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| `network_id` 作为唯一链身份 | 无法区分同类别（如两个 testnet）；跨 testnet 重放风险 |
| 全局固定 HRP=`nova` | 地址文本无网络提示，易误用（跨网地址混淆） |
| Registry 负责生成 chain_id | 职责混淆；chain_id 是 Genesis 配置值（`genesis-v1.md`） ❌ |

## Consequences

- **正面**：网络注册表 + 网络特定 HRP 提供人类可读层隔离；`ChainIdentity` 三元组提供协议层链身份；职责清晰（registry 只管网络分类）。
- **成本**：HRP 网络特定使地址文本随网络变化（需在钱包/Explorer 中明确网络）。
- **可迁移**：新网络（如安全测试网）经注册表登记，不影响已有协议。

## Security Impact

- 防 cross-network replay（T18）：`chain_id` 签名绑定 + `network_id`/HRP 地址校验双重阻止。
- 未注册 `network_id` 拒绝 ⇒ 防网络混淆。
- `genesis_hash` 可验证 ⇒ 防"伪造同 chain_id 的假链"（链身份可复现核验）。
