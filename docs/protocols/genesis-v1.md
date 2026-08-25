# Nova Chain Genesis Specification v1（协议冻结）

- **Status**: Frozen（待批准）
- **Date**: 2026-08-26
- **Scope**: PHASE 2 — Cryptography（PHASE 7 实现 Genesis）
- **权威**：本文件定义 Genesis canonical data 与 `genesis_hash`；**`chain_id` 是 Genesis 明确配置值，禁止从 `genesis_hash` 截断派生**（用户评审要求）。
- 关联：ADR-0004/0005/0008/0009/0010/0011/0012、`crypto-serialization-v1.md`、`crypto-test-vectors-v1.md`

## 1. Genesis canonical data（字段）

```
Genesis {
    network_id:            u8,          // 网络类别/注册标识（ADR-0011）
    chain_id:              u64,         // Genesis 明确配置的固定值（非派生）
    genesis_timestamp:     u64,         // Unix 秒（LE）
    initial_validator_set: Vec<ValidatorInit>,  // 初始验证者集
    initial_accounts:      Vec<AccountInit>,    // 初始账户/余额
    protocol_parameters:   ProtocolParams,      // 共识/网络/执行参数
    economics_parameters:  EconomicsParams,     // 供应/质押/奖励参数
}
```

- 所有字段 canonical 编码遵循 `crypto-serialization-v1.md`（LE、固定 field order、禁止重排）。
- 子结构（`ValidatorInit`/`AccountInit`/`ProtocolParams`/`EconomicsParams`）的 canonical 编码在对应
  Phase（Validator/Staking/Economics）定稿，但 **field order 一经冻结不可重排**。

## 2. genesis_hash

```
genesis_hash = SHA-256(canonical_genesis)   // 32B 完整 Genesis 承诺
```

- `genesis_hash` 是对**完整 canonical Genesis** 的承诺（覆盖上述全部字段，包括 `chain_id`）。
- **`genesis_hash` 不参与生成 `chain_id`**（`chain_id` 是 Genesis 显式配置的输入字段，非输出推导）。

## 3. chain_id

- `chain_id` 是 Genesis 中**明确配置的固定 `u64`**，不是派生值。
- **不得从** `genesis_hash` / `block_hash` / `address` / `network_id` **派生**。
- **唯一性声明**：不声称"u64 chain_id 在数学上绝对唯一"；`chain_id` 必须由
  **Nova 网络配置 / Genesis 管理规则**分配，并在对应**生态注册表**中保持唯一。
- **真正用于安全绑定的是**：`chain_id + genesis_hash + domain separation`。

## 4. 三职责严格分离

| 职责 | 值 | 来源 |
|------|-----|------|
| `network_id` | 网络类别/注册标识 | ADR-0011（Network Registry） |
| `chain_id` | Genesis 明确配置的固定 u64 | Genesis 配置 |
| `genesis_hash` | SHA-256(canonical_genesis)（32B） | 由 canonical Genesis 计算 |

三者不可互相替代、不可互相推导。

## 5. ValidateGenesis()（节点启动验证）

节点启动阶段必须执行，**任何一步失败 ⇒ 节点启动失败，不得进入运行状态**：

```
ValidateGenesis():
  1. canonical encoding       // genesis 可被唯一解码（无歧义）
  2. compute genesis_hash     // 对 canonical_genesis 计算 SHA-256
  3. verify configured genesis_hash   // computed == configured
  4. verify chain_id          // genesis.chain_id == configured_chain_id
  5. verify network_id        // genesis.network_id == configured_network_id
  6. verify protocol version  // 协议版本兼容
  7. verify validator set     // 验证者集非空、权重合法、无重复身份
  8. verify initial state     // 初始账户/余额合法（非负、总供应与 economics 一致）
```

## 6. 节点启动校验（防 fork / 跨网）

```
configured_chain_id   == genesis.chain_id        // 否则拒绝启动
computed_genesis_hash == configured_genesis_hash // 否则拒绝启动
```

- 即使 `chain_id` 意外相同（独立 fork 场景），`genesis_hash` 不同 ⇒ 链身份验证拒绝。

## 7. 复现性

- 相同 `canonical_genesis` ⇒ 相同 `genesis_hash` ⇒ 相同链身份（可复现，Master Prompt §70）。
- Genesis 文件是权威输入；`genesis_hash` 用于链身份验证（PHASE 7 实现）。

## 8. Cross-Network / Fork Protection（补充证明）

| 场景 | 防护 |
|------|------|
| Testnet → Mainnet | `chain_id` 不同（Genesis 配置不同）⇒ 签名验证失败 |
| Mainnet → 独立 Fork | 即使 `chain_id` 意外相同，`genesis_hash` 不同 ⇒ `ValidateGenesis()`/启动校验拒绝 |
| 地址跨网 | `network_id`/HRP 不匹配 ⇒ 解码/展示层拒绝（ADR-0011） |
