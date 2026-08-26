# ADR-0014: Genesis Schema V1（嵌套类型冻结）

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography（Genesis canonical data）
- 关联：ADR-0004（地址）、ADR-0008（address_type）、ADR-0010/0011（链身份/网络）、ADR-0012（算法）、
  ADR-0015（canonical 编码）、ADR-0016（accounting invariants）、`genesis-v1.md`

## Context

`genesis-v1.md` 已冻结顶层 `Genesis` 的 7 个字段，但四个嵌套类型
（`ValidatorInit`/`AccountInit`/`ProtocolParams`/`EconomicsParams`）的字段与编码未定义，
导致 STEP 6（Chain Identity / Genesis Validation）被 BLOCKED。

本 ADR 冻结这四个嵌套类型。**总体原则（用户评审）**：

> Genesis 必须只包含"启动 Nova Chain 所必需、且必须形成 Chain Identity 承诺的参数"。
> 不得把尚未定稿的未来功能塞进 Genesis；未来治理/升级参数不得为了"看起来完整"而提前定义成协议。

## Decision（建议，待批准）

### GenesisV1 顶层（字段顺序固定，不可重排）

```rust
GenesisV1 {
    network_id:            u8,                  // ADR-0011
    chain_id:              u64,                 // Genesis 显式配置，非派生
    genesis_timestamp:     u64,                 // Unix 秒（> 0）
    initial_validator_set: Vec<ValidatorInit>,  // 非空、按 validator_id 升序
    initial_accounts:      Vec<AccountInit>,    // 非空、按地址 payload 升序
    protocol_parameters:   ProtocolParamsV1,
    economics_parameters:  EconomicsParamsV1,
}
```

### ValidatorInit

```rust
ValidatorInit {
    account_address:      NovaAddress,  // 地址文本（bech32m，网络必须匹配 Genesis network_id）
    consensus_public_key: [u8; 32],     // Ed25519 公钥（压缩点，RFC 8032）
    bonded_stake:         u128,         // 从对应账户 liquid 划转的质押（LE）
    commission_bps:       u16,          // 佣金基点（≤ 10_000）
}
```

- **不保存 `voting_power`**：`voting_power` 必须由 `bonded_stake` 按**未来批准的共识权重规则**派生。
  Genesis 禁止同时保存 `bonded_stake` + `voting_power`（避免状态不一致）。
- **validator identity（派生，不存储）**：

  ```
  validator_id = SHA-256(consensus_public_key)   // 32B；派生身份，非独立 Genesis 输入字段
  ```

- 校验规则（任意失败 ⇒ `GenesisError::InvalidValidator` / `DuplicateValidator`）：
  - `bonded_stake > 0`
  - `commission_bps <= 10_000`
  - `account_address` 有效（可解码、HRP/网络匹配 Genesis `network_id`）
  - `consensus_public_key` 有效（32B 且为合法 Ed25519 压缩点）
  - `account_address` 唯一；`consensus_public_key` 唯一；`validator_id` 唯一
  - **同一个 consensus_public_key 禁止出现两次**

### AccountInit

```rust
AccountInit {
    address:        NovaAddress,  // 地址文本（bech32m，网络必须匹配 Genesis network_id）
    liquid_balance: u128,         // Genesis 初始化前该账户的 liquid balance（LE）
}
```

- **V0.1 implicit defaults（不写入 Genesis）**：`nonce = 0`、`code = empty`、`storage = empty`。
- 校验规则：
  - `address` 有效（可解码、HRP/网络匹配）
  - `address` 唯一（重复 ⇒ `GenesisError::DuplicateAccount`）
  - `liquid_balance >= 0`（`u128` 天然非负；编码解码不得下溢）

### ProtocolParamsV1（最小、真正需要 Genesis 承诺的参数）

```rust
ProtocolParamsV1 {
    max_tx_bytes:              u32,   // 最大交易字节
    max_block_bytes:           u32,   // 最大区块字节
    max_gas_per_block:         u64,   // 每区块最大 gas
    max_contract_code_bytes:   u32,   // 最大合约代码字节
    max_contract_storage_bytes: u32,  // 最大合约存储字节
    epoch_length_blocks:       u64,   // 每 epoch 区块数
    snapshot_interval_blocks:  u64,   // 快照间隔区块数
}
```

- 校验：`max_tx_bytes > 0`、`max_block_bytes >= max_tx_bytes`、`max_gas_per_block > 0`、
  `max_contract_code_bytes > 0`、`max_contract_storage_bytes > 0`、`epoch_length_blocks > 0`、
  `snapshot_interval_blocks > 0`。
- **合理上限（防启动资源耗尽；违反 ⇒ `InvalidProtocolParams`）**：

  | 参数 | V0.1 上限 |
  |------|-----------|
  | `max_tx_bytes` | 1 MiB（1_048_576） |
  | `max_block_bytes` | 8 MiB（8_388_608） |
  | `max_gas_per_block` | 100_000_000_000 |
  | `max_contract_code_bytes` | 512 KiB（524_288） |
  | `max_contract_storage_bytes` | 16 MiB（16_777_216） |
  | `epoch_length_blocks` | 1_000_000 |
  | `snapshot_interval_blocks` | 10_000_000 |

- **不**在本阶段自行添加共识委员会算法参数（等 Consensus Phase 批准）。

### EconomicsParamsV1

```rust
EconomicsParamsV1 {
    total_supply:              u128,  // 总供应量
    min_validator_stake:       u128,  // 最低验证者质押
    unbonding_period_seconds:  u64,   // 解绑期（秒）
    fee_burn_bps:              u16,   // 费用销毁基点
}
```

- 校验：`total_supply > 0`、`min_validator_stake > 0`、`unbonding_period_seconds > 0`、
  `fee_burn_bps <= 10_000`。

### Economics Scope Boundary（V0.1 不加入）

- Creator reward formula / AI reward / NFT reward / storage reward / compute reward /
  recommendation reward / future governance allocations / future economic curves。
- 这些分别进入 Economics / Creator / Storage / Compute / Governance phases；
  **不得为了"字段完整"提前创造协议**。

### Empty Collections

- `initial_validator_set`：**REJECT 为空**（无验证者无法运行 PoS）。
- `initial_accounts`：**REJECT 为空**（至少 1 个账户；且 validator 账户必须存在于其中，
  见 ADR-0016 stake accounting）。

### Resource Limits（集合大小上限，防 oversized Genesis）

| 集合 | V0.1 上限 |
|------|-----------|
| `initial_validator_set` | 10_000 |
| `initial_accounts` | 1_000_000 |

- 超限 ⇒ `GenesisError::InvalidValidator` / `InvalidInitialState`。

### 其他顶层校验

- `network_id`：注册（`0x01`/`0x02`/`0x03`，ADR-0011）；`0x00`/`0x04+` ⇒ `GenesisError::InvalidNetwork`。
- `chain_id`：`> 0`（`0` 保留为"未配置"哨兵 ⇒ `GenesisError::InvalidChainId`）。
- `genesis_timestamp`：`> 0`（`0` 视为未设置 ⇒ `GenesisError::InvalidTimestamp`）。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 保存 `voting_power` | 与 `bonded_stake` 状态不一致风险；权重规则未定，不提前固化 |
| 保存 `validator_id` 为输入字段 | 派生身份重复存储 ⇒ 不一致风险（应即时计算） |
| Protocol/Economics 参数无限扩张 | 把未定稿的未来功能固化为协议（违反总体原则） |
| 允许空 validator set | PoS 无验证者无法运行；V0.1 正式网络必须 REJECT |

## Consequences

- **正面**：Genesis 自包含且最小；validator/account 顺序与身份规则明确 ⇒ canonical 承诺无歧义。
- **成本**：未来共识权重/Economics 曲线变化需经新 ADR 修订（不破坏 V0.1 承诺）。
- **可迁移**：新网络（testnet/devnet）仅需不同 `network_id`/`chain_id`/参数值，schema 不变。

## Security Impact

- 防重复验证者/账户（identity 冲突）；防质押重复计入（ADR-0016）；防 oversized Genesis（资源上限）；
- 地址网络必须匹配 Genesis `network_id` ⇒ 防跨网 Genesis 混用（ADR-0011）。
- 具体编码见 ADR-0015；accounting invariants 见 ADR-0016。
