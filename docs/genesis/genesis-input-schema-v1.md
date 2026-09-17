# YAZIMAO Genesis 生产输入 Schema v1（`genesis.json`）

> **状态**：v1（Closed Internal Testnet 冻结流程配套）
> **工具**：`cargo run -p nova-genesis-builder --bin yazimao-genesis -- build --input <genesis.json> --out-dir <dir>`
> **权威编码**：本 schema **不是**协议编码。canonical 字节 / `genesis_hash` 一律由
> `nova_crypto::identity`（ADR-0014/0015）定义与计算；本文件只是**输入文件的书写规范**。
> **配套**：冻结与复核流程见 `genesis-freeze-workflow-v1.md`；Owner 数据收集模板见
> `genesis-owner-data-template.md`（模板本身不属于本 schema）。

---

## 1. 顶层结构（**未知字段一律拒绝**）

```json
{
  "chain_id": 2002,
  "network_id": 2,
  "genesis_timestamp": 1750000200,
  "validators": [ /* ValidatorInit[] */ ],
  "accounts": [ /* AccountInit[] */ ],
  "protocol_params": { /* ProtocolParamsV1 */ },
  "economics_params": { /* EconomicsParamsV1 */ }
}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `chain_id` | 整数（JSON integer 或十进制字符串） | `1 … u64::MAX`；**`0` 被拒绝**（保留为"未配置"）；`0x02A2`… 见 Owner 决策（Testnet 建议 `2002`） |
| `network_id` | 整数 | 仅 `1`(mainnet) / `2`(testnet) / `3`(devnet)；其余拒绝 |
| `genesis_timestamp` | 整数 | Unix 秒，**`> 0`**；**必须由 Owner 提供**（工具**不会**自动生成，也不会使用当前时间） |
| `validators` | 数组 | **非空**；≤ 10,000 |
| `accounts` | 数组 | **非空**；≤ 1,000,000 |
| `protocol_params` | 对象 | 7 个字段，全部必填（见 §3） |
| `economics_params` | 对象 | 4 个字段，全部必填（见 §4） |

---

## 2. `validators[]`（每元素恰好 4 个字段）

```json
{
  "account_address": "novat1...",
  "consensus_public_key": "<64 位小写 hex>",
  "bonded_stake": "10000000",
  "commission_bps": 500
}
```

| 字段 | 规则 |
|---|---|
| `account_address` | bech32m 文本；**必须**与 `network_id` 匹配（`novat`/`nova`/`novad`）；**必须**同时出现在 `accounts[]`；**必须**等于 `derive(consensus_public_key, UserAccount, network_id)` |
| `consensus_public_key` | **64 位小写 hex**（拒绝大写）；必须是合法 Ed25519 压缩点；且必须是 **canonical 编码**（`Y < p`，由构建时的 decode 回读强制） |
| `bonded_stake` | **十进制字符串** u128；`> 0`；`≤` 该账户 `liquid_balance`；`≥ economics_params.min_validator_stake` |
| `commission_bps` | 整数 u16；`≤ 10000` |

- `validator_id`（`SHA-256(consensus_public_key)`）**不写入文件**：由工具与链上实现派生。
- **禁止**出现 `private_key` / `seed` / `mnemonic` / `secret` / `keystore`（命中即硬失败）。
- 列表**顺序任意**：工具会按 `validator_id` 升序排序，并在 `genesis_summary.json` 中报告
  `validators_reordered` 与 `original_index → canonical_index` 全量映射（**不静默排序**）。

---

## 3. `accounts[]`（每元素恰好 2 个字段）

```json
{ "address": "novat1...", "liquid_balance": "20000000" }
```

| 字段 | 规则 |
|---|---|
| `address` | bech32m 文本；网络匹配 `network_id`；**唯一** |
| `liquid_balance` | **十进制字符串** u128；`Σ liquid_balance` **必须等于** `economics_params.total_supply` |

- 每个 validator 的账户**必须**在此列表中出现（否则 `InvalidStake` / 工具预检失败）。
- 隐式字段（`nonce=0`、`code_hash`、`storage_root`）**不写入文件**，由协议定义。
- 列表**顺序任意**：工具按地址 35B payload 升序排序并报告重排映射。

---

## 4. `protocol_params`（7 字段，全部必填；**代码中无默认值**）

| 字段 | 类型 | 合法区间（`nova-crypto` 校验） |
|---|---|---|
| `max_tx_bytes` | u32 | `> 0`，`≤ 1_048_576` |
| `max_block_bytes` | u32 | `≥ max_tx_bytes`，`≤ 8_388_608` |
| `max_gas_per_block` | u64 | `> 0`，`≤ 100_000_000_000` |
| `max_contract_code_bytes` | u32 | `> 0`，`≤ 524_288` |
| `max_contract_storage_bytes` | u32 | `> 0`，`≤ 16_777_216` |
| `epoch_length_blocks` | u64 | `> 0`，`≤ 1_000_000` |
| `snapshot_interval_blocks` | u64 | `> 0`，`≤ 10_000_000` |

> 以上是**合法性边界**，不是建议值，也不是默认值。数值由 Owner 决策。

---

## 5. `economics_params`（4 字段，全部必填）

| 字段 | 类型 | 规则 |
|---|---|---|
| `total_supply` | **十进制字符串** u128 | `> 0`，且 `== Σ accounts[].liquid_balance`（checked 求和，溢出即失败） |
| `min_validator_stake` | **十进制字符串** u128 | `> 0`，且 `≤` 每个 validator 的 `bonded_stake` |
| `unbonding_period_seconds` | u64 | `> 0` |
| `fee_burn_bps` | u16 | `≤ 10000`（ADR-0051 FINAL 政策值：`0`） |

---

## 6. 数值书写规则（严格）

| 类别 | 允许 | 拒绝 |
|---|---|---|
| `u128`（4 个字段） | **仅十进制字符串** `"1000000000"` | JSON 数字 `1000000000`、浮点 `1000000000.0`、指数 `1e9`、前导零 `"0100"`、符号 `"+1"`/`"-1"`、空串 |
| 其它整数 | JSON 整数字面量 或十进制字符串 | 浮点 / 指数 / 负数 / 非数字 |
| 字符串（地址、公钥） | canonical 形式（bech32m 小写；hex 小写） | 大写、占位值 |

**占位值**（任意字符串字段）：空串、`TBD`、`PENDING`（大小写不敏感）⇒ **拒绝**。

---

## 7. 已知限制（诚实记录）

1. **重复 JSON 键**：`serde_json` 以"后者覆盖"解析，工具**无法**检测重复键。
   缓解：输入经人工复核，并以 `genesis_summary.json` 的最终取值为准。
2. **十进制字符串首尾空白**会被 trim（宽松）；其余非 canonical 形式一律拒绝。
3. 工具**不校验**分配政策（例如"Genesis Validator 合计 = 100,000,000"）；
   该政策由 ADR-0051 与 Owner 复核保证，`genesis_summary.json` 会列出各分项合计供核对。

---

## 8. 完整最小示例（**示例值不是生产值**）

```json
{
  "chain_id": 2002,
  "network_id": 2,
  "genesis_timestamp": 1750000200,
  "validators": [
    {
      "account_address": "novat1...",
      "consensus_public_key": "<64 hex>",
      "bonded_stake": "20000000",
      "commission_bps": 500
    }
  ],
  "accounts": [
    { "address": "novat1...", "liquid_balance": "100000000" },
    { "address": "novat1...", "liquid_balance": "900000000" }
  ],
  "protocol_params": {
    "max_tx_bytes": 65536,
    "max_block_bytes": 1048576,
    "max_gas_per_block": 1000000000,
    "max_contract_code_bytes": 32768,
    "max_contract_storage_bytes": 1048576,
    "epoch_length_blocks": 100,
    "snapshot_interval_blocks": 1000
  },
  "economics_params": {
    "total_supply": "1000000000",
    "min_validator_stake": "1000000",
    "unbonding_period_seconds": 1209600,
    "fee_burn_bps": 0
  }
}
```
