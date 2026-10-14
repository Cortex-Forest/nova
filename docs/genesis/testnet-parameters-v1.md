# YAZIMAO L1 — Testnet 参数记录 v1（**已批准基线的书面化**）

> **状态**：`DRAFT FOR OWNER REVIEW`。本文件只**记录**已批准参数，**不新设**任何参数。
> 任何数值变更 = **新链实例**（须重走 `genesis-freeze-workflow-v1.md`）。
> **本文件不含任何密钥/seed/助记词**；也不含真实验证者身份（仍为 Owner 待提供项，见 §4）。
>
> **来源**：Owner 批准的 Testnet 架构基线 + `ADR-0051-fixed-supply-tokenomics-final-freeze.md`。
> **配套**：输入书写规范 `genesis-input-schema-v1.md`；流程 `genesis-freeze-workflow-v1.md`；
> 运行手册 `../testnet/testnet-runbook-v1.md`；Akash 部署 `../testnet/akash-deployment-v1.md`。

---

## 1. 已批准参数（**冻结后只读**）

| 参数 | 值 | 载体 | 备注 |
|---|---|---|---|
| 平台 | Akash Testnet | 部署描述 | `deploy/akash/testnet-sdl-v1.yaml` |
| 拓扑 | **1 Seed + 7 Validator**（8 个工作负载） | 部署描述 | Seed **仅引导**：不参与共识/finality，无管理权限 |
| `chain_id` | **2002** | `genesis.json` + 每节点 `--chain-id` | ADR-0011：`chain_id` 非派生，同 `network_id` 可多链 |
| `network_id` | **2**（testnet，HRP `novat`） | `genesis.json` + 每节点 `--network-id testnet` | 地址前缀必须匹配 |
| 验证者数 | **7** | `validators[]` 长度 | 验证者集合是 **Genesis 静态集合**，无运行期准入 |
| 每验证者 bonded stake | **10,000,000 NOVA** | `validators[].bonded_stake`（十进制字符串） | 必须 `≤` 该账户 `liquid_balance` 且 `≥ min_validator_stake` |
| 总 bonded stake | **70,000,000 NOVA** | 派生 | 7 × 10,000,000 |
| Quorum | **46,666,667 NOVA** | 派生（共识规则，**不写入** `genesis.json`） | 见 ADR-0051 §8 / 共识规范；本文件不重述规则 |
| 总供应量 | **1,000,000,000 NOVA** | `economics_params.total_supply` | ADR-0051 固定供应；工具**强制**（`ADR_0051_FIXED_SUPPLY`） |
| 分配桶（链外 provenance） | Community/Public 500M · Ecosystem 200M · Team 120M · Foundation 80M · Genesis Validator 100M | Owner 分配表 | **不由** schema 表达（ADR-0051 §11 禁 `allocation_type` 字段）；由 Owner GATE-3/3V 保证 |
| `fee_burn_bps` | **0** | `economics_params.fee_burn_bps` | ADR-0051 no-burn；工具**强制** `== 0` |
| 增发/通胀/提高上限 | **不存在**（禁止引入） | — | ADR-0051 政策 |
| peer 机制 | **静态配置**（`--peer`），**无** discovery | 每节点 CLI | 代码无 Kademlia/mDNS；peer 由操作者静态给出 |
| 端口规划 | Seed `17770`；Validator `17771`…`17777` | 每节点 `--listen` | 代码**无**默认端口；省略 `--listen` = 不监听 |
| 每工作负载资源 | 2 CPU · 4 GiB RAM · ≥ 60 GiB 持久化 · GPU OFF · TEE OFF | Akash SDL | — |

---

## 2. 端到端生成流程（Owner 输入 → 冻结记录）

> 与 `genesis-freeze-workflow-v1.md` 完全一致；此处给出**Testnet 化的可执行形态**。

### 2.1 前置（全部满足才可开始）

| # | 条件 | 状态 |
|---|---|---|
| 1 | Owner 冻结 `chain_id`/`network_id`/`genesis_timestamp` | ⏳ `chain_id`/`network_id` 已批准（2002/2）；**`genesis_timestamp` 待提供** |
| 2 | 7 个验证者的 `account_address` + `consensus_public_key`（Ed25519，64 位小写 hex） | ⏳ **待提供** |
| 3 | 4 类分配账户地址 + `liquid_balance`（Σ = 1,000,000,000） | ⏳ **待提供** |
| 4 | `protocol_params` 7 项取值（区间见 schema §4） | ⏳ **待提供**（工具无默认值） |
| 5 | `min_validator_stake`（必须 ≤ 10,000,000）+ `unbonding_period_seconds` | ⏳ **待提供** |
| 6 | 地址与公钥一致（`account_address == derive(pubkey, UserAccount, 2)`）、地址在 `novat` 网络下派生 | ⏳ 随 §2/§3 提供 |
| 7 | 输入文件中**无** `private_key`/`seed`/`mnemonic`/`secret`/`keystore` | ✅ 由工具硬失败保证 |

### 2.2 生成（仅 genesis 负责人；本机离线）

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  build --input testnet-genesis.json --out-dir out/testnet-genesis
```

产物：`genesis.bin`（canonical 二进制）、`genesis_hash.txt`（64 位小写 hex + 换行）、`genesis_summary.json`。
已存在同名产物 ⇒ 默认**拒绝覆盖**（需 `--force`）；工具**不**生成时间戳、**不**填默认值。

### 2.3 自校验 + 第二人复核

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  verify --genesis out/testnet-genesis/genesis.bin --hash out/testnet-genesis/genesis_hash.txt
```

- 复核项见 `genesis-freeze-workflow-v1.md` §3.1–§3.6（独立执行、比对摘要、核对分配合计与重排映射、核对
  `canonical_len == 1 + 8 + 8 + 4 + 85N + 4 + 51M + 40 + 42`；Testnet：`N = 7` 验证者、`M` = 账户数）。
- **`verify` 不运行预检**（设计如此，只做 decode + 语义/哈希校验）⇒ **`build` 阶段**才是 ADR-0051
  固定供应与 no-burn 的强制点。

### 2.4 hash 分发与节点启动

`genesis_hash` 经**至少一个独立于仓库的渠道**分发；每节点以 `--genesis-hash` 作为外部信任锚
（节点**绝不**从 `genesis.bin` 反推）。启动参数映射：

| `genesis.json` 字段 | 节点 CLI |
|---|---|
| `chain_id` | `--chain-id 2002` |
| `network_id` | `--network-id testnet` |
| （`genesis_hash.txt`） | `--genesis-hash <64 hex>` |
| （`genesis.bin`） | `--genesis /read-only/genesis/genesis.bin` |

### 2.5 冻结记录（随版本留档；`genesis-freeze-workflow-v1.md` §6）

| 项 | 值 |
|---|---|
| 生成日期 / 执行者 | ⏳ |
| 输入摘要（**不含密钥**） | ⏳ |
| `canonical_len` | ⏳ |
| `genesis_hash`（64 hex） | ⏳ |
| 复核人 / 日期 / 退出码 | ⏳ |
| 分发渠道 + 时间 | ⏳ |
| 各节点 verify 结果（8 节点） | ⏳ |

---

## 3. Testnet 输入骨架（**结构示例；所有 `REPLACE_*` 必须由 Owner 替换**）

```json
{
  "chain_id": 2002,
  "network_id": 2,
  "genesis_timestamp": 0,
  "validators": [
    { "account_address": "REPLACE_V1_ADDRESS", "consensus_public_key": "REPLACE_V1_PUBKEY_HEX64",
      "bonded_stake": "10000000", "commission_bps": 0 }
  ],
  "accounts": [
    { "address": "REPLACE_COMMUNITY_ADDRESS", "liquid_balance": "500000000" }
  ],
  "protocol_params": {
    "max_tx_bytes": 0, "max_block_bytes": 0, "max_gas_per_block": 0,
    "max_contract_code_bytes": 0, "max_contract_storage_bytes": 0,
    "epoch_length_blocks": 0, "snapshot_interval_blocks": 0
  },
  "economics_params": {
    "total_supply": "1000000000",
    "min_validator_stake": "REPLACE_MIN_STAKE",
    "unbonding_period_seconds": 0,
    "fee_burn_bps": 0
  }
}
```

**本骨架用 0 / `REPLACE_*` 是有意的**：它**不是**可用输入——`genesis_timestamp = 0`、
`protocol_params` 为 0、占位地址都会被工具的 fail-closed 校验拒绝（`ZeroTimestamp` / 参数非法 /
占位值拒绝）。请勿把它当作 `genesis.json` 直接提交。

---

## 4. 仍需 Owner 提供（**不得由 AI 填补**）

1. `genesis_timestamp`（Unix 秒，> 0，Owner 明确确认）。
2. 7 个验证者：`account_address` + `consensus_public_key`（64 位小写 hex）+ 各自 `commission_bps`。
3. 分配账户：Community/Public 500M、Ecosystem 200M、Team 120M、Foundation 80M、Genesis Validator 100M
   对应的地址与 `liquid_balance`（含托管/Custody 映射与 provenance）。
4. `protocol_params` 7 项取值；`min_validator_stake`；`unbonding_period_seconds`。
5. 每节点两枚 32 字节 seed（network / validator）——**离线生成，永不入库**（`../testnet/testnet-runbook-v1.md` §3.1）。
6. 审批（GATE-1/2/3/3V/5/6/7/8）与复核签字。

---

## 5. 本文件**不**声明的内容（诚实边界）

- 正式 Testnet Genesis **尚未生成**，`genesis_hash` **尚不存在**。
- `tests/vectors/genesis/*.json` 是**测试夹具**（含 `chain_id=2002` 的 testnet 夹具），
  **不是**生产输入；`genesis-image/` 当前内置的是 **devnet** genesis（`network_id 3 / chain_id 3004`），
  **不得**用于 Testnet。
- 本文件不修改任何协议规则、经济政策或共识参数。
