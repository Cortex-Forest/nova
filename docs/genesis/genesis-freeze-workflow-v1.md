# YAZIMAO Genesis Freeze Workflow v1

> **适用**：Closed Internal Testnet（`network_id = 2` / `chain_id = 2002`）Genesis 冻结。
> **工具**：`cargo run -p nova-genesis-builder --bin yazimao-genesis`
> **原则**：**生成 → 自校验 → 第二人复核 → hash 分发 → 冻结后只读**。
> **红线**：任何私钥 / seed / mnemonic **绝不**进入输入文件、仓库或日志。

---

## 0. 前置条件（全部满足才可开始）

| # | 条件 |
|---|---|
| 1 | Owner 已确认 `chain_id` / `network_id` / `genesis_timestamp` |
| 2 | Owner 已确认 validator 数量与全部公开数据（地址 / 公钥 / bonded_stake / commission_bps） |
| 3 | Owner 已确认 `protocol_params`(7) 与 `economics_params`(4) |
| 4 | Owner 已确认分配账户与余额（`Σ liquid == total_supply`） |
| 5 | 所有生产地址在 `network_id` 冻结**之后**派生（HRP 与网络一致） |
| 6 | 输入文件**不含**任何密钥类字段 |

---

## 1. 生成（Generation）

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  build --input genesis.json --out-dir out/genesis
```

产物：

| 文件 | 内容 |
|---|---|
| `genesis.bin` | canonical Genesis 二进制（节点 `--genesis` 直接读取；**不是 JSON**） |
| `genesis_hash.txt` | 64 位小写 hex + 换行（作为 `--genesis-hash` 信任锚） |
| `genesis_summary.json` | 人工复核摘要（字段快照、计数、canonical 长度、hash、重排映射、分配合计） |

**行为约定**：

- 已存在同名产物 ⇒ **拒绝覆盖**（需显式 `--force`）。
- 工具**不自动生成** `genesis_timestamp`、**不填默认值**、**不自动决定任何参数**。
- 列表乱序 ⇒ **自动排序并在摘要中报告** `validators_reordered` / `accounts_reordered`
  以及 `original_index → canonical_index` 全量映射（不静默）。

### 生成阶段的 fail-closed 校验链

```
strict JSON 解析（未知字段/敏感字段/占位值/u128 编码）
  → 预检（供应不变量、账户存在性、stake 记账、commission、唯一性、地址↔公钥派生一致性）
  → canonical_genesis_bytes（nova-crypto）
  → compute_genesis_hash（nova-crypto）
  → decode_genesis_bytes(输出) + validate_genesis_with_expected(..., hash)   ← 自校验
```

任一步失败 ⇒ **不写出任何产物**，工具以非零退出码结束。

---

## 2. 自校验（Self-verification）

工具已在 `build` 内部完成一次回读；发布前**再独立执行一次只读复核**：

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  verify --genesis out/genesis/genesis.bin --hash out/genesis/genesis_hash.txt
```

`verify` 只做两件事（**不触碰输入 JSON、不写文件**）：

1. `decode_genesis_bytes(genesis.bin)` —— 结构 / canonical 顺序 / 尾随字节 / **公钥 canonical 编码**；
2. `validate_genesis_with_expected(..., hash)` —— 语义规则 + **computed == configured**。

**篡改检测基线（已在测试中固化）**：

| 篡改 | 期望 |
|---|---|
| `genesis.bin` 任意 1 字节（含 timestamp 区间） | 失败（hash 不匹配） |
| `genesis.bin` 追加 1 字节 | 失败（trailing bytes） |
| `genesis_hash.txt` 任一字符（保持格式合法） | 失败（hash 不匹配） |
| `genesis_hash.txt` 非 canonical（大写/长度错误） | 失败（格式拒绝） |

---

## 3. 第二人复核（Independent cross-check）

**必须由生成者以外的第二人执行**，且**不共享本次会话的中间产物**。步骤：

| # | 动作 | 记录 |
|---|---|---|
| 3.1 | 独立运行 §2 的 `verify` 命令 | 退出码 + 输出的 `genesis_hash` |
| 3.2 | 比对 `genesis_summary.json` 与 Owner 数据表：逐项核对 `chain_id`/`network_id`/`genesis_timestamp`/validator 数/account 数 | 逐项签字 |
| 3.3 | 核对分配合计：`account_liquid_sum == total_supply`；`validator_bonded_sum ≤ validator_liquid_sum` | 数值记录 |
| 3.4 | 核对 `reorder` 映射（若 `*_reordered = true`，逐条确认映射符合预期，而非掩盖错填） | 映射表 |
| 3.5 | 核对 `canonical_len` 与公式 `1 + 8 + 8 + 4 + 85N + 4 + 51M + 40 + 42` | 数值记录 |
| 3.6 | 记录 hash（小写 hex 全 64 位），用于分发与公告 | `genesis_hash.txt` |

> **独立性要求**：3.1 必须使用只读 `verify` 路径；**不得**通过重新生成来"验证"（同路径不构成独立验证）。

---

## 4. hash 分发（Distribution）

1. **冻结 hash**：以 §2/§3 一致的 64 位小写 hex 为唯一权威值。
2. **分发内容**：`genesis.bin` + `genesis_hash.txt`（+ `genesis_summary.json` 供核对）。
3. **分发通道**：每个操作者自持有相同的 `genesis.bin`；`genesis_hash` 通过至少一个**独立通道**
   （例如发布公告 / 代码仓库外的受控渠道）交叉确认。
4. **节点启动参数**（必须与文件一致）：

```bash
yazimao-node \
  --genesis  <path>/genesis.bin \
  --genesis-hash <64 hex> \
  --chain-id <chain_id> \
  --network-id testnet \
  --storage-dir <path> \
  --network-seed-file <path> \
  --listen <ip:port> \
  --peer <nodeid_hex@ip:port> [--peer ...]
```

节点会**硬拒绝**以下任一不符：`genesis_hash` 不符（`GenesisHashMismatch`）、
`chain_id` 不符（`ChainIdMismatch`）、`network_id` 不符（`NetworkIdMismatch`）；
P2P 握手亦以 `network_id + chain_id + genesis_hash` 三方绑定拒绝异链节点。

5. **分发后核对**：每台机器启动前执行一次 `verify`，确认本地文件 hash 与公告一致。

---

## 5. 冻结（Freeze）与冻结后纪律

**冻结时刻** = §3 复核通过且 hash 公告之时。冻结范围（**任何一项改动都会改变 `genesis_hash`**）：

```
network_id · chain_id · genesis_timestamp · validators（数量/顺序/全部 4 字段）
accounts（数量/顺序/地址/余额）· protocol_params（7）· economics_params（4）
```

**冻结后禁止**：修改输入文件、重新生成、`--force` 覆盖产物、以任何理由"微调"参数。

**如需变更** ⇒ 视为**新链实例**：重新走 §0–§4，并（按 ADR-0011 §53-54）分配**新的 `chain_id`**；
旧 hash 立即作废，新旧节点无法互联（握手与 QC `validator_set_id` 均绑定 `genesis_hash`）。

---

## 6. 记录表（建议随版本留档）

| 项 | 值 |
|---|---|
| 生成日期 / 执行者 | |
| 输入文件名 + 内容摘要（**不含密钥**） | |
| `genesis.bin` 长度（canonical_len） | |
| `genesis_hash`（64 hex） | |
| 复核人 / 复核日期 | |
| 复核命令退出码 | |
| 公告渠道 + 时间 | |
| 各节点 verify 结果 | |

---

## 7. 常见失败与处置

| 现象 | 原因 | 处置 |
|---|---|---|
| `unknown field` | 输入含 schema 外字段（含抄写错误） | 修正输入，重新生成 |
| `禁止字段` | 输入含 `private_key`/`seed`/`mnemonic`/`secret`/`keystore` | **立即停止**，从输入中移除；确认密钥从未进入任何仓库/日志 |
| `u128 必须写成十进制字符串` | 用了 JSON 数字/浮点/指数 | 改为字符串 |
| `占位值/空值不被接受` | 残留 `TBD`/`PENDING`/空串 | 补齐真实值 |
| `与 consensus_public_key 派生结果不一致` | 地址与公钥不匹配（多为手抄错误） | 由公钥重新派生地址 |
| `Σ accounts liquid != total_supply` | 分配未对齐 | 修正余额，使合计等于 `total_supply` |
| `genesis_hash mismatch`（verify） | 文件被修改 / 分发了不同版本 | 回到 §2 重新取权威文件与 hash |
| 节点启动 `ChainIdMismatch` / `NetworkIdMismatch` | CLI 参数与文件不一致 | 用公告值启动 |
| 握手 `WrongGenesisHash` | 同行节点使用了不同 genesis | 统一分发权威文件 |

---

## 8. 与既有文档的关系

- 协议规范（canonical 编码 / 校验 / hash）：`docs/protocols/genesis-v1.md`、ADR-0014/0015/0016
  —— **本流程不修改、不重述**这些规则，只调用其生产实现。
- Owner 数据收集：`docs/genesis/genesis-owner-data-template.md`（模板）。
- 输入文件书写规范：`docs/genesis/genesis-input-schema-v1.md`。
