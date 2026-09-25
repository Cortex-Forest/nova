# YAZIMAO L1 — Closed Internal Testnet Runbook v1

> **适用范围**：**邀请制** Closed Internal Testnet（`network_id = testnet`）。
> **不适用**：Public Testnet / Mainnet。当前实现**明确 NOT MAINNET READY**。
> **配套文档**：`docs/genesis/genesis-freeze-workflow-v1.md`（Genesis 冻结流程）、
> `docs/genesis/genesis-input-schema-v1.md`（输入规范）、`docs/genesis/genesis-owner-data-template.md`（Owner 数据）。
> **红线**：任何私钥 / seed / mnemonic **绝不**进入本仓库、文档或日志。
> 本文件只描述**如何运维**；**不定义**任何协议参数，也不得用于"自动决定"参数。

---

## 0. 启动前置条件（Owner Gate：全部满足才可开始）

| # | 条件 | 判定方式 |
|---|---|---|
| 1 | Owner 已**冻结并发布** `chain_id` / `network_id` / `genesis_timestamp` | Owner 书面确认（本 runbook 不含取值） |
| 2 | Owner 已发布 `genesis.bin` 与 `genesis_hash`（64 位小写 hex） | 见 §2 |
| 3 | 已按 `genesis-freeze-workflow-v1.md` 完成 **生成 → 自校验 → 第二人复核 → hash 通过带外渠道分发** | 复核记录 |
| 4 | 每个验证者已有**离线生成**的 32 字节 seed 文件（validator / network 各一），且**未入库** | 见 §3.3 |
| 5 | 每台机器目录规划完成：`--storage-dir` 与 `--safety-dir` **不得复用**同一目录 | 现场检查 |
| 6 | 拓扑与端口规划完成（§4） | 现场检查 |

> **冻结后纪律**：`genesis.bin` / `genesis_hash` / `chain_id` / `network_id` / `genesis_timestamp`
> **只读**。任何变更都会改变 `genesis_hash`，必须视为**新链实例**重新走冻结流程。

---

## 1. 节点环境要求

| 项 | 要求 | 依据 |
|---|---|---|
| OS | Linux x86_64（生产/CI 目标）；Windows 可用于本地演练 | `.github/workflows/ci.yml`（ubuntu-latest） |
| Rust | 工具链由 `rust-toolchain.toml` 锁定：**channel `1.96.1`** + `rustfmt` / `clippy`（workspace `rust-version = 1.96`） | `rust-toolchain.toml`、根 `Cargo.toml` |
| 网络 | 节点间 TCP 可达（默认示例端口 `17777`）；**无 discovery**，必须手工配置 peer | bin `--peer` 文档 |
| 磁盘 | 每节点独立 `chain` 与 `safety` 目录（持久化 + 安全日志） | §3.1 |

### 1.1 编译

```bash
git clone <repo>
cd nova
# 校验工具链与代码质量（与 CI 相同门禁）
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo build --workspace --release
# 产出：target/release/yazimao-node
```

### 1.2 启动命令（完整形态）

```
yazimao-node --genesis <path> --genesis-hash <hex64> --chain-id <u64> \
             --network-id <devnet|testnet|mainnet> --storage-dir <path> \
             --network-seed-file <path> [options]
```
必填：`--genesis`、`--genesis-hash`、`--chain-id`、`--network-id`、`--storage-dir`、`--network-seed-file`。
常用选项：`--listen <ip:port>`、`--peer <nodeid_hex@ip:port>`（可重复）、`--validator`、`--safety-dir`、
`--validator-seed-file`、`--idle-ms <1..50>`（默认 1）、`--run-steps <n>`（默认 5000；**`0` = 持续运行**）、`--help`、`--version`。

> **mainnet 限制**：`--validator` + `--network-id mainnet` 会被**拒绝**（Mainnet 级密钥管理未实现）。

---

## 2. Genesis 流程

### 2.1 生成（仅 genesis 负责人执行）

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  build --input genesis.json --out-dir out/genesis
```

产物（缺任意项即视为失败）：

| 文件 | 内容 |
|---|---|
| `genesis.bin` | canonical Genesis 二进制（**不是 JSON**；节点 `--genesis` 直接读取） |
| `genesis_hash.txt` | 64 位小写 hex + 换行（作为所有节点的 `--genesis-hash` 信任锚） |
| `genesis_summary.json` | 人工复核摘要（字段快照、计数、canonical 长度、hash、分配合计） |

行为约定：同名产物**默认拒绝覆盖**（需显式 `--force`）；输入含 `private_key` / `seed` / `mnemonic` / `secret` /
`keystore` 字段或占位值（空串 / `TBD` / `PENDING`）⇒ **直接拒绝**。

### 2.2 独立验证（复核人执行，read-only）

```bash
cargo run -p nova-genesis-builder --bin yazimao-genesis -- \
  verify --genesis out/genesis/genesis.bin --hash out/genesis/genesis_hash.txt
```
退出码：`0` 成功 · `1` 用法错误 · `2` 操作失败。

### 2.3 genesis_hash 校验（每个节点启动前）

1. 通过**带外渠道**（非代码仓库）取得权威 `genesis_hash`。
2. 与本地 `genesis_hash.txt` 逐字符比对（64 位小写 hex）。
3. 启动节点时传入同一 hash。节点将其作为**外部信任锚**（**绝不从 `genesis.bin` 反推**），
   并在启动前校验：`genesis hash` / `chain_id` / `network_id` 任一不符 ⇒ **拒绝启动（fail-closed）**。

---

## 3. 节点启动流程

### 3.1 目录规划（示例）

```
/etc/yazimao/genesis.bin              # 只读；由 Owner 分发
/etc/yazimao/genesis_hash.txt         # 只读；期望 hash
/etc/yazimao/network-seed-<node>.hex  # 64 hex；节点网络身份（每节点独立，离线生成）
/etc/yazimao/validator-seed-<node>.hex# 64 hex；仅验证者需要（离线生成）
/var/lib/yazimao/<node>/chain         # --storage-dir（区块 / 状态 / WAL / head）
/var/lib/yazimao/<node>/safety        # --safety-dir（仅验证者；vote/lock/identity journal）
```
seed 文件格式：**64 位小写 hex**（允许结尾换行）；文件权限 `0600`，属主为节点运行账号。

### 3.2 Seed node（Node-A：seed + validator）

```bash
target/release/yazimao-node \
  --genesis /etc/yazimao/genesis.bin \
  --genesis-hash <OWNER_GENESIS_HASH> \
  --chain-id <OWNER_CHAIN_ID> \
  --network-id testnet \
  --storage-dir /var/lib/yazimao/a/chain \
  --safety-dir  /var/lib/yazimao/a/safety \
  --network-seed-file   /etc/yazimao/network-seed-a.hex \
  --validator-seed-file /etc/yazimao/validator-seed-a.hex \
  --validator \
  --init-validator-safety \
  --listen 10.0.0.1:17777 \
  --idle-ms 1 --run-steps 0
```

> **`--init-validator-safety` 仅用于首次启动**（`--safety-dir` 下 `safety.journal` 尚不存在）。
> 重启（journal 已存在）**不得**携带：携带会被拒绝且报 `SafetyJournalAlreadyExists`（§6.6）。
> 该 flag 表示「创建新的 SafetyStore 状态」，**不是恢复**；mainnet 下被拒绝。

### 3.3 Validator（Node-B）

```bash
target/release/yazimao-node \
  --genesis /etc/yazimao/genesis.bin \
  --genesis-hash <OWNER_GENESIS_HASH> \
  --chain-id <OWNER_CHAIN_ID> \
  --network-id testnet \
  --storage-dir /var/lib/yazimao/b/chain \
  --safety-dir  /var/lib/yazimao/b/safety \
  --network-seed-file   /etc/yazimao/network-seed-b.hex \
  --validator-seed-file /etc/yazimao/validator-seed-b.hex \
  --validator \
  --init-validator-safety \
  --listen 10.0.0.2:17777 \
  --peer <A_node_id_hex>@10.0.0.1:17777 \
  --idle-ms 1 --run-steps 0
```

> 同上：`--init-validator-safety` **仅首次启动**携带；重启不得携带（§6.6）。

### 3.4 peer 配置

- 格式：`--peer <nodeid_hex>@<ip>:<port>`，可重复；**只有 configured peer**，无 discovery。
- **如何取得 `nodeid_hex`**：节点启动后 stdout 的启动行直接打印自身 NodeId：
  ```
  yazimao-node: runtime assembled (P1-A.3); node_id=<64 hex> listen=Some(10.0.0.1:17777) peer_auth=<true|false>; entering continuous run loop (run_steps=unlimited idle_ms=1)
  ```
  （`--run-steps` 有限时显示 `entering bounded run loop (run_steps=<n> ...)`。）
- 双向可达性：被 dial 的节点**必须**提供 `--listen`；否则对端无法建立连接。
- **无自动重连策略**：socket 断开后不会自动重连（见 §6.4）。

---

## 4. 网络拓扑示例（3 节点最小闭环）

```
        +--------------------+        +--------------------+        +--------------------+
        | Node-A             |  TCP   | Node-B             |  TCP   | Node-C             |
        | seed + validator   |<------>| validator          |<------>| observer/full node |
        | 10.0.0.1:17777     |        | 10.0.0.2:17777     |        | 10.0.0.3:17777     |
        +--------------------+        +--------------------+        +--------------------+
```

| 节点 | `--validator` | `--listen` | `--peer` | 说明 |
|---|---|---|---|---|
| Node-A | 是 | `10.0.0.1:17777` | （可省；建议配 B、C） | 供他人 dial 的入口 |
| Node-B | 是 | `10.0.0.2:17777` | `A@10.0.0.1:17777` | |
| Node-C | **否** | `10.0.0.3:17777` | `A@…`、`B@…` | observer/full node：同步区块，不投票 |

> 验证者集合是 **Genesis 静态集合**（`initial_validator_set`）；**没有**运行期注册、质押或开放准入。
> Node-C 不进入验证者集合，仅用于观察与同步验证。

---

## 5. 验收标准

| # | 验收项 | 判据 | 观测来源 |
|---|---|---|---|
| 1 | 节点成功启动 | stdout 出现启动行；进程存活；**无** `Error:` 输出 | stdout |
| 2 | block height 增长 | `head_height` 随 `steps` 递增；3 个节点最终一致 | periodic status 行 |
| 3 | finality 产生 | `finalized_height` 递增并最终 **== `head_height`**（不落后、不回退） | periodic status 行 |
| 4 | peer 连接成功 | `established_peers >= 1`；被 dial 方 `inbound_connections >= 1` | periodic status 行 |
| 5 | restart 恢复成功 | 同 `--storage-dir` / `--safety-dir` 重启后，`head_height` 与 `finalized_height` **不低于**重启前，且继续增长；重启命令**不得**携带 `--init-validator-safety` | 重启前后 status 行 |

periodic status 行（每 `STATUS_INTERVAL_STEPS = 100` 步一行）字段：

```
yazimao-node: status steps=<n> head_height=<h> finalized_height=<f> consensus_height=<c> round=<r>
              configured_peers=<n> established_peers=<n> inbound_connections=<n>
              sync_pending=<n> block_inbound_skipped=<n> pending_external_qc=<n> qc_served=<n>
              validator_enabled=<true|false>
```

### 5.1 验收记录模板

| 节点 | 启动行 NodeId | 启动时间 | head (t0) | head (t1) | finalized (t1) | established_peers | inbound_connections | 重启后 head | 重启后 finalized | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|
| A | | | | | | | | | | PASS/FAIL |
| B | | | | | | | | | | PASS/FAIL |
| C | | | | | | | | | | PASS/FAIL |

`genesis_hash`（三方必须一致）：`________________________________`

---

## 6. 故障处理

### 6.1 节点异常退出

1. 读取 stdout 的**退出摘要行**与错误行（形如 `Error: Run("BlockCommit: …")`）。
2. **不要删除或手工编辑** `--storage-dir` / `--safety-dir`；如需排查，先**整目录复制**备份。
3. 直接按原命令行重启（同目录、同 seed 文件）。持久化设计为 crash-consistent：重启会加载快照并重放 WAL。
4. 若同一错误可复现 ⇒ 停止重启，收集：启动行、退出摘要行、`Error:` 全文、最后一次 status 行，交 Owner。

### 6.2 WAL 恢复

- 正常路径：`--storage-dir` 下 `snapshot`（全量 KV）+ `WAL`（`batch_id + changes + SHA-256`）
  在启动时**自动**加载/重放；已 fsync 的写入不会丢失。
- 异常尾部（未完成的 WAL 记录）会被丢弃，不会导致启动失败。
- **禁止**手工编辑 `snapshot` / WAL / `blocks/**` 文件；任何以"修数据"为目的的改动都属于越权。
- 恢复判据：重启后 `head_height` / `finalized_height` ≥ 重启前，且继续增长（§5 第 5 项）。

### 6.3 genesis mismatch（拒绝启动）

| 现象 | 含义 | 处置 |
|---|---|---|
| `genesis hash ≠ --genesis-hash` | 本地 `genesis.bin` 与权威 hash 不符（文件被替换/版本错） | 从 Owner 带外渠道**重新获取** `genesis.bin` 与 hash，逐字符复核 |
| `genesis chain_id ≠ --chain-id` | 启动参数与 genesis 不一致 | 用 Owner 发布的 `chain_id` |
| `genesis network_id ≠ --network-id` | 同一网络的地址/参数会不兼容 | 用 Owner 发布的 `network_id`（Testnet） |

这三类均 **fail-closed**：节点拒绝启动，**不得**通过改参数"绕过"。

### 6.4 peer 断开 / 连接不建立

| 现象 | 可能原因 | 处置 |
|---|---|---|
| `established_peers = 0`（配置了 peer） | 目标未 `--listen`、地址/端口错、防火墙拦截 | 核对 `--listen`、`ip:port`、防火墙；用 `node_id` 与启动行核对 |
| 连接曾建立后断开 | **无自动重连策略**（当前实现） | 重启该节点使其重新 dial；持续掉线则记录并上报 |
| 只有单向连接 | 单向可达（NAT/安全组） | 两侧都配置 `--listen`（如需双向） |

### 6.5 停滞（无高度增长）

1. 观察 `sync_pending` / `pending_external_qc` / `qc_served` / `established_peers`。
2. 若三者均为 0 且 `head_height` 不增：确认本地是否为**当选 proposer**（多数节点应能在若干步内推进）。
3. 单节点卡住而其他节点正常 ⇒ 重启该节点（同目录），观察是否追平（catch-up）。
4. 全网无高度增长 ⇒ 立即停止演练，保留全部 status 行/日志片段，上报 Owner 判定。

### 6.6 safety journal 缺失（验证者拒绝启动）

validator 模式下，`--safety-dir` 下的 `safety.journal` 是本地 vote/lock 历史的**唯一 durable 记录**
（double-vote 防护）。因此它是启动**前置条件**：缺失时**拒绝启动**，绝不被隐式创建（ADR-0065）。

| 现象 | 含义 | 处置 |
|---|---|---|
| `Error: Runtime(SafetyJournalMissing)` | `safety.journal` 不存在：卷丢失 / 目录误删 / `--safety-dir` 变更 | 见下方流程；**不得**直接重新初始化 |
| `Error: Runtime(SafetyJournalAlreadyExists)` | 携带了 `--init-validator-safety`，但 journal **已存在** | 去掉该 flag（这是重启，不是初始化）；既有 journal 未被改动 |

**正常重启（journal 存在）**

```
journal exists
      ↓
strict recovery（header / identity / checksum 全部校验）
      ↓
继续参与（不带 --init-validator-safety）
```

**safety 卷丢失（journal 不存在）**

```
volume loss detected
      ↓
node refuses validator startup（fail closed；不产生 vote / 不重建 journal）
      ↓
operator 从备份恢复 safety 目录（整目录复制）
      ↓
restart（不带 --init-validator-safety）
```

**无备份可用**

```
no backup exists
      ↓
DO NOT silently initialize
      ↓
由 Owner 明确决定是否为该 validator 初始化新的安全状态
```

只有在 Owner 明确批准「该 validator 以**新的**安全状态重新开始」时，才可携带：

```
--init-validator-safety
```

> **`--init-validator-safety` 不是恢复。** 它创建**新的** SafetyStore 状态（空 vote/lock 历史），
> **不恢复**任何历史；旧状态无法由此找回。既有 journal 存在时该 flag **被拒绝**（journal 字节不变）。
> `--network-id mainnet` 下该 flag **被拒绝**：mainnet 丢失安全状态必须经备份恢复 / 单独授权。
> full-node / observer 不触碰 safety 路径，无 journal 也可以正常启动。

---

## 7. 安全与能力边界

**必须遵守**
- 私钥 / seed / mnemonic **绝不**入库、绝不粘贴到工单或聊天；seed 文件 `0600`。
- `genesis.bin` / `genesis_hash` 冻结后只读；变更 = 新链实例。
- 不得为"让测试变绿"而修改共识规则 / genesis 算法 / tokenomics / validator 经济模型。

**当前能力边界（诚实声明）**
- 无 peer discovery、无自动重连策略；zero-operator / permissionless bootstrap **未完成**。
- 无结构化日志与遥测（仅 periodic status 行与退出摘要行）；无 Explorer；无 RPC 服务。
- 交易路径未启用：出块为**空交易列表**；wallet / tx 客户端为占位。
- 无运行期质押/罚没/奖励；验证者集合为 Genesis 静态集合。
- **NOT MAINNET READY**。

---

## 8. 附录：速查

```bash
# 1) 构建
cargo build --workspace --release

# 2) 生成/验证 genesis（Owner / 复核人）
cargo run -p nova-genesis-builder --bin yazimao-genesis -- build  --input genesis.json --out-dir out/genesis
cargo run -p nova-genesis-builder --bin yazimao-genesis -- verify --genesis out/genesis/genesis.bin --hash out/genesis/genesis_hash.txt

# 3) 启动（见 §3.2/§3.3/§3.4 的完整参数）

# 4) 有限预算冒烟（本地演练）
target/release/yazimao-node … --run-steps 2000 --idle-ms 1

# 5) 代码门禁（与 CI 一致）
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```
