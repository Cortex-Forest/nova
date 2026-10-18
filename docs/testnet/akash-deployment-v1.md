# YAZIMAO L1 — Akash Testnet 部署说明 v1（**DRAFT FOR OWNER REVIEW**）

> **状态**：`DRAFT`。本文件与 `deploy/akash/testnet-sdl-v1.yaml` 只准备**可审查的部署描述**；
> **未**创建任何 Akash lease、**未**推送镜像、**未**启动 Testnet（属 Owner 授权范围外）。
> **拓扑与参数**：已批准基线，见 `../genesis/testnet-parameters-v1.md`（本文件不重新设计）。
> **运行手册**：`testnet-runbook-v1.md`（启动前准备 / 启动 / 验收 / 故障处置）。
>
> **2026-10-14 第二轮更新**：**官方** SDL 校验**已首次执行并通过**（§15，官方文档指定的客户端库途径）；
> 卷隔离获**官方证据**（§15.2）；Mount Guard 已落地为生产代码（§16）；`P-9`（持久化存储语法）与
> `P-12`（命名卷缺显式 `class`）已修复。**P-6 仍 = BLOCKED**，仅剩容器/Provider 侧实证（§19.3）。

---

## 1. 交付物与状态

| 交付物 | 路径 | 状态 |
|---|---|---|
| Akash SDL v2（1 Seed + 7 Validator） | `deploy/akash/testnet-sdl-v1.yaml` | `READY FOR REVIEW`（含显式占位，见 §5） |
| 本部署说明 | `docs/testnet/akash-deployment-v1.md` | `READY FOR REVIEW` |
| Testnet 参数记录 | `docs/genesis/testnet-parameters-v1.md` | `NEEDS OWNER INPUT`（身份/时间戳/分配） |
| 含 Testnet genesis 的镜像 | — | ❌ **不存在**（仓库现有内置 genesis 镜像为 **devnet**） |

> **本轮更新（2026-10-14，只修改本文件与 SDL）**：新增 §9 重启与 safety 初始化生命周期
> （含**已实测实质性阻断**与两种处置）、§10 静态 peer 两阶段配置、§11 seed 投递与持久卷。

---

## 2. 硬件与端口规划（SDL 已表达）

| 工作负载 | 数量 | CPU | RAM | 持久化卷 | 内部监听 | 公开端口 |
|---|---|---|---|---|---|---|
| Seed（仅 bootstrap） | 1 | 2 | 4 GiB | **60 GiB**（`data` → `/storage`） | `0.0.0.0:17770` | 17770/tcp |
| Validator 1–7 | 7 | 2 | 4 GiB | **60 GiB**（`data` 55 GiB → `/storage` + `safety` 5 GiB → `/safety`） | `0.0.0.0:17771`…`17777` | 17771–17777/tcp |

> 另加 **1 GiB 无名临时 root 卷**（官方语法的必需条目，**不**计入持久化容量）。
> 故每工作负载：**持久化 60 GiB / 总磁盘额度 61 GiB**。需求来源 = `docs/genesis/testnet-parameters-v1.md` §1
> “≥ 60 GiB 持久化”。

- **GPU OFF / TEE OFF**：SDL **不**请求 `gpu`/`tee` 段（= 关闭）。
- **端口依据**：代码**无**默认端口常量，`--listen` 省略即不监听（`crates/node/src/bin/yazimao-node.rs`）。
  故端口必须显式给出；本文件按已批准规划（Seed 17770 / Validator 17771–17777）写入。
- **公开端口理由**：peer 列表是**静态** `--peer <nodeid_hex@host:port>`，无 discovery ⇒ 每个被 dial 的
  节点必须可从对端到达（§4 的 8 节点全互联）。

---

## 3. 镜像（**PENDING：尚未发布**）

1. 现状（已核验）：
   - CI 只构建/推送 node 镜像到 `ghcr.io/cortex-forest/nova`（tag `sha-<short>`，**非 PR 才 push**）；
     `ci.yml:81` 明确"**不**部署（无 Akash / 无 SDL / 无 lease / 无 persistent volume）"。
   - `genesis-image/Containerfile` 是**派生层**：`FROM ghcr.io/cortex-forest/nova@sha256:1a394c1d…`
     + `COPY genesis.bin /read-only/genesis/genesis.bin`（0444）。
   - **当前内置的 genesis 是 devnet**（注释/label：`network_id 3 / chain_id 3004 / 1 validator`，
     `SHA256 c9a823c6…`）⇒ **不得**用于 Testnet。
2. 发布步骤（**需 Owner 授权镜像发布**）：
   ```bash
   # 1) 由正式 Testnet 输入生成 genesis（见 ../genesis/testnet-parameters-v1.md §2）
   # 2) 用 2.3 的官方 genesis.bin 替换 genesis-image/genesis.bin（本地临时目录，勿提交）
   # 3) 以 genesis-image/Containerfile 构建并推送，记录返回的 digest
   ```
   SDL 中的 `image:` 必须替换为该 **digest**（`REPLACE_WITH_TESTNET_GENESIS_IMAGE_DIGEST`）。
   **禁止**使用占位 tag，也**禁止**把 seal/seed 打进镜像。

---

## 4. NodeId 导出与 peer 表（两阶段启动的**原因**）

`nodeid_hex` = 由 `--network-seed-file` 派生的网络身份公钥，**只在启动行打印**：

```
yazimao-node: runtime assembled (P1-A.3); node_id=<64 hex> listen=Some(...) peer_auth=<bool>; entering … run loop
```

⇒ SDL 不能预先算出 8 个 NodeId。**离线导出（推荐，无网络、无共识）**：

```bash
# 对每个 seed 文件各跑一次，取启动行的 node_id=<64 hex>（bounded 运行，立即退出）
yazimao-node --genesis <path>/genesis.bin --genesis-hash <64 hex> --chain-id 2002 \
  --network-id testnet --storage-dir /tmp/nid-probe-<n> \
  --network-seed-file <path>/network-seed-<n>.hex --run-steps 1
```

然后填写 SDL 中所有 `REPLACE_*_NODEID` / `REPLACE_*_HOST`（host 取 lease 端点）。
**全互联要求**：8 个节点两两可达（每个 Validator 与 Seed 及另外 6 个 Validator 互配 `--peer`）。

---

## 5. 部署前必须关闭的 PENDING 项（SDL 头部注释同源）

| # | 项 | 依据 / 影响 |
|---|---|---|
| P-1 | 发布含**正式 Testnet genesis** 的镜像 digest | 现有镜像内置 devnet genesis；不可混用 |
| P-2 | 冻结 `genesis.bin` + `genesis_hash`（64 hex） | 节点把 `--genesis-hash` 当外部信任锚，**绝不**从文件反推 ⇒ 缺失即无法启动 |
| P-3 | **身份 seed 投递机制** | `--network-seed-file`/`--validator-seed-file` 为**必需文件参数**；CLI **不读环境变量**，Akash **无** secret 文件注入 ⇒ 需 Owner 决定（严禁写入镜像/SDL/仓库） |
| P-4 | 8 个 NodeId + lease 端点填入 `--peer` | 见 §4 |
| P-5 | 持久卷可写性（UID/GID 10001） | 容器以非 root 运行；卷默认 root 拥有 ⇒ 需确保 `/storage`、`/safety` 可写（否则 BlockStore/safety journal 写入失败 → fail-closed 退出） |
| P-6 | **【实质性阻断】** 首次启动 vs 重启的参数差异 | 本 SDL 各 Validator **无条件**传 `--init-validator-safety` ⇒ 第 2 次启动必失败（`runtime.rs:3744/3767`，错误名已实测）。处置见 §9：**方式 A（手工两步，推荐）** / 方式 B（入口包装，未在容器验证） |
| P-7 | 用 akash/provider-services 工具链做 SDL 校验 | 本机**无**该 CLI；本次只做 §7 的**本地结构校验** |
| P-8 | 占位符未替换前不可启动 | `--genesis-hash REPLACE_...` ⇒ `Error: Cli(InvalidGenesisHash)`（exit 1，已实测）；`--peer REPLACE_*@…` 需 `<64 hex>@<ip:port>`（见 §7/§10） |

---

## 6. 部署（**Owner 授权后才执行**；本文件不代为执行）

```bash
# 1) 创建部署（示例；denom/费用以 Owner 授权为准）
akash tx deployment create deploy/akash/testnet-sdl-v1.yaml --from <owner-key> --node <rpc> --chain-id <akash-chain> --deposit 5uakt
# 2) 选择 provider 并发送 manifest
provider-services send-manifest deploy/akash/testnet-sdl-v1.yaml --dseq <dseq> --from <owner-key> --provider <provider>
# 3) 查看状态与日志（无 HTTP 健康端点，日志即主要观测面）
provider-services lease-status  --dseq <dseq> --from <owner-key> --provider <provider>
provider-services lease-logs    --dseq <dseq> --from <owner-key> --provider <provider>
```

**观测说明（已核验）**：节点只输出 **stdout 文本行**（启动行 + 每 `STATUS_INTERVAL_STEPS = 100` 步一行
status + 退出摘要行）；容器**无** `HEALTHCHECK`、**无** HTTP/健康端点、**无**优雅关闭（SIGTERM 走 OS 默认），
持久化设计为 **crash-consistent**（快照 + WAL 重放）。⇒ **不要**为 SDL 编造健康探针；
验收一律按 `testnet-runbook-v1.md` §5 的 status 行字段判定。

---

## 7. 本次已执行的本地校验（范围诚实声明）

| 校验 | 方法 | 结果 |
|---|---|---|
| YAML 可解析 + SDL v2 关键结构 | 本地 Python（`yaml.safe_load`）+ 结构断言（8 services / 每 service 有 image+command+expose / `deployment` 引用存在的 `profiles` / 端口唯一且等于 17770…17777 / 每 profile 有 cpu·memory·storage / 卷挂载名与 profile 声明一致） | 见执行报告 §F |
| CLI 参数真实性 | 与 `crates/node/src/bin/yazimao-node.rs` 逐一对照（含拒绝规则） | ✅ 全部为真实参数 |
| 路径真实性 | 与 `Containerfile` / `genesis-image/Containerfile` 对照（`/storage`、`/safety`、`/read-only/genesis/genesis.bin`、USER 10001） | ✅ |
| Akash 工具链校验 | `akash` / `provider-services` | ❌ **未执行**（本机无该 CLI，且未授权外部操作） |
| CLI 占位符 fail-closed | 真实节点二进制 + 本 SDL 的占位参数启动 | ✅ `Error: Cli(InvalidGenesisHash)`，exit **1** |
| Seed 命令形态可用 | 真实二进制 + 合成 genesis（`chain_id=2002/network_id=2`）+ 本地测试 seed，`--run-steps 50` | ✅ exit **0**；启动行 + 有界退出；`wal.log` 写入 `--storage-dir` |
| 验证者身份门禁 | 同上但加 `--validator`（测试身份不在 genesis 集合） | ✅ `Error: Identity(ValidatorNotInValidatorSet)`，exit **1**；**未**创建 journal |
| safety 生命周期（单元） | `cargo test -p nova-node --lib safety_store::tests` / `block_safety::tests` / `--bin yazimao-node` | ✅ **16/16、24/24、55/55** 通过，exit 0 |
| safety 生命周期（集成） | `cargo test -p nova-node --test runtime_tests g5d72` / `--test restart_safety_tests rt_` | ✅ **3/3、16/16** 通过，exit 0 |
| 入口包装脚本（方式 B） | — | ❌ **未执行**（本机无 POSIX shell：无 docker/podman/Git-bash，WSL 无已安装发行版） |

> 结论口径：SDL 是**结构上自洽、参数真实、含显式 PENDING 占位**的审查草案；
> **不等于**"可部署"或"已验证可调度"。

---

## 8. 未执行的外部动作（明确声明）

- ❌ 未创建 Akash lease / 未产生付费资源 / 未注册 provider。
- ❌ 未构建或推送任何镜像 / 未创建 tag / 未发布任何网络资源。
- ❌ 未生成或冻结正式 Testnet Genesis / 未分发任何 hash。
- ❌ 未修改 ADR、经济政策、共识规则、网站仓库。

---

## 9. 重启与 safety 初始化生命周期（本轮验证）

### 9.1 根因（已实测的实质性阻断）

Validator 模式下，两枚持久化 journal 由**同一个** flag 门控，且是严格的 2×2 矩阵（`crates/node/src/runtime.rs`）：

| 文件 | 检查/创建点 |
|---|---|
| `<--safety-dir>/safety.journal` | 路径 `:3740`；遗漏+无 flag ⇒ `SafetyJournalMissing` `:3747`；已存在+flag ⇒ `SafetyJournalAlreadyExists` `:3744` |
| `<--safety-dir>/block-safety.journal` | 路径 `:3753`；同上 `:3770` / `:3767` |

（空卷 + flag ⇒ `create_new(true)` 创建两枚文件，各 114 B header；`--safety-dir` 内不写其他文件。）

>> **因此：本 SDL 原本的“固定启动命令”在**每一次重启**都会传 `--init-validator-safety`
>> ⇒ 第 2 次启动必定 `Error: Runtime(SafetyJournalAlreadyExists)` 而拒启。
>> 这是本 SDL 的**实质性阻断**（不是未来待办），必须在部署前选择下列处置之一。

### 9.2 节点侧安全性质（已由测试验证，可作为所有处置方案的依据）

| 性质 | 验证（本轮实跑） |
|---|---|
| 空卷 + flag ⇒ 创建有效 journal | `g5d72_t2_fresh_explicit_initialization_creates_valid_journal` ✓ |
| 缺 journal + 无 flag ⇒ 拒绝启动，且**不会**被隐式重建 | `rt_25_missing_safety_journal_fails_closed`、`g5d72_t1_missing_journal_fails_closed_and_is_not_recreated` ✓ |
| 已有 journal + flag ⇒ 拒绝，且**字节不变** | `g5d72_t3_existing_journal_rejects_initialization_and_keeps_bytes` ✓ |
| `create` **永不**覆盖既有历史 | `safety_store::…::create_never_overwrites_existing_history`、`block_safety::…::create_never_overwrites_existing_journal` ✓ |
| 损坏 / 截断 ⇒ fail-closed，**不**丢弃尾部记录 | `rt_12_corrupted_checksum_fails_closed`、`rt_13_truncated_record_fails_closed_not_discarded`、`block_safety::…::truncated_tail_and_bad_checksum_fail_closed` ✓ |
| 仅有其中一枚 journal（不完整状态）⇒ 对缺失那枚报 `SafetyJournalMissing` | 代码路径 `:3747`/`:3770`（同一矩阵） |
| 代码中**不存在**删除/截断/重建既有 journal 的路径 | （已代码审计；`remove_file` 仅出现在 `qc_history.rs` 的 tmp 清理） |

CLI 层面：`--init-validator-safety` 必须与 `--validator` 同时出现（`g2`），mainnet 拒绝（`g3`），重复传报错（`g4`），`--help` 列出（`g5`）。

### 9.3 方式 A（推荐：无新增构件、纯操作性）

- **首次部署**：使用本 SDL 原样的 `command`（含 `--init-validator-safety`）⇒ 在空卷上创建两枚 journal。
- **此后每次重启 / 更新部署**：使用**去掉** `--init-validator-safety` 的同一命令（其余参数、卷名、挂载路径一字不改）。
- **可重复性**：两种状态下重复执行都是确定的——状态与参数不匹配时节点 fail-closed 拒绝，**绝不会**静默重建或删除既有 journal。
- **不完整/损坏状态**：仅一枚 journal 存在 ⇒ 节点报 `SafetyJournalMissing` 并拒绝启动（**不得**重试 flag 绕过）；正确处置 = 从备份整目录恢复 → 不带 flag 启动；无备份 ⇒ 上报 Owner（该节点不得继续参与共识）。

### 9.4 方式 B（入口包装：可审查，但本轮**未在容器中验证**）

若 Owner 希望自动化，可将 SDL 的 `command` 换为 `["/bin/sh","-c", <下方脚本>]`（保持 exec 形式传递信号）：

```sh
set -eu
SAFETY_DIR=/safety
VOTE_JOURNAL="$SAFETY_DIR/safety.journal"
BLOCK_JOURNAL="$SAFETY_DIR/block-safety.journal"
if [ -e "$VOTE_JOURNAL" ]; then have_vote=1; else have_vote=0; fi
if [ -e "$BLOCK_JOURNAL" ]; then have_block=1; else have_block=0; fi
if [ "$have_vote" -eq 1 ] && [ "$have_block" -eq 1 ]; then
  INIT=""                          # 重启：两枚 journal 已在 ⇒ 绝不重新初始化
elif [ "$have_vote" -eq 0 ] && [ "$have_block" -eq 0 ]; then
  INIT="--init-validator-safety"    # 首次启动：空持久卷
else
  echo "FATAL: inconsistent safety state under $SAFETY_DIR (vote=$have_vote block=$have_block)" >&2
  exit 78
exec /usr/local/bin/yazimao-node \
  --genesis /read-only/genesis/genesis.bin \
  --genesis-hash <FROZEN_HASH_64HEX> \
  --chain-id 2002 --network-id testnet \
  --storage-dir /storage --safety-dir /safety \
  --network-seed-file /read-only/secrets/network-seed.hex \
  --validator-seed-file /read-only/secrets/validator-seed.hex \
  --validator --listen 0.0.0.0:<PORT> \
  <PEER_ARGS> $INIT --idle-ms 1 --run-steps 0
```

| 约束（本轮指令 §4） | 方式 B 如何满足 |
|---|---|
| 不自动删除/覆盖/重建 journal | 脚本只做 `-e` 存在性测试，从不写/删；节点侧 `create_new` 仍是否决者 |
| 不以忽略错误掩盖状态问题 | 不完整状态 ⇒ 显式 `exit 78`；否则交给节点自身 fail-closed |
| 不在已有 journal 时再初始化 | 两枚均在 ⇒ `INIT` 为空 |
| 不将 seed/私钥写入日志 | 脚本只输出**路径**，不读/不打印文件内容；节点错误串不含 seed 字节 |
| 首次启动与重启可重复执行 | 决策完全由持久卷状态决定（幂等） |
| 缺失/损坏安全状态明确失败 | 缺失 ⇒ 节点 `SafetyJournalMissing`；损坏 ⇒ 节点 `TruncatedRecord`/`ChecksumMismatch`（均 fail-closed） |

> **验证状态（诚实声明）**：方式 B 的脚本**未在任何容器或 POSIX shell 中执行过**——本机无
> `docker`/`podman`、无 Git-bash、WSL **无已安装发行版**（均已实测）。`debian:bookworm-slim`
> 提供 `/bin/sh`（dash）与 `[` 内建属于**推断**（官方基础镜像且 runtime 阶段无 `apt` 安装），
> 未经本机实验。⇒ 按本轮停止条件，**未**把该脚本落地为仓库构件；若采用方式 B，需 Owner
> 批准并在具备容器运行时的环境中先验证。注意：`genesis-image/*` 本轮禁止修改。

---

## 10. 静态 peer 两阶段配置

**可在部署前获得的值**：genesis / `genesis_hash` / `chain_id` / `network_id` / 端口 / 目录 / seed 文件（由 Owner 提供）。
**只能在部署后获得的值**：每个 service 的 lease 端点（host）。
**必须先有 seed 文件才能获得的值**：8 个 `nodeid_hex`（由 `--network-seed-file` 派生，仅启动行打印）。

两阶段流程：

1. **准备阶段（离线，不需网络/共识）**：对每份 network seed 各跑一次
   `yazimao-node --genesis <path> --genesis-hash <64hex> --chain-id 2002 --network-id testnet \
   --storage-dir /tmp/nid-probe-<n> --network-seed-file <path>/network-seed-<n>.hex --run-steps 1`
   ⇒ 从启动行取 `node_id=<64 hex>`。
2. **最终配置阶段**：把 `<nodeid>@<host>:<port>` 填入 SDL 全部 `REPLACE_*`（每 Validator 7 条，Seed 7 条），
   更新部署。**更新时不得改动卷名/大小/挂载路径**（否则 `/storage`、`/safety` 失联 ⇒ journal 丢失 ⇒ 拒绝启动）。

约束与校验：不会出现“把自身当 peer”（节点 `validate_network_targets` 拒 self/重复）；不得遗漏连接（全互联）；
占位符未替换前启动必失败（`Error: Cli(InvalidGenesisHash)`，已实测）。迁移时可本地用脚本枚举每个 service 的 `--peer`
数量必须是 7 且不含自身 NodeId。

> 未解决依赖：P-1（镜像）→ P-2（genesis）→ P-3（seed 投递）必须先闭合，才能产出真实 NodeId（P-4）。

---

## 11. seed 投递与持久卷（已验证事实 / 阻断 / Owner 决策）

### 11.1 CLI 硬要求（已核验）
- 两枚 **文件**：`--network-seed-file`（必需）；`--validator-seed-file`（`--validator` 时必需）；内容为 32 字节 hex
  （大小写均接受；仅**尾部**空白被 trim）；**不读任何环境变量**（`-e` 无效）；两 seed 派生身份相同 ⇒ 拒绝。
- `--safety-dir` 在 validator 模式**必需**（缺 ⇒ CLI 错误）；full-node 模式下仅占位（默认 `<storage-dir>/safety`，不创建/不读取）。
- 每节点**必须独立身份**：不同 Validator 必须使用不同（且互异）的 network/validator seed。

### 11.2 阻断（未变，维持 P-3）
**seed 投递机制仍未确定**：Akash 无 secret 文件注入，节点只接受文件路径，且 CLI 无 seed 生成子命令。
候选（① Owner 私有镜像层注入；② provider 侧预置只读卷）**均需 Owner 批准**；本轮**不**自行决定密钥托管方案。
禁止：写入 SDL / Git / 镜像层 / 普通日志。

### 11.3 持久卷（已核验）
- `--storage-dir` 内：`wal.log`、`snapshot`、`blocks/`（运行期实测已生成 `wal.log`）；快照提交 = 同文件系统 `rename` ⇒ 卷必须支持同 FS rename。
- `--safety-dir` 内：`safety.journal`、`block-safety.journal`（首次初始化各 114 B header）。
- 容器以 **UID/GID 10001** 运行且 runtime 阶段**无** `apt` 安装 ⇒ 卷必须对 10001 可写（否则 BlockStore / journal 写入失败 ⇒ fail-closed）。
- 挂载一致性：SDL 计算 profile 的 `storage` 条目名（`data`/`safety`）与服务 `params.storage.<name>.mount` 必须一致；挂载点为 `/storage`、`/safety`。本地结构检查已断言该一致性（§7），且该一致性现已由**官方库校验**确认（**P-7 关闭**，见 §15）。

---

## 12. P-6 审计结论（2026-10-14，只读审计）：**BLOCKED**

### 12.1 结论与依据

**P-6 = BLOCKED**（不可关闭）。依据三条，均为本轮实测/当前源核验：

1. **平台语义未验证**：本仓库内**无** Akash 规范/SDL 工具链（`akash`、`provider-services` 均 `NOT FOUND`），`ci.yml:81` 明确 CI 不部署；因此“平台自动重启是否复用**更新后**的 `command`”、“更新失败/回滚是否会把 `--init-validator-safety` 带回”均属 **UNVERIFIED**（不得假定）。
2. **容器 E2E 不可运行**：本机无 `docker`/`podman`、无 POSIX shell（`sh` 不存在；WSL **无已安装发行版**）⇒ `/bin/sh` 可用性与入口脚本行为**无法实测**；按停止条件，方式 B **不落地、不声称修复**。
3. **半完成状态无测试覆盖**（本轮代码推导，见 §12.3）。

### 12.2 三方案比较（不得混为一谈）

| 方案 | 首次启动 | 平台自动重启 | 更新 / 回滚 | 安全状态保护 | 真实环境验证 | 结论 |
|---|---|---|---|---|---|---|
| **A** SDL 固定命令 + 人工移除 flag | ✅ 节点语义已验证（空卷+flag ⇒ `create_new` 创建两枚） | ❌ **UNVERIFIED**（依赖 Akash 是否对自动重启使用更新后 command） | ⚠️ 回滚可能带回 flag ⇒ 节点拒启（fail-closed，但需人工介入） | ✅ 节点从不删除/覆盖/重建 | ❌ 未做 | **不足以关闭 P-6** |
| **B** 入口包装脚本 | ⚙️ 设计上可行（两枚不存在 ⇒ 传 flag）；**未在容器执行** | ⚙️ 设计上幂等（两枚均在 ⇒ 不传 flag）；**UNVERIFIED** | ⚙️ 同 A 依赖平台语义 | ✅ 仅做存在性测试；半完成 ⇒ `exit 78` | ❌ **未做**（无容器/无 shell） | **不落地、不声称修复** |
| **C** 两阶段人工运维 | ✅ 可（同 A） | ❌ **UNVERIFIED**（同 A） | ❌ **UNVERIFIED** | ✅ 依赖节点 fail-closed | ❌ 未做 | 仅作**运维预案**，不能关闭 P-6 |

> 三种方案的**节点侧**语义都已验证；未验证的是 **Akash 平台的 command/重启/回滚语义**与**容器内执行**。
> 因此本项不能因文档已写、单元测试通过或自定义静态检查通过而标记为 CLOSED。

### 12.3 半完成状态危害（代码推导；**无专用测试覆盖**）

初始化顺序：先 `safety.journal`（`runtime.rs:3740-3747`），再 `block-safety.journal`（`:3753-3770`）。
若第一枚创建成功、第二枚创建前进程被杀死（或第二枚 `create` 因 IO/权限/空间失败），则留下
**仅一枚 journal** 的状态。此时两条启动路径**都拒绝**：

- 带 flag ⇒ 第一枚命中 `(true,true)` ⇒ `SafetyJournalAlreadyExists`（`:3744`）——**根本到不了第二枚**；
- 不带 flag ⇒ 第二枚命中 `(false,false)` ⇒ `SafetyJournalMissing`（`:3770`）。

⇒ 该状态**无法由节点自行修复**，只能从备份整目录恢复（或经 Owner 批准的运维干预）。
本轮已全仓检索：**不存在**针对“仅一枚 journal”的 runtime 级测试 ⇒ 标记为**代码推导、未测试**。

### 12.4 关闭 P-6 的最小条件

1. 一个**可运行的容器环境**（docker/podman 或真实 Akash 环境）；
2. 一份可用 genesis **+ 与之一致的验证者身份**（否则被身份门禁拒启；真身份/专用测试密钥**需 Owner 授权**）；
3. 对 Akash 官方语义的**可引证确认**：更新后自动重启使用哪条 command；回滚行为；
4. 在上述环境跑通四条路径：**空卷首启 → 平台自动重启 → 更新 → 回滚**，并断言 journal **未被重复初始化**。

### 12.5 本轮证据摘要（与当前源/当前 SDL 一致，均重跑）

| 项 | 结果 |
|---|---|
| CLI flag 集与拒绝规则（`runtime.rs:3740-3772`、`bin/yazimao-node.rs`） | ✅ 与 §9.1 一致（含 `create_new` 与竞态 ⇒ AlreadyExists fail-closed） |
| SDL 每个 Validator 的 `command` | ✅ 确认**无条件**携带 `--init-validator-safety`，**无**入口包装，exec 形式直接调用二进制 |
| 单元/集成测试（重跑） | ✅ `safety_store` 16/16、`block_safety` 24/24、`bin` 55/55、`runtime_tests g5d72` 3/3、`restart_safety_tests rt_` 16/16（均 exit 0） |
| 官方 SDL 校验 | ❌ **NOT PERFORMED**（无工具链，未安装任何软件） |
| 容器内 Validator 自动重启 E2E | ❌ **CONTAINER_E2E = NOT RUN** |

---

## 13. P-6 One-shot 审计（2026-10-14）：回归测试 + 官方 Akash 语义证据

### 13.1 子状态矩阵（§10.2 口径；**不得与整个 P-6 混为一谈**）

| 子项 | 状态 |
|---|---|
| **P-6（整体）** | **BLOCKED** |
| `SAFETY_JOURNAL_REGRESSION` | **FAIL**（T4 红：生产实现存在状态副作用，见 §13.4） |
| `RUST_TESTS` | 本任务新增 4 项：**3 PASS / 1 FAIL**（T4=预期红）；既有套件全新绿：`safety_store` 16/16、`block_safety` 24/24、`bin` 55/55、`restart_safety_tests` 16/16；`runtime_tests` **12/15**（失败 3 = T4 + **2 个既有失败**，见 §13.5） |
| `AKASH_SEMANTICS` | **部分 VERIFIED / 部分 UNVERIFIED**（§13.2） |
| `CONTAINER_E2E` | **NOT RUN**（无容器运行时/POSIX shell；WSL 无发行版） |
| `VOLUME_MOUNT_GUARD` | **UNVERIFIED**（§13.6；且新增严重发现 §13.3） |
| `OFFICIAL_SDL_VALIDATION` | **NOT PERFORMED**（无 `akash`/`provider-services`；未安装任何软件） |

### 13.2 Akash 官方语义证据表

来源：Akash 官方站点 “**SDL Syntax Reference**”（`akash.network/docs/developers/deployment/akash-sdl/syntax-reference`），2026-10-14 读取；另读 “SDL (Stack Definition Language)” 概览页。

| # | 问题 | 结论 | 标记 | 证据（章节/写法） |
|---|---|---|---|---|
| 1 | `command` 定义与格式 | `command` **可选，用于覆盖容器 entrypoint**；官方示例 `command: [/bin/sh, -c]` + `args: [<脚本>]` ⇒ 本 SDL 将完整 argv（二进制+参数）放入 `command` 属**合法**用法 | **VERIFIED**（官方文档） | Services → command & args |
| 2 | `command` 是否替换镜像默认入口 / argv 处理 | 是：覆盖 entrypoint；`args` 为独立字段 | **VERIFIED**（官方文档） | 同上 |
| 3 | 进程异常退出后的重启行为 | 官方页面**未述** | **UNVERIFIED** | — |
| 4 | 更新后新容器使用哪一版 command | 官方页面**未述** | **UNVERIFIED** | — |
| 5 | 更新失败/回滚后生效定义 | 官方页面**未述** | **UNVERIFIED** | — |
| 6 | 命名卷在重调度/重建/更新期间的保留 | **部分 VERIFIED**：持久化需 `name` + `attributes: {persistent: true}`（官方注释 “Survives restarts”）；`count` **部署后不可修改**（Max 50） | **VERIFIED（语法）**；保留细节仍部分 UNVERIFIED | Profiles → compute → storage；Deployment |
| 7 | `count: 1` 是否排除更新期新旧实例短暂重叠 | 官方页面**未述** | **UNVERIFIED** | — |
| 8 | 官方 SDL 验证器能否校验本文件 | 本机无工具链 ⇒ 未执行 | **NOT PERFORMED** | — |

> 已排除的猜测：官方文档**未**将 Web 上一般 Kubernetes 语义作为 Akash 事实陈述；上表仅采信官方页面原文。

### 13.3 【已修复 · 2026-10-14】存储条目持久化语法（原为严重缺陷 P-9）

- 官方写法（Profiles → compute → storage）：
  ```yaml
  storage:
    - size: 1Gi                    # 至少一个临时 root 卷（必需）
    - name: data                   # 持久卷（可选）
      size: 10Gi
      attributes:
        persistent: true           # “Survives restarts”
        class: beta3
  ```
- 本 SDL 现状：仅 `- name: data / size: 60Gi`（Seed）与 `- name: data 55Gi` + `- name: safety 5Gi`（Validator），**无 root 卷条目、无 `attributes.persistent`**。
- **后果**：即使卷被正确挂载，也**不保证跨重启保留** ⇒ `safety.journal`/`block-safety.journal` 与 chain 数据可能丢失 ⇒ **P-6 的“重启使用既有 journal”前提不成立**（无 flag ⇒ 拒启；有 flag ⇒ 在 §13.4 的缺陷下会留下空历史）。
- **最小变更建议（本轮未实施）**：`- size: 1Gi`（临时 root）+ `data: 54Gi / persistent: true` + `safety: 5Gi / persistent: true`（合计 60 GiB/节点）。
  > ⚠️ 以上为 **2026-10-14 修复前**的历史记录（`54Gi` 是当时的建议值，后已证明持久量不足）。
  > **当前实际值见 §14.1**：Seed `data 60Gi`；Validator `data 55Gi` + `safety 5Gi`（持久 60 GiB / 总 61 GiB）。
- **未实施原因**：修改 SDL 运行结构超出本任务授权（§1），且**无官方校验器**可用 ⇒ 只记录证据与最小变更建议，待 Owner 授权。
- SDL 头部已加 **P-9** 注释记录同一事实。
- ✅ **本轮已修复（2026-10-14）**：临时 root 卷 + 命名持久卷 `attributes.persistent: true` 已写入 SDL；
  本节“未实施/待授权”描述已由 **§14.1** 取代（容量口径歧义与官方校验未执行仍保留为遗留项）。

### 13.4 新增半完成状态回归测试（`crates/node/tests/runtime_tests.rs`）

| 用例 | 构造 | 断言 | 结果 |
|---|---|---|---|
| `rt_safety_journal_partial_vote_only_without_init_fails_closed`（T1） | 生产 `ValidatorSafetyStore::create` 写 vote header；无 block | 启动失败 = `SafetyJournalMissing`；vote **字节不变**；block **未被创建** | ✅ **PASS** |
| `rt_safety_journal_partial_block_only_without_init_fails_closed`（T2） | 生产 `BlockSafetyJournal::create` 写 block header；无 vote | 启动失败 = `SafetyJournalMissing`；block **字节不变**；vote **未被创建** | ✅ **PASS** |
| `rt_safety_journal_partial_vote_only_with_init_flag_fails_closed`（T3） | 仅 vote + `validator_safety_init = true` | 拒绝 = `SafetyJournalAlreadyExists`；vote **字节不变**；block **未被创建** | ✅ **PASS** |
| `rt_safety_journal_partial_block_only_with_init_flag_fails_closed`（T4） | 仅 block + `validator_safety_init = true` | 拒绝 = `SafetyJournalAlreadyExists`（✓）；block 字节不变（✓）；**不得静默创建 vote journal（✗ 失败）** | ❌ **FAIL（预期红）** |

**T4 失败即生产行为证据**（实测，非推导）：失败启动路径 **创建了一枚空历史 `safety.journal`**（断言 `!vote.exists()` 失败，`runtime_tests.rs:779`）。

- 生产根因（当前源）：`crates/node/src/runtime.rs:3745-3746` 在 vote 分支 `(false, true)` **先执行 `create`**，随后才在 block 分支 `:3767` 因 `(true, true)` 拒绝。
- **安全影响**：该失败会留下“vote = 空 header / block = 有历史”的状态；若随后**不带 flag** 启动 ⇒ 两枚均存在 ⇒ **可正常恢复但 vote ledger 为空**（丢失 vote/lock 历史）⇒ **double-vote 风险面**。
- 处置：按本任务 §5.1 **未修改生产逻辑**；作为生产级阻断上报（§14 P0-1）。修复选项（待 Owner/设计裁定）：① 将两枚 journal 的存在性检查**前置**到任何 `create` 之前；② 或要求初始化 flag 仅在**两枚均不存在**时才被接受。

### 13.5 本轮测试台账（真实命令与退出码）

| 命令（`--locked --offline`，`--target-dir %TEMP%\nova-tn1-target`） | 退出码 | 结果 | 日志 |
|---|---|---|---|
| `cargo test -p nova-node --test runtime_tests rt_safety_journal_partial -- --test-threads=1` | **101** | 4 tests：**3 passed / 1 failed**（T4） | `%TEMP%\nova-p6-oneshot\new4.txt` |
| `cargo test -p nova-node --test runtime_tests -- --test-threads=1`（全集） | **101** | 15 tests：**12 passed / 3 failed** = T4 + `rt_28_validator_id_mismatch_startup_fails` + `rt_29_runtime_processes_consensus_command` | `full-rt.txt` |
| 同上，过滤 `rt_2`（**排除本任务新测试**） | **101** | 6 tests：4 passed / **2 failed**（同上两个）⇒ **既有失败，与本任务无关** | `rt2.txt` |
| `cargo test -p nova-node --test restart_safety_tests -- --test-threads=1`（全集） | **0** | **16 passed / 0 failed** | `full-rs.txt` |
| `cargo test -p nova-node --lib safety_store::tests` | **0** | **16 passed / 0 failed** | `lib1.txt` |
| `cargo test -p nova-node --lib block_safety::tests` | **0** | **24 passed / 0 failed** | `lib2.txt` |
| `cargo test -p nova-node --bin yazimao-node` | **0** | **55 passed / 0 failed** | `bin.txt` |
| 本地自定义 SDL 结构检查（非官方） | **0** | 115/115 | （脚本：`%TEMP%\nova-tn1\sdl_check.py`） |

> 既有失败定位：`runtime_tests.rs:307`（`rt_28_validator_id_mismatch_startup_fails`）与 `:340`（`rt_29_runtime_processes_consensus_command`），失败形态为 `left: None` vs `right: Some(ProposalRef{block_hash:[170,…]})`，属身份/共识命令处理范畴，**与 journal 无关**；且在不含本任务新测试的过滤运行中**同样失败** ⇒ 归因于当前工作区既有状态（此前各轮仅跑过 `g5d72` 过滤，从未跑该目标全集）。

### 13.6 卷未挂载风险审查（未添加任何挂载检测逻辑）

- 基础镜像 **内已存在** `/storage`、`/safety` 目录（Dockerfile 创建，属 uid 10001）⇒ 若持久卷**未挂载或未持久化**，存在性检查会看到“两枚 journal 均不存在” ⇒ 在**容器可写层**初始化 ⇒ 重启后丢失（无 flag ⇒ 拒启；有 flag ⇒ 结合 §13.4 会留下空历史）。
- 当前部署**无任何挂载验证机制**（无健康探针、无标记文件、无设备号核对）⇒ 标记 **UNVERIFIED**；需部署期运维校验或后续获授权的防护逻辑。
- 本任务**未**添加挂载检测逻辑、未修改镜像入口（超授权）。

### 13.7 本轮修改与证据位置

| 文件 | 变更 |
|---|---|
| `crates/node/tests/runtime_tests.rs` | 新增 4 个半完成状态回归测试 + 1 行 import（`block_safety::{BlockSafetyIdentity, BlockSafetyJournal}`）+ 2 个预置 helper；**未修改任何生产代码** |
| `deploy/akash/testnet-sdl-v1.yaml` | **仅注释**（状态行 + 新增 P-9）；服务/profile/deployment/卷结构**未改**（结构检查仍 115/115） |
| `docs/testnet/akash-deployment-v1.md` | 新增 §13（本节） |

证据日志：`%TEMP%\nova-p6-oneshot\`（status/check/diffstat/untracked + `new4.txt`/`full-rt.txt`/`rt2.txt`/`full-rs.txt`/`lib1.txt`/`lib2.txt`/`bin.txt`）。
**未执行的外部操作**：未安装任何软件；未创建容器/远程资源/lease；未产生费用；未构建/推送镜像；未修改 Genesis；未生成或分发任何密钥；未 `git add`/commit/push/tag/release。

### 13.8 P-6 最小关闭条件（本轮更新）

1. 修正 **§13.3** 的存储语法缺陷（获 Owner 授权的 SDL 结构修改 + 官方工具链校验）；
2. 裁定 **§13.4** 的生产行为（T4）——修复后 T4 必须转绿；
3. 可运行的容器环境（docker/podman 或真实 Akash），用以跑通：空卷首启 → 自动重启 → 更新 → 回滚，并断言 journal 未被重复初始化；
4. 可用 genesis + 与之一致的验证者身份（否则身份门禁拒启）；
5. 对 Akash **更新/回滚/自动重启语义**的可引证确认（当前 UNVERIFIED）。

---

## 14. Remediation（2026-10-14）：SDL 持久化修复 + safety 初始化原子性修复

### 14.1 SDL 存储布局（2026-10-14 落地；2026-10-18 **R4 容量更正**）

| 工作负载 | 临时 root（ephemeral） | data（persistent） | safety（persistent） | **持久化容量** | 总磁盘额度 |
|---|---|---|---|---|---|
| Seed ×1 | 1 GiB | **60 GiB** | — | **60 GiB** | 61 GiB |
| Validator ×7 | 1 GiB | **55 GiB** | 5 GiB | **60 GiB** | 61 GiB |

- 临时 root 卷 = 官方语法要求的“至少一个仅 `size` 的临时卷条目”；命名卷均显式 `attributes: { persistent: true }`（官方：“Survives restarts”）。
- **未改变**：1 Seed + 7 Validator 拓扑、Seed bootstrap-only、静态 peer、端口（17770 / 17771–17777）、`chain_id`/`network_id`、镜像与启动命令、验证者数量与身份隔离。
- **容量口径（R4 已锁定，不再悬而未决）**：“持久化”只计 `attributes.persistent: true` 的**命名卷**；无名临时 root 卷**不**计入。依据 = `docs/genesis/testnet-parameters-v1.md` §1 的“≥ 60 GiB 持久化”。
  - 旧状态（2026-10-14 – 2026-10-18）：Seed `data 59Gi`、Validator `data 54Gi + safety 5Gi` ⇒ 持久仅 **59 GiB**，**低于**需求 1 GiB。
  - R4 更正：Seed `data 60Gi`；Validator `data 55Gi` + `safety 5Gi` ⇒ 持久 **60 GiB** / 总 **61 GiB**（预算 +1 GiB/工作负载，全集群 +8 GiB）。
  - 校验器已同步：`scripts/check_akash_sdl.py` 现在直接断言**持久化容量 ≥ 60 GiB**（并对总量与持久量分开展示），不再把 `总==60 / 持久==59` 固化成通过目标。
- 本地结构校验：`LOCAL_STRUCTURAL_VALIDATION = PASS`（`checks_passed=211 checks_failed=0`，见 §14.4）；**官方 SDL 校验 = NOT PERFORMED**（无 `akash`/`provider-services`；未安装任何软件）。

### 14.2 safety 初始化原子性（本轮修复）

- **缺陷**（P0）：`runtime.rs` 旧实现先按 vote 分支可能 `create`，之后才在 block 分支拒结 ⇒ “仅 block journal 存在 + `--init-validator-safety`”会在**启动失败**中新建一枚空 vote journal。
- **修复**（`crates/node/src/runtime.rs::build_validator`）：**在任何 create 之前**先读取两枚 journal 的存在性，并按下表统一判定：

| 状态 | 行为（均为零写入） |
|---|---|
| 仅一枚存在 + 未声明初始化 | `SafetyJournalMissing` |
| 仅一枚存在 + 已声明初始化 | `SafetyJournalAlreadyExists` |
| 两枚均存在 + 已声明初始化 | `SafetyJournalAlreadyExists`（既有字节不变） |
| 两枚均不存在 + 未声明初始化 | `SafetyJournalMissing` |
| 两枚均不存在 + 已声明初始化 | **唯一**允许 `create`（`create_new(true)`）的路径 |
| 两枚均存在 + 未声明初始化 | 严格 `recover()`（语义与修复前一致） |

- **保留不变**：`create_new(true)` 防覆盖、header/identity/checksum/replay 的 fail-closed 行为、不存在删除/补齐/重建路径、不因测试方便而放宽任何校验。
- **原子性边界（诚实披露）**：`exists()` **不提供跨进程原子性**（并发启动仍由 `create_new` 兜底 ⇒ 失败方 fail closed，不损坏不覆盖）；首次初始化需连续创建两枚文件，**两枚之间发生 I/O 失败或进程被杀仍可能留下单枚状态**（两个文件无法构成写事务）——但该状态在**后续启动会被 §14.2 的预检零写入拒绝**，不再产生新副作用。本任务**未**新增并发/故障注入测试（当前实现不支持），该边界标记为**未覆盖**。

### 14.3 P-6 子状态（修复后）

| 子项 | 状态 |
|---|---|
| `SAFETY_JOURNAL_REGRESSION` | **PASS**（T1–T4 全绿，见 §14.4） |
| `AKASH_SDL_PERSISTENCE` | **FIXED**（本地结构已验证；**官方校验未执行**） |
| `CONTAINER_E2E` | **NOT RUN** |
| `OFFICIAL_SDL_VALIDATION` | **NOT PERFORMED** |
| Akash 更新/回滚/自动重启语义 | **UNVERIFIED** |
| **P-6（整体）** | **BLOCKED**（仅剩：容器 E2E、官方校验、Akash 更新/回滚语义） |

### 14.4 本轮验证台账

见执行报告 §E（命令 / 退出码 / 通过失败数 / 日志路径）。日志目录：`%TEMP%\nova-p6-fix\`。

### 14.5 部署前必查（未变，新增一项）

1. `/storage`、`/safety` 已挂载在**声明为持久**的卷上（而非容器可写层）；
2. 首次启动使用 `--init-validator-safety`，此后所有重启/更新**移除**该参数；
3. 更新部署时**不得**改动卷名/大小/mount 路径；
4. `genesis_hash` 带外核对；
5. 确认 provider 实际采纳了 `attributes.persistent`、显式 `class` 与 root 卷条目（**官方库 schema 校验已通过**，见 §15；provider 侧采纳仍需部署时核对）。

---

## 15. 官方 SDL 校验（2026-10-14 首次执行）与卷隔离结论

> 本节**取代** §12.5 / §13.5 / §14.3 中“官方校验 NOT PERFORMED”的历史记录（那些是各自轮次的真实快照，不改写）。

### 15.1 方法与来源（可复现）

- 官方文档指定的本地校验途径（`akash-sdl/best-practices` → Testing and Validation → Test Locally First）：
  TypeScript `@akashnetwork/chain-sdk`、Go `pkg.akt.dev/go/sdl`。
- 官方 CLI（`provider-services`）**全量命令列表已复核，不存在 `validate` 子命令**
  （来源：`akash.network/docs/developers/deployment/cli/commands-reference`）。本机 `akash`/`provider-services` 均 NOT FOUND。
- 实际执行：`@akashnetwork/chain-sdk@1.0.0-alpha.46`，**仅安装到临时目录** `%TEMP%\nova-p6-final\sdl-official`
  （`npm install --ignore-scripts`）；**仓库未被改动**，**未做系统级安装**。
- **诚实标注**：该 SDK 当前只有 alpha 版本；SDK 自身未导出 YAML 解析器（仅导出模板助手），
  YAML 由 `js-yaml` 解析后交给**官方库**做 schema 校验与 manifest 生成。

### 15.2 结果（官方库输出，退出码 0）

- `validateSDL` → `undefined`（= 无 ValidationError）；`generateManifest` → OK。
- 官方 manifest：**1 个 group（`akash`）含 8 个 service**，每个 `count: 1`：
  - `seed` → `data->/storage`
  - `validator-1..7` → `data->/storage, safety->/safety`
- 官方 deployment group spec（on-chain 资源单元）：
  | resource | count | root（临时） | data（持久） | safety（持久） | attributes |
  |---|---|---|---|---|---|
  | id=1（seed） | **1** | 1 GiB | 59 GiB | — | `class=beta1`, `persistent=true` |
  | id=2（validator） | **7** | 1 GiB | 54 GiB | 5 GiB | `class=beta1`, `persistent=true` |
  > ⚠️ 上表是 **2026-10-14 官方库实测时点**的 SDL 内容（持久 59 GiB）。
  > **2026-10-18 R4** 已将 Seed `data` 改为 `60Gi`、Validator `data` 改为 `55Gi`（持久 60 GiB / 总 61 GiB）。
  > 该次更正**尚未**再用官方库复测（本环境无 `akash`/`provider-services`，见 §14.1）——不得把上表当作
  > **当前** SDL 的校验结果。
- **卷隔离结论 = PASS（官方证据，三条独立）**：
  1. 官方文档 `learn/core-concepts/persistent-storage` → **Limitations → Not Shared Between Services**：
     *“Each service gets its own storage volume. Services cannot share persistent storage.”*；
  2. 官方库实测：8 个**独立 service**（各 `count: 1`）各自携带自己的 `params.storage` 挂载；
     group spec 对 7 个 Validator 以 `count=7` 分配资源（即 7×（54 GiB + 5 GiB））；
  3. 官方源码 `akash-network/akash-api`（`go/manifest/v2beta2/service.go`）：存储属 group 资源单元，
     `Service.count` 是**同一 service 的副本数**并消耗 `gRes.Count` ⇒ **单 service + `count: 7` 不等价于 7 个独立 service**
     （本 SDL 未采用该危险写法）。
- **残留（诚实）**：Provider 侧 Kubernetes PVC 的实际实例化细节无法在**无付费部署**的前提下观测。
  关闭该残留需部署后执行：“在一台 Validator 写入标记 → 断言其余 6 台不可见”（需 lease/费用，超出本轮授权）。

### 15.3 官方校验发现并修复的缺陷（P-12）

- 首次官方校验返回 **5 条错误**，其中 3 条为：命名持久卷的 `attributes` **缺少必需字段 `class`**
  （`Missing required field: "class"`）；另 2 条为同一联合类型分支失败的伴随错误（补 `class` 后消失）。
- 修复：三枚命名持久卷均显式 `class: beta1`（官方文档：“If you don't specify a class, beta1 is used by default”）
  ⇒ **不改变容量与成本口径**，仅把默认值显式化以满足官方 schema。修复后官方校验 **PASS**。
- **Owner 决策（未变更）**：如需 NVMe 可改 `class: beta3`（官方对 I/O 密集负载推荐；影响费用与 Provider 匹配范围）——P-11。

### 15.4 证据分级（不得混淆）

| 方式 | 工具 | 本次结果 | 性质 |
|---|---|---|---|
| 官方库校验 | `@akashnetwork/chain-sdk` `validateSDL`/`generateManifest` | **PASS**（exit 0） | **官方**（官方文档指定途径；SDK 为 alpha） |
| 自定义静态校验 | 仓库内 `scripts/check_akash_sdl.py`（含 `--selftest`） | **211/211 PASS** | **自定义**，非官方 |
| YAML 解析 | PyYAML / js-yaml | OK | 仅语法 |
| 官方 CLI 校验 | `provider-services` | **不可用**（NOT FOUND；且无 validate 子命令） | — |
| 真实 Provider/容器 | Akash lease + 容器 | **未执行**（需付费/授权） | — |

---

## 16. Mount Guard（P-6 生产防护，2026-10-14 落地）

### 16.1 检查什么

- 位置：`crates/node/src/bin/yazimao-node.rs` 的 `Action::Run` **最开头** —— 早于 genesis pre-flight、
  早于任何 `create_dir_all`、journal 初始化与 BlockStore 打开。
- 对象：`--storage-dir` **总是**检查；`--safety-dir` **只要 CLI 提供了**就检查（validator 模式必需）。
- 判据：`canonicalize` 后的路径与 `/proc/self/mountinfo` 第 5 字段**精确相等**（可识别独立文件系统与 bind mount）。
  不做“位于挂载点之下”的前缀推断。
- 两枚目录**各自独立**判定；任一失败 ⇒ 拒绝启动；**零写入**（仅 `canonicalize` + 只读读取）。
- 错误信息包含目标（storage/safety）、路径与原因（非挂载点 / 路径不可解析 / 无法读取挂载信息）。

### 16.2 容器内 fail-closed 矩阵

| 情形 | 容器内行为 |
|---|---|
| 目录存在但不是挂载点（镜像内预建 `/storage`、`/safety`） | **拒绝启动** |
| 目录不存在 / 不可解析 | **拒绝启动**（且不代其创建） |
| 挂载信息不可读/不可用 | **拒绝启动** |
| storage 合法 + safety 非法（或反之） | **拒绝启动**（无半初始化） |
| 两枚均为挂载点 | 通过，进入既有初始化流程 |

### 16.3 容器探测信号与**限制**

- 信号（任一成立 ⇒ 容器；全部只读）：`/.dockerenv`；`/run/.containerenv`；
  `/proc/self/cgroup` 或 `/proc/1/cgroup` 含 `docker`/`kubepods`/`containerd`/`libpod`；
  `/var/run/secrets/kubernetes.io/serviceaccount` 存在；环境变量 `KUBERNETES_SERVICE_HOST`。
- **非容器环境**：无法判定持久性 ⇒ 返回 `SkippedNotContainer`，stderr 打印明确提示后继续。
  实测（Windows 真实进程）：打印
  `mount guard skipped (not running in a container); persistent-volume persistence is NOT verified in this environment`
  并继续进入 pre-flight（**这不是安全保证**，仅为不阻断本地/CI）。
- **已知限制（诚实）**：若运行时使用 cgroup v2 统一层级且其路径不含上述关键字、又未注入任何标记文件/环境变量，
  则判定为“非容器”⇒ 守卫**会跳过**。该限制已被固化为可执行测试，而不是文档承诺。
- **无绕过开关**：CLI 未新增任何可静默关闭守卫的参数或环境变量。

### 16.4 启动前核对（运维步骤）

```bash
# 1) 两枚目录必须**本身**是挂载点（不是镜像内预建目录）
awk '{print $5}' /proc/self/mountinfo | grep -Fx /storage
awk '{print $5}' /proc/self/mountinfo | grep -Fx /safety
# 2) dev/ino 与挂载点一致（防 bind 到可写层）
stat -c '%d %i %n' /storage /safety
# 3) UID 10001 可写（P-5）
# 4) 平台重启后标记文件仍在（证明持久）
```

- 只要 (1) 失败，或 (2) 指向 overlay 层，即视为**未挂载**：**不得**启动 Validator。

### 16.5 若一枚必需持久卷缺失（安全恢复）

- 正确行为：**停止**。**不要**用 `--init-validator-safety` 强行启动（该参数以“两枚都不存在”为前提）。
- 节点自身保护：仅一枚 journal ⇒ 启动被**零写入拒绝**（`SafetyJournalMissing` / `SafetyJournalAlreadyExists`，见 §14.2）；
  代码中**不存在**删除/补齐/重建既有 journal 的路径。
- 恢复：从带外备份**整目录**恢复 `/storage` 与 `/safety`；或经 Owner 批准以**全新身份**重新初始化
  （**仅**在确认无历史投票/锁定记录可复用时）。

---

## 17. Validator 身份与 safety journal 红线（永不）

- 永不把 network/validator seed 写入 SDL、Git、镜像层、命令行或普通日志（§11.2）。
- 永不在两枚 journal 已存在时使用 `--init-validator-safety`。
- 永不手工删除、截断、替换 `safety.journal` / `block-safety.journal`（丢失投票历史 ⇒ double-vote 风险面）。
- 永不把 `/storage`、`/safety` 指向容器可写层或共享 NFS——官方明确：持久卷**不跨** lease 关闭与 Provider 迁移存活，
  且**服务间不可共享**；共享存储会破坏身份隔离。
- 永不在未核对 `genesis_hash` 的情况下启动。
- 永不把 7 个 Validator 合并为单一 service + `count: 7`（官方源码：`count` 是同一 service 的副本数，§15.2）。

---

## 18. 证据分级口径（本仓库统一）

| 级别 | 含义 | 本轮是否有 |
|---|---|---|
| L1 真实 Provider/容器 | 真实 Akash lease + 容器内观测 | **无**（需付费/授权） |
| L2 官方工具/库 | 官方校验器/官方 SDK 对**真实文件**的判定 | **有**：`validateSDL` + `generateManifest` PASS |
| L3 官方文档/源码引证 | 官方站点原文 / 官方仓库源码 | **有**：卷隔离声明、`service.go` |
| L4 本地测试 | 仓库内 Rust 单元/集成测试 | **有**：§19.1 |
| L5 自定义静态检查 | `scripts/check_akash_sdl.py` | **有**：211/211（**非官方**） |
| L6 推导/未测 | 代码推导、无专用测试 | 并发初始化边界（§14.2） |

---

## 19. 2026-10-14 第二轮：测试台账与剩余阻断

### 19.1 台账（真实命令与退出码；日志目录 `%TEMP%\nova-p6-final\`）

| 套件 | 退出码 | 结果 |
|---|---|---|
| `cargo test -p nova-node --lib mount_guard::tests` | 0 | **18 passed / 0 failed** |
| `cargo test -p nova-node --bin yazimao-node` | 0 | **55 passed / 0 failed** |
| `cargo test -p nova-node --test runtime_tests rt_safety_journal_partial -- --test-threads=1` | 0 | **4 passed / 0 failed**（T1–T4） |
| `cargo test -p nova-node --lib safety_store::tests` | 0 | **16 passed / 0 failed** |
| `cargo test -p nova-node --lib block_safety::tests` | 0 | **24 passed / 0 failed** |
| `cargo test -p nova-node --test restart_safety_tests -- --test-threads=1` | 0 | **16 passed / 0 failed** |
| `cargo test -p nova-node --test runtime_tests -- --test-threads=1` | 101 | **13 passed / 2 failed**（既有失败，§19.2） |
| `cargo check --locked --offline --workspace --all-targets` | 0 | **0 error / 0 warning** |
| 官方 SDK 校验（§15） | 0 | **PASS** |
| 自定义结构校验（§15.4） | 0 | **211 / 211** |
| 真实进程接线（Windows，非容器） | 1 | 守卫跳过提示 + `Error: Preflight(GenesisRead)`（预期：genesis 路径不存在）；**storage 目录零创建** |

### 19.2 既有失败归因（本轮**未修**，超范围）

`rt_28_validator_id_mismatch_startup_fails`（`runtime_tests.rs:307:5`）与
`rt_29_runtime_processes_consensus_command`（`:340:5`）的失败形态与上一轮基线**逐字一致**：
`assertion \`left == right\` failed`、`left: None`、`right: Some(ProposalRef{block_hash:[170;32], proposer: ValidatorId([...])})`；
仅 `proposer` 字节随运行时派生的身份变化。`runtime_tests.rs` 与 `runtime.rs` 哈希与基线完全一致 ⇒
**PRE-EXISTING FAILURE**（非本轮引入，未做任何断言弱化）。

### 19.3 剩余阻断（更新）

| 阻断 | 状态 | 下一步（最小动作） |
|---|---|---|
| 容器内挂载拒绝的**实证** | **BLOCKED**（无容器运行时、WSL 无发行版；安装属系统级变更，未授权） | 在 Owner 控制的容器环境运行 Mount Guard E2E：未挂载 ⇒ 拒启；已挂载 ⇒ 通过 |
| Provider 侧卷隔离**实证** | **未执行**（需 lease/费用） | 部署后：在一台 Validator 写标记 → 断言其余 6 台不可见 |
| Akash 更新/回滚/自动重启语义 | **UNVERIFIED** | 官方答复或真机验证 |
| P-3 seed 投递机制 | **BLOCKED**（Owner 决策） | Owner 批准托管方案 |
| P-1/P-2 镜像与 genesis | **BLOCKED**（Owner 交付） | 发布含正式 genesis 的镜像 digest + 冻结 `genesis_hash` |
| 容量口径（“持久 ≥ 60 GiB”？） | **已解决（2026-10-18 R4）** | 按需求文档改为“持久 60 / 总 61 GiB”，SDL + 校验器 + 本文件已同步 |
| 存储类 `beta1` vs `beta3` | **Owner 决策** | 影响费用与 Provider 匹配范围 |
| 定价 `denom`（`uakt` vs `uact`） | **Owner 决策** | 官方文档表明 escrow 使用 ACT（`uact`）；本 SDL 仍为 `uakt`，**未擅自更改** |

> 结论：**P-6 仍不可关闭**——生产侧挂载防护已落地并有单元证明，但“容器/Provider 内实际拒绝未挂载目录”
> 与“7 台 Validator 卷互不可见”两项**实证**缺失，且属 L1 级别证据。
