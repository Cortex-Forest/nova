# 本地单节点 Disposable Devnet — 验收基线 v1

> **Status**: 基线说明（非规范性）。仅描述**本地 Windows 单节点 disposable devnet** 的可重复验收方法。
> 与 `docs/testnet/testnet-runbook-v1.md`（多节点 / Closed Internal Testnet）互补，不替代之。
> **不**适用于 Akash / 容器 / 公网；Validator 在 Akash 上的密钥托管仍为 `BLOCKED_SECURITY`
> （见 `docs/decisions/2026-10-25-akash-validator-key-custody-hold-decision.md`，状态 PROPOSED/DRAFT）。

| 字段 | 值 |
|---|---|
| 基线建立时间 | 2026-10-25（UTC） |
| Repo HEAD（建立时） | `851dfdd5d984db5ca4c6e3ebb21647a18f663e8e` |
| 平台 | Windows（x86_64-pc-windows-msvc，release 构建） |
| 证据目录（本轮） | `%TEMP%\nova-devnet-baseline-20261025T023021Z\` |

---

## 1. 目标与范围

**目标**：让后续工程人员能在本机重复验证「单节点 disposable devnet 能出块、能达成最终性、能正确重启、能按预期拒绝错误身份」，且**不需要**接触任何长期身份或正式 Genesis。

**范围内**：单节点（observer / validator），有限步数（5–20 步），进程级停止与重启，负向控制。
**范围外**：容器、Akash、多节点共识、公网连通、长期稳定性、正式 Testnet Genesis、远程签名器。

---

## 2. 前置工具

- Rust 工具链：`cargo 1.96.1` / `rustc 1.96.1`（与 `rust-toolchain.toml` 一致）
- 构建（离线可行，需本地 crate 缓存）：
  ```
  CARGO_NET_OFFLINE=true cargo build --release -p nova-node --bin yazimao-node --locked -j 1
  ```
  说明：并行构建在低内存机器上曾出现 `rustc` 崩溃（`0xc0000409`）；可用 `-j 1` 规避。
- 产物：`target\release\yazimao-node.exe`（Windows PE；**不是** Linux 二进制）

---

## 3. 测试 Genesis（重要：不要混用）

| 用途 | 文件 | SHA-256 | 参数 |
|---|---|---|---|
| **本基线实际使用** | 一次性 devnet genesis（由既有证据目录提供） | `76d9b719cf82ccc857c5c5c27c2aa820d14c81cd82d28c6f14615f9e4826550b` | network_id `0x03`(devnet) / chain_id **3004** / 1 validator / 243 B |
| **仓库 fixture（不用于本基线）** | `genesis-image/genesis.bin` | `c9a823c6163676448f88f4fa4ea758b86a1c1ea5db83d2146cea04bd6d441019` | 同为 3004 / devnet / 1 validator，但**其验证者私钥不存在于仓库或证据中** |

> ⚠ 两者**不是**同一份 Genesis。仓库 fixture 没有配套 seed ⇒ 用它启动 validator 必然 `Identity(ValidatorNotInValidatorSet)`。
> 仓库 fixture 也**不是**正式 Testnet Genesis。

自查命令（read-only）：
```
yazimao-genesis verify --genesis <genesis.bin> --hash <genesis_hash.txt>
```
预期输出含 `network_id / chain_id / canonical_len / genesis_hash / validators`，退出码 0。

---

## 4. 测试身份材料的安全前提

- 所用 `network-seed` 与 `validator-seed` 据既有生成记录为**一次性 disposable devnet** 材料（随一次性 genesis 成对生成），
  仅存放于本机 `%TEMP%` 证据目录，**未**进入仓库（`git ls-files` 无任何 `.hex`/`.seed`）。
- **`DISPOSABLE_ATTRIBUTE = UNVERIFIED`**：该属性只能依据「历史生成记录 + 存放位置（`%TEMP%`） + 未入库」三项间接事实，
  **没有**密码学保管链或 Owner 签署声明；在获得更强证据前，任何复用均按 `UNVERIFIED` 前提处理。
- **禁止**把 seed 内容写进命令示例、日志、报告、镜像、SDL 或环境变量。本文档只使用**变量占位**：
  ```
  $NETWORK_SEED_FILE   # 指向 network seed 文件（64 hex 字符 + 可选行尾空白）
  $VALIDATOR_SEED_FILE # 指向 validator seed 文件
  ```
- 文件权限建议：仅当前用户可读（Windows ACL 收紧；Linux 请 `chmod 0400` 且属主为运行用户）。
- 一次性材料的使用前提：**价值为零、devnet 结束后作废、不得复用到 Testnet/主网**。
  若无法确认某份 seed 的来源与一次性属性，**不得**用它执行 validator 测试。

---

## 5. Observer 启动（无 validator 私钥）

```
yazimao-node --genesis <genesis.bin> --genesis-hash 76d9b719…32bytes… \
  --chain-id 3004 --network-id devnet \
  --storage-dir <fresh-dir> --network-seed-file $NETWORK_SEED_FILE \
  --idle-ms 5 --run-steps 5
```
验收要点：
- 退出码 **0**
- 末行 `stopped after 5/5 steps` 中 `head_height=0`、`finalized_height=none`
- 状态行 `validator_enabled=false`
⇒ 能启动但不产块（observer 的预期行为）。

> `--network-seed-file` 是**必填**（缺 ⇒ `Cli(MissingRequired("--network-seed-file"))`，退出码 1），即使 observer 也需要。

---

## 6. Validator 启动（单节点出块）

**首次启动（空 safety 目录，必须带初始化标志）**
```
yazimao-node --genesis <genesis.bin> --genesis-hash 76d9b719… \
  --chain-id 3004 --network-id devnet \
  --storage-dir <dir-A> --safety-dir <dir-B> \
  --network-seed-file $NETWORK_SEED_FILE --validator-seed-file $VALIDATOR_SEED_FILE \
  --validator --init-validator-safety \
  --idle-ms 5 --run-steps 5
```
验收要点（实测）：退出码 **0**；`head_height=2`、`finalized_height=2`、`consensus_height=2`；`validator_enabled=true`。

约束：`--validator` 必须同时给出 `--safety-dir` 与 `--validator-seed-file`
（缺则 `Cli(ValidatorRequiresSafetyDir)` / `Cli(ValidatorRequiresSeedFile)`，退出码 1）。

---

## 7. 出块与最终性验收方法

唯一可信来源 = 节点自身输出：
- 每 **100 步**输出一行 `status steps=… head_height=… finalized_height=… consensus_height=… validator_enabled=…`
- 结束行 `stopped after N/N steps; head_height=… finalized_height=…`

判定：`finalized_height` 随 `head_height` 增长且**相等**（本基线实测相等）。
**不要**用 `curl` 探测：节点**没有** RPC/HTTP/健康检查端点。

---

## 8. 负向控制（必须失败）

| 用例 | 命令差异 | 预期结果（实测） |
|---|---|---|
| 网络身份与 Validator 身份同源 | `--validator-seed-file $NETWORK_SEED_FILE`（同一文件） | 退出码 **1**，`Error: Identity(NetworkAndValidatorIdentityMustDiffer)` |
| Validator 不在 Genesis ValidatorSet | 用仓库 fixture `genesis-image/genesis.bin` + disposable seed | 退出码 **1**，`Error: Identity(ValidatorNotInValidatorSet)` |
| 必要身份材料缺失 | `--network-seed-file <不存在的路径>` | 退出码 **1**，`Error: Seed(Read)` |

失败原因必须是上述身份/配置错误；若是构建失败、端口占用或超时，则**不算**通过。

---

## 9. 停止与重启验证（实测通过，可复现）

语义：节点无信号处理（`--help` 明示），停止即 OS 默认终止；状态为 crash-consistent，
靠 `--storage-dir` + `--safety-dir` 恢复。

**步骤**（全部使用**同一组**临时目录，且第 2 步**不得**带 `--init-validator-safety`）：

1. 首次：`... --safety-dir <S> --init-validator-safety --run-steps 20`
   - 实测：退出码 0，`head_height=10`、`finalized_height=10`
   - journal：`safety.journal=5774 B`、`block-safety.journal=3314 B`
2. 重启：**删除** `--init-validator-safety`，其余参数与目录**完全不变**，`--run-steps 10`
   - 实测：退出码 0，`head_height=15`、`finalized_height=15`（从 10 继续，非回退）
   - journal：`safety.journal=8604 B`、`block-safety.journal=4914 B`（**只增不减**）
   - 未出现 `Runtime(SafetyJournalAlreadyExists)`
3. 失败模式（负向，勿删 journal 规避）：
   - 空 safety 目录 + 不带 `--init-validator-safety` ⇒ `Runtime(SafetyJournalMissing)`
   - 已有 journal + 带 `--init-validator-safety` ⇒ `Runtime(SafetyJournalAlreadyExists)`

> 「进程能再次启动」≠「共识安全状态恢复正确」：本基线以 **高度连续性 + journal 单调增长 + 无重复初始化** 三项**观测**作为判定证据。
> **限制**：这三项属**外部可观测的一致性证据**，**不构成**对「共识安全状态（vote lock / locked state / 双签防护）完整恢复正确」的形式化证明；
> 该主张需针对 `ValidatorSafetyStore` 的定向断言测试或故障注入才能成立，本基线**未**执行（`NOT_RUN`）。

---

## 10. 证据保存

- 每次运行单独日志：`<case>.out.log` / `<case>.err.log`；汇总 `results.csv`、`summary.txt`、`journal-sizes.txt`
- 每条证据至少含：UTC 时间、HEAD、命令、退出码、genesis SHA-256、关键高度、限制说明
- **不要把大批临时日志或任何 seed 材料加入仓库**

---

## 11. 如何确保证据不含密钥

1. 只记录 `node_id`（公钥）、高度、错误名等公开字段；
2. 运行前对证据目录做 seed 字符串扫描（本基线：60 个文件，命中 0）；
3. 不要把 seed 作为命令行参数传入（CLI 只接受**文件路径**，天然避免命令历史泄露）；
4. 不要把 `%TEMP%` 证据目录打包上传或提交。

---

## 12. 常见失败原因

| 现象 | 原因 | 处置 |
|---|---|---|
| `Cli(MissingRequired("--network-seed-file"))` | 漏传必填参数 | 补上文件路径（非内容） |
| `Seed(Read)` / `Seed(Malformed)` / `Seed(Bom)` | 文件不存在 / 非 64 hex / 含 BOM | 检查文件本身（不要打印内容） |
| `Identity(ValidatorNotInValidatorSet)` | seed 与 genesis 的 ValidatorSet 不匹配 | 使用**成对**的 genesis + seed，勿混用 |
| `Identity(NetworkAndValidatorIdentityMustDiffer)` | 两枚 seed 用同一文件 | 换用两枚不同 seed |
| `Runtime(SafetyJournalAlreadyExists)` | 重启时仍带 `--init-validator-safety` | 重启时去掉该参数 |
| `Runtime(InboundListener(Bind))` | 端口被占用 | 换端口或释放占用 |
| 高度停滞 | 非 validator 模式 / 未连上 peer | 检查 `validator_enabled` 与 `configured_peers` |

---

## 13. 本地 Windows 与 Linux / Akash 的边界

| 能力 | 本地 Windows（本基线） | Linux 容器 | Akash |
|---|---|---|---|
| 二进制 | ✅ PE/COFF | 未验证（无容器引擎） | 镜像内为 ELF x86-64（已核验，但未运行） |
| 单节点出块 / 最终性 | ✅ 有限步数 | `NOT_RUN` | `NOT_RUN` |
| 重启恢复 | ✅ 本机实测 | `NOT_RUN` | `NOT_RUN` |
| Validator 私钥保密（对 Provider） | 不适用（本地自有） | 不适用 | **BLOCKED_SECURITY** |

**结论**：本基线**不**构成 Linux 容器可用性、Akash 可运行性或 Provider 密钥隔离的任何证明。
