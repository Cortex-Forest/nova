# ADR-0065: Validator Safety Initialization & Fail-Closed Startup

- Status: ACCEPTED (G5-D.7.2, 2026-09-25)
- Related: ADR-0038（Finality Architecture，F-14）/ ADR-0054（Node Lifecycle Architecture）/ ADR-0031（Persistent Backend）
- Scope: **node-local 启动安全语义**（不改变 consensus / crypto / core / storage 格式，不改变 Genesis）
- Supersedes: 无（不修改 ADR-0054；仅补充其未描述的 `safety.journal` 缺失分支）

## Context

`ValidatorSafetyStore`（`crates/node/src/safety_store.rs`，STEP 10-15T + HARDEN/OBS-3B）是 validator-local 的
append-only 安全日志，持久化本地的 vote intent / signature / `LockedState`，用于 **double-vote 防护**与
「恢复前不得参与」的安全不变量。

其**写入路径**已被设计为 fail-closed（OBS-3B）：`append_record` 不 `create`，journal 缺失时立即 `Err(Io)`，
绝不静默重建。既有测试 `rt_25_missing_safety_journal_fails_closed` 覆盖了「进程存活期间 journal 被删除」。

但 **启动路径** 未采用同一不变量。`NodeRuntime::build_validator` 原先为：

```text
journal_path.exists()
    ? ValidatorSafetyStore::at(...)      // 绑定既有历史（recover 严格校验）
    : ValidatorSafetyStore::create(...)  // 隐式创建全新空安全状态
```

该分支的唯一判据是「文件是否存在」，因此**无法区分**：

- 首次启动（合法初始化）；与
- 既有 validator 的 `safety.journal` **丢失**（卷丢失 / 目录误删 / `--safety-dir` 变更）。

两者都会走 `create()` ⇒ `recover()` 得到**空 ledger / 空 lock** ⇒ validator 可继续投票，而它对既往
(height, round, vote_type) 的投票与 lock 记忆已消失。ADR-0038 F-14（恢复后再参与）与 ADR-0054 §2/§18
（SafetyStore open → strict recover；验证者侧任一步安全失败 ⇒ 启动失败）的**意图**因此无法在
「记录缺失」情形下被保证。

Akash 部署语境（G5-D.7 PRECHECK）使该情形成为**常规事件类别**：provider-local 持久卷在 lease 终止 /
provider 迁移 / provider 故障下**不保证保留**。

## Decision

### 1. Fail-closed rule（核心）

validator 模式下，`safety.journal` 的存在性是**启动前置条件**：

```text
journal exists                     ⇒ at()  + strict recover（现状不变）
journal missing + init == false    ⇒ FAIL CLOSED（NodeRuntimeError::SafetyJournalMissing）
journal missing + init == true     ⇒ create()（create_new(true)；仅此情形允许创建）
journal exists  + init == true     ⇒ FAIL CLOSED（NodeRuntimeError::SafetyJournalAlreadyExists；
                                     既有 journal 字节保持不变）
```

- **绝不隐式初始化**：缺失不再触发 `create()`。
- 缺失必须**可诊断**，不得伪装为普通 IO failure：专用变体
  `NodeRuntimeError::SafetyJournalMissing`
  （*Safety journal is missing; validator startup requires explicit safety initialization or
  restoration from backup.*）。
- 不引入任何「依据 chain storage 推断首启」的判据：chain storage 进度（head / state / `MissingHeadWithState`）
  只能证明**链**的状态，不能证明**该 validator 是否曾初始化/使用** safety 状态（例如「已同步 storage 但从未投票
  的新 validator」会被误判为「既有 validator 丢失 journal」）。SafetyStore 与 chain storage 的 recovery 语义
  **保持独立**（沿用 ADR-0054 §7 目录分离纪律）。

### 2. Explicit initialization entry

唯一允许创建新安全状态的路径是**显式声明**：

- 载体：`NodeConfig.validator_safety_init: bool`（默认 `false`；runtime 仍为 SafetyStore 的唯一 owner，
  沿用 ADR-0054 §18 的 `Runtime open→recover→identity check→inject` 划分）。
- 生产入口：CLI `--init-validator-safety`（仅在 `--validator` 模式下有意义）。

语义边界（必须与实现、HELP、runbook、ADR 一致表述）：

> `--init-validator-safety` 声明的是**一次新的 SafetyStore 初始化**。
> 它**不是** restore / repair / recover / reset，也**不得**被描述为「恢复丢失的 SafetyStore」。

### 3. Mainnet restriction

mainnet 下 `--init-validator-safety` **被拒绝**（与既有 `--validator` + mainnet 的 fail-closed 风格一致）。

理由：该 flag 的语义是「允许创建全新的 validator 安全状态」。mainnet 上安全状态丢失必须走
**备份恢复 / 明确的治理与运维决定**，不能由启动参数变成自修复按钮；否则任何持有 validator seed 的进程
都可以在丢失安全状态后一键重启并继续签名，ADR-0038 F-14 将被绕过。devnet / testnet 允许。

### 4. Existing journal protection

「既有 journal + 初始化声明」必须**拒绝**（不是幂等成功），保留两层保护：

- `SafetyStore::create()` 的 `create_new(true)`（OS 级 O_EXCL）与 `path.exists()` 前置返回（`AlreadyExists`）；
- runtime 启动期的显式判定 ⇒ `NodeRuntimeError::SafetyJournalAlreadyExists`。

最终结果：**startup failure + 既有 journal byte-for-byte 不变**（不 truncate / overwrite / append / replace）。

### 5. Operational recovery semantics

**Safety initialization ≠ Safety recovery。**

```text
missing journal
      ↓
fail closed（节点拒绝以 validator 身份启动；不产生 vote / 不推进本地安全状态）
      ↓
（a）restore from backup（整目录恢复 safety/）→ restart（不带 --init-validator-safety）
（b）no backup ⇒ DO NOT silently initialize ⇒ Owner 明确决定是否初始化新的安全状态
              （此时才使用 --init-validator-safety，且理解为「新状态起点」而非恢复）
```

- `--init-validator-safety` 建立的是**新的、空的**安全状态；**不恢复任何历史** vote / lock。
- 备份 / 恢复**工具**不属于本 ADR 范围（见 Non-goals）。
- full-node / observer（`validator_enabled = false`）不触碰 safety 路径，不受本规则影响。

### 6. Unchanged invariants

- `safety.journal` **格式不变**：header（114B）/ record 布局 / magic / version / checksum / `recover()` 语义不变。
- 不新增 durable artifact（无 marker / nonce / version bump / 新文件）。
- double-vote 防护语义不变：`VoteLedger` + persist-before-sign 不变；本 ADR 只是把「缺失即不参与」这一
  不变量从**写入路径**延伸到**启动路径**。

## Consequences

**正面**

- 消除「安全状态缺失 ⇒ 静默空状态继续投票」路径；ADR-0038 F-14 在缺失情形下重新成立（改为拒绝启动）。
- 缺失与「已存在却声明初始化」两种操作者错误均有专用、可诊断的失败；不伪装为 IO failure。
- 无 on-disk 迁移：既有部署在 journal 存在时行为完全不变。
- 与 OBS-3B（写入路径绝不静默重建）形成一致的 fail-closed 语义闭环。

**代价 / 影响**

- 所有 validator 启动方必须显式声明首启：CLI / testnet runbook / 测试 harness 的首启调用需携带该 flag；
  重启调用**不得**携带（携带即被拒绝）。
- `NodeConfig` 新增一个字段（node-local 装配层；不涉及协议）。
- 运维语义新增一个失败态（`SafetyJournalMissing`），需要 runbook 与操作者知晓。

**风险（已缓解）**

- 误把初始化当恢复 ⇒ 通过命名（init，非 restore）、HELP 表述、ADR 与 runbook 明确区分缓解；
  且既有 journal 在场时该 flag 被拒绝，无法覆盖历史。
- harness 误给重启加 flag ⇒ 失败是**响亮**的（启动拒绝），不会造成静默安全回归。

## Non-goals

- 不实现备份 / 恢复 / 导出 / 导入工具、对象存储集成、Akash 备份 sidecar（独立工作项）。
- 不实现 marker / nonce / journal 格式或版本变更。
- 不修改 `VoteLedger` 冻结 API、`SigningCapability`、consensus / crypto / core / storage 语义。
- 不修改 ADR-0054（frozen）；本 ADR 补充其未描述的缺失分支。
- 不引入 chain storage → safety 的首启推断判据。
- 不实现 validator onboarding（以已同步 storage 接入）的自动化流程。
