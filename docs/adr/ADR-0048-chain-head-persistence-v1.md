# ADR-0048: ChainHead Persistence Boundary V1

- **Status**: Draft（待批准；未冻结）
- **Date**: 2026-09-01
- **Deciders**: Nova Chain 架构组（STEP 7-H Owner Decision 授权落盘）
- **Scope**: PHASE 3 — Node/Storage（Canonical ChainHead Persistence Boundary；OPTION A）
- 关联：ADR-0031（Persistent Backend，本 ADR 的 **bounded amendment** 目标）、ADR-0028（StateStore）、
  ADR-0029（Block State Root）、ADR-0030（StateRootCalculator / commit_changes 单源）、ADR-0040（Fork Choice，
  FROZEN）、ADR-0042（Block，FROZEN）、ADR-0046/0047（Node Integration / KeyResolver，候选）、
  `crates/storage/src/{persistent.rs,store.rs,backend.rs}`、`crates/node/src/block_adapter.rs`

## 1. Context

- STEP 7-E 确认：`ChainHead`（height / block_hash / parent_hash / state_root）当前仅为 **Node 内存态**；
  `StateStore recovery ≠ ChainHead recovery`。Restart 后无法可靠恢复 canonical 应用点，从而无法安全构造 N+1。
- STEP 7-F 比较 OPTION A/B/C/D；STEP 7-G 起草 ADR-0048；STEP 7-H 收敛 OD-1~OD-7。
- **核心事实**（仓库代码）：`StateStore::apply_block` 内部自动 `flush()`（一个 WAL 批次）；若 head 单独写，
  将成 `Batch N=state / Batch N+1=head` ⇒ state-durable/head-stale 窗口 ⇒ 违反 HP-3。
- **裁决**：OPTION A（ChainHead 与 State Changes 同 WAL 批次、同 fsync、同 recovery boundary）。

## 2. Decision（Owner 已裁决，待批准冻结）

### 2.1 ChainHead 语义
- `ChainHead` = 当前 Node 已成功应用、并由 consensus 确定的 canonical block 的**持久化应用点**。
- **不是** fork choice / consensus decision engine / validator set / block store / state snapshot / execution context。
- 实际类型（`block_adapter.rs`）：`{ height: u64, block_hash: [u8;32], parent_hash: [u8;32], state_root: NodeHash }`。

### 2.2 OPTION A — State + Head 同一 WAL batch
```
Consensus decides（ADR-0040）
    ↓
Node coordinates（选定块 + head candidate → runtime → storage）
    ↓
Runtime executes / verifies（冻结 7-step）
    ↓
Storage atomically persists: state changes + canonical head metadata
    ↓
single WAL batch · single fsync · single recovery boundary
```
- Storage **persist(result)**，不 **choose(result)**；Storage 不决定 fork choice。
- 禁止：`state durable ∧ head not durable`；禁止 `head durable ∧ state not durable`。

### 2.3 OD 裁决（STEP 7-H）
| ID | 决策 | 状态 |
|---|---|---|
| OD-1 | HeadRecord 编码：逻辑字段已定（height u64 / block_hash [u8;32] / parent_hash [u8;32] / state_root NodeHash）；**物理字节布局（tag/endian/length/version）未定，FOLLOW-UP IMPLEMENTATION DESIGN**（不虚构格式；须确定性、禁 serde/bincode、禁平台 endian 差异、禁 HashMap 序） | 接受，follow-up |
| OD-2 | WAL batch 顺序：**state changes → head record**；batch-atomic 保证全或无 | 接受 |
| OD-3 | snapshot 必须携带 **recoverable head** + checksum 覆盖 **state+head**（否则 WAL 截断丢 head） | 接受 |
| OD-4 | RecoveryError 需区分 **discardable/truncated tail** 与 **integrity failure**；具体 error API 留 follow-up | 接受，API follow-up |
| OD-5 | Migration：**显式 bootstrap/checkpoint head（M2 路径）**；旧数据 head 不可用时不得自动假设 | 接受 |
| OD-6 | ADR-0031 仅 **bounded amendment**（E-3/E-4/E-5/E-6） | 接受 |
| OD-7 | co-commit API = **PRIMARY**：`StateStore::enqueue_head(head)` → `StorageBackend::enqueue_meta(bytes)` → runtime ⑥ `commit_block` 不变（apply_block 单次 flush） | **选择 PRIMARY** |

### 2.4 OD-7 PRIMARY（本 ADR 记录；实现留后续授权）
```
Node（adapter）: ④ → ⑤ → StateStore::enqueue_head(head) → ⑥ commit_block（冻结，不变）
    head.state_root = header.state_root（④ 已验证 == commit root；ADR-0030 C-3 单源）
    commit 失败 ⇒ apply_block 内部 rollback ⇒ pending 清空 ⇒ head 不持久化（无 phantom）
StorageBackend::enqueue_meta(bytes)（additive；默认 no-op/Err）→ PersistentBackend: head 入 pending
→ apply_block flush: pending=[head+state] → 单 WAL 批次 + checksum + fsync
```
- **Node 不得** access pending / WAL / encode WAL / PersistentBackend internals（经 StateStore 公开 API）。
- 备选 `apply_block_with_head(...)`（替换 runtime ⑥）**NOT SELECTED**（默认 PRIMARY；除非 Owner 改选）。

## 3. Recovery Algorithm

```
PersistentBackend::open()
    ↓ 加载 snapshot（state + head metadata）
    ↓ 恢复 snapshot state + snapshot head
    ↓ 顺序重放 WAL：每有效批次应用 state changes + head record
    ↓ 丢弃无效/损坏尾部
    ↓ 返回 recovered state + recovered ChainHead（= 最后有效 HeadRecord）
规则: 最后有效 HeadRecord = canonical recovered head
     禁 state_root 猜 height · 禁 HashMap 迭代推导 head · 禁 block_hash 反推 state
     禁网络重选 canonical head · 禁 Storage 调 consensus
```

## 4. Crash Matrix（OPTION A 语义）

| Crash 点 | State | Head | Recovery |
|---|---|---|---|
| commit 前 | N | N | open 得旧 N/N |
| 内存 apply 后、WAL 写前 | N | N | 无批次 ⇒ 旧 N/N |
| WAL partial write | N | N | 尾部损坏丢弃 ⇒ 旧 N/N |
| WAL full + fsync 前 | N | N | 丢弃 ⇒ 旧 N/N |
| WAL fsync 后 | N+1 | N+1 | 同批次重放 ⇒ 新 N+1/N+1 |
| replay 中 | 确定性 | 最后 head 记录 | 幂等 ⇒ 同结果 |
| snapshot tmp/fsync/rename 前 | N+1 | N+1 | 旧快照 + 完整 WAL ⇒ N+1/N+1 |
| rename 后、WAL 截断前 | N+1 | N+1 | 新快照 + WAL 重放（幂等）⇒ N+1/N+1 |
| WAL 截断后 | N+1 | N+1 | snapshot 恢复 state+head（**快照必须含 head**）|
| malformed HeadRecord（checksum 过、结构非法） | N+1 | ? | RecoveryError（integrity failure），不猜 |
| state/head mismatch | N+1 | N | RecoveryError，不自动修 |
| legacy snapshot/WAL（无 head） | N | N/A | state 恢复、head=N/A ⇒ recovery incomplete（M2 bootstrap）|

## 5. Security Invariants（HP-1 ~ HP-5）

| # | 不变量 | 保证机制 |
|---|---|---|
| HP-1 | Head 不得超前于 durable state | 同批次 fsync 后推进；无 head-first |
| HP-2 | 无 phantom head（head→N 而 state→N-1） | 同批次边界 |
| HP-3 | 无 committed head 丢失（restart 后） | head 与 state 共 durable + snapshot 携带 head |
| HP-4 | State+Head 共享一个 recoverable commit boundary | 单 WAL 批次 + 单 fsync（recoverable atomicity，非 Strong atomic） |
| HP-5 | 恢复确定性 | batch_id + SHA-256 + 顺序重放；无 HashMap/文件序/时间戳/随机/网络序 |

措辞：**recoverable atomicity / single-WAL-batch durability boundary / crash-consistent**
—— 与现有 ADR-0031 WAL durability model 一致；非跨对象强事务系统。

## 6. Consensus Boundary

```
Consensus (ADR-0040, FROZEN): 决定 canonical block（fork choice / finality）
Node:    协调 canonical application（选定块 + head candidate → runtime → storage）
Runtime: 执行/验证（decode/validate/execute/verify/commit）—— 不碰 WAL/snapshot/persistent head/restart
Storage: 持久化 state + head（WAL/snapshot/recovery）—— 禁 fork choice / proposer selection / validator authority / consensus
```

## 7. Alternatives（已评估并记录 rejected）

| 方案 | 否决原因 |
|---|---|
| B — Dedicated Head File | state fsync → head fsync 存在 "state durable ∧ head stale" 窗口（HP-3 FAIL，无自愈数据源） |
| C — Derive Head From State | state_root 不能唯一推出 height/block_hash/parent_hash（单向承诺） |
| D — Commit Journal | A 方案下单对象单批次无需三态 journal；仅未来多独立 durable 对象时重估 |

## 8. Compatibility

```
ADR-0042 Block FROZEN → unchanged（不增 head metadata 到 Block）
ADR-0019 Transaction  → unchanged
ADR-0017 State        → unchanged
ADR-0040 Consensus    → unchanged（选择 vs 持久化边界）
Runtime frozen API    → unchanged（⑥ commit_block 不变；无 WAL/head 逻辑入 runtime）
Node consensus boundary → unchanged
性质: additive storage metadata capability
```

## 9. Migration（M2 路径）

- 旧 WAL/snapshot 无 head ⇒ state 可恢复、head 不可用 ⇒ **recovery incomplete**，禁止直接生产继续。
- **M2（裁决）**：首次升级要求显式 checkpoint/bootstrap head（Owner 提供或从权威源重建）。
- 禁止自动假设 head=genesis / 自动猜测。

## 10. Testing Plan（设计；实现留后续授权）

```
Unit:       HeadRecord encode/decode · malformed record · checksum failure · deterministic replay
Crash:      crash before WAL · partial WAL · fsync boundary · snapshot + WAL truncate
Recovery:   state/head equality · restart N→N+1 · old WAL compatibility
Integration: Block N → state N+1 + head N → restart → Block N+1 → state N+2 + head N+1
Negative:   phantom head · stale head · state/head mismatch · invalid parent · corrupted HeadRecord
```

## 11. ADR-0031 Bounded Amendment（见 ADR-0031 变更记录）

- E-3：WAL 支持 additive HeadRecord（记录类型扩展，batch-atomic 保持）
- E-4：snapshot 携带可恢复 ChainHead metadata；checksum 覆盖 state+head
- E-5：recovery 一致返回 state + head；区分 discardable tail vs RecoveryError
- E-6：确定性重建 + head cross-check（state_root == head.state_root）
- 同步：durability 措辞（recoverable atomicity / single-WAL-batch boundary）；backend 边界（additive enqueue_meta）

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-09-01 | 初稿：ChainHead Persistence Boundary V1（OPTION A / OD-1~OD-7 裁决 / HP-1~5 / crash 矩阵 / M2 migration / 备选 B/C/D 否决） | STEP 7-E/F/G/H Owner Decision → 授权 ADR-0048 落盘（DRAFT，未冻结） |
