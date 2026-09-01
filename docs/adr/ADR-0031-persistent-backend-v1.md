# ADR-0031: Persistent Backend V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（Persistence Backend，STEP 8E）
- 关联：ADR-0025（S-F：MemoryBackend 先、DB 留 8E）、ADR-0028（StorageBackend D-1）、
  ADR-0026（SMT State Root）、ADR-0030（StateRootCalculator / commit_changes 单源）、
  ADR-0018（canonical account bytes）

## Context

8C-8D 完成内存 StateStore + 区块执行闭环（单节点可验证执行引擎）。8E 目标：补齐**数据落盘 /
restart recovery / crash safety / state reload**，升级为可运行节点状态机。

**8E 范围**：自研文件持久化后端（实现 `StorageBackend`）+ WAL + 快照 + crash recovery + state reload
+ 与 `StateStore` 集成 + 持久化测试。
**不做**：RocksDB/MDBX 选型（8F）、网络同步（STEP 9）、共识（STEP 10-12）、完整区块格式（PHASE 7）。

## Decision（冻结）

### E-1 — PersistentBackend 选型（冻结）

- **V0.1 自研文件后端**（零第三方 DB 依赖；满足 `StorageBackend` trait；8F 无缝换 RocksDB/MDBX）。
- 理由：ADR-0025 S-F"不一开始绑定数据库，防 schema 污染"；8E 目标是 durability/recovery/
  deterministic reload，非性能。
- **RocksDB/MDBX 评估延后 8F**。

### E-2 — StorageBackend flush 扩展（冻结）

```rust
pub trait StorageBackend {
    // ...（get/put/delete/snapshot/restore）
    /// 确保所有未持久化写入已 durable（WAL fsync）。MemoryBackend = Ok(())。
    fn flush(&mut self) -> Result<(), StorageError>;
}
```

- trait 保持最小；**禁止** trait 出现 `write_wal` / `create_snapshot` / `recover` / `database`
  （属 PersistentBackend 实现细节）。

### E-3 — WAL 策略（冻结）

- 提交顺序：`AccountChange → canonical encode → WAL append → flush/fsync → backend apply → trie update`。
- WAL 记录 = `(batch_id, changes[], checksum)`；`changes` 为 `(key35, canonical_bytes)`。
- **WAL 顺序 == `commit_changes` 顺序**（否则重放 root 漂移；ADR-0030 C-3 单源）。
- 恢复：有效批次重放；**无效尾部丢弃**（checksum 失败/不完整）。
- **bounded amendment（STEP 7-H / ADR-0048）**：WAL 支持 **additive ChainHead HeadRecord** 记录类型；
  HeadRecord 与同批 state changes **同批次、同 checksum、同 fsync**（batch-atomic 保持）；
  禁止 `state durable ∧ head not durable` 或反之。

### E-4 — Snapshot 模型（冻结）

- 快照文件 = 全量 KV + checksum + 元数据（state_root 可选）。
- 写入：`snapshot.tmp → fsync → atomic rename → snapshot`（防半写快照）。
- 触发：`persist_snapshot()` API / 每 N 块；**不绑定共识规则**。
- **bounded amendment（STEP 7-H / ADR-0048）**：快照必须携带**可恢复 ChainHead metadata**；
  checksum 覆盖 **state + head**（防 WAL 截断后丢 head）；禁止 snapshot state=N 而 head=N-1。

### E-5 — Recovery / Reload（冻结）

```rust
impl PersistentBackend {
    pub fn create(path: &Path) -> Result<Self, StorageError>;
    pub fn open(path: &Path) -> Result<Self, StorageError>;   // 快照 + WAL 重放
    pub fn close(self) -> Result<(), StorageError>;           // flush + 落盘
}
```

- `open`：加载快照（校验 checksum）→ 重放 WAL 有效批次 → 丢弃损坏尾部 → ready。
- **幂等**：同一目录多次 `open` ⇒ 同一状态 / 同一 root。
- **bounded amendment（STEP 7-H / ADR-0048）**：`open` 一致返回 **recovered state + recovered ChainHead**；
  区分 **discardable/truncated tail**（丢弃，非错误）与 **integrity failure**（RecoveryError，不自动修复）。

### E-6 — Trie 持久化边界（冻结，模型 1）

- **backend（truth storage）必须落盘**（canonical account bytes）。
- **trie 不落盘**：重启后由 WAL 重放 changes **重建 SMT**（固定深度 SMT 是确定性函数，
  ADR-0026；重放得同一 root）。
- 避免提前冻结 trie 二进制格式 / node serialization / version migration。
- **bounded amendment（STEP 7-H / ADR-0048）**：确定性重建后执行 **head cross-check**
  （recovered `state_root == ChainHead.state_root`）；不一致 ⇒ `RecoveryError`（integrity failure），不猜测、不自动覆盖。

### E-7 — Crash Safety 测试（冻结）

1. **Roundtrip**：apply → close → open ⇒ 同 root / 同账户。
2. **Crash recovery**：模拟 WAL 尾部截断 ⇒ recover = 最后完整批次（部分写入丢弃）。
3. **Snapshot + WAL**：persist_snapshot → 新 changes → crash → open（快照 + 重放）= 全量一致。
4. **StateStore 集成**：`StateStore<MemoryBackend>` == `StateStore<PersistentBackend>`（同输入同 root）。
5. **Atomicity**：apply_block 失败 ⇒ 无半 WAL / 无部分状态。
6. **Backend equivalence**：Memory 与 Persistent 满足同一 `StorageBackend` 行为契约。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| E-1 | 自研文件后端（RocksDB/MDBX 留 8F） | 冻结 |
| E-2 | trait 仅加 `flush()` | 冻结 |
| E-3 | WAL 记录 `(batch_id, changes[], checksum)`；顺序 = commit_changes | 冻结 |
| E-4 | 全量快照 + atomic rename；不绑定共识 | 冻结 |
| E-5 | `create/open/close`；快照 + WAL 重放；幂等 | 冻结 |
| E-6 | trie 不落盘，WAL 重放重建 SMT（模型 1） | 冻结 |
| E-7 | 测试（roundtrip / crash / snapshot+wal / 集成 / 原子性 / 等价） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| RocksDB/MDBX 直接引入 | 重依赖；schema 提前绑定；8E 目标非性能（E-1） |
| trait 暴露 WAL/snapshot API | 破坏 backend 抽象边界（E-2） |
| trie 落盘 | 提前冻结 trie 二进制格式 / migration（E-6） |
| WAL 独立批次接口 | trait 最小化；批次语义在 PersistentBackend 内部（E-2/E-3） |

## Consequences

- **正面**：崩溃安全（WAL + 快照）、确定性重放、backend 可替换。
- **成本**：WAL/恢复自研；每次事务 flush（V0.1 正确性优先）。
- **可迁移**：8F 换 RocksDB/MDBX 零侵入（`StorageBackend` trait）。

## Security Impact

- **防半写**：快照 atomic rename + WAL checksum（E-3/E-4）。
- **防重放漂移**：WAL 顺序 = 状态转换顺序（E-3）。
- **防状态歧义**：幂等 open + 确定性 SMT 重建（E-5/E-6）。

---

## Bounded Amendment（STEP 7-H / ADR-0048）

- **范围**：仅 E-3/E-4/E-5/E-6 的有界扩展；**不重写** E-1~E-7 既有冻结语义。
- **durability 措辞**：统一为 **recoverable atomicity / single-WAL-batch durability boundary /
  crash-consistent**（与既有 WAL durability model 一致；非跨对象强事务系统）。
- **backend 边界**：`StorageBackend` 仅新增 additive metadata 能力（如 `enqueue_meta`，默认 no-op/Err）；
  不暴露 `write_wal` / `create_snapshot` / `recover` 等实现细节（延续 E-2 原则）。
- **细节**：HeadRecord 物理字节布局（tag/endian/length/version）为 **FOLLOW-UP IMPLEMENTATION DESIGN**（ADR-0048 OD-1）。

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-28 | 初稿：Persistent Backend V1（E-1~E-7 冻结） | STEP 8E |
| 2026-09-01 | **bounded amendment（STEP 7-H）**：E-3 HeadRecord WAL 支持 / E-4 快照携带 head / E-5 恢复返回 state+head / E-6 head cross-check；措辞与 backend 边界同步 | STEP 7-E/F/G/H Owner Decision → 授权 ADR-0031 amendment 落盘（配合 ADR-0048） |
