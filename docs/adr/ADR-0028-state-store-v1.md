# ADR-0028: State Store & Memory Backend V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（StateStore + MemoryBackend，STEP 8C）
- 关联：ADR-0025（Storage 架构 S-A~S-H）、ADR-0017（AccountState）、ADR-0018（account_commitment）、
  ADR-0023（StateTransition / AccountChange / G-J 顺序）、ADR-0026（SMT State Root）、
  ADR-0027（Proof Boundary）

## Context

8A 冻结 Storage 架构；8B 冻结 Trie/StateRoot/Proof。本 ADR 冻结 **StateStore + MemoryBackend（8C）**：
`StorageBackend` trait、`StateStore` 结构、`AccountChange[] → SMT` 更新、两阶段原子 `apply`、
区块级快照、Execution(7G) → Storage(8C) 衔接。

**8C 范围**：MemoryBackend + StateStore + `apply(AccountChange[])` + snapshot/commit/rollback +
`state_root()` + `canonical_account_bytes`/`account_commitment` + 7H 向量集成。

**不做**：持久化后端（8E）、block state root verification（8D）、proof fixture、RPC/network/state sync。

**冻结边界（8C 不得回改）**：7G/7H 行为零变化；ADR-0025 S-A~S-H；ADR-0026 SMT 固定深度；
ADR-0018 canonical_account_bytes 布局。

## Decision（建议，待批准）

### D-1 — StorageBackend（backend 层，冻结）

```rust
pub trait StorageBackend {
    type Snapshot: Clone;
    fn get(&self, key: &TrieKey) -> Option<Vec<u8>>;
    fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError>;
    fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError>;
    fn snapshot(&self) -> Self::Snapshot;
    fn restore(&mut self, snap: &Self::Snapshot);
}
```

- **分层**：`backend = byte storage`；`store = protocol state encoding`；`trie = commitment structure`。
- backend **不知道** `AccountState`（serialization responsibility 在 store）；8E RocksDB/MDBX 复用同一 trait。
- **delete primitive boundary**：`backend delete` 仅为底层存储原语（migration / pruning / snapshot restore 用）；
  **协议层 AccountState 删除 V0.1 禁止**（ADR-0017）。两者不可混淆。

### D-2 — StateStore（store 层，冻结）

```rust
pub struct StateStore<B: StorageBackend> {
    backend: B,                    // truth storage（完整账户 canonical bytes）
    trie: SparseMerkleTree,        // commitment index（key → account_commitment）
}
```

- **backend = truth storage；trie = commitment index**。**禁止从 trie decode state**
  （trie 只存 32B commitment，无法还原；且未来 RocksDB 迁移会困难）。
- 实现 `AccountStateView`：`account()` 从 **backend** 读 → decode 88B → `AccountState`。
- `state_root()` → `trie.root()`（空 = `EMPTY_STATE_ROOT`）。

### D-3 — Canonical Account Commitment（协议 API，冻结）

- **归属 `nova-core::state`**（AccountState 协议类型所在）：
  ```rust
  pub fn canonical_account_bytes(state: &AccountState) -> [u8; 88];
  pub fn account_commitment(state: &AccountState) -> [u8; 32];
  pub fn decode_account_bytes(bytes: &[u8; 88]) -> AccountState;   // storage 层 account() 读取
  ```
  - 布局：`balance(16B LE) ‖ nonce(8B LE) ‖ code_hash(32B) ‖ storage_root(32B) = 88B`（ADR-0018 §12）。
  - **返回固定长度**（`[u8; 88]` / `[u8; 32]`），**不暴露 `Vec<u8>`**。
  - `account_commitment = SHA-256(canonical_account_bytes)`（经 protocol_hash）。
- **`NovaAddressPayload::to_bytes() -> [u8; 35]`**（nova-crypto 暴露；`payload_to_bytes` 现有逻辑公开）。
  - **禁止 storage 自行 enum→bytes**（地址格式未来升级避免两个实现）。

### D-4 — apply 两阶段内部事务（冻结）

- 签名保持 S-C：`apply(&[AccountChange]) -> Result<(), StorageError>`。
- **两阶段**（非链级共识事务，仅 storage 原子保护）：
  1. **prepare**：validate all changes（构造 `AccountState`、canonical 编码、commitment 计算）；
     任一失败 ⇒ 返回 Err，**零副作用**。
  2. **snapshot**：保存当前 trie + backend。
  3. **commit**：write backend（`put`）→ update trie（`insert`）。
  4. 失败 ⇒ **rollback** 恢复 snapshot；成功 ⇒ 保留（新 state_root 就位）。
- **固定顺序**：`validate all → calculate all commitments → snapshot → write backend → update trie`。
  **禁止**逐 change 交错 `put/insert`（DB backend 可能部分写入；两阶段更接近事务模型）。
- V0.1 `apply` **只 upsert 不 delete**（`created` 不影响写入逻辑；存在即写）。

### D-5 — snapshot / commit / rollback（冻结）

```rust
pub fn snapshot(&self) -> StateSnapshot;                 // trie.clone() + backend.snapshot()
pub fn commit(&mut self, snapshot: StateSnapshot);       // drop(snapshot)：确认当前状态、释放快照资源；不 mutate state
pub fn rollback(&mut self, snapshot: StateSnapshot);     // 恢复 trie + backend → 快照（区块前状态）
```

- `commit` 语义：**确认当前状态并释放快照资源，不修改状态**（`drop(snapshot)` 即可）。
- 8D block state root verification 复用此原语包住整个区块。

### D-6 — Execution(7G) → Storage(8C) 衔接（冻结）

```rust
let store = StateStore::new(MemoryBackend::new());
let t = apply_transaction(&store, tx, vk, ctx)?;   // 只读纯函数（calculate）
store.apply(&t.changes)?;                          // commit（storage）
let root = store.state_root();
```

- **先 calculate 后 commit**（ADR-0025 S-C）。
- 依赖方向：`execution → storage` **不允许**；禁 `storage → execution`。
- 7H 向量集成放 `tests/vectors`（依赖 `nova-storage`，无反向依赖）。

### D-7 — 测试（冻结）

- **必测 1 — Atomicity**：`change[0] success + change[1] failure` ⇒
  `root_before == root_after` 且 `account_before == account_after`。
- **必测 2 — Backend/Trie consistency**：随机 `AccountChange[]` apply 后，
  backend 中 commitment == trie leaf `value_hash`（防 backend/trie 分叉）。
- 其他：apply 空/多 change、`account()` 回读、`state_root()` 空/变化、snapshot→rollback 恢复、
  MemoryBackend roundtrip、canonical golden、proptest（回读一致 / 可交换性 / rollback 幂等）。

### 实现分期

- **8C-2（骨架）**：`error.rs` + `backend.rs` + `memory.rs` + `store.rs`
  （MemoryBackend + StateStore skeleton + snapshot/rollback + `account()`；**不含 apply**）。
- **8C-3（apply）**：D-3 协议 API 落地于 apply + 两阶段事务 + 7H 向量集成。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| D-1 | StorageBackend 通用 KV + `Snapshot` 关联类型 + delete 原语边界 | 冻结 |
| D-2 | `StateStore{backend, trie}`；backend=truth storage, trie=commitment index | 冻结 |
| D-3 | canonical_account_bytes/account_commitment/decode 于 nova-core；`to_bytes()` 于 nova-crypto | 冻结 |
| D-4 | apply 两阶段内部事务（prepare/snapshot/commit；失败 rollback） | 冻结 |
| D-5 | snapshot / commit(=drop) / rollback | 冻结 |
| D-6 | execution→storage 衔接（先 calculate 后 commit）+ tests/vectors 集成 | 冻结 |
| D-7 | 测试（Atomicity / Backend-Trie consistency 必测） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| backend 暴露 `AccountState` | 8E DB 后端需 bytes；接口不统一（D-1） |
| 从 trie decode state | trie 只存 commitment 无法还原；RocksDB 迁移困难（D-2） |
| canonical 放 nova-crypto | 类型归属在 core；避免 storage 跨层取类型（D-3） |
| apply 逐 change 交错 put/insert | DB 可能部分写入；两阶段更接近事务模型（D-4） |
| `commit(snapshot)` 永久 no-op | 语义不清；`drop` 显式释放快照资源（D-5） |

## Consequences

- **正面**：backend/trie 职责分离、两阶段原子、区块级快照、Execution/Storage 解耦。
- **成本**：V0.1 快照为深拷贝（数据量小可接受；COW 优化留 8E）。
- **可迁移**：backend trait 供 8E RocksDB/MDBX 复用；7H 集成验证 7G→8C 无行为漂移。

## Security Impact

- **原子性**：apply 两阶段防部分提交（D-4 / ADR-0025 S-D）。
- **backend/trie 一致性**：commitment 双写一致性规则（D-7 必测 2）。
- **delete 边界**：协议层禁删账户，防状态删改（D-1 / ADR-0017）。
- **trie 不作 truth**：防 commitment 被当作完整状态解码（D-2）。
