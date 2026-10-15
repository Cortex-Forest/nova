# nova-storage

YAZIMAO 存储层（PHASE 4；SMT + StateStore + 持久化后端**已实现**）。

## 状态

- **已实现**：`hashing` / `node` / `trie`（Sparse Merkle Tree）/ `proof`（STEP 8B；ADR-0026 / ADR-0027）、
  `StateStore` + `MemoryBackend`（STEP 8C；ADR-0028）、`PersistentBackend` + `block_store` + chain head
  （ADR-0031 / ADR-0048）。
- 数据库版本常量 `DATABASE_VERSION = 1`；数据库版本与软件 / 协议 / API 版本相互独立（ADR-0001）。
- **不引入外部数据库依赖**（未使用 RocksDB）；快照 / 修剪等能力尚未实现。

## 依赖方向

`nova-storage` 属于 **Protocol 层**，可依赖 `nova-crypto`（哈希）。

## 测试

```bash
cargo test -p nova-storage
```
