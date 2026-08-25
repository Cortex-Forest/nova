# nova-storage

Nova Chain 存储层（**PHASE 1 占位**）。

## 状态

- 当前仅定义数据库版本常量 `DATABASE_VERSION = 1`。
- RocksDB schema / 状态树 / 快照 / 修剪：`NOT IMPLEMENTED`（待 ADR-0007 + PHASE 6）。

## 依赖方向

`nova-storage` 属于 **Protocol 层**，可依赖 `nova-crypto`（哈希）。

## 测试

```bash
cargo test -p nova-storage
```
