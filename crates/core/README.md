# nova-core

Nova Chain 核心协议类型（**PHASE 1 占位**）。

## 状态

- 当前仅定义协议版本常量 `PROTOCOL_VERSION = "0.1"` 与统一错误模型骨架（`NovaError` trait + `ErrorKind` 分类，无具体业务错误）。
- 交易 / 状态 / 区块等核心类型：`NOT IMPLEMENTED`（待对应 PHASE + ADR）。

## 依赖方向

`nova-core` 属于 **Protocol 层**，可依赖 `nova-crypto`（Infrastructure 层），不得被上层反向依赖。

## 测试

```bash
cargo test -p nova-core
```
