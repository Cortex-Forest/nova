# nova-execution

Nova Chain WASM 执行层（**PHASE 1 占位**）。

## 状态

- `NOT IMPLEMENTED`（无任何执行逻辑）。
- 技术选型：Wasmtime 或经评审等价方案（ADR-0010），待 PHASE 12。

## 纪律

- 合约必须有 Gas / 执行 / 内存 / 栈 / 表 / 调用深度 / Host 函数 / 交易大小限制（Master Prompt §12）。
- 必须沙箱化 + deterministic gas（Master Prompt §13）。

## 测试

```bash
cargo test -p nova-execution
```
