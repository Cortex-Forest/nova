# nova-execution

YAZIMAO 执行层（PHASE 3；state transition 与 block 执行**纯计算已实现**；WASM 未实现）。

## 状态

- `state_transition`：**已实现**（STEP 7G；`apply_transaction`，ADR-0023）。
- `block`：**已实现**（STEP 8D；`execute_block` / `validate_block` 纯计算，ADR-0029）。
- `NOT IMPLEMENTED`：WASM / 合约执行（技术选型 Wasmtime 或经评审等价方案，待 PHASE 12 ADR）。
- **不实现**（属其它 crate 职责）：storage / trie / state root（`nova-storage`）、完整 Block 编码与提交
  （`nova-runtime`）。

## 纪律

- 合约必须有 Gas / 执行 / 内存 / 栈 / 表 / 调用深度 / Host 函数 / 交易大小限制（Master Prompt §12）。
- 必须沙箱化 + deterministic gas（Master Prompt §13）。

## 测试

```bash
cargo test -p nova-execution
```
