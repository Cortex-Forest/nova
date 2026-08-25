# nova-node

Nova Chain 节点组装层（**PHASE 1 占位**）。

## 状态

- 配置系统骨架（`Config` / `ConfigLoader`）：`IMPLEMENTED`（骨架，无具体参数）。
- feature flags 机制（`devnet` / `testnet` / `mainnet`）：`IMPLEMENTED`（占位，无逻辑）。
- 节点服务 / 启动流程：`NOT IMPLEMENTED`。

## 依赖方向

`nova-node` 属于 **Application 层**，依赖所有下层 crate；本阶段未建立任何 Cargo 依赖。

## 测试

```bash
cargo test -p nova-node
```
