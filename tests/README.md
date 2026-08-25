# Nova Chain 集成测试

## 状态

- PHASE 1 — Project Foundation。
- 本目录为**跨 crate 集成测试**预留入口；当前无集成测试。

## 未来目标

- 跨模块集成（如 交易 → 状态机 → 存储）。
- 多节点测试（1/4/10/50/100 节点，Master Prompt §64）。
- 故障注入（kill/partition/disk corruption，Master Prompt §63）。

## 运行方式

```bash
cargo test --workspace
```
