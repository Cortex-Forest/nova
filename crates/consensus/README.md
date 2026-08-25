# nova-consensus

Nova Chain 共识层（**PHASE 1 占位**）。

## 状态

- `NOT IMPLEMENTED`（无任何共识逻辑）。
- 前置依赖：Consensus Specification（ADR-0008 DAG↔BFT 桥接、ADR-0009 安全模型）。

## 纪律

- DAG ≠ 最终共识（Master Prompt §5）。
- 禁止未经批准修改共识；必须先有规范再实现（Master Prompt §7）。

## 测试

```bash
cargo test -p nova-consensus
```
