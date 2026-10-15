# nova-core

YAZIMAO 核心协议类型与规则（PHASE 3；交易有效性 / nonce / replay / gas / 状态类型**已实现**）。

## 状态

- 协议版本常量 `PROTOCOL_VERSION = "0.1"`；统一错误模型骨架（`YazimaoError` trait + `ErrorKind` 分类）。
- `transaction`：**已实现**（STEP 7E/7F；nonce / replay / gas-fee 规则，ADR-0021 / ADR-0022）。
- `state`：**已实现**（STEP 7G 协议类型：`AccountState` / `AccountChange` / `TransactionReceipt` /
  `StateTransition`；ADR-0017 / ADR-0018 / ADR-0023）。
- `block`：Block / BlockHeader / `block_hash` 类型已实现（ADR-0042）；执行与提交分别由
  `nova-execution` / `nova-runtime` 承担。
- 本 crate **不持有**任何 policy 阈值（consensus 规则与本地 mempool policy 严格分离）。

## 依赖方向

`nova-core` 属于 **Protocol 层**，可依赖 `nova-crypto`（Infrastructure 层），不得被上层反向依赖。

## 测试

```bash
cargo test -p nova-core
```
