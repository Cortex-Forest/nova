# nova-node

YAZIMAO 节点组装层（运行时 / 集成层**已实现**，持续 integration hardening）。

## 状态

- **已实现**：`NodeRuntime` + driver、validator safety（fail-closed）/ 重启恢复、bootstrap、egress、
  block builder、inbound / dispatch、sync / follower sync persistence、canonical commit
  （ADR-0054 / ADR-0057 / ADR-0058 / ADR-0065）。
- 配置系统（`Config` / `ConfigLoader`）与 feature flags（`devnet` / `testnet` / `mainnet`）已就位。
- **未接入**：RPC / Wallet / Explorer（对应 crate 仍为占位，见根 README §3）。
- 测试状态与**已知失败项**：见 `docs/testing/`。

## 依赖方向

`nova-node` 属于 **Application 层**，依赖其下层 crate（具体依赖以 `crates/node/Cargo.toml` 为准；
分层方向见根 README §7 与 ADR-0001）。

## 测试

```bash
cargo test -p nova-node
```
