# YAZIMAO 运维文档

## 状态

- PHASE 2 — Implementation & Integration In Progress。
- **当前无运行中的公共网络**（Devnet / Testnet / Mainnet 均未发布，见根 README §3）。
- 本目录含日志规范；部署与演练文档位于 `docs/testnet/`。

## 待落实（后续 Phase）

- 可观测性：metrics / logs / health / readiness / liveness（Master Prompt §56）。
- 监控指标：block height / finalized height / peer count / mempool / tx throughput /
  latency / consensus rounds / storage / CPU / memory / disk。
- 备份：Genesis / Validator identity / Snapshot / Config；必须验证可恢复（Master Prompt §57）。
- 部署与发布流程：version / commit / build hash / release notes / migration / checksum（Master Prompt §88）。
