# YAZIMAO Scripts

## 状态

- `bench_percentiles.ps1`：对 benchmark 原始样本计算 p50 / p95 / p99（用法见 `crates/crypto/benches/README.md`）。
- `check_akash_sdl.py`：Akash SDL **仓库内静态检查**（部署配置见 `deploy/akash/`）。
  仅校验 SDL 结构与持久卷容量等静态约束，`--selftest` 覆盖其自身判定；
  **不代表**官方 SDL validator 校验通过，**不代表** provider / 挂载 / 网络连通性已验证，也**不代表**已部署。

## 未来目标

- 本地多节点启动脚本（localnet）。
- 构建/发布辅助脚本。
- 备份/恢复验证脚本（Master Prompt §57）。
- 依赖审计脚本。
