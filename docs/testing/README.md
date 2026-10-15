# YAZIMAO 测试文档

## 状态

- PHASE 2 — Implementation & Integration In Progress（测试基础设施已可用；**不再只有 smoke test**）。
- 现有形态：单元测试、集成测试（真实进程 / 真实 TCP）、协议测试向量 loader、fuzz target。
- 测试数字**不在本文件重复维护**：最新验证结果、已知失败项与证明范围限制见
  [o2-round-change-real-tcp-tests.md](o2-round-change-real-tcp-tests.md)。

## 当前测试入口

| 入口 | 命令 / 位置 | 说明 |
|------|-------------|------|
| 单元 + 集成（全量） | `cargo test --workspace` | CI `ci` job 同名命令 |
| 长时间多进程 | `.github/workflows/ci.yml` 的 `long-tests` job（`--test-threads=1`） | 真实二进制 / 多进程 / 重连场景 |
| 协议测试向量 | `cargo test -p nova-test-vectors` | `tests/vectors/`（loader 独立重算比对） |
| fuzz | `cargo +nightly fuzz run <target>` | `fuzz/`（独立 crate，需 nightly） |
| O2 Round Change（真实多进程 TCP） | 见专项文档 | [o2-round-change-real-tcp-tests.md](o2-round-change-real-tcp-tests.md) |

## 测试体系（目标，Master Prompt §58）

| 类型 | 说明 | 落地 Phase |
|------|------|-----------|
| Unit Test | 每个模块单元测试 | 各模块 Phase |
| Integration Test | 跨 crate/跨模块 | 各模块 Phase + `tests/` |
| Property Test | 性质测试（proptest） | PHASE 2+ |
| Fuzz Test | 模糊测试 | `fuzz/`，各 Phase |
| Failure Test | 故障注入 | PHASE 22 |
| Regression Test | 任何修复必加回归测试 | 全程 |
| Differential Test | 核心模块差分测试 | 核心模块 |

## 测试通过的定位（重要）

- 测试通过只证明**被测行为在被测范围内符合断言**，**不证明**协议整体正确性或安全性。
- 专项集成测试通过 ≠ 部署验收通过；单元测试数量**不**作为品质宣传。
- 协议正确性须由单元 / 集成 / property / fuzz / 故障注入测试共同证明（Master Prompt §58）；
  **未覆盖路径与证明边界必须在文档中显式标注**（示例见 O2 专项文档的证明范围限制章节）。

## 本地命令

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## CI

见 `.github/workflows/ci.yml`：

- `ci`：fmt → check → clippy → test（`cargo test --workspace`）→ build
- `long-tests`：真实二进制 / 多进程测试（单独 job、独立超时预算）
- `container-image`：构建 / 推送容器镜像（**不部署**）

任何 PR 未过 CI 不得合并（Master Prompt §51）。
