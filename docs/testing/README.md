# Nova Chain 测试文档

## 状态

- PHASE 1 — Project Foundation。
- 当前仅冒烟测试（验证 crate 可编译、测试基础设施可用）。

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

## 本地命令

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## CI

见 `.github/workflows/ci.yml`（fmt → check → clippy → test → build）。
任何 PR 未过 CI 不得合并（Master Prompt §51）。
