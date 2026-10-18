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
| 节点整包全量 | `cargo test -p nova-node --no-fail-fast` | 单个包的全部 target（真实进程 E2E 占多数，耗时较长） |

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

### 分层执行（isolated / target / 整包）

单个用例通过、单个 target 通过、整包套件通过是**三个不同层级**的事实，不可互相替代：

```bash
# 1) 单个用例（隔离）
cargo test -p nova-node --test <target> -- --exact <test_name> --nocapture
# 2) 单个 target（该二进制内的全部用例）
cargo test -p nova-node --test <target> -- --nocapture
# 3) 整包全量（全部 target；某个 target 失败后仍继续执行其余 target）
cargo test -p nova-node --no-fail-fast
```

### 回归测试（修复必加）

| 修复 | 回归测试位置 | 覆盖内容 |
|------|--------------|----------|
| R8 QC 历史候选选择 | `crates/node/src/runtime.rs` 的 `#[cfg(test)] mod r8_qc_history_candidate_selection` | 过期 primary 不得遮蔽匹配的 fallback；无匹配候选时保持可重试 no-op；匹配 primary 优先 |

### 最近一次已验证快照（2026-10-18，一次性快照，非持续维护）

| 层级 | 命令 | 结果 |
|------|------|------|
| 单元（`nova-node`） | `cargo test -p nova-node --lib` | 304 passed / 0 failed |
| 单元（`nova-consensus`） | `cargo test -p nova-consensus --lib` | 178 passed / 0 failed |
| 包（`nova-genesis-builder`） | `cargo test -p nova-genesis-builder` | 43 passed / 0 failed |
| 整包全量（`nova-node`） | `cargo test -p nova-node --no-fail-fast` | exit 0；757 passed / 0 failed / 0 ignored |

> 上表是**某一代码状态**下的验证快照，不随每次提交自动更新；日常数字维护仍以专项文档为准。
> 代码变更后必须重新执行对应层级；**target 级通过不得当作整包通过**。

## CI

见 `.github/workflows/ci.yml`：

- `ci`：fmt → check → clippy → test（`cargo test --workspace`）→ build
- `long-tests`：真实二进制 / 多进程测试（单独 job、独立超时预算）
- `container-image`：构建 / 推送容器镜像（**不部署**）

任何 PR 未过 CI 不得合并（Master Prompt §51）。

---

## 附：2026-10-18 R14 复跑记录（与上文快照的关系）

上文"最近一次已验证快照"中的整包数字（`nova-node --no-fail-fast` 757 passed、`nova-consensus --lib`
178 passed）产生于 **R8 代码状态**，早于 R11–R14 新增的用例（`t53`、`a3_4_liveness_invariant_characterization`
4 项、`d10_p1_a30_seven_validator_devnet` 24 项等）。因此：

- 那两行是**历史快照**，不代表当前 HEAD 的包级总数；当前 HEAD 的整包总数**本轮未测**。
- 任何"整包全绿"的声明都必须重新执行整包命令后才成立。

本轮（R14）实际执行并验证的层级：

| 层级 | 命令 | 结果 |
|---|---|---|
| 单元（`nova-node --lib`） | `cargo test --locked --offline -p nova-node --lib` | 304 passed / 0 failed（R12 实测；本轮未重跑） |
| 单元（`nova-node --bin yazimao-node`） | `cargo test --locked --offline -p nova-node --bin yazimao-node` | 58 passed / 0 failed（R12 实测；本轮未重跑） |
| target（`a3_4_liveness_invariant_characterization`） | `cargo test --locked --offline -p nova-node --test a3_4_liveness_invariant_characterization` | 4 passed / 0 failed（R12 实测；本轮未重跑） |
| target（`d10_p1_a30_seven_validator_devnet`） | 逐用例 `--exact` 执行 24 次 | **24 passed / 0 failed**（R14 实测，见 `R14_TEST_MATRIX.md`） |
| 包（`nova-genesis-builder`） | `cargo test --locked --offline -p nova-genesis-builder` | 43 passed / 0 failed（R12 实测；本轮未重跑） |

> 追加于 R14：仅补充新的执行记录与快照时效说明，上文正文**未改写**。
