# YAZIMAO 测试基础设施

## 状态

- `tests/vectors/`：**协议测试向量 crate**（package `nova-test-vectors`，dev-only）——Address / Domain /
  Signature / Genesis / Transaction / Block / Round-Change 向量 + loader（**loader 独立重算比对，
  不信任向量中的期望值**）；各目录 schema 见 `tests/vectors/*/README.md`。
- 跨 crate / 跨进程集成测试位于各 crate 的 `tests/`（当前主要在 `crates/node/tests/`，含真实进程 /
  真实 TCP 场景）。
- 测试体系、入口与已知失败项：见 `docs/testing/`。

## 未来目标

- 多节点规模测试（1/4/10/50/100 节点，Master Prompt §64）。
- 故障注入（kill/partition/disk corruption，Master Prompt §63）。

## 运行方式

```bash
cargo test --workspace            # 全量（含向量 loader 测试）
cargo test -p nova-test-vectors   # 仅协议测试向量
```
