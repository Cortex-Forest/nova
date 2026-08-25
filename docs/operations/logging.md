# Nova Chain 日志规范（structured logging）

> **状态**：PHASE 1 定义规范；完整 telemetry subsystem 为后续阶段（Master Prompt §56）。
> 本文件是**约定规范**，当前无代码实现。

## 1. 原则

- 所有生产模块使用 **structured logging**（结构化日志）。
- **禁止**在生产代码中使用 `println!` / `eprintln!`。
- **禁止记录**：私钥 / 助记词 / seed / auth token / secret / 敏感个人信息（Master Prompt §55）。

## 2. 必定义项

| 项 | 规范 | 示例 |
|----|------|------|
| **Level** | `error` / `warn` / `info` / `debug` / `trace` | `info` |
| **Module name** | `nova::<crate>::<module>` | `nova::consensus::vote` |
| **Event name** | `nova.<crate>.<event>` | `nova.consensus.vote_received` |

## 3. 事件命名约定

- 统一前缀 `nova.` + crate 名 + `.` + 小写下划线事件名。
- 事件名使用过去式或名词短语：`block_applied`、`peer_connected`、`tx_rejected`。

## 4. 字段约定

- 使用键值对字段（结构化），避免拼接到消息字符串中。
- 时间戳、调用方、进程信息由 logger 基础设施注入，事件体**不记录**自身时间戳。

## 5. 实现规划

- 后续阶段评估 `tracing` / `tracing-subscriber`（需经依赖六项审查 + ADR）。
- 生产环境默认级别与采样策略在 telemetry Phase 定义。
