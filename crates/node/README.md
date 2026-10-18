# nova-node

YAZIMAO 节点组装层（运行时 / 集成层**已实现**，持续 integration hardening）。

## 状态

- **已实现**：`NodeRuntime` + driver、validator safety（fail-closed）/ 重启恢复、bootstrap、egress、
  block builder、inbound / dispatch、sync / follower sync persistence、canonical commit
  （ADR-0054 / ADR-0057 / ADR-0058 / ADR-0065）。
- 配置系统（`Config` / `ConfigLoader`）与 feature flags（`devnet` / `testnet` / `mainnet`）已就位。
- **未接入**：RPC / Wallet / Explorer（对应 crate 仍为占位，见根 README §3）。
- 测试状态与**已知失败项**：见 `docs/testing/`。

## 持久化 QC 历史（对端服务能力，非 safety 原语）

`runtime::persist_qc_history_if_needed` 为**已 final 块**写入 per-height PrecommitQC artifact
（`storage_dir/qc_history/`）；`sync_responder::serve_qc` 在对端追赶时按请求高度附发。

- **写入条件**：只有候选 QC 的 `target == finality.finalized_reference` 才写入；写入仍经既有
  `QcHistory::put` 校验（`vote_type == Precommit`、`height == context.height + 1`、同高度冲突永不覆盖）。
- **候选选择**：候选集合必须**逐个**比对 `target`；某个候选不匹配时，**不得**因此忽略仍有效的其他候选。
  历史缺陷（R8 已修复）正是「只取第一个非空候选」：一次外部 QC 采纳后其 target 长期不再匹配，
  本地派生 QC 被永久遮蔽，导致该高度之后的 QC 历史写入静默停止。
- **已知限制**：`finalized_height`（= `qc_history.tip_height()`）是**服务提示**，不是 consensus finality
  判据，可能滞后；落后节点能追到的高度受网络中**可提供**的 QC 历史前沿限制。
- **范围边界（重要）**：本修复只解决「QC 历史写入被过期候选遮蔽，导致追赶前沿停滞」这一**具体**子问题；
  它**不**构成 round-advance liveness 边界（`ADR-0077`，状态 *Accepted-as-Record · Not Implemented*）
  的整体根因结论，也**不**表示该边界已关闭。相关 Owner 决定（OD-X）仍未授权实现。
- **回归测试**：`cargo test -p nova-node --lib r8_qc_history_candidate_selection`（3 项）。

### 状态行诊断字段（R11 新增；**仅观测**）

`yazimao-node` 的 `status` 行追加 6 个**只读**计数（全部读自 `NodeRuntime` **既有** accessor；
不新增埋点、不改动任何共识/执行路径）：

| 字段 | 含义 |
|---|---|
| `qc_history_written=` / `qc_history_write_failed=` | per-height QC 历史写入成功 / 失败次数 |
| `qc_serve_skipped=` | QC 附发被跳过次数（超尺寸 / 签名失败 / artifact 损坏） |
| `ext_qc_adopted=` / `ext_qc_rejected=` | 外部 finality 采纳 / 未采纳次数 |
| `inbound_qc_deferred=` | 入站 QC 因 `target ∉ 本地 DAG` 被有界暂存次数 |

用途：把「QC 未到达 / 到达但无法应用 / 到达但被拒 / 采纳但未持久化」四类**区分开**。
**范围边界**：**不**补齐 `ADR-0077 §4.4` 的 proposal 分因与 proposer-availability 缺口，
**不**改变 P4 的活性判定，**不**构成 `A-OBS` 实现。
回归测试：`cargo test -p nova-node --bin yazimao-node t53`。

## 依赖方向

`nova-node` 属于 **Application 层**，依赖其下层 crate（具体依赖以 `crates/node/Cargo.toml` 为准；
分层方向见根 README §7 与 ADR-0001）。

## 测试

```bash
cargo test -p nova-node
```
