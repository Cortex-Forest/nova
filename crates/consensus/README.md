# nova-consensus

YAZIMAO 共识层（PoS + DAG + BFT；协议 **FINAL FROZEN** + 纯计算核心**已实现**）。

## 状态

- 协议设计 **FINAL FROZEN**：`docs/protocols/consensus-spec-v1.md`；架构决策 ADR-0033 ~ ADR-0040、ADR-0050。
- **已实现**（STEP 10-1~10-14）：`validator` / `vote` / `dag` / `witness` / `round` / `finality` /
  `checkpoint` / `fork_choice` / `proposer` / `integration`；Round Change Certificate 与 Abandon attestation
  的规范见 ADR-0049 / ADR-0066 / ADR-0070 / ADR-0072 / ADR-0074。
- **不涉及**（属其它 crate 职责）：完整 Block 格式（`nova-core` / `nova-runtime`，ADR-0042）与 node
  协调层（`nova-node`）。
- 边界（ADR-0033 C-1/C-3）：依赖 `nova-core` / `nova-crypto`；**禁止**依赖 `execution` / `storage` / `network`（纯计算）。

## 纪律

- DAG ≠ 最终共识（Master Prompt §5）。
- 禁止未经批准修改共识；必须先有规范再实现（Master Prompt §7）。

## 测试

```bash
cargo test -p nova-consensus
```
