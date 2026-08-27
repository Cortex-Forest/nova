# ADR-0027: State Proof V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（State Proof，STEP 8B-4）
- 关联：ADR-0026（固定深度 SMT / Node / hash domain）、ADR-0006（protocol_hash）、
  ADR-0018（account commitment）

## Context

State Root 已冻结（8B-3）。本 ADR 冻结 **Merkle Proof 格式**（inclusion / exclusion）、验证算法、
序列化边界，为 light client / state sync / fraud proof 提供确定性基础。

**8B-4 只做**：proof 数据结构、inclusion/exclusion proof、verification algorithm、serialization。
**不实现**：light client / RPC / network message / state sync / fraud proof protocol。

## Decision（建议，待批准）

### P-1 — Fixed 280 Sibling（冻结）

- **inclusion proof 固定 280 sibling**（`[NodeHash; 280]`），空 sibling 用 `EMPTY_NODE_HASH` 填充。
- **不压缩**：无省略规则 / 无 depth bitmap / 无编码歧义；任意语言实现容易复刻。
- 大小：`280 × 32B = 8960B`（light client / state sync / fraud proof 可接受）。
- 未来若引入压缩 proof ⇒ **必须新增 ADR**（不能直接修改当前格式）。

### P-2 — Proof 自包含 key / value（冻结）

- **Inclusion**：`key(35B) + value_hash(32B) + siblings`——验证者重算 leaf_hash，无需查询 storage / 信任提供方。
- **Exclusion**：`key(35B) + empty_depth + siblings`——证明该路径不存在 leaf。
- 验证流程（inclusion）：`leaf_hash = SHA256(STATE_LEAF ‖ key ‖ value_hash)` → 280 次 branch → root。

### P-3 — Serialization 双层（冻结）

- **协议层 canonical binary**：
  ```
  PROOF_INCLUSION = 0x01
  PROOF_EXCLUSION = 0x02
  Inclusion: 0x01 ‖ key(35) ‖ value_hash(32) ‖ siblings(280×32B)
  Exclusion: 0x02 ‖ key(35) ‖ empty_depth(u16 LE) ‖ siblings(empty_depth×32B)
  ```
  域前缀防 proof type confusion；`empty_depth` 0..=280 用 u16 LE（280 > u8::MAX）。
- **测试层 JSON fixture**：`schema_version: "state-proof-v1"`（hex 字段 + expected root；生成器/loader 模式同 7H / 8B-3 golden）。

### P-4 — Verification API（冻结）

```rust
pub fn verify_proof(proof: &SparseMerkleProof, root: &NodeHash) -> bool;
```

- 归属：`nova-storage::proof`。
- **必须**：pure function / no storage access / no backend dependency / independent recomputation。
- **禁止** `verify(root, database)`——proof 验证可脱离节点独立运行。

### P-5 — empty_depth 语义（冻结）

- `empty_depth` = 路径上**第一个空子树深度**（0..=280）。
- 空树：`empty_depth=0`，`siblings=[]`，验证 `EMPTY_NODE_HASH == root`。
- 非空树路径不存在（如 depth 73 遇 EMPTY）：`empty_depth=73`，从 `EMPTY_NODE_HASH` 向上恢复至 root。
- **与固定深度 SMT 一致**：无 path compression / branch collapse / variable depth proof；proof 永远对应 280-bit path。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| P-1 | 固定 280 sibling（`[NodeHash; 280]`），不压缩 | 冻结 |
| P-2 | proof 自包含 key / value_hash | 冻结 |
| P-3 | 二进制 canonical（0x01/0x02 域前缀）+ JSON fixture | 冻结 |
| P-4 | `verify_proof(proof, root) -> bool` 纯函数（nova-storage::proof） | 冻结 |
| P-5 | `empty_depth` = 首个空子树深度（0..=280；u16 LE 编码） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 压缩 sibling | 省略规则/编码歧义；V0.1 确定性 > 压缩效率；未来新 ADR |
| verify 依赖 storage | 破坏脱离节点独立验证（P-4 必须） |
| empty_depth 用 u8 | 280 > 255 溢出；须 u16 |

## Consequences

- **正面**：proof 确定性、自包含、可脱离节点验证；跨实现一致。
- **成本**：固定 280 sibling 较大（8960B）；未来压缩需新 ADR。
- **可迁移**：light client / state sync 直接消费；proof vectors 跨语言可复刻。

## Security Impact

- 防 proof type confusion：域前缀（P-3）。
- 防 sibling 篡改：验证者独立重算，不信任 sibling（P-4）。
- 防歧义：固定 280 sibling 无省略规则（P-1）。
