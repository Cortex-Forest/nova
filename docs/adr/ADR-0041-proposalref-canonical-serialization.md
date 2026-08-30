# ADR-0041: ProposalRef Canonical Serialization V1

- **Status**: **FROZEN（ACCEPTED）**（STEP 11-7；ProposalRef Canonical Serialization，2026-08-30）
- **Date**: 2026-08-30
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 11-7 — ProposalRef wire canonical serialization
- 关联：ADR-0037（B-1 ProposalRef 定义，FROZEN）、ADR-0009（签名覆盖）、ADR-0034（V-4 validator_id 表示）、
  `crypto-serialization-v1.md`（§3 定长 / §6 字段顺序 / §7 禁止表示）、STEP 11-1 §3（wire representation
  待冻结后复用）、STEP 11-7 Design + Review。

## Context

- `ProposalRef { block_hash: [u8; 32], proposer: ValidatorId }`（ADR-0037 B-1，round.rs）——数据结构/语义已冻结，
  但 **wire canonical serialization 未定义**（SPEC-NOT-FROZEN，11-1 §3）。
- STEP 11-1 §3：ProposalRef wire representation 仅在其对应编码规范**已冻结后**复用；本 ADR 即冻结该编码规范。
- 新增点：canonical serialization（64B）+ 新错误面 `InvalidProposalEncoding`。**不改 ADR-0037**（保持历史决策可追溯）。

## Decision（冻结）

### PR-1 — Canonical Layout（冻结）

```
canonical_proposal_ref = block_hash(32B) ‖ proposer(32B)   （total 64B，定长）
```

- `block_hash`：32B raw（crypto-serialization §3 定长 bytes，无长度前缀）。
- `proposer`：`ValidatorId` raw 32B（`as_bytes` / `from_bytes`，与 vote canonical / encode_qc 中
  validator_id 表示一致）。
- 字段顺序 = ADR-0037 B-1 定义顺序（§6 固定顺序禁止重排）。

### PR-2 — 唯一性（冻结）

- 定长 64B 全字段 ⇒ 唯一 canonical 表示；无 minimal-length / trailing / alternate（§7 禁止表示）。
- `decode(encode(p)) == p` roundtrip（§8 契约）。

### PR-3 — Decode 拒绝条件（冻结）

- `len != 64` ⇒ `InvalidProposalEncoding`（拒截断 / 超长 / trailing）。
- `block_hash` = bytes[0..32]；`proposer` = `ValidatorId::from_bytes(bytes[32..64])`。

### PR-4 — Decode 边界（冻结）

- **decode 不做** authority / membership / signature 验证（`proposer` 身份/authority 归 consensus 逻辑；
  `ValidatorId` 任意 32B 接受——同 vote decode 的 `validator_id` 处理）。

### PR-5 — 错误（冻结）

- 新增 `ConsensusError::InvalidProposalEncoding`（decode 结构失败专用；与 `InvalidVoteEncoding` 对称）。

### PR-6 — API（冻结）

- `pub fn encode_proposal_ref(p: &ProposalRef) -> Vec<u8>`（64B）
- `pub fn decode_proposal_ref(bytes: &[u8]) -> Result<ProposalRef, ConsensusError>`

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| PR-1 | canonical = block_hash(32)‖proposer(32) = 64B | 冻结 |
| PR-2 | 唯一 canonical 表示 + roundtrip | 冻结 |
| PR-3 | decode 长度严格 64B | 冻结 |
| PR-4 | decode 不做 authority/membership/signature 验证 | 冻结 |
| PR-5 | 新 `InvalidProposalEncoding` | 冻结 |
| PR-6 | encode/decode 对称 API | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 修改 ADR-0037 加入 encoding | 破坏已冻结 ADR；历史决策不可追溯（采用新 ADR-0041） |
| proposer = SHA-256 hash 表示 | 与既有 ValidatorId raw 32B 体系不一致（PR-1 保持 raw） |
| 变长/长度前缀编码 | 定长字段无需前缀；§3 定长规则（PR-1） |

## Consequences

- **正面**：ProposalRef wire representation 冻结；Node/Network 集成具备合法 decode 边界；与 vote/QC
  canonical 体系一致。
- **成本**：新增 ConsensusError variant（错误面扩展）。
- **可迁移**：未来 Proposal 完整格式（PHASE 7）可复用该引用编码。

## Security Impact

- decode 不泄漏 semantic（authority/membership 归 consensus）。
- 长度严格校验防 malformed input DoS（PR-3）。
- 不新增 proposer authority 验证（A11 保持 DEFERRED；本 ADR 仅 serialization，不改变 authority 语义）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：ADR-0041 ProposalRef Canonical Serialization（PR-1~PR-6 冻结） | 用户裁决新建 ADR-0041（不改 ADR-0037）；STEP 11-7 Design + ADR/Protocol Review PASS |
| 2026-08-30 | **FROZEN（ACCEPTED）**：64B canonical + `InvalidProposalEncoding` 冻结。仅 ADR；**不实现**（编码实现归 11-7 Implementation 授权） | 用户裁决 → ADR-0041 ACCEPTED/FROZEN |
| 2026-08-30 | **IMPLEMENTATION VERIFIED（11-7）**：`encode_proposal_ref` / `decode_proposal_ref` 实现于 `round.rs`，`InvalidProposalEncoding` 于 `error.rs`；nova-consensus 121 tests（roundtrip / 拒截断·超长·trailing / 字段精度 / 无 authority 检查）；四项 Gate 全 PASS；PR-1~PR-6 全部落实（canonical 唯一性 + roundtrip 成立；decode 无 semantic 泄漏） | STEP 11-7 Implementation commit `2adf10a` → 保持 FROZEN |
