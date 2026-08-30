# Nova Chain — ProposalRef Serialization Design V1（11-7）

- **Status**: Draft（STEP 11-7；ProposalRef Serialization Design；待统一 Independent Review；
  **只设计不实现**）
- **Date**: 2026-08-30
- **Scope**: 冻结 `ProposalRef` 的 canonical wire encoding（当前 **SPEC-NOT-FROZEN**，11-1 §3）。
- **依据**（全部 READ-ONLY）：ADR-0037 B-1（ProposalRef 定义）+ 11-1 §3（wire representation 待冻结）+
  crypto-serialization-v1 §3/§6（canonical 编码规则）+ round.rs 实现。

## 0. FACT AUDIT

- `ProposalRef { block_hash: [u8; 32], proposer: ValidatorId }`（round.rs:28，ADR-0037 B-1）。
- **无 encode/decode**；无 ADR/spec 定义 wire representation（SPEC-NOT-FROZEN）。
- 11-1 §3："ProposalRef wire representation 仅在其对应编码规范已冻结后复用；本设计不新定义"——本 STEP 即冻结该编码规范。

## 1. Canonical Encoding 提案

- **布局**（crypto-serialization §3 定长无长度前缀 + §6 字段顺序）：
  ```
  block_hash(32B) ‖ proposer(32B) = 64B 定长
  ```
  - `block_hash`：原始 32B（§3 定长 bytes）。
  - `proposer`：`ValidatorId` 的 32B raw（`ValidatorId::as_bytes()`，与 vote canonical 中 validator_id 一致）。
- **API**（对称，仿 `decode_validator_vote` 模式）：
  ```rust
  pub fn encode_proposal_ref(p: &ProposalRef) -> Vec<u8>      // 64B
  pub fn decode_proposal_ref(bytes: &[u8]) -> Result<ProposalRef, ConsensusError>
  ```
  - `decode`：长度严格 64B（拒截断/超长/trailing，§7）；`block_hash` = bytes[0..32]；
    `proposer` = `ValidatorId::from_bytes(bytes[32..64])`。
- **错误**：需新 `ConsensusError` variant `InvalidProposalEncoding`（无既有合适 variant）。

## 2. ⚠️ ADR 触发（必须标记）

> **定义 ProposalRef canonical encoding = 新 canonicalization（B7 触发）；新增 `ConsensusError` variant
> = 新 consensus 错误面。⇒ ADR / Protocol Review REQUIRED**（不能作为 implementation detail 绕过）。
> 本设计仅提出编码提案；**ADR 评估是冻结前置条件**，未评估前不实现。

## 3. 明确不做（本设计）

- ❌ 不实现 encode/decode（等 ADR 评估 + Review + 实现授权）。
- ❌ 不修改 11-1 §3 / ADR-0037 / 冻结规范。
- ❌ 不实现 Node Proposal 集成（本设计仅冻结 encoding）。
- ❌ 不新增 ConsensusEvent variant / QC ingestion / external.rs。

## 4. 测试计划（设计）

- roundtrip（encode→decode）；拒截断/超长/trailing；字段精度（block_hash/proposer）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：ProposalRef Serialization Design V1（64B canonical 提案 + ADR 触发标记 + 硬边界） | 用户授权并行 STEP 11-7（仅设计不实现） |
| 2026-08-30 | ADR/Protocol Review PASS + ADR-0041 FROZEN（新建 ADR-0041，不改 ADR-0037；64B canonical + `InvalidProposalEncoding`） | 用户裁决 + 11-7 ADR/Protocol Review |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（11-7）**：`error.rs` 加 `ConsensusError::InvalidProposalEncoding`；`round.rs` 实现 `encode_proposal_ref` / `decode_proposal_ref`（ADR-0041 PR-1~PR-6，64B 定长 / 严格长度 / 无 authority 验证）；nova-consensus 121 tests（4 新：roundtrip / 拒截断·超长·trailing·空 / 字段精度 / 无 authority 检查）；四项 Gate 全 PASS；Security/Protocol Review 0 Blocker/0 Must-Fix/0 Protocol Violation | 用户授权 STEP 11-7 Implementation → commit `2adf10a` |
| 2026-08-30 | **FINAL FREEZE（11-7）**：STEP 11-7 全链封版（ADR-0041 FROZEN + IMPLEMENTATION COMPLETE）。仅文档变更记录更新；**不修改实现代码/不改变协议语义**。QC ingestion / A11 保持 DEFERRED；transition / ConsensusEvent 未触碰；external.rs NOT CREATED | 用户裁决 → STEP 11-7 FINAL FREEZE（独立 documentation commit） |
