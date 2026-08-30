# Nova Chain — STEP 11 阶段性 Release Freeze V1

- **Status**: **FROZEN**（STEP 11 Phase Release Freeze；2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 固化 STEP 11 已稳定子 STEP（11-1~11-7）为阶段性基线；明确 QC / A11 为**独立后续 Track**，
  不污染已冻结部分。

## 0. 阶段性基线（固化）

```
STEP 10 Consensus（10-1~10-14）   FINAL FROZEN
Serialization Boundary（P0-B1）    FINAL FROZEN
STEP 11-1 Integration Design      FINAL FROZEN
STEP 11-2 Wire Types              FINAL FROZEN（Implementation + Freeze）
STEP 11-3 Envelope Verification   FINAL FROZEN（Implementation + Freeze）
STEP 11-4 Node Assembly           FINAL FROZEN（Vote + RoundTimeout）
STEP 11-5 RoundTimeout            FINAL FROZEN
STEP 11-6 Vote Integration        FINAL FROZEN（GAP-1 CLOSED，verify_vote_input 门面）
STEP 11-7 Proposal                FINAL FROZEN（ADR-0041 + serialization + Node Integration）
────────────────────────────────────────────────
Git 基线: HEAD a2659ce · CLEAN
Release Gates: fmt / check / clippy / workspace test 全 PASS
Security: 0 Blocker / 0 High / 0 Medium / 0 Low
Protocol Defect: NO · ADR 触发: 0（本阶段）
```

## 1. 已冻结链路（不再反复审查）

| 链路 | 组件 | 冻结依据 |
|---|---|---|
| Wire Types | MessageType 0x08/0x09/0x0A | 11-2 / MF-11-2-1/2 |
| Envelope Verification | validate_consensus_envelope | 11-3 / N-4 |
| RoundTimeout | Node-local → RoundTimeout → transition | B-3 / 11-1 §7 |
| Vote | decode_validator_vote → verify_vote_input → Vote → transition | P0-B1 / 11-6 |
| Proposal | decode_proposal_ref → SetProposal → transition | ADR-0041 / 11-7 |

## 2. 独立后续 Track（不污染基线）

```
STEP 11-8 QC Ingestion    🔒 DEFERRED — 独立 Track（先 verification boundary design → ADR 决策）
A11 / proposer authority  🔒 DEFERRED — 独立 Track
```

- **原则**：已冻结部分彻底封存；QC/A11 设计变化不得影响 Vote/Proposal/RoundTimeout 稳定基线。
- QC：不新增 `ConsensusEvent::Qc`（除非专门协议决策）；`verify_qc → admit` 边界明确；
  不因"verify_qc 兜底"绕过 ingestion verification。

## 3. Release 状态

- STEP 11 核心网络化（Envelope + Vote + Proposal + RoundTimeout）已端到端可验证。
- 剩余：QC ingestion（独立 Track）、ProposalRef→完整 Block（PHASE 7）、Node 全量运行时（后续）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11 阶段性 Release Freeze V1（固化 11-1~11-7 基线 + QC/A11 独立 Track 声明 + Release 状态） | 用户裁决 STEP 11 阶段性 Release Freeze |
