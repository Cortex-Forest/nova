# Nova Chain — STEP 11-13 Traceability Matrix V1

- **Status**: Draft（STEP 11-13；待 Review → Freeze）
- **Date**: 2026-08-30
- **Scope**: `ADR → Protocol Spec → Design → Implementation → Test → Security Audit → Freeze`
  全链路映射（**文档 only**）。
- **依据**（全部 READ-ONLY）：已冻结 ADR/规范/设计 + 既有实现/测试。

## Traceability Matrix

| 行为 | ADR | Protocol Spec | Design | Implementation | Test | Security | Freeze |
|---|---|---|---|---|---|---|---|
| Network MessageType | ADR-0032 N-4 | crypto-serialization §5 | 11-2 | message.rs | 11-2 T1~T7 | threat model | 11-2 FINAL |
| Envelope verification | ADR-0032 N-4 | crypto-serialization §8 | 11-3 | validate_consensus_envelope | 11-3 T1~T9 | threat model | 11-3 FINAL |
| sender binding | ADR-0032 N-2/N-4 | — | STEP 9 | verify_message | message.rs | threat model | STEP 9 |
| signature coverage | ADR-0009 | crypto-serialization §10 | N-4 | verify_message | 11-3 T4 | threat model | STEP 9 |
| size constraints | ADR-0032 N-5 | — | gossip | check_size | 11-3 T3/T6 | threat model | STEP 9 |
| opaque payload | 11-1 §5 | — | 11-1/11-2/11-3 | validate_consensus_envelope | 11-3 T5 | threat model | 11-3 FINAL |
| Vote | ADR-0034 V-4/V-5 | consensus-spec §14 | 10-2 | vote.rs | 10-2 ✅ | adversarial audit | 10-2 |
| Proposal | ADR-0037 B-1/B-4 | consensus-spec | 10-5 | round.rs | 10-5 ✅ | adversarial audit | 10-5 |
| QC | ADR-0038 F-2/F-6a | consensus-spec | 10-6 | finality.rs | 10-6 ✅ | adversarial audit | 10-6 |
| RoundTimeout | ADR-0037 B-3 | consensus-spec §8 | 11-1 §7 | integration.rs | 10-9 ✅ | threat model | 10-9 |
| replay | 10-5.1 | consensus-spec | guards | round.rs | 10-5.1 ✅ | adversarial audit | 10-5.1 |
| deterministic transition | MF-12 | consensus-spec | 10-9.2 | integration.rs | T9/T17/T23 | adversarial audit | 10-9 |
| A6 equivocation | — | consensus-spec §3 | — | — | — | **ASSUMPTION** | 10-13 |
| A11 proposer auth | — | consensus-spec | 11-1 §10 | — | — | **DEFERRED** | 11-1 |

## ⚠️ TRACEABILITY GAP — SERIALIZATION BOUNDARY（不自行填补）

| 项 | 现状 | 分类 | 状态 |
|---|---|---|---|
| `ValidatorVote` decode | canonical 布局冻结（ADR-0034 V-4 / ADR-0009 / crypto-serialization §8）；**专门 decode API 未冻结/未实现** | **SPEC-FROZEN-BUT-API-MISSING（候选，待裁决）** | OPEN |
| `ProposalRef` wire encoding | 11-1 §3 明确不定义；无 ADR/spec encoding | **SPEC-NOT-FROZEN** | **DEFERRED** |

- 上述两项在 **Serialization Boundary 裁决** 前无合法实现路径；
  Node 不得复制 canonical layout（双重 canonicalization 风险）。
- 若裁决需新增 Consensus API ⇒ **HARD STOP → ADR/Protocol Review**（不自行添加）。

## 明确不做

- 不新增映射/不填补 Gap（文档 only）。
- 不修改 Consensus / ADR-0032 / 不创建 external.rs。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-13 Traceability Matrix V1（ADR→Spec→Design→Impl→Test→Security→Freeze 全链路 + SERIALIZATION BOUNDARY GAP 标记） | MASTER PARALLEL EXECUTION ROUND 2 — Track E |
