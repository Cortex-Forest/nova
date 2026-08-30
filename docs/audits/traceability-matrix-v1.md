# Nova Chain — STEP 11-13 Traceability Matrix V1

- **Status**: **FROZEN**（STEP 11-13；Traceability Matrix Design V1 FINAL FREEZE，2026-08-30）
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
| `ValidatorVote` decode | canonical 布局冻结（ADR-0034 V-4 / ADR-0009 / crypto-serialization §8）；**专门 decode API 未冻结/未实现** | **SPEC-FROZEN / API-MISSING**（ROUND 3 B1 结论：crypto-serialization §8 roundtrip 契约 + V-4 布局冻结；decode 缺失实现、无隐含实现、消费者全直接构造结构体） | OPEN（→ Minimal API Restoration Proposal 待授权） |
| `ProposalRef` wire encoding | 11-1 §3 明确不定义；无 ADR/spec encoding | **SPEC-NOT-FROZEN** | **DEFERRED** |

- 上述两项在 **Serialization Boundary 裁决** 前无合法实现路径；
  Node 不得复制 canonical layout（双重 canonicalization 风险）。
- 若裁决需新增 Consensus API ⇒ **HARD STOP → ADR/Protocol Review**（不自行添加）。

### ROUND 3 证据链（B1）

- `ValidatorVote` 消费者（vote/round/checkpoint/fork_choice/integration）**全部直接构造结构体**
  （字段 pub），无 decode 路径、无隐含 decode。
- `verify_vote` 接受已构造 `&ValidatorVote`（不接收 bytes）——不隐含 decode。
- crypto-serialization §8 冻结 roundtrip 契约（`decode(encode(payload)) == payload`）——
  是通用要求；ValidatorVote 的 decode 侧未实现 ⇒ **API/Implementation Gap（非 Protocol Defect）**。

## 明确不做

- 不新增映射/不填补 Gap（文档 only）。
- 不修改 Consensus / ADR-0032 / 不创建 external.rs。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-13 Traceability Matrix V1（ADR→Spec→Design→Impl→Test→Security→Freeze 全链路 + SERIALIZATION BOUNDARY GAP 标记） | MASTER PARALLEL EXECUTION ROUND 2 — Track E |
| 2026-08-30 | ROUND 3 补充：B1 证据链（消费者全直接构造 / verify_vote 不隐含 decode / §8 roundtrip 未实现） | MASTER PARALLEL EXECUTION ROUND 3 — Track E |
| 2026-08-30 | **DESIGN FREEZE（11-13）**：Status Draft→FROZEN。Serialization Boundary GAP 诚实标记：ValidatorVote = SPEC-FROZEN / API-MISSING；ProposalRef = SPEC-NOT-FROZEN / DEFERRED。GAP 不隐藏、不猜测填补 | MASTER PARALLEL EXECUTION v4.0 — P1 Track E |
