# Nova Chain — STEP 11-10 Security Threat Model V1

- **Status**: Draft（STEP 11-10；待 Review → Freeze）
- **Date**: 2026-08-30
- **Scope**: Network / Node / Consensus 三层攻击面威胁模型（**DESIGN only，不实现**）。
- **依据**（全部 READ-ONLY）：STEP 11-1/11-2/11-3（FROZEN）+ 10-11（FROZEN）+
  consensus-spec-v1.md（FROZEN）+ ADR-0032 N-4/N-5/N-7 + 既有安全审计
  （consensus-adversarial-security-audit-v1.md FINAL）。

## Network 层

| Threat | Trust Boundary | Existing Mitigation | Test | Owner | Status |
|---|---|---|---|---|---|
| sender spoofing | Network→Node | N-4 签名 + sender 身份绑定 | 11-3 T4 | Network | ENFORCED |
| signature tampering | Network→Node | N-4 签名覆盖 version‖type‖payload | 11-3 T4 | Network | ENFORCED |
| type/version tampering | Network→Node | N-4 签名覆盖 | 11-3 T4 | Network | ENFORCED |
| payload tampering | Network→Node | N-4 签名覆盖 | 11-3 T4 | Network | ENFORCED |
| length abuse / DoS | Network→Node | 既有 max_msg_bytes | 11-3 T3/T6 | Network | ENFORCED |
| unknown discriminator | Network→Node | TryFrom 拒 | 11-2 T5 | Network | ENFORCED |
| malformed input | Network→Node | decode 纯函数无 panic | 11-3 T7 | Network | ENFORCED |
| duplicate delivery | Network→Node | gossip dedup / Consensus 去重 | I-8 | Network/Consensus | 分层 |

## Node 层

| Threat | Trust Boundary | Existing Mitigation | Test | Owner | Status |
|---|---|---|---|---|---|
| unauthorized semantic verification | Node→Consensus | 11-1 §5（Node 只 decode/dispatch） | 11-10 #19 | Node | 边界声明 |
| malformed decode | Node→Consensus | 仅 Network decode + 冻结布局 | 11-9 #8 | Node | ENFORCED |
| event fabrication | Node→Consensus | ConsensusEvent 由 Node 构造，Consensus 验证 | 11-6 | Node/Consensus | 边界声明 |
| context injection | Node→Consensus | Consensus context guards | 11-9 #13 | Consensus | ENFORCED |
| peer identity confusion | Node | NodeId ≠ ValidatorId ≠ NovaAddress（N-2） | 11-10 | Node | ENFORCED |
| proposer/validator authority confusion | Node | **A11 = DEFERRED**；NodeId ≠ proposer authority | — | Node | DEFERRED |

## Consensus 层

| Threat | Trust Boundary | Existing Mitigation | Test | Owner | Status |
|---|---|---|---|---|---|
| invalid vote | Consensus | V-5 verify_vote 五步 | 10-2 ✅ | Consensus | ENFORCED |
| invalid QC | Consensus | verify_qc（F-6a） | 10-6 ✅ | Consensus | ENFORCED |
| replay | Consensus | context guards | 10-5.1 ✅ | Consensus | ENFORCED |
| duplicate vote | Consensus | VoteAccumulator 去重 | 10-9 ✅ | Consensus | ENFORCED |
| wrong context | Consensus | guards | 10-9 ✅ | Consensus | ENFORCED |
| terminal state | Consensus | terminal guard | 10-5.1 ✅ | Consensus | ENFORCED |
| equivocation | Consensus | **A6 = ASSUMPTION**（slashing DEFERRED） | — | Consensus | ASSUMPTION |
| proposer authenticity | Consensus | **A11 = DEFERRED**（envelope valid ≠ proposer authority） | — | Consensus | DEFERRED |
| QC ingestion 越权路径 | Consensus | **QC ingestion = DEFERRED**（无合法入口不造 API） | 11-8 | Consensus | DEFERRED |

## Serialization Security Boundary（ROUND 3 补充）

| 责任 | 归属 | 依据 | 状态 |
|---|---|---|---|
| canonical encode（Vote/QC/Checkpoint） | Consensus（vote.rs / finality.rs / checkpoint.rs） | ADR-0034 V-4 / F-2 / CP-3 | ENFORCED |
| canonical decode（QC/Checkpoint） | Consensus（decode_qc / decode_checkpoint） | F-2 / CP-MF-9 | ENFORCED |
| canonical decode（ValidatorVote） | **SPEC-FROZEN / API-MISSING**（应属 consensus::vote 对称 API） | crypto-serialization §8 | **OPEN（待裁决）** |
| Vote semantic validation | Consensus（verify_vote V-5） | ADR-0034 V-5 | ENFORCED |
| Envelope signature / sender binding | Network（verify_message N-4） | ADR-0032 N-4 | ENFORCED |
| Replay（语义） | Consensus（context guards） | 10-5.1 | ENFORCED |
| Replay（网络去重） | Network（gossip dedup N-5） | ADR-0032 N-5 | ENFORCED |
| Proposer authority | **A11 = DEFERRED**（不新增验证） | 11-1 §10 | DEFERRED |
| QC validation / ingestion | Consensus verify_qc；**ingestion DEFERRED** | F-6a / 11-1 §12 | DEFERRED |

- **威胁（Serialization）**：Node 手写 decode → 双重 canonicalization 风险（Node 第二套规则 vs
  Consensus 规则）。缓解：decode 只归属 Consensus（不选 A）；不新增 consensus API 前不实现（不选 B）。
- **Residual Risk**：`ValidatorVote` decode API 缺失期间，Vote wire → ConsensusEvent 集成路径不可达
  （Vote 集成 = BLOCKED）。

## 标记（全局）

- `A6 equivocation = ASSUMPTION`（不得自动加 slashing / detector）
- `A11 proposal authenticity = DEFERRED`（Network sender ≠ Consensus proposer authority）
- `QC ingestion = DEFERRED`（无冻结合法入口，不创造 API）

## 明确不做

- 不实现任何检测/惩罚（DESIGN only）。
- 不新增 slashing / equivocation detector / proposer 签名验证 / QC ingestion。
- 不修改 Consensus / ADR-0032。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-10 Security Threat Model V1（Network/Node/Consensus 三层威胁 → Trust Boundary → Mitigation → Test → Owner → Status + A6/A11/QC 标记） | MASTER PARALLEL EXECUTION ROUND 2 — Track D |
