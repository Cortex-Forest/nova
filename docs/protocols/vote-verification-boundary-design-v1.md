# Nova Chain — Vote Verification Boundary Design V1（11-6 / GAP-1 Resolution）

- **Status**: Draft（STEP 11-6；Verification Boundary Design / GAP-1 Resolution Proposal；
  待独立 Review → 第二阶段实现授权；**只设计不实现**）
- **Date**: 2026-08-30
- **Scope**: 解决 **GAP-1（Medium）**——Vote 的 V-5 验证生产调用点缺失，MF-2 precondition 未满足。
  方案 **(b)**：**Consensus 侧验证门面**（Node 不拥有 V-5 语义）。
- **依据**（全部 READ-ONLY）：STEP 11-1（FROZEN）§5 + 10-11（FROZEN）L1 + 11-4（FROZEN）+
  ADR-0034 V-4/V-5（FROZEN）+ vote.rs / validator.rs / integration.rs 实现 + STEP 11-5/11-6 审计（GAP-1）。

## 0. 背景（GAP-1）

- 当前 Vote 链路：envelope 签名验证（Network）→ decode → `ConsensusEvent::Vote` → `transition`
  （**不验证 vote 签名**，MF-2 假设已验证）。
- `verify_vote` 生产调用点仅 `finality.rs:270`（verify_qc 内部）；**网络到达 Vote 的验证调用点缺失**。
- 下游 `verify_qc` 兜底（fork_choice FC-13 / precommit 分支）⇒ 无 finality 突破，但违反 MF-2 防御纵深
  （未验证 evidence 占用 round_evidence/registry + 契约违反）。**不因兜底视为已解决。**

## 1. 方案 (b)：Consensus 侧验证门面

- **关键区分**：
  - **(a)** Node 直接调 `verify_vote` ⇒ Node 承担验证调用语义，重开 11-1 §5 职责边界 → **不选**。
  - **(b)** Consensus 提供**验证门面**，Node 调用门面（Node 是门面的调用者，V-5 语义全在 Consensus）。
- **门面设计**（consensus crate；建议 `integration` 模块或独立 `verification` 模块——实现授权时定）：

```rust
/// Consensus 验证门面（GAP-1 解决；V-5 验证入口，供 Node 在构造 `ConsensusEvent::Vote` 前调用）。
///
/// - **只委托既有 `verify_vote`（V-5），不复制验证逻辑**。
/// - 从 `set` 按 `vote.validator_id` 解析共识公钥（**不信任 envelope sender / NodeId**，B5）；
///   `set.info` 查无 ⇒ `UnknownValidator`。
/// - 语义：MF-2 precondition 的强制入口——未通过 V-5 的 vote 不得进入 `ConsensusEvent::Vote`。
pub fn verify_vote_input(
    vote: &ValidatorVote,
    signature: &[u8; 64],
    chain_id: u64,
    set: &ValidatorSet,
) -> Result<(), ConsensusError> {
    let info = set.info(&vote.validator_id).ok_or(ConsensusError::UnknownValidator)?;
    let vk = VerifyingKey::from_bytes(&info.consensus_public_key)
        .map_err(|_| ConsensusError::UnknownValidator)?;
    verify_vote(vote, signature, &vk, chain_id, set)
}
```

## 2. Node 集成（设计）

```
handle_vote(payload):
  (vote, signature) = classify_vote_payload(payload)?      // 结构解析
  verify_vote_input(&vote, &signature, chain_id, &set)?    // Consensus 门面（MF-2 强制）
      .map_err(NodeError::VoteVerification)?               // 未通过 ⇒ 拒绝，不构造 event
  transition(...)                                          // 仅验证通过后
```

- Node **调用门面**（V-5 实现全在 Consensus）；Node 不拥有 V-5 语义。
- 验证通过后构造 `ConsensusEvent::Vote`（event 形状不变）。
- `transition` **完全不变**。

## 3. 8 点约束映射（硬边界）

| # | 约束 | 设计满足 |
|---|---|---|
| 1 | 门面只调用既有 `verify_vote`，不复制 | ✅ `verify_vote_input` 仅委托 `verify_vote` + `set.info` 查公钥 |
| 2 | Node 不拥有 V-5 语义 | ✅ V-5 实现仍在 vote.rs；Node 只调用门面 |
| 3 | signature/domain/sender/membership 检查不可绕过 | ✅ 全在 `verify_vote`（V-5 五步）内；门面无新检查、不绕过 |
| 4 | `ConsensusEvent::Vote` 仅 MF-2 满足后进入 transition | ✅ 门面 Ok 后才构造 event |
| 5 | 不新增 `ConsensusEvent` variant | ✅ 无 |
| 6 | 不修改 `transition` | ✅ 无 |
| 7 | 不触碰 ProposalRef / QC ingestion / A11 | ✅ 无 |
| 8 | ADR 以实际影响判定，不预设 | ⚠️ 见 §5 |

## 4. 关键边界（B5）

- **envelope sender（NodeId）≠ vote validator（ValidatorId）**：门面从 `set` 解析
  `consensus_public_key`，**不信任 envelope sender**（N-2 / B5）。vote 的验证身份由
  `vote.validator_id` + set 决定，与网络 sender 无关。

## 5. ADR 判断

- 倾向 **ADR NOT REQUIRED**：`verify_vote_input` 是**既有冻结 API 的 integration facade**
  （只委托 `verify_vote` + `set.info` 查公钥；无新 canonicalization / signature / domain / quorum /
  validation 规则 / transition / event / ingestion）。
- **不预设**：独立 Review 时按实际 API/协议影响确认。若 Review 判定属新 consensus primitive
  ⇒ ADR 评估 / Protocol Review。

## 6. 明确不做（本 Design）

- ❌ 不实现（只设计）。
- ❌ 不修改 `verify_vote` / `transition` / `ConsensusEvent`。
- ❌ 不新增 ConsensusEvent variant / QC ingestion / external.rs / ProposalRef encoding。
- ❌ Node 不直接调 `verify_vote`（不选 a）。
- ❌ 不修改 ADR-0032 / 冻结规范。

## 7. 测试计划（设计，实现授权后执行）

- 门面：合法 vote 签名 Ok / 篡改签名 Err / 未知 validator Err / 错误 chain_id Err。
- Node 集成：Vote envelope 有效签名 → Applied；**vote 签名错（envelope 有效）⇒ 拒绝（双层签名独立闭合）**；
  上下文错 → Ignored（Consensus guards 不变）。
- 回归：workspace 四项 Gate。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Vote Verification Boundary Design V1（GAP-1 Resolution 方案 (b)：Consensus 侧验证门面 `verify_vote_input` + Node 集成 + 8 点约束映射 + B5 边界 + ADR 判断） | 用户授权 STEP 11-6 Verification Boundary Design（只设计不实现） |
| 2026-08-30 | **Independent Review PASS（11-6）**：8 点约束全满足；B5 确认（门面从 `set.info(validator_id)` 解析公钥，不信任 envelope sender，模式与 verify_qc 一致）；MF-2 真正满足；ADR = NOT REQUIRED（integration facade，与 P0-B1 先例一致）。Observation：Micro-Fix 建议 `VerifyingKey::from_bytes` 失败用 `ValidatorIdentityMismatch`（与 verify_qc 一致） | 用户授权 Independent Review（只读）→ PASS |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（11-6）**：`vote.rs` 实现 `verify_vote_input`（set.info 解析公钥 + Micro-Fix `ValidatorIdentityMismatch` + 只委托 `verify_vote` V-5，不复制）+ 4 测试；`assembly.rs` `NodeError::VoteVerification` + `handle_vote` 集成（门面 MF-2 强制后构造 `ConsensusEvent::Vote`）+ `handle_envelope_rejects_invalid_vote_signature`（双层签名独立闭合）；nova-consensus 117 / nova-node 8 passed；四项 Gate 全 PASS；GAP-1 CLOSED（生产验证调用点建立）；transition 零改动 / 无新 event variant / Proposal·QC·A11 零越界 / external.rs NOT CREATED | 用户第二阶段明确授权 → commit `2576fac` |
| 2026-08-30 | **FINAL FREEZE（11-6）**：STEP 11-6 全链封版（Design FROZEN + Review PASS + Implementation COMPLETE）。仅文档变更记录更新；**不修改实现代码/不改变协议**。GAP-1 CLOSED；双层独立验证链完整；ADR NOT REQUIRED；Consensus/Network/ADR-0032 UNCHANGED；external.rs NOT CREATED | 用户裁决 → STEP 11-6 FINAL FREEZE（独立 documentation commit） |
