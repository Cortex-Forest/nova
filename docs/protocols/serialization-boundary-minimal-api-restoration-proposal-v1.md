# Nova Chain — Serialization Boundary Minimal API Restoration Proposal V1（P0-B1）

- **Status**: **FINAL FROZEN**（P0-B1；Serialization Boundary Minimal API Restoration FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 恢复 `ValidatorVote` 的冻结 serialization contract 中缺失的 decode API
  （`SPEC-FROZEN / API-MISSING`）。**ProposalRef 不在此范围（SPEC-NOT-FROZEN → DEFERRED）。**
- **依据**（全部 READ-ONLY）：ADR-0034 V-4/V-5（FROZEN）+ ADR-0009（FROZEN）+
  crypto-serialization-v1 §7/§8（FROZEN）+ consensus-spec §14（FROZEN）+ 11-1 §3（FROZEN）+
  vote.rs / error.rs 实现。

## 0. 分类结论（B1 Deep Fact Audit）

```
ValidatorVote = SPEC-FROZEN / API-MISSING
  - canonical layout 冻结（ADR-0034 V-4 + ADR-0009 + consensus-spec §14）：121B 定长
  - roundtrip 契约冻结（crypto-serialization §8：decode(encode(p)) == p + §7 禁止表示）
  - decode API 未实现；无隐含 decode；消费者全直接构造结构体
  - ConsensusError::InvalidVoteEncoding 已冻结存在（error.rs:17，ADR-0034 V-5）
```

## 1. 20 问回答

| # | 问题 | 回答 |
|---|---|---|
| 1 | decode 为何属 Consensus 非 Node | canonical serialization 知识封装在 `nova-consensus::vote`（encode 所在）；decode 是 encode 的对称逆运算，同所有权域；Node 只 decode wire envelope，不拥有 consensus canonical 布局 |
| 2 | 为何 Node 不允许复制 121B layout | 双重 canonicalization 风险（Node 第二套规则 vs Consensus 规则 ⇒ 两 codec 漂移）；node→consensus 已批准，Node 可依赖冻结 primitive |
| 3 | 最小合法 API | `pub fn decode_validator_vote(bytes: &[u8]) -> Result<ValidatorVote, ConsensusError>`（与 `decode_qc` / `decode_checkpoint` 模式一致） |
| 4 | 输入长度须严格 121B？ | 是（定长 canonical；§7 拒绝非 minimal / trailing） |
| 5 | 字段如何恢复 | `round(8LE)‖height(8LE)‖target(32)‖vote_type(1)‖source(32)‖validator_id(32)‖timestamp(8LE)` 逆序解析；`vote_type` 经 `VoteType::try_from`、`validator_id` 经 `ValidatorId::from_bytes`（复用冻结类型） |
| 6 | 允许 trailing bytes？ | 否（§7 拒绝多余/尾随填充字节） |
| 7 | 允许 alternate representation？ | 否（§7 唯一 canonical 表示） |
| 8 | decode 做 semantic validation？ | 否（仅结构解析；semantic 归 verify_vote / transition） |
| 9 | decode 验证 vote signature？ | 否（签名验证归 `verify_vote` V-5） |
| 10 | decode 验证 validator authority？ | 否（membership 归 verify_vote ①） |
| 11 | decode 做 domain separation？ | 否（domain 归 signed_bytes / verify_vote） |
| 12 | decode 做 replay/context validation？ | 否（guards 归 transition） |
| 13 | 错误属于哪层 | consensus 层（`ConsensusError`） |
| 14 | 新增 ConsensusError variant？ | **否**——`InvalidVoteEncoding` 已冻结存在（error.rs:17） |
| 15 | 需要新 test vectors？ | 是（decode roundtrip / 拒绝 trailing / 拒绝截断 / 拒绝未知 vote_type） |
| 16 | 影响 ADR-0034？ | 否（V-4 layout 不变；decode 恢复既有契约） |
| 17 | 影响 ADR-0009？ | 否（signature coverage 不变） |
| 18 | 影响 crypto-serialization-v1？ | 否（§8 roundtrip 契约已冻结；decode 是其实现） |
| 19 | protocol semantic change？ | **NO**（canonical / signature / domain / quorum / transition 全不变） |
| 20 | 真的需要 ADR？ | 语义不变 + 错误 variant 已存在 + roundtrip 契约已冻结 ⇒ 倾向 **NOT REQUIRED**；但属冻结 crate 新 public API 面 ⇒ **独立 Review + 明确授权**（不自动实施） |

## 2. 最小 API 设计（仅展示，不实现）

```rust
/// 恢复冻结 roundtrip 契约（crypto-serialization §8）的 decode 侧。
/// 仅结构解析；semantic/签名/domain/replay 均不验证（归 verify_vote / transition）。
pub fn decode_validator_vote(bytes: &[u8]) -> Result<ValidatorVote, ConsensusError> {
    // ① 长度严格 = 8+8+32+1+32+32+8 = 121B（§7 拒绝 trailing/截断）
    // ② round 8LE / height 8LE / target 32
    // ③ vote_type: VoteType::try_from(bytes[48])?   （拒绝未知 ⇒ InvalidVoteEncoding）
    // ④ source 32 / validator_id: ValidatorId::from_bytes(bytes[49..81]) / timestamp 8LE
}
```

**强制最小化原则**：只恢复冻结 serialization contract；不改变 canonical bytes / signature coverage /
domain / verification / transition / quorum / replay / event / state。任何超范围 ⇒ STOP → classify →
ADR review → explicit authorization。

## 3. 影响面

| 项 | 状态 |
|---|---|
| Protocol semantic change | NO |
| Canonicalization change | NO |
| Signature / domain / quorum / transition / event / state | 全不变 |
| ConsensusError | 复用 `InvalidVoteEncoding`（已冻结，0 新增） |
| ADR-0034 / ADR-0009 / crypto-serialization-v1 | 全不变 |
| ADR-0041 | 倾向 NOT REQUIRED（待用户裁决确认） |
| 测试 | 新增 decode roundtrip / 拒绝 trailing / 截断 / 未知 vote_type |
| 依赖方向 | 不变（node→consensus 已批准） |

## 4. 明确不做（本 Proposal）

- ❌ 不实现 decode_validator_vote（等待授权）
- ❌ 不修改 consensus / node / ADR-0032
- ❌ 不定义 ProposalRef encoding（保持 DEFERRED）
- ❌ 不实现 QC ingestion / 不创建 external.rs

## 5. 裁决请求

> **P0-B1 结论：ValidatorVote decode = SPEC-FROZEN / API-MISSING → Minimal API Restoration
> （恢复 `decode_validator_vote`，语义零变化）。**
>
> 需要您裁决：
> (A) 批准 Minimal API Restoration（展开独立 Review → 授权实现）
> (B) DEFER ValidatorVote decode（Vote 集成保持 BLOCKED）
> (C) 其他

**HARD STOP：不写代码，等待裁决。**

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Serialization Boundary Minimal API Restoration Proposal V1（20 问 + 最小 API 设计 + 影响面 + 裁决请求） | MASTER PARALLEL EXECUTION v4.0 — P0-B1 |
| 2026-08-30 | **Independent Review PASS（阶段 1）**：6 点验证全 PASS（① 严格 121B layout 对称 ② 复用 `InvalidVoteEncoding` ③ `decode(encode(v))==v` 可证 ④ 拒截断/超长/非法 vote_type/非 canonical ⑤ 不改 verify_vote/签名/domain/transition ⑥ 无新协议语义）；证据：decode 模式已在 decode_qc 内部验证可行；构建块全部冻结可用。观察（INFO）：validator_id 不验证 membership（归 verify_vote ①） | 用户两阶段授权（阶段 1）→ Review PASS |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（阶段 2）**：`crates/consensus/src/vote.rs` 实现 `decode_validator_vote`（+135，仅该文件）；5 新测试（roundtrip / 拒截断 / 拒超长+trailing / 拒非法 vote_type / 字段精度 / 无 membership 检查——实际 5 个含 no_membership）；nova-consensus 113 passed；四项 Gate 全 PASS（fmt/check/clippy exit 0，workspace 53 result 全 ok）。Security/Protocol Review：0 Blocker / 0 Must-Fix / 0 Protocol Violation | 用户第二阶段明确授权 → commit `80570e0` |
| 2026-08-30 | **FINAL FREEZE（P0-B1）**：Serialization Boundary Minimal API Restoration = **FINAL FROZEN**。仅文档变更记录更新；不修改实现代码。Protocol semantic change = 0；`ProposalRef` wire encoding **仍 DEFERRED**（SPEC-NOT-FROZEN）；QC ingestion DEFERRED；external.rs NOT CREATED | 用户裁决 → P0-B1 FINAL FREEZE（独立 documentation commit） |
