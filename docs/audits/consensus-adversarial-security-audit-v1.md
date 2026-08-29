# Nova Chain — Consensus Adversarial Security Audit V1（10-13）

- **Status**: **FINAL**（STEP 10-13；Consensus Adversarial Security Audit，2026-08-30）
- **依据**: ADR-0033~0040（FROZEN）+ `consensus-spec-v1.md`（FROZEN）+ 10-9/10-10/10-11/10-12（FROZEN）+ 实际代码 + 临时 adversarial tests（运行后删除）。
- **本报告是审计产物，不修改任何冻结契约/代码**；仅记录验证结果。

---

## 1. Objective

以**实际代码、测试、调用链与临时 adversarial tests** 为证据，验证共识层在恶意输入 / 异常顺序 / 重复消息 / QC 操纵 / finality conflict / equivocation / replay / determinism / panic-DoS 下的安全性。**允许推翻 FACT AUDIT 结论。**

## 2. Repository Evidence

- 生产代码：`validator/vote/dag/witness/round/finality/checkpoint/fork_choice/integration`（11 模块）。
- 依赖：`consensus → core/crypto` 单向（cargo tree）；无反向依赖。
- 确定性：grep 确认生产代码无 `SystemTime/Instant/rand/static mut/Mutex/Atomic/迭代顺序依赖`；仅 2 处不可达 `expect`。
- 临时 adversarial tests（`crates/consensus/tests/adversarial_security.rs`，**运行后删除**）：10 tests 全 PASS。

## 3. Attack Surface

| 模块 | 冻结防御 | 攻击面 |
|---|---|---|
| Validator | identity 检查（V-5 ②） | forged validator（需私钥） |
| Vote | verify_vote 五步 | invalid sig / wrong domain / wrong chain |
| VoteAccumulator | 按 target 去重 | duplicate（防御）；**equivocation（无检测，ASSUMPTION）** |
| DAG | add_block 唯一+parents 存在+height 严格递增 | 环/坏引用/冲突（拒绝） |
| Witness | deterministic_select（W-2） | 无下游消费（DEFERRED） |
| BFT Round | context+terminal guards + proposal 匹配 | stale/future/wrong-height/wrong-target/after-finality |
| Finality | verify_qc（F-6a 五层） | malformed/forged/insufficient/duplicate QC |
| Checkpoint | derive（CP-MF-4）/verify（CP-MF-10） | checkpoint 操纵 |
| Fork Choice | 纯函数 + FC-12 短路 | fork-choice 操纵 |
| Integration | transition 三元组 + 原子性 | replay/dup/malformed/determinism |

## 4. A1~A23 Results

| # | 攻击 | 防御 | 结果 |
|---|---|---|---|
| A1 | forged validator | V-5 ② identity（需私钥） | 拒绝 ✓ |
| A2 | invalid signature | verify_vote/verify_qc | 拒绝 ✓ |
| A3 | wrong domain | 域分离（DomainId::ValidatorVote） | 拒绝 ✓ |
| A4 | wrong chain/context | context guards | Ignored ✓ |
| A5 | duplicate vote | VoteAccumulator 去重 | 不重复计权 ✓（测试 t3 / adv-dup） |
| A6 | equivocation/double vote | **无检测** | **ASSUMPTION CONFIRMED**（见 §6） |
| A7 | stale vote | context guards | Ignored ✓ |
| A8 | future-round vote | context guards | Ignored ✓ |
| A9 | wrong-height vote | context guards | Ignored ✓（adv-replay） |
| A10 | wrong-target vote | process_vote proposal 匹配 | 不推进 ✓ |
| A11 | forged proposal proposer | **set_proposal 不验身份** | **DEFERRED**（无权威，见 §7） |
| A12 | conflicting proposal | set_proposal 仅一次 | 后续 Ignored ✓ |
| A13 | malformed QC | decode_qc 结构 + verify_qc | 拒绝 ✓ |
| A14 | forged QC | verify_qc 签名 | 拒绝 ✓ |
| A15 | insufficient quorum | verify_qc 权重<quorum | 拒绝 ✓（adv-insufficient） |
| A16 | conflicting QC | F-8 Conflict≠error | finality 不前进 ✓ |
| A17 | replay after finality | terminal guard | Ignored{Terminal} ✓ |
| A18 | checkpoint manipulation | verify_checkpoint 优先序 | 拒绝/不派生 ✓ |
| A19 | fork-choice manipulation | 纯函数 + FC-12 | 无操纵面 ✓ |
| A20 | terminal-state bypass | 双重终态守卫 | 不可绕过 ✓ |
| A21 | deterministic divergence | MF-12 纯函数 | 无 ✓（adv-permutation） |
| A22 | panic/assertion abuse | decode checked；2 处 expect 不可达 | 无 panic 可达 ✓（adv-exp1） |
| A23 | DoS/resource amplification | decode 长度严格校验；DFS visited | 无小 payload 大分配 ✓ |

## 5. QC Adversarial Verification（QC-1~QC-10）

| QC | 结果 |
|---|---|
| QC-1 insufficient quorum | `InsufficientQuorum` ✓（adv 测试） |
| QC-2 invalid signature | `verify_qc` 拒绝 ✓（现有 finality tests） |
| QC-3 unknown validator | `Evidence(UnknownValidator)` ✓ |
| QC-4 wrong target（target ∉ DAG） | `UnknownTarget` ✓ |
| QC-5 wrong height（签名不匹配重建） | 签名失败 → 拒绝 ✓ |
| QC-6 wrong round | 同上 ✓ |
| QC-7 duplicate validator evidence | `DuplicateValidator` ✓（adv 测试） |
| QC-8 conflicting evidence | 升序/去重检查 + F-8 ✓ |
| QC-9 forged aggregate/malformed | decode 结构 + verify ✓ |
| QC-10 altered signed bytes | verify_strict 拒绝 ✓（现有 tests） |

## 6. A6 Equivocation Deep Dive

**实际测试**（adv `a6_*`，全 PASS）：
- 同 validator0、同 height/round、对 target A 与 B 各投 prevote ⇒ `VoteAccumulator` 两 target 都计权（100/100）——**equivocation 权重双计**。
- 但单 validator 100 < quorum 134 ⇒ **不构成 quorum / QC / 推进**（step 保持 Prevote）。
- 完整 transition：v0 双投 + v1 诚实投 A ⇒ A 达 prevote quorum（200≥134），B 未达（100<134）⇒ **无 conflicting finality**；`finalized_reference = None`。

**调用链**：`Vote → verify_vote（V-5）→ process_vote（context guard）→ VoteAccumulator（按 target 去重）→ QC formation（需 2/3 真实权重）→ verify_qc → F-8 applicability → TransitionResult`。

```
Equivocation: NOT DETECTED（VoteAccumulator 仅按 target 去重；无 validator vote-history 约束）
Can equivocation alone create invalid QC? NO（单 validator 需真实 2/3 权重）
Can equivocation alone create conflicting finality? NO（B 无 2/3；需真实 2/3 双投）
Security impact: ASSUMPTION（honest validator 不双投，spec §3；GAP C；slashing DEFERRED）
Frozen contract: consensus-spec §3（ASSUMPTION 标记）；ADR-0037 B-2（去重语义）
Protocol Defect: NO
ASSUMPTION CONFIRMED: YES（当前共识安全性依赖 honest-validator 不双投假设）
```

**多 validator equivocation 分析（如实记录，非 PASS）**：
- 单个 equivocating validator 无法构成 quorum/QC（adv 测试证实：100 < 134）。
- 若 **≥2/3 权重 validators 双投**，两个 target 各自可满足 quorum，形成**密码学有效但相互冲突的 QC**——
  这正是 classic BFT equivocation 攻击场景，由 **honest-validator 不双投假设（spec §3）** 防住。
- 状态机层：`finality.finalized_reference` 为**单值** `Option<[u8;32]>`；F-8 `Conflict` 非错误，
  `update_finalized_reference` 对 Conflict 不更新 ⇒ **不会产生"双重 finalized canonical state"**；
  但若假设被破坏（Byzantine ≥1/3），冲突 QC 到达顺序会影响不同节点的观察（safety/liveness 归安全论证）。
- **结论**：honest 假设内（<1/3 Byzantine）**无证据表明 equivocation 可组合形成非法 QC**；
  安全模型依赖假设，如实标记 ASSUMPTION，非 HARD STOP。

```
F-13-01
Classification: ASSUMPTION
Status: ASSUMPTION CONFIRMED

Evidence:
  VoteAccumulator permits the same validator to contribute to different targets
  because deduplication is target-scoped.

Security consequence:
  A single equivocating validator can contribute weight to multiple targets.

Current protocol consequence:
  By itself, one validator cannot satisfy quorum / create QC / advance finality
  because quorum requires the configured validator weight threshold.

Security model:
  Consensus safety currently relies on the frozen honest-validator assumption.

Protocol action:
  No automatic fix. Slashing/equivocation enforcement remains DEFERRED.
```

## 7. A11 Proposal Authenticity Deep Dive

**实际测试**（adv `a11_*`，PASS）：
- `set_proposal(ProposalRef{block_hash, proposer: validator1})` 被接受（`true`，step→Prevote）——**proposer 身份未验证**（可伪造声明）。
- 但仅 SetProposal 后：`finality.finalized_reference = None`、`prevote_qc=None`、`checkpoint=None`——**无 authority**。
- proposal 只是候选引用；**推进需真实 validator quorum**（prevote/precommit 2/3）。

**结论**：`proposal authenticity absent` 但 `proposal has no authority until valid quorum`——**forged proposer 不能直接 finalize / 绕过投票 / 改变 canonical finality**。真实性验证（block 签名/header 签名）归 block/network 层（PHASE 7）。

```
Can forged proposer identity directly finalize? NO
Can forged proposer identity bypass validator vote? NO
Can forged proposer identity alter canonical finality? NO
Classification: DEFERRED（block 层验证归 PHASE 7；非 consensus SECURITY DEFECT）

Proposal proposer authenticity: NOT ENFORCED in current Consensus layer
  （set_proposal 不验证 proposer 身份；ProposalRef 无签名）
BUT:
  Forged proposer identity:
    - cannot directly finalize
    - cannot bypass validator vote
    - cannot manufacture valid QC
    - cannot directly alter finality

Proposal authenticity is a future Block/Network integration boundary and remains DEFERRED.
```

## 8. Replay / Cross-Context Verification

- 旧 height vote → `Ignored{ContextMismatch}`（adv `replay_old_height_ignored` PASS；状态不变）。
- 旧 round / 已 finalize / conflicting proposal → context+terminal guards（现有 T2/T5/T18）。
- height/round/target/context confusion 全部由冻结 guards 表达，无新规则。

## 9. Determinism Adversarial Verification

- adv `determinism_permutation_same_result` PASS：同逻辑输入、不同 vote 提交顺序 ⇒ 同 `finality` + 同 `round(height/round/step)` + 同 `context`（permutation invariant）。
- 生产代码无 `HashMap/HashSet` 迭代顺序进入结果；causal_order/maximal anchor/root 均确定性（现有 T9/T17/T21/T23）。
- **无 iteration/arrival order 依赖**。

## 10. Panic / DoS Verification

**`fork_choice.rs:143`（select_root expect）**：
```
Reachability:            INTERNAL ONLY（攻击者不可达）
Attacker controllability: 不可控（add_block 强制 parent.height < height ⇒ 无环 ⇒ 非空必有 root）
Call path:              fork_choice → O-3 root fallback → select_root（前提 DAG 非空）→ expect
Impact:                 NONE（不 panic 可达；不导致 crash/liveness/inconsistent/DoS）
Evidence:               adv exp1_* 构造空/单/多 root/坏 parent/坏 height/重复 DAG，全不 panic
Classification:          INFO（non-blocking；10-8 H-1 已审计）
```

**`checkpoint.rs:157`（encode_checkpoint u32::try_from expect）**：
```
Reachability:            DEVELOPER MISUSE（attacker network-unreachable）
Attacker controllability: 不可控（QC bytes=93+count×136，超 u32::MAX 需 count>~31.5M evidence；
                         网络输入需先过 decode_qc/verify_qc 真实 bytes；validator 集有界）
Call path:              derive_checkpoint（已验证 QC）→ encode_checkpoint → u32::try_from → expect
Impact:                 NONE（consensus 内部路径不可达；无 panic/DoS）
Evidence:               10-6.2 H-1 已审计；count 无上限但需真实 bytes 匹配长度
Classification:          INFO（non-blocking）
```

**确认**：不存在 attacker-controlled panic / node crash / consensus liveness failure / state inconsistency / DoS amplification（decode 用 `checked_add/checked_mul` + 严格长度校验 `bytes.len()==total` ⇒ 无小 payload 大分配；DFS 有 visited ⇒ 无无限循环）。

## 11. Cross-Layer Boundary Verification

- Network 不能绕过 consensus verification（network 无 consensus 消息/无耦合，C-1）。
- Storage 恢复状态不能绕过 transition invariants（storage 无 ConsensusState hook；恢复归 Storage Phase，DEFERRED）。
- Node 不能直接制造 finality（node 骨架无 orchestration，DEFERRED）。
- Execution 不能伪造 consensus evidence（execution → core+crypto，无 coupling）。
- Consensus 不信任 transport metadata（transition 输入仅 (state, context, event)，MF-12）。
- RoundTimeout 仅 Node-local 构造（B-3）。
- N-4 未被绕过（无新增 DomainId）。

## 12. Frozen Contract Audit

无攻击突破冻结规则（C-1/V-1~V-6/D-1~D-5/W-1~W-6/B-1~B-6/F-1~F-18/CP-1~CP-8/FC-1~FC-14/MF-1~12/10-11/10-12）。

## 13. Findings

| ID | Severity | 内容 | Classification |
|---|---|---|---|
| F-13-01 | ASSUMPTION | equivocation/double-vote 无检测；安全模型依赖 honest 不双投（GAP C）；slashing 归 PHASE 7+ | **ASSUMPTION / DEFERRED**（非 PASS，非 defect） |
| F-13-02 | DEFERRED | proposal proposer 无签名验证；真实性验证归 block/network 层（PHASE 7）；无 consensus authority | **DEFERRED**（非 defect） |
| F-13-03 | INFO | 两处 expect 不可达（fork_choice.rs:143 / checkpoint.rs:157） | INFO（non-blocking） |
| F-13-04 | INFO | Witness 无下游消费（10-4 孤立实现） | DEFERRED（未来 proposal/block-production 消费） |

## 14. Assumptions

1. **honest validator 不双投**（spec §3；ASSUMPTION CONFIRMED——安全论证依赖，未由状态机强制）。
2. **lock 规则**（spec §1.4，GAP D）未在 `process_vote` 强制。

## 15. Deferred Risks

slashing / equivocation punishment、validator rotation、epoch、complete Block Spec（proposal 真实性）、persistent ConsensusState encoding（Storage）、network transport（Network）、Node runtime、Witness 消费点。

## 16. Security Classification

- **CRITICAL: 0**；**HIGH: 0**；**MEDIUM: 0**；**LOW: 0**（两处 expect 为 INFO，non-blocking）。
- **ASSUMPTION: 1**（equivocation）；**DEFERRED: 2**（proposal 真实性、witness 消费）。

## 17. Protocol Defect

**NO**

## 18. ADR Requirement

**NO**

## 19. Conclusion

共识层在 adversarial 输入（A1~A23 / QC-1~QC-10 / replay / determinism / panic-DoS / cross-layer）下**未发现可被攻击者利用的安全缺陷**；10 项临时 adversarial tests 全 PASS 佐证。安全模型**明确依赖 honest-validator 不双投假设**（ASSUMPTION CONFIRMED，如实记录，非 PASS）；proposal 真实性验证为 DEFERRED（PHASE 7）。

## 20. Change Record

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Consensus Adversarial Security Audit V1（FINAL）——A1~A23/QC-1~10/replay/determinism/panic-DoS/cross-layer；10 项临时 adversarial tests 运行后删除；F-13-01=ASSUMPTION、F-13-02=DEEFERRED、F-13-03/04=INFO | STEP 10-13 SECURITY VERIFICATION EXECUTION（允许推翻 FACT AUDIT；未推翻） |
