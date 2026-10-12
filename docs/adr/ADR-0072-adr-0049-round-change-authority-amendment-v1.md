# ADR-0072: ADR-0049 Amendment — Bounded Round-Change Authority

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；**Owner 授权 PHASE 6H-S —— ADR-0072 Owner Decision + Freeze**）
  （本文件为**独立修订 ADR**。**不构成 ADR-0049 的编辑**、**不授权任何实现**、
  **不修改任何既有 ADR**。**冻结 ≠ 实现授权**：O2 实现仍为 **BLOCKED**。）
- **Date**: 2026-10-07
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: 以**独立 Amendment ADR** 的形式，对 **ADR-0049 §3.13 reason 4** 作**语义层面的部分替代
  （partial supersession）**，其范围**仅限于**允许 ADR-0066 所定义的**有界 round-change 权威**
  （`RoundChangeCertificate`，`+1`）存在。**ADR-0049 本体保持逐字节不变。**
- **Type**: Independent Amendment ADR（**非**对 ADR-0049 的原地编辑）
- **Phase provenance**: PHASE 5（受控实验 E1–E5 证据）→ PHASE 6（O1–O4 比较）→ PHASE 6C（ADR-0066 草案）
  → PHASE 6H / 6H-A / 6H-B1 / 6H-B2（治理与分配）→ PHASE 6H-E（P-5 = BLOCKED）
  → PHASE 6H-M（freeze readiness = NO，P-5 = BLOCKED）→ PHASE 6H-N（D1 = C：requires independent ADR）
  → **PHASE 6H-O（Owner D1 = A：CREATE INDEPENDENT AMENDMENT ADR）**
  → **PHASE 6H-P（只读 PRECHECK：文件名 / 编号 / 范围 / 关系）**
  → **PHASE 6H-Q（本草案创建）**
- **关联（只读引用，不修改）**: **ADR-0049（Liveness / Pacemaker V1，FROZEN —— 本 ADR 的修订对象）** ·
  **ADR-0066（RoundChangeCertificate，DRAFT —— 本 ADR 所许可的权威之定义源）** ·
  ADR-0070（Canonical Serialization，DRAFT）· ADR-0053（Lock Justification & Override，FROZEN）·
  ADR-0037（BFT Round）· ADR-0038（Finality）· ADR-0069（Signing Domain Allocation Governance，FROZEN）·
  `docs/protocols/consensus-spec-v1.md`
- **非授权声明（MUST 逐字保留）**:

```text
This ADR does not authorize any implementation.

This ADR does not modify ADR-0049.
ADR-0049 remains frozen and byte-for-byte unchanged.

O2_IMPLEMENTATION_AUTHORIZED = NO
```

---

## 1. Purpose

本 ADR 的唯一目的：

```text
以【独立 Amendment ADR】的形式，消除 ADR-0049 §3.13 与 ADR-0066 之间的
frozen-vs-frozen 语义冲突 —— 且【不修改 ADR-0049 一个字节】。
```

精确措辞（MUST）：

```text
ADR-0049 §3.13 reason 4 is superseded in semantic effect only,
to the extent necessary to permit the bounded round-change authority
defined by ADR-0066.

ADR-0049 itself is NOT edited, replaced, or rewritten.

All other portions of ADR-0049 §3.13 remain in force.
```

**生效条件（MUST；PHASE 6H-S Owner Decision C-1 = APPROVE）**：

```text
The supersession defined by this ADR becomes effective only when this ADR is FROZEN.
Until that time, ADR-0049 §3.13 remains fully in force.
```

⇒ 本 ADR **冻结之前**，ADR-0049 §3.13 的 reason 1–5 与尾句**全部保持完整效力**；
本 ADR 冻结之时，reason 4 的语义效果方按 §5.1 被部分替代。

**关系链（唯一允许的解读）**：

```text
Independent amendment
        ↓
partial supersession
        ↓
only reason 4
```

**MUST NOT 声称**：

```text
× ADR-0049 is modified
× ADR-0049 is deleted
× ADR-0049 is replaced wholesale
× ADR-0066 overrides ADR-0049
```

## 2. Supersession Basis

### 2.1 冲突的精确定义

`docs/adr/ADR-0049-liveness-pacemaker-v1.md` §3.13 现为 **FROZEN** 且**逐个点名**不需要以下工件：

```text
TimeoutCertificate / RoundChangeCertificate / PacemakerCertificate
```

并给出 5 条理由，其**尾句**为：

```text
未来若需要 ⇒ 独立 ADR。
```

而 **ADR-0066（DRAFT）** 拟引入 `RoundChangeCertificate`（有界 `+1` round-transition 权威）。

⇒ 若不处理，将出现**两个 FROZEN ADR 语义互相矛盾**的治理状态。

### 2.2 程序依据（本 ADR 的合法性来源）

§3.13 的**尾句本身**即授权路径：**「未来若需要 ⇒ 独立 ADR」**。

```text
本 ADR 即为 §3.13 尾句所要求的【那个独立 ADR】。
⇒ 程序上不是「推翻 ADR-0049」，而是【执行 ADR-0049 §3.13 自身规定的程序】。
```

### 2.3 事实依据（PHASE 5 受控实验，7 个真实进程）

来自 PHASE 5（`yazimao-node`，7 个 OS 进程）的既有观测（**只读引用，未在本阶段重跑**）：

| 配置 | 结果 |
|---|---|
| **7/7** | PASS（`max_stall = 0.0s`；pacemaker 从未触发） |
| **6/7** | **FLAKY**（全样本 PASS 2/6；恢复时延 ≈ 930s） |
| **5/7** | **PERSISTENT STALL**（停滞高度恒 = 2；单高度最多 3 个 round 并存） |
| **4/7** | PASS（预期无 finality） |

**该证据的用途（严格限定）**：

```text
· 用于说明 §3.13 reason 4（"local round progression 已足够"）在分布式设置下【被经验否证】。
· local round progression 是【local】原语 ⇒ 不能产生 global round agreement。
```

**MUST NOT 声称**：

```text
× 该证据证明 RoundChangeCertificate 已经实现
× 该证据证明 O2 解决了整体 liveness 问题
× 7/7 / 6/7 / 5/7 的任何 blocker 已被解决
```

## 3. Scope of Amendment

**允许的修订范围 = 仅 §3.13 reason 4 的语义效果。**

| ADR-0049 位置 | 是否触及 | 说明 |
|---|---|---|
| **§3.13 reason 4** | ✅ **语义效果被部分替代** | 唯一被修改语义的项 |
| §3.13 reason 1 | ❌ | 保持有效 |
| §3.13 reason 2 | ❌ | 保持有效 |
| §3.13 reason 3 | ❌ | 保持有效 |
| §3.13 reason 5 | ❌ | 保持有效（并作为边界约束保留） |
| §3.13 尾句 | ❌ | 其要求已由本 ADR 满足 |
| §3.3 Timer Start | ❌ | **保持不变** |
| §3.4 Timer Reset | ❌ | **保持不变** |
| §3.4.1 Timer Event Matrix | ❌ | **语义保持不变**（见 §8） |
| §3.9 Round Change（状态矩阵） | ❌ | **保持不变**（见 §6.3） |
| §3.10 LockedState Interaction | ❌ | **保持不变**（见 §7） |
| §3.11 Partition Behavior | ❌ | **保持不变** |
| §4 Safety Guarantees | ❌ | **保持不变** |
| §5 Liveness Conditions | ⚠️ **仅注释（非编辑）** | 见 §3.1 |
| §6 Invariants（LIV-1..LIV-14） | ⚠️ **仅注释（非编辑）** | 见 §3.2 |
| §9 / §11 / §12 | ⚠️ **仅注释（非编辑）** | 见 §3.3 |

### 3.1 §5（Liveness Conditions）

本 ADR **不编辑** ADR-0049 §5。仅在此**声明**：ADR-0066 §20 的活性陈述所需的前置假设为

```text
>= ceil(2T/3) reachable validator weight
AND
>= T/3 honest validator weight timely emits timeout attestations
for each intervening round
```

该假设**不改变** ADR-0049 §5 既有条文，**不降低**既有 quorum 要求（`ceil(2T/3)` 保持）。

### 3.2 §6 / LIV-12

本 ADR **不编辑** ADR-0049 §6。仅在此**声明**：

```text
local round progression != global round agreement
```

LIV-12（`Proposer failure can be bypassed by round progression`）仍然成立，其措辞不变。

### 3.3 §9 / §11 / §12

本 ADR **不编辑** 上述各节。仅**声明**：`RoundChangeCertificate` 的**登记（§9）**、
**验证要求（§11）**、**复杂度/成本重估（§12）** 属 **ADR-0066 的未来实现映射**（ADR-0066 §18），
由 ADR-0066 及其实现阶段独立承载；本 ADR **不使**任何一条生效。

### 3.4 附随语义效果 —— ADR-0049 §3.4.1 的 round-change authority 前提
（**PHASE 6H-S Owner Decision C-2 = APPROVE OPTION (b)**）

本 ADR **不编辑** ADR-0049 §3.4.1。仅声明其**有限附随语义效果**：

```text
The supersession of ADR-0049 §3.13 reason 4 necessarily carries the limited semantic effect
that a valid RoundChangeCertificate constitutes the round-change authority referenced by
ADR-0049 §3.4.1. This does not amend or edit ADR-0049 §3.4.1 itself, and does not alter its
timer semantics or any other transition rule.
```

**范围限定（MUST）**：

```text
· ADR-0049 §3.4.1 本体【绝对不编辑】
· 【不】把整个 §3.4.1 视为 superseded —— 仅其「round-change authority」前提受此附随效果影响
· timer semantics 不变（§3.3 / §3.4 / §3.4.1 全部保留）
· RESET / NO-OP / STOP / EXPIRE 矩阵【不改变】
· RoundChangeCertificate 仍【不是】QC / 不是 finality certificate / 不是 vote / 不是 PrecommitQC /
  不是 lock override
· 【不得】unlock / 【不得】触发 finality / 【不得】替代 vote 或 PrecommitQC / 【不得】override LockedState
· 仍只允许 from_round + 1；【不允许】round jump
```

## 4. History Preservation

```text
ADR-0049 的原文（含 §3.13 全部 5 条理由与尾句）【逐字节保留】。
本 ADR 不修改 ADR-0049，不追加任何注记，不重写任何历史文本。
```

**受保护事实（MUST 保持不变）**：

```text
docs/adr/ADR-0049-liveness-pacemaker-v1.md
SHA256 = C4BF74925BBAF7E8B8AC52E83AF2E7CCAA60459165B2C0CF0553EB1D0BD8802E
```

**Owner 决策约束（PHASE 6H-P follow-up，Q-P1 = α）**：

```text
ADR-0049 MUST REMAIN BYTE-FOR-BYTE UNCHANGED.
ADR-0072 shall independently carry the supersession relationship.
Do NOT add any note to ADR-0049 at this stage.
```

⇒ 因此 **ADR-0049 §3.13 的文本仍逐字写「不需要 RoundChangeCertificate」**；
该文本层面的矛盾**由本 ADR 的 supersession 声明在语义层面消解**，而非通过编辑 ADR-0049。

**可读性说明（非规范性）**：未来若 Owner 希望文本层面亦一致，可另行授权一次**最小非规范性**
ADR-0049 §3.13 注记 —— 但**本 ADR 不请求、不预设、不依赖**该步骤。

## 5. Retained Reasons and Boundaries

### 5.1 保留的理由（逐条）

| §3.13 理由 | 处置 | 依据 |
|---|---|---|
| **1**「timeout 是 local event」 | **RETAIN** | 仍然成立 —— 证书是 timeout 的**聚合证据**，不是 timeout 本身 |
| **2**「timeout 非 finality proof」 | **RETAIN** | 仍然成立 |
| **3**「finality 必须继续依赖 valid PrecommitQC」 | **RETAIN** | 仍然成立，且 **MUST 保持** |
| **4**「local round progression（`checked_successor`）已足够」 | **PARTIAL SUPERSESSION（语义效果）** | PHASE 5 证据否证其充分性；替代范围为「允许存在一个有界 `+1` 的 round-transition 权威」 |
| **5**「避免额外 consensus proof complexity」 | **RETAIN（作为边界约束）** | 保留为「有界 +1 · 无 QC · 无 finality · 不解锁」的复杂度限制 |

> **生效时点（PHASE 6H-S C-1 = APPROVE）**：上表 **reason 4** 的 supersession **自本 ADR 冻结之时生效**；
> 其**余名项在本 ADR 冻结前后均保持有效**。详见 §1 生效条件。

### 5.2 MUST 恒真的边界（无论 reason 4 是否被部分替代）

```text
timeout 仍是 local event
timeout 仍非 finality proof
finality 仍 MUST 依赖 valid PrecommitQC
quorum 仍为 ceil(2T/3)，不得降低
Safety 仍优先于临时 Liveness（ADR-0049 §3.11 保持）
```

## 6. Bounded +1 Round-Change Authority

### 6.1 权威的定义来源（**本 ADR 不重新定义**）

`RoundChangeCertificate` 的**语义、字段、阈值、编码**由 **ADR-0066**（设计源）与
**ADR-0070**（canonical serialization，DRAFT）承载。本 ADR **仅**许可其**存在性**，
**不**重复定义、**不**修改、**不**实现。

### 6.2 有界性（MUST）

```text
to_round := checked_successor(from_round) = from_round + 1
MUST NOT 允许 to_round > from_round + 1（禁止任意 round skipping）
MUST NOT 把「交易进入 DAG」等同「最终确认」
```

### 6.3 §3.9 状态矩阵（**保持不变**）

本 ADR **不改变** ADR-0049 §3.9 的候选冻结矩阵：

```text
DAG / FinalityState / Valid historical QC / PrevoteQC registry / PrecommitQC proof / LockedState
        ⇒ Preserve
RoundState / proposal / prevotes / precommits / round_evidence
        ⇒ Reset
```

`RoundChangeCertificate` 的应用只表现为「`round` 恰好 `+1` + ARM 新 timer」，
**不改变**上述 preserve/reset 归类。

## 7. Non-Coupling with QC / Finality / Lock

**MUST NOT（协议级硬约束；与 ADR-0066 §9.1 一致）**：

```text
MUST NOT become a QC
MUST NOT create finality
MUST NOT be finality evidence
MUST NOT contribute vote weight
MUST NOT enter VoteAccumulator
MUST NOT enter RoundEvidence
MUST NOT enter QcRegistry
MUST NOT call assemble_qc
MUST NOT pass through verify_qc as a QC
MUST NOT create or advance LockedState
MUST NOT unlock LockedState
MUST NOT override an unrelated lock
MUST NOT be vote-equivalent
```

**ADR-0053 兼容（**无授权修订**）**：

```text
L-9  V1 defines no unrelated higher-round lock override        （保持）
L-10 Timeout / Round Change / Proposer Change MUST NOT unlock  （保持）
L-12 lock enforcement = Non-Scope（仍 DEFERRED）                （保持）
```

```text
higher round != lock override
round change != unlock
```

## 8. Timer Semantics Preserved

ADR-0049 §3.3 / §3.4 / §3.4.1 的 timer 语义 **MUST 保持不变**：

```text
enter (height, round, Propose) → start timer
old round timer MUST NOT remain active
new round MUST have its own timer
round transition MUST NOT inherit stale deadline
timer reset MUST NOT alter: height · round · quorum · LockedState · DAG validity · FinalityState
```

`RoundChangeCertificate` 若未来被实现，其**唯一** timer 语义为（ADR-0066 §11）：

```text
应用合法证书 ⇒ 进入新 round ⇒ ARM 新 timer（不继承 stale deadline）
```

**MUST NOT**：`inherit stale deadline` / `reuse expired timer` / `unlock local lock` /
`alter proposer-selection algorithm`。

**§3.4.1 的 RESET / NO-OP / STOP / EXPIRE 矩阵语义不变。**
（其中 `Future-round message（无 valid round-change authority）⇒ NO-OP` 一行在
**证书存在且合法**时按 ADR-0066 §7.1 处理；但在证书**不存在/不合法**时行为**完全不变**。此处
**仅声明**，**不编辑** §3.4.1。该附随语义效果的精确范围见 §3.4；PHASE 6H-S C-2 = OPTION (b)。）

## 9. Compatibility / Serialization Boundary

```text
· 不改 canonical 签名框架：algorithm_id ‖ domain_id ‖ chain_id ‖ payload_length ‖ payload
· 不改 build_signed_bytes 的签名或语义
· 不改 ValidatorVote 编码（185B 保持）
· 不改 ProposalRef（64B 保持）
· 不引入链上状态（证书不入 consensus state）
· 本 ADR 不改变任何 Rust 源码 / 测试 / 既有工件编码
```

**签名域（只读引用）**：`DomainId::RoundChangeCertificate = 0x10`（Owner 批准 PHASE 6H-B2；
分配规则 = ADR-0069（FROZEN）；登记 = ADR-0067 §0.6 / ADR-0005）。

**消息类型（独立命名空间，未分配）**：

```text
MessageType 0x0D = OWNER APPROVED CANDIDATE（非 FROZEN / 非代码分配 / 未实现）
网络消息类型的正式分配与 ADR-0072 的 supersession【彼此独立】。
```

## 10. Security Considerations

```text
S-1  本 ADR 不引入新的 safety 权威：证书 ≠ QC ≠ finality ≠ lock override ≠ vote 等价物。
S-2  域分离是防跨域重放的核心防线；证书使用专用签名域 0x10（ADR-0069 / ADR-0067）。
S-3  reason 4 的部分替代【不降低】quorum（ceil(2T/3) 保持）与 finality 条件（valid PrecommitQC）。
S-4  ADR-0049 §3.10 的「MUST NOT unlock」原则【不变】⇒ 不存在由证书引入的 lock 绕过面。
S-5  有界 `+1` 派生规则（`checked_successor`）是**唯一** round 转移原语 ⇒ 无任意跳跃面。
S-6  本 ADR 不改变 Byzantine 上限、validator 权重、staking/slashing 语义。
S-7  本 ADR 不声称抗量子特性，不改变任何密码算法或密钥格式。
```

## 11. Genesis / Testnet / Akash Impact

```text
· Genesis 影响 = NONE
    DomainId / 证书不进入 Genesis canonical bytes；本 ADR 不改变 chain_id / network_id /
    validator identity / genesis_hash。
· Testnet 影响 = NONE（本 ADR）
    不产生链上工件变化；不要求重新生成 Genesis 或重启网络。
· Akash 影响 = NONE
    本 ADR 不改变 Containerfile / SDL / 部署参数 / 镜像内容 / 种子 / 端口 / 拓扑。
```

**边界声明（Owner D5 = C，KEEP EXISTING AKASH / TESTNET GATE）**：

```text
ADR-0066 Freeze != O2 Implementation != L1 Release != Akash Testnet Deployment
本 ADR 不改变既有 Testnet / Akash release gate。
```

## 12. Open Questions（**不得静默决定**）

```text
O-1  是否需要（以及何时）对 ADR-0049 §3.13 追加【最小非规范性】注记，以使文本层面亦一致？
     （本 ADR 不请求、不预设；Owner Q-P1 = α 明确当前不做）
O-2  ✅ RESOLVED（PHASE 6H-S）：本 ADR 已于 **2026-10-07 冻结**（Owner 授权 PHASE 6H-S）；
     冻结前已完成独立 Review（PHASE 6H-R：A findings = 0，B findings = 0；C-1 / C-2 由 Owner 裁定）。
O-3  reason 5 的「复杂度边界」是否需要进一步的量化上界（例如证书消息大小的绝对上限）？
     （当前 OPEN；由 ADR-0070 §8 数值 + 实现阶段决定）
O-4  §3.4.1 的 `Future-round message` 一行在未来实现阶段是否需要**正式**措辞修订
     （属 ADR-0049 编辑 ⇒ 需另行 Owner 授权）？
O-5  ADR-0066 §18 的「本阶段不编辑 ADR-0049」表述在本 ADR 存在后成为半失效 —— 属文档同步范围。
O-6  是否需要为「独立 Amendment ADR」程序本身建立通用治理规则（对齐 ADR-0069 Rule 族）？
```

```text
These MUST NOT be silently decided by implementation.
```

## 13. Non-Authorization

```text
This ADR does not authorize any implementation.

O2_IMPLEMENTATION_AUTHORIZED = NO

未授权：RoundChangeCertificate struct / verification / signing / Abandon signing /
        codec / new MessageType / network propagation / gossip / pacemaker transition /
        RoundTimer change / round-change logic / QcRegistry / RoundEvidence /
        finality / lock / consensus / sync / deployment / genesis / Akash。
```

**依赖关系（MUST 保持独立，不得自动合并）**：

```text
ADR-0072 supersession            != O2 implementation authorization
ADR-0072 supersession            != ADR-0066 freeze
ADR-0072 supersession            != liveness fix
ADR-0072 supersession            != A17 resolution
ADR-0072 supersession            != upgrade-compatibility resolution
ADR-0072 supersession            != Akash / Testnet gate change
```

**独立 blocker（本 ADR 不解决、不声称解决）**：

```text
5/7 = persistent stall（PHASE 5 实测）
6/7 = flaky（PHASE 5 实测）
A17 = unresolved
upgrade compatibility deadlock = unresolved
```

## 14. Freeze Requirements

```text
本 ADR 当前 = FROZEN（2026-10-07）。

R-1  ✅ SATISFIED —— 独立 Review 已完成（PHASE 6H-R；A findings = 0，B findings = 0）。
R-2  ✅ SATISFIED —— Owner 明确授权（PHASE 6H-S —— ADR-0072 Owner Decision + Freeze）。
R-3  ✅ SATISFIED —— 依 Owner 决策（PHASE 6H-P follow-up，Q-P2 = YES）：
       ADR-0072 must be created and independently reviewed/frozen BEFORE ADR-0066 Freeze.
     本 ADR 已完成自身 Freeze gate；ADR-0066 Freeze 的【执行】仍为 NOT EXECUTED（独立阶段）。
R-4  ✅ 保持 —— 本 ADR 的 freeze 与 ADR-0066 的 freeze 是【两个独立授权】，不得合并。
R-5  ✅ 保持 —— ADR-0049 未因本 ADR 的 freeze 而被编辑（逐字节不变）。
```

**Freeze 前置条件核对（PHASE 6H-S）**：

```text
A findings = 0                                  ✅
B findings = 0                                  ✅
C-1 = resolved by explicit Owner Decision       ✅（C-1 = APPROVE：仅自 FROZEN 之时生效）
C-2 = resolved by explicit Owner Decision       ✅（C-2 = APPROVE OPTION (b)：有限附随语义效果，§3.4）
ADR-0072 语义仍限于其声明的修订范围              ✅
ADR-0049 逐字节不变                              ✅（C4BF7492…）
ADR-0066 不变                                    ✅（B3792634…）
无实现 / 无网络变更 / 无部署变更 / 无 Akash 变更  ✅
```

**Freeze 检查清单（PHASE 6H-S 执行时核对）**：

```text
[✓] §2.3 的 PHASE 5 证据引用准确（7/7 PASS · 6/7 flaky · 5/7 persistent stall · 4/7 PASS）
[✓] §5.1 逐条处置表与 ADR-0049 §3.13 原文（5 条理由）严格对应
[✓] §5.2 / §7 / §8 的 MUST 边界与 ADR-0066 §7.2 / §9.1 / §11 一致
[✓] ADR-0049 hash 未变（C4BF7492…）
[✓] ADR-0066 / ADR-0053 未被修改
[✓] 无任何 Rust / network / MessageType / 代码变更被夹带
```

**D / E findings（PHASE 6H-R）处置（不属 Freeze blocker）**：

```text
D-1 / D-2 / D-3 / E-1 / E-2 = ACCEPTED / DEFERRED（本次未扩大变更范围）
```

## 15. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-07 | **ADR-0072 初稿（DRAFT — NOT FROZEN）**：ADR-0049 Amendment — Bounded Round-Change Authority。以**独立 Amendment ADR**（Q-P1 = α）承载对 ADR-0049 §3.13 **reason 4** 的**语义层面部分替代**；明确 reason 1/2/3/5 保持有效、timer 语义不变、非耦合边界（非 QC / 非 finality / 非 lock override / 非 vote 等价物）、有界 `+1`、兼容性边界、安全考虑、Genesis/Testnet/Akash 影响 = NONE、Open Questions、非授权声明、Freeze 前置要求。**未修改 ADR-0049**（逐字节不变）；**未修改** ADR-0066 / ADR-0067 / ADR-0069 / ADR-0070 / ADR-0071 / ADR-0005 / ADR-0062 / ADR-0068；**未**实现任何代码；**未**分配 MessageType；**未**冻结本 ADR | Owner 授权 PHASE 6H-O D1 = A + PHASE 6H-P follow-up（Q-P1 = α，Q-P2 = YES）→ PHASE 6H-Q —— ADR-0072 CREATION ONLY |
| 2026-10-07 | **PHASE 6H-R — 独立 Review（READ-ONLY，零修改）**：治理 + 协议语义 12 项审查；**A findings = 0 · B findings = 0**；C-1（supersession 生效时点）与 C-2（§3.4.1 边界）记录为待 Owner 裁定；D-1 / D-2 / D-3 / E-1 / E-2 记录为可延后。末修改任何文件 | Owner 授权 PHASE 6H-R —— INDEPENDENT REVIEW ONLY |
| 2026-10-07 | **PHASE 6H-S — Owner Decision + FREEZE EXECUTION**：Status `DRAFT — NOT FROZEN` → **FROZEN**。新增 §1 **生效条件**（C-1 = APPROVE：supersession **仅自本 ADR 冻结之时生效**；冻结前 ADR-0049 §3.13 保持完整效力）与 §3.4 **有限附随语义效果**（C-2 = APPROVE OPTION (b)：`valid RoundChangeCertificate` 构成 ADR-0049 §3.4.1 所引用的 round-change authority，**不编辑** §3.4.1、不改 timer semantics、不改 RESET / NO-OP / STOP / EXPIRE 矩阵、不引入 QC / finality / lock override / vote 等价物、仍只允许 `+1`）；§5.1 加生效时点注记；§8 加交叉引用；§12 O-2 → RESOLVED；§14 更新为 FROZEN 并核对 Freeze 前置条件；D / E findings = ACCEPTED / DEFERRED（未扩大变更范围）。**未修改 ADR-0049**（逐字节不变）**/ ADR-0066 / ADR-0067 / ADR-0068 / ADR-0069 / ADR-0070 / ADR-0071 / ADR-0005 / ADR-0062**；**未**实现任何代码；**未**分配 MessageType；**未**冻结 ADR-0066 | Owner 授权 PHASE 6H-S —— ADR-0072 OWNER DECISION + FREEZE |

---

## References（只读）

```text
docs/adr/ADR-0049-liveness-pacemaker-v1.md             （FROZEN；§3.3/§3.4/§3.4.1/§3.9/§3.10/§3.11/§3.13/§4/§5/§6/§9/§10/§11/§12）
docs/adr/ADR-0053-lock-justification-override-v1.md    （L-1..L-12，FROZEN）
docs/adr/ADR-0066-round-change-certificate-v1.md       （DRAFT；本 ADR 所许可的权威之定义源；§5/§7/§9/§11/§18/§20/§25）
docs/adr/ADR-0067-domain-registry-amendment-v1.md      （DRAFT；§0.6 Allocation Record）
docs/adr/ADR-0069-signing-domain-allocation-governance-v1.md（FROZEN；Rule A–I）
docs/adr/ADR-0070-roundchangecertificate-canonical-serialization-v1.md（DRAFT；§8 数值已获 Owner 批准，ADR 未冻结）
docs/adr/ADR-0071-o2-design-and-preparation-record-v1.md（DRAFT；§3 ADR-0049 §3.13 修订设计）
docs/adr/ADR-0037-bft-round-architecture-v1.md         （B-1/B-3/B-5）
docs/adr/ADR-0038-finality-architecture-v1.md          （F-1..F-18）
docs/protocols/consensus-spec-v1.md                    （§5 Liveness Assumptions）
crates/crypto/src/domain.rs                            （DomainId::RoundChangeCertificate = 0x10）
```
