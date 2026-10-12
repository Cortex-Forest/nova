# ADR-0066: RoundChangeCertificate / Cross-Round Synchronization Authority V1

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；**Owner 授权 PHASE 6H-T2**）
  （本文件为**设计规范**。**不构成协议修订**、**不授权实施**、**不修改任何既有 ADR**。
  **冻结 ≠ 实现授权**：O2 实现仍为 **NOT AUTHORIZED**。）
- **Freeze metadata（PHASE 6H-T2）**: C-1 = APPROVED OPTION (a) · C-2 = APPROVED OPTION (a) ·
  P-5 = SATISFIED FOR FREEZE PURPOSES · 历史状态同步注记见 **§28**
- **Date**: 2026-10-06
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: STEP 6C — Consensus Liveness Remediation（**design only**）
- **Phase provenance**: PHASE 5（受控实验 E1–E5，证据）→ PHASE 6（O1–O4 设计比较）→ PHASE 6B（O2 形式规格审查）→ **PHASE 6C（本 ADR 草案）**
- **关联（只读引用，不修改）**:
  ADR-0005（Domain Separation / Registry）· ADR-0009（Signature Coverage）· ADR-0012（Ed25519 Algorithm Registry）·
  ADR-0033（Consensus Architecture）· ADR-0034（ValidatorSet / Vote Verification）· ADR-0037（BFT Round，
  B-1/B-3/B-5）· ADR-0038（Finality，F-1~F-18）· ADR-0041（ProposalRef Canonical Serialization）·
  ADR-0049（Liveness / Pacemaker，§3.3/§3.4/§3.4.1/§3.5/§3.13/§5/§6/§9/§11/§12）·
  ADR-0050（Proposer Selection）· **ADR-0053（Lock Justification & Override，L-1~L-12）** ·
  `docs/protocols/consensus-spec-v1.md`（§5 Liveness Assumptions = OPEN）
- **Non-regression statement**: 本 ADR 文本**未修改** ADR-0049 / ADR-0050 / ADR-0053 / ADR-0041 / consensus-spec /
  任何 Rust 源码 / 任何测试。§18 仅提供**未来**修订映射。

---

## 1. Context

### 1.1 触发证据（PHASE 5 受控实验，7 个真实 `yazimao-node` OS 进程）

| 配置 | 结果 | 关键观测 |
|---|---|---|
| **7/7** | PASS | `timeouts_by_round = [0,…]`；round 发散 0/3 采样；`max_stall = 0.0s`；pacemaker **从未触发** |
| **6/7** | **FLAKY**（全样本 PASS 2/6；同一 3000s 窗口内 1/4） | 恢复时 `time-to-recovery ≈ 930s`、`round-to-recovery = 1`；未恢复时 stall ≈ 2941s；发散 78–93% 采样 |
| **5/7** | **FAIL 6/6（PERSISTENT）** | 停滞高度恒 = 2；stall ≈ 2791s；`timeouts_by_round ≈ [10,5,5,1–2]`（round 0..3 全部耗尽）；发散 71–75% 采样；单高度最多 **3 个 round 并存** |
| **4/7** | PASS（预期无 finality） | `head = 0`、`qc_tip = None`、`qc_served = 0` |

**proposer 排除证据（E4）**：停滞高度 2 上，`(h=2, r=0)` 的 proposer 离线（可解释首轮失败），但
`(h=2, r=1)` 与 `(h=2, r=3)` 的 proposer **均在线**（`prop@(2,3) = V4`，V4 在线）**仍无法达成 quorum**。
⇒ **离线 proposer 不是充分根因。**

**计时证据（E5）**：同一次运行内逻辑 tick 速率由 **5.9 → 3.0 tick/s**（1 tick = 1 step），
同一 tick 窗口的墙钟时长相差 ~2.4× ⇒ **墙钟恢复时延 ∝ 1/step-rate**。

### 1.2 既有冻结语义（直接核实的代码/文档事实）

| # | 事实 | 出处 |
|---|---|---|
| C-1 | `RoundState::set_proposal` 仅在 `step == Propose` 时接受；`ProposalRef` 仅含 `block_hash ‖ proposer` | `crates/consensus/src/round.rs`；ADR-0041（64B，FROZEN） |
| C-2 | `ValidatorVote` **含 `(round, height)`** 且逐票独立可验证（canonical 121B；wire 185B） | `crates/consensus/src/vote.rs`；`crates/node/src/assembly.rs` |
| C-3 | `RoundEvidence` 绑定 `(height, round)`；`reset()` **清空**；`record()` 拒绝不匹配 | `crates/consensus/src/integration.rs` |
| C-4 | vote 上下文守卫：`vote.(height,round) ≠ state.round` ⇒ `Ignored{ContextMismatch}` | `crates/consensus/src/integration.rs` |
| C-5 | QC 绑定单一 `(height, round)`：`QcContext{chain_id,height,round,vote_type}`；`verify_qc` 要求 `target ∈ DAG` 且逐条 evidence **重建为 `ValidatorVote`** 后走 V-5 | `crates/consensus/src/finality.rs`（F-2/F-3/F-6a） |
| C-6 | `checked_successor(r) = r.checked_add(1)`；`MAX_ROUND = u64::MAX`；溢出 ⇒ `Rejected{RoundOverflow}` | `crates/consensus/src/integration.rs` |
| C-7 | timeout 以**逻辑 step tick** 计量；`round_timeout_window_ticks = timeout_for(min(r,64)).max(1)`；默认 `(1000, 60_000, ×2)` | `crates/node/src/runtime.rs`；ADR-0049 §3.5 |
| C-8 | `RoundTimeout` ⇒ `round+1` **且** `round_evidence.reset(height, round+1)` | `crates/consensus/src/integration.rs` |
| C-9 | **ADR-0049 §3.13（FROZEN）**：Nova V1 **不需要** TimeoutCertificate / RoundChangeCertificate / PacemakerCertificate | ADR-0049 |
| C-10 | **ADR-0049 §3.4.1（FROZEN）** 已含 `Future-round message（**无 valid round-change authority**）⇒ NO-OP` | ADR-0049 |
| C-11 | **ADR-0053 L-9**：`V1 defines no unrelated higher-round lock override`；**L-10**：Timeout / Round Change / Proposer Change **MUST NOT unlock** | ADR-0053 |
| C-12 | **ADR-0053 L-12**：lock **enforcement** = Non-Scope（仍 DEFERRED）；ADR-0049 §3.10 同 | ADR-0053 / ADR-0049 |
| C-13 | DomainId 注册表：`0x06 = Witness`、**`0x07 = Contribution`（ADR-0005 FROZEN）**；`0x00`/`0x08+` = Reserved（**必须拒绝**）；**代码将 `0x07` 实现为 `Proposer`** ⇒ 注册表冲突**未解** 【**RESOLVED** —— 已由 PHASE 6G/6H 治理解决；历史状态见 §28】 | ADR-0005；`crates/crypto/src/domain.rs` |

### 1.3 为什么需要本 ADR

ADR-0049 §3.2/§3.13 的设计前提是「**local round progression（`checked_successor`）已足够**」。
PHASE 5 证据表明该前提在**分布式设置下不成立**：

```text
checked_successor 是 **local** 原语
        ⇒ local round progression 无法产生 **global round agreement**
        ⇒ 诚实节点各自推进到不同 round
        ⇒ （结合 C-3/C-4/C-5）同一 block 上的票被分裂进多个 round bucket
        ⇒ 任何单一 round 都无法达到 quorum
        ⇒ 停滞
```

**关键结构性观察（本 ADR 的立论基础）**：

```text
vote        = round-local、ephemeral  → round 变化即**丢弃**（C-3/C-4）⇒ 发散后**永不**可合并
attestation = round-indexed、**单调累积**、无 target → 永不撤回 ⇒ 发散后**仍可**逐步合并
```

⇒ 需要一个**不依赖 round-local evidence** 的跨 round 同步权威。

---

## 2. Problem

- 诚实节点之间**没有任何可携带、可验证的「round 已失败」公共事实**（C-9/C-10 明确不引入此类证书）；
- 因而严重依赖「所有验证人同时在线且传播及时」——而 7/7 恰好满足（PHASE 5 中 pacemaker 从未触发），
  **该路径从未被正向验证**；
- 一旦出现缺席/延迟（6/7、5/7），round 发散 ⇒ 票分裂 ⇒ **停滞**，且停滞时长与 step 吞吐成反比（E5）。

**问题陈述**：在保持既有 BFT safety 假设与全部冻结语义不变的前提下，如何为 round 推进提供
**全局可验证的同步权威**，而不使其成为 QC / finality / lock override / vote 等价物？

---

## 3. Decision（**设计状态 = FROZEN**；实现状态 = NOT AUTHORIZED / FUTURE；每项标注状态）

### RC-1 — 引入 `RoundChangeCertificate`（round-transition authority）

```text
RoundChangeCertificate {
    validator_set_id : [u8;32]     // = genesis_hash（与 ADR-0038 F-11 同构口径）
    height           : u64
    from_round       : u64
    evidence[]       : { validator_id: [u8;32], signature: [u8;64] }   // ValidatorId 升序、无重复
}

to_round := from_round + 1          // 【派生】不编码 / 不签名 / 不由发送方提供
```

- 语义：`≥ ceil(2T/3)` 权重对 `(height, from_round)` 的 **Abandon Attestation** 聚合。
- **`to_round` MUST 由 `from_round` 派生**（见 §6）。
- **MUST NOT** 允许 `to_round > from_round + 1`（禁止任意 round skipping）。
- 状态：**设计已冻结 / FUTURE IMPLEMENTATION（未授权实施）**

> **术语校正（§24）**：本对象**不得**被称为「round certificate」（过泛）、「timeout QC」「mini QC」
> （暗示其为 QC —— 见 §7 的形式证明）、「finality certificate」（非 finality 证据）、
> 「lock certificate」（无 lock 权威）。正确名称为 **RoundChangeCertificate**，其中每一项签名为
> **Abandon Attestation**。

### RC-2 — `to_round` 派生规则（唯一）

```text
to_round := checked_successor(from_round) = from_round + 1
```
- MUST 使用**既有轮次后继语义**（`checked_successor`，C-6）；**MUST NOT** 引入替代的 round 算术原语。
- MUST NOT 允许发送方提供 `to_round`（无论签名与否）。
- 状态：**设计已冻结**（实现未授权）

### RC-3 — 阈值 `Q = ceil(2T/3)`（与 QC 同口径）

- 形成证书需要 `total voting weight >= ceil(2T/3)`。
- 性质：主要为 **liveness / anti-DoS / availability-alignment** 规则（形式论证见 §8）。
- **证书形成 ≠ QC 形成 ≠ finality**。
- 状态：**设计已冻结**（实现未授权）

### RC-4 — 采用 **S1** attestation 语义（纯本地观测，**不含弃权承诺**）

```text
Abandon(chain_id, height, from_round)
语义： "At height `height`, this validator's pacemaker timer for round `from_round`
        expired, and the validator is leaving round `from_round`."
```
- **MUST NOT** 含「我承诺此后不再在 round R 投票」一类含义。
- **MUST NOT** 引入 S2（弃权承诺）语义。
- **S1 不产生任何新增 safety-journal 义务**（论证见 §10.2）。
- 状态：**设计已冻结**（实现未授权）

### RC-5 — 独立签名域（**ALLOCATED = `0x10`**）

```text
A dedicated DomainId is REQUIRED.
ValidatorVote domain MUST NOT be reused.
Reserved 0x08+ values MUST NOT be silently allocated.
The DomainId assignment is an independent Domain Registry Amendment blocker.
```
- 状态：**RESOLVED** —— `DomainId::RoundChangeCertificate = 0x10` 已由 Owner 批准分配（PHASE 6H-B2；分配规则 = ADR-0069（FROZEN）；登记 = ADR-0067 §0.6 / ADR-0005；代码已实现 registry-level）。原「BLOCKED / REQUIRES SEPARATE ADR」为历史状态，见 §28。

### RC-6 — 非耦合边界（证书不得成为 QC / finality / lock override / vote 等价物）

见 §7（形式证明）与 §9（MUST / MUST NOT 清单）。状态：**设计已冻结（协议约束，未实现）**

### RC-7 — 计时器语义：应用证书后 **ARM 新 timer**

见 §11。既有 timer start/reset 语义**保持不变**。状态：**设计已冻结**（实现未授权）

---

## 4. Certificate Semantics

### 4.1 Abandon Attestation（签名陈述）

- **陈述内容**：`Abandon(chain_id, height, from_round)`。
- **语义**：**纯本地 timeout 观测** —— 该验证人在 `(height, from_round)` 的 pacemaker 计时器到期，
  因此正在离开 `from_round`。
- **语义唯一性（关键）**：对任意给定 `(height, from_round)`，**只存在一个可能的规范陈述** ⇒
  一个诚实验证人**结构上不可能**对同一 `(height, from_round)` 产生两份**不同**签名
  ⇒ **不存在 equivocation 面**。
- **MUST NOT** 表达：对未来的投票承诺、对某 block 的承诺、lock 相关授权、finality 相关断言。

### 4.2 字段判定（必要 / 充分 / 签名 / canonical / Byzantine / 冲突 / 持久化 / 防重放）

| 字段 | 必要 | 充分 | 签名 | 进 canonical bytes | Byzantine 可否操纵 | 可否冲突解释 | 需持久化 | 防重放作用 |
|---|---|---|---|---|---|---|---|---|
| `validator_set_id` | ✅ | 否（需 height/from_round） | ✅ MUST | ✅ 32B | ❌ | ❌ | ❌ | 阻止跨验证人集合重放 |
| `height` | ✅ | | ✅ MUST | ✅ 8B LE | ❌ | ❌ | ❌ | 阻止跨高度重放 |
| `from_round` | ✅ | | ✅ MUST | ✅ 8B LE | ❌ | ❌ | ❌ | 阻止跨 round 重放 |
| `to_round` | ❌ **不必要且危险** | — | ❌ MUST NOT | ❌ MUST NOT | — | — | ❌ | — |
| `evidence[]` | ✅ | ✅（配合阈值） | 每项含签名 | ✅ | 仅限自身 | 需 canonical 排序 + 去重 | ❌ | 逐项由域 + chain + height + round 保护 |
| `chain_id` | ✅ | | 由**框架字段**承载（与 Vote/Block 同构；**不重复进 payload**） | 框架 | ❌ | ❌ | ❌ | 阻止跨链重放 |

### 4.3 与 QC 的语义分离（MUST 保持）

```text
RoundChangeCertificate formation
        !=
PrecommitQC formation
        !=
Finality
```

---

## 5. Canonical Encoding

### 5.1 签名陈述编码（复用既有签名框架）

```text
signed_bytes =
      algorithm_id(1B)
    ‖ domain_id(1B)              // 需**专用** DomainId = 0x10（分配规则 = ADR-0069；见 §28）
    ‖ chain_id(8B LE)
    ‖ payload_length(4B LE)      // = 16
    ‖ payload

payload =
      height(8B LE)
    ‖ from_round(8B LE)
```

- 字段顺序**固定**，禁止重排（ADR-0005 / ADR-0009 体制）。
- `payload_length` **精确 = 16**；**MUST 拒绝**任何 trailing bytes / 截断 / 超长。
- **MUST NOT** 包含 `to_round`、`target`、`vote_type`、`source_block_hash`、`timestamp`。

### 5.2 证书容器编码（**FUTURE IMPLEMENTATION / 需独立 canonical 规格**）

```text
certificate_bytes =
      validator_set_id(32B)
    ‖ height(8B LE)
    ‖ from_round(8B LE)
    ‖ evidence_count(2B LE)          // 上限 = 21（数值由 ADR-0070 携带）
    ‖ evidence[0..n]                 // 每项 = validator_id(32B) ‖ signature(64B) = 96B 定长
```

- evidence **MUST** 按 `validator_id` 字节**升序**（与 ADR-0038 F-12 同纪律）。
- **MUST** 拒绝重复 `validator_id`。
- **MUST** 拒绝 `evidence_count` 与实际长度不一致、非精确长度、trailing bytes。
- 本容器的**权威 canonical 规格**由**独立**的 serialization ADR（**ADR-0070**）携带（沿用 ADR-0041 先例）。
  状态：**DRAFTED = ADR-0070**（设计已获 Owner 批准；ADR-0070 本身仍 DRAFT）。
- **已批准的数值上界**（由 **ADR-0070** 规格；本 ADR **不重新定义**，仅引用）：
  `MAX_EVIDENCE_COUNT = 21`；`MAX_CERTIFICATE_BYTES = 2066`（`= 50 + 96 × 21`）。

### 5.3 绑定清单（MUST）

| 绑定 | 承载位置 | 状态 |
|---|---|---|
| chain binding | `chain_id`（框架，签名内） | MUST |
| height binding | payload `height` | MUST |
| round binding | payload `from_round` | MUST |
| validator binding | `validator_id = SHA-256(consensus_public_key)`（V-5 ② 同构） | MUST |
| 独立签名域 | `domain_id` | MUST（**专用域 = `0x10`**；分配规则 = ADR-0069；状态同步见 §28） |
| 算法绑定 | `algorithm_id`（当前 `Ed25519 = 0x01`，ADR-0012） | MUST |

---

## 6. Validation Rules（确定性）

### 6.1 ACCEPT 当且仅当**全部**成立

```text
structure valid
AND exact length valid（无 trailing / 无截断）
AND validator_set_id matches expected set
AND height is valid
AND from_round is valid
AND evidence is canonically ordered（validator_id 升序）
AND no duplicate validator_id exists
AND every signature independently verifies（V-5 同构五步）
AND signatures use the dedicated domain
AND total voting weight >= ceil(2T/3)
AND derived to_round > local_round
AND all size / count limits are satisfied
```

### 6.2 REJECT 条件（任一即拒；拒因须可区分、可审计）

```text
malformed encoding
trailing bytes
wrong validator_set_id
wrong height
wrong chain
wrong domain
invalid signature
duplicate validator
non-canonical ordering
insufficient quorum
oversized evidence（count 或字节数超限）
to_round <= local_round        （→ 无 round 回退）
round overflow                 （→ 复用 checked_successor 的拒绝语义）
```

### 6.3 确定性要求

- 验证**必须**是纯函数：同输入同结论；无时钟、无随机、无 I/O、无本地策略分支。
- **MUST** 使用 `checked_successor` 语义派生 `to_round`；**MUST NOT** 引入替代 round 算术。
- 结果**MUST** 以可审计的 transition 结果表达（沿用既有 `Applied / Ignored / Rejected` 纪律：
  `Ignored`/`Rejected` ⇒ **state 与 context 均不变**）。

---

## 7. Round Transition Rule + 非耦合形式证明

### 7.1 转移规则

```text
收到合法 RoundChangeCertificate（from_round ∈ {local_round 允许范围}）
        ⇒ 本节点 local_round 由 from_round 前进到 derived to_round = from_round + 1
        ⇒ ARM 新 timer（见 §11）
        ⇒ MUST NOT unlock / MUST NOT override lock / MUST NOT 影响 finality
```

### 7.2 形式证明：`RoundChangeCertificate != QC`（MUST 恒真）

`verify_qc`（`crates/consensus/src/finality.rs`）依次要求：

```text
① target ∈ DAG                        // **区块承诺**
② validator_set_id == genesis_hash
③ evidence 按 validator_id 升序
④ 无重复 validator
⑤ 逐条 **重建 ValidatorVote{ round: ctx.round, height: ctx.height, target_block_hash: qc.target }**
   并以 **DomainId::ValidatorVote** 走 V-5 五步验签
⑥ 权重累计 >= quorum
```

Abandon Attestation **无 `target`**（① 不可满足）、**非 `ValidatorVote` 域**（⑤ 不可满足）
⇒ **结构性不可能**通过 `verify_qc`。**∎**

因而 `RoundChangeCertificate` **不能**：
成为 QC、贡献投票权重、满足 PrevoteQC、满足 PrecommitQC、改变 `finalized_reference`、
unlock 验证人、override lock、创建 block commitment。

---

## 8. Threshold 语义与形式论证（`Q = ceil(2T/3)`）

### 8.1 形式论证：为何阈值**不**由 safety 要求

一个节点**今天已经可以**仅凭本地 timer 到期把 round 前进（零证据；ADR-0049 §3.2/§3.3；**LIV-5**
「Round may advance without QC」）。⇒ 证书**未授予**任何单节点不具备的权限 ⇒
**不存在依赖该阈值的安全性质**。

### 8.2 为何仍 MUST 取 `ceil(2T/3)`

1. **必须 > f**：否则 Byzantine（权重 ≤ `f = floor((T−1)/3)`）可独自制造协调性 round 变更 ⇒ griefing/DoS。
   本模型下 `f = 466_666 < Q = 933_334` ✅
2. **≥ 2T/3 提供「可用性对齐」**：证书**只在可达权重 ≥ 2T/3 时**可形成，与 QC 的可得性条件**一致**
   ⇒ **证书绝不能在 QC 不可行时制造虚假进展**。

### 8.3 各配置判定（7 验证人 / 等额权重）

| 配置 | 可达权重 | ≥ `Q = 933_334`? | **证书可形成?** | **finality 可用?** |
|---|---|---|---|---|
| **7/7** | 1_400_000 | ✅ | ✅ | ✅ |
| **6/7** | 1_200_000 | ✅ | ✅ | ✅（但 PHASE 5 实测 FLAKY） |
| **5/7** | 1_000_000 | ✅ | ✅ | ✅（但 PHASE 5 实测 0/6 —— 见 §12） |
| **4/7** | 800_000 | ❌ | ❌ | ❌ |

```text
certificate availability  与  finality availability  **是两个独立的命题**
```

### 8.4 一项量化活性优势

- QC 形成需：≥ `Q − f = T/3` 诚实票**在同一目标的同一 round**；
- 证书形成需：≥ `Q − f = T/3` 诚实 attestation**在同一 `(height, from_round)`**，且 attestation
  **单调累积、无 target** ⇒ **在存在发散时，证书形成条件严格弱于 QC 形成条件**。

### 8.5 MUST NOT 复用 QC 验签路径

证书 **MUST** 使用独立验证器 + 专用域 + 无 `target`；**MUST NOT** 复用 `verify_qc` / `assemble_qc` /
`QcRegistry::admit`。

---

## 9. Safety Invariants

### 9.1 MUST NOT（协议级硬约束）

```text
MUST NOT create a QC
MUST NOT create finality
MUST NOT contribute vote weight
MUST NOT enter VoteAccumulator
MUST NOT enter RoundEvidence
MUST NOT enter QcRegistry
MUST NOT call assemble_qc
MUST NOT pass through verify_qc as a QC
MUST NOT create or advance LockedState
MUST NOT unlock a lock
MUST NOT override an unrelated lock
MUST NOT change proposer selection
MUST NOT change ProposalRef
MUST NOT change ValidatorVote encoding
MUST NOT change quorum
---
MUST derive to_round（NOT carry it as a signed field）
MUST NOT allow arbitrary round jumps（MUST NOT allow to_round > from_round + 1）
MUST be domain separated（专用域）
MUST be height bound / round bound / chain bound / validator bound
MUST use canonical encoding
MUST deduplicate validators（validator_id 升序 + 无重复）
MUST enforce maximum evidence size（count + bytes）
MUST reject malformed / trailing bytes
MUST be rejected when derived to_round <= local_round（no round regression）
MUST re-ARM RoundTimer for the new round（MUST NOT inherit stale deadline）
MUST NOT be treated as justification for an unrelated branch
MUST NOT be required for, nor block, vote production
```

### 9.2 潜在意外耦合点（MUST 显式排除）

| # | 位置（只读引用） | MUST 保持 |
|---|---|---|
| 1 | `RoundEvidence::record/reset`（`integration.rs`） | 证书 evidence **MUST NOT** 进入 |
| 2 | `VoteAccumulator::record` / `process_vote`（`round.rs`） | **MUST NOT** 进入 / MUST NOT 贡献权重 |
| 3 | `RoundEvidence::assemble_qc`（`integration.rs`） | **MUST NOT** 可达 |
| 4 | `QcRegistry::admit`（`integration.rs`；bounded 64；仅 PrevoteQC） | **MUST NOT** admit 证书 |
| 5 | `verify_qc`（`finality.rs`） | **MUST NOT** 接受证书（§7.2 已证） |
| 6 | finality pipeline → `update_finalized_reference` | **MUST NOT** 可达 |
| 7 | `LockedState::lock`（F-7） | **MUST NOT** 由证书触发 |
| 8 | `LockedState::is_compatible` / lock override | **MUST NOT** 受影响 |
| 9 | `select_proposer`（`proposer.rs`） | **MUST NOT** 受影响（仅 `round` 变化） |
| 10 | `checked_successor`（`integration.rs`） | 必须是**唯一** round 转移原语 |
| 11 | `RoundTimer`（`runtime.rs`） | 应用证书后 **MUST ARM 新 timer** |
| 12 | `ValidatorActor::sign_vote` + vote safety journal | **MUST NOT** 触碰 |
| 13 | `BlockSafety` / block journal | **MUST NOT** 触碰 |

### 9.3 ADR-0053 兼容（MUST 保持；**无授权修订**）

```text
ADR-0053 L-9 and L-10 remain unchanged.

Round change MUST NOT unlock.
Higher round alone MUST NOT create lock override.
```

---

## 10. Journal Dependency

### 10.1 结论

```text
S1 creates no additional safety-journal obligation.
Journal dependency = NONE.
```
**本设计不要求修改任何 safety journal / block journal / journal lifecycle。**

### 10.2 论证

`Abandon(chain_id, height, from_round)` 在给定 `(height, from_round)` 下**只有一个可能的规范陈述**：
- 诚实验证人**不可能**对同一 `(height, from_round)` 产生两份**不同**签名 ⇒ **无 equivocation 面**；
- 防重放已由「专用域 + `chain_id` + `height` + `from_round` 全在签名范围内」提供；
- 重复签发**相同字节**为幂等，无一致性义务。

（**反例记录，未采用**：若采用 **S2 弃权承诺**语义，则「签过 `Abandon(H,R)` 后不得在 R 投票」
将成为新的本地义务，必须由 signer-owned journal 强制 —— 否则重启/双签会破坏「R 已死」声明的可靠性。
**本 ADR 明确不采用 S2。**）

---

## 11. Timer Semantics

当合法证书使节点由 `from_round` 前进到 `from_round + 1` 时，接收方 **MUST**：

```text
enter the new round
ARM a fresh timer for the new round
```

**MUST NOT**：

```text
inherit stale deadline
reuse expired timer
unlock local lock
alter proposer-selection algorithm
```

**既有 timer start / reset 语义保持不变**（ADR-0049 §3.3 / §3.4 / §3.4.1）。
进入 `(height, to_round)` 即启动该 round 自己的计时器；**绝不继承**上一 round 的剩余/已过期 deadline。

状态：**设计已冻结**（未来实现依赖 `runtime.rs` 的 `RoundTimer` 语义保持不变）。

---

## 12. Byzantine Analysis

| # | 情形 | 判定 | 原因 |
|---|---|---|---|
| 1 | 验证人**拒绝** attestation | **无工件产生**（不劣于现状） | 证书需 `Q − f = T/3` 诚实 attestation；与既有 quorum 前提**一致**，**非新增假设**。**本 ADR 不声称 Byzantine 不能拒发/扣留消息。** |
| 2 | **重复 evidence** | **REJECT** | duplicate `validator_id`（ADR-0038 F-12 同纪律） |
| 3 | **畸形 evidence** | **REJECT** | 长度/结构/升序/trailing/计数一致性与上限校验失败 |
| 4 | **无效签名** | **REJECT** | V-5 同构五步验签失败（membership / identity / domain / hash / verify_strict） |
| 5 | **跨链重放** | **REJECT** | `chain_id` 在签名范围内 |
| 6 | **跨高度重放** | **REJECT** | `height` 在签名范围内 + 证书 `height` 绑定 |
| 7 | **跨 round 重放** | **REJECT** | `from_round` 在签名范围内；且 `to_round <= local_round` ⇒ 拒绝（无回退） |
| 8 | **伪造未来 `to_round`** | **结构上不可能** | `to_round` **派生**（`from_round + 1`），**不签名、不携带** ⇒ Byzantine cannot sign arbitrary future to_round |
| 9 | **矛盾证书** | **语义等价 ⇒ 无害** | 同一 `(height, from_round)` 的一切有效证书**语义等价**（`to_round` 唯一）；接受只依赖 evidence 独立签名 + 阈值 |
| 10 | **证书洪泛** | **限流 / 拒绝** | 见 §14（Max Size、evidence count 上限、双重去重、flood/rate protection）—— **当前网络层缺成熟原语，见 §15** |

**额外（review 发现）**：Byzantine **预签**「未来 round」的 attestation 无害 —— 形成证书仍需该
`(height, from_round)` 上 ≥ `Q − f = T/3` **诚实** attestation，而诚实者**仅在本地计时器对
`(height, from_round)` 到期后才签**（本地确定性规则）⇒ 预签收益被 `f` 界定。

---

## 13. Partition Analysis

| 场景 | A 侧 | B 侧 | 证书 | finality | 说明 |
|---|---|---|---|---|---|
| **7/7** | 1_400_000 | — | ✅ 可形成 | ✅ | 无分区 |
| **6/7 + 1/7** | 1_200_000 | 200_000 | ✅ | ✅ | 少数侧停滞 |
| **5/7 + 2/7** | 1_000_000 | 400_000 | ✅（多数侧） | ✅（多数侧） | 多数侧可 finality；**少数侧不可** |
| **4/7 + 3/7** | 800_000 | 600_000 | ❌ **两侧皆不可** | ❌ **两侧皆不可** | 双侧停滞（与现状一致） |

- **少数侧不能凭证书推进**到与多数侧冲突的状态（无法达 `Q`）。
- **愈合后**：多数侧证书/QC/区块传播至少数侧；少数侧经**证书链逐 +1** 追赶 ⇒ 收敛。
- **延迟证书不能造成 round 回退**（`to_round <= local_round ⇒ REJECT`）。
- **保持既有 BFT safety 假设**：证书**不参与 finality**；finality 仍由 `PrecommitQC` + **quorum 交集**
  （2/3 + 2/3 > 1，`f < T/3`）保证 ⇒ **分区不产生 conflicting finality**（ADR-0038 / ADR-0049 §3.11 保持）。
- **不声明** 5/7 自动产生 finality（见 §8.3、§16）。

---

## 14. Restart Analysis

| 项 | 结论 |
|---|---|
| 证书是否持久化 | **ephemeral**（**不要求持久化**） |
| S1 下是否需 safety-journal 持久化 | **不需要**（见 §10） |
| 重启丢失证书的影响 | **仅影响收敛速度**（liveness），**绝不影响 safety** |
| 重启后能否重新获取 | **可以**：向 peer **按需重新获取**（on-demand；策略见 D-1） |
| 证书能否把本地 round 移回**旧** round | **不能**（`to_round <= local_round ⇒ REJECT`） |
| 重启到**更新** round | 不受影响 |
| 重启到**旧** round | 可被收到的证书链向前拉动（liveness 改善） |

**本 ADR 不修改 journal lifecycle / 持久化实现。**

---

## 15. Migration

未来实现 **MUST** 具备（**FUTURE IMPLEMENTATION**；**现不实施**）：

```text
new message type
protocol version / capability negotiation
unknown-message fail-closed handling
maximum message size
maximum evidence count
validator deduplication
certificate deduplication
flood / rate protection
```

### 15.1 混合版本行为（显式陈述）

```text
MIXED-VERSION OPERATION IS SAFE BUT PROVIDES NO O2 LIVENESS BENEFIT.
```

- **安全**：未升级节点不产生/不消费证书，但其 Vote 仍被接受；升级节点的证书路径不影响既有语义。
- **活性**：升级节点在等待一个**永远不会形成**的证书 ⇒ **混合期无活性收益**。

```text
O2 liveness benefit requires compatible validator participation.
```

- **MUST NOT** 要求旧节点拒绝正常 Vote（那会**劣化**活性）。

### 15.2 兼容性

- **不改** `ProposalRef`（ADR-0041 64B 保持）· **不改** `ValidatorVote`（185B 保持）⇒ 既有工件/编码完全兼容。
- **无链上状态迁移**（证书不入 consensus state）⇒ **无 genesis 影响**。

---

## 16. Network Dependencies

```text
Current network is based on std::net::TcpStream.
libp2p / GossipSub / Kademlia / Noise / QUIC are not currently adopted.
```

⇒ **peer scoring / rate limiting 当前不是可用的成熟网络原语**。
这是**实施前置条件 / 补偿控制要求**（见 §14 第 10 项、§21 D-7）。**本 ADR 不修改网络实现。**

---

## 17. Domain Registry Dependency（**RESOLVED —— 见 §28**）

```text
RoundChangeCertificate requires a dedicated signing domain.
ValidatorVote domain MUST NOT be reused.
Reserved 0x08+ values MUST NOT be silently allocated.
Existing 0x07 registry conflict remains an independent blocker.
                                        [HISTORICAL — RESOLVED; see §28]
```

理由：
- `ValidatorVote` 域的 payload 结构（含 `target` / `vote_type`）与语义不同；复用会违反
  「一域一用途」契约（ADR-0005 / ADR-0009）；
- **`verify_qc` 会把 evidence 重建为 `ValidatorVote`**（§7.2 ⑤）⇒ 若 attestation 使用同一域，
  存在被**误构造成 vote 形态**的域混淆风险 ⇒ **必须使用专用域**；
- ADR-0005（FROZEN）注册表将 `0x08+` 标为 **Reserved / 未注册 ⇒ 必须拒绝**，并明确
  「不得分配 `0x08` / `0x09` 等」。

**既有冲突在本 ADR 中保持原状（不解不并）** —— *以下为 PHASE 6C 时点的历史快照*：

```text
ADR-0005         : 0x07 = Contribution
ADR-0050 / code  : Proposer = 0x07
                                        [HISTORICAL — RESOLVED; see §28]
```

```text
A separate Domain Registry Amendment ADR is required.
                    [HISTORICAL — COMPLETED: ADR-0069 (FROZEN) + ADR-0067 §0.6 +
                     ADR-0005 registry sync (PHASE 6H-D); see §28]
```

**本 ADR 本身不分配任何 DomainId、不修改 Domain Registry**（`0x10` 的分配由 ADR-0069 承载、
由 ADR-0067 §0.6 / ADR-0005 登记；见 §28）。

---

## 18. ADR-0049 Amendment Map（**未来**修订映射；本阶段**不编辑** ADR-0049）

> **状态同步（PHASE 6H-T2）**：
> · `§3.13` → **COMPLETED BY ADR-0072（FROZEN）**（reason 4 的语义效果部分替代；reason 1/2/3/5 保持）
> · `§3.4.1` → **LIMITED SEMANTIC EFFECT PROVIDED BY ADR-0072（FROZEN）**（C-2 = OPTION (b)：仅
>   `valid RoundChangeCertificate` = round-change authority 前提；不改 timer semantics / 其它 transition rule）
> · `§5` / `§6 / LIV-12` / `§9` / `§11` / `§12` → **IMPLEMENTATION / DOCUMENTATION / VERIFICATION FUTURE WORK**
>   （不属本次 Freeze 前置；见 §25 P-5 状态同步）
> · `§3.3` / `§3.4` → **保持不变的既有 timer 语义**
> · **ADR-0049 本体逐字节未编辑**（SHA256 = `C4BF7492…D0BD8802E`）。

| ADR-0049 位置 | 未来需要的动作 |
|---|---|
| **§3.13** | 重新审视「NO TimeoutCertificate / RoundChangeCertificate」的冻结陈述：PHASE 5 经验性活性证据要求重新评估（其 5 条理由中「local round progression 已足够」已被否证；「timeout 是 local event」仍成立，但**证书是 timeout 的聚合证据、非 timeout 本身**；「finality 必须依赖 valid PrecommitQC」**保持**） |
| **§3.4.1** | 新增「valid round-change authority」语义：`advance by exactly +1` → `arm new timer` → `do not unlock` |
| **§5** | 更新活性假设，加入：`>= ceil(2T/3) reachable validator weight` **且** `>= T/3 honest timely attestation weight` |
| **§6 / LIV-12** | 澄清：`local round progression != global round agreement`；跨 round 同步可能需要可验证权威 |
| **LIV additions** | 新增证书专用不变式（证书 ≠ QC / 不产生 finality / 不解锁 / `to_round` 派生 / 阈值 `ceil(2T/3)` / evidence 去重与上限） |
| **§9** | 将 `RoundChangeCertificate` 登记为**未来实现项** |
| **§11** | 新增未来验证要求（结构/域/升序/去重/阈值/无 target/不产生 QC/不 finality/不解锁） |
| **§12** | 重新评估「NO timeout certificate 保持协议简洁」的复杂度/成本与活性收益对比 |
| **§3.3 / §3.4** | **保持不变**（应用证书后 ARM 新 timer，不继承 stale deadline） |

```text
ADR-0049 IS NOT AMENDED DURING PHASE 6C.
```

---

## 19. ADR-0053 Compatibility（**无授权修订**）

本 ADR **显式保持** ADR-0053 下列条款不变：

```text
L-1   LockedState is validator-local（远程 Vote 不因本地 lock 被拒）
L-3   lock 获取仅来自 valid PrecommitQC（PrevoteQC 不获取 lock）
L-4   lock 兼容性使用完整传递 DAG ancestry
L-5   JustifiedDescendant = same-or-ancestor（V1 不要求额外 PrevoteQC）
L-6   PrevoteQC MUST NOT acquire/advance/unlock/override/establish finality
L-7   PrecommitQC 不自动授予 unrelated-lock override
L-8   same/descendant ⇒ ALLOW；unrelated ⇒ valid-but-inapplicable（≠ invalid，证据保留）
L-9   V1 defines no unrelated higher-round lock override
L-10  Timeout / Round Change / Proposer Change MUST NOT unlock
L-12  lock enforcement = Non-Scope（仍 DEFERRED）
```

```text
higher round != lock override
round change != unlock
```

**No amendment to ADR-0053 is authorized.**

---

## 20. Liveness Claim（**故意限定的强度**）

> **Under the existing BFT assumptions and eventual-synchrony assumptions, if at least `ceil(2T/3)`
> validator weight is reachable and at least `T/3` honest validator weight timely emits timeout
> attestations for each intervening round, a valid `RoundChangeCertificate` provides a globally
> verifiable, monotonically accumulating, bounded (`+1`) round-transition authority that prevents
> indefinite independent round divergence among honest validators.**

随即必须说明：

```text
This does NOT guarantee finality.
Finality still requires a valid PrecommitQC.
```

并必须声明继承的安全限制：

```text
Local lock enforcement remains deferred under ADR-0049 §3.10 / ADR-0053 L-12.
This ADR does not claim that the existing lock-enforcement gap has been solved.
```

**本 ADR MUST NOT 声称「O2 guarantees liveness」。**

### 20.1 子句可辩护性核对

| 子句 | 成立 | 依据 |
|---|---|---|
| `>= T/3` honest | ✅ | `Q − f = 2T/3 − T/3 = T/3`（即使 Byzantine 全部拒签亦可达阈值） |
| for each intervening round | ✅ | `to_round = from_round + 1` ⇒ k 轮落后需 k 份证书；诚实者每离开一轮**恰好**产生一份 attestation |
| monotonically accumulating | ✅ | S1 为纯观测、永不撤回、按 round 索引 ⇒ 累积 |
| bounded (`+1`) | ✅ | 派生规则 ⇒ 不可能跳跃 ⇒ **不绕过 ADR-0053 L-9** |
| prevents indefinite **round** divergence | ✅（**仅对 round 变量**） | 未保证 finality |
| 不保证 finality | ✅（正确限制） | round 同步后仍需提案 + 同 round ≥ 2T/3 票 |

---

## 21. Non-Goals

```text
NOT:
- a consensus redesign
- a new QC
- a finality mechanism
- a lock override mechanism
- a proposer-selection change
- a ProposalRef change
- a ValidatorVote change
- a quorum change
- a journal redesign
- a genesis change
- an Akash deployment change
- an A17 sync fix
- an upgrade compatibility fix
- a DomainId registry resolution
```

附加边界：本 ADR 亦**不**处理 slashing / equivocation detection / validator rotation / epoch /
网络栈替换 / 状态同步（A17 / ADR-0062 域）。

---

## 22. Open Questions（**未来决策，非实施**）

```text
D-1  attestation retention / gossip strategy（有界窗口 K vs on-demand 索取）
D-2  evidence maximum count / maximum byte size
D-3  bounded in-memory certificate storage policy（是否进入任何 bounded 结构；对标 QcRegistry=64）
D-4  interaction boundary with ADR-0062（sync-target-semantics）
D-5  ✅ RESOLVED —— `0x10` 已正式分配（ADR-0069 FROZEN；ADR-0067 §0.6；ADR-0005 已同步）；0x07 冲突已解决（见 §28）
D-6  protocol version / capability negotiation details
D-7  network flood / rate-limit mechanism（当前无成熟原语）
```

```text
These MUST NOT be silently decided by implementation.
```

---

## 23. Consequences

**正面**
- 为 round 推进提供**全局可验证、单调累积、有界（+1）**的同步权威，直接针对 PHASE 5 观测到的
  `round divergence → vote 分裂 → 停滞` 病理；
- 不引入新的 safety 权威（§7/§8/§9）；不改任何既有工件编码（ADR-0041 / ADR-0038 F-2 均不变）；
- 与 ADR-0053 L-9/L-10 完全兼容（不构成 lock override）；
- 与 journal lifecycle **零耦合**（S1 语义，§10）。

**成本 / 风险**
- **协议变更**：必须修订 ADR-0049 §3.13（FROZEN）—— 需 Owner 批准的新 ADR（本文件）；
  【**已提供**：ADR-0072（FROZEN）；ADR-0049 本体未编辑。见 §28】
- **外部依赖**：① Domain Registry Amendment（**独立 blocker**）【**已解决**：ADR-0069（FROZEN）+
  ADR-0067 §0.6 + ADR-0005 同步（PHASE 6H-D）；见 §28】② 网络层 flood/rate 控制缺口（§16）；
- **实现复杂度**：新签名工件 + 新 canonical 规格 + 新消息类型 + 新 transition 事件；
- **迁移**：混合版本**无活性收益**（§15.1）⇒ 需兼容验证人参与；
- **残余限制**：lock enforcement 仍 deferred（§20）⇒ 不得宣称已完成 safety proof。

---

## 24. Validation Plan（**FUTURE**；本阶段不执行）

| 层 | 验证项 |
|---|---|
| 纯函数 | 编码/解码精确长度、trailing 拒绝、升序、去重、计数上限、域分离、chain/height/round 绑定 |
| 纯函数 | **非耦合负例**：证书**绝不**产生 QC / finality / lock / 进入 `RoundEvidence` / `VoteAccumulator` / `QcRegistry` |
| 集成 | 应用证书 ⇒ `round` 恰好 +1；`RoundEvidence` 仍 reset；`FinalityState` 保持；`Ignored/Rejected` ⇒ state/context 不变 |
| 集成 | `to_round <= local_round` ⇒ REJECT（无回退）；round overflow ⇒ 复用既有拒绝语义 |
| 集成 | **ADR-0053 负例**：证书不解锁、不 override unrelated lock |
| 7 节点（沿用 A30 结构） | **5/7 停滞必须在窗口内终结**；6/7 尾延迟有界；**7/7 行为不变**；**4/7 仍无 finality** |
| 网络 | unknown message ⇒ fail-closed；超长/超计数 ⇒ 拒绝；洪泛 ⇒ 限流生效 |
| 恢复 | 重启节点可从 peer 重新获取证书；证书不能使 round 回退 |

---

## 25. Implementation Prerequisites（**全部为阻塞项，未满足前不得实施**）

```text
P-1  Owner approval of THIS ADR（解除 DRAFT → FROZEN）
P-2  Domain Registry Amendment ADR（专用 DomainId 分配）—— 独立 blocker
P-3  本证书容器的 canonical serialization 规格 ADR（ADR-0041 先例）
P-4  网络层 flood / rate-limit 能力（或经 Owner 批准的补偿控制）
P-5  ADR-0049 §3.13 / §3.4.1 / §5 / §6 / §9 / §11 / §12 的正式修订 ADR
P-6  D-1..D-7 全部闭合，或经 Owner 明确接受为受控风险
P-7  Consensus Liveness blocker 的整体解除由 Owner 单独裁决
```

**P-5 状态同步（PHASE 6H-T2；Owner C-1 = APPROVED OPTION (a)）**：

```text
P-5 = SATISFIED FOR FREEZE PURPOSES

ADR-0072 (FROZEN) now independently carries the bounded amendment for
ADR-0049 §3.13 reason 4 and the limited §3.4.1 round-change-authority
semantic effect.

The remaining references to ADR-0049 §5, §6/LIV-12, §9, §11 and §12 are
implementation-stage documentation / mapping / verification prerequisites
and do not require a separate amendment ADR for this Freeze.
Their implementation remains unauthorized and future-gated.
```

（`P-5 = satisfied for FREEZE PURPOSES` **≠** implementation complete。）

**状态标注（PHASE 6H-T2 同步）**：
- 本 ADR 全文：**FROZEN**（2026-10-07，Owner 授权 PHASE 6H-T2）
- 证书实现：**FUTURE IMPLEMENTATION（未授权）** —— 保持不变
- DomainId 分配：**ALLOCATED = `0x10`**（ADR-0069 FROZEN；ADR-0067 §0.6；ADR-0005 已同步；代码已实现 registry-level）
- 载体 canonical 规格：**DRAFTED = ADR-0070**（设计已获 Owner 批准；ADR-0070 本身仍 DRAFT）
- 网络 flood/rate：**DESIGN ONLY（ADR-0071 §9）**；绝对阈值 = OPEN
- ADR-0049 修订：**PROVIDED BY ADR-0072（FROZEN）** —— §3.13 reason 4 + §3.4.1 有限附随语义效果；ADR-0049 本体未编辑
- 历史「BLOCKED / REQUIRES SEPARATE ADR」表述为**历史状态**，见 §28

---

## 26. References

```text
docs/adr/ADR-0005-domain-separation.md                 （Domain Registry；0x07 = Contribution，FROZEN）
docs/adr/ADR-0009-signature-coverage.md                （签名字段级覆盖原则）
docs/adr/ADR-0012-cryptographic-algorithm-registry.md  （AlgorithmId::Ed25519 = 0x01）
docs/adr/ADR-0033-consensus-architecture-v1.md         （C-5 ≥2/3 quorum）
docs/adr/ADR-0034-validator-set-vote-verification-v1.md（V-4/V-5 verify_vote）
docs/adr/ADR-0037-bft-round-architecture-v1.md         （B-1/B-3/B-5）
docs/adr/ADR-0038-finality-architecture-v1.md          （F-1..F-18；F-2/F-3/F-4/F-11/F-12）
docs/adr/ADR-0041-proposalref-canonical-serialization.md（64B ProposalRef，FROZEN）
docs/adr/ADR-0049-liveness-pacemaker-v1.md             （§3.3/§3.4/§3.4.1/§3.5/§3.13/§5/§6/§9/§11/§12）
docs/adr/ADR-0050-proposer-selection-v1.md             （确定性 proposer selection，FROZEN）
docs/adr/ADR-0053-lock-justification-override-v1.md    （L-1..L-12，FROZEN）
docs/protocols/consensus-spec-v1.md                    （§5 Liveness Assumptions = OPEN）
crates/consensus/src/round.rs                          （ProposalRef / RoundState / checked_successor）
crates/consensus/src/vote.rs                           （ValidatorVote / canonical_vote_payload）
crates/consensus/src/integration.rs                    （RoundEvidence / QcRegistry / transition）
crates/consensus/src/finality.rs                       （QcContext / verify_qc / FinalityState）
crates/consensus/src/proposer.rs                       （select_proposer）
crates/crypto/src/domain.rs                            （DomainId / AlgorithmId / build_signed_bytes）
crates/node/src/runtime.rs                             （RoundTimer / round_timeout_window_ticks）
```

---

## 27. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-06 | **ADR-0066 初稿（DRAFT — NOT FROZEN）**：RoundChangeCertificate / Cross-Round Synchronization Authority V1。基于 PHASE 5（E1–E5 证据）→ PHASE 6（O1–O4 比较）→ PHASE 6B（O2 形式规格审查）→ PHASE 6C（本草案）。仅文档；**未修改任何既有 ADR / consensus-spec / Rust 源码 / 测试**；**未分配 DomainId** | Owner 授权 PHASE 6C — ADR DRAFT ONLY |
| 2026-10-07 | **PHASE 6H-T2 — Owner Decision + Minimal Documentation Correction + FREEZE EXECUTION**：Status `DRAFT — NOT FROZEN` → **FROZEN**。Owner 决策：**C-1 = OPTION (a)**（§25 **P-5 = SATISFIED FOR FREEZE PURPOSES**：§3.13/§3.4.1 由 ADR-0072 承接；§5/§6/§9/§11/§12 属实现阶段文档/映射/验证前置，无需独立 amendment ADR）与 **C-2 = OPTION (a)**（最小状态同步）。同步项：§1.2 C-13（0x07 冲突 → RESOLVED）· §3 段头及各 RC 状态（DRAFT → **设计已冻结 / 实现未授权**）· §RC-5（BLOCKED → **ALLOCATED = `0x10`**）· §5.1 / §5.3（专用域 = `0x10`）· §5.2（引用 **ADR-0070** 的 21 / 2066）· §17（独立 blocker → RESOLVED）· §18（状态同步注记）· §22 D-5（RESOLVED）· §23（协议变更已提供 / 外部依赖已解决）· §25（P-5 状态同步 + 状态标注同步）· 新增 **§28 Status Synchronization Note**。**未改变任何规范设计**（serialization / domain semantics / acceptance rules / quorum / evidence bounds / round transition / safety boundary 均不变）；**未修改 ADR-0049 / ADR-0072 / ADR-0067 / ADR-0068 / ADR-0069 / ADR-0070 / ADR-0071 / ADR-0005 / ADR-0062**；**未**实现任何代码；**未**分配 MessageType；**未**改变 liveness / Genesis / Akash / deployment | Owner 授权 PHASE 6H-T2 —— ADR-0066 OWNER DECISION + MINIMAL DOCUMENTATION CORRECTION + FREEZE |

---

## 28. Status Synchronization Note（PHASE 6H-T2，2026-10-07）

> 本节由 **PHASE 6H-T2**（Owner 授权 C-2 = OPTION (a)）新增，用于同步本 ADR 中【已成为历史】的
> 状态陈述。**历史文本未被删除**；本节仅记录状态迁移（对标 ADR-0067 §0.7 的做法）。

```text
Historical status note:
The earlier 0x07 namespace conflict has been resolved by the subsequent
domain-governance amendments. DomainId::RoundChangeCertificate is formally
allocated as 0x10 under ADR-0069, with the registry state synchronized by the
subsequent governance record. The historical BLOCKED / REQUIRES SEPARATE ADR
wording in this document is therefore superseded as a status statement only;
it does not alter the normative RoundChangeCertificate design defined by this ADR.
```

**逐项状态映射**：

| # | 位置（原文保留） | 历史状态 | 当前状态 |
|---|---|---|---|
| 1 | §1.2 C-13 | 「注册表冲突**未解**」 | **RESOLVED** —— PHASE 6G-A/C（`0x07 = Contribution` 保留；Proposer → `HashDomain`，ADR-0068 FROZEN） |
| 2 | §3 RC-5 标题 / 状态 | 「REQUIRES SEPARATE ADR」/「BLOCKED」 | **RESOLVED** —— `0x10` 已分配（PHASE 6H-B2）；规则 = ADR-0069（FROZEN）；登记 = ADR-0067 §0.6；ADR-0005 已同步（PHASE 6H-D） |
| 3 | §5.1 / §5.3 | 「本 ADR 不分配」 | **已同步** —— `DomainId::RoundChangeCertificate = 0x10` |
| 4 | §5.2 | 「上限见 D-2（Open Question）」 | **RESOLVED** —— 数值由 **ADR-0070** 携带：21 / 2066 |
| 5 | §17 | 「Existing 0x07 registry conflict remains an independent blocker」/「A separate Domain Registry Amendment ADR is required」 | **RESOLVED** —— ADR-0069 + ADR-0067 §0.6 + ADR-0005 |
| 6 | §22 D-5 | 「须先处理或显式共存 0x07 冲突」 | **RESOLVED** |
| 7 | §25 P-2 状态标注 | 「DomainId 分配：BLOCKED / REQUIRES SEPARATE ADR」 | **已同步** —— ALLOCATED = `0x10` |
| 8 | §25 状态标注 | 「ADR-0049 修订：REQUIRES SEPARATE ADR」 | **PROVIDED BY ADR-0072（FROZEN）** —— §3.13 reason 4 + §3.4.1 有限附随语义效果；ADR-0049 本体未编辑 |
| 9 | §25 P-5 | 「ADR-0049 … §5/§6/§9/§11/§12 的正式修订 ADR」 | **P-5 = SATISFIED FOR FREEZE PURPOSES**（Owner C-1 = (a)） |
| 10 | §3 段头 / 各 RC 状态标记 | 「全部为 DRAFT」/「状态：DRAFT」 | **设计状态 = FROZEN；实现状态 = NOT AUTHORIZED / FUTURE** |

```text
本注记仅同步【状态/来源】；不改 RoundChangeCertificate 的规范设计
（serialization / domain semantics / acceptance rules / quorum / evidence bounds /
round transition / safety boundary 全部不变）。
```

**不因此授权实现**：

```text
O2 IMPLEMENTATION = NOT AUTHORIZED
Certificate implementation / codec / signing / verification / network message /
pacemaker / timer integration = FUTURE（本 ADR 冻结不改变这一点）
```
