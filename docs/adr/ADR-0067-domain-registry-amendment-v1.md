# ADR-0067: Domain Registry Amendment — Dedicated RoundChangeCertificate Signing Domain

- **Status**: **DRAFT — NOT FROZEN**
  （本文件为设计草案。**不构成协议修订**、**不授权实施**、**不解决 `0x07` 冲突**、
  **不修改任何既有 ADR / 源码 / 测试 / consensus-spec**。）
  - **2026-10-07 更新（PHASE 6H-B2）**：本 ADR 现**登记**一项 **Owner 已批准**的数值分配
    （`0x10 = RoundChangeCertificate`；见 §0.6）。该分配由 **Owner 决策**作出，分配规则 = **ADR-0069**；
    本 ADR 仅承担**登记与 provenance**，**不自授权**、**不冻结**、**不修改 ADR-0005**。
- **Date**: 2026-10-06
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: STEP 6D — Domain Registry Amendment（**design only**）
- **Phase provenance**: PHASE 4/6（`0x07` 冲突识别）→ PHASE 6C（ADR-0066：O2 需要专用域）→ **PHASE 6D（本 ADR 草案）**
- **关联（只读引用，不修改）**:
  **ADR-0005（Domain Separation / Nova Domain Registry）** · ADR-0009（Signature Coverage）·
  ADR-0010（chain_id 域分离）· ADR-0012（Algorithm Registry）· ADR-0043（Proof of Contribution V1，
  `DomainId::Contribution = 0x07`）· **ADR-0050（Proposer Selection V1）** · **ADR-0066（RoundChangeCertificate，
  DRAFT）** · ADR-0037（BFT Round）· ADR-0038（Finality）· ADR-0041（ProposalRef canonical）·
  ADR-0049（Liveness / Pacemaker）· **ADR-0053（Lock Justification & Override，L-1~L-12）** ·
  `docs/protocols/consensus-spec-v1.md`
- **Non-regression statement**: 本 ADR 文本**未修改**任何既有 ADR / consensus-spec；
  **未创建任何代码预留**。（**PHASE 6H-B2**：本 ADR 现登记 Owner 批准的 `0x10` 分配；其代码实现
  在 `crates/crypto/src/domain.rs`，分配规则由 **ADR-0069** 承载。）

---

## 0. OWNER-APPROVED RESOLUTION（PHASE 6F 批准 → PHASE 6G-A 实施）

> 本节记录 Owner 已批准的具体决议。**除本节及变更记录外，本 ADR 正文保持不变。**

```text
OWNER-APPROVED RESOLUTION

D1  0x07 归属              = Contribution（保留 ADR-0005 注册表 + ADR-0043 FROZEN 分配）
D2  Proposer 处置           = 分离哈希域命名空间（C-1）；保留哈希域前缀字节 0x07
D3  O2 RoundChangeCertificate = 注册表修复后分配【新的专用签名 DomainId】
D4  注册表治理             = 采纳显式唯一域分配规则（见 §12）
```

### 0.1 D1/D2 的落地结果

```text
DomainId::Contribution  = 0x07        已恢复（与 ADR-0005 / ADR-0043 一致）
DomainId::Proposer      = （已移除）   不再是活跃签名域变体
HashDomain::Proposer    = 0x07        新【哈希域】命名空间（ADR-0068）
ProposerSeedInput       = 逐字节不变（57B）⇒ ProposerSeed / proposer 序列不变
```

- 哈希域命名空间由 **ADR-0068（Hash Domain Namespace V1，FROZEN 2026-10-07）** 承载；
  本 ADR **不**重复定义该命名空间，仅记录其与本注册表修正的关系。
- 本 ADR 仍为 **DRAFT — NOT FROZEN**（未获得冻结授权）。

### 0.2 D3 的状态（必须明确）

```text
O2 numeric DomainId NOT YET ALLOCATED        ← 截至 PHASE 6G-C；已由 §0.6 取代（SUPERSEDED）
```

- **未**选择 `0x08`，**未**选择 `0x09`，**未**选择任何 Reserved 值，**未**猜测任何数值。
- O2 仍为：`BLOCKED — DOMAIN NUMERIC ALLOCATION PENDING`（截至 PHASE 6G-C）。
- O2 域 **MUST** 为**签名** `DomainId`（ADR-0066 RC-5）；**MUST NOT** 为 `HashDomain`。
- **→ 见 §0.6（PHASE 6H-B2）：Owner 已批准 `0x10 = RoundChangeCertificate`。**

### 0.3 D4 的落地结果

§12 的治理规则草案（G-1…G-9）**被 D4 采纳为方向**；其成文与实施仍属后续工作项。

### 0.4 PHASE 6G-C 批准与治理闭合（2026-10-07）

```text
PHASE 6G-C OWNER DECISIONS

D1  APPROVE   0x07 = Contribution
D2  APPROVE   HashDomain::Proposer = 0x07 / C-1
D3  APPROVE   ADR-0068 READY FOR FREEZE   → 已于 2026-10-07 冻结（见 ADR-0068）
D4  AUTHORIZE documentation correction of FROZEN ADR-0049
              （仅修正失效的 DomainId::Proposer 引用；不改 pacemaker / liveness 语义）→ 已应用
D5  KEEP      O2 DOMAIN BLOCKED / UNALLOCATED
```

- **D4 已应用**：ADR-0049 §3.7 / §10 / §12 中失效的 `DomainId::Proposer` 引用已改为指向 **ADR-0068** 的
  `HashDomain` 命名空间（`HashDomain::Proposer = 0x07`；`0x07` 的 signing 分配仍为 `Contribution`）；
  **未**改变任何 pacemaker / liveness 语义。
- **D5 保持**：

  ```text
  O2 numeric DomainId NOT YET ALLOCATED
  ```

- **unique-domain allocation rule**（PHASE 6F 的 D4）仍为权威方向（见 §12）。

### 0.5 本 ADR 的冻结状态（精确）

```text
本 ADR 当前仍为 DRAFT — NOT FROZEN。
```

**理由**：PHASE 6G-C 的 Owner 决策中，**D3 仅授权冻结 ADR-0068**，**未**明确授权冻结本 ADR-0067。
依 PHASE 6G-C §5 的纪律「将 ADR-0067 状态改为 FROZEN，**仅当 Owner 明确授权冻结**」，
**本阶段未改变本 ADR 的状态**。

```text
ADR-0067 FREEZE AUTHORIZATION = NOT PROVIDED（需单独 Owner 授权）
```

### 0.6 PHASE 6H-B2 — O2 DomainId `0x10` 正式分配（Owner 批准）

```text
ALLOCATION RECORD

Allocated DomainId   = 0x10
Purpose              = O2 RoundChangeCertificate（专用【签名】域）
Signing statement    = Abandon(chain_id, height, from_round)     （ADR-0066 RC-4 / S1 语义）
Authority            = Owner-approved（PHASE 6H-B2，2026-10-07）
Allocation rule      = ADR-0069（Signing Domain Allocation Governance v1）
Previous status      = Reserved（ADR-0005：`0x08+` = Reserved / 未注册）
Allocation method    = Explicit governance（**非** max+1 自动分配）
Collision audit      = PHASE 6H-B1（全仓库按命名空间分类；实际冲突 = 0）
Code implementation  = crates/crypto/src/domain.rs（DomainId::RoundChangeCertificate = 0x10）
Status               = allocated / governance-approved
```

**保留不变（MUST）**：

```text
0x07                   = Contribution            （ADR-0005 注册表 + ADR-0043 FROZEN）—— 不变
0x08 – 0x0F            = Reserved / Unallocated   —— 不变
0x11+                  = Reserved / Unknown（拒绝）—— 不变
HashDomain::Proposer   = 0x07                     （ADR-0068；**不同命名空间**）—— 不变
MessageType 0x08–0x0B  （网络命名空间）             —— 不变；**不**并入 DomainId 注册表
```

**边界（MUST）**：

```text
O2 implementation（certificate / verification / signing path / network message /
pacemaker / timer）仍为 BLOCKED —— 本次仅建立 registry-level numeric identity。
```

**为何选择 `0x10` 而非 `0x08`（Owner 理由，记录在案）**：

```text
· 0x08–0x0B 已有明确的 MessageType（网络）语义 ⇒ 避免新的永久数值巧合
· 0x08 另有现存的 DomainId negative test（crates/crypto/src/domain.rs）需一并改动
· 0x10 未发现其它协议命名空间的实际分配
· 0x10 仍属 Reserved 区间 ⇒ 必须经正式 Registry Amendment（即本节登记）
· 不采用 max+1 自动分配
```

**注册表移转的不对称（**必留记录**）**：

```text
docs/adr/ADR-0005-domain-separation.md 为**受保护文件**（本阶段禁止修改）
⇒ ADR-0005 注册表表体仍书 `0x08+ = Reserved`，**尚未**写入 `0x10 = RoundChangeCertificate`。
⇒ **DOCUMENTATION FOLLOW-UP REQUIRED**：将来需由 Owner 单独授权的一次 ADR-0005 注册表同步。
   在此之前，O2 域的**唯一权威登记** = 本 ADR §0.6 + ADR-0069 Allocation Record + 代码。
```

### 0.7 PHASE 6H-G — 陈旧标记 Cleanup + Freeze Preparation（Owner 授权 D10）

> **原则（Owner 指令）**：仅做 **cleanup + freeze preparation**；**保留历史记录，不重写历史**。
> 本节**只增补状态映射与清单**，**不删除、不改写**任何历史文本。

#### A. 陈旧标记状态映射（原文一律保留）

| # | 位置 | 历史内容（原文保留，不删改） | 当前状态 |
|---|---|---|---|
| 1 | §0.6 末（注册表移转不对称） | 称 ADR-0005 表体「尚未写入 `0x10`」 | **SUPERSEDED** —— PHASE 6H-D 已完成 ADR-0005 最小 Registry Sync（`0x10 = RoundChangeCertificate` 已登记） |
| 2 | §4.2（GOVERNANCE AMBIGUITY 段） | 「OWNER DECISION REQUIRED」 | **RESOLVED** —— PHASE 6F D1/D2 → PHASE 6G-A/C 实施（Option A / C-1） |
| 3 | §6（CURRENT FACT / OWNER DECISION REQUIRED 段） | 「0x07 冲突未决」「OWNER DECISION REQUIRED : 是」 | **RESOLVED** —— `0x07 = Contribution` 已恢复；O2 域取值 = `0x10` |
| 4 | §12（治理规则草案段末） | 「OWNER DECISION REQUIRED；本 ADR 不自行定案」 | **RESOLVED** —— Owner 已裁决；规则由 **ADR-0069** 承载（Owner D11 = AUTHORIZE FREEZE） |
| 5 | §13 Open Questions `D-1` / `D-3` / `D-4` | 「→ OWNER DECISION REQUIRED」 | **RESOLVED** —— D-1 = `0x07 = Contribution`；D-3 = C-1 哈希域分离；D-4 = `0x10` |
| 6 | §1.1 / §1.2 | PHASE 6D 快照表 | 已于 6H-B2 加「PHASE 6D 快照」声明（**内容保留**） |

```text
历史文本未被删除；上述映射仅为状态标注（state annotation）。
```

#### B. Freeze Preparation Checklist（D10 = CLEANUP + FREEZE PREPARATION ONLY）

```text
[✓] registry contradiction  = 无（0x07 / 0x10 与 ADR-0005 权威注册表一致）
[✓] provenance              = §0.6 + ADR-0005 变更记录 + ADR-0069 §2.1
[✓] 陈旧 OPEN 标记           = 已映射（§0.7.A），原文保留
[ ] authority 表述           = ADR-0005 自身 Status(Proposed) vs 本 ADR 多处称 FROZEN
                               ⇒ 未决（Owner D12 = KEEP CURRENT STATUS）
[ ] 本 ADR 冻结授权           = 未授权（Owner 仅授权 CLEANUP + FREEZE PREPARATION）
```

```text
本 ADR 仍为 DRAFT — NOT FROZEN。Freeze 需 Owner 后续明确授权（本阶段未冻结）。
```

---

## 1. Context

### 1.1 当前 DomainId 注册表现状（**双源不一致** —— **PHASE 6D 快照**）

> **快照声明**：本表为 PHASE 6D 时点。`0x07` 冲突已由 PHASE 6G-A/C 解决（见 §0.1）；
> `0x10` 的分配见 §0.6。

| 来源 | `0x07` 的声明 | 出处 |
|---|---|---|
| **ADR-0005**（标题即 **Nova Domain Registry** 表） | `0x07 = Contribution` — *Proof of Contribution / Contribution protocol domain（ADR-0043，FROZEN）* | `docs/adr/ADR-0005-domain-separation.md` 注册表行 |
| **ADR-0043**（FROZEN 2026-08-31） | `DomainId::Contribution = 0x07 已冻结` | `docs/adr/ADR-0043-proof-of-contribution-v1.md` |
| **ADR-0050**（FROZEN 2026-09-03） | `DomainId::Proposer = 0x07 —— **proposed** registry allocation`；`Status = PROPOSED / pending implementation registry update（crates/crypto/src/domain.rs **未实现，不改**）`；头部：*DomainId::Proposer 注册仍 deferred* | `docs/adr/ADR-0050-proposer-selection-v1.md` §13 行 154/155、行 3、行 208 |
| **代码**（`crates/crypto/src/domain.rs`） | `Proposer = 0x07`（枚举值 L60；`try_from(0x07) ⇐ Proposer` L81） | 见 §1.2 |

### 1.2 代码事实（直接核实 —— **PHASE 6D 快照**）

> **快照声明**：本表为 PHASE 6D 时点的代码事实。其后的修复见 §0.1（`0x07 = Contribution`、
> `DomainId::Proposer` 已移除、哈希域移至 ADR-0068）与 §0.6（`0x10 = RoundChangeCertificate`）。
> K-1/K-2/K-5/K-10 中的 `DomainId::Proposer` 为**历史**描述，**不再**反映当前代码。

| # | 事实 | 位置 |
|---|---|---|
| K-1 | `DomainId` 枚举：`Transaction=0x01` · `ValidatorVote=0x02` · `Block=0x03` · `Governance=0x04` · `Address=0x05` · `Witness=0x06` · **`Proposer=0x07`** | `crates/crypto/src/domain.rs` L52-60 |
| K-2 | `TryFrom<u8>`：`0x07 ⇒ Ok(Proposer)`；其余未列值 ⇒ `Err(UnknownDomainId(v))` | 同上 L74-84 |
| K-3 | `DomainId::try_from(0x08) == Err(UnknownDomainId(0x08))`，且**有测试断言该拒绝行为** | 同上 L290-291 |
| K-4 | `DomainId::try_from(0x00)` / `(0xff)` 亦被拒（有测试） | 同上 L286、L294 |
| K-5 | **`DomainId::Proposer` 的唯一生产用途**：`out[0] = DomainId::Proposer.as_u8();` —— 即 `ProposerSeedInput[0]`（**哈希域前缀**，**非** `build_signed_bytes`） | `crates/consensus/src/proposer.rs` L43 |
| K-6 | **不存在** `build_signed_bytes(_, DomainId::Proposer, …)` 调用点（全仓库） | 检索结果 |
| K-7 | **不存在** `DomainId::Contribution` 变体（Contribution 协议未实现） | `crates/crypto/src/domain.rs` |
| K-8 | 实际进入 `build_signed_bytes` 的生产域 = `Transaction` · `ValidatorVote` · `Block` · `Witness` | `crypto/transaction.rs`、`consensus/vote.rs/finality.rs/integration.rs/checkpoint.rs/fork_choice.rs`、`core/block.rs`、`consensus/witness.rs` |
| K-9 | **另一个独立命名空间**：`MessageType`（网络层）使用 `Status=0x07`、`ConsensusVote=0x08` ⇒ **`0x07`/`0x08` 在 MessageType 中的含义与 DomainId 无关** | `crates/network/src/message.rs` L35-37、L64-65 |
| K-10 | 测试断言 `DomainId::Proposer.as_u8() == 0x07` 与 `proposer_seed_input(…)[0] == 0x07` | `crypto/domain.rs` L301-303；`consensus/proposer.rs` L355-356 |

### 1.3 O2 依赖（规范性）

ADR-0066（DRAFT）要求：

```text
RoundChangeCertificate
        ↓
Abandon(chain_id, height, from_round)
        ↓
dedicated signing domain
```

ADR-0066 明确：
- 专用域 **MUST** 与 `ValidatorVote` 不同；
- **MUST NOT** 复用既有域；
- **MUST NOT** 静默分配 `0x08+`；
- **MUST NOT** 在 `0x07` 冲突未决期间使用 `0x07`；
- **MUST** 通过**经批准的 registry amendment** 显式注册。

**为什么禁止复用 `ValidatorVote`**：`verify_qc`（`crates/consensus/src/finality.rs` L223+）会把每条 QC evidence
**重建为 `ValidatorVote`** 并以 `DomainId::ValidatorVote` 走 V-5 五步验签。若 Abandon attestation 使用同一域，
则存在被**误构造成 vote 形态**的域混淆风险 ⇒ 必须使用**专用域**。

**为什么必须显式 registry amendment**：`DomainId` 是**密码协议命名空间**的一部分
（进入 `build_signed_bytes`，进而决定签名消息身份），因此 **MUST NOT 被视为非正式的实现细节**。

### 1.4 为什么 O2 在注册表归属不清时不能安全推进

若 `0x07` 同时被理解为 `Contribution`（ADR-0005/ADR-0043）与 `Proposer`（代码/ADR-0050 提案），则：
1. **两个不同语义目的**共享同一 1B 域值 ⇒ 域分离契约被破坏；
2. 任何未来为 `Contribution` 或 `Proposer` 引入签名的一方，都会**无法判断该域是否可用**；
3. O2 若在此状态下被分配某个值，将使**冲突扩散到第三处**。

---

## 2. Problem — `0x07` 冲突的精确定义

```text
CURRENT FACT（事实）

  文档权威（ADR-0005 注册表 + ADR-0043 FROZEN）: 0x07 = Contribution
  代码实现（crates/crypto/src/domain.rs）        : 0x07 = Proposer
  ADR-0050 自述                                   : 0x07 = Proposer 为 **PROPOSED**，
                                                    且明确 "crates/crypto/src/domain.rs 未实现，不改"

⇒ 冲突三方：ADR-0005/ADR-0043 与 代码 直接冲突；ADR-0050 并未授权该代码变更。
```

**冲突的性质**：这不是「两个 ADR 观点不同」，而是
**代码在 ADR-0050 明确声明「未实现、不改」的前提下，实际执行了该注册**
⇒ 构成一次**未经 ADR 授权的注册表变更**，并**覆盖**了 ADR-0005 的 FROZEN 分配。

**为什么 O2 不能在此状态下推进**：
```text
只要 0x07 的归属不可判定：
  · 无法判断 O2 的专用域是否可以复用 0x07（不可）
  · 无法判断未来 Contribution 签名是否会与既有产物撞域
  · 任何对 0x07 的处置都会改变 (height, round) → proposer 的确定性（见 §10.2）
⇒ O2 implementation is BLOCKED until the registry decision is approved.
```

---

## 3. Existing Registry（**已核实表**）

> 数值与语义均取自仓库实际内容；**无任何臆造值**。

| DomainId | Meaning | Authority | Status |
|---|---|---|---|
| `0x01` | Transaction | ADR-0005 注册表；`DomainId::Transaction` | **代码已实现**（`build_signed_bytes` 使用者） |
| `0x02` | ValidatorVote | ADR-0005 注册表；ADR-0034/0038；`DomainId::ValidatorVote` | **代码已实现**（V-5 验签路径；K-8） |
| `0x03` | Block | ADR-0005 注册表；`DomainId::Block` | **代码已实现**（K-8） |
| `0x04` | Governance | ADR-0005 注册表；`DomainId::Governance` | 已定义；**未发现生产调用点** |
| `0x05` | Address | ADR-0005 注册表；`DomainId::Address` | 已定义；**未发现生产调用点** |
| `0x06` | Witness | ADR-0005 注册表（ADR-0036，FROZEN）；`DomainId::Witness` | **代码已实现**（`consensus/witness.rs` L78） |
| `0x07` | Contribution | ADR-0005 注册表 + ADR-0043（FROZEN） | **RESOLVED**（PHASE 6G-A/C） |
| ~~`0x07`~~ | ~~Proposer~~（历史） | 代码（PHASE 6G-A 前）+ ADR-0050（自述 proposed/deferred） | **RESOLVED —— 已移除**；proposer 哈希域 → ADR-0068 |
| `0x00` | —（未注册） | ADR-0005：「Reserved / 未注册 ⇒ 必须拒绝」 | **代码拒绝**（有测试断言） |
| `0x08` – `0x0F` | —（未注册） | ADR-0005：「**Reserved / 未注册 ⇒ 必须拒绝**」；「`0x08+` 保留给未来协议域」 | **Reserved / Unallocated**；**代码拒绝**（K-3/K-4） |
| **`0x10`** | **RoundChangeCertificate** | **Owner 批准（PHASE 6H-B2）；分配规则 = ADR-0069；登记 = 本 ADR §0.6** | **ALLOCATED / governance-approved**（`DomainId::RoundChangeCertificate`） |
| `0x11+` | —（未注册） | ADR-0005：「Reserved / 未注册 ⇒ 必须拒绝」 | **代码拒绝** |
| **O2 domain** | **RoundChangeCertificate / Abandon attestation** | **本 ADR §0.6（登记）** | **ALLOCATED = `0x10`** |

**命名空间边界（防混淆，K-9）**：`MessageType`（网络层）为**独立**命名空间
（`Status=0x07`、`ConsensusVote=0x08`）；其取值与 `DomainId` **无任何关系**。
未来 O2 的网络消息类型需要的是 **`MessageType`** 取值，**与本 ADR 的 `DomainId` 决策彼此独立**。

---

## 4. Registry Authority

### 4.1 判定结果

```
REGISTRY AUTHORITY = ADR-0005（Nova Domain Registry 表）+ ADR-0043（0x07 = Contribution 的分配者）
```

**依据（非歧义）**：
1. ADR-0005 的注册表标题即为「**Nova Domain Registry（domain_id: u8）**」，并定义 `signed_bytes` 的字段语义；
2. ADR-0005 的变更记录显示 **2026-08-31 执行过 Registry Synchronization**，明确「`0x08+` 保持 Reserved」，
   且标注「**未实现代码**（协议文档同步）」；
3. ADR-0050 **自身**把 `DomainId::Proposer` 标为 **proposed**，并指出注册应「pending implementation
   registry update（`crates/crypto/src/domain.rs` 未实现，不改）」，且提到「若 Owner 认为 DomainId 注册
   应单独 ADR 处理，亦明确此依赖」⇒ **ADR-0050 将注册权归属让给注册表流程，而非自行占有**。

⇒ **注册表权威不构成歧义**；**不一致方是代码**。

### 4.2 但存在**治理层面**的歧义（必须由 Owner 裁决）

```
GOVERNANCE AMBIGUITY — OWNER DECISION REQUIRED
```

- 该代码变更**没有对应的授权 ADR**（ADR-0050 明文「未实现，不改」）；
- 因此「代码现状是否可被**追认**（ratify）」属 **Owner 决策**，本 ADR **不自行判定**；
- 本 ADR 亦**不删除**任一含义（既不删 ADR-0005 的 `Contribution`，也不删代码的 `Proposer`）。

---

## 5. Proposed Resolution — Options

> **重要标注（不得静默处理）**：Owner 在 PHASE 6D §7 给出的 **Option A 与 Option B 的文字表述互相重叠**
> （A：「保留 ADR-0005 的 `0x07 = Contribution`，移动/重命名冲突的 Proposer 赋值」；
> B：「修改注册表使 Proposer 获得不同 ID」）。**按字面理解，B 与 A 等价**。
> 另需注意：Owner 在 PHASE 4/6 的 lettering 为**相反**（当时 A = 保留 Proposer）。
> ⇒ 为避免误读，本节按**内容**定义选项，并显式标出需要 Owner 澄清之处。

### Option A — 保留 `0x07 = Contribution`，将 `Proposer` 迁移到新 DomainId

| 维度 | 分析 |
|---|---|
| compatibility impact | 不改任何**签名**兼容性（K-6：无签名绑定 `0x07`）；**改变** `ProposerSeedInput[0]` ⇒ 改变 `(h,r) → proposer` 映射 |
| affected source | `crates/crypto/src/domain.rs`（枚举值 + `try_from`）、`crates/consensus/src/proposer.rs`（若改为引用新变体则无需改逻辑） |
| affected ADRs | ADR-0005（注册表补一行）、ADR-0050（§154/§155/§208 的 "0x07" 措辞需修订为最终分配值） |
| migration impact | **无链上/持久化迁移**；仅**测试断言**需更新（K-10）；必须在 **genesis freeze 之前**完成 |
| canonical-signing implications | `ProposerSeedInput` 首字节改变 ⇒ `ProposerSeed` 改变 ⇒ **proposer 选择序列改变** |
| old signatures remain verifiable? | **YES** —— `0x07` 从未用于签名（K-6） |
| historical data affected? | **NO**（无已签名产物、无持久化域 0x07 记录；Genesis 未冻结） |
| implementation scope | 小（1 个枚举值 + 关联测试 + 文档） |
| safety risk | **无安全影响**（proposer 身份与安全证明无关）；仅影响确定性与活性分布 |
| 与注册表权威一致性 | ✅ **一致**（尊重 ADR-0005 + ADR-0043 FROZEN） |

### Option B — 按 §7-B 字面（"Proposer receives a different ID"）= 与 A 相同

⇒ **与 Option A 等价 ⇒ 不构成独立选项。**
**若 Owner 的本意是相反方向（即「追认代码：`0x07 = Proposer`，把 `Contribution` 迁移到新 ID」），请明确 —— 该方向需要显式推翻 ADR-0005/ADR-0043 的 FROZEN 分配，属更高影响的治理行为。**

| 维度（B′ = 追认代码、迁移 Contribution） | 分析 |
|---|---|
| compatibility impact | 改动 `Contribution` 的分配 ⇒ 但 **Contribution 未实现**（K-7），故无签名兼容影响 |
| affected source | `crates/crypto/src/domain.rs`（**无需改**，与现状一致） |
| affected ADRs | **必须修订 ADR-0005（FROZEN）注册表行 + ADR-0043（FROZEN）** —— 属**修改两个冻结 ADR** |
| migration impact | 无链上迁移；但建立「后发 ADR/代码可覆盖早发冻结分配」的**先例** |
| canonical-signing implications | `ProposerSeedInput` **保持不变** |
| old signatures remain verifiable? | YES |
| historical data affected? | NO |
| implementation scope | 文档为主（但触及**两个冻结 ADR**） |
| safety risk | 无直接安全风险；**治理风险高**（注册表权威被削弱） |

### Option C — 其他「仓库支持的」解法

**检索结论：未发现任何**已有仓库规则**支持第三种自动解法。** 以下仅为**设计可能性**，**均需新政策**：

| 候选 | 说明 | 是否被现有规则支持 |
|---|---|---|
| C-1 | **区分命名空间**：签名域（`build_signed_bytes`）与**哈希域**（`ProposerSeed` 前缀）各自独立编号体系 | ❌ 需新 ADR（且触及 ADR-0050 的 57B seed 结构） |
| C-2 | **注册表版本化 + 批量重编号**（≥0x08 整体重排） | ❌ 无既有规则；迁移代价最高 |
| C-3 | 把 hash-domain 常量移出 `DomainId`（如独立 `HashDomainId`） | ❌ 需新 ADR；与 C-1 实质相同 |

### 5.1 选项选择

```text
本 ADR **不选**任何选项。
```

原因：仓库既有规则**未确定性地**指向 A 或 B′ —— 权威在文档侧（ADR-0005/ADR-0043），
但代码已构成既成事实，其**追认与否**属 Owner 决策。

```text
OWNER DECISION REQUIRED
```

---

## 6. O2 Domain Allocation（**需求定义；数值已由 §0.6 分配**）

```text
Purpose       : RoundChangeCertificate / Abandon attestation
Artifact      : RoundChangeCertificate
Signing stmt  : Abandon(chain_id, height, from_round)
Domain        : Dedicated / non-ValidatorVote
DomainId      : 0x10（Owner 批准 PHASE 6H-B2；见 §0.6）
                （原状态：OWNER DECISION REQUIRED → 已解决）
```

**必须声明**：
> The domain is bound to the semantic purpose of **round-transition authority** and **MUST NOT** be reused
> for votes, finality certificates, locks, or unrelated signing artifacts.

**登记要求（未来）**：
- **MUST** 由**经批准的 registry amendment** 显式登记（即本 ADR 经 Owner 批准并冻结后）；
- **MUST NOT** 在 `0x07` 冲突未决期间占用 `0x07`；
- **MUST NOT** 静默占用 `0x08+`（ADR-0005 明示「不得分配 `0x08` / `0x09` 等」；且 K-3 显示 `0x08`
  **当前被代码拒绝并有测试断言** ⇒ 若分配 `0x08`，**该测试必须一并显式修改**，属实现阶段工作项）。

**数值分配策略的真实状态**：
```text
CURRENT FACT            : 0x07 冲突未决；0x08+ 为 Reserved 且被代码拒绝（有测试断言）
PROPOSED POLICY         : 见 §11（Registry Governance 的 8 条规则草案）
PROPOSED ALLOCATION     : 无 —— 本 ADR 不提议具体数值
OWNER DECISION REQUIRED : 是（DomainId 归属、Proposer 处置、O2 域取值、是否建立永久分配政策）
```

**明示**：**本 ADR 不自动选择 `0x08`**；**不创建任何代码预留**；**不修改源码以占用取值**。
（**PHASE 6H-B2**：`0x10` 是在 **Owner 明确批准**后**显式分配**的，**非**自动选择 ⇒ 不违反本句。）

---

## 7. Canonical Encoding（引用 ADR-0066，不重新设计）

O2 的签名陈述使用既有签名框架（ADR-0005 / ADR-0009）：

```text
algorithm_id(1B)
‖ domain_id(1B)              ← 本 ADR 讨论的对象（专用域）
‖ chain_id(8B LE)
‖ payload_length(4B LE)
‖ payload

payload = height(8B LE) ‖ from_round(8B LE)      // 16B 定长
```

**本 ADR 必须声明（关键的密码学后果）**：

> 改变 `domain_id` 会改变**域分离**，从而改变**签名消息身份**（signed message identity）。
> 因此 `DomainId` 分配属于**密码协议命名空间**，**MUST NOT** 被视为非正式的实现细节。

- **MUST NOT** 修改 `build_signed_bytes`；
- **MUST NOT** 在本阶段实现任何内容；
- 详细的 canonical 规格（含证书容器）由 ADR-0066 §5 及其后续独立 serialization ADR 承担。

---

## 8. Historical Signature Compatibility（**基于检索的事实，非猜测**）

| 对象 | 是否受 `0x07` 处置影响 | 证据 |
|---|---|---|
| **既有 proposer 签名** | **不存在此类签名** | K-6：`DomainId::Proposer` **从未**进入 `build_signed_bytes`；唯一用途是哈希域前缀（K-5） |
| **既有 vote 签名** | **不受影响** | vote 使用 `DomainId::ValidatorVote = 0x02`（K-8） |
| **既有 block 签名** | **不受影响** | 使用 `DomainId::Block = 0x03`（K-8） |
| **既有 witness 签名** | **不受影响** | 使用 `DomainId::Witness = 0x06`（K-8） |
| **既有 transaction 签名** | **不受影响** | 使用 `DomainId::Transaction = 0x01`（K-8） |
| **Contribution 签名** | **不存在** | K-7：`DomainId::Contribution` 变体不存在，协议未实现 |
| **genesis artifacts** | **不受影响（内容层面）** | genesis 不含域字节；但 `validator_set_id = genesis_hash` 参与 proposer seed ⇒ 见 §8.2 |
| **persisted journals**（vote / block safety journal） | **不受影响** | 其记录对象为 `ValidatorVote` / `Block` 域；与 `0x07` 无关 |
| **replay verification** | **不受影响** | 防重放由 `chain_id` + `height` + `round` 在签名范围内提供；`0x07` 不承载任何签名产物 |
| **historical blocks** | **不存在**（无已发布链） | Genesis = BLOCKED；无主网 |
| **test vectors / 单元测试** | **受影响** | K-10：`domain.rs` L301-303 与 `proposer.rs` L355-356 断言 `0x07`；K-3：`domain.rs` L290-291 断言 `0x08` 被拒 |

### 8.1 结论

```
No persisted production artifact binds DomainId 0x07.
⇒ No historical migration is required for ANY option that keeps 0x07 unused-by-signature.
```

### 8.2 唯一**实质性**影响：proposer 选择确定性

```text
DomainId::Proposer 的数值进入 ProposerSeedInput[0]
        ⇒ 改变该数值 ⇒ 改变 ProposerSeed ⇒ 改变 (height, round) → proposer
        ⇒ 改变出块 proposer 序列（**不是** 签名兼容性问题）
```

- **不影响 safety**（任意诚实 proposer 出块均安全）；
- 影响**确定性与活性分布**；
- ⇒ **该决策 MUST 在 genesis freeze 之前定案**（当前 Genesis = BLOCKED，故代价≈0）。

### 8.3 若未来需要迁移

仅可能为「**测试断言更新**」与「**文档同步**」；**不存在**链上/持久化迁移路径。
任何迁移**仅作为未来实现要求**描述，**本阶段不执行**。

---

## 9. ADR Dependency Map

```text
ADR-0005  ──►  Domain Registry Authority（Nova Domain Registry 表；0x07 = Contribution；0x08+ Reserved）
   │
   ├── ADR-0043 ──►  分配 0x07 = Contribution（FROZEN 2026-08-31）
   │
ADR-0050  ──►  Proposer Domain **Proposal**（自述 PROPOSED / deferred；明文「domain.rs 未实现，不改」）
   │                 ⇒ 与 ADR-0005/ADR-0043 冲突
   │
ADR-0066  ──►  RoundChangeCertificate requires a dedicated signing domain（DRAFT）
   │
NEW ADR-0067（本文件） ──►  解决 registry allocation policy / 0x07 冲突
                            （OWNER DECISION REQUIRED；本 ADR 不自行定案）
```

**需显式兼容性注记的其他冻结 ADR（**均不修改**）**：

| ADR | 是否需兼容注记 | 理由 |
|---|---|---|
| **ADR-0009**（Signature Coverage） | ✅ 需 | 定义「签名字段级覆盖」原则：本 ADR 的 O2 陈述须按其体例定义覆盖字段（ADR-0066 §5 已给）。**注意其头部 Status 为 "Proposed"**，与正文冻结表述不一致（既有观察，不修改） |
| ADR-0037（BFT Round） | ✅ 需（弱） | B-5 lock 语义与 round 变更的关系；由 ADR-0053 承接 |
| ADR-0041（ProposalRef 64B） | ✅ 需 | O2 **不得**扩展 `ProposalRef`；域变更不影响其编码 |
| **ADR-0053** | ✅ 需（强） | 见 §10；**必须保持 L-3/L-6/L-7/L-8/L-9/L-10/L-12 不变** |
| ADR-0010 / ADR-0012 | ✅ 需（弱） | `chain_id` 绑定与 `AlgorithmId` 绑定均在 `signed_bytes` 中，域变更不改变其语义 |
| consensus-spec-v1.md | ✅ 需 | §5 Liveness Assumptions = OPEN；与 ADR-0066 的活性声明相关 |

**不得修改上述任何 ADR。**

---

## 10. ADR-0053 Compatibility（**无授权修订**）

本 ADR **显式保持** ADR-0053 以下条款不变：

```text
L-3   lock 获取仅来自 valid PrecommitQC（PrevoteQC 不获取 lock）
L-6   PrevoteQC MUST NOT acquire/advance/unlock/override/establish finality
L-7   PrecommitQC 不自动授予 unrelated-lock override
L-8   same/descendant ⇒ ALLOW；unrelated ⇒ valid-but-inapplicable（≠ invalid，证据保留）
L-9   V1 defines no unrelated higher-round lock override
L-10  Timeout / Round Change / Proposer Change MUST NOT unlock
L-12  lock enforcement = Non-Scope（仍 DEFERRED）
```

**MUST 恒真**（本 ADR 的任何选项都不得违反）：

```text
Domain registry amendment MUST NOT create a lock override.
RoundChangeCertificate MUST NOT unlock.
RoundChangeCertificate MUST NOT become vote-equivalent.
RoundChangeCertificate MUST NOT become PrecommitQC.
RoundChangeCertificate MUST NOT become finality evidence.
```

**No changes to ADR-0053.**

---

## 11. Security Requirements

| 要求 | 说明 |
|---|---|
| **domain separation** | 每个签名语义必须拥有**唯一** 1B 域值；同一值不得服务两个语义 |
| **cross-protocol signature confusion** | 域值共享将使不同工件之间的签名**可互相解释** ⇒ 必须禁止（`build_signed_bytes` 的 1B 域是**唯一**的语义分隔符） |
| **replay across artifact types** | 域 + `chain_id` + `height` + `from_round` 共同提供；**MUST NOT** 依赖单一字段 |
| **chain_id binding** | MUST（经 `build_signed_bytes`，ADR-0010） |
| **height binding** | MUST（payload） |
| **from_round binding** | MUST（payload） |
| **algorithm binding** | MUST（`algorithm_id`，ADR-0012；当前仅 `Ed25519 = 0x01`） |
| **domain binding** | MUST（本 ADR 的对象） |
| **validator-set binding where applicable** | O2 证书携带 `validator_set_id = genesis_hash`（ADR-0066 §4.2） |
| **historical signature verification** | 任何注册表变更 **MUST** 保证既有签名**仍可验证**（§8 已证：`0x07` 无签名产物） |
| **malicious reuse of a domain** | 注册表 **MUST** 提供**唯一性不变式**与**冲突检测**（§12） |
| **future registry collision prevention** | 见 §12 的 8 条治理规则草案 |

**必须显式声明**：

> **DomainId allocation is part of the cryptographic protocol namespace and therefore MUST NOT be treated
> as an informal implementation detail.**

---

## 12. Registry Governance（**未来治理规则草案**）

> 若项目已有相应规则，**应对齐而非另立矛盾政策**。经检索：ADR-0005 的同步说明已包含
> 「`0x08+` 保留（不得分配）」与「必须拒绝未注册值」，但**未见**完整的分配程序与唯一性不变式的成文规则。
> ⇒ 以下为**草案**（**需新 ADR 或本 ADR 批准后采纳**）。

| # | 规则 | 现状 |
|---|---|---|
| G-1 | **唯一权威注册表**：仅 ADR-0005 的 Nova Domain Registry 具有分配权 | 部分存在（ADR-0005 有表，但无程序） |
| G-2 | **DomainId 唯一性不变式**：一个值 ⇔ 一个语义 | 被 `0x07` 破坏 |
| G-3 | **显式保留**：Reserved 值不得隐式占用 | 存在（「`0x08+` 不得分配」） |
| G-4 | **禁止静默复用**：任何复用需显式 ADR | 被 `0x07` 破坏 |
| G-5 | **每个已分配域必须引用其授权 ADR** | 部分存在 |
| G-6 | **实现前冲突检查**：注册代码前必须核验注册表 | **缺失**（本次事故根因） |
| G-7 | **历史兼容性要求**：不得使既有签名不可验证 | 隐含存在 |
| G-8 | **冻结协议变更须 Owner 批准** | 存在（既有实践） |

**建议新增（根治本次事故）**：
```
G-6+  注册表一致性检查：crates/crypto/src/domain.rs 的枚举/取值
      必须与 ADR-0005 注册表逐项一致；任何不一致 ⇒ 构建/审查阶段即失败。
G-9   哈希域与签名域命名空间分离（对应 Option C-1/C-3，需独立 ADR）。
```

---

## 13. Open Questions（**不得静默回答**）

```text
D-1  Which existing assignment owns 0x07?                     → OWNER DECISION REQUIRED
     （文档侧 ADR-0005/ADR-0043 主张 Contribution；代码侧为 Proposer）
D-2  What is the authoritative registry source?               → 判定结果：ADR-0005（+ADR-0043）
     （治理层面的「是否追认代码」仍 → OWNER DECISION REQUIRED）
D-3  Should Proposer retain a dedicated domain?               → OWNER DECISION REQUIRED
     （当前仅作**哈希域前缀**使用；是否应改由独立的 hash-domain 命名空间承载，见 Option C-1/C-3）
D-4  Which DomainId should RoundChangeCertificate receive?    → OWNER DECISION REQUIRED
     （本 ADR **不**提议数值；**不**自动选择 0x08）
D-5  Does any historical artifact require compatibility handling? → **NO（已证，§8）**
     （唯一影响为测试断言 + proposer 选择确定性；无持久化/链上迁移）
D-6  Does the registry need a permanent reservation/allocation policy? → YES（草案见 §12）
```

---

## 14. Non-Goals

本阶段 **NOT**：

```text
- modify DomainId
- modify AlgorithmId
- modify signing code
- modify build_signed_bytes
- modify ValidatorVote
- implement RoundChangeCertificate
- implement network messages
- modify consensus transitions
- modify timers
- modify locks
- modify finality
- modify ADR-0053
- modify ADR-0049
- modify consensus-spec
- resolve A17
- resolve upgrade compatibility
- resolve Genesis / image / Akash blockers
```

附加边界：本 ADR 亦**不**修改 ADR-0005 / ADR-0009 / ADR-0043 / ADR-0050 / ADR-0066，
**不**创建代码预留，**不**为实现便利而分配任何 `DomainId`。

---

## 15. Consequences

**正面**
- 把 `0x07` 冲突从「隐性事实」提升为**有据可查的正式问题**，并**精确归属**权威（ADR-0005 + ADR-0043）；
- 明确 **O2 实施被注册表决策前置阻塞**，防止冲突扩散到第三处；
- 提供**基于检索的历史兼容性结论**（无签名绑定 `0x07` ⇒ 无迁移需求）；
- 提出**治理规则草案**（G-6+ / G-9）以根治同类事故。

**代价 / 风险**
- 本 ADR **不解决**冲突（Owner 决策前置）；
- 任一选项都需修订 **ADR-0005（FROZEN）** 注册表；
- Option B′（追认代码）需修订 **两个冻结 ADR**，并有**治理先例风险**；
- 决策**必须在 genesis freeze 之前**完成，否则 proposer 确定性变更代价升高。

---

## 16. Validation Plan（**FUTURE**；本阶段不执行）

| 层 | 验证项 |
|---|---|
| 文档 | ADR-0005 注册表与 `crates/crypto/src/domain.rs` **逐项一致**（G-6+） |
| 纯函数 | `DomainId::try_from` 对每个已注册值 ⇔ 唯一枚举；未注册值 ⇒ `Err` |
| 纯函数 | 域唯一性：不存在两个语义共享同一值 |
| 纯函数 | O2 陈述按 ADR-0066 §5 编码；域变更 ⇒ `signed_bytes` 与 `message_hash` 均改变（域隔离测试同构） |
| 兼容 | 既有签名（Transaction/ValidatorVote/Block/Witness）在注册表变更后**仍可验证** |
| 回归 | proposer 选择：**记录**变更前后的 `(h,r) → proposer` 差异（预期存在；不得视为失败） |
| 治理 | 注册表一致性检查可在 CI 中自动失败（G-6+） |

---

## 17. Implementation Prerequisites（**全部为阻塞项**）

```text
P-1  Owner 裁决 D-1 / D-3 / D-4 / D-6
P-2  本 ADR 经 Owner 批准并由 DRAFT → FROZEN            （仍未完成：冻结授权未提供）
P-3  ADR-0005 注册表修订（并同步 ADR-0043 / ADR-0050 措辞）  （✅ 完成：PHASE 6H-D Owner-authorized
                                                           Registry Amendment 已登记 `0x10`；见 §0.7.A #1）
P-4  注册表治理规则（§12）成文                         （✅ 完成：ADR-0069 = FROZEN，2026-10-07）
P-5  测试断言更新（K-10 / K-3）                        （部分完成：PHASE 6H-B2 已更新 DomainId
                                                           fail-closed 边界测试与 0x10 映射测试）
P-6  ADR-0066 的 O2 域分配经批准                       （✅ 完成：PHASE 6H-B2 Owner 批准 `0x10`；
                                                           实现仍 BLOCKED）
```

---

## 18. References

```text
docs/adr/ADR-0005-domain-separation.md                    （Nova Domain Registry；0x07 = Contribution；0x08+ Reserved）
docs/adr/ADR-0009-signature-coverage.md                   （签名字段级覆盖原则；头部 Status = Proposed）
docs/adr/ADR-0010-chain-domain-separation.md              （chain_id 绑定）
docs/adr/ADR-0012-cryptographic-algorithm-registry.md     （AlgorithmId）
docs/adr/ADR-0043-proof-of-contribution-v1.md             （DomainId::Contribution = 0x07，FROZEN）
docs/adr/ADR-0050-proposer-selection-v1.md                （§154/§155/§208：proposed / deferred / 未实现）
docs/adr/ADR-0066-round-change-certificate-v1.md          （O2 需专用域；DRAFT）
docs/adr/ADR-0053-lock-justification-override-v1.md       （L-1..L-12）
crates/crypto/src/domain.rs                               （DomainId / AlgorithmId / build_signed_bytes —— 权威代码位置）
crates/consensus/src/proposer.rs                          （ProposerSeedInput；DomainId::Proposer 唯一生产用途）
crates/consensus/src/finality.rs                          （verify_qc；evidence 重建为 ValidatorVote）
crates/network/src/message.rs                             （MessageType —— **独立**命名空间）
```

---

## 19. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-06 | **ADR-0067 初稿（DRAFT — NOT FROZEN）**：Domain Registry Amendment — Dedicated RoundChangeCertificate Signing Domain。记录 `0x07` 冲突（ADR-0005/ADR-0043 vs 代码/ADR-0050 proposal）、判定注册表权威、列举选项与影响、给出治理规则草案与 Open Questions。**未分配任何 DomainId**；**未修改任何既有 ADR / 源码 / 测试 / consensus-spec** | Owner 授权 PHASE 6D — ADR DRAFT ONLY |
| 2026-10-06 | **新增 §0 OWNER-APPROVED RESOLUTION**：记录 PHASE 6F 批准的 D1（`0x07 = Contribution`）、D2（Proposer → 独立哈希域命名空间 C-1，保留前缀字节 `0x07`）、D3（O2 仍 `NOT YET ALLOCATED`）、D4（采纳唯一域分配规则）。同步记录 PHASE 6G-A 的实施结果与 ADR-0068 的引用关系。**本 ADR 仍为 DRAFT — NOT FROZEN** | Owner 授权 PHASE 6G-A — CONTROLLED IMPLEMENTATION |
| 2026-10-07 | **治理闭合（PHASE 6G-C）**：新增 §0.4（记录 PHASE 6G-C 的 D1/D2 批准、ADR-0068 已冻结、ADR-0049 文档修正已应用、O2 仍 UNALLOCATED）与 §0.5（**本 ADR 冻结授权未提供 ⇒ 保持 DRAFT — NOT FROZEN**）。**未**重新设计正文；**未**分配 O2 numeric DomainId | Owner 授权 PHASE 6G-C — GOVERNANCE CLOSURE |
| 2026-10-07 | **PHASE 6H-B2 — O2 DomainId `0x10` 登记**：新增 §0.6 ALLOCATION RECORD（`0x10 = RoundChangeCertificate`；Authority = Owner-approved；Allocation rule = ADR-0069；Collision audit = PHASE 6H-B1）；§3 注册表表更新（`0x10` = ALLOCATED；`0x08`–`0x0F` 保持 Reserved；`0x07` = RESOLVED）；§6 数值状态更新；§17 P-6 完成；修正 §0.1 中陈旧的「ADR-0068 DRAFT」文字（纯文档一致性）；§1.1/§1.2 加 PHASE 6D 快照声明。**保留不变**：`0x07 = Contribution` · `0x08`–`0x0F` Reserved · HashDomain 命名空间 · MessageType 注册表（**不**并入）。**本 ADR 仍为 DRAFT — NOT FROZEN**；**未**修改 ADR-0005（受保护 ⇒ 见表体不一致记录） | Owner 授权 PHASE 6H-B2 — CONTROLLED GOVERNANCE IMPLEMENTATION |
| 2026-10-07 | **PHASE 6H-G — Cleanup + Freeze Preparation（Owner 授权 D10）**：新增 §0.7（A. 陈旧标记状态映射表，6 项，**原文全部保留、不删不改**；B. Freeze Preparation Checklist）。**本 ADR 仍为 DRAFT — NOT FROZEN**；**未**冻结、**未**删除任何历史记录、**未**修改其他 ADR / 代码 / Genesis / Akash | Owner 授权 PHASE 6H-F D10 —— AUTHORIZE CLEANUP + FREEZE PREPARATION ONLY |
| 2026-10-07 | **PHASE 6H-L — 最小治理同步（Owner 授权 C）**：新增 §20 Governance Synchronization Record（治理交叉引用 / 前置条件状态同步）；§17 P-3 状态更新为 ✅ 完成（PHASE 6H-D Registry Amendment 已登记 `0x10`）、P-4 状态更新为 ✅ 完成（ADR-0069 = FROZEN）。**未改变**：registry semantics · DomainId 取值 · `0x10` 分配 · ADR-0005 Status · ADR-0068 内容；**未**重新分配任何 DomainId。**本 ADR 仍为 DRAFT — NOT FROZEN**；**未**修改任何 Rust / 代码 / Genesis / Akash | Owner 授权 PHASE 6H-K C（PHASE 6H-L 执行）—— MINIMAL GOVERNANCE CROSS-REFERENCE / STATUS SYNCHRONIZATION ONLY |

---

## 20. Governance Synchronization Record（PHASE 6H-L，2026-10-07）

> 本节由 **PHASE 6H-L**（Owner 授权 C）新增，仅记录**治理交叉引用 / 前置条件状态同步**。
> **未改变**：registry semantics · DomainId 取值 · `0x10` 分配 · ADR-0005 Status · ADR-0068 内容。
> **未**重新分配任何 DomainId。本 ADR 仍为 **DRAFT**（§0.5 不变）。

```text
同步项（PHASE 6H-L）
  1. ADR-0069 = FROZEN（2026-10-07，Owner D11 / PHASE 6H-F）          ⇒ §17 P-4 更新为 ✅ 完成
  2. PHASE 6H-D 已完成 ADR-0005 Registry Amendment（`0x10` 登记）      ⇒ §17 P-3 更新为 ✅ 完成
  3. O2 `0x10 = RoundChangeCertificate` allocation governance 完成      ⇒ §3 / §6 记录保持不变
  4. 关联 ADR 当前治理状态（只读交叉引用，不修改）：
       ADR-0070 = DRAFT + OWNER APPROVED DESIGN（21 / 2066；PHASE 6H-J 批准）
       ADR-0071 = DRAFT + OWNER APPROVED DECISIONS（O-1..O-8；PHASE 6H-J 批准）
       ADR-0066 = DRAFT / NOT FROZEN（未修改）
       ADR-0049 = UNCHANGED（未修改）
```

```text
未变（MUST）
  ADR-0005 Status              = Proposed（待批准）
  DomainId registry semantics  = 不变
  0x10 = RoundChangeCertificate = 不变（已分配）
  ADR-0068 内容                = 不变
  DomainId 重新分配            = 无
```

```text
ADR-0067 FREEZE AUTHORIZATION = NOT PROVIDED（本 ADR 仍为 DRAFT — NOT FROZEN）
```
