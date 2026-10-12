# ADR-0069: Signing Domain Allocation Governance v1

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；**Owner 授权 D11 — PHASE 6H-F Decision Gate**）
  （本 ADR 的技术与治理内容已冻结。**不构成协议修订**、**不授权任何实现**、
  **不修改任何既有 ADR**。**冻结 ≠ 实现授权**：O2 实现仍为 **BLOCKED**。）
- **Date**: 2026-10-07
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: 治理（governance only）—— 定义「新增 **signing `DomainId`**」的唯一合法流程、
  唯一性审计要求、命名空间边界、冻结分配保护、fail-closed 要求与 pre-freeze 要求。
- **Phase provenance**: PHASE 4/6（`0x07` 冲突识别）→ PHASE 6B/6C（O2 规格 + ADR-0066 草案）→
  PHASE 6E/6F（Owner 决策评审）→ PHASE 6G-A/B/C（C-1 实施 + 治理闭合）→
  **PHASE 6H（O2 最终 Owner Review；D1 方向 = 先立分配治理，数值继续 UNALLOCATED）** →
  **PHASE 6H-A（本 ADR 草案）**
- **关联（只读引用，不修改）**: ADR-0005（Nova Domain Registry）· ADR-0009（Signature Coverage）·
  ADR-0012（Algorithm Registry）· ADR-0043（`DomainId::Contribution = 0x07`，FROZEN）·
  ADR-0050（Proposer Selection，FROZEN）· ADR-0053（Lock Justification，FROZEN）·
  ADR-0066（RoundChangeCertificate，DRAFT）· ADR-0067（Domain Registry Amendment，DRAFT）·
  ADR-0068（Hash Domain Namespace，FROZEN）· `docs/protocols/consensus-spec-v1.md`
- **非授权声明（MUST 逐字保留；**PHASE 6H-A 时点的原始声明**）**:

```text
O2 numeric DomainId is intentionally NOT allocated by this ADR.
```

> **更新（PHASE 6H-B2，2026-10-07）**：Owner 已**明确批准** `0x10 = RoundChangeCertificate`。
> 该数值由 **Owner 决策**分配（**非**本 ADR 自行分配），本 ADR 仅新增 **§2.1 Allocation Record** 予以登记。

```text
This ADR does not authorize O2 implementation.
```

---

## 1. Status

```text
Status = FROZEN（2026-10-07）
```

- 本 ADR 已于 **2026-10-07** 由 **Owner 授权 D11（PHASE 6H-F）正式冻结**；Rule A–I 成为生效治理。
- **冻结范围**：Rule A–I · §6 注册表 · §7 命名空间分离 · §9 17 步审计清单 · §2.1 Allocation Record。
- **冻结 ≠ 实现授权**：`This ADR does not authorize O2 implementation.`（仍成立）。
- **PHASE 6H-B2**：新增 **§2.1 Allocation Record**（Owner 批准的 `0x10`）。
- 本 ADR **不**修改 ADR-0005 / ADR-0043 / ADR-0050 / ADR-0053 / ADR-0066 / ADR-0068 /
  consensus-spec-v1 / 任何 Rust 源码 / 任何测试 / Genesis / Akash。
- 本 ADR **不**分配任何 `DomainId`，**不**添加任何枚举变体，**不**添加任何 `MessageType`。

## 2. Owner / Governance State

| 项 | 状态 |
|---|---|
| 本 ADR 冻结授权 | **NOT PROVIDED**（需 Owner 明确批准） |
| O2 numeric `DomainId` | **`0x10` = RoundChangeCertificate**（Owner 批准 PHASE 6H-B2；见 §2.1） |
| O2 实现 | **NOT AUTHORIZED**（仍为 BLOCKED） |
| ADR-0067 状态 | **DRAFT — NOT FROZEN**（本 ADR 不冻结它） |
| ADR-0068 状态 | **FROZEN**（2026-10-07；本 ADR 不改动它） |

PHASE 6H 的 Owner 方向（本 ADR 的授权来源）：

```text
D1 = 不自动分配 0x08；先建立明确的 Domain allocation governance rule；
     O2 numeric DomainId 继续保持 UNALLOCATED，直到 Owner 明确批准具体数值。
D2 = Approve ADR-0066 S1            （签署陈述语义）
D3 = Approve ceil(2T/3)             （阈值）
D4 = Approve current evidence model （evidence 模型）
D5 = Approve S1 / no new journal    （持久化）
D6 = ADR-0067 KEEP DRAFT
D7 = O2 implementation BLOCKED
```

> **边界声明**：D2–D5 的批准**仅**表示 O2 **设计**被接受，**不**授权实现；
> D7 明确 O2 实现仍为 **BLOCKED**。本 ADR **只**处理 D1 所涉的**分配治理**。

### 2.1 Allocation Record — O2 DomainId `0x10`（PHASE 6H-B2，Owner 批准）

> 本节记录一次**已完成的**分配。它**不**使本 ADR 生效、**不**冻结本 ADR、**不**授权 O2 实现。

```text
ALLOCATION RECORD

Allocated DomainId  = 0x10
Purpose             = RoundChangeCertificate（O2 / Abandon attestation 专用【签名】域）
Authority           = Owner-approved（PHASE 6H-B2，2026-10-07）
Date                = 2026-10-07
Previous status     = Reserved（ADR-0005：`0x08+` = Reserved / 未注册）
Allocation method   = Explicit governance（**非** max+1 自动分配；符合 Rule A/B）
Collision audit     = PHASE 6H-B1（全仓库按命名空间分类；实际冲突 = 0）
Allocation rule     = ADR-0069（本 ADR）
Registry record     = ADR-0067 §0.6（登记）
Code                = crates/crypto/src/domain.rs（DomainId::RoundChangeCertificate = 0x10）
```

```text
O2 implementation = NOT AUTHORIZED BY THIS ADR
```

**保留不变（MUST）**：`0x07 = Contribution` · `0x08`–`0x0F` = Reserved · `0x11+` = Reserved/Unknown ·
`HashDomain::Proposer = 0x07`（独立命名空间）· `MessageType 0x08–0x0B`（独立命名空间，**不**并入）。

**未触碰**：`docs/adr/ADR-0005-domain-separation.md`（受保护）仍书 `0x08+ = Reserved`
⇒ 注册表表体同步 = **DOCUMENTATION FOLLOW-UP REQUIRED**（见 ADR-0067 §0.6）。

## 3. Context

### 3.1 实际发生过的一次分配缺陷（事实记录）

```text
ADR-0005 注册表 + ADR-0043（FROZEN） : 0x07 = Contribution
代码 crates/crypto/src/domain.rs      : 0x07 = Proposer            ← 未获授权的注册表变更
ADR-0050 自述                          : Proposer 注册 = PROPOSED / pending
                                        （"crates/crypto/src/domain.rs 未实现，不改"）
```

该缺陷的性质**不是**「数值被占用」，而是：

```text
(a) 一个【未被授权的】签名域取值进入了生产代码；
(b) 该取值同时与一个【已 FROZEN 的注册表分配】冲突；
(c) 冲突在数个月后的 PHASE 4/6 审计才被发现；
(d) 当时【不存在】任何成文规则说明「谁、在什么条件下、按什么流程可以分配 DomainId」。
```

PHASE 6G-A/C 通过 C-1（独立 `HashDomain` 命名空间）修复了代码与注册表；
PHASE 6H-A（本 ADR）处理**剩余的治理缺口**：把「分配流程」写成规则。

### 3.2 触发本 ADR 的具体议题

O2（`RoundChangeCertificate` / Abandon attestation）**需要一个专用签名域**：

```text
ADR-0066 RC-5 : A dedicated DomainId is REQUIRED.
                ValidatorVote domain MUST NOT be reused.
                Reserved 0x08+ values MUST NOT be silently allocated.
                状态 = BLOCKED / REQUIRES SEPARATE ADR
```

⇒ 必须回答：**未来 O2（以及任何新域）应当如何合法地取得一个唯一、专用、可审计的 `DomainId`？**

## 4. Problem

```text
1. 无成文分配规则 ⇒ 任何人都可能「顺手」占用一个未注册取值（已发生过一次）。
2. 「当前最大值 + 1」是诱惑性的错误启发式 ⇒ 会把 Reserved 区间当作可用区间。
3. 存在【多个独立数值命名空间】⇒ 「数值相同」被误读为「冲突」，
   或反向被用于「反正数值一样，那就复用吧」。
4. 已 FROZEN 的分配没有显式的保护条款。
5. 未知取值若不做 fail-closed，会静默退化为「默认域」。
6. 分配时机与 Genesis / Testnet 冻结的关系未定义。
7. 分配 provenance（依据、审计、批准者）没有可追溯载体。
```

## 5. Scope

### 5.1 In Scope

```text
· 新增【signing】DomainId（进入 build_signed_bytes 的域）的完整流程
· 唯一性 / 非复用 / 非重新编号的证明义务
· 命名空间边界（DomainId vs HashDomain vs MessageType vs AlgorithmId vs 存储 magic）
· 冻结分配保护
· fail-closed 要求
· ADR 要求 + Owner 批准要求
· pre-freeze（Genesis / Testnet / protocol freeze）要求
· 分配 provenance 与全仓库审计清单
· O2 在本规则下的**申请形态**（不含数值）
```

### 5.2 Non-Scope

```text
NOT: 分配 O2 的具体数值 · 实现 O2 · 修改 DomainId enum · 修改 HashDomain ·
     新增 MessageType · 修改 QC / finality / lock / pacemaker / timer / sync /
     network · 修改 Genesis · 修改 Akash · 冻结 ADR-0067 · 修改 ADR-0005 / ADR-0043 /
     ADR-0050 / ADR-0053 / ADR-0066 / ADR-0068 / consensus-spec-v1
```

## 6. DomainId Registry（as of 2026-10-07，已核实）

> 数值与语义均取自仓库实际内容（`crates/crypto/src/domain.rs` + ADR-0005 + ADR-0043 + ADR-0068）。

| `DomainId` | 语义 | Authority | 代码状态 |
|---|---|---|---|
| `0x01` | Transaction | ADR-0005 注册表；ADR-0009 §1 | 已实现 |
| `0x02` | ValidatorVote | ADR-0005；ADR-0034 / ADR-0038 | 已实现（V-5 验签路径） |
| `0x03` | Block | ADR-0005；ADR-0009 §3 | 已实现 |
| `0x04` | Governance | ADR-0005；ADR-0009 §4 | 已定义；未发现生产调用点 |
| `0x05` | Address | ADR-0005；ADR-0004 | 已定义；未发现生产调用点 |
| `0x06` | Witness | ADR-0005；ADR-0036 W-5（FROZEN） | 已实现（`consensus/witness.rs`） |
| `0x07` | Contribution | ADR-0005 注册表 + **ADR-0043（FROZEN）** | 已实现（`DomainId::Contribution`） |
| `0x00` | —（未注册） | ADR-0005：「Reserved / 未注册 ⇒ 必须拒绝」 | 代码拒绝 + 测试断言 |
| `0x08` – `0x0F` | —（未注册） | ADR-0005：「**Reserved / 未注册 ⇒ 必须拒绝**」；「`0x08+` 保留给未来协议域」 | **Reserved / Unallocated**；代码拒绝 + 测试断言 |
| **`0x10`** | **RoundChangeCertificate** | **Owner 批准（PHASE 6H-B2）；本 ADR §2.1 Allocation Record；登记 = ADR-0067 §0.6** | **已实现（registry-level）**：`DomainId::RoundChangeCertificate = 0x10` |
| `0x11+` | —（未注册） | ADR-0005：「Reserved / 未注册 ⇒ 必须拒绝」 | 代码拒绝 + 测试断言 |
| **O2 domain** | RoundChangeCertificate / Abandon attestation | **本 ADR §2.1（登记）** | **ALLOCATED = `0x10`**（实现仍 BLOCKED） |

**关键事实（MUST 记录）**：

```text
截至 PHASE 6H-A：0x08+ 全部 = Reserved；O2 numeric DomainId = UNALLOCATED。
自 PHASE 6H-B2（Owner 批准）：0x10 = RoundChangeCertificate；0x08–0x0F 与 0x11+ 仍为 Reserved。
```

## 7. Namespace Separation

### 7.1 彼此独立的数值命名空间（MUST NOT 互相顶替）

| 命名空间 | 用途 | 消费者 | 示例（现有取值） |
|---|---|---|---|
| **`DomainId`** | **签名域** | `build_signed_bytes(algorithm_id, domain_id, chain_id, payload)` | `0x01`–`0x07` |
| **`HashDomain`** | **协议哈希输入前缀**（不参与签名） | `H(hash_domain_byte ‖ …)`，如 `ProposerSeedInput[0]` | `HashDomain::Proposer = 0x07` |
| **`MessageType`** | **网络消息类型** | 网络 envelope | `Status = 0x07`、`ConsensusVote = 0x08`、`ConsensusProposal = 0x09`、`ConsensusQc = 0x0A`、`GossipBlock = 0x0B` |
| **`AlgorithmId`** | 密码算法 | `build_signed_bytes` 第 1 字节 | `Ed25519 = 0x01` |
| **存储 magic** | 文件/记录标识 | 持久化层 | 例如 `BLOCK_FILE_MAGIC = 0x07` |

### 7.2 规则

```text
· 数值相同【不】自动构成 collision（不同命名空间、不同构造、从不出现在同一编码中）。
· 数值相同【也】【不】构成复用许可 —— 绝不可因「数值一样」而跨命名空间互传。
· 任何 ADR 在引入新取值时【MUST】显式声明其命名空间。
· 跨命名空间的「统一编号」被【明令禁止】（会重新制造 `0x07` 型混淆）。
```

### 7.3 HashDomain 的治理关系

`HashDomain` 的分配规则见 **ADR-0068 HD-9 / HD-10 / HD-11**：

```text
· 新增 HashDomain 同样需要显式治理批准（与 DomainId 规则【同构但独立】）。
· 分配 HashDomain 【不】自动分配 DomainId；反之亦然。
```

本 ADR 的规则 **MUST** 以同构方式适用于 `HashDomain`（未来可将本 ADR 扩展为统一注册表治理）。

### 7.4 MessageType 的治理关系

```text
· 网络消息类型归【网络协议注册表】，与 DomainId 决策【彼此独立】。
· O2 未来若需要网络消息 ⇒ 需要【独立的】MessageType 分配（不得借用 DomainId 决策代替）。
· 现有 MessageType 取值 0x01–0x0B；其与 DomainId 的数值重合【不】构成任何约束关系。
```

## 8. Allocation Rules

### Rule A — No implicit allocation（禁止隐式分配）

```text
MUST NOT allocate a DomainId merely because it is "the next number"
（"当前最大值 + 1"）or "the next free-looking value".
```

禁止的启发式（非穷举）：

```text
× max(existing) + 1
× "0x08 看起来是空的"
× "先写代码，注册表以后再补"
× "与某个其它命名空间数值相同也没关系，反正合法"
× 通过测试/示例代码「顺手」固化一个未注册取值
```

### Rule B — Explicit governance（显式治理）

任何新 signing `DomainId` **MUST** 同时具备：

```text
1. 明确用途（该域保护哪一类签名消息身份）
2. 独立设计依据（引用的设计 ADR / 规格）
3. 唯一性审计（见 §9）
4. Owner approval（见 §13）
5. 正式 ADR / Registry Amendment（见 §12）
6. provenance 记录（见 §9.3）
```

### Rule C — Frozen assignment protection（冻结分配保护）

```text
已 FROZEN 的 DomainId：
  MUST NOT 重新编号
  MUST NOT 重新解释（改语义）
  MUST NOT 复用（移作它用）
  MUST NOT 静默删除
```

例外（唯一路径）：**高等级治理流程** —— 需
① Owner 明确授权 ② 独立 ADR ③ 显式迁移/兼容计划 ④ 影响范围审计 ⑤ 回滚方案。
**本 ADR 不触发任何此类流程。**

### Rule D — Namespace separation（命名空间分离）

见 §7。要点复述：

```text
· DomainId / HashDomain / MessageType / AlgorithmId / storage magic 彼此独立。
· 数值相同 ⇒ 既不是 collision，也不是复用许可。
· ADR MUST 声明命名空间。
```

### Rule E — Fail closed（未知取值必须拒绝）

```text
未知 DomainId ⇒ REJECT（返回错误），MUST NOT fallback 到任何默认域。
```

现有实现已满足（作为证据，非本 ADR 的产物）：

```text
crates/crypto/src/domain.rs
  TryFrom<u8> for DomainId : 0x01..=0x07 => Ok(..) ; _ => Err(DomainError::UnknownDomainId(v))
  build_signed_bytes(... domain_id: DomainId ...) -> Result<Vec<u8>, DomainError>
```

新域加入时 **MUST** 保持同一 fail-closed 语义，并 **MUST** 附否定测试（拒绝 `0x00`、
未分配值、`0xff`）。

### Rule F — Pre-freeze requirement（冻结前完成分配）

```text
若某新 signing domain 的签名会出现在【将被冻结的链上工件】中，
该域的正式分配 MUST 在该 network / genesis / protocol freeze【之前】完成。
冻结之后才分配 ⇒ 需额外评估是否需要重签/重新派生，属高成本路径。
```

### Rule G — No reuse / no renumbering / no recycling

```text
· 域被废弃 ⇒ 标记 DEPRECATED，数值【永久保留】，永不回收再分配。
· 域的语义变更 ⇒ 新域（新 ADR），不得原地改义。
· 域的删除 ⇒ 仅标记，不删除（注册表是历史账本）。
```

### Rule H — Auditability（可审计性）

```text
每个分配 MUST 可在仓库内被独立复算与审计（见 §9）。
分配 MUST 有 provenance：ADR 编号 + 注册表行 + 变更记录 + 批准依据 + 日期。
```

### Rule I — Type safety at the signing boundary（签名边界类型安全）

```text
· build_signed_bytes 的 domain_id 形参 MUST 保持【强类型 DomainId】。
· MUST NOT 引入 impl Into<DomainId> / From<HashDomain> / 等价的隐式转换，
  否则会重新打开「哈希域被当作签名域」的缺口。
· MUST 保持编译期隔离举证（现有：hash_domain.rs 模块级 compile_fail doctest）。
```

### 8.9 Owner 提问 → 规则映射（20 项逐条）

| # | 问题 | 结论（规则） |
|---|---|---|
| 1 | 谁可以申请新的 DomainId？ | 任何协议设计方（Nova 架构组）可**提案**；批准权归 **Owner**（§13 / Rule B） |
| 2 | 什么条件下可以申请？ | 存在**新的签名消息身份**需求，且**无法复用**既有域（Rule A/B） |
| 3 | 如何证明不存在 collision？ | 全仓库审计清单（§9）+ 注册表 diff（Rule H） |
| 4 | 如何证明不会复用已有 domain？ | 语义唯一性论证 + 注册表逐行比对（§9.2） |
| 5 | 如何处理 HashDomain namespace？ | 独立；同构但独立规则（§7.3；ADR-0068 HD-9/10/11） |
| 6 | 如何处理 MessageType namespace？ | 独立网络注册表；O2 网络消息需独立 MessageType 分配（§7.4） |
| 7 | 如何处理历史/废弃 domain？ | 标记 `DEPRECATED`，数值**永久保留**，不回收（Rule G） |
| 8 | 是否允许 domain reuse？ | **禁止**（Rule C / Rule G） |
| 9 | 是否允许重新编号？ | **禁止**（Rule C） |
| 10 | 是否允许修改 frozen domain assignments？ | **禁止**，除非高等级治理流程（Rule C 例外条款） |
| 11 | 新 domain 是否必须拥有独立 ADR？ | **必须**（§12 / Rule B） |
| 12 | 新 domain 是否必须在 Genesis/Testnet freeze 前完成？ | **必须**（若进入冻结工件；Rule F / §19 / §20） |
| 13 | 谁最终批准 numeric allocation？ | **Owner**（§13） |
| 14 | 如何记录 allocation provenance？ | ADR + 注册表行 + 变更记录 + 批准依据 + 日期 + SHA256（§9.3） |
| 15 | 如何进行 full repository audit？ | 见 §9.1 的 17 步清单 |
| 16 | 如何处理 future reserved range？ | 保持显式 Reserved 且**代码拒绝**；预留区间如需启用 ⇒ 独立 ADR（Rule A/E/F） |
| 17 | 如何避免「下一个数字自动分配」？ | **Rule A**（明文禁止）+ §9 审计 |
| 18 | 如何处理 numeric collision across independent namespaces？ | **Rule D**（§7）：数值相同 ≠ collision，也 ≠ 复用许可 |
| 19 | 如何保证 `build_signed_bytes` 的 DomainId type safety？ | **Rule I**（强类型形参 + 禁 `impl Into` + `compile_fail` 举证） |
| 20 | 如何保证 unknown values fail closed？ | **Rule E**（`TryFrom` ⇒ `Err`；禁 fallback；附否定测试） |

## 9. Collision Prevention

### 9.1 Full Repository Audit Checklist（17 步，MUST 全部执行并留痕）

```text
 1. 列出 ADR-0005 注册表当前全部已分配取值与其语义。
 2. 列出 crates/crypto/src/domain.rs 的 DomainId 变体与 TryFrom 分支（逐值比对）。
 3. 全仓库搜索 `DomainId::<CandidateName>`（含未跟踪文件）。
 4. 全仓库搜索候选数值字面量（`0xNN`）并逐条分类：
      (a) DomainId 上下文 (b) HashDomain 上下文 (c) MessageType 上下文
      (d) AlgorithmId 上下文 (e) storage magic / 其它 (f) 无关数值
 5. 全仓库搜索 `build_signed_bytes` 的全部调用点，确认候选域未被使用。
 6. 全仓库搜索 `TryFrom<u8> for DomainId` / `DomainId::try_from`，确认分支集合。
 7. 搜索 `HashDomain` 全部取值与 try_from 分支（防跨命名空间占用）。
 8. 搜索 `MessageType` 全部取值（确认数值重合为已知且合法）。
 9. 搜索 `AlgorithmId` 全部取值。
10. 搜索存储 magic / 文件格式常量（防与持久化格式混用）。
11. 搜索测试与 fuzz 目标中的「未注册取值」断言（确认 fail-closed 覆盖）。
12. 搜索 docs/ 中对该数值的历史引用（区分历史叙述与有效分配）。
13. 确认候选数值与【全部】既有分配不同。
14. 确认候选域语义与既有域语义不同（不可复用论证）。
15. 确认不存在跨命名空间的隐式转换（Rule I 举证仍在）。
16. 确认注册表 Authority 一致（ADR-0005 表 + 分配者 ADR + 代码三方一致）。
17. 记录审计结论 + 执行日期 + 执行者 + 探针（命令/模式）。
```

### 9.2 非复用论证（MUST 提供）

```text
MUST 明确写出：候选域保护的签名消息身份是什么，
以及为什么【不能】由 0x01–0x07（或任何既有域）承担。
```

对 O2 而言（仅作为示例，**不含数值**）：

```text
O2 签署的是 Abandon(chain_id, height, from_round) —— 无 target、非 vote、非 finality。
ValidatorVote(0x02) 的 payload 结构含 target / vote_type，语义与 O2 不同；
复用会使 verify_qc 的「重建为 ValidatorVote」路径产生域混淆风险（ADR-0066 §7.2/§17）。
⇒ 必须专用域。
```

### 9.3 Provenance 记录（MUST）

| 记录项 | 载体 |
|---|---|
| 分配依据 ADR | ADR 文件路径 + 章节 |
| 注册表行 | ADR-0005 注册表（未来经 Registry Amendment ADR） |
| 数值 | 分配 ADR 正文（**唯一权威来源**） |
| 语义 | 分配 ADR 正文 |
| 批准者 | Owner（日期 + 阶段标识） |
| 审计结论 | 分配 ADR 的审计章节 |
| 变更记录 | 分配 ADR 的 change log |

## 10. Frozen Assignment Protection

见 Rule C。补充说明：

```text
· FROZEN 的分配（含 `0x07 = Contribution`）其【数值与语义】均为不可变事实。
· 任何「重新解释」尝试 MUST 被拒绝；如确需变更 ⇒ 走 Rule C 例外的高等级流程。
· 历史实现的错误（例如曾经的 `DomainId::Proposer = 0x07`）其正确处理方式是
  【新增独立命名空间 / 新域】，而非复用或篡改既有 FROZEN 分配
  （先例：ADR-0067 + ADR-0068 的 C-1 方案）。
```

## 11. Fail-Closed Behavior

见 Rule E。要求：

```text
· 未知 DomainId ⇒ Err（禁 fallback / 禁默认域）。
· 新增取值 MUST 附【否定测试】：该取值以外的未注册值仍被拒绝。
· 解析路径（decode）MUST 与构造路径使用同一 TryFrom 语义（单源真相）。
```

## 12. ADR Requirement

```text
· 任何新 signing DomainId MUST 由一个或多个【正式 ADR】承载：
    - 协议设计 ADR（该域为何存在、签署什么、验证规则）
    - 注册表分配 ADR / Registry Amendment（数值 + 语义 + 审计 + 批准）
· MUST NOT 通过在既有 ADR 中「顺手写一个数值」完成分配。
· MUST NOT 通过代码注释 / 测试 / 示例完成分配。
· 注册表变更（ADR-0005 的编辑）MUST 由独立的 Registry Amendment ADR 授权。
```

## 13. Owner Approval Requirement

```text
· 最终数值分配权归【Owner】。
· AI / 实现者 / 测试代码 MUST NOT 自行决定数值。
· 缺少 Owner 明确批准 ⇒ 状态保持 UNALLOCATED。
· 批准 MUST 可追溯（阶段标识 + 日期 + 决策编号）。
```

## 14. Pre-Freeze Requirement

见 Rule F。补充：

```text
· 分配时机 MUST 早于对应 network / genesis / protocol freeze。
· 「先冻结、以后再补域」MUST 被视为需要重签/重新派生的高成本路径。
· 尚未冻结的链（当前 Testnet 未冻结）中，分配成本最低，但仍【必须】走完整流程。
```

## 15. O2 Application

### 15.1 O2 用途（申请形态）

```text
Purpose       : RoundChangeCertificate / Abandon attestation
签署陈述      : Abandon(chain_id, height, from_round)   （ADR-0066 RC-4；S1 语义，已获 D2 批准）
审批状态      : 设计已获批准（D2/D3/D4/D5）；实现 BLOCKED（D7）
```

### 15.2 O2 Domain Requirements（逐条）

```text
· dedicated signing domain   ⇒ 是（ADR-0066 RC-5 MUST）
· not ValidatorVote           ⇒ 是（MUST NOT 复用 0x02）
· not HashDomain              ⇒ 是（哈希域不参与签名；ADR-0068 HD-3/HD-15）
· not MessageType             ⇒ 是（网络命名空间，与签名域无关）
· unique                     ⇒ 是（需 §9 审计证明）
· fail-closed                ⇒ 是（Rule E）
· explicitly allocated       ⇒ 是（Rule B；需独立 Allocation ADR + Owner 批准）
```

### 15.3 O2 的申请步骤（本规则下）

```text
Step 1  Owner 批准本 ADR（ADR-0069 → FROZEN）      —— 未完成
Step 2  起草 O2 Domain Allocation ADR（含 §9 审计） —— 未开始
Step 3  Owner 批准【具体数值】                       —— 未开始
Step 4  执行 Registry Amendment（ADR-0005 编辑授权） —— 未开始
Step 5  代码实现（DomainId 变体 + try_from）         —— BLOCKED（D7）
Step 6  O2 协议实现                                  —— BLOCKED（D7）
```

> **本 ADR 不填写任何具体数值。**

## 16. Explicit O2 Unallocated Statement（**PHASE 6H-A 时点**）

> **本节的 UNALLOCATED 声明是 PHASE 6H-A 的原始记录**；其分配状态已由 **PHASE 6H-B2** 更新（见 §2.1）。

```text
[PHASE 6H-A] O2 numeric DomainId is intentionally NOT allocated by this ADR.
[PHASE 6H-A] O2 numeric DomainId = UNALLOCATED.
```

```text
This ADR does not authorize O2 implementation.        ← 仍然成立
```

**PHASE 6H-B2 更新（Owner 批准）**：

```text
O2 numeric DomainId = 0x10 = RoundChangeCertificate
Authority           = Owner-approved（**非**本 ADR 自行分配）
实现状态             = BLOCKED（本 ADR / 本次分配均不授权实现）
```

补充记录：

```text
· 分配（PHASE 6H-B2）仅建立 registry-level numeric identity；未创建签名路径 / certificate / verification。
· 实现仍须等待独立授权（且需 §23 的全部前置条件）。
· 该分配【未】修改 ADR-0005（受保护文件）⇒ 见表体不一致记录（ADR-0067 §0.6）。
```

## 17. 0x08 / MessageType Distinction

**必须保留的事实**：

```text
MessageType::ConsensusVote = 0x08（crates/network/src/message.rs）
MessageType::ConsensusProposal = 0x09
MessageType::ConsensusQc = 0x0A
MessageType::Status = 0x07
MessageType::GossipBlock = 0x0B
```

**命名空间判定**：

```text
MessageType 是【网络命名空间】，与 DomainId 不是同一个注册表。
```

**因此（关键澄清）**：

```text
"DomainId 不能用 0x08"
  × 不能仅因为 MessageType 使用了 0x08（数值相同在跨命名空间下是合法的）

真正的治理理由是：
  ADR-0005 当前明确规定 0x08+ = Reserved / unallocated。
  因此，在没有 Registry Amendment / Owner approval 之前，
  不能把 0x08 作为 DomainId 使用。
```

**最终结论（MUST 逐字保留）**：

```text
0x08 is technically namespace-distinct,
but governance-forbidden until explicitly allocated.
```

历史/分析性提及（**均非分配**）：

```text
0x08 = NOT ALLOCATED（DomainId）   0x09 = NOT ALLOCATED   0x0A = NOT ALLOCATED
```

## 18. Compatibility

```text
· 本 ADR 不改变任何 canonical 签名格式：
    algorithm_id(1B) ‖ domain_id(1B) ‖ chain_id(8B LE) ‖ payload_length(4B LE) ‖ payload
· 本 ADR 不改变 build_signed_bytes 的签名或其强类型形参。
· 本 ADR 不改变 0x01–0x07 的任何语义。
· 本 ADR 不改变 HashDomain / MessageType / AlgorithmId。
· 本 ADR 不改变 QC / finality / lock / pacemaker / timer / sync。
· 本 ADR 不改变任何既有工件编码（ProposalRef 64B / ValidatorVote 185B 等）。
· 本 ADR 不引入新的链上状态。
⇒ 与现有链上工件、节点、测试完全兼容（因为它不改变任何执行路径）。
```

## 19. Genesis Impact

```text
· DomainId 分配【不】进入 Genesis canonical bytes。
  Genesis canonical 编码 = network_id ‖ chain_id ‖ genesis_timestamp ‖
                            validators[] ‖ accounts[] ‖ ProtocolParams ‖ EconomicsParams
  ⇒ 无 DomainId 字段。
· DomainId 分配【不】改变 chain_id / network_id / validator identity /
  validator seed / network seed。
· 只读核查：genesis-image/ 与 docs/testnet / docs/genesis / docs/operations 中
  DomainId / HashDomain / domain_id 命中 = 0。
⇒ Genesis impact = NONE（分配本身）。
```

## 20. Testnet Impact

```text
· 当前 Testnet 尚未 freeze ⇒ 在此窗口内完成分配的成本最低（Rule F）。
· 分配本身不产生链上工件变化 ⇒ 不要求重新生成 Genesis / 不要求重启网络。
· 但【O2 实现】若引入新网络消息 ⇒ 需要版本兼容性审查（见 §21 与 ADR-0066 §15.1）。
⇒ 分配本身对 Testnet 无直接影响；实现另议。
```

## 21. Akash Impact

```text
· 只读结论：
    Domain allocation itself does not change current Akash deployment artifacts.
· 分配不改变：Containerfile / SDL / 部署参数 / 镜像内容 / 种子 / 端口 / 拓扑。
· 但：future O2 implementation may require a new protocol/network message and therefore
    requires version compatibility review.
⇒ Current deployment impact = NONE.
  Future O2 protocol impact  = FUTURE REVIEW ONLY.
```

## 22. Security Considerations

```text
S-1  域分离是防【跨域重放】的核心防线（ADR-0005 / ADR-0009）。
     错误分配 ⇒ 两类消息共用同一签名身份 ⇒ 可构造跨域重放。
S-2  隐式分配（Rule A）是【已被实证】的风险（`0x07` 事件）。
S-3  隐式类型转换（Rule I 禁止项）会在编译期失去「哈希域≠签名域」的保护。
S-4  fail-open（Rule E 违反）会把未知域静默降级为默认域 ⇒ 静默重放面。
S-5  复用 / 重新编号（Rule C/G 违反）会破坏历史签名的可解释性 ⇒ 审计不可复算。
S-6  Reserved 区间若被「反正没人用」地占用 ⇒ 未来协议域无可用空间。
S-7  跨命名空间的「统一编号」倾向（Rule D 违反）会重造 `0x07` 型混淆。
S-8  分配时间过晚（Rule F 违反）⇒ 需重签 / 重新派生 ⇒ 影响已冻结工件。
```

## 23. Future Extension Procedure

### 23.1 新域申请模板（Allocation ADR 最小内容）

```text
1. Purpose                    —— 签署什么消息身份
2. Non-reuse argument         —— 为何不能复用既有域（§9.2）
3. Proposed numeric value     —— 由 Owner 最终批准
4. Namespace declaration      —— 明确是 DomainId（而非 HashDomain / MessageType）
5. Audit result               —— §9.1 的 17 步结论
6. Signing statement encoding —— canonical payload 布局
7. Verification rules         —— 确定性验证（纯函数 / fail-closed）
8. Non-coupling constraints   —— 不得成为 QC / finality / lock override / vote
9. Compatibility              —— 既有工件 / 编码 / 迁移
10. Genesis / Testnet impact  —— 显式 NONE 或迁移计划
11. Pre-freeze confirmation   —— Rule F
12. Provenance                —— 批准者 + 日期 + 阶段
13. Open questions            —— 未决项必须显式列出，禁止实现期静默决定
```

### 23.2 未来统一注册表（可选方向，未决定）

```text
可选：把 DomainId / HashDomain / MessageType / AlgorithmId 的分配规则
      统一到一份 Registry Governance 文档族；
      但各命名空间的【取值空间与批准流程】仍 MUST 保持独立（Rule D）。
```

## 24. Open Questions

```text
G-1  ✅ RESOLVED（2026-10-07，Owner 授权 D11）：本 ADR 已 FROZEN
G-2  是否把 HashDomain / MessageType / AlgorithmId 一并纳入本 ADR 的适用范围（当前仅同构引用）
G-3  是否为「高等级治理流程」（Rule C 例外）单独定义门槛与证据要求
G-4  是否建立机器可校验的注册表（例如单一 source-of-truth 表 + 生成测试），
     以替代人工 §9 审计
G-5  O2 的具体数值（由未来 Allocation ADR 决定；本 ADR 不预判）
G-6  废弃域（DEPRECATED）是否需要独立的 registry 状态字段
G-7  pre-freeze 对「已部署但未冻结」网络的精确定义
```

```text
These MUST NOT be silently decided by implementation.
```

## 25. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-07 | **ADR-0069 初稿（DRAFT — NOT FROZEN）**：Signing Domain Allocation Governance v1。建立 Rule A–I（禁止隐式分配 · 显式治理 · 冻结保护 · 命名空间分离 · fail-closed · pre-freeze · 禁复用/重新编号 · 可审计性 · 签名边界类型安全）+ 17 步全仓库审计清单 + 0x08/MessageType 澄清 + O2 申请形态（**不含数值**）。**未**分配任何 DomainId；**未**修改 ADR-0005 / ADR-0043 / ADR-0050 / ADR-0053 / ADR-0066 / ADR-0068 / consensus-spec / 任何 Rust 源码 / 测试 / Genesis / Akash | Owner 授权 PHASE 6H-A —— DOMAIN ALLOCATION GOVERNANCE ADR DRAFT ONLY |
| 2026-10-07 | **新增 §2.1 Allocation Record（PHASE 6H-B2）**：登记 **Owner 批准**的 `0x10 = RoundChangeCertificate`（Authority = Owner-approved；Previous status = Reserved；Allocation method = Explicit governance；Collision audit = PHASE 6H-B1；**O2 implementation = NOT AUTHORIZED BY THIS ADR**）。同步更新 §1 / §2 表 / §6 注册表 / §6 关键事实 / §16（保留 PHASE 6H-A 原始 UNALLOCATED 声明为历史记录）与本变更记录。**本 ADR 仍为 DRAFT — NOT FROZEN**；**未**修改 `DomainId` 以外任何命名空间；**未**修改 ADR-0005 / ADR-0043 / ADR-0050 / ADR-0053 / ADR-0066 / ADR-0068 / consensus-spec / Genesis / Akash | Owner 授权 PHASE 6H-B2 — CONTROLLED GOVERNANCE IMPLEMENTATION |
| 2026-10-07 | **FREEZE EXECUTION（Owner 授权 D11 — PHASE 6H-F）**：Status `DRAFT — NOT FROZEN` → **FROZEN**。仅更新 Status 头 / §1 / §24 G-1（RESOLVED）与本变更记录。**技术内容未作任何变更**（Rule A–I · §2.1 · §6 注册表 · §7 · §9 全部不变）；**冻结 ≠ 实现授权**：O2 实现仍 **BLOCKED**；**未**修改任何 Rust 源码 / 测试 / ADR-0005 / ADR-0043 / ADR-0050 / ADR-0053 / ADR-0062 / ADR-0066 / ADR-0067 / ADR-0068 / Genesis / Akash | Owner 授权 PHASE 6H-F D11 — AUTHORIZE FREEZE |
