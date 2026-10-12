# ADR-0068: Hash Domain Namespace V1

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；PHASE 6G-C —— **Owner 授权 D3**。
  本 ADR 正式冻结其技术内容；**不**修改任何既有 ADR。）
- **Date**: 2026-10-06
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: STEP 6G-A — 建立**哈希域**（Hash Domain）独立命名空间；把 proposer 选择的哈希域前缀
  从签名域枚举 `DomainId` 中分离。
- **Phase provenance**: PHASE 4/6（`0x07` 冲突识别）→ PHASE 6B/6D（O2 专用域、注册表修正草案）→
  PHASE 6E（Owner 决策评审）→ **PHASE 6F（Owner 暂定批准：D1/D2）** → **PHASE 6G-A（本 ADR + C-1 实施）**
- **关联（只读引用，不修改）**: ADR-0005（Nova Domain Registry）· ADR-0009（Signature Coverage）·
  ADR-0012（Algorithm Registry）· ADR-0043（`DomainId::Contribution = 0x07`，FROZEN）·
  ADR-0049 §3.7（Proposer seed 域分离，FROZEN）· **ADR-0050 §13/§20（proposer seed 57B 布局，FROZEN）** ·
  ADR-0066（RoundChangeCertificate，DRAFT）· **ADR-0067（Domain Registry Amendment，DRAFT）**
- **治理状态（已闭合）**：C-1 的代码实现已于 **PHASE 6G-A** 经 Owner 授权完成；本 ADR 于 **2026-10-07**
  由 **Owner 授权 D3（PHASE 6G-C）正式冻结** ⇒ 先前的「已实现 / 未冻结」状态不对称**已消除**。
  **技术内容自 PHASE 6G-A 起未作任何变更**。

---

## 1. Context

PHASE 4–6 确认了 `DomainId = 0x07` 的注册表冲突：

```text
ADR-0005 注册表 + ADR-0043（FROZEN） : 0x07 = Contribution
代码 crates/crypto/src/domain.rs      : 0x07 = Proposer
ADR-0050 自述                          : Proposer 注册为 PROPOSED / deferred；
                                       且明文 "crates/crypto/src/domain.rs 未实现，不改"
```

PHASE 6B 的源码复核发现根因不仅是「数值被占用」，而是**两种不同用途共用一个命名空间**：

```text
签名用途（真正需要 DomainId）:
    build_signed_bytes(algorithm_id, domain_id: DomainId, chain_id, payload)
    ⇒ domain_id 进入 signed_bytes，决定【签名消息身份】

哈希用途（并不需要 DomainId）:
    proposer_seed_input: out[0] = DomainId::Proposer.as_u8()
    ⇒ 该字节进入协议【哈希输入】ProposerSeedInput，从不参与任何签名
```

对照事实证明该混用是**个例**而非设计：

```text
witness_seed(prev_finality_reference, height) = protocol_hash(prev_finality_reference ‖ height)
deterministic_select: rank = SHA-256(seed ‖ validator_id)
⇒ witness 侧的哈希域【不使用】DomainId
⇒ ProposerSeed 是全仓库【唯一】借用签名域枚举的哈希域
```

PHASE 6E 的 Owner 决策（PHASE 6F 记录）选择：

```text
D1  0x07 = Contribution（保留冻结注册表分配）
D2  Proposer 采用 C-1：分离哈希域命名空间，并【保留取值 0x07】
```

---

## 2. Problem

```text
1. 0x07 被两个语义同时主张 ⇒ 域分离契约（ADR-0005 / ADR-0009）被破坏。
2. 由于签名域枚举被用作哈希域，【类型系统无法阻止】混淆。
3. 若直接把 Proposer 迁到另一个【签名域】取值，会【改变】proposer 种子前缀
   ⇒ 改变 (height, round) → proposer 序列 ⇒ 对确定性与未来 genesis 产生不必要影响。
4. 若保留 DomainId::Proposer = 0x07，则保护了种子兼容性，但注册表冲突依旧。
⇒ 需要一种【同时】满足「注册表一致」「种子逐字节不变」「类型可强制隔离」的方案。
```

---

## 3. Decision（**DRAFT**）

### HD-1 — HashDomain 与 DomainId 是**分离的命名空间**

```text
HashDomain != DomainId
```

### HD-2 — `DomainId` 是**签名域**命名空间

`DomainId` 只描述 `build_signed_bytes` 的 `domain_id`，即**协议签名消息身份**的域分隔。
`DomainId` **MUST NOT** 再被用于任何哈希用途。

**注册表修复（由 ADR-0067 承载）**：

```text
DomainId::Contribution = 0x07      （恢复 ADR-0005 注册表 + ADR-0043 FROZEN 分配）
DomainId::Proposer                 （不再是活跃签名域变体；已移除）
```
**未新增**任何签名域变体；**未**为 Proposer 另分配签名域数值。

### HD-3 — `HashDomain` 是**哈希 / 协议输入**命名空间

`HashDomain` 只用于**协议哈希输入**的前缀，例如确定性 proposer 选择的种子。
它**不参与任何签名**，**MUST NOT** 进入 `build_signed_bytes`。

### HD-4 — `HashDomain` 与 `DomainId` 是**不同的 Rust 类型**

```rust
pub enum DomainId { … }        // crates/crypto/src/domain.rs
pub enum HashDomain { … }      // crates/crypto/src/hash_domain.rs
```
**禁止**任何 `type HashDomain = DomainId;` 之类的别名，**禁止**继承式/包装式同构。

### HD-5 — 两者之间**无隐式转换**

**MUST NOT** 实现：

```text
From<HashDomain> for DomainId
From<DomainId> for HashDomain
Into<DomainId> / Into<HashDomain>
Deref / DerefMut
impl Into<DomainId> 形参泛化
```

显式 `as_u8()` 是可接受的（协议输入需要一个字节），但它**不**提供跨类型转换。
本约束通过模块级 **`compile_fail` doctest** 机器校验（见 `hash_domain.rs`）。

### HD-6 — `HashDomain::Proposer = 0x07`

语义：**确定性 proposer 选择的哈希域前缀**（`ProposerSeedInput[0]`）。
**不是**签名域。

### HD-7 — 本 ADR **保持既有 proposer 种子字节**

```text
old: DomainId::Proposer.as_u8()   = 0x07
new: HashDomain::Proposer.as_u8() = 0x07
⇒ ProposerSeedInput（57B）逐字节不变
⇒ ProposerSeed 不变
⇒ 确定性 proposer 序列不变
```
由回归测试 `proposer::tests::hash_domain_migration_preserves_seed_input_bytes` 与
ADR-0050 §33 的 **golden vector** 测试共同举证。

### HD-8 — 本 ADR **不**使 `0x07` 成为「第二个签名域」

`0x07` 在**签名域**命名空间中**仅**表示 `Contribution`（ADR-0005/ADR-0043）。
`HashDomain::Proposer = 0x07` 属于**另一命名空间**，且其字节从不进入 `signed_bytes`
⇒ 不构成第二个签名域。

### HD-9 — 未知 / 未分配 HashDomain 取值**必须拒绝**

与 `DomainId` 相同的 fail-closed 哲学：`HashDomain::try_from(v)`
对未注册 `v` 返回 `Err(HashDomainError::UnknownHashDomain(v))`，**禁止 fallback**。

### HD-10 — 新增 HashDomain **需要显式注册表治理**

新增取值 **MUST** 经 Owner 批准的注册表流程登记（本条与 ADR-0067 的 `DomainId` 分配规则**同构但独立**）；
**MUST NOT** 通过代码直接占用未登记取值。

### HD-11 — 分配 HashDomain **不**自动分配 `DomainId`

反之亦然。两个命名空间的分配是**彼此独立**的治理行为。

### HD-12 — 其它数值命名空间**彼此独立**，不得混淆

```text
DomainId            （密码签名域）
HashDomain          （本 ADR）
MessageType         （网络消息类型 —— 例如 Status = 0x07、ConsensusVote = 0x08）
storage magic       （例如 BLOCK_FILE_MAGIC = 0x07）
```
**MUST NOT** 在这些命名空间之间互相顶替或互推取值。

### HD-13 — **不**改变 canonical 签名格式

```text
algorithm_id ‖ domain_id ‖ chain_id(8B LE) ‖ payload_length(4B LE) ‖ payload
```
**完全不变**；`build_signed_bytes` 的签名**不变**（其形参仍为 `DomainId`，不使用 `impl Into`）。

### HD-14 — **不**改变 consensus finality 语义

本 ADR 不触及 QC / PrevoteQC / PrecommitQC / finality / lock / pacemaker / 网络协议。

### HD-15 — **不**改变 O2 `RoundChangeCertificate` 的域分配

O2 仍需**独立**的**签名** `DomainId`（ADR-0066 RC-5；由 ADR-0067 承载分配流程）。

```text
O2 numeric DomainId = NOT YET ALLOCATED
```

---

## 4. 实施记录（PHASE 6G-A）

| 项 | 内容 |
|---|---|
| 新增文件 | `crates/crypto/src/hash_domain.rs`（`HashDomain` / `HashDomainError`） |
| 修改文件 | `crates/crypto/src/lib.rs`（`pub mod hash_domain;`） |
| 修改文件 | `crates/crypto/src/domain.rs`（`Proposer` → `Contribution = 0x07`；`try_from`；2 个测试） |
| 修改文件 | `crates/consensus/src/proposer.rs`（改用 `HashDomain::Proposer`；文档/测试；新增兼容回归） |
| 未触碰 | `build_signed_bytes` / `ValidatorVote` / `Block` / `Witness` / `Transaction` 签名域 / QC / finality / 网络 / Genesis / A30 |

**兼容性举证**：

```text
HashDomain::Proposer                = 0x07
ProposerSeedInput 长度               = 57 → 57
ProposerSeedInput 字节              = BYTE-FOR-BYTE UNCHANGED
ProposerSeed                        = UNCHANGED
Deterministic proposer sequence     = UNCHANGED
```

---

## 5. 域名分配状态

| 命名空间 | 取值 | 状态 |
|---|---|---|
| `DomainId` | `0x07 = Contribution` | **已恢复**（ADR-0005 / ADR-0043 一致） |
| `DomainId` | （原 Proposer） | **已移除**（不再是签名域变体） |
| `HashDomain` | `0x07 = Proposer`（哈希域前缀） | **已实现**（本 ADR） |
| `DomainId` | O2 `RoundChangeCertificate` | **NOT YET ALLOCATED**（待 ADR-0067 完成分配流程） |

---

## 6. Open Questions

```text
H-1  ✅ RESOLVED（2026-10-07，PHASE 6G-C D3）：本 ADR 已冻结，状态不对称已消除
H-2  HashDomain 注册表应位于何处（本 ADR 内表 vs 独立 registry 文档）
H-3  是否应把 witness 侧哈希输入（当前【无域前缀】）也纳入 HashDomain 命名空间评审
H-4  HashDomain 是否需要与 DomainId 相同的「预留 / 不得静默分配」成文规则
H-5  ADR-0049 §3.7 中的 `DomainId::Proposer` 标识符为 FROZEN 文本引用，
     是否需要单独的 ADR 修订授权（本阶段**未**修改 ADR-0049）
```

---

## 7. Non-Goals

```text
NOT: 修改 DomainId 注册表以外的任何签名域 · 修改签名格式 · 修改 QC/finality/lock ·
     实现 O2 · 分配任何 O2 DomainId · 修改网络协议 / MessageType · 修改 Genesis ·
     重新设计 proposer selection 算法 · 修改 ProposerSeedInput 布局
```

---

## 8. References

```text
docs/adr/ADR-0005-domain-separation.md          （Nova Domain Registry；0x07 = Contribution；0x08+ Reserved）
docs/adr/ADR-0009-signature-coverage.md         （签名字段级覆盖原则）
docs/adr/ADR-0043-proof-of-contribution-v1.md   （DomainId::Contribution = 0x07，FROZEN）
docs/adr/ADR-0049-liveness-pacemaker-v1.md      （§3.7 proposer seed 域分离；§10 DomainId::Proposer = future ADR）
docs/adr/ADR-0050-proposer-selection-v1.md      （§13/§20 proposer seed 57B 布局，FROZEN）
docs/adr/ADR-0066-round-change-certificate-v1.md（O2 需独立签名域；DRAFT）
docs/adr/ADR-0067-domain-registry-amendment-v1.md（DomainId 注册表修正；DRAFT）
crates/crypto/src/hash_domain.rs                （HashDomain 实现）
crates/crypto/src/domain.rs                     （DomainId = 签名域命名空间）
crates/consensus/src/proposer.rs                （ProposerSeedInput 使用 HashDomain::Proposer）
```

---

## 9. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-06 | **ADR-0068 初稿（DRAFT — NOT FROZEN）**：建立 HashDomain 独立命名空间；`HashDomain::Proposer = 0x07`；`DomainId` 回归签名域语义（`0x07 = Contribution`）；proposer seed **逐字节不变**。同时记录 C-1 的代码实现（PHASE 6G-A）。**未修改** ADR-0005 / ADR-0043 / ADR-0049 / ADR-0053 / ADR-0066 / consensus-spec | Owner 授权 PHASE 6G-A — CONTROLLED IMPLEMENTATION |
| 2026-10-07 | **FREEZE EXECUTION（PHASE 6G-C；Owner 授权 D3）**：Status `DRAFT — NOT FROZEN` → **FROZEN**。仅更新 status/header、治理状态说明（状态不对称已消除）、§6 H-1（RESOLVED）与本变更记录。**技术内容自 PHASE 6G-A 起未作任何变更**：`HashDomain::Proposer = 0x07` · C-1 · 57B proposer seed 兼容性 · `DomainId` 命名空间 · `build_signed_bytes` · canonical signing bytes **全部不变**；**未**分配 O2 domain | Owner 授权 PHASE 6G-C — D3 APPROVE ADR-0068 READY FOR FREEZE |
