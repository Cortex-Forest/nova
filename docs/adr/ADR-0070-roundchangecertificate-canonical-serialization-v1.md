# ADR-0070: RoundChangeCertificate Canonical Serialization v1

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；**Owner 授权 PHASE 6H-V —— D1 = A**）
  （本文件为 **canonical 规格**。**不构成协议修订**、**不授权实现**、**不修改任何既有 ADR**。
  **冻结 ≠ 实现授权**：codec / test vector / O2 实现仍为 **NOT AUTHORIZED**。）
- **Freeze metadata（PHASE 6H-V）**: D1 = A（FREEZE NOW）· D1-V = V2（test vector = implementation-stage artifact）·
  数值已由 Owner 批准（`21` / `2066`）
- **Date**: 2026-10-07
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: O2 `RoundChangeCertificate` 的 **canonical 容器编码规格**（设计）。
  本 ADR **不**实现 codec，**不**定义 consensus 语义，**不**修改签名框架。
- **Phase provenance**: PHASE 6C（ADR-0066 §5.2 标记 `REQUIRES SEPARATE ADR`）→
  PHASE 6H-E（P-4 = BLOCKED）→ **PHASE 6H-F（Owner D2 = AUTHORIZE CANONICAL SERIALIZATION ADR DRAFT ONLY）**
  → **PHASE 6H-G（本草案）**
- **关联（只读引用，不修改）**: ADR-0005（Nova Domain Registry）· ADR-0009（Signature Coverage）·
  ADR-0012（Algorithm Registry）· ADR-0038（Finality；F-2/F-11/F-12）· ADR-0041（ProposalRef canonical，FROZEN）·
  **ADR-0066（RoundChangeCertificate 设计源，DRAFT）** · ADR-0067（Domain Registry Amendment，DRAFT）·
  **ADR-0069（Signing Domain Allocation Governance，FROZEN）**
- **非授权声明（MUST 保留）**:

```text
This ADR does not authorize any implementation.
It does not authorize RoundChangeCertificate, a codec, signing, verification,
network integration, pacemaker integration, or consensus integration.
```

---

## 1. Status 与授权边界

```text
Status              = FROZEN（2026-10-07；Owner 授权 PHASE 6H-V D1 = A）
实现授权             = NOT GRANTED（冻结 ≠ 实现授权）
数值                 = OWNER APPROVED（max_evidence_count = 21；max_certificate_bytes = 2066；见 §8）
数值冻结             = GRANTED（随本 ADR 冻结生效）
test vector          = IMPLEMENTATION-STAGE ARTIFACT（D1-V = V2；本阶段不生成）
```

> **PHASE 6H-L 治理同步**：原第 3 行曾为 `数值冻结             = NOT GRANTED（max count / max bytes 见 §8，仍需 Owner 决定）`
> （PHASE 6H-G 时点）。该历史状态与迁移记录见 §16 Governance Synchronization Record。

Owner 授权（PHASE 6H-F D2）：

```text
A = AUTHORIZE SERIALIZATION ADR DRAFT
不得实现 codec
不得修改 ADR-0066 / build_signed_bytes / domain.rs / network / consensus
```

本 ADR **未**触碰上述任何文件。

## 2. Context（P-4 缺口，PHASE 6H-E 记录）

PHASE 6H-E 审计结论：`P4_CANONICAL_SERIALIZATION = BLOCKED`。理由：

```text
· ADR-0066 §5.2 仅给出【草案布局】，并自标
  「FUTURE IMPLEMENTATION / REQUIRES SEPARATE ADR」；
· 全仓库无 CertificateCodec / encode_certificate / decode_certificate；
· docs/adr 中无 RoundChangeCertificate serialization ADR；
· 无 test vector。
```

本 ADR 即为该 `REQUIRES SEPARATE ADR` 的**草案载体**（沿用 ADR-0041 先例：先冻结 canonical 规格，再实现）。

## 3. Scope / Non-Scope

### 3.1 In Scope（本 ADR 只定义）

```text
· 签名陈述（Abandon attestation）的 canonical payload 布局（引用 ADR-0066 §5.1）
· 证书容器的 canonical byte 布局（字段顺序 / 宽度 / 长度编码）
· evidence 的 canonical 排序与去重规则
· decode 的畸形 / 截断 / trailing / 计数不一致拒绝规则
· 每个字段的签名覆盖状态
```

### 3.2 Non-Scope（明确排除）

```text
NOT: 实现 codec · 修改 build_signed_bytes · 修改 DomainId / HashDomain / MessageType ·
     定义 consensus 语义 · 定义网络消息 · 定义 retention / gossip · 定义 flood/rate ·
     定义 max count / max bytes 的最终数值 · 修改 ADR-0066 / ADR-0005 / ADR-0043 / ADR-0062
```

## 4. 术语与常量（**引用，不新造**）

| 项 | 来源 | 值 |
|---|---|---|
| `validator_set_id` | ADR-0038 F-11 | `= genesis_hash`（`[u8;32]`） |
| `validator_id` | ADR-0034 V-4 / ADR-0038 F-12 | `SHA-256(consensus_public_key)`（`[u8;32]`） |
| 签名算法 | ADR-0012 | `AlgorithmId::Ed25519 = 0x01` |
| 专用签名域 | ADR-0067 §0.6 / ADR-0005 registry | **`DomainId::RoundChangeCertificate = 0x10`** |
| `payload_length` 语义 | ADR-0005 / ADR-0009 | `u32` LE，= canonical payload 字节数 |

```text
本 ADR 不改变上述任何既有定义。
```

## 5. 签名陈述（Abandon Attestation）canonical payload

**引用 ADR-0066 §5.1（不重新定义，不修改 ADR-0066）**：

```text
signed_bytes =
      algorithm_id(1B)              // 0x01 = Ed25519
    ‖ domain_id(1B)                 // 0x10 = RoundChangeCertificate
    ‖ chain_id(8B LE)
    ‖ payload_length(4B LE)         // 精确 = 16
    ‖ payload

payload =
      height(8B LE)
    ‖ from_round(8B LE)
```

**MUST**：

```text
· payload_length 精确 = 16；拒绝 trailing / 截断 / 超长
· MUST NOT 含 to_round / target / vote_type / source_block_hash / timestamp
· 字段顺序固定，禁止重排
```

```text
本 ADR 不分配/不修改 domain_id；0x10 由 ADR-0005（权威注册表）+ ADR-0067 §0.6 + ADR-0069 承载。
```

## 6. 证书容器 canonical byte 布局（**本 ADR 的核心提案**）

```text
certificate_bytes =
      validator_set_id(32B)
    ‖ height(8B LE)
    ‖ from_round(8B LE)
    ‖ evidence_count(2B LE)                    // 上限 = §8（Owner 决定）
    ‖ evidence[0..n]                           // n = evidence_count
```

**每项 evidence（定长 96B）**：

```text
evidence[i] =
      validator_id(32B)
    ‖ signature(64B)
```

**总长度（派生）**：

```text
len(certificate_bytes) = 32 + 8 + 8 + 2 + (96 × n) = 50 + 96n   （n = evidence_count）
```

**字段表**：

| 字段 | 宽度 | 编码 | 进 signed_bytes | 进 certificate_bytes | Byzantine 可否操纵 |
|---|---|---|---|---|---|
| `validator_set_id` | 32B | 原始 digest | ❌（在每项签名框架外） | ✅ | ❌ |
| `height` | 8B | `u64` LE | ✅（经 payload） | ✅ | ❌ |
| `from_round` | 8B | `u64` LE | ✅（经 payload） | ✅ | ❌ |
| `evidence_count` | 2B | `u16` LE | ❌（容器元数据） | ✅ | 仅可为长度声明（受 §7 校验） |
| `validator_id` | 32B | 原始 digest | ❌（由 pubkey 派生） | ✅ | 仅限自身 |
| `signature` | 64B | Ed25519 原始 | —（产物） | ✅ | 仅限自身 |
| `to_round` | — | **不编码** | ❌ | ❌ | 结构上不可能（派生 = `from_round + 1`） |

**MUST NOT**：编码 `to_round` / `target` / `vote_type` / 任何 pointer / 任何 optional 字段 /
任何 timestamp / 任何 padding 到非定宽。

## 7. Evidence 排序、去重与长度一致性（确定性规则）

```text
1. 排序：evidence MUST 按 validator_id 的【字节升序】（32B 无符号字典序）
         与 ADR-0038 F-12 同纪律；MUST NOT 依赖容器序 / 插入序 / 到达序。
2. 去重：MUST 拒绝任何重复 validator_id（任意两条相等 ⇒ REJECT）。
3. 计数：evidence_count MUST 精确等于实际 evidence 项数；
         MUST 拒绝 count 与长度不符、非精确长度、trailing bytes。
4. 域：每项签名 MUST 使用 DomainId::RoundChangeCertificate = 0x10
      （MUST NOT 复用 DomainId::ValidatorVote = 0x02）。
5. 纯函数：decode/verify MUST 无时钟 / 无随机 / 无 I/O / 无本地策略分支。
```

## 8. Maximum Count / Maximum Bytes（**OWNER APPROVED**）

**本 ADR 不冻结最终数值**（Owner 指令：`Candidate limits may be proposed, but do NOT freeze final
numeric values without a later explicit Owner decision.`）。

> **UPDATE（PHASE 6H-J 批准；PHASE 6H-L 同步，2026-10-07）**：Owner 已批准最终数值
> （`MAX_EVIDENCE_COUNT = 21`；`MAX_CERTIFICATE_BYTES = 2066`）。
> 数值【已批准】，但本 ADR 仍为 **DRAFT — NOT FROZEN**（`APPROVED ≠ FROZEN`）。
> 上方原文（含「不冻结最终数值」措辞）保留为历史记录（PHASE 6H-G 时点）。

**派生上界（仅数学关系，非决策）**：

```text
len = 50 + 96 × n
⇒ n = 0   → 50 B          （无 evidence；必然因阈值不足被 §9 拒绝）
⇒ n = 7   → 722 B
⇒ n = 21  → 2066 B
⇒ n = 100 → 9650 B
⇒ n = 1000 → 96050 B
```

**候选区间（**仅候选，未冻结，需 Owner 明确批准**）**：

| 候选 | max evidence count | 对应 max bytes（含 50B 头） | 备注 |
|---|---|---|---|
| C-1 | **21** | 2066 B | 若 ValidatorSet 上限为 21 的静态集合 —— **SELECTED / OWNER APPROVED（PHASE 6H-J）** |
| C-2 | **100** | 9650 B | 宽裕余量；远小于通用网络上限 1 MiB |
| C-3 | **1024** | 98354 B | 上界宽松；仍 < 1 MiB |

**不可协商的约束（来自既有事实，非本 ADR 新增）**：

```text
· max bytes MUST ≤ 既有通用网络上限 MAX_NETWORK_MESSAGE_PAYLOAD_BYTES（1 MiB，security.rs:41）
  —— 否则新消息类型无法装入现有传输层。
· max count MUST ≤ |ValidatorSet|（否则阈值/去重语义不可满足）。
· 任一候选被选中前，D-2 保持 OPEN。
```

```text
MAX_EVIDENCE_COUNT   = OWNER APPROVED  ⇒ 21
MAX_CERTIFICATE_BYTES = OWNER APPROVED  ⇒ 2066
（历史：PHASE 6H-G 时点为 OWNER DECISION REQUIRED；见 §16）
```

## 9. 与阈值的关系（引用，不重新定义）

```text
Q = ceil(2T/3)（ADR-0066 RC-3，已获 Owner D3 批准）
⇒ 证书可形成当且仅当 Σ voting_weight(evidence) ≥ Q
⇒ 因此 evidence_count 的【实际下界】≥ ΣQ 所需的 validator 数
```

本 ADR **不**改变阈值；**不**定义 verification 流程（归未来实现阶段 + ADR-0066 §6）。

## 10. Malformed / Duplicate Rejection（MUST，可审计）

```text
REJECT：
  · 长度 < 50B
  · 长度 ≠ 50 + 96 × evidence_count（非精确长度）
  · trailing bytes / 截断
  · evidence_count 与实际残留长度不符
  · validator_id 非升序（non-canonical ordering）
  · 重复 validator_id
  · 超出 max count / max bytes（数值见 §8，未冻结）
  · 任一项签名无效 / 域不符 / 未注册 validator
```

**错误分类要求**：拒绝原因 MUST 可区分、可审计（沿用既有 `Applied / Ignored / Rejected` 纪律：
`Ignored` / `Rejected` ⇒ state 与 context 均不变）。

## 11. Test Vector 要求（未来，FUTURE）

```text
未来实现阶段 MUST 提供（本 ADR 不创建）：
· 精确长度向量（n = 0 / 1 / 典型 / 上限）
· 排序负例（乱序）
· 去重负例（重复 validator_id）
· 截断 / trailing / count 不符负例
· 域混淆负例（用 0x02 签名 ⇒ MUST 拒绝）
· 确定性重放（同输入 ⇒ 同字节）
```

**沿用 ADR-0041 先例**：canonical 规格与其向量应在实现前冻结。

## 12. Compatibility

```text
· 不改 canonical 签名框架（algorithm_id ‖ domain_id ‖ chain_id ‖ payload_length ‖ payload）
· 不改 build_signed_bytes 签名 / 语义
· 不改 ValidatorVote 编码（185B 不变）
· 不改 ProposalRef（64B 不变）
· 不改任何既有 ADR
· 不引入链上状态（证书不入 consensus state）
```

## 13. Open Questions（**不得静默回答**）

```text
S-1  ✅ RESOLVED（PHASE 6H-J Owner 批准）：MAX_EVIDENCE_COUNT = 21
S-2  ✅ RESOLVED（PHASE 6H-J Owner 批准）：MAX_CERTIFICATE_BYTES = 2066
S-3  evidence 是否允许「同一 validator 多个 (height, from_round)」—— 本 ADR 假设证书绑定单一
     (height, from_round)，与 ADR-0066 §4.1 一致；若需扩展 ⇒ 新 ADR
S-4  certificate_bytes 是否需要显式 domain 前缀（当前不需要：容器不经 build_signed_bytes；
     域绑定由每项签名提供）
S-5  容器级 checksum 是否需要（当前：不需要，每项签名已提供完整性；若需要 ⇒ 新 ADR）
S-6  与 ADR-0066 §5.2 草案布局的差异确认（本 ADR 的字段顺序与 ADR-0066 §5.2 草案一致）
```

```text
These MUST NOT be silently decided by implementation.
```

## 14. References（只读）

```text
docs/adr/ADR-0005-domain-separation.md                （Nova Domain Registry；0x10 已登记）
docs/adr/ADR-0009-signature-coverage.md               （签名字段级覆盖）
docs/adr/ADR-0012-cryptographic-algorithm-registry.md （AlgorithmId = 0x01）
docs/adr/ADR-0038-finality-architecture-v1.md         （F-2 / F-11 / F-12）
docs/adr/ADR-0041-proposalref-canonical-serialization.md（canonical 规格先行先例）
docs/adr/ADR-0066-round-change-certificate-v1.md      （设计源；§5.1 / §5.2 / §6）
docs/adr/ADR-0067-domain-registry-amendment-v1.md     （§0.6 Allocation Record）
docs/adr/ADR-0069-signing-domain-allocation-governance-v1.md（FROZEN；Rule A–I）
crates/crypto/src/domain.rs                           （DomainId / build_signed_bytes —— 权威代码位置）
crates/network/src/security.rs                        （MAX_NETWORK_MESSAGE_PAYLOAD_BYTES = 1 MiB）
```

## 15. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-07 | **ADR-0070 初稿（DRAFT — NOT FROZEN）**：RoundChangeCertificate Canonical Serialization v1。定义签名陈述 payload（引用 ADR-0066 §5.1）、证书容器布局（`validator_set_id(32) ‖ height(8) ‖ from_round(8) ‖ evidence_count(2) ‖ evidence[96×n]`）、evidence 排序/去重/长度一致性规则、畸形与重复拒绝规则、test vector 要求；`max evidence count` / `max certificate bytes` **保持 OWNER DECISION REQUIRED**（仅提出候选 C-1/C-2/C-3，**未冻结**）。**未**实现 codec；**未**修改 ADR-0066 / build_signed_bytes / domain.rs / network / consensus / 任何既有 ADR / 任何 Rust 源码 | Owner 授权 PHASE 6H-F D2 —— AUTHORIZE CANONICAL SERIALIZATION ADR DRAFT ONLY |
| 2026-10-07 | **PHASE 6H-L — 治理同步（Owner 授权 A/B/C）**：将 PHASE 6H-J Owner 批准的数值正式同步：`MAX_EVIDENCE_COUNT = 21` / `MAX_CERTIFICATE_BYTES = 2066`（§8 的 `OWNER DECISION REQUIRED` → `OWNER APPROVED`；C-1 标记为 SELECTED；§13 S-1/S-2 → RESOLVED；新增 §16 Governance Synchronization Record）。**本 ADR 仍为 DRAFT — NOT FROZEN**（`APPROVED ≠ FROZEN`）；**未**冻结、**未**实现 codec、**未**新增 test vector、**未**修改任何 Rust / ADR-0066 / ADR-0049 / ADR-0005 | Owner 授权 PHASE 6H-K A（PHASE 6H-L 执行）—— DOCUMENTATION SYNCHRONIZATION ONLY |
| 2026-10-07 | **PHASE 6H-V — FREEZE EXECUTION（Owner 授权 D1 = A）**：Status `DRAFT — NOT FROZEN` → **FROZEN**。仅更新状态头 / §1 状态块 / §16.1；**规规范内容零改动**（canonical signed bytes · payload `height(8B LE)‖from_round(8B LE)` · `DomainId 0x10` · 容器布局 · 排序/去重 · 长度校验 · fail-closed · 21 / 2066 全部不变）。D1-V = V2：**test vector = implementation-stage artifact，本阶段不生成**。**未**实现 codec；**未**新增 test vector；**未**修改任何 Rust / ADR-0066 / ADR-0049 / ADR-0005 / ADR-0072 | Owner 授权 PHASE 6H-V —— ADR-0070 FREEZE EXECUTION |

---

## 16. Governance Synchronization Record（PHASE 6H-L，2026-10-07）

> 本节由 **PHASE 6H-L**（Owner 授权 A/B/C）新增，用于记录 **PHASE 6H-J Owner 批准** 与本 ADR 正文的同步。
> **历史文本未被删除**；本节仅记录状态迁移。

```text
ITEM                  | BEFORE (PHASE 6H-G)      | AFTER (PHASE 6H-J / 6H-L)
----------------------|--------------------------|------------------------------------
MAX_EVIDENCE_COUNT    | OWNER DECISION REQUIRED  | OWNER APPROVED = 21
MAX_CERTIFICATE_BYTES | OWNER DECISION REQUIRED  | OWNER APPROVED = 2066
§13 S-1               | OWNER DECISION REQUIRED  | RESOLVED = 21
§13 S-2               | OWNER DECISION REQUIRED  | RESOLVED = 2066
§8 候选 C-1            | 候选（未冻结）            | SELECTED / OWNER APPROVED
ADR-0070 Status       | DRAFT — NOT FROZEN       | DRAFT — NOT FROZEN（不变）
```

**数学关系（MUST 保持）**：

```text
len(certificate_bytes) = 50 + 96 × n
n = 21  ⇒  50 + 96 × 21 = 50 + 2016 = 2066   ✓
```

**保留不变（MUST）**：canonical serialization 规则（§6 容器布局）· ascending `validator_id`（§7.1）·
duplicate rejection（§7.2）· exact-length validation（§7.3）· fail-closed semantics（§10）·
C-2 / C-3 候选记录（仅供历史对照，未被选）。

**未授权（MUST REMAIN NOT AUTHORIZED）**：

```text
FREEZE ADR-0070    = NO
IMPLEMENT CODEC    = NO
ADD TEST VECTOR    = NO
MODIFY RUST        = NO
O2 implementation  = NOT AUTHORIZED
```

---

### 16.1 PHASE 6H-V — ADR-0070 FREEZE EXECUTION（2026-10-07）

```text
ITEM                  | BEFORE (PHASE 6H-L)      | AFTER (PHASE 6H-V)
----------------------|--------------------------|----------------------------------
ADR-0070 Status       | DRAFT — NOT FROZEN       | FROZEN ✓
数值冻结              | NOT GRANTED              | GRANTED（随冻结生效）
FREEZE ADR-0070       | NO                       | YES（Owner D1 = A）
IMPLEMENT CODEC       | NO                       | NO（仍为 NOT AUTHORIZED）
ADD TEST VECTOR       | NO                       | NO（D1-V = V2：implementation-stage artifact）
MODIFY RUST           | NO                       | NO
O2 implementation     | NOT AUTHORIZED           | NOT AUTHORIZED
```

**Freeze 前置核对（PHASE 6H-V §3 = PASS）**：
canonical signed bytes ✓ · payload = `height(8B LE) ‖ from_round(8B LE)` ✓ · `DomainId = 0x10` ✓ ·
`MAX_EVIDENCE_COUNT = 21` ✓ · `MAX_CERTIFICATE_BYTES = 2066` ✓ ·
test vector = FUTURE / implementation-stage ✓ · 无未决 Owner decision 被写成冻结事实 ✓

**冻结不改动任何规范内容**：serialization · payload · domain · `chain_id` encoding · byte ordering ·
bounds · semantics 全部保持原样。
