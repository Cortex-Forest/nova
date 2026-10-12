# ADR-0074 — Abandon Attestation Canonical Serialization v1

- **Status**: **FROZEN**（PHASE 6H-AE，2026-10-07，Owner 授权 D-5）
- **Owner authorization**: PHASE 6H-AE `D-5`（ADR-A → ADR-0074；状态 = FROZEN）
- **Supersedes**: （无）
- **Related**:
  - `ADR-0066`（Round-Change Certificate v1；RC-4 S1 semantics / RC-5 域 `0x10` / RC-6 非耦合 / §9.2 / §10.1 / §11）
  - `ADR-0070`（RoundChangeCertificate canonical serialization v1；其 §5 = 签名陈述 payload；其 §3.2 明确排除「定义网络消息」）
  - `ADR-0067`（Domain Registry Amendment；`0x10` 登记）
  - `ADR-0069`（Signing DomainId Allocation Governance；§2.1 `0x10` allocation record）
  - `ADR-0073`（MessageType Wire Allocation Governance；Rule M-1…M-6）
  - `ADR-0075`（Abandon Attestation MessageType Allocation Governance v1；承载本容器的 MessageType 登记）

---

## 1. Status 与授权边界

```text
本 ADR 定义 Individual Abandon Attestation 的 **wire container** canonical serialization。
本 ADR 于 2026-10-07 由 Owner 授权（PHASE 6H-AE D-5）**正式冻结**。

本 ADR **不授权**任何代码实现。
本 ADR **不**分配 MessageType（由 ADR-0075 承载）。
本 ADR **不**新增 / 修改任何 DomainId（`0x10` 由 ADR-0067 / ADR-0069 承载）。
本 ADR **不**修改 ADR-0066 / ADR-0067 / ADR-0069 / ADR-0070 / ADR-0072 / ADR-0073。
```

---

## 2. Context

### 2.1 问题

`ADR-0066` RC-4 冻结了 **S1 Abandon 语句**的语义；`ADR-0070` §5 冻结了该语句的**签名 payload**
（`height(8B LE) ‖ from_round(8B LE)`，精确 16B）与 `build_signed_bytes` 拼接规则。

但**单条 attestation 在网络上的传输容器**从未被任何冻结规格定义：

```text
ADR-0070 §3.2 Non-Scope 已明文排除：… 定义网络消息 …
⇒ attestation 的网络传输容器 = ADR-0070 明确声明的缺口（本 ADR 填补该缺口）。
```

### 2.2 为何不能复用证书容器

`ADR-0070` §6 的证书容器要求 `len == 50 + 96n` 且携带 `validator_set_id` / `evidence_count`；
单条 attestation（112B）与之**不兼容**，且两者语义不同（聚合权威 vs 单验证人陈述）。
`ADR-0073` Rule M-3（语义变更 ⇒ 新取值，不得原地改义）与 Rule M-1（禁止启发式）共同要求：
**单条 attestation 必须有自己的容器规格与自己的 MessageType。**

### 2.3 触发证据

O2（`RoundChangeCertificate`）已实现证书侧 codec / 验证 / 有界累积池 / `0x0D` 传输；
多验证人 E2E 缺少 **individual attestation 的网络传输规格** ⇒ 证书在活网中不可形成（PHASE 6H-AA/AB/AC/AD 只读审查结论）。

---

## 3. Scope / Non-Scope

### 3.1 In Scope（本 ADR 只定义）

```text
· Individual Abandon Attestation 的 wire container 字节布局（字段顺序 / 宽度 / 精确长度）
· 该容器的 decode 规则与 fail-closed 边界
· 该容器的 replay 绑定口径（声明验证所需输入集合）
· 该容器的 duplicate / conflicting-signature 处置口径
· 该容器的 codec 归属层声明
· 该容器与既有冻结规格的引用关系（signed statement / 域 / algorithm）
```

### 3.2 Non-Scope（明确排除）

```text
NOT: quorum · finality · lock · vote · QC · PrevoteQC · PrecommitQC ·
     RoundChangeCertificate authority · round transition ·
     slashing · fault evidence · ban · punishment ·
     D3 rate limit 政策 · MessageType allocation（ADR-0075）· new DomainId ·
     修改 ADR-0066 / ADR-0067 / ADR-0069 / ADR-0070 / ADR-0072 / ADR-0073 ·
     修改 build_signed_bytes · 修改 consensus 语义
```

---

## 4. 术语与常量（**引用，不新造**）

| 项 | 来源 | 值 |
|---|---|---|
| `validator_id` | ADR-0034 V-4 / ADR-0038 F-12 / ADR-0070 §4 | `SHA-256(consensus_public_key)`（`[u8;32]`） |
| 签名算法 | ADR-0012 | `AlgorithmId::Ed25519 = 0x01` |
| 专用签名域 | ADR-0005 registry / ADR-0067 §0.6 / ADR-0069 §2.1 | **`DomainId::RoundChangeCertificate = 0x10`** |
| 签名陈述 payload | ADR-0070 §5（引用 ADR-0066 §5.1） | `height(8B LE) ‖ from_round(8B LE)`，**精确 16B** |
| `chain_id` 承载 | ADR-0066 §4.2（与 Vote/Block 同构） | **框架字段**，不重复进 payload |

```text
本 ADR 不改变上述任何既有定义。
```

---

## 5. 冻结的 S1 语义

**原样沿用（不重新定义、不修改 ADR-0066）**：

```text
S1:  Abandon(chain_id, height, from_round)
语义: Validator entered round `from_round` at height `height`, its local pacemaker timer for
      (height, from_round) expired, and it is abandoning that round.
```

```text
MUST NOT 含（本 ADR 不得引入，容器不得承载）:
    target_round · proposal_hash · block_hash · vote · QC · lock · finality claim ·
    future-round authorization
```

**语义唯一性（引用 ADR-0066 §4.1）**：对任意 `(height, from_round)` 只存在一个规范陈述 ⇒
一个诚实验证人结构上不可能对同一 `(height, from_round)` 产生两份**不同**签名。

---

## 6. Canonical wire container（**本 ADR 的核心冻结**）

### 6.1 布局（OWNER APPROVED，PHASE 6H-AE D-5）

```text
byte offset   field           type        width
-----------   -------------   ---------   -----
0..8          height          u64 LE      8
8..16         from_round      u64 LE      8
16..48        validator_id    [u8;32]     32
48..112       signature       [u8;64]     64
-----------   -------------   ---------   -----
TOTAL                                    112 bytes（精确）
```

**Canonical order（固定，禁止重排）**：

```text
height ‖ from_round ‖ validator_id ‖ signature
```

**MUST**：

```text
· 精确长度 = 112 字节；任何其它长度 ⇒ 拒绝
· 定长编码；MUST NOT 变长 / 可选字段 / 备用编码
· MUST NOT trailing bytes
· MUST NOT unknown fields（拒绝，不得静默忽略）
· MUST NOT field reordering
· 字段顺序与宽度构成本 ADR 的唯一 canonical form ⇒ 同输入 ⇒ 同字节（确定性）
```

### 6.2 字段覆盖状态（关键精确性）

| 字段 | 是否在签名陈述内 | 绑定机制 |
|---|---|---|
| `height` | **是**（ADR-0070 §5 payload 首字段） | 签名覆盖 |
| `from_round` | **是**（ADR-0070 §5 payload 第二字段） | 签名覆盖 |
| `validator_id` | **否** | **验证期绑定**：定位到的共识公钥必须满足 `SHA-256(pubkey) == validator_id`（identity 检查） |
| `signature` | —（签名本体） | `verify_strict` |

```text
⇒ 容器承载 112B，但**签名覆盖**的仅是 (algorithm, domain, chain_id, height, from_round)。
   validator_id 不进签名 payload（与证书 evidence 的既有口径一致：ADR-0066 §4.2 / ADR-0070 §4）。
```

---

## 7. 签名绑定（继续使用既有冻结）

```text
signed_bytes =
      algorithm_id(1B)   // 0x01 = Ed25519
    ‖ domain_id(1B)      // 0x10 = RoundChangeCertificate
    ‖ chain_id(8B LE)
    ‖ payload_length(4B LE)   // 精确 = 16
    ‖ payload = height(8B LE) ‖ from_round(8B LE)
```

**引用**：`ADR-0070` §5（本 ADR **不**重新定义 `build_signed_bytes`、**不**修改其规则）、
`ADR-0066` §5.1、`ADR-0069` §2.1（域分配）、`ADR-0067` §0.6（域登记）。

**MUST NOT**：

```text
· 新建 DomainId · 创建新的 Abandon domain · 修改 DomainId 0x10 · 修改 ADR-0069 allocation
· 修改 ADR-0070 §5 signed-bytes 规则 · 修改 ADR-0066 S1
```

**`chain_id`**：

```text
chain_id = framework context + signed into build_signed_bytes
chain_id MUST NOT be duplicated in the attestation wire body（§6 布局不含 chain_id）
```

---

## 8. Validator set 绑定（**FROZEN**）

```text
validator_set_id
    NOT INCLUDED
in Individual Abandon Attestation wire body.
```

接收节点验证模型：

```text
validator_id
    ↓
current validator set（本地本地验证人集合 context）
    ↓
public key lookup
    ↓
signature verification
```

```text
· 错误 validator set（该 validator_id 不属本地集合 / 身份不符）⇒ REJECT
· 跨 validator-set replay ⇒ 由本地集合绑定 + identity 检查阻断
· MUST NOT 因「attestation body 不含 validator_set_id」而改变 RoundChangeCertificate 的
  frozen format（ADR-0070 §6 保持不变：其容器继续携带 validator_set_id）
```

---

## 9. Validation 模型

**验证所需输入集合**：

```text
chain_id · height · from_round · validator_id · validator_set · signature
```

**验证步骤（V-5 同构五步；复用既有冻结验证器）**：

```text
① membership      : validator_id ∈ 本地 ValidatorSet
② identity        : SHA-256(consensus_public_key) == validator_id
③ signed_bytes    : build_signed_bytes(Ed25519, 0x10, chain_id, height ‖ from_round)
④ message hash    : SHA-256(signed_bytes)
⑤ verify_strict   : Ed25519 严格验证（拒绝非规范 S / small-order / weak key）
```

```text
MUST 复用 nova_consensus::round_change::verify_evidence
MUST NOT 创建新的 consensus verifier
MUST NOT 引入新的 consensus primitive
```

---

## 10. Replay 防护

```text
cross-chain         → chain_id 经签名域绑定 ⇒ 拒绝
cross-height        → height ∈ signed payload ⇒ 拒绝
cross-round         → from_round ∈ signed payload ⇒ 拒绝
cross-validator     → validator_id ∈ body + 公钥定位 + identity 检查 ⇒ 拒绝
wrong validator-set → 本地集合绑定（§8）⇒ 拒绝
```

```text
防重放 MUST NOT 依赖「已见集合 / 去重缓存」作为唯一机制（缓存仅作幂等优化）。
协议级防护 = 域 + chain_id + height + from_round 全部在签名范围内（ADR-0066 §4.2 口径）。
```

---

## 11. Duplicate / Conflict（**FROZEN**）

### 11.1 Same bytes（幂等）

```text
same (height, from_round, validator_id) + same canonical bytes
⇒ idempotent duplicate / ignore
```

### 11.2 Conflicting signature

```text
same (height, from_round, validator_id) + different signature bytes
⇒ reject / ignore second instance
```

**MUST NOT（不得从此行为推导任何新共识语义）**：

```text
NO slashing · NO fault evidence · NO vote equivocation · NO ban · NO punishment ·
NO finality evidence
```

```text
若未来需要为 conflicting signature 定义证据 / 惩罚语义 ⇒ 必须另行独立治理，本 ADR 不授予。
两侧（先到 / 后到）均不产生状态变更以外的任何副作用。
```

---

## 12. Failure Handling（fail-closed）

**非法输入（任一即拒）**：

```text
wrong length · trailing bytes · malformed encoding · invalid validator_id ·
invalid signature · wrong chain · wrong validator set · unknown fields
```

**拒绝时（NO side effects）**：

```text
NO round transition · NO pool insertion · NO broadcast ·
NO QC mutation · NO finality mutation · NO lock mutation ·
NO vote journal mutation · NO block-safety journal mutation
```

```text
非法输入 ⇒ zero state mutation（可审计：拒因必须可区分）。
MUST NOT fallback decoding / 备用编码 / permissive trailing / unknown-field ignore /
ambiguous interpretation。
```

---

## 13. Codec 归属（**FROZEN**）

```text
Individual Abandon Attestation wire container
    → network/wire layer
```

```text
MUST NOT 把 wire container semantics 放进 consensus core。
MUST 继续复用 nova_consensus::round_change::verify_evidence（验证器仍在 consensus 层，
     因其为冻结 V-5 同构五步的唯一实现）。
MUST NOT 创建新的 consensus verifier。
```

---

## 14. 与 ADR-0070 / ADR-0066 的关系（**不扩展、不重定义**）

```text
ADR-0070 继续只负责:
    · 签名陈述（Abandon attestation）canonical payload（其 §5，引用 ADR-0066 §5.1）
    · RoundChangeCertificate 容器 canonical byte 布局（其 §6）
    · evidence 排序 / 去重 / 长度一致性（其 §7）
    · malformed / duplicate rejection（其 §10）
ADR-0074 只负责:
    · Individual Abandon Attestation 的 wire container（§6）
```

```text
MUST NOT extend ADR-0070 silently
   （ADR-0070 §3.2 Non-Scope 已明文排除「定义网络消息」——本 ADR 填补其【声明的缺口】，
     不构成对 ADR-0070 语义范围的扩展）
MUST NOT reuse certificate codec with another semantic meaning
   （ADR-0073 Rule M-3）
```

---

## 15. Safety Boundary（**MUST 恒真**）

```text
Individual Abandon Attestation NEVER enters:
    VoteLedger · vote journal · block-safety journal · VoteAccumulator · QcRegistry ·
    verify_qc · assemble_qc · Finality · LockedState

Individual Abandon Attestation
    ≠ Vote
    ≠ QC（PrevoteQC / PrecommitQC）
    ≠ RoundChangeCertificate
```

```text
quorum                          = unchanged
checked_successor               = unchanged（仍是唯一 round transition primitive）
RoundChangeCertificate          = unchanged
S1                              = unchanged
DomainId::RoundChangeCertificate = unchanged（0x10）
```

---

## 16. Test Vector 要求（FUTURE；不得静默决定）

依 `ADR-0070` §11 先例，实现阶段 **SHOULD** 提供 canonical test vector，至少覆盖：

```text
· exact canonical bytes（112B，含逐字段偏移断言）
· exact signing statement（signed_bytes 逐字节）+ message hash
· algorithm_id = 0x01 · domain_id = 0x10 · chain_id 编码 · height · from_round
· signature verification（有效 / 无效）
· malformed：长度不符（< 112 / > 112）· trailing · unknown field 位置
· replay：跨 chain / 跨 height / 跨 round / 跨 validator / 错误集合
· duplicate（同字节幂等）· conflicting signature（reject/ignore，无惩罚语义）
```

具体向量形态与生成方式由实现阶段决定（**不得**在本 ADR 中预先冻结）。

---

## 17. Malformed / Duplicate Rejection 的可审计性（MUST）

```text
· 拒绝原因必须可区分（长度 / trailing / 未知字段 / 身份 / 签名 / 链 / 集合 / 重复 / 冲突）
· 拒因可审计：不得以单一「无效」笼统表示（实现阶段落实）
· 拒绝路径 MUST NOT 产生任何状态变更（§12）
```

---

## 18. Open Questions（**不得静默决定**）

```text
Q-1  attestation 的 wire framing（envelope 层）完全沿用既有 network 层规格；本 ADR 不定义。
     是否需要独立 framing 约束？—— 结论：不需要（沿用既有 envelope；ADR-0073 §6 口径）。
Q-2  attestation 的限流 / 配额政策（含是否与 `0x0D` 共享 D3 口径）—— Owner policy，另行决定。
Q-3  是否需要为 conflicting signature 定义（或明确永不定义）证据语义 —— Owner 决定；
     本 ADR 当前立场 = 不定义、不授权（§11.2）。
```

```text
These MUST NOT be silently decided by implementation.
```

---

## 19. Non-Authorization

```text
This ADR does not authorize any code implementation.

未授权：attestation codec 实现 / MessageType enum 修改 / wire handler / rate limiter / storage /
        pool 网络集成 / validator 签名路径 / consensus 变更 / pacemaker / RoundTimer /
        sync / finality / lock / Genesis / Akash / deployment。
```

（Owner 已在 PHASE 6H-AE §20 授权**下一阶段**实施；本 ADR 本身不构成该授权。）

---

## 20. References（只读）

```text
ADR-0005（Domain registry）· ADR-0012（Algorithm registry）· ADR-0034 V-4 / ADR-0038 F-11/F-12
ADR-0066（RC-1…RC-7 · §4.1/§4.2/§4.3 · §5.1 · §7.2 · §9.1/§9.2 · §10.1/§10.2 · §11）
ADR-0067（§0.6 域登记）· ADR-0069（§2.1 allocation record · §7.1/§7.2 命名空间分离）
ADR-0070（§3.2 Non-Scope · §4 · §5 · §6 · §7 · §10 · §11）
ADR-0072（§3.4 有限附随语义效果）· ADR-0073（Rule M-1…M-6 · §8 · §9 · §10）
ADR-0075（本容器所登记的 MessageType）
```

---

## 21. Change Log / Provenance

| 日期 | 事件 | 授权 |
|---|---|---|
| 2026-10-07 | **创建 + FROZEN**（PHASE 6H-AE）：Owner 授权 D-5 批准 ADR-A → ADR-0074；冻结 112B canonical wire container（`height(8B LE) ‖ from_round(8B LE) ‖ validator_id(32B) ‖ signature(64B)`）、exact-length、fail-closed、replay 绑定、duplicate/conflict 处置（无惩罚语义）、codec 归属 = network/wire 层。**未**修改任何既有冻结 ADR；**未**修改代码；**未**分配 MessageType（由 ADR-0075 承载） | Owner PHASE 6H-AE D-5 |
