# ADR-0073: MessageType / Wire Allocation Governance v1

- **Status**: **FROZEN**（2026-10-07 Freeze Execution；**Owner 授权 PHASE 6H-W —— D7 = FREEZE ADR-0073**）
  （本文件为**治理规范**。**不构成协议修订**、**不授权实现**、**不修改任何既有 ADR**。
  **冻结 ≠ 实现授权**：enum / codec / handler / rate limiter / O2 实现仍为 **NOT AUTHORIZED**。）
- **Freeze metadata（PHASE 6H-W）**: D7 = FREEZE ADR-0073 · `ConsensusRoundChange = 0x0D`（**wire allocation only**）
- **Date**: 2026-10-07
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: **wire 分配治理（governance only）** —— 登记当前 `MessageType` 实际状态、正式分配 O2
  `ConsensusRoundChange` 的 wire 取值、明确 `MessageType` 命名空间边界，并建立后续新增取值的**分配规则**。
  **不实现**任何 codec / handler / enum 变更。
- **Type**: Independent Governance ADR（**非**实现授权）
- **Phase provenance**: PHASE 6H-U（O2 Implementation Gate：Network message = `NEW ADR REQUIRED`）
  → **PHASE 6H-U2（Owner Decision Gate：D7 = REQUIRED；D2 = C —— MessageType 须经独立治理 ADR 分配）**
  → **PHASE 6H-V（本草案）**
- **关联（只读引用，不修改）**: **ADR-0032（P2P Network Architecture V1 —— N-4 历史枚举记录）** ·
  ADR-0005（Domain Separation / Nova Domain Registry）· ADR-0006（Hash Policy）· ADR-0012（Crypto Registry）·
  **ADR-0066（RoundChangeCertificate，FROZEN）** · **ADR-0069（Signing Domain Allocation Governance，FROZEN；§7.4）** ·
  ADR-0071（O2 Design & Preparation Record，DRAFT）· ADR-0072（ADR-0049 Amendment，FROZEN）·
  ADR-0062（Sync Target Semantics，PROPOSED —— **不修改**）
- **非授权声明（MUST 保留）**:

```text
This ADR does not authorize any implementation.

It authorizes a wire allocation only.
It does not authorize an enum change, a codec, a handler, a rate limiter,
a protocol-version change, an O2 implementation, or any deployment.

O2_IMPLEMENTATION_AUTHORIZED = NO
```

---

## 1. Purpose

本 ADR 的唯一目的：

```text
为【网络消息类型（MessageType）】建立显式、唯一、可审计的 wire 分配治理，
并据此正式分配 O2 所需的 ConsensusRoundChange 取值。
```

**为什么需要独立 ADR（不可由既有 ADR 承载）**：

```text
· ADR-0032 N-4 冻结的是「MessageType V0.1（【7 类】）」这一历史枚举；
  而当前代码实际为【11 类】⇒ 既有冻结枚举与代码现实已存在未登记漂移。
· 【不存在】任何 MessageType 分配程序 / 注册表治理文件。
· ADR-0069 §7.4 明文要求：「O2 未来若需要网络消息 ⇒ 需要【独立的】MessageType 分配
  （不得借用 DomainId 决策代替）。」
⇒ 属 PHASE 6H-U2 §16 所列「new wire allocation governance」情形 ⇒ 需新的独立 ADR。
```

## 2. Namespace Declaration（MUST）

```text
本条 ADR 的对象是【MessageType】命名空间 —— 仅此一个命名空间。
```

`MessageType` **是**网络 envelope 的 wire discriminator；`MessageType` **不是**：

```text
× DomainId（签名域；ADR-0005 / ADR-0069 §7）
× HashDomain（哈希输入前缀；ADR-0068）
× AlgorithmId（密码算法；ADR-0012）
× 存储 magic / 文件格式常量
```

**MUST**（沿用 ADR-0069 Rule D 的精神）：

```text
· 数值相同【不】构成 collision（不同命名空间）。
· 数值相同【也】【不】构成复用许可。
· 跨命名空间的「统一编号」被【明令禁止】。
· 本 ADR 的分配【不】影响也不授权任何 DomainId / HashDomain / AlgorithmId 决策。
```

## 3. 当前 MessageType 实际状态登记（as of 2026-10-07，已核实）

以 `crates/network/src/message.rs` 为唯一事实来源（只读核实）：

| 取值 | 名称 | 状态 |
|---|---|---|
| `0x01` | `Handshake` | **已实现**（在代码中注册） |
| `0x02` | `Ping` | **已实现** |
| `0x03` | `Pong` | **已实现** |
| `0x04` | `GossipTransaction` | **已实现** |
| `0x05` | `SyncBlockRequest` | **已实现** |
| `0x06` | `SyncBlockResponse` | **已实现** |
| `0x07` | `Status` | **已实现** |
| `0x08` | `ConsensusVote` | **已实现**（STEP 11-2 注册；payload opaque） |
| `0x09` | `ConsensusProposal` | **已实现**（STEP 11-2 注册） |
| `0x0A` | `ConsensusQc` | **已实现**（STEP 11-2 注册） |
| `0x0B` | `GossipBlock` | **已实现**（P7-5 注册） |
| `0x0C` | — | **未分配**（仅作为**否定测试样本**出现于 `message.rs` / `network_service.rs`；**不得**视为已分配） |
| **`0x0D`** | **`ConsensusRoundChange`** | **本 ADR 正式分配（wire allocation）** —— 见 §5 |
| `0x0E` – `0x7F` | — | **未分配 / Reserved** |
| `0x80` – `0xFF` | — | **未分配 / Reserved**（未注册值 ⇒ 必须拒绝） |

```text
关键澄清（MUST）：测试代码中出现某一取值（包括作为“未知类型”否定样本）
【不构成】wire 分配。分配只能由本 ADR 这类显式治理行为完成。
```

## 4. Historical Drift Record（**只记录，不追溯修改**）

```text
HISTORICAL DRIFT（登记，不改动）
  ADR-0032 N-4（Status = Proposed）记录 MessageType V0.1 = 【7 类】：
    Handshake / Ping / Pong / GossipTransaction / SyncBlockRequest / SyncBlockResponse / Status
  当前代码实际 = 【11 类】（0x01–0x0B；新增 ConsensusVote / ConsensusProposal /
    ConsensusQc / GossipBlock）。
```

**MUST**：

```text
· ADR-0032 的冻结内容【不得】由本 ADR 追溯修改（本 ADR 不修改 ADR-0032 的任何字节）。
· 上述漂移【仅作历史记录】登记在本 ADR；其治理化修正（若需要）属【另行授权】的独立事项。
· 本 ADR 不声称 ADR-0032 已被修订。
```

执行漂移（如“代码超出 ADR-0032 枚举”）**先于本 ADR 存在**，本 ADR 不追溯、不归责、不静默修正。

## 5. ALLOCATION RECORD — `ConsensusRoundChange = 0x0D`

```text
ALLOCATION RECORD（wire allocation）

Allocated MessageType  = 0x0D
Name                   = ConsensusRoundChange
Namespace              = MessageType（网络 envelope wire discriminator）
Purpose                = 承载 O2 RoundChangeCertificate 的网络传输（wire 载体）
Authority              = Owner-approved（PHASE 6H-U2 D2 = C / D7 = REQUIRED；PHASE 6H-V 执行）
Date                   = 2026-10-07
Previous status        = Unallocated（0x0D 从未出现于任何文件）
Allocation method      = Explicit governance（非“下一个可用值”自动分配）
Code implementation    = NOT IMPLEMENTED（message.rs 未修改）
```

**本分配仅具以下效力**：

```text
wire allocation authorization ONLY
```

**明确【不】构成**（MUST）：

```text
× code implementation authorization（不授权修改 enum / codec / handler）
× network deployment authorization
× O2 implementation authorization
× rate-limit / flood-protection 数值决策
× protocol-version / capability 变更
```

**为什么选 `0x0D` 而非 `0x0C`**（记录在案）：

```text
· 0x0C 已被既有测试用作「未知类型」否定样本
  （message.rs:337/340、network_service.rs:1007）⇒ 若分配 0x0C，必须一并修改既有测试，
    且会削弱「未知类型 fail-closed」的负向覆盖。
· 0x0D 在任何文件中【0 命中】⇒ 零冲突、零测试扰动。
```

## 6. Wire Envelope 与 Payload 边界（只读引用，不修改）

```text
MessageEnvelope = version(1B) ‖ message_type(1B) ‖ payload_len(4B LE) ‖ payload
                  ‖ sender(32B) ‖ signature(64B)
签名覆盖 = version ‖ message_type ‖ payload（不覆盖 sender）
```

- `payload` 对 Network 层为 **opaque**（网络不解析共识语义；沿用 ADR-0032 N-4 / message.rs 既有约定）。
- `ConsensusRoundChange` 的 **payload 编码** 由 **ADR-0070（RoundChangeCertificate Canonical
  Serialization，FROZEN）** 承载 —— **本 ADR 不重新定义**。
- **MUST NOT** 使 certificate 进入 Network 层的共识语义解释路径。

## 7. Size / Framing Compatibility（只读结论）

```text
· 证书上界 = MAX_CERTIFICATE_BYTES = 2066（ADR-0070，FROZEN）
· 通用 payload 上限 = MAX_NETWORK_MESSAGE_PAYLOAD_BYTES = 1 MiB（security.rs）
· 传输帧 = len(4B LE) ‖ payload，且 len ≤ max_frame
⇒ 2066 < 1 MiB = PASS；无需修改 framing。
```

**本 ADR 不修改**：framing · size validation · encode/decode 路径 · 任何网络实现。

## 8. Backward Compatibility / Fail-Closed（治理原则）

```text
MUST：未知 MessageType ⇒ 拒绝（fail-closed），MUST NOT 静默忽略 / 不得降级解释。
```

**现状（已满足，作为证据而非本 ADR 的产物）**：

```text
message.rs：TryFrom<u8> for MessageType ⇒ 未注册值 ⇒ NetworkError::InvalidMessageType
```

**混合版本行为（沿用 ADR-0066 §15.1 / ADR-0071 §8）**：

```text
未升级节点收到 ConsensusRoundChange(0x0D) ⇒ InvalidMessageType ⇒ fail-closed
   ⇒ 不 crash · 不产生隐式投票 · 不产生 finality · 不触碰 LockedState
MIXED-VERSION = SAFE，但【无活性收益】（升级节点会等待一个永不形成的证书）
```

**本 ADR 不实施** version / capability negotiation（Owner D5 = A）：

```text
首次 O2 implementation 不依赖 protocol-version negotiation。
minimum protocol_version N 仍未定义、仍为 OPEN（Owner policy）。
本 ADR 不定义 N、不新增 capability、不修改 capabilities/协议版本字段。
```

## 9. 后续新增 MessageType 的分配规则

**Rule M-1 — No implicit allocation（禁止隐式分配）**：

```text
MUST NOT 以“下一个数字”“看起来空的取值”“先写代码再补登记”“反正与别的命名空间数值相同”
等启发式分配 MessageType。
```

**Rule M-2 — Explicit governance（显式治理）**：任何新 wire 取值 MUST 同时具备

```text
1. 明确用途（该消息承载什么 wire 载荷）
2. 命名空间声明（MessageType，而非 DomainId / HashDomain / …）
3. 唯一性检查（与 0x01–0x0B 及 Reserved 区间不冲突）
4. 负向覆盖确认（不得占用既有「未知类型」否定测试所用取值）
5. Owner approval
6. 正式登记（本 ADR 或后续同类治理 ADR）
7. provenance（ADR 编号 + 名称 + 取值 + 用途 + 日期）
```

**Rule M-3 — No reuse / no renumbering / no recycling**：

```text
· 取值一经分配 ⇒ 数值与名称【永久保留】。
· 废弃 ⇒ 标记 DEPRECATED，数值永不回收。
· 语义变更 ⇒ 新取值（新治理决策），不得原地改义。
```

**Rule M-4 — Fail closed**：见 §8（未注册值必须拒绝；新增取值 MUST 附否定测试）。

**Rule M-5 — Namespace separation**：见 §2。

**Rule M-6 — Test values are not allocations**：见 §3 关键澄清。

## 10. 保留值 / 未分配值（显式状态）

```text
0x01 – 0x0B  = 已实现（不得重新编号 / 不得改义 / 不得回收）
0x0C         = 未分配（且被既有否定测试占用 ⇒ 分配前须先评估测试影响）
0x0D         = 【本 ADR 正式分配】= ConsensusRoundChange（wire allocation only）
0x0E – 0xFF  = 未分配 / Reserved（未注册值 ⇒ 必须拒绝）
```

## 11. 与 ADR-0069 的关系

```text
· ADR-0069 = 【signing DomainId 分配治理】（FROZEN）。
· 本 ADR = 【MessageType wire 分配治理】。
· 二者【同构但独立】（ADR-0069 §7.1/§7.4）：
    分配 DomainId 不自动分配 MessageType；反之亦然。
· 本 ADR 不修改 ADR-0069；ADR-0069 Rule A–I 不受本 ADR 影响。
```

## 12. 与 ADR-0062（sync）的边界（MUST 保持）

```text
· RoundChangeCertificate MUST NOT become a sync target.
· RoundChangeCertificate MUST NOT become finality evidence.
· RoundChangeCertificate MUST NOT alter sync canonicality.
⇒ 本 ADR 【不】修改 ADR-0062；ConsensusRoundChange(0x0D) 的引入【不】使证书进入 sync 路径。
```

**Retention（Owner D6 = A）**：

```text
R-2 = pure on-demand 保持不变。
首次 O2 implementation 不要求 retrieval protocol。
```

## 13. Rate Limit / Flood Protection（**不承载数值**）

```text
Owner D3 = B：RoundChangeCertificate MUST 具备专属限流/配额策略后
            才能进入 O2 implementation gate。
```

**本 ADR 明确不定义**（属后续 Owner policy）：

```text
× messages/sec   × peer/hour   × ban threshold   × CPU budget   × memory budget
× B-1 storage capacity 数值
```

**本 ADR 不实施**任何 rate limiter。

## 14. Non-Normative Note — 实现状态（供后续阶段引用）

```text
本 ADR 通过时：
· message.rs = UNCHANGED（0x0D 未写入代码）
· 无 handler、无 codec、无 rate limiter、无 storage
· RoundChangeCertificate type = NOT IMPLEMENTED
· O2 IMPLEMENTATION = NOT AUTHORIZED
```

## 15. Open Questions（**不得静默决定**）

```text
M-1  0x0C 是否最终保留为「永不分配」的哨兵值（以保护既有否定测试）？—— Owner 决定
M-2  是否需要将 ADR-0032 N-4 的 7 类枚举与当前 11 类现实正式对齐（独立事项）？—— Owner 决定
M-3  Reserved 区间（0x0E+）是否需要按用途分段（例如 consensus / sync / gossip）？—— Owner 决定
M-4  RoundChange 专属限流/配额的数值与策略载体（D3 = B）—— Owner policy，另行决定
M-5  本 ADR 自身是否随 ADR-0070/ADR-0066 一并进入 Freeze？—— Owner 决定（当前 = DRAFT）
```

```text
These MUST NOT be silently decided by implementation.
```

## 16. Non-Authorization

```text
This ADR does not authorize any implementation.
It authorizes a wire allocation only.

O2_IMPLEMENTATION_AUTHORIZED = NO

未授权：MessageType enum 修改 / wire codec / network handler / rate limiter / storage /
        RoundChangeCertificate 实现 / protocol-version 变更 / capability 变更 /
        gossip 变更 / TCP framing 变更 / consensus / pacemaker / RoundTimer / sync /
        finality / lock / Genesis / Akash / deployment。
```

## 17. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-07 | **ADR-0073 初稿（DRAFT — NOT FROZEN）**：MessageType / Wire Allocation Governance v1。登记当前 `MessageType` 实际状态（0x01–0x0B 已实现；0x0C 未分配且被否定测试占用）；**正式分配 `ConsensusRoundChange = 0x0D`（wire allocation only）**；记录 ADR-0032 N-4 的历史枚举漂移（**不修改 ADR-0032**）；建立 Rule M-1…M-6 分配治理规则；明确与 ADR-0069（同构但独立）、ADR-0062（不改 sync 边界）、ADR-0070（payload 编码归其承载）的关系；不承载任何 rate-limit / capacity 数值。**未**实现任何代码；**未**修改 ADR-0032 / ADR-0062 / ADR-0066 / ADR-0069 / ADR-0070 / ADR-0005 / `message.rs` / 任何 Rust / Genesis / Akash；**未**冻结本 ADR | Owner 授权 PHASE 6H-U2 D2 = C / D7 = REQUIRED → PHASE 6H-V —— ADR-0073 MINIMAL WIRE ALLOCATION GOVERNANCE |
| 2026-10-07 | **PHASE 6H-W — FREEZE EXECUTION（Owner 授权 D7）**：Status `DRAFT — NOT FROZEN` → **FROZEN**。**仅状态冻结**：allocation 取值（`0x0D`）· 治理规则（Rule M-1…M-6）· wire 语义 · safety 边界【全部不变】。D3（RoundChange 专属限流：4 msg/sec/peer · burst 8 · 超限 DROP/REJECT · 不自动 BAN）与 D4（bounded in-memory：64 certificates per height · R-2 pure on-demand · no journal · deterministic eviction）为 **Owner implementation policy**；依本 ADR §13 范围【不由本 ADR 承载】，仅于 PHASE 6H-W readiness 记录中登记。**未**修改 `message.rs` / 任何 Rust / ADR-0032 / ADR-0062 / ADR-0066 / ADR-0069 / ADR-0070 / ADR-0049 / Genesis / Akash | Owner 授权 PHASE 6H-W —— ADR-0073 FREEZE + O2 POLICY GATE |

---

## References（只读）

```text
docs/adr/ADR-0032-p2p-network-architecture-v1.md      （N-1…N-7；N-4 历史 7 类枚举记录）
docs/adr/ADR-0005-domain-separation.md                （Domain Registry —— 不同命名空间）
docs/adr/ADR-0062-sync-target-semantics-v1.md         （PROPOSED；sync 边界，本 ADR 不修改）
docs/adr/ADR-0066-round-change-certificate-v1.md      （FROZEN；§15.1 混合版本；§17 Domain Registry）
docs/adr/ADR-0069-signing-domain-allocation-governance-v1.md（FROZEN；§7 命名空间分离；§7.4 MessageType）
docs/adr/ADR-0070-roundchangecertificate-canonical-serialization-v1.md（FROZEN；payload 编码归属）
docs/adr/ADR-0071-o2-design-and-preparation-record-v1.md（DRAFT；§8 mixed-version 设计）
docs/adr/ADR-0072-adr-0049-round-change-authority-amendment-v1.md（FROZEN；round-change 权威边界）
crates/network/src/message.rs                         （MessageType 现状；未修改）
crates/network/src/security.rs                        （MAX_NETWORK_MESSAGE_PAYLOAD_BYTES = 1 MiB）
crates/network/src/transport.rs                       （frame = len(4B LE) ‖ payload）
```
