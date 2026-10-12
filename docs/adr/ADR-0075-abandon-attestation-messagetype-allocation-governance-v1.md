# ADR-0075 — Abandon Attestation MessageType Allocation Governance v1

- **Status**: **FROZEN**（PHASE 6H-AE，2026-10-07，Owner 授权 D-1 / D-2 / D-3 / D-4 / D-6）
- **Owner authorization**: PHASE 6H-AE `D-1`（`0x0E` = `ConsensusAbandonAttestation`）· `D-2`（不建立 Reserved 分段政策）· `D-3`（`0x0C` = 永久 unknown/negative-test sentinel）· `D-4`（ADR-0073 保持原文）/ `D-6`（ADR-B → ADR-0075，FROZEN）
- **Supersedes**: （无）
- **Related**:
  - `ADR-0074`（Abandon Attestation Canonical Serialization v1；`0x0E` 所承载载荷的 canonical 规格）
  - `ADR-0073`（MessageType Wire Allocation Governance；Rule M-1…M-6 / §3 / §5 / §8 / §9 / §10 / §15）
  - `ADR-0069`（命名空间分离；§7.1/§7.2/§7.4）
  - `ADR-0066`（S1 semantics / §15.1 混合版本口径）

---

## 1. Status 与授权边界

```text
本 ADR 为 Individual Abandon Attestation 登记一个【独立】MessageType（wire allocation only）。

本 ADR 于 2026-10-07 由 Owner 授权（PHASE 6H-AE D-1/D-6）**正式冻结**。

本 ADR **不**重新定义：Abandon semantics · certificate semantics · quorum · finality · lock ·
                    consensus transition · 任何既有 MessageType 语义。
本 ADR **不**修改 ADR-0073（其 §3 / §5 / §10 / §15 保持原文，见 §9）。
本 ADR **不**授权任何代码实现（见 §14）。
本 ADR **不**建立 Reserved 区间分段政策（见 §8）。
```

---

## 2. Namespace Declaration（MUST）

```text
Namespace = MessageType（网络 envelope 消息类型）
```

依 `ADR-0069` §7.1/§7.2：

```text
· 数值相同【不】自动构成 collision（不同命名空间、不同构造、从不出现在同一编码中）。
· 数值相同【也】【不】构成复用许可 —— 绝不可因「数值一样」而跨命名空间互传。
· 任何 ADR 在引入新取值时【MUST】显式声明其命名空间。   ← 本 §2 即为该声明
· 跨命名空间的「统一编号」被【明令禁止】。
```

```text
本 ADR 仅声明并登记 **MessageType** 命名空间下的一个取值。
本 ADR 不涉及 DomainId / HashDomain / AlgorithmId / 存储 magic（彼此独立命名空间）。
```

---

## 3. 当前 MessageType 实际状态登记（as of 2026-10-07，已核实）

| 取值 | 名称 | 状态 |
|---|---|---|
| `0x01` | `Handshake` | 已实现（不得重编号 / 改义 / 回收） |
| `0x02` | `Ping` | 已实现 |
| `0x03` | `Pong` | 已实现 |
| `0x04` | `GossipTransaction` | 已实现 |
| `0x05` | `SyncBlockRequest` | 已实现 |
| `0x06` | `SyncBlockResponse` | 已实现 |
| `0x07` | `Status` | 已实现 |
| `0x08` | `ConsensusVote` | 已实现 |
| `0x09` | `ConsensusProposal` | 已实现 |
| `0x0A` | `ConsensusQc` | 已实现 |
| `0x0B` | `GossipBlock` | 已实现 |
| **`0x0C`** | — | **永久保留 = unknown / negative-test sentinel**（Owner D-3；见 §7） |
| `0x0D` | `ConsensusRoundChange` | ADR-0073 §5 正式分配（**wire allocation only**）；**保持独占**（见 §6） |
| **`0x0E`** | **`ConsensusAbandonAttestation`** | **本 ADR 正式分配（Owner-approved allocation）** —— 见 §4 |
| `0x0F` – `0xFF` | — | **未分配 / Reserved**（未注册值 ⇒ 必须拒绝） |

```text
本 §3 为本 ADR 自身的登记表（不修改 ADR-0073 的表，见 §9）。
```

---

## 4. ALLOCATION RECORD — `ConsensusAbandonAttestation = 0x0E`

```text
MessageType:            0x0E
Name:                   ConsensusAbandonAttestation
Namespace:              MessageType
Purpose:                Individual Abandon Attestation transport
Payload:                ADR-0074 canonical wire container（精确 112 bytes）
Canonical Serialization: ADR-0074
Owning ADR:             ADR-0075
Allocation Authority:   Owner（Owner-approved allocation）
Owner approval:         PHASE 6H-AE D-1（2026-10-07）
Previous status:        Unallocated / Reserved（`0x0E` 从未作为合法 MessageType 出现于任何代码）
Date:                   2026-10-07
Supersedes:             （none）
Status:                 FROZEN
```

### 4.1 Allocator 声明（**MUST 记录**）

```text
`0x0E` 的来源是 **Owner 明确治理批准**，不是 AI 的启发式选择。

MUST NOT 作为分配理由出现：
    · next available number
    · first free number
    · "0x0E because it is free"

本 allocation record 的权威依据 = Owner PHASE 6H-AE D-1。
```

### 4.2 与 `0x0D` 的选择关系（记录在案）

```text
· `0x0D` 已于 ADR-0073 §5 分配（ConsensusRoundChange）⇒ Rule M-3：数值永久保留，不得复用于
  attestation。
· `0x0C` 已被既有「未知类型」否定测试使用，并于本 ADR §7 被 Owner 永久保留为 sentinel
  ⇒ 不作为正常 MessageType 分配。
· 上述两项均为**排除性事实**，不构成对 `0x0E` 的选择理由；选择依据为 Owner 治理批准（§4.1）。
```

---

## 5. Rule M-2 — 七项 allocation material（逐项 checklist）

| # | Rule M-2 要求 | 本 ADR 的证据 / 落点 |
|---|---|---|
| 1 | **明确用途**（该消息承载什么 wire 载荷） | Individual Abandon Attestation transport；载荷 = **ADR-0074** 冻结的 112B canonical container |
| 2 | **命名空间声明**（MessageType，而非 DomainId / HashDomain / …） | §2（显式声明 = MessageType） |
| 3 | **唯一性检查**（与 `0x01–0x0B` 及 Reserved 区间不冲突） | §3 登记表；`0x0E` 在代码中不存在 enum 变体 / `TryFrom` 分支（仅曾作为**测试**负向样本，见 §10） |
| 4 | **负向覆盖确认**（不得占用既有「未知类型」否定测试所用取值） | 见 §10：既有负向样本已从 `0x0E` **迁移**至 `0x0C`（sentinel）；`0x0E` 不再承担负向用途 |
| 5 | **Owner approval** | PHASE 6H-AE **D-1**（Owner-approved allocation，2026-10-07） |
| 6 | **正式登记**（本 ADR 或后续同类治理 ADR） | 本 ADR（依 ADR-0073 §9「**本 ADR 或后续同类治理 ADR**」）§4 |
| 7 | **provenance**（ADR 编号 + 名称 + 取值 + 用途 + 日期） | §4 + §15 |

```text
M-2 = SATISFIED（七项齐备）。
```

---

## 6. Rule M-3 / `0x0D` 保护（**保持独占**）

```text
0x0D = ConsensusRoundChange
```

继续**专用**于：

```text
RoundChangeCertificate（ADR-0066 / ADR-0070；wire allocation only）
```

**MUST NOT**：

```text
· 0x0D = Certificate OR Attestation
· 在任何单一 MessageType 下进行 semantic multiplexing
· 重新编号 / 回收 / 原地改义任何已分配取值
```

`ADR-0073` 保持冻结且**不修改**。

---

## 7. `0x0C` — Permanent Unknown / Negative-Test Sentinel（Owner D-3）

```text
0x0C
    = permanently reserved unknown/negative-test sentinel
用途 = Unknown MessageType negative testing
```

```text
· 未来 unknown MessageType 否定测试 **推荐使用 `0x0C`**。
· MUST NOT 将 `0x0C` 注册为正常（production）MessageType。
· 除非未来另行通过**明确治理 ADR** 修改本政策。
```

与既有代码状态一致（只读核实）：

```text
· `message.rs` / `network_service.rs` 既有否定测试使用 `0x0C` 作为「未知类型」样本
  ⇒ 该用法与本节政策**一致**，无需改动。
· ADR-0073 §15 M-1（「0x0C 是否最终保留为哨兵值」）由本 ADR §7 依 Owner D-3 **裁定为：保留**。
```

```text
本 ADR 记录该事实，但不修改 ADR-0073。
```

---

## 8. Reserved 区间分段政策（Owner D-2；ADR-0073 §15 M-3 的裁定）

```text
0x0E 的分配【不】建立新的 Reserved range segmentation policy。
```

```text
MUST NOT 因本次分配而新增：
    · 0x0E–0x1F = consensus
    · 0x20–…    = sync
    · 或任何类似用途分段
```

```text
ADR-0073 §15 M-3 的裁定:
    No new segmentation policy is established by this allocation.

未来若需要 Reserved 区间按用途分段 ⇒ 必须【另行治理】（独立 ADR），不得由实现或本 ADR 隐含建立。
```

---

## 9. ADR-0073 历史记录（Owner D-4；**不追溯修改**）

```text
ADR-0073 remains unchanged.
```

**MUST NOT** 修改：

```text
ADR-0073 §3 · §5 · §10 · §15
```

本 ADR 明确记录：

> **ADR-0073 的历史登记表保持原文，不进行追溯修改；本次 `0x0E` allocation 由后续同类 governance ADR（本 ADR-0075）正式登记。**

```text
性质 = Historical Drift Record（依 ADR-0073 §4 的既有先例「只记录，不追溯修改」），
      而【不是】对 ADR-0073 的隐式修改。

可验证证据：ADR-0073 SHA256 =
    91C1E79D95097915D2D0DC3003EA9DA4DB0F63B97CD5FCA19479061E1CB62053
（本 ADR 创建后必须保持不变）
```

---

## 10. 测试样本迁移记录（**test-only**；`0x0E` → `0x0C`）

原因：`0x0E` 被既有 unknown-type 负向测试用作样本（Rule M-2 第 4 项），现已由 Owner 分配为
`ConsensusAbandonAttestation` ⇒ 负向样本必须改指向永久 sentinel（§7）。

```text
文件 = crates/network/tests/round_change_wire_tests.rs
性质 = **仅测试用途**（不涉及任何 production protocol semantics）

迁移内容:
· unknown-type 断言样本：0x0E → 0x0C
· fail-closed 复现路径的 raw frame 类型字节：0x0E → 0x0C
· 期望错误值：InvalidMessageType(0x0E) → InvalidMessageType(0x0C)

迁移后:
  0x0E → valid future MessageType（§4；本阶段【未】写入 production 代码，见 §14）
  0x0C → unknown / negative-test sentinel（§7）
```

```text
MUST NOT 在本阶段之外自行扩大迁移范围；MUST NOT 修改 production 代码。
```

---

## 11. Mixed-Version 行为

```text
no protocol-version negotiation      （ADR-0073 §8：Owner D5 = A；minimum protocol_version N 仍 OPEN）
unknown MessageType ⇒ fail closed    （ADR-0073 §8 MUST）
```

旧节点收到 `ConsensusAbandonAttestation(0x0E)`：

```text
0x0E
    ↓
unknown MessageType
    ↓
NetworkError::InvalidMessageType
    ↓
reject / fail closed
```

**MUST NOT** fallback 为：

```text
Vote · QC · Proposal · RoundChangeCertificate
```

```text
mixed-version safety   = preserved（结构性：`TryFrom<u8>` 无该值分支 ⇒ 拒绝；不 crash / 不隐式投票 /
                         不 finality / 不触碰 lock）
mixed-version liveness = not guaranteed for mixed-version deployment（ADR-0073 §8：SAFE 但无活性收益）
```

---

## 12. Wire Envelope 与 Payload 边界（引用，不修改）

```text
· envelope 层 = 既有 network 层规格（既有 framing / 签名 / session / 认证）；本 ADR 不修改。
· payload = ADR-0074 的 112B canonical container（精确长度）。
· 112B payload 远低于既有单消息 payload 上限与 frame 上限 ⇒ 无需 framing 变更。
```

```text
MUST NOT 因本次分配而修改：envelope 结构 · framing · 握手 / 认证 · gossip 参数 ·
                            TCP 传输语义 · protocol-version / capability 字段。
```

---

## 13. 与其它 ADR 的关系

```text
· ADR-0074 : 定义本 MessageType 所承载载荷的 canonical serialization（成对 ADR）。
· ADR-0066 : S1 semantics / 非耦合边界（§9.1/§9.2）/ §15.1 混合版本口径 —— 引用，不修改。
· ADR-0069 : 命名空间分离（§7.1/§7.2/§7.4）—— 引用，不修改；分配 MessageType【不】自动分配 DomainId。
· ADR-0070 : 证书容器规格 —— 与本 ADR 无交集（本 ADR 不定义容器）。
· ADR-0072 : 权威语义（RC 构成 round-change authority）—— 单条 attestation 不构成 authority。
· ADR-0073 : 本 ADR 为其 §9 所允许的「后续同类治理 ADR」；其冻结内容【逐字节不变】。
· ADR-0062 : attestation / certificate 均不得成为 sync target 或 finality evidence（保持不变）。
```

---

## 14. Non-Authorization（本阶段）

```text
本 ADR 冻结的是【治理登记】，不是代码实现。

production code registration = NOT YET
    · `0x0E` MUST NOT 在本阶段被加入 `MessageType` enum
    · 无 `TryFrom<u8>` 分支 · 无 `TryFrom` 变体 · 无 `NetworkEvent` · 无 handler · 无 codec
    · 无 egress / inbound / pool / runtime / validator 改动

O2_IMPLEMENTATION_AUTHORIZED（本 ADR 自身）= NO
（Owner 已于 PHASE 6H-AE §20 授权【下一阶段】实施；D3 network enforcement 仍未授权。）
```

**下一阶段实施时仍严禁**：

```text
new ConsensusEvent · new consensus primitive · change checked_successor · change quorum ·
change QC · change finality · change LockedState · change VoteAccumulator · change VoteLedger ·
change vote journal · change block-safety journal · change S1 · change DomainId 0x10 ·
change ADR-0066 / ADR-0070 / ADR-0072 semantics
Abandon Attestation ≠ Vote ≠ QC ≠ RoundChangeCertificate
```

---

## 15. Provenance

```text
Owning ADR            = ADR-0075
Allocation            = MessageType 0x0E / ConsensusAbandonAttestation
Allocation authority  = Owner-approved allocation（PHASE 6H-AE D-1，2026-10-07）
Canonical payload ADR = ADR-0074
Namespace             = MessageType
Registration vehicle  = 后续同类治理 ADR（ADR-0073 §9 允许）
ADR-0073 modification = NONE（§9；SHA256 保持 91C1E79D…2053）
Sentinel policy       = 0x0C permanently reserved（§7，Owner D-3）
Segmentation policy   = none established by this allocation（§8，Owner D-2）
Date                  = 2026-10-07
Supersedes            = none
Status                = FROZEN
```

---

## 16. References（只读）

```text
ADR-0062（sync 边界）· ADR-0066（S1 / §9.1 / §9.2 / §15.1）· ADR-0069（§7.1/§7.2/§7.4）
ADR-0070（证书容器；与本 ADR 无交集）· ADR-0072（authority 语义）
ADR-0073（§3 登记状态 · §4 Historical Drift Record · §5 `0x0D` record · §8 fail-closed ·
          §9 Rule M-1…M-6 · §10 保留区 · §12 sync 边界 · §15 Open Questions M-1/M-3）
ADR-0074（本 MessageType 的 canonical serialization）
```

---

## 17. Change Log

| 日期 | 事件 | 授权 |
|---|---|---|
| 2026-10-07 | **创建 + FROZEN**（PHASE 6H-AE）：Owner 授权 D-1（`0x0E` = `ConsensusAbandonAttestation`，Owner-approved allocation）、D-2（不建立 Reserved 分段政策）、D-3（`0x0C` = 永久 unknown/negative-test sentinel）、D-4（ADR-0073 保持原文，不追溯修改）、D-6（ADR-B → ADR-0075，FROZEN）；完成 Rule M-2 七项 allocation material；记录 test-only 负向样本迁移（`0x0E` → `0x0C`）；**未**修改 ADR-0073；**未**修改 production 代码 | Owner PHASE 6H-AE D-1/D-2/D-3/D-4/D-6 |
