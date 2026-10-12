# ADR-0071: O2 Design & Preparation Record v1

- **Status**: **DRAFT — NOT FROZEN**（+ **OWNER APPROVED DECISIONS**，PHASE 6H-J 批准 / PHASE 6H-L 同步）
  （本文件为**设计与准备记录草案**。**不构成协议修订**、**不授权实现**、**不修改任何既有 ADR**。）
  **治理同步（PHASE 6H-L）**：O-1..O-8 已获 Owner 批准（见 §15 Governance Synchronization Record）；
  `APPROVED ≠ FROZEN`（本文件仍为 DRAFT）；部分参数（capacity / N / 绝对阈值）仍 OPEN。
- **Date**: 2026-10-07
- **Deciders**: Nova Chain 架构组（Owner）
- **Scope**: 承载 PHASE 6H-F 授权的 **D1 / D3 / D4 / D5 / D6 / D7 / D8 / D9** 之
  **设计（design）与准备（preparation）** 内容。**不含任何实现。**
- **Phase provenance**: PHASE 5（E1–E5 证据）→ PHASE 6（O1–O4）→ PHASE 6B/6C（O2 规格 + ADR-0066）→
  PHASE 6G-A/B/C（C-1 实施 + 治理闭合）→ PHASE 6H / 6H-A / 6H-B1 / 6H-B2 / 6H-C / 6H-D / 6H-E（审计 +
  最小 Registry Sync + 前置条件审计）→ **PHASE 6H-F（Owner Decision Gate：D1–D12）** → **PHASE 6H-G（本记录）**
- **关联（只读引用，不修改）**: ADR-0049（Liveness / Pacemaker，FROZEN）· **ADR-0062（Sync Target
  Semantics，PROPOSED）** · **ADR-0066（O2 设计源，DRAFT）** · ADR-0067（DRAFT）· ADR-0069（FROZEN）·
  **ADR-0070（Canonical Serialization，DRAFT）** · ADR-0053（Lock，FROZEN）
- **非授权声明（MUST 保留）**:

```text
This ADR does not authorize any implementation.
It does not authorize RoundChangeCertificate, a codec, signing, verification,
network integration, pacemaker integration, or consensus integration.
```

---

## 1. 授权边界（Owner PHASE 6H-F 决策）

| 决策 | Owner 选择 | 本记录对应节 |
|---|---|---|
| D1 ADR-0049 §3.13 | **A = ADR REVISION DESIGN ONLY** | §3 |
| D2 Serialization ADR | **A = SERIALIZATION ADR DRAFT ONLY** | → 已落实为 **ADR-0070**（独立文件） |
| D3 D-1 Retention/Gossip | **A = AUTHORIZE DESIGN** | §4 |
| D4 D-2 Evidence Bounds | **A = AUTHORIZE DESIGN（候选参数可用，**不得冻结数值**）** | §5 |
| D5 D-3 Bounded Storage | **A = AUTHORIZE DESIGN（保留已批准的 S1）** | §6 |
| D6 D-4 ADR-0062 Boundary | **A = AUTHORIZE DESIGN REVIEW** | §7 |
| D7 D-6 Mixed Version | **A = AUTHORIZE DESIGN** | §8 |
| D8 D-7 Flood/Rate | **A = AUTHORIZE NETWORK SECURITY DESIGN** | §9 |
| D9 ADR-0066 Freeze | **A = FREEZE PREPARATION ONLY** | §10 |
| D10 ADR-0067 | **A = CLEANUP + FREEZE PREPARATION ONLY** | → 已落实于 ADR-0067 §0.7 |
| D11 ADR-0069 | **A = AUTHORIZE FREEZE** | → 已执行（ADR-0069 = FROZEN） |
| D12 ADR-0005 Status | **C = KEEP CURRENT STATUS** | 未改动（`Proposed（待批准）`） |

**未获授权（MUST NOT）**：O2 implementation · production consensus change · production network change ·
ADR-0049 直接修改 · ADR-0066 直接修改 · ADR-0062 修改 · final serialization implementation ·
final numeric evidence bounds · capability implementation · rate-limit implementation ·
deployment · genesis · Akash · commit · push。

**本记录 §3–§9 全部为设计；§10 为准备清单；无任何实现动作。**

## 2. 当前证据基线（PHASE 6H-E 审计，只读）

```text
P-1 = BLOCKED  P-2 = BLOCKED  P-3 = READY  P-4 = BLOCKED
P-5 = BLOCKED  P-6 = BLOCKED  P-7 = BLOCKED
MIXED VERSION = BLOCKED   EVIDENCE BOUNDS = BLOCKED
PERSISTENCE = READY       SAFETY BOUNDARY = CONSISTENT
EXISTING LIVENESS BLOCKERS = PRESENT（5/7 stall · 6/7 flaky · A17 unresolved · upgrade-compat deadlock）
```

```text
本记录不改变上述任何审计结论；仅将 Owner 授权的【设计】逐项展开。
```

---

## 3. §A — ADR-0049 §3.13 Revision Design（D1；DESIGN ONLY）

### 3.1 当前证据（原文，只读）

`docs/adr/ADR-0049-liveness-pacemaker-v1.md` L220–L226：

```text
### 3.13 Timeout Certificate 【FROZEN：NO】
- Nova V1 不需要 TimeoutCertificate / RoundChangeCertificate / PacemakerCertificate。理由：
  1. timeout 是 local event；2. timeout 非 finality proof；3. finality 必须继续依赖 valid PrecommitQC；
  4. local round progression（checked_successor）已足够；5. 避免额外 consensus proof complexity。
- 未来若需要 ⇒ 独立 ADR。
```

### 3.2 冲突定位

```text
§3.13 明确【逐个点名】不需要 RoundChangeCertificate。
ADR-0066（DRAFT）则以 PHASE 5 经验证据否证其第 4 条理由（local round progression 已足够）。
⇒ 直接冲突；且 §3.13 自身规定「未来若需要 ⇒ 独立 ADR」。
```

### 3.3 修订设计（**提案结构，不改 ADR-0049**）

未来修订 ADR（尚未起草）的**建议结构**（内容供 Owner 决定）：

```text
§3.13 拟改为三段式（保留历史 + 修正 + 边界）：

(1) 保留历史陈述：「Nova V1 曾不需要 …（原 5 条理由，原文保留，标注 HISTORICAL）」
(2) 修正陈述：
      · 理由 4（local round progression 已足够）—— 被 PHASE 5 证据否证 ⇒ 撤销
      · 理由 1/2/3/5 —— 仍然成立（timeout 仍是 local event；仍非 finality proof；
        finality 仍 MUST 依赖 valid PrecommitQC；仍避免引入新的 finality 证明）
      · 新增：允许一个【有界 +1】的 round-transition 权威（RoundChangeCertificate），
        其语义、阈值与边界由 ADR-0066 + ADR-0070 定义
(3) 边界（MUST 保持）：
      · 证书 ≠ QC ≠ finality proof；不产生 finality；不解锁不 override lock
      · finality 仍 MUST 依赖 valid PrecommitQC
      · 证书 MUST NOT 进入 RoundEvidence / VoteAccumulator / QcRegistry
```

**该修订波及（须在同一修订 ADR 内处理或显式声明不变）**：§3.4.1（Timer Event Matrix 的
「valid round-change authority」措辞）· §5（Liveness Assumptions）· §6（LIV-12）· §9（Implementation
Boundary）· §11（Validation Requirements）· §12（Consequences）。**§3.3/§3.4 timer 语义保持不变**
（应用证书后 ARM 新 timer，不继承 stale deadline）。

### 3.4 变更分类（判断，非自行决定）

```text
分类 = protocol semantics change + governance amendment
     （不是纯 documentation clarification：它解除一条 FROZEN 禁止并引入新工件类别）
```

### 3.5 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-1 = **A（NEW INDEPENDENT ADR）**。
> ADR-0049 原始历史必须保留；未来 amendment 仅允许 **SUPERSEDE reason 4**，保留 reason 1/2/3/5。
> **本阶段未创建 amendment ADR**；**未修改 ADR-0049**（D = NOT AUTHORIZED）。下方原文为 PHASE 6H-G 时点记录。

```text
U-A1  是否正式起草该修订 ADR（本阶段仅授权 design；起草需另行授权）
U-A2  修订应采用「原地修订 ADR-0049」还是「新 ADR + ADR-0049 交叉引用」（需 Owner 选择）
U-A3  §3.13 的 NO 结论应标记为 SUPERSEDED 还是 HISTORICAL
U-A4  §3.4.1 / §5 / §6 / §9 / §11 / §12 是否同批修订
```

```text
本阶段【未修改 ADR-0049】（hash 复核通过）。
```

## 4. §B — D-1 Retention / Gossip Design（D3）

### 4.1 当前证据

```text
· ADR-0066 §22 D-1 = OPEN：「attestation retention / gossip strategy（有界窗口 K vs on-demand 索取）」
· ADR-0066 §14：证书 ephemeral；重启后可【按需重新获取】（on-demand；策略见 D-1）
· ADR-0066 §15：未来 MUST 具备 new message type / capability negotiation / dedup / flood 保护
· 代码：MessageType 无证书类型（0x01–0x0B 已占）；无证书 gossip 调度器
```

### 4.2 设计提案（两方案对比，**不由本记录选择**）

| 方案 | 机制 | 优点 | 代价 / 风险 |
|---|---|---|---|
| **R-1 有界窗口 K** | 节点保留最近 K 个 `(height, from_round)` 的 attestation 集合，向 peer 主动 gossip | 收敛快；无需请求/响应往返 | 需 K 值（**Owner 参数**）；需 per-peer 去重与限流（D-7）；内存上界 = K × evidence 数 |
| **R-2 纯 on-demand** | 不主动 gossip；节点落后时向 peer 请求「`(height, from_round)` 的 attestation 集合」 | 无背景带宽；无 K 参数；内存占用低 | 需请求/响应协议 + 超时 + 重试（复用既有 sync correlator 思路）；收敛受往返时延限制 |

**共同 MUST（无论选哪一个）**：

```text
· 去重：同一 (height, from_round, validator_id) 只计一次
· 有界：retention 必须显式有界（窗口 K 或请求预算）
· S1 保持：无新增 safety-journal 持久化义务（PHASE 6H D5 = Approve S1）
· 不得使证书成为 finality evidence / lock 依据 / QcRegistry 条目
```

### 4.3 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-4 Retention = **R-2（pure on-demand）**。
> R-1 的 K 值不适用（未选择 R-1）；S1（无新增 safety journal）保持。下方原文为 PHASE 6H-G 时点记录。

```text
U-B1  选择 R-1（有界窗口 K）或 R-2（on-demand）或混合
U-B2  若 R-1：K 的具体数值
U-B3  若 R-2：请求/响应是否复用既有 sync 通道语义（涉及 ADR-0062 边界 ⇒ §7）
U-B4  证书消息是否走 gossip 泛洪或点对点（影响 D-7 设计）
```

```text
本阶段不实现任何 gossip 或 retention 代码。
```

## 5. §C — D-2 Evidence Bounds Design（D4；**候选参数可用，不得冻结数值**）

### 5.1 当前证据

```text
· ADR-0066 §5.2：evidence_count(2B LE)，注释「上限见 D-2（Open Question）」
· ADR-0066 §22 D-2 = OPEN：「evidence maximum count / maximum byte size」
⇒ 三项未定义：max evidence count / max certificate bytes / max validator entries
```

### 5.2 设计提案

```text
编码关系与候选区间见 ADR-0070 §8（C-1 = 21 / C-2 = 100 / C-3 = 1024；均【未冻结】）。
不可协商的既有约束：
  · max bytes MUST ≤ MAX_NETWORK_MESSAGE_PAYLOAD_BYTES（1 MiB，security.rs:41）
  · max count MUST ≤ |ValidatorSet|
```

### 5.3 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-3 = **C-1（`max_evidence_count = 21`；
> `max_certificate_bytes = 2066`）**。已同步至 **ADR-0070 §8 / §16**；数值已批准，ADR-0070 仍 DRAFT（未冻结）。
> 下方原文为 PHASE 6H-G 时点记录。

```text
U-C1  max evidence count 的最终数值（C-1 / C-2 / C-3 / 其他）
U-C2  max certificate bytes 的最终数值（可由 U-C1 派生：50 + 96n）
U-C3  是否引入「按 round 的证书数量上限」与「按 peer 的证书速率上限」（与 §9 耦合）
```

```text
本阶段【未冻结任何数值】；未修改 ADR-0066。
```

## 6. §D — D-3 Bounded Storage Design（D5；**保留已批准的 S1**）

### 6.1 当前证据

```text
· ADR-0066 §10.1：S1 creates no additional safety-journal obligation；Journal dependency = NONE
· ADR-0066 §14：证书 ephemeral（不要求持久化）
· Owner（PHASE 6H D5）：Approve S1 / no new journal  ← 正式设计决定
· Owner（PHASE 6H-F D5）：AUTHORIZE D-3 DESIGN；Preserve S1
⇒ D-3【不得】被解释为需要 journal。
```

### 6.2 设计提案（**仅内存层**）

```text
D-3 的对象 = 内存中的 attestation / certificate 集合的有界化（不是持久化）。

候选（对比，未选择）：
  B-1 固定容量的证书缓存（对标 QcRegistry 的 bounded=64 先例）
  B-2 按 (height, from_round) 有界窗口（与 §4 R-1 的 K 耦合）
  B-3 容量 + TTL 双约束（容量满或超期即淘汰）
共同 MUST：
  · 有界（禁止无界 HashMap）
  · 淘汰策略 MUST deterministic（禁依赖迭代序 / 时钟随机性；时间用逻辑 tick）
  · 淘汰【不得】改变任何 safety 结论（证书本就非 safety 依据）
  · 与 S1 一致：不引入任何 journal 写入
```

### 6.3 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-4 Storage = **B-1（fixed capacity）**。
> **capacity 数值仍为 OPEN**（未选择、未填写）；deterministic 淘汰要求保持；S1 保持。下方原文为 PHASE 6H-G 时点记录。

```text
U-D1  选择 B-1 / B-2 / B-3
U-D2  容量数值与 TTL 数值（若适用）
U-D3  淘汰是否必须可观测（metrics / 日志）
```

```text
本阶段未实现任何缓存结构；未修改任何 journal。
```

## 7. §E — D-4 ADR-0062 Sync-Boundary Design Review（D6）

### 7.1 当前证据（只读）

```text
ADR-0062 = PROPOSED（设计冻结；待 Owner 批准后接线实现），SHA256 = 3A110B2D…4EAC93
全文【0 处】提及 certificate
L135：CanonicalNextCandidate = finality-authorized
L136：commit 授权仍属共识/finality 层职责（不在本 ADR）
L189：Dispatcher 不负责 target inference / consensus / finality / commit
⇒ ADR-0062 目前【不能明确支持】下列三条约束。
```

### 7.2 Owner 指令明确要求保留的三条约束（**MUST，逐字记录**）

```text
RoundChangeCertificate must not become a sync target.
RoundChangeCertificate must not become finality evidence.
RoundChangeCertificate must not alter sync canonicality.
```

### 7.3 设计审查结论

```text
1. 三条约束与 ADR-0062 现有内容【不冲突】（证书不在其 scope 内）。
2. 但 ADR-0062 【未定义】证书与 sync 的关系 ⇒ 按 Owner 规则：D6_SUB_CHECK = BLOCK。
3. 建议（供 Owner 决定）：把三条约束作为【O2 侧约束】写入未来 O2 implementation spec，
   并在获授权时于 ADR-0062 增补一条交叉引用（本阶段【不得】修改 ADR-0062）。
4. 结构理由：sync target 的唯一合法来源是 finality-authorized canonical candidate；
   证书非 finality 证据 ⇒ 结构上不应进入 target 选择路径。
```

### 7.4 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-5 = **A（O2 implementation ADR / spec 作为 boundary 主要载体）**。
> 三条约束（not sync target / not finality evidence / not alter sync canonicality）保持；
> **未修改 ADR-0062**（未获授权）。下方原文为 PHASE 6H-G 时点记录。

```text
U-E1  三条约束的权威载体（O2 implementation spec / ADR-0062 交叉引用 / 新 ADR）
U-E2  是否授权在【未来】修改 ADR-0062 以登记该交叉引用
U-E3  若 §4 选择 R-2（on-demand），证书请求是否复用 sync 通道（⇒ 与 ADR-0062 边界交叉）
```

```text
本阶段【未修改 ADR-0062】（hash 复核通过）。
```

## 8. §F — D-6 Mixed-Version / Capability Design（D7）

### 8.1 当前证据

```text
· 握手含 protocol_version(1B) 与 capabilities（security.rs / session.rs）
· session.rs:73：不支持的 protocol_version ⇒ 拒绝，不降级（无协商）
· 未知 MessageType ⇒ InvalidMessageType（fail-closed；message.rs / network_service.rs）
· capabilities 仅被承载与长度校验，【无协商逻辑】、无按版本启用的功能开关
```

### 8.2 设计提案

```text
M-1 版本门控（minimal）：证书消息仅在双方 protocol_version ≥ N 时启用；
    旧节点对未知类型 fail-closed 拒绝（现状）⇒ 安全但混合期无活性收益。
M-2 能力协商（explicit）：握手 capabilities 中加入 capability bit（例如 0x01 = round-change-cert）；
    双方均声明才启用；未声明 ⇒ 不发不收。
共同 MUST：
  · 混合版本必须 SAFE（ADR-0066 §15.1：旧节点不产生/不消费证书，但其 Vote 仍被接受）
  · 混合版本 MUST NOT 承诺活性收益（no O2 liveness benefit without compatible participation）
  · MUST NOT 要求旧节点拒绝正常 Vote（那会劣化活性）
  · 未知消息 MUST 保持 fail-closed（不得静默忽略或误解释）
```

### 8.3 未决（**PHASE 6H-J OWNER APPROVED**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-6 = **M-1 → M-2（v1 protocol-version gating；`N` 保持 OPEN）**。
> **U-F3（MessageType 取值）→ 候选人 = `0x0D` = OWNER APPROVED CANDIDATE**（非 FROZEN / 非代码分配 / 未实现）。
> **`0x0D` 未在代码中分配**（`crates/network/src/message.rs` 未修改）；正式 wire allocation 仍需独立 gate。
> 下方原文为 PHASE 6H-G 时点记录。

```text
U-F1  选择 M-1 或 M-2（或先 M-1 后 M-2 分阶段）
U-F2  capability bit 的具体编码与命名空间（注意：capability bytes ≠ DomainId ≠ MessageType）
U-F3  新证书消息的 MessageType 取值（当前 0x01–0x0B 已占；0x0C 起可用 ⇒ **需 Owner 分配**）
```

```text
本阶段【未实现 capability 协商】；未分配任何 MessageType。
```

## 9. §G — D-7 Network Flood / Rate-Limit Security Design（D8）

### 9.1 当前证据（只读）

```text
[✓] 通用 message size limit：security.rs:41 MAX_NETWORK_MESSAGE_PAYLOAD_BYTES = 1 MiB
                           message.rs:182 payload.len() > max_msg_bytes ⇒ 拒绝
                           transport frame：len(4B LE) ‖ payload，len ≤ max_frame
[✓] per-peer handshake limit：session.rs:125 per_peer_handshake_limit（默认 3），
                           network_service.rs:745 实施
[△] gossip.rs:22 peer_rate_limit（默认 100）—— 配置字段存在，【未发现实施点】
[✗] per-message-type rate limit：无
[✗] certificate-specific flood protection：无
[△] bounded drain：network_service.rs:336 MAX_FRAMES_PER_CONNECTION = 16
⇒ P-7 = BLOCKED
```

### 9.2 设计提案（**仅设计；禁止修改 production network code**）

```text
N-1 per-peer 速率限制（消息数/逻辑 tick）：需要限流器 + 逻辑时钟（禁墙钟/随机）
N-2 per-message-type 配额：对证书类型单独配额（比通用消息更严）
N-3 去重缓存：按 (height, from_round, validator_id) 去重（与 §4/§6 耦合）
N-4 证书级大小上限：由 ADR-0070 §8 的 max count/bytes 提供（数值未冻结）
N-5 背压：连接级有界队列（现有 MAX_FRAMES_PER_CONNECTION 为雏形）
共同 MUST：
  · 限流器 MUST deterministic（逻辑 tick；禁止墙钟 / 随机 / 线程调度依赖）
  · 拒绝 MUST fail-closed 且可观测
  · 惩罚/ban 策略需 Owner 决定；本记录不定义
```

### 9.3 未决（**PHASE 6H-J OWNER APPROVED DESIGN DIRECTION**）

> **PHASE 6H-J 批准 / PHASE 6H-L 同步（2026-10-07）**：O-8 = **N-1 per-peer rate + N-2 per-message-type quota
> + N-3 dedup + N-4 certificate byte limit**（N-5 = 现有 bounded backpressure，supporting measure）。
> **所有绝对数值（rate / quota / window / peer-score / ban thresholds）= OPEN**（未填写）。
> 下方原文为 PHASE 6H-G 时点记录。

```text
U-G1  是否实施 gossip.rs 中已声明但未实施的 peer_rate_limit（其语义与阈值需定义）
U-G2  证书专属配额数值（与 §5 U-C3 耦合）
U-G3  是否引入 peer scoring / ban（范围可能超出 O2 ⇒ 需单独 ADR）
U-G4  限流的逻辑时钟来源（既有 tick 统一口径）
```

```text
本阶段【未修改】network_service.rs / session.rs / gossip.rs / transport.rs / message.rs。
```

## 10. §H — ADR-0066 Freeze Preparation Checklist（D9；**FREEZE PREPARATION ONLY**）

```text
[ ] P-1 Owner approval of ADR-0066（解除 DRAFT → FROZEN）        → NOT DONE（D9 仅授权 preparation）
[~] P-2 Domain Registry Amendment ADR                              → 实质完成（0x10 已分配 + ADR-0005 已同步）；
                                                                    但 ADR-0066 自身 §16/§17 文本仍写「未分配」（受保护 ⇒ 需授权更新）
[✗] P-3 证书容器 canonical serialization 规格 ADR                  → DRAFTED = ADR-0070（D2 授权）；**未冻结**
[~] P-4 网络 flood / rate-limit 能力（或经批准的补偿控制）          → DESIGN ONLY（§9，D8 授权）；**未实现**
[✗] P-5 ADR-0049 §3.13 / §3.4.1 / §5 / §6 / §9 / §11 / §12 正式修订 → DESIGN ONLY（§3，D1 授权）；**未起草修订 ADR**
[~] P-6 D-1..D-7 全部闭合，或经 Owner 明确接受为受控风险            → D-5 CLOSED；D-1/D-2/D-3/D-4/D-6/D-7 均为 DESIGN ONLY；
                                                                    未闭合、亦未被接受为受控风险
[✗] P-7 Consensus Liveness blocker 整体解除由 Owner 单独裁决        → 仍 PRESENT（5/7 stall · 6/7 flaky · A17 · upgrade-compat）
配套项：
[~] serialization ADR            → ADR-0070 DRAFT（未冻结）
[~] ADR-0049 relationship        → §3 设计（未修订）
[~] network security             → §9 设计（未实现）
[~] mixed version                → §8 设计（未实现）
[~] evidence bounds              → §5 候选（未冻结）
[✓] safety boundary              → CONSISTENT（代码零耦合）
```

```text
⇒ ADR-0066 FREEZE PREPARATION = INCOMPLETE
本阶段【未冻结 ADR-0066】；未修改 ADR-0066（hash 复核通过）。
```

## 11. 剩余 Owner 控制事项（**不得静默决定**）

> **PHASE 6H-L 状态更新（2026-10-07）**：O-1..O-8 已由 Owner 于 **PHASE 6H-J** 批准，
> 详见 §15 Governance Synchronization Record。下方原文列表保留为历史记录（PHASE 6H-G 时点）。
> **仍 OPEN**：storage capacity · minimum protocol_version N · O-8 absolute numeric thresholds。

```text
O-1  ADR-0049 §3.13 修订 ADR 的起草授权（§3 U-A1/U-A2）
O-2  max evidence count / max certificate bytes 的最终数值（§5 U-C1/U-C2）
O-3  D-1 保留/传播方案（R-1 / R-2）与 K 值（§4 U-B1/U-B2）
O-4  D-3 有界存储方案与容量（§6 U-D1/U-D2）
O-5  证书与新 MessageType 的取值分配（§8 U-F3）
O-6  混合版本方案（M-1 / M-2）（§8 U-F1）
O-7  网络限流配额 / peer scoring 范围（§9 U-G2/U-G3）
O-8  D-4 边界约束的权威载体与是否授权修改 ADR-0062（§7 U-E1/U-E2）
O-9  ADR-0066 最终冻结（§10；需 P-1..P-7 闭合或受控风险接受）
```

## 12. Non-Authorization Restatement

```text
This ADR does not authorize any implementation.

O2_IMPLEMENTATION_AUTHORIZED = NO

未授权：RoundChangeCertificate struct / verification / signing / Abandon signing /
        codec / new MessageType / network propagation / pacemaker transition /
        RoundTimer change / round-change logic / QcRegistry / RoundEvidence /
        finality / lock / consensus / sync / deployment / genesis / Akash。
```

## 13. References（只读）

```text
docs/adr/ADR-0049-liveness-pacemaker-v1.md             （§3.3/§3.4/§3.4.1/§3.13/§5/§6/§9/§11/§12）
docs/adr/ADR-0053-lock-justification-override-v1.md    （L-1..L-12，FROZEN）
docs/adr/ADR-0062-sync-target-semantics-v1.md          （PROPOSED；sync 边界）
docs/adr/ADR-0066-round-change-certificate-v1.md       （O2 设计源；§5/§6/§10/§14/§15/§22/§25）
docs/adr/ADR-0067-domain-registry-amendment-v1.md      （§0.6 / §0.7）
docs/adr/ADR-0069-signing-domain-allocation-governance-v1.md（FROZEN）
docs/adr/ADR-0070-roundchangecertificate-canonical-serialization-v1.md（本阶段草案）
crates/network/src/security.rs                         （MAX_NETWORK_MESSAGE_PAYLOAD_BYTES）
crates/network/src/session.rs                          （per_peer_handshake_limit / protocol_version）
crates/network/src/gossip.rs                           （peer_rate_limit 声明）
crates/network/src/network_service.rs                  （MAX_FRAMES_PER_CONNECTION）
crates/node/src/safety_store.rs                        （NOVASAFE journal）
crates/node/src/block_safety.rs                        （NOVABLKS journal）
```

## 14. Change Log

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-10-07 | **ADR-0071 初稿（DRAFT — NOT FROZEN）**：O2 Design & Preparation Record v1。承载 Owner PHASE 6H-F 授权的 D1（§3 ADR-0049 §3.13 修订设计）· D3（§4 D-1 retention/gossip 设计）· D4（§5 D-2 evidence bounds 设计，候选参数未冻结）· D5（§6 D-3 bounded storage 设计，保留 S1）· D6（§7 D-4 ADR-0062 边界设计审查）· D7（§8 D-6 mixed-version/capability 设计）· D8（§9 D-7 flood/rate 设计）· D9（§10 ADR-0066 freeze preparation checklist）；§11 列出 9 项剩余 Owner 控制事项。**未**实现任何代码；**未**修改 ADR-0049 / ADR-0062 / ADR-0066 / ADR-0067 / ADR-0005 / 任何 Rust 源码 / 测试 / Genesis / Akash；**未**分配 MessageType；**未**冻结任何数值 | Owner 授权 PHASE 6H-F D1/D3/D4/D5/D6/D7/D8/D9 —— DESIGN & PREPARATION ONLY |
| 2026-10-07 | **PHASE 6H-L — 治理同步（Owner 授权 A/B/C）**：将 **PHASE 6H-J Owner 批准** 的 O-1..O-8 正式记录（新增 §15 Governance Synchronization Record）；§3.5 / §4.3 / §5.3 / §6.3 / §7.4 / §8.3 / §9.3 的未决状态标记由 `OWNER DECISION REQUIRED` 同步为 `PHASE 6H-J OWNER APPROVED`（**原文保留**）；§11 加状态更新注记。**仍 OPEN**：storage capacity · minimum protocol_version N · O-8 absolute thresholds（**未填写**）。**本文件仍为 DRAFT — NOT FROZEN**；**未**实现任何代码；**未**修改 ADR-0049 / ADR-0062 / ADR-0066 / ADR-0005 / ADR-0067 / ADR-0069 / `message.rs` / 任何 Rust 源码 / Genesis / Akash；**未**分配 MessageType；**未**冻结数值 | Owner 授权 PHASE 6H-K B（PHASE 6H-L 执行）—— DOCUMENTATION SYNCHRONIZATION ONLY |

---

## 15. Governance Synchronization Record（PHASE 6H-L，2026-10-07）

> 本节由 **PHASE 6H-L**（Owner 授权 A/B/C）新增，正式记录 **PHASE 6H-J Owner 批准** 的 O-1..O-8。
> **历史文本未被删除**；§3.5 / §4.3 / §5.3 / §6.3 / §7.4 / §8.3 / §9.3 / §11 的原文保留，仅补充状态注记。

### 15.1 Owner Approvals（PHASE 6H-J）

```text
O-1 = OWNER APPROVED
      New independent ADR for ADR-0049 amendment
      （保留 ADR-0049 历史；未来仅允许 SUPERSEDE reason 4；保留 reason 1/2/3/5）

O-2 = OWNER APPROVED
      Accept ADR-0070 canonical serialization design

O-3 = OWNER APPROVED
      max_evidence_count    = 21
      max_certificate_bytes = 2066

O-4 Retention = OWNER APPROVED
      R-2 pure on-demand

O-4 Storage = OWNER APPROVED
      B-1 fixed capacity（capacity 数值 = OPEN）

O-5 = OWNER APPROVED
      O2 implementation ADR / spec carries boundary

O-6 = OWNER APPROVED
      M-1 -> M-2（v1 protocol-version gating；minimum protocol_version N = OPEN）

O-7 = OWNER APPROVED CANDIDATE
      MessageType candidate = 0x0D
      （NOT FROZEN / NOT ALLOCATED IN CODE / NOT IMPLEMENTED）

O-8 = OWNER APPROVED DESIGN DIRECTION
      N-1 per-peer rate
      N-2 per-message-type quota
      N-3 dedup
      N-4 certificate byte limit
      N-5 existing bounded backpressure（supporting measure only）
```

### 15.2 Still OPEN（不得自行填写）

```text
storage capacity
minimum protocol_version N
O-8 absolute rate / quota / window / peer-score / ban thresholds
```

### 15.3 状态迁移对照

```text
ITEM    | BEFORE (PHASE 6H-G)     | AFTER (PHASE 6H-J / 6H-L)
--------|-------------------------|--------------------------------
O-1     | OWNER DECISION REQUIRED | OWNER APPROVED（new independent ADR）
O-2     | OWNER DECISION REQUIRED | OWNER APPROVED（ADR-0070 design）
O-3     | OWNER DECISION REQUIRED | OWNER APPROVED = 21 / 2066
O-4 Ret | OWNER DECISION REQUIRED | OWNER APPROVED = R-2
O-4 Sto | OWNER DECISION REQUIRED | OWNER APPROVED = B-1（capacity OPEN）
O-5     | OWNER DECISION REQUIRED | OWNER APPROVED（O2 ADR/spec carrier）
O-6     | OWNER DECISION REQUIRED | OWNER APPROVED = M-1 → M-2（N OPEN）
O-7     | OWNER DECISION REQUIRED | OWNER APPROVED CANDIDATE = 0x0D
O-8     | OWNER DECISION REQUIRED | OWNER APPROVED DESIGN DIRECTION = N-1..N-4
Status  | DRAFT — NOT FROZEN      | DRAFT — NOT FROZEN（不变；APPROVED ≠ FROZEN）
```

```text
本记录不授权任何实现：O2_IMPLEMENTATION_AUTHORIZED = NO。
```
