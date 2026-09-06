# ADR-0059: Network Security Architecture v1

## Status

DESIGN FROZEN（STEP 10-18I-K Design Freeze Review，2026-09-06）
Freeze Date: 2026-09-06

Freeze Scope:
本 ADR 冻结 Network Security 架构设计（身份 / 签名域 / 反重放 / 握手 / 会话 /
限流 / 威胁模型 / 安全不变量）。本 ADR 为 Design Only；**不** 授权 production transport /
async runtime / Rc/Arc/Mutex workaround；实现（K 阶段及之后）需另行授权。
Stage K（STEP 10-18I-K）实现 Network Security Primitives v1（纯安全原语 + 确定性编码），
不 wire 进 NetworkService/EventLoop/Runtime。

Implementation Mapping（K 阶段；不改 wire protocol）：
- `NetworkMessageSigningContext` / canonical signing bytes / digest / sign / verify /
  NodeId 绑定 / handshake commitment / SessionNonce·RequestId helper → `crates/network/src/security.rs`。
- 安全域绑定属**演进路径**（既有 `MessageEnvelope` wire 冻结于 ADR-0032 N-4，本阶段不改其
  `sign_message`/`verify_message` 语义；新 primitive 以独立 canonical context 表达，供未来 wire
  演进接入）。

Implementation Status：
- Network Security Primitives: **implemented**（STEP 10-18I-K，`crates/network/src/security.rs`；
  SEC-P1..P19 测试）。
- Handshake / session runtime: **implemented**（STEP 10-18I-L，`crates/network/src/session.rs` +
  `NetworkService` peer-auth gate / session / replay / rate / diagnostics；L-1..L-20 测试）。
- Production Transport: **implemented**（STEP 10-18I-M，`crates/network/src/transport.rs` 同步
  `std::net` `TcpTransport` + length-prefix frame（bounded / 超限拒绝）+ 连接身份首包 + idle
  timeout；无 async runtime / 无第三方网络库；M-1..M-22 测试）。
- Secure Egress: **implemented**（STEP 10-18I-N-IMPL）——`crates/node/src/egress.rs` Node
  Production Egress Adapter：Driver semantic outbound（`OutboundConsensusMessage`，仅验证 PASS
  才 record）→ canonical encoding（`canonical_vote_payload ‖ sig` / `encode_qc` /
  `encode_proposal_ref`）→ `NetworkSigner` 网络签名 envelope → `NetworkService` broadcast/
  enqueue（established-only）→ flush。`NodeRuntime::step` egress 编排：drain driver outbound →
  sign → broadcast → flush（sign 失败 fail-closed；NS 满/无 established 按 backpressure drop）。
  仅 Driver 已 verify 的 QC 可出（`VerifiedQc`）；envelope 签名用网络身份（≠ validator key；
  NS-SEC-8）。N-IMPL-1..7 测试。
- Block sync: **deferred**（SyncBlockRequest/Response primitive 存在，完整 sync 未实现）。
- Peer discovery / Gossipsub: **deferred**。

Related: ADR-0032（P2P Network Architecture）、ADR-0010（Chain Domain Separation）、
ADR-0011（Network Registry）、ADR-0012（Crypto Algorithm Registry）、ADR-0054（Node Lifecycle）、
ADR-0055（NetworkService）、ADR-0056（EventLoop）、ADR-0057（Node Runtime Ownership Migration）、
ADR-0058（Node Runtime Composition Architecture）、STEP 10-18I-I（Production Network Review）。

## Context

已冻结 / 已建立（以代码为准）：

- `NodeId = 网络 Ed25519 公钥 canonical bytes（[u8;32]）`（node_id.rs；`NodeId::from_verifying_key`）。
- `MessageEnvelope{version:u8, message_type:MessageType, payload:Vec<u8>, sender:NodeId,
  signature:[u8;64]}`；wire = `version(1B) ‖ type(1B) ‖ payload_len(4B LE) ‖ payload ‖ sender(32B) ‖
  signature(64B)`；签名覆盖 `signed_payload = version ‖ type ‖ payload`（sender 不签，由验证
  key 派生绑定）；hash 经 `hash_signing_message`（SHA-256 域哈希，独立于链上 domain）。
- `MessageType` 注册：Handshake=0x01 / Ping=0x02 / Pong=0x03 / GossipTransaction=0x04 /
  SyncBlockRequest=0x05 / SyncBlockResponse=0x06 / Status=0x07 / ConsensusVote=0x08 /
  ConsensusProposal=0x09 / ConsensusQc=0x0A / GossipBlock=0x0B。
- `NetworkService<T: Transport>`：envelope 验签 / 身份绑定 / 分类 / 队列（bounded）/ peer
  登记（register/connect/disconnect/remove/is_connected/connected_peers）；不解析共识语义。
- `NetworkIdentity` seam：`NetworkSigner`（node_id + sign_envelope）/ `NetworkIdentityProvider` /
  `SoftwareNetworkIdentity`（注入式；与 validator identity 分离；生产网络 key = GAP-A）。
- `NodeRuntime` Full Composition（f1d14db，ADR-0058）：`Driver + Option<NetworkStack>{NS, EL, signer}`；
  `shutdown(self)`、`step()`、`take_consensus_outbound()` 已落地。

## Problem

生产网络尚未实现（STEP 10-18I-I 结论），且存在三类安全缺口必须先冻结设计：

1. **签名域不绑定链身份**：envelope 签名覆盖 `version‖type‖payload`，**不含**
   `network_id / chain_id / genesis_hash` ⇒ 同一密钥 + 同一 payload 可跨 Mainnet/Testnet/Devnet 重放。
2. **无反重放 / 无握手协议 / 无会话生命周期**：Handshake 仅是 message type（payload opaque）；
   网络层无反重放缓存；无法防连错网络；无法证明 claimed NodeId == 实际公钥身份。
3. **身份密钥生命周期 / 限流 / 信誉未冻结**：生产网络身份仅 seam；无受管密钥持久化；无
   per-peer/global/handshake/request 限流；无无效消息分级处置。

## Goals

- 冻结 Network Security 架构：签名域、反重放、握手、会话、限流、威胁模型、安全不变量。
- 保持 `Network security ≠ Consensus safety`；网络安全层**不取代**共识层安全。
- 与 ADR-0032/0054/0055/0056/0057/0058、Transport trait、MessageEnvelope、ValidatorActor、
  SafetyStore 完全兼容（不破坏既有冻结）。
- 与 transport 无关（安全协议运行在 `Transport` 抽象之上；TCP/QUIC/libp2p 未来可换而不改
  安全语义）。
- 为 J-Freeze 与 K..P 分阶段实现提供精确输入。

## Non-Goals（本 ADR 不授权 / 不涉及）

- 不引入 TCP / QUIC / libp2p / Noise / Kademlia / Gossipsub / async runtime。
- 不实现任何生产代码（本 ADR = design draft）。
- 不重新设计 ValidatorId / SigningCapability / ValidatorActor / SafetyStore / VoteLedger。
- 不修改 MessageEnvelope 既有 wire（现 wire 冻结于 ADR-0032 N-4；本 ADR 定义的签名域扩展
  走**协议演进路径**，见 §Migration；如与 wire 冲突以兼容升级为准）。
- 不引入新的密码算法；不引入 post-quantum 算法（仅 future migration path）。
- 不硬编码未经测试的限流数值（一律 protocol parameter / runtime configuration）。

## Security Model

```text
Network Identity → Message Envelope → Handshake → Peer Session → Anti-Replay
        → NetworkService → EventLoop → NodeConsensusHandler → Command → Runtime → Driver → Consensus
```
关键原则：

```text
Network security  ≠  Consensus safety
网络安全：peer 身份 / 消息签名域 / 反重放 / 会话 / 限流 / DoS。
共识安全：vote verify（verify_vote_input）/ QC verify（verify_qc）/ VoteLedger DV /
SafetyStore / ConsensusState / LockedState / finality —— 全部仍在共识/验证者域。
```
网络安全失败 = fail-closed；但**不映射成共识 finality 决策**。

## Network Identity

冻结：
```text
NetworkIdentity  →  NetworkSigner  →  NodeId            （网络身份域）
ValidatorIdentity →  SigningCapability → ValidatorId    （验证者身份域）
```
- `NodeId`（现状，不重设计）：`NodeId = 网络 Ed25519 公钥 canonical bytes`；
  `NodeId::from_verifying_key` 派生；`NetworkSigner::node_id()` 返回同一值。
- `ValidatorId`（现状，不重设计）：`SHA-256(validator pubkey)`（consensus/crypto 冻结）。
- 二者**语义不可互换**、不互相推导、密钥不同源。Validator private key **绝不**作网络身份。

## Key Lifecycle

生产网络身份密钥生命周期（第一阶段最小 = **encrypted software key**；HSM/KMS/remote signer
为未来扩展，不在当前要求内）：

```text
Generate  Load  Use  Persist  Rotate  Backup/Recovery  Destroy
```
- Generate：显式生成（CSPRNG）或导入；**绝不自动生成并静默持久化永久身份**。
- Load：由 `NetworkIdentityProvider` 加载（不暴露私钥给 Provider 边界外）。
- Use：`NetworkSigner::sign_envelope`；NodeId = pubkey canonical。
- Persist（Phase 1 最小）：**加密**软件存储（如口令派生的对称加密密钥文件），fail-closed；
  文件权限与目录受控；独立于 validator safety 存储目录。
- Rotate：提供显式轮换路径（旧 key 继续验证已见 envelope，新 key 签发新消息 —— 具体策略
  属 K 阶段细化；不得与 validator key rotation 混淆）。
- Backup/Recovery：加密备份 + 显式恢复流程（不硬编码）。
- Destroy：显式销毁（安全擦除）。
- **不变量**：`Network key ≠ Validator private key`；不自动复用；不写入 canonical storage；
  不写入 SafetyStore。

## Canonical Signing Domain

目标：使每条网络消息的签名唯一绑定其链 / 网络上下文。

提议（**设计建议**；wire 定案留 J-Freeze/实现评审，不假定为最终 wire）：

```text
NetworkMessageSigningContext
    = domain_tag
      ‖ network_id
      ‖ chain_id
      ‖ genesis_hash
      ‖ protocol_version
      ‖ message_type
      ‖ payload
```
编码要求：
- domain tag：网络消息签名域专用固定 tag（与链上 Transaction/Vote/Block 域分离）。
- field order 固定；integer 采用 canonical LE；长度前缀固定宽度；genesis_hash / payload 原样
  字节；version 为显式 protocol_version 字段。
- **Canonical 唯一**：不得存在两种不同字节序列表示同一上下文。

兼容分析（现状约束）：
- 现有 `signed_payload = version ‖ type ‖ payload`（+ sender 由验证 key 绑定）已冻结于
  ADR-0032 N-4。**直接改写现有 envelope 会破坏既有冻结**。
- 演进路径（本 ADR 建议，K 阶段定案）：在既有 envelope 之上引入「网络握手建立的
  signed session/chain context」或在 envelope v2 / 握手负载中携带并验证链身份承诺
  （`network_id ‖ chain_id ‖ genesis_hash ‖ protocol_version`），使链身份进入签名/验证域，
  而**不重写**现有共识消息 envelope wire。两种路径二选一在 K-Design 定案（见 Migration）。

## Envelope Security

（现状逐项）
| 项 | 现状 | 本 ADR 要求 |
|---|---|---|
| payload 签名覆盖 | 是 | 保持 |
| message_type 签名覆盖 | 是 | 保持 |
| version 保护 | 是（signed_payload 含 version） | 保持 |
| sender 身份绑定 | 是（verify：vk 派生 NodeId == sender） | 保持 |
| invalid signature | fail-closed（drop + diagnostic） | 保持 |
| 链身份绑定（network/chain/genesis/protocol） | **无** | **新增**（§Canonical Signing Domain；GAP-A/演进） |
| 反重放 | **无** | **新增**（§Anti-Replay） |

## Anti-Replay

**不做** 简单 timestamp 方案。按消息分类设计：

### Class A — Consensus（Vote / Proposal / QC）
- 共识安全**主要由** `height / round / vote_type / target / source / verify_qc / VoteLedger /
  ConsensusState` 负责（网络层反重放不承担共识安全）。
- 网络层仅提供**辅助** replay suppression（见 Replay Cache），用于减少重复传输/放大。

### Class B — Request / Response（SyncBlockRequest / SyncBlockResponse / Status）
- 设计 `request_id / nonce`（canonical；K 阶段定字段）＋ **request-response binding**
  （Response 携带对应 Request 的 nonce）；无绑定匹配 ⇒ drop。

### Class C — Session（Handshake / Ping / Pong）
- 设计 `session_nonce / challenge / expiry`；握手/心跳消息绑定当前 session；过期/不匹配 ⇒
  drop / 会话关闭。

## Replay Cache Ownership

- Replay/session state **不**属于 `ConsensusState / VoteLedger / ValidatorActor`。
- 归属：`NetworkService` owns network replay/session state（经 NetworkStack 属 Runtime）。
- 约束：**bounded、per-peer、expiry-based**（不得无限增长）；满 ⇒ 驱逐最旧/降级新条目并计数。

## Handshake Protocol

现状：`MessageType::Handshake`（0x01）仅为 opaque wire 注册（payload 不解析）；无协议。

设计（最小 canonical handshake，两阶段；需结合现有单 type 决定是复用 0x01 + 结构化 payload
还是新增 type —— K-Design 定案，仅设计）：

```text
HandshakeInit（A → B）：
  network_id ‖ chain_id ‖ genesis_hash ‖ protocol_version ‖
  claimed NodeId(A) ‖ capabilities ‖ session_nonce(A) ‖ signature_A（签上述链身份承诺 + nonce）
HandshakeAck（B → A）：
  接受/拒绝 ‖ session_nonce(B) ‖ 对 A 承诺的确认签名_B（证明 claimed NodeId(B) == 实际 pubkey）
```
验证：
- B 验 A 的链身份承诺 == 自身链身份 ⇒ 否则 **reject / close / 无共识流量**。
- A 验 B 的签名 ⇒ `claimed NodeId(B)` == 实际公钥身份。
- `handshake failure → 不得 continue normal consensus`（fail-closed）。

## Peer Authentication

- `NetworkService` 负责：peer authentication state、NodeId verification、handshake state、
  session lifecycle。
- `Consensus Driver` 负责：validator identity、vote verification、QC verification、finality。
- 两者**不混合**；Driver 永不消费未握手 peer 的 consensus 输入（见 Session Security）。

## Session Security

状态机（网络层）：

```text
Unauthenticated → Handshake → Authenticated → Established → Closing → Closed
```
- 禁止 `Unauthenticated → ConsensusVote / ConsensusQc`（本 ADR 不允许例外）。
- Established 才可承载共识流量（仍须过 NetworkService envelope/身份/反重放 + Driver 门面）。

## Message Acceptance Pipeline

```text
Raw bytes → Frame size check → Envelope decode → Version check → Message type check
 → Network security domain verification（链身份）
 → Node identity verification（sender == vk 派生）
 → Handshake/session validation
 → Anti-replay check
 → Message-specific validation
 → NetworkEvent → EventLoop
```
规定：`NetworkService NEVER finalizes consensus`。

## Invalid Message Policy

| Failure | Action |
|---|---|
| malformed frame | drop |
| oversized frame | drop |
| invalid signature | drop |
| NodeId mismatch | drop |
| wrong network_id | reject |
| wrong chain_id | reject |
| wrong genesis_hash | reject |
| unsupported version | reject |
| invalid handshake | close session |
| replay detected | drop |
| invalid request binding | drop |
| invalid QC | Driver rejects |
| invalid Vote | Driver rejects |
| network failure | 网络层错误；**不映射成 consensus finality** |

## Rate Limiting / DoS

- 限流对象：per-peer、global、handshake、invalid-message、request、gossip、sync。
- 保证：bounded memory / bounded CPU / bounded retry（无 busy-loop、无无限重试）。
- 数值一律为 **protocol parameter / runtime configuration**（本 ADR 不硬编码未经测试数字）。
- 超出 ⇒ drop + diagnostic；持续滥用进 Peer Reputation。

## Peer Reputation

- 分级（不过度复杂）：invalid signature / protocol violation / replay abuse / handshake
  failure / request abuse ⇒ 依次 `disconnect → temporary penalty → ban`。
- 第一阶段**不引入复杂 scoring 算法**。

## Network / Consensus Boundary

- `NS-SEC-6`：NetworkService 不决定共识 finality。
- `NS-SEC-7`：网络安全不取代 ValidatorActor safety。
- Driver 门面（verify_vote_input / verify_qc / submit_proposal）仍是共识输入唯一 choke。

## Transport Independence

- 本安全架构**独立于** TCP/QUIC/libp2p；安全协议运行在 `Transport` 抽象之上。
- 未来可替换 `MemoryTransport → TCP/QUIC/libp2p` 而**不改变**：network security domain、
  handshake semantics、NodeId semantics、anti-replay semantics。

## Quantum-Resistance Position

- 当前网络签名使用 **classical cryptography**（Ed25519 + SHA-256；ADR-0012）。
- **不得宣称「当前网络身份已抗量子」**。
- Post-quantum network identity = **future protocol upgrade path**（新算法经算法注册演进；
  不引入 PQ 算法于本 ADR/本轮）。

## Threat Model

| # | Threat → Attack | Defense | Owner | Residual |
|---|---|---|---|---|
| T1 | forged NodeId | envelope sender==vk 派生绑定 | NetworkService | key 泄漏则伪造（T14） |
| T2 | forged network message | Ed25519 签名验证 fail-closed | NetworkService | — |
| T3 | cross-network replay | 链身份签名域绑定（network/chain/genesis） | NetworkService+演进 | 域绑定上线前存在（K 前） |
| T4 | same-network replay | 反重放缓存 + 共识域守卫 | NetworkService + Consensus | 缓存窗口外靠共识幂等 |
| T5 | malicious peer | peer auth + reputation 分级 | NetworkService | — |
| T6 | malformed packet | decode/结构拒绝 drop | NetworkService | — |
| T7 | oversized packet | max_msg_bytes 拒绝 | NetworkService | — |
| T8 | handshake downgrade | 固定 protocol_version + 拒绝降级 | NetworkService | — |
| T9 | wrong genesis network | handshake 链身份承诺 reject/close | NetworkService | — |
| T10 | validator/network identity confusion | 双身份域隔离 + NS-SEC-8 | node 架构 | 配置错误需引导校验 |
| T11 | peer flooding | per-peer/global 限流 bounded | NetworkService | — |
| T12 | request amplification | request 限流 + request_id binding | NetworkService | — |
| T13 | connection exhaustion | connection/handshake 限流（M 阶段） | NetworkService | — |
| T14 | key compromise | 加密存储 + rotation/destroy 流程 | KeyManager(未来) | 泄露窗口 |
| T15 | transport substitution | 安全域与 transport 解耦（§Transport Independence） | 架构 | — |

## Security Invariants

- `NS-SEC-1` Every authenticated network message is bound to the correct network identity.
- `NS-SEC-2` Network messages are cryptographically separated by network_id + chain_id + genesis_hash.
- `NS-SEC-3` A NodeId cannot be claimed by another network public key.
- `NS-SEC-4` Unauthenticated peers cannot inject authenticated consensus traffic.
- `NS-SEC-5` Replay handling is bounded and cannot cause unbounded memory growth.
- `NS-SEC-6` NetworkService never decides consensus finality.
- `NS-SEC-7` Network security never replaces ValidatorActor safety.
- `NS-SEC-8` Validator identity and Network identity remain independent.
- `NS-SEC-9` Transport implementation cannot redefine the network security domain.
- `NS-SEC-10` Security failure is fail-closed.
（可加，不删以上原则。）

## Migration Plan

```text
J-Design        （本 ADR DRAFT；STEP 10-18I-J）
   ↓
J-Freeze        （Owner Design Freeze Authorization）
   ↓
K-Implementation: Security primitives（链身份签名域上下文 + 签名/验证演进；NetworkSigner 扩展）
   ↓
L-Implementation: Handshake / session / anti-replay cache / peer auth 状态机
   ↓
M-Production Transport（TCP/QUIC/libp2p 择一；独立步骤 + Owner 授权）
   ↓
N-Egress（semantic → envelope → NS fan-out）
   ↓
O-Block Sync
   ↓
P-Production Network Integration
```
> 下一步优先 = **Security ADR Freeze**，不是直接写 Transport。
> 各阶段编号仅作占位说明；是否沿此顺序/是否合并由 Owner 定。

## Testing Strategy

测试矩阵（只设计，不实现；实现阶段逐项落地）：
```
SEC-1 valid signature            SEC-2 invalid signature
SEC-3 sender mismatch            SEC-4 wrong network_id
SEC-5 wrong chain_id             SEC-6 wrong genesis_hash
SEC-7 replay                     SEC-8 cross-network replay
SEC-9 handshake mismatch         SEC-10 session nonce
SEC-11 malformed envelope        SEC-12 oversized envelope
SEC-13 queue exhaustion          SEC-14 peer flood
SEC-15 validator/network identity separation
SEC-16 transport substitution    SEC-17 restart identity stability
```

## Deferred Items

- HSM / KMS / remote signer。
- Post-quantum network identity。
- Production Transport（TCP/QUIC/libp2p 选择）。
- Production egress（fan-out/backpressure）。
- Block sync（完整）。
- 限流具体数值标定（runtime/protocol 参数）。

## Alternatives Considered

- 仅 timestamp 反重放：拒绝（时钟不可信、可重放窗口）。
- 复用 validator key 作网络身份：拒绝（NS-SEC-8；validator 泄漏危及共识）。
- 直接把链身份塞进既有 envelope wire：记录兼容成本 —— 保留为演进路径（K-Design 二选一）。
- 引入复杂 peer scoring：拒绝（第一阶段分级足够）。

## Compatibility

- ADR-0032（P2P N-1..N-7）/ ADR-0055 / ADR-0056 / ADR-0057 / ADR-0058：**兼容**（本 ADR 不
  改 Runtime ownership、不改 EventLoop/NetworkService 既有结构）。
- Transport trait / MessageEnvelope（N-4 wire）：本 ADR **不重写**；签名域扩展走演进路径。
- ValidatorActor / SafetyStore / VoteLedger / ConsensusState：**零改动**。
- 如实现阶段发现与上述冻结冲突 ⇒ 标记 Compatibility issue 并 STOP，不自行修改旧 ADR。

## Decision

（待 Owner Design Freeze。）本 ADR 冻结 Network Security 架构设计；批准后进入 J-Freeze，
随后按 K..P 顺序（各自授权）实现。本 ADR 不授权任何生产代码 / 新依赖 / 新 transport。
