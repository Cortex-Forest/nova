# ADR-0055: NetworkService Architecture v1

- Status: FROZEN (STEP 10-18C, 2026-09-05)
- Related: ADR-0054（Node Lifecycle）、ADR-0032（P2P Network）、STEP 10-18A / 10-18 IMPLEMENT（待授权）
- Scope: node-local 运行层服务（NetworkService 装配于 NodeRuntime）；不改变 consensus/crypto/safety 语义

## Context

当前 `crates/network`（ADR-0032 / STEP 9）提供 P2P **原语层**：

已有模块：`message.rs`、`transport.rs`、`node_id.rs`、`gossip.rs`、`sync.rs`。
已有能力：`MessageEnvelope`、`MessageType`、`NodeId`、`Transport` trait、`MemoryTransport`、Gossip primitives（`GossipValidator`/`GossipDecision`）、Sync request/response（`SyncBlockRequest`/`SyncBlockResponse`）。

缺失（生产运行所需、当前不存在）：
- NetworkService（统一网络状态服务）
- Peer lifecycle（连接状态机）
- Connection management（connect/disconnect/keepalive/reconnect）
- Routing layer（envelope → consensus / block / sync 分类路由）
- Inbound / outbound queues（事件缓冲与发送队列）

**为什么需要 NetworkService**：原语层只提供「单条消息如何编解码/校验/单跳收发」与「单条 gossip/sync 决策」，没有「节点级网络状态」：谁是我的 peers、如何维持连接、入站消息如何分类并交给 EventLoop、出站消息如何排队发送、断线如何重连。若把这些逻辑散落进 Consensus/EventLoop/Driver，会破坏单一 owner 与「网络不碰共识决策」边界（10-17 PASS）。NetworkService = 把这些网络状态职责集中为 NodeRuntime 下一个可注入、可 shutdown 的服务。

## Decision

定义 `NetworkService` 职责（node-local 网络状态 owner）：

### 1. Peer Management
负责：peer connection state、connect/disconnect、keepalive、reconnect。
不负责：validator selection、consensus decision（网络层不参与谁是 proposer / 是否投票）。

### 2. Transport Management
负责 `Transport` 生命周期：start / send / receive / shutdown。
未来兼容：QUIC / libp2p / Noise（皆为同一 `Transport` 载体实现）。当前不实现 real transport。

### 3. Message Routing
NetworkService 负责按 `MessageType` 把 `MessageEnvelope` 路由到三类：
- Consensus messages（Vote / Proposal → 验证后交 EventLoop→Driver）
- Block messages（→ block/sync 路径）
- Sync messages（→ sync 处理）
但：**NetworkService 不解析 consensus 规则**（不判断 vote/QC 语义，只做传输级分类）。

### 4. Gossip Boundary
可以：gossip broadcast、seen cache、ttl。
不能：判断 vote 正确性、判断 QC、判断 finality。

### 5. Sync Boundary
可以：request block、receive block payload。
Block validity：`NodeBlockAdapter`（应用层）。
Consensus validity：`Consensus transition`（canonical；`verify_vote_input` / `verify_qc` 门面）。

## Ownership
```
NodeRuntime        : 生命周期 owner（创建/持有/shutdown 顺序）
NetworkService     : network state owner（peers/transport/routing/queues）
EventLoop          : event consumer（drain→dispatch；不持网络状态）
ConsensusDriver    : consensus execution owner（submit_*/process_transition_derived）
```
- 谁创建：NodeRuntime.start（consensus+validator 就绪后、EventLoop 前）。
- 谁 shutdown：NodeRuntime.stop（EventLoop → NetworkService → Driver → Storage）。
- 谁 reconnect：NetworkService 内部（peer 策略；EventLoop maintenance 触发或内部定时）。

## Security Boundary
- Network 层**可以**：verify envelope signature、verify NodeId。
- Network 层**不能**：verify consensus vote correctness、verify QC、write SafetyStore、sign messages。
- 身份：`NodeId != ValidatorId`（网络身份与共识身份隔离；envelope sender=NodeId，vote.validator_id=ValidatorId，两层独立验证）。
- 入站只在传输/结构层被接受；任何 consensus 语义验证均由 Node（verify_vote_input/verify_qc）在 EventLoop→Driver 路径完成；无效消息 ⇒ drop，不改 ConsensusState / 不写 SafetyStore / 不触发签名。

## Lifecycle
```
Startup : NodeRuntime → Storage → Consensus → Validator → NetworkService → EventLoop
Shutdown: EventLoop stop → NetworkService shutdown → Driver release → Storage close
Recovery: Network = reconnect（NetworkService 内部）；NetworkService 无持久安全状态（不存私钥/Safety）
```

## Non Goals
本 ADR 不实现：
- real transport（QUIC/libp2p/Noise adapter）
- peer discovery（网络内自动发现协议）
- validator networking（投票专用链路/优先级）
- gossip production（真实 Gossipsub 调度/路由表）
- sync production（完整区块同步引擎/状态同步）
- network encryption（传输加密/握手之上的隐私层）
以上均为后续独立授权/独立 commit 的运行层实现。

---

> DRAFT（STEP 10-18A）。待 Owner 审查后 DESIGN FREEZE → 单独授权 IMPLEMENT。
