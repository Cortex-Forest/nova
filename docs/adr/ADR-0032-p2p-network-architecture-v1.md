# ADR-0032: P2P Network Architecture V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 9 — P2P Network（架构冻结，9-1）
- 关联：ADR-0005（Domain Separation）、ADR-0006（Hash Policy）、ADR-0012（Crypto Registry）、
  ADR-0009（validator identity 模式）、ADR-0028/0031（Storage 边界——不影响）

## Context

8C-8E 完成单节点确定性闭环。STEP 9 引入多节点通信：peer identity / handshake / message protocol /
gossip / sync 边界。本 ADR 冻结网络架构（N-1~N-7），**不绑定网络实现**（libp2p/QUIC/Noise 延后）。

**9 范围**：nova-network 消息层（NodeId + MessageEnvelope + Message Codec + Transport 抽象 + Gossip 规则 +
Sync 边界）。
**不做**：共识（STEP 10-12）、区块提议/production、完整状态同步、加密传输（Noise/TLS）、DAG、
node 协调层（nova-node）。

## Decision（冻结）

### N-1 — nova-network crate 边界

- 依赖：`nova-network → nova-core`（协议类型）、`nova-network → nova-crypto`（签名/哈希）。
- **禁止** `network → execution`、`network → storage`（消息层不执行状态转换；防 P2P 直接改状态）。
- 分层：未来 `nova-node` 协调 network ↔ execution ↔ storage。

### N-2 — Peer Identity

- **`NodeId([u8; 32])` = Ed25519 公钥 canonical bytes**（非 `Hash(pubkey)`——可直接验证签名、免 key lookup、
  与 validator identity 体系一致）。
- **NodeId（P2P 身份）≠ NovaAddress（链账户）≠ ValidatorId（共识身份）**，三者禁混用。

### N-3 — Transport Abstraction

- `Transport` trait + V0.1 实现：`TcpTransport`（length-prefixed 帧）+ `MemoryTransport`（测试）。
- **libp2p / QUIC / Noise / Kademlia / Gossipsub 暂不引入**（先冻结 Nova 网络协议，不绑定实现；
  STEP 9 后评估 adapter）。

### N-4 — Message Envelope

```rust
pub struct MessageEnvelope {
    pub version: u8,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub sender: NodeId,
    pub signature: [u8; 64],
}
```

- **签名覆盖** `version ‖ message_type ‖ payload`（**不覆盖 sender**——sender 由验证 key 决定）。
- `MessageType` V0.1（7 类）：`Handshake` / `Ping` / `Pong` / `GossipTransaction` /
  `SyncBlockRequest` / `SyncBlockResponse` / `Status`。
- 序列化 canonical binary；envelope 签名用 `protocol_hash`（SHA-256）域分离（独立于链上 Transaction/Vote/Block domain）。

### N-5 — Gossip Rules

- 交易传播：`Receive → Verify Envelope Signature → Validate Tx Basic Rules → Deduplicate → TTL Check →
  Rate Limit → Forward`。
- **禁止** gossip 阶段执行交易（网络层不能影响执行确定性）。
- 参数（数值实现阶段定）：`max_ttl` / `max_msg_bytes` / `peer_rate_limit` / `seen_cache_size`。

### N-6 — Sync Boundary

```rust
pub struct SyncBlockRequest { pub height: u64, pub block_hash: Option<[u8; 32]> }
pub struct SyncBlockResponse { pub blocks: Vec<BlockPayload> }
```

- `BlockPayload` = 原始区块字节占位（完整 Block 格式 PHASE 7）。
- **不实现**：状态下载 / state root 验证链 / fork resolution / checkpoint sync（STEP 10-12 + PHASE 7）。

### N-7 — Security Boundary

- **认证**：envelope Ed25519 签名。
- **防 DoS**：`max_msg_bytes` / rate limit / peer score / ban threshold。
- **消息纪律**：每消息 ID / Version / Encoding / Max Size / Timeout 冻结（Master Prompt §21）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| N-1 | network→core/crypto；禁→execution/storage | 冻结 |
| N-2 | `NodeId` = Ed25519 pubkey（≠ 账户/Validator） | 冻结 |
| N-3 | Transport trait + TCP/Memory；libp2p 延后 | 冻结 |
| N-4 | `MessageEnvelope`（签名覆盖 version‖type‖payload）+ 7 类 | 冻结 |
| N-5 | Gossip（验证后转发 / 去重 / TTL / 限速；禁执行） | 冻结 |
| N-6 | Sync 边界（Request/Response；完整同步延后） | 冻结 |
| N-7 | 安全（签名 / 大小上限 / rate limit / scoring） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| NodeId = Hash(pubkey) | 需 key lookup；不能直接验证签名（N-2） |
| libp2p/QUIC/Noise 直接引入 | 绑定网络实现；先冻结协议（N-3） |
| 签名覆盖 sender | sender 由验证 key 决定，重复绑定（N-4） |
| gossip 阶段执行 tx | 网络层影响执行确定性（N-5） |
| 完整状态同步 | 属共识/PHASE 7（N-6） |

## Consequences

- **正面**：网络协议与实现解耦；消息层确定性（不碰状态）；安全边界明确。
- **成本**：V0.1 自研 transport；完整同步延后。
- **可迁移**：libp2p/QUIC adapter 不破坏上层协议。

## Security Impact

- 防伪装：envelope 签名认证（N-4/N-7）。
- 防 DoS：大小上限 / rate limit / scoring / ban（N-7）。
- 防状态污染：network 不触达 execution/storage（N-1/N-5）。
