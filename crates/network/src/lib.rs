//! Nova Chain P2P 网络层（STEP 9 — P2P Network；ADR-0032）。
//!
//! # 模块
//! - [`node_id`]：**STEP 9-2**——`NodeId`（Ed25519 公钥 canonical bytes；P2P 身份，N-2）。
//! - [`message`]：**STEP 9-2**——`MessageEnvelope` + `MessageType` + canonical codec +
//!   签名/验证（N-4）。
//! - [`transport`]：**STEP 9-3**——`Transport` trait + `MemoryTransport`（N-3；libp2p 延后）。
//! - [`gossip`]：**STEP 9-4**——Gossip 验证/转发决策（N-5；不执行交易）。
//! - [`sync`]：**STEP 9-5**——`SyncBlockRequest`/`SyncBlockResponse` 边界（N-6）。
//!
//! # 边界（ADR-0032 N-1）
//! - 依赖：`network → core`（协议类型）/ `network → crypto`（签名/哈希）。
//! - **禁止** `network → execution` / `network → storage`（消息层不执行状态转换）。
//! - 未实现：libp2p adapter / QUIC / Noise / Gossipsub 调度 / 完整状态同步。

pub mod gossip;
pub mod message;
pub mod node_id;
pub mod sync;
pub mod transport;
