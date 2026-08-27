//! Nova Chain 核心协议规则（STEP 7E — Nonce / Replay Protection）。
//!
//! 依赖 `nova-crypto`（协议类型：`TransactionV1` / `ChainIdentity` / `NetworkId`），
//! 实现 **protocol validity** 语义（非 crypto codec；7C/7D 保持在 `nova-crypto`）。

pub mod nonce;
pub mod replay;
