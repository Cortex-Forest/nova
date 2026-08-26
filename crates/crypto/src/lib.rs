//! Nova Chain 密码学基础设施。
//!
//! # 模块
//! - [`hash`]：**STEP 2 已实现**——`protocol_hash`（SHA-256，协议承诺）与
//!   `content_hash`（BLAKE3，链下内容哈希）。API 边界见 ADR-0006 / ADR-0013。
//! - [`domain`]：**STEP 3 已实现**——`DomainId`/`AlgorithmId` 注册表校验、
//!   `signed_bytes` 构造（crypto-serialization-v1.md §10）、`SigningMessageHash` newtype。
//! - [`signature`]：**STEP 4 已实现**——Ed25519 封装（`sign_message_hash`/`verify_message_hash`，
//!   仅接受 `SigningMessageHash`，strict canonical verification）。
//! - [`key`]：**STEP 4 已实现**——`KeyPair` 生成（OS CSPRNG 无 fallback）与密钥材料生命周期保护。
//! - 地址（Address）：后续 STEP（ADR-0004 评审后实现）。
//!
//! # 纪律（Master Prompt §15/§16）
//! - **禁止自研任何密码学算法**；必须使用经过长期审查的成熟密码库。
//! - 具体选型经 ADR 评审（ADR-0003 / ADR-0006 / ADR-0012）。
//! - 生产代码禁止 `unsafe`（workspace lints）。

pub mod domain;
pub mod hash;
pub mod key;
pub mod signature;
