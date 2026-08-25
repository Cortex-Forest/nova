//! Nova Chain 密码学基础设施。
//!
//! # 模块
//! - [`hash`]：**STEP 2 已实现**——`protocol_hash`（SHA-256，协议承诺）与
//!   `content_hash`（BLAKE3，链下内容哈希）。API 边界见 ADR-0006 / ADR-0013。
//! - 签名（Ed25519）、密钥、地址：后续 STEP（经 ADR-0002/0004/0007 评审后实现）。
//!
//! # 纪律（Master Prompt §15/§16）
//! - **禁止自研任何密码学算法**；必须使用经过长期审查的成熟密码库。
//! - 具体选型经 ADR 评审（ADR-0003 / ADR-0006 / ADR-0012）。
//! - 生产代码禁止 `unsafe`（workspace lints）。

pub mod hash;
