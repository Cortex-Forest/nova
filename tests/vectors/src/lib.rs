//! Nova Chain 协议测试向量基础设施（dev-only）。
//!
//! # 职责（crypto-test-vectors-v1.md §16）
//! 1. Read（`include_str!` 内嵌，确定性——不依赖文件系统顺序/网络/OS 随机）
//! 2. Parse（serde_json + 重复键检测，STEP 1 §21）
//! 3. Validate schema
//! 4. Decode hex（严格小写，§4）
//! 5. Recompute derived values（`signed_bytes` / `message_hash` 按冻结规范，§5/§6/§7）
//! 6. Compare expected values
//! 7. Report failures
//!
//! # 边界（重要）
//! - 本 crate 是**测试基础设施**，**不含任何生产密码学实现**。
//! - `signed_bytes` / `message_hash` 重算依据 `crypto-serialization-v1.md` §10。
//! - Ed25519 签名/公钥验证与 address codec 实现：`NOT_IMPLEMENTED`（STEP 1 不实现），
//!   相关向量标记 `DEFERRED_VALIDATION`，报告 `VECTOR_VALIDATION_READY` 而非伪造 PASS。
//! - JSON 只是 Human-readable Test Vector Format，**不是 Nova 协议编码**（§3）。

pub mod address;
pub mod domain;
pub mod genesis;
pub mod hex;
pub mod json;
pub mod signature;
