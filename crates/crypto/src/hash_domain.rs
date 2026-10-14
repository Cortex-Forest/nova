//! YAZIMAO **哈希域命名空间**（Hash Domain Namespace）—— [`HashDomain`]。
//!
//! # 与 `DomainId` 的关系（ADR-0068）
//!
//! - [`DomainId`](crate::domain::DomainId) = **签名域**命名空间：只被
//!   [`build_signed_bytes`](crate::domain::build_signed_bytes) 消费，决定协议**签名消息身份**。
//! - `HashDomain` = **哈希域**命名空间：只被**协议哈希输入**消费（例如确定性 proposer 选择的
//!   种子前缀），**不参与任何签名**。
//!
//! 两者是**不同的 Rust 类型**，且**刻意不提供任何隐式转换**（无 `From` / `Into` / `Deref`）。
//! 因此把 [`HashDomain`] 传给 `build_signed_bytes`（其 `domain_id` 形参类型为
//! [`DomainId`](crate::domain::DomainId)）会在**编译期**被拒绝。
//!
//! # 为什么两个命名空间的数值可以相同
//!
//! 两个命名空间的**用途与构造均不同**：
//! - 签名域进入 `algorithm_id ‖ domain_id ‖ chain_id ‖ payload_length ‖ payload`；
//! - 哈希域进入 `H(hash_domain_byte ‖ …)`（如 `ProposerSeedInput`）。
//!
//! 数值相同**不构成冲突**，因为它们从不出现在同一构造中。**禁止**因数值相同就跨命名空间互传。
//!
//! # 注册纪律（ADR-0068）
//!
//! - 新增 `HashDomain` 取值需要**显式治理批准**（独立于 `DomainId` 注册表）。
//! - 分配一个 `HashDomain` **不会**自动分配任何 `DomainId`。
//! - 未知/未注册取值 ⇒ **必须拒绝**（fail-closed，禁 fallback）。
//!
//! # 类型隔离证明（编译期，机器校验）
//!
//! 正确用法（应编译通过）：
//! ```
//! use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes};
//! use nova_crypto::hash_domain::HashDomain;
//!
//! let d: DomainId = DomainId::Contribution;
//! let h: HashDomain = HashDomain::Proposer;
//! let _ = build_signed_bytes(AlgorithmId::Ed25519, d, 1, b"payload").unwrap();
//! let _ = h.as_u8();
//! ```
//!
//! 误用（**必须编译失败** —— `HashDomain` 不能替代 `DomainId`）：
//! ```compile_fail
//! use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes};
//! use nova_crypto::hash_domain::HashDomain;
//!
//! fn expects_domain(_d: DomainId) {}
//!
//! expects_domain(HashDomain::Proposer);                    // ← 类型不同 ⇒ 编译失败
//! let _ = build_signed_bytes(AlgorithmId::Ed25519, HashDomain::Proposer, 1, b"x");
//! ```
//!
//! # 边界
//!
//! - 本模块**不**提供任何签名路径；[`HashDomain`] **不得**进入 `build_signed_bytes`。
//! - `MessageType`（网络层）与存储 magic 等其它数值命名空间与 `HashDomain` **彼此独立**，
//!   不得互相顶替（ADR-0068 §12）。

use core::fmt;

/// 哈希域错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDomainError {
    /// 未知/未注册哈希域取值（拒绝，禁 fallback）。
    UnknownHashDomain(u8),
}

impl fmt::Display for HashDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownHashDomain(id) => write!(f, "unknown hash_domain: {id:#04x}"),
        }
    }
}

impl std::error::Error for HashDomainError {}

/// 已注册的哈希域（ADR-0068）。
///
/// **注意**：本类型与 [`DomainId`](crate::domain::DomainId) **不是同一命名空间**，
/// 二者之间**无任何转换**（无 `From`/`Into`/`Deref`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HashDomain {
    /// 确定性 proposer 选择的**哈希域前缀**（ADR-0049 §3.7 / ADR-0050 §20 / ADR-0068 §6）。
    ///
    /// - 语义：`ProposerSeedInput[0]`。
    /// - **不是**签名域；**不得**传给
    ///   [`build_signed_bytes`](crate::domain::build_signed_bytes)。
    /// - 取值 `0x07` 与历史实现（原 `DomainId::Proposer = 0x07`）**逐字节一致**，
    ///   因此 `ProposerSeedInput`(57B) / `ProposerSeed` / 确定性 proposer 序列
    ///   **均不变**（ADR-0068 §7）。
    Proposer = 0x07,
}

impl HashDomain {
    /// 底层字节值。
    ///
    /// 使协议哈希输入可以取用该前缀字节；**不**构成与
    /// [`DomainId`](crate::domain::DomainId) 的转换。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for HashDomain {
    type Error = HashDomainError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x07 => Ok(Self::Proposer),
            _ => Err(HashDomainError::UnknownHashDomain(v)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainId;

    #[test]
    fn proposer_hash_domain_is_0x07() {
        assert_eq!(HashDomain::Proposer.as_u8(), 0x07);
        assert_eq!(HashDomain::try_from(0x07), Ok(HashDomain::Proposer));
    }

    #[test]
    fn unknown_hash_domain_rejected_fail_closed() {
        for v in [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0a, 0x10, 0xff,
        ] {
            assert_eq!(
                HashDomain::try_from(v),
                Err(HashDomainError::UnknownHashDomain(v)),
                "hash_domain {v:#04x} 必须被拒绝（fail-closed，禁 fallback）"
            );
        }
    }

    /// **命名空间隔离**：两个**不同**命名空间的数值相同是**刻意合法**的（ADR-0068 §4/§8）。
    #[test]
    fn distinct_namespaces_may_legally_share_a_byte_value() {
        // 签名域：0x07 = Contribution（ADR-0005 注册表 + ADR-0043 FROZEN）
        assert_eq!(DomainId::Contribution.as_u8(), 0x07);
        // 哈希域：0x07 = Proposer 前缀（ADR-0068）
        assert_eq!(HashDomain::Proposer.as_u8(), 0x07);
        // 它们不是同一命名空间 ⇒ 数值相同不构成冲突
    }

    /// 类型隔离（运行期可见部分）；编译期隔离由模块级 `compile_fail` doctest 证明。
    #[test]
    fn namespace_types_are_distinct() {
        fn takes_domain(_d: DomainId) {}
        fn takes_hash(_h: HashDomain) {}

        takes_domain(DomainId::Contribution);
        takes_hash(HashDomain::Proposer);
    }

    #[test]
    fn error_display_is_actionable() {
        let e = HashDomainError::UnknownHashDomain(0x08);
        assert!(e.to_string().contains("0x08"));
    }
}
