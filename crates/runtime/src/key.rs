//! Key resolution boundary（PHASE 3 STEP 7-D；ADR-0047 Key Resolver Boundary）。
//!
//! - ADR-0042 Block FROZEN ⇒ Block **不携带 sender public key**；
//!   而执行需要 `sender address → public key → verify signature`。
//! - E4 冻结："`sender_keys` 外部传入"（沿用 `execute_block` 契约）。
//!   [`KeyResolver`] 仅是该外部供应的**协议边界契约**（Address → PublicKey）。
//! - **不是 Runtime 自动调用**：冻结的 7-step API 签名不变（④ 仍收 `sender_keys`）；
//!   由调用方（Node 适配层）在调用 ④ 之前经 resolver 构造 `sender_keys`。
//! - 实现方：Node / Wallet / Mempool（本 crate 只定义 trait，不实现、不持有注册表）。
//! - `None` 语义（ADR-0046 §6 / ADR-0047 Security）：**整块拒绝**；
//!   禁止 skip transaction / silent continue / dummy key。

use nova_crypto::address::NovaAddress;
use nova_crypto::signature::VerifyingKey;

/// Address → PublicKey 解析契约（ADR-0047）。
///
/// - `None` ⇒ sender key 未知 ⇒ 调用方**整块拒绝**（禁止 skip）。
/// - 确定性要求：同一 address 在同一链/上下文必须稳定返回同一 key，
///   否则不同节点将产生不同 execution result ⇒ 不同 state_root（破坏确定性）。
pub trait KeyResolver {
    /// 解析 `address` 对应的 verifying key；未知 ⇒ `None`。
    fn resolve(&self, address: NovaAddress) -> Option<VerifyingKey>;
}
