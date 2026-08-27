//! Nova Chain 交易 Replay Protection 上下文校验（STEP 7E — Nonce / Replay Protection）。
//!
//! 严格依据冻结规范：**ADR-0021** §4–§6（N10/N12/N13/N14）。
//!
//! # 边界（ADR-0021）
//! - 只检查 **chain_id / network_id / expiration** 三项（Consensus）。
//! - **不重复实现** signature / domain validation（7D 保证；`domain_id` 在 signed_bytes 中
//!   由构造固定，非交易字段）。
//! - `chain_id` = **cryptographic replay domain**；`network_id` = **address-network
//!   compatibility constraint**（辅助，≠ chain_id）。
//! - `Expired` 只表示 `current_height > expiration`；"太远" 是 Mempool Policy，**无共识语义**
//!   （N14）。
//! - **不实现**：gas / fee / balance sufficiency / state transition / revert（7F/7G）。

use core::fmt;
use nova_crypto::identity::ChainIdentity;
use nova_crypto::transaction::TransactionV1;

/// Replay 上下文错误（ADR-0021 §5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// `tx.chain_id != chain.chain_id`（跨链重放；N10）。
    ChainIdMismatch,
    /// sender / receiver `network_id != chain.network_id`（跨网地址；N12）。
    NetworkMismatch,
    /// `current_height > tx.expiration`（时间窗已过；N13）。
    Expired,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch => write!(f, "chain_id mismatch (cross-chain replay)"),
            Self::NetworkMismatch => write!(f, "network_id mismatch (cross-network address)"),
            Self::Expired => write!(f, "transaction expired"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// 校验交易 replay 上下文（ADR-0021 §5；Consensus）。
///
/// 顺序：
/// 1. `chain_id`：`tx.chain_id == chain.chain_id`（N10；7C 双绑 + 7D 验签之外的纵深防御）。
/// 2. `network_id`：sender / receiver 必须与当前链网络一致（N12；防跨网地址混淆）。
/// 3. `expiration`：`current_height <= tx.expiration`（N13；时间窗）。
///
/// `domain_id` 由 7D 签名验证保证（不在此重复实现）。
pub fn check_replay_context(
    tx: &TransactionV1,
    chain: &ChainIdentity,
    current_height: u64,
) -> Result<(), ReplayError> {
    // 1) chain_id：cryptographic replay domain（主防线）。
    if tx.chain_id != chain.chain_id {
        return Err(ReplayError::ChainIdMismatch);
    }
    // 2) network_id：address-network compatibility constraint（辅助，防地址混淆）。
    if tx.sender.payload().network_id != chain.network_id
        || tx.receiver.payload().network_id != chain.network_id
    {
        return Err(ReplayError::NetworkMismatch);
    }
    // 3) expiration：temporal replay boundary。仅时间已过 ⇒ Expired；
    //    "太远" 是 Mempool Policy，此处无共识语义（N14）。
    if current_height > tx.expiration {
        return Err(ReplayError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};

    fn addr(net: NetworkId) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: 1,
            address_type: AddressType::UserAccount,
            network_id: net,
            key_hash: [0x11; 32],
        })
    }

    fn chain(net: NetworkId, chain_id: u64) -> ChainIdentity {
        ChainIdentity {
            network_id: net,
            chain_id,
            genesis_hash: [0x22; 32],
        }
    }

    fn tx(
        chain_id: u64,
        sender: NovaAddress,
        receiver: NovaAddress,
        expiration: u64,
    ) -> TransactionV1 {
        TransactionV1 {
            version: 0x01,
            chain_id,
            nonce: 0,
            sender,
            receiver,
            amount: 0,
            gas_limit: 0,
            gas_price: 0,
            transaction_type: nova_crypto::transaction::TransactionType::Transfer,
            payload: Vec::new(),
            expiration,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn matching_context_ok() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1001,
            addr(NetworkId::Mainnet),
            addr(NetworkId::Mainnet),
            1_000,
        );
        // current_height <= expiration ⇒ OK
        assert_eq!(check_replay_context(&t, &c, 1_000), Ok(()));
        assert_eq!(check_replay_context(&t, &c, 0), Ok(()));
        // 远期 expiration 不产生错误（N14；"太远" 是 Mempool Policy，无共识语义）
        assert_eq!(check_replay_context(&t, &c, 500), Ok(()));
    }

    #[test]
    fn chain_id_mismatch_rejected() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1002,
            addr(NetworkId::Mainnet),
            addr(NetworkId::Mainnet),
            1_000,
        );
        assert_eq!(
            check_replay_context(&t, &c, 500),
            Err(ReplayError::ChainIdMismatch)
        );
    }

    #[test]
    fn sender_cross_network_rejected() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1001,
            addr(NetworkId::Testnet),
            addr(NetworkId::Mainnet),
            1_000,
        );
        assert_eq!(
            check_replay_context(&t, &c, 500),
            Err(ReplayError::NetworkMismatch)
        );
    }

    #[test]
    fn receiver_cross_network_rejected() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1001,
            addr(NetworkId::Mainnet),
            addr(NetworkId::Devnet),
            1_000,
        );
        assert_eq!(
            check_replay_context(&t, &c, 500),
            Err(ReplayError::NetworkMismatch)
        );
    }

    #[test]
    fn expired_rejected() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1001,
            addr(NetworkId::Mainnet),
            addr(NetworkId::Mainnet),
            999,
        );
        // current_height = 1000 > expiration = 999 ⇒ Expired
        assert_eq!(
            check_replay_context(&t, &c, 1_000),
            Err(ReplayError::Expired)
        );
    }

    #[test]
    fn expired_at_exact_boundary() {
        let c = chain(NetworkId::Mainnet, 1001);
        let t = tx(
            1001,
            addr(NetworkId::Mainnet),
            addr(NetworkId::Mainnet),
            1_000,
        );
        // current_height == expiration ⇒ 有效
        assert_eq!(check_replay_context(&t, &c, 1_000), Ok(()));
        // current_height = expiration + 1 ⇒ Expired
        assert_eq!(
            check_replay_context(&t, &c, 1_001),
            Err(ReplayError::Expired)
        );
    }

    #[test]
    fn replay_error_display() {
        assert_eq!(
            ReplayError::ChainIdMismatch.to_string(),
            "chain_id mismatch (cross-chain replay)"
        );
        assert_eq!(
            ReplayError::NetworkMismatch.to_string(),
            "network_id mismatch (cross-network address)"
        );
        assert_eq!(ReplayError::Expired.to_string(), "transaction expired");
    }
}
