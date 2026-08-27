//! STEP 7E Property Tests（proptest）：Replay Context（ADR-0021）。
//!
//! 覆盖：`check_replay_context`——正确上下文通过；篡改 chain_id / sender network /
//! receiver network ⇒ 对应错误；`current_height > expiration` ⇒ Expired；
//! 远期 expiration 无共识语义（不产生错误）。

use nova_core::transaction::replay::{ReplayError, check_replay_context};
use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::transaction::{TransactionType, TransactionV1};
use proptest::prelude::*;

fn addr(net: NetworkId) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: 1,
        address_type: AddressType::UserAccount,
        network_id: net,
        key_hash: [0x11; 32],
    })
}

fn tx(chain_id: u64, expiration: u64) -> TransactionV1 {
    TransactionV1 {
        version: 0x01,
        chain_id,
        nonce: 0,
        sender: addr(NetworkId::Mainnet),
        receiver: addr(NetworkId::Mainnet),
        amount: 0,
        gas_limit: 0,
        gas_price: 0,
        transaction_type: TransactionType::Transfer,
        payload: Vec::new(),
        expiration,
        signature: [0u8; 64],
    }
}

proptest! {
    #[test]
    fn replay_context(
        chain_id in any::<u64>(),
        expiration in any::<u64>(),
        current_height in any::<u64>(),
    ) {
        let chain = ChainIdentity {
            network_id: NetworkId::Mainnet,
            chain_id,
            genesis_hash: [0u8; 32],
        };
        let t = tx(chain_id, expiration);

        // 正确上下文：current_height <= expiration ⇒ Ok；否则 Expired
        let expect = if current_height > expiration {
            Err(ReplayError::Expired)
        } else {
            Ok(())
        };
        prop_assert_eq!(check_replay_context(&t, &chain, current_height), expect);

        // 篡改 chain_id ⇒ ChainIdMismatch（wrapping_add(1) 恒 ≠ 原值）
        let mut m = t.clone();
        m.chain_id = m.chain_id.wrapping_add(1);
        prop_assert_eq!(
            check_replay_context(&m, &chain, current_height),
            Err(ReplayError::ChainIdMismatch)
        );

        // 篡改 sender network ⇒ NetworkMismatch（network 检查先于 expiration）
        let mut m = t.clone();
        m.sender = addr(NetworkId::Testnet);
        prop_assert_eq!(
            check_replay_context(&m, &chain, current_height),
            Err(ReplayError::NetworkMismatch)
        );

        // 篡改 receiver network ⇒ NetworkMismatch
        let mut m = t.clone();
        m.receiver = addr(NetworkId::Devnet);
        prop_assert_eq!(
            check_replay_context(&m, &chain, current_height),
            Err(ReplayError::NetworkMismatch)
        );
    }
}
