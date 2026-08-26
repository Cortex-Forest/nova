//! STEP 7C Property Tests（proptest）：Transaction canonical serialization / txid。
//!
//! 覆盖：canonical roundtrip（encode→decode→equal）、txid determinism、
//! mutation changes txid、signature 进入 txid、chain_id 篡改检测。

use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::transaction::{
    TransactionType, TransactionV1, canonical_transaction_bytes, canonical_tx_payload,
    compute_txid, decode_transaction,
};
use proptest::collection::vec;
use proptest::prelude::*;

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: 1,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// 随机 TransactionV1（合法地址；任意 payload / signature）。
fn tx() -> impl Strategy<Value = TransactionV1> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u64>(),
        any::<u64>(),
        any::<u128>(),
        any::<u64>(),
        any::<u128>(),
        vec(any::<u8>(), 0..64),
        any::<u64>(),
        any::<[u8; 64]>(),
    )
        .prop_map(
            |(
                khs,
                khr,
                chain_id,
                nonce,
                amount,
                gas_limit,
                gas_price,
                payload,
                expiration,
                signature,
            )| {
                TransactionV1 {
                    version: 0x01,
                    chain_id,
                    nonce,
                    sender: addr(khs),
                    receiver: addr(khr),
                    amount,
                    gas_limit,
                    gas_price,
                    transaction_type: TransactionType::Transfer,
                    payload,
                    expiration,
                    signature,
                }
            },
        )
}

proptest! {
    // Canonical roundtrip + txid determinism + re-encode stability
    #[test]
    fn roundtrip_and_determinism(t in tx()) {
        let bytes = canonical_transaction_bytes(&t).unwrap();
        let d = decode_transaction(&bytes).unwrap();
        prop_assert_eq!(&d, &t, "decode(encode(t)) == t");
        let dbytes = canonical_transaction_bytes(&d).unwrap();
        prop_assert_eq!(&dbytes, &bytes, "re-encode stable");
        let id1 = compute_txid(&t).unwrap();
        let id2 = compute_txid(&d).unwrap();
        prop_assert_eq!(id1, id2, "txid determinism");
    }

    // signature 进入 txid（改签名 ⇒ txid 变）
    #[test]
    fn signature_enters_txid(t in tx()) {
        let mut m = t.clone();
        m.signature[0] ^= 0xff;
        let id1 = compute_txid(&t).unwrap();
        let id2 = compute_txid(&m).unwrap();
        prop_assert_ne!(id1, id2, "signature must enter txid");
    }

    // mutation changes txid（金额 / gas / nonce / chain_id / expiration）
    #[test]
    fn mutation_changes_txid(t in tx()) {
        let base = compute_txid(&t).unwrap();
        let mut m;
        m = t.clone(); m.amount = m.amount.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "amount");
        m = t.clone(); m.gas_limit = m.gas_limit.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "gas_limit");
        m = t.clone(); m.nonce = m.nonce.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "nonce");
        m = t.clone(); m.chain_id = m.chain_id.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "chain_id");
        m = t.clone(); m.expiration = m.expiration.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "expiration");
        m = t.clone(); m.gas_price = m.gas_price.wrapping_add(1);
        prop_assert_ne!(compute_txid(&m).unwrap(), base, "gas_price");
    }

    // signature 不进入 canonical_tx_payload（payload 编码长度与签名无关）
    #[test]
    fn signature_not_in_payload(t in tx()) {
        let mut m = t.clone();
        m.signature[63] ^= 0x01;
        let a = canonical_tx_payload(&t).unwrap();
        let b = canonical_tx_payload(&m).unwrap();
        prop_assert_eq!(&a, &b, "signature must NOT enter canonical_tx_payload");
    }

    // chain_id 篡改检测：payload 内 chain_id 变化 ⇒ decode 后 txid 变化
    #[test]
    fn chain_id_tamper_detected(t in tx()) {
        let bytes = canonical_transaction_bytes(&t).unwrap();
        let mut tampered = bytes.clone();
        tampered[1] ^= 0x01; // payload chain_id 低字节
        let dt = decode_transaction(&tampered).unwrap();
        prop_assert_ne!(compute_txid(&dt).unwrap(), compute_txid(&t).unwrap());
    }
}
