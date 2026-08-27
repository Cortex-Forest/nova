//! 生成 block 状态根向量（STEP 8D-5 — ADR-0029/ADR-0030；schema `block-state-root-v1`）。
//!
//! 一次性固化：运行后 fixtures 静态提交；loader 独立重算比对（`validate_block_vector`）。
//! 生成方式：seed StateStore → `execute_block` → `apply_block` → `state_root`。

use nova_core::state::AccountChange;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, VerifyingKey};
use nova_crypto::transaction::{TransactionType, TransactionV1, sign_transaction};
use nova_execution::block::{BlockError, execute_block};
use nova_execution::state_transition::ExecutionContext;
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;
use serde_json::{Value, json};
use std::path::Path;

const OUT_DIR: &str = "block";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn addr_from_kh(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn addr_of(kp: &KeyPair) -> NovaAddress {
    NovaAddress::from_verifying_key(
        kp.verifying_key(),
        AddressType::UserAccount,
        NetworkId::Mainnet,
    )
    .unwrap()
}

fn mk_tx(
    sender: NovaAddress,
    receiver: NovaAddress,
    nonce: u64,
    amount: u128,
    sk: &SigningKey,
    chain_id: u64,
) -> TransactionV1 {
    let mut tx = TransactionV1 {
        version: 0x01,
        chain_id,
        nonce,
        sender,
        receiver,
        amount,
        gas_limit: 100_000,
        gas_price: 1,
        transaction_type: TransactionType::Transfer,
        payload: Vec::new(),
        expiration: 0,
        signature: [0u8; 64],
    };
    sign_transaction(sk, &mut tx).unwrap();
    tx
}

fn ctx(chain_id: u64) -> ExecutionContext {
    ExecutionContext {
        chain: ChainIdentity {
            network_id: NetworkId::Mainnet,
            chain_id,
            genesis_hash: [0u8; 32],
        },
        current_height: 0,
        fee_burn_bps: 0,
    }
}

fn emit(
    base: &Path,
    id: &str,
    note: &str,
    seed: &[(NovaAddress, u128, u64)],
    txs: &[(TransactionV1, &VerifyingKey)],
    chain_id: u64,
    max_gas: u64,
) {
    let store = StateStore::new(MemoryBackend::new());
    let seed_changes: Vec<AccountChange> = seed
        .iter()
        .map(|(a, b, n)| AccountChange {
            address: *a,
            new_balance: *b,
            new_nonce: *n,
            created: false,
        })
        .collect();
    let mut store = store;
    store.apply(&seed_changes).unwrap();

    let tx_only: Vec<TransactionV1> = txs.iter().map(|(t, _)| t.clone()).collect();
    let keys: Vec<VerifyingKey> = txs.iter().map(|(_, vk)| **vk).collect();
    let ctx = ctx(chain_id);

    let (result, error, state_root) = match execute_block(&store, &tx_only, &keys, &ctx, max_gas) {
        Ok(ber) => {
            let changes: Vec<&[AccountChange]> = ber
                .tx_transitions
                .iter()
                .map(|t| t.changes.as_slice())
                .collect();
            let root = store.apply_block(&changes).unwrap();
            ("valid", Value::Null, json!(hex(root.as_bytes())))
        }
        Err(be) => {
            let name = match be {
                BlockError::NonceConflict => "NonceConflict",
                BlockError::GasLimitExceeded => "GasLimitExceeded",
                BlockError::InvalidBlockArgument => "InvalidBlockArgument",
            };
            ("invalid", json!(name), Value::Null)
        }
    };

    let tx_array: Vec<Value> = txs
        .iter()
        .map(|(tx, vk)| {
            json!({
                "sender_public_key": hex(&vk.to_bytes()),
                "transaction": {
                    "version": tx.version,
                    "chain_id": tx.chain_id,
                    "nonce": tx.nonce,
                    "sender": tx.sender.encode().unwrap(),
                    "receiver": tx.receiver.encode().unwrap(),
                    "amount": tx.amount.to_string(),
                    "gas_limit": tx.gas_limit,
                    "gas_price": tx.gas_price.to_string(),
                    "transaction_type": tx.transaction_type.as_u8(),
                    "payload_hex": hex(&tx.payload),
                    "expiration": tx.expiration,
                    "signature_hex": hex(&tx.signature),
                }
            })
        })
        .collect();

    let accounts: serde_json::Map<String, Value> = seed
        .iter()
        .map(|(a, b, n)| {
            (
                a.encode().unwrap(),
                json!({ "balance": b.to_string(), "nonce": n }),
            )
        })
        .collect();

    let v = json!({
        "schema_version": "block-state-root-v1",
        "id": id,
        "note": note,
        "chain_id": chain_id,
        "network_id": 1,
        "current_height": 0,
        "fee_burn_bps": 0,
        "max_gas_per_block": max_gas,
        "initial_state": { "accounts": accounts },
        "transactions": tx_array,
        "expected": { "result": result, "error": error, "state_root": state_root },
    });

    let path = base.join(format!("{id}.json"));
    let out = serde_json::to_string_pretty(&v).expect("json");
    std::fs::write(&path, format!("{out}\n")).expect("write");
    println!("wrote: {}", path.display());
}

fn main() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(OUT_DIR);
    std::fs::create_dir_all(&base).expect("create dir");

    const CHAIN: u64 = 1001;
    const MAX_GAS: u64 = 100_000_000_000;

    // ---- 1. 单 tx 成功 ----
    let kp = KeyPair::generate().unwrap();
    let sender = addr_of(&kp);
    let receiver = addr_from_kh([0x22; 32]);
    let seed = vec![(sender, 1_000_000u128, 0u64)];
    let txs = vec![(
        mk_tx(sender, receiver, 0, 100, kp.signing_key(), CHAIN),
        kp.verifying_key(),
    )];
    emit(
        &base,
        "block-single-transfer-001",
        "single successful transfer",
        &seed,
        &txs,
        CHAIN,
        MAX_GAS,
    );

    // ---- 2. 多 tx（同 sender 连续 nonce）----
    let kp = KeyPair::generate().unwrap();
    let sender = addr_of(&kp);
    let r1 = addr_from_kh([0x31; 32]);
    let r2 = addr_from_kh([0x32; 32]);
    let seed = vec![(sender, 1_000_000u128, 0u64)];
    let txs = vec![
        (
            mk_tx(sender, r1, 0, 100, kp.signing_key(), CHAIN),
            kp.verifying_key(),
        ),
        (
            mk_tx(sender, r2, 1, 200, kp.signing_key(), CHAIN),
            kp.verifying_key(),
        ),
    ];
    emit(
        &base,
        "block-multi-transfer-001",
        "two txs, same sender, nonce 0 then 1",
        &seed,
        &txs,
        CHAIN,
        MAX_GAS,
    );

    // ---- 3. 失败 tx skip（余额不足）----
    let kp_ok = KeyPair::generate().unwrap();
    let kp_bad = KeyPair::generate().unwrap();
    let ok_sender = addr_of(&kp_ok);
    let bad_sender = addr_of(&kp_bad);
    let receiver = addr_from_kh([0x43; 32]);
    let seed = vec![(ok_sender, 1_000_000u128, 0u64), (bad_sender, 10u128, 0u64)];
    let txs = vec![
        (
            mk_tx(ok_sender, receiver, 0, 100, kp_ok.signing_key(), CHAIN),
            kp_ok.verifying_key(),
        ),
        (
            mk_tx(
                bad_sender,
                receiver,
                0,
                1_000_000,
                kp_bad.signing_key(),
                CHAIN,
            ),
            kp_bad.verifying_key(),
        ),
    ];
    emit(
        &base,
        "block-skip-failed-001",
        "second tx insufficient balance => skipped",
        &seed,
        &txs,
        CHAIN,
        MAX_GAS,
    );

    // ---- 4. nonce 冲突 ⇒ Block Invalid ----
    let kp = KeyPair::generate().unwrap();
    let sender = addr_of(&kp);
    let r1 = addr_from_kh([0x54; 32]);
    let r2 = addr_from_kh([0x55; 32]);
    let seed = vec![(sender, 1_000_000u128, 0u64)];
    let txs = vec![
        (
            mk_tx(sender, r1, 0, 100, kp.signing_key(), CHAIN),
            kp.verifying_key(),
        ),
        (
            mk_tx(sender, r2, 0, 200, kp.signing_key(), CHAIN),
            kp.verifying_key(),
        ),
    ];
    emit(
        &base,
        "block-nonce-conflict-001",
        "duplicate (sender, nonce) => Block Invalid",
        &seed,
        &txs,
        CHAIN,
        MAX_GAS,
    );

    // ---- 5. gas 超限 ⇒ Block Invalid ----
    let kp = KeyPair::generate().unwrap();
    let sender = addr_of(&kp);
    let receiver = addr_from_kh([0x66; 32]);
    let seed = vec![(sender, 1_000_000u128, 0u64)];
    let txs = vec![(
        mk_tx(sender, receiver, 0, 100, kp.signing_key(), CHAIN),
        kp.verifying_key(),
    )];
    emit(
        &base,
        "block-gas-over-limit-001",
        "tx gas (21000) > max_gas_per_block (100)",
        &seed,
        &txs,
        CHAIN,
        100,
    );
}
