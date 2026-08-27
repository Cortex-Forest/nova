//! 生成器（一次性开发工具）：生成 **23 个 Transaction 测试向量**（STEP 7H / ADR-0024）。
//!
//! - 随机 keypair（生成一次，commit fixture；测试运行时不重新生成）。
//! - 运行：`cargo run -p nova-test-vectors --bin gen_transaction_vectors`。
//! - 输出：`tests/vectors/transaction/tx-*.json`（include_str! 内嵌，确定性）。
//! - 六层期望（canonical_tx_payload / signed_bytes / message_hash / signature /
//!   canonical_transaction_bytes / txid）由生产实现重算写入；loader 独立重算比对。

use nova_core::state::{AccountState, EMPTY_CODE_HASH};
use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::key::KeyPair;
use nova_crypto::transaction::{
    TransactionType, TransactionV1, canonical_transaction_bytes, canonical_tx_payload,
    compute_txid, sign_transaction, tx_message_hash, tx_signed_bytes,
};
use nova_execution::state_transition::{
    AccountStateView, ExecutionContext, ExecutionError, apply_transaction,
};
use nova_test_vectors::hex::encode_lower_hex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

const OUT_DIR: &str = "transaction";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    encode_lower_hex(b)
}

fn addr_from_kh(kh: [u8; 32], net: NetworkId) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: 1,
        address_type: AddressType::UserAccount,
        network_id: net,
        key_hash: kh,
    })
}

fn sender_addr(kp: &KeyPair, net: NetworkId) -> NovaAddress {
    NovaAddress::from_verifying_key(kp.verifying_key(), AddressType::UserAccount, net).unwrap()
}

fn account(balance: u128, nonce: u64) -> AccountState {
    AccountState {
        balance,
        nonce,
        code_hash: EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    }
}

/// 内存状态视图（生成器用）。
struct MemState(HashMap<NovaAddress, AccountState>);

impl AccountStateView for MemState {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
        self.0.get(addr).copied()
    }
}

fn classify(err: &ExecutionError) -> (&'static str, String) {
    match err {
        ExecutionError::Signature(e) => ("signature", format!("{e:?}")),
        ExecutionError::Replay(e) => ("replay", format!("{e:?}")),
        ExecutionError::NonceNotCurrent => ("nonce", "NonceNotCurrent".to_string()),
        ExecutionError::Gas(e) => ("gas", format!("{e:?}")),
        ExecutionError::BalanceInsufficient => ("balance", "BalanceInsufficient".to_string()),
        ExecutionError::ReceiverOverflow => ("execution", "ReceiverOverflow".to_string()),
        ExecutionError::SenderOverflow => ("execution", "SenderOverflow".to_string()),
        ExecutionError::NonceExhausted => ("nonce", "NonceExhausted".to_string()),
        ExecutionError::Malformed(e) => ("execution", format!("{e:?}")),
    }
}

/// 单场景数据。
struct Scenario {
    id: String,
    note: String,
    chain_id: u64,
    network_id: u8,
    current_height: u64,
    fee_burn_bps: u16,
    tx: TransactionV1,
    sender_pk: [u8; 32],
    account_sender: Option<(u128, u64)>,
    account_receiver: Option<(u128, u64)>, // None = 不存在
}

#[allow(clippy::too_many_arguments)]
fn mk_tx(
    kp: &KeyPair,
    chain_id: u64,
    nonce: u64,
    sender_net: NetworkId,
    receiver: NovaAddress,
    amount: u128,
    gas_limit: u64,
    gas_price: u128,
    expiration: u64,
) -> TransactionV1 {
    let mut tx = TransactionV1 {
        version: 0x01,
        chain_id,
        nonce,
        sender: sender_addr(kp, sender_net),
        receiver,
        amount,
        gas_limit,
        gas_price,
        transaction_type: TransactionType::Transfer,
        payload: Vec::new(),
        expiration,
        signature: [0u8; 64],
    };
    sign_transaction(kp.signing_key(), &mut tx).unwrap();
    tx
}

fn ctx_of(s: &Scenario) -> ExecutionContext {
    ExecutionContext {
        chain: ChainIdentity {
            network_id: NetworkId::try_from(s.network_id).unwrap_or(NetworkId::Mainnet),
            chain_id: s.chain_id,
            genesis_hash: [0u8; 32],
        },
        current_height: s.current_height,
        fee_burn_bps: s.fee_burn_bps,
    }
}

fn state_of(s: &Scenario) -> MemState {
    let mut accounts = HashMap::new();
    if let Some((b, n)) = s.account_sender {
        accounts.insert(s.tx.sender, account(b, n));
    }
    if let Some((b, n)) = s.account_receiver {
        accounts.insert(s.tx.receiver, account(b, n));
    }
    MemState(accounts)
}

/// 写出单个向量。
fn emit(base: &Path, s: &Scenario) {
    let payload = canonical_tx_payload(&s.tx)
        .map(|b| hex(&b))
        .unwrap_or_default();
    let signed = tx_signed_bytes(&s.tx).map(|b| hex(&b)).unwrap_or_default();
    let mh = tx_message_hash(&s.tx)
        .map(|h| hex(h.as_bytes()))
        .unwrap_or_default();
    let canon = canonical_transaction_bytes(&s.tx)
        .map(|b| hex(&b))
        .unwrap_or_default();
    let txid = compute_txid(&s.tx).map(|h| hex(&h)).unwrap_or_default();

    let (result, phase, error) =
        match apply_transaction(&state_of(s), &s.tx, &verifying_key(s), &ctx_of(s)) {
            Ok(_) => ("valid", Value::Null, Value::Null),
            Err(e) => {
                let (p, name) = classify(&e);
                ("invalid", json!(p), json!(name))
            }
        };

    let account_json = |a: Option<(u128, u64)>| -> Value {
        match a {
            Some((b, n)) => json!({ "balance": b.to_string(), "nonce": n }),
            None => Value::Null,
        }
    };

    let v = json!({
        "schema_version": "transaction-vector-v1",
        "id": s.id,
        "category": "transaction",
        "note": s.note,
        "chain_id": s.chain_id,
        "network_id": s.network_id,
        "current_height": s.current_height,
        "fee_burn_bps": s.fee_burn_bps,
        "transaction": {
            "version": s.tx.version,
            "chain_id": s.tx.chain_id,
            "nonce": s.tx.nonce,
            "sender": s.tx.sender.encode().unwrap(),
            "receiver": s.tx.receiver.encode().unwrap(),
            "amount": s.tx.amount.to_string(),
            "gas_limit": s.tx.gas_limit,
            "gas_price": s.tx.gas_price.to_string(),
            "transaction_type": s.tx.transaction_type.as_u8(),
            "payload_hex": hex(&s.tx.payload),
            "expiration": s.tx.expiration,
            "signature_hex": hex(&s.tx.signature),
        },
        "sender_public_key": hex(&s.sender_pk),
        "account_sender": account_json(s.account_sender),
        "account_receiver": account_json(s.account_receiver),
        "expected": {
            "result": result,
            "phase": phase,
            "error": error,
            "canonical_tx_payload": payload,
            "signed_bytes": signed,
            "message_hash": mh,
            "signature": hex(&s.tx.signature),
            "canonical_transaction_bytes": canon,
            "txid": txid,
        },
    });

    let path = base.join(format!("{}.json", s.id));
    let out = serde_json::to_string_pretty(&v).expect("json");
    std::fs::write(&path, format!("{out}\n")).expect("write");
    println!("wrote: {}", path.display());
}

fn verifying_key(s: &Scenario) -> nova_crypto::signature::VerifyingKey {
    nova_crypto::signature::VerifyingKey::from_bytes(&s.sender_pk).unwrap()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(OUT_DIR);
    std::fs::create_dir_all(&base).expect("create dir");

    let mut scenarios: Vec<Scenario> = Vec::new();
    let mainnet_receiver = addr_from_kh([0x22; 32], NetworkId::Mainnet);
    let testnet_receiver = addr_from_kh([0x33; 32], NetworkId::Testnet);
    let chain = 1001u64;
    let height = 1000u64;
    let bps = 1000u16;

    // ===================== 组 1 — 基础交易 =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            5,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-normal-transfer-001".into(),
            note: "normal transfer: deduct amount+fee, credit receiver, nonce+1".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((10_000_000, 5)),
            account_receiver: Some((500, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            addr_from_kh([0x44; 32], NetworkId::Mainnet),
            0,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-zero-amount-001".into(),
            note: "zero amount: fee charged, nonce+1, receiver NOT created".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: None,
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(&kp, NetworkId::Mainnet);
        let tx = mk_tx(
            &kp,
            chain,
            3,
            NetworkId::Mainnet,
            sender,
            10_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-self-transfer-001".into(),
            note: "self transfer: single change, net amount = 0, only fee deducted".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 3)),
            account_receiver: None,
        });
    }

    // ===================== 组 2 — Nonce =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            7,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-nonce-current-001".into(),
            note: "current nonce (tx.nonce == account.nonce)".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 7)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            4,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-nonce-too-low-001".into(),
            note: "nonce too low (tx.nonce < account.nonce) => NonceNotCurrent".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 5)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            6,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-nonce-future-001".into(),
            note: "future nonce (tx.nonce > account.nonce) => NonceNotCurrent".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 5)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            u64::MAX,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-nonce-max-001".into(),
            note: "nonce exhausted (account.nonce == u64::MAX) => NonceExhausted (N15)".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, u64::MAX)),
            account_receiver: Some((0, 0)),
        });
    }

    // ===================== 组 3 — Gas/Fee =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            2_000,
            50_000,
            7,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-fee-normal-001".into(),
            note: "normal fee (fee_max / required computed without overflow)".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            u64::MAX,
            u128::MAX,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-fee-overflow-001".into(),
            note: "fee overflow (gas_limit * gas_price overflows u128) => FeeMaxOverflow".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            u128::MAX,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-required-overflow-001".into(),
            note: "required overflow (amount + fee_max overflows u128) => RequiredOverflow".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((u128::MAX, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            0,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-gas-limit-invalid-001".into(),
            note: "gas_limit == 0 => InvalidGasParams".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            0,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-gas-price-invalid-001".into(),
            note: "gas_price == 0 => InvalidGasParams".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }

    // ===================== 组 4 — Replay =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            1002,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-wrong-chain-001".into(),
            note: "wrong chain_id (signed for 1002, node chain 1001) => ChainIdMismatch".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Testnet,
            testnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-wrong-network-001".into(),
            note: "wrong network_id (sender testnet, node mainnet) => NetworkMismatch".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            50,
        );
        scenarios.push(Scenario {
            id: "tx-expired-001".into(),
            note: "expired (current_height 1000 > expiration 50) => Expired".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }

    // ===================== 组 5 — Account =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            addr_from_kh([0x55; 32], NetworkId::Mainnet),
            5_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-receiver-created-001".into(),
            note: "implicit creation: receiver absent + positive value => created".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: None,
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            5_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-receiver-existing-001".into(),
            note: "receiver exists: balance credited, not created".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((700, 2)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            addr_from_kh([0x66; 32], NetworkId::Mainnet),
            0,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-zero-value-no-create-001".into(),
            note: "zero value: receiver absent, NOT created (fee charged, nonce+1)".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: None,
        });
    }

    // ===================== 组 6 — Signature =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-signature-valid-001".into(),
            note: "valid signature (verify passes)".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let mut tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        tx.amount += 1; // 篡改 payload（签名仍针对原字段）
        scenarios.push(Scenario {
            id: "tx-modified-payload-001".into(),
            note: "modified payload (amount+1) after signing => SignatureVerificationFailed".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let mut tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000,
            21_000,
            10,
            2_000_000,
        );
        tx.signature[0] ^= 0xff; // 篡改签名
        scenarios.push(Scenario {
            id: "tx-modified-signature-001".into(),
            note: "modified signature (byte flipped) => SignatureVerificationFailed".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((1_000_000, 0)),
            account_receiver: Some((0, 0)),
        });
    }

    // ===================== 组 7 — Execution =====================
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            9,
            NetworkId::Mainnet,
            mainnet_receiver,
            123_456,
            21_000,
            11,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-success-transition-001".into(),
            note: "full success transition: six-layer consistent + receipt fields".into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((50_000_000, 9)),
            account_receiver: Some((1_000, 0)),
        });
    }
    {
        let kp = KeyPair::generate().unwrap();
        let tx = mk_tx(
            &kp,
            chain,
            0,
            NetworkId::Mainnet,
            mainnet_receiver,
            1_000_000,
            21_000,
            10,
            2_000_000,
        );
        scenarios.push(Scenario {
            id: "tx-failed-no-mutation-001".into(),
            note: "balance insufficient at execution => BalanceInsufficient, no state mutation"
                .into(),
            chain_id: chain,
            network_id: 1,
            current_height: height,
            fee_burn_bps: bps,
            tx,
            sender_pk: kp.verifying_key().to_bytes(),
            account_sender: Some((100, 0)),
            account_receiver: Some((0, 0)),
        });
    }

    // ---- 校验数量 + 写入 ----
    assert_eq!(scenarios.len(), 23, "must generate exactly 23 vectors");
    for s in &scenarios {
        emit(&base, s);
    }
    println!("generated {} transaction vectors", scenarios.len());
}
