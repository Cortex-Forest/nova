//! Transaction 向量校验（STEP 7H — ADR-0024）。
//!
//! 职责：schema 校验 → 六层重算比对 → 结果分类（`apply_transaction`）→ 失败无副作用断言。
//! loader 委托生产实现（`nova_crypto` / `nova_core` / `nova_execution`）重算，**不含生产密码学实现**。
//!
//! # 六层（ADR-0024 §3）
//! - 派生重算（loader 独立计算并比对）：`canonical_tx_payload` / `signed_bytes` /
//!   `message_hash` / `canonical_transaction_bytes` / `txid`。
//! - `signature` 是**输入 + 验证**（fixture 提供；valid 经 `verify`，signature 类 invalid 验证失败）。
//! - 任何一层变化 ⇒ txid 变化（7C/7D proptest + 本 loader 逐层比对固化）。

use crate::hex;
use crate::json;
use nova_core::state::{AccountChange, AccountState};
use nova_core::transaction::gas_fee::TRANSFER_INTRINSIC_GAS;
use nova_crypto::address::{NetworkId, NovaAddress};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_crypto::transaction::{
    TransactionType, TransactionV1, canonical_transaction_bytes, canonical_tx_payload,
    compute_txid, tx_message_hash, tx_signed_bytes,
};
use nova_execution::state_transition::{
    AccountStateView, ExecutionContext, ExecutionError, apply_transaction,
};
use nova_storage::memory::MemoryBackend;
use nova_storage::store::StateStore;
use serde_json::Value;
use std::collections::HashMap;

/// Transaction 向量校验结果。
#[derive(Debug, Clone)]
pub struct TransactionValidation {
    pub id: String,
    pub ok: bool,
    pub errors: Vec<String>,
}

/// 内存账户视图（fixture 驱动；STEP 8 之前仅测试用）。
struct FixtureState {
    accounts: HashMap<NovaAddress, AccountState>,
}

impl AccountStateView for FixtureState {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
        self.accounts.get(addr).copied()
    }
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn parse_u128(s: &str) -> Result<u128, String> {
    s.parse::<u128>()
        .map_err(|_| format!("invalid u128 decimal: {s}"))
}

/// 从 JSON `transaction` 对象构建 TransactionV1。
fn build_tx(value: &Value) -> Result<TransactionV1, String> {
    let t = value
        .get("transaction")
        .ok_or_else(|| "missing field: transaction".to_string())?;
    let version = t
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.version".to_string())? as u8;
    let chain_id = t
        .get("chain_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.chain_id".to_string())?;
    let nonce = t
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.nonce".to_string())?;
    let sender =
        NovaAddress::decode(get_str(t, "sender").ok_or_else(|| "transaction.sender".to_string())?)
            .map_err(|e| format!("transaction.sender: {e}"))?;
    let receiver = NovaAddress::decode(
        get_str(t, "receiver").ok_or_else(|| "transaction.receiver".to_string())?,
    )
    .map_err(|e| format!("transaction.receiver: {e}"))?;
    let amount = parse_u128(get_str(t, "amount").ok_or_else(|| "transaction.amount".to_string())?)?;
    let gas_limit = t
        .get("gas_limit")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.gas_limit".to_string())?;
    let gas_price =
        parse_u128(get_str(t, "gas_price").ok_or_else(|| "transaction.gas_price".to_string())?)?;
    let tt = t
        .get("transaction_type")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.transaction_type".to_string())? as u8;
    let transaction_type =
        TransactionType::try_from(tt).map_err(|e| format!("transaction.transaction_type: {e}"))?;
    let payload = hex::decode_strict_lower_hex(
        get_str(t, "payload_hex").ok_or_else(|| "transaction.payload_hex".to_string())?,
    )
    .map_err(|e| format!("transaction.payload_hex: {e}"))?;
    let expiration = t
        .get("expiration")
        .and_then(Value::as_u64)
        .ok_or_else(|| "transaction.expiration".to_string())?;
    let sig = hex::decode_strict_lower_hex(
        get_str(t, "signature_hex").ok_or_else(|| "transaction.signature_hex".to_string())?,
    )
    .map_err(|e| format!("transaction.signature_hex: {e}"))?;
    if sig.len() != 64 {
        return Err(format!(
            "transaction.signature_hex length {} != 64",
            sig.len()
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig);

    Ok(TransactionV1 {
        version,
        chain_id,
        nonce,
        sender,
        receiver,
        amount,
        gas_limit,
        gas_price,
        transaction_type,
        payload,
        expiration,
        signature,
    })
}

/// 解析账户字段（balance 十进制 / nonce）。
fn parse_account(value: &Value) -> Result<(u128, u64), String> {
    let balance =
        parse_u128(get_str(value, "balance").ok_or_else(|| "account.balance".to_string())?)?;
    let nonce = value
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| "account.nonce".to_string())?;
    Ok((balance, nonce))
}

/// 六层比对 helper。
fn compare_layer(errors: &mut Vec<String>, expected: &Value, key: &str, actual: &str) {
    let want = expected
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    if want != actual {
        errors.push(format!("{key}: expected {want}, recomputed {actual}"));
    }
}

/// 将 ExecutionError 分类为 (phase, error_name)。
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

/// 校验单个 transaction 向量 JSON。
pub fn validate_transaction_vector(input: &str) -> TransactionValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return TransactionValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();
    let mut errors: Vec<String> = Vec::new();

    // ---- schema 校验 ----
    if get_str(&value, "schema_version") != Some("transaction-vector-v1") {
        errors.push("schema_version must be 'transaction-vector-v1'".into());
    }
    for key in [
        "category",
        "chain_id",
        "network_id",
        "current_height",
        "fee_burn_bps",
        "transaction",
        "sender_public_key",
        "account_sender",
        "expected",
    ] {
        if value.get(key).is_none() {
            errors.push(format!("missing required field: {key}"));
        }
    }
    let expected = value.get("expected").cloned().unwrap_or(Value::Null);
    for key in [
        "result",
        "phase",
        "error",
        "canonical_tx_payload",
        "signed_bytes",
        "message_hash",
        "signature",
        "canonical_transaction_bytes",
        "txid",
    ] {
        if expected.get(key).is_none() {
            errors.push(format!("expected missing field: {key}"));
        }
    }

    // ---- 构建交易 ----
    let tx = match build_tx(&value) {
        Ok(t) => t,
        Err(e) => {
            errors.push(e);
            return TransactionValidation {
                id,
                ok: errors.is_empty(),
                errors,
            };
        }
    };

    // ---- 六层重算比对（signature 为输入，不重算）----
    let payload = match canonical_tx_payload(&tx) {
        Ok(b) => hex::encode_lower_hex(&b),
        Err(e) => format!("<err:{e}>"),
    };
    compare_layer(&mut errors, &expected, "canonical_tx_payload", &payload);

    let signed = match tx_signed_bytes(&tx) {
        Ok(b) => hex::encode_lower_hex(&b),
        Err(e) => format!("<err:{e}>"),
    };
    compare_layer(&mut errors, &expected, "signed_bytes", &signed);

    let mh = match tx_message_hash(&tx) {
        Ok(h) => hex::encode_lower_hex(h.as_bytes()),
        Err(e) => format!("<err:{e}>"),
    };
    compare_layer(&mut errors, &expected, "message_hash", &mh);

    // signature：hex 合法 + 64B（输入）
    if let Some(sig) = expected.get("signature").and_then(Value::as_str) {
        match hex::decode_strict_lower_hex(sig) {
            Ok(b) if b.len() == 64 => {}
            Ok(b) => errors.push(format!("expected.signature length {} != 64", b.len())),
            Err(e) => errors.push(format!("expected.signature hex: {e}")),
        }
    }

    let canon = match canonical_transaction_bytes(&tx) {
        Ok(b) => hex::encode_lower_hex(&b),
        Err(e) => format!("<err:{e}>"),
    };
    compare_layer(
        &mut errors,
        &expected,
        "canonical_transaction_bytes",
        &canon,
    );

    let txid = match compute_txid(&tx) {
        Ok(h) => hex::encode_lower_hex(&h),
        Err(e) => format!("<err:{e}>"),
    };
    compare_layer(&mut errors, &expected, "txid", &txid);

    // ---- 执行上下文 ----
    let network_id = match value.get("network_id").and_then(Value::as_u64) {
        Some(n) => NetworkId::try_from(n as u8).unwrap_or(NetworkId::Mainnet),
        None => NetworkId::Mainnet,
    };
    let ctx = ExecutionContext {
        chain: ChainIdentity {
            network_id,
            chain_id: value.get("chain_id").and_then(Value::as_u64).unwrap_or(0),
            genesis_hash: [0u8; 32],
        },
        current_height: value
            .get("current_height")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        fee_burn_bps: value
            .get("fee_burn_bps")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u16,
    };

    // ---- 账户状态 ----
    let mut accounts = HashMap::new();
    let mut account_err = None;
    for (addr_key, acc_key) in [
        ("sender", "account_sender"),
        ("receiver", "account_receiver"),
    ] {
        match value.get(acc_key) {
            Some(Value::Null) | None => {}
            Some(acc) => {
                let addr = if addr_key == "sender" {
                    &tx.sender
                } else {
                    &tx.receiver
                };
                match parse_account(acc) {
                    Ok((balance, nonce)) => {
                        accounts.insert(
                            *addr,
                            AccountState {
                                balance,
                                nonce,
                                code_hash: nova_core::state::EMPTY_CODE_HASH,
                                storage_root: [0u8; 32],
                            },
                        );
                    }
                    Err(e) => account_err = Some(e),
                }
            }
        }
    }
    if let Some(e) = account_err {
        errors.push(e);
    }
    let state = FixtureState { accounts };

    let sender_vk = match expected_verifying_key(&value) {
        Ok(vk) => vk,
        Err(e) => {
            errors.push(e);
            return TransactionValidation {
                id,
                ok: errors.is_empty(),
                errors,
            };
        }
    };

    // ---- 结果分类 ----
    match apply_transaction(&state, &tx, &sender_vk, &ctx) {
        Ok(transition) => {
            // valid：校验 receipt 与上下文/六层一致
            if expected.get("result").and_then(Value::as_str) != Some("valid") {
                errors.push(format!(
                    "expected result=valid, got execution success (expected {:?})",
                    expected.get("result").and_then(Value::as_str)
                ));
            }
            if transition.receipt.tx_hash != compute_txid(&tx).unwrap_or([0u8; 32]) {
                errors.push("receipt.tx_hash != txid".into());
            }
            if transition.receipt.gas_used != TRANSFER_INTRINSIC_GAS {
                errors.push(format!(
                    "receipt.gas_used {} != TRANSFER_INTRINSIC_GAS {}",
                    transition.receipt.gas_used, TRANSFER_INTRINSIC_GAS
                ));
            }
            let actual_fee = (TRANSFER_INTRINSIC_GAS as u128) * tx.gas_price;
            if transition.receipt.fee_paid != actual_fee {
                errors.push(format!(
                    "receipt.fee_paid {} != actual_fee {}",
                    transition.receipt.fee_paid, actual_fee
                ));
            }
            let burned = actual_fee * (ctx.fee_burn_bps as u128) / 10_000;
            if transition.receipt.burned_fee != burned {
                errors.push(format!(
                    "receipt.burned_fee {} != expected burn {}",
                    transition.receipt.burned_fee, burned
                ));
            }
            // 失败无副作用由 apply 的 Ok 路径天然保证（Err 无 StateTransition）
        }
        Err(err) => {
            if expected.get("result").and_then(Value::as_str) != Some("invalid") {
                errors.push(format!(
                    "expected result=invalid, got execution error (expected {:?})",
                    expected.get("result").and_then(Value::as_str)
                ));
            }
            let (phase, error_name) = classify(&err);
            let want_phase = expected.get("phase").and_then(Value::as_str).unwrap_or("");
            if want_phase != phase {
                errors.push(format!("phase: expected {want_phase}, got {phase}"));
            }
            let want_err = expected.get("error").and_then(Value::as_str).unwrap_or("");
            if want_err != error_name {
                errors.push(format!("error: expected {want_err}, got {error_name}"));
            }
        }
    }

    TransactionValidation {
        id,
        ok: errors.is_empty(),
        errors,
    }
}

/// 解析 sender 公钥（hex → VerifyingKey）。
fn expected_verifying_key(value: &Value) -> Result<VerifyingKey, String> {
    let pk_hex = get_str(value, "sender_public_key")
        .ok_or_else(|| "missing sender_public_key".to_string())?;
    let pk =
        hex::decode_strict_lower_hex(pk_hex).map_err(|e| format!("sender_public_key hex: {e}"))?;
    VerifyingKey::from_bytes(&pk).map_err(|e| format!("sender_public_key invalid: {e:?}"))
}

/// 8C-3：在 `StateStore` 上验证完整执行链（`apply_transaction` → `StateStore::apply`）。
///
/// 与 [`validate_transaction_vector`] 不同，本函数以真实 `StateStore`（backend + SMT 双写）
/// 承载执行：
/// - 以 `account_sender`/`account_receiver`（交易前状态）seed store。
/// - **valid**：`apply_transaction` 成功 → `store.apply(changes)` → 每个 change 的 `account()`
///   反映其声明的最终状态、`state_root()` 变化。
/// - **invalid**：`apply_transaction` 返回 `Err` ⇒ store（root/account）不变（失败无副作用）。
/// - 验证 `StateStore` 是确定性承诺：7G 计算结果 → storage 提交 → 状态可读、root 可验证
///   （ADR-0028 D-6）。
pub fn validate_transaction_vector_on_store(input: &str) -> TransactionValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return TransactionValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();
    let mut errors: Vec<String> = Vec::new();

    let tx = match build_tx(&value) {
        Ok(t) => t,
        Err(e) => {
            errors.push(e);
            return TransactionValidation {
                id,
                ok: errors.is_empty(),
                errors,
            };
        }
    };
    let ctx = ExecutionContext {
        chain: ChainIdentity {
            network_id: value
                .get("network_id")
                .and_then(Value::as_u64)
                .map(|n| NetworkId::try_from(n as u8).unwrap_or(NetworkId::Mainnet))
                .unwrap_or(NetworkId::Mainnet),
            chain_id: value.get("chain_id").and_then(Value::as_u64).unwrap_or(0),
            genesis_hash: [0u8; 32],
        },
        current_height: value
            .get("current_height")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        fee_burn_bps: value
            .get("fee_burn_bps")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u16,
    };
    let sender_vk = match expected_verifying_key(&value) {
        Ok(vk) => vk,
        Err(e) => {
            errors.push(e);
            return TransactionValidation {
                id,
                ok: errors.is_empty(),
                errors,
            };
        }
    };

    // 以交易前账户状态 seed store（backend + trie 双写）
    let mut store = StateStore::new(MemoryBackend::new());
    let mut seed: Vec<AccountChange> = Vec::new();
    for (addr_key, acc_key) in [
        ("sender", "account_sender"),
        ("receiver", "account_receiver"),
    ] {
        match value.get(acc_key) {
            Some(Value::Null) | None => {}
            Some(acc) => {
                let addr = if addr_key == "sender" {
                    tx.sender
                } else {
                    tx.receiver
                };
                match parse_account(acc) {
                    Ok((balance, nonce)) => seed.push(AccountChange {
                        address: addr,
                        new_balance: balance,
                        new_nonce: nonce,
                        created: false,
                    }),
                    Err(e) => errors.push(e),
                }
            }
        }
    }
    if !errors.is_empty() {
        return TransactionValidation {
            id,
            ok: false,
            errors,
        };
    }
    if let Err(e) = store.apply(&seed) {
        errors.push(format!("seed apply: {e}"));
        return TransactionValidation {
            id,
            ok: false,
            errors,
        };
    }

    let expected_result = value
        .get("expected")
        .and_then(|e| e.get("result"))
        .and_then(Value::as_str);
    let root_before = store.state_root();
    let sender_before = store.account(&tx.sender);
    let receiver_before = store.account(&tx.receiver);

    match apply_transaction(&store, &tx, &sender_vk, &ctx) {
        Ok(transition) => {
            if expected_result != Some("valid") {
                errors.push("expected result=valid, got execution success".into());
            }
            if let Err(e) = store.apply(&transition.changes) {
                errors.push(format!("store.apply: {e}"));
            }
            // valid：每个 change 应用后 account() 反映其声明状态
            for c in &transition.changes {
                match store.account(&c.address) {
                    Some(acc) => {
                        if acc.balance != c.new_balance {
                            errors.push(format!(
                                "account {:?} balance {} != change new_balance {}",
                                c.address, acc.balance, c.new_balance
                            ));
                        }
                        if acc.nonce != c.new_nonce {
                            errors.push(format!(
                                "account {:?} nonce {} != change new_nonce {}",
                                c.address, acc.nonce, c.new_nonce
                            ));
                        }
                    }
                    None => errors.push(format!(
                        "change account {:?} missing after apply",
                        c.address
                    )),
                }
            }
            // root 变化（valid 执行必有 sender change：nonce+1 / fee）
            if root_before == store.state_root() {
                errors.push("valid tx must change state root".into());
            }
        }
        Err(_err) => {
            if expected_result != Some("invalid") {
                errors.push("expected result=invalid, got execution error".into());
            }
            // 失败无副作用：root 与账户均不变
            if store.state_root() != root_before {
                errors.push("invalid tx must not change state root".into());
            }
            if store.account(&tx.sender) != sender_before {
                errors.push("invalid tx must not change sender account".into());
            }
            if store.account(&tx.receiver) != receiver_before {
                errors.push("invalid tx must not change receiver account".into());
            }
        }
    }

    TransactionValidation {
        id,
        ok: errors.is_empty(),
        errors,
    }
}
