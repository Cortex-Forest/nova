//! Block 向量校验（STEP 8D-5 — ADR-0029/ADR-0030；schema `block-state-root-v1`）。
//!
//! 链：seed StateStore → `execute_block` → `apply_block` → `state_root` → `verify`（ADR-0029 D-6）。
//! - **valid**：execute 成功 → apply → `verify_block_state_root` == `expected.state_root`。
//! - **invalid**：`execute_block` 返回 [`BlockError`]（nonce conflict / gas over / 参数）→ 状态不变。

use crate::hex;
use crate::json;
use crate::transaction::{build_tx, get_str, parse_account};
use nova_core::state::AccountChange;
use nova_crypto::address::{NetworkId, NovaAddress};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_execution::block::{BlockError, execute_block};
use nova_execution::state_transition::ExecutionContext;
use nova_storage::memory::MemoryBackend;
use nova_storage::node::NodeHash;
use nova_storage::state_root::verify_block_state_root;
use nova_storage::store::StateStore;
use serde_json::Value;

/// Block 向量校验结果。
#[derive(Debug, Clone)]
pub struct BlockValidation {
    pub id: String,
    pub ok: bool,
    pub errors: Vec<String>,
}

/// `BlockError` → 稳定错误名（与生成器一致）。
fn block_error_name(e: &BlockError) -> &'static str {
    match e {
        BlockError::NonceConflict => "NonceConflict",
        BlockError::GasLimitExceeded => "GasLimitExceeded",
        BlockError::InvalidBlockArgument => "InvalidBlockArgument",
    }
}

/// 校验单个 block 向量 JSON。
pub fn validate_block_vector(input: &str) -> BlockValidation {
    let value = match json::parse(input) {
        Ok(v) => v,
        Err(e) => {
            return BlockValidation {
                id: "<parse-error>".into(),
                ok: false,
                errors: vec![format!("parse: {e}")],
            };
        }
    };
    let id = get_str(&value, "id").unwrap_or("<missing-id>").to_string();
    let mut errors: Vec<String> = Vec::new();

    if get_str(&value, "schema_version") != Some("block-state-root-v1") {
        errors.push("schema_version must be 'block-state-root-v1'".into());
    }
    for key in [
        "chain_id",
        "network_id",
        "current_height",
        "fee_burn_bps",
        "max_gas_per_block",
        "initial_state",
        "transactions",
        "expected",
    ] {
        if value.get(key).is_none() {
            errors.push(format!("missing required field: {key}"));
        }
    }
    if !errors.is_empty() {
        return BlockValidation {
            id,
            ok: false,
            errors,
        };
    }

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
    let max_gas_per_block = value
        .get("max_gas_per_block")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    // seed initial_state
    let mut store = StateStore::new(MemoryBackend::new());
    let mut seed: Vec<AccountChange> = Vec::new();
    if let Some(accounts) = value.get("initial_state").and_then(|v| v.get("accounts")) {
        if let Some(obj) = accounts.as_object() {
            for (addr_str, acc) in obj {
                match NovaAddress::decode(addr_str) {
                    Ok(addr) => match parse_account(acc) {
                        Ok((balance, nonce)) => seed.push(AccountChange {
                            address: addr,
                            new_balance: balance,
                            new_nonce: nonce,
                            created: false,
                        }),
                        Err(e) => errors.push(format!("initial_state {addr_str}: {e}")),
                    },
                    Err(e) => errors.push(format!("initial_state {addr_str} address: {e}")),
                }
            }
        } else {
            errors.push("initial_state.accounts must be an object".into());
        }
    }
    if !errors.is_empty() {
        return BlockValidation {
            id,
            ok: false,
            errors,
        };
    }
    if let Err(e) = store.apply(&seed) {
        errors.push(format!("seed apply: {e}"));
        return BlockValidation {
            id,
            ok: false,
            errors,
        };
    }
    let root_before = store.state_root();

    // build txs + sender keys
    let mut txs = Vec::new();
    let mut keys = Vec::new();
    if let Some(arr) = value.get("transactions").and_then(Value::as_array) {
        for (i, entry) in arr.iter().enumerate() {
            match build_tx(entry) {
                Ok(tx) => txs.push(tx),
                Err(e) => errors.push(format!("transactions[{i}]: {e}")),
            }
            match get_str(entry, "sender_public_key")
                .and_then(|pk_hex| hex::decode_strict_lower_hex(pk_hex).ok())
            {
                Some(pk) if pk.len() == 32 => match VerifyingKey::from_bytes(&pk) {
                    Ok(vk) => keys.push(vk),
                    Err(e) => errors.push(format!("transactions[{i}] pk: {e:?}")),
                },
                Some(_) => errors.push(format!("transactions[{i}] pk length != 32")),
                None => errors.push(format!(
                    "transactions[{i}] missing/invalid sender_public_key"
                )),
            }
        }
    } else {
        errors.push("transactions must be an array".into());
    }
    if !errors.is_empty() {
        return BlockValidation {
            id,
            ok: false,
            errors,
        };
    }

    let expected = value.get("expected").cloned().unwrap_or(Value::Null);
    match execute_block(&store, &txs, &keys, &ctx, max_gas_per_block) {
        Ok(ber) => {
            if expected.get("result").and_then(Value::as_str) != Some("valid") {
                errors.push("expected result=valid, got block execution success".into());
            }
            let tx_changes: Vec<&[AccountChange]> = ber
                .tx_transitions
                .iter()
                .map(|t| t.changes.as_slice())
                .collect();
            let actual_root = match store.apply_block(&tx_changes) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(format!("apply_block: {e}"));
                    return BlockValidation {
                        id,
                        ok: false,
                        errors,
                    };
                }
            };
            match expected.get("state_root").and_then(Value::as_str) {
                Some(hex_str) => match hex::decode_strict_lower_hex(hex_str) {
                    Ok(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        if let Err(e) =
                            verify_block_state_root(&NodeHash::from_bytes(arr), &actual_root)
                        {
                            errors.push(format!("state_root mismatch: {e}"));
                        }
                    }
                    _ => errors.push("expected.state_root must be 64-hex".into()),
                },
                None => errors.push("expected missing state_root".into()),
            }
        }
        Err(be) => {
            if expected.get("result").and_then(Value::as_str) != Some("invalid") {
                errors.push("expected result=invalid, got block execution error".into());
            }
            let want_err = expected.get("error").and_then(Value::as_str).unwrap_or("");
            let got_err = block_error_name(&be);
            if want_err != got_err {
                errors.push(format!("block error: expected {want_err}, got {got_err}"));
            }
            if store.state_root() != root_before {
                errors.push("invalid block must not change state root".into());
            }
        }
    }

    BlockValidation {
        id,
        ok: errors.is_empty(),
        errors,
    }
}
