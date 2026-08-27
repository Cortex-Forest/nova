//! STEP 7G Property Tests（proptest）：State Transition（ADR-0023）。
//!
//! 覆盖：成功 transfer 不变量（sender/receiver 余额、nonce、receipt）、self-transfer 单 change、
//! 失败无副作用。

use nova_core::state::{AccountState, EMPTY_CODE_HASH};
use nova_core::transaction::gas_fee::TRANSFER_INTRINSIC_GAS;
use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::key::KeyPair;
use nova_crypto::transaction::{TransactionType, TransactionV1, sign_transaction};
use nova_execution::state_transition::{AccountStateView, ExecutionContext, apply_transaction};
use proptest::prelude::*;
use std::collections::HashMap;

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: 1,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn account_state(balance: u128, nonce: u64) -> AccountState {
    AccountState {
        balance,
        nonce,
        code_hash: EMPTY_CODE_HASH,
        storage_root: [0u8; 32],
    }
}

struct MemState(HashMap<NovaAddress, AccountState>);

impl AccountStateView for MemState {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
        self.0.get(addr).copied()
    }
}

fn ctx() -> ExecutionContext {
    ExecutionContext {
        chain: ChainIdentity {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_hash: [0x11; 32],
        },
        current_height: 0,
        fee_burn_bps: 1_000, // 10%
    }
}

fn sender_addr(kp: &KeyPair) -> NovaAddress {
    NovaAddress::from_verifying_key(
        kp.verifying_key(),
        AddressType::UserAccount,
        NetworkId::Mainnet,
    )
    .unwrap()
}

fn build_tx(
    kp: &KeyPair,
    nonce: u64,
    receiver: NovaAddress,
    amount: u128,
    gas_limit: u64,
    gas_price: u128,
) -> TransactionV1 {
    let mut tx = TransactionV1 {
        version: 0x01,
        chain_id: 1001,
        nonce,
        sender: sender_addr(kp),
        receiver,
        amount,
        gas_limit,
        gas_price,
        transaction_type: TransactionType::Transfer,
        payload: Vec::new(),
        expiration: 1_000_000,
        signature: [0u8; 64],
    };
    sign_transaction(kp.signing_key(), &mut tx).unwrap();
    tx
}

proptest! {
    // 成功 transfer 不变量（非 self；sender 余额充足保证成功）
    #[test]
    fn success_transfer_invariants(
        sender_balance in 1_000_000u128..10_000_000u128,
        receiver_balance in 0u128..1_000_000u128,
        amount in 0u128..1_000_000u128,
        gas_limit in 21_000u64..100_000u64,
        gas_price in 1u128..1_000u128,
        nonce in 0u64..100u64,
    ) {
        let fee_max = (gas_limit as u128) * gas_price;
        let required = amount + fee_max;
        if sender_balance < required {
            return Ok(()); // 保持成功路径
        }
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(&kp);
        let receiver = addr([0x22; 32]);
        let mut st = MemState(HashMap::new());
        st.0.insert(sender, account_state(sender_balance, nonce));
        st.0.insert(receiver, account_state(receiver_balance, 0));

        let tx = build_tx(&kp, nonce, receiver, amount, gas_limit, gas_price);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx()).unwrap();
        let actual_fee = (TRANSFER_INTRINSIC_GAS as u128) * gas_price;

        // sender：扣 amount + actual_fee，nonce+1
        prop_assert_eq!(out.changes.len(), 2, "sender + receiver");
        prop_assert_eq!(out.changes[0].address, sender);
        prop_assert_eq!(out.changes[0].new_balance, sender_balance - amount - actual_fee);
        prop_assert_eq!(out.changes[0].new_nonce, nonce + 1);
        // receiver：加 amount
        prop_assert_eq!(out.changes[1].address, receiver);
        prop_assert_eq!(out.changes[1].new_balance, receiver_balance + amount);
        // receipt 一致性
        prop_assert_eq!(out.receipt.gas_used, TRANSFER_INTRINSIC_GAS);
        prop_assert_eq!(out.receipt.fee_paid, actual_fee);
        prop_assert!(out.receipt.burned_fee <= actual_fee, "burn <= fee");
        prop_assert_eq!(out.gas_used, TRANSFER_INTRINSIC_GAS);
    }

    // self-transfer：single change，net amount = 0，仅扣 fee + nonce+1
    #[test]
    fn self_transfer_single_change(
        sender_balance in 1_000_000u128..10_000_000u128,
        amount in 0u128..1_000_000u128,
        gas_limit in 21_000u64..100_000u64,
        gas_price in 1u128..1_000u128,
        nonce in 0u64..100u64,
    ) {
        let fee_max = (gas_limit as u128) * gas_price;
        let required = amount + fee_max;
        if sender_balance < required {
            return Ok(());
        }
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(&kp);
        let mut st = MemState(HashMap::new());
        st.0.insert(sender, account_state(sender_balance, nonce));

        let tx = build_tx(&kp, nonce, sender, amount, gas_limit, gas_price);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx()).unwrap();
        let actual_fee = (TRANSFER_INTRINSIC_GAS as u128) * gas_price;

        prop_assert_eq!(out.changes.len(), 1, "self-transfer: single change");
        prop_assert_eq!(out.changes[0].address, sender);
        prop_assert_eq!(out.changes[0].new_balance, sender_balance - actual_fee, "net amount = 0");
        prop_assert_eq!(out.changes[0].new_nonce, nonce + 1);
    }

    // 失败（余额不足）无副作用：state / nonce / fee 全不变
    #[test]
    fn balance_insufficient_no_side_effect(
        sender_balance in 0u128..1_000_000u128,
        amount in 1_000_000u128..2_000_000u128,
        gas_limit in 21_000u64..100_000u64,
        gas_price in 1u128..1_000u128,
        nonce in 0u64..100u64,
    ) {
        // required = amount + fee_max > sender_balance（amount >= 1M > balance 上限 1M-1）
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(&kp);
        let receiver = addr([0x33; 32]);
        let mut st = MemState(HashMap::new());
        st.0.insert(sender, account_state(sender_balance, nonce));

        let tx = build_tx(&kp, nonce, receiver, amount, gas_limit, gas_price);
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx()).unwrap_err();
        prop_assert!(
            matches!(err, nova_execution::state_transition::ExecutionError::BalanceInsufficient),
            "expected BalanceInsufficient, got {err:?}"
        );
        // state 不变（原 state 未被修改）
        prop_assert_eq!(st.0[&sender].balance, sender_balance);
        prop_assert_eq!(st.0[&sender].nonce, nonce);
    }
}
