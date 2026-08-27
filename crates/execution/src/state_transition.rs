//! Nova Chain 状态转换引擎（STEP 7G — State Transition）。
//!
//! 严格依据冻结规范：**ADR-0023**（G1–G3、G-E、G-F、G-I、G-J、G-K）、ADR-0019（四状态）、
//! ADR-0021（7E nonce/replay）、ADR-0022（7F gas/fee）。
//!
//! # 边界（ADR-0023）
//! - [`apply_transaction`] 是**纯函数**：不直接修改 state，返回确定性 [`StateTransition`]。
//! - 执行顺序（G2）：signature → replay → gas → load sender → nonce → balance → 执行 →
//!   扣费 → burn → nonce+1 → commit。
//! - **calculate first, commit last**（G-E）：全部计算/校验通过后才构建 `AccountChange`，
//!   无半状态污染。
//! - **原子性（G-I）**：成功提交全部；失败提交无。
//! - `AccountChange` 顺序 sender → receiver（G-J；self-transfer 仅 sender）。
//! - 失败（Invalid / Failed）⇒ nonce 不变、fee 无、state 无、**无 receipt**（G-B/G-E/G-K）。
//! - **不实现**：storage / trie / state root（STEP 8）、区块 gas 聚合（Block STEP）、WASM。

use core::fmt;
use nova_core::state::{
    AccountChange, AccountState, StateTransition, TransactionReceipt, TxStatus,
};
use nova_core::transaction::gas_fee::{
    TRANSFER_INTRINSIC_GAS, check_balance_sufficient, check_gas_params, compute_actual_fee,
    compute_burn, compute_fee_max, compute_required,
};
use nova_core::transaction::nonce::{NonceClass, checked_next_nonce, classify_nonce};
use nova_core::transaction::replay::{ReplayError, check_replay_context};
use nova_crypto::address::NovaAddress;
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_crypto::transaction::{
    TransactionError, TransactionV1, compute_txid, verify_transaction_signature,
};

/// 状态视图（STEP 8 实现 storage；7G 只定义接口）。
///
/// `None` = 账户不存在（逻辑默认：balance=0, nonce=0, code_hash=EMPTY_CODE_HASH,
/// storage_root=EMPTY_STORAGE_ROOT）。
pub trait AccountStateView {
    /// 读取账户；`None` 表示不存在。
    fn account(&self, addr: &NovaAddress) -> Option<AccountState>;
}

/// 执行上下文（**只读**；禁止写入）。
#[derive(Debug, Clone, Copy)]
pub struct ExecutionContext {
    pub chain: ChainIdentity,
    pub current_height: u64,
    /// 来自 EconomicsParamsV1（≤10_000；Genesis 已保证）。
    pub fee_burn_bps: u16,
}

/// 执行错误（ADR-0023 G-F）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionError {
    /// 7D：签名 / 身份验证失败。
    Signature(TransactionError),
    /// 7E：replay 上下文（chain_id / network_id / expiration）。
    Replay(ReplayError),
    /// 7E：nonce 非 Current（TooLow 或 Future；执行层均拒）。
    NonceNotCurrent,
    /// 7F：gas / fee 计算或参数错误。
    Gas(nova_core::transaction::gas_fee::GasFeeError),
    /// 执行期余额不足（7G 层检查；区别于 7F admission 的 `InsufficientBalance`）。
    BalanceInsufficient,
    /// receiver.balance + amount 溢出。
    ReceiverOverflow,
    /// sender 扣款不足（防御；admission 已保证 `balance >= required`）。
    SenderOverflow,
    /// nonce == u64::MAX，无法递增（N15）。
    NonceExhausted,
    /// txid / canonical 编码失败（7C 层传播）。
    Malformed(TransactionError),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(e) => write!(f, "signature/identity: {e}"),
            Self::Replay(e) => write!(f, "replay: {e}"),
            Self::NonceNotCurrent => write!(f, "nonce not current"),
            Self::Gas(e) => write!(f, "gas/fee: {e}"),
            Self::BalanceInsufficient => write!(f, "insufficient balance at execution"),
            Self::ReceiverOverflow => write!(f, "receiver balance overflow"),
            Self::SenderOverflow => write!(f, "sender deduction overflow"),
            Self::NonceExhausted => write!(f, "nonce exhausted (u64::MAX)"),
            Self::Malformed(e) => write!(f, "malformed transaction: {e}"),
        }
    }
}

impl std::error::Error for ExecutionError {}

/// 应用一笔交易（完整 admission + 执行；纯函数）。
///
/// `sender_vk` 由调用方提供（7D `verify_transaction_signature` 负责身份绑定：公钥必须匹配
/// `tx.sender` 的 key_hash；错误公钥无法通过）。公钥来源 / 存储由 STEP 8 / 账户层决定。
pub fn apply_transaction<S: AccountStateView>(
    state: &S,
    tx: &TransactionV1,
    sender_vk: &VerifyingKey,
    ctx: &ExecutionContext,
) -> Result<StateTransition, ExecutionError> {
    // ---- 1. Signature verify（7D；含身份绑定）----
    verify_transaction_signature(tx, sender_vk).map_err(ExecutionError::Signature)?;

    // ---- 2. Replay check（7E：chain_id / network_id / expiration）----
    check_replay_context(tx, &ctx.chain, ctx.current_height).map_err(ExecutionError::Replay)?;

    // ---- 3. Gas validation（7F）----
    check_gas_params(tx.gas_limit, tx.gas_price).map_err(ExecutionError::Gas)?;
    let fee_max = compute_fee_max(tx.gas_limit, tx.gas_price).map_err(ExecutionError::Gas)?;
    let required = compute_required(tx.amount, fee_max).map_err(ExecutionError::Gas)?;

    // ---- 4. Load sender ----
    let sender_state = state.account(&tx.sender);
    let sender_balance = sender_state.map(|s| s.balance).unwrap_or(0);
    let sender_nonce = sender_state.map(|s| s.nonce).unwrap_or(0);

    // ---- 5. Nonce check（7E）----
    if !matches!(classify_nonce(tx.nonce, sender_nonce), NonceClass::Current) {
        return Err(ExecutionError::NonceNotCurrent);
    }

    // ---- 6. Balance check（7F required；执行期用真实 state 重新检查）----
    check_balance_sufficient(sender_balance, required)
        .map_err(|_| ExecutionError::BalanceInsufficient)?;

    // ---- 7. Load receiver ----
    let receiver_state = state.account(&tx.receiver);

    // ---- 8-11. calculate first（G-E）：全部 checked 计算，不落账 ----
    let gas_used = TRANSFER_INTRINSIC_GAS;
    let actual_fee = compute_actual_fee(gas_used, tx.gas_price).map_err(ExecutionError::Gas)?;
    let burned_fee = compute_burn(actual_fee, ctx.fee_burn_bps).map_err(ExecutionError::Gas)?;

    // 余额变更（self-transfer：net amount = 0，仅扣 fee）
    let (sender_new_balance, receiver_new_balance, receiver_created) = if tx.sender == tx.receiver {
        let sb = sender_balance
            .checked_sub(actual_fee)
            .ok_or(ExecutionError::SenderOverflow)?;
        (sb, sb, false)
    } else {
        let sa = sender_balance
            .checked_sub(tx.amount)
            .ok_or(ExecutionError::SenderOverflow)?;
        let sb = sa
            .checked_sub(actual_fee)
            .ok_or(ExecutionError::SenderOverflow)?;
        let rb = receiver_state
            .map(|s| s.balance)
            .unwrap_or(0)
            .checked_add(tx.amount)
            .ok_or(ExecutionError::ReceiverOverflow)?;
        let created = tx.amount > 0 && receiver_state.is_none();
        (sb, rb, created)
    };

    // nonce 递增（N15：u64::MAX ⇒ Exhausted）
    let sender_new_nonce =
        checked_next_nonce(sender_nonce).map_err(|_| ExecutionError::NonceExhausted)?;

    // ---- 12. commit（构建 AccountChange；原子性 G-I；顺序 sender → receiver G-J）----
    let mut changes = Vec::with_capacity(2);
    changes.push(AccountChange {
        address: tx.sender,
        new_balance: sender_new_balance,
        new_nonce: sender_new_nonce,
        created: false, // sender 在成功路径必存在（balance >= required > 0）
    });
    if tx.sender != tx.receiver {
        match receiver_state {
            Some(rs) => changes.push(AccountChange {
                address: tx.receiver,
                new_balance: receiver_new_balance,
                new_nonce: rs.nonce,
                created: false,
            }),
            None if receiver_created => changes.push(AccountChange {
                address: tx.receiver,
                new_balance: receiver_new_balance,
                new_nonce: 0,
                created: true,
            }),
            None => {} // amount == 0 且 receiver 不存在：不创建、无变化（G-K / ADR-0017 §3）
        }
    }

    // ---- 13. receipt ----
    let tx_hash = compute_txid(tx).map_err(ExecutionError::Malformed)?;
    let receipt = TransactionReceipt {
        tx_hash,
        status: TxStatus::Success,
        gas_used,
        fee_paid: actual_fee,
        burned_fee,
    };

    Ok(StateTransition {
        changes,
        receipt,
        gas_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::state::EMPTY_CODE_HASH;
    use nova_crypto::address::{AddressType, NetworkId, NovaAddress, NovaAddressPayload};
    use nova_crypto::key::KeyPair;
    use nova_crypto::transaction::{TransactionType, sign_transaction};
    use std::collections::HashMap;

    /// 内存状态视图（测试用；非协议存储）。
    struct MemState {
        accounts: HashMap<NovaAddress, AccountState>,
    }

    impl MemState {
        fn new() -> Self {
            Self {
                accounts: HashMap::new(),
            }
        }
        fn insert(&mut self, addr: NovaAddress, state: AccountState) {
            self.accounts.insert(addr, state);
        }
    }

    impl AccountStateView for MemState {
        fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
            self.accounts.get(addr).copied()
        }
    }

    fn addr(kh: [u8; 32], net: NetworkId) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: 1,
            address_type: AddressType::UserAccount,
            network_id: net,
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

    fn ctx(chain_id: u64) -> ExecutionContext {
        ExecutionContext {
            chain: ChainIdentity {
                network_id: NetworkId::Mainnet,
                chain_id,
                genesis_hash: [0x11; 32],
            },
            current_height: 100,
            fee_burn_bps: 1_000, // 10%
        }
    }

    /// 构造签名完成的交易（sender 地址绑定 kp）。
    fn signed_tx(
        kp: &KeyPair,
        chain_id: u64,
        nonce: u64,
        receiver: NovaAddress,
        amount: u128,
        gas_limit: u64,
        gas_price: u128,
    ) -> TransactionV1 {
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let mut tx = TransactionV1 {
            version: 0x01,
            chain_id,
            nonce,
            sender,
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

    // ---- 成功 transfer ----
    #[test]
    fn successful_transfer() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x22; 32], NetworkId::Mainnet);
        let amount = 1_000u128;
        let gas_limit = 21_000u64;
        let gas_price = 10u128;
        let actual_fee = 210_000u128;
        let burned = 21_000u128; // 210_000 * 1000 / 10000

        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 5));
        st.insert(receiver, account_state(500, 0));

        let tx = signed_tx(&kp, 1001, 5, receiver, amount, gas_limit, gas_price);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap();

        // AccountChange 顺序：sender → receiver（G-J）
        assert_eq!(out.changes.len(), 2);
        assert_eq!(out.changes[0].address, sender);
        assert_eq!(out.changes[0].new_balance, 1_000_000 - amount - actual_fee);
        assert_eq!(out.changes[0].new_nonce, 6);
        assert!(!out.changes[0].created);
        assert_eq!(out.changes[1].address, receiver);
        assert_eq!(out.changes[1].new_balance, 500 + amount);
        assert!(!out.changes[1].created);

        // Receipt
        assert_eq!(out.receipt.status, TxStatus::Success);
        assert_eq!(out.receipt.gas_used, TRANSFER_INTRINSIC_GAS);
        assert_eq!(out.receipt.fee_paid, actual_fee);
        assert_eq!(out.receipt.burned_fee, burned);
        assert_eq!(out.receipt.tx_hash, compute_txid(&tx).unwrap());
        assert_eq!(out.gas_used, TRANSFER_INTRINSIC_GAS);

        // 原 state 未被修改（纯函数）
        assert_eq!(st.accounts[&sender].balance, 1_000_000);
        assert_eq!(st.accounts[&receiver].balance, 500);
    }

    // ---- 隐式创建 ----
    #[test]
    fn implicit_creation_positive_value() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x33; 32], NetworkId::Mainnet);

        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        let tx = signed_tx(&kp, 1001, 0, receiver, 5_000, 21_000, 10);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap();

        assert_eq!(out.changes.len(), 2);
        assert!(out.changes[1].created, "receiver created on positive value");
        assert_eq!(out.changes[1].address, receiver);
        assert_eq!(out.changes[1].new_balance, 5_000);
        assert_eq!(out.changes[1].new_nonce, 0);
    }

    // ---- zero-value：不创建 ----
    #[test]
    fn zero_value_does_not_create() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x44; 32], NetworkId::Mainnet);

        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        let tx = signed_tx(&kp, 1001, 0, receiver, 0, 21_000, 10);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap();

        assert_eq!(out.changes.len(), 1, "zero-value: receiver not created");
        assert_eq!(out.changes[0].address, sender);
        // fee 照扣 + nonce+1（ADR-0019 §11）
        assert_eq!(out.changes[0].new_balance, 1_000_000 - 210_000);
        assert_eq!(out.changes[0].new_nonce, 1);
    }

    // ---- self-transfer：single change ----
    #[test]
    fn self_transfer_single_change() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();

        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 3));

        let tx = signed_tx(&kp, 1001, 3, sender, 10_000, 21_000, 10);
        let out = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap();

        assert_eq!(out.changes.len(), 1, "self-transfer: single change");
        assert_eq!(out.changes[0].address, sender);
        // net amount = 0，仅扣 fee（ADR-0019 §12）
        assert_eq!(out.changes[0].new_balance, 1_000_000 - 210_000);
        assert_eq!(out.changes[0].new_nonce, 4);
    }

    // ---- 失败：无副作用 ----
    #[test]
    fn signature_failure_no_side_effect() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        let mut tx = signed_tx(&kp, 1001, 0, receiver, 1_000, 21_000, 10);
        tx.amount += 1; // 篡改 ⇒ 签名失效
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::Signature(_)));
        assert_eq!(st.accounts[&sender].balance, 1_000_000);
        assert_eq!(st.accounts[&sender].nonce, 0);
    }

    #[test]
    fn wrong_chain_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        // 签名链 1002，但执行链 1001
        let tx = signed_tx(&kp, 1002, 0, receiver, 1_000, 21_000, 10);
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(
            err,
            ExecutionError::Replay(ReplayError::ChainIdMismatch)
        ));
    }

    #[test]
    fn expired_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        // 构造时就用过期 expiration（签名覆盖 expiration=50 < current_height=100）
        let mut tx = TransactionV1 {
            version: 0x01,
            chain_id: 1001,
            nonce: 0,
            sender,
            receiver,
            amount: 1_000,
            gas_limit: 21_000,
            gas_price: 10,
            transaction_type: TransactionType::Transfer,
            payload: Vec::new(),
            expiration: 50, // 过期
            signature: [0u8; 64],
        };
        sign_transaction(kp.signing_key(), &mut tx).unwrap();
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::Replay(ReplayError::Expired)));
    }

    #[test]
    fn nonce_too_low_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 5));

        let tx = signed_tx(&kp, 1001, 4, receiver, 1_000, 21_000, 10); // nonce < account.nonce
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::NonceNotCurrent));
    }

    #[test]
    fn future_nonce_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 5));

        let tx = signed_tx(&kp, 1001, 6, receiver, 1_000, 21_000, 10); // future
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::NonceNotCurrent));
    }

    #[test]
    fn balance_insufficient_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(100, 0)); // < required (amount + fee)

        let tx = signed_tx(&kp, 1001, 0, receiver, 1_000, 21_000, 10);
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::BalanceInsufficient));
        assert_eq!(st.accounts[&sender].balance, 100);
        assert_eq!(st.accounts[&sender].nonce, 0);
    }

    #[test]
    fn receiver_overflow_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(u128::MAX, 0));
        st.insert(receiver, account_state(u128::MAX, 0));

        // sender 足够（u128::MAX >= amount + fee），但 receiver + amount 溢出
        let tx = signed_tx(&kp, 1001, 0, receiver, 1, 21_000, 10);
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::ReceiverOverflow));
        // 无副作用
        assert_eq!(st.accounts[&sender].balance, u128::MAX);
        assert_eq!(st.accounts[&receiver].balance, u128::MAX);
    }

    #[test]
    fn nonce_exhausted_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, u64::MAX));

        let tx = signed_tx(&kp, 1001, u64::MAX, receiver, 1_000, 21_000, 10);
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::NonceExhausted));
    }

    #[test]
    fn zero_gas_params_failure() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0x55; 32], NetworkId::Mainnet);
        let mut st = MemState::new();
        st.insert(sender, account_state(1_000_000, 0));

        let tx = signed_tx(&kp, 1001, 0, receiver, 1_000, 0, 10); // gas_limit = 0
        let err = apply_transaction(&st, &tx, kp.verifying_key(), &ctx(1001)).unwrap_err();
        assert!(matches!(err, ExecutionError::Gas(_)));
    }
}
