//! 区块执行（STEP 8D — ADR-0029 D-2/D-3）。
//!
//! - [`execute_block`]：**纯计算**——内部影子状态（overlay + fallback base），逐 tx
//!   [`apply_transaction`]，成功记录 transition 并应用 changes 到 overlay；失败 **skip**
//!   （D-3 Model A：无 change / 无 receipt / 区块继续）。
//! - [`validate_block`]：block validity 预检（ADR-0021 §7 nonce 唯一 / ADR-0023 G6 gas 上限）；
//!   违反 ⇒ [`BlockError`] ⇒ 整块回滚（Block Invalid，无状态变更）。
//! - **禁止**：storage write / trie mutation / backend access / state root calculation（D-2 边界）。

use core::fmt;
use nova_core::block::BlockExecutionResult;
use nova_core::state::{
    AccountChange, AccountState, AccountStateView, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT,
};
use nova_core::transaction::gas_fee::TRANSFER_INTRINSIC_GAS;
use nova_crypto::address::NovaAddress;
use nova_crypto::signature::VerifyingKey;
use nova_crypto::transaction::TransactionV1;
use std::collections::{HashMap, HashSet};

use crate::state_transition::{ExecutionContext, apply_transaction};

/// 区块执行错误（ADR-0029 D-2/D-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// block 内同 `(sender, nonce)` 重复（ADR-0021 §7 ⇒ Block Invalid）。
    NonceConflict,
    /// 累计 gas 超过 `max_gas_per_block`（ADR-0023 G6 ⇒ Block Invalid）。
    GasLimitExceeded,
    /// 参数错误（tx 与 sender 公钥数量不对齐等）。
    InvalidBlockArgument,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonceConflict => write!(f, "block contains duplicate (sender, nonce)"),
            Self::GasLimitExceeded => write!(f, "block gas exceeds max_gas_per_block"),
            Self::InvalidBlockArgument => {
                write!(f, "invalid block argument (txs/sender_keys mismatch)")
            }
        }
    }
}

impl std::error::Error for BlockError {}

/// 影子状态：base（只读 fallback）+ overlay（本 block 已执行写入；ADR-0029 D-2）。
struct BlockState<'a, S: AccountStateView> {
    base: &'a S,
    overlay: HashMap<NovaAddress, AccountState>,
}

impl<S: AccountStateView> AccountStateView for BlockState<'_, S> {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
        self.overlay
            .get(addr)
            .copied()
            .or_else(|| self.base.account(addr))
    }
}

/// 把 change 应用到 overlay（block 内部影子写；最终落盘由 storage 负责）。
fn apply_change(overlay: &mut HashMap<NovaAddress, AccountState>, c: &AccountChange) {
    overlay.insert(
        c.address,
        AccountState {
            balance: c.new_balance,
            nonce: c.new_nonce,
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        },
    );
}

/// Block validity 预检（ADR-0029 D-3 阶段 1；ADR-0021 §7 / ADR-0023 G6）。
///
/// - `(sender, nonce)` 在 block 内唯一。
/// - V0.1 每 tx 固定 `TRANSFER_INTRINSIC_GAS`：乐观检查 `n × gas ≤ max_gas_per_block`
///   （全成功也不超限；否则该 block 永不可能合法）。
pub fn validate_block(txs: &[TransactionV1], max_gas_per_block: u64) -> Result<(), BlockError> {
    let mut seen = HashSet::new();
    for tx in txs {
        let key = (tx.sender.payload().to_bytes(), tx.nonce);
        if !seen.insert(key) {
            return Err(BlockError::NonceConflict);
        }
    }
    let total = (txs.len() as u64)
        .checked_mul(TRANSFER_INTRINSIC_GAS)
        .ok_or(BlockError::GasLimitExceeded)?;
    if total > max_gas_per_block {
        return Err(BlockError::GasLimitExceeded);
    }
    Ok(())
}

/// 执行一个区块（纯计算；ADR-0029 D-2/D-3）。
///
/// - `sender_keys[i]` 对应 `txs[i]` 的 sender 公钥（7D 身份绑定）；长度必须一致（否则
///   [`BlockError::InvalidBlockArgument`]）。
/// - 逐 tx：成功 ⇒ transition + changes 应用 overlay + gas 累加；失败 ⇒ **skip**（无 change/receipt）。
/// - 返回 [`BlockExecutionResult`]（**不含** final root——由 nova-storage 计算，ADR-0029 D-1）。
pub fn execute_block<S: AccountStateView>(
    state: &S,
    txs: &[TransactionV1],
    sender_keys: &[VerifyingKey],
    ctx: &ExecutionContext,
    max_gas_per_block: u64,
) -> Result<BlockExecutionResult, BlockError> {
    if txs.len() != sender_keys.len() {
        return Err(BlockError::InvalidBlockArgument);
    }
    validate_block(txs, max_gas_per_block)?;

    let mut bs = BlockState {
        base: state,
        overlay: HashMap::new(),
    };
    let mut tx_transitions = Vec::new();
    let mut gas_used_total = 0u64;

    for (tx, vk) in txs.iter().zip(sender_keys.iter()) {
        match apply_transaction(&bs, tx, vk, ctx) {
            Ok(transition) => {
                for c in &transition.changes {
                    apply_change(&mut bs.overlay, c);
                }
                gas_used_total = gas_used_total
                    .checked_add(transition.gas_used)
                    .ok_or(BlockError::GasLimitExceeded)?;
                if gas_used_total > max_gas_per_block {
                    return Err(BlockError::GasLimitExceeded);
                }
                tx_transitions.push(transition);
            }
            Err(_exec_err) => {
                // Model A：单 tx 失败 ⇒ skip（无 change / 无 receipt；区块继续）
            }
        }
    }

    Ok(BlockExecutionResult {
        tx_transitions,
        gas_used_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::state::AccountState;
    use nova_crypto::address::{ADDRESS_VERSION, AddressType, NetworkId, NovaAddressPayload};
    use nova_crypto::identity::ChainIdentity;
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::SigningKey;
    use nova_crypto::transaction::TransactionType;
    use nova_crypto::transaction::sign_transaction;

    struct MapState {
        accounts: HashMap<NovaAddress, AccountState>,
    }
    impl AccountStateView for MapState {
        fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
            self.accounts.get(addr).copied()
        }
    }

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
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
            version: 1,
            chain_id,
            nonce,
            sender,
            receiver,
            amount,
            gas_limit: 100_000,
            gas_price: 1,
            transaction_type: TransactionType::Transfer,
            payload: vec![0u8; 140],
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

    #[test]
    fn validate_rejects_duplicate_nonce() {
        let kp = KeyPair::generate().unwrap();
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let txs = vec![
            mk_tx(a, b, 5, 100, kp.signing_key(), 1),
            mk_tx(a, b, 5, 200, kp.signing_key(), 1), // 同 (sender, nonce)
        ];
        assert_eq!(
            validate_block(&txs, 1_000_000),
            Err(BlockError::NonceConflict)
        );
    }

    #[test]
    fn validate_rejects_gas_over_limit() {
        let kp = KeyPair::generate().unwrap();
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let txs = vec![mk_tx(a, b, 0, 100, kp.signing_key(), 1)];
        // 1 tx × 21000 > 10000
        assert_eq!(
            validate_block(&txs, TRANSFER_INTRINSIC_GAS - 1),
            Err(BlockError::GasLimitExceeded)
        );
    }

    #[test]
    fn execute_block_single_success_and_skip() {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0xbb; 32]);
        let mut accounts = HashMap::new();
        accounts.insert(
            sender,
            AccountState {
                balance: 1_000_000,
                nonce: 0,
                code_hash: EMPTY_CODE_HASH,
                storage_root: EMPTY_STORAGE_ROOT,
            },
        );
        let state = MapState { accounts };

        // tx1 合法；tx2 余额不足（amount 巨大）⇒ skip
        let ok_tx = mk_tx(sender, receiver, 0, 100, kp.signing_key(), 1);
        let bad_tx = mk_tx(sender, receiver, 1, u128::MAX, kp.signing_key(), 1); // 余额不足
        let keys = vec![*kp.verifying_key(), *kp.verifying_key()];
        let result = execute_block(&state, &[ok_tx, bad_tx], &keys, &ctx(1), 1_000_000).unwrap();
        assert_eq!(result.tx_transitions.len(), 1, "bad tx skipped");
        assert_eq!(
            result.gas_used_total, TRANSFER_INTRINSIC_GAS,
            "only success gas counted"
        );
    }

    #[test]
    fn execute_block_rejects_key_count_mismatch() {
        let kp = KeyPair::generate().unwrap();
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let state = MapState {
            accounts: HashMap::new(),
        };
        let tx = mk_tx(a, b, 0, 100, kp.signing_key(), 1);
        assert_eq!(
            execute_block(&state, &[tx], &[], &ctx(1), 1_000_000),
            Err(BlockError::InvalidBlockArgument)
        );
    }
}
