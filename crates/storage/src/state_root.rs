//! StateRootCalculator（STEP 8D-2 — ADR-0030）。
//!
//! - [`calculate_state_root`]：**只读重算**——基于 store 深拷贝的临时状态应用 `tx_changes`，
//!   返回预期 root（不落盘、不污染 store；ADR-0030 C-1/C-2/C-3）。
//! - [`verify_block_state_root`]：区块 state root 校验（ADR-0029 D-5；**仅 root**，不含
//!   block_hash / header validation / timestamp / prev_hash / producer / consensus——PHASE 7）。

use crate::backend::StorageBackend;
use crate::error::StorageError;
use crate::node::NodeHash;
use crate::store::StateStore;
use nova_core::state::AccountChange;

/// 区块 state root 校验错误（ADR-0029 D-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStateRootError {
    /// 重算 root ≠ 期望 root。
    Mismatch,
}

impl core::fmt::Display for BlockStateRootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mismatch => write!(f, "recomputed state root does not match expected"),
        }
    }
}

impl std::error::Error for BlockStateRootError {}

/// 只读重算 state root（ADR-0030 C-1/C-2/C-3）。
///
/// - 基于 `store.clone()` 临时状态（trie 深拷贝 + backend 快照），应用 `tx_changes`
///   （顺序 = block 顺序，**不排序不合并**），返回预期 root。
/// - 调用后 `store` **完全不变**（root / account / backend / trie）。
/// - 空 `tx_changes` ⇒ 返回 store 当前 root（C-5）。
pub fn calculate_state_root<B: StorageBackend + Clone>(
    store: &StateStore<B>,
    tx_changes: &[&[AccountChange]],
) -> Result<NodeHash, StorageError> {
    let mut tmp = store.clone();
    tmp.commit_changes(tx_changes)?;
    Ok(tmp.state_root())
}

/// 区块 state root 校验（ADR-0029 D-5）。
pub fn verify_block_state_root(
    expected: &NodeHash,
    computed: &NodeHash,
) -> Result<(), BlockStateRootError> {
    if expected == computed {
        Ok(())
    } else {
        Err(BlockStateRootError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryBackend;
    use nova_core::state::{AccountState, AccountStateView, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
    }

    fn change(addr: NovaAddress, balance: u128, nonce: u64) -> AccountChange {
        AccountChange {
            address: addr,
            new_balance: balance,
            new_nonce: nonce,
            created: true,
        }
    }

    #[test]
    fn calculate_is_read_only_and_equals_apply_block() {
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        // 先用单批建立初始状态
        store
            .apply(&[change(a, 1000, 0), change(b, 500, 0)])
            .unwrap();
        let root_before = store.state_root();

        let tx_changes: Vec<Vec<AccountChange>> =
            vec![vec![change(a, 900, 1)], vec![change(b, 600, 0)]];
        let refs: Vec<&[AccountChange]> = tx_changes.iter().map(|v| v.as_slice()).collect();

        // calculate：只读重算
        let calc = calculate_state_root(&store, &refs).unwrap();
        // store 不变
        assert_eq!(
            store.state_root(),
            root_before,
            "calculate must not mutate store"
        );

        // apply_block：提交并返回同一 root
        let applied = store.apply_block(&refs).unwrap();
        assert_eq!(calc, applied, "calculate == apply_block (root equivalence)");
        assert_eq!(
            store.account(&a),
            Some(AccountState {
                balance: 900,
                nonce: 1,
                code_hash: EMPTY_CODE_HASH,
                storage_root: EMPTY_STORAGE_ROOT,
            })
        );
    }

    #[test]
    fn calculate_empty_block_returns_current_root() {
        let mut store = StateStore::new(MemoryBackend::new());
        store.apply(&[change(addr([0xaa; 32]), 1000, 0)]).unwrap();
        let root = store.state_root();
        let calc = calculate_state_root(&store, &[]).unwrap();
        assert_eq!(calc, root, "empty block ⇒ root unchanged");
    }

    #[test]
    fn verify_state_root_match_and_mismatch() {
        let a = addr([0xaa; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        store.apply(&[change(a, 1000, 0)]).unwrap();
        let root = store.state_root();
        assert_eq!(verify_block_state_root(&root, &root), Ok(()));
        let wrong = NodeHash::from_bytes(EMPTY_STORAGE_ROOT);
        assert_eq!(
            verify_block_state_root(&root, &wrong),
            Err(BlockStateRootError::Mismatch)
        );
    }
}
