//! StateStore（STEP 8C — ADR-0028 D-2/D-5；8C-2 骨架，**不含 apply**）。
//!
//! - `backend = truth storage`（完整账户 canonical bytes）；`trie = commitment index`
//!   （key → account_commitment）；**禁止从 trie decode state**（D-2，未来 RocksDB 迁移困难）。
//! - 实现 `AccountStateView`（ADR-0025 S-A / S-C）：`account()` 从 backend 读 → decode 88B。
//! - 快照：`snapshot / commit(=drop) / rollback`（D-5）；8D block state root verification 复用。
//! - **8C-2 不实现 `apply`**（D-4 两阶段内部事务在 8C-3）。

use crate::backend::StorageBackend;
use crate::node::{NodeHash, TrieKey};
use crate::trie::SparseMerkleTree;
use nova_core::state::{AccountState, AccountStateView, decode_account_bytes};
use nova_crypto::address::NovaAddress;

/// 区块级快照（trie + backend；D-5）。
#[derive(Clone)]
pub struct StateSnapshot<S> {
    trie: SparseMerkleTree,
    backend: S,
}

/// State store（ADR-0028 D-2）。
pub struct StateStore<B: StorageBackend> {
    backend: B,
    trie: SparseMerkleTree,
}

impl<B: StorageBackend> StateStore<B> {
    /// 以空状态构建（root = `EMPTY_STATE_ROOT`）。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            trie: SparseMerkleTree::new(),
        }
    }

    /// 当前 state root（空 = `EMPTY_STATE_ROOT`；ADR-0026 T-6）。
    pub fn state_root(&self) -> NodeHash {
        self.trie.root()
    }

    /// 快照当前状态（区块级事务回滚基线；D-5）。
    pub fn snapshot(&self) -> StateSnapshot<B::Snapshot> {
        StateSnapshot {
            trie: self.trie.clone(),
            backend: self.backend.snapshot(),
        }
    }

    /// 确认当前状态并释放快照资源（**不 mutate state**；D-5）。
    pub fn commit(&mut self, snapshot: StateSnapshot<B::Snapshot>) {
        drop(snapshot);
    }

    /// 回滚到快照（恢复 trie + backend 到区块前状态；D-5）。
    pub fn rollback(&mut self, snapshot: StateSnapshot<B::Snapshot>) {
        self.trie = snapshot.trie;
        self.backend.restore(&snapshot.backend);
    }
}

impl<B: StorageBackend> AccountStateView for StateStore<B> {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState> {
        let key: TrieKey = addr.payload().to_bytes();
        let bytes = self.backend.get(&key)?;
        let arr: [u8; 88] = bytes.as_slice().try_into().ok()?;
        Some(decode_account_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryBackend;
    use nova_core::state::{EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT};
    use nova_crypto::address::{ADDRESS_VERSION, AddressType, NetworkId, NovaAddressPayload};

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
    }

    fn acc(balance: u128, nonce: u64) -> AccountState {
        AccountState {
            balance,
            nonce,
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        }
    }

    #[test]
    fn empty_store_root_is_emtpry_state_root() {
        let store = StateStore::new(MemoryBackend::new());
        assert_eq!(store.state_root(), NodeHash::from_bytes(EMPTY_STORAGE_ROOT));
        assert!(store.account(&addr([0u8; 32])).is_none());
    }

    #[test]
    fn memory_backend_put_get_roundtrip() {
        let mut b = MemoryBackend::new();
        let key = [0x11u8; 35];
        assert_eq!(b.get(&key), None);
        b.put(key, vec![0xaa; 88]).unwrap();
        assert_eq!(b.get(&key), Some(vec![0xaa; 88]));
        assert_eq!(b.len(), 1);
        b.delete(&key).unwrap();
        assert!(b.is_empty());
    }

    #[test]
    fn memory_backend_snapshot_restore_roundtrip() {
        let mut b = MemoryBackend::new();
        let k1 = [0x11u8; 35];
        b.put(k1, vec![1u8; 88]).unwrap();
        let snap = b.snapshot();
        b.put([0x22u8; 35], vec![2u8; 88]).unwrap();
        b.put(k1, vec![9u8; 88]).unwrap();
        assert_eq!(b.len(), 2);
        b.restore(&snap);
        assert_eq!(b.len(), 1);
        assert_eq!(b.get(&k1), Some(vec![1u8; 88]));
    }

    #[test]
    fn store_account_roundtrip_and_rollback() {
        let a = addr([0xaa; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        // 骨架阶段无 apply：手工写 backend + trie 以测 account()/rollback
        let snap = store.snapshot();
        store
            .backend
            .put(
                a.payload().to_bytes(),
                nova_core::state::canonical_account_bytes(&acc(100, 1)).to_vec(),
            )
            .unwrap();
        assert_eq!(store.account(&a), Some(acc(100, 1)));
        store.rollback(snap);
        assert_eq!(
            store.account(&a),
            None,
            "rollback must restore block-before state"
        );
    }

    #[test]
    fn commit_releases_snapshot_without_mutating() {
        let mut store = StateStore::new(MemoryBackend::new());
        let snap = store.snapshot();
        store.commit(snap); // drop：确认当前状态，不 mutate
        assert_eq!(store.state_root(), NodeHash::from_bytes(EMPTY_STORAGE_ROOT));
    }
}
