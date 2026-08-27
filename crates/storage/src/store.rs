//! StateStore（STEP 8C — ADR-0028 D-2/D-5；8C-2 骨架，**不含 apply**）。
//!
//! - `backend = truth storage`（完整账户 canonical bytes）；`trie = commitment index`
//!   （key → account_commitment）；**禁止从 trie decode state**（D-2，未来 RocksDB 迁移困难）。
//! - 实现 `AccountStateView`（ADR-0025 S-A / S-C）：`account()` 从 backend 读 → decode 88B。
//! - 快照：`snapshot / commit(=drop) / rollback`（D-5）；8D block state root verification 复用。
//! - **8C-2 不实现 `apply`**（D-4 两阶段内部事务在 8C-3）。

use crate::backend::StorageBackend;
use crate::error::StorageError;
use crate::node::{NodeHash, TrieKey, ValueHash};
use crate::trie::SparseMerkleTree;
use nova_core::state::{
    AccountChange, AccountState, AccountStateView, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT,
    account_commitment, canonical_account_bytes, decode_account_bytes,
};
use nova_crypto::address::NovaAddress;

/// 区块级快照（trie + backend；D-5）。
#[derive(Clone)]
pub struct StateSnapshot<S> {
    trie: SparseMerkleTree,
    backend: S,
}

/// State store（ADR-0028 D-2）。
#[derive(Clone)]
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

    /// 查询 `addr` 在 trie 中的 account_commitment（backend/trie 一致性验证、未来 proof 用；
    /// **非完整状态**——trie 只存 commitment，禁止从 trie decode state，D-2）。
    pub fn commitment(&self, addr: &NovaAddress) -> Option<ValueHash> {
        let key: TrieKey = addr.payload().to_bytes();
        self.trie.get(&key)
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

    /// 原子应用一批账户变更（ADR-0028 D-4；**两阶段内部事务**）。
    ///
    /// - snapshot → [`Self::apply_changes_inner`] → 成功保留；失败 rollback。
    pub fn apply(&mut self, changes: &[AccountChange]) -> Result<(), StorageError> {
        let snap = self.snapshot();
        if let Err(e) = self.apply_changes_inner(changes) {
            self.rollback(snap);
            return Err(e);
        }
        drop(snap);
        Ok(())
    }

    /// 区块级原子提交（ADR-0029 D-4）：snapshot → 逐成功 tx changes → final root；失败整块回滚。
    ///
    /// `tx_changes` 外层 = block 内成功 tx 顺序；内层 = 单 tx 的 changes（sender→receiver）。
    /// **不排序、不合并**（ADR-0030 C-4）。空区块 ⇒ root 不变（C-5）。
    pub fn apply_block(
        &mut self,
        tx_changes: &[&[AccountChange]],
    ) -> Result<NodeHash, StorageError> {
        let snap = self.snapshot();
        if let Err(e) = self.commit_changes(tx_changes) {
            self.rollback(snap);
            return Err(e);
        }
        drop(snap);
        Ok(self.state_root())
    }

    /// 两阶段内部核心（**不负责 snapshot/rollback**；ADR-0030 C-3 单源）。
    ///
    /// phase 1 prepare（validate + calculate，零副作用）→ phase 2 commit（backend → trie）。
    fn apply_changes_inner(&mut self, changes: &[AccountChange]) -> Result<(), StorageError> {
        let mut prepared = Vec::with_capacity(changes.len());
        for c in changes {
            let key: TrieKey = c.address.payload().to_bytes();
            let state = account_state(c);
            prepared.push((
                key,
                canonical_account_bytes(&state).to_vec(),
                account_commitment(&state),
            ));
        }
        for (key, canonical, commitment) in &prepared {
            self.backend.put(*key, canonical.clone())?;
            self.trie.insert(key, commitment);
        }
        Ok(())
    }

    /// 逐 tx 应用（ADR-0030 C-3；`apply_block` 与 `calculate_state_root` 共享核心）。
    pub(crate) fn commit_changes(
        &mut self,
        tx_changes: &[&[AccountChange]],
    ) -> Result<(), StorageError> {
        for changes in tx_changes {
            self.apply_changes_inner(changes)?;
        }
        Ok(())
    }
}

/// `AccountChange` → 目标 `AccountState`（ADR-0028 D-3：code_hash/storage_root 固定常量）。
fn account_state(c: &AccountChange) -> AccountState {
    AccountState {
        balance: c.new_balance,
        nonce: c.new_nonce,
        code_hash: EMPTY_CODE_HASH,
        storage_root: EMPTY_STORAGE_ROOT,
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
    use crate::error::StorageError;
    use crate::memory::{MemoryBackend, MemorySnapshot};
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
        let change = AccountChange {
            address: a,
            new_balance: 100,
            new_nonce: 1,
            created: true,
        };
        store.apply(std::slice::from_ref(&change)).unwrap();
        assert_eq!(store.account(&a), Some(acc(100, 1)));
        let snap = store.snapshot();
        store
            .apply(&[AccountChange {
                address: a,
                new_balance: 200,
                new_nonce: 2,
                created: false,
            }])
            .unwrap();
        assert_eq!(store.account(&a), Some(acc(200, 2)));
        store.rollback(snap);
        assert_eq!(
            store.account(&a),
            Some(acc(100, 1)),
            "rollback restores prior state"
        );
    }

    #[test]
    fn commit_releases_snapshot_without_mutating() {
        let mut store = StateStore::new(MemoryBackend::new());
        let snap = store.snapshot();
        store.commit(snap); // drop：确认当前状态，不 mutate
        assert_eq!(store.state_root(), NodeHash::from_bytes(EMPTY_STORAGE_ROOT));
    }

    // ---- apply（8C-3，两阶段事务）----
    #[test]
    fn apply_empty_is_noop() {
        let mut store = StateStore::new(MemoryBackend::new());
        let root = store.state_root();
        store.apply(&[]).unwrap();
        assert_eq!(store.state_root(), root);
    }

    #[test]
    fn apply_single_creates_account_and_root_changes() {
        let a = addr([0xaa; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        let empty_root = store.state_root();
        store
            .apply(&[AccountChange {
                address: a,
                new_balance: 1000,
                new_nonce: 0,
                created: true,
            }])
            .unwrap();
        assert_eq!(store.account(&a), Some(acc(1000, 0)));
        assert_ne!(store.state_root(), empty_root, "create must change root");
    }

    #[test]
    fn apply_preserves_change_order_upsert() {
        // 同 address 连续两 change：后者覆盖（若排序则结果相反）
        let a = addr([0xaa; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        store
            .apply(&[
                AccountChange {
                    address: a,
                    new_balance: 100,
                    new_nonce: 1,
                    created: true,
                },
                AccountChange {
                    address: a,
                    new_balance: 50,
                    new_nonce: 2,
                    created: false,
                },
            ])
            .unwrap();
        assert_eq!(
            store.account(&a),
            Some(acc(50, 2)),
            "later change wins (order preserved)"
        );
    }

    #[test]
    fn apply_multiple_changes_all_land() {
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        store
            .apply(&[
                AccountChange {
                    address: a,
                    new_balance: 100,
                    new_nonce: 1,
                    created: true,
                },
                AccountChange {
                    address: b,
                    new_balance: 50,
                    new_nonce: 0,
                    created: true,
                },
            ])
            .unwrap();
        assert_eq!(store.account(&a), Some(acc(100, 1)));
        assert_eq!(store.account(&b), Some(acc(50, 0)));
    }

    /// 在指定 key 上 `put` 失败的 backend（原子性测试注入；仅测试用）。
    struct FailingBackend {
        inner: MemoryBackend,
        fail_key: TrieKey,
    }

    impl StorageBackend for FailingBackend {
        type Snapshot = MemorySnapshot;

        fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
            self.inner.get(key)
        }

        fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError> {
            if key == self.fail_key {
                return Err(StorageError::BackendFailure);
            }
            self.inner.put(key, value)
        }

        fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn snapshot(&self) -> MemorySnapshot {
            self.inner.snapshot()
        }

        fn restore(&mut self, snap: &MemorySnapshot) {
            self.inner.restore(snap)
        }
    }

    #[test]
    fn apply_failure_rolls_back_atomically() {
        // D-7 必测 1（Atomicity）：change[0] 成功 + change[1] 失败 ⇒ root/account 不变
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let failing = FailingBackend {
            inner: MemoryBackend::new(),
            fail_key: b.payload().to_bytes(),
        };
        let mut store = StateStore::new(failing);
        let root_before = store.state_root();
        let changes = vec![
            AccountChange {
                address: a,
                new_balance: 100,
                new_nonce: 1,
                created: true,
            },
            AccountChange {
                address: b,
                new_balance: 200,
                new_nonce: 1,
                created: true,
            },
        ];
        assert_eq!(store.apply(&changes), Err(StorageError::BackendFailure));
        assert_eq!(store.state_root(), root_before, "root must roll back");
        assert_eq!(store.account(&a), None, "change[0] must roll back");
        assert_eq!(store.account(&b), None);
    }

    // ---- apply_block（8D，区块级原子；ADR-0029 D-4）----
    #[test]
    fn apply_block_multiple_and_empty() {
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        // 空区块 ⇒ root 不变（ADR-0030 C-5）
        let root0 = store.state_root();
        assert_eq!(store.apply_block(&[]).unwrap(), root0);
        // 两个 tx 的 changes
        let tx1 = vec![AccountChange {
            address: a,
            new_balance: 100,
            new_nonce: 1,
            created: true,
        }];
        let tx2 = vec![AccountChange {
            address: b,
            new_balance: 50,
            new_nonce: 0,
            created: true,
        }];
        let refs: Vec<&[AccountChange]> = vec![&tx1, &tx2];
        let root = store.apply_block(&refs).unwrap();
        assert_ne!(root, root0);
        assert_eq!(store.account(&a), Some(acc(100, 1)));
        assert_eq!(store.account(&b), Some(acc(50, 0)));
    }

    #[test]
    fn apply_block_failure_rolls_back_atomically() {
        let a = addr([0xaa; 32]);
        let b = addr([0xbb; 32]);
        let failing = FailingBackend {
            inner: MemoryBackend::new(),
            fail_key: b.payload().to_bytes(),
        };
        let mut store = StateStore::new(failing);
        let root_before = store.state_root();
        let tx1 = vec![AccountChange {
            address: a,
            new_balance: 100,
            new_nonce: 1,
            created: true,
        }];
        let tx2 = vec![AccountChange {
            address: b,
            new_balance: 50,
            new_nonce: 0,
            created: true,
        }];
        let refs: Vec<&[AccountChange]> = vec![&tx1, &tx2];
        assert_eq!(store.apply_block(&refs), Err(StorageError::BackendFailure));
        assert_eq!(store.state_root(), root_before, "block must roll back");
        assert_eq!(store.account(&a), None, "tx1 must roll back");
        assert_eq!(store.account(&b), None);
    }
}
