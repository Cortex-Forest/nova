//! OD-7 ChainHead durability 集成测试（PHASE 3 STEP 7-J；ADR-0048 / ADR-0031 E-3 amendment）。
//!
//! 覆盖：state+head 同批持久化与恢复、cross-check、WAL legacy/new、snapshot 携带 head、
//!       state/head mismatch（integrity failure）、M2 migration（legacy 无 head 检测）、截断尾部丢弃。

use nova_core::state::{AccountChange, AccountStateView};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_storage::backend::StorageBackend;
use nova_storage::error::StorageError;
use nova_storage::head::{HeadRecord, decode_head_record, encode_head_record};
use nova_storage::node::NodeHash;
use nova_storage::persistent::PersistentBackend;
use nova_storage::state_root::calculate_state_root;
use nova_storage::store::StateStore;
use tempfile::TempDir;

fn addr(key_hash: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash,
    })
}

fn change(a: NovaAddress, balance: u128, nonce: u64) -> AccountChange {
    AccountChange {
        address: a,
        new_balance: balance,
        new_nonce: nonce,
        created: true,
    }
}

fn head_record(height: u64, root: NodeHash) -> HeadRecord {
    HeadRecord {
        height,
        block_hash: [height as u8; 32],
        parent_hash: [0xaa; 32],
        state_root: root,
    }
}

/// 模拟 adapter ④→⑤→enqueue_head→⑥：head 与 state 同批提交。
/// head.state_root 由只读 `calculate_state_root` 预知（= commit root，ADR-0030 C-3）。
fn commit_block_with_head(
    store: &mut StateStore<PersistentBackend>,
    height: u64,
    a: NovaAddress,
    balance: u128,
    nonce: u64,
) -> NodeHash {
    let changes = [change(a, balance, nonce)];
    let tx_refs: Vec<&[AccountChange]> = vec![&changes];
    let expected = calculate_state_root(store, &tx_refs).unwrap();
    store.enqueue_head(head_record(height, expected)).unwrap();
    let root = store.apply_block(&tx_refs).unwrap();
    assert_eq!(root, expected, "commit root == pre-computed root (C-3)");
    root
}

#[test]
fn persistent_state_and_head_persist_then_recover() {
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    let root1;
    {
        let mut store = StateStore::new(PersistentBackend::create(dir.path()).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap();
        root1 = commit_block_with_head(&mut store, 1, a, 900, 1);
    }
    // 重启恢复：state + head 同批重放 + cross-check
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let (store, recovered) = StateStore::load_with_head(backend).unwrap();
    assert_eq!(store.state_root(), root1, "state recovered");
    let h = recovered.expect("head recovered");
    assert_eq!(h.height, 1);
    assert_eq!(
        h.state_root, root1,
        "head.state_root == recovered state_root"
    );
    assert_eq!(store.account(&a).unwrap().balance, 900);
}

#[test]
fn wal_legacy_state_only_recovers_without_head() {
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    {
        let mut store = StateStore::new(PersistentBackend::create(dir.path()).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap(); // legacy state-only 批次（magic 0x01，无 head）
    }
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let (store, head) = StateStore::load_with_head(backend).unwrap();
    assert_eq!(
        store.account(&a).unwrap().balance,
        1000,
        "legacy state recoverable"
    );
    assert!(head.is_none(), "legacy WAL 无 head ⇒ M2 检测点");
}

#[test]
fn truncated_wal_tail_discarded_preserves_head() {
    use std::io::Write;
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    {
        let mut store = StateStore::new(PersistentBackend::create(dir.path()).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap();
        let changes = [change(a, 900, 1)];
        let tx_refs: Vec<&[AccountChange]> = vec![&changes];
        let expected = calculate_state_root(&store, &tx_refs).unwrap();
        store.enqueue_head(head_record(1, expected)).unwrap();
        store.apply_block(&tx_refs).unwrap();
    }
    // 追加损坏/不完整尾部
    let wal = dir.path().join("wal.log");
    let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
    f.write_all(&[0xff, 0x00, 0x01, 0x02]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    // 重开：有效批次（state+head）保留，损坏尾部丢弃
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let (store, head) = StateStore::load_with_head(backend).unwrap();
    let h = head.expect("head from valid batch");
    assert_eq!(h.height, 1);
    assert_eq!(h.state_root, store.state_root(), "state/head consistent");
    assert_eq!(store.account(&a).unwrap().balance, 900);
}

#[test]
fn snapshot_carries_head_after_wal_truncation() {
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    let hr = head_record(3, NodeHash::from_bytes([0xcc; 32]));
    let head_bytes = encode_head_record(&hr);
    {
        let mut backend = PersistentBackend::create(dir.path()).unwrap();
        backend.enqueue_meta(&head_bytes).unwrap();
        backend.put(a.payload().to_bytes(), vec![0xaa; 88]).unwrap();
        backend.flush().unwrap(); // 单批：state + head
        assert!(backend.recovered_meta().is_some());
        backend.persist_snapshot().unwrap(); // 截断 WAL
    }
    // 重新打开：WAL 已截断 ⇒ head 必须来自 snapshot
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let meta = backend.recovered_meta().expect("head from snapshot");
    let h = decode_head_record(&meta).unwrap();
    assert_eq!(h.height, 3);
}

#[test]
fn state_head_mismatch_recovery_error() {
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    {
        let mut store = StateStore::new(PersistentBackend::create(dir.path()).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap();
        // enqueue head 但 state_root 错误（与实际提交 root 不符；checksum 有效 ⇒ integrity failure）
        store
            .enqueue_head(head_record(1, NodeHash::from_bytes([0x11; 32])))
            .unwrap();
        let changes = [change(a, 900, 1)];
        let tx_refs: Vec<&[AccountChange]> = vec![&changes];
        store.apply_block(&tx_refs).unwrap();
    }
    // cross-check 失败 ⇒ CorruptedState（integrity failure；RecoveryError 为 follow-up）
    let res = StateStore::load_with_head(PersistentBackend::open(dir.path()).unwrap());
    assert!(matches!(res, Err(StorageError::CorruptedState)));
}

#[test]
fn migration_legacy_bootstrap_then_persist_head() {
    // M2：legacy 无 head ⇒ 恢复 head=None ⇒ 显式 bootstrap（state_root 交叉一致）⇒ persist ⇒ 恢复 head。
    let dir = TempDir::new().unwrap();
    let a = addr([0xaa; 32]);
    {
        let mut store = StateStore::new(PersistentBackend::create(dir.path()).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap();
    }
    // 恢复：head None（M2 检测点）
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let (mut store, head) = StateStore::load_with_head(backend).unwrap();
    assert!(head.is_none());
    // Node bootstrap：head.state_root 必须 == 恢复 state_root
    let bootstrap_root = store.state_root();
    store.enqueue_head(head_record(0, bootstrap_root)).unwrap();
    store.apply_block(&[] as &[&[AccountChange]]).unwrap(); // 空区块 flush（不改 state）
    // 再次恢复：head 存在且与 state 一致；幂等（head 已存在，不再 bootstrap）
    let backend = PersistentBackend::open(dir.path()).unwrap();
    let (store2, head2) = StateStore::load_with_head(backend).unwrap();
    let h = head2.expect("bootstrapped head recovered");
    assert_eq!(h.height, 0);
    assert_eq!(
        h.state_root,
        store2.state_root(),
        "bootstrap head matches state"
    );
    assert_eq!(store2.state_root(), bootstrap_root);
}
