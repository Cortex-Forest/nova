//! STEP 8E Persistence 测试（ADR-0031 E-7）。
//!
//! 覆盖：
//! 1. **Roundtrip**：StateStore<PersistentBackend> apply → drop → open + load ⇒ 同 root/账户。
//! 2. **Crash recovery**：WAL 尾部附加垃圾（模拟半写批次）⇒ open 丢弃尾部，保留完整批次。
//! 3. **Snapshot + WAL**：persist_snapshot → 新 changes → WAL 截断 ⇒ open（快照 + 重放）= 全量。
//! 4. **Backend equivalence**：Memory 与 Persistent 对同操作序列产生相同状态（entries）。
//! 5. **StateStore 集成**：Memory 与 Persistent 同输入 ⇒ 同 root / 同账户。
//! 6. **Atomicity**：rollback 后 pending 清空（WAL 无残留半批次）。

use nova_core::state::{
    AccountChange, AccountState, AccountStateView, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT,
};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_storage::backend::StorageBackend;
use nova_storage::memory::MemoryBackend;
use nova_storage::node::TrieKey;
use nova_storage::persistent::PersistentBackend;
use nova_storage::store::StateStore;
use std::fs::OpenOptions;
use std::io::Write;
use tempfile::tempdir;

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

fn acc(balance: u128, nonce: u64) -> AccountState {
    AccountState {
        balance,
        nonce,
        code_hash: EMPTY_CODE_HASH,
        storage_root: EMPTY_STORAGE_ROOT,
    }
}

fn append_garbage(path: &std::path::Path, bytes: &[u8]) {
    let wal = path.join("wal.log");
    let mut f = OpenOptions::new()
        .append(true)
        .open(&wal)
        .expect("open wal");
    f.write_all(bytes).expect("append garbage");
}

// 1. Roundtrip：StateStore<PersistentBackend> 持久化后 reload 同状态
#[test]
fn state_store_roundtrip_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let a = addr([0xaa; 32]);
    let b = addr([0xbb; 32]);
    let root;
    {
        let mut store = StateStore::new(PersistentBackend::create(path).unwrap());
        store.apply(&[change(a, 1000, 0)]).unwrap();
        store.apply(&[change(b, 500, 1)]).unwrap();
        root = store.state_root();
        // apply 已 flush；drop 后 backend 释放
    }
    let backend = PersistentBackend::open(path).unwrap();
    let store = StateStore::load(backend).unwrap();
    assert_eq!(store.state_root(), root, "reload root == pre-close root");
    assert_eq!(store.account(&a), Some(acc(1000, 0)));
    assert_eq!(store.account(&b), Some(acc(500, 1)));
}

// 2. Crash recovery：WAL 尾部垃圾被丢弃，完整批次保留
#[test]
fn crash_recovery_discards_corrupted_wal_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let k1 = [0x11u8; 35];
    let k2 = [0x22u8; 35];
    {
        let mut b = PersistentBackend::create(path).unwrap();
        b.put(k1, vec![1u8; 88]).unwrap();
        b.flush().unwrap();
        b.put(k2, vec![2u8; 88]).unwrap();
        b.flush().unwrap();
    }
    append_garbage(path, &[0xff; 20]); // 模拟崩溃半写批次
    let b2 = PersistentBackend::open(path).unwrap();
    assert_eq!(b2.get(&k1), Some(vec![1u8; 88]));
    assert_eq!(b2.get(&k2), Some(vec![2u8; 88]), "完整批次保留");
}

// 3. Snapshot + WAL：快照后新 changes 经 WAL 重放恢复全量
#[test]
fn snapshot_then_wal_replay_recovers_full_state() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let k1 = [0x11u8; 35];
    let k2 = [0x22u8; 35];
    let mut b = PersistentBackend::create(path).unwrap();
    b.put(k1, vec![1u8; 88]).unwrap();
    b.flush().unwrap();
    b.persist_snapshot().unwrap(); // 快照含 k1；WAL 截断
    b.put(k2, vec![2u8; 88]).unwrap();
    b.flush().unwrap(); // WAL 含 k2 批次
    append_garbage(path, &[0xee; 8]); // 模拟崩溃
    let b2 = PersistentBackend::open(path).unwrap();
    assert_eq!(b2.get(&k1), Some(vec![1u8; 88]), "快照恢复");
    assert_eq!(b2.get(&k2), Some(vec![2u8; 88]), "WAL 重放");
}

// 4. Backend equivalence：Memory 与 Persistent 同操作序列产生相同 entries
#[test]
fn backend_behavior_equivalent() {
    let dir = tempdir().unwrap();
    let mut m = MemoryBackend::new();
    let mut p = PersistentBackend::create(dir.path()).unwrap();
    let k1 = [0x11u8; 35];
    let k2 = [0x22u8; 35];
    // 相同操作序列（put/delete 原语）
    m.put(k1, vec![1u8; 88]).unwrap();
    p.put(k1, vec![1u8; 88]).unwrap();
    m.put(k2, vec![2u8; 88]).unwrap();
    p.put(k2, vec![2u8; 88]).unwrap();
    m.delete(&k2).unwrap();
    p.delete(&k2).unwrap();
    assert_eq!(m.entries(), p.entries(), "backend behavior contract 一致");
    assert_eq!(m.get(&k1), p.get(&k1));
    assert_eq!(m.get(&k2), p.get(&k2));
}

// 5. StateStore 集成：Memory 与 Persistent 同输入 ⇒ 同 root / 同账户
#[test]
fn memory_and_persistent_state_store_equivalent() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let a = addr([0xaa; 32]);
    let b = addr([0xbb; 32]);
    let mut m = StateStore::new(MemoryBackend::new());
    let mut p = StateStore::new(PersistentBackend::create(path).unwrap());
    let changes = [change(a, 1000, 0), change(b, 500, 1), change(a, 900, 1)];
    for c in &changes {
        m.apply(std::slice::from_ref(c)).unwrap();
        p.apply(std::slice::from_ref(c)).unwrap();
    }
    assert_eq!(m.state_root(), p.state_root(), "同输入同 root");
    assert_eq!(m.account(&a), p.account(&a));
    assert_eq!(m.account(&b), p.account(&b));
    // reload 后仍一致
    let backend = PersistentBackend::open(path).unwrap();
    let p2 = StateStore::load(backend).unwrap();
    assert_eq!(p2.state_root(), m.state_root());
}

// 6. Atomicity：rollback 后 pending 清空（WAL 无残留半批次）
#[test]
fn restore_clears_pending_after_rollback() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let k1 = [0x11u8; 35];
    let k2 = [0x22u8; 35];
    let mut b = PersistentBackend::create(path).unwrap();
    b.put(k1, vec![1u8; 88]).unwrap();
    b.flush().unwrap(); // k1 持久化
    let snap = b.snapshot();
    b.put(k2, vec![2u8; 88]).unwrap(); // pending 有 k2
    b.restore(&snap); // 回滚：kv 恢复 + pending 清空
    b.flush().unwrap(); // pending 空 ⇒ 不写 WAL
    let b2 = PersistentBackend::open(path).unwrap();
    assert_eq!(b2.get(&k1), Some(vec![1u8; 88]));
    assert_eq!(b2.get(&k2), None, "rolled-back write must not persist");
}

// 空目录 open ⇒ 空状态（幂等 create/open）
#[test]
fn open_idempotent_same_state() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let k1 = [0x33u8; 35];
    {
        let mut b = PersistentBackend::create(path).unwrap();
        b.put(k1, vec![7u8; 88]).unwrap();
        b.flush().unwrap();
    }
    let s1 = PersistentBackend::open(path).unwrap().entries();
    let s2 = PersistentBackend::open(path).unwrap().entries();
    assert_eq!(s1, s2, "多次 open 同一状态");
    let _: Vec<(TrieKey, Vec<u8>)> = s1;
}
