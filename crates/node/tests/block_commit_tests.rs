//! Block Commit v1 集成测试（STEP 10-19-8）。
//!
//! 验证 crash-consistent commit protocol：BlockStore durable-first → StateStore + ChainHead
//! 同批（既有 WAL）→ HeadRecord 即 state+head commit marker → recovery 校验 canonical block
//! 存在且与 head 一致（mismatch ⇒ CorruptedState fail-closed）。
//!
//! 测试用真实 `PersistentBackend`（文件）+ `BlockStore`（blocks 子目录）+ `NodeBlockAdapter`
//!（`with_block_store`）。空 block（无 tx ⇒ state_root 不变 = 父 root）聚焦 commit 结构而非
//! execution（execution/state 推进已由 block_adapter/execution 既有测试覆盖）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nova_crypto::address::NetworkId;
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::block_store::BlockStore;
use nova_storage::head::HeadRecord;
use nova_storage::persistent::PersistentBackend;
use nova_storage::store::StateStore;

use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;

type FileAdapter = NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>;

/// 临时目录 fixture（自建；Drop 清理）。
struct TestChain {
    dir: PathBuf,
    chain_dir: PathBuf,
    blocks_dir: PathBuf,
}

impl TestChain {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_10_19_8_{}_{}", std::process::id(), n));
        let chain_dir = dir.join("chain");
        let blocks_dir = dir.join("blocks");
        Self {
            dir,
            chain_dir,
            blocks_dir,
        }
    }
}

impl Drop for TestChain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 首次创建（空 backend + genesis head + BlockStore）。
fn create_adapter(chain: &TestChain) -> FileAdapter {
    std::fs::create_dir_all(&chain.chain_dir).unwrap();
    let backend = PersistentBackend::create(&chain.chain_dir).unwrap();
    let store = StateStore::new(backend);
    let root = store.state_root();
    let head = ChainHead::genesis(GENESIS_HASH, root);
    let bs = BlockStore::open(&chain.blocks_dir).unwrap();
    NodeBlockAdapter::with_block_store(
        store,
        NoAccountsKeyResolver,
        CHAIN_ID,
        GENESIS_HASH,
        MAX_GAS,
        0,
        head,
        NetworkId::Mainnet,
        Some(bs),
    )
}

/// 重启：open backend → load_with_head（WAL 恢复 state+head）→ 重装配 BlockStore → 恢复校验。
fn reopen_adapter(chain: &TestChain) -> (FileAdapter, HeadRecord) {
    let backend = PersistentBackend::open(&chain.chain_dir).unwrap();
    let (store, head_rec) = StateStore::load_with_head(backend).unwrap();
    let head_rec = head_rec.expect("committed head recovered");
    let head = ChainHead {
        height: head_rec.height,
        block_hash: head_rec.block_hash,
        state_root: head_rec.state_root,
        parent_hash: head_rec.parent_hash,
    };
    let bs = BlockStore::open(&chain.blocks_dir).unwrap();
    let adapter = NodeBlockAdapter::with_block_store(
        store,
        NoAccountsKeyResolver,
        CHAIN_ID,
        GENESIS_HASH,
        MAX_GAS,
        0,
        head,
        NetworkId::Mainnet,
        Some(bs),
    );
    adapter
        .verify_committed_head_block()
        .expect("head block consistent");
    (adapter, head_rec)
}

/// 空 block 的 proposer 块签名（DomainId::Block + chain_id + canonical header）。
fn block_signature(header: &BlockHeader, sk: &SigningKey) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

/// 下一个空 block（parent = head；state_root = 当前 store root —— 空执行不变）+ wire。
fn next_empty_block(adapter: &FileAdapter, kp: &KeyPair) -> (Block, Vec<u8>) {
    let head = adapter.head();
    let height = head.height + 1;
    let state_root = *adapter.store().state_root().as_bytes();
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height,
        parent_hash: head.block_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let block = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let wire = encode_block(&block).unwrap();
    (block, wire)
}

fn setup() -> (TestChain, KeyPair) {
    (TestChain::new(), KeyPair::generate().unwrap())
}

// BC-TEST-1 + 2 + 3 + 4：首次 commit 成功；BlockStore 保存 block；state_root 一致；head 推进。
#[test]
fn bc_1_4_first_commit_consistent() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let root0 = *adapter.store().state_root().as_bytes();
    let (block, wire) = next_empty_block(&adapter, &kp);
    let h = adapter.apply_block(&wire, kp.verifying_key()).unwrap();

    // BC-TEST-1：首次 commit 成功 + head 推进（BC-TEST-4）
    assert_eq!(h.height, 1);
    assert_eq!(adapter.head(), &h);
    // BC-TEST-2：BlockStore 存在 committed block
    assert!(
        adapter
            .block_store()
            .unwrap()
            .contains(&h.block_hash)
            .unwrap()
    );
    let stored = adapter
        .block_store()
        .unwrap()
        .get(&h.block_hash)
        .unwrap()
        .unwrap();
    assert_eq!(stored, block);
    // BC-TEST-3：state_root 与 block 一致（空执行 ⇒ root 不变）
    assert_eq!(*h.state_root.as_bytes(), root0);
    assert_eq!(h.state_root, adapter.store().state_root());
    assert_eq!(block.header.state_root, root0);
}

// BC-TEST-5 + 6：重复 commit idempotent；canonical content-address（同 hash 必同 bytes）。
#[test]
fn bc_5_6_duplicate_idempotent_and_content_address() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let (b, wire) = next_empty_block(&adapter, &kp);
    let h1 = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
    let root_after = adapter.store().state_root();

    // BC-TEST-5：再次 commit 同 block ⇒ idempotent（Ok；head/root 不变）
    let h2 = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
    assert_eq!(h2, h1, "idempotent：head 不变");
    assert_eq!(adapter.store().state_root(), root_after, "state 不变");
    assert_eq!(adapter.head(), &h1);

    // BC-TEST-6：canonical content-address —— 同 hash 必同 canonical bytes ⇒ 重复 put 幂等
    // （同 hash 不同 bytes 的冲突 / 损坏拒绝语义已由 storage BS-6 / BS-7 在记录层覆盖）。
    let bs = adapter.block_store().unwrap();
    bs.put(&b).unwrap(); // 幂等
    let record_count = std::fs::read_dir(&chain.blocks_dir).unwrap().count();
    assert_eq!(record_count, 1, "仅一份 canonical block 记录");
}

// BC-TEST-7：height gap 拒绝（head=1 提交 height=3）。
#[test]
fn bc_7_height_gap_rejected() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let (_b, w1) = next_empty_block(&adapter, &kp);
    adapter.apply_block(&w1, kp.verifying_key()).unwrap(); // head = 1
    let head1 = adapter.head().clone();
    let root = *adapter.store().state_root().as_bytes();
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 3, // gap（应 2）
        parent_hash: head1.block_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: root,
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let gap = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let err = adapter
        .apply_block(&encode_block(&gap).unwrap(), kp.verifying_key())
        .unwrap_err();
    assert!(matches!(
        err,
        nova_node::block_adapter::NodeBlockApplicationError::Pipeline(_)
    ));
    assert_eq!(adapter.head(), &head1, "head 不变");
}

// BC-TEST-8：stale block（height ≤ head.height 且非当前 head hash）拒绝。
#[test]
fn bc_8_stale_rejected() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let (_b, w1) = next_empty_block(&adapter, &kp);
    let h1 = adapter.apply_block(&w1, kp.verifying_key()).unwrap(); // head=1
    // 提交 height=1 的另一 block（不同 timestamp ⇒ 不同 hash；同高度但非 head ⇒ stale 拒绝）
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&BlockBody { txs: Vec::new() }),
        state_root: *h1.state_root.as_bytes(),
        validator_set_hash: [0u8; 32],
        timestamp: 5, // 不同 timestamp ⇒ 不同于已提交 h1 的 hash
    };
    let stale = Block {
        header: header.clone(),
        body: BlockBody { txs: Vec::new() },
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let err = adapter
        .apply_block(&encode_block(&stale).unwrap(), kp.verifying_key())
        .unwrap_err();
    assert!(matches!(
        err,
        nova_node::block_adapter::NodeBlockApplicationError::Pipeline(_)
    ));
    assert_eq!(adapter.head(), &h1, "head 不变");
}

// BC-TEST-9：conflicting head —— 同高度不同 hash（head 已指向 h1，提交另一 hash）拒绝。
#[test]
fn bc_9_conflicting_head_rejected() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let (_b, w1) = next_empty_block(&adapter, &kp);
    let h1 = adapter.apply_block(&w1, kp.verifying_key()).unwrap();
    // 另一 height=1 block（同 head 高度但不同 hash：不同 timestamp ⇒ 不同 hash）
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: h1.parent_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&BlockBody { txs: Vec::new() }),
        state_root: *h1.state_root.as_bytes(),
        validator_set_hash: [0u8; 32],
        timestamp: 99, // 不同 timestamp ⇒ 不同 block hash
    };
    let other = Block {
        header: header.clone(),
        body: BlockBody { txs: Vec::new() },
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    assert_ne!(nova_runtime::block_hash(&other).unwrap(), h1.block_hash);
    let err = adapter
        .apply_block(&encode_block(&other).unwrap(), kp.verifying_key())
        .unwrap_err();
    assert!(matches!(
        err,
        nova_node::block_adapter::NodeBlockApplicationError::Pipeline(_)
    ));
    assert_eq!(adapter.head(), &h1, "head 不变");
}

// BC-TEST-10 + 16 + 18：restart 后 canonical block + state + head 一致；重复 recovery 幂等；
// 连续多块 restart 顺序一致。
#[test]
fn bc_10_16_18_restart_consistent_and_idempotent() {
    let (chain, kp) = setup();
    let mut last_hash = [0u8; 32];
    {
        let mut adapter = create_adapter(&chain);
        for _ in 0..3 {
            let (_b, wire) = next_empty_block(&adapter, &kp);
            let h = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
            last_hash = h.block_hash;
        }
    } // drop（模拟进程结束）

    // BC-TEST-10：重启后 head/state/block 一致
    let (adapter, head_rec) = reopen_adapter(&chain);
    assert_eq!(
        head_rec.block_hash, last_hash,
        "恢复 head 为最后 committed block"
    );
    assert_eq!(adapter.head().block_hash, last_hash);
    // BC-TEST-16：重复 recovery（再次 reopen + verify）幂等
    drop(adapter);
    let (adapter2, head_rec2) = reopen_adapter(&chain);
    assert_eq!(head_rec2.block_hash, last_hash);
    // BC-TEST-18 关键断言：canonical head block 存在且与恢复 head 字段一致
    let stored = adapter2
        .block_store()
        .unwrap()
        .get(&head_rec2.block_hash)
        .unwrap()
        .expect("canonical head block exists");
    assert_eq!(stored.header.height, head_rec2.height);
    assert_eq!(stored.header.state_root, *head_rec2.state_root.as_bytes());
    assert_eq!(stored.header.parent_hash, head_rec2.parent_hash);
}

// BC-TEST-11：head 存在但 BlockStore block 缺失 ⇒ 恢复 CorruptedState（fail closed）。
#[test]
fn bc_11_missing_head_block_fail_closed() {
    let (chain, kp) = setup();
    {
        let mut adapter = create_adapter(&chain);
        let (_b, wire) = next_empty_block(&adapter, &kp);
        adapter.apply_block(&wire, kp.verifying_key()).unwrap();
    }
    // 删除 committed block 文件
    let (adapter, head_rec) = reopen_no_verify(&chain);
    let path = chain
        .blocks_dir
        .join(format!("block_{}.blk", hex(head_rec.block_hash)));
    std::fs::remove_file(&path).unwrap();
    let err = adapter.verify_committed_head_block().unwrap_err();
    assert!(
        matches!(
            err,
            nova_node::block_adapter::NodeBlockApplicationError::Pipeline(
                nova_runtime::BlockPipelineError::Storage(
                    nova_storage::error::StorageError::CorruptedState
                )
            )
        ),
        "head block 缺失 ⇒ CorruptedState"
    );
}

// BC-TEST-12：BlockStore block 损坏 ⇒ 恢复 CorruptedState（fail closed）。
#[test]
fn bc_12_corrupted_head_block_fail_closed() {
    let (chain, kp) = setup();
    let hash = {
        let mut adapter = create_adapter(&chain);
        let (_b, wire) = next_empty_block(&adapter, &kp);
        let h = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
        h.block_hash
    };
    let path = chain.blocks_dir.join(format!("block_{}.blk", hex(hash)));
    let mut bytes = std::fs::read(&path).unwrap();
    let flip = bytes.len() - 34; // canonical 区
    bytes[flip] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    let (adapter, _hr) = reopen_no_verify(&chain);
    let err = adapter.verify_committed_head_block().unwrap_err();
    assert!(
        matches!(
            err,
            nova_node::block_adapter::NodeBlockApplicationError::Pipeline(
                nova_runtime::BlockPipelineError::Storage(
                    nova_storage::error::StorageError::CorruptedState
                )
            )
        ),
        "block 损坏 ⇒ CorruptedState"
    );
}

// BC-TEST-13：block header state_root 与 canonical state 不一致 ⇒ commit fail closed。
#[test]
fn bc_13_state_root_mismatch_rejected() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let head0 = adapter.head().clone();
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: head0.block_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&BlockBody { txs: Vec::new() }),
        state_root: [0xAA; 32], // 错误 root（实际 = EMPTY parent root）
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let bad = Block {
        header: header.clone(),
        body: BlockBody { txs: Vec::new() },
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let err = adapter
        .apply_block(&encode_block(&bad).unwrap(), kp.verifying_key())
        .unwrap_err();
    assert!(
        matches!(
            err,
            nova_node::block_adapter::NodeBlockApplicationError::Pipeline(_)
        ),
        "state_root mismatch ⇒ ④ 拒绝（durable state commit 前）"
    );
    assert_eq!(adapter.head(), &head0, "head 不变");
}

// BC-TEST-14：parent mismatch 拒绝（head 不变）。
#[test]
fn bc_14_parent_mismatch_rejected() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let (_b, w1) = next_empty_block(&adapter, &kp);
    let h1 = adapter.apply_block(&w1, kp.verifying_key()).unwrap();
    // height=2 但 parent ≠ head1.block_hash
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 2,
        parent_hash: [0x00; 32],
        finality_reference: None,
        transaction_root: compute_transaction_root(&BlockBody { txs: Vec::new() }),
        state_root: *h1.state_root.as_bytes(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let bad = Block {
        header: header.clone(),
        body: BlockBody { txs: Vec::new() },
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let err = adapter
        .apply_block(&encode_block(&bad).unwrap(), kp.verifying_key())
        .unwrap_err();
    assert!(matches!(
        err,
        nova_node::block_adapter::NodeBlockApplicationError::Pipeline(_)
    ));
    assert_eq!(adapter.head(), &h1, "head 不变");
}

// BC-TEST-17：连续提交 N → N+1 → N+2 → N+3 全部一致（head/root/block 逐块）。
#[test]
fn bc_17_sequential_blocks() {
    let (chain, kp) = setup();
    let mut adapter = create_adapter(&chain);
    let mut prev = adapter.head().clone();
    for i in 1..=3u64 {
        let (b, wire) = next_empty_block(&adapter, &kp);
        let h = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
        assert_eq!(h.height, i);
        assert_eq!(h.parent_hash, prev.block_hash, "parent = 前一块");
        assert_eq!(h.block_hash, nova_runtime::block_hash(&b).unwrap());
        assert!(
            adapter
                .block_store()
                .unwrap()
                .contains(&h.block_hash)
                .unwrap()
        );
        prev = h;
    }
    assert_eq!(prev.height, 3);
}

// 辅助：reopen 但**不**调用 verify（供失败注入测试）。
fn reopen_no_verify(chain: &TestChain) -> (FileAdapter, HeadRecord) {
    let backend = PersistentBackend::open(&chain.chain_dir).unwrap();
    let (store, head_rec) = StateStore::load_with_head(backend).unwrap();
    let head_rec = head_rec.expect("committed head recovered");
    let head = ChainHead {
        height: head_rec.height,
        block_hash: head_rec.block_hash,
        state_root: head_rec.state_root,
        parent_hash: head_rec.parent_hash,
    };
    let bs = BlockStore::open(&chain.blocks_dir).unwrap();
    let adapter = NodeBlockAdapter::with_block_store(
        store,
        NoAccountsKeyResolver,
        CHAIN_ID,
        GENESIS_HASH,
        MAX_GAS,
        0,
        head,
        NetworkId::Mainnet,
        Some(bs),
    );
    (adapter, head_rec)
}

fn hex(hash: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
