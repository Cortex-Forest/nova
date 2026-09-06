//! Node-level Block Inbound Dispatch 集成测试（STEP 10-19-10-A）。
//!
//! 覆盖 BDIS-1..10：`wiring::NodeConsensusHandler` 收集 GossipBlock / SyncBlockResponse →
//! `block_dispatch::{dispatch_gossip_block, dispatch_sync_block_response}` → 10-19-9
//! `validate_block_inbound` seam → typed verdict；**全程零 mutation**（不 commit / 不写
//! BlockStore / 不推进 ChainHead / 不更新 StateStore）。
//!
//! 诚实能力边界：BlockV1 header 无 proposer identity，Node 当前不能可靠确定远端 proposer key
//! ⇒ dispatch 上下文 `expected_proposer_vk = None` ⇒ 对"canonical next"候选，validator 返回
//! `UnsupportedValidation(ProposerSignature)`（**不伪造 vk / 不 None→accept**）。CanonicalNextCandidate
//! 产出需未来 proposer-key seam（A11）；validator 有 vk 时的产出由 block_inbound_tests BIV-1 覆盖。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nova_crypto::address::NetworkId;
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_network::event_loop::{EventHandler, NodeEvent};
use nova_network::network_service::NetworkEvent;
use nova_network::node_id::NodeId;
use nova_network::sync::{BlockPayload, SyncBlockResponse};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::block_store::BlockStore;
use nova_storage::memory::MemoryBackend;
use nova_storage::persistent::PersistentBackend;
use nova_storage::store::StateStore;

use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};
use nova_node::block_dispatch::{dispatch_gossip_block, dispatch_sync_block_response};
use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict, UnverifiableItem};
use nova_node::wiring::{BlockInboundMessage, NodeConsensusHandler};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024; // 协议上限（本测试上下文）

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
        let dir = std::env::temp_dir().join(format!("nova_10_19_10a_{}_{}", std::process::id(), n));
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

/// 空 block 的 proposer 块签名（DomainId::Block + chain_id + canonical header）。
fn block_signature(header: &BlockHeader, sk: &SigningKey) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

/// 空 body block（height / parent / state_root 显式；签名用 `sk`）。
fn empty_block(
    height: u64,
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    sk: &SigningKey,
    timestamp: u64,
) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height,
        parent_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: [0u8; 32],
        timestamp,
    };
    Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, sk),
    }
}

fn wire(block: &Block) -> Vec<u8> {
    encode_block(block).unwrap()
}

/// 空 store 的空 root（= EMPTY；MemoryBackend 只读推导，与测试用空 PersistentBackend 同值）。
fn empty_root() -> [u8; 32] {
    *StateStore::new(MemoryBackend::new())
        .state_root()
        .as_bytes()
}

/// canonical next 空块（genesis head 之上：height 1 / parent = genesis / root = 空 root）。
fn canonical_next_block(kp: &KeyPair) -> Block {
    empty_block(1, GENESIS_HASH, empty_root(), kp.signing_key(), 0)
}

// ---------------------------------------------------------------------------
// BDIS-1 + BDIS-10：Gossip 合法 canonical-next block 经 seam；诚实能力边界；零 mutation
// ---------------------------------------------------------------------------

#[test]
fn bdis_1_gossip_valid_block_seam_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let block = canonical_next_block(&kp);
    let gossip = wire(&block);
    let root_before = adapter.store().state_root();
    let head_before = adapter.head().clone();
    let hash = nova_runtime::block_hash(&block).unwrap();

    // 诚实能力边界：Node 无远端 proposer key（BlockV1 header 无 proposer id）⇒ Unsupported
    // （绝不 None→accept / 不伪造 vk）。size/decode/chain/hash/order/txroot 已过 —— 仅卡 proposer。
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &gossip);
    assert_eq!(
        result,
        Err(InboundBlockError::UnsupportedValidation(
            UnverifiableItem::ProposerSignature
        ))
    );

    // BDIS-10：零 mutation（BlockStore / StateStore / ChainHead 均不变）
    assert_eq!(adapter.store().state_root(), root_before, "state unchanged");
    assert_eq!(adapter.head(), &head_before, "head unchanged");
    assert!(
        !adapter.block_store().unwrap().contains(&hash).unwrap(),
        "no blockstore write"
    );
}

// ---------------------------------------------------------------------------
// BDIS-2 / BDIS-3：Malformed / WrongChain（零 mutation）
// ---------------------------------------------------------------------------

#[test]
fn bdis_2_malformed_gossip_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let root_before = adapter.store().state_root();
    let head_before = adapter.head().clone();
    let mut bad = wire(&canonical_next_block(&kp));
    bad.truncate(bad.len() - 5); // 截断 ⇒ decode Malformed
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &bad);
    assert_eq!(result, Err(InboundBlockError::Malformed));
    assert_eq!(adapter.store().state_root(), root_before);
    assert_eq!(adapter.head(), &head_before);
}

#[test]
fn bdis_3_wrong_chain_gossip_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let root_before = adapter.store().state_root();
    let head_before = adapter.head().clone();
    // 错误 chain_id 的合法块（签名按错误 chain 自洽；chain 检查在签名前）
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: 999,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let block = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key()),
    };
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&block));
    assert_eq!(result, Err(InboundBlockError::WrongChain { found: 999 }));
    assert_eq!(adapter.store().state_root(), root_before);
    assert_eq!(adapter.head(), &head_before);
}

// ---------------------------------------------------------------------------
// BDIS-5 / BDIS-6 / BDIS-7：head 推进后 Gossip stale / future / conflicting parent
// ---------------------------------------------------------------------------

/// 推进 head 到 1（apply 一个 canonical 空块）。
fn advance_head(adapter: &mut FileAdapter, kp: &KeyPair) -> [u8; 32] {
    let block = canonical_next_block(kp);
    let h = adapter
        .apply_block(&wire(&block), kp.verifying_key())
        .unwrap();
    h.block_hash
}

#[test]
fn bdis_5_stale_gossip_classified_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let mut adapter = create_adapter(&chain);
    let head1 = advance_head(&mut adapter, &kp); // head = blockA (height 1)
    let root_before = adapter.store().state_root();
    // 同高不同块（timestamp 不同 ⇒ 不同 hash）⇒ Stale
    let block_a2 = empty_block(1, GENESIS_HASH, empty_root(), kp.signing_key(), 99);
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&block_a2));
    assert!(matches!(
        result,
        Ok(InboundBlockVerdict::Stale { height: 1, .. })
    ));
    assert_eq!(adapter.head().block_hash, head1, "head unchanged");
    assert_eq!(adapter.store().state_root(), root_before);
}

#[test]
fn bdis_6_future_gossip_classified_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let mut adapter = create_adapter(&chain);
    let head1 = advance_head(&mut adapter, &kp);
    let root_before = adapter.store().state_root();
    // height 3 > head(1)+1 ⇒ FutureMissingAncestor
    let future = empty_block(3, head1, empty_root(), kp.signing_key(), 0);
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&future));
    assert!(matches!(
        result,
        Ok(InboundBlockVerdict::FutureMissingAncestor { height: 3, .. })
    ));
    assert_eq!(adapter.head().block_hash, head1);
    assert_eq!(adapter.store().state_root(), root_before);
}

#[test]
fn bdis_7_conflicting_parent_gossip_classified_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let mut adapter = create_adapter(&chain);
    let head1 = advance_head(&mut adapter, &kp); // head1 = blockA hash
    let root_before = adapter.store().state_root();
    // height = head+1 = 2 但 parent ≠ head1（指向 genesis）⇒ ConflictingParent
    let conflict = empty_block(2, GENESIS_HASH, empty_root(), kp.signing_key(), 0);
    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&conflict));
    match result {
        Ok(InboundBlockVerdict::ConflictingParent {
            height,
            parent_hash,
            expected_parent,
            ..
        }) => {
            assert_eq!(height, 2);
            assert_eq!(parent_hash, GENESIS_HASH);
            assert_eq!(expected_parent, head1);
        }
        other => panic!("expected ConflictingParent, got {other:?}"),
    }
    assert_eq!(adapter.head().block_hash, head1);
    assert_eq!(adapter.store().state_root(), root_before);
}

// ---------------------------------------------------------------------------
// BDIS-8 / BDIS-9：SyncBlockResponse / GossipBlock 经同一 seam（含 handler 收集）
// ---------------------------------------------------------------------------

#[test]
fn bdis_8_sync_response_same_seam_as_gossip() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let block = canonical_next_block(&kp);
    let response = SyncBlockResponse {
        blocks: vec![BlockPayload::from_block(&block).unwrap()],
    };
    let payload = response.encode();

    // SyncBlockResponse → 同一 seam（内部 decode response → 每块 validate_block_inbound）
    let sync_results = dispatch_sync_block_response(&adapter, MAX_BLOCK_BYTES, &payload);
    assert_eq!(sync_results.len(), 1);
    // 与 Gossip 同块结果一致（诚实能力边界：Unsupported ProposerSignature）
    let gossip_result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&block));
    assert_eq!(sync_results[0], gossip_result);
}

#[test]
fn bdis_8_sync_response_malformed_payload_typed_error() {
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let results = dispatch_sync_block_response(&adapter, MAX_BLOCK_BYTES, &[1u8, 2, 3]);
    assert_eq!(results, vec![Err(InboundBlockError::Malformed)]);
}

#[test]
fn bdis_9_handler_collects_gossip_and_sync_block_payloads() {
    // wiring seam：NetworkEvent::GossipBlock / SyncBlockResponse → NodeConsensusHandler 队列
    let kp = KeyPair::generate().unwrap();
    let block = canonical_next_block(&kp);
    let gossip_payload = wire(&block);
    let sync_payload = SyncBlockResponse {
        blocks: vec![BlockPayload::from_block(&block).unwrap()],
    }
    .encode();
    let sender = NodeId::from_bytes([0x77; 32]);
    let mut handler = NodeConsensusHandler::new();

    // 与 consensus 类消息互不干扰：只收集 block payload（non_consensus 计数保留）
    handler
        .handle(&NodeEvent::Network(NetworkEvent::GossipBlock {
            sender,
            payload: gossip_payload.clone(),
        }))
        .unwrap();
    handler
        .handle(&NodeEvent::Network(NetworkEvent::SyncBlockResponse {
            sender,
            payload: sync_payload.clone(),
        }))
        .unwrap();
    handler
        .handle(&NodeEvent::Network(NetworkEvent::Ping {
            sender,
            payload: Vec::new(),
        }))
        .unwrap();

    assert_eq!(handler.non_consensus_seen(), 3);
    let collected = handler.take_block_inbound();
    assert_eq!(
        collected,
        vec![
            BlockInboundMessage::GossipBlock(gossip_payload),
            BlockInboundMessage::SyncBlockResponse(sync_payload),
        ]
    );
    assert!(
        handler.pending_commands() == 0,
        "block 不产生 consensus command"
    );
}

// ---------------------------------------------------------------------------
// BDIS-4 说明 + BDIS-10 综合：seam 无 claimed-hash 通道；全路径零 mutation
// ---------------------------------------------------------------------------

#[test]
fn bdis_10_no_mutation_across_reject_paths() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let root_before = adapter.store().state_root();
    let head_before = adapter.head().clone();
    let block = canonical_next_block(&kp);
    let hash = nova_runtime::block_hash(&block).unwrap();
    // 各 reject / 分类路径均零写
    let mut malformed = wire(&block);
    malformed.truncate(malformed.len() - 1);
    let _ = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &malformed); // Malformed
    let _ = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &wire(&block)); // Unsupported
    let _ = dispatch_gossip_block(&adapter, 16, &wire(&block)); // Oversized
    assert_eq!(adapter.store().state_root(), root_before, "state unchanged");
    assert_eq!(adapter.head(), &head_before, "head unchanged");
    assert!(!adapter.block_store().unwrap().contains(&hash).unwrap());
}
