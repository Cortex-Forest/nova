//! Block Inbound Validation Boundary v1 集成测试（STEP 10-19-9）。
//!
//! 覆盖 BIV-1..18：远端 Block wire → `validate_block_inbound`（纯只读验证 + 分类）。
//! 重点证明：验证成功也**不 commit / 不推进 ChainHead / 不更新 StateStore / 不写 BlockStore**
//! （BIV-15..18）；远端输入绝不直接进入 `apply_block`（模块无 commit 依赖，scope audit 佐证）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_crypto::transaction::{TransactionType, TransactionV1};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::block_store::BlockStore;
use nova_storage::memory::MemoryBackend;
use nova_storage::node::NodeHash;
use nova_storage::store::StateStore;

use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver};
use nova_node::block_inbound::{
    InboundBlockContext, InboundBlockError, InboundBlockVerdict, UnverifiableItem,
    validate_block_inbound,
};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];

// ---------------------------------------------------------------------------
// 测试 fixtures（内存 state / 临时 block store / 块构造 helper）
// ---------------------------------------------------------------------------

/// 临时目录 fixture（自建；Drop 清理）。
struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nova_10_19_9_{}_{}_{}", tag, std::process::id(), n));
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// 空 canonical store（state root = EMPTY）。
fn empty_store() -> StateStore<MemoryBackend> {
    StateStore::new(MemoryBackend::new())
}

/// genesis head（空 store root）。
fn genesis_head() -> ChainHead {
    let root = empty_store().state_root();
    ChainHead::genesis(GENESIS_HASH, root)
}

/// 手工 head（stale/future/conflict 测试用；height 语义单一来源）。
fn head_at(height: u64, block_hash: [u8; 32]) -> ChainHead {
    ChainHead {
        height,
        block_hash,
        state_root: NodeHash::from_bytes([0x00; 32]),
        parent_hash: [0u8; 32],
    }
}

/// proposer 块签名（DomainId::Block + chain_id + canonical header；与冻结语义一致）。
fn block_signature(header: &BlockHeader, sk: &SigningKey, chain_id: u64) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

/// 空 body block（height / parent / state_root / chain_id / version 显式；签名用 `sk`）。
fn empty_block(
    chain_id: u64,
    height: u64,
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    sk: &SigningKey,
) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id,
        height,
        parent_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, sk, chain_id),
    }
}

/// 手工 TransactionV1（结构合法；signature 由调用方决定——inbound ordering/resolve 阶段不验签）。
fn raw_tx(sender: NovaAddress, receiver: NovaAddress, nonce: u64) -> TransactionV1 {
    TransactionV1 {
        version: 1,
        chain_id: CHAIN_ID,
        nonce,
        sender,
        receiver,
        amount: 100,
        gas_limit: 100_000,
        gas_price: 1,
        transaction_type: TransactionType::Transfer,
        payload: vec![0u8; 140],
        expiration: 1_000_000,
        signature: [0u8; 64],
    }
}

fn empty_block_wire(block: &Block) -> Vec<u8> {
    encode_block(block).unwrap()
}

fn canonical_wire(kp: &KeyPair, state_root: [u8; 32]) -> Vec<u8> {
    // 空 store + genesis head 之上的 canonical next（height 1 / parent = genesis）。
    let b = empty_block(CHAIN_ID, 1, GENESIS_HASH, state_root, kp.signing_key());
    encode_block(&b).unwrap()
}

// ---------------------------------------------------------------------------
// BIV-1 / BIV-16 / BIV-17 / BIV-18（valid canonical + 全程零 mutation）
// ---------------------------------------------------------------------------

#[test]
fn biv_1_valid_canonical_next_and_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let root_before = store.state_root();
    let head = genesis_head();
    let block = empty_block(
        CHAIN_ID,
        1,
        GENESIS_HASH,
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    // BIV-18：临时 BlockStore 提供（只读）；验证成功也**不写入**
    let tmp = TempDir::new("biv1");
    let bs = BlockStore::open(tmp.path()).unwrap();
    let computed = nova_runtime::block_hash(&block).unwrap();

    let ctx = InboundBlockContext {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
        fee_burn_bps: 0,
        max_gas_per_block: 1_000_000,
        max_block_bytes: 1024 * 1024,
        state_store: &store,
        head: &head,
        block_store: Some(&bs),
        sender_resolver: &NoAccountsKeyResolver,
        expected_proposer_vk: Some(kp.verifying_key()),
        expected_hash: None,
    };
    let verdict = validate_block_inbound(&wire, &ctx).unwrap();

    // BIV-1：wire + canonical 全验证通过 ⇒ CanonicalNextCandidate（非 finality 授权；
    // 不携带 Block——验证与消费解耦；调用方可凭 bytes/hash 重新 decode）
    match verdict {
        InboundBlockVerdict::CanonicalNextCandidate { block_hash, height } => {
            assert_eq!(block_hash, computed);
            assert_eq!(height, 1);
        }
        other => panic!("expected CanonicalNextCandidate, got {other:?}"),
    }
    // BIV-16：ChainHead 不变（验证成功也不推进；head 为只读借用，validate 不改）
    assert_eq!(ctx.head.height, 0, "head 未被推进");
    assert_eq!(ctx.head.block_hash, GENESIS_HASH);
    // BIV-17：StateStore 不变（只读执行重算）
    assert_eq!(store.state_root(), root_before, "state root unchanged");
    // BIV-18：BlockStore 未写入（validated 但非 commit；本 STEP 不写）
    assert!(!bs.contains(&computed).unwrap(), "no blockstore write");
}

// ---------------------------------------------------------------------------
// BIV-2 / BIV-3 / BIV-4 / BIV-5 / BIV-6（wire / identity 层 reject）
// ---------------------------------------------------------------------------

fn base_ctx<'a>(
    store: &'a StateStore<MemoryBackend>,
    head: &'a ChainHead,
) -> InboundBlockContext<'a, MemoryBackend> {
    InboundBlockContext {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
        fee_burn_bps: 0,
        max_gas_per_block: 1_000_000,
        max_block_bytes: 1024 * 1024,
        state_store: store,
        head,
        block_store: None,
        sender_resolver: &NoAccountsKeyResolver,
        expected_proposer_vk: None,
        expected_hash: None,
    }
}

#[test]
fn biv_2_malformed_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let ctx = base_ctx(&store, &head);
    let mut wire = canonical_wire(&kp, *store.state_root().as_bytes());
    wire.truncate(wire.len() - 5); // 截断 ⇒ decode InvalidLength
    assert_eq!(
        validate_block_inbound(&wire, &ctx),
        Err(InboundBlockError::Malformed)
    );
}

#[test]
fn biv_3_oversized_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let wire = canonical_wire(&kp, *store.state_root().as_bytes());
    let ctx = InboundBlockContext {
        max_block_bytes: 16, // 远小于 block wire
        ..base_ctx(&store, &head)
    };
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert!(matches!(err, InboundBlockError::Oversized { .. }));
}

#[test]
fn biv_4_wrong_version_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let ctx = base_ctx(&store, &head);
    let mut block = empty_block(
        CHAIN_ID,
        1,
        GENESIS_HASH,
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    block.header.version = 0x02; // 未知版本（decode 拒）
    let wire = encode_block(&block).unwrap();
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert!(matches!(err, InboundBlockError::WrongVersion { .. }));
}

#[test]
fn biv_5_wrong_chain_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let ctx = base_ctx(&store, &head);
    // 错误 chain_id 的合法块（签名按该 chain_id 自洽；chain 检查在签名之前）
    let block = empty_block(
        999,
        1,
        GENESIS_HASH,
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert!(matches!(err, InboundBlockError::WrongChain { found: 999 }));
}

#[test]
fn biv_6_hash_mismatch_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let wire = canonical_wire(&kp, *store.state_root().as_bytes());
    let ctx = InboundBlockContext {
        expected_hash: Some([0xEE; 32]), // 声称 hash ≠ 实际
        ..base_ctx(&store, &head)
    };
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert!(matches!(err, InboundBlockError::HashMismatch { .. }));
}

// ---------------------------------------------------------------------------
// BIV-7..BIV-10（canonical 层 reject：signature / tx-root / state-root / ordering）
// ---------------------------------------------------------------------------

fn canonical_ctx<'a>(
    store: &'a StateStore<MemoryBackend>,
    head: &'a ChainHead,
    proposer_vk: &'a nova_crypto::signature::VerifyingKey,
) -> InboundBlockContext<'a, MemoryBackend> {
    InboundBlockContext {
        expected_proposer_vk: Some(proposer_vk),
        ..base_ctx(store, head)
    }
}

#[test]
fn biv_7_invalid_proposer_signature_rejected() {
    let kp = KeyPair::generate().unwrap();
    let other = KeyPair::generate().unwrap(); // 非签名者
    let store = empty_store();
    let head = genesis_head();
    let wire = canonical_wire(&kp, *store.state_root().as_bytes());
    let ctx = canonical_ctx(&store, &head, other.verifying_key());
    assert_eq!(
        validate_block_inbound(&wire, &ctx),
        Err(InboundBlockError::InvalidProposerSignature)
    );
}

#[test]
fn biv_8_transaction_root_mismatch_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let mut block = empty_block(
        CHAIN_ID,
        1,
        GENESIS_HASH,
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    block.header.transaction_root = [0x55; 32]; // ≠ TX_EMPTY（空 body）
    let wire = encode_block(&block).unwrap();
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    assert_eq!(
        validate_block_inbound(&wire, &ctx),
        Err(InboundBlockError::TransactionRootMismatch)
    );
}

#[test]
fn biv_9_state_root_mismatch_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    // state_root 声明为错误值（≠ EMPTY）；header 已按错误 root 重签（签名域含 state_root）
    let block = empty_block(CHAIN_ID, 1, GENESIS_HASH, [0xAA; 32], kp.signing_key());
    let wire = empty_block_wire(&block);
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    assert_eq!(
        validate_block_inbound(&wire, &ctx),
        Err(InboundBlockError::StateRootMismatch)
    );
}

#[test]
fn biv_10_non_canonical_tx_ordering_rejected() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let s = addr([0x10; 32]);
    let r = addr([0xbb; 32]);
    // 同 sender、nonce 2 在前（descending）⇒ 违反 (addr ASC, nonce ASC)
    let body = BlockBody {
        txs: vec![raw_tx(s, r, 2), raw_tx(s, r, 1)],
    };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body), // 与 body 自洽（避免误报 tx-root）
        state_root: *store.state_root().as_bytes(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let block = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key(), CHAIN_ID),
    };
    let wire = encode_block(&block).unwrap();
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    assert_eq!(
        validate_block_inbound(&wire, &ctx),
        Err(InboundBlockError::NonCanonicalTransactionOrdering)
    );
}

// ---------------------------------------------------------------------------
// BIV-11 / BIV-12 / BIV-13 / BIV-14（head 关系分类）
// ---------------------------------------------------------------------------

#[test]
fn biv_11_stale_classified() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = head_at(3, [0x10; 32]); // local head height = 3
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    // height 2 < head 3 ⇒ Stale（即便 wire/canonical 本可验，也不 commit）
    let block = empty_block(
        CHAIN_ID,
        2,
        [0x10; 32],
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    let verdict = validate_block_inbound(&wire, &ctx).unwrap();
    assert!(matches!(
        verdict,
        InboundBlockVerdict::Stale { height: 2, .. }
    ));
}

#[test]
fn biv_12_future_classified() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = head_at(3, [0x10; 32]);
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    // height 5 > head 3 + 1 ⇒ FutureMissingAncestor（祖先缺失，不 commit）
    let block = empty_block(
        CHAIN_ID,
        5,
        [0x10; 32],
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    let verdict = validate_block_inbound(&wire, &ctx).unwrap();
    assert!(matches!(
        verdict,
        InboundBlockVerdict::FutureMissingAncestor { height: 5, .. }
    ));
}

#[test]
fn biv_13_conflicting_parent_classified() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = head_at(3, [0x10; 32]);
    let ctx = canonical_ctx(&store, &head, kp.verifying_key());
    // height == head+1 但 parent ≠ head.block_hash ⇒ ConflictingParent
    let block = empty_block(
        CHAIN_ID,
        4,
        [0x99; 32],
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    let verdict = validate_block_inbound(&wire, &ctx).unwrap();
    match verdict {
        InboundBlockVerdict::ConflictingParent {
            height,
            parent_hash,
            expected_parent,
            ..
        } => {
            assert_eq!(height, 4);
            assert_eq!(parent_hash, [0x99; 32]);
            assert_eq!(expected_parent, [0x10; 32]);
        }
        other => panic!("expected ConflictingParent, got {other:?}"),
    }
}

#[test]
fn biv_14_already_known_classified() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let block = empty_block(
        CHAIN_ID,
        1,
        GENESIS_HASH,
        *store.state_root().as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&block);
    // 先持久化（模拟本地已 known）→ 验证器应分类 AlreadyKnown（只读 contains，不重复写）
    let tmp = TempDir::new("biv14");
    let bs = BlockStore::open(tmp.path()).unwrap();
    bs.put(&block).unwrap();
    let ctx = InboundBlockContext {
        block_store: Some(&bs),
        ..base_ctx(&store, &head)
    };
    let verdict = validate_block_inbound(&wire, &ctx).unwrap();
    assert!(matches!(verdict, InboundBlockVerdict::AlreadyKnown { .. }));
}

// ---------------------------------------------------------------------------
// BIV-15：remote 输入绝不直接 reach apply_block（结构性：模块无 commit 依赖；
//         佐证：即便 CanonicalNextCandidate，也零 mutation —— 见 biv_1）。
//         此处再证 reject 路径也零 mutation（BIV-16/17/18 覆盖 reject + accept 两侧）。
// ---------------------------------------------------------------------------

#[test]
fn biv_15_16_17_18_reject_path_no_mutation() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let root_before = store.state_root();
    let head = genesis_head();
    let head_before = head.clone();
    let tmp = TempDir::new("biv15");
    let bs = BlockStore::open(tmp.path()).unwrap();
    // 错误 chain（reject 路径）
    let bad = empty_block(
        999,
        1,
        GENESIS_HASH,
        *root_before.as_bytes(),
        kp.signing_key(),
    );
    let wire = empty_block_wire(&bad);
    let ctx = InboundBlockContext {
        block_store: Some(&bs),
        ..base_ctx(&store, &head)
    };
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert!(matches!(err, InboundBlockError::WrongChain { .. }));
    // 零 mutation（BIV-16 head / BIV-17 state / BIV-18 blockstore）
    assert_eq!(ctx.head.height, 0);
    assert_eq!(ctx.head, &head_before);
    assert_eq!(store.state_root(), root_before);
    assert!(
        !bs.contains(&nova_runtime::block_hash(&bad).unwrap())
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// 诚实能力边界：含交易 + NoAccountsKeyResolver（NodeRuntime 现装配）⇒
// state_root 不可验证 ⇒ UnsupportedValidation（不跳过 / 不信任远端 root）。
// ---------------------------------------------------------------------------

#[test]
fn biv_unsupported_state_execution_with_txs() {
    let kp = KeyPair::generate().unwrap();
    let store = empty_store();
    let head = genesis_head();
    let s = addr([0x10; 32]);
    let r = addr([0xbb; 32]);
    // 单 sender tx（结构合法；ordering/tx-root/sig 可验）→ ⑦d resolve：NoAccounts ⇒ None
    let body = BlockBody {
        txs: vec![raw_tx(s, r, 0)],
    };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: *store.state_root().as_bytes(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let block = Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key(), CHAIN_ID),
    };
    let wire = encode_block(&block).unwrap();
    let ctx = canonical_ctx(&store, &head, kp.verifying_key()); // NoAccountsKeyResolver
    let err = validate_block_inbound(&wire, &ctx).unwrap_err();
    assert_eq!(
        err,
        InboundBlockError::UnsupportedValidation(UnverifiableItem::StateExecution)
    );
    // 零 mutation
    assert_eq!(ctx.head.height, 0);
    assert_eq!(store.state_root(), head.state_root);
}
