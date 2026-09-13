//! D9 A11 Proposer/Validator Integration Seam — 定向测试（STEP 1–4）。
//!
//! 覆盖：canonical-next block 经 `block_dispatch::dispatch_gossip_block_with_validator_set`
//! 注入期望 proposer 公钥后，执行真实 proposer 签名验证：
//! - T1 valid proposer：正确当选 key 签名的块 → `CanonicalNextCandidate`；apply 后 head 推进。
//! - T2 wrong proposer：另一**成员**（非当选）key 签名 → `InvalidProposerSignature`，head 不变。
//! - T3 invalid signature：当选 key 签名但篡改 `proposer_signature` → `InvalidProposerSignature`，head 不变。
//! - T4 unknown validator：**非成员** key 签名（块无 proposer 自证字段；非成员无法伪造当选者签名）
//!   → `InvalidProposerSignature`，head 不变。
//! - T8 负路径：wrong height / wrong parent 在 `with_validator_set` 下仍正确分类（不误伤、不推进）。
//! - None 诚实保留：无 ValidatorSet 的原观测入口对 canonical-next 仍 `UnsupportedValidation(ProposerSignature)`
//!   （seam 未把 None 放宽为“跳过验证”）。
//!
//! 协议冻结：本测试使用确定性测试 genesis（chain_id=1001、空 accounts、真实 Ed25519 KeyPair 作为
//! consensus_public_key）；不修改生产 genesis / 协议标识符 / golden vectors。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nova_consensus::proposer::select_proposer;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::sign_message_hash;
use nova_network::security::RequestId;
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
use nova_node::block_dispatch::{
    dispatch_gossip_block, dispatch_gossip_block_round_aware,
    dispatch_gossip_block_with_validator_set, dispatch_sync_block_response_round_aware,
    dispatch_sync_block_response_with_validator_set, resolve_proposer_round_evidence,
    resolve_proposer_round_from_evidences,
};
use nova_node::block_inbound::{InboundBlockError, InboundBlockVerdict, UnverifiableItem};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;

type FileAdapter = NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>;

// ---------------------------------------------------------------------------
// Fixtures（deterministic test chain；自建临时目录，Drop 清理）
// ---------------------------------------------------------------------------

struct TestChain {
    dir: PathBuf,
    chain_dir: PathBuf,
    blocks_dir: PathBuf,
}

impl TestChain {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d9_a11_{}_{}", std::process::id(), n));
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

/// 空 store 的空 root（= EMPTY）。
fn empty_root() -> [u8; 32] {
    *StateStore::new(MemoryBackend::new())
        .state_root()
        .as_bytes()
}

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn vin(kp: &KeyPair, stake: u128) -> ValidatorInit {
    ValidatorInit {
        account_address: addr(kp.verifying_key().to_bytes()),
        consensus_public_key: kp.verifying_key().to_bytes(),
        bonded_stake: stake,
        commission_bps: 100,
    }
}

fn genesis_with(validators: Vec<ValidatorInit>) -> GenesisV1 {
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 0,
        initial_validator_set: validators,
        initial_accounts: Vec::new(),
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: MAX_GAS,
            max_contract_code_bytes: 0,
            max_contract_storage_bytes: 0,
            epoch_length_blocks: 1_000_000,
            snapshot_interval_blocks: 10_000_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply: 1_000_000_000,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 100,
        },
    }
}

fn id_of(kp: &KeyPair) -> ValidatorId {
    ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
}

/// canonical-next 空块（genesis head 之上：height 1 / parent = genesis / root = 空 root）。
fn canonical_next_block(kp: &KeyPair) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(kp.signing_key(), &msg).to_bytes(),
    }
}

fn wire(block: &Block) -> Vec<u8> {
    encode_block(block).unwrap()
}

/// P1-A.18 Stage 2 —— 单块 `SyncBlockResponse` payload（既有 codec；固定测试 RequestId）。
fn sync_payload(block: &Block) -> Vec<u8> {
    let payload = BlockPayload::from_block(block).expect("payload");
    SyncBlockResponse {
        request_id: RequestId::from_bytes([0x5A; 16]),
        blocks: vec![payload],
    }
    .encode()
}

fn assert_head_unchanged(adapter: &FileAdapter, before: &ChainHead) {
    assert_eq!(
        adapter.head(),
        before,
        "head must not advance on rejected block"
    );
}

// ---------------------------------------------------------------------------
// T1 — valid proposer：当选 key 签名 ⇒ CanonicalNextCandidate；apply ⇒ head+1
// ---------------------------------------------------------------------------

#[test]
fn d9_t1_valid_proposer_canonical_next_and_advances() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));

    // 期望 proposer（head=0 父高轮 ⇒ select(0, round 0)）必须就是唯一验证者。
    let expected_id = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    assert_eq!(expected_id, id_of(&kp), "single validator must be selected");

    let block = canonical_next_block(&kp);
    let gossip = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();
    let root_before = adapter.store().state_root();

    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: hash,
            height: 1,
        }),
        "valid proposer must pass full canonical validation"
    );
    // dispatch 只读：head / state / blockstore 不变
    assert_eq!(adapter.head(), &head_before, "dispatch is read-only");
    assert_eq!(adapter.store().state_root(), root_before);
    assert!(
        !adapter.block_store().unwrap().contains(&hash).unwrap(),
        "dispatch does not write blockstore"
    );

    // head advancement 走既有 apply 路径
    let mut adapter = adapter;
    let new_head = adapter.apply_block(&gossip, kp.verifying_key()).unwrap();
    assert_eq!(new_head.block_hash, hash);
    assert_eq!(adapter.head().height, 1, "head advances by one");
}

// ---------------------------------------------------------------------------
// T2 — wrong proposer：另一成员（非当选）key 签名 ⇒ 拒绝，head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_t2_two_validators_non_selected_member_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_a, 100), vin(&kp_b, 100)]));
    let head_before = adapter.head().clone();

    // canonical-next（块高 = head+1）由父高轮（head.height = 0）proposer 产出，与
    // build_proposal gate（rs.height == head.height）/ vote request（height 0）语义一致。
    // canonical-next（块高 = head+1）由父高轮（head.height = 0）proposer 产出，与
    // build_proposal gate（rs.height == head.height）/ vote request（height 0）语义一致。
    let expected_id = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    // 用「非当选」成员签名：若当选 A 用 B 签，若当选 B 用 A 签。
    let signer = if expected_id == id_of(&kp_a) {
        &kp_b
    } else {
        &kp_a
    };
    assert_ne!(
        id_of(signer),
        expected_id,
        "signer must be the non-selected member"
    );

    let gossip = wire(&canonical_next_block(signer));
    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Err(InboundBlockError::InvalidProposerSignature),
        "non-selected member cannot produce a valid canonical-next block"
    );
    assert_head_unchanged(&adapter, &head_before);
}

// ---------------------------------------------------------------------------
// T3 — invalid signature：当选 key 签名但篡改 proposer_signature ⇒ 拒绝，head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_t3_corrupted_proposer_signature_rejected() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let head_before = adapter.head().clone();

    let mut block = canonical_next_block(&kp);
    block.proposer_signature[0] ^= 0xFF; // 篡改签名（block_hash 不含签名 ⇒ 结构/hash 仍一致）
    let gossip = wire(&block);

    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Err(InboundBlockError::InvalidProposerSignature),
        "bad signature under correct identity must be rejected"
    );
    assert_head_unchanged(&adapter, &head_before);
}

// ---------------------------------------------------------------------------
// P1-A.18 RC-1（Stage 1）—— **证据绑定 round-aware** 期望 proposer
// ---------------------------------------------------------------------------

/// `select_proposer(head, r) != select_proposer(head, 0)` 的首个 `r > 0`
/// （确定性且**有界**扫描；不引入无限遍历）。
fn first_round_with_different_proposer(set: &ValidatorSet, head_height: u64) -> u64 {
    let p0 = select_proposer(CHAIN_ID, head_height, 0, &GENESIS_HASH, set).unwrap();
    for r in 1..=16u64 {
        if select_proposer(CHAIN_ID, head_height, r, &GENESIS_HASH, set).unwrap() != p0 {
            return r;
        }
    }
    panic!("no round <= 16 differs from round 0 (unexpected for a 3-validator set)");
}

/// `select_proposer(head, r) != exclude` 的首个 `r > 0`（用于「错误轮证据」负例）。
fn first_round_with_proposer_other_than(
    set: &ValidatorSet,
    head_height: u64,
    exclude: ValidatorId,
) -> u64 {
    for r in 1..=16u64 {
        if select_proposer(CHAIN_ID, head_height, r, &GENESIS_HASH, set).unwrap() != exclude {
            return r;
        }
    }
    panic!("no round <= 16 selects a proposer other than the excluded id");
}

/// 按 `ValidatorId` 找 fixture key（找不到 ⇒ 测试失败，不静默 fallback）。
fn key_for<'a>(target: ValidatorId, kps: &[&'a KeyPair]) -> &'a KeyPair {
    kps.iter()
        .copied()
        .find(|kp| id_of(kp) == target)
        .expect("proposer must be one of the fixture members")
}

/// **证据解析契约（纯函数）**：只有**绑定**（hash 严格相等）的证据生效；冲突 ⇒ `Err`。
#[test]
fn p1a18_evidence_resolver_contract() {
    let h = [0x11u8; 32];
    let other = [0x22u8; 32];
    assert_eq!(resolve_proposer_round_evidence(h, None, None), Ok(0));
    assert_eq!(
        resolve_proposer_round_evidence(h, Some((3, h)), None),
        Ok(3)
    );
    assert_eq!(
        resolve_proposer_round_evidence(h, None, Some((4, h))),
        Ok(4)
    );
    assert_eq!(
        resolve_proposer_round_evidence(h, Some((3, h)), Some((3, h))),
        Ok(3),
        "same round from both sources is not a conflict"
    );
    assert_eq!(
        resolve_proposer_round_evidence(h, Some((3, h)), Some((4, h))),
        Err(()),
        "conflicting bound rounds must be rejected (no silent pick)"
    );
    assert_eq!(
        resolve_proposer_round_evidence(h, Some((3, other)), Some((4, h))),
        Ok(4),
        "evidence bound to another hash is unusable"
    );
    assert_eq!(
        resolve_proposer_round_evidence(h, Some((3, other)), None),
        Ok(0),
        "hash mismatch => fall back to round 0"
    );
}

/// **T1（回归）**：无证据 ⇒ round-aware 入口与既有 round-0 入口**逐字等价**。
#[test]
fn p1a18_t1_no_evidence_is_identical_to_round0_entry() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let block = canonical_next_block(&kp);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let expected = Ok(InboundBlockVerdict::CanonicalNextCandidate {
        block_hash: hash,
        height: 1,
    });
    assert_eq!(
        dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &w, &set),
        expected
    );
    assert_eq!(
        dispatch_gossip_block_round_aware(&adapter, MAX_BLOCK_BYTES, &w, &set, None, None, None),
        expected
    );
}

/// **T2（RC-1 回归）**：`round r > 0` 的当选 proposer 产块 —— 无绑定证据 ⇒ 拒（修复前行为）；
/// 有**绑定** proposal 证据 ⇒ **接受**，并可用该 proposer key 走既有 apply 路径推进 head。
#[test]
fn p1a18_t2_round_gt0_proposer_accepted_with_bound_evidence() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_c = KeyPair::generate().unwrap();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![
        vin(&kp_a, 100),
        vin(&kp_b, 100),
        vin(&kp_c, 100),
    ]));

    let r = first_round_with_different_proposer(&set, 0);
    let p_0 = select_proposer(CHAIN_ID, 0, 0, &GENESIS_HASH, &set).unwrap();
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    assert_ne!(p_r, p_0, "round {} proposer must differ from round 0", r);
    let signer = key_for(p_r, &kps);

    let block = canonical_next_block(signer);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();

    assert_eq!(
        dispatch_gossip_block_round_aware(&adapter, MAX_BLOCK_BYTES, &w, &set, None, None, None),
        Err(InboundBlockError::InvalidProposerSignature),
        "without bound evidence a round-{} block is rejected (pre-fix behavior)",
        r
    );
    assert_eq!(
        dispatch_gossip_block_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &w,
            &set,
            None,
            Some((r, hash)),
            None
        ),
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: hash,
            height: 1,
        }),
        "bound round-{} proposer must be accepted",
        r
    );
    assert_eq!(adapter.head(), &head_before, "dispatch is read-only");

    let mut adapter = adapter;
    let new_head = adapter.apply_block(&w, signer.verifying_key()).unwrap();
    assert_eq!(new_head.block_hash, hash);
    assert_eq!(adapter.head().height, 1, "head advances by one");
}

/// **T5（负例）**：证据轮次的当选 proposer **不是**签名者 ⇒ 拒绝
/// （不得因为「签名者 ∈ ValidatorSet」而接受）。
#[test]
fn p1a18_t5_wrong_round_evidence_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_c = KeyPair::generate().unwrap();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![
        vin(&kp_a, 100),
        vin(&kp_b, 100),
        vin(&kp_c, 100),
    ]));

    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let r_wrong = first_round_with_proposer_other_than(&set, 0, p_r);
    assert_ne!(
        r_wrong, r,
        "the wrong-round evidence must differ from the real round"
    );

    let block = canonical_next_block(signer);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();

    assert_eq!(
        resolve_proposer_round_evidence(hash, Some((r_wrong, hash)), None),
        Ok(r_wrong),
        "the evidence itself is bound (but names the wrong round)"
    );
    assert_eq!(
        dispatch_gossip_block_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &w,
            &set,
            None,
            Some((r_wrong, hash)),
            None
        ),
        Err(InboundBlockError::InvalidProposerSignature),
        "evidence round {} selects a proposer other than the signer => reject",
        r_wrong
    );
    assert_head_unchanged(&adapter, &head_before);
}

/// **T6（负例）**：QC 证据绑定到**另一个 block hash** ⇒ 其轮**不得**被采用
/// （防止 `Block H + QC for X ⇒ derive proposer for X ⇒ accept H`）。
#[test]
fn p1a18_t6_qc_target_mismatch_never_supplies_round() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_c = KeyPair::generate().unwrap();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![
        vin(&kp_a, 100),
        vin(&kp_b, 100),
        vin(&kp_c, 100),
    ]));

    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let block = canonical_next_block(signer);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let other_hash = [0xEEu8; 32];
    assert_ne!(other_hash, hash);

    assert_eq!(
        dispatch_gossip_block_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &w,
            &set,
            None,
            None,
            Some((r, other_hash))
        ),
        Err(InboundBlockError::InvalidProposerSignature),
        "QC bound to another target must not supply its round"
    );
    assert_eq!(
        dispatch_gossip_block_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &w,
            &set,
            None,
            Some((r, hash)),
            Some((r, other_hash))
        ),
        Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: hash,
            height: 1,
        }),
        "the hash-bound proposal evidence is what enables acceptance"
    );
}

/// **T6b（负例）**：两个来源都绑定该块 hash 但轮不同 ⇒ 拒绝（不静默择一）。
#[test]
fn p1a18_t6b_conflicting_bound_evidence_rejected() {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_c = KeyPair::generate().unwrap();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![
        vin(&kp_a, 100),
        vin(&kp_b, 100),
        vin(&kp_c, 100),
    ]));

    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let r2 = if r == 1 { 2 } else { 1 };
    assert_ne!(r2, r);

    let block = canonical_next_block(signer);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();

    assert_eq!(
        dispatch_gossip_block_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &w,
            &set,
            None,
            Some((r, hash)),
            Some((r2, hash))
        ),
        Err(InboundBlockError::InvalidProposerSignature),
        "conflicting bound rounds ({} vs {}) must be rejected",
        r,
        r2
    );
}

// ---------------------------------------------------------------------------
// P1-A.18 RC-1（Stage 2）—— sync / catch-up：**QC 证据绑定** round-aware proposer
// ---------------------------------------------------------------------------

/// `select_proposer(head, r) != select_proposer(head, 0)` 且 `r >= 2` 的首个轮（证明非 round-1 特判）。
fn first_round_ge2_with_different_proposer(set: &ValidatorSet, head_height: u64) -> u64 {
    let p0 = select_proposer(CHAIN_ID, head_height, 0, &GENESIS_HASH, set).unwrap();
    for r in 2..=32u64 {
        if select_proposer(CHAIN_ID, head_height, r, &GENESIS_HASH, set).unwrap() != p0 {
            return r;
        }
    }
    panic!("no round in 2..=32 differs from round 0 (unexpected for a 3-validator set)");
}

/// 三验证者 fixture（a/b/c 各 100 权重）＋ adapter/set。
fn three_validator_fixture() -> (
    KeyPair,
    KeyPair,
    KeyPair,
    TestChain,
    FileAdapter,
    ValidatorSet,
) {
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let kp_c = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![
        vin(&kp_a, 100),
        vin(&kp_b, 100),
        vin(&kp_c, 100),
    ]));
    (kp_a, kp_b, kp_c, chain, adapter, set)
}

/// **切片解析契约（纯函数）**：仅绑定条目生效；冲突 ⇒ `Err`。
#[test]
fn p1a18_sync_evidence_slice_contract() {
    let h = [0x33u8; 32];
    let other = [0x44u8; 32];
    assert_eq!(resolve_proposer_round_from_evidences(h, &[]), Ok(None));
    assert_eq!(
        resolve_proposer_round_from_evidences(h, &[(2, other)]),
        Ok(None),
        "hash mismatch => no bound evidence"
    );
    assert_eq!(
        resolve_proposer_round_from_evidences(h, &[(2, h)]),
        Ok(Some(2))
    );
    assert_eq!(
        resolve_proposer_round_from_evidences(h, &[(2, h), (2, h)]),
        Ok(Some(2)),
        "repeated identical bound round is not a conflict"
    );
    assert_eq!(
        resolve_proposer_round_from_evidences(h, &[(2, h), (3, h)]),
        Err(()),
        "two distinct bound rounds => reject"
    );
    assert_eq!(
        resolve_proposer_round_from_evidences(h, &[(2, other), (5, h), (5, other)]),
        Ok(Some(5)),
        "only bound entries count"
    );
}

/// **T1**：round-0 sync 回归 —— 无证据时 round-aware 入口与既有入口**逐字等价**。
#[test]
fn p1a18_t1_sync_round0_no_evidence_is_identical() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let block = canonical_next_block(&kp);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let expected = vec![Ok(InboundBlockVerdict::CanonicalNextCandidate {
        block_hash: hash,
        height: 1,
    })];
    assert_eq!(
        dispatch_sync_block_response_with_validator_set(&adapter, MAX_BLOCK_BYTES, &payload, &set),
        expected
    );
    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[]
        ),
        expected
    );
}

/// **T2**：round > 0 历史块 + **绑定 QC 证据** ⇒ sync 路径接受（无证据 ⇒ 拒绝为对照）。
#[test]
fn p1a18_t2_sync_round_gt0_accepted_with_bound_qc_evidence() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let block = canonical_next_block(signer);
    let payload = sync_payload(&block);
    let w = wire(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[]
        ),
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "without bound evidence a round-{} sync block is rejected",
        r
    );
    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r, hash)]
        ),
        vec![Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: hash,
            height: 1,
        })],
        "bound round-{} QC evidence must make the sync block acceptable",
        r
    );
    assert_eq!(adapter.head(), &head_before, "dispatch is read-only");

    let mut adapter = adapter;
    let new_head = adapter.apply_block(&w, signer.verifying_key()).unwrap();
    assert_eq!(new_head.block_hash, hash);
    assert_eq!(adapter.head().height, 1, "head advances by one");
}

/// **T3**：round ≥ 2 同样成立（非 round-1 特判）。
#[test]
fn p1a18_t3_sync_round_ge2_accepted_with_bound_qc_evidence() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_ge2_with_different_proposer(&set, 0);
    assert!(r >= 2);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let block = canonical_next_block(signer);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r, hash)]
        ),
        vec![Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: hash,
            height: 1,
        })],
        "round {} (>= 2) must work via the same bound-evidence rule",
        r
    );
}

/// **T4**：证据轮正确但**签名者错误** ⇒ 拒绝，head 不变。
#[test]
fn p1a18_t4_sync_wrong_proposer_rejected() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    // 非当选成员（但仍在集合内）签名。
    let wrong = kps
        .iter()
        .copied()
        .find(|kp| id_of(kp) != p_r)
        .expect("a non-selected member exists");
    let block = canonical_next_block(wrong);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r, hash)]
        ),
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "correct evidence round + wrong signer must be rejected"
    );
    assert_head_unchanged(&adapter, &head_before);
}

/// **T5**：块由 `P_r` 签名但证据给 `r'`（`P_r' != P_r`）⇒ 拒绝。
#[test]
fn p1a18_t5_sync_wrong_round_evidence_rejected() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let r_wrong = first_round_with_proposer_other_than(&set, 0, p_r);
    assert_ne!(r_wrong, r);
    let block = canonical_next_block(signer);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let head_before = adapter.head().clone();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r_wrong, hash)]
        ),
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "evidence round {} selects a different proposer than the signer => reject",
        r_wrong
    );
    assert_head_unchanged(&adapter, &head_before);
}

/// **T6**：QC target 与块 hash 不匹配 ⇒ 该 QC 的 round **绝不使用** ⇒ 拒绝。
///
/// 关键强度：证据轮**恰好等于**签名者的轮（`P_r` 签名、证据 round = r），但 QC 绑定到**另一个
/// block hash** ⇒ 若实现（错误地）无视绑定使用该 round，本用例会**通过验签**；必须拒绝。
#[test]
fn p1a18_t6_sync_qc_target_mismatch_never_supplies_round() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let block = canonical_next_block(signer);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();
    let other_hash = [0xEEu8; 32];
    assert_ne!(other_hash, hash);
    let head_before = adapter.head().clone();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r, other_hash)]
        ),
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "QC bound to another target must not supply its round"
    );
    assert_head_unchanged(&adapter, &head_before);
}

/// **T7**：同一块 hash 的两个不同绑定轮 ⇒ 拒绝（不静默择一）。
#[test]
fn p1a18_t7_sync_conflicting_evidence_rejected() {
    let (kp_a, kp_b, kp_c, _chain, adapter, set) = three_validator_fixture();
    let kps: [&KeyPair; 3] = [&kp_a, &kp_b, &kp_c];
    let r = first_round_with_different_proposer(&set, 0);
    let p_r = select_proposer(CHAIN_ID, 0, r, &GENESIS_HASH, &set).unwrap();
    let signer = key_for(p_r, &kps);
    let r2 = if r == 1 { 2 } else { 1 };
    assert_ne!(r2, r);
    let block = canonical_next_block(signer);
    let payload = sync_payload(&block);
    let hash = nova_runtime::block_hash(&block).unwrap();

    assert_eq!(
        dispatch_sync_block_response_round_aware(
            &adapter,
            MAX_BLOCK_BYTES,
            &payload,
            &set,
            None,
            &[(r, hash), (r2, hash)]
        ),
        vec![Err(InboundBlockError::InvalidProposerSignature)],
        "conflicting bound rounds ({} vs {}) for the same block must be rejected",
        r,
        r2
    );
}

// ---------------------------------------------------------------------------
// T4 — unknown validator：非成员 key 签名 ⇒ 拒绝，head 不变
// ---------------------------------------------------------------------------

#[test]
fn d9_t4_non_member_proposer_rejected() {
    let kp_member = KeyPair::generate().unwrap();
    let kp_outsider = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp_member, 100)]));
    let head_before = adapter.head().clone();
    assert!(
        !set.contains(&id_of(&kp_outsider)),
        "outsider must not be a member"
    );

    // 非成员签名块：validator 按本地集合选出当选者(member) vk 验签 ⇒ 失败。
    let gossip = wire(&canonical_next_block(&kp_outsider));
    let result = dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &gossip, &set);
    assert_eq!(
        result,
        Err(InboundBlockError::InvalidProposerSignature),
        "non-member cannot forge the selected proposer signature"
    );
    assert_head_unchanged(&adapter, &head_before);
}

// ---------------------------------------------------------------------------
// T8 — negative classification paths（with_validator_set 不误伤分类层、不推进）
// ---------------------------------------------------------------------------

#[test]
fn d9_t8_wrong_height_and_wrong_parent_classified_with_set() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let set = ValidatorSet::from_genesis(&genesis_with(vec![vin(&kp, 100)]));
    let head_before = adapter.head().clone();

    // wrong height：height 2（> head+1）⇒ FutureMissingAncestor（分类在 proposer 前）
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 2,
        parent_hash: GENESIS_HASH,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root: empty_root(),
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let block = Block {
        header,
        body,
        proposer_signature: sign_message_hash(kp.signing_key(), &hash_signing_message(&signed))
            .to_bytes(),
    };
    let result =
        dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &wire(&block), &set);
    assert!(
        matches!(
            result,
            Ok(InboundBlockVerdict::FutureMissingAncestor { height: 2, .. })
        ),
        "height > head+1 must classify as future, got {result:?}"
    );
    assert_head_unchanged(&adapter, &head_before);

    // wrong parent：height 1 但 parent ≠ genesis ⇒ ConflictingParent（分类在 proposer 前）
    let mut b = canonical_next_block(&kp);
    b.header.parent_hash = [0x99; 32];
    let result =
        dispatch_gossip_block_with_validator_set(&adapter, MAX_BLOCK_BYTES, &wire(&b), &set);
    assert!(
        matches!(
            result,
            Ok(InboundBlockVerdict::ConflictingParent { height: 1, .. })
        ),
        "wrong parent must classify as conflicting, got {result:?}"
    );
    assert_head_unchanged(&adapter, &head_before);
}

// ---------------------------------------------------------------------------
// None 诚实保留：无 ValidatorSet 的观测入口仍 UnsupportedValidation(ProposerSignature)
// ---------------------------------------------------------------------------

#[test]
fn d9_none_observation_entry_stays_honest() {
    let kp = KeyPair::generate().unwrap();
    let chain = TestChain::new();
    let adapter = create_adapter(&chain);
    let gossip = wire(&canonical_next_block(&kp));

    let result = dispatch_gossip_block(&adapter, MAX_BLOCK_BYTES, &gossip);
    assert_eq!(
        result,
        Err(InboundBlockError::UnsupportedValidation(
            UnverifiableItem::ProposerSignature
        )),
        "seam must NOT turn None into skip-verification"
    );
}
