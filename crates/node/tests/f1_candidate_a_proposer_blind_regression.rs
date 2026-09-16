//! YAZIMAO L1 — F-1 **Candidate A 确定性回归测试**（测试专用新增；**生产逻辑零修改**）。
//!
//! # 目的
//! 用确定性最小测试证明：`BlockStore` 的 **proposer-blind 读取**（`get_content`）**确实能够**产生
//! F-1 观测到的致命错误：
//! ```text
//! BlockCommit: block application pipeline: block validation: block validation: invalid proposer signature
//! ```
//!
//! # 被测机制（全部为**现有生产代码**；本测试不修改任何生产逻辑）
//! ```text
//! QC.context.round = R                        crates/consensus/src/finality.rs:30
//!   ↓ runtime.rs:866-874                      select_proposer(chain_id, block.height-1, R, genesis_hash, set)
//! expected proposer P
//!   ↓ runtime.rs:876-886                      ValidatorSet.info(P) → VerifyingKey
//!   ↓ runtime.rs:833                          BlockStore::get_content(X)        ← **proposer-blind**
//! retrieved encoding（= 最小 proposer 字节序 或 legacy）  storage/src/block_store.rs:322-336
//!   ↓ runtime.rs:889                          encode_block(retrieved)           ← wire 承载**该 encoding** 的签名
//!   ↓ runtime.rs:895                          NodeBlockAdapter::apply_block_with_proposer(wire, vk_P, P)
//!   ↓ node/src/block_adapter.rs:256           validate_block_signature(block, vk_P, chain_id)
//!   ↓ runtime/src/block.rs:~330               BlockPipelineError::Validation(BlockValidationFailure::Block(..))
//!   ↓ core/src/block.rs:415                   verify_message_hash(vk_P, msg, sig_Q) ⇒ Err
//! → BlockValidationError::InvalidProposerSignature（**致命** → RuntimeError::BlockCommit）
//! ```
//!
//! # Level B 声明（必须）
//! `finality_commit_bridge()` 是 `crates/node/src/runtime.rs` 的**私有自由函数**，集成测试无法直接调用。
//! 本测试以**同一批公开 API、同一调用顺序**复现其 Gate 3b → Gate 5 片段
//! （`BlockStore::get_content` → `encode_block` → `NodeBlockAdapter::apply_block_with_proposer`）：
//! ```text
//! Candidate A mechanism reproduced deterministically,
//! but finality_commit_bridge itself was not invoked.
//! ```
//!
//! # 确定性（不依赖随机巧合）
//! - `block_hash(P) == block_hash(Q) == X`：`proposer_signature ∉ block_hash`（ADR-0042；`core/src/block.rs:319-326`）；
//! - **Q := 小 `ValidatorId`，P := 大 `ValidatorId`**（`ValidatorId = SHA-256(consensus_public_key)`，
//!   `validator.rs:19-20`），而 `get_content` 选择规则 = **最小 proposer 字节序**
//!   （`block_store.rs:332-335`）⇒ `get_content(X)` **必** 返回 Q 的 encoding（`id_q < id_p` 由断言固定）；
//! - P 由**真实 `select_proposer`** 在某个 `R` 上导出（与桥 Gate 3 同源），并断言该 `R` 存在。
//!
//! # rig 重复说明
//! 本文件自带的 `TestChain` / 空块构造与 `crates/node/tests/block_commit_tests.rs` 的等价 rig **最小重复**：
//! Rust 集成测试是各自独立的 crate，**无法** import 另一测试文件的 helper；为保证**零修改既有测试文件**，
//! 此处仅复制本测试所需的最小片段（约 70 行），**未**引入新的生产/测试语义。

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
use nova_crypto::signature::{SigningKey, VerifyingKey, sign_message_hash};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block,
    encode_block_header,
};
use nova_storage::block_store::{BlockStore, PutOutcome};
use nova_storage::persistent::PersistentBackend;
use nova_storage::store::StateStore;

use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;

/// 生产观测到的 F-1 stderr 尾巴（`Error: Run("BlockCommit: <此串>")`）。
const F1_OBSERVED_INNER: &str =
    "block application pipeline: block validation: block validation: invalid proposer signature";

type FileAdapter = NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>;

// ---------------------------------------------------------------------------
// 最小 rig（自建；Drop 清理）
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
        let dir = std::env::temp_dir().join(format!("nova_f1_candA_{}_{}", std::process::id(), n));
        Self {
            dir: dir.clone(),
            chain_dir: dir.join("chain"),
            blocks_dir: dir.join("blocks"),
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

/// 空 block 的 proposer 块签名（`DomainId::Block` + `chain_id` + canonical header）。
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

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// ValidatorSet（2 成员，等权）—— 仅供 `select_proposer` 导出 P
// ---------------------------------------------------------------------------

fn validator_init(consensus_public_key: [u8; 32], account_key_hash: [u8; 32]) -> ValidatorInit {
    ValidatorInit {
        account_address: YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: account_key_hash,
        }),
        consensus_public_key,
        bonded_stake: 1,
        commission_bps: 100,
    }
}

fn genesis_two_validators(pk_a: [u8; 32], pk_b: [u8; 32]) -> GenesisV1 {
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 0,
        initial_validator_set: vec![
            validator_init(pk_a, [0xA1; 32]),
            validator_init(pk_b, [0xB2; 32]),
        ],
        initial_accounts: Vec::new(),
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: 100_000_000_000,
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

// ---------------------------------------------------------------------------
// F-1 Candidate A 回归测试
// ---------------------------------------------------------------------------

#[test]
fn f1_candidate_a_proposer_blind_encoding_yields_invalid_proposer_signature() {
    // ---- 0. rig ----
    let chain = TestChain::new();
    let mut adapter = create_adapter(&chain);
    let kp_a = KeyPair::generate().unwrap();
    let kp_b = KeyPair::generate().unwrap();
    let vk_a = kp_a.verifying_key();
    let vk_b = kp_b.verifying_key();

    // ---- 1. 同一 canonical 内容的两个 encoding（签名不同 ⇒ hash 相同） ----
    //   `block_a` 由 `kp_a` 签；`block_b` = 同 header/body、改由 `kp_b` 签。
    let (block_a, _wa) = next_empty_block(&adapter, &kp_a);
    let mut block_b = block_a.clone();
    block_b.proposer_signature = block_signature(&block_a.header, kp_b.signing_key());
    let x = nova_runtime::block_hash(&block_a).unwrap();
    assert_eq!(
        nova_runtime::block_hash(&block_b).unwrap(),
        x,
        "Q1前提：proposer_signature ∉ block_hash（ADR-0042）⇒ P/Q 同 X"
    );
    assert_ne!(
        block_a.proposer_signature, block_b.proposer_signature,
        "Q1前提：两份 encoding 签名必不同"
    );
    let height = block_a.header.height;

    // ---- 2. ValidatorSet（2 成员等权）；Q := 小 id，P := 大 id（观测字节序，非巧合） ----
    let set = ValidatorSet::from_genesis(&genesis_two_validators(vk_a.to_bytes(), vk_b.to_bytes()));
    assert_eq!(set.len(), 2, "rig：2 validators");
    let id_a = ValidatorId::from_consensus_public_key(&vk_a.to_bytes());
    let id_b = ValidatorId::from_consensus_public_key(&vk_b.to_bytes());
    assert_ne!(id_a, id_b, "rig：两个 id 必不同");

    let q_is_a = id_a.as_bytes() < id_b.as_bytes();
    let (q_id, p_id, vk_q, vk_p, blk_q, blk_p) = if q_is_a {
        (&id_a, &id_b, vk_a, vk_b, &block_a, &block_b)
    } else {
        (&id_b, &id_a, vk_b, vk_a, &block_b, &block_a)
    };
    let (id_q_bytes, id_p_bytes) = (q_id.as_bytes(), p_id.as_bytes());
    assert!(
        id_q_bytes < id_p_bytes,
        "PHASE 3：Q 必须是**最小** proposer 字节序（get_content 的选择规则）"
    );
    let (sig_q, sig_p) = (blk_q.proposer_signature, blk_p.proposer_signature);
    assert_ne!(sig_q, sig_p);

    // ---- 3. P 的来源 = **QC round R**（与 runtime.rs:866-874 同源） ----
    //   等权 2 成员下 `select_proposer` 由 x=seed%2 决定 ⇒ 必存在 R 使结果为**大 id**（= P）。
    let r = (0u64..=64)
        .find(|r| &select_proposer(CHAIN_ID, height - 1, *r, &GENESIS_HASH, &set).unwrap() == p_id)
        .expect("PHASE 3：必存在 QC round R 使 select_proposer(...) == P（大 id）");
    // Gate 4 等价：P 的 vk 来自 ValidatorSet.info（不是来自 storage / 文件名）。
    let vk_p_from_set = VerifyingKey::from_bytes(
        &set.info(p_id)
            .expect("PHASE 3：P ∈ ValidatorSet")
            .consensus_public_key,
    )
    .unwrap();
    assert_eq!(
        vk_p_from_set.to_bytes(),
        vk_p.to_bytes(),
        "Gate 4：P 的 key 来自 ValidatorSet"
    );

    // ---- 4. storage：两份 encoding 共存；`get_content` 忽略 expected proposer ----
    let bs = BlockStore::open(&chain.blocks_dir).unwrap();
    assert!(matches!(
        bs.put_verified(blk_p, id_p_bytes, &vk_p_from_set, CHAIN_ID, set.len())
            .unwrap(),
        PutOutcome::Inserted
    ));
    assert!(matches!(
        bs.put_verified(blk_q, id_q_bytes, vk_q, CHAIN_ID, set.len())
            .unwrap(),
        PutOutcome::Inserted
    ));
    let labels = bs.list_proposers(&x).unwrap();
    assert_eq!(
        labels.len(),
        2,
        "Q1：同一 block_hash 下 P/Q 两份 encoding 共存"
    );
    assert!(labels.contains(id_p_bytes) && labels.contains(id_q_bytes));

    let retrieved = bs.get_content(&x).unwrap().expect("Q2：内容型读可得");
    assert_eq!(
        retrieved.proposer_signature, sig_q,
        "Q2：get_content **proposer-blind** ⇒ 返回最小 id（Q）的 encoding"
    );
    assert_ne!(
        retrieved.proposer_signature, sig_p,
        "Q2：返回的 encoding 不是 expected proposer P 所签"
    );

    // ---- 5. 签名身份矩阵（Block 无 signer 字段 ⇒ 只能「给定 key ⇒ 验签」） ----
    let ok_qq = nova_runtime::validate_block_signature(blk_q, vk_q, CHAIN_ID);
    let ok_pp = nova_runtime::validate_block_signature(blk_p, &vk_p_from_set, CHAIN_ID);
    let err_qp =
        nova_runtime::validate_block_signature(blk_q, &vk_p_from_set, CHAIN_ID).unwrap_err();
    let err_pq = nova_runtime::validate_block_signature(blk_p, vk_q, CHAIN_ID).unwrap_err();
    assert!(ok_qq.is_ok() && ok_pp.is_ok(), "Q+vk_Q / P+vk_P ⇒ PASS");
    assert!(
        format!("{err_qp}").contains("invalid proposer signature"),
        "Q+vk_P ⇒ InvalidProposerSignature（实际 {err_qp}）"
    );
    assert!(
        format!("{err_pq}").contains("invalid proposer signature"),
        "P+vk_Q ⇒ InvalidProposerSignature（实际 {err_pq}）"
    );

    // ---- 6. Bridge Gate 5 等价调用（同一公开 API / 同一顺序） ----
    let wire_q = encode_block(&retrieved).unwrap();
    let head_before = adapter.head().clone();
    let err = adapter
        .apply_block_with_proposer(&wire_q, &vk_p_from_set, id_p_bytes, set.len())
        .unwrap_err();
    let msg = format!("{err}");
    assert_eq!(
        msg, F1_OBSERVED_INNER,
        "Q3：与生产 F-1 stderr 尾巴**逐字一致**的致命错误"
    );
    assert_eq!(
        adapter.head(),
        &head_before,
        "fail-closed：不 commit / head 不推进 / state 不变"
    );

    // ---- 7. Q4：proposer-aware 读取（现有 API）可得 P 的 encoding 并成功 commit ----
    let p_encoding = bs
        .get_for_proposer_verified(&x, id_p_bytes, &vk_p_from_set, CHAIN_ID)
        .unwrap()
        .expect("Q4：get_for_proposer_verified(X, P, vk_P) ⇒ P 的 encoding");
    assert_eq!(p_encoding.proposer_signature, sig_p);
    let wire_p = encode_block(&p_encoding).unwrap();
    let head = adapter
        .apply_block_with_proposer(&wire_p, &vk_p_from_set, id_p_bytes, set.len())
        .unwrap();
    assert_eq!(
        head.height, height,
        "Q4：同一 X 用 P 的 encoding ⇒ commit 成功"
    );
    assert_eq!(head.block_hash, x);

    // ---- 证据输出（`--nocapture`） ----
    println!("F1-CANDIDATE-A Q1 two_proposer_encodings_coexist = PASS (labels=2)");
    println!(
        "F1-CANDIDATE-A ORDER id_q={} id_p={} q_lt_p={}",
        hex(id_q_bytes),
        hex(id_p_bytes),
        id_q_bytes < id_p_bytes
    );
    println!(
        "F1-CANDIDATE-A QC_ROUND R={} P=select_proposer(chain_id,height-1,R,genesis,set)={}",
        r,
        hex(p_id.as_bytes())
    );
    println!("F1-CANDIDATE-A Q2 get_content_is_proposer_blind = PASS (returned Q encoding)");
    println!("F1-CANDIDATE-A Q3 invalid_proposer_signature = PASS err=\"{msg}\"");
    println!("F1-CANDIDATE-A Q4 get_for_proposer_verified(P) + commit = PASS head={head:?}");
    println!(
        "F1-CANDIDATE-A BRIDGE_DIRECTLY_INVOKED = NO (private fn; equivalent public call sequence)"
    );
}
