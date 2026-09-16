//! YAZIMAO L1 — F-1 **Candidate A 修复后回归测试**（post-fix regression evidence）。
//!
//! # 与 pre-fix 测试的关系（不要混淆）
//! - `crates/node/tests/f1_candidate_a_proposer_blind_regression.rs` = **pre-fix 缺陷证据**
//!   （proposer-blind `get_content` ⇒ 取到 Q ⇒ `InvalidProposerSignature`）。**本轮未修改它**。
//! - 本文件 = **post-fix 证据**：生产修复后，Finality Bridge 的等价公开调用序改为
//!   `QC round R → P → vk_P → BlockStore::get_for_proposer_verified(X, P, vk_P, chain_id)`。
//!
//! # 被测生产改动（crates/node/src/runtime.rs `finality_commit_bridge` Gate 3b）
//! ```text
//! old: bs.get_content(&x)                                   ← proposer-blind（可能取到 Q）
//!      → encode_block → apply_block_with_proposer(wire, vk_P, P) → InvalidProposerSignature（fatal）
//! new: R (hash-bound QC evidence) → P = select_proposer(chain_id, height-1, R, genesis, set)
//!      → vk_P = ValidatorSet.info(P) → bs.get_for_proposer_verified(&x, P, vk_P, chain_id)
//!      → Some(P encoding)  ⇒ encode_block → apply_block_with_proposer(...) ⇒ commit
//!      → Ok(None)          ⇒ defer（既有语义；不猜 / 不回退他人 encoding / 不 fatal）
//!      → Err(CorruptedState) ⇒ fail-closed（fatal；不吞错）
//! ```
//!
//! # Level B 声明
//! `finality_commit_bridge()` 是 `runtime.rs` 的**私有自由函数**，集成测试无法调用（且本轮禁止为测试放宽
//! visibility）⇒ 本文件以**同一批公开 API、同一顺序**复现其修复后 Gate 3b → Gate 5 片段：
//! ```text
//! Candidate A FIX reproduced via the same public call sequence;
//! finality_commit_bridge itself was not invoked.
//! ```
//!
//! # 确定性
//! Q/P 由 `ValidatorId`（= `SHA-256(consensus_public_key)`）的**观测字节序**赋值（Test A: Q<P；Test B: P<Q），
//! 并以断言固定 ⇒ 不依赖随机巧合；P 由真实 `select_proposer` 在找到的 `R` 上导出。

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
use nova_storage::error::StorageError;
use nova_storage::persistent::PersistentBackend;
use nova_storage::store::StateStore;

use nova_node::block_adapter::{ChainHead, NoAccountsKeyResolver, NodeBlockAdapter};

const CHAIN_ID: u64 = 1001;
const GENESIS_HASH: [u8; 32] = [0x42; 32];
const MAX_GAS: u64 = 1_000_000;

type FileAdapter = NodeBlockAdapter<PersistentBackend, NoAccountsKeyResolver>;

// ---------------------------------------------------------------------------
// 最小 rig（与 pre-fix 测试同款；集成测试为独立 crate ⇒ 无法互相 import helper）
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
        let dir = std::env::temp_dir().join(format!("nova_f1_fixA_{}_{}", std::process::id(), n));
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

fn block_signature(header: &BlockHeader, sk: &SigningKey) -> [u8; 64] {
    let payload = encode_block_header(header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    sign_message_hash(sk, &msg).to_bytes()
}

fn next_empty_block(adapter: &FileAdapter, kp: &KeyPair) -> Block {
    let head = adapter.head();
    let state_root = *adapter.store().state_root().as_bytes();
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: head.height + 1,
        parent_hash: head.block_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: [0u8; 32],
        timestamp: 0,
    };
    Block {
        header: header.clone(),
        body,
        proposer_signature: block_signature(&header, kp.signing_key()),
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

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

/// rig：同一 canonical 内容的两个 encoding（A 由 `kp_a` 签、B 由 `kp_b` 签）+ 2 成员 ValidatorSet。
struct Rig {
    chain: TestChain,
    adapter: FileAdapter,
    id_a: [u8; 32],
    id_b: [u8; 32],
    block_a: Block,
    block_b: Block,
    x: [u8; 32],
    set: ValidatorSet,
}

impl Rig {
    fn new() -> Self {
        let chain = TestChain::new();
        let adapter = create_adapter(&chain);
        let kp_a = KeyPair::generate().unwrap();
        let kp_b = KeyPair::generate().unwrap();
        let block_a = next_empty_block(&adapter, &kp_a);
        let mut block_b = block_a.clone();
        block_b.proposer_signature = block_signature(&block_a.header, kp_b.signing_key());
        let x = nova_runtime::block_hash(&block_a).unwrap();
        assert_eq!(
            nova_runtime::block_hash(&block_b).unwrap(),
            x,
            "rig：proposer_signature ∉ block_hash ⇒ P/Q 同 X"
        );
        let pk_a = kp_a.verifying_key().to_bytes();
        let pk_b = kp_b.verifying_key().to_bytes();
        let set = ValidatorSet::from_genesis(&genesis_two_validators(pk_a, pk_b));
        let id_a = *ValidatorId::from_consensus_public_key(&pk_a).as_bytes();
        let id_b = *ValidatorId::from_consensus_public_key(&pk_b).as_bytes();
        assert_ne!(id_a, id_b, "rig：两个 ValidatorId 必不同");
        Self {
            chain,
            adapter,
            id_a,
            id_b,
            block_a,
            block_b,
            x,
            set,
        }
    }

    fn store(&self) -> BlockStore {
        BlockStore::open(&self.chain.blocks_dir).unwrap()
    }

    /// 找到使 `select_proposer(chain_id, height-1, R, genesis, set) == want` 的 QC round R（= 桥的 Gate 3）。
    fn round_for(&self, want: &[u8; 32], height: u64) -> u64 {
        (0u64..=64)
            .find(|r| {
                select_proposer(CHAIN_ID, height - 1, *r, &GENESIS_HASH, &self.set)
                    .unwrap()
                    .as_bytes()
                    == want
            })
            .expect("必存在 QC round R 使 select_proposer(...) == P")
    }

    fn vk_of(&self, id: &[u8; 32]) -> VerifyingKey {
        let vid = ValidatorId::from_bytes(*id);
        VerifyingKey::from_bytes(&self.set.info(&vid).expect("P ∈ set").consensus_public_key)
            .unwrap()
    }

    fn block_of(&self, id: &[u8; 32]) -> &Block {
        if *id == self.id_a {
            &self.block_a
        } else {
            &self.block_b
        }
    }

    /// 编码文件路径（storage 文档化布局：`<blocks>/<hash64>/p_<proposer64>.blk`）。
    fn encoding_path(&self, id: &[u8; 32]) -> PathBuf {
        self.chain
            .blocks_dir
            .join(hex(&self.x))
            .join(format!("p_{}.blk", hex(id)))
    }

    /// 写入两份 encoding（P + Q），全部经生产同款 `put_verified`。
    fn put_both(&self, p_id: &[u8; 32], q_id: &[u8; 32]) {
        let bs = self.store();
        assert!(matches!(
            bs.put_verified(
                self.block_of(p_id),
                p_id,
                &self.vk_of(p_id),
                CHAIN_ID,
                self.set.len()
            )
            .unwrap(),
            PutOutcome::Inserted
        ));
        assert!(matches!(
            bs.put_verified(
                self.block_of(q_id),
                q_id,
                &self.vk_of(q_id),
                CHAIN_ID,
                self.set.len()
            )
            .unwrap(),
            PutOutcome::Inserted
        ));
        assert_eq!(bs.list_proposers(&self.x).unwrap().len(), 2);
    }
}

// ---------------------------------------------------------------------------
// Test A — Q < P（pre-fix 会取到 Q）：修复后必须取到 **P** 并 commit 成功
// ---------------------------------------------------------------------------

#[test]
fn f1_fix_test_a_p_encoding_selected_when_q_is_smaller() {
    let mut rig = Rig::new();
    let q_is_a = rig.id_a < rig.id_b; // 小 id = Q（get_content 的选择）
    let (q_id, p_id) = if q_is_a {
        (rig.id_a, rig.id_b)
    } else {
        (rig.id_b, rig.id_a)
    };
    assert!(
        q_id < p_id,
        "Test A：必须 Q < P（proposer-blind get_content 会取到 Q）"
    );
    let height = rig.block_a.header.height;
    let r = rig.round_for(&p_id, height);
    rig.put_both(&p_id, &q_id);
    let bs = rig.store();

    // ① 记录**修复前**的缺陷形态（不调用修复路径）：proposer-blind 读 → Q
    let blind = bs.get_content(&rig.x).unwrap().unwrap();
    assert_eq!(
        blind.proposer_signature,
        rig.block_of(&q_id).proposer_signature,
        "Test A：get_content（proposer-blind）确实取到 Q 的 encoding"
    );
    assert_ne!(
        blind.proposer_signature,
        rig.block_of(&p_id).proposer_signature
    );

    // ② 修复后的等价生产调用序：R → P → vk_P → get_for_proposer_verified → apply
    let vk_p = rig.vk_of(&p_id);
    let p_encoding = bs
        .get_for_proposer_verified(&rig.x, &p_id, &vk_p, CHAIN_ID)
        .unwrap()
        .expect("Test A：P encoding 必须可取（修复后按 proposer 定向检索）");
    assert_eq!(
        p_encoding.proposer_signature,
        rig.block_of(&p_id).proposer_signature,
        "Test A：检索到的是 **P** 的 encoding（不是 Q）"
    );
    let n_encodings = rig.set.len();
    let head = rig
        .adapter
        .apply_block_with_proposer(
            &encode_block(&p_encoding).unwrap(),
            &vk_p,
            &p_id,
            n_encodings,
        )
        .unwrap();
    assert_eq!(
        head.height, height,
        "Test A：commit 成功 ⇒ head 推进到 X.height"
    );
    assert_eq!(head.block_hash, rig.x, "Test A：head.hash == X");

    println!(
        "F1-FIX-A PASS q_id={} p_id={} q_lt_p=true R={} retrieved=P committed=true head_height={}",
        hex(&q_id),
        hex(&p_id),
        r,
        head.height
    );
}

// ---------------------------------------------------------------------------
// Test B — P < Q（反序）：修复不得依赖 proposer 字节序
// ---------------------------------------------------------------------------

#[test]
fn f1_fix_test_b_encoding_selection_is_order_independent() {
    let mut rig = Rig::new();
    let a_is_smaller = rig.id_a < rig.id_b;
    // Test B：P = 小 id，Q = 大 id（与 Test A 相反的顺序）
    let (p_id, q_id) = if a_is_smaller {
        (rig.id_a, rig.id_b)
    } else {
        (rig.id_b, rig.id_a)
    };
    assert!(p_id < q_id, "Test B：必须 P < Q（反序）");
    let height = rig.block_a.header.height;
    let r = rig.round_for(&p_id, height);
    rig.put_both(&p_id, &q_id);
    let bs = rig.store();

    let vk_p = rig.vk_of(&p_id);
    let p_encoding = bs
        .get_for_proposer_verified(&rig.x, &p_id, &vk_p, CHAIN_ID)
        .unwrap()
        .expect("Test B：P encoding 可取（与字节序无关）");
    assert_eq!(
        p_encoding.proposer_signature,
        rig.block_of(&p_id).proposer_signature
    );
    let n_encodings = rig.set.len();
    let head = rig
        .adapter
        .apply_block_with_proposer(
            &encode_block(&p_encoding).unwrap(),
            &vk_p,
            &p_id,
            n_encodings,
        )
        .unwrap();
    assert_eq!(head.height, height);
    assert_eq!(head.block_hash, rig.x);

    println!(
        "F1-FIX-B PASS p_id={} q_id={} p_lt_q=true R={} retrieved=P committed=true head_height={}",
        hex(&p_id),
        hex(&q_id),
        r,
        head.height
    );
}

// ---------------------------------------------------------------------------
// Test C — P encoding 缺失（仅 Q 存在）：必须 Ok(None) ⇒ 既有 defer 语义（不 fatal / 不回退 Q）
// ---------------------------------------------------------------------------

#[test]
fn f1_fix_test_c_missing_p_encoding_defers() {
    let rig = Rig::new();
    let q_is_a = rig.id_a < rig.id_b;
    let (q_id, p_id) = if q_is_a {
        (rig.id_a, rig.id_b)
    } else {
        (rig.id_b, rig.id_a)
    };
    let height = rig.block_a.header.height;
    let _r = rig.round_for(&p_id, height);

    // 仅写 Q 的 encoding（P 缺失）
    let bs = rig.store();
    assert!(matches!(
        bs.put_verified(
            rig.block_of(&q_id),
            &q_id,
            &rig.vk_of(&q_id),
            CHAIN_ID,
            rig.set.len()
        )
        .unwrap(),
        PutOutcome::Inserted
    ));
    assert_eq!(bs.list_proposers(&rig.x).unwrap(), vec![q_id], "仅 Q 存在");

    let vk_p = rig.vk_of(&p_id);
    let got = bs.get_for_proposer_verified(&rig.x, &p_id, &vk_p, CHAIN_ID);
    assert_eq!(
        got,
        Ok(None),
        "Test C：P encoding 缺失 ⇒ Ok(None)（⇒ bridge 既有 defer 路径，不 fatal）"
    );
    // defer 语义：无 commit、head 不动、**不回退** Q 的 encoding
    assert_eq!(
        rig.adapter.head().height,
        0,
        "Test C：无 commit（head 保持 genesis）"
    );
    assert_eq!(
        bs.list_proposers(&rig.x).unwrap(),
        vec![q_id],
        "Test C：不得因 P 缺失而回退/改写为 Q 的 encoding"
    );

    println!(
        "F1-FIX-C PASS p_id={} p_missing=true get_for_proposer_verified=Ok(None) defer=true fallback_Q=false",
        hex(&p_id)
    );
}

// ---------------------------------------------------------------------------
// Test D — P encoding 存在但损坏：必须 Err(CorruptedState) ⇒ fail-closed（不 defer / 不回退 Q）
// ---------------------------------------------------------------------------

#[test]
fn f1_fix_test_d_corrupted_p_encoding_is_fail_closed() {
    let rig = Rig::new();
    let q_is_a = rig.id_a < rig.id_b;
    let (q_id, p_id) = if q_is_a {
        (rig.id_a, rig.id_b)
    } else {
        (rig.id_b, rig.id_a)
    };
    rig.put_both(&p_id, &q_id);
    let vk_p = rig.vk_of(&p_id);
    let bs = rig.store();

    // D-① 记录层损坏（magic/version/len/checksum）
    let p_path = rig.encoding_path(&p_id);
    std::fs::write(&p_path, b"corrupt").unwrap();
    let got = bs.get_for_proposer_verified(&rig.x, &p_id, &vk_p, CHAIN_ID);
    assert_eq!(
        got,
        Err(StorageError::CorruptedState),
        "Test D①：P encoding 记录损坏 ⇒ CorruptedState（fail-closed，不 defer）"
    );

    // D-② 文件名 proposer 与实际签名者不符（把 Q 的记录写到 P 的路径下）
    std::fs::copy(rig.encoding_path(&q_id), &p_path).unwrap();
    let got2 = bs.get_for_proposer_verified(&rig.x, &p_id, &vk_p, CHAIN_ID);
    assert_eq!(
        got2,
        Err(StorageError::CorruptedState),
        "Test D②：P 路径下的签名不是 P 的 ⇒ CorruptedState（不静默回退 Q、不 defer）"
    );
    assert_eq!(rig.adapter.head().height, 0, "Test D：无 commit / 状态不变");

    println!(
        "F1-FIX-D PASS p_id={} corrupted_record=CorruptedState spoofed_encoding=CorruptedState defer=false fallback_Q=false",
        hex(&p_id)
    );
}
