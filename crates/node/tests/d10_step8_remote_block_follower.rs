//! D10-C Step 8 — 远端 canonical block ⇒ DAG + BlockStore（follower finality/commit 路径）。
//!
//! 证明：远端经传输到达、且已由本地 `block_dispatch`（本地 `ValidatorSet` 推导期望 proposer +
//! 真实验签）判定为 `CanonicalNextCandidate` 的 canonical block，会被 node orchestration
//! **durable 落盘（BlockStore）并登记进共识 DAG**（真实 height / parent）—— 从而使 follower 具备
//! 「可被 frozen `verify_qc`（target ∈ DAG）与 commit bridge（`BlockStore.get`）消费」的前提。
//!
//! 诚实边界（本文件断言）：
//! - 登记 / 落盘本身 **不** commit、**不** 推进 head、**不** 产生 finality；
//! - finality 仍需真实 quorum（本节点 auto-drive 本地票 + 远端真实签名 vote）；
//! - commit 仍只由 `finality_commit_bridge`（frozen finality 唯一授权）执行；commit 后 Step 7-B
//!   使 consensus 进入下一高度轮。
//! - Gossip 与 SyncBlockResponse **统一处理**（两者先经同一 validator seam）。
//!
//! 全部断言基于真实 production 路径（真实 genesis / 真实签名 / 真实 storage / 真实 frozen
//! transition）；无 mock head / 无手设 round / 无人工注入最终状态。

use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_network::message::{MessageEnvelope, MessageType, decode, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_encode, random_session_nonce,
};
use nova_network::sync::{BlockPayload, SyncBlockRequest, SyncBlockResponse};
use nova_network::transport::{ConnectionTarget, MemoryTransport, TcpTransport, Transport};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, compute_transaction_root, encode_block_header,
};
use nova_storage::block_store::BlockStore;

use nova_node::block_adapter::NoAccountsKeyResolver;
use nova_node::block_inbound::InboundBlockVerdict;
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::{NodeRuntime, PeerStatus};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

// ---------------------------------------------------------------------------
// Fixtures（双验证者；A = height 0 当选者，B = 本测试的 follower runtime）
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn genesis_with(validators: Vec<([u8; 32], u128)>) -> GenesisV1 {
    let n = validators.len();
    let accounts: Vec<AccountInit> = (0..n)
        .map(|i| AccountInit {
            address: addr([0x11 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut vs: Vec<ValidatorInit> = validators
        .iter()
        .zip(accounts.iter())
        .map(|((pk, stake), acct)| ValidatorInit {
            account_address: acct.address,
            consensus_public_key: *pk,
            bonded_stake: *stake,
            commission_bps: 0,
        })
        .collect();
    vs.sort_by_key(|v| ValidatorId::from_consensus_public_key(&v.consensus_public_key));
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vs,
        initial_accounts: accounts,
        protocol_parameters: ProtocolParamsV1 {
            max_tx_bytes: 64 * 1024,
            max_block_bytes: 8 * 1024 * 1024,
            max_gas_per_block: 1_000_000,
            max_contract_code_bytes: 1024,
            max_contract_storage_bytes: 1024,
            epoch_length_blocks: 1_000,
            snapshot_interval_blocks: 10_000,
        },
        economics_parameters: EconomicsParamsV1 {
            total_supply,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_d10c8_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        Self {
            _dir: dir,
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self) -> NodeConfig {
        self.config_with_peers(Vec::new())
    }

    fn config_with_peers(&self, peers: Vec<ConnectionTarget>) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr: None,
        }
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// 循环生成双验证者 keys 直至 `select_proposer(0,0) == A`（概率 1/2；bounded）。
fn pair_until_proposer_a() -> (KeyPair, KeyPair, GenesisV1, [u8; 32]) {
    for _ in 0..64 {
        let kp_a = KeyPair::generate().unwrap();
        let kp_b = KeyPair::generate().unwrap();
        let genesis = genesis_with(vec![
            (kp_a.verifying_key().to_bytes(), STAKE),
            (kp_b.verifying_key().to_bytes(), STAKE),
        ]);
        let hash = compute_genesis_hash(&genesis).unwrap();
        let set = ValidatorSet::from_genesis(&genesis);
        let id_a = ValidatorId::from_consensus_public_key(&kp_a.verifying_key().to_bytes());
        if select_proposer(CHAIN_ID, 0, 0, &hash, &set).unwrap() == id_a {
            return (kp_a, kp_b, genesis, hash);
        }
    }
    panic!("bounded 重试内未找到 A 当选的 keys");
}

/// A 侧（对端）真实签名 envelope（与 d10_step2/3 同款 harness）。
fn sign_peer_envelope(
    net_key: &KeyPair,
    message_type: MessageType,
    payload: Vec<u8>,
) -> MessageEnvelope {
    let sender = node_id_of(net_key);
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender,
        signature: [0u8; 64],
    };
    sign_message(net_key.signing_key(), &mut envelope).expect("sign envelope");
    envelope
}

fn peer_handshake(net_key: &KeyPair, genesis_hash: [u8; 32]) -> MessageEnvelope {
    let id = node_id_of(net_key);
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        &id,
        &SessionNonce::from_bytes([1; 16]),
        b"",
    )
    .expect("handshake encode");
    sign_peer_envelope(net_key, MessageType::Handshake, payload)
}

/// 远端 canonical block（height / parent 显式；真实 proposer 签名 —— 与本节点成员集合可校验）。
fn remote_block(
    sk: &SigningKey,
    genesis_hash: [u8; 32],
    state_root: [u8; 32],
    height: u64,
    parent_hash: [u8; 32],
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
        validator_set_hash: genesis_hash,
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

/// 真实签名 consensus vote（DomainId::ValidatorVote；与 verify_vote 同构）。
fn signed_vote(
    kp: &KeyPair,
    target: [u8; 32],
    height: u64,
    round: u64,
    vote_type: VoteType,
) -> (ValidatorVote, [u8; 64]) {
    let validator_id = ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes());
    let vote = ValidatorVote {
        height,
        round,
        target_block_hash: target,
        vote_type,
        source_block_hash: [0u8; 32],
        validator_id,
        timestamp: 0,
    };
    let payload = canonical_vote_payload(&vote);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        CHAIN_ID,
        &payload,
    )
    .unwrap();
    let sig = sign_message_hash(kp.signing_key(), &hash_signing_message(&signed)).to_bytes();
    (vote, sig)
}

/// vote wire = canonical_vote_payload(121B) ‖ signature(64B)。
fn vote_wire(vote: &ValidatorVote, signature: [u8; 64]) -> Vec<u8> {
    let mut out = canonical_vote_payload(vote);
    out.extend_from_slice(&signature);
    out
}

fn head_height(runtime: &NodeRuntime) -> u64 {
    runtime.block_production().unwrap().head().height
}

fn head_hash(runtime: &NodeRuntime) -> [u8; 32] {
    runtime.block_production().unwrap().head().block_hash
}

fn store_has(config: &NodeConfig, hash: &[u8; 32]) -> bool {
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    bs.contains(hash).unwrap_or(false)
}

/// 启动 follower runtime B，并完成 A 侧握手（真实 handshake envelope ⇒ Established）。
fn start_follower_with_peer(
    config: &NodeConfig,
    kp_b: KeyPair,
    net_a: &KeyPair,
    genesis_hash: [u8; 32],
) -> (NodeRuntime, MemoryTransport, NodeId, NodeId) {
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(net_a);
    let b_id = node_id_of(&net_b);
    let (tx_b, mut tx_a) = MemoryTransport::pair(b_id, a_id);
    let mut runtime = NodeRuntime::start_with_network(
        config,
        Some(&SoftwareKeyProvider::from_keypair(kp_b)),
        Box::new(tx_b),
        Box::new(SoftwareNetworkIdentity::new(net_b)),
    )
    .expect("follower validator + network 启动");
    let hs = peer_handshake(net_a, genesis_hash);
    tx_a.send(&b_id, encode(&hs)).expect("inject handshake");
    runtime.step().expect("step handshake ok");
    assert!(
        runtime.network_peer_established(a_id),
        "A 侧握手完成（Established；sync/egress 前置）"
    );
    (runtime, tx_a, a_id, b_id)
}

// ---------------------------------------------------------------------------
// T8-1 — 远端 canonical-next block：登记进 DAG + durable 落盘，但**不** commit
// ---------------------------------------------------------------------------

#[test]
fn d10_c8_t1_remote_canonical_block_registered_and_stored_without_commit() {
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_proposer_a();
    let env = Env::new(&genesis);
    let config = env.config();
    let net_a = KeyPair::generate().unwrap();
    let (mut runtime, mut tx_a, _a_id, b_id) =
        start_follower_with_peer(&config, kp_b, &net_a, genesis_hash);

    // 远端 A 的 canonical-next block（真实 A 签名；state_root = 本地 genesis root ⇒ 可通过 ⑦d）。
    let state_root = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    let block = remote_block(
        kp_a.signing_key(),
        genesis_hash,
        state_root,
        1,
        genesis_hash,
    );
    let a_hash = nova_runtime::block_hash(&block).unwrap();
    let wire = nova_runtime::encode_block(&block).unwrap();
    assert!(!store_has(&config, &a_hash), "起点：BlockStore 无该块");

    let gossip = sign_peer_envelope(&net_a, MessageType::GossipBlock, wire);
    tx_a.send(&b_id, encode(&gossip))
        .expect("inject remote block");
    runtime.step().expect("step remote block ok");

    // 验证 seam 裁决（真实 proposer 验签 + state root）：CanonicalNextCandidate。
    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes.iter().any(|o| matches!(
            o,
            Ok(InboundBlockVerdict::CanonicalNextCandidate { block_hash, height })
                if *block_hash == a_hash && *height == 1
        )),
        "远端块经 D9 seam 判定 canonical-next：{outcomes:?}"
    );
    // DAG 登记（真实 height / parent）：genesis → A。
    let dag = runtime.consensus().dag();
    assert!(dag.contains(&genesis_hash), "genesis 根存在");
    assert!(dag.contains(&a_hash), "远端块已登记进 DAG");
    assert_eq!(
        dag.parents_of(&a_hash),
        Some(&[genesis_hash][..]),
        "A.parent == genesis（真实 ancestry）"
    );
    // durable 落盘（commit bridge Gate 3 的前提）。
    assert!(store_has(&config, &a_hash), "远端块已 durable 落盘");
    // 不 commit / 不推进 head / 无 finality。
    assert_eq!(head_height(&runtime), 0, "inbound 不得 commit");
    assert_eq!(head_hash(&runtime), genesis_hash, "head 仍为 genesis");
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "登记 ≠ finality"
    );
    assert_eq!(runtime.consensus().state().round.proposal, None);
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T8-2 — finality 仍需真实 quorum（仅块 + proposal + 单条远端 prevote ⇒ 无 finality）
// ---------------------------------------------------------------------------

#[test]
fn d10_c8_t2_no_finality_without_real_quorum() {
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_proposer_a();
    let env = Env::new(&genesis);
    let config = env.config();
    let set = ValidatorSet::from_genesis(&genesis);
    assert!(STAKE < set.quorum(), "单票不足 quorum（需双方参与）");
    let net_a = KeyPair::generate().unwrap();
    let (mut runtime, mut tx_a, a_id, b_id) =
        start_follower_with_peer(&config, kp_b, &net_a, genesis_hash);

    let state_root = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    let block = remote_block(
        kp_a.signing_key(),
        genesis_hash,
        state_root,
        1,
        genesis_hash,
    );
    let a_hash = nova_runtime::block_hash(&block).unwrap();
    let wire = nova_runtime::encode_block(&block).unwrap();
    let id_a = ValidatorId::from_consensus_public_key(&kp_a.verifying_key().to_bytes());

    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(&net_a, MessageType::GossipBlock, wire)),
    )
    .unwrap();
    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(
            &net_a,
            MessageType::ConsensusProposal,
            encode_proposal_ref(&ProposalRef {
                block_hash: a_hash,
                proposer: id_a,
            }),
        )),
    )
    .unwrap();
    let (v, sig) = signed_vote(&kp_a, a_hash, 0, 0, VoteType::Prevote);
    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(
            &net_a,
            MessageType::ConsensusVote,
            vote_wire(&v, sig),
        )),
    )
    .unwrap();

    for _ in 0..6 {
        runtime.step().expect("step ok");
    }
    // prevote quorum 可达（A + B = 2×STAKE），但 precommit quorum 缺 A 的 precommit ⇒ 无 finality。
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "无 precommit quorum ⇒ 无 finality（不伪造）"
    );
    assert_eq!(head_height(&runtime), 0, "无 finality ⇒ 无 commit");
    assert!(runtime.consensus().dag().contains(&a_hash), "块已登记");
    assert!(
        runtime.consensus().state().round.proposal.is_some(),
        "proposal 已进入共识（真实 transition）"
    );
    let _ = a_id;
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T8-3 — follower 达 finality 并 commit 远端块（+ Step 7-B 高度推进）
// ---------------------------------------------------------------------------

#[test]
fn d10_c8_t3_follower_finalizes_and_commits_remote_block() {
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_proposer_a();
    let env = Env::new(&genesis);
    let config = env.config();
    let net_a = KeyPair::generate().unwrap();
    let (mut runtime, mut tx_a, _a_id, b_id) =
        start_follower_with_peer(&config, kp_b, &net_a, genesis_hash);

    let state_root = *runtime
        .block_production()
        .unwrap()
        .store()
        .state_root()
        .as_bytes();
    let block = remote_block(
        kp_a.signing_key(),
        genesis_hash,
        state_root,
        1,
        genesis_hash,
    );
    let a_hash = nova_runtime::block_hash(&block).unwrap();
    let wire = nova_runtime::encode_block(&block).unwrap();
    let id_a = ValidatorId::from_consensus_public_key(&kp_a.verifying_key().to_bytes());

    // 块（登记 + 落盘）→ proposal → A 的 prevote → A 的 precommit（全部 A 真实签名）。
    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(&net_a, MessageType::GossipBlock, wire)),
    )
    .unwrap();
    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(
            &net_a,
            MessageType::ConsensusProposal,
            encode_proposal_ref(&ProposalRef {
                block_hash: a_hash,
                proposer: id_a,
            }),
        )),
    )
    .unwrap();
    for vt in [VoteType::Prevote, VoteType::Precommit] {
        let (v, sig) = signed_vote(&kp_a, a_hash, 0, 0, vt);
        tx_a.send(
            &b_id,
            encode(&sign_peer_envelope(
                &net_a,
                MessageType::ConsensusVote,
                vote_wire(&v, sig),
            )),
        )
        .unwrap();
    }

    // follower 真实推进：proposal → prevote(A+B) → Precommit → precommit(A+B) → finality → commit。
    for _ in 0..40 {
        runtime
            .step()
            .expect("step ok（无错误：无 DagRegister / DoubleVote / LockConflict）");
        if head_height(&runtime) >= 1 {
            break;
        }
    }
    assert_eq!(head_height(&runtime), 1, "follower 已 commit 远端块");
    assert_eq!(head_hash(&runtime), a_hash, "head == 远端 finalized 块");
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        Some(a_hash),
        "finality 由 frozen transition 产生（真实 QC + quorum）"
    );
    // durable commit（apply_block ⑥：height/parent 由 head 派生校验）。
    let bs = BlockStore::open(&config.storage_dir.join("blocks")).unwrap();
    let committed = bs.get(&a_hash).unwrap().expect("committed block durable");
    assert_eq!(committed.header.height, 1);
    assert_eq!(committed.header.parent_hash, genesis_hash);
    // Step 7-B：commit 后 consensus 进入下一高度轮（follower 同样适用）。
    let round = &runtime.consensus().state().round;
    assert_eq!(round.height, 1, "consensus 高度已跟进 durable head");
    assert_eq!(round.round, 0);
    assert_eq!(round.step, RoundStep::Propose);
    assert!(round.proposal.is_none(), "新高度轮无 stale proposal");
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T8-4 — future block（height > head + 1）⇒ FutureMissingAncestor：不登记 / 不落盘 / 不变 head
// ---------------------------------------------------------------------------

#[test]
fn d10_c8_t4_future_block_not_registered_not_stored() {
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_proposer_a();
    let env = Env::new(&genesis);
    let config = env.config();
    let net_a = KeyPair::generate().unwrap();
    let (mut runtime, mut tx_a, _a_id, b_id) =
        start_follower_with_peer(&config, kp_b, &net_a, genesis_hash);

    // height 3 / parent 未知（head=genesis，height > head+1）⇒ FutureMissingAncestor（高度守卫在
    // 签名 / state root 之前裁决）。
    let future = remote_block(kp_a.signing_key(), genesis_hash, [0u8; 32], 3, [0xAB; 32]);
    let future_hash = nova_runtime::block_hash(&future).unwrap();
    let wire = nova_runtime::encode_block(&future).unwrap();
    tx_a.send(
        &b_id,
        encode(&sign_peer_envelope(&net_a, MessageType::GossipBlock, wire)),
    )
    .unwrap();
    runtime.step().expect("step future block ok");

    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Ok(InboundBlockVerdict::FutureMissingAncestor { .. }))),
        "future block ⇒ FutureMissingAncestor：{outcomes:?}"
    );
    assert!(
        !runtime.consensus().dag().contains(&future_hash),
        "未登记（不建立断链 reference）"
    );
    assert!(!store_has(&config, &future_hash), "未落盘");
    assert_eq!(head_height(&runtime), 0, "head 不变");
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
    runtime.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// T8-5 — 统一处理：SyncBlockResponse 来源的 canonical-next block 同样登记 + 落盘（且不 commit）
//
// 真实 TCP 对端（与 d8_3_1 同款程序化 peer）：runtime 为 validator A（dial 对端 ⇒
// `connected` ⇒ sync 请求可真实发出）；对端先发 future block 触发同步，再用 canonical-next
// block 回应同一 request_id ⇒ 走 sync 分支的同一 validator seam。
// ---------------------------------------------------------------------------

const PEER_MAX_ITER: usize = 4000;

/// 对端侧 peer-auth 配置（与 runtime 装配值一致：Mainnet / CHAIN_ID / genesis / protocol 1）。
fn peer_auth(genesis_hash: [u8; 32]) -> PeerAuthConfig {
    PeerAuthConfig {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_hash,
        protocol_version: 1,
        capabilities: b"",
        per_peer_handshake_limit: 8,
        global_handshake_limit: 128,
        replay_cache_capacity: 256,
    }
}

fn envelope(
    signer: &dyn NetworkSigner,
    message_type: MessageType,
    payload: Vec<u8>,
) -> MessageEnvelope {
    MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: signer.node_id(),
        signature: [0u8; 64],
    }
}

fn init_envelope(signer: &dyn NetworkSigner, auth: &PeerAuthConfig) -> MessageEnvelope {
    let nonce = random_session_nonce().unwrap();
    let local = signer.node_id();
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        auth.network_id,
        auth.chain_id,
        auth.genesis_hash,
        auth.protocol_version,
        &local,
        &nonce,
        auth.capabilities,
    )
    .unwrap();
    let mut env = envelope(signer, MessageType::Handshake, payload);
    signer.sign_envelope(&mut env).unwrap();
    env
}

/// 程序化 TCP 对端（非生产；测试 fixture）：
/// 读 A 的 Init → 回 B Init → 发 future block（Gossip）→ 对每个 SyncBlockRequest 回带
/// canonical-next block 的 SyncBlockResponse（同一 request_id）。
fn run_peer_reply(
    listener: TcpListener,
    peer_kp: KeyPair,
    auth: PeerAuthConfig,
    future_wire: Vec<u8>,
    canonical_wire: Vec<u8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let peer_id = NodeId::from_verifying_key(peer_kp.verifying_key());
        let signer = SoftwareNetworkIdentity::new(peer_kp);
        let mut tcp = match TcpTransport::accept(
            &listener,
            peer_id,
            1024 * 1024,
            Some(Duration::from_secs(10)),
        ) {
            Ok(t) => t,
            Err(_) => return,
        };
        let a_id = tcp.peer_id();
        // ① 读 A 的 Init（A dial 后立即发出）。
        let mut got_init = false;
        for _ in 0..PEER_MAX_ITER {
            if let Ok(Some(_)) = tcp.try_recv() {
                got_init = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if !got_init {
            return;
        }
        let _ = tcp.send(&a_id, encode(&init_envelope(&signer, &auth)));
        // ② 按 TCP 顺序发 future block（A 先处理 Init ⇒ 已认证，再处理该块）。
        let mut gossip = envelope(&signer, MessageType::GossipBlock, future_wire);
        signer.sign_envelope(&mut gossip).unwrap();
        let _ = tcp.send(&a_id, encode(&gossip));
        // ③ 回带 canonical-next block 的 SyncBlockResponse。
        for _ in 0..PEER_MAX_ITER {
            if tcp.is_closed() {
                return;
            }
            let received = match tcp.try_recv() {
                Ok(Some((_, bytes))) => decode(&bytes).ok(),
                _ => None,
            };
            if let Some(env) = received
                && env.message_type == MessageType::SyncBlockRequest
                && let Ok(request) = SyncBlockRequest::decode(&env.payload)
            {
                let response = SyncBlockResponse {
                    request_id: request.request_id,
                    blocks: vec![BlockPayload(canonical_wire.clone())],
                };
                let mut out = envelope(&signer, MessageType::SyncBlockResponse, response.encode());
                signer.sign_envelope(&mut out).unwrap();
                let _ = tcp.send(&a_id, encode(&out));
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

#[test]
fn d10_c8_t5_sync_response_canonical_block_registered_not_committed() {
    // 双验证者集合（A = height 0 当选者；D = 第二验证者但从不参与）⇒ 本流程无可达 quorum，
    // 从而可隔离断言「sync 来源 canonical block 被登记 + 落盘，但 sync 本身不 commit」。
    let (kp_a, _kp_d, genesis, genesis_hash) = pair_until_proposer_a();
    let env = Env::new(&genesis);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let peer_kp = KeyPair::generate().unwrap();
    let peer_id = node_id_of(&peer_kp);
    let config = env.config_with_peers(vec![ConnectionTarget {
        peer_id,
        address: laddr,
    }]);

    // state_root 取自 genesis bootstrap（首启 head = genesis ⇒ 与 runtime 一致；adapter 随作用域释放）。
    let state_root = {
        let adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, &config).unwrap();
        *adapter.store().state_root().as_bytes()
    };
    // future block（触发同步；高度守卫在签名/state root 之前）与 canonical-next block（timestamp 区分
    // 于 runtime 本地 proposal，避免同 hash ⇒ AlreadyKnown）。
    let future = remote_block(kp_a.signing_key(), genesis_hash, state_root, 3, [0xAB; 32]);
    let future_wire = nova_runtime::encode_block(&future).unwrap();
    let canonical = {
        let mut b = remote_block(
            kp_a.signing_key(),
            genesis_hash,
            state_root,
            1,
            genesis_hash,
        );
        b.header.timestamp = 7;
        let payload = encode_block_header(&b.header);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
        b.proposer_signature =
            sign_message_hash(kp_a.signing_key(), &hash_signing_message(&signed)).to_bytes();
        b
    };
    let canonical_hash = nova_runtime::block_hash(&canonical).unwrap();
    let canonical_wire = nova_runtime::encode_block(&canonical).unwrap();

    let net_a = KeyPair::generate().unwrap();
    let a_net_id = node_id_of(&net_a);
    let (tx_a, _dummy_peer) = MemoryTransport::pair(a_net_id, NodeId::from_bytes([0x99; 32]));
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp_a)),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("validator A + network 启动");
    assert!(runtime.network_peer_auth_enabled(), "peer-auth 已装配");

    let handle = run_peer_reply(
        listener,
        peer_kp,
        peer_auth(genesis_hash),
        future_wire,
        canonical_wire,
    );

    // 建立 configured peer（真实 TCP dial ⇒ `connected` ⇒ sync 请求可发出）。
    let mut established = false;
    for _ in 0..PEER_MAX_ITER {
        let res = runtime.establish_configured_peers().expect("establish ok");
        if matches!(res[0].status, PeerStatus::Established) {
            established = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(established, "A Established B（真实 TCP 握手）");
    assert!(runtime.network_peer_established(peer_id));

    // 推进直到 sync 来源的 canonical block 被登记（限 bounded 迭代）。
    let mut registered = false;
    for _ in 0..PEER_MAX_ITER {
        runtime.step().expect("step ok");
        if runtime.consensus().dag().contains(&canonical_hash) {
            registered = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    // 统一处理：Sync 来源同样登记 + 落盘（与 Gossip 一致）。
    assert!(
        registered,
        "Sync 来源 canonical block 已登记进 DAG（统一处理）"
    );
    assert_eq!(
        runtime.consensus().dag().parents_of(&canonical_hash),
        Some(&[genesis_hash][..]),
        "真实 ancestry（parent = genesis）"
    );
    assert!(
        store_has(&config, &canonical_hash),
        "Sync 来源 canonical block 已 durable 落盘"
    );
    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes.iter().any(|o| matches!(
            o,
            Ok(InboundBlockVerdict::CanonicalNextCandidate { block_hash, height })
                if *block_hash == canonical_hash && *height == 1
        )),
        "sync 分支经同一 validator seam 判定 canonical-next：{outcomes:?}"
    );
    assert!(
        runtime.sync_resolved_responses() >= 1,
        "request lifecycle 已 resolve（真实 correlation）"
    );
    // 仍不 commit：sync / inbound 本身不是 finality 授权。
    assert_eq!(head_height(&runtime), 0, "sync 块本身不得 commit");
    assert_eq!(head_hash(&runtime), genesis_hash, "head 仍为 genesis");
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "sync 块本身不产生 finality"
    );
    drop(runtime);
    let _ = handle.join();
}
