//! D10-A Step 3 — Runtime Integration（把已验证 `auto_drive` 接入生产 Runtime 主循环）。
//!
//! 证明：validator-mode `NodeRuntime`（网络主循环）在本节点接受一个真实 canonical proposal
//! （本地 proposer 产块）后，**经 runtime `step()` 自动执行本地 vote progression**
//! （`drive_local_consensus` → `driver.auto_drive()`）→ 既有 transition → Prevote/Precommit →
//! 生产 QC / Finality；且：无效 / 错误 proposer 的远端 block 经 D9 validator-set-aware seam 拒
//! （不自动 drive）；重复 tick 幂等安全；双验证者下 runtime 只产生**本地** vote、不伪造远程。
//!
//! 禁用：手动 `submit_local_vote` / 手动改 ConsensusState / FinalityState / QC / head；runtime
//! 无 pub driver accessor ⇒ 测试只能经 `runtime.step()` 驱动（结构保证 auto-drive 经 runtime）。
//! 不修改 consensus 规则 / 协议 / golden；D9 seam 保留。

use std::path::PathBuf;

use nova_consensus::proposer::select_proposer;
use nova_consensus::round::RoundStep;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::sign_message_hash;
use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{HandshakeKind, handshake_payload_encode};
use nova_network::transport::{MemoryTransport, Transport};

use nova_node::block_inbound::InboundBlockError;
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// canonical 有序 genesis（每个 validator 一个账户；账户/validator 均按协议要求排序）。
fn genesis_with(validators: Vec<([u8; 32], u128)>) -> GenesisV1 {
    let n = validators.len();
    // 账户：每 validator 一个（liquid 1_000_000 ≥ bonded）；地址 0x11.. 天然升序。
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
    // canonical：validator 按 validator_id（= SHA-256(pk)）升序。
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
    dir: PathBuf,
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
        let dir = std::env::temp_dir().join(format!("nova_d10a3_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        Self {
            dir,
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: true,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

/// 真实 canonical-next block（height1 / parent=genesis / state_root = 给定 root）+ `sk` 域签名。
fn raw_canonical_block(
    sk: &nova_crypto::signature::SigningKey,
    genesis_hash: [u8; 32],
    state_root: [u8; 32],
) -> nova_runtime::Block {
    let body = nova_runtime::BlockBody { txs: Vec::new() };
    let header = nova_runtime::BlockHeader {
        version: nova_runtime::BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: genesis_hash,
        finality_reference: None,
        transaction_root: nova_runtime::compute_transaction_root(&body),
        state_root,
        validator_set_hash: genesis_hash,
        timestamp: 0,
    };
    let payload = nova_runtime::encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    nova_runtime::Block {
        header,
        body,
        proposer_signature: sign_message_hash(sk, &msg).to_bytes(),
    }
}

/// 循环生成双验证者 keys 直至 `select_proposer(0,0)` == 目标（概率 1/2；bounded）。
fn pair_until_selected(want_b: bool) -> (KeyPair, KeyPair, GenesisV1, [u8; 32]) {
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
        let id_b = ValidatorId::from_consensus_public_key(&kp_b.verifying_key().to_bytes());
        let sel = select_proposer(CHAIN_ID, 0, 0, &hash, &set).unwrap();
        let selected_is_b = sel == id_b;
        if selected_is_b == want_b {
            let _ = id_a;
            return (kp_a, kp_b, genesis, hash);
        }
    }
    panic!("无法在 bounded 重试内找到满足 proposer 条件的 keys");
}

/// 三验证者 genesis 中选出：A = runtime validator、B = 当选者、C = 另一成员（wrong-proposer
/// 签名者，不占用 A 的 key）。
fn triple_until_selected_b() -> (KeyPair, KeyPair, KeyPair, GenesisV1, [u8; 32]) {
    for _ in 0..64 {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let c = KeyPair::generate().unwrap();
        let genesis = genesis_with(vec![
            (a.verifying_key().to_bytes(), STAKE),
            (b.verifying_key().to_bytes(), STAKE),
            (c.verifying_key().to_bytes(), STAKE),
        ]);
        let hash = compute_genesis_hash(&genesis).unwrap();
        let set = ValidatorSet::from_genesis(&genesis);
        let id_b = ValidatorId::from_consensus_public_key(&b.verifying_key().to_bytes());
        if select_proposer(CHAIN_ID, 0, 0, &hash, &set).unwrap() == id_b {
            return (a, b, c, genesis, hash);
        }
    }
    panic!("无法在 bounded 重试内让 B 当选（3 验证者）");
}

/// B 端（测试 peer）Handshake Init envelope（令 A Established B）。
fn peer_handshake(b_net: &KeyPair, genesis_hash: [u8; 32]) -> MessageEnvelope {
    let b_id = node_id_of(b_net);
    let payload = handshake_payload_encode(
        HandshakeKind::Init,
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        &b_id,
        &SessionNonce::from_bytes([1; 16]),
        b"",
    )
    .expect("handshake encode");
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: b_id,
        signature: [0u8; 64],
    };
    sign_message(b_net.signing_key(), &mut envelope).expect("sign handshake");
    envelope
}

/// 用 test network key 签任意 payload 信封（对端注入）。
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

// ---------------------------------------------------------------------------
// T10-R1 — 单验证者 Runtime Auto-Drive → Finality（enabled 主循环；无手动 submit_local_vote）
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r1_single_validator_runtime_auto_finality() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();
    let set = ValidatorSet::from_genesis(&genesis);
    assert!(
        set.quorum() <= STAKE,
        "单验证者自身可达 quorum（{} ≤ {STAKE}）",
        set.quorum()
    );

    // enabled 网络主循环（validator mode + MemoryTransport）。
    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp)),
        Box::new(tx_a),
        Box::new(identity),
    )
    .expect("validator + network 启动");

    // 多 step 经 runtime 主循环自动推进至 Finality（runtime_propose → register → auto_drive）。
    let mut finalized = None;
    for _ in 0..6 {
        runtime.step().expect("step ok");
        if let Some(f) = runtime.consensus().state().finality.finalized_reference {
            finalized = Some(f);
            break;
        }
    }
    let pb = runtime
        .last_proposal()
        .expect("本地 proposer 产出真实 block")
        .clone();
    assert_eq!(
        finalized,
        Some(pb.block_hash),
        "Runtime 自动推进 → finalized == 本地真实 block（由 transition 产生，非手设）"
    );
    // D10-C Step 7-B：finality（且同 tick 内 bridge commit）后 Node 以 durable head 推进到
    // **下一高度轮**（不再停在单块 Finalized 终态）。
    let head = runtime.block_production().unwrap().head().clone();
    assert_eq!(head.height, 1, "A 已 commit");
    let round = &runtime.consensus().state().round;
    assert_eq!(
        round.height, head.height,
        "Step 7-B：consensus 高度 == durable canonical head 高度"
    );
    assert_eq!(round.round, 0, "新高度轮从 round 0 开始");
    assert_eq!(
        round.step,
        RoundStep::Propose,
        "已进入下一高度轮（Propose）"
    );
    assert!(round.proposal.is_none(), "新高度轮无 stale proposal");
}

// ---------------------------------------------------------------------------
// T10-R2 — Runtime 确实调用 Auto-Drive（经 runtime step 入口；runtime 无 driver accessor，
//          结构上测试无法绕过 —— 推进只可能由 step 内 drive_local_consensus 触发）
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r2_runtime_step_calls_auto_drive() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();

    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp)),
        Box::new(tx_a),
        Box::new(identity),
    )
    .expect("启动");

    // step #1：runtime_propose 产块 + submit（→ Prevote）+ auto_drive 本地 prevote
    //          （单验者 quorum 自达 ⇒ 推进到 Precommit）—— runtime_propose 本身只到 Prevote，
    //          因此「> Prevote」的推进**只可能**来自 step 内 drive_local_consensus → auto_drive。
    runtime.step().expect("step1 ok");
    assert_eq!(
        runtime.consensus().state().round.step,
        RoundStep::Precommit,
        "runtime step 内 auto-drive 已投本地 prevote（propose 只到 Prevote）"
    );

    // step #2：auto-drive precommit ⇒ QC + Finality（同 tick bridge commit ⇒ Step 7-B 推进高度）。
    runtime.step().expect("step2 ok");
    let pb = runtime.last_proposal().expect("proposal").clone();
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        Some(pb.block_hash),
        "第二次 step 经 auto-drive precommit 达成 finality"
    );
    let head = runtime.block_production().unwrap().head().clone();
    assert_eq!(
        pb.block_hash, head.block_hash,
        "finalized 块已被 bridge commit"
    );
    assert_eq!(
        runtime.consensus().state().round.height,
        head.height,
        "Step 7-B：consensus 高度已跟进 durable head（下一高度轮）"
    );
    assert_eq!(
        runtime.consensus().state().round.step,
        RoundStep::Propose,
        "已进入下一高度轮（Propose）"
    );
}

// ---------------------------------------------------------------------------
// T10-R3 — Runtime Repeated Tick Safety（多 step：no panic / no duplicate / no fake）
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r3_runtime_repeated_tick_safety() {
    let kp = KeyPair::generate().unwrap();
    let pk = kp.verifying_key().to_bytes();
    let genesis = genesis_with(vec![(pk, STAKE)]);
    let env = Env::new(&genesis);
    let config = env.config();

    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp)),
        Box::new(tx_a),
        Box::new(identity),
    )
    .expect("启动");

    // 8 个连续 tick：全 Ok；本地 finality + bridge commit + Step 7-B 高度推进持续进行。
    for _ in 0..8 {
        runtime.step().expect("连续 tick 均 Ok（无 panic）");
    }
    let head = runtime.block_production().unwrap().head().clone();
    assert!(
        head.height >= 1,
        "本地 consensus finality 已 commit 至少一个块"
    );
    let finalized = runtime
        .consensus()
        .state()
        .finality
        .finalized_reference
        .expect("finality 存在");
    assert_eq!(
        finalized, head.block_hash,
        "canonical head == 最新本地 finalized 块（finality 是唯一 commit 授权）"
    );
    assert_eq!(
        runtime.consensus().state().round.height,
        head.height,
        "Step 7-B：consensus 高度跟随 durable head（不回退 / 不滞后）"
    );
    // 再多 tick：无 panic；head 单调不回退；finality 不回退。
    let before = (head.height, head.block_hash, finalized);
    runtime.step().expect("step ok");
    let after = runtime.block_production().unwrap().head().clone();
    assert!(
        after.height >= before.0,
        "head 单调不回退（{} → {}）",
        before.0,
        after.height
    );
    let finalized_after = runtime
        .consensus()
        .state()
        .finality
        .finalized_reference
        .expect("finality 存在");
    let dag = runtime.consensus().dag();
    assert!(
        finalized_after == before.2 || dag.is_ancestor(&before.2, &finalized_after),
        "finality 单调（不回退到无关分支）"
    );
}

// ---------------------------------------------------------------------------
// T10-R4 — Invalid proposer signature 经 runtime 网络收块被 D9 seam 拒；runtime 不自动 drive
//          双验证者：A 是 runtime validator、当选者是 B（A 非 proposer ⇒ 无本地提案干扰）
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r4_invalid_signature_block_rejected_no_drive() {
    // A = runtime validator（非当选，不产本地提案）；B = 当选者（kp_b 仅构造 block，不进 provider）。
    let (kp_a, kp_b, genesis, genesis_hash) = pair_until_selected(true);
    let env = Env::new(&genesis);
    let config = env.config();

    // B（当选者）产真实 canonical-next block → 篡改 proposer signature。proposer 验签在
    // state-root 之前 ⇒ root 占位即可（D9 seam 在 proposer 阶段即拒）。
    let mut block = raw_canonical_block(kp_b.signing_key(), genesis_hash, [0xEE; 32]);
    block.proposer_signature[0] ^= 0xFF;
    let wire = nova_runtime::encode_block(&block).unwrap();

    // A runtime（validator）持有 kp_a；网络对端 net_b（与 consensus key 分离）。
    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, mut tx_b) = MemoryTransport::pair(a_id, b_id);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp_a)),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("A validator + network 启动");

    // B 握手（Established）→ 注入篡改 block → step。
    let hs = peer_handshake(&net_b, genesis_hash);
    tx_b.send(&a_id, encode(&hs)).expect("inject handshake");
    runtime.step().expect("step handshake ok");
    let gossip = sign_peer_envelope(&net_b, MessageType::GossipBlock, wire);
    tx_b.send(&a_id, encode(&gossip)).expect("inject bad block");
    runtime.step().expect("step bad block ok");

    // D9 validator-set-aware seam：篡改签名 ⇒ InvalidProposerSignature（proposer 验证不绕过）。
    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(InboundBlockError::InvalidProposerSignature))),
        "坏块经 runtime block inbound（with ValidatorSet）被拒：{:?}",
        outcomes
    );
    // runtime 不自动 drive：无 proposal / 无 vote / 无 QC / 无 finality。
    assert_eq!(runtime.consensus().state().round.proposal, None);
    assert_eq!(
        runtime.consensus().state().round.step,
        RoundStep::Propose,
        "坏块未进入共识 ⇒ 无推进"
    );
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None,
        "无 finality"
    );
}

// ---------------------------------------------------------------------------
// T10-R5 — Wrong proposer（成员但非当选）经 runtime 网络收块被 D9 seam 拒；不绕过 gate
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r5_wrong_proposer_block_rejected_no_drive() {
    // A = runtime validator（成员但非当选）；B = 当选者；C = 另一成员（wrong-proposer 签名者）。
    let (kp_a, _kp_b, kp_c, genesis, genesis_hash) = triple_until_selected_b();
    let env = Env::new(&genesis);
    let config = env.config();

    // C（成员但非当选）签 canonical-next block（root 占位 —— proposer 阶段即拒）。
    let block = raw_canonical_block(kp_c.signing_key(), genesis_hash, [0xEE; 32]);
    let wire = nova_runtime::encode_block(&block).unwrap();

    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, mut tx_b) = MemoryTransport::pair(a_id, b_id);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp_a)),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("A validator + network 启动");

    let hs = peer_handshake(&net_b, genesis_hash);
    tx_b.send(&a_id, encode(&hs)).expect("inject handshake");
    runtime.step().expect("step handshake ok");
    let gossip = sign_peer_envelope(&net_b, MessageType::GossipBlock, wire);
    tx_b.send(&a_id, encode(&gossip))
        .expect("inject wrong-proposer block");
    runtime.step().expect("step wrong-proposer block ok");

    let outcomes = runtime.take_block_inbound_outcomes();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(InboundBlockError::InvalidProposerSignature))),
        "wrong proposer 经 runtime block inbound 被拒：{:?}",
        outcomes
    );
    assert_eq!(runtime.consensus().state().round.proposal, None);
    assert_eq!(runtime.consensus().state().round.step, RoundStep::Propose);
    assert_eq!(
        runtime.consensus().state().finality.finalized_reference,
        None
    );
}

// ---------------------------------------------------------------------------
// T10-R6 — 双验证者：Runtime 只产生自己的本地 vote（不替 B 投 / 不伪造 quorum / 无 fake finality）
//          当选者 = A（本节点）；B 的参与需真实 remote 路径（D9 Step6 已证），runtime 不代劳。
// ---------------------------------------------------------------------------

#[test]
fn d10_s3_r6_two_validator_runtime_local_vote_only() {
    let (kp_a, _kp_b, genesis, _hash) = pair_until_selected(false);
    let env = Env::new(&genesis);
    let config = env.config();
    let set = ValidatorSet::from_genesis(&genesis);
    assert!(
        STAKE < set.quorum(),
        "双验证者：单方 STAKE 不足 quorum（需 B 参与）"
    );

    let net_kp = KeyPair::generate().unwrap();
    let (tx_a, _tx_b) = MemoryTransport::pair(
        node_id_of(&net_kp),
        node_id_of(&KeyPair::generate().unwrap()),
    );
    let identity = SoftwareNetworkIdentity::new(net_kp);
    let mut runtime = NodeRuntime::start_with_network(
        &config,
        Some(&SoftwareKeyProvider::from_keypair(kp_a)),
        Box::new(tx_a),
        Box::new(identity),
    )
    .expect("A validator + network 启动");

    // A（当选者）经 runtime 自动产块并投本地 prevote；单票 STAKE < quorum ⇒ 停在 Prevote。
    for _ in 0..4 {
        runtime.step().expect("step ok");
    }
    let pb = runtime.last_proposal().expect("A 产出 proposal").clone();
    let state = runtime.consensus().state();
    assert_eq!(
        state.round.step,
        RoundStep::Prevote,
        "A 单票 < quorum ⇒ 未推进到 Precommit（不伪造 B 票）"
    );
    assert_eq!(
        state.finality.finalized_reference, None,
        "无 fake finality（缺 B remote vote）"
    );
    // prevotes 只含 A 的本地票（weight = STAKE；非 quorum；无 B 重复计权）。
    let weight = state.round.prevotes.weight_of(&pb.block_hash);
    assert_eq!(
        weight, STAKE,
        "仅 A 本地一票（auto-drive 不替 B 制造 vote）"
    );
    assert!(STAKE < set.quorum(), "单票不足 ⇒ 不会因重复 tick 翻倍计权");
    // 幂等：再多 tick 不产生第二份本地 vote / 不推进。
    runtime.step().expect("step ok");
    assert_eq!(
        runtime
            .consensus()
            .state()
            .round
            .prevotes
            .weight_of(&pb.block_hash),
        STAKE,
        "重复 tick 幂等（无重复计权）"
    );
    assert_eq!(
        runtime.consensus().state().round.step,
        RoundStep::Prevote,
        "B 的 prevote 必须经真实 remote 路径（D9 Step6）—— runtime 不代劳"
    );
}
