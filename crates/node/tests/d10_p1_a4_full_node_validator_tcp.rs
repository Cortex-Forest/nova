//! P1-A.4 — **full-node ↔ validator 真实 TCP**（入站 consensus 拒绝边界）+ 畸形入站 vote/QC 注入。
//!
//! # 背景（P1-A.3 实测故障）
//! full-node 收到 validator 对端广播的 PrecommitQC 后，既有 `NodeRuntime::step()` 会沿
//! `take_commands → process_command → driver.submit_inbound_qc → verify_qc` 命中冻结检查 ①
//! 「`target ∈ DAG`」（`crates/consensus/src/finality.rs:229-232`，`FinalityError::UnknownTarget`）——
//! 因为 full-node 无 canonical adapter（`block_production = None`）⇒ 远端区块被跳过（不计入 DAG），
//! 于是返回 `DriverError::QcVerification` ⇒ `RuntimeError::Driver` ⇒ 节点 fail-closed 退出。
//!
//! # P1-A.4 修复边界（本测试验证）
//! **只有** `take_commands() → process_command(..)` 这条**网络来源**路径改为「拒绝 + 计数 + 继续」；
//! 本地路径（`auto_drive` / proposer / commit bridge / DAG 登记 / egress）仍 fail-closed。
//! 被拒命令**零 canonical 变更**（driver verify-then-transition；无 lock / 无 outbound）。
//!
//! # 测试矩阵
//! - **A**：A = full-node（真实 listener，端口由内核分配）+ B = validator（dial A，真实 TCP）；
//!   B 产生真实共识流量（proposal / vote / **PrecommitQC** / gossip block）；A 必须**存活**、
//!   计入 `inbound_consensus_rejected >= 1`、保持零验证者权威（无 actor / 无 adapter / height 0）。
//! - **B**：full-node + `MemoryTransport` 精确注入（既有 C-2 套路）：
//!   ① 结构合法但签名无效的 vote（`DriverError::VoteVerification`）；
//!   ② 结构合法但 `target ∉ DAG` 的 QC（`DriverError::QcVerification(UnknownTarget)`）。
//!   两者都必须：`step()` 成功、计数 +1、round 状态零变更、无 outbound、节点仍可用。
//!
//! 纪律：有界等待（`MAX_ITER` + `HARD_DEADLINE`），无无限等待；不修改 driver/network/共识；
//! 不新增依赖；fixture 仅写系统临时目录。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nova_consensus::finality::{QcContext, QuorumCertificate, encode_qc};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, MessageType, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{HandshakeKind, handshake_payload_encode};
use nova_network::transport::{ConnectionTarget, MemoryTransport, Transport};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, derive_validator_id};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// 有界驱动循环上限（每次 1ms；确定性退出）。
const MAX_ITER: usize = 1500;
/// 整个测试的硬上限（防挂死；有界等待）。
const HARD_DEADLINE: Duration = Duration::from_secs(90);
/// 注入 transport 的「陌生对端」：既非 A 亦非 B ⇒ `MemoryTransport` 不可能承载 A↔B 帧（Test B）。
const STRANGER_NODE_ID: [u8; 32] = [0x99; 32];
/// 注入用目标 hash（Test B；不要求存在于任何 DAG）。
const TARGET: [u8; 32] = [0xAA; 32];

// ---------------------------------------------------------------------------
// Fixtures（与既有 node 测试同套路；本文件独立复制以避免跨文件依赖）
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// TEST GENESIS ONLY：单 validator（被测公钥）；Σliquid == total_supply。
fn genesis_for(validator_pk: [u8; 32]) -> GenesisV1 {
    let acc1 = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    let acc2 = AccountInit {
        address: addr([0x22; 32]),
        liquid_balance: 1_000_000,
    };
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: acc1.address,
            consensus_public_key: validator_pk,
            bonded_stake: STAKE,
            commission_bps: 0,
        }],
        initial_accounts: vec![acc1, acc2],
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
            total_supply: 2_000_000,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

/// 每节点独立 chain/safety 目录（同一 genesis 内容 ⇒ 同一链身份）。
struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1, tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nova_p1a4_{}_{}_{}", std::process::id(), n, tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let genesis_hash = compute_genesis_hash(genesis).expect("genesis hash");
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(
            &genesis_path,
            canonical_genesis_bytes(genesis).expect("canonical"),
        )
        .expect("write genesis");
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

    fn config(
        &self,
        validator_enabled: bool,
        listen_addr: Option<SocketAddr>,
        peers: Vec<ConnectionTarget>,
    ) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production()
        .map(|ad| ad.head().height)
        .unwrap_or(0)
}

/// 启动真实 runtime（真实网络装配）。`validator_kp = None` ⇒ full-node（不构造 actor）。
fn start_node(config: &NodeConfig, validator_kp: Option<KeyPair>, net_kp: KeyPair) -> NodeRuntime {
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_stranger) =
        MemoryTransport::pair(net_id, NodeId::from_bytes(STRANGER_NODE_ID));
    let provider = validator_kp.map(SoftwareKeyProvider::from_keypair);
    NodeRuntime::start_with_network(
        config,
        provider.as_ref().map(|p| p as &dyn KeyProvider),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("start_with_network（真实网络装配）")
}

/// 对端 Handshake Init envelope（既有 D5 套路：peer-auth 装配后普通消息需 Established sender）。
fn b_handshake(net_kp: &KeyPair, genesis_hash: [u8; 32], b_id: NodeId) -> MessageEnvelope {
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
    sign_message(net_kp.signing_key(), &mut envelope).expect("sign handshake");
    envelope
}

/// 用 test network key 签任意 payload 信封（对端注入帧）。
fn sign_envelope(net_kp: &KeyPair, message_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    let sender = node_id_of(net_kp);
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender,
        signature: [0u8; 64],
    };
    sign_message(net_kp.signing_key(), &mut envelope).expect("sign envelope");
    envelope
}

/// 注入一帧到 runtime（peer 侧 transport）。
fn inject(
    tx: &mut MemoryTransport,
    net_kp: &KeyPair,
    to: &NodeId,
    message_type: MessageType,
    payload: Vec<u8>,
) {
    let envelope = sign_envelope(net_kp, message_type, payload);
    tx.send(to, encode(&envelope)).expect("inject frame");
}

// ---------------------------------------------------------------------------
// Test A：full-node ↔ validator，真实 TCP（核心回归）
// ---------------------------------------------------------------------------

#[test]
fn p1a4_full_node_survives_validator_consensus_traffic() {
    // B 的 validator 身份 = genesis 中唯一 validator。
    let validator_kp = KeyPair::generate().expect("validator keypair");
    let genesis = genesis_for(validator_kp.verifying_key().to_bytes());
    let env_a = Env::new(&genesis, "a");
    let env_b = Env::new(&genesis, "b");

    let net_a = KeyPair::generate().expect("net keypair A");
    let net_b = KeyPair::generate().expect("net keypair B");
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);

    // ---------- A：full-node + 真实 listener（内核分配端口）----------
    let cfg_a = env_a.config(
        false,
        Some("127.0.0.1:0".parse().expect("addr")),
        Vec::new(),
    );
    let mut a = start_node(&cfg_a, None, net_a);
    assert!(!a.validator_enabled(), "A 必须是 full-node");
    assert!(
        a.validator().is_none(),
        "A 不得持有任何 actor（零验证者权威）"
    );
    assert!(
        a.block_production().is_none(),
        "A 无 canonical adapter（因此远端区块不会进入其 DAG）"
    );
    let a_addr = a.network_listen_addr().expect("A 必须绑定真实 listener");
    assert_ne!(a_addr.port(), 0, "端口 0 必须被内核分配为真实端口");

    // ---------- B：validator（dial A）----------
    let cfg_b = env_b.config(
        true,
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut b = start_node(&cfg_b, Some(validator_kp), net_b);
    assert!(b.validator_enabled(), "B 是 validator");

    // ---------- 有界驱动：B 产生真实共识流量；A 必须存活 ----------
    let deadline = Instant::now() + HARD_DEADLINE;
    let mut a_failure: Option<String> = None;
    let mut b_failure: Option<String> = None;
    let mut iterations = 0usize;
    for i in 0..MAX_ITER {
        iterations = i + 1;
        // 幂等建立 / 推进 configured peer 握手（真实 TCP dial 由 runtime 内部 dialer 完成）。
        let _ = b.establish_configured_peers();
        // **核心断言**：full-node 收到 peer 的 proposal/vote/QC/gossip block 后不得致命。
        if let Err(e) = a.step() {
            a_failure = Some(format!("A.step 失败（入站 peer 流量不得致命）: {e:?}"));
            break;
        }
        if let Err(e) = b.step() {
            b_failure = Some(format!("B.step 失败: {e:?}"));
            break;
        }
        if a.inbound_consensus_rejected() >= 1 && head_height(&b) >= 1 {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    assert!(a_failure.is_none(), "{}", a_failure.unwrap_or_default());
    assert!(b_failure.is_none(), "{}", b_failure.unwrap_or_default());

    // ---------- A 侧：认证 + Established 成立 ----------
    assert!(
        a.network_peer_established(b_id),
        "A 必须与 B 达到 Established（认证路径成功）"
    );
    assert!(
        b.network_peer_established(a_id),
        "B 必须与 A 达到 Established"
    );

    // ---------- 核心：A 计入被拒入站 consensus command 且仍存活 ----------
    let rejected = a.inbound_consensus_rejected();
    assert!(
        rejected >= 1,
        "A 必须拒绝至少一条不可应用的入站 consensus command（实测 iterations={iterations}）"
    );

    // ---------- A 仍是 full-node：零验证者权威 / 零 canonical 推进 ----------
    assert!(!a.validator_enabled(), "A 不得变成 validator");
    assert!(a.validator().is_none(), "A 不得持有 actor（无 lock 获取）");
    assert!(a.block_production().is_none(), "A 无 canonical adapter");
    assert_eq!(
        a.consensus().state().round.height,
        0,
        "A 的 canonical 高度不得因入站命令推进"
    );
    assert_eq!(head_height(&a), 0, "A 不得提交任何区块");

    // ---------- B 继续正常出块（validator 行为不变）----------
    assert!(
        head_height(&b) >= 1,
        "B 必须继续产出并提交区块（head={}）",
        head_height(&b)
    );

    // ---------- A 持续存活（额外有界步数，确认非「侥幸一次 Ok」）----------
    for _ in 0..64 {
        assert!(
            a.step().is_ok(),
            "A 在拒绝入站命令后必须继续可驱动（持续存活）"
        );
    }
    assert!(a.inbound_consensus_rejected() >= rejected, "计数单调不减");
}

// ---------------------------------------------------------------------------
// Test B：畸形入站 vote / QC（精确注入；既有 C-2 套路）
// ---------------------------------------------------------------------------

#[test]
fn p1a4_malformed_inbound_vote_and_qc_are_rejected_not_fatal() {
    let validator_kp = KeyPair::generate().expect("validator keypair");
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let genesis = genesis_for(validator_pk);
    let env = Env::new(&genesis, "inj");

    let net_a = KeyPair::generate().expect("net keypair A");
    let net_b = KeyPair::generate().expect("net keypair B");
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, mut tx_b) = MemoryTransport::pair(a_id, b_id);

    let cfg = env.config(false, None, Vec::new());
    let mut runtime = NodeRuntime::start_with_network(
        &cfg,
        None,
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("start_with_network");
    assert!(!runtime.validator_enabled(), "被测节点必须是 full-node");

    // 对端先握手 ⇒ Established（普通消息才放行）。
    let hs = b_handshake(&net_b, env.genesis_hash, b_id);
    tx_b.send(&a_id, encode(&hs)).expect("inject handshake");
    runtime.step().expect("handshake step Ok");
    assert_eq!(
        runtime.inbound_consensus_rejected(),
        0,
        "握手不产生 consensus command"
    );

    // 状态快照（用于断言被拒命令零状态变更）。
    let before = {
        let s = runtime.consensus().state();
        (
            s.round.height,
            s.round.round,
            s.round.step,
            s.round.proposal.clone(),
        )
    };
    assert!(
        runtime.take_consensus_outbound().is_empty(),
        "初始无待广播 consensus 输出"
    );

    // ---------- ① 结构合法但签名无效的 vote ⇒ DriverError::VoteVerification ----------
    let vote = ValidatorVote {
        round: 0,
        height: 0,
        target_block_hash: TARGET,
        vote_type: VoteType::Prevote,
        source_block_hash: [0u8; 32],
        validator_id: derive_validator_id(&validator_pk),
        timestamp: 0,
    };
    let mut vote_wire = canonical_vote_payload(&vote);
    vote_wire.extend_from_slice(&[0xAAu8; 64]); // 无效签名（结构合法 ⇒ decode 通过）
    inject(
        &mut tx_b,
        &net_b,
        &a_id,
        MessageType::ConsensusVote,
        vote_wire,
    );
    runtime
        .step()
        .expect("畸形 vote 必须被拒绝而非致命（step 仍 Ok）");
    assert_eq!(
        runtime.inbound_consensus_rejected(),
        1,
        "无效 vote ⇒ 计数 +1"
    );
    let after_vote = {
        let s = runtime.consensus().state();
        (
            s.round.height,
            s.round.round,
            s.round.step,
            s.round.proposal.clone(),
        )
    };
    assert_eq!(
        after_vote, before,
        "被拒 vote 不得改变 canonical round 状态"
    );
    assert!(
        runtime.take_consensus_outbound().is_empty(),
        "被拒 vote 不得产生任何 outbound consensus 输出"
    );
    assert!(runtime.validator().is_none(), "A 不得获得验证者权威");

    // ---------- ② 结构合法但 target ∉ DAG 的 QC ⇒ DriverError::QcVerification(UnknownTarget) ----------
    let qc = QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 1,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target: [0xAB; 32],
        validator_set_id: env.genesis_hash,
        evidence: Vec::new(),
    };
    inject(
        &mut tx_b,
        &net_b,
        &a_id,
        MessageType::ConsensusQc,
        encode_qc(&qc),
    );
    runtime
        .step()
        .expect("不可应用 QC 必须被拒绝而非致命（step 仍 Ok）");
    assert_eq!(
        runtime.inbound_consensus_rejected(),
        2,
        "不可应用 QC ⇒ 计数再 +1"
    );
    let after_qc = {
        let s = runtime.consensus().state();
        (
            s.round.height,
            s.round.round,
            s.round.step,
            s.round.proposal.clone(),
        )
    };
    assert_eq!(after_qc, before, "被拒 QC 不得改变 canonical round 状态");
    assert!(
        runtime.take_consensus_outbound().is_empty(),
        "被拒 QC 不得产生任何 outbound consensus 输出"
    );
    assert_eq!(
        runtime.consensus().state().round.height,
        0,
        "无 finality 推进 / 无 canonical commit"
    );

    // ---------- ③ 节点仍可用：继续可驱动，计数不再变化 ----------
    for _ in 0..3 {
        runtime.step().expect("节点必须仍可驱动（可用性保持）");
    }
    assert_eq!(
        runtime.inbound_consensus_rejected(),
        2,
        "无新入站命令 ⇒ 计数不变"
    );
}
