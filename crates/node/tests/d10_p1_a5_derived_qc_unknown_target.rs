//! P1-A.5 — **派生 QC `UnknownTarget` 不得终止 runtime**（本地 / 派生 consensus 路径）。
//!
//! # 背景（Design Gate 判定：HIGH）
//! P1-A.4 只把 **入站（peer 提供）** consensus command 的 Driver 失败改为「拒绝 + 计数 + 继续」；
//! 本地/派生路径仍 fail-closed。但冻结 transition 的 `SetProposal` 守卫**只**要求 `step == Propose`
//! （`crates/consensus/src/integration.rs`；**不**要求 `proposal.block_hash ∈ DAG`）⇒ 一个
//! validator 完全可能「有 proposal、无该块」时按 `proposal.block_hash` 投出本地票；若该票恰好
//! 完成 **precommit quorum**，冻结 transition ⑥ 会组装 `derived.precommit_qc`，而节点侧
//! `process_transition_derived` → `verify_qc` 命中冻结检查 ①「`target ∈ DAG`」
//! （`crates/consensus/src/finality.rs:229-232`，`FinalityError::UnknownTarget`）
//! ⇒ `DriverError::QcVerification` ⇒ `RuntimeError::Driver` ⇒ **validator 进程退出**。
//!
//! # P1-A.5 修复边界（本测试验证）
//! `UnknownTarget` 语义 = 「该 QC 对**本节点**尚**不适用**」—— **不是**「QC 已验证有效」，也**不是**
//! 运行错误：错误在 lock routing / outbound push **之前**产生 ⇒ **零** canonical 变更
//! （无 lock / 无 outbound / 无 finality 推进 / 无 DAG 修改 / 无 commit / 无 head 推进），
//! `verify_qc` 未被绕过。因此：计数（`derived_qc_not_applicable`）+ 继续。
//! **其余全部** Driver 失败仍 fail-closed（不得扩大容错范围）。
//!
//! # 测试矩阵
//! - **T1**（核心回归；**真实 TCP**：本节点绑定 `127.0.0.1:0` listener，对端 dial 入）：validator
//!   runtime（单验证者：本地票即可达 quorum）；对端在**同一批**发送 Init + 「无块 proposal」
//!   （`block_hash = TARGET ∉ DAG`）—— 必须早于 phase 12 本地自提案（`build_proposal` 幂等守卫
//!   `proposal.is_some()` ⇒ `Ok(None)`），否则本地会先登记真实块并随后锁定，使后续对 unrelated
//!   TARGET 的本地票被 LOCK 授权层拒。随后：Prevote（step ①，quorum ⇒ step 推进 Precommit；
//!   此时**无**派生 precommit QC）→ Precommit（step ②，**precommit quorum ⇒ 派生 QC ⇒
//!   `verify_qc` UnknownTarget**）。断言：`step()` 仍 `Ok`、计数 == 1、lock 不变、finality 不变、
//!   head 不变、高度不变、DAG 不变，且对端**未收到任何 `ConsensusQc` 帧**（对照：确已收到
//!   prevote / precommit 帧 ⇒ 「无 QC 广播」非空断言）；随后继续可驱动且计数不再增长。
//! - **T2**（负向）：Established 对端注入**结构合法但签名无效**的 vote
//!   （`DriverError::VoteVerification`）⇒ 仍为「拒绝 + 计数」（`inbound_consensus_rejected` +1），
//!   **不**被计入 `derived_qc_not_applicable`，节点不退出。
//!   （补充：`DriverError` 变体**精确性**穷举在 `runtime.rs` 单元测试
//!   `p1a5_tolerance_is_exactly_qc_unknown_target` —— 该边界无法经公开 API 在本地路径构造其它
//!   变体，故以单元负向穷举证明「未写成 `Err(_)` / `QcVerification(_)`」。）
//!
//! 纪律：不修改 driver / wiring / egress / consensus / network；不新增依赖；有界（唯一等待 =
//! 对端 TCP 的有界 1ms 轮询 + 50 轮 idle 上限）；fixture 仅写系统临时目录。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, MessageType, decode, encode, sign_message};
use nova_network::node_id::NodeId;
use nova_network::security::SessionNonce;
use nova_network::session::{HandshakeKind, handshake_payload_encode};
use nova_network::transport::{MemoryTransport, TcpTransport, Transport};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, SoftwareKeyProvider};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::NodeRuntime;

use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// 注入的 proposal target —— **故意**不存在于任何本地 DAG（不 register_block / 不 commit）。
const TARGET: [u8; 32] = [0xAA; 32];
/// 测试对端 TCP 读帧上限（本测试帧均很小；仍给足余量）。
const MAX_FRAME: usize = 1 << 20;
/// 对端 TCP idle / connect 超时（有界；防挂死）。
const PEER_IO_TIMEOUT: Duration = Duration::from_secs(5);

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

/// 节点独立 chain/safety 目录（同一 genesis 内容 ⇒ 同一链身份）。
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
            std::env::temp_dir().join(format!("nova_p1a5_{}_{}_{}", std::process::id(), n, tag));
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

    fn config(&self, validator_enabled: bool, listen_addr: Option<SocketAddr>) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers: Vec::new(),
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

/// 对端 Handshake Init payload（既有 D5 套路；普通消息需 Established sender）。
fn handshake_payload(genesis_hash: [u8; 32], peer_id: NodeId) -> Vec<u8> {
    handshake_payload_encode(
        HandshakeKind::Init,
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        &peer_id,
        &SessionNonce::from_bytes([1; 16]),
        b"",
    )
    .expect("handshake encode")
}

/// 用 test network key 签任意 payload 信封（对端注入帧）。
fn sign_envelope(net_kp: &KeyPair, message_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
    let mut envelope = MessageEnvelope {
        version: 1,
        message_type,
        payload,
        sender: node_id_of(net_kp),
        signature: [0u8; 64],
    };
    sign_message(net_kp.signing_key(), &mut envelope).expect("sign envelope");
    envelope
}

/// 对端 Handshake Init envelope。
fn peer_handshake(net_kp: &KeyPair, genesis_hash: [u8; 32], peer_id: NodeId) -> MessageEnvelope {
    sign_envelope(
        net_kp,
        MessageType::Handshake,
        handshake_payload(genesis_hash, peer_id),
    )
}

/// 注入一帧到 runtime（对端侧 MemoryTransport）。
fn inject(
    tx: &mut MemoryTransport,
    net_kp: &KeyPair,
    to: &NodeId,
    message_type: MessageType,
    payload: Vec<u8>,
) {
    tx.send(to, encode(&sign_envelope(net_kp, message_type, payload)))
        .expect("inject frame");
}

/// 启动 validator runtime（真实节点装配；注入 transport = 对端为陌生 non-validator peer）。
///
/// 返回 `(runtime, 对端 transport, 对端网络密钥, 本端 NodeId, 对端 NodeId)`。
fn start_validator(
    env: &Env,
    validator_kp: KeyPair,
) -> (NodeRuntime, MemoryTransport, KeyPair, NodeId, NodeId) {
    let net_a = KeyPair::generate().expect("net keypair A");
    let net_b = KeyPair::generate().expect("net keypair B");
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, tx_b) = MemoryTransport::pair(a_id, b_id);
    let provider = SoftwareKeyProvider::from_keypair(validator_kp);
    let cfg = env.config(true, None);
    let rt = NodeRuntime::start_with_network(
        &cfg,
        Some(&provider as &dyn KeyProvider),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("start_with_network（validator 装配）");
    (rt, tx_b, net_b, a_id, b_id)
}

/// 对端握手至 Established（否则非 Handshake 消息由 NetworkService fail-closed 丢弃）。
fn establish(
    rt: &mut NodeRuntime,
    tx_b: &mut MemoryTransport,
    net_b: &KeyPair,
    a_id: NodeId,
    b_id: NodeId,
    genesis_hash: [u8; 32],
) {
    let hs = peer_handshake(net_b, genesis_hash, b_id);
    tx_b.send(&a_id, encode(&hs)).expect("inject handshake");
    rt.step().expect("handshake step（必须 Ok）");
    assert!(
        rt.network_peer_established(b_id),
        "对端必须 Established（否则后续注入被丢弃）"
    );
}

/// 启动 validator runtime并绑定 **真实 listener**（用于「真实 TCP 对端 dial 入本节点」场景：
/// accept 侧 ⇒ peer `connected` + Established ⇒ `broadcast` 可达对端 ⇒ outbound 可被对端观测）。
///
/// 注入 transport 仅为满足 `start_with_network` 签名（陌生 non-validator 对端，本测试不使用）。
/// 返回 `(runtime, 本端 NodeId, listener 地址)`。
fn start_validator_listening(
    env: &Env,
    validator_kp: KeyPair,
) -> (NodeRuntime, NodeId, SocketAddr) {
    let net_a = KeyPair::generate().expect("net keypair A");
    let a_id = node_id_of(&net_a);
    let (tx_a, _tx_stranger) = MemoryTransport::pair(a_id, NodeId::from_bytes([0x99; 32]));
    let provider = SoftwareKeyProvider::from_keypair(validator_kp);
    let cfg = env.config(true, Some("127.0.0.1:0".parse().expect("listen addr")));
    let rt = NodeRuntime::start_with_network(
        &cfg,
        Some(&provider as &dyn KeyProvider),
        Box::new(tx_a),
        Box::new(SoftwareNetworkIdentity::new(net_a)),
    )
    .expect("start_with_network（validator + 真实 listener）");
    let addr = rt.network_listen_addr().expect("必须绑定真实 listener");
    (rt, a_id, addr)
}

/// 从真实 TCP 对端读取并统计 consensus 帧（有界：iterations + idle rounds + 1ms 轮询；无无限等待）。
fn drain_tcp_frames(tcp: &mut TcpTransport) -> (usize, usize) {
    let mut qc = 0usize;
    let mut votes = 0usize;
    let mut idle = 0usize;
    for _ in 0..2000 {
        match tcp.try_recv() {
            Ok(Some((_from, payload))) => {
                idle = 0;
                let Ok(envelope) = decode(&payload) else {
                    continue;
                };
                if matches!(envelope.message_type, MessageType::ConsensusQc) {
                    qc += 1;
                } else if matches!(envelope.message_type, MessageType::ConsensusVote) {
                    votes += 1;
                }
            }
            Ok(None) => {
                idle += 1;
                if idle >= 50 || tcp.is_closed() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break,
        }
    }
    (qc, votes)
}

// ---------------------------------------------------------------------------
// T1：派生 QC UnknownTarget 不得终止 runtime（核心回归）
// ---------------------------------------------------------------------------

#[test]
fn p1a5_derived_qc_unknown_target_is_not_fatal() {
    let validator_kp = KeyPair::generate().expect("validator keypair");
    let genesis = genesis_for(validator_kp.verifying_key().to_bytes());
    let env = Env::new(&genesis, "t1");
    let (mut rt, a_id, listen_addr) = start_validator_listening(&env, validator_kp);
    let net_b = KeyPair::generate().expect("net keypair B");
    let b_id = node_id_of(&net_b);

    assert!(rt.validator_enabled(), "被测节点必须是 validator");
    assert_eq!(rt.network_node_id(), Some(a_id), "listener 身份 = 装配身份");

    // ---------- 前提断言（全新节点：Propose 窗口 / TARGET ∉ DAG / **无 lock** / 无 finality）----------
    let round = rt.consensus().state().round.clone();
    assert_eq!(round.step, RoundStep::Propose, "前提：初始 step = Propose");
    assert!(round.proposal.is_none(), "前提：初始无 proposal");
    assert!(
        !rt.consensus().dag().contains(&TARGET),
        "前提：TARGET 必须不在本地 DAG"
    );
    let locked_before = *rt
        .validator()
        .expect("validator view")
        .actor()
        .locked_state();
    assert!(
        !locked_before.is_locked(),
        "前提：全新节点无 lock（否则对 unrelated TARGET 的本地票会被 LOCK 授权层拒绝）"
    );
    assert!(
        rt.consensus()
            .state()
            .finality
            .finalized_reference
            .is_none(),
        "前提：初始无 finality"
    );
    assert_eq!(head_height(&rt), 0, "前提：初始 head = 0");
    assert_eq!(rt.derived_qc_not_applicable(), 0, "前提：计数从 0 开始");

    // ---------- 期望当选者（单验证者 ⇒ 本地；`auto_drive` proposer-authority gate 需要匹配）----------
    let set = rt.consensus().validator_set().clone();
    let expected = select_proposer(CHAIN_ID, round.height, round.round, &env.genesis_hash, &set)
        .expect("单验证者集合必然可推导 proposer");
    let proposal = ProposalRef {
        block_hash: TARGET,
        proposer: expected,
    };

    // ---------- 真实 TCP：对端 B dial 本节点，**同批**发送 ① Init ② 无块 proposal ----------
    // - 本节点为 accept 侧 ⇒ B `connected` + Established ⇒ egress `broadcast` 可达 B
    //   （使「无 QC 广播」成为**可观测**非空断言：本地 vote 帧应当收到，QC 帧不得收到）。
    // - Init 与 proposal **同批**（同一 step 的同一 poll）⇒ proposal 在 phase 12（本地自提案）
    //   之前生效（`build_proposal` 幂等守卫 `proposal.is_some()` ⇒ `Ok(None)`）—— 否则本地
    //   自提案会先登记真实块并随后锁定，使后续对 unrelated TARGET 的本地票被 LOCK 授权层拒绝。
    let mut tcp = TcpTransport::dial(listen_addr, b_id, a_id, MAX_FRAME, Some(PEER_IO_TIMEOUT))
        .expect("dial 本节点 listener");
    tcp.send(
        &a_id,
        encode(&peer_handshake(&net_b, env.genesis_hash, b_id)),
    )
    .expect("send Init");
    tcp.send(
        &a_id,
        encode(&sign_envelope(
            &net_b,
            MessageType::ConsensusProposal,
            encode_proposal_ref(&proposal),
        )),
    )
    .expect("send proposal");

    // ---------- 第 1 step：Handshake 建立 + proposal 应用（Propose → Prevote）+ 本地 Prevote ----------
    rt.step().expect("proposal step 必须 Ok（proposal 合法）");
    assert!(
        rt.network_peer_connected(b_id),
        "accept 侧对端必须 connected（广播目标集非空）"
    );
    assert!(
        rt.network_peer_established(b_id),
        "同批 Init 必须已建立 Established（否则 proposal 被 drop）"
    );
    assert_eq!(
        rt.inbound_consensus_rejected(),
        0,
        "合法 proposal 不得计入入站拒绝"
    );
    assert_eq!(
        rt.derived_qc_not_applicable(),
        0,
        "prevote 阶段无派生 precommit QC ⇒ 计数仍 0"
    );
    {
        let s = rt.consensus().state();
        assert_eq!(
            s.round.proposal.as_ref().map(|p| p.block_hash),
            Some(TARGET),
            "proposal 已应用（target = TARGET）"
        );
        assert_eq!(
            s.round.step,
            RoundStep::Precommit,
            "本地 prevote 已达 quorum ⇒ step 推进 Precommit"
        );
    }
    assert!(
        !rt.consensus().dag().contains(&TARGET),
        "proposal 不得使 TARGET 进入 DAG（未 register_block）"
    );

    // 该 QC 生效前的快照（用于「QC 零副作用」断言）。
    let locked_pre_qc = *rt
        .validator()
        .expect("validator view")
        .actor()
        .locked_state();
    let finality_pre_qc = rt.consensus().state().finality.finalized_reference;
    let height_pre_qc = rt.consensus().state().round.height;
    let dag_len_pre_qc = rt.consensus().dag().len();
    let head_pre_qc = head_height(&rt);

    // ---------- 第 2 step：本地 Precommit（quorum）⇒ 派生 QC ⇒ verify_qc UnknownTarget ----------
    // 修复前：此处 `RuntimeError::Driver` ⇒ 节点退出。修复后：不适用 + 计数 + 继续。
    rt.step()
        .expect("派生 QC UnknownTarget 不得终止 runtime（step 必须 Ok）");
    assert_eq!(
        rt.derived_qc_not_applicable(),
        1,
        "UnknownTarget ⇒ 计数恰好 +1"
    );
    assert_eq!(
        rt.inbound_consensus_rejected(),
        0,
        "本地派生路径不得计入入站拒绝计数（两个计数相互独立）"
    );

    // 前提成立证明：本地 vote 确实完成了 **precommit quorum**（frozen transition 置 Finalized）。
    assert_eq!(
        rt.consensus().state().round.step,
        RoundStep::Finalized,
        "precommit quorum 已达成（否则不会有 derived.precommit_qc）"
    );

    // ---------- 核心：QC 被安全丢弃 —— 零 canonical 副作用 ----------
    // （round.step → Finalized 由**本地 vote** 经冻结 transition 产生，不是 QC 的副作用；
    //   下面断言的是 QC 本身的副作用面：finality / 高度 / head / DAG / lock / outbound。）
    assert_eq!(
        rt.consensus().state().finality.finalized_reference,
        finality_pre_qc,
        "UnknownTarget QC 不得推进 finality（绝不当作有效 QC）"
    );
    assert_eq!(
        rt.consensus().state().round.height,
        height_pre_qc,
        "高度不得改变（无 commit / 无 advance）"
    );
    assert_eq!(
        head_height(&rt),
        head_pre_qc,
        "head 不得推进（无 canonical commit）"
    );
    assert!(
        !rt.consensus().dag().contains(&TARGET),
        "不得把 QC target 错误插入 DAG"
    );
    assert_eq!(
        rt.consensus().dag().len(),
        dag_len_pre_qc,
        "DAG 必须完全不变（无插入 / 无删除）"
    );
    let locked_after = *rt
        .validator()
        .expect("validator view")
        .actor()
        .locked_state();
    assert_eq!(
        locked_after, locked_pre_qc,
        "lock 必须不变（verify_qc 失败 ⇒ 不进入 acquire_lock 路由）"
    );
    assert_eq!(
        locked_after, locked_before,
        "lock 自注入以来未改变（无 QC 路由）"
    );

    // ---------- 无 outbound effect：从未广播 QC（对比：本地 vote 确实广播过）----------
    let (qc_frames, vote_frames) = drain_tcp_frames(&mut tcp);
    assert_eq!(
        qc_frames, 0,
        "不适用 QC 绝不得广播（无该 QC 的 outbound effect）"
    );
    assert!(
        vote_frames >= 2,
        "本地 prevote / precommit 已真实广播至对端（对照：证明「无 QC 帧」不是「什么都没发」的空断言）"
    );

    // ---------- 持续存活：round 已 Finalized ⇒ auto_drive Idle ⇒ 计数不再增长 ----------
    for _ in 0..16 {
        rt.step().expect("节点在容忍后必须继续可驱动");
    }
    assert_eq!(
        rt.derived_qc_not_applicable(),
        1,
        "无新派生事件 ⇒ 计数保持恰好 1"
    );
    assert_eq!(head_height(&rt), head_pre_qc, "仍无 commit");
    rt.shutdown().expect("shutdown 必须成功");
}

// ---------------------------------------------------------------------------
// T2：非 UnknownTarget 仍保持既有拒绝 / fail-closed 语义（不得被新计数吸收）
// ---------------------------------------------------------------------------

#[test]
fn p1a5_non_unknown_target_is_not_tolerated() {
    let validator_kp = KeyPair::generate().expect("validator keypair");
    let genesis = genesis_for(validator_kp.verifying_key().to_bytes());
    let env = Env::new(&genesis, "t2");
    let (mut rt, mut tx_b, net_b, a_id, b_id) = start_validator(&env, validator_kp);
    establish(&mut rt, &mut tx_b, &net_b, a_id, b_id, env.genesis_hash);

    let local_id = rt.validator().expect("validator view").validator_id();
    let round = rt.consensus().state().round.clone();

    // ---------- ① 结构合法但**签名无效**的本地身份 vote ⇒ VoteVerification ----------
    // wire = `canonical_vote_payload(121B) ‖ sig(64B)`；签名全 0 ⇒ 结构合法、验证失败。
    let vote = ValidatorVote {
        round: round.round,
        height: round.height,
        target_block_hash: TARGET,
        vote_type: VoteType::Prevote,
        source_block_hash: [0u8; 32],
        validator_id: local_id,
        timestamp: 0,
    };
    let mut wire = canonical_vote_payload(&vote);
    wire.extend_from_slice(&[0u8; 64]);
    inject(&mut tx_b, &net_b, &a_id, MessageType::ConsensusVote, wire);

    rt.step()
        .expect("无效 vote 必须被拒绝而非致命（P1-A.4 语义不变）");
    assert_eq!(
        rt.inbound_consensus_rejected(),
        1,
        "VoteVerification 仍按「拒绝 + 计数」处理（语义保持）"
    );
    assert_eq!(
        rt.derived_qc_not_applicable(),
        0,
        "VoteVerification **不得**被 P1-A.5 的新计数容忍"
    );

    // ---------- ② 被拒 vote 零痕迹（forge 的票不得进入任何 accumulator）+ 节点仍可用 ----------
    // 注：节点在后续 step 会**自主**推进（出块 / commit / advance）—— 那与 forge 的 vote 无关；
    //     因此这里只断言该 vote 自身留下的痕迹为零。
    assert_eq!(
        rt.consensus().state().round.prevotes.weight_of(&TARGET),
        0,
        "被拒 vote 不得在该 round 的 prevote accumulator 中留下任何权重"
    );
    for _ in 0..4 {
        rt.step().expect("节点必须仍可驱动");
    }
    assert_eq!(rt.inbound_consensus_rejected(), 1, "无新命令 ⇒ 计数不变");
    assert_eq!(
        rt.derived_qc_not_applicable(),
        0,
        "本地无派生事件 ⇒ 计数仍 0"
    );
    rt.shutdown().expect("shutdown 必须成功");
}
