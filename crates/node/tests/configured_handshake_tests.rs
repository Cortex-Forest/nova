//! Outbound Handshake Initiation（STEP 10-19-10-B7-A1-D5）—— NodeRuntime 端到端集成测试。
//!
//! 验证：auth 装配（peer_auth Some）→ dial → 发送本端 Handshake Init → 对端 process_handshake →
//! 对端回 Init → 本端 Established + configured peer_id 身份一致 → 成功；mismatch ⇒ fail-closed
//! 断开 + typed error；wrong context 不 Established；nonce 每次新。
//! 只到 `Established`（无 retry/timeout/multi-peer/sync）。测试用 localhost TCP（非公网）。

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::message::{MessageEnvelope, MessageType, decode, encode, sign_message};
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_decode, handshake_payload_encode,
    random_session_nonce,
};
use nova_network::transport::{
    BoxTransport, ConnectionTarget, MemoryTransport, TcpDialer, TcpTransport, Transport,
};

use nova_node::bootstrap::NodeConfig;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::{NodeRuntime, NodeRuntimeError, PeerEstablishment, PeerStatus};
use nova_node::sync_correlator::SyncRequestTarget;
use nova_node::sync_dispatch::{NetworkSyncDispatcher, OutboundSyncDispatcher, SyncDispatchResult};
use nova_node::sync_scheduler::SyncRequestIntent;

const CHAIN_ID: u64 = 3003;

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

fn genesis() -> GenesisV1 {
    let validator_vk = KeyPair::generate().unwrap().verifying_key().to_bytes();
    let mut accounts = vec![
        AccountInit {
            address: addr([0x11; 32]),
            liquid_balance: 1_000_000,
        },
        AccountInit {
            address: addr([0x22; 32]),
            liquid_balance: 500_000,
        },
    ];
    accounts.sort_by_key(|a| a.address.payload().to_bytes());
    let total_supply: u128 = accounts.iter().map(|a| a.liquid_balance).sum();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: vec![ValidatorInit {
            account_address: accounts[0].address,
            consensus_public_key: validator_vk,
            bonded_stake: 200_000,
            commission_bps: 0,
        }],
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
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let g = genesis();
        let dir = std::env::temp_dir().join(format!("nova_d5_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(&g).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(&g).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        let safety_dir = dir.join("safety");
        std::fs::create_dir_all(&chain_dir).unwrap();
        std::fs::create_dir_all(&safety_dir).unwrap();
        Self {
            genesis_hash,
            genesis_path,
            chain_dir,
            safety_dir,
        }
    }

    fn config(&self, peers: Vec<ConnectionTarget>) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: false,
            safety_dir: self.safety_dir.clone(),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
        }
    }

    fn auth(&self) -> PeerAuthConfig {
        PeerAuthConfig {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_hash: self.genesis_hash,
            protocol_version: 1,
            capabilities: b"",
            per_peer_handshake_limit: 8,
            global_handshake_limit: 128,
            replay_cache_capacity: 256,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.genesis_path.parent().unwrap());
    }
}

fn start_a(env: &Env, peers: Vec<ConnectionTarget>) -> NodeRuntime {
    let cfg = env.config(peers);
    let kp = KeyPair::generate().unwrap();
    let self_id = NodeId::from_verifying_key(kp.verifying_key());
    let other = NodeId::from_bytes([0x99; 32]);
    let transport: Box<dyn nova_network::transport::Transport> =
        Box::new(MemoryTransport::pair(self_id, other).0);
    let signer: Box<dyn nova_node::network_identity::NetworkSigner> =
        Box::new(SoftwareNetworkIdentity::new(kp));
    NodeRuntime::start_with_network(&cfg, None, transport, signer).expect("start A")
}

/// 由 B 的 key 签名的手握 Init envelope（claimed = B NodeId）。
fn b_init(b_kp: &KeyPair, auth: &PeerAuthConfig) -> MessageEnvelope {
    let local = NodeId::from_verifying_key(b_kp.verifying_key());
    let nonce = random_session_nonce().unwrap();
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
    let mut env = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: local,
        signature: [0u8; 64],
    };
    sign_message(b_kp.signing_key(), &mut env).unwrap();
    env
}

/// 对端 B（纯 transport；不跑 NS）—— reconnect 生命周期测试用：每轮 accept 一条新连接，
/// 读 A 的 Init（记录其 session_nonce）并回 B 的 Init。B 不 process A（A 侧 NS 验证 B Init 即可
/// 使 A Established B）。用于验证 disconnect→reconnect 每轮发出新 nonce 的 Init。
fn run_peer_b_reconnect(
    listener: TcpListener,
    auth: PeerAuthConfig,
    b_kp: KeyPair,
    rounds: usize,
) -> thread::JoinHandle<Vec<[u8; 16]>> {
    thread::spawn(move || {
        let mut nonces = Vec::new();
        for _ in 0..rounds {
            let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
            let Ok(mut tcp) =
                TcpTransport::accept(&listener, b_id, 4096, Some(Duration::from_secs(5)))
            else {
                break;
            };
            let a_id = tcp.peer_id();
            let mut got: Option<Vec<u8>> = None;
            for _ in 0..500 {
                if let Ok(Some((_, frame))) = tcp.try_recv() {
                    got = Some(frame);
                    break;
                }
                thread::yield_now();
            }
            if let Some(frame) = got
                && let Ok(env) = decode(&frame)
                && let Ok(hs) = handshake_payload_decode(&env.payload)
            {
                nonces.push(*hs.session_nonce.as_bytes());
            }
            let _ = tcp.send(&a_id, encode(&b_init(&b_kp, &auth)));
            // keep-alive：等 A 关闭（disconnect_configured_peer / drop）再 accept 下一连接。
            for _ in 0..600 {
                let _ = tcp.try_recv();
                if tcp.is_closed() {
                    break;
                }
                thread::yield_now();
            }
        }
        nonces
    })
}

/// 对端 B（listener 侧）：accept A → 处理 A 的 Init（若 context 匹配则 B 侧 Established A）→
/// 回 B 的 Init。返回是否完成回送。
fn run_peer_b(
    listener: TcpListener,
    auth: PeerAuthConfig,
    b_kp: KeyPair,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
        let tcp = match TcpTransport::accept(&listener, b_id, 4096, Some(Duration::from_secs(5))) {
            Ok(t) => t,
            Err(_) => return,
        };
        let a_id = tcp.peer_id();
        let mut bns = NetworkService::<BoxTransport>::new(
            NetworkServiceConfig {
                peer_auth: Some(auth),
                ..Default::default()
            },
            b_id,
            BoxTransport::new(Box::new(tcp)),
        );
        // 标记 A connected（B 回送需 enqueue_outbound 要求 connected）。
        let _ = bns.connect_peer(a_id);
        // 处理 A 的 Init；仅当 context 匹配 B Established A。
        for _ in 0..200 {
            let _ = bns.poll_transport();
            if bns.is_peer_established(a_id) {
                break;
            }
            thread::yield_now();
        }
        if bns.is_peer_established(a_id) {
            // B 侧已认证 A ⇒ 回 B 的 Init（A 侧将 Established B）。
            let _ = bns.enqueue_outbound(a_id, b_init(&b_kp, &auth));
            let _ = bns.flush_outbound();
        }
        // keep-alive：保持连接直到 A 关闭（EOF）—— 模拟稳定对端（非发完即断）；
        // D7-Implementation-2 EOF 检测下，回送后立即断会让 A 刚 Established 即断开。
        for _ in 0..600 {
            let _ = bns.poll_transport();
            if bns.transport().is_closed() {
                break;
            }
            thread::yield_now();
        }
    })
}

// T1 — auth 装配：网络启用时 peer_auth Some；网络 disabled 时无。
#[test]
fn network_peer_auth_enabled() {
    let env = Env::new();
    let rt = start_a(&env, Vec::new());
    assert!(
        rt.network_peer_auth_enabled(),
        "start_with_network 装配 peer_auth"
    );
    drop(rt);
    // 网络 disabled（start）⇒ 不装配。
    let cfg = env.config(Vec::new());
    let rt2 = NodeRuntime::start(&cfg, None).expect("start no network");
    assert!(
        !rt2.network_peer_auth_enabled(),
        "start（无网络）不装配 peer_auth"
    );
}

// T6 — nonce 每次新（OS CSPRNG）
#[test]
fn handshake_nonce_unique_per_init() {
    let a = random_session_nonce().unwrap();
    let b = random_session_nonce().unwrap();
    assert_ne!(a, b, "每次 outbound Init 新 nonce");
}

// T3 — valid remote identity：A dial→发 Init→B 认证 A→回 Init→A Established B（身份一致）
#[test]
fn valid_remote_establishes_configured_peer() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let auth = env.auth();
    let handle = run_peer_b(listener, auth, b_kp);

    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
    );
    // 有界推进（幂等：不重 dial / 不重发 Init；只 poll 推进）。
    let mut established = None;
    for _ in 0..500 {
        match rt.establish_configured_peer() {
            Ok(Some(p)) => {
                established = Some(p);
                break;
            }
            Ok(None) => thread::yield_now(),
            Err(e) => panic!("establish error: {e:?}"),
        }
    }
    assert_eq!(
        established,
        Some(b_id),
        "configured peer Established（身份一致）"
    );
    // 幂等：再次 establish ⇒ 已完成。
    assert_eq!(rt.establish_configured_peer().unwrap(), Some(b_id));
    // B 为稳定对端（keep-alive）：关闭 A 连接后 B 检测 EOF 退出。
    drop(rt);
    handle.join().unwrap();
}

// T4 — identity mismatch：configured = C，实际对端 = B ⇒ **fail-closed（绝不误认证）**。
// 单连接 dial 模型：A transport 身份 label = 期望 peer（C）；真实对端 B 的握手帧因
// `envelope.sender(B) != raw_sender(label=C)` 被 NetworkService sender 校验静默拒绝 ⇒ C 永不
// Established（address 正确 ≠ identity 正确；不会把 B 当 C 信任）。显式 IdentityMismatch 错误
// 分支（`established_peers` foreign）在 listener/inbound 场景可观测，属防御性保留。
#[test]
fn identity_mismatch_fail_closed() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let wrong_cfg = NodeId::from_bytes([0x0c; 32]); // configured 声称 C ≠ 实际 B
    let handle = run_peer_b(listener, env.auth(), b_kp);

    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: wrong_cfg,
            address: laddr,
        }],
    );
    // 有界推进：configured C 绝不能 Established（错身份对端不获信任）。
    for _ in 0..200 {
        match rt.establish_configured_peer() {
            Ok(None) => thread::yield_now(),
            Ok(Some(p)) => {
                panic!("不应成功（configured {wrong_cfg:?} ≠ 实际 {b_id:?}），却返回 {p:?}")
            }
            Err(e) => panic!("establish error: {e:?}"),
        }
    }
    // 关闭 A 连接 → B keep-alive 检测 EOF 退出。
    drop(rt);
    handle.join().unwrap();
    // fail-closed 达成：configured C 从未 Established（无 Ok(Some) 触发过 panic）。
}

// T5 — wrong chain context：B 用不匹配的 auth ⇒ A 的 Init 被拒 ⇒ 不 Established（pending）
#[test]
fn wrong_context_not_established() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    // B 端错误 chain_id（A 用正确 chain —— 双方 context 不一致）。
    let mut bad_auth = env.auth();
    bad_auth.chain_id = CHAIN_ID + 1;
    let handle = run_peer_b(listener, bad_auth, b_kp);

    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
    );
    // 有界：B 拒 A Init（不 Established A → 不回）⇒ A 永远收不到 B 握手 ⇒ pending（不 Established）。
    for _ in 0..200 {
        match rt.establish_configured_peer() {
            Ok(None) => thread::yield_now(),
            Ok(Some(p)) => {
                panic!("wrong context 不应 Established（got {p:?}）");
            }
            Err(e) => panic!("establish error: {e:?}"),
        }
    }
    // 关闭 A 连接 → B keep-alive 检测 EOF 退出。
    drop(rt);
    handle.join().unwrap();
    // wrong chain context ⇒ configured peer 从未 Established（未触发任何 Ok(Some) panic）。
}

// T9 — self peer 保持 fail-closed（启动即拒；A3 语义）
#[test]
fn self_peer_rejected_at_startup() {
    let env = Env::new();
    let kp = KeyPair::generate().unwrap();
    let self_id = NodeId::from_verifying_key(kp.verifying_key());
    let cfg = env.config(vec![ConnectionTarget {
        peer_id: self_id,
        address: SocketAddr::from(([127, 0, 0, 1], 1)),
    }]);
    let other = NodeId::from_bytes([0x77; 32]);
    let transport: Box<dyn nova_network::transport::Transport> =
        Box::new(MemoryTransport::pair(self_id, other).0);
    let signer: Box<dyn nova_node::network_identity::NetworkSigner> =
        Box::new(SoftwareNetworkIdentity::new(kp));
    let res = NodeRuntime::start_with_network(&cfg, None, transport, signer);
    assert!(matches!(
        res,
        Err(NodeRuntimeError::NetworkTarget(
            nova_node::bootstrap::ConnectionTargetError::SelfTarget { .. }
        ))
    ));
}

// T5/T6/T7 — disconnect 清状态 + reconnect（L5/L6）：Established → disconnect → 再 establish
// （新 dial + 新 nonce + 新 Init）→ Established；两轮 Init nonce 不同；Established 幂等。
#[test]
fn disconnect_then_reconnect_establishes_with_new_nonce() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let rounds = 2;
    let handle = run_peer_b_reconnect(listener, env.auth(), b_kp, rounds);

    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
    );
    for round in 0..rounds {
        let mut done = false;
        for _ in 0..800 {
            match rt.establish_configured_peer() {
                Ok(Some(p)) => {
                    assert_eq!(p, b_id);
                    done = true;
                    break;
                }
                Ok(None) => thread::yield_now(),
                Err(e) => panic!("establish error round {round}: {e:?}"),
            }
        }
        assert!(done, "round {round} 应 Established");
        if round + 1 < rounds {
            rt.disconnect_configured_peer().expect("disconnect ok");
        }
    }
    // L3 — Established 幂等：再调 establish 直接成功（不重 dial / 不重发 Init）。
    assert_eq!(rt.establish_configured_peer().unwrap(), Some(b_id));
    // B keep-alive：关闭 A 使 B 最后轮退出。
    drop(rt);
    let nonces = handle.join().unwrap();
    assert_eq!(nonces.len(), rounds, "每轮收到一次 A Init（无重复发送）");
    assert_ne!(
        nonces[0], nonces[1],
        "reconnect 必须新 nonce（handshake_init_sent_for 已清）"
    );
}

// T9 — dial 失败不自动 retry / 不自动 switch（typed 错误；不 Established）。
#[test]
fn dial_failure_no_auto_retry() {
    let env = Env::new();
    let b_id = NodeId::from_bytes([0x0b; 32]);
    // localhost 未监听端口（非公网；connect 快速 refused）。
    let laddr = SocketAddr::from(([127, 0, 0, 1], 1));
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
    );
    let res = rt.establish_configured_peer();
    assert!(
        res.is_err(),
        "dial 失败 typed error（不 Established / 不静默成功）"
    );
    // 显式再次调用（非自动 retry）仍不成功（不自动转 Ok(Some) / 不自动换 peer）。
    let res2 = rt.establish_configured_peer();
    assert!(res2.is_err(), "不自动 retry / 不自动 switch");
}

// ===== STEP 10-19-10-B7-A1-D7-Implementation-3：Node Runtime Multi-Configured Peer =====

/// 建一个正常对端（run_peer_b：accept → 处理 A Init → 回 B Init → keep-alive）。
fn spawn_peer_b(env: &Env) -> (SocketAddr, NodeId, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let handle = run_peer_b(listener, env.auth(), b_kp);
    (laddr, b_id, handle)
}

/// 无效地址（localhost 未监听 ⇒ dial 快速 refused）。
fn bad_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1))
}

/// 反复调用 `establish_configured_peers` 直至无 Pending（Established/Failed 即 settle）。
/// 返回最后一次 per-peer 结果。不含任何 sleep / retry 语义 —— 纯多次显式调用驱动 poll。
fn drive_until_settled(rt: &mut NodeRuntime, budget: usize) -> Vec<PeerEstablishment> {
    let mut last = rt.establish_configured_peers().expect("poll 无全局错误");
    for _ in 0..budget {
        if last
            .iter()
            .all(|e| !matches!(e.status, PeerStatus::Pending))
        {
            break;
        }
        last = rt.establish_configured_peers().expect("poll 无全局错误");
    }
    last
}

// T1 — no configured peers：空 peers ⇒ 空结果；无 panic / 无 dial。
#[test]
fn d7_3_no_configured_peers() {
    let env = Env::new();
    let mut rt = start_a(&env, Vec::new());
    let res = rt.establish_configured_peers().expect("正常返回");
    assert!(res.is_empty(), "T1 no configured peers ⇒ empty");
}

// T2 — single peer regression：multi 方法对单 configured peer 行为与既有一致。
#[test]
fn d7_3_single_peer_regression_via_multi() {
    let env = Env::new();
    let (addr, b_id, handle) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: addr,
        }],
    );
    let res = drive_until_settled(&mut rt, 500);
    assert_eq!(res.len(), 1);
    assert!(
        matches!(res[0].status, PeerStatus::Established),
        "T2 single peer Established: {res:?}"
    );
    assert!(rt.network_peer_established(b_id));
    drop(rt);
    handle.join().unwrap();
}

// T3/T4 — two / three peers establish independently（各对端正常）。
#[test]
fn d7_3_two_peers_establish_independently() {
    let env = Env::new();
    let (addr1, id1, h1) = spawn_peer_b(&env);
    let (addr2, id2, h2) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![
            ConnectionTarget {
                peer_id: id1,
                address: addr1,
            },
            ConnectionTarget {
                peer_id: id2,
                address: addr2,
            },
        ],
    );
    let res = drive_until_settled(&mut rt, 800);
    assert_eq!(res.len(), 2);
    assert!(
        matches!(res[0].status, PeerStatus::Established),
        "T3 peer1 Established: {res:?}"
    );
    assert!(
        matches!(res[1].status, PeerStatus::Established),
        "T3 peer2 Established: {res:?}"
    );
    assert!(rt.network_peer_established(id1) && rt.network_peer_established(id2));
    drop(rt);
    h1.join().unwrap();
    h2.join().unwrap();
}

#[test]
fn d7_3_three_peers_establish_independently() {
    let env = Env::new();
    let mut peers = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let (addr, id, h) = spawn_peer_b(&env);
        peers.push(ConnectionTarget {
            peer_id: id,
            address: addr,
        });
        handles.push(h);
    }
    let mut rt = start_a(&env, peers);
    let res = drive_until_settled(&mut rt, 1000);
    assert_eq!(res.len(), 3);
    assert!(
        res.iter()
            .all(|e| matches!(e.status, PeerStatus::Established)),
        "T4 all three Established: {res:?}"
    );
    for h in handles {
        h.join().unwrap();
    }
    drop(rt);
}

// T5 — first peer dial failure 不阻塞 second peer 建立（最重要隔离测试之一）。
#[test]
fn d7_3_first_peer_failure_does_not_block_second() {
    let env = Env::new();
    let fail_id = NodeId::from_bytes([0x0a; 32]);
    let (addr_b, b_id, handle_b) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![
            ConnectionTarget {
                peer_id: fail_id,
                address: bad_addr(),
            },
            ConnectionTarget {
                peer_id: b_id,
                address: addr_b,
            },
        ],
    );
    let res = drive_until_settled(&mut rt, 500);
    assert_eq!(res.len(), 2);
    assert!(
        matches!(res[0].status, PeerStatus::Failed(_)),
        "T5 peer A dial failure recorded, not blocking others: {res:?}"
    );
    assert!(
        matches!(res[1].status, PeerStatus::Established),
        "T5 peer B still Established despite A failure: {res:?}"
    );
    assert!(rt.network_peer_established(b_id));
    drop(rt);
    handle_b.join().unwrap();
}

// T6 — middle peer failure 不阻塞后序 peer。
#[test]
fn d7_3_middle_peer_failure_does_not_block_later() {
    let env = Env::new();
    let fail_id = NodeId::from_bytes([0x0b; 32]);
    let (addr1, id1, h1) = spawn_peer_b(&env);
    let (addr3, id3, h3) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![
            ConnectionTarget {
                peer_id: id1,
                address: addr1,
            },
            ConnectionTarget {
                peer_id: fail_id,
                address: bad_addr(),
            },
            ConnectionTarget {
                peer_id: id3,
                address: addr3,
            },
        ],
    );
    let res = drive_until_settled(&mut rt, 800);
    assert_eq!(res.len(), 3);
    assert!(matches!(res[0].status, PeerStatus::Established), "{res:?}");
    assert!(matches!(res[1].status, PeerStatus::Failed(_)), "{res:?}");
    assert!(matches!(res[2].status, PeerStatus::Established), "{res:?}");
    drop(rt);
    h1.join().unwrap();
    h3.join().unwrap();
}

// T7 — 已 Established 的 peer 在再次 orchestration 中不被重 dial / 重 Init；其它 peer 仍可建立。
#[test]
fn d7_3_established_peer_not_redialed_while_other_establishes() {
    let env = Env::new();
    let (addr_a, a_id, h_a) = spawn_peer_b(&env);
    let (addr_b, b_id, h_b) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![
            ConnectionTarget {
                peer_id: a_id,
                address: addr_a,
            },
            ConnectionTarget {
                peer_id: b_id,
                address: addr_b,
            },
        ],
    );
    let res = drive_until_settled(&mut rt, 800);
    assert!(matches!(res[0].status, PeerStatus::Established), "{res:?}");
    assert!(matches!(res[1].status, PeerStatus::Established), "{res:?}");
    // 再次 orchestration：A/B 均 Established（不重 dial —— 对端只 accept 一次仍成立）。
    let again = rt.establish_configured_peers().expect("poll ok");
    assert!(
        matches!(again[0].status, PeerStatus::Established),
        "{again:?}"
    );
    assert!(
        matches!(again[1].status, PeerStatus::Established),
        "{again:?}"
    );
    assert!(rt.network_peer_connected(a_id) && rt.network_peer_established(a_id));
    drop(rt);
    h_a.join().unwrap();
    h_b.join().unwrap();
}

// T8 — disconnect 隔离：disconnect(A) 只清 A；B/C Established 保留。
#[test]
fn d7_3_disconnect_isolation_among_three() {
    let env = Env::new();
    let mut peers = Vec::new();
    let mut handles = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (addr, id, h) = spawn_peer_b(&env);
        peers.push(ConnectionTarget {
            peer_id: id,
            address: addr,
        });
        handles.push(h);
        ids.push(id);
    }
    let mut rt = start_a(&env, peers);
    let res = drive_until_settled(&mut rt, 1000);
    assert!(
        res.iter()
            .all(|e| matches!(e.status, PeerStatus::Established))
    );
    // 断 A（ids[0]）。
    rt.disconnect_configured_peer_for(ids[0])
        .expect("disconnect ok");
    assert!(!rt.network_peer_connected(ids[0]), "T8 A disconnected");
    assert!(
        !rt.network_peer_established(ids[0]),
        "T8 A 不再 Established"
    );
    assert!(rt.network_peer_established(ids[1]), "T8 B 保留");
    assert!(rt.network_peer_established(ids[2]), "T8 C 保留");
    assert!(rt.network_peer_connected(ids[1]) && rt.network_peer_connected(ids[2]));
    drop(rt);
    for h in handles {
        h.join().unwrap();
    }
}

// T9 — 显式 reconnect：EOF/断开 A → 再次显式 orchestration ⇒ A 重新 Established。
#[test]
fn d7_3_explicit_reconnect_after_disconnect() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    // 对端 accept 两轮（reconnect 需第二轮 accept）。
    let handle = run_peer_b_reconnect(listener, env.auth(), b_kp, 2);
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
    );
    // 第一轮：Established。
    let mut done = false;
    for _ in 0..800 {
        let res = rt.establish_configured_peers().expect("poll ok");
        if matches!(res[0].status, PeerStatus::Established) {
            done = true;
            break;
        }
    }
    assert!(done, "第一轮 Established");
    // 断开 A。
    rt.disconnect_configured_peer_for(b_id)
        .expect("disconnect ok");
    assert!(!rt.network_peer_connected(b_id));
    // 显式再次 orchestration ⇒ 重建（新连接）。
    let mut redone = false;
    for _ in 0..800 {
        let res = rt.establish_configured_peers().expect("poll ok");
        if matches!(res[0].status, PeerStatus::Established) {
            redone = true;
            break;
        }
    }
    assert!(redone, "T9 explicit reconnect re-Established");
    assert!(rt.network_peer_established(b_id));
    drop(rt);
    let nonces = handle.join().unwrap();
    assert_eq!(nonces.len(), 2, "每轮一次 Init（无自动重复）");
    assert_ne!(nonces[0], nonces[1], "reconnect 新 nonce");
}

// T10 — no automatic retry：dial 失败即 Failed；不会内部自动重试成功 / 等待 timer。
#[test]
fn d7_3_no_automatic_retry_on_dial_failure() {
    let env = Env::new();
    let fail_id = NodeId::from_bytes([0x0c; 32]);
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: fail_id,
            address: bad_addr(),
        }],
    );
    // 单次 orchestration 调用（不循环）：dial 失败 ⇒ Failed（不 hang / 不内部 retry）。
    let res = rt.establish_configured_peers().expect("调用返回");
    assert_eq!(res.len(), 1);
    assert!(
        matches!(res[0].status, PeerStatus::Failed(_)),
        "T10 dial failure ⇒ Failed once（无自动 retry）: {res:?}"
    );
    // 显式再次调用仍 Failed（不自动转成功 / 不自动换 peer）。
    let res2 = rt.establish_configured_peers().expect("调用返回");
    assert!(matches!(res2[0].status, PeerStatus::Failed(_)));
}

// T11 — handshake idempotency per peer：A/B Established 后重复 orchestration ⇒
// 不重复 Init（对端只 accept 一次仍 Established 保留）、A 状态不影响 B。
#[test]
fn d7_3_handshake_idempotent_per_peer() {
    let env = Env::new();
    let (addr_a, a_id, h_a) = spawn_peer_b(&env);
    let (addr_b, b_id, h_b) = spawn_peer_b(&env);
    let mut rt = start_a(
        &env,
        vec![
            ConnectionTarget {
                peer_id: a_id,
                address: addr_a,
            },
            ConnectionTarget {
                peer_id: b_id,
                address: addr_b,
            },
        ],
    );
    let res = drive_until_settled(&mut rt, 800);
    assert!(
        res.iter()
            .all(|e| matches!(e.status, PeerStatus::Established))
    );
    // 重复 orchestration：两 peer 均 Established（幂等；不因 A 状态跳过 B / 反之）。
    for _ in 0..5 {
        let again = rt.establish_configured_peers().expect("poll ok");
        assert_eq!(again.len(), 2);
        assert!(
            matches!(again[0].status, PeerStatus::Established),
            "{again:?}"
        );
        assert!(
            matches!(again[1].status, PeerStatus::Established),
            "{again:?}"
        );
    }
    drop(rt);
    h_a.join().unwrap();
    h_b.join().unwrap();
}

// ===== STEP 10-19-10-B7-A1-D8-2：outbound sync orchestration（生产 adapter 集成）=====

/// A 的 outbound Handshake Init（claimed = A network NodeId；仿 runtime build_outbound_handshake）。
fn a_signed_init(signer: &dyn NetworkSigner, auth: &PeerAuthConfig) -> MessageEnvelope {
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
    let mut env = MessageEnvelope {
        version: 1,
        message_type: MessageType::Handshake,
        payload,
        sender: local,
        signature: [0u8; 64],
    };
    signer.sign_envelope(&mut env).unwrap();
    env
}

fn sync_intent_for(peer: NodeId, height: u64) -> SyncRequestIntent {
    SyncRequestIntent {
        request_id: nova_network::security::random_request_id().unwrap(),
        peer,
        target: SyncRequestTarget {
            height,
            block_hash: None,
        },
    }
}

/// A 裸 NetworkService（不经 runtime）：dial 每个对端（listener 已由 run_peer_b 监听）→
/// 发 A Init → poll 至 Established。返回 (ns, signer)。不拥有 transport（NS owner）。
fn a_ns_established(
    env: &Env,
    a_kp: KeyPair,
    targets: &[(SocketAddr, NodeId)],
) -> (NetworkService<BoxTransport>, Box<dyn NetworkSigner>) {
    let a_id = NodeId::from_verifying_key(a_kp.verifying_key());
    let other = NodeId::from_bytes([0x99; 32]);
    let transport: Box<dyn Transport> = Box::new(MemoryTransport::pair(a_id, other).0);
    let signer: Box<dyn NetworkSigner> = Box::new(SoftwareNetworkIdentity::new(a_kp));
    let mut ns = NetworkService::<BoxTransport>::new(
        NetworkServiceConfig {
            peer_auth: Some(env.auth()),
            ..Default::default()
        },
        a_id,
        BoxTransport::new(transport),
    )
    .with_dialer(Box::new(TcpDialer));
    for (addr, b_id) in targets {
        let max_frame = ns.config().max_msg_bytes;
        ns.dial_peer(*addr, *b_id, max_frame, None).unwrap();
        let init = a_signed_init(signer.as_ref(), &env.auth());
        ns.enqueue_outbound(*b_id, init).unwrap();
        ns.flush_outbound().unwrap();
        let mut done = false;
        for _ in 0..1000 {
            ns.poll_transport().unwrap();
            if ns.is_peer_established(*b_id) {
                done = true;
                break;
            }
            thread::yield_now();
        }
        assert!(done, "A 应 Established peer {b_id:?}");
    }
    (ns, signer)
}

// T6/T7 — adapter：Established peer ⇒ SyncBlockRequest → envelope → enqueue_outbound（Sent）；
// 未 Established/未连接 peer ⇒ no send（Rejected）。
#[test]
fn d8_2_sync_dispatcher_established_gate_and_send() {
    let env = Env::new();
    let a_kp = KeyPair::generate().unwrap();
    let (addr_b, b_id, h_b) = spawn_peer_b(&env);
    let (mut ns, signer) = a_ns_established(&env, a_kp, &[(addr_b, b_id)]);
    {
        let mut d = NetworkSyncDispatcher::new(&mut ns, signer.as_ref());
        // T7 — Established B ⇒ Sent（SyncBlockRequest 经签名 → enqueue_outbound）。
        let it_b = sync_intent_for(b_id, 101);
        assert_eq!(
            d.dispatch(&it_b),
            SyncDispatchResult::Sent,
            "T7 Established peer send"
        );
        // T6 — 未连接 / 未 Established peer ⇒ Rejected（no outbound send）。
        let d_id = NodeId::from_bytes([0xdd; 32]);
        let it_d = sync_intent_for(d_id, 101);
        assert_eq!(
            d.dispatch(&it_d),
            SyncDispatchResult::Rejected,
            "T6 un-established peer rejected"
        );
    }
    drop(ns);
    drop(signer);
    h_b.join().unwrap();
}

// T8/T9 — 多 peer 各自可达（deterministic selection 由 scheduler tests 覆盖）；disconnect 隔离。
#[test]
fn d8_2_sync_dispatcher_multi_peer_disconnect_isolation() {
    let env = Env::new();
    let a_kp = KeyPair::generate().unwrap();
    let (addr_b, b_id, h_b) = spawn_peer_b(&env);
    let (addr_c, c_id, h_c) = spawn_peer_b(&env);
    let (mut ns, signer) = a_ns_established(&env, a_kp, &[(addr_b, b_id), (addr_c, c_id)]);
    // T8 — B、C 两个 Established peer 各自 dispatch 成功（多 peer 不互相干扰）。
    {
        let mut d = NetworkSyncDispatcher::new(&mut ns, signer.as_ref());
        assert_eq!(
            d.dispatch(&sync_intent_for(b_id, 101)),
            SyncDispatchResult::Sent
        );
        assert_eq!(
            d.dispatch(&sync_intent_for(c_id, 102)),
            SyncDispatchResult::Sent
        );
    }
    // T9 — disconnect B ⇒ B Rejected；C 仍 Established ⇒ Sent（单 peer 失败不破坏其它）。
    ns.disconnect_peer(b_id).unwrap();
    assert!(!ns.is_peer_established(b_id));
    assert!(ns.is_peer_established(c_id), "C 不受 B 断开影响");
    {
        let mut d = NetworkSyncDispatcher::new(&mut ns, signer.as_ref());
        assert_eq!(
            d.dispatch(&sync_intent_for(b_id, 103)),
            SyncDispatchResult::Rejected,
            "T9 disconnected B rejected"
        );
        assert_eq!(
            d.dispatch(&sync_intent_for(c_id, 104)),
            SyncDispatchResult::Sent,
            "T9 healthy C still sent"
        );
    }
    drop(ns);
    drop(signer);
    h_b.join().unwrap();
    h_c.join().unwrap();
}
