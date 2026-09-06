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
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
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
    BoxTransport, ConnectionTarget, MemoryTransport, TcpTransport, Transport,
};

use nova_node::bootstrap::NodeConfig;
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, NodeRuntimeError};

const CHAIN_ID: u64 = 3003;

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
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
    handle.join().unwrap();
    assert_eq!(
        established,
        Some(b_id),
        "configured peer Established（身份一致）"
    );
    // 幂等：再次 establish ⇒ 已完成。
    assert_eq!(rt.establish_configured_peer().unwrap(), Some(b_id));
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
