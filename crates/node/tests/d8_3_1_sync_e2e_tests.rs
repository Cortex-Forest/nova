//! D8-3-1.1：Runtime Sync Request E2E test seam —— 解锁 D8-3-1 T11。
//!
//! 用**真实生产链**验证 sync request lifecycle：
//! A（validator-mode NodeRuntime + NetworkService）↔ B（Programmable Peer：真实 TCP +
//! 手工 signed envelope）：
//!   B 注入合法 future GossipBlock → A Runtime.step → FutureMissingAncestor → Ledger →
//!   Scheduler → Correlator.register → Dispatcher → NetworkService outbound（SyncBlockRequest）
//!   → B 捕获 → 读 request_id → 回 SyncBlockResponse（同 id）→ A inbound → Correlator.resolve
//!   → active 释放；canonical head / state root 不变（无提前 commit）。
//!
//! 使用真实 NodeRuntime / SyncRequestScheduler / SyncRequestCorrelator /
//! NetworkSyncDispatcher。测试专用线程 = TCP 对端 fixture（既有 configured 测试同款；非生产）。
//!
//! 禁止：response persistence / apply_block / commit / retry / timeout 策略修改 / async。

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
use nova_network::message::{MessageEnvelope, MessageType, decode, encode};
use nova_network::node_id::NodeId;
use nova_network::security::RequestId;
use nova_network::session::{
    HandshakeKind, PeerAuthConfig, handshake_payload_encode, random_session_nonce,
};
use nova_network::sync::{SyncBlockRequest, SyncBlockResponse};
use nova_network::transport::{ConnectionTarget, MemoryTransport, TcpTransport, Transport};

use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::SoftwareKeyProvider;
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::NodeRuntime;

const CHAIN_ID: u64 = 1001;
/// 本轮 poll / 驱动迭代上限（bounded；防无限 loop）。
const MAX_ITER: usize = 600;

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// TEST GENESIS ONLY：validator pubkey = A 的 validator key（NodeRuntime validator mode 装配）。
fn genesis_for(pk: [u8; 32]) -> GenesisV1 {
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
            consensus_public_key: pk,
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

/// 临时目录 fixture（validator genesis 写入 + 清理）。
struct Env {
    dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
    safety_dir: PathBuf,
}

impl Env {
    /// `validator_kp` 的公钥必须为 genesis validator pubkey（provider 用同 key 装配）。
    fn new(validator_kp: &KeyPair) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let genesis = genesis_for(validator_kp.verifying_key().to_bytes());
        let dir = std::env::temp_dir().join(format!("nova_d8311_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(&genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(&genesis).unwrap()).unwrap();
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

    fn config(&self, peers: Vec<ConnectionTarget>) -> NodeConfig {
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
        }
    }

    /// peer-auth（A runtime 装配值：Mainnet / CHAIN_ID / genesis / protocol 1 / 空 caps）。
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
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 用 signer 构造 outbound Handshake Init（claimed = signer.node_id()）。
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

/// 真实 future block（height 2 > genesis head(0)+1 ⇒ FutureMissingAncestor；
/// 无需 proposer/state 校验 —— validate_block_inbound ⑥ 分支即返回）。payload = encode_block。
fn future_gossip_bytes() -> Vec<u8> {
    let body = nova_runtime::BlockBody { txs: Vec::new() };
    let header = nova_runtime::BlockHeader {
        version: nova_runtime::BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 2,
        parent_hash: [0u8; 32],
        finality_reference: None,
        transaction_root: nova_runtime::compute_transaction_root(&body),
        state_root: [0u8; 32],
        validator_set_hash: [0u8; 32],
        timestamp: 1,
    };
    nova_runtime::encode_block(&nova_runtime::Block {
        header,
        body,
        proposer_signature: [0u8; 64],
    })
    .unwrap()
}

/// A 的 validator + network runtime（validator mode + NetworkService + configured peers）。
fn start_a(
    env: &Env,
    peers: Vec<ConnectionTarget>,
    net_kp: KeyPair,
    validator_kp: KeyPair,
) -> NodeRuntime {
    let cfg = env.config(peers);
    let provider = SoftwareKeyProvider::from_keypair(validator_kp);
    let a_id = NodeId::from_verifying_key(net_kp.verifying_key());
    let transport: Box<dyn nova_network::transport::Transport> =
        Box::new(MemoryTransport::pair(a_id, NodeId::from_bytes([0x99; 32])).0);
    let identity: Box<dyn NetworkSigner> = Box::new(SoftwareNetworkIdentity::new(net_kp));
    NodeRuntime::start_with_network(&cfg, Some(&provider), transport, identity).expect("A start")
}

/// Programmable Peer B 的可观测结果（B 线程写入）。
#[derive(Default)]
struct PeerOutcome {
    /// B 捕获到的 SyncBlockRequest request_id（request 已被 A 生产发出）。
    request_id: Option<RequestId>,
    request_height: Option<u64>,
    /// B 已回 response（同 request_id）。
    response_sent: bool,
    /// B 已重发同 response（duplicate）。
    duplicate_sent: bool,
}

/// Programmable Peer B：真实 TCP server 线程（纯 transport + 手工 signed envelope）。
/// 阶段（`phase` 由主线程推进）：
///   0 = 握手（accept → 读 A Init → 回 B Init）；
///   1 = 主线程确认 A Established B ⇒ B 发 future GossipBlock；
///   2 = 主线程确认 active==1 ⇒ B 回 SyncBlockResponse（同 request_id）；
///   3 = 主线程确认 resolve ⇒ B 重发同 response（duplicate）。
fn run_peer_b(
    listener: TcpListener,
    auth: PeerAuthConfig,
    b_kp: KeyPair,
    phase: Arc<Mutex<u8>>,
    outcome: Arc<Mutex<PeerOutcome>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
        let signer = SoftwareNetworkIdentity::new(b_kp);
        let mut tcp =
            match TcpTransport::accept(&listener, b_id, 1024 * 1024, Some(Duration::from_secs(10)))
            {
                Ok(t) => t,
                Err(_) => return,
            };
        let a_id = tcp.peer_id();
        // 握手：读 A 的 Init（A establish 已发）→ 回 B Init（A 侧 process ⇒ A Established B）。
        let mut got_init = false;
        for _ in 0..MAX_ITER {
            if let Ok(Some((_, _bytes))) = tcp.try_recv() {
                got_init = true;
                break;
            }
        }
        assert!(got_init, "B 应收到 A 的 Handshake Init");
        let _ = tcp.send(&a_id, encode(&init_envelope(&signer, &auth)));
        // phase 1：主线程确认 A Established B ⇒ B 注入 future block（Gossip）。
        wait_phase(&phase, 1);
        let mut future = MessageEnvelope {
            version: 1,
            message_type: MessageType::GossipBlock,
            payload: future_gossip_bytes(),
            sender: b_id,
            signature: [0u8; 64],
        };
        signer.sign_envelope(&mut future).unwrap();
        let _ = tcp.send(&a_id, encode(&future));
        // 轮询捕获 A 的 SyncBlockRequest（对端关闭 / 超预算 ⇒ graceful 结束，避免后台 panic）。
        let mut captured: Option<(RequestId, u64)> = None;
        for _ in 0..MAX_ITER {
            if tcp.is_closed() {
                return;
            }
            let got = match tcp.try_recv() {
                Ok(Some((_, bytes))) => decode(&bytes)
                    .ok()
                    .filter(|e| e.message_type == MessageType::SyncBlockRequest),
                _ => None,
            };
            if let Some(env) = got
                && let Ok(req) = SyncBlockRequest::decode(&env.payload)
            {
                captured = Some((req.request_id, req.height));
                break;
            }
        }
        let (rid, rheight) = match captured {
            Some(x) => x,
            None => return, // 无 request（A 未驱动 / 已关闭）：静默结束（主线程断言兜底）。
        };
        {
            let mut o = outcome.lock().unwrap();
            o.request_id = Some(rid);
            o.request_height = Some(rheight);
        }
        // phase 2：主线程确认 A active==1 ⇒ B 回 response（同 request_id；blocks 空 = 最小合法）。
        wait_phase(&phase, 2);
        let response = SyncBlockResponse {
            request_id: rid,
            blocks: Vec::new(),
        };
        let mut resp_env = MessageEnvelope {
            version: 1,
            message_type: MessageType::SyncBlockResponse,
            payload: response.encode(),
            sender: b_id,
            signature: [0u8; 64],
        };
        signer.sign_envelope(&mut resp_env).unwrap();
        let _ = tcp.send(&a_id, encode(&resp_env));
        outcome.lock().unwrap().response_sent = true;
        // phase 3：主线程确认 resolve ⇒ 重发同 response（duplicate）。
        wait_phase(&phase, 3);
        let _ = tcp.send(&a_id, encode(&resp_env));
        outcome.lock().unwrap().duplicate_sent = true;
        // phase 4：主线程确认 duplicate 拒 ⇒ 发一个**从未 register** 的 unknown response（T11-A）。
        wait_phase(&phase, 4);
        let unknown = SyncBlockResponse {
            request_id: RequestId::from_bytes([0xAB; 16]),
            blocks: Vec::new(),
        };
        let mut unknown_env = MessageEnvelope {
            version: 1,
            message_type: MessageType::SyncBlockResponse,
            payload: unknown.encode(),
            sender: b_id,
            signature: [0u8; 64],
        };
        signer.sign_envelope(&mut unknown_env).unwrap();
        let _ = tcp.send(&a_id, encode(&unknown_env));
    })
}

/// 自旋等待 phase（bounded；每轮 ~1ms —— 测试后台线程 fixture）。
fn wait_phase(phase: &Arc<Mutex<u8>>, want: u8) {
    for _ in 0..MAX_ITER * 10 {
        if *phase.lock().unwrap() >= want {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("wait_phase({want}) 超时（bounded）");
}

// ===== 握手 smoke：验证 validator-mode + NetworkService + TCP Established 组合可行 =====
#[test]
fn d8_3_1_1_fixture_smoke_established() {
    let vk = KeyPair::generate().unwrap();
    let env = Env::new(&vk);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let phase = Arc::new(Mutex::new(0u8));
    let outcome = Arc::new(Mutex::new(PeerOutcome::default()));
    let handle = run_peer_b(listener, env.auth(), b_kp, phase.clone(), outcome.clone());

    let a_net_kp = KeyPair::generate().unwrap();
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
        a_net_kp,
        vk,
    );
    assert!(rt.validator_enabled(), "validator mode");
    assert!(rt.network_peer_auth_enabled(), "network peer-auth 装配");

    let mut established = false;
    for _ in 0..MAX_ITER {
        let res = rt.establish_configured_peers().expect("establish ok");
        if matches!(res[0].status, nova_node::runtime::PeerStatus::Established) {
            established = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(established, "A Established B（smoke）");
    assert!(rt.network_peer_established(b_id));
    // 关停：phase 置顶使 B 结束等待（避免挂死 join）。
    *phase.lock().unwrap() = 99;
    drop(rt);
    let _ = handle.join();
}

// ===== D8-3-1 T11：真实 Runtime E2E —— future block → request → response → resolve =====
#[test]
fn d8_3_1_t11_runtime_sync_request_response_correlation() {
    let vk = KeyPair::generate().unwrap();
    let env = Env::new(&vk);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let laddr = listener.local_addr().unwrap();
    let b_kp = KeyPair::generate().unwrap();
    let b_id = NodeId::from_verifying_key(b_kp.verifying_key());
    let phase = Arc::new(Mutex::new(0u8));
    let outcome = Arc::new(Mutex::new(PeerOutcome::default()));
    let handle = run_peer_b(listener, env.auth(), b_kp, phase.clone(), outcome.clone());

    let a_net_kp = KeyPair::generate().unwrap();
    let mut rt = start_a(
        &env,
        vec![ConnectionTarget {
            peer_id: b_id,
            address: laddr,
        }],
        a_net_kp,
        vk,
    );
    // STEP1/2 — A validator + head（genesis）；Established B。
    let head_before = {
        let a = rt.block_production().expect("validator adapter");
        (a.head().block_hash, a.head().height, a.store().state_root())
    };
    let mut established = false;
    for _ in 0..MAX_ITER {
        let res = rt.establish_configured_peers().expect("establish ok");
        if matches!(res[0].status, nova_node::runtime::PeerStatus::Established) {
            established = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(established, "STEP2 A Established B");
    assert!(rt.network_peer_established(b_id));
    // STEP3/4/5 — 让 B 发 future block；A step 推进（FutureMissingAncestor → ledger → sync → request）。
    *phase.lock().unwrap() = 1;
    let mut request_captured = false;
    for _ in 0..MAX_ITER {
        rt.step().expect("step ok");
        if outcome.lock().unwrap().request_id.is_some() {
            request_captured = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        request_captured,
        "STEP5 B 捕获 SyncBlockRequest（真实 dispatcher 产出）"
    );
    // STEP6 — request_id 16 bytes（生产 RequestId）。
    let rid = outcome.lock().unwrap().request_id.expect("rid");
    assert_eq!(rid.as_bytes().len(), 16, "STEP6 request_id = 16B");
    assert_eq!(
        outcome.lock().unwrap().request_height,
        Some(1),
        "target.height = local_head(0) + 1"
    );
    // STEP7 — Correlator active == 1（request 已 register，尚未 resolve）。
    assert_eq!(rt.sync_pending_requests(), 1, "STEP7 active == 1");
    // STEP8/9/10 — B 回 response（同 request_id）→ A step → resolve。
    *phase.lock().unwrap() = 2;
    let mut resolved = false;
    for _ in 0..MAX_ITER {
        rt.step().expect("step ok");
        if rt.sync_resolved_responses() >= 1 {
            resolved = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        resolved,
        "STEP10 Correlator.resolve 成功（真实 Runtime correlation）"
    );
    // STEP11 — active == 0（resolve 释放）。
    assert_eq!(rt.sync_pending_requests(), 0, "STEP11 active == 0");
    // STEP12 — duplicate response：A step 后 unknown++；active 保持 0（不可二次 resolve）。
    *phase.lock().unwrap() = 3;
    let mut dup_seen = false;
    for _ in 0..MAX_ITER {
        rt.step().expect("step ok");
        if rt.sync_unknown_responses() >= 1 {
            dup_seen = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(dup_seen, "STEP12 duplicate response 被拒（unknown）");
    assert_eq!(rt.sync_pending_requests(), 0, "STEP12 active 不变");
    assert_eq!(rt.sync_resolved_responses(), 1, "仅一次 resolve");
    // T11-A — 从未 register 的 unknown request_id response ⇒ reject（unknown++）；active 不变。
    *phase.lock().unwrap() = 4;
    let mut unknown_seen = false;
    for _ in 0..MAX_ITER {
        rt.step().expect("step ok");
        if rt.sync_unknown_responses() >= 2 {
            unknown_seen = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        unknown_seen,
        "T11-A unknown(never-registered) response 被拒"
    );
    assert_eq!(rt.sync_pending_requests(), 0, "T11-A active 不变");
    assert_eq!(
        rt.sync_resolved_responses(),
        1,
        "T11-A 不产生第二次 resolve"
    );
    // STEP13 — D10-B 后语义：本地 validator 经 consensus 获得 finality 后，production runtime
    //         经 Finality → Commit Bridge（NodeBlockAdapter::apply_block）可推进 canonical head
    //         —— 这是**本地 auto-finality commit**（非 inbound / sync commit）。
    //         保留的 D8 安全不变量：inbound / sync block 本身绝不因收到 / 验证通过就 commit；
    //         `finality` 是唯一 commit 授权；head 只可能 = genesis 或本地共识 finalized 块。
    let head_after = {
        let a = rt.block_production().expect("validator adapter");
        (a.head().block_hash, a.head().height, a.store().state_root())
    };
    let finalized = rt.consensus().state().finality.finalized_reference;
    if head_after.1 == head_before.1 {
        // 本流程未产生本地 auto-finality commit ⇒ head 保持 genesis（未 commit）。
        assert_eq!(
            head_after.0, head_before.0,
            "未产生本地 finality commit ⇒ canonical head 不变"
        );
    } else {
        // 本地 auto-finality 已把 canonical head 推进到 finalized 块：head 推进**仅**由
        // consensus finality 授权（bridge），绝不因 inbound / sync block 而 commit。
        assert_eq!(
            head_after.1,
            head_before.1 + 1,
            "线性推进恰好一个高度（本地 finalized block）"
        );
        assert_eq!(
            finalized,
            Some(head_after.0),
            "canonical head == 本地 consensus finalized 块（finality 是唯一 commit 授权）"
        );
    }
    // (b) inbound/sync 安全：B 注入的 future block（height>head+1，从未 finality）在整个流程中
    //     只被观测为 FutureMissingAncestor（未注册 / 未 submit / 未 commit）—— canonical head
    //     绝不因任何 inbound/sync block 到达而推进（上文已证 head 仅 = genesis 或本地 finalized 块）。

    *phase.lock().unwrap() = 99;
    drop(rt);
    let _ = handle.join();
}

// ===== T11-A（并入 T11）：unknown never-registered response ⇒ reject；active 不变 =====
// T11 主测试 phase4 已覆盖：从未 register 的 request_id response ⇒ `sync_unknown_responses`++
// 且 active == 0（见 d8_3_1_t11_runtime_sync_request_response_correlation）。
// T11-B（duplicate response isolation）：STEP12 已覆盖（resolve 后同 id response ⇒ 拒绝，
// active 不变，无第二次 resolve）。
// T11-C（send-failure release）：由 sync_dispatch::dispatch_batch 单元测试（Rejected ⇒ release）
// 与 sync_correlator::d8_3_1_send_failure_releases 覆盖（真实 outbound failure 需制造断连竞态，
// 属 D8-3-2 seam；不扩大 NetworkService）。
