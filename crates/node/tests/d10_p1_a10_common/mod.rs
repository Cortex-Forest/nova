//! P1-A.10 — Testnet Evidence 共享 rig（**tests-only**；无任何生产改动）。
//!
//! 提供：确定性 validator/network 身份、N 验证者 genesis、真实 TCP 多节点 rig、
//! 有界推进（条件轮询 + 硬超时）、可停止的 test-owned TCP relay（链路级 partition）、
//! 以及 finality / 投票聚合 / 状态收敛的只读断言辅助。
#![allow(dead_code)]

use core::sync::atomic::AtomicBool;
use std::collections::BTreeSet;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nova_consensus::validator::ValidatorId;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::signature::{Signature, SigningKey, VerifyingKey, sign_message_hash};
use nova_network::message::{MessageEnvelope, sign_message};
use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, KeyProviderError};
use nova_node::network_identity::{NetworkSigner, NetworkSigningError};
use nova_node::runtime::{NodeRuntime, derive_validator_id};
use nova_node::signer::{SigningCapability, SigningError};

pub const CHAIN_ID: u64 = 1001;
pub const STAKE: u128 = 200_000;

/// 确定性 validator 身份 seed（genesis 成员）。
pub const SEED_V1: [u8; 32] = [0x31; 32];
pub const SEED_V2: [u8; 32] = [0x32; 32];
pub const SEED_V3: [u8; 32] = [0x33; 32];
/// 确定性 **network**（P2P）身份 seed（必须与 validator seed 不同 —— 生产 CLI 约束）。
pub const SEED_N1: [u8; 32] = [0x41; 32];
pub const SEED_N2: [u8; 32] = [0x42; 32];
pub const SEED_N3: [u8; 32] = [0x43; 32];

/// `ceil(total_weight * 2 / 3)`（consensus 冻结公式）。
pub const fn quorum_for(total_weight: u128) -> u128 {
    total_weight.saturating_mul(2).div_ceil(3)
}

// ---------------------------------------------------------------------------
// 确定性身份（validator 与 network 分离；重启后同一身份可复现）
// ---------------------------------------------------------------------------

pub fn pubkey_from_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
}

pub fn validator_id_of_seed(seed: [u8; 32]) -> ValidatorId {
    derive_validator_id(&pubkey_from_seed(seed))
}

pub fn net_node_id(seed: [u8; 32]) -> NodeId {
    NodeId::from_verifying_key(&SigningKey::from_seed(seed).verifying_key())
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 生产 CLI 同源：network seed ⇒ `SigningKey` ⇒ `NodeId` / 信封签名（**不重新实现算法**）。
pub struct SeedNetworkIdentity {
    signing: SigningKey,
}

impl SeedNetworkIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_seed(seed),
        }
    }
}

impl NetworkSigner for SeedNetworkIdentity {
    fn node_id(&self) -> NodeId {
        NodeId::from_verifying_key(&self.signing.verifying_key())
    }

    fn sign_envelope(&self, envelope: &mut MessageEnvelope) -> Result<(), NetworkSigningError> {
        sign_message(&self.signing, envelope).map_err(NetworkSigningError::Sign)
    }
}

struct SeedSigner {
    key: SigningKey,
}

impl SigningCapability for SeedSigner {
    fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign(&self, message_hash: &SigningMessageHash) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(&self.key, message_hash))
    }
}

struct SeedKeyProvider {
    seed: [u8; 32],
}

impl KeyProvider for SeedKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        Ok(Box::new(SeedSigner {
            key: SigningKey::from_seed(self.seed),
        }))
    }
}

// ---------------------------------------------------------------------------
// genesis / 临时目录
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// N 验证者 genesis：**等额 stake** ⇒ `total = N × STAKE`、`quorum = ceil(2N/3)`。
pub fn genesis_with(val_seeds: &[[u8; 32]]) -> GenesisV1 {
    let accounts: Vec<AccountInit> = (0..val_seeds.len())
        .map(|i| AccountInit {
            address: addr([0x10 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut validators: Vec<(ValidatorId, [u8; 32], YazimaoAddress)> = val_seeds
        .iter()
        .enumerate()
        .map(|(i, seed)| {
            let pk = pubkey_from_seed(*seed);
            (derive_validator_id(&pk), pk, accounts[i].address)
        })
        .collect();
    validators.sort_by_key(|v| v.0);
    let initial_validator_set = validators
        .into_iter()
        .map(|(_, pk, account_address)| ValidatorInit {
            account_address,
            consensus_public_key: pk,
            bonded_stake: STAKE,
            commission_bps: 0,
        })
        .collect();
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set,
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
            total_supply: 1_000_000 * val_seeds.len() as u128,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

/// 测试临时根目录（`%TEMP%/yazimao_p1a10_<pid>_<n>`；Drop 递归清理；不触碰仓库）。
pub struct Env {
    base: PathBuf,
    genesis_path: PathBuf,
    genesis_hash: [u8; 32],
}

impl Env {
    pub fn new(tag: &str, val_seeds: &[[u8; 32]]) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "yazimao_p1a10_{}_{}_{}",
            tag,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let g = genesis_with(val_seeds);
        let genesis_hash = compute_genesis_hash(&g).expect("genesis hash");
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(
            &genesis_path,
            canonical_genesis_bytes(&g).expect("canonical genesis"),
        )
        .expect("write genesis");
        Self {
            base: dir,
            genesis_path,
            genesis_hash,
        }
    }

    pub fn root(&self, label: &str) -> PathBuf {
        self.base.join(label)
    }

    pub fn config(
        &self,
        label: &str,
        listen_addr: Option<SocketAddr>,
        peers: Vec<ConnectionTarget>,
    ) -> NodeConfig {
        let root = self.root(label);
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: root.join("chain"),
            validator_enabled: true,
            safety_dir: root.join("safety"),
            key_provider_config: nova_node::key_provider::KeyProviderConfig::Software,
            peers,
            listen_addr,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// ---------------------------------------------------------------------------
// 节点
// ---------------------------------------------------------------------------

pub struct Node {
    pub label: &'static str,
    pub val_seed: [u8; 32],
    pub net_seed: [u8; 32],
    pub listen: Option<SocketAddr>,
    pub rt: NodeRuntime,
    /// 最近一次 `step()` 错误（诊断用；非敏感 —— 仅 typed error 的 Debug）。
    pub last_err: Option<String>,
    /// 本节点 configured peer 的 NodeId（用于 Established 断言）。
    pub peer_ids: Vec<NodeId>,
}

impl Node {
    /// 全部 configured peer 均已 Established。
    pub fn all_peers_established(&self) -> bool {
        !self.peer_ids.is_empty()
            && self
                .peer_ids
                .iter()
                .all(|p| self.rt.network_peer_established(*p))
    }
}

pub fn start_node(
    env: &Env,
    label: &'static str,
    val_seed: [u8; 32],
    net_seed: [u8; 32],
    listen: Option<SocketAddr>,
    peers: Vec<ConnectionTarget>,
) -> Node {
    let cfg = env.config(label, listen, peers.clone());
    let self_id = net_node_id(net_seed);
    let (tx_self, _tx_other) = MemoryTransport::pair(self_id, NodeId::from_bytes([0x99; 32]));
    let provider = SeedKeyProvider { seed: val_seed };
    let rt = NodeRuntime::start_with_network(
        &cfg,
        Some(&provider),
        Box::new(tx_self),
        Box::new(SeedNetworkIdentity::from_seed(net_seed)),
    )
    .expect("runtime 启动（validator + network）");
    let listen = rt.network_listen_addr();
    let peer_ids = peers.into_iter().map(|p| p.peer_id).collect();
    Node {
        label,
        val_seed,
        net_seed,
        listen,
        rt,
        last_err: None,
        peer_ids,
    }
}

pub fn target(peer_id: NodeId, address: SocketAddr) -> ConnectionTarget {
    ConnectionTarget { peer_id, address }
}

/// 供多进程/CLI 场景构造 `--peer <hex64>@<addr>` 字符串。
pub fn peer_arg(peer_id: NodeId, address: SocketAddr) -> String {
    format!("{}@{}", hex32(peer_id.as_bytes()), address)
}

/// 环境句柄：动态端口 / 测试自有 relay 地址。
pub fn free_port() -> u16 {
    let l = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind 0");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

// ---------------------------------------------------------------------------
// 只读观测辅助
// ---------------------------------------------------------------------------

pub fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production().map_or(0, |a| a.head().height)
}

pub fn head_hash(rt: &NodeRuntime) -> [u8; 32] {
    rt.block_production()
        .map_or([0u8; 32], |a| a.head().block_hash)
}

pub fn finalized_ref(rt: &NodeRuntime) -> Option<[u8; 32]> {
    rt.driver().consensus().state().finality.finalized_reference
}

pub fn consensus_height(rt: &NodeRuntime) -> u64 {
    rt.driver().consensus().state().round.height
}

pub fn consensus_round(rt: &NodeRuntime) -> u64 {
    rt.driver().consensus().state().round.round
}

pub fn tip_height(rt: &NodeRuntime) -> Option<u64> {
    rt.qc_history_tip_height()
}

pub fn proposal_hash(rt: &NodeRuntime) -> Option<[u8; 32]> {
    rt.driver()
        .consensus()
        .state()
        .round
        .proposal
        .as_ref()
        .map(|p| p.block_hash)
}

pub fn proposal_proposer(rt: &NodeRuntime) -> Option<ValidatorId> {
    rt.driver()
        .consensus()
        .state()
        .round
        .proposal
        .as_ref()
        .map(|p| p.proposer)
}

/// 当前轮提案 target 上已聚合的 prevote 权重。
pub fn prevote_weight(rt: &NodeRuntime) -> u128 {
    let st = rt.driver().consensus().state();
    match st.round.proposal.as_ref() {
        Some(p) => st.round.prevotes.weight_of(&p.block_hash),
        None => 0,
    }
}

pub fn precommit_weight(rt: &NodeRuntime) -> u128 {
    let st = rt.driver().consensus().state();
    match st.round.proposal.as_ref() {
        Some(p) => st.round.precommits.weight_of(&p.block_hash),
        None => 0,
    }
}

/// 已建立的 configured peer 数（按 label 传入的对端）。
pub fn established_count(rt: &NodeRuntime, peers: &[NodeId]) -> usize {
    peers
        .iter()
        .filter(|p| rt.network_peer_established(**p))
        .count()
}

// ---------------------------------------------------------------------------
// 有界推进（条件轮询 + 硬超时；禁止 sleep-only 判定）
// ---------------------------------------------------------------------------

/// 第一阶段：**只建立连接/握手，不推进共识**（`establish_configured_peers` 内部 poll 事件循环）。
///
/// 必要性：若在无 Established peer 时就 `step()`，当前 proposer 会产出提案并在无对端时广播
///（提案丢失）⇒ 本轮永久停滞（测试环境启动顺序造成，非生产缺陷）。
pub fn connect_all(nodes: &mut [Node], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let all_connected = nodes.iter().all(|n| {
            let expected = n.rt.driver().consensus().validator_set().len();
            let _ = expected;
            let configured = n.rt.peer_dial_attempts_total();
            let _ = configured;
            n.all_peers_established()
        });
        if all_connected {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        for n in nodes.iter_mut() {
            let _ = n.rt.establish_configured_peers();
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// 交替 `establish_configured_peers()` + `step()`（所有节点）直到 `done` 为真。
/// 返回 `true` = 达成；`false` = 硬超时/迭代预算耗尽（由调用方判定 FAIL 或 BLOCKED）。
///
/// 入口先执行 [`connect_all`]（只握手），使共识从**全互联**状态开始。
pub fn advance_all<F: FnMut(&[Node]) -> bool>(
    nodes: &mut [Node],
    budget: usize,
    hard_timeout: Duration,
    mut done: F,
) -> bool {
    let _ = connect_all(nodes, Duration::from_secs(30));
    let deadline = Instant::now() + hard_timeout;
    for _ in 0..budget {
        if done(nodes) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        for n in nodes.iter_mut() {
            let _ = n.rt.establish_configured_peers();
            if let Err(e) = n.rt.step() {
                n.last_err = Some(format!("{e:?}"));
            }
        }
        thread::yield_now();
    }
    done(nodes)
}

/// 推进直到所有节点 head >= target。
pub fn advance_to_height(nodes: &mut [Node], target: u64, budget: usize, t: Duration) -> bool {
    advance_all(nodes, budget, t, |ns| {
        ns.iter().all(|n| head_height(&n.rt) >= target)
    })
}

// ---------------------------------------------------------------------------
// test-owned TCP relay（链路级 partition 证据；不解析 / 不修改 protocol）
// ---------------------------------------------------------------------------

/// 单向 relay：accept 本地连接 → dial `upstream` → 双向字节转发。
///
/// `stop()`：置停止位 + `shutdown(Both)` 全部存量连接 + 丢弃 listener
///（⇒ 存量连接死、后续 dial 被拒 ⇒ 该链路**双向静默**，而两端进程仍存活）。
pub struct Relay {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<TcpStream>>>,
    handle: JoinHandle<()>,
}

impl Relay {
    pub fn start(upstream: SocketAddr) -> Self {
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("relay bind");
        let addr = listener.local_addr().expect("relay addr");
        listener.set_nonblocking(true).expect("relay nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_c = Arc::clone(&stop);
        let conns_c = Arc::clone(&conns);
        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((down, _)) => {
                        let Ok(up) = TcpStream::connect(upstream) else {
                            continue;
                        };
                        let _ = down.set_nodelay(true);
                        let _ = up.set_nodelay(true);
                        let (Ok(mut d_rd), Ok(mut d_wr), Ok(mut u_rd), Ok(mut u_wr)) = (
                            down.try_clone(),
                            down.try_clone(),
                            up.try_clone(),
                            up.try_clone(),
                        ) else {
                            continue;
                        };
                        {
                            let mut g = conns_c.lock().expect("relay conns");
                            g.push(down);
                            g.push(up);
                        }
                        // down → upstream
                        thread::spawn(move || {
                            let mut buf = [0u8; 16 * 1024];
                            while let Ok(n) = d_rd.read(&mut buf) {
                                if n == 0 || u_wr.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                                let _ = u_wr.flush();
                            }
                            let _ = d_rd.shutdown(Shutdown::Both);
                            let _ = u_wr.shutdown(Shutdown::Both);
                        });
                        // upstream → down
                        thread::spawn(move || {
                            let mut buf = [0u8; 16 * 1024];
                            while let Ok(n) = u_rd.read(&mut buf) {
                                if n == 0 || d_wr.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                                let _ = d_wr.flush();
                            }
                            let _ = u_rd.shutdown(Shutdown::Both);
                            let _ = d_wr.shutdown(Shutdown::Both);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
            // 停止：关闭全部存量连接。
            if let Ok(g) = conns_c.lock() {
                for s in g.iter() {
                    let _ = s.shutdown(Shutdown::Both);
                }
            }
        });
        Self {
            addr,
            stop,
            conns,
            handle,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(g) = self.conns.lock() {
            for s in g.iter() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }

    /// 阻塞等待 accept 线程退出（Drop 语义；bounded）。
    pub fn join(self) {
        self.stop();
        let _ = self.handle.join();
    }
}

use std::io::{Read, Write};

// ---------------------------------------------------------------------------
// 磁盘增长观测（只读；T5）
// ---------------------------------------------------------------------------

pub fn dir_stats(dir: &std::path::Path) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let (c, b) = dir_stats(&p);
                count += c;
                bytes += b;
            } else if let Ok(md) = e.metadata() {
                count += 1;
                bytes += md.len();
            }
        }
    }
    (count, bytes)
}

pub fn file_len(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map_or(0, |m| m.len())
}

/// 观察到的 proposer 集合（T1 提案轮转证据）。
pub fn collect_proposers(nodes: &[Node], seen: &mut BTreeSet<ValidatorId>) {
    for n in nodes {
        if let Some(p) = proposal_proposer(&n.rt) {
            seen.insert(p);
        }
    }
}
