//! Configured ConnectionTarget → NodeRuntime → NetworkService dial seam（STEP 10-19-10-B7-A3-Implementation）。
//!
//! R1a empty peers ⇒ connect no-op；R1b self target ⇒ 启动 fail-closed（dial 前）；R1c 可达 localhost
//! target ⇒ dial 成功到 `Connected`（single-active；不 handshake / 不 Established）。

use std::net::SocketAddr;
use std::path::PathBuf;

use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};

use nova_node::bootstrap::{ConnectionTargetError, NodeConfig};
use nova_node::network_identity::{NetworkSigner, SoftwareNetworkIdentity};
use nova_node::runtime::{NodeRuntime, NodeRuntimeError};

const CHAIN_ID: u64 = 2002;

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// 通过 `validate_genesis` 形态的最小测试 genesis（账户升序；Σliquid==total_supply；
/// validator pubkey 为真实 Ed25519 verifying key —— decode 要求 canonical）。
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
        let dir = std::env::temp_dir().join(format!("nova_a3_{}_{}", std::process::id(), n));
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
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.genesis_path.parent().unwrap());
    }
}

fn nid(tag: u8) -> NodeId {
    NodeId::from_bytes([tag; 32])
}

/// 启动带网络的 runtime（注入 memory transport 占位 + network signer）。
fn start_net(cfg: &NodeConfig) -> Result<NodeRuntime, NodeRuntimeError> {
    let kp = KeyPair::generate().unwrap();
    let self_id = NodeId::from_verifying_key(kp.verifying_key());
    let other = nid(0x99);
    let transport: Box<dyn nova_network::transport::Transport> =
        Box::new(MemoryTransport::pair(self_id, other).0);
    let signer: Box<dyn NetworkSigner> = Box::new(SoftwareNetworkIdentity::new(kp));
    NodeRuntime::start_with_network(cfg, None, transport, signer)
}

// R1a — empty peers ⇒ connect no-op（无网络 peer 不失败）
#[test]
fn connect_configured_empty_ok() {
    let env = Env::new();
    let cfg = env.config(Vec::new());
    let mut rt = start_net(&cfg).expect("start");
    assert_eq!(rt.connect_configured_peer().unwrap(), None);
}

// R1b — configured self target ⇒ 启动 fail-closed（validate 在 dial 前）
#[test]
fn connect_configured_self_rejected_at_startup() {
    let env = Env::new();
    let kp = KeyPair::generate().unwrap();
    let self_id = NodeId::from_verifying_key(kp.verifying_key());
    let cfg = env.config(vec![ConnectionTarget {
        peer_id: self_id,
        address: SocketAddr::from(([127, 0, 0, 1], 1)),
    }]);
    // 用与 start_net 相同 identity 的 signer 以匹配 self_id。
    let other = nid(0x99);
    let transport: Box<dyn nova_network::transport::Transport> =
        Box::new(MemoryTransport::pair(self_id, other).0);
    let signer: Box<dyn NetworkSigner> = Box::new(SoftwareNetworkIdentity::new(kp));
    let res = NodeRuntime::start_with_network(&cfg, None, transport, signer);
    assert!(
        matches!(
            res,
            Err(NodeRuntimeError::NetworkTarget(
                ConnectionTargetError::SelfTarget { .. }
            ))
        ),
        "self target 必须在 dial 前拒绝（启动 fail-closed）"
    );
}

// R1c — 可达 localhost target ⇒ connect dials → Connected（single-active；无 handshake）
#[test]
fn connect_configured_reachable_localhost() {
    let env = Env::new();
    // 保持 listener open：dial 完成 TCP 三次握手（无 accept thread；localhost 非公网）。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let laddr = listener.local_addr().expect("addr");
    let remote = nid(0x77);
    let cfg = env.config(vec![ConnectionTarget {
        peer_id: remote,
        address: laddr,
    }]);
    let mut rt = start_net(&cfg).expect("start");
    assert_eq!(
        rt.connect_configured_peer().unwrap(),
        Some(remote),
        "dial 成功 → Connected（返回 connected peer_id）"
    );
    // single-active 幂等：已有 active connection ⇒ 不再重连/替换。
    assert_eq!(rt.connect_configured_peer().unwrap(), None);
    drop(listener);
}
