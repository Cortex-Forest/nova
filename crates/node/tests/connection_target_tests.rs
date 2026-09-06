//! Configured ConnectionTarget 校验（STEP 10-19-10-B7-A3-Implementation）—— NodeConfig 层。
//!
//! C1 empty peers 合法 / C2 单 peer 合法 / C3 duplicate NodeId 拒 / C4 duplicate address 拒 /
//! C5 self peer 拒 / C6 localhost 允许（测试/本地开发）。

use std::net::SocketAddr;
use std::path::PathBuf;

use nova_crypto::address::NetworkId;
use nova_network::node_id::NodeId;
use nova_network::transport::ConnectionTarget;

use nova_node::bootstrap::{ConnectionTargetError, NodeConfig};
use nova_node::key_provider::KeyProviderConfig;

fn nid(tag: u8) -> NodeId {
    NodeId::from_bytes([tag; 32])
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn config(peers: Vec<ConnectionTarget>) -> NodeConfig {
    NodeConfig {
        genesis_path: PathBuf::from("dummy-genesis.bin"),
        expected_genesis_hash: [0; 32],
        expected_chain_id: 1,
        expected_network_id: NetworkId::Mainnet,
        storage_dir: PathBuf::from("dummy-chain"),
        validator_enabled: false,
        safety_dir: PathBuf::from("dummy-safety"),
        key_provider_config: KeyProviderConfig::Software,
        peers,
    }
}

fn target(peer: NodeId, address: SocketAddr) -> ConnectionTarget {
    ConnectionTarget {
        peer_id: peer,
        address,
    }
}

// C1 — empty peers ⇒ valid（无网络 peer 不阻止配置）
#[test]
fn empty_peers_valid() {
    let cfg = config(Vec::new());
    assert_eq!(cfg.validate_network_targets(nid(0xaa)), Ok(()));
}

// C2 — single valid peer（localhost 允许）⇒ valid
#[test]
fn single_localhost_peer_valid() {
    let cfg = config(vec![target(nid(0xbb), addr(1))]);
    assert_eq!(cfg.validate_network_targets(nid(0xaa)), Ok(()));
}

// C3 — duplicate NodeId ⇒ reject（dial 前）
#[test]
fn duplicate_node_id_rejected() {
    let cfg = config(vec![target(nid(0xbb), addr(1)), target(nid(0xbb), addr(2))]);
    assert_eq!(
        cfg.validate_network_targets(nid(0xaa)),
        Err(ConnectionTargetError::DuplicateNodeId { peer_id: nid(0xbb) })
    );
}

// C4 — duplicate SocketAddr ⇒ reject（dial 前）
#[test]
fn duplicate_address_rejected() {
    let cfg = config(vec![target(nid(0xbb), addr(9)), target(nid(0xcc), addr(9))]);
    assert_eq!(
        cfg.validate_network_targets(nid(0xaa)),
        Err(ConnectionTargetError::DuplicateAddress { address: addr(9) })
    );
}

// C5 — self peer（peer_id == self_id）⇒ reject（dial 前）
#[test]
fn self_peer_rejected() {
    let cfg = config(vec![target(nid(0xaa), addr(1))]);
    assert_eq!(
        cfg.validate_network_targets(nid(0xaa)),
        Err(ConnectionTargetError::SelfTarget { peer_id: nid(0xaa) })
    );
}

// C6 — localhost 明确允许（不自禁；测试/本地开发需要）
#[test]
fn localhost_allowed() {
    let cfg = config(vec![target(
        nid(0xbb),
        SocketAddr::from(([127, 0, 0, 1], 30303)),
    )]);
    assert_eq!(cfg.validate_network_targets(nid(0xaa)), Ok(()));
}
