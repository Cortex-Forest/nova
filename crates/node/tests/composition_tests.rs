//! NodeRuntime Stage C Full Composition 测试（STEP 10-18I-G；C-1..C-7）。
//!
//! 覆盖：`start_with_network` 网络注入（C-1）、Runtime `step()` 网络→Driver 闭环（C-2）、
//! 网络 disabled（C-3）、`shutdown(self)`（C-4/C-5）、identity 分离（C-7）。
//! C-6（Storage close failure）无法无侵入稳定构造 —— 不做 fault 注入；类型映射
//! `ShutdownError::Storage` 由正常关闭路径 + 编译期类型检查覆盖（见报告）。
//!
//! 纪律：不修改生产 runtime / network / consensus；网络对端注入用 test-only KeyPair +
//! `MemoryTransport`（与 H-1..H-6 相同套路）。

use std::path::PathBuf;

use nova_consensus::round::{ProposalRef, RoundStep, encode_proposal_ref};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
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
use nova_network::transport::{MemoryTransport, Transport};
use nova_storage::persistent::PersistentBackend;

use nova_node::bootstrap::NodeConfig;
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, derive_validator_id};

const CHAIN_ID: u64 = 1001;
const TARGET: [u8; 32] = [0xAA; 32];

// ---------- fixtures（与 runtime_tests 同套路；此处独立复制以免跨文件依赖） ----------

fn addr(kh: [u8; 32]) -> NovaAddress {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// TEST GENESIS ONLY：单 validator（被测公钥）；Σliquid == total_supply。
fn genesis_for(pk: [u8; 32]) -> GenesisV1 {
    let accounts = vec![
        AccountInit {
            address: addr([0x11; 32]),
            liquid_balance: 1_000_000,
        },
        AccountInit {
            address: addr([0x22; 32]),
            liquid_balance: 500_000,
        },
    ];
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

struct Env {
    dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    chain_dir: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_stagec_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_hash = compute_genesis_hash(genesis).unwrap();
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(&genesis_path, canonical_genesis_bytes(genesis).unwrap()).unwrap();
        let chain_dir = dir.join("chain");
        Self {
            dir,
            genesis_hash,
            genesis_path,
            chain_dir,
        }
    }

    fn config(&self) -> NodeConfig {
        NodeConfig {
            genesis_path: self.genesis_path.clone(),
            expected_genesis_hash: self.genesis_hash,
            expected_chain_id: CHAIN_ID,
            expected_network_id: NetworkId::Mainnet,
            storage_dir: self.chain_dir.clone(),
            validator_enabled: false, // full-node（C-1..C-5/C-7 聚焦网络组合，不经 validator）
            safety_dir: self.dir.join("safety"),
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

/// 对端 B 的 Handshake Init envelope（STEP 10-19-10-B7-A1-D5：runtime 装配 peer-auth 后，
/// 普通消息需 Established sender —— 对端先握手成为 Established）。
fn b_handshake(b_kp: &KeyPair, genesis_hash: [u8; 32], b_id: NodeId) -> MessageEnvelope {
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
    sign_message(b_kp.signing_key(), &mut envelope).expect("sign handshake");
    envelope
}

/// 用 test network key 签任意 payload 信封（对端注入帧）。
fn sign_envelope(
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

// ---------- C-1 : Network Injection ----------

/// C-1：`start_with_network` ⇒ NetworkStack `Some`；`NetworkService.self_id ==
/// NetworkSigner::node_id()`（经 `runtime.network_node_id()` 观察）。
#[test]
fn c1_network_injection_sets_stack_and_identity() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    let net_key = KeyPair::generate().unwrap();
    let net_id = node_id_of(&net_key);
    let (tx_a, _tx_b) = MemoryTransport::pair(net_id, node_id_of(&KeyPair::generate().unwrap()));
    let identity = SoftwareNetworkIdentity::new(net_key);

    let runtime =
        NodeRuntime::start_with_network(&config, None, Box::new(tx_a), Box::new(identity))
            .expect("start_with_network 成功");

    assert_eq!(
        runtime.network_node_id(),
        Some(net_id),
        "NetworkStack 启用；NetworkService self_id == NetworkSigner::node_id()"
    );
    assert_eq!(
        runtime.network_node_id().unwrap(),
        net_id,
        "NodeId 来自网络 key（≠ ValidatorId；见 C-7）"
    );
}

// ---------- C-2 : Runtime Step ----------

/// C-2：对端注入 ConsensusProposal 帧 → `runtime.step()`：
/// NetworkService → EventLoop dispatch → Handler decode → owned `Proposal` command →
/// Runtime drain → `process_command` → Driver → ConsensusNode（step=Prevote）。
#[test]
fn c2_runtime_step_drives_network_to_driver() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    // 网络两端：runtime 持 A（tx_a）；测试持 B（tx_b）注入帧。
    let net_a = KeyPair::generate().unwrap();
    let net_b = KeyPair::generate().unwrap();
    let a_id = node_id_of(&net_a);
    let b_id = node_id_of(&net_b);
    let (tx_a, mut tx_b) = MemoryTransport::pair(a_id, b_id);
    let identity = SoftwareNetworkIdentity::new(net_a);

    let mut runtime =
        NodeRuntime::start_with_network(&config, None, Box::new(tx_a), Box::new(identity))
            .expect("start_with_network 成功");
    assert_eq!(runtime.network_node_id(), Some(a_id));

    // D5：runtime 装配 peer-auth ⇒ 对端 B 先握手（Established），普通消息才放行。
    let hs_frame = b_handshake(&net_b, env.genesis_hash, b_id);
    tx_b.send(&a_id, encode(&hs_frame))
        .expect("inject handshake");
    runtime.step().expect("step handshake Ok");

    // 合法 proposal（proposer = genesis validator —— set 成员）。
    let pr = ProposalRef {
        block_hash: TARGET,
        proposer: derive_validator_id(&validator_pk),
    };
    let env_frame = sign_envelope(
        &net_b,
        MessageType::ConsensusProposal,
        encode_proposal_ref(&pr),
    );
    tx_b.send(&a_id, encode(&env_frame))
        .expect("inject frame to runtime");

    // step：poll → dispatch → command → Driver。
    runtime.step().expect("step Ok");

    let state = runtime.consensus().state();
    assert_eq!(
        state.round.proposal,
        Some(pr),
        "Driver 实际收到 Proposal command 并 Applied"
    );
    assert_eq!(
        state.round.step,
        RoundStep::Prevote,
        "canonical transition 推进到 Prevote"
    );
}

// ---------- C-3 : Network Disabled ----------

/// C-3：`start()` ⇒ network disabled（无网络身份）；consensus/storage 正常；`step()` ⇒ `Ok(())`。
#[test]
fn c3_network_disabled_start_step_ok() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    let mut runtime = NodeRuntime::start(&config, None).expect("start（disabled）成功");
    assert_eq!(runtime.network_node_id(), None, "不装配网络身份");
    assert!(
        !runtime.validator_enabled(),
        "full-node：validator 未启用（consensus 仍正常）"
    );
    assert_eq!(
        runtime.consensus().state().round.height,
        0,
        "consensus 正常启动"
    );
    assert!(env.chain_dir.exists(), "chain storage 已初始化");
    assert!(runtime.step().is_ok(), "网络 disabled ⇒ step 空转 Ok");
}

// ---------- C-4 : Shutdown ----------

/// C-4：`shutdown(self)` Ok；storage close 后同目录可重新 open。
#[test]
fn c4_shutdown_closes_storage_reopenable() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    let net_key = KeyPair::generate().unwrap();
    let net_id = node_id_of(&net_key);
    let (tx_a, _tx_b) = MemoryTransport::pair(net_id, node_id_of(&KeyPair::generate().unwrap()));
    let identity = SoftwareNetworkIdentity::new(net_key);

    let runtime =
        NodeRuntime::start_with_network(&config, None, Box::new(tx_a), Box::new(identity))
            .expect("start_with_network 成功");
    runtime
        .shutdown()
        .expect("shutdown Ok（EL/NS stop → Driver drop → Storage close）");

    // Storage 已 close：同目录可重新 open（close 已 flush 持久化）。
    PersistentBackend::open(&env.chain_dir).expect("storage 可重新 open");
}

// ---------- C-5 : Shutdown Consuming ----------

/// C-5：`shutdown(self)` 为 **consuming**（签名 `self`，非 `&mut self`）。
/// 调用后原 runtime 被 move —— 之后无法再次使用（编译期保证；无 &mut workaround）。
#[test]
fn c5_shutdown_is_consuming() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    let net_key = KeyPair::generate().unwrap();
    let net_id = node_id_of(&net_key);
    let (tx_a, _tx_b) = MemoryTransport::pair(net_id, node_id_of(&KeyPair::generate().unwrap()));
    let identity = SoftwareNetworkIdentity::new(net_key);

    let runtime =
        NodeRuntime::start_with_network(&config, None, Box::new(tx_a), Box::new(identity))
            .expect("start_with_network 成功");
    // runtime 被消费（move 进 shutdown）；单次确定性终止。
    runtime.shutdown().expect("consuming shutdown Ok");
}

// ---------- C-7 : Identity Separation ----------

/// C-7：`NetworkSigner::node_id()` ≠ ValidatorId（不同源 key）；
/// Runtime 未复用 validator private key 作网络身份。
#[test]
fn c7_network_identity_separate_from_validator_identity() {
    let validator_kp = KeyPair::generate().unwrap();
    let validator_pk = validator_kp.verifying_key().to_bytes();
    let env = Env::new(&genesis_for(validator_pk));
    let config = env.config();

    let net_key = KeyPair::generate().unwrap();
    let net_id = node_id_of(&net_key);
    let (tx_a, _tx_b) = MemoryTransport::pair(net_id, node_id_of(&KeyPair::generate().unwrap()));
    let identity = SoftwareNetworkIdentity::new(net_key);

    let runtime =
        NodeRuntime::start_with_network(&config, None, Box::new(tx_a), Box::new(identity))
            .expect("start_with_network 成功");

    let network_node_id = runtime.network_node_id().expect("网络身份存在");
    let validator_id = derive_validator_id(&validator_pk);
    assert_ne!(
        network_node_id.as_bytes().to_vec(),
        validator_id.as_bytes().to_vec(),
        "网络 key pubkey ≠ validator pubkey；Network NodeId ≠ ValidatorId（validator private key 未作网络身份）"
    );
}
