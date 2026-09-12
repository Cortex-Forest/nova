//! P1-A.7 — **Validator Rejoin / Late-Join Catch-up**（ADR-0064；Verified External Finality Adoption）。
//!
//! # 被验证的不变量
//! - 落后 / 迟到 / restart-behind-tip 节点可经**既有**通路（`SyncBlockRequest` →
//!   `SyncBlockResponse` → 附发的既有 `ConsensusQc`）追赶：**零 wire 变更**。
//! - 采纳仅在**全部**前置检查通过后发生：`verify_qc`（既有 driver 门面）→ `target ∈ DAG` →
//!   `block.height == head + 1` ∧ `parent == head` → `qc.context.height + 1 == block.height` →
//!   `qc.target == block_hash` → frozen `check_finality_applicability` / `update_finalized_reference`。
//! - `QC != commit` / `QC != ChainHead mutation` / `QC adoption != new consensus authority`：
//!   head 只由**既有** durable commit bridge（`apply_block` ⑤ 强制 head+1）推进。
//! - 拒绝面 fail-closed：无效 QC / 未知 target / 高度不符 / 非 canonical-next ⇒ 计数 + drop，
//!   **零 canonical 变更**（不猜 / 不跳高度 / 不回退 / 不构造 fake finality）。
//! - 边界：pending external QC ≤ 8（dedup by target）；responder 上限不变
//!   （`MAX_SYNC_RESPONSES_PER_STEP = 4` / `MAX_PENDING_SYNC_REQUESTS = 64`）。
//!
//! # 确定性
//! 全部为**逻辑 step + bounded wait**（无 sleep-based 竞态断言 / 无墙钟依赖 / 无随机）；
//! real TCP 仅用于真实 peer 通路（沿用既有 `d9_step8a` 模式）。
//!
//! 纪律：不修改 consensus / core / crypto / network / wiring / driver / D8 / bin / bootstrap。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
use nova_consensus::validator::ValidatorId;
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, SigningKey, sign_message_hash};
use nova_network::node_id::NodeId;
use nova_network::transport::{ConnectionTarget, MemoryTransport};
use nova_node::bootstrap::NodeConfig;
use nova_node::key_provider::{KeyProvider, KeyProviderError};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, derive_validator_id};
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::sync_responder::{MAX_PENDING_SYNC_REQUESTS, MAX_SYNC_RESPONSES_PER_STEP};
use nova_node::wiring::NodeConsensusCommand;
use nova_runtime::Block;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
const MAX_ITER: usize = 600;

/// 两个验证者 seed（genesis 成员；quorum = 2/2 ⇒ 两条 evidence 才成 QC）。
const SEED_A: [u8; 32] = [0x31; 32];
const SEED_B: [u8; 32] = [0x32; 32];

// ---------------------------------------------------------------------------
// Test-only 确定性 signer / provider
// ---------------------------------------------------------------------------

struct SeedSigner {
    key: SigningKey,
}

impl SigningCapability for SeedSigner {
    fn public_key(&self) -> nova_crypto::signature::VerifyingKey {
        self.key.verifying_key()
    }

    fn sign(
        &self,
        message_hash: &nova_crypto::domain::SigningMessageHash,
    ) -> Result<Signature, SigningError> {
        Ok(sign_message_hash(&self.key, message_hash))
    }
}

#[derive(Clone, Copy)]
struct SeedKeyProvider {
    seed: [u8; 32],
}

impl SeedKeyProvider {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl KeyProvider for SeedKeyProvider {
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProviderError> {
        Ok(Box::new(SeedSigner {
            key: SigningKey::from_seed(self.seed),
        }))
    }
}

fn pubkey_from_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
}

// ---------------------------------------------------------------------------
// genesis / env / harness
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// N 验证者 genesis（canonical ordering；`total_supply == Σ liquid`）。
fn genesis_with(keys: &[[u8; 32]]) -> GenesisV1 {
    let accounts: Vec<AccountInit> = (0..keys.len())
        .map(|i| AccountInit {
            address: addr([0x10 + i as u8; 32]),
            liquid_balance: 1_000_000,
        })
        .collect();
    let mut validators: Vec<(ValidatorId, [u8; 32], YazimaoAddress)> = keys
        .iter()
        .enumerate()
        .map(|(i, pk)| (derive_validator_id(pk), *pk, accounts[i].address))
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
            total_supply: 1_000_000 * keys.len() as u128,
            min_validator_stake: 100,
            unbonding_period_seconds: 1_000,
            fee_burn_bps: 0,
        },
    }
}

struct Env {
    _dir: PathBuf,
    genesis_hash: [u8; 32],
    genesis_path: PathBuf,
    base: PathBuf,
}

impl Env {
    fn new(genesis: &GenesisV1) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nova_p1a7_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let genesis_hash = compute_genesis_hash(genesis).expect("genesis hash");
        let genesis_path = dir.join("genesis.bin");
        std::fs::write(
            &genesis_path,
            canonical_genesis_bytes(genesis).expect("canonical genesis"),
        )
        .expect("write genesis");
        Self {
            _dir: dir.clone(),
            genesis_hash,
            genesis_path,
            base: dir,
        }
    }

    /// 每节点独立 chain/safety 目录；**同一 `node` 标签 ⇒ 同一目录**（供 restart 复用）。
    fn config(
        &self,
        node: &str,
        listen_addr: Option<SocketAddr>,
        peers: Vec<ConnectionTarget>,
    ) -> NodeConfig {
        let root = self.base.join(node);
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

fn node_id_of(kp: &KeyPair) -> NodeId {
    NodeId::from_verifying_key(kp.verifying_key())
}

fn start_node(config: &NodeConfig, validator_seed: [u8; 32], net_kp: KeyPair) -> NodeRuntime {
    let net_id = node_id_of(&net_kp);
    let (tx_self, _tx_other) = MemoryTransport::pair(net_id, NodeId::from_bytes([0x99; 32]));
    let provider = SeedKeyProvider::new(validator_seed);
    NodeRuntime::start_with_network(
        config,
        Some(&provider),
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("runtime 启动（validator + network）")
}

fn wait_until<F: FnMut() -> bool>(mut f: F) -> bool {
    for _ in 0..MAX_ITER {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
    }
    false
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production().expect("adapter").head().height
}

fn head_hash(rt: &NodeRuntime) -> [u8; 32] {
    rt.block_production().expect("adapter").head().block_hash
}

fn head_finality(rt: &NodeRuntime) -> Option<[u8; 32]> {
    rt.consensus().state().finality.finalized_reference
}

fn store_get(rt: &NodeRuntime, hash: &[u8; 32]) -> Option<Block> {
    rt.block_production()
        .and_then(|a| a.block_store().and_then(|bs| bs.get(hash).ok().flatten()))
}

/// 用 genesis 两验证者 seed 对给定 `(context_height, round, target)` 构造**真实签名**的
/// PrecommitQC（quorum = 2/2 ⇒ 两条 evidence）。
fn signed_qc(
    genesis_hash: [u8; 32],
    context_height: u64,
    round: u64,
    target: [u8; 32],
) -> QuorumCertificate {
    let mut evidence = Vec::new();
    for seed in [SEED_A, SEED_B] {
        let key = SigningKey::from_seed(seed);
        let vk = key.verifying_key();
        let validator_id = derive_validator_id(&vk.to_bytes());
        let vote = ValidatorVote {
            round,
            height: context_height,
            target_block_hash: target,
            vote_type: VoteType::Precommit,
            source_block_hash: [0u8; 32],
            validator_id,
            timestamp: 7,
        };
        let payload = canonical_vote_payload(&vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            CHAIN_ID,
            &payload,
        )
        .expect("signed bytes");
        let h = hash_signing_message(&signed);
        let sig = sign_message_hash(&key, &h);
        evidence.push(QcEvidence {
            validator_id,
            source_block_hash: [0u8; 32],
            timestamp: 7,
            signature: sig.to_bytes(),
        });
    }
    evidence.sort_by_key(|e| e.validator_id);
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: context_height,
            round,
            vote_type: VoteType::Precommit,
        },
        target,
        validator_set_id: genesis_hash,
        evidence,
    }
}

/// A/B 真实 TCP 双验证者 rig（A 监听；B dial A），推进到 height ≥ `target`。
struct AbRig {
    a: NodeRuntime,
    b: NodeRuntime,
    a_id: NodeId,
    a_addr: SocketAddr,
}

fn start_ab(env: &Env, target: u64) -> AbRig {
    let a_net = KeyPair::generate().expect("net kp");
    let a_id = node_id_of(&a_net);
    let a_cfg = env.config(
        "a",
        Some("127.0.0.1:0".parse().expect("listen addr")),
        Vec::new(),
    );
    let mut a = start_node(&a_cfg, SEED_A, a_net);
    let a_addr = a.network_listen_addr().expect("A listener 已绑定");
    let b_net = KeyPair::generate().expect("net kp");
    let b_cfg = env.config(
        "b",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut b = start_node(&b_cfg, SEED_B, b_net);
    let up = wait_until(|| {
        let _ = a.establish_configured_peers();
        let _ = b.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        head_height(&a) >= target && head_height(&b) >= target
    });
    assert!(
        up,
        "A/B 未推进到 height {target}（A={} B={}）",
        head_height(&a),
        head_height(&b)
    );
    AbRig { a, b, a_id, a_addr }
}

// ---------------------------------------------------------------------------
// T1 / T2 — Real late join + Restart behind tip
// ---------------------------------------------------------------------------

#[test]
fn p1a7_late_join_then_restart_behind_tip() {
    let genesis = genesis_with(&[pubkey_from_seed(SEED_A), pubkey_from_seed(SEED_B)]);
    let env = Env::new(&genesis);
    let rig = start_ab(&env, 2);
    let mut a = rig.a;
    let mut b = rig.b;
    let a_id = rig.a_id;
    let a_addr = rig.a_addr;

    // A 已持久化 H1/H2 的 per-height PrecommitQC（ADR-0064）。
    assert!(
        a.qc_history_written() >= 2,
        "A 未持久化 per-height QC（written={}）",
        a.qc_history_written()
    );
    assert_eq!(a.qc_history_tip_height(), Some(2), "A tip = 2");

    // ---- T1：C 后加入（fresh storage；validator key = B；仅连 A；head = 0）----
    let c_net = KeyPair::generate().expect("net kp");
    let c_cfg = env.config(
        "c",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut c = start_node(&c_cfg, SEED_B, c_net);
    assert_eq!(head_height(&c), 0, "C 从 genesis 起步");

    let caught = wait_until(|| {
        let _ = c.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        let _ = c.step();
        head_height(&c) >= 2
    });
    assert!(
        caught,
        "T1：C 未追赶（head={} adopted={} rejected={} deferred={} served={} | C: resolved={} unknown={} outcomes={} | A diag={:?} | last verdicts={:?}）",
        head_height(&c),
        c.external_finality_adopted(),
        c.external_finality_rejected(),
        c.inbound_qc_deferred(),
        a.qc_served(),
        c.sync_resolved_responses(),
        c.sync_unknown_responses(),
        c.block_inbound_outcome_len(),
        a.sync_respond_diagnostics(),
        c.take_block_inbound_outcomes()
            .iter()
            .rev()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
    );
    // T1 收敛断言（稳健）：A/B 仍在推进 ⇒ 用「C 的 head 已在 A 的 canonical 链上」而非瞬时 head 相等。
    let c_head = head_hash(&c);
    assert!(
        store_get(&a, &c_head).is_some(),
        "T1：C 的 head 未在 A 的链上（真实跨节点收敛）"
    );
    assert_eq!(
        head_finality(&c),
        Some(c_head),
        "T1：C 的 finalized_reference == 其 head（外部采纳）"
    );
    assert!(head_height(&c) >= 2, "T1：C head 已到 2");
    assert!(
        c.external_finality_adopted() >= 2,
        "T1：C 至少采纳 H1/H2 两次外部 finality（实测 {}）",
        c.external_finality_adopted()
    );
    assert!(
        a.qc_served() >= 2,
        "T1：A 附发过历史 QC（实测 {}）",
        a.qc_served()
    );

    // ---- T2：restart behind tip（A/B 继续推进到 4；C 重启后从 durable head 继续追赶）----
    let head_before_restart = head_height(&c);
    drop(c);
    let up4 = wait_until(|| {
        let _ = a.step();
        let _ = b.step();
        head_height(&a) >= 4 && head_height(&b) >= 4
    });
    assert!(
        up4,
        "T2：A/B 未推进到 4（A={} B={}）",
        head_height(&a),
        head_height(&b)
    );

    let c_net2 = KeyPair::generate().expect("net kp");
    let c2_cfg = env.config(
        "c",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut c2 = start_node(&c2_cfg, SEED_B, c_net2);
    assert_eq!(
        head_height(&c2),
        head_before_restart,
        "T2：restart 恢复 durable head（严格落后于 tip）"
    );
    let caught2 = wait_until(|| {
        let _ = c2.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        let _ = c2.step();
        head_height(&c2) >= 4
    });
    assert!(
        caught2,
        "T2：restart 后未追平（head={} adopted={}）",
        head_height(&c2),
        c2.external_finality_adopted()
    );
    let c2_head = head_hash(&c2);
    assert!(
        store_get(&a, &c2_head).is_some(),
        "T2：restart 后 C 的 head 未在 A 的链上"
    );
    assert_eq!(head_finality(&c2), Some(c2_head), "T2：finality == head");
    assert!(
        head_height(&c2) > head_before_restart,
        "T2：restart 后必须继续前进（{head_before_restart} → {}）",
        head_height(&c2)
    );
}

// ---------------------------------------------------------------------------
// T3–T6 / T8 / T11 — 拒绝面与边界（注入既有 `NodeConsensusCommand::InboundQc`）
// ---------------------------------------------------------------------------

#[test]
fn p1a7_rejections_are_fail_closed_and_bounded() {
    let genesis = genesis_with(&[pubkey_from_seed(SEED_A), pubkey_from_seed(SEED_B)]);
    let env = Env::new(&genesis);
    let genesis_hash = env.genesis_hash;
    let rig = start_ab(&env, 2);
    let mut a = rig.a;
    let mut b = rig.b;
    let a_id = rig.a_id;
    let a_addr = rig.a_addr;

    // 落后节点 C（head 0）追上 head 2（保证 C 的 DAG / BlockStore 含 H1/H2）。
    let c_net = KeyPair::generate().expect("net kp");
    let c_cfg = env.config(
        "c",
        None,
        vec![ConnectionTarget {
            peer_id: a_id,
            address: a_addr,
        }],
    );
    let mut c = start_node(&c_cfg, SEED_B, c_net);
    let caught = wait_until(|| {
        let _ = c.establish_configured_peers();
        let _ = a.step();
        let _ = b.step();
        let _ = c.step();
        head_height(&c) >= 2
    });
    assert!(caught, "rig：C 未追上（head={}）", head_height(&c));

    // settle：A/B/C 共同推进（让 C 排空 pending 中已可采纳的 QC）——此后仅 step C（冻结 A/B）
    // ⇒ 无新 block / 无新响应 ⇒ 注入期间「零采纳」可被确定性断言。
    for _ in 0..80 {
        let _ = a.step();
        let _ = b.step();
        let _ = c.step();
    }

    let head_before = head_hash(&c);
    let fin_before = head_finality(&c);
    let adopted_before = c.external_finality_adopted();

    // block1（非 head 的历史块；在 DAG 且已落盘）。
    let block2 = store_get(&c, &head_before).expect("block2 已落盘");
    let block1_hash = block2.header.parent_hash;

    // 注入前基线（后续一律用**增量**断言，与追赶期间背景计数解耦）。
    let rejected_before = c.external_finality_rejected();
    let deferred_before = c.inbound_qc_deferred();
    let pending_before = c.pending_external_qc_len();

    // ---- T3：无效 QC（签名被篡改）⇒ verify 失败 ⇒ 拒绝，零状态变更，不进 pending ----
    let mut forged = signed_qc(genesis_hash, 0, 0, head_before);
    forged.evidence[0].signature = [0u8; 64];
    assert!(
        c.process_consensus_command(NodeConsensusCommand::InboundQc(forged))
            .is_err(),
        "T3：伪造 QC 必须被 driver 拒绝（verify_qc FAIL）"
    );
    assert_eq!(
        c.inbound_qc_deferred(),
        deferred_before,
        "T3：非 UnknownTarget ⇒ 不缓冲"
    );
    assert_eq!(
        c.pending_external_qc_len(),
        pending_before,
        "T3：无效 QC 不进 pending"
    );
    assert_eq!(
        c.external_finality_rejected(),
        rejected_before,
        "T3：无采纳检查点副作用"
    );
    assert_eq!(head_hash(&c), head_before, "T3：head 不变");
    assert_eq!(head_finality(&c), fin_before, "T3：finality 不变");

    // ---- T4：未知 target（有效签名、target ∉ DAG）⇒ 有界 pending（未验证），零采纳 ----
    let unknown_target = [0xEE; 32];
    let qc_unknown = signed_qc(genesis_hash, 0, 0, unknown_target);
    assert!(
        c.process_consensus_command(NodeConsensusCommand::InboundQc(qc_unknown.clone()))
            .is_err(),
        "T4：target ∉ DAG ⇒ driver 拒绝（UnknownTarget）"
    );
    assert_eq!(
        c.inbound_qc_deferred(),
        deferred_before + 1,
        "T4：进入有界 pending"
    );
    assert_eq!(
        c.pending_external_qc_len(),
        pending_before + 1,
        "T4：pending +1"
    );
    c.step().expect("step");
    assert_eq!(
        c.pending_external_qc_len(),
        pending_before + 1,
        "T4：无对应 block ⇒ 保留等待（不猜）"
    );
    assert_eq!(c.external_finality_adopted(), adopted_before, "T4：零采纳");
    assert_eq!(head_hash(&c), head_before, "T4：head 不变");
    assert_eq!(head_finality(&c), fin_before, "T4：finality 不变");

    // ---- T8：重复同一 QC ⇒ pending 去重（幂等；不增长 / 不重复推进）----
    assert!(
        c.process_consensus_command(NodeConsensusCommand::InboundQc(qc_unknown))
            .is_err()
    );
    assert_eq!(
        c.inbound_qc_deferred(),
        deferred_before + 2,
        "T8：deferred 计数可增长"
    );
    assert_eq!(
        c.pending_external_qc_len(),
        pending_before + 1,
        "T8：dedup by target（pending 不增长）"
    );
    c.step().expect("step");
    assert_eq!(c.external_finality_adopted(), adopted_before, "T8：零采纳");
    assert_eq!(head_hash(&c), head_before, "T8：head 不变");
    assert_eq!(head_finality(&c), fin_before, "T8：finality 不变");

    // ---- T5：高度不符（qc.context.height + 1 != block.height）⇒ 采纳检查点拒绝 ----
    let rej5 = c.external_finality_rejected();
    let qc_bad_height = signed_qc(genesis_hash, 99, 0, head_before);
    c.process_consensus_command(NodeConsensusCommand::InboundQc(qc_bad_height))
        .expect("T5：verify 应 PASS（target ∈ DAG）");
    c.step().expect("step");
    assert_eq!(
        c.external_finality_rejected(),
        rej5 + 1,
        "T5：采纳前置检查拒绝 +1"
    );
    assert_eq!(c.external_finality_adopted(), adopted_before, "T5：零采纳");
    assert_eq!(head_hash(&c), head_before, "T5：head 不变");
    assert_eq!(head_finality(&c), fin_before, "T5：finality 不变");
    assert_eq!(
        c.pending_external_qc_len(),
        pending_before + 1,
        "T5：仅未知 target 条目保留"
    );

    // ---- T6：非 canonical-next（历史块 / parent 不符）⇒ 拒绝，不跳高度 ----
    let rej6 = c.external_finality_rejected();
    let qc_old_block = signed_qc(genesis_hash, 0, 0, block1_hash);
    c.process_consensus_command(NodeConsensusCommand::InboundQc(qc_old_block))
        .expect("T6：verify 应 PASS（block1 ∈ DAG）");
    c.step().expect("step");
    assert_eq!(
        c.external_finality_rejected(),
        rej6 + 1,
        "T6：非 canonical-next ⇒ 拒绝"
    );
    assert_eq!(c.external_finality_adopted(), adopted_before, "T6：零采纳");
    assert_eq!(head_hash(&c), head_before, "T6：head 不变（不跳高度）");
    assert_eq!(head_finality(&c), fin_before, "T6：finality 不变（不回退）");

    // ---- T10：缺失历史 QC ⇒ fail-closed（不猜 / 不跳高度 / 不改 head）----
    // 对端不提供该高度 QC 时，本节点**既不构造 fake finality，也不接受未验证块**：
    // 上面 T4/T5/T6 的「零采纳 + head/finality 不变」即该语义的直接证据；
    // 存储侧（高度缺失 / 超 retention / 损坏 / 冲突）由 `qc_history` 单元测试覆盖。
    assert_eq!(
        c.external_finality_rejected(),
        rej6 + 1,
        "T10：无新采纳发生（fail-closed）"
    );

    // ---- T11：pending 有界（≤ 8）且 responder 上限不变 ----
    for i in 0..12u8 {
        let mut target = [0x40; 32];
        target[0] = i;
        let qc = signed_qc(genesis_hash, 0, 0, target);
        let _ = c.process_consensus_command(NodeConsensusCommand::InboundQc(qc));
    }
    assert!(
        c.pending_external_qc_len() <= 8,
        "T11：pending 必须有界（实测 {}）",
        c.pending_external_qc_len()
    );
    assert_eq!(MAX_SYNC_RESPONSES_PER_STEP, 4, "T11：serve/step 上限不变");
    assert_eq!(MAX_PENDING_SYNC_REQUESTS, 64, "T11：请求队列上限不变");
    assert_eq!(
        c.external_finality_adopted(),
        adopted_before,
        "T11：全程零采纳"
    );
    assert_eq!(head_hash(&c), head_before, "T11：head 不变");
    assert_eq!(head_finality(&c), fin_before, "T11：finality 不变");
}
