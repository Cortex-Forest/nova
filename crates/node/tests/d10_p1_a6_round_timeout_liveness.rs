//! P1-A.6 — **Round Timeout Liveness**（node-local pacemaker；ADR-0049 冻结语义的 node 层落地）。
//!
//! # 被验证的不变量
//! - `window(round) = min(initial × backoff^round, max)`（冻结 `RoundTimeoutConfig` 语义；**逻辑 step
//!   tick** 解释，非协议常量）。
//! - 计时器绑 `(height, round)`：新轮 / 新高度 ⇒ **不继承** elapsed（ADR-0049 §3.3）。
//! - 到期 ⇒ 调用**既有** `ConsensusNode::round_timeout()`（不新增共识语义、不产生 vote / QC /
//!   finality / lock / DAG 变更、不广播）；新当选 proposer 随后走**既有**提案路径。
//! - DISARM 必须「已被 finality 确认」（`step == Finalized` **且** proposal 存在 **且**
//!   `finalized_reference == proposal.block_hash`）—— P1-A.5 实测的「Finalized 但无 finality」
//!   状态必须仍可 timeout，否则该高度永久滞留。
//! - timeout 不改 consensus authority：陈旧 proposal / 陈旧 QC 不产生投票 / 不回滚 finality /
//!   不改 lock 语义 / 不破坏 P1-A.4–A.5 的拒绝与容忍边界。
//! - 计时器**不持久化**：restart 后全新窗口（无 stale deadline），round 亦不持久化。
//!
//! # 确定性
//! 全部测试用 **逻辑 tick**（无 `sleep` / 无墙钟 / 无并发）：`set_round_timeout_config` 提供
//! node-local 测试 seam（非生产配置面：无 CLI flag、不进 `NodeConfig`、不改共识语义）；
//! fixture 由**固定 seed 扫描**构造（无 RNG 依赖 ⇒ 每次运行同一 fixture）。
//!
//! 纪律：不修改 consensus / driver / assembly / bin / bootstrap / D8；不新增依赖；fixture 仅写
//! 系统临时目录。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nova_consensus::finality::{FinalityError, QcContext, QuorumCertificate};
use nova_consensus::proposer::select_proposer;
use nova_consensus::round::{ProposalRef, RoundStep, RoundTimeoutConfig};
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_consensus::vote::VoteType;
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
};
use nova_crypto::domain::SigningMessageHash;
use nova_crypto::identity::{
    AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
    canonical_genesis_bytes, compute_genesis_hash,
};
use nova_crypto::key::KeyPair;
use nova_crypto::signature::{Signature, SigningKey, VerifyingKey, sign_message_hash};
use nova_network::node_id::NodeId;
use nova_network::transport::MemoryTransport;
use nova_node::bootstrap::NodeConfig;
use nova_node::driver::DriverError;
use nova_node::key_provider::{KeyProvider, KeyProviderError};
use nova_node::network_identity::SoftwareNetworkIdentity;
use nova_node::runtime::{NodeRuntime, derive_validator_id};
use nova_node::signer::{SigningCapability, SigningError};
use nova_node::wiring::NodeConsensusCommand;

const CHAIN_ID: u64 = 1001;
const STAKE: u128 = 200_000;
/// 注入用的「不在本节点 DAG 的 target」。
const TARGET: [u8; 32] = [0xAA; 32];

/// 测试用极小窗口：round 0 ⇒ 3 tick，round 1 ⇒ 6 tick（backoff ×2），round 2+ ⇒ cap 6。
const WINDOW_ROUND0: u64 = 3;
const WINDOW_CAP: u64 = 6;

fn tiny_timeout() -> RoundTimeoutConfig {
    RoundTimeoutConfig {
        initial_timeout: WINDOW_ROUND0,
        max_timeout: WINDOW_CAP,
        backoff_factor: 2,
    }
}

// ---------------------------------------------------------------------------
// Test-only 确定性 signer / provider（seed 重建同一身份；跨 restart 可复现）
// ---------------------------------------------------------------------------

/// Test-only signer：真实 Ed25519 签名（经 crypto 公开 API）。
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

/// Test-only provider：每次 `load_signer` 从固定 seed **重新构造**（不共享对象 / 无 Arc / 无 global）
/// ⇒ 可真实模拟 restart 后同一 validator 身份的种子重建。
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
// Fixtures
// ---------------------------------------------------------------------------

fn addr(kh: [u8; 32]) -> YazimaoAddress {
    YazimaoAddress::from_payload(YazimaoAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: AddressType::UserAccount,
        network_id: NetworkId::Mainnet,
        key_hash: kh,
    })
}

/// TEST GENESIS ONLY：给定 `(consensus_public_key, bonded_stake)` 列表（≤ 3 个验证者，各自使用
/// **不同**的初始账户地址）；Σliquid == total_supply。
///
/// canonical 顺序（ADR-0015 / genesis-v1.md §63）：`initial_validator_set` 必须按 `validator_id`
/// 字节升序 —— 本 fixture 作为 genesis **作者**先排序（验证层禁止 sort-and-accept，测试构造可以）；
/// `initial_accounts` 按 payload bytes 升序（0x11… < 0x22… < 0x33…）。
fn genesis_for(validators: &[([u8; 32], u128)]) -> GenesisV1 {
    assert!(validators.len() <= 3, "本 fixture 仅支持 ≤ 3 个验证者");
    let mut sorted: Vec<([u8; 32], u128)> = validators.to_vec();
    sorted.sort_by_key(|(pk, _)| derive_validator_id(pk));
    let acc1 = AccountInit {
        address: addr([0x11; 32]),
        liquid_balance: 1_000_000,
    };
    let acc2 = AccountInit {
        address: addr([0x22; 32]),
        liquid_balance: 1_000_000,
    };
    let acc3 = AccountInit {
        address: addr([0x33; 32]),
        liquid_balance: 1_000_000,
    };
    let accounts = [acc1.address, acc2.address, acc3.address];
    GenesisV1 {
        network_id: NetworkId::Mainnet,
        chain_id: CHAIN_ID,
        genesis_timestamp: 1,
        initial_validator_set: sorted
            .iter()
            .enumerate()
            .map(|(i, (pk, stake))| ValidatorInit {
                account_address: accounts[i],
                consensus_public_key: *pk,
                bonded_stake: *stake,
                commission_bps: 0,
            })
            .collect(),
        initial_accounts: vec![acc1, acc2, acc3],
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
            total_supply: 3_000_000,
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
            std::env::temp_dir().join(format!("nova_p1a6_{}_{}_{}", std::process::id(), n, tag));
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

    fn config(&self, validator_enabled: bool) -> NodeConfig {
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
            listen_addr: None,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn head_height(rt: &NodeRuntime) -> u64 {
    rt.block_production()
        .map(|ad| ad.head().height)
        .unwrap_or(0)
}

/// 启动 runtime（网络已装配；注入 transport 的对端为「陌生 peer」—— 本文件不做任何网络注入）。
fn start_runtime(env: &Env, provider: Option<&dyn KeyProvider>) -> NodeRuntime {
    let net_kp = KeyPair::generate().expect("net keypair");
    let net_id = NodeId::from_verifying_key(net_kp.verifying_key());
    let (tx_self, _tx_stranger) = MemoryTransport::pair(net_id, NodeId::from_bytes([0x99; 32]));
    let cfg = env.config(provider.is_some());
    NodeRuntime::start_with_network(
        &cfg,
        provider,
        Box::new(tx_self),
        Box::new(SoftwareNetworkIdentity::new(net_kp)),
    )
    .expect("start_with_network")
}

fn start_full_node(env: &Env) -> NodeRuntime {
    start_runtime(env, None)
}

fn start_validator(env: &Env, seed: [u8; 32]) -> NodeRuntime {
    let provider = SeedKeyProvider::new(seed);
    start_runtime(env, Some(&provider as &dyn KeyProvider))
}

/// 「round-0 当选者缺席」确定性 fixture。
struct Fixture {
    env: Env,
    local_seed: [u8; 32],
    local_id: ValidatorId,
    genesis_hash: [u8; 32],
}

/// 固定 seed 扫描（**无 RNG 依赖**）：3 验证者，本地（权重 4/6 = 2/3 ⇒ 单票即达 quorum）+ 对端两个
/// （各 1/6 权重，**从不启动** ⇒ 缺席）；要求 `select_proposer(0, 0)` ≠ 本地（本节点不是 round-0
/// 当选者）。`local_proposer_at_round1` 进一步要求 round-1 当选者是 / 不是本地：
/// - `true`  ⇒ timeout 后**同一 step** 即可由本地出块（用于「恢复」断言）；
/// - `false` ⇒ round 1 仍无提案，且 round-1 当选者 ≠ round-0 当选者（用于「陈旧 proposal 不得被
///   投票」断言：`ProposalRef` 无 round 字段 ⇒ 只有当选者不同才能区分旧轮提案）。
fn absent_proposer_fixture(tag: &str, local_proposer_at_round1: bool) -> Fixture {
    const LOCAL_SEED: [u8; 32] = [0x77; 32];
    let local_pk = pubkey_from_seed(LOCAL_SEED);
    let local_id = derive_validator_id(&local_pk);
    for byte in 1u8..=255 {
        let other1_pk = pubkey_from_seed([byte; 32]);
        let other2_pk = pubkey_from_seed([!byte; 32]);
        if other1_pk == local_pk || other2_pk == local_pk || other1_pk == other2_pk {
            continue;
        }
        let genesis = genesis_for(&[
            (other1_pk, STAKE),
            (other2_pk, STAKE),
            (local_pk, 4 * STAKE),
        ]);
        let genesis_hash = compute_genesis_hash(&genesis).expect("genesis hash");
        let set = ValidatorSet::from_genesis(&genesis);
        let proposer0 = select_proposer(CHAIN_ID, 0, 0, &genesis_hash, &set).expect("proposer");
        if proposer0 == local_id {
            continue;
        }
        let proposer1 = select_proposer(CHAIN_ID, 0, 1, &genesis_hash, &set).expect("proposer");
        let round1_ok = if local_proposer_at_round1 {
            proposer1 == local_id
        } else {
            // 除「round-1 当选者 ≠ 本地」外，还需 `proposer1 != proposer0`：否则陈旧（round-0）
            // proposal 的 proposer 恰好 = 当前 round 期望当选者 ⇒ proposer-authority gate 放行
            // （ProposalRef 无 round 字段）⇒ 无法验证「未授权投票」断言。
            proposer1 != local_id && proposer1 != proposer0
        };
        if round1_ok {
            return Fixture {
                env: Env::new(&genesis, tag),
                local_seed: LOCAL_SEED,
                local_id,
                genesis_hash,
            };
        }
    }
    panic!("未能在 255 个确定性 seed 内找到满足条件的 fixture");
}

// ---------------------------------------------------------------------------
// T1 — 计时器：arm / 未到期 / 恰好到期 / 重开 / backoff / cap / 确定性
// ---------------------------------------------------------------------------

#[test]
fn p1a6_timer_expires_deterministically_with_backoff_and_cap() {
    let seed = [0x21u8; 32];
    let genesis = genesis_for(&[(pubkey_from_seed(seed), STAKE)]);
    let env_a = Env::new(&genesis, "t1a");
    // full-node：无 proposer / 无 vote ⇒ 无 canonical 进展 ⇒ 纯计时观测（确定性）。
    let mut rt = start_full_node(&env_a);
    assert!(!rt.validator_enabled(), "full-node（无提案 / 无投票）");
    rt.set_round_timeout_config(tiny_timeout());

    assert_eq!(rt.round_timeout_window_ticks(), None, "尚未 arm");
    assert_eq!(rt.round_timeout_elapsed_ticks(), None, "尚未 arm");
    assert_eq!(rt.round_timeouts(), 0);

    let mut trace = Vec::new();
    for step in 1..=WINDOW_ROUND0 {
        rt.step().expect("step");
        trace.push((
            rt.consensus().state().round.round,
            rt.round_timeouts(),
            rt.round_timeout_elapsed_ticks(),
            rt.round_timeout_window_ticks(),
        ));
        if step < WINDOW_ROUND0 {
            assert_eq!(rt.round_timeouts(), 0, "第 {step} step 未到期");
            assert_eq!(rt.consensus().state().round.round, 0, "round 不提前推进");
        }
    }
    // 恰好到达窗口 ⇒ 到期（且仅一次）
    assert_eq!(rt.round_timeouts(), 1, "window 到期 ⇒ 恰好一次 timeout");
    assert_eq!(rt.consensus().state().round.round, 1, "round 0 → 1");
    assert_eq!(
        rt.round_timeout_window_ticks(),
        Some(WINDOW_CAP),
        "backoff：round 0 = 3 → round 1 = 6"
    );
    assert_eq!(
        rt.round_timeout_elapsed_ticks(),
        Some(1),
        "新 round 立即重开（elapsed 不继承）"
    );
    // 逐 step elapsed（arming step 记 1；无进展 ⇒ 单调 +1）
    assert_eq!(trace[0].2, Some(1), "arming step elapsed = 1");
    assert_eq!(trace[1].2, Some(2));
    // 到期 step：计数 +1 且**同 step 内**已按新 round 重开（故观测 elapsed = 1，而非 window）。
    assert_eq!(trace[2].1, 1, "到期 step ⇒ timeout 计数 = 1");
    assert_eq!(trace[2].2, Some(1), "到期后立即 re-arm（elapsed 不继承）");

    // cap：round 1 窗口 = 6；到期后 round 2 的窗口仍 = 6（max）
    // （arming 已计 1 tick ⇒ 从 re-arm 到下次到期需 window - 1 个 step。）
    for _ in 0..(WINDOW_CAP - 2) {
        rt.step().expect("step");
        assert_eq!(rt.round_timeouts(), 1, "新窗口未到期");
    }
    rt.step().expect("step");
    assert_eq!(rt.round_timeouts(), 2, "第 {WINDOW_CAP} tick 到期");
    assert_eq!(rt.consensus().state().round.round, 2);
    assert_eq!(
        rt.round_timeout_window_ticks(),
        Some(WINDOW_CAP),
        "窗口 cap 于 max（不再增长）"
    );

    // 确定性 / 无墙钟：另一 fresh runtime 跑同一序列 ⇒ 逐 step 观测完全一致
    let env_b = Env::new(&genesis, "t1b");
    let mut rt2 = start_full_node(&env_b);
    rt2.set_round_timeout_config(tiny_timeout());
    let mut trace2 = Vec::new();
    for _ in 1..=trace.len() {
        rt2.step().expect("step");
        trace2.push((
            rt2.consensus().state().round.round,
            rt2.round_timeouts(),
            rt2.round_timeout_elapsed_ticks(),
            rt2.round_timeout_window_ticks(),
        ));
    }
    assert_eq!(trace, trace2, "同输入同输出（无墙钟 / 无随机 / 无线程）");

    rt.shutdown().expect("shutdown");
    rt2.shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// T2 — proposer 缺席 ⇒ timeout ⇒ 新 proposer ⇒ 既有全链 ⇒ head 前进
// ---------------------------------------------------------------------------

#[test]
fn p1a6_absent_proposer_recovers_liveness_after_timeout() {
    let fixture = absent_proposer_fixture("t2", true);
    let mut rt = start_validator(&fixture.env, fixture.local_seed);
    rt.set_round_timeout_config(tiny_timeout());

    let local_id = rt.validator().expect("validator view").validator_id();
    assert_eq!(local_id, fixture.local_id, "本地身份 = fixture 本地密钥");

    // 前提：round 0 当选者 = 对端（缺席）；round 1 当选者 = 本地（⇒ 有界恢复）
    let set = rt.consensus().validator_set().clone();
    assert_ne!(
        select_proposer(CHAIN_ID, 0, 0, &fixture.genesis_hash, &set).expect("proposer"),
        local_id,
        "前提：本地节点不是 round-0 当选者（该 proposer 缺席）"
    );
    assert_eq!(
        select_proposer(CHAIN_ID, 0, 1, &fixture.genesis_hash, &set).expect("proposer"),
        local_id,
        "前提：round-1 当选者 = 本地"
    );
    {
        let s = rt.consensus().state();
        assert_eq!((s.round.height, s.round.round), (0, 0));
        assert_eq!(s.round.step, RoundStep::Propose);
        assert!(s.round.proposal.is_none());
        assert!(s.finality.finalized_reference.is_none());
    }

    // 无进展 ⇒ 窗口到期（前 W-1 step 不得触发）
    for step in 1..WINDOW_ROUND0 {
        rt.step().expect("step");
        assert_eq!(rt.round_timeouts(), 0, "第 {step} step 不得提前 timeout");
        assert_eq!(rt.consensus().state().round.round, 0);
    }
    rt.step().expect("step");
    assert_eq!(rt.round_timeouts(), 1, "round 0 到期 ⇒ timeout");
    assert_eq!(rt.consensus().state().round.round, 1, "round 0 → 1");
    assert_eq!(head_height(&rt), 0, "timeout 本身不产生 commit（非证据）");

    // 既有 pipeline 继续：新当选 proposer 出块 → 既有提案/投票/QC/finality/commit
    let mut steps = 0usize;
    while head_height(&rt) == 0 {
        rt.step().expect("step");
        steps += 1;
        assert!(steps <= 8, "有界：round-1 当选者必须由既有路径出块");
    }
    assert_eq!(head_height(&rt), 1, "canonical head 前进");
    let head_hash = rt
        .block_production()
        .expect("validator adapter")
        .head()
        .block_hash;
    assert_eq!(
        rt.consensus().state().finality.finalized_reference,
        Some(head_hash),
        "finality = 已 commit 的 canonical 块（既有 verify_qc → finality → bridge 全链）"
    );
    assert_eq!(
        rt.consensus().state().round.height,
        1,
        "commit 后 advance_to_height 生效"
    );
    assert!(
        rt.validator()
            .expect("validator view")
            .actor()
            .locked_state()
            .is_locked(),
        "lock 经既有 QC 路由获得（未绕过 verify_qc / acquire_lock）"
    );
    assert!(rt.round_timeouts() >= 1, "timeout 计数单调（诊断）");
    rt.shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// T3 — 「Finalized 但无 finality」不得永久滞留（DISARM 判据精确性）
// ---------------------------------------------------------------------------

#[test]
fn p1a6_finalized_without_finality_still_times_out() {
    let seed = [0x31u8; 32];
    let genesis = genesis_for(&[(pubkey_from_seed(seed), STAKE)]);
    let env = Env::new(&genesis, "t3");
    let mut rt = start_validator(&env, seed);
    rt.set_round_timeout_config(tiny_timeout());

    let local_id = rt.validator().expect("validator view").validator_id();
    assert_eq!(
        select_proposer(
            CHAIN_ID,
            0,
            0,
            &env.genesis_hash,
            rt.consensus().validator_set()
        )
        .expect("proposer"),
        local_id,
        "单验证者 ⇒ 本地为 round-0 当选者"
    );

    // 注入「proposal 指向不存在的 block」⇒ 本地 prevote/precommit quorum，但派生 QC target ∉ DAG
    // （P1-A.5 场景）⇒ 冻结 transition 置 Finalized 而 **finality 不推进**。
    rt.process_consensus_command(NodeConsensusCommand::Proposal(ProposalRef {
        block_hash: TARGET,
        proposer: local_id,
    }))
    .expect("proposal 结构合法 ⇒ 应用");
    rt.step().expect("step：proposal 应用 + prevote quorum");
    rt.step()
        .expect("step：precommit quorum ⇒ Finalized（QC 不适用被容忍）");

    {
        let s = rt.consensus().state();
        assert_eq!(
            s.round.step,
            RoundStep::Finalized,
            "前提：precommit quorum ⇒ step = Finalized"
        );
        assert!(
            s.finality.finalized_reference.is_none(),
            "前提：QC target ∉ DAG ⇒ finality **未**推进（P1-A.5）"
        );
        assert!(s.round.proposal.is_some());
    }
    assert_eq!(rt.derived_qc_not_applicable(), 1, "P1-A.5 容忍语义保持");

    // **关键**：该状态不得 DISARM ⇒ 计时器必须仍能到期并推进 round（否则该高度永久滞留）
    let mut steps = 0usize;
    while rt.consensus().state().round.round == 0 {
        rt.step().expect("step");
        steps += 1;
        assert!(steps <= 8, "Finalized 但无 finality ⇒ 必须最终 timeout");
    }
    assert!(rt.round_timeouts() >= 1, "该滞留状态必须仍可 timeout");

    // 恢复：新 round 由本节点（唯一成员）出块 ⇒ 既有全链完成 finality / commit
    let mut steps = 0usize;
    while head_height(&rt) == 0 {
        rt.step().expect("step");
        steps += 1;
        assert!(steps <= 8, "有界恢复");
    }
    assert_eq!(head_height(&rt), 1, "滞留解除 ⇒ head 前进");
    assert_eq!(
        rt.consensus().state().finality.finalized_reference,
        Some(
            rt.block_production()
                .expect("validator adapter")
                .head()
                .block_hash
        ),
        "恢复路径同样经既有 finality 全链"
    );
    rt.shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// T4 — 陈旧（旧轮）proposal 不产生投票 / 不回退 / 不产生 conflicting finality
// ---------------------------------------------------------------------------

#[test]
fn p1a6_stale_old_round_proposal_is_not_voted() {
    let fixture = absent_proposer_fixture("t4", false);
    let mut rt = start_validator(&fixture.env, fixture.local_seed);
    rt.set_round_timeout_config(tiny_timeout());

    for _ in 0..WINDOW_ROUND0 {
        rt.step().expect("step");
    }
    assert_eq!(rt.round_timeouts(), 1, "round 0 到期");
    assert_eq!(rt.consensus().state().round.round, 1, "已进入 round 1");
    assert_eq!(
        rt.consensus().state().round.step,
        RoundStep::Propose,
        "round 1 无提案（该轮当选者缺席）"
    );

    // 注入**旧轮** proposal（proposer = round-0 当选者）。诚实记录：`ProposalRef` 无 (height, round)
    // 字段（ADR-0041 冻结编码）⇒ transition 只按 `step == Propose` 判定，无法按轮拒收。
    let old_proposer = select_proposer(
        CHAIN_ID,
        0,
        0,
        &fixture.genesis_hash,
        rt.consensus().validator_set(),
    )
    .expect("proposer");
    let stale = ProposalRef {
        block_hash: TARGET,
        proposer: old_proposer,
    };
    rt.process_consensus_command(NodeConsensusCommand::Proposal(stale))
        .expect("结构合法 ⇒ 被接受为当前 round 的 proposal");

    rt.step()
        .expect("step（不得因陈旧 proposal 而投票 / 不得致命）");
    let state = rt.consensus().state();
    assert_eq!(state.round.round, 1, "当前 round 不回退");
    assert_eq!(
        state.round.step,
        RoundStep::Prevote,
        "proposer-authority gate 拒绝驱动 ⇒ 未产生任何本地投票"
    );
    assert_eq!(
        state.round.prevotes.weight_of(&TARGET),
        0,
        "旧轮 proposal 不得获得任何本地票权重"
    );
    assert!(
        state.finality.finalized_reference.is_none(),
        "无 finality（更不可能产生 conflicting finality）"
    );
    assert_eq!(head_height(&rt), 0, "无 commit");
    assert!(
        state
            .round
            .proposal
            .as_ref()
            .is_some_and(|p| p.block_hash == TARGET),
        "已知协议级观察：陈旧 proposal 可被安装（编码无 round 字段）—— 但不得被投票"
    );

    // runtime 持续可用（不得因陈旧输入致命）
    for _ in 0..4 {
        rt.step().expect("节点必须仍可驱动");
    }
    assert!(rt.round_timeouts() >= 1, "计数单调");
    rt.shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// T5 — 陈旧 QC：不改 canonical / 不回滚 finality / 不改 lock 语义 / 容忍边界保持
// ---------------------------------------------------------------------------

#[test]
fn p1a6_stale_qc_does_not_mutate_canonical_state() {
    let fixture = absent_proposer_fixture("t5", true);
    let mut rt = start_validator(&fixture.env, fixture.local_seed);
    rt.set_round_timeout_config(tiny_timeout());

    // 跑到第一个 commit（round-1 当选者 = 本地）
    let mut steps = 0usize;
    while head_height(&rt) == 0 {
        rt.step().expect("step");
        steps += 1;
        assert!(steps <= 16, "有界：必须完成一次 commit");
    }
    assert_eq!(head_height(&rt), 1);

    let head_hash = rt
        .block_production()
        .expect("validator adapter")
        .head()
        .block_hash;
    let finalized_before = rt.consensus().state().finality.finalized_reference;
    assert_eq!(finalized_before, Some(head_hash));
    let lock_before = *rt
        .validator()
        .expect("validator view")
        .actor()
        .locked_state();
    assert!(lock_before.is_locked(), "commit 后本节点已持 lock");
    let rejected_before = rt.inbound_consensus_rejected();
    let not_applicable_before = rt.derived_qc_not_applicable();

    // ---------- Case A：真实旧轮 QC，target ∈ DAG（由本节点自己产生并缓存的 PrecommitQC）----------
    let qc = rt
        .driver()
        .consensus()
        .last_precommit_qc()
        .cloned()
        .expect("已缓存与 finality 一致的 PrecommitQC");
    assert_eq!(
        qc.target, head_hash,
        "QC target = 已 commit 的 canonical 块"
    );
    assert!(rt.consensus().dag().contains(&qc.target), "target ∈ DAG");
    rt.process_consensus_command(NodeConsensusCommand::InboundQc(qc))
        .expect("verify_qc PASS ⇒ 命令被接受");

    let state = rt.consensus().state();
    assert_eq!(
        state.finality.finalized_reference, finalized_before,
        "无 finality 回滚 / 无 finality 变更"
    );
    assert_eq!(head_height(&rt), 1, "无 canonical 回滚");
    assert_eq!(
        rt.inbound_consensus_rejected(),
        rejected_before,
        "verify PASS ⇒ 不计入入站拒绝"
    );
    assert_eq!(
        *rt.validator()
            .expect("validator view")
            .actor()
            .locked_state(),
        lock_before,
        "同 target ⇒ acquire_lock no-op（lock 语义不变）"
    );

    // ---------- Case B：target ∉ DAG 的 QC ⇒ 入站边界仍拒绝（P1-A.4 语义）----------
    let unknown = QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target: TARGET,
        validator_set_id: fixture.genesis_hash,
        evidence: Vec::new(),
    };
    let err = rt
        .process_consensus_command(NodeConsensusCommand::InboundQc(unknown))
        .expect_err("target ∉ DAG ⇒ 入站命令被拒绝");
    assert!(
        matches!(
            err,
            DriverError::QcVerification(FinalityError::UnknownTarget)
        ),
        "拒绝原因 = QC 验证失败（UnknownTarget）"
    );
    assert_eq!(
        rt.derived_qc_not_applicable(),
        not_applicable_before,
        "入站 QC 不进入派生路径计数（两计数相互独立）"
    );
    let state = rt.consensus().state();
    assert_eq!(
        state.finality.finalized_reference, finalized_before,
        "被拒 QC 不改 canonical / finality"
    );
    assert_eq!(head_height(&rt), 1, "被拒 QC 不 commit / 不回滚");
    assert_eq!(
        *rt.validator()
            .expect("validator view")
            .actor()
            .locked_state(),
        lock_before,
        "被拒 QC 不得改 lock"
    );

    // runtime 继续可驱动（无 panic / 无致命）
    rt.step().expect("节点仍可驱动");
    rt.shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// T6 — restart：计时器不持久化 ⇒ 全新窗口（无 stale deadline）；无 safety 回归
// ---------------------------------------------------------------------------

#[test]
fn p1a6_restart_uses_fresh_timer_without_regression() {
    let fixture = absent_proposer_fixture("t6", false);
    let mut rt = start_validator(&fixture.env, fixture.local_seed);
    rt.set_round_timeout_config(tiny_timeout());

    for _ in 0..WINDOW_ROUND0 {
        rt.step().expect("step");
    }
    assert_eq!(rt.round_timeouts(), 1, "round 0 到期");
    assert_eq!(rt.consensus().state().round.round, 1, "round 已推进");
    assert_eq!(head_height(&rt), 0, "无 commit");
    assert!(
        rt.consensus()
            .state()
            .finality
            .finalized_reference
            .is_none(),
        "无 finality"
    );
    rt.shutdown().expect("shutdown（storage / safety 落盘）");

    // 重启：同一 seed ⇒ 同一 validator 身份；round / 计时器状态**不**持久化
    let mut rt2 = start_validator(&fixture.env, fixture.local_seed);
    assert_eq!(
        rt2.validator().expect("validator view").validator_id(),
        fixture.local_id,
        "restart 后同一 validator 身份"
    );
    assert_eq!(
        rt2.consensus().state().round.round,
        0,
        "round 不持久化 ⇒ 回到 round 0"
    );
    assert_eq!(rt2.round_timeouts(), 0, "计时器状态不持久化");
    assert_eq!(rt2.round_timeout_elapsed_ticks(), None, "restart 后未 arm");
    assert_eq!(head_height(&rt2), 0, "head 不前进 / 不回退");
    assert!(
        rt2.consensus()
            .state()
            .finality
            .finalized_reference
            .is_none(),
        "finality 不回滚 / 不新增"
    );

    // 无 stale deadline：fresh 窗口 ⇒ 前 W-1 step 不得触发，第 W step 确定触发（可继续推进）
    rt2.set_round_timeout_config(tiny_timeout());
    for step in 1..WINDOW_ROUND0 {
        rt2.step().expect("step");
        assert_eq!(
            rt2.round_timeouts(),
            0,
            "第 {step} step 不得提前触发（无 stale deadline 继承）"
        );
    }
    rt2.step().expect("step");
    assert_eq!(rt2.round_timeouts(), 1, "fresh 窗口 ⇒ 确定在第 W step 触发");
    assert_eq!(
        rt2.consensus().state().round.round,
        1,
        "restart 后仍可经 timeout 推进 round（liveness 恢复）"
    );
    rt2.shutdown().expect("shutdown");
}
