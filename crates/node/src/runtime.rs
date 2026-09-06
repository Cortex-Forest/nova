//! NodeRuntime —— 生产节点生命周期装配层（STEP 10-16；Phase 1 骨架）。
//!
//! # 职责（仅装配 / 生命周期；不实现共识算法）
//! 固定启动顺序：`Config → Genesis → ChainIdentity 校验 → chain storage →（validator mode）
//! KeyProvider → derive ValidatorId → SafetyStore open → strict recover → ValidatorActor →
//! ConsensusNode → NodeConsensusDriver`（STEP 10-18I-C：Runtime 经 [`crate::driver::NodeConsensusDriver`]
//! 持有 ConsensusNode + ValidatorActor）。Stage C（STEP 10-18I-G）：Network / EventLoop /
//! NetworkIdentity 以可选 `NetworkStack` 装配（`start` = 网络 disabled；`start_with_network` = 启用）。
//!
//! # 边界
//! - [`NodeRuntime`] **拥有生命周期**（组件创建顺序 / 注入），但：
//!   - 不持有共识状态（`ConsensusNode` 是 canonical 状态 owner，Runtime 只持 handle 引用层）；
//!   - 不改变 `ConsensusState` / 共识算法 / DAG / finality / fork choice；
//!   - 不替代 [`crate::validator::ValidatorActor`]（安全逻辑仍在 actor 内）；
//!   - **不存储私钥 / vote history / SafetyRecord**（私钥在 SigningCapability 边界内；
//!     vote history 在 ValidatorSafetyStore / actor ledger）。
//! - chain storage（`config.storage_dir`）与 validator safety storage（`config.safety_dir`）
//!   **目录分离**，绝不混用；SafetyStore recover 失败 = validator mode 启动失败（fail closed）。
//! - full-node（`validator_enabled=false`）：跳过 key / safety / validator，不触碰 Provider。

use std::path::PathBuf;

use nova_consensus::dag::Dag;
use nova_consensus::validator::{ValidatorId, ValidatorSet};
use nova_crypto::identity::ChainIdentity;
use nova_network::event_loop::{EventLoop, EventLoopConfig, EventLoopError};
use nova_network::message::NetworkError;
use nova_network::network_service::{NetworkService, NetworkServiceConfig};
use nova_network::node_id::NodeId;
use nova_network::transport::Transport;
use nova_storage::error::StorageError;
use nova_storage::persistent::PersistentBackend;

use crate::assembly::ConsensusNode;
use crate::bootstrap::{self, NodeConfig, NodeStartupError};
use crate::driver::{DriverError, NodeConsensusDriver};
use crate::key_provider::{KeyProvider, KeyProviderError};
use crate::network_identity::NetworkSigner;
use crate::outbound::OutboundConsensusMessage;
use crate::proposer::proposer_decision;
use crate::safety_store::{SafetyIdentity, ValidatorSafetyError, ValidatorSafetyStore};
use crate::signer::SigningCapability;
use crate::validator::{ValidatorActor, ValidatorActorError};
use crate::wiring::{NodeConsensusCommand, NodeConsensusHandler, process_command};

/// ValidatorActor 的签名能力类型（Phase 1：trait object）。
type DynSigner = Box<dyn SigningCapability>;

/// Node-local proposer step（STEP 10-19-2）：判定本节点是否当前 proposer → submit ProposalRef。
///
/// - 纯编排：`driver.consensus()` 只读判定；提交走 `NodeConsensusDriver::submit_proposal`
///   （`SetProposal` → canonical transition；阶段守卫 + 幂等由 decision 与 consensus 保证）。
/// - 不自动投票：proposal 成功后 local vote 仍走既有 `submit_local_vote` 路径（ValidatorActor）。
/// - 无 validator actor ⇒ no-op；decision 错误（非法 ValidatorSet）⇒ `Err`（fail-closed）。
fn runtime_propose(
    driver: &mut NodeConsensusDriver<DynSigner>,
) -> Result<(), nova_consensus::error::ConsensusError> {
    let Some(local_id) = driver.actor(0).map(|a| a.validator_id()) else {
        return Ok(());
    };
    let decision = proposer_decision(local_id, driver.consensus())?;
    if let Some(pr) = decision {
        let _ = driver.submit_proposal(pr);
    }
    Ok(())
}

/// NodeRuntime 启动错误（node-local；typed；fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRuntimeError {
    /// genesis / storage / identity 校验失败（复用 bootstrap NodeStartupError）。
    Startup(NodeStartupError),
    /// validator mode 但未提供 KeyProvider（fail closed：不默认生成不稳定密钥）。
    KeyNotProvisioned,
    /// KeyProvider 加载 signer 失败。
    KeyProvider(KeyProviderError),
    /// SafetyStore create / recover / identity 校验失败。
    Safety(ValidatorSafetyError),
    /// ValidatorActor 构造 / 恢复失败（含 identity mismatch）。
    Validator(ValidatorActorError),
}

/// Runtime 运行期错误（Stage C `step`；分层、不吞错、不改底层语义）。
#[derive(Debug)]
pub enum RuntimeError {
    /// EventLoop / Network 错误（poll/dispatch 层；NS 错误经 `EventLoopError::Network` 内嵌）。
    EventLoop(EventLoopError),
    /// Driver 验证 / transition 门面失败（与网络错误分层 —— 不伪装成 NetworkError）。
    Driver(DriverError),
    /// Node Egress 网络签名失败（fail-closed；不吞安全错误）。
    Egress(crate::egress::EgressError),
    /// Node-local Proposer orchestration 失败（select_proposer 非法 ValidatorSet；fail-closed）。
    Proposer(nova_consensus::error::ConsensusError),
}

/// Runtime 关闭错误（Stage C `shutdown`；仅 Storage 可失败 ——
/// EventLoop/NetworkService shutdown 均 infallible，Driver 无显式 shutdown）。
#[derive(Debug)]
pub enum ShutdownError {
    /// ChainStorage 关闭失败（`PersistentBackend::close`）。
    Storage(StorageError),
}

/// 最小 trait-object transport 适配（Stage C）：使 `Box<dyn Transport>` 满足 `Transport`
/// bound（network crate 不提供 blanket impl；**不修改** network crate）。
/// 非 speculative abstraction —— 必要 trait-object 适配（D1 冻结：Runtime 组合层类型擦除）。
struct BoxTransport(Box<dyn Transport>);

impl Transport for BoxTransport {
    fn send(&mut self, peer: &NodeId, message: Vec<u8>) -> Result<(), NetworkError> {
        self.0.send(peer, message)
    }

    fn try_recv(&mut self) -> Result<Option<(NodeId, Vec<u8>)>, NetworkError> {
        self.0.try_recv()
    }
}

/// Stage C 网络子栈（最小 owned container；非 factory / provider / framework）。
///
/// - `ns`：网络状态 owner（own `Transport` / peers / queues；内部经 `Box<dyn Transport>` 注入）。
/// - `el`：dispatch-only（own handler / queue / timer；**不拥有** `ns` —— poll 经注入借用）。
/// - `signer`：网络身份（NodeId + envelope 签名；与 validator identity 分离）。
struct NetworkStack {
    ns: NetworkService<BoxTransport>,
    el: EventLoop<NodeConsensusHandler>,
    signer: Box<dyn NetworkSigner>,
}

impl NetworkStack {
    /// 本网络身份 NodeId（= 网络 key pubkey；≠ ValidatorId）。
    fn node_id(&self) -> NodeId {
        self.signer.node_id()
    }
}

/// 单验证者只读 **compatibility view**（STEP 10-18I-C；非 owning）。
///
/// - ValidatorActor 的真正 ownership 在 [`NodeConsensusDriver`]（`actors: Vec<ValidatorActor<DynSigner>>`）。
/// - [`NodeRuntime::validator`] 在调用时**动态构造**本 view（含对 `driver.actor(0)` 的借用），
///   避免 self-referential ownership；不长期存储 actor 引用字段。
pub struct ValidatorView<'a> {
    validator_id: ValidatorId,
    journal_path: &'a std::path::Path,
    actor: &'a ValidatorActor<DynSigner>,
}

impl ValidatorView<'_> {
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// 本地 ValidatorActor（只读；safety/signing owner 在 actor —— 经 driver 拥有）。
    pub fn actor(&self) -> &ValidatorActor<DynSigner> {
        self.actor
    }

    pub fn journal_path(&self) -> &std::path::Path {
        self.journal_path
    }
}

/// 生产节点生命周期装配根（STEP 10-16 Phase 1 骨架；STEP 10-18I-C ownership migration；
/// STEP 10-18I-G Stage C Full Composition）。
///
/// - **ConsensusNode + ValidatorActor 的实际 ownership 在 [`NodeConsensusDriver`]**（`driver` 字段）；
///   Runtime **不再**独立持有 ConsensusNode / ValidatorActor（避免 duplication，ADR-0057）。
/// - 网络（NetworkService / EventLoop / NetworkSigner）以可选 [`NetworkStack`] 装配：
///   `start()` ⇒ `None`（网络 disabled，不生成网络身份）；`start_with_network()` ⇒ `Some`。
/// - Runtime 只负责 composition / lifecycle / accessor delegation（最终 lifecycle coordinator）。
pub struct NodeRuntime {
    chain_identity: ChainIdentity,
    chain_storage: PersistentBackend,
    driver: NodeConsensusDriver<DynSigner>,
    /// 可选网络子栈（Stage C；`start` ⇒ `None`）。
    network_stack: Option<NetworkStack>,
    /// validator 元数据（safety journal 路径；actor 本体在 driver）。full-node ⇒ `None`。
    validator_journal: Option<PathBuf>,
}

impl NodeRuntime {
    /// 启动（网络 disabled）：Consensus + Storage（+ validator）正常启动；**不**装配
    /// NetworkStack（不生成网络身份）。行为与 Stage C 前完全兼容。
    pub fn start(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, None)
    }

    /// 启动（Stage C Full Composition）：在 `start` 基础上注入网络 assets ——
    /// `transport: Box<dyn Transport>`（MemoryTransport test/dev；未来 production adapter 注入）
    /// 与 `network_identity: Box<dyn NetworkSigner>`（网络身份；**不得**用 validator key）。
    ///
    /// 顺序保证：`NetworkIdentity → node_id() → NetworkService::new(self_id, transport)`；
    /// `NodeId = NetworkSigner::node_id()`（≠ ValidatorId）。
    pub fn start_with_network(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        transport: Box<dyn Transport>,
        network_identity: Box<dyn NetworkSigner>,
    ) -> Result<Self, NodeRuntimeError> {
        Self::start_inner(config, key_provider, Some((transport, network_identity)))
    }

    /// 内部启动：固定顺序（§模块 doc）。任何安全失败 ⇒ `Err`（fail closed）。
    ///
    /// - `key_provider`：validator mode 时**必须**提供（None ⇒ `KeyNotProvisioned`）；
    ///   full-node 时忽略。
    /// - `network_assets`：`Some((transport, network_identity))` ⇒ 装配 NetworkStack。
    /// - SafetyStore 打开 / recover 仍在 Runtime lifecycle（`build_validator`）；
    ///   Driver 只接收已构造好的 `ConsensusNode` + `ValidatorActor(s)`。
    fn start_inner(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
        network_assets: Option<(Box<dyn Transport>, Box<dyn NetworkSigner>)>,
    ) -> Result<Self, NodeRuntimeError> {
        // 2/3. Genesis + ChainIdentity validation（expected hash/chain/network）。
        let (genesis, identity) =
            bootstrap::load_genesis(config).map_err(NodeRuntimeError::Startup)?;

        // 4. chain storage init（独立目录；PersistentBackend；Phase 1 只打开/持有 handle）。
        std::fs::create_dir_all(&config.storage_dir)
            .map_err(|_| NodeRuntimeError::Startup(NodeStartupError::StorageIo))?;
        let chain_storage = PersistentBackend::open(&config.storage_dir)
            .map_err(NodeStartupError::Storage)
            .map_err(NodeRuntimeError::Startup)?;

        // 10. ConsensusNode（canonical state owner）——随后装配进 NodeConsensusDriver。
        let set = ValidatorSet::from_genesis(&genesis);
        let consensus = ConsensusNode::new(
            0,
            0,
            identity.chain_id,
            set,
            identity.genesis_hash,
            Dag::new(),
        );

        // 5–11. validator mode：KeyProvider → id → SafetyStore → recover → ValidatorActor
        //      （Runtime lifecycle）→ 与 ConsensusNode 一并装配进 NodeConsensusDriver。
        let (driver, validator_journal) = if config.validator_enabled {
            let (actor, journal_path) = Self::build_validator(config, &identity, key_provider)?;
            let driver = NodeConsensusDriver::new(consensus, vec![actor]);
            (driver, Some(journal_path))
        } else {
            // full-node：consensus-only driver（actors = []）；不触碰 Provider。
            let driver = NodeConsensusDriver::<DynSigner>::new(consensus, Vec::new());
            (driver, None)
        };

        // Stage C：网络资产注入 ⇒ NetworkStack（identity → node_id → NetworkService）。
        let network_stack = network_assets.map(|(transport, network_identity)| {
            let self_id = network_identity.node_id();
            let ns = NetworkService::new(
                NetworkServiceConfig::default(),
                self_id,
                BoxTransport(transport),
            );
            let el = EventLoop::new(EventLoopConfig::default(), NodeConsensusHandler::new());
            NetworkStack {
                ns,
                el,
                signer: network_identity,
            }
        });

        Ok(Self {
            chain_identity: identity,
            chain_storage,
            driver,
            network_stack,
            validator_journal,
        })
    }

    /// validator mode 生命周期装配（key provider → derive id → safety store → recover → actor）。
    /// 返回 `(actor, journal_path)`；actor 随后移入 Driver（ownership）。
    fn build_validator(
        config: &NodeConfig,
        identity: &ChainIdentity,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<(ValidatorActor<DynSigner>, PathBuf), NodeRuntimeError> {
        // 5. KeyProvider（validator mode 必填；不默认生成不稳定生产密钥）。
        let provider = key_provider.ok_or(NodeRuntimeError::KeyNotProvisioned)?;
        let signer = provider
            .load_signer()
            .map_err(NodeRuntimeError::KeyProvider)?;
        let public_key = signer.public_key().to_bytes();

        // 6. derive ValidatorId（单一来源）。
        let validator_id = derive_validator_id(&public_key);

        // 7. SafetyIdentity + SafetyStore open（独立 safety_dir；与 chain storage 分离）。
        let safety_identity = SafetyIdentity::new(
            identity.network_id,
            identity.chain_id,
            identity.genesis_hash,
            &validator_id,
        );
        let journal_path = config.safety_dir.join("safety.journal");
        let store = if journal_path.exists() {
            ValidatorSafetyStore::at(&journal_path, safety_identity)
        } else {
            ValidatorSafetyStore::create(&journal_path, safety_identity)
                .map_err(NodeRuntimeError::Safety)?
        };

        // 8/9. strict recover（restore 内部执行）→ 构造 ValidatorActor。
        //      recover / identity mismatch ⇒ Err ⇒ validator mode 启动失败（fail closed）。
        let actor = ValidatorActor::restore(validator_id, signer, identity.chain_id, store)
            .map_err(NodeRuntimeError::Validator)?;

        Ok((actor, journal_path))
    }

    pub fn chain_identity(&self) -> &ChainIdentity {
        &self.chain_identity
    }

    /// chain storage handle（只读；Phase 1 生命周期 handle）。
    pub fn chain_storage(&self) -> &PersistentBackend {
        &self.chain_storage
    }

    /// NodeConsensusDriver（只读；ConsensusNode + ValidatorActor 的 owner）。
    pub fn driver(&self) -> &NodeConsensusDriver<DynSigner> {
        &self.driver
    }

    /// 网络身份 NodeId（`start_with_network` 启用时 `Some`）。
    /// NodeId 来自网络 key pubkey（≠ ValidatorId；Network/Validator identity 分离）。
    pub fn network_node_id(&self) -> Option<NodeId> {
        self.network_stack.as_ref().map(NetworkStack::node_id)
    }

    /// 取走 Driver 验证 PASS 后待广播的 consensus outbound **semantic**（手动提取 / 测试用；
    /// `step()` 会自行 drain + egress）。网络 disabled 亦可调用（outbound 在 Driver，独立于
    /// NetworkStack）。
    pub fn take_consensus_outbound(&mut self) -> Vec<OutboundConsensusMessage> {
        self.driver.take_outbound()
    }

    /// consensus orchestration 入口（STEP 10-18I-D-A Option A）：把 node 层 consensus command
    /// （EventLoop → Handler decode queue → Runtime 承接）交给 Driver 的既有安全门面。
    /// - verify/decode/transition 门面 FAIL 原样以 `DriverError` 传出（不吞错、不改状态）。
    /// - outbound：验证 PASS 后入 Driver pending（STEP 10-18I-N-IMPL：`step()` 末尾 drain →
    ///   egress adapter 签名 → `NetworkService` broadcast）；本方法仅承接 command。
    /// - 借用生命周期严格限当前调用（不长期借 Driver；无 self-reference）。
    pub fn process_consensus_command(
        &mut self,
        command: NodeConsensusCommand,
    ) -> Result<(), DriverError> {
        process_command(&mut self.driver, command)
    }

    /// canonical consensus node handle（只读）—— **delegate** `driver.consensus()`（不复制）。
    pub fn consensus(&self) -> &ConsensusNode {
        self.driver.consensus()
    }

    /// validator mode 是否启用 —— **delegate** `driver.actor_count()`。
    pub fn validator_enabled(&self) -> bool {
        self.driver.actor_count() > 0
    }

    /// 单验证者只读 view（validator mode 时为 `Some`）—— **delegate** `driver.actor(0)`。
    /// 调用时动态构造（含对 actor 的借用）；不长期存储 actor 引用（无 self-reference）。
    pub fn validator(&self) -> Option<ValidatorView<'_>> {
        let actor = self.driver.actor(0)?;
        let journal = self.validator_journal.as_ref()?;
        Some(ValidatorView {
            validator_id: actor.validator_id(),
            journal_path: journal.as_path(),
            actor,
        })
    }

    /// 一轮运行时驱动（Stage C）：网络 disabled（`start`）⇒ `Ok(())`（不产生网络 identity）；
    /// 启用网络（`start_with_network`）⇒ EventLoop poll NetworkService → dispatch →
    /// Handler 产 **owned** `NodeConsensusCommand` → Runtime drain → `process_command` →
    /// Driver（既有验证门面）→ ConsensusNode / ValidatorActor。
    ///
    /// borrow-safe：`poll_once` 临时借 `stack.el` + `stack.ns`（同栈内 disjoint 字段）；
    /// `take_commands()` 返回 owned commands 后即释放 EventLoop 借用；随后才 `&mut self.driver`。
    /// 无 `Handler → &mut Driver/Runtime`、无 self-reference（无 Rc/RefCell/Arc/unsafe/async）。
    pub fn step(&mut self) -> Result<(), RuntimeError> {
        let Some(stack) = &mut self.network_stack else {
            // 网络 disabled：仍执行 node-local proposer orchestration（无网络 identity 依赖）。
            runtime_propose(&mut self.driver).map_err(RuntimeError::Proposer)?;
            return Ok(());
        };
        stack
            .el
            .poll_once(&mut stack.ns)
            .map_err(RuntimeError::EventLoop)?;
        let commands = stack.el.handler_mut().take_commands();
        for command in commands {
            process_command(&mut self.driver, command).map_err(RuntimeError::Driver)?;
        }
        // STEP 10-19-2：node-local proposer orchestration —— 仅本节点为当前 proposer 且阶段
        // Propose 且本轮未提案时提交 ProposalRef；否则幂等 no-op。不触碰 validator 安全；
        // 不自动投票（vote 仍走既有路径）。
        runtime_propose(&mut self.driver).map_err(RuntimeError::Proposer)?;
        // STEP 10-18I-N-IMPL：production egress —— drain Driver semantic outbound →
        // NetworkSigner 编码签名 → NetworkService.broadcast（established-only/queue 由 NS 负责）
        // → flush（TCP send）。sign 失败 fail-closed；NS broadcast/flush 失败（queue full / 无
        // established）按 backpressure drop —— 不 panic、不阻塞共识。
        let outbound = self.driver.take_outbound();
        for msg in outbound {
            let envelope = crate::egress::envelope_for(&msg, stack.signer.as_ref())
                .map_err(RuntimeError::Egress)?;
            let _ = stack.ns.broadcast(envelope);
        }
        let _ = stack.ns.flush_outbound();
        Ok(())
    }

    /// 确定性生命周期终止（D2 冻结；**consuming** `self`）。
    ///
    /// 顺序（destructure 一次析构全部字段，显式顺序调用）：
    /// EventLoop stop → NetworkService stop → Driver 生命周期结束（owns ConsensusNode +
    /// ValidatorActor）→ `ChainStorage::close(self)`（最后；consuming）。
    /// - 网络 disabled：跳过 EventLoop/NetworkService；仍 Driver drop + Storage close。
    /// - `PersistentBackend::close` 是唯一可失败子调用 ⇒ `ShutdownError::Storage`。
    /// - 不用 Option 化 Storage / Rc / Arc / Mutex / mem::replace（无绕 ownership workaround）。
    pub fn shutdown(self) -> Result<(), ShutdownError> {
        let Self {
            chain_identity: _,
            chain_storage,
            driver,
            network_stack,
            validator_journal: _,
        } = self;

        if let Some(mut stack) = network_stack {
            // EventLoop stop → NetworkService stop（独立 owner；EventLoop 不级联 NS）。
            stack.el.shutdown();
            stack.ns.shutdown();
            // signer（Box<dyn NetworkSigner>）随 stack drop（无显式 shutdown）。
        }
        // Driver 生命周期结束（ConsensusNode + ValidatorActor drop；safety 已 durable journal）。
        drop(driver);
        // Storage 最后关闭（consuming）。
        chain_storage.close().map_err(ShutdownError::Storage)
    }
}

/// ValidatorId 单一来源（STEP 10-16）：node 装配层统一入口。
///
/// 实现委托 consensus `ValidatorId::from_consensus_public_key`（= SHA-256(pubkey)，crypto 冻结）。
/// 未来把 crypto `identity::validator_id` 与共识实现收敛至此（本步保持值不变，仅统一调用入口）。
pub fn derive_validator_id(public_key: &[u8; 32]) -> ValidatorId {
    ValidatorId::from_consensus_public_key(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::identity::validator_id as crypto_validator_id;
    use nova_crypto::key::KeyPair;

    /// 单一来源一致性：derive_validator_id == consensus impl == crypto identity::validator_id。
    #[test]
    fn derive_validator_id_matches_existing_sources() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let derived = derive_validator_id(&pk);
        assert_eq!(
            derived,
            ValidatorId::from_consensus_public_key(&pk),
            "derive == consensus 实现"
        );
        assert_eq!(
            *derived.as_bytes(),
            crypto_validator_id(&pk),
            "derive == crypto identity::validator_id（值不变）"
        );
    }
}
