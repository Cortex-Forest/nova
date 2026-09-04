//! NodeRuntime —— 生产节点生命周期装配层（STEP 10-16；Phase 1 骨架）。
//!
//! # 职责（仅装配 / 生命周期；不实现共识算法）
//! 固定启动顺序：`Config → Genesis → ChainIdentity 校验 → chain storage →（validator mode）
//! KeyProvider → derive ValidatorId → SafetyStore open → strict recover → ValidatorActor →
//! ConsensusNode`（Network / EventLoop 为 future 占位）。
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
use nova_storage::persistent::PersistentBackend;

use crate::assembly::ConsensusNode;
use crate::bootstrap::{self, NodeConfig, NodeStartupError};
use crate::key_provider::{KeyProvider, KeyProviderError};
use crate::safety_store::{SafetyIdentity, ValidatorSafetyError, ValidatorSafetyStore};
use crate::signer::SigningCapability;
use crate::validator::{ValidatorActor, ValidatorActorError};

/// ValidatorActor 的签名能力类型（Phase 1：trait object）。
type DynSigner = Box<dyn SigningCapability>;

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

/// 单验证者运行时视图（Phase 1：每 NodeRuntime 至多一个验证者）。
pub struct ValidatorRuntime {
    validator_id: ValidatorId,
    actor: ValidatorActor<DynSigner>,
    journal_path: PathBuf,
}

impl ValidatorRuntime {
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub fn actor(&self) -> &ValidatorActor<DynSigner> {
        &self.actor
    }

    /// safety journal 文件路径（只读；生命周期审计）。
    pub fn journal_path(&self) -> &std::path::Path {
        &self.journal_path
    }
}

/// 生产节点生命周期装配根（STEP 10-16 Phase 1 骨架）。
pub struct NodeRuntime {
    chain_identity: ChainIdentity,
    chain_storage: PersistentBackend,
    consensus: ConsensusNode,
    validator: Option<ValidatorRuntime>,
}

impl NodeRuntime {
    /// 启动：固定顺序（§模块 doc）。任何安全失败 ⇒ `Err`（fail closed）。
    ///
    /// - `key_provider`：validator mode 时**必须**提供（None ⇒ `KeyNotProvisioned`）；
    ///   full-node 时忽略。
    pub fn start(
        config: &NodeConfig,
        key_provider: Option<&dyn KeyProvider>,
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

        // 10. ConsensusNode handle（canonical 状态 owner 在 ConsensusNode；Runtime 只持有）。
        let set = ValidatorSet::from_genesis(&genesis);
        let consensus = ConsensusNode::new(
            0,
            0,
            identity.chain_id,
            set,
            identity.genesis_hash,
            Dag::new(),
        );

        // 5–9. validator mode 生命周期（key → id → safety → recover → actor）。
        let validator = if config.validator_enabled {
            Some(Self::build_validator(config, &identity, key_provider)?)
        } else {
            None
        };

        Ok(Self {
            chain_identity: identity,
            chain_storage,
            consensus,
            validator,
        })
    }

    /// validator mode 生命周期装配（key provider → derive id → safety store → recover → actor）。
    fn build_validator(
        config: &NodeConfig,
        identity: &ChainIdentity,
        key_provider: Option<&dyn KeyProvider>,
    ) -> Result<ValidatorRuntime, NodeRuntimeError> {
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

        Ok(ValidatorRuntime {
            validator_id,
            actor,
            journal_path,
        })
    }

    pub fn chain_identity(&self) -> &ChainIdentity {
        &self.chain_identity
    }

    /// chain storage handle（只读；Phase 1 生命周期 handle）。
    pub fn chain_storage(&self) -> &PersistentBackend {
        &self.chain_storage
    }

    /// canonical consensus node handle（只读）。
    pub fn consensus(&self) -> &ConsensusNode {
        &self.consensus
    }

    /// validator mode 是否启用。
    pub fn validator_enabled(&self) -> bool {
        self.validator.is_some()
    }

    /// validator 运行时（validator mode 时为 `Some`）。
    pub fn validator(&self) -> Option<&ValidatorRuntime> {
        self.validator.as_ref()
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
