//! Block Inbound Validation Boundary v1（STEP 10-19-9）。
//!
//! # 定位
//! 远端 Block wire（`GossipBlock` payload / `SyncBlockResponse` payload / 未来网络输入）进入
//! Node 后的**第一道 canonical validation boundary**。把
//!
//! ```text
//! REMOTE RECEIVED
//!      ↓ （本模块：Wire + Canonical validation，纯只读）
//! CANONICAL VALIDATED  (CanonicalNextCandidate)
//!      ↓ FINALITY AUTHORIZED        ← 未实现（未来层；本模块永不产出）
//!      ↓ CANONICAL COMMIT           ← 未实现（未来层；本模块永不调用）
//! ```
//!
//! 本模块**最多实现到 CANONICAL VALIDATED**：
//! - 验证并分类远端 Block；返回 typed verdict / reject reason。
//! - **绝不调用** `apply_block` / `commit_block` / `enqueue_head` —— 不推进 ChainHead、
//!   不更新 StateStore、不写 BlockStore（BlockStore 仅用于 `contains` 只读 already-known 判断）。
//! - 产出 [`InboundBlockVerdict::CanonicalNextCandidate`] **不代表 finality 授权**：它只是
//!   "wire + canonical 全验证通过、且与本地 head 连续" 的 commit **候选**。`GossipBlock` /
//!   `SyncBlockResponse` / `Proposal` **都不是 finality proof**（本模块不把任何输入当作已
//!   finalized 处理）。finality→storage 集成 / QC ingestion 属未来 STEP。
//!
//! # 边界（与冻结架构一致）
//! - NetworkService / EventLoop（ADR-0055/0056 FROZEN）**不被修改**：本模块是 Node 层 seam，
//!   由未来 wiring/sync 调用方在 NetworkEvent 之后接入（本 STEP 不改 wiring）。
//! - 复用冻结原语（nova-core P7-2/3、nova-runtime 分层 API、nova-storage）；**不重造** decode /
//!   hash / signature / tx-root / state-root / ordering 规则；不创建新 wire format。
//! - 只读：对 `StateStore`（state-root 重算）/ `ChainHead`（height/parent 分类）/
//!   `BlockStore`（`contains`）均为只读借用。
//! - 诚实验证（不假装成功）：若缺少 expected proposer vk（A11 membership 未接线）或含交易
//!   但 sender 无法经 resolver 解析（如 `NoAccountsKeyResolver`），返回
//!   [`InboundBlockError::UnsupportedValidation`]，**不跳过 / 不信任远端 root / 不 fake resolver**。

use nova_crypto::identity::address_payload_bytes;
use nova_crypto::signature::VerifyingKey;
use nova_runtime::{
    BLOCK_VERSION, Block, BlockCodecError, BlockPipelineError, BlockValidationFailure,
    ExecutionContext, KeyResolver, block_hash, decode_block, execute_and_verify_state_root,
    validate_block_signature, validate_transaction_root,
};
use nova_storage::backend::StorageBackend;
use nova_storage::block_store::BlockStore;
use nova_storage::error::StorageError;
use nova_storage::store::StateStore;

use crate::block_adapter::ChainHead;

/// 远端块入站验证上下文（Node-local；全部为只读引用 / 显式参数；无身份 / 无私钥 / 无随机）。
pub struct InboundBlockContext<'a, B: StorageBackend + Clone> {
    /// 本地网络 ID（ExecutionContext 链身份；不重新定义 ChainIdentity）。
    pub network_id: nova_crypto::address::NetworkId,
    /// 本地 genesis chain_id（`block.header.chain_id` 必须 == 此值）。
    pub chain_id: u64,
    /// 本地 genesis hash（ExecutionContext 链身份）。
    pub genesis_hash: [u8; 32],
    /// fee burn bps（ExecutionContext；来自 genesis economics）。
    pub fee_burn_bps: u16,
    /// 每区块最大 gas（state-root 执行重算上限；来自 genesis protocol）。
    pub max_gas_per_block: u64,
    /// 入站 payload 允许最大字节数（超出 ⇒ `Oversized`）。
    pub max_block_bytes: usize,
    /// 本地 canonical state 视图（**只读**；state-root 重算用）。
    pub state_store: &'a StateStore<B>,
    /// 本地 canonical head（**只读**；height/parent 关系分类用）。
    pub head: &'a ChainHead,
    /// 本地 block storage（**只读**；`contains` 仅用于 already-known 判断；本模块**不写入**）。
    pub block_store: Option<&'a BlockStore>,
    /// sender 地址 → 验证公钥（state-root 执行验证用）。`NoAccountsKeyResolver`（NodeRuntime
    /// 现装配）resolve 恒 None ⇒ 含交易远端块无法执行验证 ⇒ `UnsupportedValidation(StateExecution)`。
    pub sender_resolver: &'a dyn KeyResolver,
    /// 期望的 proposer 验证公钥（A11：纯签名、无 membership）。远端 Block 无 proposer 标识字段；
    /// `Some(vk)` 时才可执行 proposer signature 验证；`None` ⇒ 该项
    /// `UnsupportedValidation(ProposerSignature)`（不假装验证成功）。
    pub expected_proposer_vk: Option<&'a VerifyingKey>,
    /// 请求方声称的 block hash（如 `SyncBlockRequest.block_hash` 上下文）；`None` = 无声称。
    pub expected_hash: Option<[u8; 32]>,
}

/// 本节点当前无法验证的项（诚实：不跳过 / 不信任远端 / 不 fake resolver）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableItem {
    /// 缺少 expected proposer 验证公钥（A11 membership 未接线 ⇒ 无法验 proposer 签名）。
    ProposerSignature,
    /// 含交易但 sender 无法经 resolver 解析（或本地状态无法完成执行验证）⇒ state_root 不可验证。
    StateExecution,
}

impl core::fmt::Display for UnverifiableItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ProposerSignature => write!(f, "proposer signature (no expected proposer key)"),
            Self::StateExecution => write!(f, "state execution (sender unresolved / local state)"),
        }
    }
}

/// 远端块 reject / 不可验证原因（typed；远端验证失败**不用** String / panic / unwrap 表达）。
///
/// 尽量复用冻结错误语义（BlockCodecError / BlockValidationError / StorageError 原语），
/// 仅在需要跨层分类时在此收窄为 typed reason。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundBlockError {
    /// payload 超 `max_block_bytes`。
    Oversized { limit: usize, actual: usize },
    /// 结构解码失败（截断 / 超长 / trailing bytes / tx codec；nova-core P7-2）。
    Malformed,
    /// 未知 Block 版本（`decode_block` 拒；V0.1 = 0x01）。
    WrongVersion { found: u8 },
    /// `block.header.chain_id != 本地 chain_id`。
    WrongChain { found: u64 },
    /// 声称 hash（`expected_hash`）≠ 重算 canonical hash。
    HashMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// proposer 签名验证失败（仅当 `expected_proposer_vk` 提供时）。
    InvalidProposerSignature,
    /// 重算 transaction_root ≠ `header.transaction_root`。
    TransactionRootMismatch,
    /// `body.txs` 不符合 ADR-0061 canonical ordering（不得替远端排序后接受）。
    NonCanonicalTransactionOrdering,
    /// 重算 state_root ≠ `header.state_root`（空块 / sender 全可解析时验证）。
    StateRootMismatch,
    /// 本节点当前无法验证该项（详见 [`UnverifiableItem`]）。
    UnsupportedValidation(UnverifiableItem),
    /// BlockStore 读取失败（already-known 判断）。
    Storage(StorageError),
}

impl core::fmt::Display for InboundBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Oversized { limit, actual } => {
                write!(f, "oversized block payload: limit {limit}, actual {actual}")
            }
            Self::Malformed => write!(f, "malformed block wire"),
            Self::WrongVersion { found } => write!(f, "wrong block version: {found:#04x}"),
            Self::WrongChain { found } => write!(f, "wrong chain_id: {found}"),
            Self::HashMismatch { claimed, computed } => {
                write!(
                    f,
                    "block hash mismatch: claimed {claimed:?}, computed {computed:?}"
                )
            }
            Self::InvalidProposerSignature => write!(f, "invalid proposer signature"),
            Self::TransactionRootMismatch => write!(f, "transaction root mismatch"),
            Self::NonCanonicalTransactionOrdering => {
                write!(f, "non-canonical transaction ordering (ADR-0061)")
            }
            Self::StateRootMismatch => write!(f, "state root mismatch"),
            Self::UnsupportedValidation(item) => {
                write!(f, "unsupported validation: {item}")
            }
            Self::Storage(e) => write!(f, "block store error: {e}"),
        }
    }
}

impl std::error::Error for InboundBlockError {}

/// 远端块验证结果分类（本层**不 commit / 不推进**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundBlockVerdict {
    /// 本地已持久化该 hash（BlockStore `contains`；含 canonical head 链上历史）——非新信息。
    AlreadyKnown { height: u64, block_hash: [u8; 32] },
    /// 严格落后于 local head（`height <= head.height` 且非已 known）——不得 commit。
    Stale {
        height: u64,
        block_hash: [u8; 32],
        head_height: u64,
    },
    /// 高于 `head.height + 1`（祖先缺失）——不得 commit；需祖先顺序获取（未来 BlockSync）。
    FutureMissingAncestor {
        height: u64,
        block_hash: [u8; 32],
        head_height: u64,
    },
    /// `height == head.height + 1` 但 `parent_hash != head.block_hash`——分叉候选，不得 commit。
    ConflictingParent {
        height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        expected_parent: [u8; 32],
    },
    /// Wire + canonical 全验证通过，且与 local head 连续 —— **canonical commit 候选**。
    ///
    /// **非 finality-authorized**：本层不拥有 finality；调用方不得仅凭本 verdict 触发
    /// canonical commit（commit 必须经未来 finality 授权层）。
    /// 不携带完整 `Block`（验证与消费解耦）：调用方如需 block，凭 `block_hash` / `bytes`
    /// 重新 decode 即可（避免 enum 大变体）。
    CanonicalNextCandidate { block_hash: [u8; 32], height: u64 },
}

/// 校验 `body.txs` 是否符合 ADR-0061 canonical ordering（`(address_payload_bytes ASC, nonce ASC)`
/// 严格递增）。**不替远端排序**；任何非递增 / 重复 `(sender, nonce)` ⇒ false。
fn is_canonically_ordered(block: &Block) -> bool {
    let keys: Vec<([u8; 35], u64)> = block
        .body
        .txs
        .iter()
        .map(|tx| (address_payload_bytes(&tx.sender), tx.nonce))
        .collect();
    keys.windows(2).all(|w| w[0] < w[1])
}

/// 远端 Block wire → 验证 + 分类（纯只读；**不 commit / 不推进 / 不写 BlockStore**）。
///
/// # 层序（验证失败即 `Err`；通过后按 head 关系返回 verdict）
/// ```text
/// ① size        → Oversized
/// ② decode      → Malformed / WrongVersion
/// ③ chain_id    → WrongChain
/// ④ hash 重算   → （expected_hash 声称不一致 ⇒ HashMismatch）
/// ⑤ already-known（BlockStore.contains，只读）→ AlreadyKnown
/// ⑥ head 关系分类：Stale / FutureMissingAncestor / ConflictingParent / CanonicalNext 候选
/// ⑦ canonical full validation（仅 CanonicalNext 候选）：
///    ordering → transaction_root → proposer signature → state_root（执行重算）
/// ```
pub fn validate_block_inbound<B: StorageBackend + Clone>(
    bytes: &[u8],
    ctx: &InboundBlockContext<'_, B>,
) -> Result<InboundBlockVerdict, InboundBlockError> {
    // ① size
    if bytes.len() > ctx.max_block_bytes {
        return Err(InboundBlockError::Oversized {
            limit: ctx.max_block_bytes,
            actual: bytes.len(),
        });
    }
    // ② decode（structure + version；nova-core P7-2）
    let block = decode_block(bytes).map_err(|e| match e {
        BlockPipelineError::Decode(BlockCodecError::UnknownVersion(v)) => {
            InboundBlockError::WrongVersion { found: v }
        }
        _ => InboundBlockError::Malformed,
    })?;
    debug_assert_eq!(block.header.version, BLOCK_VERSION, "decode 已保证 version");
    // ③ chain_id
    if block.header.chain_id != ctx.chain_id {
        return Err(InboundBlockError::WrongChain {
            found: block.header.chain_id,
        });
    }
    // ④ canonical block hash（SHA-256(canonical_header ‖ canonical_body)；不含 signature）
    let computed = block_hash(&block).map_err(|_| InboundBlockError::Malformed)?;
    if let Some(claimed) = ctx.expected_hash
        && claimed != computed
    {
        return Err(InboundBlockError::HashMismatch { claimed, computed });
    }
    // ⑤ already-known（只读 BlockStore.contains；本模块绝不写入）
    if let Some(bs) = ctx.block_store
        && bs.contains(&computed).map_err(InboundBlockError::Storage)?
    {
        return Ok(InboundBlockVerdict::AlreadyKnown {
            height: block.header.height,
            block_hash: computed,
        });
    }
    // ⑥ head 关系分类
    let head = ctx.head;
    let height = block.header.height;
    let verdict = if height == 0 {
        // genesis 无 BlockV1 实体；高度 0 的 block wire 非 canonical 链单元
        if computed == head.block_hash {
            InboundBlockVerdict::AlreadyKnown {
                height,
                block_hash: computed,
            }
        } else {
            InboundBlockVerdict::Stale {
                height,
                block_hash: computed,
                head_height: head.height,
            }
        }
    } else if height < head.height {
        InboundBlockVerdict::Stale {
            height,
            block_hash: computed,
            head_height: head.height,
        }
    } else if height == head.height {
        if computed == head.block_hash {
            InboundBlockVerdict::AlreadyKnown {
                height,
                block_hash: computed,
            }
        } else {
            InboundBlockVerdict::Stale {
                height,
                block_hash: computed,
                head_height: head.height,
            }
        }
    } else if height > head.height.saturating_add(1) {
        InboundBlockVerdict::FutureMissingAncestor {
            height,
            block_hash: computed,
            head_height: head.height,
        }
    } else {
        // height == head.height + 1
        if block.header.parent_hash != head.block_hash {
            InboundBlockVerdict::ConflictingParent {
                height,
                block_hash: computed,
                parent_hash: block.header.parent_hash,
                expected_parent: head.block_hash,
            }
        } else {
            // ⑦ CanonicalNext 候选：full validation
            return validate_canonical_next(&block, computed, ctx);
        }
    };
    Ok(verdict)
}

/// ⑦ CanonicalNext 候选的完整 canonical 验证（唯一需要 execution 的路径）。
///
/// 顺序：ordering → transaction_root → proposer signature → state_root（执行重算比对）。
/// 全部通过才产出 [`InboundBlockVerdict::CanonicalNextCandidate`]。
fn validate_canonical_next<B: StorageBackend + Clone>(
    block: &Block,
    computed: [u8; 32],
    ctx: &InboundBlockContext<'_, B>,
) -> Result<InboundBlockVerdict, InboundBlockError> {
    // ⑦a ADR-0061 canonical ordering（不替远端排序）
    if !is_canonically_ordered(block) {
        return Err(InboundBlockError::NonCanonicalTransactionOrdering);
    }
    // ⑦b transaction_root
    validate_transaction_root(block).map_err(|_| InboundBlockError::TransactionRootMismatch)?;
    // ⑦c proposer signature（A11：纯签名无 membership；需要调用方提供 expected vk）
    match ctx.expected_proposer_vk {
        Some(vk) => validate_block_signature(block, vk, ctx.chain_id)
            .map_err(|_| InboundBlockError::InvalidProposerSignature)?,
        None => {
            return Err(InboundBlockError::UnsupportedValidation(
                UnverifiableItem::ProposerSignature,
            ));
        }
    }
    // ⑦d state_root：解析全部 sender（空块 ⇒ 空 keys）后执行重算比对
    let sender_keys: Option<Vec<VerifyingKey>> = block
        .body
        .txs
        .iter()
        .map(|tx| ctx.sender_resolver.resolve(tx.sender))
        .collect();
    let sender_keys = sender_keys.ok_or(InboundBlockError::UnsupportedValidation(
        UnverifiableItem::StateExecution,
    ))?;
    let exec_ctx = ExecutionContext {
        chain: nova_crypto::identity::ChainIdentity {
            network_id: ctx.network_id,
            chain_id: ctx.chain_id,
            genesis_hash: ctx.genesis_hash,
        },
        current_height: ctx.head.height,
        fee_burn_bps: ctx.fee_burn_bps,
    };
    match execute_and_verify_state_root(
        ctx.state_store,
        block,
        &sender_keys,
        &exec_ctx,
        ctx.max_gas_per_block,
    ) {
        Ok(_) => Ok(InboundBlockVerdict::CanonicalNextCandidate {
            block_hash: computed,
            height: block.header.height,
        }),
        Err(BlockPipelineError::Validation(BlockValidationFailure::StateRoot(_))) => {
            Err(InboundBlockError::StateRootMismatch)
        }
        // 本地状态无法完成执行验证（执行期失败）——如实标记不可验证，不假装成功。
        Err(_) => Err(InboundBlockError::UnsupportedValidation(
            UnverifiableItem::StateExecution,
        )),
    }
}
