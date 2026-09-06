//! Node-local BlockBuilder（STEP 10-19-5 — ADR-0061 Transaction Ordering 落地）。
//!
//! # 管线（冻结链）
//! ```text
//! candidate transactions
//!         ↓  (sender,nonce) canonical ordering（ADR-0061）
//! ordered transactions
//!         ↓  execute（nova-execution，经 runtime 只读组合）
//!         ↓  post-state root（nova-storage calculate_state_root，只读）
//!         ↓  transaction root（nova-core compute_transaction_root，ADR-0042 §11）
//! BlockV1 assembly（nova-core，经 nova-runtime re-export）
//!         ↓  block_hash = SHA-256(canonical_header ‖ canonical_body)（ADR-0042 §6）
//! ```
//!
//! # 确定性 / 边界
//! - **纯确定性**：不访问系统时间 / 网络 / 文件系统 / 随机 / 私钥 / 持久化；`height` /
//!   `parent_hash` / `finality_reference` / `validator_set_hash` / `timestamp` 由 caller 显式传入
//!   （[`BlockContext`]）；`chain_id` / `network_id` / `genesis_hash` / `current_height` /
//!   `fee_burn_bps` 由 [`ExecutionContext`] 提供（复用既有 context，优先于新建）。
//! - ordering 规则（ADR-0061）：primary key = `address_payload_bytes(tx.sender)`（35B canonical
//!   ASC），secondary key = `nonce`（ASC）；同 `(sender, nonce)` 重复 ⇒ **Block Invalid**
//!   （[`BlockBuilderError::DuplicateSenderNonce`]；禁止 first-wins / last-wins / dedup）。
//! - 不重造 execution / SMT / state root / Merkle：全部复用冻结件（execution 经
//!   [`execute_and_compute_state_root`]；node **不直接依赖** nova-execution / nova-core，E1=A）。
//! - 签名 seam：本轮不接 ProposerService；[`attach_proposer_signature`] 用既有
//!   [`SigningCapability`]（node signer）对 canonical header 签名回填；
//!   `proposer_signature ∉ block_hash`（ADR-0042 §6）。
//!
//! # 不负责
//! ConsensusState / Finality / QC / Vote / ValidatorActor / VoteLedger / LockedState / ForkChoice /
//! Network / EventLoop / Gossip / BlockSync / Mempool / 持久化 / 私钥存储 / Genesis 变更 / 经济。

use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::identity::address_payload_bytes;
use nova_crypto::signature::VerifyingKey;
use nova_crypto::transaction::TransactionV1;
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockCodecError, BlockExecutionResult, BlockHeader,
    BlockPipelineError, ExecutionContext, block_hash, compute_transaction_root,
    encode_block_header, execute_and_compute_state_root,
};
use nova_storage::backend::StorageBackend;
use nova_storage::store::StateStore;

use crate::signer::SigningCapability;

/// BlockBuilder 错误（node-local；区分集合级 invalid / 底层管线 / 结构级 assembly / 签名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBuilderError {
    /// ADR-0021 §7 / ADR-0061：候选集内 `(sender, nonce)` 重复 ⇒ Block Invalid。
    /// 禁止 first-wins / last-wins / 自动去重。
    DuplicateSenderNonce,
    /// 底层 runtime 管线错误（execution / state root / storage 分类保留）。
    Pipeline(BlockPipelineError),
    /// Block canonical encode / block_hash 失败（结构级，nova-core）。
    Encode(BlockCodecError),
    /// 构造 proposer signature domain-bound bytes 失败（crypto 域）。
    SignatureEncoding,
    /// signer 签名失败（node-local；HSM / remote 载体可失败）。
    SigningFailed,
}

impl From<BlockPipelineError> for BlockBuilderError {
    fn from(e: BlockPipelineError) -> Self {
        Self::Pipeline(e)
    }
}

impl core::fmt::Display for BlockBuilderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateSenderNonce => write!(
                f,
                "duplicate (sender, nonce) in candidate set ⇒ Block Invalid"
            ),
            Self::Pipeline(e) => write!(f, "block pipeline: {e}"),
            Self::Encode(e) => write!(f, "block assembly encode: {e}"),
            Self::SignatureEncoding => write!(f, "proposer signature domain bytes construction"),
            Self::SigningFailed => write!(f, "proposer signing capability failed"),
        }
    }
}

impl std::error::Error for BlockBuilderError {}

/// 候选交易（7D 身份绑定：交易 + sender verifying key 成对输入）。
///
/// `sender_vk` 与 `tx.sender` 的一致性由调用方保证（执行层 `verify_transaction_signature`
/// 以 `sender_vk` 验签，nova-execution 7D）；BlockBuilder 不重复校验、不获取任何外部来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateTransaction {
    /// 已签名候选交易（V0.1 `TransactionV1`）。
    pub tx: TransactionV1,
    /// 该交易 sender 的验证公钥（排序/执行的身份绑定输入）。
    pub sender_vk: VerifyingKey,
}

/// `BlockHeader` 显式上下文（BlockBuilder 不自行获取任何 header 来源）。
///
/// `chain_id` 由 [`ExecutionContext::chain`] 提供（单来源，避免不一致）；
/// `timestamp` 必须由 caller 显式提供（**禁止**系统时间/本地时钟 —— block_hash 需确定性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// 拟产出高度（`parent.height < height`；ADR-0042）。
    pub height: u64,
    /// 父区块 block_hash（单父；genesis 父 = 零哈希）。
    pub parent_hash: [u8; 32],
    /// 前序 finality 引用（指向过去 finalized block_hash；无循环）。
    pub finality_reference: Option<[u8; 32]>,
    /// 当前 validator set 承诺（由共识层提供）。
    pub validator_set_hash: [u8; 32],
    /// 提议时间（LE；metadata；caller 显式提供）。
    pub timestamp: u64,
}

/// BlockBuilder 产物：真实 `BlockV1`（非 ProposalRef placeholder）+ 其 block_hash + 执行结果。
///
/// - `block.proposer_signature` 初始为 `[0u8; 64]`（签名由 [`attach_proposer_signature`] seam
///   填充；signature ∉ block_hash，故 `block_hash` 不受签名影响）。
/// - `execution` 供调用方审计（receipt / gas / burned_fee 等派生数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBuildResult {
    /// 组装完成的 BlockV1（header/body/占位 signature）。
    pub block: Block,
    /// `block_hash = SHA-256(canonical_header ‖ canonical_body)`（ADR-0042 §6）。
    pub block_hash: [u8; 32],
    /// 有序交易执行结果（含成功 transition 的 changes / receipt / gas）。
    pub execution: BlockExecutionResult,
}

/// 组装确定性 Block（STEP 10-19-5 主入口；同步、纯计算、只读 store）。
///
/// # 步骤
/// 1. 候选集按 `(address_payload_bytes(sender) ASC, nonce ASC)` canonical ordering（ADR-0061）；
///    排序后相邻同 `(sender, nonce)` ⇒ [`BlockBuilderError::DuplicateSenderNonce`]。
/// 2. 由有序候选派生 `txs` / `sender_keys`（与 BlockBody 顺序**完全一致**）。
/// 3. [`execute_and_compute_state_root`]：执行有序 txs（复用 nova-execution，失败 skip Model A）+
///    只读计算 post-state root（nova-storage）。
/// 4. `transaction_root = compute_transaction_root(BlockBody{ordered})`（ADR-0042 §11）。
/// 5. 组装 `BlockHeader` / `BlockBody` / `Block`；`state_root` 取自 ③。
/// 6. `block_hash`。
///
/// `store` 为 parent 状态视图（`AccountStateView` 实现），调用后**完全不变**（只读重算）。
pub fn build_block<B: StorageBackend + Clone>(
    store: &StateStore<B>,
    context: &BlockContext,
    exec_ctx: &ExecutionContext,
    max_gas_per_block: u64,
    candidates: &[CandidateTransaction],
) -> Result<BlockBuildResult, BlockBuilderError> {
    // ---- 1. canonical ordering（ADR-0061；纯函数，无 tie-break：重复 ⇒ Block Invalid）----
    let mut ordered: Vec<&CandidateTransaction> = candidates.iter().collect();
    ordered.sort_by(|a, b| {
        address_payload_bytes(&a.tx.sender)
            .cmp(&address_payload_bytes(&b.tx.sender))
            .then_with(|| a.tx.nonce.cmp(&b.tx.nonce))
    });
    for pair in ordered.windows(2) {
        if pair[0].tx.sender == pair[1].tx.sender && pair[0].tx.nonce == pair[1].tx.nonce {
            return Err(BlockBuilderError::DuplicateSenderNonce);
        }
    }

    // ---- 2. 与 block 顺序一致的 txs / sender_keys ----
    let txs: Vec<TransactionV1> = ordered.iter().map(|c| c.tx.clone()).collect();
    let sender_keys: Vec<VerifyingKey> = ordered.iter().map(|c| c.sender_vk).collect();

    // ---- 3. execution + post-state root（只读；runtime 组合层；node 不直接依赖 execution）----
    let (execution, state_root) =
        execute_and_compute_state_root(store, &txs, &sender_keys, exec_ctx, max_gas_per_block)?;

    // ---- 4. transaction root（依有序 txs；ADR-0042 §11）----
    let body = BlockBody { txs };
    let transaction_root = compute_transaction_root(&body);

    // ---- 5. BlockV1 assembly（proposer_signature 由签名 seam 提供；∉ block_hash）----
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: exec_ctx.chain.chain_id,
        height: context.height,
        parent_hash: context.parent_hash,
        finality_reference: context.finality_reference,
        transaction_root,
        state_root: *state_root.as_bytes(),
        validator_set_hash: context.validator_set_hash,
        timestamp: context.timestamp,
    };
    let block = Block {
        header,
        body,
        proposer_signature: [0u8; 64],
    };

    // ---- 6. block_hash ----
    let hash = block_hash(&block).map_err(BlockBuilderError::Encode)?;
    Ok(BlockBuildResult {
        block,
        block_hash: hash,
        execution,
    })
}

/// 签名 seam（STEP 10-19-5；ProposerService integration 保留点）。
///
/// 用既有 [`SigningCapability`]（node-local，接受 domain-bound [`nova_crypto::domain::SigningMessageHash`]）
/// 对 **canonical header** 签名并回填 `block.proposer_signature`：
/// `payload = canonical_header`；`DomainId::Block` + `chain_id` 域分离（与 core P7-3
/// `verify_block_signature` 同构）。
///
/// - **signature ∉ block_hash**（ADR-0042 §6）：attach 前后 `block_hash` 不变。
/// - 不持有/不暴露私钥；不持久化；同步。
pub fn attach_proposer_signature(
    block: &mut Block,
    signer: &dyn SigningCapability,
) -> Result<(), BlockBuilderError> {
    let chain_id = block.header.chain_id;
    let payload = encode_block_header(&block.header);
    let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload)
        .map_err(|_| BlockBuilderError::SignatureEncoding)?;
    let message_hash = hash_signing_message(&signed);
    let signature = signer
        .sign(&message_hash)
        .map_err(|_| BlockBuilderError::SigningFailed)?;
    block.proposer_signature = signature.to_bytes();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::identity::ChainIdentity;
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::SigningKey;
    use nova_crypto::transaction::{TransactionType, TransactionV1, sign_transaction};
    use nova_runtime::AccountChange;
    use nova_runtime::validate_block_signature;
    use nova_storage::memory::MemoryBackend;

    use crate::signer::SoftwareSigner;

    const CHAIN_ID: u64 = 1001;
    const MAX_GAS: u64 = 100_000_000;

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
    }

    fn sender_addr(sk: &SigningKey) -> NovaAddress {
        let vk = sk.verifying_key();
        NovaAddress::from_verifying_key(&vk, AddressType::UserAccount, NetworkId::Mainnet).unwrap()
    }

    /// 注资 store（nonce 0；created）。
    fn seed_store(entries: &[(NovaAddress, u128)]) -> StateStore<MemoryBackend> {
        seed_store_nonce(entries, 0)
    }

    /// 注资 store（指定账户起始 nonce；created）。
    fn seed_store_nonce(entries: &[(NovaAddress, u128)], nonce: u64) -> StateStore<MemoryBackend> {
        let mut store = StateStore::new(MemoryBackend::new());
        let changes: Vec<AccountChange> = entries
            .iter()
            .map(|(a, b)| AccountChange {
                address: *a,
                new_balance: *b,
                new_nonce: nonce,
                created: true,
            })
            .collect();
        store.apply(&changes).unwrap();
        store
    }

    fn exec_ctx(chain_id: u64, fee_burn_bps: u16) -> ExecutionContext {
        ExecutionContext {
            chain: ChainIdentity {
                network_id: NetworkId::Mainnet,
                chain_id,
                genesis_hash: [0u8; 32],
            },
            current_height: 0,
            fee_burn_bps,
        }
    }

    fn block_ctx() -> BlockContext {
        BlockContext {
            height: 1,
            parent_hash: [0x11; 32],
            finality_reference: None,
            validator_set_hash: [0x33; 32],
            timestamp: 0,
        }
    }

    /// 构造已签名 transfer 候选（gas_price=1 ⇒ fee=21_000；expiration 大以通过高度窗）。
    fn signed_candidate(
        sk: &SigningKey,
        receiver: NovaAddress,
        nonce: u64,
        amount: u128,
        chain_id: u64,
    ) -> CandidateTransaction {
        let vk = sk.verifying_key();
        let sender = sender_addr(sk);
        let mut tx = TransactionV1 {
            version: 1,
            chain_id,
            nonce,
            sender,
            receiver,
            amount,
            gas_limit: 100_000,
            gas_price: 1,
            transaction_type: TransactionType::Transfer,
            payload: vec![0u8; 140],
            expiration: 1_000_000,
            signature: [0u8; 64],
        };
        sign_transaction(sk, &mut tx).unwrap();
        CandidateTransaction { tx, sender_vk: vk }
    }

    fn build(
        store: &StateStore<MemoryBackend>,
        ctx: &ExecutionContext,
        candidates: &[CandidateTransaction],
    ) -> BlockBuildResult {
        build_block(store, &block_ctx(), ctx, MAX_GAS, candidates).unwrap()
    }

    // ---- BB-1：空 transaction set ⇒ 合法 empty block candidate ----
    #[test]
    fn bb_1_empty_set_forms_valid_empty_block() {
        let store = StateStore::new(MemoryBackend::new());
        let root_before = store.state_root();
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[]);
        assert!(res.block.body.txs.is_empty(), "empty body");
        assert!(
            res.execution.tx_transitions.is_empty(),
            "no transitions for empty block"
        );
        // transaction_root = TX_EMPTY root（ADR-0042 §11）
        assert_eq!(
            res.block.header.transaction_root,
            compute_transaction_root(&BlockBody { txs: vec![] })
        );
        // 空执行 ⇒ state_root 不变
        assert_eq!(res.block.header.state_root, *root_before.as_bytes());
        assert_eq!(
            res.block.header.state_root,
            *store.state_root().as_bytes(),
            "store untouched"
        );
    }

    // ---- BB-2：单 transaction ⇒ Block 正常生成 ----
    #[test]
    fn bb_2_single_tx_builds_block() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let root_before = store.state_root();
        let cand = signed_candidate(kp.signing_key(), addr([0xBB; 32]), 0, 100, CHAIN_ID);
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        assert_eq!(res.block.body.txs.len(), 1);
        assert_eq!(res.execution.tx_transitions.len(), 1, "success");
        assert_eq!(res.execution.gas_used_total, 21_000);
        assert_ne!(
            res.block.header.state_root,
            *root_before.as_bytes(),
            "state root reflects transfer"
        );
    }

    // ---- BB-3：same-sender ordering（输入 nonce 3,1,2 ⇒ body 1,2,3；账户 current=1 ⇒ 1,2,3 全成功）----
    #[test]
    fn bb_3_same_sender_orders_by_nonce() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        // 账户当前 nonce = 1（nonce 0 已在链上）⇒ 候选 1,2,3 为连续 Current
        let store = seed_store_nonce(&[(sender, 10_000_000)], 1);
        let r = addr([0xBB; 32]);
        let candidates = [
            signed_candidate(kp.signing_key(), r, 3, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 1, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 2, 100, CHAIN_ID),
        ];
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &candidates);
        let nonces: Vec<u64> = res.block.body.txs.iter().map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![1, 2, 3], "nonce ascending");
        assert_eq!(
            res.execution.tx_transitions.len(),
            3,
            "no gap ⇒ all three succeed"
        );
    }

    // ---- §21：Alice nonce 8,5,7 ⇒ body 5,7,8（账户 current=4 ⇒ 5 成功；7/8 按 Future skip）----
    #[test]
    fn same_sender_8_5_7_orders_5_7_8() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        // 账户当前 nonce = 5（0..4 已在链上）⇒ 候选 5 为 Current，7/8 为 Future
        let store = seed_store_nonce(&[(sender, 10_000_000)], 5);
        let r = addr([0xBB; 32]);
        let candidates = [
            signed_candidate(kp.signing_key(), r, 8, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 5, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 7, 100, CHAIN_ID),
        ];
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &candidates);
        let nonces: Vec<u64> = res.block.body.txs.iter().map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![5, 7, 8], "body order = nonce ascending");
        // 执行：nonce 5 成功（nonce→6）；7、8 为 Future ⇒ skip（Model A，不新增 invalid rule）
        assert_eq!(
            res.execution.tx_transitions.len(),
            1,
            "only nonce 5 succeeds"
        );
    }

    // ---- BB-4：cross-sender ordering = canonical 35B address payload ASC ----
    #[test]
    fn bb_4_cross_sender_sorts_by_address_payload() {
        let kp_a = KeyPair::generate().unwrap();
        let kp_b = KeyPair::generate().unwrap();
        let kp_c = KeyPair::generate().unwrap();
        let (sa, sb, sc) = (
            sender_addr(kp_a.signing_key()),
            sender_addr(kp_b.signing_key()),
            sender_addr(kp_c.signing_key()),
        );
        let store = seed_store(&[(sa, 1_000_000), (sb, 1_000_000), (sc, 1_000_000)]);
        let r = addr([0xBB; 32]);
        // 输入逆序 [c, a, b]
        let candidates = [
            signed_candidate(kp_c.signing_key(), r, 0, 100, CHAIN_ID),
            signed_candidate(kp_a.signing_key(), r, 0, 100, CHAIN_ID),
            signed_candidate(kp_b.signing_key(), r, 0, 100, CHAIN_ID),
        ];
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &candidates);
        let mut expected = vec![sa, sb, sc];
        expected.sort_by_key(address_payload_bytes);
        let got: Vec<NovaAddress> = res.block.body.txs.iter().map(|t| t.sender).collect();
        assert_eq!(got, expected, "sender payload ASC");
    }

    // ---- BB-5：duplicate (sender, nonce) ⇒ Block Invalid ----
    #[test]
    fn bb_5_duplicate_sender_nonce_rejected() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 10_000_000)]);
        let r = addr([0xBB; 32]);
        let candidates = [
            signed_candidate(kp.signing_key(), r, 5, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 5, 200, CHAIN_ID), // 同 (sender, nonce)
        ];
        let err = build_block(
            &store,
            &block_ctx(),
            &exec_ctx(CHAIN_ID, 0),
            MAX_GAS,
            &candidates,
        )
        .unwrap_err();
        assert_eq!(err, BlockBuilderError::DuplicateSenderNonce);
    }

    // ---- BB-6：same candidate set + same state ⇒ 多次 build 完全一致 ----
    #[test]
    fn bb_6_repeated_build_is_deterministic() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 10_000_000)]);
        let root_before = store.state_root();
        let r = addr([0xBB; 32]);
        let candidates = [
            signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID),
            signed_candidate(kp.signing_key(), r, 1, 200, CHAIN_ID),
        ];
        let ctx = exec_ctx(CHAIN_ID, 0);
        let a = build_block(&store, &block_ctx(), &ctx, MAX_GAS, &candidates).unwrap();
        let b = build_block(&store, &block_ctx(), &ctx, MAX_GAS, &candidates).unwrap();
        assert_eq!(a.block, b.block, "identical block");
        assert_eq!(a.block_hash, b.block_hash, "identical block hash");
        assert_eq!(
            store.state_root(),
            root_before,
            "build is read-only: store untouched"
        );
    }

    // ---- BB-7：input order permutation ⇒ same block ----
    #[test]
    fn bb_7_input_permutation_same_block() {
        let kp_a = KeyPair::generate().unwrap();
        let kp_b = KeyPair::generate().unwrap();
        let kp_c = KeyPair::generate().unwrap();
        let store = seed_store(&[
            (sender_addr(kp_a.signing_key()), 1_000_000),
            (sender_addr(kp_b.signing_key()), 1_000_000),
            (sender_addr(kp_c.signing_key()), 1_000_000),
        ]);
        let r = addr([0xBB; 32]);
        let ta = signed_candidate(kp_a.signing_key(), r, 0, 100, CHAIN_ID);
        let tb = signed_candidate(kp_b.signing_key(), r, 0, 100, CHAIN_ID);
        let tc = signed_candidate(kp_c.signing_key(), r, 0, 100, CHAIN_ID);
        let ctx = exec_ctx(CHAIN_ID, 0);
        let ab = build_block(
            &store,
            &block_ctx(),
            &ctx,
            MAX_GAS,
            &[ta.clone(), tb.clone(), tc.clone()],
        )
        .unwrap();
        let cb = build_block(&store, &block_ctx(), &ctx, MAX_GAS, &[tc, tb, ta]).unwrap();
        assert_eq!(ab.block, cb.block);
        assert_eq!(ab.block_hash, cb.block_hash);
        assert_eq!(ab.block.header.state_root, cb.block.header.state_root);
        assert_eq!(
            ab.block.header.transaction_root,
            cb.block.header.transaction_root
        );
    }

    // ---- BB-8：state-changing tx 变化 ⇒ state_root 变化 ----
    #[test]
    fn bb_8_state_root_changes_with_valid_state_change() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let r = addr([0xBB; 32]);
        let ctx = exec_ctx(CHAIN_ID, 0);
        let empty = build_block(&store, &block_ctx(), &ctx, MAX_GAS, &[]).unwrap();
        let one = build_block(
            &store,
            &block_ctx(),
            &ctx,
            MAX_GAS,
            &[signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID)],
        )
        .unwrap();
        assert_ne!(
            empty.block.header.state_root, one.block.header.state_root,
            "state root differs"
        );
    }

    // ---- BB-9：ordered transaction set 变化 ⇒ transaction_root 变化 ----
    #[test]
    fn bb_9_transaction_root_changes_with_set() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 10_000_000)]);
        let r = addr([0xBB; 32]);
        let ctx = exec_ctx(CHAIN_ID, 0);
        let one = build_block(
            &store,
            &block_ctx(),
            &ctx,
            MAX_GAS,
            &[signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID)],
        )
        .unwrap();
        let two = build_block(
            &store,
            &block_ctx(),
            &ctx,
            MAX_GAS,
            &[
                signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID),
                signed_candidate(kp.signing_key(), r, 1, 200, CHAIN_ID),
            ],
        )
        .unwrap();
        assert_ne!(
            one.block.header.transaction_root, two.block.header.transaction_root,
            "tx root differs with set"
        );
    }

    // ---- BB-10..BB-14：header 单字段变化 ⇒ block_hash 变化 ----
    #[test]
    fn bb_10_14_header_field_changes_change_block_hash() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let r = addr([0xBB; 32]);
        let cand = signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID);
        let base = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        let hash_of = |mutate: &dyn Fn(&mut BlockHeader)| -> [u8; 32] {
            let mut b = base.block.clone();
            mutate(&mut b.header);
            block_hash(&b).unwrap()
        };
        // BB-10：transaction_root 改变
        let h = hash_of(&|h| h.transaction_root = [0xAA; 32]);
        assert_ne!(h, base.block_hash, "BB-10 tx root ⇒ hash");
        // BB-11：state_root 改变
        let h = hash_of(&|h| h.state_root = [0xAB; 32]);
        assert_ne!(h, base.block_hash, "BB-11 state root ⇒ hash");
        // BB-12：parent_hash 改变
        let h = hash_of(&|h| h.parent_hash = [0xAC; 32]);
        assert_ne!(h, base.block_hash, "BB-12 parent hash ⇒ hash");
        // BB-13：height 改变
        let h = hash_of(&|h| h.height = base.block.header.height + 1);
        assert_ne!(h, base.block_hash, "BB-13 height ⇒ hash");
        // BB-14：timestamp 改变
        let h = hash_of(&|h| h.timestamp = base.block.header.timestamp + 1);
        assert_ne!(h, base.block_hash, "BB-14 timestamp ⇒ hash");
    }

    // ---- BB-15：signature exclusion —— 不同 proposer_signature ⇒ 相同 block_hash ----
    #[test]
    fn bb_15_signature_excluded_from_block_hash() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let r = addr([0xBB; 32]);
        let cand = signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID);
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        let hash_unsigned = res.block_hash;
        let mut b1 = res.block.clone();
        b1.proposer_signature = [0x01; 64];
        let mut b2 = res.block;
        b2.proposer_signature = [0x02; 64];
        assert_eq!(
            block_hash(&b1).unwrap(),
            block_hash(&b2).unwrap(),
            "different valid signatures ⇒ same block hash"
        );
        assert_eq!(hash_unsigned, block_hash(&b1).unwrap());
    }

    // ---- BB-17：fee burn ⇒ receipt.burned_fee>0 + BURN_ADDRESS balance 增 + state_root 反映 ----
    #[test]
    fn bb_17_burn_compat_into_canonical_state() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let root_before = store.state_root();
        let r = addr([0xBB; 32]);
        let cand = signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID);
        // fee_burn_bps = 1000（10%）⇒ burned_fee = 21_000 * 1000 / 10_000 = 2_100
        let res = build(&store, &exec_ctx(CHAIN_ID, 1000), &[cand]);
        let transition = &res.execution.tx_transitions[0];
        assert!(transition.receipt.burned_fee > 0, "burned_fee > 0");
        assert_eq!(transition.receipt.burned_fee, 2_100);
        // changes 内含 burn 账户 change（balance == burned_fee）
        let burn = transition
            .changes
            .iter()
            .find(|c| c.address == crate_burn_address())
            .expect("burn account change present");
        assert_eq!(burn.new_balance, 2_100);
        // state_root 反映 burn（≠ 执行前 store root）
        assert_ne!(res.block.header.state_root, *root_before.as_bytes());
    }

    // ---- BB-18：zero burn（fee_burn_bps=0）⇒ 不建 burn leaf / 无 burn change ----
    #[test]
    fn bb_18_zero_burn_no_burn_leaf() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let r = addr([0xBB; 32]);
        let cand = signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID);
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        let transition = &res.execution.tx_transitions[0];
        assert_eq!(transition.receipt.burned_fee, 0, "no burn with bps=0");
        assert!(
            transition
                .changes
                .iter()
                .all(|c| c.address != crate_burn_address()),
            "no burn account change"
        );
    }

    // ---- BB-19：nonce gap 按现有 Future 语义（不新增 invalid rule）----
    #[test]
    fn bb_19_nonce_gap_is_future_skip_not_invalid() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        // 账户当前 nonce = 5
        let mut store = StateStore::new(MemoryBackend::new());
        store
            .apply(&[AccountChange {
                address: sender,
                new_balance: 1_000_000,
                new_nonce: 5,
                created: true,
            }])
            .unwrap();
        let root_before = store.state_root();
        let r = addr([0xBB; 32]);
        // 候选 nonce = 10（> current 5 ⇒ Future）
        let cand = signed_candidate(kp.signing_key(), r, 10, 100, CHAIN_ID);
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        assert_eq!(res.block.body.txs.len(), 1, "tx enters block");
        assert!(
            res.execution.tx_transitions.is_empty(),
            "Future nonce skipped (Model A), not invalid"
        );
        assert_eq!(
            res.block.header.state_root,
            *root_before.as_bytes(),
            "no state change from skipped tx"
        );
    }

    // ---- 签名 seam roundtrip：attach ⇒ verify OK 且 block_hash 不变 ----
    #[test]
    fn signature_seam_attaches_and_verifies() {
        let kp = KeyPair::generate().unwrap();
        let sender = sender_addr(kp.signing_key());
        let store = seed_store(&[(sender, 1_000_000)]);
        let r = addr([0xBB; 32]);
        let cand = signed_candidate(kp.signing_key(), r, 0, 100, CHAIN_ID);
        let res = build(&store, &exec_ctx(CHAIN_ID, 0), &[cand]);
        let hash_before = res.block_hash;
        let signer = SoftwareSigner::new(KeyPair::generate().unwrap());
        let mut block = res.block;
        attach_proposer_signature(&mut block, &signer).unwrap();
        assert_eq!(hash_before, block_hash(&block).unwrap(), "sig ∉ block hash");
        validate_block_signature(&block, &signer.public_key(), CHAIN_ID)
            .expect("attached signature verifies (core P7-3)");
    }

    // 测试辅助：BURN_ADDRESS 地址（与 core `burn_address` 同构；node 不直接依赖 core，自建同构引用）。
    fn crate_burn_address() -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: [0u8; 32],
        })
    }
}
