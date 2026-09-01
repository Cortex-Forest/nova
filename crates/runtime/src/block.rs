//! Block 生命周期协调（P7-4；E1=A / E2=B / E3=A 冻结）。
//!
//! - **分层步骤 API**（E2=B）：不提供单 `process_block`；调用方按序调用
//!   `decode_block → validate_block_signature → validate_transaction_root →
//!   execute_and_verify_state_root → validate_height_parent → commit_block`。
//! - **错误组合**（E3=A）：[`BlockPipelineError`] 区分 decode / validation / execution / storage；
//!   **不改变底层错误语义**（直接包装，不吞掉、不重映射）。
//! - **不重造**底层冻结函数：全部委托 nova-core（P7-2/3）/ nova-execution（8D）/ nova-storage（8D）。

use nova_core::block::{
    Block, BlockCodecError, BlockExecutionResult, BlockValidationError, ParentContext,
    verify_block_signature, verify_height_parent, verify_transaction_root,
};
use nova_core::state::AccountChange;
use nova_crypto::signature::VerifyingKey;
use nova_execution::block::{BlockError, execute_block};
use nova_execution::state_transition::ExecutionContext;
use nova_storage::backend::StorageBackend;
use nova_storage::error::StorageError;
use nova_storage::node::NodeHash;
use nova_storage::state_root::{
    BlockStateRootError, calculate_state_root, verify_block_state_root,
};
use nova_storage::store::StateStore;

/// Block 验证类失败细分（E3=A）：Block 验证 vs state_root mismatch。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockValidationFailure {
    /// ②③⑤ Block 验证（nova-core `BlockValidationError`）。
    Block(BlockValidationError),
    /// ④ state_root 比对 mismatch（nova-storage `BlockStateRootError`）。
    StateRoot(BlockStateRootError),
}

impl core::fmt::Display for BlockValidationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Block(e) => write!(f, "block validation: {e}"),
            Self::StateRoot(e) => write!(f, "state root validation: {e}"),
        }
    }
}

impl std::error::Error for BlockValidationFailure {}

/// Block 生命周期管线错误（P7-4，E3=A 冻结）。
///
/// 4 顶层类别（decode / validation / execution / storage）明确区分失败域；
/// **不改变底层错误语义**（直接包装底层错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockPipelineError {
    /// ① 结构解码失败（nova-core）。
    Decode(BlockCodecError),
    /// ②③⑤ 验证失败 / ④ state_root mismatch（validation 类）。
    Validation(BlockValidationFailure),
    /// ④ 区块执行失败（nova-execution）。
    Execution(BlockError),
    /// ④ state_root 重算 / ⑥ 提交失败（nova-storage）。
    Storage(StorageError),
}

impl core::fmt::Display for BlockPipelineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "block decode: {e}"),
            Self::Validation(e) => write!(f, "block validation: {e}"),
            Self::Execution(e) => write!(f, "block execution: {e}"),
            Self::Storage(e) => write!(f, "block storage: {e}"),
        }
    }
}

impl std::error::Error for BlockPipelineError {}

/// ① 结构（薄封装 nova-core `decode_block`）。
pub fn decode_block(bytes: &[u8]) -> Result<Block, BlockPipelineError> {
    nova_core::block::decode_block(bytes).map_err(BlockPipelineError::Decode)
}

/// ② proposer signature 验证（委托 nova-core P7-3；纯签名，无 membership，A11 DEFERRED）。
pub fn validate_block_signature(
    block: &Block,
    proposer_vk: &VerifyingKey,
    chain_id: u64,
) -> Result<(), BlockPipelineError> {
    verify_block_signature(block, proposer_vk, chain_id)
        .map_err(|e| BlockPipelineError::Validation(BlockValidationFailure::Block(e)))
}

/// ③ transaction_root 验证（委托 nova-core P7-3）。
pub fn validate_transaction_root(block: &Block) -> Result<(), BlockPipelineError> {
    verify_transaction_root(&block.header.transaction_root, &block.body)
        .map_err(|e| BlockPipelineError::Validation(BlockValidationFailure::Block(e)))
}

/// ④ 执行 + state_root 重算比对（跨层组合：execution 8D + storage 8D）。
///
/// - `execute_block`（纯计算）→ 收集 `tx_changes` → `calculate_state_root`（只读重算）→
///   `verify_block_state_root`（比对 `header.state_root`）。
/// - **不提交**（commit 归 ⑥）；只验证执行承诺。
pub fn execute_and_verify_state_root<B: StorageBackend + Clone>(
    store: &StateStore<B>,
    block: &Block,
    sender_keys: &[VerifyingKey],
    ctx: &ExecutionContext,
    max_gas_per_block: u64,
) -> Result<BlockExecutionResult, BlockPipelineError> {
    let result = execute_block(store, &block.body.txs, sender_keys, ctx, max_gas_per_block)
        .map_err(BlockPipelineError::Execution)?;
    let tx_changes: Vec<&[AccountChange]> = result
        .tx_transitions
        .iter()
        .map(|t| t.changes.as_slice())
        .collect();
    let computed = calculate_state_root(store, &tx_changes).map_err(BlockPipelineError::Storage)?;
    let expected = NodeHash::from_bytes(block.header.state_root);
    verify_block_state_root(&expected, &computed)
        .map_err(|e| BlockPipelineError::Validation(BlockValidationFailure::StateRoot(e)))?;
    Ok(result)
}

/// ⑤ height/parent 链式验证（委托 nova-core P7-3；parent 外部提供，单父 V0.1）。
pub fn validate_height_parent(
    block: &Block,
    parent: &ParentContext,
) -> Result<(), BlockPipelineError> {
    verify_height_parent(block, parent)
        .map_err(|e| BlockPipelineError::Validation(BlockValidationFailure::Block(e)))
}

/// ⑥ 提交（委托 nova-storage 8D `apply_block`；区块级原子事务）。
pub fn commit_block<B: StorageBackend + Clone>(
    store: &mut StateStore<B>,
    execution_result: &BlockExecutionResult,
) -> Result<NodeHash, BlockPipelineError> {
    let tx_changes: Vec<&[AccountChange]> = execution_result
        .tx_transitions
        .iter()
        .map(|t| t.changes.as_slice())
        .collect();
    store
        .apply_block(&tx_changes)
        .map_err(BlockPipelineError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::block::{
        BLOCK_VERSION, BlockBody, BlockHeader, compute_transaction_root, encode_block_header,
    };
    use nova_core::transaction::gas_fee::TRANSFER_INTRINSIC_GAS;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::ChainIdentity;
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use nova_crypto::transaction::{TransactionType, sign_transaction};
    use nova_storage::memory::{MemoryBackend, MemorySnapshot};
    use nova_storage::node::TrieKey;

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
    }

    fn ctx(chain_id: u64) -> ExecutionContext {
        ExecutionContext {
            chain: ChainIdentity {
                network_id: NetworkId::Mainnet,
                chain_id,
                genesis_hash: [0u8; 32],
            },
            current_height: 0,
            fee_burn_bps: 0,
        }
    }

    fn signed_tx(
        sender: NovaAddress,
        receiver: NovaAddress,
        nonce: u64,
        amount: u128,
        sk: &nova_crypto::signature::SigningKey,
        chain_id: u64,
    ) -> nova_crypto::transaction::TransactionV1 {
        let mut tx = nova_crypto::transaction::TransactionV1 {
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
            expiration: 0,
            signature: [0u8; 64],
        };
        sign_transaction(sk, &mut tx).unwrap();
        tx
    }

    fn block_signature(
        header: &BlockHeader,
        sk: &nova_crypto::signature::SigningKey,
        chain_id: u64,
    ) -> [u8; 64] {
        let payload = encode_block_header(header);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload).unwrap();
        let msg = hash_signing_message(&signed);
        sign_message_hash(sk, &msg).to_bytes()
    }

    /// 构造一个完整合法 Block（签名 tx + 匹配 tx_root/state_root + proposer 签名）。
    fn make_valid_block(
        chain_id: u64,
        height: u64,
        parent: &ParentContext,
        max_gas: u64,
    ) -> (
        StateStore<MemoryBackend>,
        Block,
        Vec<VerifyingKey>,
        ExecutionContext,
        KeyPair,
    ) {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0xbb; 32]);
        let mut store = StateStore::new(MemoryBackend::new());
        store
            .apply(&[AccountChange {
                address: sender,
                new_balance: 1_000_000,
                new_nonce: 0,
                created: true,
            }])
            .unwrap();
        let tx = signed_tx(sender, receiver, 0, 100, kp.signing_key(), chain_id);
        let txs = vec![tx];
        let keys = vec![*kp.verifying_key()];
        let ctx = ctx(chain_id);
        let body = BlockBody { txs };
        let tx_root = compute_transaction_root(&body);
        let ber = execute_block(&store, &body.txs, &keys, &ctx, max_gas).unwrap();
        let changes: Vec<&[AccountChange]> = ber
            .tx_transitions
            .iter()
            .map(|t| t.changes.as_slice())
            .collect();
        let state_root = *calculate_state_root(&store, &changes).unwrap().as_bytes();
        let header = BlockHeader {
            version: BLOCK_VERSION,
            chain_id,
            height,
            parent_hash: parent.parent_hash,
            finality_reference: None,
            transaction_root: tx_root,
            state_root,
            validator_set_hash: [0x33; 32],
            timestamp: 0,
        };
        let block = Block {
            header: header.clone(),
            body: body.clone(),
            proposer_signature: block_signature(&header, kp.signing_key(), chain_id),
        };
        (store, block, keys, ctx, kp)
    }

    #[test]
    fn lifecycle_execute_verify_commit_ok() {
        // 全管线 ①~⑥ ok：②③⑤ 验证 → ④ 执行+state_root → ⑥ 提交落库。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (mut store, block, keys, ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);

        // ① decode roundtrip
        let bytes = nova_core::block::encode_block(&block).unwrap();
        assert_eq!(decode_block(&bytes).unwrap(), block);
        // ② ③ ⑤
        assert!(validate_block_signature(&block, &keys[0], chain_id).is_ok());
        assert!(validate_transaction_root(&block).is_ok());
        assert!(validate_height_parent(&block, &parent).is_ok());
        // ④
        let ber = execute_and_verify_state_root(&store, &block, &keys, &ctx, max_gas).unwrap();
        // ⑥
        let root = commit_block(&mut store, &ber).unwrap();
        assert_eq!(root.as_bytes(), &block.header.state_root);
    }

    #[test]
    fn pipeline_rejects_signature_tamper() {
        // ② 篡改 header（签名后）⇒ Validation(Block(InvalidProposerSignature))；④ 不执行。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, mut block, keys, ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);
        block.header.state_root[0] ^= 0xff;
        assert!(matches!(
            validate_block_signature(&block, &keys[0], chain_id),
            Err(BlockPipelineError::Validation(
                BlockValidationFailure::Block(BlockValidationError::InvalidProposerSignature)
            ))
        ));
        let _ = store;
        let _ = ctx;
    }

    #[test]
    fn pipeline_rejects_transaction_root_mismatch() {
        // ③ body 篡改 ⇒ Validation(Block(TransactionRootMismatch))。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, mut block, keys, _ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);
        block.body.txs[0].amount += 1;
        assert!(matches!(
            validate_transaction_root(&block),
            Err(BlockPipelineError::Validation(
                BlockValidationFailure::Block(BlockValidationError::TransactionRootMismatch)
            ))
        ));
        let _ = store;
        let _ = keys;
    }

    #[test]
    fn pipeline_rejects_state_root_mismatch() {
        // ④ header.state_root 与执行结果不符（重新签名使 ② 过）⇒ Validation(StateRoot(Mismatch))。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, block, keys, ctx, kp) = make_valid_block(chain_id, 1, &parent, max_gas);
        // 篡改 state_root 并重签（② 过；④ 应 StateRoot(Mismatch)）
        let mut bad = block.clone();
        bad.header.state_root = [0x00; 32];
        bad.proposer_signature = block_signature(&bad.header, kp.signing_key(), chain_id);
        assert!(validate_block_signature(&bad, kp.verifying_key(), chain_id).is_ok());
        assert!(matches!(
            execute_and_verify_state_root(&store, &bad, &keys, &ctx, max_gas),
            Err(BlockPipelineError::Validation(
                BlockValidationFailure::StateRoot(BlockStateRootError::Mismatch)
            ))
        ));
    }

    #[test]
    fn pipeline_rejects_height_parent() {
        // ⑤ height 不连续 / parent_hash 不匹配 ⇒ Validation(Block(...))。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, block, keys, ctx, _kp) = make_valid_block(chain_id, 2, &parent, max_gas); // height=2
        let bad_height = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        }; // 0+1 != 2
        assert!(matches!(
            validate_height_parent(&block, &bad_height),
            Err(BlockPipelineError::Validation(
                BlockValidationFailure::Block(BlockValidationError::InvalidHeightChain)
            ))
        ));
        let bad_hash = ParentContext {
            parent_height: 1,
            parent_hash: [0x00; 32],
        };
        assert!(matches!(
            validate_height_parent(&block, &bad_hash),
            Err(BlockPipelineError::Validation(
                BlockValidationFailure::Block(BlockValidationError::ParentHashMismatch)
            ))
        ));
        let _ = store;
        let _ = keys;
        let _ = ctx;
    }

    #[test]
    fn pipeline_decode_error_category() {
        // ① decode 失败 ⇒ Decode 类别。
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (_store, block, _keys, _ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);
        let bytes = nova_core::block::encode_block(&block).unwrap();
        assert!(matches!(
            decode_block(&bytes[..bytes.len() - 1]),
            Err(BlockPipelineError::Decode(
                BlockCodecError::InvalidLength { .. }
            ))
        ));
    }

    /// TASK 1: execute_block 失败（重复 sender+nonce）⇒ Execution 类别，底层 BlockError 保留，
    /// 不吞不 generic；不进入 commit（execute_and_verify_state_root 直接 Err）。
    #[test]
    fn pipeline_execution_failure_preserves_block_error() {
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, mut block, keys, ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);

        // 复制 tx → 同 sender 同 nonce → validate_block 返回 NonceConflict
        let dup_tx = block.body.txs[0].clone();
        block.body.txs.push(dup_tx);
        let dup_keys = vec![keys[0], keys[0]];

        let err =
            execute_and_verify_state_root(&store, &block, &dup_keys, &ctx, max_gas).unwrap_err();
        assert!(matches!(
            err,
            BlockPipelineError::Execution(BlockError::NonceConflict)
        ));
        // 底层错误保留（Display 含具体信息，非 generic）
        assert!(err.to_string().contains("nonce"));
    }

    /// STEP 7-A (TASK 3): execute_block 失败（累计 gas 超 max_gas_per_block）⇒ Execution 类别，
    /// 底层 BlockError 保留，不吞不 generic；不进入 commit（execute_and_verify_state_root 直接 Err）；
    /// ②③ 先过（签名 + tx root 合法），失败纯粹来自 ④ gas 预算。
    ///
    /// 触发路径：`execute_block` → `validate_block` 预检 `n × TRANSFER_INTRINSIC_GAS > max_gas`
    /// ⇒ `Err(BlockError::GasLimitExceeded)`（在逐 tx apply 之前，零状态副作用）。
    #[test]
    fn pipeline_gas_limit_failure_preserves_block_error() {
        let chain_id = 1001;
        // 每 tx intrinsic gas = 21_000；预算只够 2 个 tx，3-tx body 必然超限
        let max_gas = TRANSFER_INTRINSIC_GAS * 2;
        let (store, block, keys, ctx, proposer_vk) = make_gas_exceeding_block(chain_id, max_gas);

        // ②③ 先过（签名 + tx root 合法）⇒ 失败纯粹来自 ④ gas 预算
        assert!(validate_block_signature(&block, &proposer_vk, chain_id).is_ok());
        assert!(validate_transaction_root(&block).is_ok());

        let root_before = store.state_root();
        let err = execute_and_verify_state_root(&store, &block, &keys, &ctx, max_gas).unwrap_err();
        assert!(matches!(
            err,
            BlockPipelineError::Execution(BlockError::GasLimitExceeded)
        ));
        // 底层错误保留（Display 含具体信息，非 generic）
        assert!(err.to_string().contains("gas"));
        // commit 未执行：execute_and_verify_state_root 直接 Err，无 result 可提交；
        // state 未变化（execute 纯计算，未落盘）
        assert_eq!(store.state_root(), root_before);
    }

    /// STEP 7-A helper：构造一个 gas 超限但结构合法的 Block。
    ///
    /// - N = 3 个**不同 sender** 的 tx（各 nonce 0，sender 均注资）→ 不触发 NonceConflict；
    ///   transaction_root 覆盖完整 N-tx body（③ 通过）。
    /// - state_root 由执行前 K = N-1 个 tx 计算（K×gas ≤ max_gas，根是"合法"的）；
    ///   但完整 N-tx body 累计 gas 超 `max_gas` ⇒ ④ `validate_block` 预检触发
    ///   `GasLimitExceeded`（逐 tx apply 之前，零副作用）。
    fn make_gas_exceeding_block(
        chain_id: u64,
        max_gas: u64,
    ) -> (
        StateStore<MemoryBackend>,
        Block,
        Vec<VerifyingKey>,
        ExecutionContext,
        VerifyingKey,
    ) {
        let n_txs = 3usize;
        let ctx = ctx(chain_id);
        let mut store = StateStore::new(MemoryBackend::new());
        let mut kps = Vec::with_capacity(n_txs);
        let mut txs = Vec::with_capacity(n_txs);
        let mut keys = Vec::with_capacity(n_txs);

        for _ in 0..n_txs {
            let kp = KeyPair::generate().unwrap();
            let sender = NovaAddress::from_verifying_key(
                kp.verifying_key(),
                AddressType::UserAccount,
                NetworkId::Mainnet,
            )
            .unwrap();
            store
                .apply(&[AccountChange {
                    address: sender,
                    new_balance: 1_000_000,
                    new_nonce: 0,
                    created: true,
                }])
                .unwrap();
            let mut tx = nova_crypto::transaction::TransactionV1 {
                version: 1,
                chain_id,
                nonce: 0,
                sender,
                receiver: addr([0xbb; 32]),
                amount: 100,
                gas_limit: 100_000,
                gas_price: 1,
                transaction_type: TransactionType::Transfer,
                payload: vec![0u8; 140],
                expiration: 0,
                signature: [0u8; 64],
            };
            sign_transaction(kp.signing_key(), &mut tx).unwrap();
            txs.push(tx);
            keys.push(*kp.verifying_key());
            kps.push(kp);
        }

        let body = BlockBody { txs };
        let tx_root = compute_transaction_root(&body);

        // 前 K = N-1 个 tx 的 gas 在预算内 ⇒ 以其执行结果计算 state_root（合法根）
        let k = n_txs - 1;
        let ber = execute_block(&store, &body.txs[..k], &keys[..k], &ctx, max_gas).unwrap();
        let changes: Vec<&[AccountChange]> = ber
            .tx_transitions
            .iter()
            .map(|t| t.changes.as_slice())
            .collect();
        let state_root = *calculate_state_root(&store, &changes).unwrap().as_bytes();

        let header = BlockHeader {
            version: BLOCK_VERSION,
            chain_id,
            height: 1,
            parent_hash: [0xaa; 32],
            finality_reference: None,
            transaction_root: tx_root,
            state_root,
            validator_set_hash: [0x33; 32],
            timestamp: 0,
        };
        let block = Block {
            header: header.clone(),
            body: body.clone(),
            proposer_signature: block_signature(&header, kps[0].signing_key(), chain_id),
        };
        (store, block, keys, ctx, *kps[0].verifying_key())
    }

    /// TASK 2: apply_block 失败（backend put 注入失败）⇒ Storage 类别；
    /// 原子回滚（state root 不变，无部分提交）；commit 未完成（返回 Err）。
    #[derive(Clone)]
    struct FailingBackend {
        inner: MemoryBackend,
    }

    impl StorageBackend for FailingBackend {
        type Snapshot = MemorySnapshot;

        fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
            self.inner.get(key)
        }

        fn put(&mut self, _key: TrieKey, _value: Vec<u8>) -> Result<(), StorageError> {
            Err(StorageError::BackendFailure)
        }

        fn delete(&mut self, key: &TrieKey) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn snapshot(&self) -> Self::Snapshot {
            self.inner.snapshot()
        }

        fn restore(&mut self, snap: &Self::Snapshot) {
            self.inner.restore(snap);
        }

        fn flush(&mut self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn entries(&self) -> Vec<(TrieKey, Vec<u8>)> {
            self.inner.entries()
        }
    }

    #[test]
    fn pipeline_storage_failure_atomic_rollback() {
        let chain_id = 1001;
        let max_gas = 1_000_000;
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        let (store, block, keys, ctx, _kp) = make_valid_block(chain_id, 1, &parent, max_gas);

        // ④ 正常执行 + state_root 验证（MemoryBackend）
        let ber = execute_and_verify_state_root(&store, &block, &keys, &ctx, max_gas).unwrap();

        // ⑥ 提交到 FailingBackend（put 注入失败）→ Storage 错误 + 原子回滚
        let mut fstore = StateStore::new(FailingBackend {
            inner: MemoryBackend::new(),
        });
        let root_before = fstore.state_root();
        let err = commit_block(&mut fstore, &ber).unwrap_err();
        assert!(matches!(
            err,
            BlockPipelineError::Storage(StorageError::BackendFailure)
        ));
        // 原子回滚：无部分提交（root 不变）
        assert_eq!(fstore.state_root(), root_before);
    }
}
