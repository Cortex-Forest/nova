//! Node 区块应用适配层（PHASE 3 STEP 7-D；ADR-0046 Node Integration Architecture）。
//!
//! - 连接：收到/产生的 Block wire → 冻结 `nova-runtime` 7-step 管线 → `StateStore` 提交 → Node 持有 ChainHead。
//! - **Node 不直接依赖 execution**；一切执行/验证/提交经 runtime 冻结函数 + storage 公开 API。
//! - Runtime 无状态；ChainHead 由 Node 持有（ADR-0046 §8）。
//! - 管线顺序冻结（ADR-0046 §12）：①decode → ②signature → ③tx-root → ④execute+verify-root →
//!   ⑤height/parent → ⑥commit；**禁止重排 / commit-before-verify / update-head-before-commit**。

use nova_crypto::address::{NetworkId, NovaAddress};
use nova_crypto::identity::ChainIdentity;
use nova_crypto::signature::VerifyingKey;
use nova_runtime::{
    Block, BlockPipelineError, ExecutionContext, KeyResolver, ParentContext, block_hash,
    commit_block, decode_block, execute_and_verify_state_root, validate_block_signature,
    validate_height_parent, validate_transaction_root,
};
use nova_storage::backend::StorageBackend;
use nova_storage::node::NodeHash;
use nova_storage::store::StateStore;

/// Node 持有的 canonical head（ADR-0046 §8；Runtime 无状态）。
///
/// - ⑥ commit 成功 → head 更新为 N；Block N+1 的 `ParentContext` 由 head 派生。
/// - `block_hash` = 当前 head 的 block_hash（= 下一块的 parent_hash）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    /// 已提交高度。
    pub height: u64,
    /// 当前 head 的 block_hash（= 下一块 ⑤ 的 parent_hash）。
    pub block_hash: [u8; 32],
    /// 当前 head 的 state root（= ⑥ `commit_block` 返回值）。
    pub state_root: NodeHash,
    /// 当前 head 的父块 hash（genesis = 0）。
    pub parent_hash: [u8; 32],
}

impl ChainHead {
    /// genesis head：height 0，`block_hash` = genesis_hash，`state_root` = genesis 状态 root。
    pub fn genesis(genesis_hash: [u8; 32], genesis_state_root: NodeHash) -> Self {
        Self {
            height: 0,
            block_hash: genesis_hash,
            state_root: genesis_state_root,
            parent_hash: [0u8; 32],
        }
    }
}

/// Node 层区块应用错误（typed；ADR-0046 §18 —— 保留底层 runtime/storage 错误，不 String 化、不 Box 隐藏）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeBlockApplicationError {
    /// runtime 管线错误（decode / validation / execution / storage 4 类，保留底层错误）。
    Pipeline(BlockPipelineError),
    /// sender key 未知 ⇒ 整块拒绝（ADR-0046 §6 / ADR-0047 Security；禁止 skip）。
    KeyResolution(NovaAddress),
    /// head 派生失败（如 height 溢出）。
    HeadInvalid,
}

impl From<BlockPipelineError> for NodeBlockApplicationError {
    fn from(e: BlockPipelineError) -> Self {
        Self::Pipeline(e)
    }
}

impl core::fmt::Display for NodeBlockApplicationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pipeline(e) => write!(f, "block application pipeline: {e}"),
            Self::KeyResolution(addr) => {
                write!(f, "unknown sender key for {addr:?}: rejecting whole block")
            }
            Self::HeadInvalid => write!(f, "chain head derivation invalid"),
        }
    }
}

impl std::error::Error for NodeBlockApplicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pipeline(e) => Some(e),
            _ => None,
        }
    }
}

/// Node 区块应用适配器（ADR-0046 §4/§7）。
///
/// - 持有：`StateStore<B>`（storage 公开构造）+ `KeyResolver`（sender key 解析）+ 运行参数 + `ChainHead`。
/// - 只调 runtime 冻结 7-step 函数；**不执行 execution、不碰 trie/SMT/commit_changes/apply_changes_inner**。
/// - 失败短路：任一失败 ⇒ 不 commit、不更新 head。
pub struct NodeBlockAdapter<B: StorageBackend + Clone, R: KeyResolver> {
    store: StateStore<B>,
    resolver: R,
    chain_id: u64,
    genesis_hash: [u8; 32],
    max_gas_per_block: u64,
    fee_burn_bps: u16,
    head: ChainHead,
}

impl<B: StorageBackend + Clone, R: KeyResolver> NodeBlockAdapter<B, R> {
    /// 构造适配器（Node 负责提供 store / resolver / 运行参数 / 初始 head）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: StateStore<B>,
        resolver: R,
        chain_id: u64,
        genesis_hash: [u8; 32],
        max_gas_per_block: u64,
        fee_burn_bps: u16,
        head: ChainHead,
    ) -> Self {
        Self {
            store,
            resolver,
            chain_id,
            genesis_hash,
            max_gas_per_block,
            fee_burn_bps,
            head,
        }
    }

    /// 当前 head（只读）。
    pub fn head(&self) -> &ChainHead {
        &self.head
    }

    /// 当前 state store（只读）。
    pub fn store(&self) -> &StateStore<B> {
        &self.store
    }

    /// 应用一个完整 block wire（冻结顺序 ①~⑥；ADR-0046 §12）。
    ///
    /// 返回更新后的 [`ChainHead`]（仅 ⑥ commit 成功后才更新 head）。
    pub fn apply_block(
        &mut self,
        wire: &[u8],
        proposer_vk: &VerifyingKey,
    ) -> Result<ChainHead, NodeBlockApplicationError> {
        // ① decode
        let block = decode_block(wire)?;
        // ② proposer signature（A11 DEFERRED：仅对给定 key 验证，无 membership）
        validate_block_signature(&block, proposer_vk, self.chain_id)?;
        // ③ transaction root
        validate_transaction_root(&block)?;
        // sender key resolution（任一未知 ⇒ 整块拒绝，ADR-0046 §6）
        let sender_keys = self.resolve_sender_keys(&block)?;
        // E4 执行上下文（current_height = head.height）
        let ctx = ExecutionContext {
            chain: ChainIdentity {
                network_id: NetworkId::Mainnet,
                chain_id: self.chain_id,
                genesis_hash: self.genesis_hash,
            },
            current_height: self.head.height,
            fee_burn_bps: self.fee_burn_bps,
        };
        // ④ execute + state root verify（只读重算，不提交）
        let exec = execute_and_verify_state_root(
            &self.store,
            &block,
            &sender_keys,
            &ctx,
            self.max_gas_per_block,
        )?;
        // ⑤ height/parent（parent 由 head 派生）
        let parent = ParentContext {
            parent_height: self.head.height,
            parent_hash: self.head.block_hash,
        };
        validate_height_parent(&block, &parent)?;
        // ⑥ commit（区块级原子；失败 ⇒ storage 内部 rollback）
        let root = commit_block(&mut self.store, &exec)?;
        // head 更新（仅成功 commit 后；先 commit 再更新 head）
        let new_hash = block_hash(&block)
            .map_err(|e| NodeBlockApplicationError::Pipeline(BlockPipelineError::Decode(e)))?;
        let next = ChainHead {
            height: self
                .head
                .height
                .checked_add(1)
                .ok_or(NodeBlockApplicationError::HeadInvalid)?,
            block_hash: new_hash,
            state_root: root,
            parent_hash: self.head.block_hash,
        };
        self.head = next.clone();
        Ok(next)
    }

    /// 解析 block 内全部 sender key；任一未知 ⇒ 整块拒绝（禁止 skip）。
    fn resolve_sender_keys(
        &self,
        block: &Block,
    ) -> Result<Vec<VerifyingKey>, NodeBlockApplicationError> {
        block
            .body
            .txs
            .iter()
            .map(|tx| {
                self.resolver
                    .resolve(tx.sender)
                    .ok_or(NodeBlockApplicationError::KeyResolution(tx.sender))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{ADDRESS_VERSION, AddressType, NovaAddressPayload};
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::{SigningKey, sign_message_hash};
    use nova_crypto::transaction::{TransactionType, TransactionV1, sign_transaction};
    use nova_runtime::{
        BLOCK_VERSION, BlockBody, BlockHeader, TRANSFER_INTRINSIC_GAS, compute_transaction_root,
        encode_block, encode_block_header,
    };
    use nova_storage::error::StorageError;
    use nova_storage::memory::{MemoryBackend, MemorySnapshot};
    use nova_storage::node::TrieKey;
    use std::collections::HashMap;

    fn addr(key_hash: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash,
        })
    }

    /// 初始 store：给 sender 注资 1_000_000（nonce 0），返回 store + genesis root。
    fn genesis_store(sender: NovaAddress) -> (StateStore<MemoryBackend>, NodeHash) {
        let mut store = StateStore::new(MemoryBackend::new());
        store
            .apply(&[nova_runtime::AccountChange {
                address: sender,
                new_balance: 1_000_000,
                new_nonce: 0,
                created: true,
            }])
            .unwrap();
        let root = store.state_root();
        (store, root)
    }

    /// 构造已签名 transfer tx（gas_price=1，fee_burn_bps=0 ⇒ fee=21_000；expiration 足够大以通过 N13 高度窗）。
    fn signed_tx(
        sender: NovaAddress,
        receiver: NovaAddress,
        nonce: u64,
        amount: u128,
        sk: &SigningKey,
        chain_id: u64,
    ) -> TransactionV1 {
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
        tx
    }

    /// proposer 块签名（复用 runtime 测试同款 frozen 语义）。
    fn block_signature(header: &BlockHeader, sk: &SigningKey, chain_id: u64) -> [u8; 64] {
        let payload = encode_block_header(header);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload).unwrap();
        let msg = hash_signing_message(&signed);
        sign_message_hash(sk, &msg).to_bytes()
    }

    /// 构造完整合法 Block（header/body/signature 与 `state_root` 一致）。
    fn make_valid_block(
        chain_id: u64,
        height: u64,
        parent: &ParentContext,
        tx: TransactionV1,
        state_root: NodeHash,
        proposer_kp: &KeyPair,
    ) -> Block {
        let body = BlockBody { txs: vec![tx] };
        let tx_root = compute_transaction_root(&body);
        let header = BlockHeader {
            version: BLOCK_VERSION,
            chain_id,
            height,
            parent_hash: parent.parent_hash,
            finality_reference: None,
            transaction_root: tx_root,
            state_root: *state_root.as_bytes(),
            validator_set_hash: [0x33; 32],
            timestamp: 0,
        };
        Block {
            header: header.clone(),
            body: body.clone(),
            proposer_signature: block_signature(&header, proposer_kp.signing_key(), chain_id),
        }
    }

    /// Fixture：单 transfer 的 AccountChanges（冻结语义：gas_used=21_000，gas_price=1，
    /// fee_burn_bps=0 ⇒ fee=21_000）。**仅测试用**；不依赖 execution（不重造执行逻辑）。
    fn transfer_changes(
        tx: &TransactionV1,
        sender_balance: u128,
        sender_nonce: u64,
        receiver_exists: bool,
        receiver_balance: u128,
        receiver_nonce: u64,
    ) -> Vec<nova_runtime::AccountChange> {
        let fee = TRANSFER_INTRINSIC_GAS as u128; // gas_price = 1
        let mut changes = vec![nova_runtime::AccountChange {
            address: tx.sender,
            new_balance: sender_balance - tx.amount - fee,
            new_nonce: sender_nonce + 1,
            created: false,
        }];
        if tx.sender != tx.receiver {
            if receiver_exists {
                changes.push(nova_runtime::AccountChange {
                    address: tx.receiver,
                    new_balance: receiver_balance + tx.amount,
                    new_nonce: receiver_nonce,
                    created: false,
                });
            } else {
                changes.push(nova_runtime::AccountChange {
                    address: tx.receiver,
                    new_balance: tx.amount,
                    new_nonce: 0,
                    created: true,
                });
            }
        }
        changes
    }

    /// 在 probe store（storage 公开 `StateStore::apply`）上应用单 transfer changes ⇒ 期望 root。
    fn expected_state_root(
        base: &StateStore<MemoryBackend>,
        tx: &TransactionV1,
        sender_balance: u128,
        sender_nonce: u64,
        receiver_exists: bool,
        receiver_balance: u128,
        receiver_nonce: u64,
    ) -> NodeHash {
        let changes = transfer_changes(
            tx,
            sender_balance,
            sender_nonce,
            receiver_exists,
            receiver_balance,
            receiver_nonce,
        );
        let mut probe = base.clone();
        probe.apply(&changes).unwrap();
        probe.state_root()
    }

    /// MemoryKeyRegistry：最小测试实现（ADR-0047 Ownership；cfg(test)）。
    #[derive(Clone, Default)]
    struct MemoryKeyRegistry {
        map: HashMap<NovaAddress, VerifyingKey>,
    }

    impl MemoryKeyRegistry {
        fn with(entries: impl IntoIterator<Item = (NovaAddress, VerifyingKey)>) -> Self {
            Self {
                map: entries.into_iter().collect(),
            }
        }
    }

    impl KeyResolver for MemoryKeyRegistry {
        fn resolve(&self, address: NovaAddress) -> Option<VerifyingKey> {
            self.map.get(&address).copied()
        }
    }

    /// 标准测试环境：proposer kp（= sender kp）、sender/receiver、genesis store/root、registry。
    fn test_env() -> (
        KeyPair,
        NovaAddress,
        NovaAddress,
        StateStore<MemoryBackend>,
        NodeHash,
        MemoryKeyRegistry,
    ) {
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0xbb; 32]);
        let (store, genesis_root) = genesis_store(sender);
        let registry = MemoryKeyRegistry::with([(sender, *kp.verifying_key())]);
        (kp, sender, receiver, store, genesis_root, registry)
    }

    #[test]
    fn node_applies_block_successfully() {
        // wire → ①decode → ②③validate → ④execute+verify-root → ⑤height/parent → ⑥commit → head update
        let chain_id = 1001;
        let genesis_hash = [0xaa; 32];
        let max_gas = 1_000_000;
        let (kp, sender, receiver, store, genesis_root, registry) = test_env();
        let head = ChainHead::genesis(genesis_hash, genesis_root);
        let mut adapter =
            NodeBlockAdapter::new(store, registry, chain_id, genesis_hash, max_gas, 0, head);

        let tx = signed_tx(sender, receiver, 0, 100, kp.signing_key(), chain_id);
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: genesis_hash,
        };
        let expected_root = expected_state_root(adapter.store(), &tx, 1_000_000, 0, false, 0, 0);
        let block = make_valid_block(chain_id, 1, &parent, tx, expected_root, &kp);
        let wire = encode_block(&block).unwrap();

        let new_head = adapter.apply_block(&wire, kp.verifying_key()).unwrap();
        assert_eq!(new_head.height, 1);
        assert_eq!(new_head.state_root, expected_root);
        assert_eq!(new_head.parent_hash, genesis_hash);
        assert_eq!(adapter.head(), &new_head, "head advanced after commit");
        assert_eq!(
            adapter.store().state_root(),
            expected_root,
            "state committed == expected root"
        );
    }

    #[test]
    fn node_rejects_unknown_sender_key() {
        // 缺 sender key ⇒ 整块拒绝；state/head 不变。
        let chain_id = 1001;
        let genesis_hash = [0xaa; 32];
        let max_gas = 1_000_000;
        let (kp, sender, receiver, store, genesis_root, _registry) = test_env();
        let empty_registry = MemoryKeyRegistry::default();
        let head = ChainHead::genesis(genesis_hash, genesis_root);
        let mut adapter = NodeBlockAdapter::new(
            store,
            empty_registry,
            chain_id,
            genesis_hash,
            max_gas,
            0,
            head,
        );
        let root_before = adapter.store().state_root();
        let head_before = adapter.head().clone();

        let tx = signed_tx(sender, receiver, 0, 100, kp.signing_key(), chain_id);
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: genesis_hash,
        };
        let expected_root = expected_state_root(adapter.store(), &tx, 1_000_000, 0, false, 0, 0);
        let block = make_valid_block(chain_id, 1, &parent, tx, expected_root, &kp);
        let wire = encode_block(&block).unwrap();

        let err = adapter.apply_block(&wire, kp.verifying_key()).unwrap_err();
        assert!(
            matches!(err, NodeBlockApplicationError::KeyResolution(a) if a == sender),
            "unknown sender key must reject whole block"
        );
        assert_eq!(adapter.store().state_root(), root_before, "state unchanged");
        assert_eq!(adapter.head(), &head_before, "head unchanged");
    }

    #[test]
    fn node_multi_block_continuity() {
        // Block N commit → head=N → Block N+1 parent=Block N → 基于 N 提交状态执行 → commit → head 推进
        let chain_id = 1001;
        let genesis_hash = [0xaa; 32];
        let max_gas = 1_000_000;
        let (kp, sender, receiver_b, store, genesis_root, registry) = test_env();
        let receiver_c = addr([0xcc; 32]);
        let head = ChainHead::genesis(genesis_hash, genesis_root);
        let mut adapter =
            NodeBlockAdapter::new(store, registry, chain_id, genesis_hash, max_gas, 0, head);

        // Block N (height 1)：A → B，amount 100
        let tx_n = signed_tx(sender, receiver_b, 0, 100, kp.signing_key(), chain_id);
        let parent_n = ParentContext {
            parent_height: 0,
            parent_hash: genesis_hash,
        };
        let root_n = expected_state_root(adapter.store(), &tx_n, 1_000_000, 0, false, 0, 0);
        let block_n = make_valid_block(chain_id, 1, &parent_n, tx_n, root_n, &kp);
        let head_n = adapter
            .apply_block(&encode_block(&block_n).unwrap(), kp.verifying_key())
            .unwrap();
        assert_eq!(head_n.height, 1, "N commit ok");
        assert_eq!(head_n.state_root, root_n);

        // Block N+1 (height 2)：A → C，amount 50，A nonce=1（看到 N 提交的状态：balance 978_900）
        let tx_n1 = signed_tx(sender, receiver_c, 1, 50, kp.signing_key(), chain_id);
        let parent_n1 = ParentContext {
            parent_height: 1,
            parent_hash: head_n.block_hash,
        };
        let root_n1 = expected_state_root(adapter.store(), &tx_n1, 978_900, 1, false, 0, 0);
        let block_n1 = make_valid_block(chain_id, 2, &parent_n1, tx_n1, root_n1, &kp);
        let head_n1 = adapter
            .apply_block(&encode_block(&block_n1).unwrap(), kp.verifying_key())
            .unwrap();

        assert_eq!(head_n1.height, 2, "N+1 commit ok");
        assert_eq!(head_n1.state_root, root_n1, "N+1 state root ok");
        assert_eq!(head_n1.parent_hash, head_n.block_hash, "N+1 parent = N");
        assert_ne!(head_n1.state_root, root_n, "state advanced");
        assert_eq!(adapter.head(), &head_n1, "head advanced to N+1");
        assert_eq!(
            adapter.store().state_root(),
            root_n1,
            "committed state = N+1 root"
        );
    }

    #[test]
    fn node_rejects_wrong_parent() {
        // ⑤ parent 不匹配 ⇒ 拒绝；state/head 不变。
        let chain_id = 1001;
        let genesis_hash = [0xaa; 32];
        let max_gas = 1_000_000;
        let (kp, sender, receiver, store, genesis_root, registry) = test_env();
        let head = ChainHead::genesis(genesis_hash, genesis_root);
        let mut adapter =
            NodeBlockAdapter::new(store, registry, chain_id, genesis_hash, max_gas, 0, head);
        let root_before = adapter.store().state_root();
        let head_before = adapter.head().clone();

        // height 1 但 parent_hash 错误（期望 genesis_hash 0xaa，给 0x00）
        let tx = signed_tx(sender, receiver, 0, 100, kp.signing_key(), chain_id);
        let wrong_parent = ParentContext {
            parent_height: 0,
            parent_hash: [0x00; 32],
        };
        let expected_root = expected_state_root(adapter.store(), &tx, 1_000_000, 0, false, 0, 0);
        let block = make_valid_block(chain_id, 1, &wrong_parent, tx, expected_root, &kp);
        let wire = encode_block(&block).unwrap();

        let err = adapter.apply_block(&wire, kp.verifying_key()).unwrap_err();
        assert!(
            matches!(
                err,
                NodeBlockApplicationError::Pipeline(BlockPipelineError::Validation(_))
            ),
            "wrong parent must fail at ⑤ validation"
        );
        assert_eq!(adapter.store().state_root(), root_before, "state unchanged");
        assert_eq!(adapter.head(), &head_before, "head unchanged");
    }

    /// Failing backend fixture：put 计数 ≥ `fail_after` 后失败。
    /// **Clone 重置 put 计数** ⇒ ④ `calculate_state_root`（对 clone 只读重算）成功，
    /// ⑥ `commit_block`（真实 store）失败 ⇒ `apply_block` 内部 rollback，head 不变。
    struct FailAfterBackend {
        inner: MemoryBackend,
        fail_after: usize,
        puts: usize,
    }

    impl Clone for FailAfterBackend {
        fn clone(&self) -> Self {
            // 关键：clone（仅用于只读重算）重置失败预算 → ④ 成功、⑥ 真实提交失败
            Self {
                inner: self.inner.clone(),
                fail_after: self.fail_after,
                puts: 0,
            }
        }
    }

    impl StorageBackend for FailAfterBackend {
        type Snapshot = MemorySnapshot;

        fn get(&self, key: &TrieKey) -> Option<Vec<u8>> {
            self.inner.get(key)
        }

        fn put(&mut self, key: TrieKey, value: Vec<u8>) -> Result<(), StorageError> {
            if self.puts >= self.fail_after {
                return Err(StorageError::BackendFailure);
            }
            self.puts += 1;
            self.inner.put(key, value)
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
    fn node_storage_failure_preserves_head() {
        // ⑥ commit storage 失败 ⇒ rollback（state root 不变）+ head 不变。
        let chain_id = 1001;
        let genesis_hash = [0xaa; 32];
        let max_gas = 1_000_000;
        let kp = KeyPair::generate().unwrap();
        let sender = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        let receiver = addr([0xbb; 32]);
        let registry = MemoryKeyRegistry::with([(sender, *kp.verifying_key())]);

        // fail_after=2：genesis（1 put）后真实 store puts=1；
        // ④ 只读重算 clone puts 重置 0（2 put 全过）；⑥ 真实 commit 第 2 个 put 失败 → rollback。
        let backend = FailAfterBackend {
            inner: MemoryBackend::new(),
            fail_after: 2,
            puts: 0,
        };
        let mut store = StateStore::new(backend);
        store
            .apply(&[nova_runtime::AccountChange {
                address: sender,
                new_balance: 1_000_000,
                new_nonce: 0,
                created: true,
            }])
            .unwrap();
        let genesis_root = store.state_root();
        let head = ChainHead::genesis(genesis_hash, genesis_root);
        let mut adapter =
            NodeBlockAdapter::new(store, registry, chain_id, genesis_hash, max_gas, 0, head);
        let root_before = adapter.store().state_root();
        let head_before = adapter.head().clone();

        // 期望 root：用同 genesis 的 MemoryBackend 孪生计算（与 execution 语义一致）
        let mut twin = StateStore::new(MemoryBackend::new());
        twin.apply(&[nova_runtime::AccountChange {
            address: sender,
            new_balance: 1_000_000,
            new_nonce: 0,
            created: true,
        }])
        .unwrap();
        let tx = signed_tx(sender, receiver, 0, 100, kp.signing_key(), chain_id);
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: genesis_hash,
        };
        let expected_root = expected_state_root(&twin, &tx, 1_000_000, 0, false, 0, 0);
        let block = make_valid_block(chain_id, 1, &parent, tx, expected_root, &kp);
        let wire = encode_block(&block).unwrap();

        let err = adapter.apply_block(&wire, kp.verifying_key()).unwrap_err();
        assert!(
            matches!(
                err,
                NodeBlockApplicationError::Pipeline(BlockPipelineError::Storage(
                    StorageError::BackendFailure
                ))
            ),
            "commit storage failure must surface as Storage category"
        );
        assert_eq!(
            adapter.store().state_root(),
            root_before,
            "rollback: state root unchanged"
        );
        assert_eq!(adapter.head(), &head_before, "head unchanged");
    }
}
