//! 区块级执行结果（STEP 8D — ADR-0029 D-1）与 Block 协议类型（P7-2 — ADR-0042）。
//!
//! - [`BlockExecutionResult`]：`execute_block`（nova-execution）的产物；**不含** final state root
//!   （由 nova-storage `apply_block` 计算——execution 无 SMT，ADR-0029 D-1/D-2 边界）。
//! - [`BlockHeader`] / [`BlockBody`] / [`Block`] + canonical `encode`/`decode` + [`block_hash`]
//!   （P7-2，ADR-0042 FROZEN + Signature Representation Amendment）：单父 V0.1；
//!   `Block = header + body + proposer_signature(64B)`；
//!   `block_hash = SHA-256(canonical_header ‖ canonical_body)`（**不含 signature / 自身**）；
//!   decode = structure only（semantic validation 归 P7-3）。

use crate::state::StateTransition;
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::hash::protocol_hash;
use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};
use nova_crypto::transaction::{TransactionV1, canonical_transaction_bytes, decode_transaction};

/// 区块执行结果（ADR-0029 D-1；协议类型）。
///
/// - `tx_transitions` 只含**成功** tx（失败 tx 被 skip，ADR-0029 D-3 Model A），顺序 = block 内顺序。
/// - `gas_used_total` = 成功 tx 的 `StateTransition::gas_used` 累计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionResult {
    /// 成功 tx 的状态转换（顺序 = block 内顺序）。
    pub tx_transitions: Vec<StateTransition>,
    /// 全部成功 tx 累计 gas。
    pub gas_used_total: u64,
}

/// Block 协议版本（ADR-0042；V0.1 = 0x01；未知 version ⇒ 拒）。
pub const BLOCK_VERSION: u8 = 0x01;

/// Block 结构错误（P7-2，ADR-0042 §10 rejection；**结构级，非 semantic**——验证归 P7-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCodecError {
    /// 长度不符（截断 / 超长 / trailing bytes）。
    InvalidLength { expected: usize, actual: usize },
    /// 未知 version（V0.1 = 0x01）。
    UnknownVersion(u8),
    /// `finality_reference` Option tag 非法（非 0x00/0x01）。
    InvalidOptionTag(u8),
    /// 交易 canonical 编码 / 解码失败（crypto 域）。
    TxCodec,
}

impl core::fmt::Display for BlockCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid block length: expected {expected}, got {actual}")
            }
            Self::UnknownVersion(v) => write!(f, "unknown block version: {v:#04x}"),
            Self::InvalidOptionTag(t) => write!(f, "invalid option tag: {t:#04x}"),
            Self::TxCodec => write!(f, "transaction codec error"),
        }
    }
}

impl std::error::Error for BlockCodecError {}

/// Block 语义验证错误（P7-3；**semantic 级**，区别于 [`BlockCodecError`] 结构级）。
///
/// - D5 裁决：新增错误仅把 ADR-0042 §10 rejection 分类编码，**不改变协议语义**；
///   ADR impact review 通过 ⇒ 不修改 ADR-0042。
/// - ④ state_root 复用 storage `BlockStateRootError`（8D），不在此重复。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockValidationError {
    /// ② proposer 签名验证失败（verify_strict / 畸形签名）。
    InvalidProposerSignature,
    /// ③ 重算 transaction_root ≠ header.transaction_root。
    TransactionRootMismatch,
    /// ⑤ `block.header.height != parent_height + 1`。
    InvalidHeightChain,
    /// ⑤ `block.header.parent_hash != parent_hash`。
    ParentHashMismatch,
}

impl core::fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProposerSignature => write!(f, "invalid proposer signature"),
            Self::TransactionRootMismatch => write!(f, "transaction root mismatch"),
            Self::InvalidHeightChain => {
                write!(f, "invalid height chain (height != parent_height + 1)")
            }
            Self::ParentHashMismatch => write!(f, "parent hash mismatch"),
        }
    }
}

impl std::error::Error for BlockValidationError {}

/// BlockHeader（ADR-0042 §4；字段顺序 = ADR-0009 §3 签名字段顺序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// 协议版本（V0.1 = 0x01）。
    pub version: u8,
    /// 链 ID（genesis 固定值，LE）。
    pub chain_id: u64,
    /// 区块高度（LE；`parent.height < height`）。
    pub height: u64,
    /// 父区块 block_hash（单父；genesis 父 = 零哈希）。
    pub parent_hash: [u8; 32],
    /// 前序 finality 引用（指向过去 finalized block_hash；无循环）。
    pub finality_reference: Option<[u8; 32]>,
    /// 交易集合承诺。
    pub transaction_root: [u8; 32],
    /// 执行结果承诺（SMT root，8D）。
    pub state_root: [u8; 32],
    /// 当前 validator set 承诺。
    pub validator_set_hash: [u8; 32],
    /// 提议时间（LE；metadata，不进 consensus transition）。
    pub timestamp: u64,
}

/// BlockBody（ADR-0042 §5；交易列表，V0.1 无收据 root）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBody {
    pub txs: Vec<TransactionV1>,
}

/// Block（ADR-0042 Option B Amendment；`block_hash` 只覆盖 header+body，不含 `proposer_signature`——
/// signature 承载于 Block 但 ∉ hash input；signature verification 归 P7-3 验证层）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    /// proposer 签名（Ed25519，恰好 64B；Option B 承载字段）。
    /// 冻结：`∉ block_hash input` / `∉ canonical_header` / `∉ canonical_body`；wire 位于 body 之后。
    /// decode ≠ semantic：本字段只做 representation，verification 归 P7-3。
    pub proposer_signature: [u8; 64],
}

/// Canonical BlockHeader（ADR-0042 §7）：
/// `version(1) ‖ chain_id(8LE) ‖ height(8LE) ‖ parent_hash(32) ‖ finality_ref(1 tag [+32])
///  ‖ transaction_root(32) ‖ state_root(32) ‖ validator_set_hash(32) ‖ timestamp(8LE)`。
/// 定长：None = 154B；Some = 186B。
pub fn encode_block_header(h: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(186);
    out.push(h.version);
    out.extend_from_slice(&h.chain_id.to_le_bytes());
    out.extend_from_slice(&h.height.to_le_bytes());
    out.extend_from_slice(&h.parent_hash);
    match h.finality_reference {
        Some(r) => {
            out.push(1);
            out.extend_from_slice(&r);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&h.transaction_root);
    out.extend_from_slice(&h.state_root);
    out.extend_from_slice(&h.validator_set_hash);
    out.extend_from_slice(&h.timestamp.to_le_bytes());
    out
}

/// Decode BlockHeader（structure only；长度严格 / version / tag 校验；拒 trailing）。
pub fn decode_block_header(bytes: &[u8]) -> Result<BlockHeader, BlockCodecError> {
    const MIN_LEN: usize = 154;
    const FULL_LEN: usize = 186;
    if bytes.len() < MIN_LEN {
        return Err(BlockCodecError::InvalidLength {
            expected: MIN_LEN,
            actual: bytes.len(),
        });
    }
    let version = bytes[0];
    if version != BLOCK_VERSION {
        return Err(BlockCodecError::UnknownVersion(version));
    }
    let chain_id = u64::from_le_bytes(bytes[1..9].try_into().expect("len checked"));
    let height = u64::from_le_bytes(bytes[9..17].try_into().expect("len checked"));
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&bytes[17..49]);
    let tag = bytes[49];
    let (finality_reference, tx_off, st_off, vs_off, ts_off) = match tag {
        0 => (None, 50, 82, 114, 146),
        1 => (
            {
                let mut r = [0u8; 32];
                r.copy_from_slice(&bytes[50..82]);
                Some(r)
            },
            82,
            114,
            146,
            178,
        ),
        _ => return Err(BlockCodecError::InvalidOptionTag(tag)),
    };
    let expected = if tag == 0 { MIN_LEN } else { FULL_LEN };
    if bytes.len() != expected {
        return Err(BlockCodecError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    let mut transaction_root = [0u8; 32];
    transaction_root.copy_from_slice(&bytes[tx_off..tx_off + 32]);
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&bytes[st_off..st_off + 32]);
    let mut validator_set_hash = [0u8; 32];
    validator_set_hash.copy_from_slice(&bytes[vs_off..vs_off + 32]);
    let timestamp = u64::from_le_bytes(bytes[ts_off..ts_off + 8].try_into().expect("len checked"));
    Ok(BlockHeader {
        version,
        chain_id,
        height,
        parent_hash,
        finality_reference,
        transaction_root,
        state_root,
        validator_set_hash,
        timestamp,
    })
}

/// Canonical BlockBody（ADR-0042 §7）：`count(4LE) ‖ [ len(4LE) ‖ canonical_tx ]*`。
pub fn encode_block_body(b: &BlockBody) -> Result<Vec<u8>, BlockCodecError> {
    let mut out = Vec::new();
    out.extend_from_slice(&(b.txs.len() as u32).to_le_bytes());
    for tx in &b.txs {
        let bytes = canonical_transaction_bytes(tx).map_err(|_| BlockCodecError::TxCodec)?;
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Decode BlockBody（structure only；长度严格；无 trailing）。
pub fn decode_block_body(bytes: &[u8]) -> Result<BlockBody, BlockCodecError> {
    if bytes.len() < 4 {
        return Err(BlockCodecError::InvalidLength {
            expected: 4,
            actual: bytes.len(),
        });
    }
    let count = u32::from_le_bytes(bytes[0..4].try_into().expect("len checked")) as usize;
    let mut off = 4usize;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.len() < off + 4 {
            return Err(BlockCodecError::InvalidLength {
                expected: off + 4,
                actual: bytes.len(),
            });
        }
        let len = u32::from_le_bytes(bytes[off..off + 4].try_into().expect("len checked")) as usize;
        off += 4;
        if bytes.len() < off + len {
            return Err(BlockCodecError::InvalidLength {
                expected: off + len,
                actual: bytes.len(),
            });
        }
        let tx =
            decode_transaction(&bytes[off..off + len]).map_err(|_| BlockCodecError::TxCodec)?;
        txs.push(tx);
        off += len;
    }
    if off != bytes.len() {
        return Err(BlockCodecError::InvalidLength {
            expected: off,
            actual: bytes.len(),
        });
    }
    Ok(BlockBody { txs })
}

/// Canonical Block wire（ADR-0042 §7 Option B）：
/// `canonical_header ‖ canonical_body ‖ proposer_signature(64B)`（signature 固定 64B，无长度前缀 / 无 tag）。
pub fn encode_block(b: &Block) -> Result<Vec<u8>, BlockCodecError> {
    let h = encode_block_header(&b.header);
    let body = encode_block_body(&b.body)?;
    let mut out = Vec::with_capacity(h.len() + body.len() + 64);
    out.extend_from_slice(&h);
    out.extend_from_slice(&body);
    out.extend_from_slice(&b.proposer_signature);
    Ok(out)
}

/// Decode Block（structure only；header + body + 恰好 64B signature；拒 missing/truncated/oversized/trailing）。
pub fn decode_block(bytes: &[u8]) -> Result<Block, BlockCodecError> {
    const MIN_HEADER: usize = 154;
    const SIGNATURE_LEN: usize = 64;
    // 最小：header(154) + signature(64)；body 可为空（至少 4B count）。
    if bytes.len() < MIN_HEADER + SIGNATURE_LEN {
        return Err(BlockCodecError::InvalidLength {
            expected: MIN_HEADER + SIGNATURE_LEN,
            actual: bytes.len(),
        });
    }
    let header_len = match bytes[49] {
        0 => MIN_HEADER,
        1 => 186,
        t => return Err(BlockCodecError::InvalidOptionTag(t)),
    };
    // 即使 tag=1（header 186B），也需为 signature 留足 64B。
    if bytes.len() < header_len + SIGNATURE_LEN {
        return Err(BlockCodecError::InvalidLength {
            expected: header_len + SIGNATURE_LEN,
            actual: bytes.len(),
        });
    }
    let header = decode_block_header(&bytes[..header_len])?;
    // signature 固定占尾部 64B；body = [header_len, len-64)。body 域内 trailing ⇒ 拒绝。
    let body_end = bytes.len() - SIGNATURE_LEN;
    let body = decode_block_body(&bytes[header_len..body_end])?;
    let mut proposer_signature = [0u8; SIGNATURE_LEN];
    proposer_signature.copy_from_slice(&bytes[body_end..]);
    Ok(Block {
        header,
        body,
        proposer_signature,
    })
}

/// `block_hash = SHA-256( canonical_header ‖ canonical_body )`（ADR-0042 §6；**不含 signature / 自身**）。
pub fn block_hash(b: &Block) -> Result<[u8; 32], BlockCodecError> {
    let h = encode_block_header(&b.header);
    let body = encode_block_body(&b.body)?;
    let mut input = Vec::with_capacity(h.len() + body.len());
    input.extend_from_slice(&h);
    input.extend_from_slice(&body);
    Ok(protocol_hash(&input))
}

/// 交易集合承诺 merkle root（P7-3，D4 裁决冻结；ADR-0042 §11 承诺完整性）。
///
/// 域字节（与 state 域 0x00/0x01/0x02、crypto DomainId 0x01~0x06 均分离）：
/// `TX_EMPTY = 0x20` / `TX_LEAF = 0x21` / `TX_BRANCH = 0x22`。
///
/// 规则（冻结，deterministic，无 alternate）：
/// - 空集合 ⇒ `protocol_hash(0x20)`（TX_EMPTY_ROOT 常数）。
/// - 非空：第 0 层 = `leaf(tx_i)`（block 内 tx 顺序）；自底向上两两配对；
///   层内 `len == 1` ⇒ 该节点即 root（不再配对）；奇数最后一个节点复制自身配对。
pub fn compute_transaction_root(body: &BlockBody) -> [u8; 32] {
    const TX_EMPTY: u8 = 0x20;
    const TX_LEAF: u8 = 0x21;
    const TX_BRANCH: u8 = 0x22;

    if body.txs.is_empty() {
        return protocol_hash(&[TX_EMPTY]);
    }

    let mut layer: Vec<[u8; 32]> = body
        .txs
        .iter()
        .map(|tx| {
            let canonical = canonical_transaction_bytes(tx)
                .expect("canonical transaction encoding cannot fail for a decoded TransactionV1");
            let mut input = Vec::with_capacity(1 + canonical.len());
            input.push(TX_LEAF);
            input.extend_from_slice(&canonical);
            protocol_hash(&input)
        })
        .collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left // 奇数：复制自身
            };
            let mut input = Vec::with_capacity(1 + 64);
            input.push(TX_BRANCH);
            input.extend_from_slice(&left);
            input.extend_from_slice(&right);
            next.push(protocol_hash(&input));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// ③ transaction_root 验证（P7-3，D4 裁决；ADR-0042 §9 步骤③）。
///
/// 重算 `compute_transaction_root(body)` 并与 `header.transaction_root` 比对；不符 ⇒
/// [`BlockValidationError::TransactionRootMismatch`]。
pub fn verify_transaction_root(
    expected: &[u8; 32],
    body: &BlockBody,
) -> Result<(), BlockValidationError> {
    if *expected == compute_transaction_root(body) {
        Ok(())
    } else {
        Err(BlockValidationError::TransactionRootMismatch)
    }
}

/// ② proposer signature 验证（P7-3，D2/D3 裁决；ADR-0042 §8 + ADR-0009 §3）。
///
/// - **纯密码学验证**：只证 `signature valid for supplied proposer identity/key`；
///   **不查询 ValidatorSet / 不做 membership / authority / eligibility**（A11 DEFERRED）。
/// - payload = `canonical_header`（9 header 承诺字段）；`DomainId::Block = 0x03` 域分离；
///   `verify_strict`。
/// - 不签：block_hash / body / signature 自身。
pub fn verify_block_signature(
    block: &Block,
    proposer_vk: &VerifyingKey,
    chain_id: u64,
) -> Result<(), BlockValidationError> {
    let payload = encode_block_header(&block.header);
    let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, chain_id, &payload)
        .map_err(|_| BlockValidationError::InvalidProposerSignature)?;
    let msg = hash_signing_message(&signed);
    let sig = Signature::from_bytes(&block.proposer_signature)
        .map_err(|_| BlockValidationError::InvalidProposerSignature)?;
    verify_message_hash(proposer_vk, &msg, &sig)
        .map_err(|_| BlockValidationError::InvalidProposerSignature)
}

/// ⑤ 父块上下文（P7-3，D6 裁决；外部提供，Block 不自含；单父 V0.1，无多父）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentContext {
    /// 父块高度。
    pub parent_height: u64,
    /// 父块 block_hash。
    pub parent_hash: [u8; 32],
}

/// ⑤ height/parent 链式验证（P7-3，D6 裁决；ADR-0042 §9/§10）。
///
/// 同时验证（缺一不可）：
/// - `block.header.height == parent_height + 1`（height 链式）⇒ 否则
///   [`BlockValidationError::InvalidHeightChain`]；
/// - `block.header.parent_hash == parent_hash`（parent_hash 正确指向预期父块）⇒ 否则
///   [`BlockValidationError::ParentHashMismatch`]。
///
/// 仅检查 height 而不检查 parent_hash，会允许“高度连续但父指向错误”的块。
pub fn verify_height_parent(
    block: &Block,
    parent: &ParentContext,
) -> Result<(), BlockValidationError> {
    let expected_height = parent
        .parent_height
        .checked_add(1)
        .ok_or(BlockValidationError::InvalidHeightChain)?;
    if block.header.height != expected_height {
        return Err(BlockValidationError::InvalidHeightChain);
    }
    if block.header.parent_hash != parent.parent_hash {
        return Err(BlockValidationError::ParentHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;
    use nova_crypto::transaction::TransactionType;

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn mk_tx(nonce: u64) -> TransactionV1 {
        TransactionV1 {
            version: 1,
            chain_id: 1001,
            nonce,
            sender: addr([0x01; 32]),
            receiver: addr([0x02; 32]),
            amount: 100,
            gas_limit: 21_000,
            gas_price: 1,
            transaction_type: TransactionType::Transfer,
            payload: Vec::new(),
            expiration: 1000,
            signature: [0u8; 64],
        }
    }

    fn mk_header(finality: Option<[u8; 32]>) -> BlockHeader {
        BlockHeader {
            version: BLOCK_VERSION,
            chain_id: 1001,
            height: 1,
            parent_hash: [0xaa; 32],
            finality_reference: finality,
            transaction_root: [0x11; 32],
            state_root: [0x22; 32],
            validator_set_hash: [0x33; 32],
            timestamp: 0,
        }
    }

    fn mk_block(txs: Vec<TransactionV1>) -> Block {
        Block {
            header: mk_header(Some([0xbb; 32])),
            body: BlockBody { txs },
            proposer_signature: [0xcc; 64],
        }
    }

    #[test]
    fn header_roundtrip_none_and_some() {
        for f in [None, Some([0xbb; 32])] {
            let h = mk_header(f);
            assert_eq!(decode_block_header(&encode_block_header(&h)), Ok(h));
        }
    }

    #[test]
    fn body_roundtrip_empty_and_tx() {
        let empty = BlockBody { txs: vec![] };
        assert_eq!(
            decode_block_body(&encode_block_body(&empty).unwrap()),
            Ok(empty)
        );
        let one = BlockBody {
            txs: vec![mk_tx(0)],
        };
        assert_eq!(
            decode_block_body(&encode_block_body(&one).unwrap()),
            Ok(one)
        );
    }

    #[test]
    fn block_roundtrip() {
        let b = mk_block(vec![mk_tx(0), mk_tx(1)]);
        let bytes = encode_block(&b).unwrap();
        assert_eq!(decode_block(&bytes), Ok(b));
    }

    #[test]
    fn deterministic_encoding_and_hash() {
        let b = mk_block(vec![mk_tx(0)]);
        let e1 = encode_block(&b).unwrap();
        let e2 = encode_block(&b).unwrap();
        assert_eq!(e1, e2, "canonical uniqueness");
        let h1 = block_hash(&b).unwrap();
        let h2 = block_hash(&b).unwrap();
        assert_eq!(h1, h2, "deterministic block_hash");
    }

    #[test]
    fn header_field_order() {
        let h = mk_header(Some([0xbb; 32]));
        let bytes = encode_block_header(&h);
        assert_eq!(bytes[0], BLOCK_VERSION);
        assert_eq!(&bytes[1..9], &1001u64.to_le_bytes());
        assert_eq!(&bytes[9..17], &1u64.to_le_bytes());
        assert_eq!(&bytes[17..49], &[0xaa; 32]);
        assert_eq!(bytes[49], 1);
        assert_eq!(&bytes[50..82], &[0xbb; 32]);
        assert_eq!(&bytes[82..114], &[0x11; 32]);
        assert_eq!(&bytes[114..146], &[0x22; 32]);
        assert_eq!(&bytes[146..178], &[0x33; 32]);
        assert_eq!(&bytes[178..186], &0u64.to_le_bytes());
        assert_eq!(bytes.len(), 186);
    }

    #[test]
    fn decode_rejects_malformed() {
        // 截断
        let b = mk_block(vec![mk_tx(0)]);
        let bytes = encode_block(&b).unwrap();
        assert!(matches!(
            decode_block(&bytes[..bytes.len() - 1]),
            Err(BlockCodecError::InvalidLength { .. })
        ));
        // trailing bytes（header 后额外 + body 多余）
        let h = encode_block_header(&mk_header(None));
        assert!(matches!(
            decode_block_header(&[h.as_slice(), &[0u8]].concat()),
            Err(BlockCodecError::InvalidLength { .. })
        ));
        // 空
        assert!(matches!(
            decode_block(&[]),
            Err(BlockCodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut h = mk_header(None);
        h.version = 0x02;
        let bytes = encode_block_header(&h);
        assert_eq!(
            decode_block_header(&bytes),
            Err(BlockCodecError::UnknownVersion(0x02))
        );
    }

    #[test]
    fn decode_rejects_invalid_option_tag() {
        let mut h = mk_header(None);
        h.finality_reference = None;
        let mut bytes = encode_block_header(&h);
        bytes[49] = 0x02;
        assert_eq!(
            decode_block_header(&bytes),
            Err(BlockCodecError::InvalidOptionTag(0x02))
        );
    }

    #[test]
    fn modified_field_changes_hash() {
        let base = mk_block(vec![mk_tx(0)]);
        let h_base = block_hash(&base).unwrap();
        // 修改 header 字段（state_root）⇒ hash 变化
        let mut h = base.clone();
        h.header.state_root[0] ^= 0xff;
        assert_ne!(block_hash(&h).unwrap(), h_base);
        // 修改 body（tx amount）⇒ hash 变化
        let mut h2 = base.clone();
        h2.body.txs[0].amount += 1;
        assert_ne!(block_hash(&h2).unwrap(), h_base);
    }

    #[test]
    fn block_hash_covers_header_and_body_not_signature() {
        // block_hash 只覆盖 header+body（Option B：signature ∉ hash input）。
        let b = mk_block(vec![mk_tx(0)]);
        let hash = block_hash(&b).unwrap();
        assert_ne!(hash, [0u8; 32]);
        // header 定长输入长度 = 154/186 + body
        let h = encode_block_header(&b.header);
        let body = encode_block_body(&b.body).unwrap();
        assert_eq!(
            hash,
            protocol_hash(&[h.as_slice(), body.as_slice()].concat())
        );
    }

    #[test]
    fn signature_roundtrip_and_exact_64b() {
        // 1. valid signature roundtrip；2. signature 恰好 64B。
        let b = mk_block(vec![mk_tx(0), mk_tx(1)]);
        let bytes = encode_block(&b).unwrap();
        // wire 尾部 64B == proposer_signature，位于 body 之后、无前缀 / 无 tag。
        assert_eq!(&bytes[bytes.len() - 64..], &b.proposer_signature);
        let dec = decode_block(&bytes).unwrap();
        assert_eq!(dec.proposer_signature, b.proposer_signature);
        assert_eq!(dec.header, b.header);
        assert_eq!(dec.body, b.body);
    }

    #[test]
    fn signature_mutation_does_not_change_hash() {
        // 强制安全回归：S1 != S2 且 block_hash(A) == block_hash(B)。
        let a = mk_block(vec![mk_tx(0)]);
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature[0] ^= 0xff;
        assert_ne!(a.proposer_signature, b.proposer_signature, "S1 != S2");
        assert_eq!(
            block_hash(&a).unwrap(),
            block_hash(&b).unwrap(),
            "signature mutation ⇒ block_hash unchanged (hash exclusion)"
        );
    }

    #[test]
    fn decode_rejects_missing_signature() {
        // header + body，无 signature ⇒ REJECT。
        let b = mk_block(vec![mk_tx(0)]);
        let bytes = encode_block(&b).unwrap();
        let without_sig = &bytes[..bytes.len() - 64];
        assert!(matches!(
            decode_block(without_sig),
            Err(BlockCodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_truncated_signature() {
        // 63B signature ⇒ REJECT。
        let b = mk_block(vec![mk_tx(0)]);
        let bytes = encode_block(&b).unwrap();
        assert!(matches!(
            decode_block(&bytes[..bytes.len() - 1]),
            Err(BlockCodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_oversized_signature() {
        // 65B signature ⇒ REJECT（body 域多出 1B trailing ⇒ decode_block_body 拒）。
        let b = mk_block(vec![mk_tx(0)]);
        let bytes = encode_block(&b).unwrap();
        let mut oversized = bytes.clone();
        oversized.extend_from_slice(&[0x00]); // 使 signature 域 = 65B
        assert!(matches!(
            decode_block(&oversized),
            Err(BlockCodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // valid block + extra bytes ⇒ REJECT。
        let b = mk_block(vec![mk_tx(0)]);
        let bytes = encode_block(&b).unwrap();
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&[0xde, 0xad]);
        assert!(matches!(
            decode_block(&trailing),
            Err(BlockCodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn canonical_encoding_deterministic_with_signature() {
        // same Block → encode twice → byte-for-byte identical；decode(encode(block)) == block。
        let b = mk_block(vec![mk_tx(0), mk_tx(7)]);
        let e1 = encode_block(&b).unwrap();
        let e2 = encode_block(&b).unwrap();
        assert_eq!(e1, e2, "canonical encoding = deterministic");
        assert_eq!(decode_block(&e1), Ok(b), "decode(encode(block)) == block");
    }

    // ── P7-3 ③ transaction_root merkle 规则（D4 冻结） ──

    fn tx_leaf_hash(tx: &TransactionV1) -> [u8; 32] {
        let canonical = canonical_transaction_bytes(tx).expect("canonical tx");
        let mut input = Vec::with_capacity(1 + canonical.len());
        input.push(0x21); // TX_LEAF
        input.extend_from_slice(&canonical);
        protocol_hash(&input)
    }

    fn tx_branch_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(1 + 64);
        input.push(0x22); // TX_BRANCH
        input.extend_from_slice(l);
        input.extend_from_slice(r);
        protocol_hash(&input)
    }

    #[test]
    fn transaction_root_empty_is_constant() {
        // 空集合 ⇒ protocol_hash(0x20)（TX_EMPTY_ROOT 常数）。
        let empty = BlockBody { txs: vec![] };
        let root = compute_transaction_root(&empty);
        assert_eq!(root, protocol_hash(&[0x20]));
        assert_eq!(root, compute_transaction_root(&empty), "deterministic");
    }

    #[test]
    fn transaction_root_single_is_leaf() {
        // 单元素 ⇒ root = leaf（不冗余配对）。
        let tx = mk_tx(0);
        let body = BlockBody {
            txs: vec![tx.clone()],
        };
        assert_eq!(compute_transaction_root(&body), tx_leaf_hash(&tx));
    }

    #[test]
    fn transaction_root_pair_and_odd_rules() {
        let t0 = mk_tx(0);
        let t1 = mk_tx(1);
        let t2 = mk_tx(2);
        let t3 = mk_tx(3);
        let l0 = tx_leaf_hash(&t0);
        let l1 = tx_leaf_hash(&t1);
        let l2 = tx_leaf_hash(&t2);
        let l3 = tx_leaf_hash(&t3);

        // 2 txs：root = branch(l0, l1)
        let b2 = BlockBody {
            txs: vec![t0.clone(), t1.clone()],
        };
        assert_eq!(compute_transaction_root(&b2), tx_branch_hash(&l0, &l1));

        // 3 txs（奇数复制自身）：root = branch( branch(l0,l1), branch(l2,l2) )
        let b3 = BlockBody {
            txs: vec![t0.clone(), t1.clone(), t2.clone()],
        };
        let expected3 = tx_branch_hash(&tx_branch_hash(&l0, &l1), &tx_branch_hash(&l2, &l2));
        assert_eq!(compute_transaction_root(&b3), expected3);

        // 4 txs：root = branch( branch(l0,l1), branch(l2,l3) )
        let b4 = BlockBody {
            txs: vec![t0, t1, t2, t3],
        };
        let expected4 = tx_branch_hash(&tx_branch_hash(&l0, &l1), &tx_branch_hash(&l2, &l3));
        assert_eq!(compute_transaction_root(&b4), expected4);
    }

    #[test]
    fn transaction_root_order_sensitive() {
        // tx 顺序改变 ⇒ root 变（顺序即 block body 顺序）。
        let a = BlockBody {
            txs: vec![mk_tx(0), mk_tx(1)],
        };
        let b = BlockBody {
            txs: vec![mk_tx(1), mk_tx(0)],
        };
        assert_ne!(compute_transaction_root(&a), compute_transaction_root(&b));
    }

    #[test]
    fn verify_transaction_root_ok_with_matching_header() {
        // ③ ok：header.transaction_root 与重算一致。
        let body = BlockBody {
            txs: vec![mk_tx(0), mk_tx(1)],
        };
        let mut h = mk_header(Some([0xbb; 32]));
        h.transaction_root = compute_transaction_root(&body);
        let b = Block {
            header: h,
            body,
            proposer_signature: [0xcc; 64],
        };
        assert_eq!(
            verify_transaction_root(&b.header.transaction_root, &b.body),
            Ok(())
        );
    }

    #[test]
    fn verify_transaction_root_mismatch() {
        // ③ 不符 ⇒ TransactionRootMismatch。
        let body = BlockBody {
            txs: vec![mk_tx(0)],
        };
        assert_eq!(
            verify_transaction_root(&[0u8; 32], &body),
            Err(BlockValidationError::TransactionRootMismatch)
        );
    }

    // ── P7-3 ② proposer signature（D2/D3 冻结） ──

    fn sign_block_header(
        signing: &nova_crypto::signature::SigningKey,
        header: &BlockHeader,
        chain_id: u64,
        domain: DomainId,
    ) -> [u8; 64] {
        let payload = encode_block_header(header);
        let signed = build_signed_bytes(AlgorithmId::Ed25519, domain, chain_id, &payload).unwrap();
        let msg = hash_signing_message(&signed);
        sign_message_hash(signing, &msg).to_bytes()
    }

    #[test]
    fn block_signature_verify_ok() {
        // ② ok：真实 Ed25519 签名（DomainId::Block）验证通过；纯签名，无 membership。
        let kp = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature =
            sign_block_header(kp.signing_key(), &b.header, 1001, DomainId::Block);
        assert_eq!(verify_block_signature(&b, kp.verifying_key(), 1001), Ok(()));
    }

    #[test]
    fn block_signature_rejects_tampered_header() {
        // ② 篡改 header（签名后）⇒ 签名失效。
        let kp = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature =
            sign_block_header(kp.signing_key(), &b.header, 1001, DomainId::Block);
        b.header.state_root[0] ^= 0xff;
        assert_eq!(
            verify_block_signature(&b, kp.verifying_key(), 1001),
            Err(BlockValidationError::InvalidProposerSignature)
        );
    }

    #[test]
    fn block_signature_rejects_wrong_proposer_key() {
        // ② 错误 proposer 公钥 ⇒ 失败。
        let kp = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature =
            sign_block_header(kp.signing_key(), &b.header, 1001, DomainId::Block);
        assert_eq!(
            verify_block_signature(&b, other.verifying_key(), 1001),
            Err(BlockValidationError::InvalidProposerSignature)
        );
    }

    #[test]
    fn block_signature_rejects_wrong_chain_id() {
        // ② 错误 chain_id ⇒ 域分离失败。
        let kp = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature =
            sign_block_header(kp.signing_key(), &b.header, 1001, DomainId::Block);
        assert_eq!(
            verify_block_signature(&b, kp.verifying_key(), 999),
            Err(BlockValidationError::InvalidProposerSignature)
        );
    }

    #[test]
    fn block_signature_rejects_wrong_domain() {
        // ② 错误 domain（0x02 ValidatorVote 而非 0x03 Block）⇒ 失败。
        let kp = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature =
            sign_block_header(kp.signing_key(), &b.header, 1001, DomainId::ValidatorVote);
        assert_eq!(
            verify_block_signature(&b, kp.verifying_key(), 1001),
            Err(BlockValidationError::InvalidProposerSignature)
        );
    }

    #[test]
    fn block_signature_rejects_invalid_signature_bytes() {
        // ② 无效签名字节（全零，64B 合法长度但 verify_strict 失败）⇒ 失败。
        let kp = KeyPair::generate().unwrap();
        let mut b = mk_block(vec![mk_tx(0)]);
        b.proposer_signature = [0u8; 64];
        assert_eq!(
            verify_block_signature(&b, kp.verifying_key(), 1001),
            Err(BlockValidationError::InvalidProposerSignature)
        );
    }

    // ── P7-3 ⑤ height/parent（D6 冻结） ──

    #[test]
    fn height_parent_verify_ok() {
        // ⑤ ok：height == parent_height + 1 且 parent_hash 匹配（mk_block: height=1, parent=[0xaa;32]）。
        let b = mk_block(vec![]);
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0xaa; 32],
        };
        assert_eq!(verify_height_parent(&b, &parent), Ok(()));
    }

    #[test]
    fn height_parent_rejects_height_not_continuous() {
        // ⑤ height 不连续 ⇒ InvalidHeightChain。
        let b = mk_block(vec![]);
        let parent = ParentContext {
            parent_height: 2,
            parent_hash: [0xaa; 32],
        };
        assert_eq!(
            verify_height_parent(&b, &parent),
            Err(BlockValidationError::InvalidHeightChain)
        );
    }

    #[test]
    fn height_parent_rejects_parent_hash_mismatch() {
        // ⑤ parent_hash 不匹配 ⇒ ParentHashMismatch（证明“只查 height 漏 hash”被拒）。
        let b = mk_block(vec![]);
        let parent = ParentContext {
            parent_height: 0,
            parent_hash: [0x00; 32],
        };
        assert_eq!(
            verify_height_parent(&b, &parent),
            Err(BlockValidationError::ParentHashMismatch)
        );
    }

    #[test]
    fn height_parent_rejects_parent_height_overflow() {
        // ⑤ parent_height = u64::MAX ⇒ checked_add 溢出 ⇒ InvalidHeightChain。
        let b = mk_block(vec![]);
        let parent = ParentContext {
            parent_height: u64::MAX,
            parent_hash: [0xaa; 32],
        };
        assert_eq!(
            verify_height_parent(&b, &parent),
            Err(BlockValidationError::InvalidHeightChain)
        );
    }
}
