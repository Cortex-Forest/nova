//! 区块级执行结果（STEP 8D — ADR-0029 D-1）与 Block 协议类型（P7-2 — ADR-0042）。
//!
//! - [`BlockExecutionResult`]：`execute_block`（nova-execution）的产物；**不含** final state root
//!   （由 nova-storage `apply_block` 计算——execution 无 SMT，ADR-0029 D-1/D-2 边界）。
//! - [`BlockHeader`] / [`BlockBody`] / [`Block`] + canonical `encode`/`decode` + [`block_hash`]
//!   （P7-2，ADR-0042 FROZEN）：单父 V0.1；`block_hash = SHA-256(canonical_header ‖ canonical_body)`
//!   （**不含 signature / 自身**）；decode = structure only（semantic validation 归 P7-3）。

use crate::state::StateTransition;
use nova_crypto::hash::protocol_hash;
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

/// Block（ADR-0042；`block_hash` 只覆盖 header+body，不含 signature——signature 归 P7-3 验证层）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
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

/// Canonical Block = `canonical_header ‖ canonical_body`（ADR-0042 §7；不含 signature）。
pub fn encode_block(b: &Block) -> Result<Vec<u8>, BlockCodecError> {
    let h = encode_block_header(&b.header);
    let body = encode_block_body(&b.body)?;
    let mut out = Vec::with_capacity(h.len() + body.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode Block（structure only；分割 header + body）。
pub fn decode_block(bytes: &[u8]) -> Result<Block, BlockCodecError> {
    const MIN_HEADER: usize = 154;
    if bytes.len() < MIN_HEADER {
        return Err(BlockCodecError::InvalidLength {
            expected: MIN_HEADER,
            actual: bytes.len(),
        });
    }
    let header_len = match bytes[49] {
        0 => MIN_HEADER,
        1 => 186,
        t => return Err(BlockCodecError::InvalidOptionTag(t)),
    };
    if bytes.len() < header_len {
        return Err(BlockCodecError::InvalidLength {
            expected: header_len,
            actual: bytes.len(),
        });
    }
    let header = decode_block_header(&bytes[..header_len])?;
    let body = decode_block_body(&bytes[header_len..])?;
    Ok(Block { header, body })
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

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
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
        // Block 无 signature 字段（P7-2）；block_hash 只覆盖 header+body。
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
}
