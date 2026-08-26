//! Nova Chain 交易 Canonical Serialization + Signature Integration（STEP 7C/7D）。
//!
//! 严格依据冻结规范：**ADR-0019**（Transaction Schema V1）、**ADR-0020**（TransactionType
//! Registry）、`crypto-serialization-v1.md` §13、ADR-0005/0012（signed_bytes）、ADR-0009（签名覆盖）。
//!
//! # Pipeline
//! ```text
//! TransactionV1
//!   → canonical_tx_payload（不含 signature）
//!   → tx_signed_bytes（algorithm ‖ domain(0x01 Transaction) ‖ chain_id ‖ len ‖ payload）
//!   → tx_message_hash（SHA-256 → SigningMessageHash）
//!   → Ed25519 sign / verify（唯一 SigningMessageHash 路径；7D）
//!   → canonical_transaction_bytes（payload ‖ signature(64B)）
//!   → compute_txid（SHA-256）
//! ```
//!
//! # 本模块边界
//! - **7C**：canonical 编码 / 解码 / txid。
//! - **7D**：签名生成 / 验证（[`sign_transaction`] / [`verify_transaction_signature`]），
//!   唯一走 [`SigningMessageHash`] API（`tx_message_hash` → `sign_message_hash` /
//!   `verify_message_hash`，**无第二条签名路径**）。
//! - **不实现**：Mempool / 执行 / 扣费 / State Transition（后续 STEP）。
//! - **`decode success ≠ valid transaction`**：格式正确性 ≠ 有效性（nonce / 签名 / 余额 /
//!   过期 / chain_id 语义在 7D/7E+）。
//! - `signature` **不进入** canonical_tx_payload；`signature` **进入** txid（ADR-0019 §4）。
//! - `chain_id` 双绑：payload 内 `chain_id` 与 signed_bytes 头部 `chain_id` 必须一致（§3）；
//!   篡改 chain_id ⇒ message_hash 变 ⇒ 签名验证失败。

use crate::address::NovaAddress;
use crate::domain::{
    AlgorithmId, DomainId, SigningMessageHash, build_signed_bytes, hash_signing_message,
};
use crate::hash::protocol_hash;
use crate::identity::{address_payload_bytes, decode_addr_payload};
use crate::signature::{
    Signature, SigningKey, VerifyingKey, sign_message_hash, verify_message_hash,
};
use core::fmt;

/// 交易类型注册表（ADR-0020）：`0x01 Transfer`；`0x02–0xFF` Reserved ⇒ 拒绝，禁 fallback。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransactionType {
    /// 转账（V0.1 唯一）。
    Transfer = 0x01,
}

impl TransactionType {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TransactionType {
    type Error = TransactionError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Transfer),
            _ => Err(TransactionError::UnknownTransactionType(v)),
        }
    }
}

/// 交易 codec 错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    /// 未知 / Reserved transaction_type（ADR-0020；禁 fallback）。
    UnknownTransactionType(u8),
    /// 解码失败（截断 / 非法长度 / 非法字段）。
    DecodeError,
    /// 解码后存在尾随字节（不得静默忽略）。
    TrailingBytes,
    /// 地址 payload 非法（未知 version / type / network）。
    InvalidAddress,
    /// 签名长度非法（≠ 64B）。
    InvalidSignature,
    /// 签名验证失败（Ed25519 verify_strict 拒绝；7D）。
    SignatureVerificationFailed,
    /// 提供的 sender 公钥与 sender 地址 key_hash 不匹配（身份绑定；7D）。
    SenderKeyMismatch,
    /// 编码长度溢出（u32 长度前缀 / payload 超限）。
    EncodingOverflow,
    /// chain_id 双绑不一致（payload 内 chain_id ≠ signed_bytes 头部 chain_id）。
    ChainIdMismatch,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTransactionType(t) => write!(f, "unknown transaction_type: {t:#04x}"),
            Self::DecodeError => write!(f, "decode error"),
            Self::TrailingBytes => write!(f, "trailing bytes"),
            Self::InvalidAddress => write!(f, "invalid address payload"),
            Self::InvalidSignature => write!(f, "invalid signature length"),
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::SenderKeyMismatch => {
                write!(f, "sender key does not match sender address key_hash")
            }
            Self::EncodingOverflow => write!(f, "encoding overflow"),
            Self::ChainIdMismatch => write!(f, "chain_id binding mismatch"),
        }
    }
}

impl std::error::Error for TransactionError {}

/// TransactionV1（ADR-0019 §1；字段顺序固定，禁止重排）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    pub version: u8,
    pub chain_id: u64,
    pub nonce: u64,
    pub sender: NovaAddress,
    pub receiver: NovaAddress,
    pub amount: u128,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub transaction_type: TransactionType,
    pub payload: Vec<u8>,
    pub expiration: u64,
    pub signature: [u8; 64],
}

/// 生成 canonical_tx_payload（**不含 signature**；ADR-0019 §2 / crypto-serialization §13）。
pub fn canonical_tx_payload(tx: &TransactionV1) -> Result<Vec<u8>, TransactionError> {
    let plen = u32::try_from(tx.payload.len()).map_err(|_| TransactionError::EncodingOverflow)?;
    let cap = 1 + 8 + 8 + 35 + 35 + 16 + 8 + 16 + 1 + 4 + tx.payload.len() + 8;
    let mut out = Vec::with_capacity(cap);
    out.push(tx.version);
    out.extend_from_slice(&tx.chain_id.to_le_bytes());
    out.extend_from_slice(&tx.nonce.to_le_bytes());
    out.extend_from_slice(&address_payload_bytes(&tx.sender));
    out.extend_from_slice(&address_payload_bytes(&tx.receiver));
    out.extend_from_slice(&tx.amount.to_le_bytes());
    out.extend_from_slice(&tx.gas_limit.to_le_bytes());
    out.extend_from_slice(&tx.gas_price.to_le_bytes());
    out.push(tx.transaction_type.as_u8());
    out.extend_from_slice(&plen.to_le_bytes());
    out.extend_from_slice(&tx.payload);
    out.extend_from_slice(&tx.expiration.to_le_bytes());
    Ok(out)
}

/// 构造 signed_bytes（ADR-0005/0012 §10 + ADR-0019 §3）。
///
/// `signed_bytes = algorithm_id(0x01) ‖ domain_id(0x01 Transaction) ‖ chain_id(8 LE) ‖
/// payload_length(4 LE) ‖ canonical_tx_payload`。
pub fn tx_signed_bytes(tx: &TransactionV1) -> Result<Vec<u8>, TransactionError> {
    let payload = canonical_tx_payload(tx)?;
    build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::Transaction,
        tx.chain_id,
        &payload,
    )
    .map_err(|_| TransactionError::EncodingOverflow)
}

/// 计算 message_hash（`SHA-256(signed_bytes)` → `SigningMessageHash`；签名输入，ADR-0013）。
pub fn tx_message_hash(tx: &TransactionV1) -> Result<SigningMessageHash, TransactionError> {
    let sb = tx_signed_bytes(tx)?;
    Ok(hash_signing_message(&sb))
}

/// 生成完整交易 canonical bytes（**含 signature**；txid preimage，ADR-0019 §4）。
pub fn canonical_transaction_bytes(tx: &TransactionV1) -> Result<Vec<u8>, TransactionError> {
    let mut out = canonical_tx_payload(tx)?;
    out.extend_from_slice(&tx.signature);
    Ok(out)
}

/// 计算 txid：`SHA-256(canonical_tx_payload ‖ signature)`（含签名；不进入 signature coverage）。
pub fn compute_txid(tx: &TransactionV1) -> Result<[u8; 32], TransactionError> {
    let bytes = canonical_transaction_bytes(tx)?;
    Ok(protocol_hash(&bytes))
}

/// 校验 chain_id 双绑（ADR-0019 §3）：signed_bytes 头部 chain_id == TransactionV1.chain_id。
///
/// 防御性显式校验（篡改检测）；构造路径恒一致，解码/外部输入路径防不一致。
pub fn check_chain_id_binding(tx: &TransactionV1) -> Result<(), TransactionError> {
    let sb = tx_signed_bytes(tx)?;
    // signed_bytes 布局：algorithm_id(1) ‖ domain_id(1) ‖ chain_id(8 LE) ‖ ...
    if sb.len() < 10 {
        return Err(TransactionError::DecodeError);
    }
    let head = u64::from_le_bytes(
        sb[2..10]
            .try_into()
            .map_err(|_| TransactionError::DecodeError)?,
    );
    if head != tx.chain_id {
        return Err(TransactionError::ChainIdMismatch);
    }
    Ok(())
}

// =====================================================================
// STEP 7D — Transaction Signature Integration
// =====================================================================

/// 用 sender 私钥对交易签名（**唯一签名路径**，7D）。
///
/// `tx.signature = sign_message_hash(tx_message_hash(tx))`。
/// - message_hash 经 `tx_signed_bytes`（[`AlgorithmId::Ed25519`] / [`DomainId::Transaction`] /
///   chain_id 双绑）构造，签名输入是 [`SigningMessageHash`]（ADR-0013，禁任意字节签名）。
/// - `canonical_tx_payload` 不含 signature，故签名不进入 message hash（ADR-0019 §3）。
pub fn sign_transaction(
    signing: &SigningKey,
    tx: &mut TransactionV1,
) -> Result<(), TransactionError> {
    let mh = tx_message_hash(tx)?;
    let sig = sign_message_hash(signing, &mh);
    tx.signature = sig.to_bytes();
    Ok(())
}

/// 验证交易签名 + sender 公钥绑定（**唯一验证路径**，7D）。
///
/// 顺序：
/// 1. **身份绑定**：`sender_vk` 的 `SHA-256(canonical_pubkey)` 必须等于 `tx.sender` 的
///    `key_hash`（防“用不匹配地址的公钥验证”；ADR-0004/0008）。
/// 2. **message hash**：`tx_message_hash(tx)`（篡改任意字段 ⇒ hash 变）。
/// 3. **签名**：`verify_message_hash(sender_vk, &mh, &sig)`（verify_strict；SigningMessageHash API）。
///
/// **decode success ≠ valid**：本函数只验签名/身份；nonce / 余额 / 过期等 admission 语义在 7E+。
pub fn verify_transaction_signature(
    tx: &TransactionV1,
    sender_vk: &VerifyingKey,
) -> Result<(), TransactionError> {
    // 1) 身份绑定：sender 地址 key_hash 必须来自该公钥（SHA-256(canonical_pubkey)）。
    let key_hash = protocol_hash(&sender_vk.to_bytes());
    if tx.sender.payload().key_hash != key_hash {
        return Err(TransactionError::SenderKeyMismatch);
    }
    // 2) 唯一 message hash 路径（篡改任意字段 ⇒ hash 变 ⇒ 验证失败）。
    let mh = tx_message_hash(tx)?;
    // 3) 唯一验证路径（SigningMessageHash → verify_strict）。
    let sig =
        Signature::from_bytes(&tx.signature).map_err(|_| TransactionError::InvalidSignature)?;
    verify_message_hash(sender_vk, &mh, &sig)
        .map_err(|_| TransactionError::SignatureVerificationFailed)
}

/// 解码完整交易（canonical roundtrip）。
///
/// 拒绝：truncated / trailing bytes / 未知 transaction_type / 非法地址 payload /
/// 非法长度；**不静默忽略 trailing bytes**。
pub fn decode_transaction(bytes: &[u8]) -> Result<TransactionV1, TransactionError> {
    fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], TransactionError> {
        if b.len() < *pos + n {
            return Err(TransactionError::DecodeError);
        }
        let s = &b[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }
    let arr8 = |b: &[u8]| -> [u8; 8] { b.try_into().expect("len 8") };

    let mut pos = 0usize;
    let version = take(bytes, &mut pos, 1)?[0];
    let chain_id = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));
    let nonce = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));
    let sender = decode_addr(take(bytes, &mut pos, 35)?)?;
    let receiver = decode_addr(take(bytes, &mut pos, 35)?)?;
    let amount = u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().expect("len 16"));
    let gas_limit = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));
    let gas_price = u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().expect("len 16"));
    let transaction_type = TransactionType::try_from(take(bytes, &mut pos, 1)?[0])?;
    let plen = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().expect("len 4")) as usize;
    let payload = take(bytes, &mut pos, plen)?.to_vec();
    let expiration = u64::from_le_bytes(arr8(take(bytes, &mut pos, 8)?));
    let sig = take(bytes, &mut pos, 64)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig);

    // trailing bytes：不得静默忽略（crypto-serialization §7）。
    if pos != bytes.len() {
        return Err(TransactionError::TrailingBytes);
    }

    Ok(TransactionV1 {
        version,
        chain_id,
        nonce,
        sender,
        receiver,
        amount,
        gas_limit,
        gas_price,
        transaction_type,
        payload,
        expiration,
        signature,
    })
}

fn decode_addr(b: &[u8]) -> Result<NovaAddress, TransactionError> {
    let a35: [u8; 35] = b.try_into().map_err(|_| TransactionError::DecodeError)?;
    decode_addr_payload(&a35).map_err(|_| TransactionError::InvalidAddress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{AddressType, NetworkId, NovaAddressPayload};

    fn addr(kh: [u8; 32], net: NetworkId) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: 1,
            address_type: AddressType::UserAccount,
            network_id: net,
            key_hash: kh,
        })
    }

    fn sample() -> TransactionV1 {
        TransactionV1 {
            version: 0x01,
            chain_id: 1001,
            nonce: 7,
            sender: addr([0x11; 32], NetworkId::Mainnet),
            receiver: addr([0x22; 32], NetworkId::Mainnet),
            amount: 1_000_000,
            gas_limit: 21_000,
            gas_price: 100,
            transaction_type: TransactionType::Transfer,
            payload: Vec::new(),
            expiration: 1_000_000,
            signature: [0xab; 64],
        }
    }

    // ---- 字段顺序 + LE + 地址 35B + signature 不入 payload ----
    #[test]
    fn canonical_payload_layout() {
        let tx = sample();
        let p = canonical_tx_payload(&tx).unwrap();
        // 固定部分：1+8+8+35+35+16+8+16+1+4+0+8 = 140（payload 空）
        assert_eq!(p.len(), 140, "empty payload layout");
        assert_eq!(p[0], 0x01, "version");
        assert_eq!(&p[1..9], &1001u64.to_le_bytes(), "chain_id LE");
        assert_eq!(&p[9..17], &7u64.to_le_bytes(), "nonce LE");
        assert_eq!(&p[17..52], &address_payload_bytes(&tx.sender), "sender 35B");
        assert_eq!(
            &p[52..87],
            &address_payload_bytes(&tx.receiver),
            "receiver 35B"
        );
        assert_eq!(&p[87..103], &1_000_000u128.to_le_bytes(), "amount LE");
        assert_eq!(&p[103..111], &21_000u64.to_le_bytes(), "gas_limit LE");
        assert_eq!(&p[111..127], &100u128.to_le_bytes(), "gas_price LE");
        assert_eq!(p[127], 0x01, "transaction_type");
        assert_eq!(&p[128..132], &0u32.to_le_bytes(), "payload_length LE");
        assert_eq!(&p[132..140], &1_000_000u64.to_le_bytes(), "expiration LE");
        // signature 不进入 payload：payload 长度不含 64B
        assert_eq!(
            p.len(),
            140,
            "signature must NOT be in canonical_tx_payload"
        );
    }

    #[test]
    fn payload_length_encoded() {
        let mut tx = sample();
        tx.payload = vec![0xde, 0xad, 0xbe, 0xef];
        let p = canonical_tx_payload(&tx).unwrap();
        assert_eq!(p.len(), 140 + 4);
        assert_eq!(&p[128..132], &4u32.to_le_bytes(), "payload_length u32 LE");
        assert_eq!(&p[132..136], &[0xde, 0xad, 0xbe, 0xef], "payload bytes");
    }

    // ---- signature 进入 txid ----
    #[test]
    fn signature_affects_txid() {
        let tx = sample();
        let mut other = tx.clone();
        other.signature[0] ^= 0xff;
        let id1 = compute_txid(&tx).unwrap();
        let id2 = compute_txid(&other).unwrap();
        assert_ne!(id1, id2, "signature must enter txid");
    }

    // ---- txid 确定性 + 不含 signature 的 payload 不决定 txid 全部 ----
    #[test]
    fn txid_deterministic() {
        let tx = sample();
        assert_eq!(compute_txid(&tx).unwrap(), compute_txid(&tx).unwrap());
        assert_eq!(compute_txid(&tx).unwrap().len(), 32);
    }

    // ---- canonical roundtrip ----
    #[test]
    fn canonical_roundtrip() {
        let tx = sample();
        let bytes = canonical_transaction_bytes(&tx).unwrap();
        let d = decode_transaction(&bytes).unwrap();
        assert_eq!(d, tx, "decode(encode(tx)) == tx");
        assert_eq!(
            canonical_transaction_bytes(&d).unwrap(),
            bytes,
            "re-encode stable"
        );
        // txid 一致
        assert_eq!(compute_txid(&d).unwrap(), compute_txid(&tx).unwrap());
    }

    #[test]
    fn roundtrip_with_payload() {
        let mut tx = sample();
        tx.payload = vec![1, 2, 3, 4, 5];
        let bytes = canonical_transaction_bytes(&tx).unwrap();
        assert_eq!(decode_transaction(&bytes).unwrap(), tx);
    }

    // ---- chain_id 双绑 ----
    #[test]
    fn chain_id_binding_ok() {
        let tx = sample();
        assert!(check_chain_id_binding(&tx).is_ok());
    }

    #[test]
    fn chain_id_tamper_detected_via_decode() {
        let tx = sample();
        let bytes = canonical_transaction_bytes(&tx).unwrap();
        // 篡改 payload 内 chain_id（offset 1..9）→ decode 后 chain_id 不同 → txid 不同
        let mut tampered = bytes.clone();
        tampered[1] ^= 0x01;
        let dt = decode_transaction(&tampered).unwrap();
        assert_ne!(dt.chain_id, tx.chain_id);
        assert_ne!(compute_txid(&dt).unwrap(), compute_txid(&tx).unwrap());
    }

    // ---- trailing / truncated / malformed / unknown type ----
    #[test]
    fn trailing_bytes_rejected() {
        let tx = sample();
        let mut bytes = canonical_transaction_bytes(&tx).unwrap();
        bytes.push(0x00);
        assert_eq!(
            decode_transaction(&bytes),
            Err(TransactionError::TrailingBytes)
        );
    }

    #[test]
    fn truncated_rejected() {
        let tx = sample();
        let bytes = canonical_transaction_bytes(&tx).unwrap();
        assert_eq!(
            decode_transaction(&bytes[..bytes.len() - 1]),
            Err(TransactionError::DecodeError)
        );
        assert_eq!(
            decode_transaction(&bytes[..3]),
            Err(TransactionError::DecodeError)
        );
        assert_eq!(decode_transaction(&[]), Err(TransactionError::DecodeError));
    }

    #[test]
    fn unknown_transaction_type_rejected() {
        let tx = sample();
        let mut bytes = canonical_transaction_bytes(&tx).unwrap();
        // transaction_type 在 offset 127
        bytes[127] = 0x99;
        assert_eq!(
            decode_transaction(&bytes),
            Err(TransactionError::UnknownTransactionType(0x99))
        );
        assert_eq!(
            TransactionType::try_from(0x00),
            Err(TransactionError::UnknownTransactionType(0x00))
        );
        assert_eq!(
            TransactionType::try_from(0x02),
            Err(TransactionError::UnknownTransactionType(0x02))
        );
    }

    #[test]
    fn invalid_address_payload_rejected() {
        let tx = sample();
        let mut bytes = canonical_transaction_bytes(&tx).unwrap();
        // sender address 的 address_type 字节（offset 17 + 1 = 18）改未知
        bytes[18] = 0x99;
        assert_eq!(
            decode_transaction(&bytes),
            Err(TransactionError::InvalidAddress)
        );
    }

    // ---- message_hash pipeline ----
    #[test]
    fn message_hash_pipeline() {
        let tx = sample();
        let mh = tx_message_hash(&tx).unwrap();
        let sb = tx_signed_bytes(&tx).unwrap();
        assert_eq!(mh.as_bytes(), &protocol_hash(&sb)[..]);
        // signed_bytes 布局：alg(0x01) ‖ dom(0x01) ‖ chain_id
        assert_eq!(sb[0], 0x01, "algorithm_id Ed25519");
        assert_eq!(sb[1], 0x01, "domain_id Transaction");
        assert_eq!(&sb[2..10], &tx.chain_id.to_le_bytes(), "chain_id LE");
    }

    // =====================================================================
    // STEP 7D — Signature Integration
    // =====================================================================
    use crate::signature::SigningKey as Sk;

    /// 构造签名完成、sender 地址与密钥绑定的交易。
    fn signed_tx() -> (Sk, VerifyingKey, TransactionV1) {
        let signing = Sk::from_seed([0x42u8; 32]);
        let vk = signing.verifying_key();
        let mut tx = sample();
        tx.sender =
            NovaAddress::from_verifying_key(&vk, AddressType::UserAccount, NetworkId::Mainnet)
                .unwrap();
        sign_transaction(&signing, &mut tx).unwrap();
        (signing, vk, tx)
    }

    #[test]
    fn sign_then_verify_ok() {
        let (_, vk, tx) = signed_tx();
        assert!(tx.signature.iter().any(|b| *b != 0), "signature set");
        assert_eq!(verify_transaction_signature(&tx, &vk), Ok(()));
    }

    #[test]
    fn signature_not_in_message_hash() {
        // 签名不进入 canonical_tx_payload ⇒ message_hash 与签名无关（ADR-0019 §3）
        let (_, vk, tx) = signed_tx();
        let mh_signed = tx_message_hash(&tx).unwrap();
        let mut tx2 = tx.clone();
        tx2.signature = [0u8; 64];
        let mh_unsigned = tx_message_hash(&tx2).unwrap();
        assert_eq!(
            mh_signed, mh_unsigned,
            "signature must not enter message_hash"
        );
        assert_eq!(verify_transaction_signature(&tx, &vk), Ok(()));
    }

    // 篡改任意字段 ⇒ 签名验证失败（改 hash 或改 signature）
    #[test]
    fn tamper_amount_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.amount += 1;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_receiver_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.receiver = addr([0x33; 32], NetworkId::Mainnet);
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_nonce_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.nonce += 1;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_chain_id_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.chain_id += 1;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_payload_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.payload = vec![0xde, 0xad];
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_expiration_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.expiration += 1;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_gas_price_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.gas_price += 1;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tamper_signature_fails() {
        let (_, vk, mut tx) = signed_tx();
        tx.signature[0] ^= 0xff;
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SignatureVerificationFailed)
        );
    }

    // transaction_type 只有 Transfer(0x01)；未知值在 decode 层拒绝（ADR-0020 注册表）
    #[test]
    fn tamper_transaction_type_rejected_at_decode() {
        let (_, _, tx) = signed_tx();
        let mut bytes = canonical_transaction_bytes(&tx).unwrap();
        bytes[127] = 0x02; // transaction_type
        assert_eq!(
            decode_transaction(&bytes),
            Err(TransactionError::UnknownTransactionType(0x02))
        );
    }

    // 身份绑定：换 sender 公钥 / 换 sender 地址 ⇒ 拒绝
    #[test]
    fn wrong_sender_key_fails() {
        let (_, _, tx) = signed_tx();
        let other = Sk::from_seed([0x99u8; 32]).verifying_key();
        assert_eq!(
            verify_transaction_signature(&tx, &other),
            Err(TransactionError::SenderKeyMismatch),
            "other key must not match sender key_hash"
        );
    }

    #[test]
    fn sender_address_tamper_rejected() {
        let (_, vk, mut tx) = signed_tx();
        tx.sender = addr([0x11; 32], NetworkId::Mainnet);
        assert_eq!(
            verify_transaction_signature(&tx, &vk),
            Err(TransactionError::SenderKeyMismatch)
        );
    }

    #[test]
    fn receiver_key_not_sender() {
        // 用 receiver 的公钥冒充 sender 公钥 ⇒ key_hash 不匹配 ⇒ 拒绝
        let (_, _, mut tx) = signed_tx();
        let rk = Sk::from_seed([0x77u8; 32]).verifying_key();
        tx.receiver =
            NovaAddress::from_verifying_key(&rk, AddressType::UserAccount, NetworkId::Mainnet)
                .unwrap();
        assert_eq!(
            verify_transaction_signature(&tx, &rk),
            Err(TransactionError::SenderKeyMismatch)
        );
    }
}
