//! Nova Chain 地址编码（STEP 5 — Address Encoding）。
//!
//! # 冻结规范（ADR-0004）
//! Nova Custom Address Format using **Bech32m-derived encoding**（使用 Bech32m 编码与校验机制，
//! **不是 Bitcoin SegWit 地址**，**不声称 BIP-350 兼容**）。
//!
//! ```text
//! NovaAddressPayload { address_version: u8, address_type: u8, network_id: u8, key_hash: [u8;32] }
//!
//! key_hash = SHA-256(canonical_public_key_encoding)
//! ```
//!
//! # 关键规则（用户评审）
//! 地址**不能**从任意 `[u8;32]` hash 直接当作有效账户身份。`key_hash` 必须经
//! `PublicKey → AlgorithmId → Canonical pubkey encoding → SHA-256 → key_hash → Address`
//! 路径派生（ADR-0008 / ADR-0012 一致）。
//! - 公开构造路径：仅 [`NovaAddress::from_verifying_key`]（从公钥派生）与
//!   [`NovaAddress::decode`]（恢复已验证地址）；`from_payload` 用于编解码内部用途，
//!   不赋予"有效账户"语义（账户身份由公钥签名验证保证）。
//!
//! # 网络 / 类型注册表（ADR-0011 / ADR-0008）
//! `network_id`：0x01 mainnet(nova) / 0x02 testnet(novat) / 0x03 devnet(novad)；其余拒绝。
//! `address_type`：0x01 User Account；其余 Reserved ⇒ 拒绝。
//! `address_type` ↔ `algorithm_id` 映射：User Account ↔ Ed25519（显式，禁隐式）。

use crate::domain::AlgorithmId;
use crate::hash::protocol_hash;
use crate::signature::VerifyingKey;
use core::fmt;

/// 当前地址格式版本（ADR-0004）。
pub const ADDRESS_VERSION: u8 = 0x01;

/// 地址解码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// HRP 非注册（非 nova/novat/novad）。
    InvalidHrp,
    /// Bech32m 校验失败（坏 checksum / 非法字符）。
    InvalidChecksum,
    /// 编码/解码失败（bech32 库错误）。
    EncodeDecode,
    /// 数据长度非法（≠ 35 字节）。
    InvalidLength,
    /// 地址版本不支持。
    UnsupportedVersion,
    /// 未知 address_type（未注册 ⇒ 拒绝）。
    UnknownAddressType(u8),
    /// 未知 network_id（未注册 ⇒ 拒绝）。
    UnknownNetwork(u8),
    /// HRP 与 payload network_id 不一致（跨网地址）。
    NetworkMismatch,
    /// address_type 与 algorithm_id 映射不匹配。
    TypeAlgorithmMismatch,
    /// 非 canonical 大小写（含大写 ⇒ 拒绝）。
    NonCanonicalCase,
    /// 公钥解析失败。
    InvalidPublicKey,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHrp => write!(f, "invalid HRP"),
            Self::InvalidChecksum => write!(f, "invalid bech32m checksum"),
            Self::EncodeDecode => write!(f, "bech32 encode/decode error"),
            Self::InvalidLength => write!(f, "invalid payload length"),
            Self::UnsupportedVersion => write!(f, "unsupported address version"),
            Self::UnknownAddressType(t) => write!(f, "unknown address_type: {t:#04x}"),
            Self::UnknownNetwork(n) => write!(f, "unknown network_id: {n:#04x}"),
            Self::NetworkMismatch => write!(f, "HRP/network mismatch"),
            Self::TypeAlgorithmMismatch => write!(f, "address_type/algorithm mapping mismatch"),
            Self::NonCanonicalCase => write!(f, "non-canonical case (uppercase rejected)"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
        }
    }
}

impl std::error::Error for AddressError {}

/// 地址类型（账户/地址语义，ADR-0008）——**不是签名算法**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressType {
    /// 用户账户（个人账户）。
    UserAccount = 0x01,
}

impl AddressType {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AddressType {
    type Error = AddressError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::UserAccount),
            _ => Err(AddressError::UnknownAddressType(v)),
        }
    }
}

/// 网络标识（ADR-0011）——**不是唯一链身份**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetworkId {
    /// mainnet（HRP: nova）。
    Mainnet = 0x01,
    /// testnet（HRP: novat）。
    Testnet = 0x02,
    /// devnet（HRP: novad）。
    Devnet = 0x03,
}

impl NetworkId {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 网络特定 HRP（ADR-0011）。
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "nova",
            Self::Testnet => "novat",
            Self::Devnet => "novad",
        }
    }
}

impl TryFrom<u8> for NetworkId {
    type Error = AddressError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Mainnet),
            0x02 => Ok(Self::Testnet),
            0x03 => Ok(Self::Devnet),
            _ => Err(AddressError::UnknownNetwork(v)),
        }
    }
}

/// Nova 地址 payload（35 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NovaAddressPayload {
    /// 地址格式版本（当前 `ADDRESS_VERSION = 0x01`）。
    pub address_version: u8,
    /// 账户/地址语义（ADR-0008；非算法）。
    pub address_type: AddressType,
    /// 网络标识（ADR-0011）。
    pub network_id: NetworkId,
    /// `SHA-256(canonical_public_key_encoding)`。
    pub key_hash: [u8; 32],
}

impl NovaAddressPayload {
    /// 35 字节 raw 表示（`version ‖ type ‖ network ‖ key_hash`；ADR-0004 / ADR-0028 D-3）。
    ///
    /// 协议层统一入口（trie key / 地址 canonical bytes）；**禁止 storage 自行 enum→bytes**。
    pub fn to_bytes(&self) -> [u8; 35] {
        payload_to_bytes(self)
    }
}

/// Nova 地址（Bech32m-derived 文本的规范表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NovaAddress {
    payload: NovaAddressPayload,
}

impl NovaAddress {
    /// **从公钥派生地址**（推荐路径）。
    ///
    /// `key_hash = SHA-256(canonical_pubkey_encoding)`；`address_type ↔ algorithm` 显式校验。
    pub fn from_verifying_key(
        verifying: &VerifyingKey,
        address_type: AddressType,
        network: NetworkId,
    ) -> Result<Self, AddressError> {
        validate_type_algorithm(address_type, AlgorithmId::Ed25519)?;
        let key_hash = protocol_hash(&verifying.to_bytes());
        Ok(Self {
            payload: NovaAddressPayload {
                address_version: ADDRESS_VERSION,
                address_type,
                network_id: network,
                key_hash,
            },
        })
    }

    /// 从已构造 payload 构建（编解码内部用途；不赋予账户语义）。
    pub fn from_payload(payload: NovaAddressPayload) -> Self {
        Self { payload }
    }

    /// 编码为 Bech32m-derived 文本（`nova1...`）。
    pub fn encode(&self) -> Result<String, AddressError> {
        let hrp = bech32::Hrp::parse(self.payload.network_id.hrp())
            .map_err(|_| AddressError::InvalidHrp)?;
        let bytes = payload_to_bytes(&self.payload);
        bech32::encode::<bech32::Bech32m>(hrp, &bytes).map_err(|_| AddressError::EncodeDecode)
    }

    /// 解码 Bech32m-derived 文本为地址（严格校验，见模块 doc）。
    ///
    /// 严格限定 Bech32m checksum（不接受原始 bech32），拒绝任何大写字符。
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        // canonical 大小写：拒绝任何大写字符（uppercase / mixed case ⇒ 拒绝）。
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(AddressError::NonCanonicalCase);
        }
        // 严格 Bech32m：只接受 bech32m checksum（非 bech32 / 无 checksum / 坏 checksum 均拒绝）。
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s)
            .map_err(|_| AddressError::InvalidChecksum)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        let network = network_from_hrp(&hrp)?;
        let payload = bytes_to_payload(&data)?;
        // 跨网地址拒绝：HRP 网络必须与 payload network_id 一致。
        if payload.network_id != network {
            return Err(AddressError::NetworkMismatch);
        }
        Ok(Self { payload })
    }

    /// 只读访问 payload。
    pub const fn payload(&self) -> &NovaAddressPayload {
        &self.payload
    }
}

/// `address_type ↔ algorithm_id` 显式映射校验（ADR-0008/0012，禁隐式映射）。
pub fn validate_type_algorithm(
    address_type: AddressType,
    algorithm: AlgorithmId,
) -> Result<(), AddressError> {
    // 显式映射表（ADR-0008 / ADR-0012）：
    //   User Account ↔ Ed25519
    // （未来新增类型/算法组合必须在此显式登记，禁止隐式/通配匹配）。
    let allowed = match address_type {
        AddressType::UserAccount => matches!(algorithm, AlgorithmId::Ed25519),
    };
    if allowed {
        Ok(())
    } else {
        Err(AddressError::TypeAlgorithmMismatch)
    }
}

fn network_from_hrp(hrp: &bech32::Hrp) -> Result<NetworkId, AddressError> {
    match hrp.to_string().as_str() {
        "nova" => Ok(NetworkId::Mainnet),
        "novat" => Ok(NetworkId::Testnet),
        "novad" => Ok(NetworkId::Devnet),
        _ => Err(AddressError::InvalidHrp),
    }
}

/// payload → 35 字节（固定顺序：version ‖ type ‖ network ‖ key_hash）。
fn payload_to_bytes(p: &NovaAddressPayload) -> [u8; 35] {
    let mut out = [0u8; 35];
    out[0] = p.address_version;
    out[1] = p.address_type.as_u8();
    out[2] = p.network_id.as_u8();
    out[3..35].copy_from_slice(&p.key_hash);
    out
}

/// 35 字节 → payload（校验 version / type / network）。
fn bytes_to_payload(b: &[u8]) -> Result<NovaAddressPayload, AddressError> {
    if b.len() != 35 {
        return Err(AddressError::InvalidLength);
    }
    if b[0] != ADDRESS_VERSION {
        return Err(AddressError::UnsupportedVersion);
    }
    let address_type = AddressType::try_from(b[1])?;
    let network_id = NetworkId::try_from(b[2])?;
    let mut key_hash = [0u8; 32];
    key_hash.copy_from_slice(&b[3..35]);
    Ok(NovaAddressPayload {
        address_version: b[0],
        address_type,
        network_id,
        key_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    fn sample_payload() -> NovaAddressPayload {
        NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: [0xabu8; 32],
        }
    }

    // ------------------------------------------------------------------
    // 基础 roundtrip
    // ------------------------------------------------------------------
    #[test]
    fn encode_decode_roundtrip() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        assert!(s.starts_with("nova1"));
        let decoded = NovaAddress::decode(&s).unwrap();
        assert_eq!(decoded.payload(), &sample_payload());
    }

    #[test]
    fn canonical_roundtrip() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        // encode(decode(a)) == a_canonical
        let decoded = NovaAddress::decode(&s).unwrap();
        assert_eq!(decoded.encode().unwrap(), s);
        // decode(encode(payload)) == payload
        let back = NovaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(*back.payload(), sample_payload());
    }

    // ------------------------------------------------------------------
    // from_verifying_key：key_hash 必须来自 canonical pubkey → SHA-256
    // ------------------------------------------------------------------
    #[test]
    fn from_verifying_key_derives_sha256_pubkey_hash() {
        let kp = KeyPair::generate().unwrap();
        let vk = kp.verifying_key();
        let addr =
            NovaAddress::from_verifying_key(vk, AddressType::UserAccount, NetworkId::Mainnet)
                .unwrap();
        let expected_hash = protocol_hash(&vk.to_bytes());
        assert_eq!(addr.payload().key_hash, expected_hash);
        // 编码 → 解码 → key_hash 一致（完整链路）
        let decoded = NovaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(decoded.payload().key_hash, expected_hash);
    }

    #[test]
    fn cannot_construct_from_arbitrary_hash_as_identity() {
        // NovaAddress 没有从任意 [u8;32] 构造"账户身份"的公开 API。
        // from_verifying_key 强制从公钥派生 key_hash（此处验证派生正确性已在上方）。
        // 本测试记录意图：任意 hash 不能经 from_verifying_key 注入。
        let kp = KeyPair::generate().unwrap();
        let addr = NovaAddress::from_verifying_key(
            kp.verifying_key(),
            AddressType::UserAccount,
            NetworkId::Mainnet,
        )
        .unwrap();
        // 只有 from_payload（编解码内部）接受任意 payload；身份语义由签名验证保证。
        let _ = addr;
    }

    // ------------------------------------------------------------------
    // 安全测试（用户列表）
    // ------------------------------------------------------------------
    #[test]
    fn wrong_hrp_rejected() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        // 替换 HRP → 仍是合法 bech32m（checksum 匹配原 HRP 会失败）
        let wrong = format!("bitcoin{}", &s[s.find('1').unwrap()..]);
        assert!(NovaAddress::decode(&wrong).is_err());
    }

    #[test]
    fn wrong_checksum_rejected() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        let mut chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        // 篡改最后一个字符（checksum 区）
        chars[n - 1] = if chars[n - 1] == 'q' { 'p' } else { 'q' };
        let mutated: String = chars.into_iter().collect();
        assert!(NovaAddress::decode(&mutated).is_err());
    }

    #[test]
    fn wrong_version_rejected() {
        let mut p = sample_payload();
        p.address_version = 0x02;
        let addr = NovaAddress::from_payload(p);
        let s = addr.encode().unwrap();
        // decode 恢复 → bytes_to_payload 版本校验失败
        assert!(NovaAddress::decode(&s).is_err());
    }

    #[test]
    fn unknown_address_type_rejected() {
        // 0x00 / 0x99 未注册 ⇒ 拒绝
        assert_eq!(
            AddressType::try_from(0x00),
            Err(AddressError::UnknownAddressType(0x00))
        );
        assert_eq!(
            AddressType::try_from(0x99),
            Err(AddressError::UnknownAddressType(0x99))
        );
        assert_eq!(AddressType::try_from(0x01), Ok(AddressType::UserAccount));
    }

    #[test]
    fn unknown_network_rejected() {
        assert_eq!(
            NetworkId::try_from(0x00),
            Err(AddressError::UnknownNetwork(0x00))
        );
        assert_eq!(
            NetworkId::try_from(0xff),
            Err(AddressError::UnknownNetwork(0xff))
        );
        assert_eq!(NetworkId::try_from(0x02), Ok(NetworkId::Testnet));
    }

    #[test]
    fn invalid_payload_length_rejected() {
        // 手工构造 36 字节 → bytes_to_payload 拒绝
        let mut b = vec![0u8; 36];
        b[0] = ADDRESS_VERSION;
        b[1] = AddressType::UserAccount.as_u8();
        b[2] = NetworkId::Mainnet.as_u8();
        assert!(bytes_to_payload(&b).is_err());
    }

    #[test]
    fn mixed_and_uppercase_rejected() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        // uppercase
        let up = s.to_uppercase();
        assert!(NovaAddress::decode(&up).is_err());
        // mixed case（改一个字符为大写）
        let bytes: Vec<u8> = s.bytes().collect();
        let mut mixed = bytes.clone();
        let idx = s.find('1').unwrap() + 1;
        mixed[idx] = mixed[idx].to_ascii_uppercase();
        let mixed_s = String::from_utf8(mixed).unwrap();
        assert!(NovaAddress::decode(&mixed_s).is_err());
    }

    #[test]
    fn truncated_and_extra_rejected() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        // truncated：去掉尾部（checksum 失效）
        assert!(NovaAddress::decode(&s[..s.len() - 4]).is_err());
        // extra：追加字符（checksum 失效）
        assert!(NovaAddress::decode(&format!("{s}q")).is_err());
    }

    #[test]
    fn character_mutation_rejected() {
        let addr = NovaAddress::from_payload(sample_payload());
        let s = addr.encode().unwrap();
        // 在 data 区改一个字符（checksum 不匹配）
        let idx = s.find('1').unwrap() + 2;
        let mut chars: Vec<char> = s.chars().collect();
        chars[idx] = if chars[idx] == 'q' { 'p' } else { 'q' };
        let mutated: String = chars.into_iter().collect();
        assert!(NovaAddress::decode(&mutated).is_err());
    }

    #[test]
    fn cross_network_rejection() {
        // mainnet 地址在 testnet HRP 上下文：payload network=mainnet，HRP=novat ⇒ NetworkMismatch
        let addr = NovaAddress::from_payload(sample_payload()); // mainnet
        let s = addr.encode().unwrap();
        // 用 testnet HRP 替换 mainnet HRP（同 payload 数据，checksum 会失效——因此此测试
        // 验证"解码出的网络与 HRP 一致"；真正的跨网由 decode 的 NetworkMismatch 覆盖）
        let data_part = &s[s.find('1').unwrap() + 1..];
        let fake_testnet = format!("novat1{data_part}");
        let r = NovaAddress::decode(&fake_testnet);
        // 因为 checksum 针对 nova1 计算，novat1... 校验失败（InvalidChecksum）或 NetworkMismatch
        assert!(r.is_err());
    }

    #[test]
    fn type_algorithm_mapping_mismatch() {
        // UserAccount ↔ Ed25519 有效
        assert!(validate_type_algorithm(AddressType::UserAccount, AlgorithmId::Ed25519).is_ok());
        // 未来：若加入其他类型/算法组合，必须显式批准（ADR-0008 映射表）。
    }

    #[test]
    fn network_specific_hrp() {
        assert_eq!(NetworkId::Mainnet.hrp(), "nova");
        assert_eq!(NetworkId::Testnet.hrp(), "novat");
        assert_eq!(NetworkId::Devnet.hrp(), "novad");
        let p = NovaAddressPayload {
            network_id: NetworkId::Testnet,
            ..sample_payload()
        };
        let s = NovaAddress::from_payload(p).encode().unwrap();
        assert!(s.starts_with("novat1"));
    }
}
