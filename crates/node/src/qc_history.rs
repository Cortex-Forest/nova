//! P1-A.7 — **Per-height PrecommitQC history**（node-local artifact；ADR-0064）。
//!
//! # 作用（只服务，不授权）
//! 落后 / 迟到 / restart-behind-tip 的节点需要"某个历史高度对应的 PrecommitQC"才能取得历史
//! finality。本模块把节点**本地已产出（并经 `verify_qc` PASS）**的 PrecommitQC 按高度持久化，
//! 供既有 `SyncBlockRequest` 的响应路径**附发**（`MessageType::ConsensusQc`；**零 wire 变更**）。
//!
//! # 路径与布局
//! ```text
//! storage_dir/
//! └── qc_history/
//!     ├── 00000000000000000001.qcf
//!     ├── 00000000000000000002.qcf
//!     └── ...
//! ```
//! 文件名 = `{height:020}.qcf` ⇒ **由高度直接派生路径**（零目录扫描 / 无历史遍历）。
//!
//! # Artifact 格式（严格）
//! ```text
//! magic(4 = "NQCH") ‖ version(1) ‖ network_id(1) ‖ chain_id(8 LE) ‖ genesis_hash(32)
//!   ‖ height(8 LE) ‖ reference(32) ‖ qc_len(4 LE) ‖ qc(encode_qc) ‖ checksum(32)
//! ```
//! 强绑定（写入与读取**双向**强制）：
//! - `height == qc.context.height + 1`
//! - `reference == qc.target`
//! - `qc.context.vote_type == Precommit`
//!
//! # 边界
//! - **不改** `finality_fact.bin`、**不改** canonical commit WAL、**不产生** finality / commit /
//!   head 推进；本模块只做**文件读写**（无 consensus / 无 network 依赖）。
//! - **不 panic**：所有失败 ⇒ typed `Err`（拒绝），调用方 fail-closed。
//! - **有界**：单文件 ≤ [`QC_HISTORY_MAX_ARTIFACT_BYTES`]；条目数 ≤ [`QC_HISTORY_RETENTION`]；
//!   超限 ⇒ 写入被拒（不截断）；retention 淘汰为**确定性单文件删除**（非全目录 GC）。
//! - **无墙钟 / 无随机**：临时文件名用 `pid + 进程内单调计数`（确定性可复现）。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nova_consensus::finality::{FinalityError, QuorumCertificate, decode_qc, encode_qc};
use nova_consensus::vote::VoteType;
use nova_crypto::address::NetworkId;
use nova_crypto::hash::protocol_hash;

/// `storage_dir` 下的子目录名。
pub const QC_HISTORY_DIR: &str = "qc_history";

/// 保留窗口（高度数）。**默认 4096**（Owner 批准）。
///
/// - 超过窗口的历史 QC **不再服务**（fail-closed；不猜 / 不跨高度借 / 不造 fake finality）。
/// - 实际最大追赶距离还受 responder `MAX_SYNC_WALK = 64` 限制 ⇒
///   `effective = min(QC_HISTORY_RETENTION, MAX_SYNC_WALK) = 64`（ADR-0064 明确记录）。
pub const QC_HISTORY_RETENTION: u64 = 4096;

/// Artifact magic（4B）。
const QC_HISTORY_MAGIC: [u8; 4] = *b"NQCH";
/// Artifact 版本（1B）；未知版本 ⇒ 拒。
const QC_HISTORY_VERSION: u8 = 1;
/// 头部定长：`magic(4) + version(1) + network_id(1) + chain_id(8) + genesis_hash(32) + height(8)
/// + reference(32) + qc_len(4)`。
const QC_HISTORY_HEADER_LEN: usize = 4 + 1 + 1 + 8 + 32 + 8 + 32 + 4;
/// checksum 长度（SHA-256 protocol hash）。
const QC_HISTORY_CHECKSUM_LEN: usize = 32;
/// 单 QC 编码上界（`encode_qc` = `93 + evidence×136`；evidence 上界按 64 个验证者保守取值）。
pub const QC_HISTORY_MAX_QC_BYTES: usize = 93 + 64 * 136;
/// 单个 artifact 文件上界（读路径据此拒绝超限文件；**不**加载无界数据）。
pub const QC_HISTORY_MAX_ARTIFACT_BYTES: usize =
    QC_HISTORY_HEADER_LEN + QC_HISTORY_MAX_QC_BYTES + QC_HISTORY_CHECKSUM_LEN;

/// 进程内临时文件序号（无随机 / 无墙钟；仅用于避免同进程重名）。
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// QC history 失败原因（全部 ⇒ 调用方 fail-closed；无 panic）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QcHistoryError {
    /// 文件系统 I/O 失败（读写 / 创建目录 / rename）。
    StorageIo,
    /// 结构非法（magic / version / 长度 / trailing）。
    Corrupt,
    /// identity 不符（network_id / chain_id / genesis_hash）。
    IdentityMismatch,
    /// `height != qc.context.height + 1`。
    HeightMismatch,
    /// `reference != qc.target`。
    TargetMismatch,
    /// QC 非 Precommit（frozen 强制）。
    NotPrecommitQc,
    /// QC 编码 / QC decode 失败。
    QcCodec(FinalityError),
    /// 超过 [`QC_HISTORY_MAX_QC_BYTES`] / [`QC_HISTORY_MAX_ARTIFACT_BYTES`]。
    Oversized,
    /// checksum 不符。
    ChecksumMismatch,
    /// **同高度不同 QC**（fail-closed；**永不覆盖**）。
    Conflict,
}

impl core::fmt::Display for QcHistoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageIo => write!(f, "qc history storage io error"),
            Self::Corrupt => write!(f, "qc history artifact corrupt"),
            Self::IdentityMismatch => write!(f, "qc history identity mismatch"),
            Self::HeightMismatch => write!(f, "qc history height mismatch"),
            Self::TargetMismatch => write!(f, "qc history target mismatch"),
            Self::NotPrecommitQc => write!(f, "qc history requires precommit qc"),
            Self::QcCodec(e) => write!(f, "qc history codec error: {e}"),
            Self::Oversized => write!(f, "qc history artifact oversized"),
            Self::ChecksumMismatch => write!(f, "qc history checksum mismatch"),
            Self::Conflict => write!(f, "qc history conflict (never overwrite)"),
        }
    }
}

impl std::error::Error for QcHistoryError {}

/// 链身份绑定（写入 / 读取双向强校验）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QcIdentity {
    network_id: NetworkId,
    chain_id: u64,
    genesis_hash: [u8; 32],
}

/// Per-height PrecommitQC history（node-local）。
///
/// - `tip`：**内存**最高已写入高度（供 tip hint；**不扫描目录**）。启动时可由调用方经
///   [`Self::note_tip`] 用本地 finality fact 的高度**播种**；缺失 ⇒ 本 step 不发 hint。
#[derive(Debug)]
pub struct QcHistory {
    dir: PathBuf,
    identity: QcIdentity,
    retained: u64,
    tip: Option<u64>,
}

impl QcHistory {
    /// 构造（**无 I/O**；目录按需在首次写入时创建）。
    pub fn open(
        storage_dir: &Path,
        network_id: NetworkId,
        chain_id: u64,
        genesis_hash: [u8; 32],
    ) -> Self {
        Self {
            dir: storage_dir.join(QC_HISTORY_DIR),
            identity: QcIdentity {
                network_id,
                chain_id,
                genesis_hash,
            },
            retained: QC_HISTORY_RETENTION,
            tip: None,
        }
    }

    /// 覆盖 retention 窗口（长度必须 ≥ 1；0 或不合规 ⇒ 保持默认）。
    pub fn with_retention(mut self, retained: u64) -> Self {
        if retained >= 1 {
            self.retained = retained;
        }
        self
    }

    /// 当前 retention 窗口（高度数）。
    pub fn retained(&self) -> u64 {
        self.retained
    }

    /// artifact 根目录（诊断用；只读）。
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 记录 tip 高度（**单调**；仅内存，不做 I/O）。用于启动时播种 / 写入后更新。
    pub fn note_tip(&mut self, height: u64) {
        if self.tip.is_none_or(|t| height > t) {
            self.tip = Some(height);
        }
    }

    /// 当前 tip 高度（`None` = 未知 —— 不猜测 / 不扫描）。
    pub fn tip_height(&self) -> Option<u64> {
        self.tip
    }

    /// 某高度是否已有 artifact（只做 `exists()`；不读内容）。
    pub fn contains(&self, height: u64) -> bool {
        self.path_for(height).exists()
    }

    /// 写入某高度的 PrecommitQC（幂等；同高度不同 QC ⇒ `Err(Conflict)`，**永不覆盖**）。
    ///
    /// 契约（全部强制）：
    /// - `qc.context.vote_type == Precommit`；
    /// - `height == qc.context.height + 1`；
    /// - 编码后 ≤ [`QC_HISTORY_MAX_QC_BYTES`]（超限 ⇒ `Oversized`，不截断）；
    /// - `tmp → write → sync → close → atomic rename`（临时名**不含**正式高度名）；
    /// - 同高度**同字节** ⇒ `Ok`（no-op）；同高度**不同字节** ⇒ `Err(Conflict)`。
    pub fn put(&mut self, height: u64, qc: &QuorumCertificate) -> Result<(), QcHistoryError> {
        if qc.context.vote_type != VoteType::Precommit {
            return Err(QcHistoryError::NotPrecommitQc);
        }
        if qc.context.height.saturating_add(1) != height {
            return Err(QcHistoryError::HeightMismatch);
        }
        let bytes = self.encode(height, qc)?;
        let path = self.path_for(height);
        if path.exists() {
            let existing = fs::read(&path).map_err(|_| QcHistoryError::StorageIo)?;
            if existing == bytes {
                self.note_tip(height); // 幂等（重复写同一高度同一 QC）
                return Ok(());
            }
            // 同高度不同内容：无论是不同 reference 还是同 reference 不同字节，一律 fail-closed。
            return Err(QcHistoryError::Conflict);
        }
        fs::create_dir_all(&self.dir).map_err(|_| QcHistoryError::StorageIo)?;
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!(".tmp-{}-{}.qcf", std::process::id(), n));
        {
            let mut f = fs::File::create(&tmp).map_err(|_| QcHistoryError::StorageIo)?;
            f.write_all(&bytes).map_err(|_| QcHistoryError::StorageIo)?;
            f.sync_all().map_err(|_| QcHistoryError::StorageIo)?;
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
                QcHistoryError::Conflict
            } else {
                QcHistoryError::StorageIo
            });
        }
        self.note_tip(height);
        // retention：确定性淘汰 `height - retained`（单文件删除；非目录扫描 GC）。
        if height > self.retained {
            let victim = height - self.retained;
            if victim < height {
                let _ = fs::remove_file(self.path_for(victim));
            }
        }
        Ok(())
    }

    /// 读取某高度的 PrecommitQC（**全验证**；任一不符 ⇒ `Err`；不存在 ⇒ `Ok(None)`）。
    pub fn get(&self, height: u64) -> Result<Option<QuorumCertificate>, QcHistoryError> {
        let path = self.path_for(height);
        if !path.exists() {
            return Ok(None);
        }
        let meta = fs::metadata(&path).map_err(|_| QcHistoryError::StorageIo)?;
        if meta.len() > QC_HISTORY_MAX_ARTIFACT_BYTES as u64 {
            return Err(QcHistoryError::Oversized);
        }
        let bytes = fs::read(&path).map_err(|_| QcHistoryError::StorageIo)?;
        decode_artifact(&bytes, &self.identity, height).map(Some)
    }

    /// 直接路径（**不扫描目录**）：`qc_history/{height:020}.qcf`。
    fn path_for(&self, height: u64) -> PathBuf {
        self.dir.join(format!("{height:020}.qcf"))
    }

    /// 编码 artifact（含 checksum）。
    fn encode(&self, height: u64, qc: &QuorumCertificate) -> Result<Vec<u8>, QcHistoryError> {
        let qc_bytes = encode_qc(qc);
        if qc_bytes.len() > QC_HISTORY_MAX_QC_BYTES {
            return Err(QcHistoryError::Oversized);
        }
        let mut out =
            Vec::with_capacity(QC_HISTORY_HEADER_LEN + qc_bytes.len() + QC_HISTORY_CHECKSUM_LEN);
        out.extend_from_slice(&QC_HISTORY_MAGIC);
        out.push(QC_HISTORY_VERSION);
        out.push(self.identity.network_id.as_u8());
        out.extend_from_slice(&self.identity.chain_id.to_le_bytes());
        out.extend_from_slice(&self.identity.genesis_hash);
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&qc.target);
        out.extend_from_slice(&(qc_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&qc_bytes);
        let checksum = protocol_hash(&out);
        out.extend_from_slice(&checksum);
        Ok(out)
    }
}

/// 严格解码 + 全验证（任何不符 ⇒ `Err`；**不 panic**）。
fn decode_artifact(
    bytes: &[u8],
    identity: &QcIdentity,
    expect_height: u64,
) -> Result<QuorumCertificate, QcHistoryError> {
    if bytes.len() > QC_HISTORY_MAX_ARTIFACT_BYTES {
        return Err(QcHistoryError::Oversized);
    }
    if bytes.len() < QC_HISTORY_HEADER_LEN + QC_HISTORY_CHECKSUM_LEN {
        return Err(QcHistoryError::Corrupt);
    }
    if bytes[0..4] != QC_HISTORY_MAGIC {
        return Err(QcHistoryError::Corrupt);
    }
    let version = bytes[4];
    if version != QC_HISTORY_VERSION {
        return Err(QcHistoryError::Corrupt);
    }
    let network_id = bytes[5];
    let chain_id = u64::from_le_bytes(
        bytes[6..14]
            .try_into()
            .map_err(|_| QcHistoryError::Corrupt)?,
    );
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&bytes[14..46]);
    let height = u64::from_le_bytes(
        bytes[46..54]
            .try_into()
            .map_err(|_| QcHistoryError::Corrupt)?,
    );
    let mut reference = [0u8; 32];
    reference.copy_from_slice(&bytes[54..86]);
    let qc_len = u32::from_le_bytes(
        bytes[86..90]
            .try_into()
            .map_err(|_| QcHistoryError::Corrupt)?,
    ) as usize;
    if qc_len > QC_HISTORY_MAX_QC_BYTES {
        return Err(QcHistoryError::Oversized);
    }
    let qc_end = QC_HISTORY_HEADER_LEN
        .checked_add(qc_len)
        .ok_or(QcHistoryError::Corrupt)?;
    let checksum_end = qc_end
        .checked_add(QC_HISTORY_CHECKSUM_LEN)
        .ok_or(QcHistoryError::Corrupt)?;
    if checksum_end != bytes.len() {
        return Err(QcHistoryError::Corrupt);
    }
    let computed = protocol_hash(&bytes[..qc_end]);
    if computed != bytes[qc_end..checksum_end] {
        return Err(QcHistoryError::ChecksumMismatch);
    }
    // identity（防跨链 / 换链 artifact）。
    if network_id != identity.network_id.as_u8()
        || chain_id != identity.chain_id
        || genesis_hash != identity.genesis_hash
    {
        return Err(QcHistoryError::IdentityMismatch);
    }
    // 高度（请求高度 vs artifact 内高度：**必须**一致 —— 不跨高度借 QC）。
    if height != expect_height {
        return Err(QcHistoryError::HeightMismatch);
    }
    if height == 0 {
        // 高度 0 无 "QC.context.height + 1 == 0" 解（i64 下溢）；明确拒绝。
        return Err(QcHistoryError::HeightMismatch);
    }
    let qc = decode_qc(&bytes[QC_HISTORY_HEADER_LEN..qc_end]).map_err(QcHistoryError::QcCodec)?;
    if qc.context.vote_type != VoteType::Precommit {
        return Err(QcHistoryError::NotPrecommitQc);
    }
    if qc.context.height.saturating_add(1) != height {
        return Err(QcHistoryError::HeightMismatch);
    }
    if qc.target != reference {
        return Err(QcHistoryError::TargetMismatch);
    }
    Ok(qc)
}

#[cfg(test)]
mod tests {
    use super::*;

    use nova_consensus::finality::{QcContext, QcEvidence};
    use nova_consensus::validator::{ValidatorId, ValidatorSet};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
    use nova_crypto::identity::{
        AccountInit, EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit,
        compute_genesis_hash,
    };
    use nova_crypto::signature::{Signature, SigningKey, sign_message_hash};

    use crate::runtime::derive_validator_id;

    const CHAIN_ID: u64 = 1001;

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    /// 两验证者 genesis（同一 network / chain；账户地址互异）。
    fn genesis2() -> (GenesisV1, [u8; 32], [u8; 32]) {
        let pk1 = SigningKey::from_seed([0x11; 32]).verifying_key().to_bytes();
        let pk2 = SigningKey::from_seed([0x22; 32]).verifying_key().to_bytes();
        let mut validators = vec![
            ValidatorInit {
                account_address: addr([0x41; 32]),
                consensus_public_key: pk1,
                bonded_stake: 100,
                commission_bps: 0,
            },
            ValidatorInit {
                account_address: addr([0x42; 32]),
                consensus_public_key: pk2,
                bonded_stake: 100,
                commission_bps: 0,
            },
        ];
        validators.sort_by_key(|v| derive_validator_id(&v.consensus_public_key));
        let g = GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_timestamp: 1,
            initial_validator_set: validators,
            initial_accounts: vec![
                AccountInit {
                    address: addr([0x41; 32]),
                    liquid_balance: 1_000,
                },
                AccountInit {
                    address: addr([0x42; 32]),
                    liquid_balance: 1_000,
                },
            ],
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 1024,
                max_block_bytes: 1024 * 1024,
                max_gas_per_block: 1_000_000,
                max_contract_code_bytes: 1024,
                max_contract_storage_bytes: 1024,
                epoch_length_blocks: 1_000,
                snapshot_interval_blocks: 10_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 2_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 0,
            },
        };
        (g, pk1, pk2)
    }

    /// 用固定 seed 对给定 `(height, target)` 构造**真实签名**的 2-evidence PrecommitQC。
    fn signed_qc(
        genesis_hash: [u8; 32],
        height: u64,
        round: u64,
        target: [u8; 32],
    ) -> QuorumCertificate {
        let mut evidence = Vec::new();
        for seed in [[0x11u8; 32], [0x22u8; 32]] {
            let key = SigningKey::from_seed(seed);
            let vk = key.verifying_key();
            let validator_id = ValidatorId::from_consensus_public_key(&vk.to_bytes());
            let vote = nova_consensus::vote::ValidatorVote {
                round,
                height,
                target_block_hash: target,
                vote_type: VoteType::Precommit,
                source_block_hash: [0u8; 32],
                validator_id,
                timestamp: 7,
            };
            let payload = nova_consensus::vote::canonical_vote_payload(&vote);
            let signed = build_signed_bytes(
                AlgorithmId::Ed25519,
                DomainId::ValidatorVote,
                CHAIN_ID,
                &payload,
            )
            .expect("signed bytes");
            let h = hash_signing_message(&signed);
            let sig: Signature = sign_message_hash(&key, &h);
            evidence.push(QcEvidence {
                validator_id,
                source_block_hash: [0u8; 32],
                timestamp: 7,
                signature: sig.to_bytes(),
            });
        }
        evidence.sort_by_key(|e| e.validator_id);
        QuorumCertificate {
            context: QcContext {
                chain_id: CHAIN_ID,
                height,
                round,
                vote_type: VoteType::Precommit,
            },
            target,
            validator_set_id: genesis_hash,
            evidence,
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nova_qc_history_{}_{}_{}",
            std::process::id(),
            tag,
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn open(dir: &Path, genesis_hash: [u8; 32]) -> QcHistory {
        QcHistory::open(dir, NetworkId::Mainnet, CHAIN_ID, genesis_hash)
    }

    #[test]
    fn encode_decode_roundtrip_and_tip() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("rt");
        let mut store = open(&dir, gh);
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        assert_eq!(store.tip_height(), None);
        store.put(1, &qc).expect("put");
        assert_eq!(store.tip_height(), Some(1));
        assert_eq!(store.get(1).expect("get").expect("some"), qc);
        assert_eq!(store.get(2).expect("get missing"), None);
        assert!(store.contains(1));
        assert!(!store.contains(2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_non_precommit_and_height_relation() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("pre");
        let mut store = open(&dir, gh);
        let mut qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        qc.context.vote_type = VoteType::Prevote;
        assert_eq!(store.put(1, &qc), Err(QcHistoryError::NotPrecommitQc));
        let mut qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        qc.context.vote_type = VoteType::Precommit;
        // height 关系不符：context.height + 1 = 1 ≠ 5
        assert_eq!(store.put(5, &qc), Err(QcHistoryError::HeightMismatch));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_is_idempotent_conflict_fails_closed() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("dup");
        let mut store = open(&dir, gh);
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        store.put(1, &qc).expect("first put");
        store.put(1, &qc).expect("duplicate put ⇒ idempotent Ok");
        // 同高度**不同 target**（即使 QC 本身合法）⇒ Conflict，永不覆盖。
        let other = signed_qc(gh, 0, 0, [0xCD; 32]);
        assert_eq!(store.put(1, &other), Err(QcHistoryError::Conflict));
        assert_eq!(store.get(1).expect("get").expect("some"), qc);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_network_chain_genesis_rejected() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("ident");
        let store = open(&dir, gh);
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        let mut bytes = store.encode(1, &qc).expect("encode");
        // network_id 字节（offset 5）
        let mut bad = bytes.clone();
        bad[5] = 0xFF;
        let n = bad.len();
        let cs = protocol_hash(&bad[..n - 32]);
        bad[n - 32..].copy_from_slice(&cs);
        assert_eq!(
            decode_artifact(&bad, &store.identity, 1),
            Err(QcHistoryError::IdentityMismatch)
        );
        // chain_id（offset 6..14）
        let mut bad = bytes.clone();
        bad[6] ^= 0x01;
        let n = bad.len();
        let cs = protocol_hash(&bad[..n - 32]);
        bad[n - 32..].copy_from_slice(&cs);
        assert_eq!(
            decode_artifact(&bad, &store.identity, 1),
            Err(QcHistoryError::IdentityMismatch)
        );
        // genesis_hash（offset 14..46）
        let mut bad = bytes.clone();
        bad[14] ^= 0x01;
        let n = bad.len();
        let cs = protocol_hash(&bad[..n - 32]);
        bad[n - 32..].copy_from_slice(&cs);
        assert_eq!(
            decode_artifact(&bad, &store.identity, 1),
            Err(QcHistoryError::IdentityMismatch)
        );
        bytes.clear();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_height_and_wrong_reference_rejected() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("heir");
        let store = open(&dir, gh);
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        let bytes = store.encode(1, &qc).expect("encode");
        // 请求高度 2 ≠ artifact height 1
        assert_eq!(
            decode_artifact(&bytes, &store.identity, 2),
            Err(QcHistoryError::HeightMismatch)
        );
        // reference ≠ qc.target（offset 54..86）
        let mut bad = bytes.clone();
        bad[54] ^= 0x01;
        let n = bad.len();
        let cs = protocol_hash(&bad[..n - 32]);
        bad[n - 32..].copy_from_slice(&cs);
        assert_eq!(
            decode_artifact(&bad, &store.identity, 1),
            Err(QcHistoryError::TargetMismatch)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_malformed_and_corrupt_rejected() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("bad");
        let store = open(&dir, gh);
        // 畸形：长度不足
        assert_eq!(
            decode_artifact(&[0u8; 8], &store.identity, 1),
            Err(QcHistoryError::Corrupt)
        );
        // 超限 artifact
        let huge = vec![0u8; QC_HISTORY_MAX_ARTIFACT_BYTES + 1];
        assert_eq!(
            decode_artifact(&huge, &store.identity, 1),
            Err(QcHistoryError::Oversized)
        );
        // 真实文件被破坏（checksum 不符）
        let mut s = open(&dir, gh);
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        s.put(1, &qc).expect("put");
        let path = s.path_for(1);
        let mut bytes = fs::read(&path).expect("read");
        let n = bytes.len();
        bytes[n - 40] ^= 0x01; // 改 qc 区域 ⇒ checksum 不符
        fs::write(&path, &bytes).expect("write");
        assert_eq!(s.get(1), Err(QcHistoryError::ChecksumMismatch));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_evicts_deterministically() {
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("ret");
        let mut store = open(&dir, gh).with_retention(2);
        assert_eq!(store.retained(), 2);
        for h in 1..=4u64 {
            let qc = signed_qc(gh, h - 1, 0, [h as u8; 32]);
            store.put(h, &qc).expect("put");
        }
        // 只保留最近 2 个高度（4 淘汰 2 时删除 2；3 淘汰 1 时删除 1）
        assert!(!store.contains(1), "1 已被 retention 淘汰");
        assert!(!store.contains(2), "2 已被 retention 淘汰");
        assert!(store.contains(3));
        assert!(store.contains(4));
        assert_eq!(store.tip_height(), Some(4));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_serves_persisted_history() {
        // T12(a)：QC 已持久化 → （进程内）重新打开同一目录 ⇒ 仍可服务（无 stale 内存依赖）。
        let (g, _, _) = genesis2();
        let gh = compute_genesis_hash(&g).expect("hash");
        let dir = tmp_dir("reopen");
        let qc = signed_qc(gh, 0, 0, [0xAB; 32]);
        {
            let mut store = open(&dir, gh);
            store.put(1, &qc).expect("put");
        }
        let fresh = open(&dir, gh);
        assert_eq!(fresh.tip_height(), None, "新实例 tip 未知（不扫描目录）");
        assert_eq!(fresh.get(1).expect("get").expect("some"), qc);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validatorset_helper_is_used_by_fixture() {
        // 保证 fixture genesis 可构造真实 ValidatorSet（QC evidence 与 genesis 一致）。
        let (g, pk1, pk2) = genesis2();
        let set = ValidatorSet::from_genesis(&g);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&derive_validator_id(&pk1)));
        assert!(set.contains(&derive_validator_id(&pk2)));
    }
}
