//! O2 local Abandon attestation + **bounded** attestation accumulation（PHASE 6H-Z §6/§8/§9）。
//!
//! # 治理依据（全部 **FROZEN**；本模块不修改任何 ADR）
//! - `ADR-0066` RC-1/RC-2/RC-3/RC-4（S1 语义）/RC-5（域 `0x10`）/§4.1/§8/§10.1/§11
//! - `ADR-0070`（canonical 证书编码；`MAX_EVIDENCE_COUNT = 21`）
//! - `ADR-0072` §3.4（有限附随语义效果）
//! - Owner PHASE 6H-Z：D2-1 = D2-A、D2-2 = **真实本地 EXPIRE 才可签**、禁止历史/未来 round 补签、
//!   D2-3 = 无新增 safety-journal 义务
//!
//! # 安全边界（MUST）
//! - Abandon 签名**绝不**经 `ValidatorActor::sign_vote`、**绝不**写 vote safety journal、
//!   **绝不**写 block-safety journal：本模块**不 import** 任何 journal / `ValidatorActor` /
//!   `VoteLedger` / `QcRegistry` / `VoteAccumulator` 类型（结构性隔离）。
//! - 本模块**不**形成 QC、**不**进 `QcRegistry`、**不**进 `VoteAccumulator`、
//!   **不**触发 finality、**不**触碰 `LockedState`。
//! - 无持久化（`ADR-0066` §10.1：S1 **不产生**任何新增 journal 义务 ⇒ 无 journal、
//!   重启即丢、**不**写盘）。
//! - 无墙钟、无随机、无 I/O：同输入 ⇒ 同输出（确定性）。
//!
//! # 参数（§9 报告项；**全部为 implementation-bound，非协议共识参数**）
//!
//! | 参数 | 值 | 依据 / 理由 |
//! |---|---|---|
//! | `MAX_ATTESTATIONS_PER_ROUND` | **21** | = 冻结 `MAX_EVIDENCE_COUNT`（ADR-0070 §8）；非新参数，直接派生 |
//! | `MAX_TRACKED_ROUNDS` | **64** | implementation bound；与既有 `MAX_CERTIFICATES_PER_HEIGHT = 64`、`MAX_QC_REGISTRY_ENTRIES = 64` 同量级；覆盖 ≥ 3× 证据窗口 |
//! | 每 key 最大字节 | `21 × (32 + 64) = 2016` B | `validator_id(32) + signature(64)` × 21 |
//! | 池最大字节（上界） | `64 × 2016 ≈ 129 KiB` | key 数 × 每 key 上限（含 key 开销可忽略）；**有界** |
//! | `MAX_PENDING_BROADCAST` | **64** | 待广播证书队列上界（与 `MAX_CERTIFICATES_PER_HEIGHT` 同口径） |
//! | per-peer 贡献上限 | **不适用（N/A）** | 池按 `validator_id` 去重 ⇒ 一个 validator 最多贡献 1 条；**无需**额外 per-peer 配额（网络层 D3 限速负责 flooding） |
//! | 淘汰规则 | **确定性**：新 key 在 key 容量满时淘汰**最低** `(height, from_round)`（`BTreeMap` 首元素）；每 key 达 21 条后再来**新** `validator_id` ⇒ `Rejected(TooManyEvidence)`（**不** FIFO 丢弃已有证据 —— 证据排序 canonical，丢弃任意一条会引入非确定性选择） |
//! | 组建阈值 | **`ValidatorSet::quorum()`**（= `ceil(2T/3)` 冻结公式；**不**自定义） | ADR-0066 RC-3 |
//!
//! 以上**全部**为 node-local implementation bound，**不**进入 Genesi / Governance Parameters，
//! **不**写 ADR，**不**影响 consensus determinism（池状态不参与任何 consensus transition）。
//!
//! # ⚠ 未解决的协议前置（**不**由本模块解决；见 §17 报告）
//! ADR-0073 仅分配 `MessageType::ConsensusRoundChange = 0x0D`（**证书**）。
//! **没有**逐条 attestation 的 wire 类型 ⇒ 本池**无法**从对等节点接收单条 attestation
//! ⇒ 多验证人集合下**证书组建在网络中不可达**。本模块**不**发明/分配新 MessageType
//! （那将修改 ADR-0073 —— §1 绝对禁止）。
//!
//! # ⚠ 另一未解决前置：运行循环无 validator 签名能力
//! `NodeRuntime` 仅在构造时把 `KeyProvider::load_signer()` 交给 `ValidatorActor`，**不保留**
//! validator `SigningCapability`（模块 doc：*“不存储私钥（私钥在 SigningCapability 边界内）”*）
//! ⇒ 运行循环**无法**在真实本地 EXPIRE 时调用 [`produce_local_abandon`]。
//! 按 Owner 指令（*“如果当前代码结构无法可靠证明…不要猜。STOP AND REPORT”*），本阶段**不**
//! 自行新增签名入口 / 不二次调用 KeyProvider ⇒ 本模块保持**已实现 + 已测试但未接线**。
//!
//! ```text
//! PHASE 6H-AF 更新：本模块**已接入生产路径**（`NodeRuntime` 持有池；本地真实 EXPIRE ⇒ A-C 签名
//! ⇒ 池；入站 `0x0E` ⇒ ADR-0074 decode ⇒ 冻结验签 ⇒ 池）。原 `#![allow(dead_code)]` 已删除。
//! ```

use std::collections::BTreeMap;

use nova_consensus::round_change::{
    MAX_EVIDENCE_COUNT, RoundChangeCertificate, RoundChangeError, RoundChangeEvidence,
    verify_evidence,
};
use nova_consensus::validator::{ValidatorId, ValidatorSet};

use crate::runtime::{RoundTimer, RoundTimerTick};
use crate::signer::SigningCapability;

/// 每个 `(height, from_round)` 允许的最大 attestation 数（= 冻结 `MAX_EVIDENCE_COUNT`）。
pub const MAX_ATTESTATIONS_PER_ROUND: usize = MAX_EVIDENCE_COUNT;
/// 池跟踪的最大 `(height, from_round)` 键数（implementation bound）。
pub const MAX_TRACKED_ROUNDS: usize = 64;
/// 待广播证书队列上界（implementation bound）。
pub const MAX_PENDING_BROADCAST: usize = 64;

/// 本地 EXPIRE 观测 —— **唯一**允许产生 Abandon Attestation 的凭据（Owner D2-2）。
///
/// 只能由 [`LocalExpireObservation::from_expired_timer`] 构造，而该构造函数要求：
/// 1. `tick == RoundTimerTick::Expired`；**且**
/// 2. 计时器状态**确实到期**（`elapsed_ticks >= window_ticks`）。
///
/// ⇒ `(height, from_round)` **取自计时器本身**，调用方**不能**任意指定 round；
/// 对**未来** round 而言其计时器刚 ARM（`elapsed = 1`）⇒ 结构上不可能到期 ⇒ 不可能签未来 round；
/// 对**历史** round 而言本 token 已在那一 step 被消费（一次性 `Copy` 值 + 池去重）且运行循环
/// 只持有**当前**计时器 ⇒ 无补签入口。
///
/// 类型级限制说明（诚实）：本 token 不能阻止**同 crate 内**调用方伪造一个"看起来已到期"的
/// `RoundTimer` 值；防线 = ① 必须提供真的到期状态 ② 运行循环只传当前计时器 ③ 池按
/// `validator_id` 去重（同 key 二次签约幂等，不产生第二份不同字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalExpireObservation {
    height: u64,
    from_round: u64,
}

impl LocalExpireObservation {
    /// 由**真实**计时器到期构造（`tick` 必须为 `Expired` 且计时器在该单调读数下**确实**已到期）。
    pub(crate) fn from_expired_timer(
        timer: RoundTimer,
        tick: RoundTimerTick,
        now_ns: u64,
    ) -> Option<Self> {
        if tick != RoundTimerTick::Expired {
            return None;
        }
        if timer.elapsed_ns(now_ns) < timer.window_ns {
            return None;
        }
        Some(Self {
            height: timer.height,
            from_round: timer.round,
        })
    }

    /// 观测高度。
    pub(crate) fn height(&self) -> u64 {
        self.height
    }

    /// 观测的 `from_round`（方法名避开 `from_*` 约定：本方法是 getter，不是构造器）。
    pub(crate) fn observed_from_round(&self) -> u64 {
        self.from_round
    }
}

/// 本地产生一条 **S1 Abandon Attestation**（ADR-0066 §4.1）。
///
/// `Abandon(chain_id, height, from_round)` → `build_signed_bytes(Ed25519, 0x10, chain_id, 16B)` →
/// `SHA-256` → `SigningCapability::sign`（**仅接受已 domain-bound 的 `SigningMessageHash`**）。
///
/// **不**接触 vote 路径 / vote journal / block-safety journal（本模块无相关 import）。
/// `validator_id` 由**签名者公钥**派生（`SHA-256(consensus_public_key)`）—— 不接受调用方传入。
pub(crate) fn produce_local_abandon<S: SigningCapability + ?Sized>(
    signer: &S,
    chain_id: u64,
    observation: &LocalExpireObservation,
) -> Result<RoundChangeEvidence, RoundChangeError> {
    let message_hash = abandon_hash(
        chain_id,
        observation.height(),
        observation.observed_from_round(),
    )?;
    let signature = signer
        .sign(&message_hash)
        .map_err(|_| RoundChangeError::InvalidSignature)?;
    Ok(RoundChangeEvidence {
        validator_id: ValidatorId::from_consensus_public_key(&signer.public_key().to_bytes()),
        signature: signature.to_bytes(),
    })
}

/// `Abandon` 签名消息哈希（**委托**冻结实现；不建立第二套编码）。
fn abandon_hash(
    chain_id: u64,
    height: u64,
    from_round: u64,
) -> Result<nova_crypto::domain::SigningMessageHash, RoundChangeError> {
    nova_consensus::round_change::abandon_message_hash(chain_id, height, from_round)
}

/// 单次准入结果（互斥且穷尽；**只有** `Assembled` 携带可广播证书）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PoolOutcome {
    /// 已记录（幂等新增）；`weight` = 当前该 key 的累计权重。
    Recorded {
        /// 累计权重（distinct validator 之和）。
        weight: u128,
        /// 是否已达 quorum（未达 quorum 时为 `false`）。
        quorum: bool,
    },
    /// 已达 quorum ⇒ **恰好组装一张**证书（evidence 升序、无重复；`validator_set_id` 已绑定）。
    Assembled(RoundChangeCertificate),
    /// 该 `validator_id` 已存在（幂等；不增长）。
    Duplicate,
    /// 该 key 已组装过证书（不重复产生第二张）。
    AlreadyAssembled,
    /// 拒绝（冻结原因：非成员 / 身份不符 / 验签失败 / 项数超限 / 域失败 / 高度或 round 不符）。
    Rejected(RoundChangeError),
}

/// 单个 `(height, from_round)` 的累积状态。
#[derive(Debug, Clone)]
struct RoundEntry {
    /// `validator_id → evidence`（`BTreeMap` ⇒ 天然升序 + 天然去重）。
    evidence: BTreeMap<[u8; 32], RoundChangeEvidence>,
    /// 累计权重（distinct validator 之和）。
    weight: u128,
    /// 是否已组装并发出证书。
    assembled: bool,
}

impl RoundEntry {
    fn new() -> Self {
        Self {
            evidence: BTreeMap::new(),
            weight: 0,
            assembled: false,
        }
    }

    /// 估算字节数（`evidence × (32 + 64)`）。
    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.evidence.len() * (32 + 64)
    }
}

/// 有界 attestation 池（**确定**、**无持久化**、**无墙钟**、**无随机**）。
pub(crate) struct RoundChangeAttestationPool {
    /// 本池绑定的链（域绑定；不接受跨链 attestation）。
    chain_id: u64,
    /// 本池绑定的期望 `validator_set_id`（= genesis hash；ADR-0038 F-11 口径）。
    validator_set_id: [u8; 32],
    /// `(height, from_round) → entry`（`BTreeMap` ⇒ 确定性遍历 / 淘汰）。
    rounds: BTreeMap<(u64, u64), RoundEntry>,
    /// 键容量。
    max_rounds: usize,
    /// 每键容量。
    max_per_round: usize,
    /// 已组装、待广播的证书（有界 FIFO）。
    pending_broadcast: std::collections::VecDeque<RoundChangeCertificate>,
}

impl RoundChangeAttestationPool {
    /// 以默认上界构造（绑定 `chain_id` + `validator_set_id`）。
    pub(crate) fn new(chain_id: u64, validator_set_id: [u8; 32]) -> Self {
        Self::with_caps(
            chain_id,
            validator_set_id,
            MAX_TRACKED_ROUNDS,
            MAX_ATTESTATIONS_PER_ROUND,
        )
    }

    /// 以显式容量构造（容量 0 ⇒ 提升到 1；仅供测试）。
    pub(crate) fn with_caps(
        chain_id: u64,
        validator_set_id: [u8; 32],
        max_rounds: usize,
        max_per_round: usize,
    ) -> Self {
        Self {
            chain_id,
            validator_set_id,
            rounds: BTreeMap::new(),
            max_rounds: max_rounds.max(1),
            max_per_round: max_per_round.max(1),
            pending_broadcast: std::collections::VecDeque::new(),
        }
    }

    /// 本池绑定的 `chain_id`。
    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// 本池绑定的 `validator_set_id`（测试 / 诊断）。
    #[cfg(test)]
    pub(crate) fn validator_set_id(&self) -> [u8; 32] {
        self.validator_set_id
    }

    /// 跟踪的键数（有界；测试 / 诊断）。
    #[cfg(test)]
    pub(crate) fn tracked_rounds(&self) -> usize {
        self.rounds.len()
    }

    /// 指定 key 的 attestation 数（测试 / 诊断）。
    #[cfg(test)]
    pub(crate) fn attestations_at(&self, height: u64, from_round: u64) -> usize {
        self.rounds
            .get(&(height, from_round))
            .map_or(0, |e| e.evidence.len())
    }

    /// 池内 attestation 总数（测试 / 诊断）。
    #[cfg(test)]
    pub(crate) fn total_attestations(&self) -> usize {
        self.rounds.values().map(|e| e.evidence.len()).sum()
    }

    /// 估算字节数（上界；测试 / 诊断）。
    #[cfg(test)]
    pub(crate) fn bytes_estimate(&self) -> usize {
        self.rounds.values().map(RoundEntry::bytes).sum()
    }

    /// 待广播队列深度。
    pub(crate) fn pending_broadcast_len(&self) -> usize {
        self.pending_broadcast.len()
    }

    /// 取走全部待广播证书（FIFO；owned）。
    pub(crate) fn take_pending_broadcast(&mut self) -> Vec<RoundChangeCertificate> {
        self.pending_broadcast.drain(..).collect()
    }

    /// 准入一条 attestation（**逐条冻结验签** → 去重 → 累计权重 → 达 quorum 则组装证书）。
    ///
    /// 顺序（任一步失败 ⇒ 无副作用）：
    /// ① 冻结逐条验签 [`verify_evidence`]（membership → identity → 域 `0x10` → hash → `verify_strict`）
    /// ② 去重（`validator_id` 已存在 ⇒ [`PoolOutcome::Duplicate`]；不重复计权）
    /// ③ 项数上界（`max_per_round`；超限 ⇒ `Rejected(TooManyEvidence)`）
    /// ④ 组装（权重 ≥ `set.quorum()` ⇒ **恰好一张**证书；evidence 升序、无重复、`validator_set_id` 绑定）
    pub(crate) fn admit(
        &mut self,
        set: &ValidatorSet,
        height: u64,
        from_round: u64,
        evidence: &RoundChangeEvidence,
    ) -> PoolOutcome {
        // ① 冻结验签（唯一验证器；本层不新增/放宽任何条件）。
        let weight = match verify_evidence(evidence, self.chain_id, height, from_round, set) {
            Ok(w) => w,
            Err(e) => return PoolOutcome::Rejected(e),
        };
        let key = (height, from_round);
        // 键容量：新 key 满 ⇒ 确定性淘汰**最低** key（BTreeMap 首元素）。
        if !self.rounds.contains_key(&key) && self.rounds.len() >= self.max_rounds {
            let lowest = self.rounds.keys().next().copied();
            if let Some(lowest) = lowest {
                self.rounds.remove(&lowest);
            }
        }
        let entry = self.rounds.entry(key).or_insert_with(RoundEntry::new);
        if entry.assembled {
            return PoolOutcome::AlreadyAssembled;
        }
        // ② 去重（幂等；不增长、不重复计权）。
        if entry
            .evidence
            .contains_key(evidence.validator_id.as_bytes())
        {
            return PoolOutcome::Duplicate;
        }
        // ③ 项数上界（不 FIFO 丢弃已有证据 —— 见模块 doc 淘汰规则）。
        if entry.evidence.len() >= self.max_per_round {
            return PoolOutcome::Rejected(RoundChangeError::TooManyEvidence);
        }
        entry
            .evidence
            .insert(*evidence.validator_id.as_bytes(), *evidence);
        entry.weight = entry.weight.saturating_add(weight);
        let quorum = set.is_quorum(entry.weight);
        if !quorum {
            return PoolOutcome::Recorded {
                weight: entry.weight,
                quorum: false,
            };
        }
        // ④ 组装（BTreeMap 迭代 ⇒ validator_id 严格升序；键唯一 ⇒ 无重复）。
        let assembled: Vec<RoundChangeEvidence> = entry.evidence.values().copied().collect();
        entry.assembled = true;
        let certificate = RoundChangeCertificate {
            validator_set_id: self.validator_set_id,
            height,
            from_round,
            evidence: assembled,
        };
        if self.pending_broadcast.len() >= MAX_PENDING_BROADCAST {
            let _ = self.pending_broadcast.pop_front();
        }
        self.pending_broadcast.push_back(certificate.clone());
        PoolOutcome::Assembled(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::round::RoundTimeoutConfig;
    use nova_consensus::round_change::{abandon_signed_bytes, encode_certificate};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};

    use crate::runtime::{round_timeout_window_ns, round_timer_tick};
    use crate::signer::SoftwareSigner;

    const CHAIN_ID: u64 = 1001;
    const HEIGHT: u64 = 9;

    fn addr(kh: [u8; 32]) -> YazimaoAddress {
        YazimaoAddress::from_payload(YazimaoAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: CHAIN_ID,
            genesis_timestamp: 0,
            initial_validator_set: vals,
            initial_accounts: Vec::new(),
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 64 * 1024,
                max_block_bytes: 8 * 1024 * 1024,
                max_gas_per_block: 100_000_000_000,
                max_contract_code_bytes: 0,
                max_contract_storage_bytes: 0,
                epoch_length_blocks: 1_000_000,
                snapshot_interval_blocks: 10_000_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 1_000_000_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 100,
            },
        }
    }

    fn test_set(n: usize) -> (ValidatorSet, Vec<KeyPair>, [u8; 32]) {
        let mut kps: Vec<KeyPair> = Vec::new();
        let mut vals: Vec<ValidatorInit> = Vec::new();
        for i in 0..n {
            let kp = KeyPair::generate().expect("keypair");
            vals.push(ValidatorInit {
                account_address: addr([0xa0 + i as u8; 32]),
                consensus_public_key: kp.verifying_key().to_bytes(),
                bonded_stake: 100,
                commission_bps: 0,
            });
            kps.push(kp);
        }
        vals.sort_by_key(|v| v.consensus_public_key);
        let set = ValidatorSet::from_genesis(&genesis_with(vals));
        (set, kps, [0xAB; 32])
    }

    fn cfg() -> RoundTimeoutConfig {
        RoundTimeoutConfig {
            initial_timeout: 10,
            max_timeout: 100_000,
            backoff_factor: 2,
        }
    }

    /// 取得真实的「已到期计时器」状态（用于构造诚实 EXPIRE 观测）。
    ///
    /// A3：窗口为**单调时长** ⇒ 直接把单调读数设在**恰好到期边界**（`armed_at + window`），
    /// 无需循环推进 / 无需真实等待（确定性）。
    fn expired_timer(round: u64) -> (RoundTimer, RoundTimerTick) {
        let window = round_timeout_window_ns(&cfg(), round);
        let (armed, tick) = round_timer_tick(None, HEIGHT, round, window, false, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        round_timer_tick(Some(armed), HEIGHT, round, window, false, window)
    }

    /// 已到期读数（= `armed_at + window`；仅测试用，与 [`expired_timer`] 成对）。
    fn expired_now(timer: &RoundTimer) -> u64 {
        timer.armed_at_ns.saturating_add(timer.window_ns)
    }

    // -----------------------------------------------------------------------
    // §14 D2 1-7 —— 本地 Abandon 诚实规则
    // -----------------------------------------------------------------------

    #[test]
    fn d2_1_local_expire_creates_abandon() {
        let (_set, kps, _vsid) = test_set(1);
        let signer = SoftwareSigner::new(kps.into_iter().next().expect("kp"));
        let (timer, tick) = expired_timer(3);
        let obs = LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
            .expect("expired");
        assert_eq!((obs.height(), obs.observed_from_round()), (HEIGHT, 3));
        let ev = produce_local_abandon(&signer, CHAIN_ID, &obs).expect("abandon");
        // 签名必须可由签名者公钥验证（域 0x10 + chain + height + from_round 全在签名范围）。
        let hash = abandon_hash(CHAIN_ID, HEIGHT, 3).expect("hash");
        let vk = signer.public_key();
        let sig = Signature::from_bytes(&ev.signature).expect("sig");
        assert_eq!(verify_message_hash(&vk, &hash, &sig), Ok(()));
    }

    #[test]
    fn d2_2_no_expire_no_abandon() {
        // 未到期（Armed / Waiting）⇒ 无法构造观测 ⇒ 无法产生 Abandon。
        let w = 10_000_000u64; // 10ms（ns）
        let (timer, tick) = round_timer_tick(None, HEIGHT, 0, w, false, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert!(LocalExpireObservation::from_expired_timer(timer, tick, 0).is_none());
        // 窗口 − 1ns ⇒ Waiting（未到期）。
        let (timer2, tick2) = round_timer_tick(Some(timer), HEIGHT, 0, w, false, w - 1);
        assert_eq!(tick2, RoundTimerTick::Waiting);
        assert!(LocalExpireObservation::from_expired_timer(timer2, tick2, w - 1).is_none());
    }

    #[test]
    fn d2_4_future_round_cannot_be_signed() {
        // 未来 round 的计时器刚 ARM（已历时 = 0）⇒ 不可能到期 ⇒ 不可能产生观测。
        let window = round_timeout_window_ns(&cfg(), 4);
        let (armed, tick) = round_timer_tick(None, HEIGHT, 4, window, false, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(armed.elapsed_ns(0), 0, "刚 ARM");
        assert!(
            LocalExpireObservation::from_expired_timer(armed, RoundTimerTick::Expired, 0).is_none(),
            "已历时 < 窗口 ⇒ 即使伪造 tick 也必须被拒（双重守卫）"
        );
    }

    #[test]
    fn d2_3_observation_carries_timer_round_not_caller_choice() {
        // 观测的 (height, from_round) 只能来自计时器本身 ⇒ 无法为任意/历史 round 指定。
        let (timer, tick) = expired_timer(7);
        let obs = LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
            .expect("expired");
        assert_eq!(
            obs.observed_from_round(),
            timer.round,
            "from_round 必源于计时器"
        );
        assert_eq!(obs.height(), timer.height, "height 必源于计时器");
    }

    #[test]
    fn d2_5_abandon_uses_domain_0x10() {
        let (_set, kps, _vsid) = test_set(1);
        let signer = SoftwareSigner::new(kps.into_iter().next().expect("kp"));
        let (timer, tick) = expired_timer(2);
        let obs = LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
            .expect("expired");
        let ev = produce_local_abandon(&signer, CHAIN_ID, &obs).expect("abandon");
        let signed = abandon_signed_bytes(CHAIN_ID, HEIGHT, 2).expect("signed");
        assert_eq!(signed[0], 0x01, "algorithm = Ed25519");
        assert_eq!(signed[1], 0x10, "domain = RoundChangeCertificate");
        // validator_id 必须 = SHA-256(签名者公钥) 且与签名一致。
        let expected_vid = nova_consensus::validator::ValidatorId::from_consensus_public_key(
            &signer.public_key().to_bytes(),
        );
        assert_eq!(ev.validator_id, expected_vid);
    }

    #[test]
    fn d2_6_7_abandon_is_journal_free_and_vote_free() {
        // 结构性：本模块**不** import / 不触碰 ValidatorActor / VoteLedger / safety journal /
        // block-safety journal；唯一的签名入口是 `SigningCapability::sign`（只接受
        // 已 domain-bound 的 SigningMessageHash）。
        // 行为性：一次完整 Abandon 生产不产生任何副作用（无 I/O、无文件、无状态）。
        let (_set, kps, _vsid) = test_set(1);
        let signer = SoftwareSigner::new(kps.into_iter().next().expect("kp"));
        let (timer, tick) = expired_timer(5);
        let obs = LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
            .expect("expired");
        let a = produce_local_abandon(&signer, CHAIN_ID, &obs).expect("abandon");
        let b = produce_local_abandon(&signer, CHAIN_ID, &obs).expect("abandon");
        assert_eq!(
            a, b,
            "同一 (height, from_round) 的 Abandon 唯一（无 equivocation 面）"
        );
    }

    // -----------------------------------------------------------------------
    // §14 D2 8-13 —— 池：去重 / 拒绝 / quorum 组装 / 有界淘汰 / 待广播
    // -----------------------------------------------------------------------

    fn obs_for(round: u64) -> LocalExpireObservation {
        let (timer, tick) = expired_timer(round);
        LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
            .expect("expired")
    }

    /// 由**真实**本地 EXPIRE 观测 + 真实密钥产生一条 attestation（与 [`produce_local_abandon`]
    /// 同一冻结编码路径；此处直接使用 `KeyPair` 以便测试复用同一密钥）。
    fn attestation(kp: &KeyPair, round: u64) -> RoundChangeEvidence {
        let obs = obs_for(round);
        let hash = abandon_hash(CHAIN_ID, obs.height(), obs.observed_from_round()).expect("hash");
        let sig = nova_crypto::signature::sign_message_hash(kp.signing_key(), &hash);
        RoundChangeEvidence {
            validator_id: ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes()),
            signature: sig.to_bytes(),
        }
    }

    #[test]
    fn d2_8_duplicate_attestation_dedups() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let ev = attestation(&kps[0], 1);
        assert!(matches!(
            pool.admit(&set, HEIGHT, 1, &ev),
            PoolOutcome::Recorded { .. }
        ));
        assert_eq!(pool.admit(&set, HEIGHT, 1, &ev), PoolOutcome::Duplicate);
        assert_eq!(pool.attestations_at(HEIGHT, 1), 1, "去重不增长");
    }

    #[test]
    fn d2_9_invalid_signature_rejected() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let mut ev = attestation(&kps[0], 1);
        ev.signature[0] ^= 0xFF;
        assert_eq!(
            pool.admit(&set, HEIGHT, 1, &ev),
            PoolOutcome::Rejected(RoundChangeError::InvalidSignature)
        );
        assert_eq!(pool.total_attestations(), 0, "拒绝零副作用");
    }

    #[test]
    fn d2_10_insufficient_quorum_does_not_assemble() {
        // T = 3 ⇒ quorum = 2；仅 1 条 ⇒ 不组装。
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let out = pool.admit(&set, HEIGHT, 1, &attestation(&kps[0], 1));
        assert!(matches!(out, PoolOutcome::Recorded { quorum: false, .. }));
        assert_eq!(pool.pending_broadcast_len(), 0, "未达 quorum ⇒ 无证书");
    }

    #[test]
    fn d2_11_quorum_assembles_exactly_one_certificate() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let mut assembled: Option<RoundChangeCertificate> = None;
        let mut count = 0;
        for kp in &kps {
            if let PoolOutcome::Assembled(c) = pool.admit(&set, HEIGHT, 1, &attestation(kp, 1)) {
                assembled = Some(c);
                count += 1;
            }
        }
        assert_eq!(count, 1, "quorum 恰好在第 2 条达成 ⇒ 恰好组装 1 张");
        let cert = assembled.expect("certificate");
        assert_eq!(cert.validator_set_id, vsid);
        assert_eq!((cert.height, cert.from_round), (HEIGHT, 1));
        assert_eq!(cert.to_round().expect("to_round"), 2);
        assert_eq!(cert.evidence.len(), 2);
        // 第 3 条（已组装后）⇒ AlreadyAssembled（不产生第二张）。
        let third = pool.admit(&set, HEIGHT, 1, &attestation(&kps[2], 1));
        assert_eq!(third, PoolOutcome::AlreadyAssembled);
        assert_eq!(pool.pending_broadcast_len(), 1, "只广播 1 张");
        // 证书 canonical 编码可用（冻结 codec）。
        assert_eq!(
            encode_certificate(&cert).expect("encode").len(),
            cert.encoded_len()
        );
        // evidence 严格升序。
        for w in cert.evidence.windows(2) {
            assert!(w[0].validator_id < w[1].validator_id);
        }
    }

    #[test]
    fn d2_12_bounded_eviction_is_deterministic() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::with_caps(CHAIN_ID, vsid, 2, 21);
        let ev0 = attestation(&kps[0], 10);
        let ev1 = attestation(&kps[0], 11);
        let ev2 = attestation(&kps[0], 12);
        assert!(matches!(
            pool.admit(&set, HEIGHT, 10, &ev0),
            PoolOutcome::Recorded { .. }
        ));
        assert!(matches!(
            pool.admit(&set, HEIGHT, 11, &ev1),
            PoolOutcome::Recorded { .. }
        ));
        assert_eq!(pool.tracked_rounds(), 2);
        // 第 3 个 key ⇒ 淘汰最低 (HEIGHT, 10)。
        assert!(matches!(
            pool.admit(&set, HEIGHT, 12, &ev2),
            PoolOutcome::Recorded { .. }
        ));
        assert_eq!(pool.tracked_rounds(), 2, "键数有界");
        assert_eq!(pool.attestations_at(HEIGHT, 10), 0, "最低 key 被淘汰");
        assert_eq!(pool.attestations_at(HEIGHT, 11), 1);
        assert_eq!(pool.attestations_at(HEIGHT, 12), 1);
        // 内存上界可计算。
        assert!(pool.bytes_estimate() <= 2 * 21 * 96);
    }

    /// P1-A.30 **S5-3**：`MAX_PENDING_BROADCAST` 满 ⇒ **确定性丢最旧**（`pop_front`），队列有界。
    ///
    /// 本用例不使用任何"猜测"：溢出后**逐张核对**队列内容（首张 = 第 2 轮、末张 = 最后一张，
    /// 且严格升序）⇒ 可复现的 FIFO 语义。
    #[test]
    fn s5_pending_broadcast_overflow_drops_oldest_deterministically() {
        // T = 2 ⇒ quorum = 2 ⇒ 两条 attestation 即可组装（无需 3 个成员）。
        let (set, kps, vsid) = test_set(2);
        // 轮数容量足够（不与 `MAX_TRACKED_ROUNDS` 冲突），隔离本用例要观测的**待广播队列**上界。
        let mut pool = RoundChangeAttestationPool::with_caps(CHAIN_ID, vsid, 256, 21);
        let overflow = MAX_PENDING_BROADCAST + 1;
        for r in 0..overflow as u64 {
            for kp in &kps {
                let _ = pool.admit(&set, HEIGHT, r, &attestation(kp, r));
            }
        }
        assert_eq!(
            pool.pending_broadcast_len(),
            MAX_PENDING_BROADCAST,
            "待广播队列上界（有界）"
        );
        let drained = pool.take_pending_broadcast();
        assert_eq!(drained.len(), MAX_PENDING_BROADCAST);
        assert_eq!(
            drained[0].from_round, 1,
            "最旧（from_round = 0）被确定性丢弃"
        );
        assert_eq!(
            drained[drained.len() - 1].from_round,
            overflow as u64 - 1,
            "最新一张仍在队尾"
        );
        for w in drained.windows(2) {
            assert!(w[0].from_round < w[1].from_round, "FIFO 保序");
        }
        assert_eq!(pool.pending_broadcast_len(), 0, "取走后为空");
    }

    #[test]
    fn d2_13_assembled_certificate_enters_pending_broadcast_queue() {
        let (set, kps, vsid) = test_set(2);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        // T = 2 ⇒ quorum = 2 ⇒ 两条即可组装。
        for kp in &kps {
            let _ = pool.admit(&set, HEIGHT, 4, &attestation(kp, 4));
        }
        assert_eq!(pool.pending_broadcast_len(), 1);
        let drained = pool.take_pending_broadcast();
        assert_eq!(drained.len(), 1);
        assert_eq!(pool.pending_broadcast_len(), 0, "取走后为空");
        assert_eq!(pool.chain_id(), CHAIN_ID);
        assert_eq!(pool.validator_set_id(), vsid);
    }

    #[test]
    fn d2_pool_rejects_unknown_validator_and_wrong_binding() {
        let (set, _kps, vsid) = test_set(3);
        let (_other_set, other_kps, _) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        // 非成员（来自另一组 validator 的签名）
        let foreign = attestation(&other_kps[0], 1);
        assert_eq!(
            pool.admit(&set, HEIGHT, 1, &foreign),
            PoolOutcome::Rejected(RoundChangeError::UnknownValidator)
        );
        // 跨链绑定失败（用 CHAIN_ID+1 签的名，池绑定 CHAIN_ID）
        let kp = KeyPair::generate().expect("kp");
        let signer = SoftwareSigner::new(kp);
        let h = abandon_hash(CHAIN_ID + 1, HEIGHT, 1).expect("hash");
        let sig = signer.sign(&h).expect("sign");
        let ev = RoundChangeEvidence {
            validator_id: nova_consensus::validator::ValidatorId::from_consensus_public_key(
                &signer.public_key().to_bytes(),
            ),
            signature: sig.to_bytes(),
        };
        assert!(matches!(
            pool.admit(&set, HEIGHT, 1, &ev),
            PoolOutcome::Rejected(_)
        ));
    }

    #[test]
    fn d2_pool_is_pure_and_has_no_qc_surface() {
        // 结构性：本模块不 import QcRegistry / VoteAccumulator / FinalityState / LockedState /
        // ValidatorActor / VoteLedger（见模块头）。行为性：池操作不产生任何 QC 侧产物。
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        for kp in &kps {
            let _ = pool.admit(&set, HEIGHT, 2, &attestation(kp, 2));
        }
        // 证书的 evidence 仍是 RoundChangeEvidence（**不是** QcEvidence / ValidatorVote）。
        let certs = pool.take_pending_broadcast();
        assert_eq!(certs.len(), 1);
        // T = 3 ⇒ quorum = 2 ⇒ **恰好**第 2 条时组装（第 3 条 AlreadyAssembled）⇒ 2 条证据。
        assert_eq!(certs[0].evidence.len(), 2);
        // `VerifyingKey` 仅用于验签（无 lock / 无 finality 引用）。
        let vk = VerifyingKey::from_bytes(&kps[0].verifying_key().to_bytes()).expect("vk");
        assert_eq!(vk.to_bytes(), kps[0].verifying_key().to_bytes());
    }

    // -----------------------------------------------------------------------
    // PHASE 6H-AF §17 — A-C 签名路径 / 重复与冲突处置 / E2E
    // -----------------------------------------------------------------------

    /// §17 Signing：同一签名为**错误高度 / 错误 round** 验签失败（fail-closed，零状态变更）。
    /// 这是 ADR-0074 §10（跨高度 / 跨 round 重放防护）的可执行证据：`height` / `from_round`
    /// 均在签名范围内 ⇒ 换一个高度或 round 即验签失败。
    #[test]
    fn af_signing_wrong_height_or_round_fails_verification() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let ev = attestation(&kps[0], 3); // 为 (HEIGHT, 3) 的真实签名
        assert_eq!(
            pool.admit(&set, HEIGHT + 1, 3, &ev),
            PoolOutcome::Rejected(RoundChangeError::InvalidSignature),
            "wrong height"
        );
        assert_eq!(
            pool.admit(&set, HEIGHT, 4, &ev),
            PoolOutcome::Rejected(RoundChangeError::InvalidSignature),
            "wrong round"
        );
        assert_eq!(pool.total_attestations(), 0, "拒绝 ⇒ 零状态变更");
    }

    /// §17 Pool / ADR-0074 §11：同 `(height, from_round, validator_id)` 的第二实例
    /// —— 字节相同 ⇒ 幂等；字节不同 ⇒ 被拒（零状态变更）；**均无惩罚语义**。
    ///
    /// 注：RFC 8032 Ed25519 确定性 ⇒ 合规签名者对同一消息**不可能**产生第二份**有效**签名
    ///（ADR-0066 §4.1「不存在 equivocation 面」）⇒ 可观测路径只有「幂等」或「验签失败」两种。
    #[test]
    fn af_duplicate_and_conflicting_second_instance_are_no_ops() {
        let (set, kps, vsid) = test_set(3);
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let ev = attestation(&kps[0], 1);
        assert!(matches!(
            pool.admit(&set, HEIGHT, 1, &ev),
            PoolOutcome::Recorded { .. }
        ));
        let after_first = pool.total_attestations();
        // (a) 同字节 ⇒ 幂等（不增长）。
        assert_eq!(pool.admit(&set, HEIGHT, 1, &ev), PoolOutcome::Duplicate);
        assert_eq!(pool.total_attestations(), after_first);
        // (b) 不同字节 ⇒ 拒绝（fail-closed），零状态变更、无惩罚。
        let mut conflicting = ev;
        conflicting.signature[0] ^= 0xFF;
        assert_eq!(
            pool.admit(&set, HEIGHT, 1, &conflicting),
            PoolOutcome::Rejected(RoundChangeError::InvalidSignature)
        );
        assert_eq!(pool.total_attestations(), after_first, "无状态变更");
    }

    /// §17 E2E（进程内；全部经**冻结**工件）：
    /// 真实本地 EXPIRE → A-C 签名 → ADR-0074 112B wire → decode → 冻结验签 → 池 → quorum
    /// → ADR-0070 证书 → `0x0D` canonical bytes → `verify_certificate` → D1 权威应用
    /// → 恰好 `+1` → 计时器重开（新 round 的新鲜窗口）。
    #[test]
    fn af_e2e_expire_sign_wire_pool_certificate_authority() {
        use crate::assembly::ConsensusNode;
        use crate::round_change_inbound::{RoundChangeApplication, apply_verified_round_change};
        use crate::runtime::round_timer_tick;
        use crate::signer::SoftwareSigner;
        use crate::validator::ValidatorActor;
        use nova_consensus::dag::Dag;
        use nova_consensus::validator::ValidatorId;

        let (set, kps, vsid) = test_set(3);
        let local_round = 5u64;

        // ① 真实本地 EXPIRE 观测（来自真实到期计时器状态；非手工构造）。
        let (timer, tick) = expired_timer(local_round);
        let observation =
            LocalExpireObservation::from_expired_timer(timer, tick, expired_now(&timer))
                .expect("real expire");
        assert_eq!(observation.observed_from_round(), local_round);

        // ② A-C：每个 validator 用自己的 actor 签（使用**已有** signer；不触 vote/journal）。
        let mut actors: Vec<ValidatorActor<SoftwareSigner>> = Vec::new();
        for kp in kps {
            let vid = ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes());
            actors
                .push(ValidatorActor::new(vid, SoftwareSigner::new(kp), CHAIN_ID).expect("actor"));
        }

        // ③ ADR-0074 canonical container（精确 112B）—— 模拟 wire 字节。
        let mut wire_payloads: Vec<Vec<u8>> = Vec::new();
        for actor in &actors {
            let evidence = actor
                .sign_abandon(CHAIN_ID, &observation)
                .expect("abandon signature");
            let container = nova_network::abandon_attestation::AbandonAttestation {
                height: observation.height(),
                from_round: observation.observed_from_round(),
                validator_id: *evidence.validator_id.as_bytes(),
                signature: evidence.signature,
            };
            let bytes = nova_network::abandon_attestation::encode(&container);
            assert_eq!(bytes.len(), 112);
            wire_payloads.push(bytes);
        }

        // ④ 入站路径：decode → 池 `admit`（内含冻结 `verify_evidence`）→ 池。
        let mut pool = RoundChangeAttestationPool::new(CHAIN_ID, vsid);
        let mut assembled: Vec<RoundChangeCertificate> = Vec::new();
        for bytes in &wire_payloads {
            let container =
                nova_network::abandon_attestation::decode(bytes).expect("container decode");
            let evidence = RoundChangeEvidence {
                validator_id: ValidatorId::from_bytes(container.validator_id),
                signature: container.signature,
            };
            if let PoolOutcome::Assembled(cert) =
                pool.admit(&set, container.height, container.from_round, &evidence)
            {
                assembled.push(cert);
            }
        }
        assert_eq!(assembled.len(), 1, "T = 3 ⇒ quorum = 2 ⇒ 恰好组装 1 张证书");
        let certificate = assembled.into_iter().next().expect("certificate");

        // ⑤ 既有 0x0D：ADR-0070 canonical bytes → decode → 冻结证书验证。
        let cert_bytes =
            nova_consensus::round_change::encode_certificate(&certificate).expect("encode");
        let decoded =
            nova_consensus::round_change::decode_certificate(&cert_bytes).expect("decode");
        assert_eq!(decoded, certificate);
        let transition = nova_consensus::round_change::verify_certificate(
            &decoded,
            CHAIN_ID,
            &vsid,
            &set,
            local_round,
        )
        .expect("certificate verifies");
        assert_eq!(
            (transition.from_round, transition.to_round),
            (local_round, local_round + 1)
        );

        // ⑥ D1 权威应用：复用既有冻结 transition ⇒ 恰好 +1 + 计时器重开。
        let mut node = ConsensusNode::new(HEIGHT, local_round, CHAIN_ID, set, vsid, Dag::new());
        let config = cfg();
        let prior = round_timer_tick(
            None,
            HEIGHT,
            local_round,
            round_timeout_window_ns(&config, local_round),
            false,
            0,
        )
        .0;
        match apply_verified_round_change(
            &mut node,
            &decoded,
            &vsid,
            local_round,
            &config,
            Some(prior),
            0,
        ) {
            RoundChangeApplication::Applied {
                transition: t,
                timer,
                tick,
            } => {
                assert_eq!((t.from_round, t.to_round), (local_round, local_round + 1));
                assert_eq!(node.state().round.round, local_round + 1, "恰好 +1");
                assert_eq!(tick, RoundTimerTick::Armed);
                assert_eq!(timer.armed_at_ns, 0, "不继承 stale deadline");
                assert_eq!(timer.elapsed_ns(0), 0);
                assert_eq!(timer.round, local_round + 1);
                assert_eq!(
                    timer.window_ns,
                    round_timeout_window_ns(&config, local_round + 1)
                );
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }
}
