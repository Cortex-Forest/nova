//! O2 Round-Change **Inbound Authority Seam**（PHASE 6H-Y；items 17 / 18 / 20）。
//!
//! # 治理依据（全部 **FROZEN**；本模块不修改、不重定义任何语义）
//! - `ADR-0066` round-change certificate v1（结构 / `to_round = from_round + 1` / RC ≠ QC）
//! - `ADR-0070` canonical serialization v1（编码由 `nova-consensus` 承载）
//! - `ADR-0072` ADR-0049 round-change authority amendment v1（§3.4 **有限附随语义效果**：
//!   `valid RoundChangeCertificate` 构成 ADR-0049 §3.4.1 所引用的 round-change authority；
//!   **不**编辑 §3.4.1、**不**改 timer semantics、**不**改 RESET / NO-OP / STOP / EXPIRE 矩阵、
//!   **不**引入 QC / finality / lock override / vote 等价物、仍只允许 `+1`）
//! - `ADR-0049` §3.3（round transition **MUST NOT** inherit stale deadline）
//! - `ADR-0073` wire allocation（`MessageType::ConsensusRoundChange = 0x0D`，仅 wire）
//!
//! # 唯一语义结果（严格边界）
//! 被接受的证书**只**产生一件事：本地 round `+1`，并且该 round 的计时器窗口**重开**
//!（`elapsed = 1`、`window = window(to_round)`；**不**继承旧 window / 旧 elapsed）。
//!
//! **绝不**产生：vote / QC / finality / lock 变更 / DAG 变更 / 广播（本模块**不**持有任何
//! `VoteAccumulator` / `QcRegistry` / `RoundEvidence` / `LockedState` 句柄，也**不**调用
//! `assemble_qc` / `verify_qc` / `admit`）。
//!
//! # 复用而非重实现
//! - 证书验证：委托冻结的 [`nova_consensus::round_change::verify_certificate`]（V-5 五步 +
//!   成员 / `validator_set_id` / 严格升序 / 无重复 / quorum / `+1` / 非 stale）。
//! - 计时窗口：委托既有 node-local [`crate::runtime::round_timeout_window_ticks`]
//!  （冻结 `RoundTimeoutConfig` 语义），并复用既有 [`crate::runtime::round_timer_tick`] 的
//!   ARM / 替换状态机 —— 本模块**不**建立第二套计时器。

use nova_consensus::integration::TransitionResult;
use nova_consensus::round::RoundTimeoutConfig;
use nova_consensus::round_change::{
    RoundChangeCertificate, RoundChangeError, RoundChangeTransition, verify_certificate,
};
use nova_consensus::validator::ValidatorSet;

use crate::assembly::ConsensusNode;
use crate::runtime::{RoundTimer, RoundTimerTick, round_timeout_window_ns, round_timer_tick};

/// 入站 round-change 证书的**唯一**判定结果（无 QC / 无 vote / 无 finality 分量）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundChangeDecision {
    /// 接受：本地 round `+1`（`transition.to_round = transition.from_round + 1`）。
    Apply(RoundChangeTransition),
    /// 拒绝：证书不满足冻结验收条件（含 stale / 非 `+1` 可派生 / quorum 不足等）。
    ///
    /// 拒绝**不**产生任何副作用：不推进 round、不重开计时器、不改变任何状态。
    Reject(RoundChangeError),
}

impl RoundChangeDecision {
    /// 是否被接受。
    pub fn is_apply(&self) -> bool {
        matches!(self, Self::Apply(_))
    }

    /// 接受时的目标 round（`from_round + 1`）。
    pub fn to_round(&self) -> Option<u64> {
        match self {
            Self::Apply(t) => Some(t.to_round),
            Self::Reject(_) => None,
        }
    }
}

/// 入站证书判定（**纯函数**：同输入同输出；无墙钟 / 无随机 / 无 I/O / 无全局状态）。
///
/// 全部验收条件由冻结的 `verify_certificate` 承担（本函数只做结果映射，**不**新增 / 放宽 /
/// 收紧任何条件）。`local_round` 由调用方显式给出（`to_round <= local_round` ⇒ 拒绝）。
pub fn decide_round_change(
    cert: &RoundChangeCertificate,
    chain_id: u64,
    expected_validator_set_id: &[u8; 32],
    set: &ValidatorSet,
    local_round: u64,
) -> RoundChangeDecision {
    match verify_certificate(cert, chain_id, expected_validator_set_id, set, local_round) {
        Ok(transition) => RoundChangeDecision::Apply(transition),
        Err(error) => RoundChangeDecision::Reject(error),
    }
}

/// 接受后新 round 的计时窗口（**纳秒**；**委托**既有 node-local 窗口函数）。
///
/// 语义 = `min(initial × backoff^to_round, max)`（`RoundTimeoutConfig`，毫秒）⇒ 纳秒；下界 1 ms。
pub fn rearm_window_ns(config: &RoundTimeoutConfig, to_round: u64) -> u64 {
    round_timeout_window_ns(config, to_round)
}

/// 接受后的计时器**重开**（ADR-0049 §3.3：round transition MUST NOT inherit stale deadline）。
///
/// `prev` = 旧（已到期 / 已过期）计时器；结果对新 `(height, to_round)` **重新 ARM**：
/// `elapsed = 1`（arming step 计入新 round）、`window = rearm_window_ticks(config, to_round)`。
///
/// 复用既有 [`round_timer_tick`]（`same_round == false` ⇒ `Armed`）：**不**建立第二套状态机、
/// **不**继承旧 `elapsed_ticks` / 旧 `window_ticks`。
///
/// `pub(crate)`：返回类型为既有 node-local `RoundTimer`（crate 内部类型），
/// 保持「不把内部计时器类型泄漏到 crate 公开 API」的边界。
///
/// `#[allow(dead_code)]` 已移除（PHASE 6H-Z D1-4）：本函数现已由
/// [`apply_verified_round_change`] 在运行路径上调用。
pub(crate) fn rearm_after_round_change(
    prev: Option<RoundTimer>,
    height: u64,
    to_round: u64,
    config: &RoundTimeoutConfig,
    now_ns: u64,
) -> (RoundTimer, RoundTimerTick) {
    round_timer_tick(
        prev,
        height,
        to_round,
        rearm_window_ns(config, to_round),
        false,
        now_ns,
    )
}

/// 节点层 RC 权威路径的**唯一**结果（PHASE 6H-Z；Owner D1-1 = D1-B）。
///
/// 三个分支互斥且穷尽；**只有** [`Self::Applied`] 会产生 round 前进。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundChangeApplication {
    /// `from_round == local_round`：已应用 —— 本地 round 恰为 `+1`，且计时器已为新 round **重开**。
    Applied {
        /// 冻结转移结果（round +1）。
        transition: RoundChangeTransition,
        /// 新 round 的计时器（`elapsed = 1`；**不**继承 stale deadline）。
        timer: RoundTimer,
        /// 计时器推进结果（必须为 `Armed`）。
        tick: RoundTimerTick,
    },
    /// `from_round > local_round`（Owner G-1 裁定）：**仅暂存** —— 不推进、不重开计时器。
    Stored {
        /// 已验证的转移（未来 round）；供调用方入 bounded store。
        transition: RoundChangeTransition,
    },
    /// 拒绝（含 stale / overflow / 非成员 / 验签失败 / quorum 不足 / 高度不符）：**零副作用**。
    Rejected {
        /// 冻结拒绝原因。
        error: RoundChangeError,
    },
}

/// 节点层**权威应用**（PHASE 6H-Z；Owner D1-1 = D1-B / G-1 / G-2）。
///
/// 流程（严格顺序；任一步不满足 ⇒ 立即返回且**零副作用**）：
/// ① 冻结验证 [`verify_certificate`]（唯一验证器；本层**不**新增 / 放宽 / 收紧任何验收条件）
/// ② **高度适用性**：`cert.height` 必须 == 本地高度（ADR-0066 §6.2「wrong height」；
///    `verify_certificate` 无本地高度参数 ⇒ 由本层补齐，属**实现**冻结拒绝原因，非新增条件）
/// ③ **G-1**：`from_round != local_round` ⇒ [`RoundChangeApplication::Stored`]（仅暂存）
/// ④ **检查-应用竞态守卫**：重新读取 `(height, round)`，若已变化 ⇒ fail-closed 拒绝
/// ⑤ 调用**既有冻结**转移（`ConsensusNode::round_timeout()`；**不**新增 consensus primitive /
///    **不**新增 `ConsensusEvent`；`checked_successor` 仍是唯一 round 转移原语）
/// ⑥ **双重自增 / 跳轮守卫**：转移后 round 必须恰为 `old + 1` 且 == `transition.to_round`
/// ⑦ 重开既有计时器（ADR-0066 §11 / ADR-0049 §3.3：不继承 stale deadline）
///
/// **绝不**产生：vote / QC / finality / lock / DAG 变更 / `round_evidence` 以外的任何状态
/// （`round_evidence.reset` 由冻结转移自带，属 ADR-0049 §3.9 的 frozen Round Change 矩阵）。
///
/// 呼叫方（`NodeRuntime`）据 [`RoundChangeApplication::Applied`] 递增**独立归因**计数
/// `round_changes_by_authority`（Owner G-2 / D1-3）—— **不**并入 `round_timeouts`。
pub(crate) fn apply_verified_round_change(
    node: &mut ConsensusNode,
    cert: &RoundChangeCertificate,
    expected_validator_set_id: &[u8; 32],
    local_round: u64,
    config: &RoundTimeoutConfig,
    prior_timer: Option<RoundTimer>,
    now_ns: u64,
) -> RoundChangeApplication {
    // ① 冻结验证（唯一验证器）。
    let transition = match decide_round_change(
        cert,
        node.chain_id(),
        expected_validator_set_id,
        node.validator_set(),
        local_round,
    ) {
        RoundChangeDecision::Apply(t) => t,
        RoundChangeDecision::Reject(error) => return RoundChangeApplication::Rejected { error },
    };
    // ② 高度适用性（冻结 §6.2「wrong height」）。
    if cert.height != node.state().round.height {
        return RoundChangeApplication::Rejected {
            error: RoundChangeError::WrongHeight,
        };
    }
    // ③ G-1：future round ⇒ 仅暂存（不推进 / 不重开）。
    if transition.from_round != local_round {
        return RoundChangeApplication::Stored { transition };
    }
    // ④ 检查-应用竞态守卫（单线程 step 循环内亦显式断言）。
    if node.state().round.round != local_round {
        return RoundChangeApplication::Rejected {
            error: RoundChangeError::StaleCertificate,
        };
    }
    let before = node.state().round.round;
    // ⑤ 既有冻结转移（唯一 round 转移原语）。
    let result = node.round_timeout();
    if !matches!(result, TransitionResult::Applied { .. }) {
        return RoundChangeApplication::Rejected {
            error: RoundChangeError::RoundOverflow,
        };
    }
    // ⑥ 双重自增 / 跳轮守卫。
    let after = node.state().round.round;
    if after != transition.to_round || after != before.saturating_add(1) {
        return RoundChangeApplication::Rejected {
            error: RoundChangeError::StaleCertificate,
        };
    }
    // ⑦ 重开既有计时器（新 round；不继承 stale deadline；armed_at = 本 step 单调读数）。
    let (timer, tick) = rearm_after_round_change(
        prior_timer,
        node.state().round.height,
        transition.to_round,
        config,
        now_ns,
    );
    RoundChangeApplication::Applied {
        transition,
        timer,
        tick,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_consensus::dag::Dag;
    use nova_consensus::integration::QcRegistry;
    use nova_consensus::round::RoundStep;
    use nova_consensus::round_change::{
        RoundChangeEvidence, abandon_message_hash, encode_certificate,
    };
    use nova_consensus::validator::{ValidatorId, ValidatorSet};
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, YazimaoAddress, YazimaoAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;

    const CHAIN_ID: u64 = 1001;
    const HEIGHT: u64 = 5;

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
            let pk = kp.verifying_key().to_bytes();
            vals.push(ValidatorInit {
                account_address: addr([0xa0 + i as u8; 32]),
                consensus_public_key: pk,
                bonded_stake: 100,
                commission_bps: 0,
            });
            kps.push(kp);
        }
        vals.sort_by_key(|v| v.consensus_public_key);
        let set = ValidatorSet::from_genesis(&genesis_with(vals));
        (set, kps, [0xAB; 32])
    }

    /// 构造有效证书（全部 n 个 validator 签名）。
    fn cert(
        set: &ValidatorSet,
        kps: &[KeyPair],
        vsid: &[u8; 32],
        from_round: u64,
    ) -> RoundChangeCertificate {
        let mut ids: Vec<ValidatorId> = kps
            .iter()
            .map(|kp| ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes()))
            .collect();
        // 本地 ValidatorSet 是成员权威来源：evidence 不得超出其规模。
        assert!(ids.len() <= set.len(), "evidence 超出本地 ValidatorSet");
        ids.sort();
        let hash = abandon_message_hash(CHAIN_ID, HEIGHT, from_round).expect("hash");
        let by_id = |id: &ValidatorId| -> &KeyPair {
            kps.iter()
                .find(|kp| {
                    &ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes()) == id
                })
                .expect("key present")
        };
        let evidence = ids
            .iter()
            .map(|id| {
                let kp = by_id(id);
                RoundChangeEvidence {
                    validator_id: *id,
                    signature: sign_message_hash(kp.signing_key(), &hash).to_bytes(),
                }
            })
            .collect();
        RoundChangeCertificate {
            validator_set_id: *vsid,
            height: HEIGHT,
            from_round,
            evidence,
        }
    }

    fn cfg() -> RoundTimeoutConfig {
        // max 足够大 ⇒ 窗口随 round 严格增长（便于断言「新轮窗口 = window(to_round)」）。
        RoundTimeoutConfig {
            initial_timeout: 10,
            max_timeout: 100_000,
            backoff_factor: 2,
        }
    }

    // -----------------------------------------------------------------------
    // item 17 —— local round +1 transition only
    // -----------------------------------------------------------------------

    #[test]
    fn accepted_certificate_yields_exactly_plus_one() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 7);
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 7);
        let RoundChangeDecision::Apply(t) = d else {
            panic!("expected Apply, got {d:?}");
        };
        assert_eq!(t.from_round, 7);
        assert_eq!(t.to_round, 8, "唯一语义 = +1");
        assert_eq!(d.to_round(), Some(8));
        assert!(d.is_apply());
    }

    #[test]
    fn stale_certificate_is_rejected_without_side_effect() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 3);
        // local_round = 3 ⇒ to_round = 4 > 3 ⇒ 仍可接受；local_round = 4 ⇒ to_round = 4 ⇒ stale。
        assert!(decide_round_change(&c, CHAIN_ID, &vsid, &set, 3).is_apply());
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 4);
        assert_eq!(
            d,
            RoundChangeDecision::Reject(RoundChangeError::StaleCertificate)
        );
        assert_eq!(d.to_round(), None, "拒绝不得给出目标 round");
    }

    #[test]
    fn overflow_round_cannot_produce_successor() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, u64::MAX);
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 0);
        assert_eq!(
            d,
            RoundChangeDecision::Reject(RoundChangeError::RoundOverflow)
        );
    }

    #[test]
    fn wrong_chain_and_validator_set_are_rejected() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 1);
        assert_eq!(
            decide_round_change(&c, CHAIN_ID + 1, &vsid, &set, 0),
            RoundChangeDecision::Reject(RoundChangeError::InvalidSignature)
        );
        assert_eq!(
            decide_round_change(&c, CHAIN_ID, &[0xCD; 32], &set, 0),
            RoundChangeDecision::Reject(RoundChangeError::ValidatorSetMismatch)
        );
    }

    // -----------------------------------------------------------------------
    // item 18 / §18-20 / §18-21 —— timer re-arm + expired timer replacement
    // -----------------------------------------------------------------------

    #[test]
    fn accepted_certificate_rearms_timer_for_new_round() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 7);
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 7);
        let to_round = d.to_round().expect("accepted");
        let config = cfg();

        // 旧 round 的计时器（armed_at 为旧读数、window 为旧轮窗口）。
        let stale = RoundTimer {
            height: HEIGHT,
            round: 7,
            armed_at_ns: 0,
            window_ns: rearm_window_ns(&config, 7),
        };
        let now_ns: u64 = 1_000_000_000; // 1s（任意确定读数；仅验"不继承 deadline"）
        let (next, tick) = rearm_after_round_change(Some(stale), HEIGHT, to_round, &config, now_ns);
        assert_eq!(tick, RoundTimerTick::Armed, "新 round ⇒ 重新 ARM");
        assert_eq!((next.height, next.round), (HEIGHT, to_round));
        assert_eq!(
            next.armed_at_ns, now_ns,
            "ADR-0049 §3.3：不继承 stale deadline（armed_at = 本 step 单调读数）"
        );
        assert_eq!(next.elapsed_ns(now_ns), 0, "ARM 时刻已历时 = 0");
        assert_eq!(next.window_ns, rearm_window_ns(&config, to_round));
        assert_ne!(
            next.window_ns, stale.window_ns,
            "新轮窗口 = window(to_round)（退避后更大）"
        );
        assert!(next.elapsed_ns(now_ns) < next.window_ns, "重开后不立即到期");
    }

    #[test]
    fn expired_timer_is_replaced_not_inherited() {
        let config = cfg();
        let window0 = rearm_window_ns(&config, 0);
        // ARM @ 单调读数 0。
        let (armed, tick) = round_timer_tick(None, HEIGHT, 0, window0, false, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(armed.elapsed_ns(0), 0, "ARM 时刻已历时 = 0");
        // 窗口 − 1ns ⇒ 未到期。
        let (t1, tick) = round_timer_tick(Some(armed), HEIGHT, 0, window0, false, window0 - 1);
        assert_eq!(tick, RoundTimerTick::Waiting, "尚未到期");
        assert_eq!(t1.elapsed_ns(window0 - 1), window0 - 1);
        // 恰好到期（边界 `>=`）。
        let (expired_after, t) = round_timer_tick(Some(armed), HEIGHT, 0, window0, false, window0);
        assert_eq!(t, RoundTimerTick::Expired, "恰好到期");
        assert_eq!(expired_after.elapsed_ns(window0), window0);

        // 到期后 round +1 ⇒ 计时器【替换】（不是继承旧 deadline / 旧 window）。
        let now_ns = window0.saturating_add(1);
        let (replacement, tick) =
            rearm_after_round_change(Some(expired_after), HEIGHT, 1, &config, now_ns);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(replacement.armed_at_ns, now_ns);
        assert_eq!(replacement.elapsed_ns(now_ns), 0, "不继承旧已历时");
        assert_eq!(
            replacement.window_ns,
            rearm_window_ns(&config, 1),
            "新轮窗口"
        );
        assert!(replacement.window_ns >= expired_after.window_ns);
    }

    #[test]
    fn rearm_is_deterministic_and_bounded_on_extreme_round() {
        let config = cfg();
        assert_eq!(
            rearm_window_ns(&config, u64::MAX),
            rearm_window_ns(&config, u64::MAX),
            "确定性"
        );
        assert_eq!(
            rearm_window_ns(&config, u64::MAX),
            config.max_timeout.saturating_mul(1_000_000),
            "极大 round ⇒ 饱和到 cap（ms → ns）"
        );
        let (t, tick) = rearm_after_round_change(None, HEIGHT, u64::MAX, &config, 0);
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(t.armed_at_ns, 0);
        assert_eq!(t.window_ns, config.max_timeout.saturating_mul(1_000_000));
    }

    // -----------------------------------------------------------------------
    // PHASE 6H-Z §14-D1 1-10 —— 节点层权威应用（apply_verified_round_change）
    // -----------------------------------------------------------------------

    /// 构造一个真实的 `ConsensusNode`（height = HEIGHT，round = `round`；
    /// `genesis_hash` = 证书 `validator_set_id` 同一值）。
    fn test_node(round: u64, n: usize) -> (ConsensusNode, Vec<KeyPair>, [u8; 32]) {
        let (set, kps, vsid) = test_set(n);
        let node = ConsensusNode::new(HEIGHT, round, CHAIN_ID, set, vsid, Dag::new());
        (node, kps, vsid)
    }

    #[test]
    fn d1_1_5_exact_current_round_certificate_applies_exactly_plus_one() {
        let (mut node, kps, vsid) = test_node(3, 3);
        let c = cert(&node.validator_set().clone(), &kps, &vsid, 3);
        let config = cfg();
        let before_finality = node.state().finality.clone();
        let outcome = apply_verified_round_change(&mut node, &c, &vsid, 3, &config, None, 0);
        let RoundChangeApplication::Applied {
            transition,
            timer,
            tick,
        } = outcome
        else {
            panic!("expected Applied, got {outcome:?}");
        };
        assert_eq!((transition.from_round, transition.to_round), (3, 4));
        assert_eq!(node.state().round.round, 4, "恰好 +1");
        assert_eq!(node.state().round.height, HEIGHT, "height 不变");
        // §14-D1-6：finality 不变。
        assert_eq!(node.state().finality, before_finality, "finality 不变");
        // §14-D1-10：timer 已为新 round 重开（armed_at = 本 step 读数；窗口 = window(to_round)）。
        assert_eq!(tick, RoundTimerTick::Armed);
        assert_eq!(
            (timer.height, timer.round, timer.armed_at_ns),
            (HEIGHT, 4, 0)
        );
        assert_eq!(timer.elapsed_ns(0), 0, "ARM 时刻已历时 = 0");
        assert_eq!(timer.window_ns, rearm_window_ns(&config, 4));
        // RoundState 按 ADR-0049 §3.9 重置（proposal/step/accumulator）。
        assert!(node.state().round.proposal.is_none());
        assert_eq!(node.state().round.step, RoundStep::Propose);
    }

    #[test]
    fn d1_2_future_from_round_is_store_only_no_progress_no_rearm() {
        let (mut node, kps, vsid) = test_node(3, 3);
        let c = cert(&node.validator_set().clone(), &kps, &vsid, 5);
        let config = cfg();
        let before_finality = node.state().finality.clone();
        let outcome = apply_verified_round_change(&mut node, &c, &vsid, 3, &config, None, 0);
        let RoundChangeApplication::Stored { transition } = outcome else {
            panic!("expected Stored, got {outcome:?}");
        };
        assert_eq!((transition.from_round, transition.to_round), (5, 6));
        assert_eq!(node.state().round.round, 3, "G-1：future round ⇒ 不推进");
        assert_eq!(node.state().finality, before_finality);
        // 计时器未重开（调用方以 `Application` 分支决定是否 arm）。
        assert!(!matches!(outcome, RoundChangeApplication::Applied { .. }));
    }

    #[test]
    fn d1_3_stale_certificate_rejected() {
        let (mut node, kps, vsid) = test_node(3, 3);
        // from_round = 2 ⇒ to_round = 3 <= local_round 3 ⇒ stale（无回退）。
        let c = cert(&node.validator_set().clone(), &kps, &vsid, 2);
        let outcome = apply_verified_round_change(&mut node, &c, &vsid, 2, &cfg(), None, 0);
        assert_eq!(
            outcome,
            RoundChangeApplication::Rejected {
                error: RoundChangeError::StaleCertificate
            }
        );
        assert_eq!(node.state().round.round, 3, "拒绝 ⇒ 零 round 变化");
    }

    #[test]
    fn d1_4_overflow_rejected() {
        let (mut node, kps, vsid) = test_node(u64::MAX, 3);
        let c = cert(&node.validator_set().clone(), &kps, &vsid, u64::MAX);
        let outcome = apply_verified_round_change(&mut node, &c, &vsid, u64::MAX, &cfg(), None, 0);
        assert_eq!(
            outcome,
            RoundChangeApplication::Rejected {
                error: RoundChangeError::RoundOverflow
            }
        );
        assert_eq!(
            node.state().round.round,
            u64::MAX,
            "overflow ⇒ 不 wrap / 不推进"
        );
    }

    #[test]
    fn d1_wrong_height_rejected_and_unknown_validator_rejected() {
        let (mut node, kps, vsid) = test_node(3, 3);
        // 高度不符：必须用**为该高度真实签名**的证书，否则冻结验证器会先以 `InvalidSignature`
        // 拒绝（顺序正确：冻结验证在前，节点层适用性前置在后）。
        let c = cert_at_height(&node.validator_set().clone(), &kps, &vsid, HEIGHT + 1, 3);
        assert_eq!(
            apply_verified_round_change(&mut node, &c, &vsid, 3, &cfg(), None, 0),
            RoundChangeApplication::Rejected {
                error: RoundChangeError::WrongHeight
            }
        );
        assert_eq!(node.state().round.round, 3);
        // validator_set_id 不符。
        let c2 = cert(&node.validator_set().clone(), &kps, &vsid, 3);
        assert_eq!(
            apply_verified_round_change(&mut node, &c2, &[0xCD; 32], 3, &cfg(), None, 0),
            RoundChangeApplication::Rejected {
                error: RoundChangeError::ValidatorSetMismatch
            }
        );
        assert_eq!(node.state().round.round, 3, "拒绝 ⇒ 零 round 变化");
    }

    /// 构造**指定高度**的有效证书（签名为该高度真实签名）。
    fn cert_at_height(
        set: &ValidatorSet,
        kps: &[KeyPair],
        vsid: &[u8; 32],
        height: u64,
        from_round: u64,
    ) -> RoundChangeCertificate {
        let mut ids: Vec<ValidatorId> = kps
            .iter()
            .map(|kp| ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes()))
            .collect();
        assert!(ids.len() <= set.len());
        ids.sort();
        let hash = abandon_message_hash(CHAIN_ID, height, from_round).expect("hash");
        let evidence = ids
            .iter()
            .map(|id| {
                let kp = kps
                    .iter()
                    .find(|kp| {
                        &ValidatorId::from_consensus_public_key(&kp.verifying_key().to_bytes())
                            == id
                    })
                    .expect("key present");
                RoundChangeEvidence {
                    validator_id: *id,
                    signature: sign_message_hash(kp.signing_key(), &hash).to_bytes(),
                }
            })
            .collect();
        RoundChangeCertificate {
            validator_set_id: *vsid,
            height,
            from_round,
            evidence,
        }
    }

    #[test]
    fn d1_7_8_9_dag_qc_registry_and_lock_untouched_by_application() {
        let (mut node, kps, vsid) = test_node(3, 3);
        let c = cert(&node.validator_set().clone(), &kps, &vsid, 3);
        // DAG：`transition` 的 `RoundTimeout` 分支**不**接受 / 不触碰 `dag`（仅 `state.round` +
        // `finality.clone()` + `context.round_evidence.reset`）⇒ 结构上不可变。
        // QcRegistry：位于 `IntegrationContext`，**不经** `ConsensusNode` 暴露（设计边界）；
        //   独立证据见 6H-Y 的 `round_change_path_never_touches_qc_registry_or_vote_state`。
        // LockedState：validator-local，**不在** `ConsensusState` / `IntegrationContext` 内。
        let before_finality = node.state().finality.clone();
        let before_height = node.state().round.height;
        assert!(matches!(
            apply_verified_round_change(&mut node, &c, &vsid, 3, &cfg(), None, 0),
            RoundChangeApplication::Applied { .. }
        ));
        assert_eq!(node.state().finality, before_finality);
        assert_eq!(node.state().round.height, before_height);
        // 独立 QC registry 仍为空（结构性：RC 无 `→ QuorumCertificate` 转换）。
        let registry = QcRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.prevote_qcs().is_empty());
    }

    // -----------------------------------------------------------------------
    // §18「RC can NEVER enter QcRegistry / VoteAccumulator / RoundEvidence /
    //       finality pipeline / LockedState」——行为 + 结构证据
    // -----------------------------------------------------------------------

    #[test]
    fn round_change_path_never_touches_qc_registry_or_vote_state() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 7);
        // 结构证据：本模块**不**持有 VoteAccumulator / RoundEvidence / LockedState，
        // 也**不**调用 assemble_qc / verify_qc。唯一可观测的"邻近"结构是 QcRegistry：
        let registry = QcRegistry::new();
        assert!(registry.is_empty());
        let before = registry.len();
        // 走完整入站判定 + 重开路径：
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 7);
        assert!(d.is_apply());
        let _ = rearm_after_round_change(None, HEIGHT, d.to_round().expect("accepted"), &cfg(), 0);
        // QcRegistry 不可能被 RC 影响（RC 非 QC；无 `RoundChangeCertificate → QuorumCertificate`
        // 转换，且本模块不调用 `admit`）。
        assert_eq!(registry.len(), before);
        assert!(registry.is_empty());
        assert!(!registry.is_full());
        assert!(registry.prevote_qcs().is_empty());
    }

    #[test]
    fn rejected_certificate_is_pure_no_op() {
        let (set, kps, vsid) = test_set(3);
        let c = cert(&set, &kps, &vsid, 3);
        let before = encode_certificate(&c).expect("encode");
        let d = decide_round_change(&c, CHAIN_ID, &vsid, &set, 4);
        assert!(!d.is_apply());
        // 拒绝路径不改变证书，也不产生任何 round / timer 变更（无 Apply ⇒ 无 rearm 输入）。
        let after = encode_certificate(&c).expect("encode");
        assert_eq!(before, after);
        assert_eq!(d.to_round(), None);
    }
}
