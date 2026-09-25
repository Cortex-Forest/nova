//! DAG（STEP 10-3 — ADR-0035 D-1~D-3）。
//!
//! - [`BlockReference`]：DAG 节点（仅引用 block 承诺，PHASE 7 定义完整 Block）。
//! - [`Dag`]：节点集 + tips；`add_block` 验证（hash 唯一 / parents 存在 / height 合法）。
//! - [`Dag::causal_order`]：确定性拓扑序（parent 先于 child；多 parent 用 hash 字典序）。
//! - **DAG ≠ Finality**（C-3）：只负责传播/因果/候选排序输入；finality 归 10-5/10-6。

use crate::error::ConsensusError;
use crate::validator::ValidatorId;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// DAG 节点引用（ADR-0035 D-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReference {
    /// 区块承诺（仅引用，不解析完整 Block；PHASE 7）。
    pub block_hash: [u8; 32],
    /// 提议高度。
    pub height: u64,
    /// 父引用（DAG 边；≥1，多父 = 因果/并行）。
    pub parents: Vec<[u8; 32]>,
    /// 提议者（Consensus identity；非 NodeId/Account）。
    pub proposer: ValidatorId,
}

/// 区块 DAG（ADR-0035 D-2）。
#[derive(Debug, Clone, Default)]
pub struct Dag {
    blocks: HashMap<[u8; 32], BlockReference>,
    /// 无后代叶子（候选）。
    tips: Vec<[u8; 32]>,
}

impl Dag {
    /// 空 DAG。
    pub fn new() -> Self {
        Self::default()
    }

    /// 加入区块（验证：① hash 唯一 ② parents 全部存在 ③ height 合法——`parent.height < height`）。
    pub fn add_block(&mut self, r: BlockReference) -> Result<(), ConsensusError> {
        // ① 唯一性
        if self.blocks.contains_key(&r.block_hash) {
            return Err(ConsensusError::DuplicateBlock);
        }
        // ② parents 存在
        for p in &r.parents {
            if !self.blocks.contains_key(p) {
                return Err(ConsensusError::InvalidDagReference);
            }
        }
        // ③ height 合法（parent.height < height）
        for p in &r.parents {
            let parent_height = self.blocks[p].height;
            if parent_height >= r.height {
                return Err(ConsensusError::InvalidDagReference);
            }
        }
        self.blocks.insert(r.block_hash, r);
        self.rebuild_tips();
        Ok(())
    }

    /// 是否包含某区块。
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.blocks.contains_key(hash)
    }

    /// 某区块的父引用。
    pub fn parents_of(&self, hash: &[u8; 32]) -> Option<&[[u8; 32]]> {
        self.blocks.get(hash).map(|r| r.parents.as_slice())
    }

    /// 全传递祖先判定（ADR-0053 L-4/L-8 的 canonical primitive；未来 Lock Enforcement 使用）。
    ///
    /// `ancestor` 是否为 `descendant` 的祖先（沿 DAG parent 边），或二者为同一 in-DAG 区块。
    ///
    /// - **full transitive**：沿一条或多条 parent 边；非 immediate-only（`L → A → B → Z` 时
    ///   `is_ancestor(L, Z) == true`）。
    /// - **self-inclusive**：`is_ancestor(X, X) == true`（X ∈ DAG；与既有 `dag_is_ancestor`/
    ///   `dag_reaches` 一致）。
    /// - **unknown hash**：`ancestor` 或 `descendant` 不在 DAG ⇒ `false`（不 panic、不插入节点）。
    /// - **cycle-safe**：visited 集防御（虽 `add_block` 的 `parent.height < height` 已保证结构无环）。
    /// - **deterministic / 无 mutation / 无 I/O / 无网络**：纯 DAG query。
    /// - 仅沿 parent 边判断；不用 height 差异直接推导 ancestry（`same height ≠ ancestor`）。
    pub fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool {
        if !self.contains(ancestor) || !self.contains(descendant) {
            return false;
        }
        if ancestor == descendant {
            return true;
        }
        let mut visited = HashSet::new();
        let mut stack = vec![*descendant];
        while let Some(cur) = stack.pop() {
            if cur == *ancestor {
                return true;
            }
            if !visited.insert(cur) {
                continue;
            }
            if let Some(parents) = self.parents_of(&cur) {
                stack.extend(parents.iter().copied());
            }
        }
        false
    }

    /// 叶子候选（无后代）。
    pub fn tips(&self) -> &[[u8; 32]] {
        &self.tips
    }

    /// 区块数。
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// 确定性因果（拓扑）序（ADR-0035 D-3）：`from` 可达闭包内，
    /// **parent 先于 child**；多 parent 时按 `block_hash` 字典序（跨节点一致）。
    pub fn causal_order(&self, from: &[u8; 32]) -> Vec<[u8; 32]> {
        if !self.blocks.contains_key(from) {
            return Vec::new();
        }
        // 1. 收集 from 可达闭包（含 from）
        let mut reachable = HashSet::new();
        self.collect_reachable(from, &mut reachable);
        // 2. Kahn 拓扑排序（限定 reachable）
        let mut indegree: HashMap<[u8; 32], usize> = HashMap::new();
        for h in &reachable {
            let parents_in = self.blocks[h]
                .parents
                .iter()
                .filter(|p| reachable.contains(*p))
                .count();
            indegree.insert(*h, parents_in);
        }
        let mut heap: BinaryHeap<Reverse<[u8; 32]>> = BinaryHeap::new();
        for (h, d) in &indegree {
            if *d == 0 {
                heap.push(Reverse(*h));
            }
        }
        let mut order = Vec::with_capacity(reachable.len());
        while let Some(Reverse(h)) = heap.pop() {
            order.push(h);
            // 减少以 h 为 parent 的子节点 indegree
            for child in &reachable {
                if self.blocks[child].parents.contains(&h) {
                    let d = indegree.get_mut(child).expect("in reachable");
                    *d -= 1;
                    if *d == 0 {
                        heap.push(Reverse(*child));
                    }
                }
            }
        }
        order
    }

    /// 从 `from` 出发沿 parents 收集可达闭包（含 from；**显式栈迭代 DFS**，确定性）。
    ///
    /// **D11-1（F1，stack-safety）**：原实现以 ``collect_reachable(&p, acc)`` **自递归**下降，
    /// 在长 canonical 链（恢复态 ~2.6k 深度）上耗尽主线程栈 —— P3 转储确认
    /// `STATUS_STACK_OVERFLOW (0xC00000FD)` @ `dag.rs:175`（V2 2,584 帧 / V7 2,581 帧，≈368 B/帧）。
    /// 此处改为显式 `Vec` 栈，**语义逐项不变**：
    /// - 可达集合 / visited 行为：每个 hash 仅首次插入时入栈（原递归的 `!acc.insert ⇒ return` 等价）；
    /// - 缺失节点（`from` 或 parent 不在 `blocks`）：仍登记进 `acc` 且不展开（与原实现一致）；
    /// - parent 遍历与 genesis 根 / DAG 分叉：逐一展开，成环由 `acc` 防御；
    /// - **不引入深度上限**（超长链照常完成）；遍历顺序不影响结果
    ///   （`acc` 为集合，最终顺序由 [`Dag::causal_order`] 的 Kahn 排序决定）。
    fn collect_reachable(&self, from: &[u8; 32], acc: &mut HashSet<[u8; 32]>) {
        if !acc.insert(*from) {
            return;
        }
        let mut stack: Vec<[u8; 32]> = vec![*from];
        while let Some(cur) = stack.pop() {
            let Some(r) = self.blocks.get(&cur) else {
                continue;
            };
            let mut sorted_parents = r.parents.clone();
            sorted_parents.sort_unstable();
            for p in sorted_parents {
                if acc.insert(p) {
                    stack.push(p);
                }
            }
        }
    }

    /// 重建 tips（叶子 = 无后代；V0.1 全量重算，简单正确）。
    fn rebuild_tips(&mut self) {
        let mut has_child: HashSet<[u8; 32]> = HashSet::new();
        for r in self.blocks.values() {
            for p in &r.parents {
                has_child.insert(*p);
            }
        }
        self.tips = self
            .blocks
            .keys()
            .filter(|h| !has_child.contains(*h))
            .copied()
            .collect();
        self.tips.sort_unstable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_bytes([b; 32])
    }

    fn block(hash: u8, height: u64, parents: Vec<u8>) -> BlockReference {
        BlockReference {
            block_hash: [hash; 32],
            height,
            parents: parents.iter().map(|p| [*p; 32]).collect(),
            proposer: vid(hash),
        }
    }

    #[test]
    fn add_block_validation() {
        let mut dag = Dag::new();
        // 空 parent 合法（genesis block）
        dag.add_block(block(0x01, 0, vec![])).unwrap();
        assert!(dag.contains(&[0x01; 32]));
        // 重复 hash ⇒ DuplicateBlock
        assert_eq!(
            dag.add_block(block(0x01, 1, vec![0x01])),
            Err(ConsensusError::DuplicateBlock)
        );
        // parent 不存在 ⇒ InvalidDagReference
        assert_eq!(
            dag.add_block(block(0x02, 1, vec![0x99])),
            Err(ConsensusError::InvalidDagReference)
        );
        // height 不合法（parent.height >= height）⇒ InvalidDagReference
        assert_eq!(
            dag.add_block(block(0x03, 0, vec![0x01])),
            Err(ConsensusError::InvalidDagReference)
        );
        // 合法子区块
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap();
        assert_eq!(dag.len(), 2);
    }

    #[test]
    fn tips_tracks_leaves() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap();
        assert_eq!(dag.tips(), &[[0x01; 32]]);
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap();
        // 0x01 不再是无后代
        assert_eq!(dag.tips(), &[[0x02; 32]]);
        // 多父：0x03 parent = {0x01, 0x02}
        dag.add_block(block(0x03, 2, vec![0x01, 0x02])).unwrap();
        assert_eq!(dag.tips(), &[[0x03; 32]]);
    }

    #[test]
    fn causal_order_parents_before_children() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap();
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap();
        dag.add_block(block(0x03, 1, vec![0x01])).unwrap();
        dag.add_block(block(0x04, 2, vec![0x02, 0x03])).unwrap();
        let order = dag.causal_order(&[0x04; 32]);
        // 4 个可达（0x01..0x04）
        assert_eq!(order.len(), 4);
        // parent 先于 child
        let pos = |h: u8| order.iter().position(|x| x == &[h; 32]).unwrap();
        assert!(pos(0x01) < pos(0x02));
        assert!(pos(0x01) < pos(0x03));
        assert!(pos(0x02) < pos(0x04));
        assert!(pos(0x03) < pos(0x04));
        // 0x04 最后
        assert_eq!(order.last(), Some(&[0x04; 32]));
    }

    #[test]
    fn causal_order_deterministic() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap();
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap();
        dag.add_block(block(0x03, 1, vec![0x01])).unwrap();
        let o1 = dag.causal_order(&[0x03; 32]);
        let o2 = dag.causal_order(&[0x03; 32]);
        assert_eq!(o1, o2, "同 DAG ⇒ 同结果");
        // 多 parent（0x02, 0x03 同层）按 hash 字典序：0x02 < 0x03
        let o3 = dag.causal_order(&[0x02; 32]);
        let o4 = dag.causal_order(&[0x03; 32]);
        assert_eq!(o3, vec![[0x01; 32], [0x02; 32]]);
        assert_eq!(o4, vec![[0x01; 32], [0x03; 32]]);
    }

    #[test]
    fn causal_order_unknown_returns_empty() {
        let dag = Dag::new();
        assert_eq!(dag.causal_order(&[0x77; 32]), Vec::<[u8; 32]>::new());
    }

    /// **D11-1（F1）栈安全回归**：单父链深度 **12,000**（≫ P3 转储确认的生产故障深度 2,584）。
    ///
    /// 走**真实路径** `Dag::causal_order`（→ `collect_reachable`），不测孤立 helper：
    /// - 修复前：该链在测试线程栈（2 MiB，≈368 B/帧 ⇒ ~5.4k 帧）处溢出，进程 abort；
    /// - 修复后：显式栈完成，且拓扑序语义不变（可达闭包完整、parent 先于 child、tip 最后）。
    ///   不放大线程栈、不使用任何特殊运行期配置、不加深度上限。
    #[test]
    fn causal_order_deep_chain_12000_is_stack_safe() {
        const DEPTH: u64 = 12_000;
        let mut dag = Dag::new();
        let mut prev = [0u8; 32];
        dag.add_block(BlockReference {
            block_hash: prev,
            height: 0,
            parents: Vec::new(),
            proposer: vid(0x01),
        })
        .unwrap();
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(DEPTH as usize + 1);
        hashes.push(prev);
        for h in 1..=DEPTH {
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&h.to_be_bytes());
            hash[8] = 0xD1;
            dag.add_block(BlockReference {
                block_hash: hash,
                height: h,
                parents: vec![prev],
                proposer: vid(0x02),
            })
            .unwrap();
            hashes.push(hash);
            prev = hash;
        }
        const {
            assert!(
                DEPTH >= 10_000,
                "回归深度必须 ≥ 10,000（覆盖 2,584 生产故障点）"
            );
        };
        assert_eq!(dag.len(), DEPTH as usize + 1);

        let order = dag.causal_order(&prev);
        assert_eq!(order.len(), hashes.len(), "可达闭包 = 整条链");
        assert_eq!(order[0], hashes[0], "genesis 根最先");
        assert_eq!(order[order.len() - 1], prev, "tip 最后");
        let mut pos: HashMap<[u8; 32], usize> = HashMap::with_capacity(hashes.len());
        for (i, h) in order.iter().enumerate() {
            pos.insert(*h, i);
        }
        for w in hashes.windows(2) {
            assert!(pos[&w[0]] < pos[&w[1]], "parent 必须先于 child");
        }
    }

    // ---- is_ancestor（ADR-0053 L-4/L-8 canonical primitive）----

    #[test]
    fn is_ancestor_self_and_unknown() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap();
        // self-inclusive（in-DAG）
        assert!(dag.is_ancestor(&[0x01; 32], &[0x01; 32]));
        // unknown ancestor / descendant ⇒ false（不 panic）
        assert!(!dag.is_ancestor(&[0x99; 32], &[0x01; 32]));
        assert!(!dag.is_ancestor(&[0x01; 32], &[0x99; 32]));
        assert!(
            !dag.is_ancestor(&[0x99; 32], &[0x99; 32]),
            "未知自等 ⇒ false"
        );
    }

    #[test]
    fn is_ancestor_transitive_chain() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap(); // A
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap(); // B ← A
        dag.add_block(block(0x03, 2, vec![0x02])).unwrap(); // C ← B
        dag.add_block(block(0x04, 3, vec![0x03])).unwrap(); // D ← C
        // self
        assert!(dag.is_ancestor(&[0x01; 32], &[0x01; 32]));
        // direct
        assert!(dag.is_ancestor(&[0x01; 32], &[0x02; 32]));
        // full transitive（A→B→C→D）
        assert!(dag.is_ancestor(&[0x01; 32], &[0x03; 32]));
        assert!(dag.is_ancestor(&[0x01; 32], &[0x04; 32]));
        assert!(dag.is_ancestor(&[0x02; 32], &[0x04; 32]));
        // 反向（descendant 不是 ancestor）
        assert!(!dag.is_ancestor(&[0x04; 32], &[0x01; 32]));
        assert!(!dag.is_ancestor(&[0x03; 32], &[0x02; 32]));
    }

    #[test]
    fn is_ancestor_unrelated_branches() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap(); // root A
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap(); // A-chain
        dag.add_block(block(0x11, 0, vec![])).unwrap(); // independent root X
        dag.add_block(block(0x12, 1, vec![0x11])).unwrap(); // X-chain
        assert!(!dag.is_ancestor(&[0x01; 32], &[0x12; 32]));
        assert!(!dag.is_ancestor(&[0x11; 32], &[0x02; 32]));
        assert!(!dag.is_ancestor(&[0x02; 32], &[0x12; 32]));
        assert!(!dag.is_ancestor(&[0x12; 32], &[0x01; 32]));
    }

    #[test]
    fn is_ancestor_multi_parent() {
        let mut dag = Dag::new();
        dag.add_block(block(0x01, 0, vec![])).unwrap(); // A (root)
        dag.add_block(block(0x02, 1, vec![0x01])).unwrap(); // B ← A
        dag.add_block(block(0x03, 1, vec![0x01])).unwrap(); // C ← A (B 的 sibling)
        dag.add_block(block(0x04, 2, vec![0x02, 0x03])).unwrap(); // D ← {B, C}
        // D 有多 parent：A 经 B 或 C 均可达
        assert!(dag.is_ancestor(&[0x01; 32], &[0x04; 32]));
        assert!(dag.is_ancestor(&[0x02; 32], &[0x04; 32]));
        assert!(dag.is_ancestor(&[0x03; 32], &[0x04; 32]));
        assert!(!dag.is_ancestor(&[0x04; 32], &[0x01; 32]));
    }

    #[test]
    fn is_ancestor_terminates_on_deep_chain() {
        // 深链遍历有界终止（visited 防御；DAG 结构无环由 add_block parent.height<height 保证，
        // 公共 API 无法构造真环）
        let mut dag = Dag::new();
        let mut prev: Vec<u8> = Vec::new();
        for h in 0u64..40 {
            let parents = prev.clone();
            dag.add_block(block(h as u8, h, parents)).unwrap();
            prev = vec![h as u8];
        }
        assert!(dag.is_ancestor(&[0u8; 32], &[39u8; 32]));
        assert!(!dag.is_ancestor(&[39u8; 32], &[0u8; 32]));
    }
}
