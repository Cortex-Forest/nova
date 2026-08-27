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

    /// 从 `from` 出发沿 parents 收集可达闭包（含 from；DFS，确定性）。
    fn collect_reachable(&self, from: &[u8; 32], acc: &mut HashSet<[u8; 32]>) {
        if !acc.insert(*from) {
            return;
        }
        if let Some(r) = self.blocks.get(from) {
            let mut sorted_parents = r.parents.clone();
            sorted_parents.sort_unstable();
            for p in sorted_parents {
                self.collect_reachable(&p, acc);
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
}
