//! Pure process-tree layout logic, kept free of any GTK types so that it can
//! be unit tested.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// Where a node ended up after laying out the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLayout {
    /// Position in depth-first pre-order (parents before their children,
    /// siblings in the order given by the comparison function).
    pub order: usize,
    /// Number of ancestors the node has.
    pub depth: u32,
    pub has_children: bool,
    /// `true` if any ancestor is collapsed, i.e. the node should not be shown.
    pub hidden: bool,
}

/// Lays out `nodes` (given as `(pid, parent_pid)`) as a forest.
///
/// Nodes whose parent is not part of `nodes` (or which are their own parent)
/// become roots. Nodes that are only reachable through a parent cycle are
/// promoted to roots as well so that every node is always placed exactly once.
///
/// `compare` is used to order siblings and roots, receiving indices into
/// `nodes`. `collapsed` contains the pids whose children should be hidden.
///
/// The returned vector has the same length and indexing as `nodes`.
pub fn layout(
    nodes: &[(i32, i32)],
    collapsed: &HashSet<i32>,
    mut compare: impl FnMut(usize, usize) -> Ordering,
) -> Vec<NodeLayout> {
    let index_of: HashMap<i32, usize> = nodes
        .iter()
        .enumerate()
        .map(|(index, (pid, _))| (*pid, index))
        .collect();

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut roots: Vec<usize> = Vec::new();

    for (index, (pid, parent_pid)) in nodes.iter().enumerate() {
        match index_of.get(parent_pid) {
            Some(&parent_index) if parent_pid != pid => children[parent_index].push(index),
            _ => roots.push(index),
        }
    }

    roots.sort_by(|a, b| compare(*a, *b));
    for list in &mut children {
        list.sort_by(|a, b| compare(*a, *b));
    }

    let mut result = vec![
        NodeLayout {
            order: usize::MAX,
            depth: 0,
            has_children: false,
            hidden: false,
        };
        nodes.len()
    ];
    let mut next_order = 0;

    // iterative DFS so that deep trees can't overflow the stack
    let mut walk = |root: usize, result: &mut Vec<NodeLayout>| {
        let mut stack = vec![(root, 0u32, false)];
        while let Some((index, depth, hidden)) = stack.pop() {
            if result[index].order != usize::MAX {
                continue;
            }
            result[index] = NodeLayout {
                order: next_order,
                depth,
                has_children: !children[index].is_empty(),
                hidden,
            };
            next_order += 1;

            let child_hidden = hidden || collapsed.contains(&nodes[index].0);
            for child in children[index].iter().rev() {
                stack.push((*child, depth + 1, child_hidden));
            }
        }
    };

    for root in roots {
        walk(root, &mut result);
    }

    // anything left is part of a cycle; promote it to a root
    for index in 0..nodes.len() {
        if result[index].order == usize::MAX {
            walk(index, &mut result);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_pid(nodes: &[(i32, i32)]) -> impl FnMut(usize, usize) -> Ordering + '_ {
        move |a, b| nodes[a].0.cmp(&nodes[b].0)
    }

    #[test]
    fn simple_hierarchy_is_depth_first() {
        // 1
        // ├── 2
        // │   └── 4
        // └── 3
        let nodes = [(3, 1), (1, 0), (4, 2), (2, 1)];
        let result = layout(&nodes, &HashSet::new(), by_pid(&nodes));

        let mut ordered: Vec<(i32, u32)> = nodes
            .iter()
            .zip(&result)
            .map(|((pid, _), node)| (*pid, node.depth))
            .collect();
        ordered
            .sort_by_key(|(pid, _)| result[nodes.iter().position(|n| n.0 == *pid).unwrap()].order);

        assert_eq!(ordered, vec![(1, 0), (2, 1), (4, 2), (3, 1)]);
        assert!(result[1].has_children);
        assert!(!result[2].has_children);
    }

    #[test]
    fn collapsed_parent_hides_descendants_but_not_itself() {
        let nodes = [(1, 0), (2, 1), (3, 2), (4, 1)];
        let collapsed = HashSet::from([2]);
        let result = layout(&nodes, &collapsed, by_pid(&nodes));

        assert!(!result[0].hidden);
        assert!(!result[1].hidden); // the collapsed node itself stays visible
        assert!(result[2].hidden); // its child doesn't
        assert!(!result[3].hidden); // sibling unaffected
    }

    #[test]
    fn collapsing_hides_whole_subtree() {
        let nodes = [(1, 0), (2, 1), (3, 2), (4, 3)];
        let result = layout(&nodes, &HashSet::from([1]), by_pid(&nodes));
        assert_eq!(
            result.iter().map(|n| n.hidden).collect::<Vec<_>>(),
            vec![false, true, true, true]
        );
    }

    #[test]
    fn orphans_and_self_parents_become_roots() {
        let nodes = [(10, 999), (11, 11), (12, 10)];
        let result = layout(&nodes, &HashSet::new(), by_pid(&nodes));
        assert_eq!(result[0].depth, 0);
        assert_eq!(result[1].depth, 0);
        assert_eq!(result[2].depth, 1);
    }

    #[test]
    fn cycles_do_not_lose_or_duplicate_nodes() {
        let nodes = [(1, 2), (2, 1), (3, 3)];
        let result = layout(&nodes, &HashSet::new(), by_pid(&nodes));
        let mut orders: Vec<usize> = result.iter().map(|n| n.order).collect();
        orders.sort_unstable();
        assert_eq!(orders, vec![0, 1, 2]);
    }

    #[test]
    fn sibling_order_follows_comparison() {
        let nodes = [(1, 0), (2, 1), (3, 1), (4, 1)];
        // descending by pid
        let result = layout(&nodes, &HashSet::new(), |a, b| nodes[b].0.cmp(&nodes[a].0));
        let mut by_order: Vec<i32> = vec![0; 4];
        for (node, layout) in nodes.iter().zip(&result) {
            by_order[layout.order] = node.0;
        }
        assert_eq!(by_order, vec![1, 4, 3, 2]);
    }
}
