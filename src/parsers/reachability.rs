// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet, VecDeque};

pub fn reachable_closure(
    seeds: &HashSet<crate::types::PackageName>,
    edges: &HashMap<crate::types::PackageName, HashSet<crate::types::PackageName>>,
) -> HashSet<crate::types::PackageName> {
    let mut visited: HashSet<crate::types::PackageName> = seeds.clone();
    let mut queue: VecDeque<crate::types::PackageName> = seeds.iter().cloned().collect();

    while let Some(node) = queue.pop_front() {
        if let Some(neighbors) = edges.get(&node) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PackageName;

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name)
    }

    fn pkgs(names: &[&str]) -> HashSet<PackageName> {
        names.iter().map(|n| pkg(n)).collect()
    }

    #[test]
    fn test_reachability_empty_seeds_returns_empty() {
        let seeds = HashSet::new();
        let edges = HashMap::new();
        assert!(reachable_closure(&seeds, &edges).is_empty());
    }

    #[test]
    fn test_reachability_no_edges_returns_just_seeds() {
        let seeds = pkgs(&["a", "b"]);
        let edges = HashMap::new();
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b"]));
    }

    #[test]
    fn test_reachability_linear_chain() {
        // a -> b -> c
        let seeds = pkgs(&["a"]);
        let edges = HashMap::from([(pkg("a"), pkgs(&["b"])), (pkg("b"), pkgs(&["c"]))]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b", "c"]));
    }

    #[test]
    fn test_reachability_diamond() {
        // a -> b, a -> c, b -> d, c -> d
        let seeds = pkgs(&["a"]);
        let edges = HashMap::from([
            (pkg("a"), pkgs(&["b", "c"])),
            (pkg("b"), pkgs(&["d"])),
            (pkg("c"), pkgs(&["d"])),
        ]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b", "c", "d"]));
    }

    #[test]
    fn test_reachability_cycle_does_not_loop() {
        // a -> b -> a (cycle)
        let seeds = pkgs(&["a"]);
        let edges = HashMap::from([(pkg("a"), pkgs(&["b"])), (pkg("b"), pkgs(&["a"]))]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b"]));
    }

    #[test]
    fn test_reachability_self_loop() {
        // a -> a
        let seeds = pkgs(&["a"]);
        let edges = HashMap::from([(pkg("a"), pkgs(&["a"]))]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a"]));
    }

    #[test]
    fn test_reachability_disjoint_components() {
        // a -> b (one component), c -> d (another component), seed = {a}
        let seeds = pkgs(&["a"]);
        let edges = HashMap::from([(pkg("a"), pkgs(&["b"])), (pkg("c"), pkgs(&["d"]))]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b"]));
        assert!(!result.contains(&pkg("c")));
        assert!(!result.contains(&pkg("d")));
    }

    #[test]
    fn test_reachability_multiple_seeds_union() {
        // seeds = {a, c}, a -> b, c -> d
        let seeds = pkgs(&["a", "c"]);
        let edges = HashMap::from([(pkg("a"), pkgs(&["b"])), (pkg("c"), pkgs(&["d"]))]);
        let result = reachable_closure(&seeds, &edges);
        assert_eq!(result, pkgs(&["a", "b", "c", "d"]));
    }
}
