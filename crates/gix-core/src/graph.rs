//! GlyphGraph — in-memory graph store with LQL-style query verbs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use gix_types::{GlyphEdge, GlyphNode};

/// In-memory graph of GlyphNode metadata.
/// Thread-safe by design: clone for concurrent use or wrap in Arc<Mutex<>>.
#[derive(Debug, Clone, Default)]
pub struct GlyphGraph {
    nodes: BTreeMap<String, GlyphNode>,
    edges: BTreeSet<GlyphEdge>,
}

impl GlyphGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: GlyphNode) {
        self.nodes.insert(node.canonical_id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: GlyphEdge) {
        self.edges.insert(edge);
    }

    pub fn get_node(&self, canonical_id: &str) -> Option<&GlyphNode> {
        self.nodes.get(canonical_id)
    }

    pub fn node_count(&self) -> usize { self.nodes.len() }
    pub fn edge_count(&self) -> usize { self.edges.len() }
    pub fn edges(&self) -> &BTreeSet<GlyphEdge> { &self.edges }
    pub fn nodes(&self) -> impl Iterator<Item = &GlyphNode> { self.nodes.values() }

    // ── LQL verbs ─────────────────────────────────────────────────────────────

    /// DESCRIBE: return metadata for a single node.
    pub fn describe(&self, canonical_id: &str) -> Option<&GlyphNode> {
        self.nodes.get(canonical_id)
    }

    /// SELECT: return all nodes matching an Odù base or tag filter.
    pub fn select_by_odu(&self, odu_base: u8) -> Vec<&GlyphNode> {
        self.nodes.values().filter(|n| n.odu_base == odu_base).collect()
    }

    pub fn select_by_tag(&self, tag: &str) -> Vec<&GlyphNode> {
        self.nodes.values().filter(|n| n.tags.contains(tag)).collect()
    }

    /// WALK: BFS from `start_id` up to `depth` hops, following `relation`
    /// (or all relations if None).
    pub fn walk(
        &self,
        start_id: &str,
        depth: usize,
        relation: Option<&str>,
    ) -> Vec<&GlyphNode> {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back((start_id.to_string(), 0));

        while let Some((id, d)) = queue.pop_front() {
            if visited.contains(&id) || d > depth {
                continue;
            }
            visited.insert(id.clone());
            if let Some(node) = self.nodes.get(&id) {
                result.push(node);
            }
            for edge in &self.edges {
                if edge.from == id {
                    if relation.map_or(true, |r| r == edge.relation) {
                        queue.push_back((edge.to.clone(), d + 1));
                    }
                }
            }
        }
        result
    }

    /// INFER: find nodes that share ≥ `min_shared_tags` tags with `canonical_id`.
    pub fn infer_related(
        &self,
        canonical_id: &str,
        min_shared_tags: usize,
    ) -> Vec<(&GlyphNode, usize)> {
        let base_tags = match self.nodes.get(canonical_id) {
            Some(n) => &n.tags,
            None => return vec![],
        };

        self.nodes
            .values()
            .filter(|n| n.canonical_id != canonical_id)
            .filter_map(|n| {
                let shared = n.tags.intersection(base_tags).count();
                if shared >= min_shared_tags { Some((n, shared)) } else { None }
            })
            .collect()
    }
}
