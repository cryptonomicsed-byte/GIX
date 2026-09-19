//! GlyphGraph — in-memory graph store with LQL-style query verbs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use gix_types::{GlyphEdge, GlyphNode};
use serde::{Deserialize, Serialize};

/// In-memory graph of GlyphNode metadata.
/// Thread-safe by design: clone for concurrent use or wrap in Arc<Mutex<>>.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    // ── persistence ───────────────────────────────────────────────────────────

    /// Serialize the graph to a JSON file at `path`.
    ///
    /// Writes atomically via a temp file to prevent a partial write from
    /// corrupting the stored graph on crash.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("GlyphGraph serialize error: {e}"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| format!("GlyphGraph write error ({}): {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("GlyphGraph rename error: {e}"))
    }

    /// Deserialize a `GlyphGraph` from a JSON file at `path`.
    ///
    /// Returns `Ok(GlyphGraph::default())` if the file does not exist so that
    /// a fresh broker startup never fails just because there is no prior state.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("GlyphGraph read error ({}): {e}", path.display()))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("GlyphGraph deserialize error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix_types::{GlyphEdge, GlyphNode};

    fn make_graph() -> GlyphGraph {
        let mut g = GlyphGraph::new();
        g.add_node(GlyphNode::from_chunk("node-alpha", 1.0));
        g.add_node(GlyphNode::from_chunk("node-beta",  2.0));
        let from = hex::encode(gix_types::content_hash("node-alpha"));
        let to   = hex::encode(gix_types::content_hash("node-beta"));
        g.add_edge(GlyphEdge { from, to, relation: "test".into(), weight: 3 });
        g
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.json");

        let g = make_graph();
        g.save(&path).expect("save should succeed");
        assert!(path.exists());

        let loaded = GlyphGraph::load(&path).expect("load should succeed");
        assert_eq!(loaded.node_count(), 2);
        assert_eq!(loaded.edge_count(), 1);
        assert_eq!(loaded.edges().iter().next().unwrap().weight, 3);
    }

    #[test]
    fn load_missing_file_returns_empty_graph() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let g = GlyphGraph::load(&path).expect("missing file should return empty graph");
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn save_is_atomic_via_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.json");
        let tmp  = path.with_extension("tmp");

        make_graph().save(&path).unwrap();
        // The .tmp file must not linger after a successful save
        assert!(!tmp.exists(), ".tmp file should be cleaned up");
        assert!(path.exists());
    }
}
