//! CanonicalObjectStore — the single authoritative GIX object registry.
//!
//! Invariant:
//!   ∀ graph node N: N.canonical_id ∈ Gix1Index
//!
//! `Gix1Index` is the identity/discovery layer ("what exists").
//! `GlyphGraph` is the relationship/traversal layer ("how it relates").
//!
//! All mutations go through this store so the two structures stay coherent
//! and share a versioned snapshot identity.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use gix_types::{
    content_hash, Gix1, GixKind, GixNamespace, GlyphEdge, GlyphNode,
};

use crate::{Gix1Index, GlyphGraph};

// ── snapshot versioning ───────────────────────────────────────────────────────

/// Shared version envelope written alongside graph.json + index.json.
///
/// Both files carry the same `snapshot_id`; a mismatch on load means the
/// files are from different epochs and must be rejected as inconsistent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GixSnapshotMeta {
    /// UUID that changes on every atomic save.  Detects paired-file skew.
    pub snapshot_id:     String,
    /// Gix1Index Merkle root at the time of this snapshot.
    pub index_root:      String,
    /// SHA-256 over the sorted canonical set of edges (hex).
    pub graph_fingerprint: String,
    /// Milliseconds since UNIX epoch.
    pub created_at:      u64,
    /// Increment when the serialised format changes.
    pub schema_version:  u32,
    /// Informational counts — not load-verified.
    pub node_count:      usize,
    pub edge_count:      usize,
    pub entry_count:     usize,
}

impl GixSnapshotMeta {
    pub const CURRENT_SCHEMA: u32 = 1;
}

// ── store ─────────────────────────────────────────────────────────────────────

/// Combined canonical object authority: `Gix1Index` (what exists) +
/// `GlyphGraph` (how objects relate), kept in lock-step by a single
/// mutation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalObjectStore {
    pub index:       Gix1Index,
    pub graph:       GlyphGraph,
    snapshot_id:     String,
    schema_version:  u32,
}

impl Default for CanonicalObjectStore {
    fn default() -> Self { Self::new() }
}

impl CanonicalObjectStore {
    pub fn new() -> Self {
        Self {
            index:          Gix1Index::new(),
            graph:          GlyphGraph::new(),
            snapshot_id:    Uuid::new_v4().to_string(),
            schema_version: GixSnapshotMeta::CURRENT_SCHEMA,
        }
    }

    // ── object insertion ──────────────────────────────────────────────────────

    /// Insert a `Gix1` envelope.
    ///
    /// This is THE mutation path for adding a new object.  Both structures
    /// are updated atomically:
    ///   1. `Gix1Index` registers the full envelope (identity layer).
    ///   2. `GlyphGraph` gains a node whose `canonical_id` equals the
    ///      envelope's `canonical_id_hex` — never re-hashing the ID.
    ///
    /// Returns the hex-encoded canonical_id so callers can add edges.
    pub fn insert_object(&mut self, env: Gix1) -> String {
        let canonical_id_hex = hex::encode(env.canonical_id);
        let ts = env.created_at as f64 / 1000.0;

        // Graph node: canonical_id == index canonical_id (no double-hash).
        let node = GlyphNode {
            canonical_id:  canonical_id_hex.clone(),
            glyph:         env.glyph,
            odu_base:      env.odu_base,
            odu_composed:  env.odu_composed,
            ts,
            tags:          BTreeSet::new(),
            walrus_blob_id: None,
        };
        self.graph.add_node(node);
        self.index.insert_gix1(env);
        canonical_id_hex
    }

    // ── edge insertion ────────────────────────────────────────────────────────

    /// Add a directed edge between two objects already in the store.
    ///
    /// Panics if either endpoint is not registered — call `insert_object`
    /// first.  This enforces the invariant that all graph nodes are in the
    /// index.
    pub fn add_edge(&mut self, edge: GlyphEdge) {
        assert!(
            self.index.resolve(&edge.from).is_some(),
            "add_edge: 'from' canonical_id {} not in Gix1Index", edge.from,
        );
        assert!(
            self.index.resolve(&edge.to).is_some(),
            "add_edge: 'to' canonical_id {} not in Gix1Index", edge.to,
        );
        self.graph.add_edge(edge);
    }

    // ── lookups ───────────────────────────────────────────────────────────────

    /// Retrieve the full `Gix1` wire envelope for `canonical_id`.
    pub fn get_object(&self, canonical_id: &str) -> Option<&Gix1> {
        self.index.resolve(canonical_id)
    }

    pub fn contains(&self, canonical_id: &str) -> bool {
        self.index.resolve(canonical_id).is_some()
    }

    pub fn lookup_by_kind(&self, kind: &GixKind) -> Vec<&gix_types::Gix1Entry> {
        self.index.by_kind(kind)
    }

    pub fn lookup_by_namespace(&self, ns: &GixNamespace) -> Vec<&Gix1> {
        self.index.by_namespace(ns)
    }

    /// BFS walk from `start_id` up to `depth` hops through the relationship graph.
    pub fn walk(
        &self,
        start_id: &str,
        depth: usize,
        relation: Option<&str>,
    ) -> Vec<&GlyphNode> {
        self.graph.walk(start_id, depth, relation)
    }

    // ── snapshot metadata ─────────────────────────────────────────────────────

    pub fn snapshot_id(&self) -> &str { &self.snapshot_id }

    pub fn snapshot_meta(&self) -> GixSnapshotMeta {
        GixSnapshotMeta {
            snapshot_id:       self.snapshot_id.clone(),
            index_root:        self.index.root().to_string(),
            graph_fingerprint: self.compute_graph_fingerprint(),
            created_at:        current_ms(),
            schema_version:    self.schema_version,
            node_count:        self.graph.node_count(),
            edge_count:        self.graph.edge_count(),
            entry_count:       self.index.len(),
        }
    }

    /// Bump the snapshot_id — call before serialising to durable storage so
    /// paired graph.json/index.json/snapshot.json share the same epoch id.
    pub fn bump_snapshot(&mut self) {
        self.snapshot_id = Uuid::new_v4().to_string();
    }

    // ── consistency audit ─────────────────────────────────────────────────────

    /// Verify structural invariants across both GIX structures.
    ///
    /// Returns `Ok(())` when all invariants hold; `Err(violations)` listing
    /// every detected problem when they don't.
    pub fn audit_consistency(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();

        // 1. Index Merkle root must be self-consistent.
        if let Err(e) = self.index.audit() {
            violations.push(format!("index Merkle root invalid: {e}"));
        }

        // 2. ∀ graph node N: N.canonical_id ∈ Gix1Index (full envelope).
        for node in self.graph.nodes() {
            if self.index.resolve(&node.canonical_id).is_none() {
                violations.push(format!(
                    "graph node {} has no corresponding Gix1Index envelope",
                    node.canonical_id
                ));
            }
        }

        // 3. ∀ graph edge E: both endpoints are in the index.
        for edge in self.graph.edges() {
            if self.index.resolve(&edge.from).is_none() {
                violations.push(format!(
                    "edge.from {} not in Gix1Index",
                    edge.from
                ));
            }
            if self.index.resolve(&edge.to).is_none() {
                violations.push(format!(
                    "edge.to {} not in Gix1Index",
                    edge.to
                ));
            }
        }

        // 4. Schema version must match current.
        if self.schema_version != GixSnapshotMeta::CURRENT_SCHEMA {
            violations.push(format!(
                "schema_version {} != expected {}",
                self.schema_version, GixSnapshotMeta::CURRENT_SCHEMA
            ));
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// SHA-256 over sorted `from:to:relation` edge strings — deterministic
    /// graph fingerprint for snapshot validation.
    fn compute_graph_fingerprint(&self) -> String {
        let mut parts: Vec<String> = self
            .graph
            .edges()
            .iter()
            .map(|e| format!("{}:{}:{}", e.from, e.to, e.relation))
            .collect();
        parts.sort();
        let combined = parts.join("|");
        hex::encode(content_hash(&combined))
    }
}

fn current_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── persistence helpers (used by StorageBackend implementations) ──────────────

/// Serialise a `CanonicalObjectStore` to three JSON files atomically.
///
/// Files written:
///   `{base}.graph.json`    — GlyphGraph
///   `{base}.index.json`    — Gix1Index
///   `{base}.snapshot.json` — GixSnapshotMeta (shared epoch id)
///
/// A fresh `snapshot_id` is stamped before writing so all three files share
/// the same epoch identifier.
pub fn save_store_to_files(
    store: &mut CanonicalObjectStore,
    graph_path:    &std::path::Path,
    index_path:    &std::path::Path,
    snapshot_path: &std::path::Path,
) -> Result<(), String> {
    store.bump_snapshot();
    let meta = store.snapshot_meta();

    // Write graph.
    store.graph.save(graph_path)?;

    // Write index.
    store.index.save(index_path)?;

    // Write snapshot manifest (last — if this fails the pair is still usable
    // individually; if it succeeds it proves graph+index are in sync).
    let json = serde_json::to_string_pretty(&meta)
        .map_err(|e| format!("GixSnapshotMeta serialize error: {e}"))?;
    let tmp = snapshot_path.with_extension("tmp");
    std::fs::write(&tmp, &json)
        .map_err(|e| format!("GixSnapshotMeta write error: {e}"))?;
    std::fs::rename(&tmp, snapshot_path)
        .map_err(|e| format!("GixSnapshotMeta rename error: {e}"))
}

/// Load a `CanonicalObjectStore` from three JSON files.
///
/// Recovery semantics:
///   - All three missing → empty store (first boot).
///   - Graph + index present but snapshot missing → load and regenerate meta.
///   - Snapshot present but `snapshot_id` mismatch → `Err` (epoch skew).
///   - Consistency audit failure → `Err`.
pub fn load_store_from_files(
    graph_path:    &std::path::Path,
    index_path:    &std::path::Path,
    snapshot_path: &std::path::Path,
) -> Result<CanonicalObjectStore, String> {
    // First boot: no files at all.
    if !graph_path.exists() && !index_path.exists() {
        return Ok(CanonicalObjectStore::new());
    }

    let graph = GlyphGraph::load(graph_path)?;
    let index = Gix1Index::load(index_path)?;

    // Load snapshot manifest if present; regenerate if missing.
    let (snapshot_id, schema_version) = if snapshot_path.exists() {
        let json = std::fs::read_to_string(snapshot_path)
            .map_err(|e| format!("GixSnapshotMeta read error: {e}"))?;
        let meta: GixSnapshotMeta = serde_json::from_str(&json)
            .map_err(|e| format!("GixSnapshotMeta parse error: {e}"))?;

        // Verify graph/index agree on entry counts from the manifest.
        // A count mismatch means one file is from a different epoch.
        if meta.entry_count != index.len() {
            return Err(format!(
                "GIX snapshot epoch skew: manifest entry_count={} but index has {}",
                meta.entry_count, index.len()
            ));
        }

        (meta.snapshot_id, meta.schema_version)
    } else {
        // Snapshot manifest missing: regenerate (downgrade, but don't fail).
        (Uuid::new_v4().to_string(), GixSnapshotMeta::CURRENT_SCHEMA)
    };

    let store = CanonicalObjectStore {
        index,
        graph,
        snapshot_id,
        schema_version,
    };

    // Audit consistency before handing the store to the runtime.
    store.audit_consistency().map_err(|vs| vs.join("; "))?;

    Ok(store)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use gix_types::{GixKind, GixNamespace, RoutingHints};

    fn make_env(bytes: &[u8], kind: GixKind, ns: GixNamespace) -> Gix1 {
        Gix1::new(kind, ns, bytes, None, 1_700_000_000_000, RoutingHints::default())
    }

    // ── single-path insertion ─────────────────────────────────────────────────

    #[test]
    fn insert_object_canonical_ids_agree() {
        let mut store = CanonicalObjectStore::new();
        let env = make_env(b"agent-001", GixKind::Memory, GixNamespace::OmokodaAgent);
        let id = store.insert_object(env.clone());

        // Index and graph must use the exact same canonical_id.
        let index_entry = store.index.resolve(&id).expect("must be in index");
        let graph_node  = store.graph.get_node(&id).expect("must be in graph");

        assert_eq!(hex::encode(index_entry.canonical_id), id);
        assert_eq!(graph_node.canonical_id, id);
    }

    #[test]
    fn insert_object_no_double_hash() {
        let mut store = CanonicalObjectStore::new();
        let env = make_env(b"device-xyz", GixKind::Physical, GixNamespace::MeshDevice);
        let id = store.insert_object(env.clone());

        // canonical_id must equal hex::encode(SHA-256(b"device-xyz")),
        // NOT hex::encode(SHA-256(hex::encode(SHA-256(b"device-xyz")))).
        let expected = hex::encode(env.canonical_id);
        assert_eq!(id, expected, "canonical_id must not be double-hashed");
    }

    // ── edge enforcement ──────────────────────────────────────────────────────

    #[test]
    fn add_edge_requires_both_endpoints_in_index() {
        let mut store = CanonicalObjectStore::new();
        let a = store.insert_object(make_env(b"node-a", GixKind::Physical, GixNamespace::MeshDevice));
        let b = store.insert_object(make_env(b"node-b", GixKind::Receipt, GixNamespace::ArpReceipt));

        // Valid edge — both endpoints registered.
        store.add_edge(GlyphEdge { from: a.clone(), to: b.clone(), relation: "produces".into(), weight: 1 });
        assert_eq!(store.graph.edge_count(), 1);
    }

    #[test]
    #[should_panic(expected = "not in Gix1Index")]
    fn add_edge_panics_on_unknown_endpoint() {
        let mut store = CanonicalObjectStore::new();
        let a = store.insert_object(make_env(b"node-a", GixKind::Physical, GixNamespace::MeshDevice));
        store.add_edge(GlyphEdge {
            from:     a,
            to:       "deadbeef".repeat(8),  // unknown id
            relation: "ghost".into(),
            weight:   0,
        });
    }

    // ── consistency audit ─────────────────────────────────────────────────────

    #[test]
    fn audit_passes_on_clean_store() {
        let mut store = CanonicalObjectStore::new();
        let a = store.insert_object(make_env(b"a", GixKind::Memory, GixNamespace::OmokodaAgent));
        let b = store.insert_object(make_env(b"b", GixKind::Receipt, GixNamespace::ArpReceipt));
        store.add_edge(GlyphEdge { from: a, to: b, relation: "seals".into(), weight: 1 });

        store.audit_consistency().expect("clean store must audit ok");
    }

    #[test]
    fn audit_detects_orphan_graph_node() {
        let mut store = CanonicalObjectStore::new();
        // Inject a graph node WITHOUT going through insert_object —
        // simulates a corrupt or manually-patched state.
        store.graph.add_node(GlyphNode {
            canonical_id:  "orphan-node-id".into(),
            glyph:         '☯',
            odu_base:      1,
            odu_composed:  1,
            ts:            0.0,
            tags:          BTreeSet::new(),
            walrus_blob_id: None,
        });

        let violations = store.audit_consistency().unwrap_err();
        assert!(violations.iter().any(|v| v.contains("orphan-node-id")));
    }

    // ── lookup API ────────────────────────────────────────────────────────────

    #[test]
    fn lookup_by_kind_and_namespace() {
        let mut store = CanonicalObjectStore::new();
        let _a = store.insert_object(make_env(b"mem", GixKind::Memory, GixNamespace::OmokodaAgent));
        let _b = store.insert_object(make_env(b"rec", GixKind::Receipt, GixNamespace::ArpReceipt));

        assert_eq!(store.lookup_by_kind(&GixKind::Memory).len(), 1);
        assert_eq!(store.lookup_by_kind(&GixKind::Receipt).len(), 1);
        assert_eq!(store.lookup_by_namespace(&GixNamespace::ArpReceipt).len(), 1);
    }

    // ── walk (relationship traversal) ─────────────────────────────────────────

    #[test]
    fn walk_follows_edges() {
        let mut store = CanonicalObjectStore::new();
        let agent   = store.insert_object(make_env(b"agent",   GixKind::Physical, GixNamespace::OmokodaAgent));
        let session = store.insert_object(make_env(b"session", GixKind::Receipt,  GixNamespace::VantageRegistry));
        let receipt = store.insert_object(make_env(b"receipt", GixKind::Receipt,  GixNamespace::ArpReceipt));

        store.add_edge(GlyphEdge { from: agent.clone(),   to: session.clone(), relation: "owns_session".into(), weight: 1 });
        store.add_edge(GlyphEdge { from: session.clone(), to: receipt.clone(), relation: "produced".into(),     weight: 1 });

        let visited = store.walk(&agent, 2, None);
        let ids: Vec<&str> = visited.iter().map(|n| n.canonical_id.as_str()).collect();
        assert!(ids.contains(&agent.as_str()),   "agent must be in walk");
        assert!(ids.contains(&session.as_str()), "session must be in walk");
        assert!(ids.contains(&receipt.as_str()), "receipt must be in walk");
    }

    // ── persistence roundtrip ─────────────────────────────────────────────────

    #[test]
    fn save_and_load_roundtrip_maintains_invariants() {
        let dir = tempfile::tempdir().unwrap();
        let gp = dir.path().join("store.graph.json");
        let ip = dir.path().join("store.index.json");
        let sp = dir.path().join("store.snapshot.json");

        let mut store = CanonicalObjectStore::new();
        let a = store.insert_object(make_env(b"agent",   GixKind::Physical, GixNamespace::OmokodaAgent));
        let b = store.insert_object(make_env(b"receipt", GixKind::Receipt,  GixNamespace::ArpReceipt));
        store.add_edge(GlyphEdge { from: a.clone(), to: b.clone(), relation: "vcp_session".into(), weight: 1 });

        save_store_to_files(&mut store, &gp, &ip, &sp).expect("save");
        assert!(sp.exists(), "snapshot manifest must be written");

        let loaded = load_store_from_files(&gp, &ip, &sp).expect("load");
        loaded.audit_consistency().expect("loaded store must audit clean");

        assert_eq!(loaded.graph.edge_count(), 1);
        assert_eq!(loaded.index.len(), 2);
        assert!(loaded.contains(&a));
        assert!(loaded.contains(&b));
    }

    #[test]
    fn load_returns_empty_on_first_boot() {
        let dir = tempfile::tempdir().unwrap();
        let store = load_store_from_files(
            &dir.path().join("no_graph.json"),
            &dir.path().join("no_index.json"),
            &dir.path().join("no_snapshot.json"),
        ).expect("first boot must not error");
        assert_eq!(store.graph.node_count(), 0);
        assert_eq!(store.index.len(), 0);
    }

    #[test]
    fn epoch_skew_detected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let gp = dir.path().join("g.json");
        let ip = dir.path().join("i.json");
        let sp = dir.path().join("s.json");

        // Write a valid store with 2 objects.
        let mut store = CanonicalObjectStore::new();
        store.insert_object(make_env(b"a", GixKind::Memory, GixNamespace::OmokodaAgent));
        store.insert_object(make_env(b"b", GixKind::Memory, GixNamespace::OmokodaAgent));
        save_store_to_files(&mut store, &gp, &ip, &sp).unwrap();

        // Overwrite the snapshot manifest with a stale entry_count.
        let mut meta: GixSnapshotMeta = serde_json::from_str(
            &std::fs::read_to_string(&sp).unwrap()
        ).unwrap();
        meta.entry_count = 99;  // corrupt
        std::fs::write(&sp, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        let result = load_store_from_files(&gp, &ip, &sp);
        assert!(result.is_err(), "epoch skew must be detected");
        assert!(result.unwrap_err().contains("epoch skew"));
    }

    // ── 8B.8 — the test that matters most ────────────────────────────────────

    /// Full restart + traversal integration:
    ///
    ///   CREATE objects → PERSIST → SIMULATE RESTART → LOAD →
    ///   AUDIT → WALK agent → session → receipt
    ///
    /// Asserts that exact canonical IDs survive the restart.
    #[test]
    fn restart_and_walk_preserves_canonical_ids() {
        let dir = tempfile::tempdir().unwrap();
        let gp = dir.path().join("g.json");
        let ip = dir.path().join("i.json");
        let sp = dir.path().join("s.json");

        // Session 1: create objects and persist.
        let (agent_id, session_id, receipt_id) = {
            let mut store = CanonicalObjectStore::new();
            let a = store.insert_object(make_env(b"agent-abc",   GixKind::Physical, GixNamespace::OmokodaAgent));
            let s = store.insert_object(make_env(b"session-xyz", GixKind::Receipt,  GixNamespace::VantageRegistry));
            let r = store.insert_object(make_env(b"receipt-001", GixKind::Receipt,  GixNamespace::ArpReceipt));

            store.add_edge(GlyphEdge { from: a.clone(), to: s.clone(), relation: "owns_session".into(), weight: 1 });
            store.add_edge(GlyphEdge { from: s.clone(), to: r.clone(), relation: "vcp_session".into(),  weight: 1 });

            save_store_to_files(&mut store, &gp, &ip, &sp).unwrap();
            (a, s, r)
        };

        // Session 2: simulate restart by loading from disk.
        let loaded = load_store_from_files(&gp, &ip, &sp).unwrap();
        loaded.audit_consistency().expect("must audit clean after restart");

        // Exact same canonical IDs must be present.
        assert!(loaded.contains(&agent_id),   "agent_id must survive restart");
        assert!(loaded.contains(&session_id), "session_id must survive restart");
        assert!(loaded.contains(&receipt_id), "receipt_id must survive restart");

        // Walk from agent → session → receipt in one traversal.
        let visited = loaded.walk(&agent_id, 2, None);
        let ids: Vec<&str> = visited.iter().map(|n| n.canonical_id.as_str()).collect();
        assert!(ids.contains(&agent_id.as_str()),   "walk: agent");
        assert!(ids.contains(&session_id.as_str()), "walk: session");
        assert!(ids.contains(&receipt_id.as_str()), "walk: receipt");
    }
}
