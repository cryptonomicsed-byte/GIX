//! Gix1Index — manages a GIX1 Merkle-auditable canonical_id registry.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use gix_types::{gix1_audit, gix1_merkle_root, Gix1, Gix1Entry, GixKind, GixNamespace, GIX1_EMPTY_ROOT};

/// In-memory GIX1 index with Merkle root tracking and full-envelope lookup.
///
/// Stores both lightweight `Gix1Entry` records (used for Merkle auditing) and
/// the full `Gix1` wire envelopes (used for identity resolution).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Gix1Index {
    entries:   Vec<Gix1Entry>,
    /// Full wire envelopes keyed by hex-encoded canonical_id.
    envelopes: HashMap<String, Gix1>,
    root:      String,
}

impl PartialEq for Gix1Index {
    /// Two indexes are equal when their Merkle roots match — the root is a
    /// deterministic commitment over all canonical_ids in insertion order.
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}
impl Eq for Gix1Index {}

impl Gix1Index {
    pub fn new() -> Self {
        Self {
            entries:   Vec::new(),
            envelopes: HashMap::new(),
            root:      GIX1_EMPTY_ROOT.to_string(),
        }
    }

    /// Insert a lightweight `Gix1Entry` (no full envelope stored).
    pub fn insert(&mut self, entry: Gix1Entry) {
        self.entries.push(entry);
        self.recompute_root();
    }

    /// Insert a full `Gix1` wire envelope; also registers its `Gix1Entry`.
    ///
    /// This is the preferred insertion path for Phase 3 GIX stamping — it
    /// makes the full envelope available for later `resolve()` calls.
    pub fn insert_gix1(&mut self, env: Gix1) {
        let canonical_id_hex = hex::encode(env.canonical_id);
        let entry = Gix1Entry {
            canonical_id: canonical_id_hex.clone(),
            glyph:        env.glyph,
            kind:         env.kind.clone(),
            odu_base:     env.odu_base,
            ts:           env.created_at as f64 / 1000.0,
            payload_hash: canonical_id_hex.clone(),
        };
        self.entries.push(entry);
        self.envelopes.insert(canonical_id_hex, env);
        self.recompute_root();
    }

    /// Create a `Gix1Entry` from a receipt_id string and insert it.
    /// Does NOT store a full envelope — use [`insert_gix1`] when you have one.
    pub fn add_receipt(&mut self, receipt_id: &str, kind: GixKind, ts: f64) -> &Gix1Entry {
        let entry = Gix1Entry::from_receipt(receipt_id, kind, ts);
        self.entries.push(entry);
        self.recompute_root();
        self.entries.last().unwrap()
    }

    /// Resolve a full `Gix1` wire envelope by its hex-encoded canonical_id.
    ///
    /// Returns `None` if the index was populated via [`add_receipt`] or
    /// [`insert`] (which do not store the full envelope).
    pub fn resolve(&self, canonical_id: &str) -> Option<&Gix1> {
        self.envelopes.get(canonical_id)
    }

    pub fn root(&self) -> &str { &self.root }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn entries(&self) -> &[Gix1Entry] { &self.entries }

    /// Return all entries matching the given `GixKind`.
    pub fn by_kind(&self, kind: &GixKind) -> Vec<&Gix1Entry> {
        self.entries.iter().filter(|e| &e.kind == kind).collect()
    }

    /// Return all full envelopes matching the given `GixNamespace`.
    ///
    /// Only envelopes inserted via [`insert_gix1`] are available here;
    /// entries added via [`add_receipt`] or [`insert`] have no full envelope.
    pub fn by_namespace(&self, ns: &GixNamespace) -> Vec<&Gix1> {
        self.envelopes.values().filter(|e| &e.namespace == ns).collect()
    }

    /// Verify this index's stored root is consistent with its entries.
    pub fn audit(&self) -> Result<String, String> {
        let ids: Vec<&str> = self.entries.iter().map(|e| e.canonical_id.as_str()).collect();
        gix1_audit(&self.root, &ids)
    }

    fn recompute_root(&mut self) {
        let ids: Vec<&str> = self.entries.iter().map(|e| e.canonical_id.as_str()).collect();
        self.root = gix1_merkle_root(&ids);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix_types::{GixKind, GixNamespace, RoutingHints};

    #[test]
    fn insert_gix1_and_resolve() {
        let mut idx = Gix1Index::new();
        let env = Gix1::new(
            GixKind::Receipt,
            GixNamespace::OsovmExecution,
            b"test-receipt-001",
            None,
            1_700_000_000_000,
            RoutingHints::default(),
        );
        let canonical_id_hex = hex::encode(env.canonical_id);
        idx.insert_gix1(env);

        assert_eq!(idx.len(), 1);
        assert!(idx.resolve(&canonical_id_hex).is_some());
        assert!(idx.audit().is_ok());
    }

    #[test]
    fn resolve_returns_none_for_add_receipt() {
        let mut idx = Gix1Index::new();
        let ts = 1_700_000_000.0_f64;
        idx.add_receipt("some-receipt-id", GixKind::Receipt, ts);
        // add_receipt doesn't store full envelope
        for entry in idx.entries() {
            assert!(idx.resolve(&entry.canonical_id).is_none());
        }
    }

    #[test]
    fn partial_eq_by_root() {
        let idx1 = Gix1Index::new();
        let idx2 = Gix1Index::new();
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn insert_gix1_updates_root() {
        let mut idx = Gix1Index::new();
        let empty_root = idx.root().to_string();
        idx.insert_gix1(Gix1::new(
            GixKind::Physical,
            GixNamespace::MeshDevice,
            b"device-001",
            None,
            0,
            RoutingHints::default(),
        ));
        assert_ne!(idx.root(), empty_root);
    }

    #[test]
    fn by_kind_filters_correctly() {
        let mut idx = Gix1Index::new();
        idx.insert_gix1(Gix1::new(GixKind::Receipt,    GixNamespace::OsovmExecution, b"r1", None, 0, RoutingHints::default()));
        idx.insert_gix1(Gix1::new(GixKind::Physical,   GixNamespace::MeshDevice,     b"d1", None, 0, RoutingHints::default()));
        idx.insert_gix1(Gix1::new(GixKind::Simulation, GixNamespace::OsovmExecution, b"s1", None, 0, RoutingHints::default()));

        assert_eq!(idx.by_kind(&GixKind::Receipt).len(),    1);
        assert_eq!(idx.by_kind(&GixKind::Physical).len(),   1);
        assert_eq!(idx.by_kind(&GixKind::Simulation).len(), 1);
        assert_eq!(idx.by_kind(&GixKind::Memory).len(),     0);
    }

    #[test]
    fn by_namespace_filters_correctly() {
        let mut idx = Gix1Index::new();
        idx.insert_gix1(Gix1::new(GixKind::Receipt,  GixNamespace::OsovmExecution, b"e1", None, 0, RoutingHints::default()));
        idx.insert_gix1(Gix1::new(GixKind::Physical, GixNamespace::MeshDevice,     b"d1", None, 0, RoutingHints::default()));
        idx.insert_gix1(Gix1::new(GixKind::Receipt,  GixNamespace::MeshDevice,     b"d2", None, 0, RoutingHints::default()));

        assert_eq!(idx.by_namespace(&GixNamespace::OsovmExecution).len(), 1);
        assert_eq!(idx.by_namespace(&GixNamespace::MeshDevice).len(),     2);
        assert_eq!(idx.by_namespace(&GixNamespace::Mycelium).len(),       0);
    }
}
