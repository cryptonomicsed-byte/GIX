//! Gix1Index — manages a GIX1 Merkle-auditable canonical_id registry.

use gix_types::{gix1_audit, gix1_merkle_root, Gix1Entry, GixKind, GIX1_EMPTY_ROOT};

/// In-memory GIX1 index with Merkle root tracking.
#[derive(Debug, Clone, Default)]
pub struct Gix1Index {
    entries: Vec<Gix1Entry>,
    root:    String,
}

impl Gix1Index {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            root:    GIX1_EMPTY_ROOT.to_string(),
        }
    }

    pub fn insert(&mut self, entry: Gix1Entry) {
        self.entries.push(entry);
        self.recompute_root();
    }

    pub fn add_receipt(&mut self, receipt_id: &str, kind: GixKind, ts: f64) -> &Gix1Entry {
        let entry = Gix1Entry::from_receipt(receipt_id, kind, ts);
        self.entries.push(entry);
        self.recompute_root();
        self.entries.last().unwrap()
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn entries(&self) -> &[Gix1Entry] {
        &self.entries
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
