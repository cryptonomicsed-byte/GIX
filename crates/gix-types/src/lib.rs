//! gix-types — canonical GIX (Glyph Index) primitive types.
//!
//! Single source of truth for all GIX primitives used across the sovereign
//! ecosystem.  larql-glyph, Omo-Koda2, and ARP all depend on this crate
//! instead of maintaining divergent copies.
//!
//! GIX-FOLD-v1: content-addressed memory chunks → deterministic Unicode glyph.
//! GIX1 audit: Merkle root over canonical_ids.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ── GIX-FOLD-v1 glyph encoding ───────────────────────────────────────────────

const FOLD_RANGES: [(u32, u32); 3] = [
    (0x0020, 0xD7FF - 0x0020 + 1),
    (0xE000, 0xFDCF - 0xE000 + 1),
    (0xFDF0, 0xFFFD - 0xFDF0 + 1),
];

pub fn content_hash(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().into()
}

pub fn glyph_fold(digest: &[u8; 32]) -> char {
    let total: u64 = FOLD_RANGES.iter().map(|(_, c)| *c as u64).sum();
    let mut rem: u64 = 0;
    for byte in digest {
        rem = (rem << 8 | *byte as u64) % total;
    }
    let mut idx = rem as u32;
    for (start, count) in FOLD_RANGES {
        if idx < count {
            return char::from_u32(start + idx).expect("fold ranges exclude invalid Unicode points");
        }
        idx -= count;
    }
    unreachable!()
}

/// Returns `(odu_base, odu_composed)` for a content digest.
pub fn odu_link(digest: &[u8; 32]) -> (u8, u16) {
    (digest[0], (digest[0] as u16) << 8 | digest[1] as u16)
}

// ── Canonical node types ──────────────────────────────────────────────────────

/// Metadata projection of one sealed memory chunk.
/// Plaintext is NOT retained — only the content-addressed metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlyphNode {
    pub canonical_id:  String,   // hex SHA-256 of plaintext
    pub glyph:         char,     // GIX-FOLD-v1 deterministic Unicode glyph
    pub odu_base:      u8,
    pub odu_composed:  u16,
    pub ts:            f64,      // Unix seconds (float for sub-second precision)
    pub tags:          BTreeSet<String>,
    pub walrus_blob_id: Option<String>,
}

impl GlyphNode {
    pub fn from_chunk(chunk: &str, ts: f64) -> Self {
        let digest = content_hash(chunk);
        let (odu_base, odu_composed) = odu_link(&digest);
        Self {
            canonical_id:  hex::encode(digest),
            glyph:         glyph_fold(&digest),
            odu_base,
            odu_composed,
            ts,
            tags:          BTreeSet::new(),
            walrus_blob_id: None,
        }
    }
}

/// Typed edge between two memory nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlyphEdge {
    pub from:      String,
    pub to:        String,
    pub relation:  String,
    pub weight:    i32,
}

/// GIX kind discriminant — used in ARP receipts and GIX1 audit records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GixKind {
    Memory,
    Receipt,
    Simulation,
    Physical,
    Governance,
    Custom(String),
}

/// A single GIX1 entry — wraps any canonical receipt/event with its glyph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gix1Entry {
    pub canonical_id: String,
    pub glyph:        char,
    pub kind:         GixKind,
    pub odu_base:     u8,
    pub ts:           f64,
    pub payload_hash: String,  // SHA-256 of the wrapped payload
}

impl Gix1Entry {
    pub fn from_receipt(receipt_id: &str, kind: GixKind, ts: f64) -> Self {
        let digest = content_hash(receipt_id);
        let (odu_base, _) = odu_link(&digest);
        Self {
            canonical_id: hex::encode(digest),
            glyph:        glyph_fold(&digest),
            kind,
            odu_base,
            ts,
            payload_hash: hex::encode(digest),
        }
    }
}

// ── GIX1 audit / Merkle root ─────────────────────────────────────────────────

/// The empty Merkle root for a GIX1 index with no entries.
pub const GIX1_EMPTY_ROOT: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Compute a GIX1 Merkle root over a sorted list of canonical_ids.
/// Sort-then-hash: deterministic regardless of insertion order.
pub fn gix1_merkle_root(canonical_ids: &[&str]) -> String {
    if canonical_ids.is_empty() {
        return GIX1_EMPTY_ROOT.to_string();
    }
    let mut sorted: Vec<&str> = canonical_ids.to_vec();
    sorted.sort_unstable();
    // Pairwise SHA-256 reduction (left-to-right, pad with last element if odd).
    let mut layer: Vec<[u8; 32]> = sorted
        .iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            h.finalize().into()
        })
        .collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i < layer.len() {
            let left  = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { left };
            let mut h = Sha256::new();
            h.update(&left);
            h.update(&right);
            next.push(h.finalize().into());
            i += 2;
        }
        layer = next;
    }
    hex::encode(layer[0])
}

/// Audit a GIX1 index: verify that the stored root matches a recomputed root
/// from the provided canonical_ids.  Returns `Ok(root)` on match.
pub fn gix1_audit(
    stored_root: &str,
    canonical_ids: &[&str],
) -> Result<String, String> {
    let computed = gix1_merkle_root(canonical_ids);
    if computed == stored_root {
        Ok(computed)
    } else {
        Err(format!(
            "GIX1 audit failed: stored={stored_root}, computed={computed}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root() {
        assert_eq!(gix1_merkle_root(&[]), GIX1_EMPTY_ROOT);
    }

    #[test]
    fn single_entry_root() {
        let root = gix1_merkle_root(&["abc"]);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn audit_round_trip() {
        let ids = ["a", "b", "c"];
        let root = gix1_merkle_root(&ids);
        assert!(gix1_audit(&root, &ids).is_ok());
        assert!(gix1_audit("badhash", &ids).is_err());
    }

    #[test]
    fn glyph_fold_deterministic() {
        let n1 = GlyphNode::from_chunk("hello sovereign", 0.0);
        let n2 = GlyphNode::from_chunk("hello sovereign", 0.0);
        assert_eq!(n1.canonical_id, n2.canonical_id);
        assert_eq!(n1.glyph, n2.glyph);
    }
}
