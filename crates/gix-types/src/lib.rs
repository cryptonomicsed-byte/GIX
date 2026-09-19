//! gix-types — canonical GIX (Glyph Index) primitive types.
//!
//! Single source of truth for all GIX primitives used across the sovereign
//! ecosystem.  larql-glyph, Omo-Koda2, and ARP all depend on this crate
//! instead of maintaining divergent copies.
//!
//! GIX-FOLD-v1: content-addressed memory chunks → deterministic Unicode glyph.
//! GIX1 audit: Merkle root over canonical_ids.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;

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
    /// A REM-compressed memory fold: multiple low-importance `Memory` entries
    /// collapsed into a single macro-node by the Triune-Memory REM cycle.
    MemoryFold,
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

/// Alias for [`gix1_merkle_root`] — matches the `merkle_root` name used by
/// larql-glyph so callers can migrate without renaming call sites.
#[inline]
pub fn merkle_root(canonical_ids: &[&str]) -> String {
    gix1_merkle_root(canonical_ids)
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

    /// GIX-FOLD-v1 canonical cross-language conformance vectors.
    ///
    /// Frozen against the Python reference (Vantage/backend/glyph_index.py) and
    /// the If-Script Rust implementation (If-Script/src/glyph/mod.rs). All three
    /// implementations MUST produce identical results for these inputs.
    ///
    /// Vector format: (text, glyph_codepoint, odu_base, odu_composed)
    const FOLD_VECTORS: &[(&str, u32, u8, u16)] = &[
        ("Àṣẹ",              21841, 227, 58152),
        ("hello",            23636,  44, 11506),
        ("GlyphIndex",       13726,  68, 17595),
        ("😊🚀 Unicode test", 64591, 189, 48626),
        ("Ọ̀rúnmìlà",        17963, 204, 52390),
    ];

    #[test]
    fn fold_matches_canonical_vectors() {
        for (text, codepoint, base, composed) in FOLD_VECTORS {
            let digest = content_hash(text);
            assert_eq!(
                glyph_fold(&digest) as u32, *codepoint,
                "glyph_fold mismatch for {:?}", text
            );
            assert_eq!(
                odu_link(&digest), (*base, *composed),
                "odu_link mismatch for {:?}", text
            );
        }
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

// ── GIX1 wire envelope ────────────────────────────────────────────────────────

/// Ecosystem scope — which subsystem's namespace a GIX object belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GixNamespace {
    OmokodaAgent,
    VantageRegistry,
    OsovmExecution,
    ArpReceipt,
    MeshDevice,
    Mycelium,
    IfScript,
    /// Triune-Memory orchestrator namespace: episodic, semantic, and working
    /// tier records routed through the 3-tier memory stack.
    TriuneMemory,
    Custom(String),
}

/// Optional routing hints — DIP NetworkRepr addresses where the object can be found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingHints {
    pub primary:  Option<String>,
    pub fallback: Vec<String>,
}

/// Integrity metadata — SHA-256 of the canonical serialisation of all other Gix1 fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityMeta {
    pub envelope_hash: [u8; 32],
}

/// GIX1 wire envelope — cross-system identity wrapper for any indexable object.
///
/// `canonical_id` is the cryptographic root (SHA-256 of the object's canonical bytes).
/// Odù coordinates are *projections* derived from the digest; they are NOT the identity.
/// Use [`Gix1::new`] to construct — this computes the integrity hash automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gix1 {
    pub version:      u8,
    pub kind:         GixKind,
    pub namespace:    GixNamespace,
    pub canonical_id: [u8; 32],
    pub glyph:        char,
    pub odu_base:     u8,
    pub odu_composed: u16,
    pub provenance:   Option<[u8; 32]>,
    pub created_at:   u64,             // unix milliseconds
    pub routing:      RoutingHints,
    pub integrity:    IntegrityMeta,
}

impl Gix1 {
    /// Construct a `Gix1` envelope from the object's canonical bytes.
    ///
    /// `canonical_bytes` should be the serialised form of the wrapped object.
    /// `created_at_ms` is the creation timestamp in Unix milliseconds.
    pub fn new(
        kind: GixKind,
        namespace: GixNamespace,
        canonical_bytes: &[u8],
        provenance: Option<[u8; 32]>,
        created_at_ms: u64,
        routing: RoutingHints,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(canonical_bytes);
        let digest: [u8; 32] = h.finalize().into();

        let (odu_base, odu_composed) = odu_link(&digest);
        let glyph = glyph_fold(&digest);

        let mut env = Self {
            version: 1,
            kind,
            namespace,
            canonical_id: digest,
            glyph,
            odu_base,
            odu_composed,
            provenance,
            created_at: created_at_ms,
            routing,
            integrity: IntegrityMeta { envelope_hash: [0u8; 32] },
        };
        env.integrity.envelope_hash = env.compute_envelope_hash();
        env
    }

    /// Re-verify the stored envelope_hash matches the current field values.
    pub fn verify_integrity(&self) -> bool {
        self.integrity.envelope_hash == self.compute_envelope_hash()
    }

    fn compute_envelope_hash(&self) -> [u8; 32] {
        // Serialise all fields except integrity itself, then SHA-256.
        let mut h = Sha256::new();
        h.update([self.version]);
        h.update(format!("{:?}", self.kind).as_bytes());
        h.update(format!("{:?}", self.namespace).as_bytes());
        h.update(self.canonical_id);
        h.update(self.glyph.to_string().as_bytes());
        h.update([self.odu_base]);
        h.update(self.odu_composed.to_be_bytes());
        if let Some(p) = &self.provenance {
            h.update(p);
        }
        h.update(self.created_at.to_be_bytes());
        h.update(self.routing.primary.as_deref().unwrap_or(""));
        h.finalize().into()
    }
}

// ── GIX-FOLD-v1 composite identity ───────────────────────────────────────────

/// Fold multiple canonical_ids into a single composite identity.
///
/// SHA-256 of their concatenation in order. Order matters: this operation is
/// NOT commutative (task + execution ≠ execution + task).
pub fn gix_fold_v1(inputs: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for id in inputs {
        h.update(id);
    }
    h.finalize().into()
}

// ── GixFold — REM-compressed memory fold wire type ───────────────────────────

/// Wire type for a REM-compressed memory fold.
///
/// Created by the Triune-Memory REM cycle when multiple low-importance
/// `GixKind::Memory` entries are folded into a single macro-node.
/// The `id` is `gix_fold_v1(sources)` — deterministic, order-dependent.
///
/// Register in `Gix1Index` with `GixKind::MemoryFold` so the fold appears
/// in Merkle roots alongside raw memory entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GixFold {
    /// Composite canonical_id: `gix_fold_v1` over all source canonical_ids.
    pub id:                [u8; 32],
    /// The source canonical_ids that were compressed into this fold.
    pub sources:           Vec<[u8; 32]>,
    /// Compression ratio: number of source entries per unit of information retained.
    pub compression_ratio: f32,
    /// Unix milliseconds when this fold was created.
    pub fold_ts:           u64,
}

impl GixFold {
    /// Create a `GixFold` from source canonical_ids.
    pub fn new(sources: Vec<[u8; 32]>, compression_ratio: f32) -> Self {
        let fold_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let id = gix_fold_v1(&sources);
        Self { id, sources, compression_ratio, fold_ts }
    }

    /// Hex-encoded canonical_id for this fold.
    pub fn canonical_id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Stamp a `Gix1` wire envelope for this fold node.
    pub fn to_gix1(&self, namespace: GixNamespace, routing: RoutingHints) -> Gix1 {
        Gix1::new(
            GixKind::MemoryFold,
            namespace,
            &self.id,
            None,
            self.fold_ts,
            routing,
        )
    }
}

// ── GixMemoryRef — GIX identity pointer into the Triune-Memory stack ─────────

/// Which of the three memory tiers a `GixMemoryRef` points into.
///
/// Mirrors `omokoda_core::memory::engine::MemoryTier` at the protocol level
/// so `gix-types` stays dependency-free. Conversion in `gix_bridge.rs`.
///
/// - `Working`  — high-churn session context (≤100 entries)
/// - `Episodic` — think/act outcomes this session (≤500 entries)
/// - `Semantic` — distilled patterns across sessions (≤200 entries)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GixMemoryTier {
    Working,
    Episodic,
    Semantic,
}

/// A GIX identity pointer for a Triune-Memory entry.
///
/// Links a `GixNamespace::TriuneMemory` canonical_id to its tier location and
/// fold depth within the REM compression hierarchy.
///
/// `fold_depth = 0` → raw, uncompressed `OduEntry`.
/// `fold_depth > 0` → the entry was absorbed into a `GixFold` N levels deep.
/// At depth 1 the entry's content is still addressable via the parent fold's
/// `sources`; at depth 2 the fold itself was re-folded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GixMemoryRef {
    /// GIX canonical_id (SHA-256 of the entry's canonical bytes).
    pub canonical_id: [u8; 32],
    /// GIX-FOLD-v1 deterministic Unicode glyph — quick visual fingerprint.
    pub glyph:        char,
    /// Odù base coordinate (digest[0]).
    pub odu_base:     u8,
    /// Which Triune-Memory tier this reference points into.
    pub tier:         GixMemoryTier,
    /// REM fold depth: 0 = raw entry, N = absorbed N levels into GixFold chain.
    pub fold_depth:   u8,
}

impl GixMemoryRef {
    /// Create a `GixMemoryRef` from the entry's canonical bytes.
    pub fn new(canonical_bytes: &[u8], tier: GixMemoryTier, fold_depth: u8) -> Self {
        let digest = {
            let mut h = Sha256::new();
            h.update(canonical_bytes);
            h.finalize()
        };
        let digest: [u8; 32] = digest.into();
        let (odu_base, _) = odu_link(&digest);
        Self {
            canonical_id: digest,
            glyph:        glyph_fold(&digest),
            odu_base,
            tier,
            fold_depth,
        }
    }

    /// Hex-encoded canonical_id.
    pub fn canonical_id_hex(&self) -> String {
        hex::encode(self.canonical_id)
    }

    /// Stamp a `Gix1` wire envelope for this memory reference.
    pub fn to_gix1(&self, routing: RoutingHints) -> Gix1 {
        Gix1::new(
            GixKind::Memory,
            GixNamespace::TriuneMemory,
            &self.canonical_id,
            None,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            routing,
        )
    }
}

// ── GIX-KDF-v1 domain-separated key derivation ───────────────────────────────

const HKDF_SALT: &[u8] = b"GLYPHINDEX/v1";

/// Domain labels for `gix_kdf_v1`.
///
/// Each domain derives a DIFFERENT key from the same `canonical_id` root.
/// KDF outputs are key material only — never stored as identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GixDomain {
    Memory,
    Mesh,
    Receipt,
    AgentKey,
    Encryption,
    Duress,
}

impl GixDomain {
    fn label(self) -> &'static [u8] {
        match self {
            GixDomain::Memory     => b"gix:memory:",
            GixDomain::Mesh       => b"gix:mesh:",
            GixDomain::Receipt    => b"gix:receipt:",
            GixDomain::AgentKey   => b"gix:agent:",
            GixDomain::Encryption => b"gix:enc:",
            GixDomain::Duress     => b"gix:duress:",
        }
    }
}

/// GIX-KDF-v1: derive 32-byte domain-specific key material from a canonical_id.
///
/// Uses HKDF-SHA256 with `salt = b"GLYPHINDEX/v1"`.
/// `info = domain_label + owner_bytes + context`.
///
/// Critical invariant: `gix_kdf_v1()` output is NEVER stored as identity.
/// A `canonical_id` and its KDF outputs must never be used interchangeably.
pub fn gix_kdf_v1(
    canonical_id: &[u8; 32],
    domain: GixDomain,
    owner: &[u8],
    context: &[u8],
) -> [u8; 32] {
    // HKDF-Extract
    let mut mac = HmacSha256::new_from_slice(HKDF_SALT)
        .expect("HMAC accepts any key length");
    mac.update(canonical_id);
    let prk = mac.finalize().into_bytes();

    // Build info = domain_label + owner + ":" + context
    let mut info = Vec::with_capacity(domain.label().len() + owner.len() + 1 + context.len());
    info.extend_from_slice(domain.label());
    info.extend_from_slice(owner);
    info.push(b':');
    info.extend_from_slice(context);

    // HKDF-Expand (one 32-byte block is enough for 256-bit keys)
    let mut mac2 = HmacSha256::new_from_slice(&prk)
        .expect("HMAC accepts any key length");
    mac2.update(&info);
    mac2.update(&[1u8]);
    mac2.finalize().into_bytes().into()
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    #[test]
    fn gix1_new_integrity_valid() {
        let env = Gix1::new(
            GixKind::Receipt,
            GixNamespace::ArpReceipt,
            b"test-receipt-payload",
            None,
            1_700_000_000_000,
            RoutingHints::default(),
        );
        assert_eq!(env.version, 1);
        assert!(env.verify_integrity());
    }

    #[test]
    fn gix1_canonical_id_from_bytes() {
        let payload = b"hello sovereign";
        let env = Gix1::new(
            GixKind::Memory,
            GixNamespace::OmokodaAgent,
            payload,
            None,
            0,
            RoutingHints::default(),
        );
        // canonical_id must equal SHA-256 of the payload
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(payload);
            h.finalize().into()
        };
        assert_eq!(env.canonical_id, expected);
    }

    #[test]
    fn gix_fold_v1_deterministic_and_order_dependent() {
        let a = content_hash("alpha");
        let b = content_hash("beta");
        let ab = gix_fold_v1(&[a, b]);
        let ba = gix_fold_v1(&[b, a]);
        assert_eq!(ab, gix_fold_v1(&[a, b]), "fold must be deterministic");
        assert_ne!(ab, ba, "fold must be order-dependent");
    }

    #[test]
    fn gix_kdf_v1_domain_separation() {
        let id = content_hash("agent-123");
        let enc    = gix_kdf_v1(&id, GixDomain::Encryption, b"owner", b"ctx");
        let duress = gix_kdf_v1(&id, GixDomain::Duress,     b"owner", b"ctx");
        assert_ne!(enc, duress, "enc and duress domains must produce different keys");
    }

    #[test]
    fn gix_kdf_v1_deterministic() {
        let id = content_hash("test-agent");
        let k1 = gix_kdf_v1(&id, GixDomain::Memory, b"alice", b"purpose");
        let k2 = gix_kdf_v1(&id, GixDomain::Memory, b"alice", b"purpose");
        assert_eq!(k1, k2);
    }

    #[test]
    fn odu_and_glyph_from_envelope_match_primitives() {
        let payload = "\u{00C0}\u{1E63}\u{1EB9}".as_bytes(); // Àṣẹ as UTF-8
        let env = Gix1::new(
            GixKind::Memory,
            GixNamespace::OmokodaAgent,
            payload,
            None,
            0,
            RoutingHints::default(),
        );
        let (odu_base, odu_composed) = odu_link(&env.canonical_id);
        let glyph = glyph_fold(&env.canonical_id);
        assert_eq!(env.odu_base, odu_base);
        assert_eq!(env.odu_composed, odu_composed);
        assert_eq!(env.glyph, glyph);
    }

    #[test]
    fn gix_kind_memory_fold_roundtrips() {
        let env = Gix1::new(
            GixKind::MemoryFold,
            GixNamespace::OmokodaAgent,
            b"fold-test-payload",
            None,
            1_700_000_000_000,
            RoutingHints::default(),
        );
        assert_eq!(env.kind, GixKind::MemoryFold);
        assert!(env.verify_integrity());
        let json = serde_json::to_string(&env.kind).unwrap();
        assert_eq!(json, "\"memory_fold\"");
        let decoded: GixKind = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, GixKind::MemoryFold);
    }

    #[test]
    fn gix_fold_new_deterministic() {
        let a = content_hash("entry-alpha");
        let b = content_hash("entry-beta");
        let f1 = GixFold::new(vec![a, b], 0.5);
        let f2 = GixFold::new(vec![a, b], 0.5);
        // id is gix_fold_v1 of sources — deterministic regardless of wall-clock
        assert_eq!(f1.id, f2.id);
        assert_eq!(f1.canonical_id_hex().len(), 64);
        assert_eq!(f1.sources.len(), 2);
    }

    #[test]
    fn gix_fold_to_gix1_stamps_memory_fold_kind() {
        let sources = vec![content_hash("mem-1"), content_hash("mem-2")];
        let fold = GixFold::new(sources, 0.33);
        let env = fold.to_gix1(GixNamespace::OmokodaAgent, RoutingHints::default());
        assert_eq!(env.kind, GixKind::MemoryFold);
        assert!(env.verify_integrity());
        // canonical_id = SHA-256(fold.id bytes) — Gix1::new hashes canonical_bytes
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(fold.id);
            h.finalize().into()
        };
        assert_eq!(env.canonical_id, expected);
    }

    #[test]
    fn gix_namespace_triune_memory_roundtrips() {
        let json = serde_json::to_string(&GixNamespace::TriuneMemory).unwrap();
        assert_eq!(json, "\"triune_memory\"");
        let decoded: GixNamespace = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, GixNamespace::TriuneMemory);
    }

    #[test]
    fn gix_memory_tier_serde_roundtrips() {
        for (tier, expected) in [
            (GixMemoryTier::Working,  "\"working\""),
            (GixMemoryTier::Episodic, "\"episodic\""),
            (GixMemoryTier::Semantic, "\"semantic\""),
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, expected);
            let decoded: GixMemoryTier = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, tier);
        }
    }

    #[test]
    fn gix_memory_ref_new_deterministic() {
        let r1 = GixMemoryRef::new(b"hello memory", GixMemoryTier::Episodic, 0);
        let r2 = GixMemoryRef::new(b"hello memory", GixMemoryTier::Episodic, 0);
        assert_eq!(r1.canonical_id, r2.canonical_id);
        assert_eq!(r1.glyph, r2.glyph);
        assert_eq!(r1.canonical_id_hex().len(), 64);
        assert_eq!(r1.tier, GixMemoryTier::Episodic);
        assert_eq!(r1.fold_depth, 0);
    }

    #[test]
    fn gix_memory_ref_to_gix1_uses_triune_namespace() {
        let mref = GixMemoryRef::new(b"semantic pattern", GixMemoryTier::Semantic, 1);
        let env = mref.to_gix1(RoutingHints::default());
        assert_eq!(env.kind,      GixKind::Memory);
        assert_eq!(env.namespace, GixNamespace::TriuneMemory);
        assert!(env.verify_integrity());
    }

    #[test]
    fn gix_memory_ref_fold_depth_zero_is_raw() {
        let raw  = GixMemoryRef::new(b"entry", GixMemoryTier::Working, 0);
        let fold = GixMemoryRef::new(b"entry", GixMemoryTier::Working, 2);
        // Same canonical_id regardless of fold_depth (identity is content, not tier)
        assert_eq!(raw.canonical_id, fold.canonical_id);
        assert_eq!(raw.fold_depth, 0);
        assert_eq!(fold.fold_depth, 2);
    }
}
