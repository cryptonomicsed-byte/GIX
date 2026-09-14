//! gix-core — GIX graph runtime.
//!
//! Provides the GlyphGraph store (nodes + typed edges), LQL-verb queries
//! (DESCRIBE / SELECT / WALK / INFER), and GIX1 index management.
//!
//! Depends only on gix-types — no I/O, no sealing, no Vantage coupling.

pub mod graph;
pub mod index;

pub use graph::GlyphGraph;
pub use index::Gix1Index;
pub use gix_types::{
    GlyphNode, GlyphEdge, GixKind, Gix1Entry,
    gix1_audit, gix1_merkle_root, merkle_root, GIX1_EMPTY_ROOT,
    content_hash, glyph_fold, odu_link,
};
