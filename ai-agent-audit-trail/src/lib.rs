//! The compiled listing from the zatona.dev post "AI Agent Audit Trail:
//! What to Hash, What to Anchor, What to Bind to the Frame"
//! (<https://zatona.dev/blog/ai-agent-audit-trail>), Section 7.
//!
//! `listings/block-1.rs` is the byte-identical text of the post's one
//! fenced ```rust block (extraction method and checksum in
//! `PROVENANCE.md`). The block is a sequence of statements, not a complete
//! item, and refers to three names — `step_bytes`, `receipt_json`,
//! `tsa_root_certificate` — that the prose describes but the block itself
//! does not bind. `build.rs` wraps the listing file's bytes, read
//! unmodified at build time, in a function signature; see its module docs
//! for why that has to happen in a build script rather than by an
//! `include!` inside this file.
//!
//! What is tested: `tests/live_freetsa_anchor.rs` runs [`one_step`] against
//! a real receipt anchored to a real RFC 3161 token fetched once from
//! FreeTSA specifically for this crate (fixture and provenance in
//! `fixtures/`) — a second, separate fetch from the one in the
//! `rfc-3161-vs-opentimestamps` crate in this repository, over a different
//! digest, because this receipt's anchor has to cover *this* receipt's
//! own Data Tree root, not an unrelated value. The test calls `one_step`
//! with the same `step_bytes` the fixture's `payload_hash` was built from,
//! and the listing's own `json!` metadata literal is reproduced
//! byte-for-byte when building the fixture, so the write side's computed
//! `leaf` and the read side's receipt are not merely two paths that both
//! happen to run — the test asserts the write side's `leaf` equals the
//! read side's anchored root.
//!
//! What is not tested: the post says the 2.1 witnessed-head receipt
//! members are not yet implemented in `atl-core`; this crate does not
//! exercise them either. `status_at`-style revocation checking has no
//! equivalent call in this listing — `atl-core`'s anchor verification does
//! not fetch a CRL or OCSP response, and neither does this crate.

include!(concat!(env!("OUT_DIR"), "/wrapped_block_1.rs"));
