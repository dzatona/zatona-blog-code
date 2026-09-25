//! Code for the zatona.dev post "RFC 3161 vs OpenTimestamps: What Each
//! Timestamp Proves" (<https://zatona.dev/blog/rfc-3161-vs-opentimestamps>).
//!
//! The post's own framing is that its RFC 3161 crates "stop at parsing":
//! `x509-tsp` and `cms` give the ASN.1 types and verify no signatures, so
//! "the signature check, the chain, the extended key usage and the
//! revocation decision are yours." This crate is that "yours": the six
//! fenced ```rust blocks under Sections 2, 3 and 6, unmodified
//! (`listings/`, checksums in `PROVENANCE.md`), plus the glue that makes
//! them a working verifier — the pieces the post's prose names but does
//! not print: the `Reject`/`Accepted`/`Bound`/`CertStatus` types
//! `open_token` returns and matches on, and `signer_certificate`, which the
//! post's Section 3 explains in prose ("Identification comes from the
//! certificate identifier in the signerInfo") without printing a listing
//! for it.
//!
//! See [`tsp`] for the RFC 3161 half and [`ots`] for the OpenTimestamps
//! half; each module's own docs say what is tested and what is not.

pub mod ots;
pub mod tsp;
