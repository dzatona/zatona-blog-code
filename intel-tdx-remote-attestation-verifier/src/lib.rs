//! The listing from the zatona.dev post "Intel TDX Remote Attestation
//! Verifier Without Intel Trust Authority"
//! (<https://zatona.dev/blog/intel-tdx-remote-attestation-verifier>),
//! Section 6.
//!
//! `listings/block-1.rs` is the byte-identical text of the post's one
//! fenced ```rust block (extraction method and checksum in
//! `PROVENANCE.md`), `include!`d below unmodified. No glue was needed to
//! make it compile: every name it uses (`Manifest`, `verify_td`, and the
//! `dcap_qvl`/`sha2` imports) is defined inside the block itself or in the
//! crates named in its own `use` statements.
//!
//! ## What is tested
//!
//! The post's own status sentence for this listing is: "It compiles; it
//! has not been exercised against hardware here." This crate keeps that
//! claim exactly, not a wider one. `Manifest`'s fields and `verify_td` are
//! not `pub` in the listing (neither is marked `pub`), so nothing outside
//! this module can construct a `Manifest` or call `verify_td` at all — the
//! only tests that can exist for it are unit tests in the same module,
//! below. They confirm `verify_td` runs, end to end through `dcap-qvl`'s
//! real parser, without panicking, and returns `Err` (not `Ok`) for input
//! that is not a genuine TDX quote — which is the one thing this crate can
//! honestly exercise without a TDX-capable machine.
//!
//! ## What is not tested
//!
//! Everything the post's status sentence already excludes: a real quote
//! from a real TD, a real `QuoteCollateralV3` from Intel's PCCS, and
//! therefore every one of the five decisions Section 1 describes.
//! `QuoteVerifier::new_prod()` inside the listing talks to nothing over
//! the network by itself — the collateral is a parameter, not a fetch —
//! but this crate does not fetch one either.

#![allow(dead_code)] // `Manifest`/`verify_td` are exercised only from `#[cfg(test)]` below

include!("../listings/block-1.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::QuoteCollateralV3;

    fn empty_manifest() -> Manifest {
        Manifest {
            mr_td: [0u8; 48],
            rt_mr: [[0u8; 48]; 4],
            reviewed_advisories: Vec::new(),
        }
    }

    /// Not a real collateral bundle — no TCB info, no QE identity, no
    /// certificate chains — so this is not a claim that verification
    /// against it means anything. It exists to give `verify_td` a
    /// well-typed, well-formed argument to run against, the same role the
    /// post's own `// fetched live, mirrored, or loaded from a file`
    /// comment assigns to the parameter. `QuoteCollateralV3` has no
    /// `Default` impl, so every field is named explicitly.
    fn empty_collateral() -> QuoteCollateralV3 {
        QuoteCollateralV3 {
            pck_crl_issuer_chain: String::new(),
            root_ca_crl: Vec::new(),
            pck_crl: Vec::new(),
            tcb_info_issuer_chain: String::new(),
            tcb_info: String::new(),
            tcb_info_signature: Vec::new(),
            qe_identity_issuer_chain: String::new(),
            qe_identity: String::new(),
            qe_identity_signature: Vec::new(),
            pck_certificate_chain: None,
        }
    }

    /// Not a TDX quote at all: `dcap-qvl`'s own parser must reject it, and
    /// `verify_td` must return that rejection as `Err`, not panic. This is
    /// the full extent of what this crate can honestly claim to exercise
    /// without hardware, per the post's own status sentence.
    #[test]
    fn verify_td_rejects_bytes_that_are_not_a_quote_without_panicking() {
        let garbage = vec![0u8; 64];
        let result = verify_td(
            &garbage,
            &empty_collateral(),
            0,
            &empty_manifest(),
            &[],
            &[0u8; 32],
        );
        assert!(
            result.is_err(),
            "64 zero bytes are not a well-formed TDX quote"
        );
    }

    /// An empty quote is a smaller, even more degenerate malformed input
    /// than 64 zero bytes; both must fail the same way, without a panic.
    #[test]
    fn verify_td_rejects_an_empty_quote_without_panicking() {
        let result = verify_td(
            &[],
            &empty_collateral(),
            0,
            &empty_manifest(),
            &[],
            &[0u8; 32],
        );
        assert!(result.is_err());
    }
}
