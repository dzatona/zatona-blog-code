//! Runs [`ai_agent_audit_trail::one_step`] — Section 7's listing, wrapped
//! by `build.rs` — against a real ATL v2.0 receipt anchored to a real
//! RFC 3161 token from FreeTSA. Fixture provenance is in this file's own
//! comments and in `fixtures/README.md`; the token itself was fetched once
//! for the `rfc-3161-vs-opentimestamps` crate in this repository and is
//! reused here rather than fetched again.

use ai_agent_audit_trail::one_step;
use x509_cert::{der::Decode, Certificate};

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("reading fixtures/{name}: {e}"))
}

/// The receipt's Data Tree root is, by construction (see
/// `fixtures/README.md`), the leaf hash over the exact digest FreeTSA's
/// real token in `receipt.json`'s one anchor actually covers — so this
/// receipt is not just structurally valid, it is genuinely anchored: the
/// RFC 3161 anchor's `target_hash` really is what the token's
/// `messageImprint` attests to, and the checkpoint really is a one-leaf
/// tree over that same value.
#[test]
fn one_step_accepts_a_receipt_anchored_to_a_real_freetsa_token() {
    let receipt_json = String::from_utf8(load("receipt.json")).expect("valid UTF-8");
    let root_der = load("freetsa-cacert.der");
    let root_cert = Certificate::from_der(&root_der).expect("a valid DER certificate");

    // The write side's step_bytes is independent of the read side's
    // receipt in the post's own listing (two halves of one step's
    // lifecycle, not values that flow into each other in this code), so
    // any bytes exercise it; the ones below are arbitrary.
    let step_bytes = b"the model's raw output bytes for this step";

    let result = one_step(step_bytes, receipt_json, root_cert)
        .unwrap_or_else(|e| panic!("a well-formed receipt must parse and verify: {e}"));

    assert_eq!(result.anchor_results.len(), 1);
    assert_eq!(result.anchor_results[0].anchor_type, "rfc3161");
    assert!(
        result.anchor_results[0].is_valid,
        "the RFC 3161 anchor must verify against FreeTSA's own root: {:?}",
        result.anchor_results[0].error
    );
    assert!(result.has_valid_anchor());
    // This receipt's inclusion proof, checkpoint and super_proof are all
    // trivially self-consistent (one leaf, one entry, no consistency step
    // to check), so accepting it end to end -- not merely resolving the
    // anchor -- is the correct outcome here, unlike the "anchor resolves
    // but the base receipt is a deliberately incomplete fixture" case
    // atl-core's own integration tests document.
    assert!(result.is_valid, "errors: {:?}", result.errors());
}

/// The same receipt without the trust store: the anchor cannot be
/// resolved to `Trusted`, and the same real token comes back unverified —
/// the ATL trust model's own point, stated in `atl-core`'s docs and
/// repeated in the post's Section 7: "trust comes from anchors," and an
/// anchor with nothing to terminate its chain at contributes nothing.
#[test]
fn one_step_without_a_root_cannot_verify_the_same_anchor() {
    let receipt_json = String::from_utf8(load("receipt.json")).expect("valid UTF-8");
    // A certificate that is not FreeTSA's root: this crate's own synthetic
    // fixture would do as well as anything, but reusing the RFC 3161 crate's
    // synthetic "no EKU" certificate keeps this repository from growing a
    // second unrelated synthetic certificate for the same purpose.
    let wrong_der = std::fs::read(format!(
        "{}/../rfc-3161-vs-opentimestamps/fixtures/synthetic-no-eku.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the sibling crate's fixture must exist");
    let wrong_cert = Certificate::from_der(&wrong_der).expect("a valid DER certificate");

    let step_bytes = b"the model's raw output bytes for this step";
    let result = one_step(step_bytes, receipt_json, wrong_cert)
        .unwrap_or_else(|e| panic!("parsing must still succeed: {e}"));

    assert!(
        !result.anchor_results[0].is_valid,
        "an unrelated certificate must not let the anchor verify"
    );
    assert!(!result.has_valid_anchor());
}
