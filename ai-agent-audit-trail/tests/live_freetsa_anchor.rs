//! Runs [`ai_agent_audit_trail::one_step`] — Section 7's listing, wrapped
//! by `build.rs` — against a real ATL v2.0 receipt anchored to a real
//! RFC 3161 token from FreeTSA. Fixture provenance is in `fixtures/README.md`.
//!
//! The token here is a **separate** live fetch from the one in the
//! `rfc-3161-vs-opentimestamps` crate in this repository: that crate's
//! token times-tamps an unrelated digest for its own purpose, and this
//! receipt's anchor has to cover *this* receipt's own Data Tree root
//! (`fixtures/README.md` has both fetches' commands and the reason).
//!
//! `STEP_BYTES` below is not arbitrary relative to the fixture: it is the
//! exact bytes `fixtures/receipt.json`'s `payload_hash` was computed from
//! when the fixture was built (see that file's own generator, described in
//! `fixtures/README.md`), and the fixture's `metadata` field is,
//! byte-for-byte, the object `listings/block-1.rs`'s own `json!` literal
//! constructs. So calling `one_step(STEP_BYTES, ...)` and checking that its
//! returned `leaf` equals the receipt's anchored root is not a coincidence
//! the test asserts past — it is what "the write side and the read side
//! agree" means for this listing, checked directly against the value the
//! listing itself computes, not a value recomputed independently of it.

use ai_agent_audit_trail::one_step;
use x509_cert::{der::Decode, Certificate};

/// The exact bytes `fixtures/receipt.json`'s `payload_hash` is
/// `SHA256`-of. Changing this without regenerating the fixture (or vice
/// versa) breaks the binding this test exists to check.
const STEP_BYTES: &[u8] = b"the model's raw output bytes for this step";

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("reading fixtures/{name}: {e}"))
}

/// `receipt.json`'s `proof.root_hash`, decoded from its `"sha256:<hex>"`
/// form to raw bytes, without going through `atl-core` at all — an
/// independent read of the same file the test also hands to `one_step`,
/// so the comparison below is not the library checking its own arithmetic.
fn receipt_root_hash(receipt_json: &str) -> [u8; 32] {
    let value: serde_json::Value = serde_json::from_str(receipt_json).expect("valid JSON");
    let root_hash = value["proof"]["root_hash"]
        .as_str()
        .expect("proof.root_hash is a string");
    let hex_part = root_hash
        .strip_prefix("sha256:")
        .expect("prefixed with \"sha256:\"");
    let bytes = (0..hex_part.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_part[i..i + 2], 16).expect("valid hex"))
        .collect::<Vec<u8>>();
    bytes.try_into().expect("32 bytes")
}

/// The receipt's Data Tree root is, by construction (`fixtures/README.md`),
/// the RFC 9162 leaf hash over the payload hash of `STEP_BYTES` and the
/// metadata hash of the listing's own metadata literal — so this receipt
/// is not just structurally valid, it is genuinely anchored: the RFC 3161
/// anchor's `target_hash` really is what the token's `messageImprint`
/// attests to, and the checkpoint really is a one-leaf tree over that same
/// value.
#[test]
fn one_step_accepts_a_receipt_anchored_to_a_real_freetsa_token() {
    let receipt_json = String::from_utf8(load("receipt.json")).expect("valid UTF-8");
    let expected_root = receipt_root_hash(&receipt_json);

    let root_der = load("freetsa-cacert.der");
    let root_cert = Certificate::from_der(&root_der).expect("a valid DER certificate");

    let (leaf, result) = one_step(STEP_BYTES, receipt_json, root_cert)
        .unwrap_or_else(|e| panic!("a well-formed receipt must parse and verify: {e}"));

    // The genuine binding: the write side's own computed leaf, returned
    // straight out of the listing with nothing recomputed, equals the
    // read side's anchored Data Tree root, decoded independently above.
    assert_eq!(
        leaf, expected_root,
        "the write side's leaf over STEP_BYTES and the listing's metadata must equal \
         the receipt's own anchored root, or the two sides are not talking about the \
         same step"
    );

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

    let (_leaf, result) = one_step(STEP_BYTES, receipt_json, wrong_cert)
        .unwrap_or_else(|e| panic!("parsing must still succeed: {e}"));

    assert!(
        !result.anchor_results[0].is_valid,
        "an unrelated certificate must not let the anchor verify"
    );
    assert!(!result.has_valid_anchor());
}
