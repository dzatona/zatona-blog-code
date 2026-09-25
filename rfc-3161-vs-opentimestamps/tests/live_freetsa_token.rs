//! Runs `build_request` and `open_token` (Sections 2 and 3's listings)
//! against a real response from a public Time Stamping Authority. Fixture
//! provenance, including the exact `openssl`/`curl` commands run to obtain
//! it, is in `fixtures/README.md`.
//!
//! `verify_signature` below is a real ECDSA P-384/SHA-512 verification over
//! the CMS `SignedAttributes`, re-encoded per RFC 5652 Section 5.4 (an
//! `EXPLICIT SET OF`, which is what `SignedAttributes::to_der()` produces
//! when called on the parsed value directly rather than on the wire bytes
//! under their context-specific `[0] IMPLICIT` tag) — not a closure that
//! always returns `true`. `status_at` is a stub that always returns
//! `CertStatus::Good`; see `src/tsp.rs`'s module docs for why (no crate in
//! this stack fetches a CRL or OCSP response, matching the post's own
//! statement about Check 5).

use cms::signed_data::SignedData;
use der::{Decode, Encode};
use p384::ecdsa::{DerSignature, VerifyingKey};
use rfc_3161_vs_opentimestamps::tsp::{build_request, open_token, CertStatus, Reject};
use sha2::{Digest, Sha512};
use signature::hazmat::PrehashVerifier;
use x509_cert::Certificate;

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("reading fixtures/{name}: {e}"))
}

/// The exact 8 random bytes used to build `fixtures/request.tsq` (see
/// `fixtures/README.md`); FreeTSA echoed them back as a 9-byte DER INTEGER
/// with a leading zero octet, which is precisely the scenario `block-1.rs`'s
/// own doc comment on `nonce_integer` describes.
const NONCE: [u8; 8] = [0xAD, 0xEF, 0x4D, 0xF2, 0x83, 0x59, 0xD9, 0x18];

/// 2026-09-25T04:36:23Z, FreeTSA's `genTime` for this token, in milliseconds.
/// Used as `local_now_ms` too: this test checks timeliness as of the moment
/// the response arrived, not as of whenever the test happens to run later.
const GEN_TIME_MS: i64 = 1_790_310_983_000;

/// A CMS signature check with real cryptography: re-encode `signedAttrs` as
/// an `EXPLICIT SET OF` (RFC 5652 Section 5.4), verify the `messageDigest`
/// attribute against the actual `eContent`, then verify the ECDSA
/// signature over the re-encoded attributes with the signer's SPKI. FreeTSA
/// signs with `ecdsa-with-SHA512` over a P-384 key (confirmed independently
/// with `openssl x509 -text` and `openssl asn1parse`; see
/// `fixtures/README.md`), so this only handles that one algorithm and says
/// so, rather than silently accepting anything.
fn verify_ecdsa_p384_sha512(signed_data: &SignedData, cert: &Certificate) -> bool {
    let Some(signer_info) = signed_data.signer_infos.0.iter().next() else {
        return false;
    };
    let Some(signed_attrs) = signer_info.signed_attrs.as_ref() else {
        return false;
    };

    // The messageDigest attribute must equal SHA-512 of the eContent this
    // SignedData actually carries, or the signature is over attributes with
    // nothing to do with the token being checked (the post's own warning,
    // Section 3, "The signature check has one trap independent of any crate").
    let Some(econtent) = signed_data.encap_content_info.econtent.as_ref() else {
        return false;
    };
    let content_digest = Sha512::digest(econtent.value());
    let message_digest_attr = signed_attrs
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST);
    let Some(attr) = message_digest_attr else {
        return false;
    };
    let Some(value) = attr.values.get(0) else {
        return false;
    };
    let Ok(digest_octets) = der::asn1::OctetString::from_der(&value.to_der().unwrap_or_default())
    else {
        return false;
    };
    if digest_octets.as_bytes() != &content_digest[..] {
        return false;
    }

    // RFC 5652 Section 5.4: the signature is computed over signedAttrs
    // re-encoded with an EXPLICIT SET OF tag, not over the [0] IMPLICIT
    // bytes on the wire. `signed_attrs.to_der()` does exactly that, because
    // `cms` parsed it into its own natural (SET OF) representation.
    let Ok(reencoded) = signed_attrs.to_der() else {
        return false;
    };

    let Ok(vk) = VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    ) else {
        return false;
    };
    let Ok(sig) = DerSignature::from_bytes(signer_info.signature.as_bytes()) else {
        return false;
    };
    // P-384's field size is 48 bytes; SHA-512's digest is 64. `verify_prehash`
    // applies the standard ECDSA truncation (SEC1's `bits2field`, the
    // leftmost `order_bit_length` bits) rather than requiring the digest and
    // field sizes to match, which is what makes `ecdsa-with-SHA512` over
    // P-384 -- FreeTSA's actual combination -- a verifiable signature at all.
    let digest = Sha512::digest(&reencoded);
    vk.verify_prehash(&digest, &sig).is_ok()
}

/// Always `CertStatus::Good`. No revocation source is wired up in this
/// crate; see the module docs on `crate::tsp` for why that is honest here
/// and not a shortcut around the check itself.
fn status_at_stub(_cert: &Certificate, _at_ms: i64) -> CertStatus {
    CertStatus::Good
}

fn pinned_tsa_cert() -> Certificate {
    let der = load("freetsa-tsa.der");
    Certificate::from_der(&der).expect("a valid DER certificate")
}

#[test]
fn build_request_reproduces_the_exact_bytes_sent_to_freetsa() {
    let message = load("message.txt");
    let sent_at_ms = GEN_TIME_MS - 60_000; // built shortly before the response's genTime
    let built = build_request(&message, &NONCE, sent_at_ms).expect("DER encodes");

    let expected = load("request.tsq");
    assert_eq!(
        built.der, expected,
        "build_request's output must equal, byte for byte, the request FreeTSA actually granted"
    );
}

#[test]
fn open_token_accepts_the_live_freetsa_response() {
    let message = load("message.txt");
    let sent_at_ms = GEN_TIME_MS - 60_000;
    let pending = build_request(&message, &NONCE, sent_at_ms).expect("DER encodes");

    let response = load("response.tsr");
    let cert = pinned_tsa_cert();
    // 1.2.3.4.1: FreeTSA's demo policy OID, read off this exact response
    // with `openssl asn1parse` (see fixtures/README.md).
    let policy = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.1");

    let accepted = open_token(
        &response,
        &pending,
        &[policy],
        std::slice::from_ref(&cert),
        GEN_TIME_MS,
        60_000,
        &verify_ecdsa_p384_sha512,
        &status_at_stub,
    )
    .unwrap_or_else(|e| panic!("a live, granted FreeTSA token must be accepted: {e:?}"));

    assert_eq!(accepted.gen_time_ms, GEN_TIME_MS);
    assert!(accepted.ordering, "FreeTSA's tsa.cnf sets ordering = yes");
    assert_eq!(accepted.policy, policy);
    assert_eq!(accepted.serial, hex_bytes("086B71DE"));
    // FreeTSA's response carried no `accuracy` field (`openssl ts -reply
    // -text` prints "Accuracy: unspecified" for it); Section 6 of the post
    // is explicit that this must not be read as an accuracy of zero.
    assert_eq!(
        accepted.bound,
        rfc_3161_vs_opentimestamps::tsp::Bound::Unstated
    );

    // `check_eku` (`block-4.rs`) is not `pub`, matching the post's own text
    // exactly, so it is not callable from here directly; `open_token`
    // above already called it as Check 5's second half, against this same
    // certificate, and `Ok(accepted)` above is proof it passed: FreeTSA's
    // TSA certificate carries a single, critical timeStamping EKU
    // (independently confirmed with `openssl x509 -text -ext
    // extendedKeyUsage`; see `fixtures/README.md`). The negative arms of
    // `check_eku` are unit-tested directly in `src/tsp.rs`, which is in the
    // same module and can call a private function.
}

/// The negative case for the same real cryptography: flipping one byte in
/// the DER signature must make `verify_ecdsa_p384_sha512` — and therefore
/// `open_token` — reject the token. This is what rules out a
/// `verify_signature` implementation that silently always returns `true`.
#[test]
fn open_token_rejects_the_response_with_a_tampered_signature() {
    let message = load("message.txt");
    let sent_at_ms = GEN_TIME_MS - 60_000;
    let pending = build_request(&message, &NONCE, sent_at_ms).expect("DER encodes");

    let mut response = load("response.tsr");
    // Flip a bit well inside the signature's raw octets (the last byte of
    // the response, which the ASN.1 dump in fixtures/README.md shows lands
    // inside the ECDSA-Sig-Value's `s` integer).
    let last = response.len() - 1;
    response[last] ^= 0x01;

    let cert = pinned_tsa_cert();
    let policy = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.1");

    let result = open_token(
        &response,
        &pending,
        &[policy],
        &[cert],
        GEN_TIME_MS,
        60_000,
        &verify_ecdsa_p384_sha512,
        &status_at_stub,
    );

    match result {
        Err(Reject::Signature) => {}
        Err(Reject::Malformed(_)) => {
            // Also acceptable: flipping the last byte can land outside the
            // signature and instead break DER structure elsewhere. Either
            // way the tampered response must not be `Ok`.
        }
        other => panic!("a tampered signature must not be accepted: {other:?}"),
    }
}

/// Check 1's `granted`/anything-else distinction, against a response this
/// test constructs (not a second live call): flip the status byte of a
/// copy of the real response and confirm `open_token` never reaches the
/// point of returning a token at all when the status is not `granted`.
#[test]
fn a_forged_rejection_status_short_circuits_before_the_signature_is_checked() {
    let message = load("message.txt");
    let sent_at_ms = GEN_TIME_MS - 60_000;
    let pending = build_request(&message, &NONCE, sent_at_ms).expect("DER encodes");

    let mut response = load("response.tsr");
    // The status INTEGER's content octet is at offset 8 in this response's
    // DER (see fixtures/README.md's asn1parse transcript: PKIStatusInfo's
    // SEQUENCE header is 2 bytes at offset 4, then the INTEGER's own tag
    // and length are 2 more bytes at offset 6, so its value octet is at
    // 4 + 2 + 2 = 8); 0 is `granted`, 2 is `rejection`.
    assert_eq!(
        response[8], 0x00,
        "expected the status octet at a fixed, documented offset"
    );
    response[8] = 0x02;

    let cert = pinned_tsa_cert();
    let policy = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.1");
    let result = open_token(
        &response,
        &pending,
        &[policy],
        &[cert],
        GEN_TIME_MS,
        60_000,
        // This closure must never run: a forged `rejection` status is
        // caught by Check 1, before Check 3 would call it.
        &|_, _| panic!("verify_signature must not run when status is not granted"),
        &status_at_stub,
    );

    assert!(matches!(result, Err(Reject::Status(_))));
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}
