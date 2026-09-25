//! The RFC 3161 half: Sections 2, 3 and 6 of the post, reassembled into a
//! verifier. `x509-tsp` and `cms` parse; this module adds the checks RFC
//! 3161 Section 2.2 lists and the post says no published crate makes.
//!
//! ## What is byte-identical to the post, and what is glue
//!
//! `listings/block-1.rs` through `block-6.rs` (`block-5.rs` is the
//! OpenTimestamps half, in [`crate::ots`]) are `include!`d below,
//! unmodified; extraction method and a checksum for each are in
//! `PROVENANCE.md`. Everything else in this file — the `use` items this
//! module needs beyond what `block-1.rs` already imports, the `Reject`,
//! `Accepted`, `Bound` and `CertStatus` types `open_token` (`block-2.rs`)
//! returns and matches on, `signed_data_of`/`unix_millis`/
//! `signer_certificate`, and [`verify_issued_by`] — is glue the post's
//! prose describes without printing a listing for. `signer_certificate` in
//! particular: the post's Section 3 says identification "comes from the
//! certificate identifier in the signerInfo," which is CMS's
//! `SignerIdentifier` (RFC 5652 Section 5.3) — `IssuerAndSerialNumber` or
//! `SubjectKeyIdentifier` — matched against the caller's `pinned_certs`.
//!
//! **On "the chain."** The post's own summary of what the ecosystem's
//! crates leave to the caller — "the signature check, the chain, the
//! extended key usage and the revocation decision are yours" — names four
//! things, and `open_token` (`block-2.rs`) itself implements exactly three
//! of them as its own steps: the signature check (Check 3, delegated to a
//! caller closure this crate implements for real), the extended key usage
//! (`check_eku`), and the revocation decision (`status_at`, a caller
//! closure — see "What is not tested" below). `open_token`'s Check 3
//! identifies and trusts a certificate from `pinned_certs` directly; it
//! has no path-building step to a separate root, so "the chain" is not
//! something the listing itself does. [`verify_issued_by`] is this
//! module's own addition, checked with real RSA-4096/SHA-512
//! cryptography against FreeTSA's real root in
//! `tests/live_freetsa_token.rs`, before that test pins FreeTSA's TSA
//! certificate — but it is one signature link, not RFC 5280 path
//! building; see its own doc comment for exactly what it does not do.
//!
//! ## What is tested
//!
//! `tests/live_freetsa_token.rs` runs [`build_request`] and [`open_token`]
//! against a real response from FreeTSA's public server (fixture and
//! provenance in `fixtures/`), including a real ECDSA P-384/SHA-512
//! signature verification (not a canned "always true" closure) and
//! [`check_eku`] against the real TSA certificate's extended key usage.
//! Separately, [`verify_issued_by`] checks — with real RSA-4096/SHA-512
//! verification, not a stub — that FreeTSA's real TSA certificate is
//! signed by FreeTSA's real, separately-fetched root, both as its own
//! test and inline before the accepting test pins that certificate.
//!
//! ## What is not tested
//!
//! `status_at` — Check 5's revocation half — has no crate in this stack
//! either, per the post's own text, and this crate does not fetch a CRL or
//! OCSP response for FreeTSA's certificate. The test's `status_at` closure
//! is a stub that always returns [`CertStatus::Good`], and says so.
//! Nothing about `open_token`'s revocation-status *handling* (the
//! `match status_at(...)` arms) is left untested by that, since the other
//! three arms are exercised directly against the enum, not through the
//! network. [`verify_issued_by`] is one signature link, not multi-hop path
//! building, `basicConstraints`/`keyUsage`/name-constraint checking, or
//! validity-period checking — FreeTSA's certificate hierarchy is exactly
//! two certificates deep, so one link is what a chain check needs here,
//! but a general path-building verifier this is not.

use cmpv2::status::PkiStatus;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::db::rfc5912::{ID_SHA_224, ID_SHA_384, ID_SHA_512};
use const_oid::AssociatedOid;
use der::asn1::ObjectIdentifier;
use der::{Any, Decode, Tag, Tagged};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampResp, TimeStampToken, TspVersion, TstInfo};

/// `id-ct-TSTInfo`, RFC 3161 Section 2.4.2 / RFC 5652: `1.2.840.113549.1.9.16.1.4`.
/// Not in `const-oid`'s 0.9 database (no `rfc3161` module there), so it is
/// stated directly; the digits are the OID this crate's own live fixture
/// carries as `encapContentInfo.eContentType` (`tests/live_freetsa_token.rs`
/// checks the fixture's raw bytes against it independently of this constant).
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Every way `open_token` (Section 3, `block-2.rs`) can refuse a response.
/// Not printed in the post; the post names each check but leaves its
/// caller-facing error type to the reader.
#[derive(Debug)]
pub enum Reject {
    /// A structure did not parse as the named ASN.1 type.
    Malformed(&'static str),
    /// `PKIStatusInfo.status` was not `granted`.
    Status(PkiStatus),
    /// Check 2: the token's `messageImprint` does not match the request's.
    ImprintMismatch,
    /// Check 3: no certificate in `pinned_certs` matches the signerInfo's
    /// `SignerIdentifier`.
    SignerNotFound,
    /// Check 3: the CMS signature did not verify under the signer's key.
    Signature,
    /// Check 3: the `tsa` field names a subject the signer certificate does
    /// not carry.
    TsaNameMismatch,
    /// Check 4: the token's nonce is absent or does not match the request's.
    NonceMismatch,
    /// Check 4: `genTime` (plus/minus `accuracy`) is outside the accepted
    /// skew of the local clock and the request's send time.
    NotTimely,
    /// Check 5: the signer certificate was revoked before `genTime`.
    Revoked,
    /// Check 5: the caller's `status_at` could not determine a status.
    RevocationUnknown,
    /// Check 5 continued: the extended key usage extension is missing,
    /// non-critical, repeated, or names something other than exactly
    /// `id-kp-timeStamping`.
    Eku(&'static str),
    /// Check 6: the token's policy OID is not in `accepted_policies`.
    Policy,
}

/// `genTime`'s stated bound, or the absence of one. A result type with only
/// `not_before`/`not_after` fields cannot distinguish "the token stated an
/// accuracy of zero" from "the token stated no accuracy at all" — the post's
/// Section 6 names this failure mode directly — so the bound is this enum,
/// not two `i64`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The token carried an `accuracy` field.
    Stated {
        /// `genTime - accuracy`, saturating.
        not_before_ms: i64,
        /// `genTime + accuracy`, saturating.
        not_after_ms: i64,
    },
    /// The token carried no `accuracy` field. Not an accuracy of zero.
    Unstated,
}

/// What `open_token` returns once every check in RFC 3161 Section 2.2 has
/// passed.
#[derive(Debug)]
pub struct Accepted {
    /// `genTime`, in milliseconds since the Unix epoch (whole seconds only;
    /// see `unix_millis`).
    pub gen_time_ms: i64,
    /// `genTime`'s bound, if the token stated one.
    pub bound: Bound,
    /// Whether tokens from this TSA can be totally ordered by `genTime`
    /// (RFC 3161 Section 2.4.2).
    pub ordering: bool,
    /// The policy OID the token was issued under.
    pub policy: ObjectIdentifier,
    /// The TSA's serial number for this token.
    pub serial: Vec<u8>,
}

/// A certificate's revocation status as of a stated moment (`genTime`, in
/// `open_token`'s use), never "as of now" — the post's Section 3 explains
/// why the two differ. The caller's `status_at` closure produces this;
/// `open_token` (`block-2.rs`) only matches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Not revoked as of the stated moment.
    Good,
    /// Revoked, but at or after the stated moment, with a `reasonCode` that
    /// RFC 3161 Section 4 treats as not invalidating tokens signed before
    /// the revocation (`unspecified`, `affiliationChanged`, `superseded`,
    /// `cessationOfOperation`).
    RevokedAfterWithReason,
    /// Revoked before the stated moment, or revoked with `reasonCode`
    /// absent (RFC 3161 Section 4: every token from that key is invalid).
    RevokedBefore,
    /// No revocation data covering the stated moment was available.
    Unknown,
}

/// Extract the `SignedData` a `TimeStampToken` (`= ContentInfo`) carries.
/// Mirrors `x509-tsp`'s own test (`x509_tsp::tests::response_test`), which
/// round-trips through `content.to_der()` because `ContentInfo.content` is
/// an untyped `Any`.
fn signed_data_of(token: &TimeStampToken) -> Result<SignedData, Reject> {
    use der::Encode;
    let der = token
        .content
        .to_der()
        .map_err(|_| Reject::Malformed("ContentInfo.content"))?;
    SignedData::from_der(&der).map_err(|_| Reject::Malformed("SignedData"))
}

/// `TstInfo.gen_time` as milliseconds since the Unix epoch. RFC 3161 permits
/// fractional seconds in `genTime`; `der`'s `GeneralizedTime` does not decode
/// them, so a token that used them never reaches this function at all (it
/// fails to parse as `TstInfo` first) and whole seconds is genuinely all
/// this stack ever has, not a rounding choice made here.
fn unix_millis(tst: &TstInfo) -> Option<i64> {
    let secs = i64::try_from(tst.gen_time.to_unix_duration().as_secs()).ok()?;
    secs.checked_mul(1000)
}

/// Check 3's identification step: which certificate in `pinned_certs` the
/// signerInfo names. RFC 5652 Section 5.3 defines `SignerIdentifier` as
/// `IssuerAndSerialNumber` or `SubjectKeyIdentifier`; both are matched
/// structurally against each candidate, and the first match wins (a
/// `pinned_certs` list with two certificates sharing an identifier is a
/// caller error this function does not detect).
fn signer_certificate(
    signed_data: &SignedData,
    pinned_certs: &[Certificate],
) -> Option<Certificate> {
    let signer_info = signed_data.signer_infos.0.iter().next()?;
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => pinned_certs
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(skid) => pinned_certs
            .iter()
            .find(|c| {
                let Some(exts) = c.tbs_certificate.extensions.as_ref() else {
                    return false;
                };
                exts.iter()
                    .filter(|e| e.extn_id == x509_cert::ext::pkix::SubjectKeyIdentifier::OID)
                    .filter_map(|e| {
                        x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                            e.extn_value.as_bytes(),
                        )
                        .ok()
                    })
                    .any(|cert_skid| cert_skid == *skid)
            })
            .cloned(),
    }
}

/// One link of X.509 path validation: does `issuer`'s public key verify
/// `child`'s signature over `child`'s own `TBSCertificate`?
///
/// This is *not* full RFC 5280 path building. There is no search for an
/// issuer among a candidate set, no `basicConstraints`/`keyUsage`/
/// `pathLenConstraint`/name-constraint checking, no validity-period check,
/// and no support for more than the one signature algorithm this crate's
/// real fixture actually uses (`sha512WithRSAEncryption`, RSA PKCS#1 v1.5
/// — FreeTSA's own root and TSA certificate both use it; see
/// `fixtures/README.md`). What it does check is real: it recomputes the
/// child's `TBSCertificate` DER, verifies the RSA signature over it with
/// the issuer's own public key, and returns `false` on any mismatch or on
/// an algorithm this function does not implement — it never returns `true`
/// without having checked a signature.
///
/// `open_token` (`block-2.rs`) has no chain-validation step of its own:
/// its Check 3 identifies and trusts a certificate from `pinned_certs`
/// directly (RFC 3161 Section 2.2's "verify that the token carries the
/// correct certificate identifier of the TSA"), which is direct
/// certificate pinning, not a path walk to a separate root. This function
/// exists so that the certificate a caller chooses to pin can itself be
/// checked against an independently held root, rather than trusted on
/// sight — see `tests/live_freetsa_token.rs` for where that check runs
/// before FreeTSA's TSA certificate is pinned.
pub fn verify_issued_by(child: &Certificate, issuer: &Certificate) -> bool {
    use der::Encode;
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use sha2::{Digest, Sha512};

    const SHA512_WITH_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.13";
    if child.signature_algorithm.oid.to_string() != SHA512_WITH_RSA_ENCRYPTION {
        return false;
    }

    let Ok(spki_der) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    let Ok(spki_ref) = spki::SubjectPublicKeyInfoRef::from_der(&spki_der) else {
        return false;
    };
    let Ok(public_key) = RsaPublicKey::try_from(spki_ref) else {
        return false;
    };

    let Ok(tbs_der) = child.tbs_certificate.to_der() else {
        return false;
    };
    let Some(signature_bytes) = child.signature.as_bytes() else {
        return false;
    };
    let digest = Sha512::digest(&tbs_der);

    public_key
        .verify(Pkcs1v15Sign::new::<Sha512>(), &digest, signature_bytes)
        .is_ok()
}

// `#[allow(...)]` on an `include!` invocation itself is ignored by rustc
// ("the built-in attribute `allow` will be ignored, since it's applied to
// the macro invocation `include`"); wrapping the one listing that produces
// a warning in its own module, with the attribute on the *module*, scopes
// the allow to exactly that listing's own generated items and nothing
// else in this file -- CI's `-D warnings` still fails on any new warning
// anywhere else. `pub use block_1::*;` re-exports `PendingRequest`,
// `nonce_integer` and `build_request` into this module's own namespace, so
// `block-2.rs`, `block-3.rs`, `block-4.rs` and `block-6.rs` below (which
// use `PendingRequest` and are not wrapped, because they warn about
// nothing) see them exactly as if `block-1.rs` were included flat here, as
// in every other crate in this repository.
#[allow(deprecated)] // block-1.rs:43, digest.as_slice() -- see PROVENANCE.md
mod block_1 {
    include!("../listings/block-1.rs");
}
pub use block_1::*;

include!("../listings/block-3.rs");
include!("../listings/block-4.rs");
include!("../listings/block-6.rs");
include!("../listings/block-2.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{GeneralizedTime, Int};
    use std::time::Duration;
    use x509_tsp::Accuracy;

    fn imprint(oid: ObjectIdentifier, params: Option<der::Any>, digest: &[u8]) -> MessageImprint {
        MessageImprint {
            hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
                oid,
                parameters: params,
            },
            hashed_message: der::asn1::OctetString::new(digest).unwrap(),
        }
    }

    #[test]
    fn same_imprint_requires_equal_digest_and_algorithm() {
        let a = imprint(ID_SHA_256, None, &[1, 2, 3]);
        let b = imprint(ID_SHA_256, None, &[1, 2, 3]);
        assert!(same_imprint(&a, &b));

        let different_digest = imprint(ID_SHA_256, None, &[9, 9, 9]);
        assert!(!same_imprint(&a, &different_digest));

        let different_alg = imprint(ID_SHA_384, None, &[1, 2, 3]);
        assert!(!same_imprint(&a, &different_alg));
    }

    /// RFC 5754 Section 2: a SHA-2 `AlgorithmIdentifier` with absent
    /// parameters and one with explicit NULL parameters are the same
    /// algorithm. `same_imprint` must accept this pair even though their
    /// DER encodings differ byte for byte.
    #[test]
    fn sha2_absent_and_null_parameters_are_equivalent() {
        let absent = imprint(ID_SHA_256, None, &[1, 2, 3]);
        let explicit_null = imprint(
            ID_SHA_256,
            Some(der::Any::from(der::asn1::Null)),
            &[1, 2, 3],
        );
        assert!(same_imprint(&absent, &explicit_null));
    }

    /// The exception does not generalize: outside the SHA-2 OID list, an
    /// absent-vs-explicit-NULL difference in parameters is a real
    /// difference (RSASSA-PSS is the post's own example of why).
    #[test]
    fn the_sha2_exception_does_not_apply_to_other_algorithms() {
        let not_sha2 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"); // RSASSA-PSS
        let absent = imprint(not_sha2, None, &[1, 2, 3]);
        let explicit_null = imprint(not_sha2, Some(der::Any::from(der::asn1::Null)), &[1, 2, 3]);
        assert!(!params_equal(
            &absent.hash_algorithm,
            &explicit_null.hash_algorithm
        ));
    }

    #[test]
    fn in_range_accepts_1_to_999_and_treats_absence_as_zero() {
        assert_eq!(in_range(None).unwrap(), 0);
        assert_eq!(in_range(Some(1)).unwrap(), 1);
        assert_eq!(in_range(Some(999)).unwrap(), 999);
        assert!(
            in_range(Some(0)).is_err(),
            "0 is out of RFC 3161's 1..999 range for a stated value"
        );
        assert!(in_range(Some(1000)).is_err());
        assert!(in_range(Some(-1)).is_err());
    }

    fn minimal_tst_info(accuracy: Option<Accuracy>) -> TstInfo {
        TstInfo {
            version: TspVersion::V1,
            policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
            message_imprint: imprint(ID_SHA_256, None, &[0u8; 32]),
            serial_number: Int::new(&[1]).unwrap(),
            gen_time: GeneralizedTime::from_unix_duration(Duration::from_secs(1_790_310_983))
                .unwrap(),
            accuracy,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        }
    }

    /// Section 6: an absent `accuracy` is not an accuracy of zero.
    #[test]
    fn accuracy_millis_returns_none_when_the_token_states_no_accuracy() {
        let tst = minimal_tst_info(None);
        assert_eq!(accuracy_millis(&tst).unwrap(), None);
    }

    /// The worked case FreeTSA's own demo policy configuration uses
    /// (`accuracy = secs:1, millisecs:500, microsecs:100` in `tsa.cnf`,
    /// matching `x509-tsp`'s own `response_test`): 1s + 500ms rounds to
    /// 1500ms, and 100us rounds *outward* to 1ms more, per the post's own
    /// comment on why sub-millisecond accuracy rounds outward.
    #[test]
    fn accuracy_millis_sums_seconds_millis_and_rounds_micros_outward() {
        let tst = minimal_tst_info(Some(Accuracy {
            seconds: Some(1),
            millis: Some(500),
            micros: Some(100),
        }));
        assert_eq!(accuracy_millis(&tst).unwrap(), Some(1_501));
    }

    #[test]
    fn accuracy_millis_rejects_an_out_of_range_millis_component() {
        let tst = minimal_tst_info(Some(Accuracy {
            seconds: None,
            millis: Some(0),
            micros: None,
        }));
        assert!(matches!(accuracy_millis(&tst), Err(Reject::Malformed(_))));
    }

    fn load_fixture_cert(name: &str) -> Certificate {
        let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let der = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        Certificate::from_der(&der).expect("a valid DER certificate")
    }

    /// The positive case (FreeTSA's real certificate, exactly one critical
    /// `id-kp-timeStamping` purpose) is exercised through `open_token` in
    /// `tests/live_freetsa_token.rs`; the three negative branches need
    /// certificates that do not exist in the wild, so they are synthetic
    /// (generated with `openssl req -x509 ... -addext extendedKeyUsage=...`;
    /// see `fixtures/README.md`).
    #[test]
    fn check_eku_rejects_a_certificate_with_no_extended_key_usage() {
        let cert = load_fixture_cert("synthetic-no-eku.der");
        assert!(matches!(check_eku(&cert), Err(Reject::Eku(_))));
    }

    #[test]
    fn check_eku_rejects_a_noncritical_extension() {
        let cert = load_fixture_cert("synthetic-noncritical-eku.der");
        assert!(matches!(check_eku(&cert), Err(Reject::Eku(_))));
    }

    #[test]
    fn check_eku_rejects_a_second_purpose_alongside_timestamping() {
        let cert = load_fixture_cert("synthetic-two-purpose-eku.der");
        assert!(matches!(check_eku(&cert), Err(Reject::Eku(_))));
    }
}
