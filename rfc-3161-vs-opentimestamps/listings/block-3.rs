/// RFC 3161 Section 2.4.2: the token's `messageImprint` "MUST have the same
/// value as the similar field in TimeStampReq" — the whole structure, not just
/// the digest. Comparing the DER byte for byte is the literal reading and it
/// rejects correct tokens, but only for one family of algorithms, so the
/// exception is scoped to that family and everything else matches exactly.
fn same_imprint(token: &MessageImprint, request: &MessageImprint) -> bool {
    token.hashed_message.as_bytes() == request.hashed_message.as_bytes()
        && token.hash_algorithm.oid == request.hash_algorithm.oid
        && params_equal(&token.hash_algorithm, &request.hash_algorithm)
}

/// The SHA-2 identifiers are the exception. RFC 5754 Section 2 requires
/// implementations to "accept SHA2 AlgorithmIdentifiers with absent
/// parameters" and equally with NULL, while generating the absent form, so
/// both encodings mean the same algorithm and either may arrive.
///
/// This does not generalise. Under RFC 4055 an algorithm's parameters can
/// carry meaning — RSASSA-PSS is the obvious case — and treating an absent
/// field as equal to a present one there would erase part of the algorithm.
/// So the normalisation applies to this list of OIDs and to nothing else.
const SHA2_OIDS: [ObjectIdentifier; 4] = [ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512];

fn params_equal(a: &AlgorithmIdentifier<Any>, b: &AlgorithmIdentifier<Any>) -> bool {
    if SHA2_OIDS.contains(&a.oid) {
        return absent_or_null(a) == absent_or_null(b);
    }
    match (a.parameters.as_ref(), b.parameters.as_ref()) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// True when the parameters field is absent or an explicit NULL.
fn absent_or_null(alg: &AlgorithmIdentifier<Any>) -> bool {
    match alg.parameters.as_ref() {
        None => true,
        Some(p) => p.tag() == Tag::Null,
    }
}

/// RFC 3161 Section 2.4.2 on the `tsa` field: "If present, it MUST correspond
/// to one of the subject names included in the certificate that is to be used
/// to verify the token." The subject names are the certificate's `subject` and
/// the entries of its subjectAltName extension.
///
/// This compares the decoded names structurally, which is not what a complete
/// verifier does. RFC 5280 Section 7.1 requires "a more comprehensive handling
/// of comparison" than binary equality: distinguished names that are equivalent
/// can differ in their ASN.1 representation, and DNS names compare without
/// regard to case. So this listing will reject some correct tokens. It errs in
/// the strict direction, which is the survivable one, but a production
/// verifier replaces it with a normalising comparison rather than shipping it.
pub fn tsa_name_matches(tsa: &GeneralName, cert: &Certificate) -> bool {
    if let GeneralName::DirectoryName(name) = tsa {
        if name == &cert.tbs_certificate.subject {
            return true;
        }
    }
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    exts.iter()
        .filter(|e| e.extn_id == SubjectAltName::OID)
        .filter_map(|e| SubjectAltName::from_der(e.extn_value.as_bytes()).ok())
        .any(|san| san.0.iter().any(|n| n == tsa))
}
