/// RFC 3161 Section 2.3: the certificate "MUST contain only one instance of
/// the extended key usage field extension", with `id-kp-timeStamping` as its
/// only purpose, and "This extension MUST be critical." All three are checked.
/// Parsing `ExtendedKeyUsage` out of the first matching extension would check
/// none of them: RFC 5280 forbids a repeated extension, and a verifier is the
/// thing that finds out when a certificate breaks that rule.
fn check_eku(cert: &Certificate) -> Result<(), Reject> {
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Reject::Eku("no extensions"))?;
    let mut matching = exts.iter().filter(|e| e.extn_id == ExtendedKeyUsage::OID);
    let ext = matching.next().ok_or(Reject::Eku("no extended key usage"))?;
    if matching.next().is_some() {
        return Err(Reject::Eku("more than one extended key usage extension"));
    }
    if !ext.critical {
        return Err(Reject::Eku("extended key usage is not critical"));
    }
    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|_| Reject::Eku("malformed extended key usage"))?;
    match eku.0.as_slice() {
        [only] if *only == ID_KP_TIME_STAMPING => Ok(()),
        _ => Err(Reject::Eku("not exactly one id-kp-timeStamping purpose")),
    }
}
