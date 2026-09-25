/// RFC 3161 Section 2.2, in order. Two arguments carry the work no crate in
/// this stack does: `verify_signature` over the CMS SignedData, and
/// `status_at`, which has to answer for the moment in `genTime`, not for now.
#[allow(clippy::too_many_arguments)]
pub fn open_token(
    resp_der: &[u8],
    req: &PendingRequest,
    accepted_policies: &[ObjectIdentifier],
    pinned_certs: &[Certificate],
    local_now_ms: i64,
    max_skew_ms: i64,
    verify_signature: &dyn Fn(&SignedData, &Certificate) -> bool,
    status_at: &dyn Fn(&Certificate, i64) -> CertStatus,
) -> Result<Accepted, Reject> {
    let resp = TimeStampResp::from_der(resp_der).map_err(|_| Reject::Malformed("TimeStampResp"))?;

    // Check 1. Only `granted` is a token this code accepts without further
    // work. `grantedWithMods` also carries a token, and RFC 3161 says that
    // token differs from what was asked for; accepting it silently means
    // accepting a modification nobody read. Everything else, including
    // keyUpdateWarning (6), which RFC 4210 defines and RFC 3161 does not,
    // is an error: a compliant client errors on values it does not understand.
    if resp.status.status != PkiStatus::Accepted {
        return Err(Reject::Status(resp.status.status));
    }
    let token = resp.time_stamp_token.ok_or(Reject::Malformed("no token"))?;
    let signed_data = signed_data_of(&token)?;
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Reject::Malformed("no eContent"))?;
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(Reject::Malformed("eContentType is not id-ct-TSTInfo"));
    }
    let tst = TstInfo::from_der(econtent.value()).map_err(|_| Reject::Malformed("TSTInfo"))?;
    if tst.version != TspVersion::V1 {
        return Err(Reject::Malformed("TSTInfo version"));
    }

    // Check 2. What was time-stamped is what was requested: the whole
    // MessageImprint, algorithm identifier included, not only the digest.
    if !same_imprint(&tst.message_imprint, &req.imprint) {
        return Err(Reject::ImprintMismatch);
    }

    // Check 3. Identify the signer, then verify the signature with the key in
    // that certificate. Identification comes from the certificate identifier
    // in the signerInfo; the `tsa` field is a hint and cannot select a key.
    // But the hint is not free-form: RFC 3161 Section 2.4.2 says that if it is
    // present it "MUST correspond to one of the subject names included in the
    // certificate that is to be used to verify the token", so a token whose
    // name points somewhere else is malformed and gets rejected here.
    let signer = signer_certificate(&signed_data, pinned_certs).ok_or(Reject::SignerNotFound)?;
    if !verify_signature(&signed_data, &signer) {
        return Err(Reject::Signature);
    }
    if let Some(name) = tst.tsa.as_ref() {
        if !tsa_name_matches(name, &signer) {
            return Err(Reject::TsaNameMismatch);
        }
    }

    // Check 4. Timeliness, by the nonce and by the local clock. The nonce is
    // the only one of the two that works without a trusted local clock.
    match &tst.nonce {
        Some(n) if n.as_bytes() == req.nonce.as_slice() => {}
        _ => return Err(Reject::NonceMismatch),
    }
    let gen_time_ms = unix_millis(&tst).ok_or(Reject::Malformed("genTime"))?;
    let stated = accuracy_millis(&tst)?;
    // For the window, an unstated accuracy contributes no slack. That is the
    // strict choice and it belongs here, in a comparison against the client's
    // own clock; what it must not do is travel onward as if the token had
    // claimed an interval of zero, which is why `bound` keeps the difference.
    // Saturating, because every operand comes off the wire: an overflow that
    // wrapped would move a bound past the value it is supposed to bound, and
    // the check would pass for the wrong reason.
    let slack = stated.unwrap_or(0);
    let not_before_ms = gen_time_ms.saturating_sub(slack);
    let not_after_ms = gen_time_ms.saturating_add(slack);
    if not_before_ms > local_now_ms.saturating_add(max_skew_ms)
        || not_after_ms < req.sent_at_ms.saturating_sub(max_skew_ms)
    {
        return Err(Reject::NotTimely);
    }

    // Check 5. The certificate's status at genTime. `local_now_ms` is the
    // wrong question: a certificate revoked last week was valid when the token
    // was made, and a CRL fetched today may no longer list it at all.
    match status_at(&signer, gen_time_ms) {
        CertStatus::Good | CertStatus::RevokedAfterWithReason => {}
        CertStatus::RevokedBefore => return Err(Reject::Revoked),
        CertStatus::Unknown => return Err(Reject::RevocationUnknown),
    }

    // Check 5 continued, and the one most often missing: RFC 3161 Section 2.3
    // requires exactly one extended key usage, id-kp-timeStamping, marked
    // critical. A certificate that also carries serverAuth is not a TSA
    // certificate under this specification.
    check_eku(&signer)?;

    // Check 6. The policy the token was issued under is one this application
    // accepts. The list is a deployment decision, and an empty list means the
    // check was skipped rather than passed.
    if !accepted_policies.contains(&tst.policy) {
        return Err(Reject::Policy);
    }

    Ok(Accepted {
        gen_time_ms,
        bound: match stated {
            Some(_) => Bound::Stated {
                not_before_ms,
                not_after_ms,
            },
            None => Bound::Unstated,
        },
        ordering: tst.ordering,
        policy: tst.policy,
        serial: tst.serial_number.as_bytes().to_vec(),
    })
}

