use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::{QuoteClaims, QuoteCollateralV3, QuotePolicy, TcbStatus};
use sha2::{Digest, Sha256};

/// The reference values for one approved TD image. Who signs this, and how it
/// changes when the image is rebuilt, is the operator's decision (Section 7).
struct Manifest {
    mr_td: [u8; 48],
    rt_mr: [[u8; 48]; 4],
    /// Advisory identifiers this operator has reviewed and accepts. Anything
    /// else in the platform's advisory list is disqualifying.
    reviewed_advisories: Vec<String>,
}

fn verify_td(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3, // fetched live, mirrored, or loaded from a file
    now_secs: u64,
    manifest: &Manifest,
    csr_public_key_der: &[u8],
    nonce: &[u8; 32],
) -> Result<QuoteClaims, String> {
    // Decision 1, delegated to the verification library (dcap-qvl here,
    // reimplementing the QVL's checks): signature chain to the Intel root,
    // QE identity, TCB level against the collateral, collateral validity.
    // The policy says which TCB statuses this verifier accepts. The three
    // PCK flags describe the platform (SMT enabled, dynamic platform, cached
    // keys); `strict` rejects a platform that reports any of them, so accepting
    // them is a stated choice for the fleet you run.
    let policy = QuotePolicy::strict(now_secs)
        .allow_status(TcbStatus::SWHardeningNeeded)
        .allow_smt(true)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true);
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(raw_quote, collateral, now_secs, &policy)
        .map_err(|e| format!("quote rejected by verification library: {e:?}"))?;

    // Still decision 1: a status is a list of advisories. Fail closed on any
    // advisory the operator has not reviewed.
    for id in &claims.tcb.advisory_ids {
        if !manifest.reviewed_advisories.iter().any(|r| r == id) {
            return Err(format!("unreviewed advisory {id}"));
        }
    }

    // Decision 3, the operator's: measurements against the manifest.
    let td = claims.report.as_td10().ok_or("not a TDX report")?;
    if td.mr_td != manifest.mr_td {
        return Err("MRTD is not an approved image".into());
    }
    for (i, rt) in [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3].iter().enumerate() {
        if *rt != manifest.rt_mr[i] {
            return Err(format!("RTMR{i} does not match the manifest"));
        }
    }

    // Decision 4, the operator's: the quote must bind the key being certified
    // and the nonce this verifier issued for this request.
    let mut h = Sha256::new();
    h.update(b"attestation-binding-v1");
    h.update(csr_public_key_der);
    h.update(nonce);
    let expected: [u8; 32] = h.finalize().into();
    if td.report_data[..32] != expected || td.report_data[32..] != [0u8; 32] {
        return Err("REPORTDATA does not bind this key and nonce".into());
    }
    Ok(claims)
}
