/// RFC 3161 Section 2.4.2: adding accuracy to genTime gives an upper limit and
/// subtracting it a lower one, and "a value of zero MUST be taken for the
/// missing field" — that rule is about a missing *component*, not a missing
/// `accuracy`. `None` here means the token stated no accuracy at all, which
/// the caller must not read as zero.
///
/// Milliseconds, because the field carries millis and micros; sub-millisecond
/// accuracy rounds outward, so the interval is never narrower than the RFC's.
///
/// Every number arrives on the wire. `millis` and `micros` are typed `i16` by
/// the crate while the RFC constrains them to 1..999, and `seconds` is a `u64`
/// with no ceiling at all, so out-of-range values are rejected as malformed
/// and the arithmetic is checked. A verifier that clamps instead reports a
/// narrower interval than the token claims.
fn accuracy_millis(tst: &TstInfo) -> Result<Option<i64>, Reject> {
    let Some(a) = tst.accuracy.as_ref() else {
        // Not zero: unstated. RFC 3161 says the bound "may be available
        // through other means, e.g., the TSAPolicyId", and this function
        // cannot read a policy document.
        return Ok(None);
    };
    let secs = i64::try_from(a.seconds.unwrap_or(0)).map_err(|_| Reject::Malformed("accuracy"))?;
    let millis = in_range(a.millis)?;
    let micros = in_range(a.micros)?;
    secs.checked_mul(1000)
        .and_then(|ms| ms.checked_add(millis))
        .and_then(|ms| ms.checked_add((micros + 999) / 1000))
        .map(Some)
        .ok_or(Reject::Malformed("accuracy"))
}

/// `Accuracy`'s millis and micros are `INTEGER (1..999)` in RFC 3161, and
/// absent means zero. Anything else is malformed, including the zero the
/// crate's `i16` allows and the negatives it also allows.
fn in_range(v: Option<i16>) -> Result<i64, Reject> {
    match v {
        None => Ok(0),
        Some(n) if (1..=999).contains(&n) => Ok(n as i64),
        Some(_) => Err(Reject::Malformed("accuracy")),
    }
}
