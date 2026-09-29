# rfc-3161-vs-opentimestamps

Code for [zatona.dev/blog/rfc-3161-vs-opentimestamps](https://zatona.dev/blog/rfc-3161-vs-opentimestamps).

The post's own framing: `x509-tsp` and `cms` parse RFC 3161's ASN.1 and
verify nothing, leaving the signature check, the certificate chain, the
extended key usage and the revocation decision to the caller. This crate
reconstructs the six fenced ```rust blocks the post prints (`listings/`,
checksums and line ranges in `PROVENANCE.md`), plus the glue the post
describes in prose without printing a listing for (`Reject`, `Accepted`,
`Bound`, `CertStatus`, `signer_certificate` and `verify_issued_by` for the
RFC 3161 half in [`src/tsp.rs`](src/tsp.rs); `Reached` and
`BitcoinCommitment` for the OpenTimestamps half in
[`src/ots.rs`](src/ots.rs)).

Of those four caller responsibilities, `open_token` (Section 3's
`block-2.rs`) itself implements three as its own checks (signature, via a
caller closure this crate implements for real; EKU, via `check_eku`;
revocation, via a caller closure, stubbed here — see below). It has **no
chain-building step**: Check 3 trusts whatever certificate is in
`pinned_certs` directly, which is certificate pinning, not a path walk to
a root. `verify_issued_by` (`src/tsp.rs`) is this crate's own addition on
top, not part of the listing: real RSA-4096/SHA-512 verification that
FreeTSA's real TSA certificate is signed by FreeTSA's real,
separately-fetched root — one signature link, run before that certificate
is pinned, not general path building (see `verify_issued_by`'s own doc
comment for the exact scope). The chain is therefore the one caller
responsibility the listing does not implement, and this crate's own
`verify_issued_by` addition is what closes that specific gap, not a claim
that `open_token` does so internally.

## What is tested

- **RFC 3161** (`tests/live_freetsa_token.rs`): a real response from
  FreeTSA, a public Time Stamping Authority, fetched once and committed as
  a fixture (`fixtures/`, full provenance and the exact commands run in
  `fixtures/README.md`).
  - `build_request` reproduces, byte for byte, the actual request FreeTSA
    granted.
  - `open_token` accepts that response, with a real ECDSA P-384/SHA-512
    signature verification over the CMS signed attributes (not a stub that
    always returns `true`) and a real check of `check_eku` against
    FreeTSA's real certificate.
  - Before that, `verify_issued_by` checks — with real RSA-4096/SHA-512
    verification, not a stub — that the certificate being pinned really is
    signed by FreeTSA's real, separately-fetched root; also its own test,
    plus two negative cases that are deliberately different failures: an
    unsupported-algorithm certificate rejected at the algorithm gate
    (before any RSA math runs), and FreeTSA's own real certificate with
    one signature byte flipped — correct algorithm, wrong signature —
    rejected by the RSA/SHA-512 check itself.
  - A tampered signature byte is rejected; a forged rejection status short
    circuits before the signature closure ever runs.
  - `check_eku`'s three rejecting paths (no EKU extension, a non-critical
    one, more than one purpose) run against synthetic certificates built
    for exactly this (`src/tsp.rs`'s unit tests).
  - `same_imprint`/`params_equal`, including the RFC 5754 SHA-2
    absent-vs-NULL-parameters exception and its limit, and
    `accuracy_millis`/`in_range`'s arithmetic, are unit-tested directly.
- **OpenTimestamps** (`tests/opentimestamps_examples.rs`): the reference
  client's own `hello-world.txt.ots` (688 bytes, 38 operations) replays to
  the exact Merkle root the post's Section 5 quotes for block 358391; that
  block's real header — fetched independently from a block explorer, not
  from the post or the OpenTimestamps calendar — makes the verdict
  `Anchored`. The same proof against a `HeaderSource` with nothing is
  `Indeterminate`; against the wrong root, `Contradicted`.
  `two-calendars.txt.ots` (265 bytes, matching the post's annotated hex
  dump) forks into two pending attestations and comes back `Indeterminate`
  with both calendar URIs recovered.

## What is not tested

- **Check 5's revocation half.** No crate in this stack fetches a CRL or
  OCSP response — the post says so explicitly — and neither does this one.
  `status_at` in the live test is a stub that always returns
  `CertStatus::Good`, and says so in its own doc comment.
- **A live Bitcoin node.** `ots::verify` never fetches a block header
  itself, by design (that is the post's whole point about where the trust
  decision sits); block 358391's header is a committed fixture, not a
  live call, and no other block height is exercised.
- **RFC 5816's `SigningCertificateV2` binding.** `signer_certificate`
  (glue, not a post listing) identifies the signer through CMS's own
  `SignerIdentifier` (`IssuerAndSerialNumber`/`SubjectKeyIdentifier`, RFC
  5652 Section 5.3), which is what this crate's real fixture actually
  carries. The post's own text on RFC 5816 is about a *different*,
  narrower gap — `ESSCertID`/`ESSCertIDv2` inside the `tsa` field's
  binding — and is not itself a listing this crate reconstructs.
- **General X.509 path building.** `verify_issued_by` is one signature
  link (child signed by a specific, named issuer), not a search over a
  candidate certificate set, not multi-hop path building, and it checks
  no `basicConstraints`, `keyUsage`, name constraint or validity period —
  see its own doc comment in `src/tsp.rs`. `open_token` itself has no
  chain step at all (see above); only the one link this repository's real
  fixtures have (FreeTSA's TSA certificate, signed directly by FreeTSA's
  root) is implemented or tested.
- **`grantedWithMods` and the other five `PKIStatusInfo` statuses**, and
  RFC 4210's `keyUpdateWarning`. Only `granted` (via the real fixture) and
  a forged `rejection` are exercised.

## A known, unfixed warning

See `PROVENANCE.md`: compiling `listings/block-1.rs` against the pinned
dependency versions produces one `deprecated` warning, from the listing's
own unedited line. Not patched.

## Running

```sh
cargo test
```
