# rfc-3161-vs-opentimestamps

Code for [zatona.dev/blog/rfc-3161-vs-opentimestamps](https://zatona.dev/blog/rfc-3161-vs-opentimestamps).

The post's own framing: `x509-tsp` and `cms` parse RFC 3161's ASN.1 and
verify nothing; "the signature check, the chain, the extended key usage
and the revocation decision are yours." This crate reconstructs that —
the six fenced ```rust blocks the post prints (`listings/`, checksums and
line ranges in `PROVENANCE.md`), plus the glue the post describes in prose
without printing a listing for (`Reject`, `Accepted`, `Bound`,
`CertStatus`, and `signer_certificate` for the RFC 3161 half in
[`src/tsp.rs`](src/tsp.rs); `Reached` and `BitcoinCommitment` for the
OpenTimestamps half in [`src/ots.rs`](src/ots.rs)).

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
