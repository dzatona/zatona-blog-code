# intel-tdx-remote-attestation-verifier

Code for [zatona.dev/blog/intel-tdx-remote-attestation-verifier](https://zatona.dev/blog/intel-tdx-remote-attestation-verifier).

One listing (`listings/block-1.rs`, Section 6: `Manifest` and `verify_td`),
`include!`d unmodified into `src/lib.rs`. Checksum and extraction method
in `PROVENANCE.md`.

## What is tested

The post's own status sentence for this listing is exact: "It compiles; it
has not been exercised against hardware here." `Manifest` and `verify_td`
are not `pub` in the listing, so nothing outside `src/lib.rs` can even
construct a `Manifest`; the crate's tests are therefore unit tests in the
same module. They call `verify_td` through `dcap-qvl`'s real quote parser
with inputs that are not valid TDX quotes (`&[]` and 64 zero bytes) and
check it returns `Err` without panicking — the one thing this crate can
honestly claim to exercise without a TDX-capable machine.

## What is not tested

A real quote from a real TD, a real `QuoteCollateralV3` fetched from
Intel's PCCS, and therefore every one of the five decisions the post's
Section 1 lists. No network call happens anywhere in this crate.

## Running

```sh
cargo test
```
