# ai-agent-audit-trail

Code for [zatona.dev/blog/ai-agent-audit-trail](https://zatona.dev/blog/ai-agent-audit-trail).

One listing (`listings/block-1.rs`, Section 7), wrapped as a function by
`build.rs` because Rust's `include!` cannot splice a bare sequence of
`use`/`let` statements into a function body directly (see `PROVENANCE.md`
and `build.rs`'s own doc comment for the exact rustc error and the fix).
Checksum and extraction method in `PROVENANCE.md`.

## What is tested

`tests/live_freetsa_anchor.rs` runs `one_step` against a real, fully valid
ATL v2.0 receipt (`fixtures/receipt.json`, generated — not hand-written —
by `atl-core`'s own `ReceiptBuilder`) anchored to a real RFC 3161 token
fetched once from FreeTSA, specifically for this crate, over the receipt's
actual Data Tree root (full provenance, including a real integration bug
this found in `atl-core`'s own doc comment for `token_der`, in
`fixtures/README.md`; this token is a *separate* fetch from the one in the
`rfc-3161-vs-opentimestamps` crate, which times-tamps a different, unrelated
digest).

The write side is not merely executed — it is checked against the read
side. `build.rs` returns the listing's own computed `leaf` (the write
side's `payload_hash`/`metadata_hash`/`compute_leaf_hash` output,
unaltered) alongside the verification result, and the test calls
`one_step` with the exact `step_bytes` the fixture's `payload_hash` was
built from, with a `metadata` field the fixture reproduces byte-for-byte
from the listing's own `json!` literal. The test then asserts the write
side's `leaf` equals the read side's anchored root, decoded independently
from the receipt JSON (not through `atl-core`). The receipt is accepted
end to end (`result.is_valid`), not merely "anchor resolves." A second
test with an unrelated certificate as the trust root confirms the same
anchor does *not* verify without it.

## What is not tested

The post says the 2.1 witnessed-head receipt members are not yet
implemented in `atl-core`; this crate does not exercise them either.
`atl-core`'s anchor verification does not fetch a CRL or OCSP response for
the TSA certificate, and neither does this crate — there is no
`status_at`-equivalent call in this listing to stub.

## Dependency

`atl-core` is pinned by commit in `Cargo.toml`; see the top-level README
for how that pin is kept current.

## Running

```sh
cargo test
```
