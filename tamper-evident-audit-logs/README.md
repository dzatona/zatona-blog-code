# tamper-evident-audit-logs

Code for [zatona.dev/blog/tamper-evident-audit-logs](https://zatona.dev/blog/tamper-evident-audit-logs).

Two listings, both under `listings/` (verbatim, see `PROVENANCE.md`):

- `listings/block-1.rs` (Section 3) — a hash chain: `Entry`, `entry_hash`,
  `verify_chain`. Wrapped in `src/lib.rs` as `hash_chain`.
- `listings/block-2.rs` (Section 4.3) — an RFC 9162 Merkle tree against
  `atl-core`: leaf hashing, an inclusion proof, a consistency proof, and a
  rejected-rewrite check, all as `assert!`s inside the block's own `main`.
  Wrapped as `checkpoint_tree`.

## What is tested

- `hash_chain`: the post's own construction, plus cases the prose describes
  but does not code — an empty chain, a broken genesis pointer, an edit to
  an earlier entry breaking verification against the old head, and that
  same edit's tail regenerated so it verifies again against a *new* head —
  the limit a hash chain has on its own: whoever holds the chain can
  recompute every hash after an edit and produce a chain that verifies
  against a head of their own making, so only a head trusted from outside
  that holder catches the edit.
- `checkpoint_tree`: `main()` is called from a test and required to return
  `Ok`, which only happens if every `assert!` in the post's own listing —
  inclusion proof verifies, consistency proof verifies, and consistency
  fails against a rewritten old root — holds against `atl-core`'s real
  Merkle tree implementation.

## What is not tested

Nothing in either listing is left unexercised: block 2 is already a
self-contained example whose assertions are the properties the post
claims, and block 1's functions are exercised directly. Neither block
touches an external anchor (RFC 3161 or OpenTimestamps); those are the
subject of the `rfc-3161-vs-opentimestamps` crate in this repository.

## Dependency

`atl-core` is pinned by commit in `Cargo.toml` and in `Cargo.lock`; see the
top-level README for how that pin is kept current.

## Running

```sh
cargo test
```
