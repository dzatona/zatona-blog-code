# Listing provenance

Extracted with `scripts/extract_listing.py` (repo root), which copies the
lines between a fenced ```rust block's opening and closing fence verbatim,
with no reformatting. Source: `content/blog/rfc-3161-vs-opentimestamps.mdx`
in the zatona.dev site repository, at the revision the post was published.

The post has seven fenced code blocks in total; six are ```rust (extracted
below) and one, the annotated hex dump under "The bytes" (Section 4), is
```text — not code, not extracted.

| File | Post source lines | Section | SHA-256 of extracted bytes |
| --- | --- | --- | --- |
| `listings/block-1.rs` | 95–155  | 2 | `6aa0626ef3879adba2c5fbe0ed9845aa5463a83731f701159831417eb55bae38` |
| `listings/block-2.rs` | 182–305 | 3 | `c8139285d7718e03253707bee5b61ea32a3d152728d073d7977f3e677421abd2` |
| `listings/block-3.rs` | 311–377 | 3 | `9581a636da1b53d67c6a44097a56e5108db16f44225a60a67d39da09231aefd3` |
| `listings/block-4.rs` | 385–411 | 3 | `3c6de5664b9a6952b6a0683a4e9d0233d7ba21d48b9767a0665e44cc3e38a530` |
| `listings/block-5.rs` | 508–693 | 5 | `0a42355fc775daad5044cb085add5010b0e3ce75eb4418c7ddce01094a1828ae` |
| `listings/block-6.rs` | 719–759 | 6 | `ee2376806337128d4ec678d692819bde10cacfe7d40891f8b41d7aa6ea48503a` |

`block-1.rs` through `block-4.rs` and `block-6.rs` are `include!`d into
`src/tsp.rs`; `block-5.rs` is `include!`d into `src/ots.rs`. Neither file
edits the included bytes; each module's own doc comment says exactly what
glue surrounds them and why (`signer_certificate`, `Reject`, `Accepted`,
`Bound`, `CertStatus`, `Reached`, `BitcoinCommitment` are not in any
listing — the post describes what they do in prose without printing a
listing for them, most explicitly for `signer_certificate`: "Identification
comes from the certificate identifier in the signerInfo").

## Known, unfixed warnings

Two `cargo clippy --all-targets` warnings come from inside the listings
themselves and are left as published, not patched, per this repository's
rule against silently changing a listing:

- `listings/block-1.rs:43`, `digest.as_slice()`: `deprecated`
  (`GenericArray::as_slice`) — the pinned `sha2`/`generic-array` versions
  postdate whatever the post's crates.io snapshot used.
- `listings/block-5.rs:146`, `best.map_or(true, |(h, _)| c.height < h)`:
  `clippy::unnecessary_map_or`, suggesting `Option::is_none_or` — a method
  that did not exist when this pattern was idiomatic and the post was
  written.
