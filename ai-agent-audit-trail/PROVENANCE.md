# Listing provenance

Extracted with `scripts/extract_listing.py` (repo root), which copies the
lines between a fenced ```rust block's opening and closing fence verbatim,
with no reformatting. Source: `content/blog/ai-agent-audit-trail.mdx` in
the zatona.dev site repository, at the revision the post was published.
The post has one fenced ```rust block.

| File | Post source lines | SHA-256 of extracted bytes |
| --- | --- | --- |
| `listings/block-1.rs` | 152–187 | `f221d5b0b51ade34f9276c19b6bf7f97104043dcae0c970b193343be8fda9dac` |

`listings/block-1.rs` is a sequence of `use` items and `let` statements,
not a complete function — Rust's `include!` macro cannot splice that
directly into a function body (it requires the target to be a single
expression at statement position; see `build.rs`'s own module docs for the
exact failure and why). `build.rs` reads the listing file's bytes
unmodified at every build and wraps them in a function signature,
generating `$OUT_DIR/wrapped_block_1.rs`, which `src/lib.rs` then
`include!`s at module (item) position. The listing file on disk is never
edited; `build.rs` fails the build if it is missing, so the wrapped copy
cannot silently drift from it.

`atl-core` is pinned to commit `6e652edf8029d2856321801e362b5f6a4dd0930c`
(a comment-only follow-up to `5229787cfcd5dcf76276435ae872feea3b6013e1`;
no compiled code differs between the two).
