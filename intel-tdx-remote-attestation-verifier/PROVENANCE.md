# Listing provenance

Extracted with `scripts/extract_listing.py` (repo root), which copies the
lines between a fenced ```rust block's opening and closing fence verbatim,
with no reformatting. Source:
`content/blog/intel-tdx-remote-attestation-verifier.mdx` in the zatona.dev
site repository. The post has one fenced ```rust block, in Section 6
("Binding the quote to a key and a moment"). The post has been revised
since this crate was first built and the block's line range moved with it
(the section number and the listing's own bytes did not change).

| File | Post source lines | SHA-256 of extracted bytes |
| --- | --- | --- |
| `listings/block-1.rs` | 150–218 | `c92e8cbb3fc8345894b41ee00c3b1cb00039ce7fa1748ac1760c96f7fd015d68` |

`listings/block-1.rs` is `include!`d whole into `src/lib.rs`, at module
(item) position, with no glue: every name the block uses is either defined
inside it or imported by its own `use` statements.
