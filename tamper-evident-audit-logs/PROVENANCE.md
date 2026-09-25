# Listing provenance

Extracted with `scripts/extract_listing.py` (repo root), which copies the
lines between a fenced ```rust block's opening and closing fence verbatim,
with no reformatting. Source: `content/blog/tamper-evident-audit-logs.mdx`
in the zatona.dev site repository. The post has been revised since this
crate was first built and both blocks' line ranges moved with it (Section
3, "Hash chain", and Section 4.3, "In code", did not change, and neither
did the listings' own bytes).

`atl-core` is pinned to commit `6e652edf8029d2856321801e362b5f6a4dd0930c`
(a comment-only follow-up to `5229787cfcd5dcf76276435ae872feea3b6013e1`,
the revision this crate was first built against; no compiled code differs
between the two).

| File | Post source lines | SHA-256 of extracted bytes |
| --- | --- | --- |
| `listings/block-1.rs` | 86–116 | `1390cb68a297bb3818c369e818b4c02984a0d3a6eb4fb4a859646d2ebdc023bb` |
| `listings/block-2.rs` | 150–199 | `7ac7d289a0eb7e06e66b29fa52836d8b34918bc3aebfb6f2fcfcb85d21fdab96` |
