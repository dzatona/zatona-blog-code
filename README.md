# zatona-blog-code

Code artifacts for the [zatona.dev engineering blog](https://zatona.dev/blog).
One directory per post; each is a standalone Cargo crate whose sources
contain every Rust listing published in that post, byte-identical to the
post, plus the minimal glue needed to compile and test them, and tests
that exercise them the way the post's own status sentence claims — no
more, no less. Each crate's own `README.md` states exactly what is tested
and what is not; each crate's `PROVENANCE.md` records exactly how its
listings were extracted and checksummed.

| Directory | Post |
| --- | --- |
| [`rfc-3161-vs-opentimestamps`](rfc-3161-vs-opentimestamps/) | [zatona.dev/blog/rfc-3161-vs-opentimestamps](https://zatona.dev/blog/rfc-3161-vs-opentimestamps) |
| [`intel-tdx-remote-attestation-verifier`](intel-tdx-remote-attestation-verifier/) | [zatona.dev/blog/intel-tdx-remote-attestation-verifier](https://zatona.dev/blog/intel-tdx-remote-attestation-verifier) |
| [`tamper-evident-audit-logs`](tamper-evident-audit-logs/) | [zatona.dev/blog/tamper-evident-audit-logs](https://zatona.dev/blog/tamper-evident-audit-logs) |
| [`ai-agent-audit-trail`](ai-agent-audit-trail/) | [zatona.dev/blog/ai-agent-audit-trail](https://zatona.dev/blog/ai-agent-audit-trail) |

## How a listing gets here

`scripts/extract_listing.py <post.mdx> <out-prefix> <start:end> ...` copies
the lines between a fenced ```rust block's opening and closing fence
verbatim into `<crate>/listings/block-N.rs`, with no reformatting, and
prints a SHA-256 of the result for that crate's `PROVENANCE.md`. Nothing
in a `listings/` file is ever hand-edited; where a listing needs a
container it cannot supply itself (a `use`-then-`let` fragment has no
function to live in on its own, for example), the container is generated
or written in a sibling file — never inside `listings/` — and each crate's
own docs say exactly what that container is and why.

If a listing did not compile as published, that would be reported as a
defect in the post, not silently patched here. It has not come up: all
four posts' Rust compiles as published.

## `atl-core`

Two crates depend on `atl-core`, the reference verification library for
[ATL](https://atl-protocol.org):

```toml
atl-core = { git = "https://github.com/evidentum-io/atl-core", rev = "6e652edf8029d2856321801e362b5f6a4dd0930c" }
```

The pin lives in exactly one place, that dependency line, in each of
`tamper-evident-audit-logs/Cargo.toml` and `ai-agent-audit-trail/Cargo.toml`
— so bumping it is a one-line change per crate, followed by `cargo update
-p atl-core --precise <new-rev>` (or a plain `cargo build`, since the
`rev` itself already pins the checkout) and `cargo test`. The current
revision is a comment-only follow-up to `5229787cfcd5dcf76276435ae872feea3b6013e1`
(the revision each crate was first built and tested against); no compiled
code differs between the two.

## Running everything

Each crate is independent — its own `Cargo.lock`, its own dependency
graph, no shared workspace — because their dependency trees do not agree
with each other (for one example, `dcap-qvl` and `atl-core` pull
incompatible versions of `x509-cert`). Test one crate at a time:

```sh
cd rfc-3161-vs-opentimestamps && cargo test
cd ../intel-tdx-remote-attestation-verifier && cargo test
cd ../tamper-evident-audit-logs && cargo test
cd ../ai-agent-audit-trail && cargo test
```

`.github/workflows/ci.yml` does the same, per crate, on the pinned
toolchain in `rust-toolchain.toml`, with `cargo fmt --check`, `cargo test
--locked` and `cargo clippy --all-targets --locked`.

## License

Apache-2.0. See `LICENSE`.
