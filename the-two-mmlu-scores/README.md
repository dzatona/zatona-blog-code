# the-two-mmlu-scores

Fixtures and checks for [zatona.dev/blog/the-two-mmlu-scores](https://zatona.dev/blog/the-two-mmlu-scores).

The post prints JSON frames, claims, a bridge and a relation query, and the
outputs of the `apl-ai-eval` verifier for them. This directory holds those
JSON blocks byte for byte (`fixtures/`), runs the verifier at a pinned commit
on them, and compares each printed output with the real output byte for byte.
`PROVENANCE.md` identifies each fixture by its order among the post's JSON
blocks and by its checksum, and says how to re-extract them.

## What is run

- Upstream: `github.com/evidentum-io/apl-core` on `main` at
  `e46788cfde6d5da1dc6185265318c5861c876d99` (crate `apl-ai-eval` 1.0.0),
  which builds against `github.com/evidentum-io/atl-core` at
  `02f459c3b3717610ecc9e18e5d53b62fd1bb1b95` (0.23.1). apl-core declares its
  ATL dependency as the path `../../../evidentum.io/atl-core`, so the fetch
  script places the trees at `vendor/upstream/apl/apl-core` and
  `vendor/evidentum.io/atl-core`. Both pins live in `scripts/fetch-pinned.sh`,
  which fails on any SHA or working-tree mismatch.
- `tests/post_outputs.rs` (15 tests) calls the verifier's public functions
  (`verify_receipt`, `evaluate_relation`, `canonical_hash`) with the profile
  registered and a mock carrier, the same way the upstream vector harness
  does, and asserts equality of the compact JSON output with the printed block:
  claim A alone, claim B alone (same output as A), the pair with the
  `score-delta` query and no bridge, the pair with the aspect-family-mismatch
  bridge, and the pair with the applicable runner-equivalence bridge.
- Both printed frame hashes are recomputed: frame A from the printed frame,
  frame B from frame A with the four changes the post lists, and each is
  compared with the `frame_ref.hash` printed in the claims.
- A repeatability bridge is checked to be rejected for `score-delta`, with the
  diagnostic `apl-ai-eval-bridge-relation-type-invalid`.
- The pinned crate's manifest is checked to declare version 1.0.0.
- `scripts/run.sh` also runs the upstream `cargo test -p apl-ai-eval` at the
  pinned commit; `logs/run.log` is the raw output of one full run: the upstream
  suite (109 unit tests, 3 vector integration tests, 2 doc-tests), this crate's tests,
  `cargo fmt --check` and `cargo clippy -D warnings`.

## What is not run

- The frames and claims are illustrative schema fixtures of the AI-Eval
  profile. They are not historical observations of any real model or
  evaluation, and the accuracy values say nothing about any real system.
- Inputs the post describes without printing (the frames and claims of the two
  bridge cases) are read from the pinned crate's own test vectors; the tests
  check each such input against what the post states about it. Frame B is
  constructed from frame A as the post describes.
- The malformed-record case (`apl-invalid`) is not asserted here.
- Source line references into the upstream crate are not checked.

## Run it

```sh
sh scripts/run.sh        # fetch pins, run upstream suite and this crate, write logs/run.log
cargo test --locked      # this crate only (after scripts/fetch-pinned.sh)
```

## License

Apache-2.0. See the repository `LICENSE`.
