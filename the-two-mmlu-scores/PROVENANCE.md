# Fixture provenance

Each fixture is one fenced JSON block of the post at
https://zatona.dev/blog/the-two-mmlu-scores, copied verbatim with no
reformatting. `fixtures/block-N.json` is the Nth ```` ```json ```` block of the
post, counted in document order from 1. A fixture is identified by that ordinal
and by the SHA-256 of its bytes (the text between the fences, including the
final newline), not by position in the source file.

| Ordinal | File | What it is | SHA-256 of the block bytes |
| --- | --- | --- | --- |
| 1 | `fixtures/block-1.json` | claim A | `49d36e66c5e1625b6c6241ca1d312084e41aa3b2cd6e058e0fe74a376b097602` |
| 2 | `fixtures/block-2.json` | claim B | `ceec8c1119da8c5676fb2404bf0d211688530b626eca5d9e7fe57d4d01511be2` |
| 3 | `fixtures/block-3.json` | relation query | `6973ee6c2faa022fc4e4bb50011bde7d16d385de675761e89f3ca23a7086fab6` |
| 4 | `fixtures/block-4.json` | frame A (indented) | `bdb36499de517dcd23af8f654161c7f14a39686652eada3684192e1a9a6fef8d` |
| 5 | `fixtures/block-5.json` | output, claim A alone | `01bc2377382bf2ea30bccb3ca0838d0d6e1b6290c3cdaf2683ffd9ab71e6608c` |
| 6 | `fixtures/block-6.json` | output, pair without a bridge | `d6619fe65e1d3c69b39df50fe9bb6b45e3b0b39cb02b90abc21e585b3de0f8d7` |
| 7 | `fixtures/block-7.json` | bridge (aspect family mismatch) | `afcec5e42b69c204346a147604479bb364b7fc361fca1082400b694fc5c94c56` |
| 8 | `fixtures/block-8.json` | output, pair with the mismatched bridge | `cb4db65f506a9554274b3cb3a2417a70d2a971fec20a756db1b2f0738545ef01` |
| 9 | `fixtures/block-9.json` | output, pair with the applicable bridge | `a57135ddb6a229af3b5431e91a12f297ecc16dbfbd3011a82b7ded4564ee27f2` |

## Re-extracting

Save the post's source, then from this directory:

```sh
python3 ../scripts/extract_listing.py <post.mdx> fixtures/block --lang=json
```

This writes `fixtures/block-N.json` for the Nth ```` ```json ```` block and
prints each block's SHA-256, which must equal the table above. The post's prose
may change without affecting the fixtures; a block whose hash differs from the
table is a changed block.

Fixtures are never edited to match the verifier; a mismatch between a fixture
and the real output is a defect in the post.

Pinned upstream sources (see `scripts/fetch-pinned.sh`):

| Repository | Commit |
| --- | --- |
| `github.com/evidentum-io/apl-core` | `e46788cfde6d5da1dc6185265318c5861c876d99` (`main`) |
| `github.com/evidentum-io/atl-core` | `02f459c3b3717610ecc9e18e5d53b62fd1bb1b95` |

`logs/run.log` was produced by `scripts/run.sh` with rustc 1.95.0.
