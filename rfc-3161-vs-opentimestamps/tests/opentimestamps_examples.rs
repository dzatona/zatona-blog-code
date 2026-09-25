//! Runs `ots::verify` (Section 5's listing) against the OpenTimestamps
//! reference client's own example proofs. Provenance for every fixture
//! file this test reads is in `fixtures/README.md`.

use rfc_3161_vs_opentimestamps::ots::{verify, HeaderSource, Verdict};

/// Block 358391's header, independently fetched from a second source
/// (blockstream.info, not the OpenTimestamps calendar or client) and
/// recorded in `fixtures/block-358391-header.json`. See that file and
/// `fixtures/README.md` for how the internal-byte-order root and the
/// `nTime` below were obtained and how they were cross-checked against the
/// post's own stated values.
struct FixedHeader {
    height: usize,
    root: [u8; 32],
    time: i64,
}

impl HeaderSource for FixedHeader {
    fn header(&self, height: usize) -> Option<([u8; 32], i64)> {
        if height == self.height {
            Some((self.root, self.time))
        } else {
            None
        }
    }
}

/// No header for any height: the caller's node has nothing.
struct NoHeaders;

impl HeaderSource for NoHeaders {
    fn header(&self, _height: usize) -> Option<([u8; 32], i64)> {
        None
    }
}

fn block_358391_root() -> [u8; 32] {
    let hex = "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a";
    let bytes = hex_to_bytes(hex);
    bytes.try_into().expect("32 bytes")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("reading fixtures/{name}: {e}"))
}

/// The post's Section 5 worked example, replayed end to end: "Run over
/// `hello-world.txt.ots` from the client's examples — 688 bytes, 38
/// operations ... arrives at `007ee445...b8a` with a Bitcoin attestation
/// for height 358391." With that block's real header supplied, the verdict
/// is `Anchored`.
#[test]
fn hello_world_anchors_to_block_358391() {
    use opentimestamps::ser::DetachedTimestampFile;

    let document = load("hello-world.txt");
    let ots_bytes = load("hello-world.txt.ots");
    assert_eq!(
        ots_bytes.len(),
        688,
        "fixture size must match the post's stated 688 bytes"
    );

    let ots = DetachedTimestampFile::from_reader(&ots_bytes[..]).expect("parses as a v1 OTS file");

    let headers = FixedHeader {
        height: 358391,
        root: block_358391_root(),
        time: 1_432_827_678, // 2015-05-28T15:41:18Z, see fixtures/block-358391-header.json
    };
    let outcome = verify(&ots, &document, &headers).expect("a well-formed proof");

    assert_eq!(
        outcome.verdict,
        Verdict::Anchored {
            height: 358391,
            block_time: 1_432_827_678
        }
    );
    assert_eq!(outcome.attestations.len(), 1);
}

/// The same proof against a `HeaderSource` that has nothing: the post's own
/// closing line of Section 5, "With a `HeaderSource` that has nothing at
/// that height, the verdict is `Indeterminate` and the attestation's
/// outcome is `NoHeader`."
#[test]
fn hello_world_is_indeterminate_without_a_header() {
    use opentimestamps::ser::DetachedTimestampFile;
    use rfc_3161_vs_opentimestamps::ots::AttestationOutcome;

    let document = load("hello-world.txt");
    let ots_bytes = load("hello-world.txt.ots");
    let ots = DetachedTimestampFile::from_reader(&ots_bytes[..]).expect("parses as a v1 OTS file");

    let outcome = verify(&ots, &document, &NoHeaders).expect("a well-formed proof");

    assert_eq!(outcome.verdict, Verdict::Indeterminate);
    assert_eq!(
        outcome.attestations,
        vec![AttestationOutcome::NoHeader { height: 358391 }]
    );
}

/// A header at the right height but the wrong root: `RootMismatch`, and
/// still `Indeterminate` overall since nothing else was checked — not
/// `Contradicted`, because a single mismatch is not "every attestation
/// looked at and none matched" once other paths are still unlooked-at. This
/// proof has only the one Bitcoin attestation, so `Contradicted` is exactly
/// right here: the one attestation there is was looked at, and it did not
/// match.
#[test]
fn hello_world_is_contradicted_by_the_wrong_root() {
    use opentimestamps::ser::DetachedTimestampFile;
    use rfc_3161_vs_opentimestamps::ots::AttestationOutcome;

    let document = load("hello-world.txt");
    let ots_bytes = load("hello-world.txt.ots");
    let ots = DetachedTimestampFile::from_reader(&ots_bytes[..]).expect("parses as a v1 OTS file");

    let wrong_header = FixedHeader {
        height: 358391,
        root: [0xAB; 32],
        time: 1_432_827_678,
    };
    let outcome = verify(&ots, &document, &wrong_header).expect("a well-formed proof");

    assert_eq!(outcome.verdict, Verdict::Contradicted);
    assert_eq!(
        outcome.attestations,
        vec![AttestationOutcome::RootMismatch { height: 358391 }]
    );
}

/// `two-calendars.txt.ots` — the post's other annotated example (Section 4,
/// "The bytes") — forks into two branches, both ending in a *pending*
/// attestation (Section 4's attestation table): no Bitcoin block is
/// reachable from it at all, so the verdict is `Indeterminate` regardless
/// of what any `HeaderSource` supplies, and both calendar URIs come back.
#[test]
fn two_calendars_is_indeterminate_and_recovers_both_calendar_uris() {
    use opentimestamps::ser::DetachedTimestampFile;

    let document = load("two-calendars.txt");
    let ots_bytes = load("two-calendars.txt.ots");
    assert_eq!(
        ots_bytes.len(),
        265,
        "fixture size must match the post's stated 265 bytes"
    );

    let ots = DetachedTimestampFile::from_reader(&ots_bytes[..]).expect("parses as a v1 OTS file");
    let outcome = verify(&ots, &document, &NoHeaders).expect("a well-formed proof");

    assert_eq!(outcome.verdict, Verdict::Indeterminate);
    assert!(
        outcome.attestations.is_empty(),
        "no Bitcoin attestation exists in this proof at all"
    );
    assert_eq!(outcome.calendars.len(), 2);
    assert!(outcome
        .calendars
        .iter()
        .any(|c| c.contains("alice.btc.calendar.opentimestamps.org")));
}
