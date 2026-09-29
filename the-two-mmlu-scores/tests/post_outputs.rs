//! Runs the pinned `apl-ai-eval` verifier on the frames, claims, bridge and
//! query printed in the post and compares every verifier output printed in
//! the post with the real output, byte for byte.
//!
//! Fixtures `fixtures/block-N.json` are the post's fenced JSON blocks in
//! document order (see `PROVENANCE.md`):
//!
//! | file | content |
//! | --- | --- |
//! | `block-1` | claim A |
//! | `block-2` | claim B |
//! | `block-3` | relation query |
//! | `block-4` | frame A |
//! | `block-5` | output, claim A alone |
//! | `block-6` | output, the pair without a bridge |
//! | `block-7` | bridge (aspect family mismatch) |
//! | `block-8` | output, the pair with that bridge |
//! | `block-9` | output, the pair with an applicable bridge |
//!
//! Inputs the post describes in prose but does not print (frame B, the frames
//! and claims of the two bridge cases) are constructed as the post describes
//! them or read from the pinned crate's own test vectors, and each such input
//! is checked against the post's statements before it is used.

use std::fs;
use std::path::Path;

use apl_core::prelude::*;
use serde_json::{json, Value};

const CLAIM_A: &str = include_str!("../fixtures/block-1.json");
const CLAIM_B: &str = include_str!("../fixtures/block-2.json");
const QUERY: &str = include_str!("../fixtures/block-3.json");
const FRAME_A: &str = include_str!("../fixtures/block-4.json");
const OUT_A_ALONE: &str = include_str!("../fixtures/block-5.json");
const OUT_PAIR_NO_BRIDGE: &str = include_str!("../fixtures/block-6.json");
const BRIDGE_ADVERSARIAL: &str = include_str!("../fixtures/block-7.json");
const OUT_PAIR_ADVERSARIAL: &str = include_str!("../fixtures/block-8.json");
const OUT_PAIR_BRIDGED: &str = include_str!("../fixtures/block-9.json");

const VECTORS: &str = "vendor/upstream/apl/apl-core/apl-ai-eval/test_data/vectors/pairwise";

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("fixture is valid JSON")
}

/// A fixture block ends with the newline that precedes the closing fence.
fn printed(text: &str) -> &str {
    text.strip_suffix('\n').unwrap_or(text)
}

fn hash_of(frame: &Value) -> String {
    canonical_hash(frame).to_string()
}

fn frame_b() -> Value {
    // Frame B as the post describes it: frame A with a different runner, a
    // different grader, a different split and no `subset` key.
    let mut b = json(FRAME_A);
    b["procedure"]["runner_id"] = json!("custom-runner@2.1");
    b["procedure"]["grader_id"] = json!("llm-judge-v3");
    b["scope"]["dataset_split"] = json!("test-lite");
    b["scope"]
        .as_object_mut()
        .expect("scope is an object")
        .remove("subset")
        .expect("frame A has a subset key");
    b
}

fn substitute(v: &mut Value, frames: &[Value], bridges: &[Value]) {
    match v {
        Value::Object(map) => map
            .values_mut()
            .for_each(|x| substitute(x, frames, bridges)),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|x| substitute(x, frames, bridges)),
        Value::String(s) => {
            let frame = s
                .strip_prefix("<FRAME_HASH:")
                .and_then(|t| t.strip_suffix('>'));
            let bridge = s
                .strip_prefix("<BRIDGE_HASH:")
                .and_then(|t| t.strip_suffix('>'));
            if let Some(i) = frame {
                *s = hash_of(&frames[i.parse::<usize>().expect("frame index")]);
            } else if let Some(i) = bridge {
                *s = hash_of(&bridges[i.parse::<usize>().expect("bridge index")]);
            }
        }
        _ => {}
    }
}

struct Mock {
    left: Value,
    right: Value,
}

impl CarrierVerifier for Mock {
    fn verify_carrier(&self, bytes: &[u8]) -> CarrierOutcome {
        let metadata = match bytes {
            b"left" => self.left.clone(),
            _ => self.right.clone(),
        };
        CarrierOutcome::Valid {
            payload: vec![],
            metadata,
        }
    }
}

fn resolver(frames: &[Value]) -> InMemoryFrameResolver {
    let mut r = InMemoryFrameResolver::new();
    for f in frames {
        r.insert(f.clone());
    }
    r
}

/// Verifies a single claim carrying the `metadata.apl` object `claim`.
fn verify_single(claim: &Value, frames: &[Value]) -> String {
    apl_ai_eval::register();
    let carrier = Mock {
        left: claim.clone(),
        right: claim.clone(),
    };
    let bridges = InMemoryBridgeResolver::new();
    let profile = apl_ai_eval::AiEvalProfile;
    verify_receipt(
        b"left",
        &carrier,
        &resolver(frames),
        &bridges,
        Some(&profile),
    )
    .0
    .to_json()
}

/// Evaluates a relation over two claims and returns the compact output JSON.
fn evaluate(
    left: &Value,
    right: &Value,
    frames: &[Value],
    supplied: &[Value],
    q: &Value,
) -> String {
    apl_ai_eval::register();
    let carrier = Mock {
        left: left.clone(),
        right: right.clone(),
    };
    let bridges = InMemoryBridgeResolver::new();
    let profile = apl_ai_eval::AiEvalProfile;
    let input = PairwiseInput {
        left: ReceiptInput::Bytes(b"left"),
        right: ReceiptInput::Bytes(b"right"),
        query: RelationQuery::parse(q).expect("query parses"),
        supplied_bridges: supplied.to_vec(),
    };
    evaluate_relation(input, &carrier, &resolver(frames), &bridges, Some(&profile)).to_json()
}

/// One pairwise vector of the pinned crate, with placeholders resolved.
struct CrateVector {
    left: Value,
    right: Value,
    frames: Vec<Value>,
    supplied: Vec<Value>,
    query: Value,
}

fn crate_vector(name: &str) -> CrateVector {
    let path = Path::new(VECTORS).join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/fetch-pinned.sh",
            path.display()
        )
    });
    let v = json(&text);
    let frames: Vec<Value> = v["frames"].as_array().expect("frames").clone();
    let mut supplied: Vec<Value> = v["supplied_bridges"].as_array().expect("bridges").clone();
    supplied
        .iter_mut()
        .for_each(|b| substitute(b, &frames, &[]));
    let mut left = json!({ "apl": v["left"]["metadata_apl"].clone() });
    let mut right = json!({ "apl": v["right"]["metadata_apl"].clone() });
    substitute(&mut left, &frames, &supplied);
    substitute(&mut right, &frames, &supplied);
    CrateVector {
        left,
        right,
        frames,
        supplied,
        query: v["query"].clone(),
    }
}

fn claim_a() -> Value {
    json(CLAIM_A)
}

fn claim_b() -> Value {
    json(CLAIM_B)
}

#[test]
fn pinned_crate_is_the_version_the_post_names() {
    let manifest = fs::read_to_string("vendor/upstream/apl/apl-core/apl-ai-eval/Cargo.toml")
        .expect("pinned manifest; run scripts/fetch-pinned.sh");
    assert!(manifest.lines().any(|l| l == "version = \"1.0.0\""));
}

#[test]
fn fixtures_are_single_line_or_indented_json_blocks() {
    for text in [
        CLAIM_A,
        CLAIM_B,
        QUERY,
        OUT_A_ALONE,
        OUT_PAIR_NO_BRIDGE,
        BRIDGE_ADVERSARIAL,
    ] {
        assert!(text.ends_with('\n'));
        assert!(!printed(text).contains('\n'));
    }
}

#[test]
fn frame_a_hash_matches_the_hash_printed_in_claim_a() {
    let printed_hash = claim_a()["apl"]["frame_ref"]["hash"]
        .as_str()
        .expect("hash")
        .to_owned();
    assert_eq!(hash_of(&json(FRAME_A)), printed_hash);
    assert_eq!(
        printed_hash,
        "sha256:c7b88426f2676f3653db0fad0bdbd689318f16d589d14a315bdd4cc454bca1ab"
    );
}

#[test]
fn frame_b_hash_matches_the_hash_printed_in_claim_b() {
    let printed_hash = claim_b()["apl"]["frame_ref"]["hash"]
        .as_str()
        .expect("hash")
        .to_owned();
    assert_eq!(hash_of(&frame_b()), printed_hash);
    assert_eq!(
        printed_hash,
        "sha256:c93a9c55422ddbd2158a5336caa3a251641cf3937f451fb13387a5f54f0d998e"
    );
}

#[test]
fn frame_a_hash_ignores_the_display_indentation() {
    let compact = serde_json::to_string(&json(FRAME_A)).expect("serializes");
    assert_eq!(hash_of(&json(&compact)), hash_of(&json(FRAME_A)));
}

#[test]
fn claim_a_alone_output_is_byte_identical_to_the_post() {
    let out = verify_single(&claim_a(), &[json(FRAME_A)]);
    assert_eq!(out, printed(OUT_A_ALONE));
}

#[test]
fn claim_b_alone_has_the_same_output_as_claim_a() {
    let out = verify_single(&claim_b(), &[frame_b()]);
    assert_eq!(out, printed(OUT_A_ALONE));
}

#[test]
fn pair_without_bridge_output_is_byte_identical_to_the_post() {
    let out = evaluate(
        &claim_a(),
        &claim_b(),
        &[json(FRAME_A), frame_b()],
        &[],
        &json(QUERY),
    );
    assert_eq!(out, printed(OUT_PAIR_NO_BRIDGE));
}

#[test]
fn pair_without_bridge_matches_the_crate_vector_inputs() {
    let v = crate_vector("incomparable-no-bridge.json");
    assert_eq!(v.frames, vec![json(FRAME_A), frame_b()]);
    assert_eq!(v.left, claim_a());
    assert_eq!(v.right, claim_b());
    assert_eq!(v.query, json(QUERY));
}

#[test]
fn adversarial_bridge_printed_in_the_post_is_the_crate_vector_bridge() {
    let v = crate_vector("incomparable-adversarial-bridge.json");
    let mut printed_bridge = json(BRIDGE_ADVERSARIAL);
    substitute(&mut printed_bridge, &v.frames, &[]);
    assert_eq!(v.supplied, vec![printed_bridge]);
}

#[test]
fn adversarial_bridge_frames_differ_only_in_the_aspect_the_post_names() {
    let v = crate_vector("incomparable-adversarial-bridge.json");
    assert_eq!(v.frames[0]["aspect"], json!(["accuracy"]));
    assert_eq!(v.frames[1]["aspect"], json!(["judge-score"]));
    let bridge = &v.supplied[0];
    assert_eq!(
        bridge["comparison_scope"]["source_aspects"],
        json!(["accuracy"])
    );
    assert_eq!(
        bridge["comparison_scope"]["target_aspects"],
        json!(["judge-score"])
    );
    assert_eq!(bridge["losses"], json!([]));
}

#[test]
fn pair_with_the_adversarial_bridge_output_is_byte_identical_to_the_post() {
    let v = crate_vector("incomparable-adversarial-bridge.json");
    let out = evaluate(&v.left, &v.right, &v.frames, &v.supplied, &v.query);
    assert_eq!(out, printed(OUT_PAIR_ADVERSARIAL));
}

#[test]
fn bridged_frames_differ_only_in_runner_id_as_the_post_states() {
    let v = crate_vector("bridged-runner-equivalence.json");
    let mut second = v.frames[1].clone();
    second["procedure"]["runner_id"] = v.frames[0]["procedure"]["runner_id"].clone();
    assert_eq!(second, v.frames[0]);
    assert_ne!(
        v.frames[0]["procedure"]["runner_id"],
        v.frames[1]["procedure"]["runner_id"]
    );
    assert_eq!(
        v.frames[0]["procedure"]["grader_id"],
        json!("exact-match-v1")
    );
    assert_eq!(v.frames[0]["scope"]["benchmark_id"], json!("mmlu"));
    assert_eq!(v.frames[0]["scope"]["benchmark_variant"], json!("default"));
    assert_eq!(v.frames[0]["scope"]["dataset_split"], json!("dev"));
    assert_eq!(v.frames[0]["scope"]["subset"], json!("all"));
}

#[test]
fn pair_with_the_applicable_bridge_output_is_byte_identical_to_the_post() {
    let v = crate_vector("bridged-runner-equivalence.json");
    let out = evaluate(&v.left, &v.right, &v.frames, &v.supplied, &v.query);
    assert_eq!(out, printed(OUT_PAIR_BRIDGED));
}

#[test]
fn a_repeatability_bridge_is_rejected_for_score_delta() {
    // The post states that repeatability bridges do not license `score-delta`.
    let mut v = crate_vector("bridged-runner-equivalence.json");
    v.supplied[0]["bridge_kind"] = json!("repeatability");
    // The bridge changed, so the claim's bridge reference must follow it.
    v.left["apl"]["bridge_refs"] = json!([{ "hash": hash_of(&v.supplied[0]) }]);
    let out = evaluate(&v.left, &v.right, &v.frames, &v.supplied, &v.query);
    assert!(
        out.contains("\"relation_outcome\":\"incomparable\""),
        "{out}"
    );
    assert!(
        out.contains("apl-ai-eval-bridge-relation-type-invalid"),
        "{out}"
    );
}
