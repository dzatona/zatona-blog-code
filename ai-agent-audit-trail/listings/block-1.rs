use atl_core::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256}; // atl-core exports no digest helper; sha2 is a separate dependency

// Write side. The payload is the raw bytes of the step and never enters the
// log; only its SHA-256 does. The metadata carries the frame reference and
// the parameters, in cleartext.
let payload_hash: Hash = Sha256::digest(step_bytes).into();

let metadata = json!({
    "step": 17,
    "prev_entry": "sha256:…",
    "model": "vendor/model-2026-08",
    "prompt_template": "sha256:…",
    "sampling": { "temperature": 0.0, "max_tokens": 1024 },
    "tool": { "name": "search", "version": "3.2.1", "args_hash": "sha256:…" },
    "observed_at": "2026-09-06T14:03:11Z",
    "apl": { /* the APL claim, including frame_ref; envelope omitted here */ }
});
let metadata_hash: Hash = canonicalize_and_hash(&metadata)?; // RFC 8785, then SHA-256
let leaf: Hash = compute_leaf_hash(&payload_hash, &metadata_hash);
// `leaf` is appended to the tree by the log server; a checkpoint is signed
// and anchored on the server's schedule.

// Read side, months later, offline. The receipt carries the entry, the
// inclusion path, the signed checkpoint, the super_proof and the anchors.
// TSA root certificates are verifier-supplied trust material, obtained out
// of band; without them an RFC 3161 anchor can never count as verified.
let trust = TrustStore::new().with_anchor_certificate(tsa_root_certificate);
let options = VerifyOptions { rfc3161_trust_store: Some(trust), ..VerifyOptions::default() };
let receipt = Receipt::from_json(&receipt_json)?;
let result = ReceiptVerifier::anchor_only_with_options(options).verify(&receipt);
// `result.is_valid` is true only when at least one anchor verified.
// A receipt with no verifiable anchor, and nothing about the receipt itself
// refuted, is `result.is_indeterminate()`: neither accepted nor refuted,
// which is the correct answer for a signed head with no verified anchor.
