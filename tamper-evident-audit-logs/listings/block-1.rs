use sha2::{Digest, Sha256};

type Hash = [u8; 32];

/// One audit entry as stored: the previous entry's hash is part of what this
/// entry's hash covers, so changing any earlier entry changes this one.
struct Entry {
    prev: Hash,
    body: Vec<u8>, // canonical bytes of the record (RFC 8785 for JSON)
}

fn entry_hash(e: &Entry) -> Hash {
    let mut h = Sha256::new();
    h.update(b"audit-entry-v1"); // domain separation: an entry hash is nothing else
    h.update(e.prev);
    h.update((e.body.len() as u64).to_le_bytes()); // length prefix: keeps the encoding unambiguous if fields change
    h.update(&e.body);
    h.finalize().into()
}

/// Verifying the chain means walking it from a hash you already trust.
fn verify_chain(entries: &[Entry], trusted_head: Hash) -> bool {
    let mut expected = [0u8; 32]; // genesis: the first entry's prev is all zeros
    for e in entries {
        if e.prev != expected {
            return false;
        }
        expected = entry_hash(e);
    }
    expected == trusted_head
}
