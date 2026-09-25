use atl_core::{
    compute_root, generate_consistency_proof, generate_inclusion_proof, verify_consistency,
    verify_inclusion, Hash,
};
use sha2::{Digest, Sha256};

/// RFC 9162 leaf: the 0x00 prefix keeps a leaf from ever colliding with an
/// interior node, which is hashed with 0x01 (atl-core's `hash_children`).
fn leaf_hash(entry_bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(entry_bytes);
    h.finalize().into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The log at checkpoint time: leaf hashes in append order.
    let entries: Vec<&[u8]> = vec![b"{\"event\":\"login\"}", b"{\"event\":\"export\"}", b"{\"event\":\"delete\"}"];
    let mut leaves: Vec<Hash> = entries.iter().map(|e| leaf_hash(e)).collect();
    let old_root = compute_root(&leaves);
    let old_size = leaves.len() as u64;

    // Storage callback: level 0 is the leaves; returning None for higher
    // levels makes atl-core recompute interior nodes from the leaves.
    let by_level = |leaves: &Vec<Hash>| {
        let leaves = leaves.clone();
        move |level: u32, index: u64| -> Option<Hash> {
            if level == 0 { leaves.get(index as usize).copied() } else { None }
        }
    };

    // Inclusion: prove entry 1 is under old_root. The proof is at most one hash per level.
    let proof = generate_inclusion_proof(1, old_size, by_level(&leaves))?;
    assert!(verify_inclusion(&leaves[1], &proof, &old_root)?);

    // The log grows; a new checkpoint is signed over new_root.
    leaves.push(leaf_hash(b"{\"event\":\"login\"}"));
    leaves.push(leaf_hash(b"{\"event\":\"share\"}"));
    let new_root = compute_root(&leaves);
    let new_size = leaves.len() as u64;

    // Consistency: prove the tree at new_size extends the tree at old_size.
    // A holder of the old checkpoint needs only this proof and the new root.
    let consistency = generate_consistency_proof(old_size, new_size, by_level(&leaves))?;
    assert!(verify_consistency(&consistency, &old_root, &new_root)?);

    // A rewritten history fails: any old root other than the real one is rejected.
    assert!(!verify_consistency(&consistency, &[0xff; 32], &new_root)?);
    Ok(())
}
