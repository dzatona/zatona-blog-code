//! Compiled listings from the zatona.dev post "Tamper-Evident Audit Logs:
//! Hash Chains, Merkle Trees, and External Anchoring"
//! (<https://zatona.dev/blog/tamper-evident-audit-logs>).
//!
//! Each `listings/block-N.rs` file is the byte-identical text of the post's
//! Nth ```rust fenced block; extraction method and checksums are in
//! `PROVENANCE.md`. This crate adds only the module wrapper and the test
//! harness; nothing inside the `include!`d files was edited.
//!
//! What is tested: [`hash_chain`]'s `entry_hash`/`verify_chain` against a
//! constructed chain, including a tamper detection case the post's prose
//! describes but does not code. [`checkpoint_tree`] is Section 4.3's
//! complete example, which already ends in `assert!` calls against
//! `atl-core`'s real RFC 9162 implementation; the crate's test just calls
//! its `main` and checks it returns `Ok`.
//!
//! What is not tested: nothing runtime-observable in either listing is
//! left unexercised, since block 2 is a self-contained `fn main` that
//! already asserts the properties the post claims (inclusion, consistency,
//! and rejection of a rewritten root).

/// Section 3: the hash chain. Verbatim `listings/block-1.rs`.
#[allow(dead_code)] // exercised only from `#[cfg(test)]` below
pub mod hash_chain {
    include!("../listings/block-1.rs");

    #[cfg(test)]
    mod tests {
        use super::*;

        fn chain_of(bodies: &[&[u8]]) -> Vec<Entry> {
            let mut prev = [0u8; 32];
            let mut entries = Vec::new();
            for body in bodies {
                let entry = Entry {
                    prev,
                    body: body.to_vec(),
                };
                prev = entry_hash(&entry);
                entries.push(entry);
            }
            entries
        }

        #[test]
        fn an_untampered_chain_verifies_against_its_own_head() {
            let entries = chain_of(&[b"login", b"export", b"delete"]);
            let head = entry_hash(entries.last().unwrap());
            assert!(verify_chain(&entries, head));
        }

        #[test]
        fn an_empty_chain_verifies_only_against_the_genesis_hash() {
            assert!(verify_chain(&[], [0u8; 32]));
            assert!(!verify_chain(&[], [1u8; 32]));
        }

        #[test]
        fn editing_an_earlier_entry_breaks_every_hash_after_it() {
            let mut entries = chain_of(&[b"login", b"export", b"delete"]);
            let head = entry_hash(entries.last().unwrap());
            // Tamper with the first entry's body in place, without
            // recomputing anything after it, the way an attacker who does
            // not hold the chain would have to.
            entries[0].body = b"login-as-root".to_vec();
            assert!(!verify_chain(&entries, head));
        }

        #[test]
        fn regenerating_the_tail_after_a_tamper_verifies_again() {
            // The post's stated limit of the mechanism: "whoever holds the
            // chain can regenerate the tail." A holder who edits entry 0
            // and recomputes every hash after it produces a chain that
            // verifies against a new head; only a head trusted from outside
            // this holder would catch it.
            let mut bodies: Vec<Vec<u8>> =
                vec![b"login".to_vec(), b"export".to_vec(), b"delete".to_vec()];
            bodies[0] = b"login-as-root".to_vec();
            let refs: Vec<&[u8]> = bodies.iter().map(std::vec::Vec::as_slice).collect();
            let regenerated = chain_of(&refs);
            let new_head = entry_hash(regenerated.last().unwrap());
            assert!(verify_chain(&regenerated, new_head));
        }

        #[test]
        fn a_broken_genesis_pointer_is_rejected() {
            let mut entries = chain_of(&[b"login"]);
            let head = entry_hash(entries.last().unwrap());
            entries[0].prev = [7u8; 32];
            assert!(!verify_chain(&entries, head));
        }
    }
}

/// Section 4.3: the RFC 9162 tree against `atl-core`. Verbatim
/// `listings/block-2.rs`, including its own `main` and its own asserts.
#[allow(dead_code)] // `main` and `leaf_hash` are called only from `#[cfg(test)]` below
pub mod checkpoint_tree {
    include!("../listings/block-2.rs");

    #[cfg(test)]
    mod tests {
        #[test]
        fn the_posts_own_example_runs_and_its_asserts_hold() {
            super::main().expect("Section 4.3's example asserts should all pass");
        }
    }
}
