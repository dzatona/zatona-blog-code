//! Wraps `listings/block-1.rs` — the byte-identical text of the post's one
//! fenced ```rust block — in a function signature at build time, and writes
//! the result to `$OUT_DIR`. `src/lib.rs` then `include!`s that generated
//! file.
//!
//! This indirection exists because `include!` used at *statement* position
//! (inside a function body) requires its target to expand to a single
//! expression; the post's block is a sequence of `use` items and `let`
//! statements, which only parses at *item* position (a whole `fn`, `mod`,
//! or other item). Concatenating the wrapper's signature and closing brace
//! around the listing's bytes here — rather than retyping the listing
//! inside `src/lib.rs` by hand — keeps the wrapped copy mechanically tied
//! to the file `PROVENANCE.md` records a checksum for: this script reads
//! `listings/block-1.rs` at every build and fails if it is missing, so the
//! two can never silently drift apart.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=listings/block-1.rs");

    let listing = fs::read_to_string("listings/block-1.rs")
        .expect("listings/block-1.rs must exist: it is the post's listing, not generated");

    let wrapped = format!(
        "/// Section 7's listing (`listings/block-1.rs`), wrapped as a function\n\
         /// body by `build.rs`, which reads the listing file unmodified at\n\
         /// build time; nothing between the signature and `Ok(result)` below\n\
         /// was retyped by hand. See `PROVENANCE.md` for the listing's\n\
         /// checksum and extraction method.\n\
         ///\n\
         /// # Errors\n\
         ///\n\
         /// Whatever `atl-core` or `serde_json` returned: a malformed\n\
         /// receipt, or (propagated through the `?` in the listing) a JCS\n\
         /// canonicalization failure in the metadata object.\n\
         #[allow(clippy::missing_panics_doc)]\n\
         #[allow(unused_variables)] // `leaf` is computed and, per the post's own\n\
         // comment, handed to the log server; nothing in this listing consumes it\n\
         pub fn one_step(\n    \
             step_bytes: &[u8],\n    \
             receipt_json: String,\n    \
             tsa_root_certificate: x509_cert::Certificate,\n\
         ) -> Result<atl_core::VerificationResult, Box<dyn std::error::Error>> {{\n\
         {listing}\n    \
             Ok(result)\n\
         }}\n"
    );

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo");
    let dest = Path::new(&out_dir).join("wrapped_block_1.rs");
    fs::write(&dest, wrapped).expect("failed to write wrapped listing");
}
