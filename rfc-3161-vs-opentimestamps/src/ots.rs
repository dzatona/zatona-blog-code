//! The OpenTimestamps half: Section 5 of the post. `opentimestamps` parses
//! and replays the operation tree; this module adds the header comparison
//! the post says the crate "compares nothing against a block header ...
//! because it has no way to obtain one."
//!
//! ## What is byte-identical to the post, and what is glue
//!
//! `listings/block-5.rs` is `include!`d below, unmodified (checksum in
//! `PROVENANCE.md`). It refers to two names the post's prose describes but
//! does not print a listing for: `Reached`, the per-walk accumulator
//! `walk` fills in and `verify` reads back, and `BitcoinCommitment`, one
//! reached Bitcoin attestation's height and digest. Both are defined below
//! as straightforward struct records of exactly the fields `block-5.rs`
//! reads and writes on them (`reached.bitcoin`, `.pending`, `.unknown`;
//! `c.height`, `c.reached`) — nothing in `block-5.rs` was changed to fit
//! them; they were shaped to fit it.
//!
//! ## What is tested
//!
//! `tests/opentimestamps_examples.rs` runs [`verify`] against
//! `hello-world.txt.ots` and `two-calendars.txt.ots`, the OpenTimestamps
//! reference client's own example proofs (`fixtures/`, provenance in this
//! crate's `README.md`). `hello-world.txt.ots` replays to the exact 32
//! bytes the post's Section 5 quotes as block 358391's Merkle root; the
//! test supplies that one header through a `HeaderSource` built from the
//! literal bytes and checks the verdict comes back `Anchored`. A header
//! source that returns `None` for every height is used to check the
//! `Indeterminate` path, and a wrong root checks `RootMismatch`.
//!
//! ## What is not tested
//!
//! `two-calendars.txt.ots`'s two branches both end in `Attestation::Pending`
//! (Section 4's table); no Bitcoin block header is reachable from it at
//! all, live or fixed, so the test for that fixture checks the verdict is
//! `Indeterminate` with both calendar URIs recovered, not `Anchored`. No
//! live Bitcoin node or block-explorer call is made anywhere in this
//! crate; block 358391's root is a fixture, not a fetch.

use opentimestamps::attestation::Attestation;
use opentimestamps::ser::{DetachedTimestampFile, DigestType};
use opentimestamps::timestamp::{Step, StepData};
use sha2::{Digest, Sha256};

/// One reached Bitcoin attestation: the height it names, and the digest
/// [`walk`] computed at that point in the path (checked for 32 bytes only
/// at the header-comparison step, per `block-5.rs`'s own comment on why the
/// length check belongs there and not in `walk`).
#[derive(Debug, Clone)]
pub struct BitcoinCommitment {
    /// The Bitcoin block height the attestation names.
    pub height: usize,
    /// The digest the path reached at this attestation.
    pub reached: Vec<u8>,
}

/// What [`walk`] accumulates over one proof: every Bitcoin attestation
/// reached, every pending calendar URI, and every attestation tag this
/// build does not recognize (Litecoin and Ethereum, in the
/// `opentimestamps` 0.2.0 crate the post names).
#[derive(Debug, Default)]
pub struct Reached {
    /// Every Bitcoin attestation the walk reached, in traversal order.
    pub bitcoin: Vec<BitcoinCommitment>,
    /// Every pending calendar URI the walk reached.
    pub pending: Vec<String>,
    /// Every unrecognized attestation tag the walk reached.
    pub unknown: Vec<Vec<u8>>,
}

include!("../listings/block-5.rs");
