/// What the caller has to bring: a block header per height, from its own node.
/// Nothing in the proof, and nothing in this crate, can supply it.
pub trait HeaderSource {
    /// Merkle root in internal byte order, and the header's `nTime`, for the
    /// block at `height` on the chain this source considers best.
    fn header(&self, height: usize) -> Option<([u8; 32], i64)>;
}

/// One Bitcoin attestation, after the header lookup. The three non-confirming
/// outcomes are different facts and a caller that folds them together loses
/// the only information it has about why.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationOutcome {
    /// A header exists at that height and commits to the value.
    Confirmed { height: usize, block_time: i64 },
    /// The caller's node has no header at that height: an inability. Reasons
    /// include a node still syncing and a height beyond its tip.
    NoHeader { height: usize },
    /// A header exists at that height and its Merkle root is something else.
    /// Causes include a reorg that moved the committing block off this node's
    /// best chain, a header source that is stale or wrong, and a proof that
    /// does not belong to this document after all.
    RootMismatch { height: usize },
    /// The path reached a Bitcoin attestation with something other than 32
    /// bytes, which cannot be a Merkle root.
    NotADigest { height: usize, len: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// At least one attestation confirmed. The earliest confirming block is
    /// the bound the proof supports. A proof can be `Anchored` and still carry
    /// a mismatch elsewhere; the rule is existential, and `attestations` keeps
    /// the rest for whoever is watching.
    Anchored { height: usize, block_time: i64 },
    /// Nothing confirmed, and at least one thing was never looked at: a header
    /// the caller does not have, an attestation whose value is not a digest,
    /// or a path still waiting on a calendar. An inability, not a finding.
    Indeterminate,
    /// Nothing confirmed and nothing left unlooked-at: every attestation in
    /// the proof — including the ones this build cannot interpret, of which
    /// there must be none for this verdict — was compared against a header and
    /// none matched. Still not proof that anyone forged anything, see
    /// `AttestationOutcome`, but it is the only case where the evidence is
    /// against the proof rather than absent.
    Contradicted,
}

/// The verdict plus everything that produced it. A caller that only reads the
/// verdict is throwing away its alarms: a proof with one confirming and one
/// mismatching attestation is `Anchored`, and it is also something to look at.
#[derive(Debug)]
pub struct Outcome {
    pub verdict: Verdict,
    pub attestations: Vec<AttestationOutcome>,
    pub calendars: Vec<String>,
    pub unknown_tags: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum OtsError {
    /// The proof is for a different document, or for a digest algorithm this
    /// code does not handle.
    DigestMismatch,
    /// An operation's stored result differs from replaying it.
    StepMismatch,
    /// Nothing in the proof leads anywhere: no attestation of any kind.
    NoAttestation,
}

/// Walk every path in the proof, recomputing each operation rather than
/// trusting the result the parser stored next to it.
///
/// Depth is bounded before this runs: `Timestamp::deserialize` in the
/// `opentimestamps` crate refuses to nest more than `RECURSION_LIMIT` (256)
/// levels and returns `Error::StackOverflow`, so a tree that reaches this
/// function is already shallow enough to recurse over.
pub fn walk(step: &Step, msg: Vec<u8>, out: &mut Reached) -> Result<(), OtsError> {
    let next_msg = match &step.data {
        StepData::Fork => msg,
        StepData::Op(op) => {
            let computed = op.execute(&msg);
            if computed != step.output {
                return Err(OtsError::StepMismatch);
            }
            computed
        }
        StepData::Attestation(a) => {
            match a {
                // The length check belongs at the header comparison, where the
                // outcome is reported per attestation instead of failing the
                // whole proof.
                Attestation::Bitcoin { height } => out.bitcoin.push(BitcoinCommitment {
                    height: *height,
                    reached: msg.clone(),
                }),
                Attestation::Pending { uri } => out.pending.push(uri.clone()),
                Attestation::Unknown { tag, .. } => out.unknown.push(tag.clone()),
            }
            msg
        }
    };
    for child in &step.next {
        walk(child, next_msg.clone(), out)?;
    }
    Ok(())
}

/// The whole verification: hash the document, replay the path, compare each
/// result with a header the caller's node supplied, and read the time off the
/// header. Every attestation is tried and every outcome is kept; one that
/// confirms is enough for the verdict, which is the same acceptance rule a
/// receipt carrying two kinds of anchor needs.
pub fn verify(
    ots: &DetachedTimestampFile,
    document: &[u8],
    headers: &dyn HeaderSource,
) -> Result<Outcome, OtsError> {
    if ots.digest_type != DigestType::Sha256 {
        return Err(OtsError::DigestMismatch);
    }
    let digest: [u8; 32] = Sha256::digest(document).into();
    if digest.as_slice() != ots.timestamp.start_digest.as_slice() {
        return Err(OtsError::DigestMismatch);
    }

    let mut reached = Reached::default();
    walk(&ots.timestamp.first_step, digest.to_vec(), &mut reached)?;
    if reached.bitcoin.is_empty() && reached.pending.is_empty() && reached.unknown.is_empty() {
        return Err(OtsError::NoAttestation);
    }

    let mut outcomes = Vec::with_capacity(reached.bitcoin.len());
    let mut best: Option<(usize, i64)> = None;
    for c in &reached.bitcoin {
        if c.reached.len() != 32 {
            outcomes.push(AttestationOutcome::NotADigest {
                height: c.height,
                len: c.reached.len(),
            });
            continue;
        }
        let outcome = match headers.header(c.height) {
            None => AttestationOutcome::NoHeader { height: c.height },
            Some((root, time)) if root.as_slice() == c.reached.as_slice() => {
                if best.map_or(true, |(h, _)| c.height < h) {
                    best = Some((c.height, time));
                }
                AttestationOutcome::Confirmed {
                    height: c.height,
                    block_time: time,
                }
            }
            Some(_) => AttestationOutcome::RootMismatch { height: c.height },
        };
        outcomes.push(outcome);
    }

    // `Contradicted` is reserved for the case where every attestation in the
    // proof was looked at and none of them matched. Anything left unlooked-at
    // keeps the answer at "I could not establish this": a header the caller
    // could not fetch, a value that is not a digest, a calendar still
    // outstanding — and an attestation whose tag this build does not know,
    // which is the easiest one to forget, because it never reaches the loop
    // above at all.
    let unchecked = !reached.pending.is_empty()
        || !reached.unknown.is_empty()
        || outcomes.iter().any(|o| {
            matches!(
                o,
                AttestationOutcome::NoHeader { .. } | AttestationOutcome::NotADigest { .. }
            )
        });
    let verdict = match best {
        Some((height, block_time)) => Verdict::Anchored { height, block_time },
        None if unchecked => Verdict::Indeterminate,
        None if outcomes.is_empty() => Verdict::Indeterminate,
        None => Verdict::Contradicted,
    };
    Ok(Outcome {
        verdict,
        attestations: outcomes,
        calendars: reached.pending,
        unknown_tags: reached.unknown,
    })
}
