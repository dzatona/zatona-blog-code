use const_oid::db::rfc5912::ID_SHA_256;
use der::asn1::{Int, Null, OctetString};
use der::{Any, Encode};
use sha2::{Digest, Sha256};
use x509_cert::spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TimeStampReq, TspVersion};

/// A nonce is an ASN.1 INTEGER, and DER integers are signed. Eight random
/// bytes whose top bit is set encode as a negative number unless a zero octet
/// is prepended, and the token comes back carrying that octet: a verifier that
/// compares the token's nonce against its own random bytes then fails on a
/// token that is correct.
fn nonce_integer(random: &[u8; 8]) -> der::Result<Int> {
    let mut v = Vec::with_capacity(9);
    if random[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(random);
    Int::new(&v)
}

/// What the client has to keep between sending the request and checking the
/// response. Checks 2 and 4 of Section 3 compare the token against these, so a
/// verifier that discards them can no longer make those checks. `sent_at_ms`
/// is the lower end of the window the response has to fall in, so it is a
/// parameter and never a default: left at zero, check 4 accepts any genTime
/// after 1970.
pub struct PendingRequest {
    pub der: Vec<u8>,
    pub imprint: MessageImprint,
    pub nonce: Vec<u8>,
    pub sent_at_ms: i64,
}

pub fn build_request(data: &[u8], nonce: &[u8; 8], sent_at_ms: i64) -> der::Result<PendingRequest> {
    let digest = Sha256::digest(data);
    let nonce = nonce_integer(nonce)?;
    let imprint = MessageImprint {
        hash_algorithm: AlgorithmIdentifier {
            oid: ID_SHA_256,
            parameters: Some(Any::from(Null)),
        },
        hashed_message: OctetString::new(digest.as_slice())?,
    };
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: imprint.clone(),
        req_policy: None,
        nonce: Some(nonce.clone()),
        // Without this the TSA must not return its certificate, and the token
        // is uncheckable by anyone who does not already hold it.
        cert_req: true,
        extensions: None,
    };
    Ok(PendingRequest {
        der: req.to_der()?,
        imprint,
        nonce: nonce.as_bytes().to_vec(),
        sent_at_ms,
    })
}
