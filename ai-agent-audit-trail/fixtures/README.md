# Fixture provenance

## The receipt, and the binding it exists to prove

`receipt.json` is generated (not hand-written) by a small throwaway
program that calls `atl-core`'s own `ReceiptBuilder` the same way
`atl-core`'s own integration tests do — see this repository's
`rfc-3161-vs-opentimestamps` crate for the same pattern applied to a
`Rfc3161AnchorFacts` fixture.

It is not only structurally valid; its two hashed inputs are the exact
values the listing (`listings/block-1.rs`) computes when
`tests/live_freetsa_anchor.rs` calls `one_step`, so the write side and the
read side genuinely agree rather than merely both running:

- `payload_hash = sha256:75ef60f151fbccf22549d4412dc7e20e72ac5bc0ea4d201be900d49a9c80099a`
  is `SHA256(STEP_BYTES)`, where `STEP_BYTES` is the exact byte string
  `tests/live_freetsa_anchor.rs` passes to `one_step` as `step_bytes`
  (`b"the model's raw output bytes for this step"`) — not an arbitrary
  value the receipt happens to carry.
- `metadata_hash = sha256:fa3803177ec557e7c01779f00ed4a25383d63db9723156644424d5df74223fa9`
  is the RFC 8785/JCS canonical hash of `receipt.json`'s `entry.metadata`
  object, which is byte-for-byte the object `listings/block-1.rs`'s own
  `json!` literal constructs — including its literal `"sha256:…"`
  placeholders (U+2026, not three periods) and its empty `apl: {}` (the
  block's `/* the APL claim ... */` comment is stripped by the Rust
  tokenizer before `json!` ever sees it, leaving `{}`).

The Data Tree root
(`sha256:4f134058b538221b6b9e0008d10469a821fd9e73d060ba6f435a26cf271aad1b`)
is the RFC 9162 leaf hash `SHA256(0x00 || payload_hash || metadata_hash)`
over exactly those two values — the same computation `compute_leaf_hash`
performs inside the listing when the test runs it. The checkpoint is a
one-leaf tree (`tree_size: 1`), so the root above *is* the checkpoint's
`root_hash`, signed with a throwaway Ed25519 key
(`SigningKey::from_bytes(&[42u8; 32])`) generated only for this fixture —
this signature is `atl-core`'s "integrity check, not a trust anchor" (its
own module docs), so nothing downstream trusts this key.

## The anchor: a live FreeTSA token, fetched for this receipt specifically

`leaf-response.tsr` is a real RFC 3161 response from FreeTSA
(`https://freetsa.org/tsr`), fetched once, on 2026-09-25, over the Data
Tree root above. This is a **separate fetch** from the token in
`rfc-3161-vs-opentimestamps/fixtures/response.tsr`, which times-tamps a
different value (that crate's `message.txt` digest) for that crate's own,
unrelated purpose — the two crates do not share a token. ATL's RFC 3161
anchor covers the Data Tree root (its `target` field is
`"data_tree_root"`), so a receipt genuinely anchored the way ATL means it
needs a token whose `messageImprint` is that root, not some other digest:

```sh
openssl ts -query \
  -digest 4f134058b538221b6b9e0008d10469a821fd9e73d060ba6f435a26cf271aad1b \
  -sha256 -cert -out leaf-request.tsq

curl -sS -o leaf-response.tsr \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @leaf-request.tsq \
  https://freetsa.org/tsr
```

Independently verified before being committed:

```
$ openssl ts -verify -in leaf-response.tsr -queryfile leaf-request.tsq \
    -CAfile freetsa-cacert.pem -untrusted <freetsa's TSA cert>
Verification: OK

$ openssl ts -reply -in leaf-response.tsr -text
Status info:
Status: Granted.
...
Serial number: 0x086BAF05
Time stamp: Sep 25 05:04:12 2026 GMT
```

## A real, and initially wrong, integration detail

`atl_core::ReceiptAnchor::Rfc3161::token_der`'s own doc comment says it
holds "DER-encoded `TimeStampResp`". It does not: `parse_rfc3161_token`
calls `ContentInfo::from_der` on the bytes directly, and a `TimeStampResp`
is `SEQUENCE { PKIStatusInfo, TimeStampToken }` — one level higher than a
`ContentInfo`. Passing the whole response fails with `unexpected ASN.1 DER
tag: expected OBJECT IDENTIFIER, got SEQUENCE at DER byte 2`. What the
field actually wants is the `TimeStampToken` (`= ContentInfo`) alone,
which starts at a fixed offset inside the response
(`openssl asn1parse -in leaf-response.tsr -inform DER` shows it: `9:d=1
hl=4 l=4630 cons: SEQUENCE` is the `ContentInfo`; the field right after it,
`13: OBJECT :pkcs7-signedData`, is its first member). `receipt.json`'s
`token_der` is `leaf-response.tsr[9..]`, base64-encoded.

## FreeTSA's root certificate

`freetsa-cacert.der`/`.pem` are copied from the
`rfc-3161-vs-opentimestamps` crate's own fixtures in this repository (same
provenance: fetched from `https://freetsa.org/files/cacert.pem`), used
here as the `x509_cert::Certificate` passed into `one_step` as
`tsa_root_certificate`, which becomes the `TrustStore` anchor
`atl-core`'s own RFC 3161 chain verification checks against.
