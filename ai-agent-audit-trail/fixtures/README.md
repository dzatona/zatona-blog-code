# Fixture provenance

## The receipt

`receipt.json` is generated (not hand-written) by a small throwaway
program that calls `atl-core`'s own `ReceiptBuilder` the same way
`atl-core`'s own integration tests do — see this repository's
`rfc-3161-vs-opentimestamps` crate for the same pattern applied to a
`Rfc3161AnchorFacts` fixture. It is a real, fully valid ATL v2.0 receipt,
not only a structurally well-formed one: its Data Tree root
(`sha256:ba92cde886aa4800300f236ada60da7ddb044de9ad0be9cccfa163ca207610bf`)
is the RFC 9162 leaf hash `SHA256(0x00 || payload_hash || metadata_hash)`
over

- `payload_hash = sha256:1bb1244d672e79e36c2341526946b3f4484f026a6b0993041eac2257d453821f`
  (`rfc-3161-vs-opentimestamps/fixtures/message.txt`'s digest — reused as
  an arbitrary but fixed payload hash, not because this receipt is about
  that file), and
- `metadata_hash`, the RFC 8785/JCS canonical hash of the metadata object
  literally in `receipt.json`, modeled on the post's own Section 7 sample.

The checkpoint is a one-leaf tree (`tree_size: 1`), so the root above *is*
the checkpoint's `root_hash`, signed with a throwaway Ed25519 key
(`SigningKey::from_bytes(&[42u8; 32])`) generated only for this fixture —
this signature is `atl-core`'s "integrity check, not a trust anchor" (its
own module docs), so nothing downstream trusts this key.

## The anchor: a second live FreeTSA token

`leaf-response.tsr` is a real RFC 3161 response from FreeTSA
(`https://freetsa.org/tsr`), fetched once, on 2026-09-25, over the Data
Tree root itself — **not** a re-use of the token in
`rfc-3161-vs-opentimestamps/fixtures/response.tsr`, which times-tamps a
different value (`message.txt`'s digest) for that crate's own, unrelated
purpose. ATL's RFC 3161 anchor covers the Data Tree root (its `target`
field is `"data_tree_root"`), so a receipt genuinely anchored the way ATL
means it needs a token whose `messageImprint` is that root, not some other
digest:

```sh
openssl ts -query \
  -digest ba92cde886aa4800300f236ada60da7ddb044de9ad0be9cccfa163ca207610bf \
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
Time stamp: Sep 25 04:55:53 2026 GMT
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
hl=4 l=4629 cons: SEQUENCE` is the `ContentInfo`; the field right after it,
`13: OBJECT :pkcs7-signedData`, is its first member). `receipt.json`'s
`token_der` is `leaf-response.tsr[9..]`, base64-encoded.

## FreeTSA's root certificate

`freetsa-cacert.der`/`.pem` are copied from the
`rfc-3161-vs-opentimestamps` crate's own fixtures in this repository (same
provenance: fetched from `https://freetsa.org/files/cacert.pem`), used
here as the `x509_cert::Certificate` passed into `one_step` as
`tsa_root_certificate`, which becomes the `TrustStore` anchor
`atl-core`'s own RFC 3161 chain verification checks against.
