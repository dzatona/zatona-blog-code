# Fixture provenance

## RFC 3161: a live token from FreeTSA

Fetched once, on 2026-09-25, against `https://freetsa.org/tsr`, a public
Time Stamping Authority. Not re-fetched by the test suite; `cargo test`
never makes a network call.

```sh
# The message this fixture times-tamps.
printf 'zatona-blog-code rfc-3161-vs-opentimestamps fixture, fetched 2026-09-25T00:00:00Z\n' \
  > message.txt

# The request. -cert asks for the TSA's certificate in the response
# (matches build_request's cert_req: true); the nonce is openssl's own
# random 8 bytes, echoed back by FreeTSA as a 9-byte DER INTEGER with a
# leading zero octet -- see NONCE in tests/live_freetsa_token.rs.
openssl dgst -sha256 -binary message.txt > /tmp/message.sha256
openssl ts -query -digest "$(xxd -p /tmp/message.sha256 | tr -d '\n')" \
  -sha256 -cert -out request.tsq

# The response.
curl -sS -o response.tsr \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  https://freetsa.org/tsr

# FreeTSA's own certificates, fetched separately (not taken from inside
# the response) and used as this test's pinned trust material.
curl -sS -o freetsa-tsa.crt   https://freetsa.org/files/tsa.crt
curl -sS -o freetsa-cacert.pem https://freetsa.org/files/cacert.pem
openssl x509 -in freetsa-tsa.crt    -outform DER -out freetsa-tsa.der
openssl x509 -in freetsa-cacert.pem -outform DER -out freetsa-cacert.der
```

Independently verified with OpenSSL (not this crate) before being committed:

```
$ openssl ts -verify -in response.tsr -queryfile request.tsq \
    -CAfile freetsa-cacert.pem -untrusted freetsa-tsa.crt
Verification: OK

$ openssl ts -reply -in response.tsr -text
Status info:
Status: Granted.
...
Serial number: 0x086B71DE
Time stamp: Sep 25 04:36:23 2026 GMT
Accuracy: unspecified
Ordering: yes
Nonce: 0xADEF4DF28359D918
TSA: DirName:/O=Free TSA/OU=TSA/description=.../CN=www.freetsa.org/...

$ openssl x509 -in freetsa-tsa.crt -noout -text | grep -A2 "Signature Algorithm\|Public Key Algorithm\|Extended Key Usage"
        Signature Algorithm: sha512WithRSAEncryption
            Public Key Algorithm: id-ecPublicKey
                ASN1 OID: secp384r1
            X509v3 Extended Key Usage: critical
                Time Stamping

$ openssl asn1parse -in response.tsr -inform DER | tail -8
 4518:d=7  hl=2 l=   8 prim: OBJECT            :ecdsa-with-SHA512
 4528:d=6  hl=2 l= 103 prim: OCTET STRING      [HEX DUMP]:3065...
```

So: FreeTSA's TSA certificate signs with ECDSA over P-384 (`secp384r1`),
and this response's `signerInfo.signatureAlgorithm` is `ecdsa-with-SHA512`
— which is what `tests/live_freetsa_token.rs`'s `verify_ecdsa_p384_sha512`
implements, and the one algorithm pair it claims to handle.

`request.tsq` is 68 bytes of content in a 70-byte file (`SEQUENCE` header
included); `response.tsr` is 4645 bytes. Policy OID `1.2.3.4.1` and the
`granted` status (`0x00`) were read directly off this response with
`openssl asn1parse -in response.tsr -inform DER`, which is also where
`tests/live_freetsa_token.rs`'s documented byte offset for the status
octet (8) comes from.

## OpenTimestamps: the reference client's own examples

`hello-world.txt`, `hello-world.txt.ots`, `two-calendars.txt` and
`two-calendars.txt.ots` are copied unmodified from
`opentimestamps-client`'s `examples/` directory (the upstream OpenTimestamps
reference client). `hello-world.txt` is 13 bytes, `Hello World!\n`, SHA-256
`03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340` — matches
the post's Section 5 exactly. `hello-world.txt.ots` is 688 bytes;
`two-calendars.txt.ots` is 265 bytes, matching the post's Section 4
annotated hex dump byte for byte.

## Block 358391's header

`block-358391-header.json` was fetched from a second, independent source —
`blockstream.info`'s block explorer API, not the OpenTimestamps calendar,
not the client, and not the post — specifically to cross-check the post's
own stated Merkle root and header time rather than trust them unverified:

```sh
curl -sS https://blockstream.info/api/block-height/358391
# -> 000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319
curl -sS https://blockstream.info/api/block/000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319
# -> "merkle_root": "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00", "timestamp": 1432827678
```

Reversed to internal byte order, that root is
`007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a` — the
exact string the post's Section 5 quotes — and `1432827678` is
2015-05-28T15:41:18Z, the exact header time Section 6 quotes.
`tests/opentimestamps_examples.rs` supplies this header through a
`HeaderSource` built from these literal bytes; no network call happens
inside the test.

## Synthetic certificates for `check_eku`'s negative paths

FreeTSA's real certificate exercises `check_eku`'s accepting path (via
`open_token` in `tests/live_freetsa_token.rs`). Its three rejecting paths
need certificates that do not exist among real TSAs, so they are
synthetic, generated locally and used for nothing but this test:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=no-eku-test" \
  -keyout /dev/null -out synthetic-no-eku.pem
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=noncrit-eku-test" -addext "extendedKeyUsage=timeStamping" \
  -keyout /dev/null -out synthetic-noncritical-eku.pem
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=two-purpose-eku-test" \
  -addext "extendedKeyUsage=critical,timeStamping,serverAuth" \
  -keyout /dev/null -out synthetic-two-purpose-eku.pem
openssl x509 -in synthetic-no-eku.pem            -outform DER -out synthetic-no-eku.der
openssl x509 -in synthetic-noncritical-eku.pem    -outform DER -out synthetic-noncritical-eku.der
openssl x509 -in synthetic-two-purpose-eku.pem    -outform DER -out synthetic-two-purpose-eku.der
```

Their private keys were never written to disk in the fixture (`/dev/null`)
and are not committed; nothing in this crate signs with them.
