# AKPresentation

Holder-side credential presentation for iOS 17+ / macOS 14+, built on **AKSecurity** and **AKOpenID4VCI**.

| Area | What's implemented |
|---|---|
| DCQL | Query model and validation, claim path selection, `credential_sets`, `claim_sets`, `trusted_authorities` (aki), meta (`vct_values`, `doctype_value`, `type_values`) |
| OpenID4VP 1.0 | `request` / `request_uri` (GET and POST with `wallet_metadata` / `wallet_nonce`), signed request objects, client identifier prefixes `x509_san_dns`, `x509_hash`, `redirect_uri`, `decentralized_identifier` (did:jwk), `verifier_attestation`, pre-registered |
| Response | `direct_post`, `direct_post.jwt` (JWE, ECDH-ES), `fragment`, Interactive Authorization (`ia_post`, `ia_post.jwt`) |
| SD-JWT VC | Selective disclosure by claim path, KB-JWT with `sd_hash` and `transaction_data_hashes` |
| mdoc | DeviceResponse with deviceSignature, OpenID4VP handover session transcript |
| W3C VC | `jwt_vc_json` presented in a VP JWT |
| ISO/IEC 18013-5 | Device engagement (QR, NFC static handover), BLE peripheral server and central client modes, session encryption, reader authentication, DeviceResponse |

## Main types

- `AKDCQLMatcher.match(_:credentials:)` finds candidates for each credential query.
- `AKVPRequestResolver.resolve(_:)` parses, fetches and authenticates an authorization request.
- `AKVPPresenter.vpToken(for:selections:)` builds the `vp_token`.
- `AKVPResponder.submit(vpToken:for:)` posts or encrypts the response.
- `AKProximityPresentation` runs the in-person flow and streams `AKProximityEvent`s.

## Tests

```bash
swift test
```

The test PKI in `Tests/AKPresentationTests/TestPKI.swift` is produced by `Scripts/generate_test_pki.py`. Do not use it outside tests.

## Limitations

- `ldp_vc` (Data Integrity) credentials can be matched but not presented.
- NFC engagement needs iOS 17.4+ and Apple's Host Card Emulation entitlement.
