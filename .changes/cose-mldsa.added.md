`ccf::crypto::COSEKey` and COSE verifiers support ML-DSA public keys (RFC 9964 AKP keys) and verify ML-DSA `COSE_Sign1` signatures; see [COSE Keys](doc/build_apps/crypto.rst#cose-keys).
`make_cose_verifier_from_key()` now rejects DER keys followed by trailing data.
