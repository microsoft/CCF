`ccf::crypto::MLDSAKeyPair` can issue X.509 certificates and PKCS#10 CSRs signed with pure ML-DSA, and `ccf::crypto::make_verifier()` accepts ML-DSA certificates.
ML-DSA headers are available on every build; on OpenSSL older than 3.5, `make_mldsa_key_pair()` and `make_mldsa_public_key()` throw `std::runtime_error`. See [cryptographic APIs](doc/build_apps/crypto.rst).
