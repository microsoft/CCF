# TEE Attestation Verification Crypto

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across OpenSSL and WebCrypto.
There is a fallback pure-rust backend for workloads that don't have webcrypto or openssl available.

## Backends

At least one target-compatible backend feature must be enabled. If multiple
backend features are enabled, `build.rs` selects the target-preferred backend.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_pure_rust` | Native, WASM | yes | yes | Uses RustCrypto crates and the shared X.509 path validator. |

Native targets prefer `crypto_openssl` when enabled, then `crypto_pure_rust`.
WASM targets prefer `crypto_webcrypto` when enabled, then `crypto_pure_rust`.

## Scope

This crate is intentionally limited to just what is required to verify SNP attestations, and in the future UVM endorsements.
This narrow scope ensures we don't need to implement generic cryptographic primitives.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.