# Changelog

## [1.0.3]

[1.0.3]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.3

### Added

- C FFI added. (#74)

### Changed

- Formalised packaging of wasm to single tav-wasm-<tag>.tar.gz (#74)

## [1.0.2]

[1.0.2]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.2

### Added

- Add `tee-attestation-verification-cose`, a verification-only COSE_Sign1 crate backed by the shared crypto backends. (#56)
- Add WASM64 build support for the COSE crate so it can continue using EverParse CBOR code that requires 64-bit `usize`. (#55)
- Expose SNP CPU generation and add generation-aware TCB version comparisons. (#63)
- Add `tee-attestation-verification-caci`, a high-level verification policy for CACI attestations and endorsements. (#62)

### Changed

- Expose the crypto backend as its own crate. (#51)
- Add `wasm32-unknown-unknown` compatibility for COSE/CACI by bumping EverParse CBOR (`cborrs`/`cborrs-nondet`) to include project-everest/everparse#296, allowing WASM builds to use stable `wasm-pack`. (#71)

## [1.0.1]

[1.0.1]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.1

### Added

- Expose a WASM certificate bundle splitter. (#49)

## [1.0.0]

[1.0.0]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.0

- First stable release of the TEE attestation verification library.
- Verifies AMD SEV-SNP attestation reports and collateral, including certificate chains, report signatures, and TCB values.
- Supports native Rust consumers with the `crypto_openssl` and `crypto_pure_rust` backends.
- Supports WebAssembly consumers with the `crypto_webcrypto` and `crypto_pure_rust` backends and generated `wasm-pack` wrapper output.
- Provides offline verification with caller-supplied certificates and optional `kds` verification that fetches AMD KDS collateral.

## [0.1.1]

[0.1.1]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-0.1.1

- If multiple backends are enabled, choose the backend appropriate to the target architecture, e.g. OpenSSL on native, WebCrypto on WASM (#44)

## [0.1.0]

[0.1.0]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-0.1.0

- Initial development release of the TEE attestation verification library.
- Supports native Rust consumers with the `crypto_openssl` and `crypto_pure_rust` backends.
- Supports WebAssembly consumers with the `crypto_webcrypto` and `crypto_pure_rust` backends and generated `wasm-pack` wrapper output.
- Rust consumers use tagged git dependencies with `tav-<crate-version>` tags.
- WASM consumers can use the GitHub release tarball containing the generated WebCrypto `pkg/` bundle.
