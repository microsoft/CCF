# Changelog

## [2.0.0]

[2.0.0]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-2.0.0

### Added

- C++ RAII wrapper for SNP attestation verification: `<tav/snp.hpp>` (`tav::snp::Report`), `<tav/errors.hpp>` (`tav::Exception`), and `<tav/byte_buffer.hpp>` (`tav::ByteBuffer`). (#160)
- `CborValue::parse_with_limits`, which takes the map entry limit explicitly, with `MAX_CBOR_MAP_ENTRIES` (128) as the default. The C ABI and the C++ wrapper apply the default and publish it as `TAV_CBOR_MAX_MAP_ENTRIES` and `tav::cbor::MAX_MAP_ENTRIES`. The defaults are the recommended limits for untrusted input: larger ones make it more expensive to parse. (#174, #175)
- `TAV_CBOR_DEFAULT_MAX_DEPTH` (16) in the C ABI and `tav::cbor::DEFAULT_MAX_DEPTH` in the C++ wrapper, matching `MAX_CBOR_NESTING_DEPTH`. (#174)

### Changed

- **Breaking:** non-deterministic CBOR parsing, and so `CborValue::parse_nondet`, `tav_cbor_nondet_parse`, `tav::cbor::nondet_parse`, the C# and WASM parsers, and the COSE and CACI parsers, rejects maps with more than 128 key/value pairs and maps anywhere inside a map key. It validates through EverCBOR's single-pass bounded validator with sort-based duplicate detection, so validation costs time bounded by the input length and the limits. Deterministic parsing and serialization are unchanged. Existing `CborValue` and FFI parser signatures are unchanged. (#174)
- **Breaking:** explicit Rust `Nondet` parsing limits must allow `max_depth + 1` and `3 * (max_depth + 1) * max_map_entries` scratch words to fit in `usize`; `usize::MAX` is not an unlimited-depth sentinel. Overflow returns `"CBOR limits too large"`, and scratch-allocation failures are reported separately from malformed input. (#174)
- **Breaking:** the public, doc-hidden Rust `Backend::parse` trait method now takes `max_depth` and `max_map_entries` and returns `Result` instead of `Option`. External backend implementations must update. (#174)
- **Breaking:** the default nesting depth for CBOR parsing and serialization, `MAX_CBOR_NESTING_DEPTH`, is 16 instead of 64. It applies to `CborValue::parse_nondet`, `parse_det`, `to_bytes_det` and `to_bytes_nondet`, the C# and WASM `CborValue`, and the COSE and CACI parsers. Rust, C and C++ callers can ask for a deeper limit; C# and WASM callers cannot. (#174)
- **Breaking:** the C ABI's hard cap on nesting depth, `TAV_CBOR_MAX_DEPTH`, is 64 instead of 256. A larger `max_depth` is clamped to it. (#174)
- **Breaking:** the C++ CBOR wrapper's parsers and serializers default `max_depth` to `tav::cbor::DEFAULT_MAX_DEPTH` (16), the depth the Rust, C# and WASM APIs use, instead of the `MAX_DEPTH` hard cap. Pass a larger `max_depth`, up to `MAX_DEPTH` (64), for deeper documents. (#174)
- Bump EverCBOR (`cborrs`/`cborrs-nondet`) to the merge of project-everest/everparse#364. (#174)
- The CBOR crate vendors the EverCBOR sources instead of depending on the EverParse git repository, so it can be published to crates.io. Its licence is now `MIT AND Apache-2.0`. (#179)
- The CBOR parsers and COSE and CACI verification leave input sizes unchecked: callers bound the length of untrusted input, since parsing CBOR can cost time proportional to the nesting depth times the input length. The C ABI and C# accept input buffers of any length, where they rejected ones longer than 1 GiB. (#178)
- Native CBOR, COSE, and CACI use `TavCborHandle` and the generic API in `tav/cbor.h`. C++ CBOR failures use `tav::Exception` and `tav::ErrorCode`. (#159)
- C# CBOR bindings use the C API's `TavCborHandle` handles while preserving owned input. CBOR failures now report generic CBOR error codes instead of COSE codes. COSE verification retains its COSE error codes. (#159)
- SNP verification rejects reports that are not VCEK-signed (VLEK, `None`, or reserved `SIGNING_KEY`), requires the hardware ID extension in the VCEK, and matches TCB and hardware ID extension values against exact DER INTEGER, raw, or OCTET STRING encodings only. (#147)

### Removed

- **Breaking:** the `kds` feature of `tee-attestation-verification-lib`, with `SevVerifier`, `AmdCertificates`, the `verify-attestation` CLI, and the KDS-backed WASM `verify_attestation_report`. We recommend manually fetching the VCEK and ASK from AMD KDS and pass them to `snp::verify`. (#184)
- **Breaking:** removed the deprecated native `tav_cbor_value_*` functions, `TavCborValue` alias, and `TavCborKind` enum. COSE validation and verification and the independent WASM CBOR API remain supported. (#159)

### Fixed

- `ChainVerification::WithProvidedArk` verifies the provided ARK's self-signature against the pinned ARK and rejects a corrupted ARK with `InvalidRootCertificate`. (#145)
- `tav_verify_snp_attestation` copies the report before verification and returns that verified copy, so the returned handle never holds bytes that were not verified. (#151)
- WASM `verify_caci_attestation` copies its report, UVM endorsement, and policy inputs before it returns. Freeing a handle while the returned promise was pending made the verification read freed memory. (#182)
- The OpenSSL backend's `from_pem` and `from_pem_chain` return an error for input longer than `INT_MAX` bytes. (#178)

## [1.0.8]

[1.0.8]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.8

### Added

- Handle-based CBOR API for C++ in the `tee-attestation-verification-ffi` crate, with independently owned navigation handles, for building, parsing, serializing and inspecting CBOR. The supported interface is the `<tav/cbor.hpp>` wrapper; the C ABI beneath it is an implementation detail of that header. (#133)

### Changed

- By default all crypto backends are enabled. This selects the platform's crypto backend automatically, however OpenSSL is now disabled on Windows. (#136)

### Fixed

- Reject duplicate CPUID entries in minimum-TCB policies, including case aliases supplied through WASM JSON. (#83)

### Removed

- Removed the `crypto_pure_rust` backend and feature from all crates. (#131)

## [1.0.7]

[1.0.7]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.7

### Added

- C and .NET FFI constructors for decoding SNP reports without verification. (#101)
- Windows CNG crypto provider. (#100)
- Windows and macOS x64 native libraries in the .NET NuGet package.

## [1.0.6]

[1.0.6]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.6

### Changed

- Updated the NuGet package README to consume C-ACI's published endorsement formats directly. (#98)

## [1.0.5]

[1.0.5]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.5

### Added

- Nuget packaging (#94)

## [1.0.4]

[1.0.4]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.4

### Added

- Linux x64 .NET bindings and OpenSSL-backed NuGet packaging over the C FFI. (#88)

### Fixed

- C FFI `TavCborValue` accessors now return owned rather than borrowed values. (#81)
- WASM `CborValue` accessors no longer clone CBOR subtrees during navigation. (#81)

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
