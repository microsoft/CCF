# TEE-Attestation-Verification

A minimal-external-dependencies, portable and safe library for verifying a TEE attestation and its collateral, and returning to the caller the authenticated claims.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Build for `wasm32` with a WebCrypto backend
- **Azure Linux 3.0 compatible**: Build for Azure Linux 3.0, with `rust-openssl` as the sole dependency.

## Crypto Backends

At least one target-compatible crypto backend must be enabled.
If multiple backends are enabled, the target-compatible backend is selected with `crypto_openssl` and `crypto_webcrypto` preferred over `crypto_pure_rust`.

| Feature | Platforms | sync | async | Dependencies |
|---|---|---|---|---|
| `crypto_openssl` | Native | ✓ | ✓ | OpenSSL |
| `crypto_webcrypto` | WASM only | | ✓ | WebCrypto API |
| `crypto_pure_rust` | Native, WASM | ✓ | ✓ | Pure Rust (`p384`, `rsa`, `sha2`); selected when enabled and no target-preferred backend is enabled |

## Optional Features

| Feature | Description |
|---|---|
| `kds` | Enables automatic certificate fetching from AMD's Key Distribution Service. Uses `curl`/`tokio` on native, `globalThis.fetch` on WASM. |

## Usage

Add the library to your `Cargo.toml` with a crypto backend:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X", features = ["crypto_openssl"] }
```

### Offline verification (caller provides certificates)

Parse the attestation report from its raw 1184-byte binary representation and verify with the synchronous API:

```rust
use tee_attestation_verification_lib::snp::verify::{sync as tav, ChainVerification};
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)?;
let vcek = certificate_from_pem(vcek_pem)?;
let ask = certificate_from_pem(ask_pem)?;

tav::verify_attestation(
    &attestation_report,
    &vcek,
    &ChainVerification::WithPinnedArk { ask: &ask },
)?;
```

### KDS verification (automatic certificate fetching)

Enable the `kds` feature to let the library fetch certificates from AMD's KDS:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X", features = ["crypto_openssl", "kds"] }
```

```rust
use tee_attestation_verification_lib::{AttestationReport, SevVerifier};
use zerocopy::FromBytes;

let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)?;

let mut verifier = SevVerifier::new().await?;
verifier.verify_attestation(&attestation_report).await?;
```

## SEV-SNP Verification Process

- **Certificate Validation**: Verifies the certificate chain from the ARK through the ASK to the VCEK, and the ARK against a root-of-trust
- **Signature Validation**: Validates the attestation report signature was signed by the VCEK
- **TCB Verification**: Confirms that the TCB values in the attestation report match the VCEK's X.509 v3 extensions.

## Docs
Docs are available locally by running:
- `cargo doc` for native docs
- `cargo doc --target wasm32-unknown-unknown` for WASM builds

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
