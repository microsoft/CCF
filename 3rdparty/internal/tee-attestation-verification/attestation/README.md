# TEE-Attestation-Verification

A minimal-external-dependencies, portable and safe library for verifying a TEE attestation and its collateral, and returning to the caller the authenticated claims.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Build for `wasm32` with a WebCrypto backend
- **Azure Linux 3.0 compatible**: Build for Azure Linux 3.0, with `rust-openssl` as the sole dependency.

## Crypto Backends

The default feature set enables every backend selector. The build selects the
target-compatible backend.

| Feature | Platforms | sync | async | Dependencies |
|---|---|---|---|---|
| `crypto_openssl` | Native non-Windows | ✓ | ✓ | OpenSSL |
| `crypto_webcrypto` | WASM only | | ✓ | WebCrypto API |
| `crypto_windows` | Windows | ✓ | ✓ | Windows CNG and Crypt32 |

## Usage

Add the library to your `Cargo.toml`:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X" }
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

## What verification checks

`verify_attestation` checks that the report was signed by the key in the supplied VCEK and that the report's `chip_id` and `reported_tcb` match the VCEK's hardware ID and TCB extensions. With `ChainVerification::WithPinnedArk` or `WithProvidedArk` it also verifies the ASK and VCEK against the AMD root key compiled into the crate, so the result traces back to AMD. With `ChainVerification::Skip` the result rests only on your trust in the supplied VCEK.

Chain verification checks certificate validity periods at the machine's current clock. No verification time can be supplied. Nothing checks certificate revocation: there is no CRL or OCSP lookup and no hook for one.

Verification authenticates the report. It does not authorize the guest. After `Ok`, check the fields your deployment depends on:

- `report_data` against your nonce, challenge, or public-key digest.
- `measurement`, `host_data`, key digests, `policy()`, `vmpl`, and other identity and configuration fields.
- Every TCB field against your minimum. The library checks `reported_tcb` for equality with the VCEK only. Equality is not a minimum security baseline.
- 

## Docs
Docs are available locally by running:
- `cargo doc` for native docs
- `cargo doc --target wasm32-unknown-unknown` for WASM builds

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
