# TEE Attestation Verification COSE

`tee-attestation-verification-cose` verifies COSE_Sign1 signatures using the
shared `tee-attestation-verification-crypto` backends.

This crate is intentionally verification-only. It does not expose COSE signing
or encryption APIs.

## Crypto backends

At least one target-compatible backend must be enabled.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Native OpenSSL-backed verification. |
| `crypto_pure_rust` | Native, WASM | yes | yes | Portable RustCrypto-backed verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for signature verification. |

Native targets prefer OpenSSL when enabled. WASM targets prefer WebCrypto when
enabled.

## Parsing and verification

Use `CborValue::from_bytes` to parse a COSE_Sign1 envelope. COSE_Sign1 is
encoded as CBOR tag 18 over an array:

```text
[
  protected_header : bstr,
  unprotected_header : map,
  payload : bstr / nil,
  signature : bstr,
]
```

After parsing the envelope, pass the protected-header bytes, payload bytes, and
signature bytes to `synchronous::cose_verify1` or `asynchronous::cose_verify1`.

The verifier accepts:

- COSE signature algorithm selected by the caller;
- protected-header bytes;
- detached or embedded payload bytes;
- signature bytes;
- public key imported through the active crypto backend.

If the protected header contains `alg`, it must match the caller-supplied
algorithm. If it omits `alg`, the caller-supplied algorithm is used as external
context.

## Usage

```rust
use tee_attestation_verification_cose::{
    synchronous as tav, CborValue, Key, KeyBackend, RsaPssSignatureKeyAlgorithm,
    SignatureKeyAlgorithm,
};

let envelope = CborValue::from_bytes(cose_sign1)?;
let sign1 = match envelope {
    CborValue::Tagged { tag: 18, payload } => *payload,
    _ => return Err("expected COSE_Sign1 tag".into()),
};

let protected_header = match sign1.array_at(0)? {
    CborValue::ByteString(bytes) => bytes,
    _ => return Err("protected header must be a byte string".into()),
};
let payload = match sign1.array_at(2)? {
    CborValue::ByteString(bytes) => bytes,
    _ => return Err("payload must be a byte string".into()),
};
let signature = match sign1.array_at(3)? {
    CborValue::ByteString(bytes) => bytes,
    _ => return Err("signature must be a byte string".into()),
};

let algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384);
let key = <Key as KeyBackend>::from_spki_der(subject_public_key_info_der, algorithm)?;

tav::cose_verify1(
    &key,
    algorithm,
    protected_header,
    payload,
    signature,
)?;
```

For WebCrypto or other async backends, use `asynchronous::cose_verify1`.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
