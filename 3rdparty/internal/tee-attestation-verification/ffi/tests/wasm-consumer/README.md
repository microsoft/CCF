# WASM consumer API tests

These tests import the generated `tee_attestation_verification_ffi.js` package as
a JavaScript consumer would and exercise the exported wasm API surface. They are
intended to catch accidental JS API compatibility breaks.

They are split per API area — `snp.test.cjs`, `cose.test.cjs`, `caci.test.cjs` —
sharing a common `support.cjs` harness (package loader, fixtures, and error
assertions), mirroring the layout of the C consumer tests.

From the repository root:

```sh
cd ffi
wasm-pack build --target nodejs --out-dir ../target/wasm-consumer-tests/pkg --no-default-features --features crypto_pure_rust
cd ..
node --test ffi/tests/wasm-consumer/*.test.cjs
```
