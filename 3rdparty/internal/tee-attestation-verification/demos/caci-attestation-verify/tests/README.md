# caci-attestation-verify end-to-end tests

Playwright tests that drive the `demos/caci-attestation-verify/` page in a real browser and
run the Confidential CACI fixture through the staged CACI WASM bindings.

## How to run

From the repository root, build the FFI WASM package:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.13.1 --locked

(
  cd ffi
  wasm-pack build \
    --target web \
    --out-dir ../demos/caci-attestation-verify/caci_pkg \
    --no-default-features \
    --features "crypto_webcrypto"
)
```

Install JS dependencies and run:

```sh
cd demos/caci-attestation-verify/tests
npm install
npm test
```
