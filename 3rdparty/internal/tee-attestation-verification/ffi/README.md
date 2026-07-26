# FFI bindings

`tee-attestation-verification-ffi` exposes the Rust domain crates
(`attestation`, `cose`, `caci`) to non-Rust consumers: a native C ABI and a
`wasm_bindgen` WebAssembly/JS API.

See:

- [`src/c_ffi/README.md`](src/c_ffi/README.md) — C ABI: building/linking and
  worked examples.
- [`src/wasm_ffi/README.md`](src/wasm_ffi/README.md) — WASM/JS bindings:
  release tarball consumption, building from source, and worked examples.
