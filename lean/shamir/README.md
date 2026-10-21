# Rust Shamir refinement

`src/crypto/sharing_rust.cpp` is the C++ compatibility adapter for the safe Rust implementation in [`src/rust/shamir`](../../src/rust/shamir).
The implementation uses ten independent limbs over `ZMod 2147483647`.
The existing C++ API, `Share` serialization, HKDF derivation, entropy source, input reduction, duplicate-coordinate rejection, and ignoring shares beyond the recovery threshold are preserved.
Zero recovery thresholds and share counts reaching the field characteristic are rejected.
Secret-bearing C++ scratch buffers are cleansed with OpenSSL; the recovered secret is written in place into the caller's buffer by the verified core, and neither Rust layer holds a copy of it.

## Compatibility requirement

Full bidirectional compatibility with `main` is a mandatory acceptance requirement.
Every valid serialized share emitted by `main` must be recoverable by the replacement implementation, and every valid serialized share emitted by the replacement must be recoverable by `main`, with identical recovered secrets and derived keys.
This includes partial shares, full shares, and every valid threshold-sized selection from a sharing.
Shares from independent sharings are not interchangeable.

The computational implementation may change, including polynomial evaluation order, but results and serialization must not change.
For identical sampled coefficients, both implementations must produce identical secret limbs, share coordinates, share limbs, serialized bytes, and HKDF output.
The field, limb count, coefficient sampling, threshold interpretation, input reduction, byte order, and serialized layout must remain unchanged.
Rejecting invalid inputs such as a zero recovery threshold is permitted and does not relax compatibility for valid shares.

Acceptance requires cross-implementation generation, serialization, deserialization, and recovery tests in both directions against a recorded `main` revision, including byte-level fixtures and derived-key comparisons.
Self-round-trips and refinement against CSLib alone do not establish this contract.
`sharing_test` links both backends and exchanges serialized shares in both directions, checking recovered secret bytes and derived keys for every threshold-sized subset of seven-share distributions and for full shares.
It also checks a fixed serialization fixture.
The retained C++ arithmetic comes from `main` revision `41645c55675d246605b2e26d45f4282de3d83fba`, with input guards matching the Rust adapter.
These unit checks do not replace network recovery compatibility tests.

## Backend selection

`USE_RUST_SHAMIR` defaults to `ON`.
Configure with `-DUSE_RUST_SHAMIR=OFF` to use the retained C++ implementation in `src/crypto/sharing.cpp`; see [build switches](../../doc/contribute/build_ccf.rst#build-switches).
Only the selected backend is compiled into `ccfcrypto`.
The other backend is compiled separately with renamed entry points for `sharing_test`, so both implementations are exercised in either configuration.
The C++ backend is not covered by the Rust refinement proofs.
CCF still requires Rust for attestation when the C++ Shamir backend is selected.

## Proof boundary

[`Generated/CcfShamir.lean`](Generated/CcfShamir.lean) is extracted by Aeneas from the production, dependency-free Rust core, not a handwritten substitute.
The same core crate is linked into `ccf-rs` and used by the C ABI.
`#![forbid(unsafe_code)]` applies to the entire core.
Raw-pointer conversion is confined to `src/rust/src/shamir.rs`; callers must supply live, aligned, nonoverlapping buffers of the declared lengths.
The shim checks null pointers, alignment, length arithmetic, and overlap, but cannot establish allocation validity, initialized contents, lifetimes, or the absence of concurrent access.
Those obligations remain with the C++ caller.
The C header `src/crypto/sharing_ffi.h` is generated from those Rust declarations by cbindgen; CI checks that it matches the Rust signatures, layout, limb count, and status codes, and the adapter additionally checks the layout with `static_assert`.
CI runs the C ABI tests under Miri with the Stacked Borrows and Tree Borrows aliasing models and strict provenance to check exercised pointer-handling paths for undefined behavior.
Share coordinates and values for each limb are assigned by the verified core; the C++ adapter samples coefficients and copies completed shares without recomputing either.
The C++ adapter copies members into the C representation rather than type-punning the nontrivially destructible C++ `Share`.
The core does not allocate, and recovery uses caller-owned storage linear in the threshold instead of variable-length stack arrays.
The unsafe FFI shim and the C++ adapter's OpenSSL calls are outside the verified safe core.

[`Shamir/Properties.lean`](Shamir/Properties.lean) states the refinement claims independently of their proofs.
[`Shamir/Proof.lean`](Shamir/Proof.lean) exports `sharing_refines_cslib`, `recovery_refines_cslib`, and `recovery_error_preserves_secret`.
Sharing refines CSLib's `Shamir.share` under the coefficient-vector encoding relation, for every canonical coefficient vector encoding that polynomial: filling a limb assigns coordinate `k + 1` to the share at index `k`, stores that coordinate's share value in the requested limb, and leaves every other limb unchanged.
Recovery terminates successfully for every nonempty selection of distinct field coordinates and an appropriately sized workspace, and each of its ten limbs, written in place over whatever the caller's array held, equals CSLib's `Shamir.Polynomial.reconstruct`.
For any inputs at all, a recovery that reports an error leaves the caller's array unchanged.
`recoveredLimb_eq_secret` also connects this reconstruction to CSLib's reconstruction-correctness theorem for low-degree sharing polynomials.
CCF's threshold counts shares; CSLib's `Params.threshold` is the polynomial-degree bound, one less.

The supporting proofs cover all `u64` inputs to the three-fold Mersenne reduction, overflow/underflow safety on canonical arithmetic, Horner evaluation, the share-filling loop, exponentiation, inversion, Lagrange weights, and all-limb reconstruction.
Field primality is certified with Mathlib's Lucas-Lehmer theorem.
There are no project axioms, `sorry`, or `admit`.
The extracted model and proofs do not verify pointer validity in the C adapter, OpenSSL, entropy uniformity or independence, secret erasure in compiled machine code, timing, the Rust compiler, or Aeneas's translation.
The randomness is an explicit input to deterministic polynomial sharing; this is not a proof of the real entropy source or a separate distributional refinement of CSLib's PMF sampler.

## Reproduce extraction

The pinned Linux x86-64 bundle contains matching Aeneas and Charon executables and the prebuilt Lean support library:

```bash
mkdir -p build/shamir-tools
gh release download nightly-2026.10.20-fc321a2 \
  --repo AeneasVerif/aeneas --pattern aeneas-linux-x86_64.tar.gz \
  --dir build/shamir-tools
echo '4b444e72e1e0bc475e952821bc081eb15665c984fd8032636c0346e766675794  build/shamir-tools/aeneas-linux-x86_64.tar.gz' | sha256sum --check
tar -xzf build/shamir-tools/aeneas-linux-x86_64.tar.gz -C build/shamir-tools
rustup toolchain install nightly-2026-09-17 --profile minimal \
  --component rustc-dev,rust-src,llvm-tools
AENEAS_BIN="$PWD/build/shamir-tools/aeneas" \
  CHARON_BIN="$PWD/build/shamir-tools/charon" \
  bash scripts/extract-shamir.sh
git diff --exit-code -- lean/shamir/Generated/CcfShamir.lean
```

The bundle pins Aeneas `fc321a28317f458338ce01fe684927eae0fa8f9e` and Charon `de8736f7c995ac54dc490345cef9ea5143c06c62`.
The Lake manifest pins Aeneas, CSLib `0b1e3680b43ad9cd482a66f183764f33fc8a4e8f`, Mathlib, and the common Lean 4.35.0 toolchain.
The generated LLBC is an ignored intermediate file.

## Reproduce the C header

The header is rendered with cbindgen 0.29.4 and formatted with the clang-format release pinned by `scripts/check-format.sh`:

```bash
cargo install cbindgen --version 0.29.4 --locked
bash scripts/generate-shamir-header.sh --check
```

Omit `--check` to rewrite `src/crypto/sharing_ffi.h` after changing the Rust declarations or their documentation.

## Validation

Run from the repository root:

```bash
cargo test --manifest-path src/rust/shamir/Cargo.toml --locked -j1
cargo test --manifest-path src/rust/Cargo.toml --lib --locked -j1
rustup component add miri --toolchain nightly-2026-09-17
cargo +nightly-2026-09-17 miri test --manifest-path src/rust/Cargo.toml --lib --locked -j1
MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-strict-provenance" \
  cargo +nightly-2026-09-17 miri test --manifest-path src/rust/Cargo.toml --lib --locked -j1
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
CARGO_BUILD_JOBS=1 cmake --build build --target sharing_test -j1
ctest --test-dir build -R '^sharing_test$' --no-tests=error --output-on-failure
cd lean/shamir
LEAN_NUM_THREADS=1 lake build --wfail
LEAN_NUM_THREADS=1 lake lint
cd ../..
bash scripts/check-shamir.sh --inadvisably-no-sandbox
```

The check script verifies the import-all roots and enumerates every declaration owned by both project libraries, including private and automatically generated declarations.
The standard `leanexport` exports all of these declarations and their transitive dependencies, and `lake check --from-export` kernel-checks that entire export and rejects axiom dependencies outside `propext`, `Classical.choice`, and `Quot.sound`.
This is not limited to the exported correctness theorems.
An unfiltered `lake check` also exports unused declarations from Aeneas's upstream test modules, including unfinished tests and unrelated opaque primitives, and fails its axiom audit on those declarations.
They are not dependencies of this project's declarations and are not added to the axiom allowlist.
The generated model is preserved exactly; only handwritten modules are subject to formatting and naming/documentation linting.
The no-sandbox option is for environments without working build isolation; it does not disable kernel or axiom checks.
Omit `--inadvisably-no-sandbox` where working build isolation is available.
Keep `LEAN_NUM_THREADS=1`, Cargo `-j1`, and CMake `-j1` on memory-constrained hosts.
The package limits each of its Lean compiler processes to 4500 MB; this is a Lean heap limit, not a process address-space limit.
Do not use a small `ulimit -v`: Lean memory-maps dependency artifacts and can fail imports even when physical memory remains available.
