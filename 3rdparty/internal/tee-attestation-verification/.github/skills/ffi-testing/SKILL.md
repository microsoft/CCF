---
name: ffi-testing
description: >-
  Test changes to the TAV C, WASM, and C# FFI surfaces. Use when exported
  functions, handles, constants, ownership rules, errors, goldens, or consumer
  tests change under ffi/.
argument-hint: "[c|wasm|csharp] [utils|snp|cose|caci]"
---

# FFI testing

Treat each consumer suite as an external user of its public surface.

## Required coverage

1. Enumerate the complete changed public surface from its authoritative source:
   - C: `ffi/include/tav/*.h`
   - WASM: exported items in `ffi/src/wasm_ffi`
   - C#: public types and members under `ffi/csharp/TeeAttestationVerification`
2. Exercise every matching function, property, enum member, and ownership
   operation in the corresponding consumer suite.
3. Assert behavior with known values or negative cases; successful invocation
   alone is insufficient.
4. Test owned handles, borrowed byte views, null/error behavior, and
   out-parameter reset rules where applicable.
5. Update goldens only alongside behavioral tests.

## ABI constants

When constants change:

1. Keep explicit test mappings between compiled Rust constants and their C
   names. Compare values and exact name sets in both directions.
2. For constants exposed in C#, keep explicit C-name-to-managed-name mappings.
   Parse the public C header and compare values and exact member sets with the
   reflected managed enum.
3. Reject missing, extra, duplicate, or mismatched members. Do not update only
   one side to make a test pass.
4. Use named Rust constants in runtime logic and tests; do not repeat numeric
   literals in match arms and equivalence tests.
5. Keep function signatures, handle ownership, and boolean/layout checks outside
   constant-equivalence tests.

## Validation

Use half-machine concurrency for builds.

- Native Rust: both `crypto_openssl` and `crypto_pure_rust`
- C consumer: shared and static, both native backends
- WASM consumer: `crypto_webcrypto` and `crypto_pure_rust`
- C#: `python3 ffi/csharp/run_tests.py --configuration Release`
- Repository: formatting, version sync, license headers, and `git diff --check`
