# C FFI demo

This Linux-only demo builds the `ffi` crate and links a C program against
the public header in `ffi/include/tav/snp.h`. It links dynamically by default, or
statically when configured with `-DTAV_LINK_STATIC=ON`.

Run these commands from this directory:

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/tav-c-ffi-demo \
  ../../attestation/tests/test_data/milan_attestation_report.bin \
  ../../attestation/src/pinned_arks/milan_ark.pem \
  ../../attestation/tests/test_data/milan_ask.pem \
  ../../attestation/tests/test_data/milan_vcek.pem
```

To build the same demo with static linking:

```sh
cmake -S . -B build-static -G Ninja -DTAV_LINK_STATIC=ON
cmake --build build-static
./build-static/tav-c-ffi-demo \
  ../../attestation/tests/test_data/milan_attestation_report.bin \
  ../../attestation/src/pinned_arks/milan_ark.pem \
  ../../attestation/tests/test_data/milan_ask.pem \
  ../../attestation/tests/test_data/milan_vcek.pem
```

The CMake build invokes:

```sh
cargo build --manifest-path ffi/Cargo.toml --no-default-features --features crypto_openssl
```

## Tests

`run_tests.py` builds the demo (shared and statically linked) and checks its
output against the golden files in `test-data/`, covering both the success path
and the empty-report failure path. It uses Python's `unittest` framework and
requires `cmake` and `ninja` on `PATH`:

```sh
python3 demos/c-ffi/run_tests.py
```
