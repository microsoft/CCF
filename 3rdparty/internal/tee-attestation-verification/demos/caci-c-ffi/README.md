# CACI C FFI demo

This demo verifies the checked-in Confidential ACI fixture through the staged
native C ABI declared by `ffi/include/tav/caci.h`.

The CACI library is the frontend link target for the whole flow: it exports the
SNP verifier from `ffi/include/tav/snp.h`, the CBOR/COSE helpers from
`ffi/include/tav/cose.h`, and the CACI UVM/policy functions from
`ffi/include/tav/caci.h`.

The demo hardcodes one minimum-TCB entry for the Milan fixture: CPUID
`0x00A00F11` with minimum TCB bytes `04000000000018db`, passed as the parallel
`minimum_tcb_cpuids`/`minimum_tcb_values` arrays.

```sh
cmake -S demos/caci-c-ffi -B demos/caci-c-ffi/build -G Ninja
cmake --build demos/caci-c-ffi/build

./demos/caci-c-ffi/build/tav-caci-c-ffi-demo \
  caci/tests/fixtures/report.hex \
  caci/tests/fixtures/host-amd-cert.base64 \
  caci/tests/fixtures/reference-info.base64 \
  'did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2' \
  demos/caci-c-ffi/test-data/policy.hex \
  ContainerPlat-AMD-UVM \
  104
```

Use `-DTAV_LINK_STATIC=ON` when configuring CMake to link against the Rust
static library instead of the shared library.

## Tests

`run_tests.py` builds the demo (shared and statically linked) and checks its
output against the golden files in `test-data/`, covering both the success path
and the empty-report failure path. It uses Python's `unittest` framework and
requires `cmake` and `ninja` on `PATH`:

```sh
python3 demos/caci-c-ffi/run_tests.py
```

