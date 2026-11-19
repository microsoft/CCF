# C ABI

Native C bindings for CBOR, SNP, COSE, and CACI verification.

## Build and link

On Linux with the OpenSSL development libraries installed:

```sh
cargo build --manifest-path ffi/Cargo.toml --no-default-features --features crypto_openssl
```

This produces `libtee_attestation_verification_ffi.a` and
`libtee_attestation_verification_ffi.so` under `target/debug/`.
Add `ffi/include` to the include search path and include headers as
`<tav/cbor.h>`, for example.

The [C consumer CMake setup](../../tests/c-consumer/CMakeLists.txt) supports
shared and static linking.

## Headers

Headers under [`ffi/include/tav/`](../../include/tav/) define the functions,
error codes, ownership contracts, and limits.

| C header | Surface | C++ wrapper |
|---|---|---|
| `cbor.h` | CBOR construction, parsing, navigation, and serialization | `cbor.hpp` |
| `snp.h` | SNP verification and report accessors | `snp.hpp` |
| `cose.h` | COSE validation and verification | None |
| `caci.h` | CACI endorsement and attestation verification | None |
| `errors.h` | `TavError` and error codes | `errors.hpp` |
| `byte_buffer.h` | Owned `TavByteBuffer` results | `byte_buffer.hpp` |

`utils.h` includes both C utility headers. C++ wrappers manage handle lifetimes
and report native errors through `tav::Exception`.
The C++ consumer executable runs with AddressSanitizer for shared and static
linking. The Rust library is not sanitizer-instrumented.

## Ownership and errors

Fallible functions return `NULL` on success or an owned `TavError*` on failure.
Read the error with `tav_error_code` and `tav_error_message`, then release it
with `tav_error_free`. Release buffers with `tav_byte_buffer_free`.
Fallible entry points catch unwinding Rust panics and return `TAV_ERROR_PANIC`.
Invalid pointers, allocation failure, and stack overflow are not recoverable
through this mechanism.

CBOR, COSE, and CACI use `TavCborHandle`; release each owned handle with
`tav_cbor_free`. CBOR parsing and byte/text builders borrow their input.
Keep that input alive and unchanged while derived handles use it, or use
`tav_cbor_deep_copy` to obtain an independent value. Child handles survive
parent release but do not extend caller-owned buffer lifetimes.

Owned output slots are cleared before work. Release a previous result before
reusing its slot, and keep output slots separate from input storage.
Each header documents its remaining preconditions and failure behavior.

## Examples

- [C and C++ ABI consumers](../../tests/c-consumer/): verification, CBOR readers,
  errors, and cleanup.
- [C++ CBOR consumers](../../tests/c-builder/): builders and navigation through
  `tav::cbor::Value`.
- [C++ SNP consumers](../../tests/cpp-consumer/): RAII verification and report
  accessors.
- [CACI C demo](../../../demos/caci-c-ffi/): staged verification and CBOR access
  to the returned endorsement.

## CBOR handle ownership

Navigation returns an independently owned handle that shares the immutable
document without copying its subtree. Parent and child handles can be freed
in either order. Caller-owned input must remain alive while either uses it.

```c
TavCborHandle *root = NULL;
TavCborHandle *child = NULL;
TavError *error = tav_cbor_nondet_parse(cbor, cbor_len, TAV_CBOR_DEFAULT_MAX_DEPTH, &root);
if (error == NULL) {
	error = tav_cbor_array_at(root, 0, &child);
}
tav_cbor_free(root);
if (error == NULL) {
	int kind = tav_cbor_kind(child);
	/* Use kind and child while cbor remains alive and unchanged. */
} else {
	fprintf(stderr, "%s\n", tav_error_message(error));
	tav_error_free(error);
}
tav_cbor_free(child);
```

Byte and text accessors return borrowed views. Keep the backing storage alive
while using a view. For handle-owned payloads, keep the accessor's handle alive.

## CBOR limits

| Limit | Value |
| --- | --- |
| Nesting depth, `max_depth` | Default `TAV_CBOR_DEFAULT_MAX_DEPTH` (16), hard cap `TAV_CBOR_MAX_DEPTH` (64) |
| Key/value pairs in any map | `TAV_CBOR_MAX_MAP_ENTRIES` (128) |

Every parser and serializer takes `max_depth`, and a request above the hard cap
is clamped to it. Non-deterministic parsing also caps the entries of every map
at `TAV_CBOR_MAX_MAP_ENTRIES` and rejects maps inside map keys, which bounds
validation time by the input length and the limits. The C++ wrapper applies the
default depth unless told otherwise, and COSE and CACI verification parse
within it.

Keep the default depth for untrusted input, and bound its length before parsing
it, since no parser does. A larger depth makes parsing more expensive: parsing
can cost time proportional to the depth limit times the input length, and each
non-deterministic parse allocates scratch sized by the depth limit, whatever
the input length. Expect a document nested to the hard cap to take up to four
times as long to parse as one nested to the default; `cbor.h` gives the scratch
sizes and the memory a parsed document takes. COSE and CACI verification leave
input sizes unchecked too.

## SNP verification

```c
TavSnpAttestationReport *report = NULL;
TavError *error = tav_verify_snp_attestation(
	report_bytes, report_len,
	ark_pem, ark_pem_len,
	ask_pem, ask_pem_len,
	vcek_pem, vcek_pem_len,
	&report);
if (error == NULL) {
	const uint8_t *measurement = NULL;
	size_t measurement_len = 0;
	tav_snp_attestation_report_measurement(report, &measurement, &measurement_len);
	/* Use measurement before freeing report. */
} else {
	fprintf(stderr, "%s\n", tav_error_message(error));
	tav_error_free(error);
}
tav_snp_attestation_report_free(report);
```

## CACI verification

CACI verification is staged: verify the SNP attestation and the UVM endorsement
independently, then check the relying-party policy over both verified handles.

```c
TavSnpAttestationReport *attestation = NULL;
TavCborHandle *uvm = NULL;
TavByteBuffer *report_data = NULL;
TavError *error = tav_verify_snp_attestation(
	report_bytes, report_len, ark_pem, ark_pem_len,
	ask_pem, ask_pem_len, vcek_pem, vcek_pem_len, &attestation);
if (error == NULL) {
	error = tav_verify_caci_uvm_endorsement(
		uvm_bytes, uvm_len, trusted_didx509, trusted_didx509_len, &uvm);
}
if (error == NULL) {
	error = tav_verify_caci_attestation(
		attestation,
		minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count,
		trusted_policy_digests, trusted_policy_digest_count,
		uvm, uvm_feed, uvm_feed_len, minimum_svn, &report_data);
}
if (error == NULL) {
	/* Use report_data before freeing it. */
} else {
	fprintf(stderr, "%s\n", tav_error_message(error));
	tav_error_free(error);
}
tav_byte_buffer_free(report_data);
tav_cbor_free(uvm);
tav_snp_attestation_report_free(attestation);
```

`report_data` contains the verified 64-byte SNP `REPORT_DATA`. Read it with
`tav_byte_buffer_data` and `tav_byte_buffer_len` before releasing it.
The [CACI consumer](../../tests/c-consumer/caci.cpp) covers failure cases.
