# web-verify-kernel — minimal WASM verification demo

A standalone HTML/JS page that exercises the WASM bindings from
`tee-attestation-verification-ffi` and renders the verified SEV-SNP attestation
report.

All processing happens client-side; the page makes no network calls other
than loading its own WASM module.

## Build and run

Use either a release bundle or a local build.

### Option A: use a release bundle

Download `tav-wasm-<version>.tar.gz` from the matching GitHub release,
then extract it into the demo's expected `pkg/` directory:

```sh
cd demos/web-verify-kernel
mkdir -p pkg
tar -xzf /path/to/tav-wasm-<version>.tar.gz --strip-components=1 -C pkg
python3 -m http.server 8000
```

Open <http://localhost:8000/> in a browser.

### Option B: build from source

1. From the repository root, build the WASM package with the WebCrypto
   backend, emitting `pkg/` directly inside this demo directory (which is
   what `index.html` imports via `./pkg/...`):

   ```sh
   cd ffi
   wasm-pack build --target web --out-dir ../demos/web-verify-kernel/pkg --no-default-features --features "crypto_webcrypto"
   ```

2. Serve **this directory** over HTTP.

   ```sh
   cd demos/web-verify-kernel
   python3 -m http.server 8000
   ```

3. Open <http://localhost:8000/> in a browser.

After editing Rust sources, rerun step 1 and hard-refresh the browser.

## Inputs

Four verification inputs, each accepting either a file upload or pasted text:

- **Attestation report** — 1184-byte binary (upload) or hex string (textarea).
- **VCEK**, **ASK**, **ARK** — PEM-encoded certificates.

The optional **ASK/ARK bundle splitter** accepts a PEM bundle containing ASK
followed by ARK, calls `split_certificate_bundle`, and populates the ASK and
ARK textareas before verification.

Test fixtures shipped alongside the demo in `./test-data/`:

- Milan: `milan_attestation_report.bin`, `milan_vcek.pem`, `milan_ask.pem`,
  `milan_ark.pem`.
- Turin: `turin_attestation_report.bin`, `turin_vcek.pem`, `turin_ask.pem`,
  `turin_ark.pem`.

These are mirrors of upstream files in `tests/test_data/` and
`attestation/src/pinned_arks/`.

## Scope of verification

A successful result means the page has verified:

- that the supplied ARK public key matches the pinned AMD root for the report's
  processor generation,
- the ARK → ASK → VCEK certificate chain,
- the attestation report signature against the VCEK, and
- report/VCEK TCB extension matching.

It does **not** check:

- TCB freshness or revocation status,
- the debug or single-socket policy bits,
- whether `measurement` or `report_data` match any expected value.

This is a demo for exploring the WASM surface, not a complete verifier.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
