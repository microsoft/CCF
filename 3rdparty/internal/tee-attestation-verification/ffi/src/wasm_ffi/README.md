# WASM bindings

`wasm_bindgen` bindings exposing SNP, COSE, and CACI verification to
JavaScript. See the module doc comment in `mod.rs` for the lifetime contract
on async entry points (owned args are copied at the boundary; borrowed
handles and live JS arrays must not be mutated or freed until the returned
promise settles).

## Consuming a release tarball

Release tags use the `tav-<crate-version>` format.

Releases include `tav-wasm-<version>.tar.gz`, a WASM and JS wrapper tarball
built with the WebCrypto backend. Download and extract the matching GitHub
release asset for your chosen tag into a directory served by your
application:

```sh
mkdir -p public/vendor/tav-wasm
tar -xzf tav-wasm-<version>.tar.gz --strip-components=1 -C public/vendor/tav-wasm
```

Keep the generated `.js` and `.wasm` files together. By default, the JS
wrapper loads `tee_attestation_verification_ffi_bg.wasm` next to itself using
`import.meta.url`.

```js
import init, {
  verify_attestation_async,
  verify_uvm_endorsement_async,
  verify_caci_attestation,
} from "/vendor/tav-wasm/tee_attestation_verification_ffi.js";

await init();
```

## Building from source

```bash
cd ffi
wasm-pack build --target web --no-default-features --features crypto_webcrypto
```

For Node consumers, use `--target nodejs` instead; see
`ffi/tests/wasm-consumer/README.md`.

## SNP verification

```js
const attestation = await verify_attestation_async(reportBytes, arkPem, askPem, vcekPem);
attestation.measurement; // Uint8Array; see snp.rs for the full accessor list
```

`verify_attestation_async` verifies the AMD certificate chain and report
signature and returns an opaque `SnpAttestationReport`. If you only have a
concatenated PEM chain (e.g. ASK+ARK from a single download), split it first
with `split_pem_bundle(pemChain)`. 

See `demos/web-verify-kernel` for a runnable browser demo.

## CACI verification

CACI verification is staged: verify the SNP attestation and the UVM
endorsement independently, then check the relying-party policy over both
verified handles.

```js
const attestation = await verify_attestation_async(reportBytes, arkPem, askPem, vcekPem);
const uvm = await verify_uvm_endorsement_async(uvmEndorsementBytes, trustedDidx509);

const reportData = await verify_caci_attestation(
  attestation,
  JSON.stringify(minimumTcb), // e.g. { "00a00f11": "04000000000018db" }
  trustedPolicyDigests, // Uint8Array[], one 32-byte SHA-256 digest each
  uvm,
  uvmFeed,
  BigInt(minimumSvn),
);
```

`reportData` is the verified 64-byte SNP `REPORT_DATA`. See
`demos/caci-attestation-verify` for a runnable browser demo, and
`ffi/tests/wasm-consumer/caci.test.cjs` for the failure modes.
