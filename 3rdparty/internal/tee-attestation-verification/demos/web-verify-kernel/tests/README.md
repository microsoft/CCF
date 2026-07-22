# web-verify-kernel end-to-end tests

Playwright tests that drive the `demos/web-verify-kernel/` page in a real
browser, run the Milan attestation fixture through `verify_attestation_async`,
and diff the rendered output against `milan_report.expected.txt`. Additional
tests exercise the ASK/ARK bundle splitter and the error-rendering path by
validating a Milan VCEK->ASK chain against the Turin ARK and checking that the
rendered status surfaces `ErrorCode::InvalidRootCertificate` (102).

## How to run the tests

### 1. Build the WASM bundle

From the repository root, build the WASM package directly into the demo
directory (so the page's `./pkg/...` import resolves):

```sh
cd ffi
wasm-pack build --target web --out-dir ../demos/web-verify-kernel/pkg --no-default-features --features "crypto_webcrypto"
```

Rerun this whenever you change Rust sources under `ffi/src/`, `attestation/src/`, or `crypto/src/`.

### 2. Install JS dependencies

```sh
cd demos/web-verify-kernel/tests
npm install
```

### 3. Install Chromium

```sh
npx playwright install --with-deps chromium
```

`--with-deps` installs the system libraries Chromium needs via `apt`. On
hosts where this doesn't work (anything not Ubuntu/Debian), see
"Chromium fails to launch" under Troubleshooting.

### 4. Run the tests

```sh
npm test
```

Playwright starts its own `python3 -m http.server` rooted at the demo
directory (`demos/web-verify-kernel/`) on port `8123`, so no separate server
is needed. Fixtures are served from `../test-data/` and reached at
`/test-data/...` over HTTP; the WASM bundle is loaded from `/pkg/...`.

## Troubleshooting

### Chromium fails to launch (`SIGSEGV` or "cannot open shared object file")

Playwright's bundled Chromium depends on a set of shared libraries
(`libatk-1.0.so.0`, `libgbm.so.1`, `libXcomposite.so.1`, etc.) that
`npx playwright install --with-deps` only knows how to install via `apt`.
On other distros (Azure Linux, NixOS, Fedora, RHEL, ...), the browser will
install but fail at launch with either a clear "cannot open shared object
file" message or a less-clear `SIGSEGV (Address boundary error)` from the
test runner — same root cause, different presentation.

To confirm this is your problem, look up the Chromium install path with
`npx playwright install --dry-run chromium`, then:

```sh
ldd <path-to-chrome-headless-shell> | grep "not found"
```

Any output here means the launch will fail.

The supported workaround is to use the Chromium that nixpkgs ships with
all its dependencies bundled. This invocation provides Chromium *and* runs
the tests, replacing both step 3 and step 4 above (you still need steps 1
and 2):

```sh
nix-shell -p playwright-driver.browsers --run '
  export PLAYWRIGHT_BROWSERS_PATH=$(nix-build "<nixpkgs>" -A playwright-driver.browsers --no-out-link)
  export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
  export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
  npm test
'
```

### `OSError: [Errno 98] Address already in use` from the webserver

Playwright leaves the static webserver running when the test process
crashes (e.g. on a browser segfault). Subsequent runs then fail to bind
port 8123. Kill the stale server and rerun:

```sh
pkill -f "http.server 8123"
```

### `Executable doesn't exist at .../headless_shell`

The browser isn't installed. Run step 3.

## Regenerating the golden file

Run the test with `UPDATE_GOLDEN=1` to capture the current rendered output
into `milan_report.expected.txt`:

```sh
npm run update-golden
```

Do this after any intentional change to `demo.js` rendering or to the WASM
accessors exposed from `ffi/src/wasm_ffi/snp.rs`. Inspect the diff before committing
to confirm the change matches your intent.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
