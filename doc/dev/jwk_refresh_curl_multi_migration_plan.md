# JWK refresh migration to curl multi singleton

Status note for migrating JWT/JWK auto-refresh away from the enclave/host
`RPCSessions::create_client()` outbound HTTP client and onto the curl multi
singleton infrastructure introduced in microsoft/CCF#7102.

Last reviewed: 2026-06-26.

## Current status

Implementation is complete on this branch pending validation.

- `src/node/jwt_key_auto_refresh.h` uses `ccf::curl::CurlRequest` with
  `CurlmLibuvContextSingleton::get_instance()->attach_request(...)` for both
  external OpenID metadata and JWKS fetches.
- `JwtKeyAutoRefresh` no longer stores an `RPCSessions` pointer, and
  `src/node/node_state.h` constructs it without passing `rpcsessions`.
- The internal `/node/jwt_keys/refresh` update path still goes through
  `send_refresh_jwt_keys(...)` and is intentionally unchanged.
- Curl requests now set peer and host verification, use the configured
  in-memory CA bundle, restrict protocols to HTTPS only, and bound both connect
  and total transfer timeouts.
- OpenID metadata is still fetched from the configured issuer URL. The JWKS URL
  from metadata is parsed and must use the `https` scheme before it is handed to
  curl.
- Response bodies are bounded to 1 MB.
- Curl connection and TLS failures now call `send_refresh_jwt_keys_error()` and
  are counted in refresh failure metrics. `CHANGELOG.md` documents this
  observability change.
- `tests/jwt_test.py` includes focused connection-failure and TLS-trust-failure
  coverage and wires these into `run_manual()`.
- The new failure tests remove existing JWT issuers before recording the
  baseline failure count, so their metric-delta checks are isolated from other
  auto-refresh issuers.
- `src/http/test/curl_test.cpp` already covers generic curl singleton behavior;
  JWT behavior is covered by the Python end-to-end tests.

Unrelated local changes exist in `.github/workflows/README.md`,
`perf_artifacts/`, and `perf_data/`; leave them untouched.

## Remaining validation

Run these before considering the migration complete:

1. Build affected C++ targets, at minimum the node target and `curl_test`.
2. Run `curl_test` to catch curl multi singleton regressions.
3. Run JWT manual suite coverage containing:
   - `test_jwt_key_initial_refresh`
   - `test_jwt_key_auto_refresh_connection_failure`
   - `test_jwt_key_auto_refresh_tls_failure`
4. Run broader JWT auto-refresh coverage containing:
   - `test_jwt_key_auto_refresh`
   - backup-primary variant of `test_jwt_key_auto_refresh`
   - `test_jwt_key_auto_refresh_entries`
5. Confirm shutdown has no libuv handle leaks or async lifetime issues.
6. Optional follow-up: add a direct invalid OpenID metadata auto-refresh test if
   the test harness can serve malformed metadata without duplicating large parts
   of `infra.jwt_issuer`. Current coverage exercises invalid JWKS and curl-level
   connection/TLS failures, but not malformed metadata from a reachable issuer.

## Risks to keep watching

- `JwtKeyAutoRefresh` now inherits `enable_shared_from_this`; callers must keep
  constructing it as a shared pointer before any refresh is scheduled.
- Async callback captures must own all data they use. Current callbacks capture
  `self`, issuer strings, CA bundle strings, and response bodies by value/shared
  ownership.
- CA bundle material must remain valid until libcurl has consumed it. Current
  code passes the CA bundle into `set_blob_opt(...)`; verify this remains copied
  or otherwise owned by the curl wrapper.
- The 1 MB response limit and 5 second connect/transfer timeouts are intentional
  bounds, but can reject very large or slow metadata/JWKS responses.
- The HTTPS-only checks are intentional hardening. Any future support for other
  schemes should be explicit and tested.

## Definition of done

- Both external fetches use curl multi singleton requests.
- No JWT auto-refresh external fetch uses `RPCSessions::create_client(...)`.
- JWKS URIs must be HTTPS, and curl is restricted to HTTPS protocols.
- Curl requests have bounded connect and total transfer timeouts.
- Existing auto-refresh behavior remains intact.
- New connection and TLS failure tests pass with isolated metric baselines.
- Remaining validation above has been run and recorded in the PR or commit notes.
