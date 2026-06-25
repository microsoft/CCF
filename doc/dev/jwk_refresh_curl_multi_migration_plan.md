# JWK refresh migration to curl multi singleton

This note captures the implementation plan for migrating JWT/JWK auto-refresh in CCF away from the current `RPCSessions::create_client()` outbound HTTP client and onto the curl multi singleton infrastructure introduced in microsoft/CCF#7102.

## Reference PR

PR microsoft/CCF#7102 introduced:

- `ccf::curl::UniqueCURL`
- `ccf::curl::UniqueSlist`
- `ccf::curl::RequestBody`
- `ccf::curl::ResponseBody`
- `ccf::curl::ResponseHeaders`
- `ccf::curl::CurlRequest`
- `ccf::curl::CurlmLibuvContextSingleton`

It migrated `src/node/quote_endorsements_client.h` from the enclave/host RPC client path to asynchronous curl requests attached to the singleton curl multi/libuv context.

## Current JWK refresh flow

The current JWK refresh implementation is in:

- `src/node/jwt_key_auto_refresh.h`

It uses `rpcsessions->create_client(...)` in two places:

1. OpenID metadata fetch:
   - GET `issuer + "/.well-known/openid-configuration"`
   - parse `jwks_uri`
2. JWKS fetch:
   - GET the parsed `jwks_uri`
   - parse `JsonWebKeySet`
   - call the internal `/node/jwt_keys/refresh` endpoint via `send_refresh_jwt_keys(...)`

The internal update path should remain unchanged.

## Implementation goals

- Replace both external HTTP fetches with `ccf::curl::CurlRequest`.
- Enqueue asynchronous requests with `ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(...)`.
- Preserve the existing refresh, parsing, issuer constraint, and metrics behaviour.
- Improve observability where possible: curl connection/TLS failures should call `send_refresh_jwt_keys_error()` so they are reflected in refresh failure metrics.
- Keep changes bite-sized and testable.

## Bite-sized implementation steps

### 1. Add curl dependency to JWK refresh

- Include `http/curl.h` from `src/node/jwt_key_auto_refresh.h`.
- Keep the existing implementation compiling unchanged.

Verification:

- Build affected targets.

### 2. Add request-building helpers

Add private helpers to `JwtKeyAutoRefresh` for:

- defaulting URL ports to `443` for HTTPS
- building a full request URL from `http::URL`
- setting common curl options
- attaching CA bundle material to curl
- creating a bounded `ccf::curl::ResponseBody`

Verification:

- Unit-level compile checks.
- Existing JWT tests still pass before call sites are migrated.

### 3. Implement CA bundle handling for curl

The existing code reads a PEM CA bundle from KV and constructs `tls::CA`/`tls::Cert` for the old client.

For curl, prefer in-memory CA bundle support if available:

- `CURLOPT_CAINFO_BLOB` via `UniqueCURL::set_blob_opt(...)`

If unsupported by the project's supported libcurl version, introduce a request-owned fallback that keeps temporary CA material alive for the async request lifetime.

Verification:

- Valid issuer cert signed by configured CA bundle succeeds.
- Wrong CA bundle fails and is counted as a refresh failure.

### 4. Migrate OpenID metadata fetch first

In `refresh_jwt_keys()`:

- Preserve issuer iteration, `auto_refresh` checks, attempts accounting, and missing CA bundle handling.
- Replace `rpcsessions->create_client(...)`, `connect(...)`, and `send_request(...)` with a curl GET request.
- Callback should:
  - call `send_refresh_jwt_keys_error()` on `curl_response != CURLE_OK`
  - otherwise pass status code and response body to `handle_jwt_metadata_response(...)`

Expected signature change:

```cpp
void handle_jwt_metadata_response(
  const std::string& issuer,
  std::string ca_cert_bundle_pem,
  ccf::http_status status,
  std::vector<uint8_t>&& data);
```

Verification:

- Metadata happy path still reaches JWKS fetch.
- Invalid metadata still increments failure metrics.
- Metadata connection failure increments failure metrics.

### 5. Migrate JWKS fetch

In `handle_jwt_metadata_response(...)`:

- Preserve HTTP status handling, metadata parsing, `jwks_uri` parsing, and issuer constraint extraction.
- Replace the old client with a curl GET request using the same CA bundle material.
- Callback should:
  - call `send_refresh_jwt_keys_error()` on `curl_response != CURLE_OK`
  - otherwise pass status code and body to `handle_jwt_jwks_response(...)`

Verification:

- Existing JWT auto-refresh happy path passes.
- Invalid JWKS response increments failure metrics.
- HTTP non-200 response still triggers existing error handling.

### 6. Clean up dependencies

Once both external fetches use curl:

- Remove the `rpcsessions` member from `JwtKeyAutoRefresh` if unused.
- Remove the constructor parameter if unused.
- Update all construction sites.
- Remove stale includes and comments about connection errors not being tracked.

Verification:

- Full build catches all construction-site updates.
- No `rpcsessions->create_client` usage remains in `jwt_key_auto_refresh.h`.

### 7. Tests

Add or update focused tests around:

- successful JWT key auto-refresh
- initial one-off refresh after adding an issuer
- invalid OpenID metadata
- invalid JWKS
- unavailable issuer endpoint / connection failure
- TLS trust failure with an incorrect CA bundle

Existing tests to keep passing include:

- `test_jwt_key_auto_refresh`
- `test_jwt_key_initial_refresh`
- `test_jwt_key_auto_refresh_entries`

### 8. Validation order

1. Build affected C++ targets.
2. Run curl tests introduced by microsoft/CCF#7102 where available.
3. Run JWT auto-refresh tests.
4. Run broader JWT test file.
5. Check shutdown for libuv handle leaks or async lifetime issues.

## Risks and things to watch

- Async callback captures must own all data they use.
- CA bundle material must outlive async curl requests.
- Hostname/SNI verification should use the actual target host, especially for `jwks_uri`.
- Response bodies should be bounded rather than using `SIZE_MAX` where possible.
- Curl connection failures will now be counted as refresh failures; this is an intentional observability improvement but should be noted in the PR.
- The internal `/node/jwt_keys/refresh` update path should remain unchanged.

## Definition of done

- `src/node/jwt_key_auto_refresh.h` no longer uses `rpcsessions->create_client(...)` for OpenID/JWKS external fetches.
- Metadata and JWKS requests use `ccf::curl::CurlRequest` and `CurlmLibuvContextSingleton`.
- Existing JWT auto-refresh behaviour remains intact.
- New failure-mode tests cover connection and TLS failures.
- The PR description explains the relationship to microsoft/CCF#7102 and calls out the metrics-observability improvement.
