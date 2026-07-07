# Migrating the node join client from the legacy HTTP client to libcurl

Tracking issue: [#7262](https://github.com/microsoft/CCF/issues/7262) - "Migrate
httpclients over to libcurl". The node join sequence is the **last** remaining
user of `RPCSessions::create_client()` (the legacy in-enclave TLS HTTP client).
Migrating it lets us delete the remaining legacy HTTP client infrastructure.

Reference implementation: [#8005](https://github.com/microsoft/CCF/pull/8005),
which migrated JWT/JWK OpenID discovery and key refresh to the shared curl-multi
client. The endorsements client ([#7102]) and snapshot fetch already use the same
curl client, and the snapshot fetch runs inside the join flow, so there is a
directly comparable node-to-node precedent.

## Goals

- Replace the legacy HTTP client in `NodeState::initiate_join_unsafe()` with the
  async curl-multi client (`ccf::curl::CurlmLibuvContextSingleton`).
- Preserve the join trust model exactly: the **service certificate is the only
  trust anchor**, and the joining node presents its self-signed node certificate
  as a client certificate (mutual TLS).
- **Strengthen** TLS peer verification by enabling certificate hostname
  verification (`CURLOPT_SSL_VERIFYHOST=2`), which the legacy path did not do.
- Preserve every existing join control-flow branch (redirects, snapshot re-fetch
  on `StartupSeqnoIsOld`, pending/trusted handling, fatal errors).
- Remove the now-dead legacy HTTP client infrastructure.
- Lean on existing test coverage as validation gates, and plug the gaps that the
  behavioural change introduces.

## Non-goals

- No change to the `/node/join` server endpoint or the join wire protocol.
- No change to the in-process node client (`NodeClient` / `HTTPNodeClient`),
  which is a loopback handler dispatch, not a network/TLS client.
- No change to the server-side TLS/HTTP session stack (nodes still serve RPC).

## Current implementation (baseline)

`NodeState::initiate_join_unsafe()` in `src/node/node_state.h`:

```cpp
auto network_ca = std::make_shared<::tls::CA>(std::string(
  config.join.service_cert.begin(), config.join.service_cert.end()));

auto join_client_cert = std::make_unique<::tls::Cert>(
  network_ca,
  self_signed_node_cert,
  node_sign_kp->private_key_pem(),
  target_host);

auto join_client = rpcsessions->create_client(
  std::move(join_client_cert),
  rpcsessions->get_app_protocol_main_interface());

join_client->connect(target_host, target_port, /* response cb */, /* error cb */);
join_client->send_request(POST /node/join with JSON body);
```

Relevant properties of the baseline:

- **Trust anchor**: `config.join.service_cert` only. `::tls::CA` builds an
  `X509_STORE` containing exactly that certificate; the system CA bundle is never
  consulted. `partial_ok` is `false` (full chain to the service cert required).
- **Peer verification**: `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` with
  standard OpenSSL chain validation.
- **Hostname verification**: **none**. `::tls::Cert` uses `peer_hostname` only for
  SNI (`SSL_set_tlsext_host_name`); there is no `X509_VERIFY_PARAM_set1_host`
  call, so the target's certificate name is not checked.
- **Client authentication**: the node presents `self_signed_node_cert` +
  `node_sign_kp` private key (at join time the node is not yet endorsed, so
  `endorsed_node_cert` is `std::nullopt`).
- **Concurrency**: asynchronous. `connect()` returns immediately; the response
  callback runs later and processes the result under `NodeState::lock` guarded by
  `sm.check(NodeStartupState::pending)`. The lock is **not** held during network
  I/O.
- **Retry**: `join_periodic_task` re-invokes `initiate_join_unsafe()` on a timer.

### Join response-handling branches to preserve

1. Transport/handshake failure -> fatal: write `AdminMessage::fatal_error_msg`,
   node shuts down gracefully (not retried).
2. 4xx with `ODataError` code `StartupSeqnoIsOld` and `fetch_recent_snapshot` ->
   schedule a `FetchSnapshot` task, return, and let the periodic timer retry.
3. Other 4xx -> fatal shutdown.
4. `307`/`308` with `follow_redirect` and a `Location` header -> update
   `config.join.target_rpc_address` and let the periodic timer retry.
5. Other non-200 -> log failure, wait for retry.
6. `200 OK`, `node_status == TRUSTED` -> initialise identity / ledger secrets /
   consensus, become part of (public) network, cancel the join timer.
7. `200 OK`, `node_status == PENDING` -> wait for member votes (retry).

## Target implementation

Model on `JwtKeyAutoRefresh::send_curl_get()` (`src/node/jwt_key_auto_refresh.h`)
for the TLS options and async dispatch, and on `recovery_decision_protocol.cpp`
for the client-certificate (mTLS) options.

curl easy-handle options for the join request:

| Option | Value | Rationale |
| --- | --- | --- |
| `CURLOPT_CAINFO_BLOB` | `config.join.service_cert` | Trust anchor = service cert only (matches baseline). |
| `CURLOPT_CAPATH` | `nullptr` | Do **not** fall back to the system CA bundle. Critical: keeps the accepted-CA set identical to the baseline. |
| `CURLOPT_SSL_VERIFYPEER` | `1L` | Verify the peer chain (matches baseline). |
| `CURLOPT_SSL_VERIFYHOST` | `2L` | Verify the peer certificate name (hardening; see below). |
| `CURLOPT_PROTOCOLS_STR` | `"https"` | Restrict to HTTPS (matches JWT refresh). |
| `CURLOPT_SSLCERT_BLOB` | self-signed node cert | Client cert for mTLS (matches baseline). |
| `CURLOPT_SSLCERTTYPE` | `"PEM"` | |
| `CURLOPT_SSLKEY_BLOB` | node signing key | Client key for mTLS (matches baseline). |
| `CURLOPT_SSLKEYTYPE` | `"PEM"` | |
| `CURLOPT_CONNECTTIMEOUT` / `CURLOPT_TIMEOUT` | small fixed values | Bound transport time (matches JWT refresh). |

- **Method/body**: POST `https://{target_rpc_address}/node/join` with the JSON
  `JoinNetworkNodeToNode::In` body and `Content-Type: application/json`.
- **Response body cap**: a fixed, generous `ccf::curl::ResponseBody` maximum
  (large enough for any realistic join response - identity, ledger secrets - but
  far below a snapshot). No new operator-facing config option.
- **Redirects**: do **not** set `CURLOPT_FOLLOWLOCATION`. Handle redirects
  manually exactly as today (inspect status + `Location`, update
  `target_rpc_address`), so the trust anchor is re-applied to the new target and
  the snapshot fetch picks up the redirected address.
- **Dispatch**: build the request under `lock`, then
  `CurlmLibuvContextSingleton::get_instance()->attach_request(...)` and return.
  The single `ResponseCallback` re-acquires `lock`, re-checks
  `sm.check(pending)`, and maps `CURLcode` + HTTP status to the seven branches
  above. Transport/TLS failures (`CURLcode != CURLE_OK`, e.g.
  `CURLE_PEER_FAILED_VERIFICATION`, `CURLE_SSL_CACERT`) map to the current fatal
  path and **must log a single stable, greppable message** so the test suite can
  detect a rejected service certificate.

### POST-with-body support in the curl wrapper (prerequisite)

`ccf::curl::CurlRequest` currently wires GET, HEAD and PUT (upload) fully, but the
`HTTP_POST` branch assumes the caller pre-set `CURLOPT_POSTFIELDS` and does not
enable `CURLOPT_POST`. Add first-class POST-with-body support (set `CURLOPT_POST`
and `CURLOPT_POSTFIELDSIZE`, feeding the existing `RequestBody` read callback, or
an equivalent `COPYPOSTFIELDS` helper) so the join can send a JSON body cleanly,
and cover it in `src/http/test/curl_test.cpp`.

## Security analysis: which root CAs are accepted

| Property | Baseline (legacy client) | Migrated (curl) | Verdict |
| --- | --- | --- | --- |
| Accepted trust anchors | service cert only (`::tls::CA` store) | `CAINFO_BLOB` = service cert, `CAPATH` = `nullptr` | Identical |
| System CA fallback | never | disabled via `CAPATH=nullptr` | Identical |
| Chain building | full chain, `partial_ok=false` | curl default (no partial chain) | Identical (service identity is a self-signed root; snapshot fetch already proves this against the same peer) |
| Peer chain verification | `SSL_VERIFY_PEER` | `SSL_VERIFYPEER=1` | Identical |
| Certificate name check | none (SNI only) | `SSL_VERIFYHOST=2` | **Strengthened** |
| Client auth (mTLS) | self-signed node cert | `SSLCERT_BLOB` self-signed node cert | Identical |

**Hostname verification hardening.** Enabling `VERIFYHOST=2` means a join fails if
the host in `join.target_rpc_address` is not present in the target node's
certificate SANs. CCF derives node-cert SANs from
`config.node_certificate.subject_alt_names`, or, by default, from each RPC
interface's `published_address` (`get_subject_alternative_names()`), with IPs
emitted as `iPAddress` SANs and names as `dNSName`. Redirect targets are built
from those same published addresses. The snapshot fetch inside the join flow
already uses curl with the default `VERIFYHOST=2` against the *same*
`target_rpc_address` and *same* `service_cert`, so standard deployments and the
test suite already satisfy this constraint. The residual risk is a deployment that
connects to an address deliberately absent from the target SANs; this is a
behavioural change and must be documented in `CHANGELOG.md`.

## Test strategy and validation gates

### Existing coverage to lean on

- **Security gate**: `tests/reconfiguration.py::test_add_node_invalid_service_cert`
  joins with the wrong service certificate and expects
  `infra.network.ServiceCertificateInvalid`. That exception is raised in
  `tests/infra/network.py::run_join_node()` by matching the log string
  `"invalid cert on handshake"` (emitted by `src/enclave/tls_session.h`). The curl
  path emits a **different** message, so this detection string must be updated to
  match the new stable TLS-failure log. This is the primary gap.
- **Happy paths**: `test_add_node`, `test_add_node_from_snapshot`,
  `test_add_node_from_backup`, `test_add_as_many_pending_nodes`.
- **Redirects**: `test_join_straddling_primary_replacement`, and
  `start_network.py --redirection_kind node-by-role`.
- **Fake/duplicate joins**: `test_issue_fake_join`, `node_frontend_test.cpp`.
- **Attestation error mapping**: `code_update.py` SNP join tests exercise the
  `MeasurementNotFound` / `HostDataNotFound` / `UVMEndorsementsNotAuthorised`
  detection in `run_join_node()`; these must still work with curl error handling.
- **Recovery / public-network join**: `recovery.py`.
- **curl mechanics**: `src/http/test/curl_test.cpp`.

### Gaps to plug

1. Update the `ServiceCertificateInvalid` detection in `tests/infra/network.py`
   to the new curl TLS-failure log line.
2. Add `curl_test.cpp` coverage for POST-with-body and mTLS client certificates.
3. Add/confirm coverage that `VERIFYHOST=2` succeeds for both DNS-name and IP
   published addresses, and after a redirect.
4. (Recommended) Add a negative test that a join to an address **not** in the
   target SANs is now rejected, to regression-protect the hardening.

## Removal scope (after the join no longer uses the legacy client)

Remove (confirmed to have no other users once the join and the dead
`make_http_request` are gone):

- `NodeState::make_http_request()` (`src/node/node_state.h`) and the
  `AbstractNodeState::make_http_request` declaration
  (`src/node/rpc/node_interface.h`). Already dead (no callers).
- `RPCSessions::create_client()` and `RPCSessions::create_unencrypted_client()`
  (`src/enclave/rpc_sessions.h`). The latter is already dead.
- `ClientSession` (`src/enclave/client_session.h`), `HTTPClientSession`
  (`src/http/http_session.h`), `HTTP2ClientSession` (`src/http/http2_session.h`),
  `UnencryptedHTTPClientSession` (`src/http/http_session.h`), plus their includes.

Keep:

- `NodeClient` / `HTTPNodeClient` (`src/node/node_client.h`,
  `src/node/http_node_client.h`): in-process handler dispatch
  (`RpcHandler::process`), not a network/TLS client. Used by
  `retired_nodes_cleanup.h` and `raft.h`.
- `::tls::Client` (`src/tls/client.h`): a TLS-layer primitive still exercised by
  the TLS unit test (`src/tls/test/main.cpp`); the server side still relies on the
  TLS layer. (Optional stretch: remove it too and trim the test.)
- All server-side TLS/HTTP session classes.

## Staged delivery (each stage is independently reviewable and gated)

- **Stage 0 - Branch + this plan.** Branch `join-client-curl-migration`.
- **Stage 1 - curl wrapper POST-with-body.** Extend `ccf::curl::CurlRequest` +
  `curl_test.cpp` coverage (POST body, mTLS). Gate: `curl_test`.
- **Stage 2 - curl-based join.** Rewrite the client half of
  `initiate_join_unsafe()`; remove the legacy `tls::CA`/`tls::Cert`/`create_client`
  join code. Preserve all seven branches. Gate: build + `node_frontend_test`.
- **Stage 3 - Test infra + e2e gates.** Update the `ServiceCertificateInvalid`
  detection string; run the join e2e gates; add the hostname-verification
  coverage. Gate: e2e join suite green.
- **Stage 4 - Remove dead httpclient infra.** Delete the removal set above; grep
  for zero references; build all targets and run affected unit tests. Gate: full
  build + unit tests.
- **Stage 5 - Docs, changelog, compatibility.** `CHANGELOG.md` (Changed: curl
  join migration + `VERIFYHOST` hardening migration note + infra removal), bump
  `python/pyproject.toml` if a new version is cut, review
  `doc/operations/start_network.rst` wording, run `ci-checks.sh` and formatting/
  linting, and run `lts_compatibility` with `LONG_TESTS=1` (join touches
  cross-version TLS and protocol paths).

[#7102]: https://github.com/microsoft/CCF/pull/7102
