# Release notes 2.0

TODO:


See [documentation for code upgrade 1.x to 2.0](https://microsoft.github.io/CCF/main/operations/code_upgrade_1x.html) to upgrade an existing 1.x CCF service to 2.0

---

## Developer API

### C++

- CCF is now built with Clang 10. It is strongly recommended that C++ applications upgrade to Clang 10 as well.
- Raised the minimum supported CMake version for building CCF to 3.16 (#2946).
- Removed `mbedtls` as cryptography and TLS library.

- Added `get_untrusted_host_time_v1` API. This can be used to retrieve a timestamp during endpoint execution, accurate to within a few milliseconds. Note that this timestamp comes directly from the host so is not trusted, and should not be used to make sensitive decisions within a transaction (#2550).
- Added `get_quotes_for_all_trusted_nodes_v1` API. This returns the ID and quote for all nodes which are currently trusted and participating in the service, for live audit (#2511).
- Added `get_metrics_v1` API to `BaseEndpointRegistry` for applications that do not make use of builtins and want to version or customise metrics output.
- Added `set_claims_digest()` API to `RpcContext`, see [documentation](https://microsoft.github.io/CCF/main/build_apps/logging_cpp.html#user-defined-claims-in-receipts) on how to use it to attach application-defined claims to transaction receipts.
- Added [indexing system](https://microsoft.github.io/CCF/main/architecture/indexing.html) to speed up historical queries (#3280, #3444).

- `ccf::historical::adapter_v2` now returns 404, with either `TransactionPendingOrUnknown` or `TransactionInvalid`, rather than 400 when a user performs a historical query for a transaction id that is not committed.
- `ccf::historical::AbstractStateCache::drop_requests()` renamed to `drop_cached_states()` (#3187).
- `get_state_at()` now returns receipts for signature transactions (#2785), see [documentation](https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#transaction-receipts) for details.

Key-Value Store:

- Added `kv::Value` and `kv::Set`, as a more error-proof alternative to `kv::Map`s which had a single key or meaningless values (#2599).
- Added `foreach_key` and `foreach_value` to C++ KV API, to iterate without deserializing both entries when only one is used (#2918).

### JavaScript

- Added JavaScript bytecode caching to avoid repeated compilation overhead. See the [documentation](https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html#deployment) for more information (#2643).
- Added `ccf.crypto.verifySignature()` for verifying digital signatures to the JavaScript API (#2661).
- Added experimental JavaScript API `ccf.host.triggerSubprocess()` (#2461).

- `ccf.crypto.verifySignature()` previously required DER-encoded ECDSA signatures and now requires IEEE P1363 encoded signatures, aligning with the behavior of the Web Crypto API (#2735).
- `ccf.historical.getStateRange` / `ccf.historical.dropCachedStates` JavaScript APIs to manually retrieve historical state in endpoints declared as `"mode": "readonly"` (#3033).
- JavaScript endpoints with `"mode": "historical"` now expose the historical KV at `ccf.historicalState.kv` while `ccf.kv` always refers to the current KV state. Applications relying on the old behaviour should make their code forward-compatible before upgrading to 2.x with `const kv = ccf.historicalState.kv || ccf.kv`.
- Receipts accessible through JavaScript no longer contain the redundant `root` hash field. Applications should be changed to not rely on this field anymore before upgrading to 2.x.

---

## Governance

- Updated `actions.js` constitution fragment to record service-endorsed node certificate on the `transition_node_to_trusted` action. The constitution must be updated using the existing `set_constitution` proposal (#2844).
- The existing `transition_node_to_trusted` proposal action now requires a new `valid_from` argument (and optional `validity_period_days`, which defaults to the value of `maximum_node_certificate_validity_days`).
- The `proposal_generator` has been removed from the `ccf` Python package. The majority of proposals can be trivially constructed in existing client tooling, without needing to invoke Python. This also introduces parity between the default constitution and custom constitution actions - all should be constructed and called from the same governance client code. Some jinja templates are included in `samples/templates` for constructing careful ballots from existing proposals.

---

## Operations

### `cchost` Configuration

- **Breaking change**: Configuration for CCF node is now a JSON configuration file passed in to `cchost` via `--config /path/to/config/file/` CLI argument. Existing CLI arguments have been removed. The `migrate_1_x_config.py` script (included in `ccf` Python package) should be used to migrate existing `.ini` configuration files to `.json` format (#3209).
- Added support for listening on multiple interfaces for incoming client RPCs, with individual session caps (#2628).
- The per-node session cap behaviour has changed. The `network.rpc_interfaces.<interface_name>.max_open_sessions_soft` is now a soft cap on the number of sessions. Beyond this, new sessions will receive a HTTP 503 error immediately after completing the TLS handshake. The existing hard cap (where sessions are closed immediately, before the TLS handshake) is still available, under the new argument `network.rpc_interfaces.<interface_name>.max_open_sessions_hard` (#2583).
- Snapshot files now include receipt of evidence transaction. Nodes can now join or recover a service from a standalone snapshot file. 2.x nodes can still make use of snapshots created by a 1.x node, as long as the ledger suffix containing the proof of evidence is also specified at start-up (#2998).
- If no `node_certificate.subject_alt_names` is specified at node start-up, the node certificate _Subject Alternative Name_ extension now defaults to the value of `published_address` of the first RPC interface (#2902).

### Certificate(s) Validity Period

- Nodes certificates validity period is no longer hardcoded and must instead be set by operators and renewed by members (#2924):

  - The new `node_certificate.initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the node certificate (valid from the current system time).
  - The new `command.start.service_configuration.maximum_node_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for node certificates.
  - The new `set_node_certificate_validity` proposal action allows members to renew a node certificate (or `set_all_nodes_certificate_validity` equivalent action to renew _all_ trusted nodes certificates).

- Service certificate validity period is no longer hardcoded and must instead be set by operators and renewed by members (#3363):

  - The new `service_certificate_initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the service certificate (valid from the current system time).
  - The new `maximum_service_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for service certificate.
  - The new `set_service_certificate_validity` proposal action allows members to renew the service certificate.

### Misc

- The service certificate output by first node default name is now `service_cert.pem` rather than `networkcert.pem` (#3363).
- Log more detailed errors on early startup (#3116).
- Format of node output RPC and node-to-node addresses files is now JSON (#3300).
- Joining nodes now present service-endorsed certificate in client TLS sessions _after_ they have observed their own addition to the store, rather than as soon as they have joined the service. Operators should monitor the initial progress of a new node using its self-signed certificate as TLS session certificate authority (#2844).

- Slow ledger IO operations will now be logged at level FAIL. The threshold over which logging will activate can be adjusted by the `slow_io_logging_threshold` configuration entry to cchost (#3067).
- Added a new `client_connection_timeout` configuration entry to specify the maximum time a node should wait before re-establishing failed client connections. This should be set to a significantly lower value than `consensus.election_timeout` (#2618).
- Nodes code digests are now extracted and cached at network join time in `public:ccf.gov.nodes.info`, and the `GET /node/quotes` and `GET /node/quotes/self` endpoints will use this cached value whenever possible (#2651).
- DNS resolution of client connections is now asynchronous (#3140).
- The curve-id selected for the identity of joining nodes no longer needs to match that of the network (#2525).
- Removed long-deprecated `--domain` argument from `cchost`. Node certificate Subject Alternative Names should be passed in via existing `node_certificate.subject_alt_names` configuration entry (#2798).
- Added experimental support for 2-transaction reconfiguration with CFT consensus, see [documentation](https://microsoft.github.io/CCF/main/overview/consensus/bft.html#two-transaction-reconfiguration). Note that mixing 1tx and 2tx nodes in the same network is unsupported and unsafe at this stage (#3097).

### Fixed

- Fixed issue with ledger inconsistency when starting a new joiner node without a snapshot but with an existing ledger prefix (#3064).
- Fixed issue with join nodes which could get stuck if an election was triggered while catching up (#3169).

---

## Auditor

- Receipts now include the endorsed certificate of the node, as well as its node id, for convenience (#2991).
- Retired nodes are now removed from the store/ledger as soon as their retirement is committed (#3409).
- Service-endorsed node certificates are now recorded in a new `public:ccf.gov.nodes.endorsed_certificates` table, while the existing `cert` field in the `public:ccf.gov.nodes.info` table is now deprecated (#2844).
- New `split_ledger.py` utility to split existing ledger files (#3129).
- Python `ccf.read_ledger` module now accepts custom formatting rules for the key and value based on the key-value store table name (#2791).
- [Ledger entries](https://microsoft.github.io/CCF/main/architecture/ledger.html#transaction-format) now contain a `commit_evidence_digest`, as well as an optional `claims_digest` when `set_claims_digest()` is used. The digest of the write set was previously the per-transaction leaf in the Merkle Tree, but is now combined with the digest of the commit evidence and optionally the user claims when present. [Receipt verification instructions](https://microsoft.github.io/CCF/main/audit/receipts.html) have been amended accordingly. The presence of `commit_evidence` in receipts serves two purposes: giving the user access to the TxID without having to parse the write set, and proving that a transaction has been committed by the service. Transactions are flushed to disk eagerly by the primary to keep in-enclave memory use to a minimum, so the existence of a ledger suffix is not on its own indicative of its commit status. The digest of the commit evidence is in the ledger to allow audit and recovery, but only the disclosure of the commit evidence indicates that a transaction has been committed by the service

---

## Client API

- Added support for TLS 1.3 (now used by default).

- Added `GET /gov/jwt_keys/all` endpoint (#2519).
- Added new operator RPC `GET /node/js_metrics` returning the JavaScript bytecode size and whether the bytecode is used (#2643).
- Added a new `GET /node/metrics` endpoint which includes the count of active and peak concurrent sessions handled by the node (#2596).
- Added endpoint to obtain service configuration via `GET /node/service/configuration` (#3251).
- Added QuickJS version to RPC `GET /node/version` (#2643).
- Added a `GET /node/jwt_metrics` endpoint to monitor attempts and successes of key refresh for each issuer. See [documentation](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html#extracting-jwt-metrics) on how to use it.

- Schema of `GET /network/nodes/{node_id}` and `GET /network/nodes` endpoints has been modified to include all RPC interfaces (#3300).
- Improved performance for lookup of path-templated endpoints (#2918).
- CCF now responds to HTTP requests that could not be parsed with a 400 response including error details (#2652).

- Websockets endpoints are no longer supported. Usage is insufficient to justify ongoing maintenance.
- The `ccf` Python package no longer provides utilities to issue requests to a running CCF service. This is because CCF supports widely-used client-server protocols (TLS, HTTP) that should already be provided by libraries for all programming languages. The `ccf` Python package can still be used to audit the ledger and snapshot files (#3386).

---

## Dependencies

- Upgraded Open Enclave to 0.17.5.
