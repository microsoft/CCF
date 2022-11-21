# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [4.0.0-dev1]

[4.0.0-dev1]: https://github.com/microsoft/CCF/releases/tag/ccf-4.0.0-dev1

### Added

- The [ccf Python package](https://pypi.org/project/ccf/) now includes a `ccf_cose_sign1` CLI tool, to faciliate the creation of [COSE Sign1](https://www.rfc-editor.org/rfc/rfc8152#page-18) requests for governance purposes.

### Fixed

- Session consistency is now provided even across elections. If session consistency would be broken, the inconsistent request will return an error and the TLS session will be terminated.

## [4.0.0-dev0]

[4.0.0-dev0]: https://github.com/microsoft/CCF/releases/tag/ccf-4.0.0-dev0

### Changed

- `enclave.type` configuration entry now only supports `Debug` or `Release`. Trusted Execution Environment platform should be specified via new `enclave.platform` configuration entry (`SGX`, `SNP` or `Virtual`) (#4569).

### Fixed

- Fix issue with large snapshots that may cause node crash on startup (join/recover) if configured stack size was too low (#4566).

## [3.0.0-rc2]

### Dependencies

- Upgraded OpenEnclave to 0.18.4.

### Added

- Added new `ccf.crypto.eddsaPemToJwk`, `ccf.crypto.pubEddsaPemToJwk` to JavaScript/TypesScript API to convert EdDSA keys from PEM to JWK (#4524).

### Changed

## [3.0.0-rc1]

[3.0.0-rc1]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-rc1

### Added

- `sandbox.sh` now accepts a `--consensus-update-timeout-ms` to modify the `consensus.message_timeout` value in each node's configuration. This can be used to alter multi-node commit latency.
- Add `ccf.crypto.sign()` API in the JavaScript runtime (#4454).

### Changed

- CCF is now a separate CMake project and Debian package per platform (sgx, snp and virtual), rather than the same project and package with a decorated version, to prevent accidental misuse and narrow down dependencies. (#4421).
  - C++ applications should find the appropriate CCF package in CMake with `find_package("ccf_<platform>" REQUIRED)`.
  - CCF Debian packages are now installed at `/opt/ccf_<platform>` rather than `/opt/ccf`.
- We now support QuickJS runtime caps such as `max_heap_bytes`, `max_stack_bytes` and `max_execution_time_ms`. These can be set via a governance proposal. They can also be fetched via the `GET /node/js_metrics` endpoint (#4396).

## [3.0.0-rc0]

### Developer API

### C++

- Removed deprecated `set_execute_outside_consensus()` API (#3886, #3673).
- Application code should now use the `CCF_APP_*` macros rather than `LOG_*_FMT` (eg - `CCF_APP_INFO` replacing `LOG_INFO_FMT`). The new macros will add an `[app]` tag to all lines so they can be easily filtered from framework code (#4024).
- The previous logging macros (`LOG_INFO_FMT`, `LOG_DEBUG_FMT` etc) have been deprecated, and should no longer be used by application code. Replace with the `CCF_APP_*` equivalent.
- Added a new method `get_decoded_request_path_param`s that returns a map of decoded path parameters (#4126).
- New `crypto::hmac` API (#4204).
- The `ccf::RpcContext` now contains functionality for storing user data with `set_user_data` and retrieving it with `get_user_data` (#4291).
- There are now `make_endpoint_with_local_commit_handler` and `make_read_only_endpoint_with_local_commit_handler` functions to install endpoints with post local-commit logic (#4296).
- `ccf::historical::adapter`, `ccf::historical::adapter_v1`, `ccf::historical::is_tx_committed` and `ccf::historical::is_tx_committed_v1` have been removed. Application code should upgrade to `ccf::historical::adapter_v3` and `ccf::historical::is_tx_committed_v2`.
- `ccf::EnclaveAttestationProvider` is deprecated and will be removed in a future release. It should be replaced by `ccf::AttestationProvider`.
- The functions `starts_with`, `ends_with`, `remove_prefix`, and `remove_suffix`, and the type `remove_cvref` have been removed from `nonstd::`. The C++20 equivalents should be used instead.

### JavaScript

- Add `ccf.generateEcdsaKeyPair` API in the JavaScript runtime (#4271).
- Add `secp256k1` support to `ccf.crypto.generateEcdsaKeyPair()` and `ccf.crypto.verifySignature()` (#4347).
- Add `ccf.crypto.generateEddsaKeyPair()` API with `Curve25519` support in the JavaScript runtime (#4391).
- Add new `ccf.crypto.pemToJwk`, `ccf.crypto.pubPemToJwk`, `ccf.crypto.rsaPemToJwk`, `ccf.crypto.pubRsaPemToJwk` to JavaScript/TypesScript API to convert EC/RSA keys from PEM to JWK (#4359).

---

### Governance

- `set_user` action in sample constitutions correctly handles user_data (#4229).
- Governance endpoints now support [COSE Sign1](https://www.rfc-editor.org/rfc/rfc8152#page-18) input, as well as signed HTTP requests (#4392).

---

### Operations

- The node-to-node interface configuration now supports a `published_address` to enable networks with nodes running in different (virtual) subnets (#3867).
- Primary node now automatically steps down as backup (in the same view) if it has not heard back from a majority of backup nodes for an election timeout (#3685).
- New nodes automatically shutdown if the target service certificate is misconfigured (#3895).
- New per-interface configuration entries (`network.rpc_interfaces.http_configuration`) are added to let operators cap the maximum size of body, header value size and number of headers in client HTTP requests. The client session is automatically closed if the HTTP request exceeds one of these limits (#3941).
- Added new `read_only_directory` snapshots directory node configuration so that committed snapshots can be shared between nodes (#3973).
- Fixed issue with recovery of large ledger entries (#3986).
- New `GET /node/network/removable_nodes` and `DELETE /node/network/nodes/{node_id}` exposed to allow operator to decide which nodes can be safely shut down after retirement, and clear their state from the Key-Value Store.
- Fixed issue where two primary nodes could be elected if an election occurred while a reconfiguration transaction was still pending (#4018).
- New `snpinfo.sh` script (#4196).
- New `"attestation"` section in node JSON configuration to specify remote endpoint required to retrieve the endorsement certificates for SEV-SNP attestation report (#4277, #4302).

#### Release artefacts

- `ccf_unsafe` is now a separate project and package, rather than the same project and package with a decorated version, to prevent accidental misuse.
- Release assets now include variants per TEE platform: `ccf_sgx_<version>_amd64.deb`, `ccf_snp_<version>_amd64.deb` and `ccf_virtual_<version>_amd64.deb`.
- Docker images now include variants per TEE platform, identified via image tag: `:<version>-sgx`, `:<version>-snp` and `:<version>-virtual`.

---

### Auditor

- Node and service PEM certificates no longer contain a trailing null byte (#3885).

---

### Client API

- Added a `GET /node/service/previous_identity` endpoint, which can be used during a recovery to look up the identity of the service before the catastrophic failure (#3880).
- `GET /node/version` now contains an `unsafe` flag reflecting the status of the build.
- Added new recovery_count field to `GET /node/network` endpoint to track the number of disaster recovery procedures undergone by the service (#3982).
- Added new `service_data_json_file` configuration entry to `cchost` to point to free-form JSON file to set arbitrary data to service (#3997).
- Added new `current_service_create_txid` field to `GET /node/network` endpoint to indicate `TxID` at which current service was created (#3996).
- Experimental support for HTTP/2 (#4010).
- Generated OpenAPI now describes whether each endpoint is forwarded (#3935).
- When running with `curve-id` set to `secp256r1`, we now correctly support temporary ECDH keys on curve `secp256r1` for TLS 1.2 clients.
- Application-defined endpoints are now accessible with both `/app` prefix and un-prefixed, e.g. `GET /app/log/private` and `GET /log/private` (#4147).

---

### Dependencies

- Updated PSW in images to 2.16.100.
- Upgraded Open Enclave to 0.18.1 (#4023).

---

### Documentation

- The "Node Output" page has been relabelled as "Troubleshooting" in the documentation and CLI commands for troubleshooting have been added to it.

## [3.0.0-dev7]

### Added

- Added new `ccf.crypto.pemToJwk`, `ccf.crypto.pubPemToJwk`, `ccf.crypto.rsaPemToJwk`, `ccf.crypto.pubRsaPemToJwk` to JavaScript/TypesScript API to convert EC/RSA keys from PEM to JWK (#4359).

### Changed

- JavaScript crypto API (e.g. `generateAesKey` and `wrapKey`) are now included as part of the `ccf.crypto` package (#4372).

## [3.0.0-dev6]

### Added

- Experimental `ccf::MemberCOSESign1AuthnPolicy` (#3875)
- Add secp256k1 support to `ccf.crypto.generateEcdsaKeyPair()` and `ccf.crypto.verifySignature()` (#4347).

### Deprecated

- `ccf::EnclaveAttestationProvider` is deprecated and will be removed in a future release. It should be replaced by `ccf::AttestationProvider`

## [3.0.0-dev5]

### Added

- Added a new proposal action `set_js_runtime_options` that accepts `max_heap_bytes` and `max_stack_bytes` for QuickJS runtime.
- Experimental support for AMD SEV-SNP nodes (#4106, #4235)
- New "attestation" section in node JSON configuration to specify remote endpoint required to retrieve the endorsement certificates for SEV-SNP attestation report (#4277, #4302).
- The `ccf::RpcContext` now contains functionality for storing user data with `set_user_data` and retrieving it with `get_user_data` (#4291).
- There are now `make_endpoint_with_local_commit_handler` and `make_read_only_endpoint_with_local_commit_handler` functions to install endpoints with post local-commit logic (#4296).

### Changed

- The endpoint `GET /node/js_metrics` now also returns the QuickJS runtime memory options.

### Fixed

- Also install `*.inc` files for third-party dependencies (#4266).
- Add `ccf.generateEcdsaKeyPair` API in the JavaScript runtime (#4271).

### Removed

- `ccf::historical::adapter`, `ccf::historical::adapter_v1`, `ccf::historical::is_tx_committed` and `ccf::historical::is_tx_committed_v1` have been removed. Application code should upgrade to `ccf::historical::adapter_v3` and `ccf::historical::is_tx_committed_v2`.

## [3.0.0-dev4]

### Fixed

- `set_user` action in sample constitutions correctly handles `user_data` (#4229).

### Removed

- Snapshots generated by 1.x services can no longer be used to join from or recover a new service, i.e. 1.x services should first upgrade to 2.x before upgrading to 3.x when making use of existing snapshots (#4255).

## [3.0.0-dev3]

### Added

- New `snpinfo.sh` script (#4196).
- New `crypto::hmac` API (#4204).

### Changed

- Application-defined endpoints are now accessible with both `/app` prefix and un-prefixed, e.g. `GET /app/log/private` and `GET /log/private` (#4147).
- The method `EndpointRegistry::get_metrics_for_endpoint(const EndpointDefinitionPtr&)` has been replaced with `EndpointRegistry::get_metrics_for_endpoint(const std::string& method, const std::string& verb)`.

## [3.0.0-dev2]

### Dependencies

- Upgraded OpenEnclave to 0.18.2 (#4132).

### Added

- New `GET /node/network/removable_nodes` and `DELETE /node/network/nodes/{node_id}` exposed to allow operator to decide which nodes can be safely shut down after retirement, and clear their state from the Key-Value Store.
- Added a new method `get_decoded_request_path_params` that returns a map of decoded path parameters (#4126)

### Changed

- Calling `remove(K)` on a KV handle no longer returns a bool indicating if the key was previously present. This can be simulated by calling `has(K)` beforehand. This avoids introducing a read-dependency with every call to `remove()`.

### Fixed

- Fixed issue where two primary nodes could be elected if an election occurred while a reconfiguration transaction was still pending (#4018).
- When running with `--curve-id secp256r1`, we now correctly support temporary ECDH keys on curve secp256r1 for TLS 1.2 clients.

### Deprecated

- The previous logging macros (`LOG_INFO_FMT`, `LOG_DEBUG_FMT` etc) have been deprecated, and should no longer be used by application code. Replace with the `CCF_APP_*` equivalent.

## [3.0.0-dev1]

### Added

- `/node/version` now contains an `unsafe` flag reflecting the status of the build.
- New per-interface configuration entries (`network.rpc_interfaces.http_configuration`) are added to let operators cap the maximum size of body, header value size and number of headers in client HTTP requests. The client session is automatically closed if the HTTP request exceeds one of these limits (#3941).
- Added new `recovery_count` field to `GET /node/network` endpoint to track the number of disaster recovery procedures undergone by the service (#3982).
- Added new `service_data_json_file` configuration entry to `cchost` to point to free-form JSON file to set arbitrary data to service (#3997).
- Added new `current_service_create_txid` field to `GET /node/network` endpoint to indicate `TxID` at which current service was created (#3996).
- Added new `read_only_directory` snapshots directory node configuration so that committed snapshots can be shared between nodes (#3973).
- Experimental support for HTTP/2 (#4010).

### Changed

- Generated OpenAPI now describes whether each endpoint is forwarded (#3935).
- Application code should now use the `CCF_APP_*` macros rather than `LOG_*_FMT` (eg - `CCF_APP_INFO` replacing `LOG_INFO_FMT`). The new macros will add an `[app]` tag to all lines so they can be easily filtered from framework code (#4024).

### Fixed

- Fixed issue with recovery of large ledger entries (#3986).

### Documentation

- The "Node Output" page has been relabelled as "Troubleshooting" in the documentation and CLI commands for troubleshooting have been added to it.

### Dependencies

- Upgraded Open Enclave to 0.18.1 (#4023).

## [3.0.0-dev0]

### Added

- The node-to-node interface configuration now supports a `published_address` to enable networks with nodes running in different (virtual) subnets (#3867).
- Added a `GET /node/service/previous_identity` endpoint, which can be used during a recovery to look up the identity of the service before the catastrophic failure (#3880).
- Added an automatic certificate management environment (ACME) client to automatically manage TLS certificates that are globally endorsed by an external authority, e.g. Let's Encrypt (#3877).

### Changed

- Primary node now automatically steps down as backup (in the same view) if it has not heard back from a majority of backup nodes for an election timeout (#3685).
- Node and service PEM certificates no longer contain a trailing null byte (#3885).
- New nodes automatically shutdown if the target service certificate is misconfigured (#3895).
- Updated PSW in images to 2.16.100.
- `ccf_unsafe` is now a separate project and package, rather than the same project and package with a decorated version, to prevent accidental misuse.

### Removed

- Removed deprecated `set_execute_outside_consensus()` API (#3886, #3673).

## [2.0.0]

See [documentation for code upgrade 1.x to 2.0](https://microsoft.github.io/CCF/main/operations/code_upgrade_1x.html) to upgrade an existing 1.x CCF service to 2.0

### Developer API

#### C++

- CCF is now built with Clang 10. It is strongly recommended that C++ applications upgrade to Clang 10 as well.
- Raised the minimum supported CMake version for building CCF to 3.16 (#2946).
- Removed `mbedtls` as cryptography and TLS library.

- The CCF public API is now under `include/ccf`, and all application includes of framework code should use only these files.
- Private headers have been moved to `ccf/include/ccf/_private` so they cannot be accidentally included from existing paths. Any applications relying on private headers should remove this dependency, or raise an issue to request the dependency be moved to the public API. In a future release private headers will be removed entirely from the installed package.

- The `enclave::` namespace has been removed, and all types which were under it are now under `ccf::`. This will affect any apps using `enclave::RpcContext`, which should be replaced with `ccf::RpcContext` (#3664).
- The `kv::Store` type is no longer visible to application code, and is replaced by a simpler `kv::ReadOnlyStore`. This is the interface given to historical queries to access historical state and enforces read-only access, without exposing internal implementation details of the store. This should have no impact on JS apps, but C++ apps will need to replace calls to `store->current_txid()` with calls to `store->get_txid()`, and `store->create_tx()` to `store->create_read_only_tx()`.
- The C++ types used to define public governance tables are now exposed in public headers. Any C++ applications reading these tables should update their include paths (ie - `#include "service/tables/nodes.h"` => `#include "ccf/service/tables/nodes.h"`) (#3608).
- `TxReceipt::describe()` has been replaced with `ccf::describe_receipt_v2()`. Note that the previous JSON format is still available, but must be retrieved as a JSON object from `describe_receipt_v1()`. Includes of the private `node/tx_receipt.h` from C++ applications should be removed (#3610).
- The entry point for creation of C++ apps is now `make_user_endpoints()`. The old entry point `get_rpc_handler()` has been removed (#3562). For an example of the necessary change, see [this diff](https://github.com/microsoft/CCF/commit/5b40ba7b42d5664d787cc7e3cfc9cbe18c01e5a1#diff-78fa25442e77145040265646434b9582d491928819e58be03c5693c01417c6c6) of the logging sample app (#3562).

- Added `get_untrusted_host_time_v1` API. This can be used to retrieve a timestamp during endpoint execution, accurate to within a few milliseconds. Note that this timestamp comes directly from the host so is not trusted, and should not be used to make sensitive decisions within a transaction (#2550).
- Added `get_quotes_for_all_trusted_nodes_v1` API. This returns the ID and quote for all nodes which are currently trusted and participating in the service, for live audit (#2511).
- Added `get_metrics_v1` API to `BaseEndpointRegistry` for applications that do not make use of builtins and want to version or customise metrics output.
- Added `set_claims_digest()` API to `RpcContext`, see [documentation](https://microsoft.github.io/CCF/main/build_apps/logging_cpp.html#user-defined-claims-in-receipts) on how to use it to attach application-defined claims to transaction receipts.
- Added [indexing system](https://microsoft.github.io/CCF/main/architecture/indexing.html) to speed up historical queries (#3280, #3444).
- Removed `get_node_state()` from `AbstractNodeContext`. The local node's ID is still available to endpoints as `get_node_id()`, and other subsystems which are app-visible can be fetched directly (#3552).

- Receipts now come with service endorsements of previous service identities after recoveries (#3679). See `verify_receipt` in `e2e_logging.py` for an example of how to verify the resulting certificate chain. This functionality is introduced in `ccf::historical::adapter_v3`.
- `ccf::historical::adapter_v2`, and its successor `ccf::historical::adapter_v3` now return 404, with either `TransactionPendingOrUnknown` or `TransactionInvalid`, rather than 400 when a user performs a historical query for a transaction id that is not committed.
- `ccf::historical::AbstractStateCache::drop_requests()` renamed to `drop_cached_states()` (#3187).

Key-Value Store

- Added `kv::Value` and `kv::Set`, as a more error-proof alternative to `kv::Map`s which had a single key or meaningless values (#2599).
- Added `foreach_key` and `foreach_value` to C++ KV API, to iterate without deserializing both entries when only one is used (#2918).

#### JavaScript

- Added JavaScript bytecode caching to avoid repeated compilation overhead. See the [documentation](https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html#deployment) for more information (#2643).
- Added `ccf.crypto.verifySignature()` for verifying digital signatures to the JavaScript API (#2661).
- Added experimental JavaScript API `ccf.host.triggerSubprocess()` (#2461).

- `ccf.crypto.verifySignature()` previously required DER-encoded ECDSA signatures and now requires IEEE P1363 encoded signatures, aligning with the behavior of the Web Crypto API (#2735).
- `ccf.historical.getStateRange` / `ccf.historical.dropCachedStates` JavaScript APIs to manually retrieve historical state in endpoints declared as `"mode": "readonly"` (#3033).
- JavaScript endpoints with `"mode": "historical"` now expose the historical KV at `ccf.historicalState.kv` while `ccf.kv` always refers to the current KV state. Applications relying on the old behaviour should make their code forward-compatible before upgrading to 2.x with `const kv = ccf.historicalState.kv || ccf.kv`.
- Receipts accessible through JavaScript no longer contain the redundant `root` hash field. Applications should be changed to not rely on this field anymore before upgrading to 2.x.
- Add request details with additional URL components to JS + TS API: `request.url`, `request.route`, `request.method`, `request.hostname` (#3498).

---

### Governance

- Updated `actions.js` constitution fragment to record service-endorsed node certificate on the `transition_node_to_trusted` action. The constitution must be updated using the existing `set_constitution` proposal (#2844).
- The existing `transition_node_to_trusted` proposal action now requires a new `valid_from` argument (and optional `validity_period_days`, which defaults to the value of `maximum_node_certificate_validity_days`).
- The `proposal_generator` has been removed from the `ccf` Python package. The majority of proposals can be trivially constructed in existing client tooling, without needing to invoke Python. This also introduces parity between the default constitution and custom constitution actions - all should be constructed and called from the same governance client code. Some jinja templates are included in `samples/templates` for constructing careful ballots from existing proposals.
- A new governance action `trigger_ledger_chunk` to request the creation of a ledger chunk at the next signature (#3519).
- A new governance action `trigger_snapshot` to request the creation of a snapshot at the next signature (#3544).
- Configurations and proposals now accept more date/time formats, including the Python-default ISO 8601 format (#3739).
- The `transition_service_to_open` governance proposal now requires the service identity as an argument to ensure the correct service is started. During recovery, it further requires the previous service identity to ensure the right service is recovered (#3624).

---

### Operations

#### `cchost` Configuration

- **Breaking change**: Configuration for CCF node is now a JSON configuration file passed in to `cchost` via `--config /path/to/config/file/` CLI argument. Existing CLI arguments have been removed. The `migrate_1_x_config.py` script (included in `ccf` Python package) should be used to migrate existing `.ini` configuration files to `.json` format (#3209).
- Added support for listening on multiple interfaces for incoming client RPCs, with individual session caps (#2628).
- The per-node session cap behaviour has changed. The `network.rpc_interfaces.<interface_name>.max_open_sessions_soft` is now a soft cap on the number of sessions. Beyond this, new sessions will receive a HTTP 503 error immediately after completing the TLS handshake. The existing hard cap (where sessions are closed immediately, before the TLS handshake) is still available, under the new argument `network.rpc_interfaces.<interface_name>.max_open_sessions_hard` (#2583).
- Snapshot files now include receipt of evidence transaction. Nodes can now join or recover a service from a standalone snapshot file. 2.x nodes can still make use of snapshots created by a 1.x node, as long as the ledger suffix containing the proof of evidence is also specified at start-up (#2998).
- If no `node_certificate.subject_alt_names` is specified at node start-up, the node certificate _Subject Alternative Name_ extension now defaults to the value of `published_address` of the first RPC interface (#2902).
- Primary node now also reports time at which the ack from each backup node was last received (`GET /node/consensus` endpoint). This can be used by operators to detect one-way partitions between the primary and backup nodes (#3769).
- Added new `GET /node/self_signed_certificate` endpoint to retrieve the self-signed certificate of the target node (#3767).
- New `GET /gov/members` endpoint which returns details of all members from the KV (#3615).
- The new `endorsement` configuration entry lets operators set the desired TLS certificate endorsement, either service-endorsed or node-endorsed (self-signed), for each network RPC interface of a node, defaulting to service-endorsed (#2875).

#### Certificate(s) Validity Period

- Nodes certificates validity period is no longer hardcoded and must instead be set by operators and renewed by members (#2924):

  - The new `node_certificate.initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the node certificate (valid from the current system time).
  - The new `command.start.service_configuration.maximum_node_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for node certificates.
  - The new `set_node_certificate_validity` proposal action allows members to renew a node certificate (or `set_all_nodes_certificate_validity` equivalent action to renew _all_ trusted nodes certificates).

- Service certificate validity period is no longer hardcoded and must instead be set by operators and renewed by members (#3363):

  - The new `service_certificate_initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the service certificate (valid from the current system time).
  - The new `maximum_service_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for service certificate.
  - The new `set_service_certificate_validity` proposal action allows members to renew the service certificate.

#### Misc

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
- Aside from regular release packages, CCF now also provides `unsafe` packages with verbose logging, helpful for troubleshooting. The extent of the logging in these builds make them fundamentally UNSAFE to use for production purposes, hence the name.
- Nodes no longer crash at start-up if the ledger in the read-only ledger directories (`ledger.read_only_directories`) is ahead of the ledger in the main ledger directory (`ledger.directory`) (#3597).
- Nodes now have a free-form `node_data` field, to match users and members. This can be set when the node is launched, or modified by governance. It is intended to store correlation IDs describing the node's deployment, such as a VM name or Pod identifier (#3662).
- New `GET /node/consensus` endpoint now also returns primary node ID and current view (#3666).
- HTTP parsing errors are now recorded per-interface and returned by `GET /node/metrics` (#3671).
- Failed recovery procedures no longer block subsequent recoveries: `.recovery` ledger files are now created while the recovery is in progress and ignored or deleted by nodes on startup (#3563).
- Corrupted or incomplete ledger files are now recovered gracefully, until the last valid entry (#3585).

#### Fixed

- Fixed issue with ledger inconsistency when starting a new joiner node without a snapshot but with an existing ledger prefix (#3064).
- Fixed issue with join nodes which could get stuck if an election was triggered while catching up (#3169).
- Nodes joining must have a snapshot at least as recent as the primary's (#3573).

### Release artefacts

- `cchost` can now run both SGX and virtual enclave libraries. `cchost.virtual` is no longer needed, and has been removed (#3476).
- CCF Docker images are now available through Azure Container Registry rather than Docker Hub (#3839, #3821).
  - The `ccfmsrc.azurecr.io/ccf-sgx-app-run` image is now available at `ccfmsrc.azurecr.io/public/ccf/app/run:<tag>-sgx`.
  - The `ccfmsrc.azurecr.io/ccf-sgx-app-dev` image is now available at `ccfmsrc.azurecr.io/public/ccf/app/dev:<tag>-sgx`.
  - New `ccfmsrc.azurecr.io/public/ccf/app/run-js` JavaScript application runtime image (including `libjs_generic` application under `/usr/lib/ccf`) (#3845).

---

### Auditor

- Receipts now include the endorsed certificate of the node, as well as its node id, for convenience (#2991).
- Retired nodes are now removed from the store/ledger as soon as their retirement is committed (#3409).
- Service-endorsed node certificates are now recorded in a new `public:ccf.gov.nodes.endorsed_certificates` table, while the existing `cert` field in the `public:ccf.gov.nodes.info` table is now deprecated (#2844).
- New `split_ledger.py` utility to split existing ledger files (#3129).
- Python `ccf.read_ledger` module now accepts custom formatting rules for the key and value based on the key-value store table name (#2791).
- [Ledger entries](https://microsoft.github.io/CCF/main/architecture/ledger.html#transaction-format) now contain a `commit_evidence_digest`, as well as a `claims_digest`, which can be set with `set_claims_digest()`. The digest of the write set was previously the per-transaction leaf in the Merkle Tree, but is now combined with the digest of the commit evidence and the user claims. [Receipt verification instructions](https://microsoft.github.io/CCF/main/audit/receipts.html) have been amended accordingly. The presence of `commit_evidence` in receipts serves two purposes: giving the user access to the TxID without having to parse the write set, and proving that a transaction has been committed by the service. Transactions are flushed to disk eagerly by the primary to keep in-enclave memory use to a minimum, so the existence of a ledger suffix is not on its own indicative of its commit status. The digest of the commit evidence is in the ledger to allow audit and recovery, but only the disclosure of the commit evidence indicates that a transaction has been committed by the service
- Add `--insecure-skip-verification` to `ledger_viz` utility, to allow visualisation of unverified ledger chunks (#3618).
- Add `--split-services` to `ledger_viz` utility, to easily find out at which TxID new services were created (#3621).
- Python `ccf.read_ledger` and `ccf.ledger_viz` tools now accept paths to individual ledger chunks, to avoid parsing the entire ledger.

---

### Client API

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
- Node RPC interfaces do not transition anymore from node-endorsed to service-endorsed TLS certificates but are fixed to a single configured type. While a given endorsement is not available yet (typically at start-up for service-endorsed certificates) the interface rejects TLS sessions instead of defaulting to a node-endorsed certificate (#2875).

- Websockets endpoints are no longer supported. Usage is insufficient to justify ongoing maintenance.
- The `ccf` Python package no longer provides utilities to issue requests to a running CCF service. This is because CCF supports widely-used client-server protocols (TLS, HTTP) that should already be provided by libraries for all programming languages. The `ccf` Python package can still be used to audit the ledger and snapshot files (#3386).

---

### Dependencies

- Upgraded Open Enclave to 0.17.7 (#3815).

---

### Misc Fixes

- When using the `sandbox.sh` script, always wait for `/app` frontend to be open on all nodes before marking the service as open (#3779).
- Snapshot generation no longer causes a node crash if the snapshot is larger than the ring buffer message size (`memory.max_msg_size`). Instead, the generation of the large snapshot is skipped (#3603).

---

## [2.0.0-rc9]

### Fixed

- Fixed an issue where new node started without a snapshot would be able to join from a node that started with a snapshot (#3573).
- Fixed consensus issue where a node would grant its vote even though it already knew about the current primary (#3810).
- Fixed issue with JSON configuration for `cchost` where extra fields were silently ignored rather than being rejected at startup (#3816).

### Changed

- Upgraded Open Enclave to 0.17.7 (#3815).
- CCF Docker images are now available through Azure Container Registry rather than Docker Hub (#3821).
  - The `ccfciteam/ccf-app-run` image is now available at `ccfmsrc.azurecr.io/ccf-sgx-app-run`.
  - The `ccfciteam/ccf-app-ci` image is now available at `ccfmsrc.azurecr.io/ccf-sgx-app-dev`.
- Added support for ciphers 'ECDHE-RSA-AES256-GCM-SHA384' and 'ECDHE-RSA-AES128-GCM-SHA256' when using TLS 1.2 (#3822).

## [2.0.0-rc8]

### Fixed

- When using the `sandbox.sh` script, always wait for `/app` frontend to be open on all nodes before marking the service as open (#3779).

### Changed

- Every leaf in the Merkle Tree, and every receipt now includes a claims digest (#3606).

### Added

- Primary node now also reports time at which the ack from each backup node was last received (`GET /node/consensus` endpoint). This can be used by operators to detect one-way partitions between the primary and backup nodes (#3769).
- Current receipt format is now exposed to C++ applications as `ccf::Receipt`, retrieved from `describe_receipt_v2`. Note that the previous JSON format is still available, but must be retrieved as a JSON object from `describe_receipt_v1`.

## [2.0.0-rc7]

### Fixed

- Fixed issue with incorrect node and service certificate validity period when starting node in non-GMT timezone (#3732).
- Fixed issue with self-signed node certificates that are now renewed when the `set_node_certificate_validity` proposal is applied (#3767).

## Changed

- Configurations and proposals now accept more date/time formats, including the Python-default ISO 8601 format (#3739).

## Added

- Added new `GET /node/self_signed_certificate` endpoint to retrieve the self-signed certificate of the target node (#3767).

## [2.0.0-rc6]

### Changed

- `host_processes_interface.h` is now a public header, accessible under `ccf/node/host_processes_interface.h`.

## [2.0.0-rc5]

### Changed

- Nodes now have a free-form `node_data` field, to match users and members. This can be set when the node is launched, or modified by governance. It is intended to store correlation IDs describing the node's deployment, such as a VM name or Pod identifier (#3662).
- New `GET /node/consensus` endpoint now also returns primary node ID and current view (#3666).
- The `enclave::` namespace has been removed, and all types which were under it are now under `ccf::`. This will affect any apps using `enclave::RpcContext`, which should be replaced with `ccf::RpcContext` (#3664).
- HTTP parsing errors are now recorded per-interface and returned by `GET /node/metrics` (#3671).
- The `kv::Store` type is no longer visible to application code, and is replaced by a simpler `kv::ReadOnlyStore`. This is the interface given to historical queries to access historical state and enforces read-only access, without exposing internal implementation details of the store. This should have no impact on JS apps, but C++ apps will need to replace calls to `store->current_txid()` with calls to `store->get_txid()`, and `store->create_tx()` to `store->create_read_only_tx()`.
- Receipts now come with service endorsements of previous service identities after recoveries (#3679). See `verify_receipt` in `e2e_logging.py` for an example of how to verify the resulting certificate chain. This functionality is introduced in `ccf::historical::adapter_v3`.
- Private headers have been moved to `ccf/include/ccf/_private` so they cannot be accidentally included from existing paths. Any applications relying on private headers should remove this dependence, or raise an issue to request the dependency be moved to the public API. In a future release private headers will be removed entirely from the installed package.

## [2.0.0-rc4]

### Added

- Aside from regular release packages, CCF now also provides `unsafe` packages with verbose logging, helpful for troubleshooting. The extent of the logging in these builds make them fundamentally UNSAFE to use for production purposes, hence the name.

### Changed

- The `transition_service_to_open` governance proposal now requires the service identity as an argument to ensure the correct service is started. During recovery, it further requires the previous service identity to ensure the right service is recovered (#3624).

## [2.0.0-rc3]

### Fixed

- Snapshot generation no longer causes a node crash if the snapshot is larger than the ring buffer message size (`memory.max_msg_size`). Instead, the generation of the large snapshot is skipped (#3603).

### Changed

- The C++ types used to define public governance tables are now exposed in public headers. Any C++ applications reading these tables should update their include paths (ie - `#include "service/tables/nodes.h"` => `#include "ccf/service/tables/nodes.h"`) (#3608).
- `TxReceipt::describe()` has been replaced with `ccf::describe_receipt()`. Includes of the private `node/tx_receipt.h` from C++ applications should be removed (#3610).
- Python `ccf.read_ledger` and `ccf.ledger_viz` tools now accept paths to individual ledger chunks, to avoid parsing the entire ledger.

### Added

- New `GET /gov/members` endpoint which returns details of all members from the KV (#3615).
- Add `--insecure-skip-verification` to `ledger_viz` utility, to allow visualisation of unverified ledger chunks (#3618).
- Add `--split-services` to `ledger_viz` utility, to easily find out at which TxID new services were created (#3621).

## [2.0.0-rc2]

### Changed

- The entry point for creation of C++ apps is now `make_user_endpoints()`. The old entry point `get_rpc_handler()` has been removed (#3562). For an example of the necessary change, see [this diff](https://github.com/microsoft/CCF/commit/5b40ba7b42d5664d787cc7e3cfc9cbe18c01e5a1#diff-78fa25442e77145040265646434b9582d491928819e58be03c5693c01417c6c6) of the logging sample app (#3562).
- Failed recovery procedures no longer block subsequent recoveries: `.recovery` ledger files are now created while the recovery is in progress and ignored or deleted by nodes on startup (#3563).
- Corrupted or incomplete ledger files are now recovered gracefully, until the last valid entry (#3585).
- The CCF public API is now under `include/ccf`, and all application includes of framework code should use only these files.

### Removed

- `get_node_state()` is removed from `AbstractNodeContext`. The local node's ID is still available to endpoints as `get_node_id()`, and other subsystems which are app-visible can be fetched directly (#3552).

### Fixed

- Nodes no longer crash at start-up if the ledger in the read-only ledger directories (`ledger.read_only_directories`) is ahead of the ledger in the main ledger directory (`ledger.directory`) (#3597).

## [2.0.0-rc1]

### Added

- The new `endorsement` configuration entry lets operators set the desired TLS certificate endorsement, either service-endorsed or node-endorsed (self-signed), for each network RPC interface of a node, defaulting to service-endorsed (#2875).
- A new governance action `trigger_ledger_chunk` to request the creation of a ledger chunk at the next signature (#3519).
- A new governance action `trigger_snapshot` to request the creation of a snapshot at the next signature (#3544).

### Changed

- Node RPC interfaces do not transition anymore from node-endorsed to service-endorsed TLS certificates but are fixed to a single configured type. While a given endorsement is not available yet (typically at start-up for service-endorsed certificates) the interface rejects TLS sessions instead of defaulting to a node-endorsed certificate (#2875).
- Add request details with additional URL components to JS + TS API: `request.url`, `request.route`, `request.method`, `request.hostname` (#3498).
- `cchost` can now run both SGX and virtual enclave libraries. `cchost.virtual` is no longer needed, and has been removed (#3476).

### Dependencies

- Upgraded Open Enclave to 0.17.6.

## [2.0.0-rc0]

See [documentation for code upgrade 1.x to 2.0](https://microsoft.github.io/CCF/main/operations/code_upgrade_1x.html) to upgrade an existing 1.x CCF service to 2.0

---

### Developer API

#### C++

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

Key-Value Store

- Added `kv::Value` and `kv::Set`, as a more error-proof alternative to `kv::Map`s which had a single key or meaningless values (#2599).
- Added `foreach_key` and `foreach_value` to C++ KV API, to iterate without deserializing both entries when only one is used (#2918).

#### JavaScript

- Added JavaScript bytecode caching to avoid repeated compilation overhead. See the [documentation](https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html#deployment) for more information (#2643).
- Added `ccf.crypto.verifySignature()` for verifying digital signatures to the JavaScript API (#2661).
- Added experimental JavaScript API `ccf.host.triggerSubprocess()` (#2461).

- `ccf.crypto.verifySignature()` previously required DER-encoded ECDSA signatures and now requires IEEE P1363 encoded signatures, aligning with the behavior of the Web Crypto API (#2735).
- `ccf.historical.getStateRange` / `ccf.historical.dropCachedStates` JavaScript APIs to manually retrieve historical state in endpoints declared as `"mode": "readonly"` (#3033).
- JavaScript endpoints with `"mode": "historical"` now expose the historical KV at `ccf.historicalState.kv` while `ccf.kv` always refers to the current KV state. Applications relying on the old behaviour should make their code forward-compatible before upgrading to 2.x with `const kv = ccf.historicalState.kv || ccf.kv`.
- Receipts accessible through JavaScript no longer contain the redundant `root` hash field. Applications should be changed to not rely on this field anymore before upgrading to 2.x.

---

### Governance

- Updated `actions.js` constitution fragment to record service-endorsed node certificate on the `transition_node_to_trusted` action. The constitution must be updated using the existing `set_constitution` proposal (#2844).
- The existing `transition_node_to_trusted` proposal action now requires a new `valid_from` argument (and optional `validity_period_days`, which defaults to the value of `maximum_node_certificate_validity_days`).
- The `proposal_generator` has been removed from the `ccf` Python package. The majority of proposals can be trivially constructed in existing client tooling, without needing to invoke Python. This also introduces parity between the default constitution and custom constitution actions - all should be constructed and called from the same governance client code. Some jinja templates are included in `samples/templates` for constructing careful ballots from existing proposals.

---

### Operations

#### `cchost` Configuration

- **Breaking change**: Configuration for CCF node is now a JSON configuration file passed in to `cchost` via `--config /path/to/config/file/` CLI argument. Existing CLI arguments have been removed. The `migrate_1_x_config.py` script (included in `ccf` Python package) should be used to migrate existing `.ini` configuration files to `.json` format (#3209).
- Added support for listening on multiple interfaces for incoming client RPCs, with individual session caps (#2628).
- The per-node session cap behaviour has changed. The `network.rpc_interfaces.<interface_name>.max_open_sessions_soft` is now a soft cap on the number of sessions. Beyond this, new sessions will receive a HTTP 503 error immediately after completing the TLS handshake. The existing hard cap (where sessions are closed immediately, before the TLS handshake) is still available, under the new argument `network.rpc_interfaces.<interface_name>.max_open_sessions_hard` (#2583).
- Snapshot files now include receipt of evidence transaction. Nodes can now join or recover a service from a standalone snapshot file. 2.x nodes can still make use of snapshots created by a 1.x node, as long as the ledger suffix containing the proof of evidence is also specified at start-up (#2998).
- If no `node_certificate.subject_alt_names` is specified at node start-up, the node certificate _Subject Alternative Name_ extension now defaults to the value of `published_address` of the first RPC interface (#2902).

#### Certificate(s) Validity Period

- Nodes certificates validity period is no longer hardcoded and must instead be set by operators and renewed by members (#2924):

  - The new `node_certificate.initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the node certificate (valid from the current system time).
  - The new `command.start.service_configuration.maximum_node_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for node certificates.
  - The new `set_node_certificate_validity` proposal action allows members to renew a node certificate (or `set_all_nodes_certificate_validity` equivalent action to renew _all_ trusted nodes certificates).

- Service certificate validity period is no longer hardcoded and must instead be set by operators and renewed by members (#3363):

  - The new `service_certificate_initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the service certificate (valid from the current system time).
  - The new `maximum_service_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for service certificate.
  - The new `set_service_certificate_validity` proposal action allows members to renew the service certificate.

#### Misc

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

#### Fixed

- Fixed issue with ledger inconsistency when starting a new joiner node without a snapshot but with an existing ledger prefix (#3064).
- Fixed issue with join nodes which could get stuck if an election was triggered while catching up (#3169).

---

### Auditor

- Receipts now include the endorsed certificate of the node, as well as its node id, for convenience (#2991).
- Retired nodes are now removed from the store/ledger as soon as their retirement is committed (#3409).
- Service-endorsed node certificates are now recorded in a new `public:ccf.gov.nodes.endorsed_certificates` table, while the existing `cert` field in the `public:ccf.gov.nodes.info` table is now deprecated (#2844).
- New `split_ledger.py` utility to split existing ledger files (#3129).
- Python `ccf.read_ledger` module now accepts custom formatting rules for the key and value based on the key-value store table name (#2791).
- [Ledger entries](https://microsoft.github.io/CCF/main/architecture/ledger.html#transaction-format) now contain a `commit_evidence_digest`, as well as an optional `claims_digest` when `set_claims_digest()` is used. The digest of the write set was previously the per-transaction leaf in the Merkle Tree, but is now combined with the digest of the commit evidence and optionally the user claims when present. [Receipt verification instructions](https://microsoft.github.io/CCF/main/audit/receipts.html) have been amended accordingly. The presence of `commit_evidence` in receipts serves two purposes: giving the user access to the TxID without having to parse the write set, and proving that a transaction has been committed by the service. Transactions are flushed to disk eagerly by the primary to keep in-enclave memory use to a minimum, so the existence of a ledger suffix is not on its own indicative of its commit status. The digest of the commit evidence is in the ledger to allow audit and recovery, but only the disclosure of the commit evidence indicates that a transaction has been committed by the service

---

### Client API

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

### Dependencies

- Upgraded Open Enclave to 0.17.5.

## [2.0.0-dev8]

### Added

- Added `set_claims_digest()` API to `RpcContext`, see [documentation](https://microsoft.github.io/CCF/main/build_apps/logging_cpp.html#user-defined-claims-in-receipts) on how to use it to attach application-defined claims to transaction receipts.
- Added a `GET /jwt_metrics` endpoint to monitor attempts and successes of key refresh for each issuer. See [documentation](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html#extracting-jwt-metrics) on how to use it.

### Changed

- Service certificate validity period is no longer hardcoded and can instead be set by operators and renewed by members (#3363):
  - The new `service_certificate_initial_validity_days` (defaults to 1 day) configuration entry lets operators set the initial validity period for the service certificate (valid from the current system time).
  - The new `maximum_service_certificate_validity_days` (defaults to 365 days) configuration entry sets the maximum validity period allowed for service certificate.
  - The new `set_service_certificate_validity` proposal action allows members to renew the service certificate.
- Service certificate output by first node default name is now `service_cert.pem` rather than `networkcert.pem` (#3363).
- Retired nodes are now removed from the store/ledger as soon as their retirement is committed (#3409).

### Removed

- The `ccf` Python package no longer provides utilities to issue requests to a running CCF service. This is because CCF supports widely-used client-server protocols (TLS, HTTP) that should already be provided by libraries for all programming languages. The `ccf` Python package can still be used to audit the ledger and snapshot files (#3386).
- The `proposal_generator` has been removed from the `ccf` Python package. The majority of proposals can be trivially constructed in existing client tooling, without needing to invoke Python. This also introduces parity between the default constitution and custom constitution actions - all should be constructed and called from the same governance client code. Some jinja templates are included in `samples/templates` for constructing careful ballots from existing proposals.

## [2.0.0-dev7]

### Added

- Added endpoint to obtain service configuration via `/node/service/configuration` (#3251)

### Changed

- Breaking change: Configuration for CCF node is now a JSON configuration file passed in to `cchost` via `--config /path/to/config/file/` CLI argument. Existing CLI arguments have been removed. The `migrate_1_x_config.py` script (included in `ccf` Python package) should be used to migrate existing `.ini` configuration files to `.json` format (#3209).
- Format of node output RPC and node-to-node addresses files is now JSON (#3300).
- Schema of `GET /network/nodes/{node_id}` and `GET /network/nodes` endpoints has been modified to include all RPC interfaces (#3300).

### Renamed

- `ccf::historical::AbstractStateCache::drop_requests()` renamed to `drop_cached_states()` (#3187).

### Dependency

- Upgrade OpenEnclave from 0.17.2 to 0.17.5

## [2.0.0-dev6]

### Added

- Added experimental support for 2-transaction reconfiguration with CFT consensus (#3097), see [documentation](https://microsoft.github.io/CCF/main/overview/consensus/bft.html#two-transaction-reconfiguration). Note that mixing 1tx and 2tx nodes in the same network is unsupported and unsafe at this stage.

### Changed

- DNS resolution of client connections is now asynchronous.

### Fixed

- Fixed issue with join nodes which could get stuck if an election was triggered while catching up (#3169).

## [2.0.0-dev5]

### Added

- Receipts now include the endorsed certificate of the node, as well as its node id, for convenience (#2991).
- `get_metrics_v1` API to `BaseEndpointRegistry` for applications that do not make use of builtins and want to version or customise metrics output.
- Slow ledger IO operations will now be logged at level FAIL. The threshold over which logging will activate can be adjusted by the `--io-logging-threshold` CLI argument to cchost (#3067).
- Snapshot files now include receipt of evidence transaction. Nodes can now join or recover a service from a standalone snapshot file. 2.x nodes can still make use of snapshots created by a 1.x node, as long as the ledger suffix containing the proof of evidence is also specified at start-up (#2998).
- Nodes certificates validity period is no longer hardcoded and can instead be set by operators and renewed by members (#2924):
  - The new `--initial-node-cert-validity-days` (defaults to 1 day) CLI argument to cchost lets operators set the initial validity period for the node certificate (valid from the current system time).
  - The new `--max-allowed-node-cert-validity-days` (defaults to 365 days) CLI argument to cchost sets the maximum validity period allowed for node certificates.
  - The new `set_node_certificate_validity` proposal action allows members to renew a node certificate (or `set_all_nodes_certificate_validity` equivalent action to renew _all_ trusted nodes certificates).
  - The existing `transition_node_to_trusted` proposal action now requires a new `valid_from` argument (and optional `validity_period_days`, which defaults to the value of ``--max-allowed-node-cert-validity-days`).
- `ccf.historical.getStateRange` / `ccf.historical.dropCachedStates` JavaScript APIs to manually retrieve historical state in endpoints declared as `"mode": "readonly"` (#3033).
- Log more detailed errors on early startup (#3116).
- New `split_ledger.py` utility to split existing ledger files (#3129).

### Changed

- JavaScript endpoints with `"mode": "historical"` now expose the historical KV at `ccf.historicalState.kv` while `ccf.kv` always refers to the current KV state. Applications relying on the old behaviour should make their code forward-compatible before upgrading to 2.x with `const kv = ccf.historicalState.kv || ccf.kv`.

### Removed

- Receipts accessible through JavaScript no longer contain the redundant `root` hash field. Applications should be changed to not rely on this field anymore before upgrading to 2.x.

### Fixed

- Fixed issue with ledger inconsistency when starting a new joiner node without a snapshot but with an existing ledger prefix (#3064).

## [2.0.0-dev4]

### Added

- Added `foreach_key` and `foreach_value` to C++ KV API, to iterate without deserializing both entries when only one is used (#2918).
- `ccf::historical::adapter_v2` now returns 404, with either `TransactionPendingOrUnknown` or `TransactionInvalid`, rather than 400 when a user performs a historical query for a transaction id that is not committed.

### Changed

- Service-endorsed node certificates are now recorded in a new `public:ccf.gov.nodes.endorsed_certificates` table, while the existing `cert` field in the `public:ccf.gov.nodes.info` table is now deprecated (#2844).
- Joining nodes now present service-endorsed certificate in client TLS sessions _after_ they have observed their own addition to the store, rather than as soon as they have joined the service. Operators should monitor the initial progress of a new node using its self-signed certificate as TLS session certificate authority (#2844).
- Updated `actions.js` constitution fragment to record service-endorsed node certificate on the `transition_node_to_trusted` action. The constitution should be updated using the existing `set_constitution` proposal (#2844).
- Improved performance for lookup of path-templated endpoints (#2918).
- Raised the minimum supported CMake version for building CCF to 3.16 (#2946).

### Dependency

- Upgrade OpenEnclave from 0.17.1 to 0.17.2 (#2992)

## [2.0.0-dev3]

### Added

- Added support for listening on multiple interfaces for incoming client RPCs, with individual session caps (#2628).

### Changed

- Upgrade OpenEnclave from 0.17.0 to 0.17.1.
- `get_state_at()` now returns receipts for signature transactions (#2785), see [documentation](https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#transaction-receipts) for details.
- Upgrade playbooks and base CI image to Ubuntu 20.04. CCF is now primarily developed and tested against Ubuntu 20.04.
- Python `ccf.read_ledger` module now accepts custom formatting rules for the key and value based on the key-value store table name (#2791).
- CCF is now built with Clang 10. It is recommended that C++ applications upgrade to Clang 10 as well.
- Internal `/gov/jwt_keys/refresh` endpoint has been moved to `/node/jwt_keys/refresh` (#2885).
- If no `--san` is specified at node start-up, the node certificate _Subject Alternative Name_ extension now defaults to the value of `--public-rpc-address` (#2902).

### Removed

- Remove long-deprecated `--domain` argument from `cchost`. Node certificate Subject Alternative Names should be passed in via existing `--san` argument (#2798).
- Removed Forum sample app.

## [2.0.0-dev2]

### Changed

- `ccf.crypto.verifySignature()` previously required DER-encoded ECDSA signatures and now requires IEEE P1363 encoded signatures, aligning with the behavior of the Web Crypto API (#2735).
- Upgrade OpenEnclave from 0.16.1 to 0.17.0.

### Added

- Nodes code digests are now extracted and cached at network join time in `public:ccf.gov.nodes.info`, and the `/node/quotes` and `/node/quotes/self` endpoints will use this cached value whenever possible (#2651).

### Removed

- Websockets endpoints are no longer supported. Usage is insufficient to justify ongoing maintenance.

### Bugfix

- Fixed incorrect transaction view returned in `x-ms-ccf-transaction-id` HTTP response header after primary change (i.e. new view) (#2755).

## [2.0.0-dev1]

### Added

- Added a new `--client-connection-timeout-ms` command line argument to `cchost` to specify the maximum time a node should wait before re-establishing failed client connections. This should be set to a significantly lower value than `--raft-election-timeout-ms` (#2618).
- Add `kv::Value` and `kv::Set`, as a more error-proof alternative to `kv::Map`s which had a single key or meaningless values (#2599).
- Added JavaScript bytecode caching to avoid repeated compilation overhead. See the [documentation](https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html#deployment) for more information (#2643).
- Added new operator RPC `/node/js_metrics` returning the JavaScript bytecode size and whether the bytecode is used (#2643).
- Added QuickJS version to RPC `/node/version` (#2643).
- Added `GET /gov/jwt_keys/all` endpoint (#2519).
- Added `ccf.crypto.verifySignature()` for verifying digital signatures to the JavaScript API (#2661).

### Changed

- CCF now responds to HTTP requests that could not be parsed with a 400 response including error details (#2652).

## [2.0.0-dev0]

### Added

- Added `get_untrusted_host_time_v1` API. This can be used to retrieve a timestamp during endpoint execution, accurate to within a few milliseconds. Note that this timestamp comes directly from the host so is not trusted, and should not be used to make sensitive decisions within a transaction (#2550).
- Added `get_quotes_for_all_trusted_nodes_v1` API. This returns the ID and quote for all nodes which are currently trusted and participating in the service, for live audit (#2511).
- Added node start-up check for `cchost` and enclave compatibility, which should both always be from the same release for a single node (#2532).
- Added a new `/node/version` endpoint to return the CCF version of a node (#2582).
- Added a new `/node/metrics` endpoint which includes the count of active and peak concurrent sessions handled by the node (#2596).
- Added experimental JavaScript API `ccf.host.triggerSubprocess()` (#2461).

### Changed

- The curve-id selected for the identity of joining nodes no longer needs to match that of the network (#2525).
- The per-node session cap behaviour has changed. The `--max-open-sessions` is now a soft cap on the number of sessions. Beyond this, new sessions will receive a HTTP 503 error immediately after completing the TLS handshake. The existing hard cap (where sessions are closed immediately, before the TLS handshake) is still available, under the new argument `--max-open-sessions-hard` (#2583).
- Requests with a url-encoded query string are now forwarded correctly from backups to the primary (#2587).
- Signed requests with a url-encoded query string are now handled correctly rather than rejected (#2592).
- Fixed consistency issue between ledger files on different nodes when snapshotting is active (#2607).

### Dependency

- Upgrade OpenEnclave from 0.15.0 to 0.16.1 (#2609)

## [1.0.4]

### Changed

- CCF now responds to HTTP requests that could not be parsed with a 400 response including error details (#2652).

## [1.0.3]

### Dependency

- Upgrade OpenEnclave from 0.15.0 to 0.16.1 (#2609)

## [1.0.2]

### Bugfix

- Fixed consistency issue between ledger files on different nodes when snapshotting is active (#2607).

## [1.0.1]

### Bugfix

- Requests with a url-encoded query string are now forwarded correctly from backups to the primary (#2587).
- Signed requests with a url-encoded query string are now handled correctly rather than rejected (#2592).

## [1.0.0]

The Confidential Consortium Framework CCF is an open-source framework for building a new category of secure, highly available, and performant applications that focus on multi-party compute and data.

This is the first long term support release for CCF. The 1.0 branch will only receive security and critical bug fixes, please see our [release policy](https://microsoft.github.io/CCF/main/build_apps/release_policy.html) for more detail.

Active development will continue on the `main` branch, and regular development snapshots including new features will continue to be published.

Browse our [documentation](https://microsoft.github.io/CCF/main/index.html) to get started with CCF, or [open a discussion on GitHub](https://github.com/microsoft/CCF/discussions) if you have any questions.

## [1.0.0-rc3]

### Changed

- Rename `Store::commit_version()` to the more accurate `Store::compacted_version()` (#1355).

## [1.0.0-rc2]

### Changed

- Adjust release pipeline to cope with GitHub renaming debian packages containing tildes.

## [1.0.0-rc1]

### Changed

- By default, CCF is now installed under `/opt/ccf` rather than `/opt/ccf-x.y.z`.

## [0.99.4]

### Fixed

- Fixed use of `--curve-id` argument to `cchost`, which can now start a network with both node and service identities using curve `secp256r1` (#2516).

## [0.99.3]

### Added

- `kv::MapHandle::size()` can be used to get the number of entries in a given map.
- `kv::MapHandle::clear()` can be used to remove all entries from a map.

## [0.99.2]

### Changed

- The default constitution no longer contains `set_service_principal` or `remove_service_principal` since they are not used by the core framework. Instead any apps which wish to use these tables should add them to their own constitution. A [sample implementation](https://github.com/microsoft/CCF/tree/main/samples/constitutions/test/service_principals/actions.js) is available, and used in the CI tests.
- Proposal status now includes a `final_votes` and `vote_failures` map, recording the outcome of each vote per member. `failure_reason` and `failure_trace` have been consolidated into a single `failure` object, which is also used for `vote_failures`.

## [0.99.1]

### Added

- The service certificate is now returned as part of the `/node/network/` endpoint response (#2442).

### Changed

- `kv::Map` is now an alias to `kv::JsonSerialisedMap`, which means all existing applications using `kv::Map`s will now require `DECLARE_JSON...` macros for custom key and value types. `msgpack-c` is no longer available to apps and `MSGPACK_DEFINE` macros should be removed. Note that this change may affect throughput of existing applications, in which case an app-defined serialiser (or `kv::RawCopySerialisedMap`) should be used (#2449).
- `/node/state` endpoint also returns the `seqno` at which a node was started (i.e. `seqno` of the snapshot a node started from or `0` otherwise) (#2422).

### Removed

- `/gov/query` and `/gov/read` governance endpoints are removed (#2442).
- Lua governance is removed. `JS_GOVERNANCE` env var is no longer necessary, and JS constitution is the only governance script which must be provided and will be used by the service. `--gov-script` can no longer be passed to `cchost` or `sandbox.sh`.

## [0.99.0]

This is a bridging release to simplify the upgrade to 1.0. It includes the new JS constitution, but also supports the existing Lua governance so that users can upgrade in 2 steps - first implementing all of the changes below with their existing Lua governance, then upgrading to the JS governance. Lua governance will be removed in CCF 1.0. See [temporary docs](https://microsoft.github.io/CCF/ccf-0.99.0/governance/js_gov.html) for help with transitioning from Lua to JS.

The 1.0 release will require minimal changes from this release.

### Added

- A new `read_ledger.py` Python command line utility was added to parse and display the content of a ledger directory.
- `ccf-app` npm package to help with developing JavaScript and TypeScript CCF apps. See [docs](https://microsoft.github.io/CCF/main/build_apps/js_app.html) for further details (#2331).

### Changed

- Retired members are now deleted from the store, instead of being marked as `Retired` (#1401).
- `retire_member` proposal has been renamed to `remove_member` and is now idempotent (i.e. succeeds even if the member was already removed) (#1401).
- `accept_recovery` and `open_network` proposals have been merged into a single idempotent `transition_service_to_open` proposal (#1791).
- The `/tx` endpoint now takes a single `transaction_id` query parameter. For example, rather than calling `/node/tx?view=2&seqno=42`, call `/node/tx?transaction_id=2.42`.
- The `/commit` endpoint now returns a response with a single `transaction_id` rather than separate `view` and `seqno` fields.
- `UserRpcFrontend` has been removed, and the return value of `get_rpc_handler` which apps should construct is now simply a `ccf::RpcFrontend`.
- There is now a distinction between public and private headers. The public headers under `include/ccf` are those we expect apps to use, and others are implementation details which may change/be deprecated/be hidden in future. Most apps should now be including `"ccf/app_interface.h"` and `"ccf/common_endpoint_registry.h"`.
- Various endpoint-related types have moved under the `ccf::endpoints` namespace. Apps will need to rename these types where they are not using `auto`, for instance to `ccf::endpoints::EndpointContext` and `ccf::endpoints::ForwardingRequired`.
- Ledger entry frames are no longer serialised with `msgpack` (#2343).
- In JavaScript apps, the field `caller.jwt.key_issuer` in the `Request` object has been renamed `caller.jwt.keyIssuer` (#2362).
- The proposals `set_module`, `remove_module` and `set_js_app` have been removed and `deploy_js_app` renamed to `set_js_app` (#2391).

## [0.19.3]

### Changed

- The status filter passed to `/node/network/nodes` now takes the correct CamelCased values (#2238).

## [0.19.2]

### Added

- New `get_user_data_v1` and `get_member_data_v1` C++ API calls have been added to retrieve the data associated with users/members. The user/member data is no longer included in the `AuthnIdentity` caller struct (#2301).
- New `get_user_cert_v1` and `get_member_cert_v1` C++ API calls have been added to retrieve the PEM certificate of the users/members. The user/member certificate is no longer included in the `AuthnIdentity` caller struct (#2301).

### Changed

- String values in query parameters no longer need to be quoted. For instance, you should now call `/network/nodes?host=127.0.0.1` rather than `/network/nodes?host="127.0.0.1"` (#2309).
- Schema documentation for query parameters should now be added with `add_query_parameter`, rather than `set_auto_schema`. The `In` type of `set_auto_schema` should only be used to describe the request body (#2309).
- `json_adapter` will no longer try to convert query parameters to a JSON object. The JSON passed as an argument to these handlers will now be populated only by the request body. The query string should be parsed separately, and `http::parse_query(s)` is added as a starting point. This means strings in query parameters no longer need to be quoted (#2309).
- Enum values returned by built-in REST API endpoints are now PascalCase. Lua governance scripts that use enum values need to be updated as well, for example, `"ACTIVE"` becomes `"Active"` for member info. The same applies when using the `/gov/query` endpoint (#2152).
- Most service tables (e.g. for nodes and signatures) are now serialised as JSON instead of msgpack. Some tables (e.g. user and member certificates) are serialised as raw bytes for performance reasons (#2301).
- The users and members tables have been split into `public:ccf.gov.users.certs`/`public:ccf.gov.users.info` and `public:ccf.gov.members.certs`/`public:ccf.gov.members.encryption_public_keys`/`public:ccf.gov.members.info` respectively (#2301).
- TypeScript interface/class names have been renamed to PascalCase (#2325).

## [0.19.1]

### Added

- Historical point query support has been added to JavaScript endpoints (#2285).
- RSA key generation JavaScript endpoint (#2293).

### Changed

- `"readonly"` has been replaced by `"mode"` in `app.json` in JavaScript apps (#2285).

## [0.19.0]

### Changed

- `x-ccf-tx-view` and `x-ccf-tx-seqno` response headers have been removed, and replaced with `x-ms-ccf-transaction-id`. This includes both original fields, separated by a single `.`. Historical queries using `ccf::historical::adapter` should also pass a single combined `x-ms-ccf-transaction-id` header (#2257).
- Node unique identifier is now the hex-encoded string of the SHA-256 digest of the node's DER-encoded identity public key, which is also used as the node's quote report data. The `sandbox.sh` script still uses incrementing IDs to keep track of nodes and for their respective directories (#2241).
- Members and users unique identifier is now the hex-encoded string of the SHA-256 digest of their DER-encoded identity certificate (i.e. fingerprint), which has to be specified as the `keyId` field for signed HTTP requests (#2279).
- The receipt interface has changed, `/app/receipt?commit=23` is replaced by `/app/receipt?transaction_id=2.23`. Receipt fetching is now implemented as a historical query, which means that the first reponse(s) may be 202 with a Retry-After header. Receipts are now structured JSON, as opposed to a flat byte sequence, and `/app/receipt/verify` has been removed in favour of an [offline verification sample](https://microsoft.github.io/CCF/ccf-0.19.0/use_apps/verify_tx.html#transaction-receipts).
- `ccfapp::get_rpc_handler()` now takes a reference to a `ccf::AbstractNodeContext` rather than `ccf::AbstractNodeState`. The node state can be obtained from the context via `get_node_state()`.

### Removed

- `get_receipt_for_seqno_v1` has been removed. Handlers wanting to return receipts must now use the historical API, and can obtain a receipt via `ccf::historical::StatePtr`. See the [historical query with receipt sample](https://microsoft.github.io/CCF/ccf-0.19.0/build_apps/logging_cpp.html#receipts) for reference.
- `caller_id` endpoint has been removed. Members and users can now compute their unique identifier without interacting with CCF (#2279).
- `public:ccf.internal.members.certs_der`, `public:ccf.internal.users.certs_der`, `public:ccf.internal.members.digests` and `public:ccf.internal.users.digests` KV tables have been removed (#2279).
- `view_change_in_progress` field in `network/status` response has been removed (#2288).

## [0.18.5]

### Changed

- Historical query system now supports range queries.

## [0.18.4]

### Changed

- Governance proposals can be submitted successfully against secondaries (#2247)
- `set_ca_cert`/`remove_ca_cert` proposals have been renamed `set_ca_cert_bundle`/`remove_ca_cert_bundle` and now also accept a bundle of certificates encoded as concatenated PEM string (#2221). The `ca_cert_name` parameter to the `set_jwt_issuer` proposal has been renamed to `ca_cert_bundle_name`.

### Added

- Support for multiple key wrapping algorithms for C++ and JavaScript applications (#2246)

## [0.18.3]

### Changed

- Fixed format of `notBefore` and `notAfter` in node and network certificates (#2243).
- CCF now depends on [Open Enclave 0.14](https://github.com/openenclave/openenclave/releases/tag/v0.14.0).

## [0.18.2]

### Added

- Support for historical queries after ledger rekey and service recovery (#2200).

### Changed

- CCF now supports OpenSSL for many crypto tasks like hashing, signing, and signature verification (#2123).
- In progress ledger files no longer cause a node to crash when they are committed (#2209).

## [0.18.1]

### Changed

- `"id"` field in `state` endpoint response has been renamed to `"node_id"` (#2150).
- `user_id` endpoint is renamed `caller_id` (#2142).
- Nodes' quotes format updated to Open Enclave's `SGX_ECDSA`. Quote endorsements are also stored in CCF and can be retrieved via the `quotes/self` and `quotes` endpoints (#2161).
- `get_quote_for_this_node_v1()` takes a `QuoteInfo` structure (containing the format, raw quote and corresponding endorsements) as out parameter instead of the distinct format and raw quote as two out paramters (#2161).
- Several internal tables are renamed (#2166).
- `/node/network/nodes` correctly returns all nodes if no filter is specified (#2188).

## [0.18.0]

### Changed

- `endpoint_metrics` is renamed `api/metrics` and now returns an array of objects instead of nested path/method objects (#2068).
- Governance proposal ids are now digests of the proposal and store state observed during their creation, hex-encoded as strings. This makes votes entirely specific to an instance of a proposal without having to include a nonce. (#2104, #2135).
- `quote` endpoint has been renamed to `quotes/self` (#2149).
- `TxView`s have been renamed to `MapHandle`s, to clearly distinguish them from consensus views. Calls to `tx.get_view` must be replaced with `tx.rw`.
- `tx.rw` does not support retrieving multiple views in a single call. Instead of `auto [view1, view2] = tx.get_view(map1, map2);`, you must write `auto handle1 = tx.rw(map1); auto handle2 = tx.rw(map2);`.

### Added

- Added `get_version_of_previous_write(const K& k)` to `MapHandle`. If this entry was written to by a previous transaction, this returns the version at which that transaction was applied. See docs for more details.

### Removed

- The `x-ccf-global-commit` header is no longer sent with responses (#1586, #2144). This was a hint of global commit progress, but was known to be imprecise and unrelated to the executed transaction. Instead, clients should call `/commit` to monitor commit progress or `/tx` for a specific transaction.

## [0.17.2]

### Fixed

- Fixed incorrect ledger chunking on backup nodes when snapshotting is enabled (#2110).

## [0.17.1]

### Changed

- JS endpoints now list their auth policies by name, similar to C++ endpoints. The fields `require_client_identity`, `require_client_signature`, and `require_jwt_authentication` are removed, and should be replaced by `authn_policies`. For example, the previous default `"require_client_identity": true` should be replaced with `"authn_policies": ["user_cert"]`, an endpoint which would like to handle a JWT but will also accept unauthenticated requests would be `"authn_policies": ["jwt", "no_auth"]`, and a fully unauthenticated endpoint would be `"authn_policies": []`. See [docs](https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html#metadata) for further detail.

## [0.17.0]

### Added

- Versioned APIs for common CCF functionality: `get_status_for_txid_v1`, `get_last_committed_txid_v1`, `generate_openapi_document_v1`, `get_receipt_for_seqno_v1`, `get_quote_for_this_node_v1`. We will aim to support these function signatures long-term, and provide similar functionality with incremental version bumps when this is no longer possible. In particular, this enables building an app which does not expose the [default endpoints](https://microsoft.github.io/CCF/main/build_apps//logging_cpp.html#default-endpoints) but instead exposes similar functionality through its own API.

### Changed

- `/network`, `/network_info`, `/node/ids`, `/primary_info` have been restructured into `/network`, `/network/nodes`, `/network/nodes/{id}`, `/network/nodes/self`, `/network/nodes/primary` while also changing the response schemas (#1954).
- `/ack` responds with HTTP status `204` now instead of `200` and `true` as body (#2088).
- `/recovery_share` has new request and response schemas (#2089).

## [0.16.3]

### Changed

- To avoid accidentally unauthenticated endpoints, a vector of authentication policies must now be specified at construction (as a new argument to `make_endpoint`) rather than by calling `add_authentication`. The value `ccf::no_auth_required` must be used to explicitly indicate an unauthenticated endpoint.
- All `/gov` endpoints accept signature authentication alone correctly, regardless of session authentication.
- `ccf.CCFClient` now allows separate `session_auth` and `signing_auth` to be passed as construction time. `ccf.CCFClient.call()` no longer takes a `signed` argument, clients with a `signing_auth` always sign. Similarly, the `disable_session_auth` constructor argument is removed, the same effect can be achieved by setting `session_auth` to `None`.

## [0.16.2]

### Changed

- Snapshots are generated by default on the current primary node, every `10,000` committed transaction (#2029).
- Node information exposed in the API now correctly reports the public port when it differs from the local one. (#2001)
- All `/gov` endpoints accept signature authentication again. Read-only `/gov` endpoints had been incorrectly changed in [0.16.1] to accept session certification authentication only (#2033).

## [0.16.1]

### Added

- C++ endpoints can be omitted from OpenAPI with `set_openapi_hidden(true)` (#2008).
- JS endpoints can be omitted from OpenAPI if the `"openapi_hidden"` field in `app.json` is `true` (#2008).

### Changed

- Error responses of built-in endpoints are now JSON and follow the OData schema (#1919).
- Code ids are now deleted rather than marked as `RETIRED`. `ACTIVE` is replaced with the more precise `ALLOWED_TO_JOIN` (#1996).
- Authentication policies can be specified per-endpoint with `add_authentication`. Sample policies are implemented which check for a user TLS handshake, a member TLS handshake, a user HTTP signature, a member HTTP signature, and a valid JWT. This allows multiple policies per-endpoints, and decouples auth from frontends - apps can define member-only endpoints (#2010).
- By default, if no authentication policy is specified, endpoints are now unauthenticated and accessible to anyone (previously the default was user TLS handshakes, where the new default is equivalent to `set_require_client_identity(false)`).
- CCF now depends on [Open Enclave 0.13](https://github.com/openenclave/openenclave/releases/tag/v0.13.0).

### Removed

- The methods `Endpoint::set_require_client_signature`, `Endpoint::set_require_client_identity` and `Endpoint::set_require_jwt_authentication` are removed, and should be replaced by calls to `add_authentication`. For unauthenticated endpoints, either add no policies, or add the built-in `empty_auth` policy which accepts all requests.
  - `.set_require_client_signature(true)` must be replaced with `.add_authentication(user_signature_auth_policy)`
  - `.set_require_client_identity(true)` must be replaced with `.add_authentication(user_cert_auth_policy)`
  - `.set_require_jwt_authentication(true)` must be replaced with `.add_authentication(jwt_auth_policy)`

## [0.16.0]

### Added

- CLI options are printed on every node launch (#1923).
- JS logging sample app is included in CCF package (#1932).
- C++ apps can be built using cmake's `find_package(ccf REQUIRED)` (see [cmake sample](https://github.com/microsoft/CCF/blob/main/samples/apps/logging/CMakeLists.txt)) (#1947).

### Changed

- JWT signing keys are auto-refreshed immediately when adding a new issuer instead of waiting until the next auto-refresh event is due (#1978).
- Snapshots are only committed when proof of snapshot evidence is committed (#1972).
- Snapshot evidence must be validated before joining/recovering from snapshot (see [doc](https://microsoft.github.io/CCF/main/operations/ledger_snapshot.html#join-recover-from-snapshot)) (#1925).

### Fixed

- Ledger index is recovered correctly even if `--ledger-dir` directory is empty (#1953).
- Memory leak fixes (#1957, #1959, #1974, #1982).
- Consensus fixes (#1977, #1981).
- Enclave schedules messages in a fairer way (#1991).

### Security

- Hostname of TLS certificate is checked when auto-refreshing JWT signing keys (#1934).
- Evercrypt update to 0.3.0 (#1967).

## [0.15.2]

### Added

- JWT key auto-refresh (#1908), can be enabled by providing `"auto_refresh": true` and `"ca_cert_name": "..."` in `set_jwt_issuer` proposal.
  - Auto-refresh is currently only supported for providers following the OpenID Connect standard where keys are published under the `/.well-known/openid-configuration` path of the issuer URL.
  - `ca_cert_name` refers to a certificate stored with a `set_ca_cert` proposal and is used to validate the TLS connection to the provider endpoint.
- JWT signature validation (#1912), can be enabled with the `require_jwt_authentication` endpoint property.

### Changed

- Members can no longer vote multiple times on governance proposals (#1743).
- `update_ca_cert` proposal has been replaced by `set_ca_cert`/`remove_ca_cert` (#1917).

### Deprecated

- `set_js_app` proposal and `--js-app-script` argument are deprecated, and should be replaced by `deploy_js_app` and `--js-app-bundle`. See #1895 for an example of converting from the old style (JS embedded in a Lua script) to the new style (app bundle described by `app.json`).

### Removed

- `kv::Store::create` is removed.
- `luageneric` is removed.

## [0.15.1]

### Added

- [JWT documentation](https://microsoft.github.io/CCF/main/developers/auth/jwt.html#jwt-authentication) (#1875).
- [Member keys in HSM documentation](https://microsoft.github.io/CCF/main/members/hsm_keys.html) (#1884).

### Changed

- `/gov/ack/update_state_digest` and `/gov/ack` now only return/accept a hex string (#1873).
- `/node/quote` schema update (#1885).
- AFT consensus improvements (#1880, #1881).

## [0.15.0]

### Added

- Support for non-recovery members: only members with an associated public encryption key are handed recovery shares (#1866).
- AFT consensus verify entry validity (#1864).
- JWT validation in forum sample app (#1867).
- JavaScript endpoints OpenAPI definition is now included in `/api` (#1874).

### Changed

- The `keyId` field in the Authorization header must now be set to the hex-encoded SHA-256 digest of the corresponding member certificate encoded in PEM format. The `scurl.sh` script and Python client have been modified accordingly. `scurl.sh` can be run with `DISABLE_CLIENT_AUTH=1` (equivalent `disable_client_auth=False` argument to Python client) to issue signed requests without session-level client authentication (#1870).
- Governance endpoints no longer require session-level client authentication matching a member identity, the request signature now serves as authentication. The purpose of this change is to facilitate member key storage in systems such as HSMs (#1870).
- Support for [hs2019 scheme](https://tools.ietf.org/html/draft-cavage-http-signatures-12) for HTTP signatures (#1872).
  - `ecdsa-sha256` scheme will be deprecated in the next release.

## [0.14.3]

### Added

- Added support for storing JWT public signing keys (#1834).
  - The new proposals `set_jwt_issuer`, `remove_jwt_issuer`, and `set_jwt_public_signing_keys` can be generated with the latest version of the ccf Python package.
  - `sandbox.sh` has a new `--jwt-issuer <json-path>` argument to easily bootstrap with an initial set of signing keys using the `set_jwt_issuer` proposal.
  - See [`tests/npm-app/src/endpoints/jwt.ts`](https://github.com/microsoft/CCF/blob/70b09e53cfdc8cee946193319446f1e22aed948f/tests/npm-app/src/endpoints/jwt.ts#L23) for validating tokens received in the `Authorization` HTTP header in TypeScript.
  - Includes special support for SGX-attested signing keys as used in [MAA](https://docs.microsoft.com/en-us/azure/attestation/overview).

### Changed

- CCF now depends on [Open Enclave 0.12](https://github.com/openenclave/openenclave/releases/tag/v0.12.0) (#1830).
- `/app/user_id` now takes `{"cert": user_cert_as_pem_string}` rather than `{"cert": user_cert_as_der_list_of_bytes}` (#278).
- Members' recovery shares are now encrypted using [RSA-OAEP-256](https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt) (#1841). This has the following implications:
  - Network's encryption key is no longer output by the first node of a CCF service is no longer required to decrypt recovery shares.
  - The latest version of the `submit_recovery_share.sh` script should be used.
  - The latest version of the `proposal_generator.py` should be used (please upgrade the [ccf Python package](https://microsoft.github.io/CCF/main/quickstart/install.html#python-package)).
- `submit_recovery_share.sh` script's `--rpc-address` argument has been removed. The node's address (e.g. `https://127.0.0.1:8000`) should be used directly as the first argument instead (#1841).
- The constitution's `pass` function now takes an extra argument: `proposer_id`, which contains the `member_id` of the member who submitted the proposal. To adjust for this change, replace `tables, calls, votes = ...` with `tables, calls, votes, proposer_id = ...` at the beginning of the `pass` definition.
- Bundled votes (ie. the `ballot` entry in `POST /proposals`) have been removed. Votes can either happen explicitly via `POST /proposals/{proposal_id}/votes`, or the constitution may choose to pass a proposal without separate votes by examining its contents and its proposer, as illustrated in the operating member constitution sample. The `--vote-against` flag in `proposal_generator.py`, has also been removed as a consequence.

### Fixed

- Added `tools.cmake` to the install, which `ccf_app.cmake` depends on and was missing from the previous release.

### Deprecated

- `kv::Store::create` is deprecated, and will be removed in a future release. It is no longer necessary to create a `kv::Map` from a `Store`, it can be constructed locally (`kv::Map<K, V> my_map("my_map_name");`) or accessed purely by name (`auto view = tx.get_view<K, V>("my_map_name");`) (#1847).

## [0.14.2]

### Changed

- The `start_test_network.sh` script has been replaced by [`sandbox.sh`](https://microsoft.github.io/CCF/main/quickstart/test_network.html). Users wishing to override the default network config (a single node on '127.0.0.1:8000') must now explictly specify if they should be started locally (eg. `-n 'local://127.4.4.5:7000'`) or on remote machine via password-less ssh (eg. `-n 'ssh://10.0.0.1:6000'`).
- `node/quote` endpoint now returns a single JSON object containing the node's quote (#1761).
- Calling `foreach` on a `TxView` now iterates over the entries which previously existed, ignoring any modifications made by the functor while iterating.
- JS: `ccf.kv.<map>.get(key)` returns `undefined` instead of throwing an exception if `key` does not exist.
- JS: `ccf.kv.<map>.delete(key)` returns `false` instead of throwing an exception if `key` does not exist, and `true` instead of `undefined` otherwise.
- JS: `ccf.kv.<map>.set(key, val)` returns the map object instead of `undefined`.

## [0.14.1]

### Added

- `/node/memory` endpoint exposing the maximum configured heap size, peak and current used sizes.

### Changed

- Public tables in the KV must now indicate this in their name (with a `public:` prefix), and internal tables have been renamed. Any governance or auditing scripts which operate over internal tables must use the new names (eg - `ccf.members` is now `public:ccf.gov.members`).
- `--member-info` on `cchost` can now take a third, optional file path to a JSON file containing additional member data (#1712).

### Removed

- `/api/schema` endpoints are removed, as the same information is now available in the OpenAPI document at `/api`.

### Deprecated

- Passing the `SecurityDomain` when creating a KV map is deprecated, and will be removed in a future release. This should be encoded in the table's name, with a `public:` prefix for public tables.

## [0.14.0]

### Added

- Nodes can recover rapidly from a snapshot, rather than needing to reprocess an entire ledger (#1656)
- Python client code wraps creation and replacement of an entire JS app bundle in a single operation (#1651)
- Snapshots are only usable when the corresponding evidence is committed (#1668).
- JSON data associated to each consortium member to facilitate flexible member roles (#1657).

### Changed

- `/api` endpoints return an OpenAPI document rather than a custom response (#1612, #1664)
- Python ledger types can process individual chunks as well as entire ledger (#1644)
- `POST recovery_share/submit` endpoint is renamed to `POST recovery_share` (#1660).

### Fixed

- Elections will not allow transactions which were reported as globally committed to be rolled back (#1641)

### Deprecated

- `lua_generic` app is deprecated and will be removed in a future release. Please migrate old Lua apps to JS

## [0.13.4]

### Changed

- Fixed infinite memory growth issue (#1639)
- Step CLI updated to 0.15.2 (#1636)

## [0.13.3]

### Added

- Sample TypeScript application (#1614, #1596)

### Changed

- Handlers can implement custom authorisation headers (#1203, #1563)
- Reduced CPU usage when nodes are idle (#1625, #1626)
- Upgrade to Open Enclave 0.11 (#1620, #1624)
- Snapshots now include view history, so nodes resuming from snapshots can accurately serve transaction status requests (#1616)
- Request is now passed as an argument to JavaScript handlers (#1604), which can return arbitrary content types (#1575)
- Quote RPC now returns an error when the quote cannot be found (#1594)
- Upgraded third party dependencies (#1589, #1588, #1576, #1572, #1573, #1570, #1569)
- Consensus types renamed from `raft` and `pbft` to `cft` and `bft` (#1591)

### Removed

- Notification server (#1582)

## [0.13.2]

### Added

- retire_node_code proposal (#1558)
- Ability to update a collection of JS modules in a single proposal (#1557)

## [0.13.1]

### Fixed

- Handle setting multiple subject alternative names correctly in node certificate (#1552)
- Fix host memory check on startup ecall (#1553)

## [0.13.0]

### Added

- Experimental

  - New CCF nodes can now join from a [snapshot](https://microsoft.github.io/CCF/ccf-0.13.0/operators/start_network.html#resuming-from-existing-snapshot) (#1500, #1532)
  - New KV maps can now be created dynamically in a transaction (#1507, #1528)

- CLI

  - Subject Name and Subject Alternative Names for the node certificates can now be passed to cchost using the --sn and --san CLI switches (#1537)
  - Signature and ledger splitting [flags](https://microsoft.github.io/CCF/ccf-0.13.0/operators/start_network.html#signature-interval) have been renamed more accurately (#1534)

- Governance

  - `user_data` can be set at user creation, as well as later (#1488)

- Javascript
  - `js_generic` endpoints are now modules with a single default call. Their dependencies can be stored in a separate table and loaded with `import`. (#1469, #1472, #1481, #1484)

### Fixed

- Retiring the primary from a network is now correctly handled (#1522)

### Deprecated

- CLI
  - `--domain=...` is superseded by `--san=dNSName:...` and will be removed in a future release

### Removed

- API
  - Removed redirection from legacy frontend names (`members` -> `gov`, `nodes` -> `node`, `users` -> `app`) (#1543)
  - Removed old `install()` API, replaced by `make_endpoint()` in [0.11.1](https://github.com/microsoft/CCF/releases/tag/ccf-0.11.1) (#1541)

## [0.12.2]

### Fixed

- Fix published containers

## [0.12.1]

### Changed

- Release tarball replaced by a .deb

### Fixed

- Fix LVI build for applications using CCF (#1466)

## [0.12.0]

### Added

- Tooling
  - New Python proposal and vote generator (#1370). See [docs](https://microsoft.github.io/CCF/ccf-0.12.0/members/proposals.html#creating-a-proposal).
  - New CCF tools Python package for client, ledger parsing and member proposal/vote generation (#1429, #1435). See [docs](https://microsoft.github.io/CCF/ccf-0.12.0/users/python_tutorial.html).
- HTTP endpoints
  - Templated URI for HTTP endpoints (#1384, #1393).
  - New `remove_user` proposal (#1379).
  - New node endpoints: `/node/state` and `/node/is_primary` (#1387, #1439)
  - New `metrics` endpoint (#1422).

### Changed

- Tooling
  - Updated version of Open Enclave (0.10) (#1424). Users should use the Intel PSW tested with Open Enclave 0.10, see Open Enclave releases notes: https://github.com/openenclave/openenclave/releases/tag/v0.10.0 for more details.
  - CCF releases no longer include a build of Open Enclave, instead the upstream binary release should be used. Playbooks and containers have been updated accordingly (#1437).
  - CCF is now built with LVI mitigations (#1427). CCF should now be built with a new LVI-enabled toolchain, available via CCF playbooks and containers.
  - Updated version of `snmalloc` (#1391).
- HTTP endpoints
  - Pass PEM certificates rather than byte-arrays (#1374).
  - Member `/ack` schema (#1395).
  - Authorisation HTTP request header now accepts unquoted values (#1411).
  - Fix double opening of `/app` on backups after recovery (#1445).
- Other
  - Merkle tree deserialisation fix (#1363).
  - Improve resilience of node-to-node channels (#1371).
  - First Raft election no longer fails (#1392).
  - Fix message leak (#1442).

### Removed

- `mkSign` endpoint (#1398).

## [0.11.7]

### Changed

1. Fix a bug that could cause signatures not to be recorded on transactions hitting conflicts (#1346)
2. Fix a bug that could allow transactions to be executed by members before a recovered network was fully opened (#1347)
3. Improve error reporting on transactions with invalid signatures (#1356)

### Added

1. All format and linting checks are now covered by `scripts/ci-checks.sh` (#1359)
2. `node/code` RPC returns all code versions and their status (#1351)

## [0.11.4]

### Changed

- Add clang-format to the application CI container, to facilitate application development (#1340)
- Websocket handlers are now distinct, and can be defined by passing `ws::Verb::WEBSOCKET` as a verb to `make_endpoint()` (#1333)
- Custom KV serialisation is [documented](https://microsoft.github.io/CCF/main/developers/kv/kv_serialisation.html#custom-key-and-value-types)

### Fixed

- Fix application runtime container, which had been missing a dependency in the previous release (#1340)

## [0.11.1]

### Added

- CLI tool for managing recovery shares (#1295). [usage](https://microsoft.github.io/CCF/main/members/accept_recovery.html#submitting-recovery-shares)
- New standard endpoint `node/ids` for retrieving node ID from IP address (#1319).
- Support for read-only transactions. Use `tx.get_read_only_view` to retrieve read-only views, and install with `make_read_only_endpoint` if all operations are read-only.
- Support for distinct handlers on the same URI. Each installed handler/endpoint is now associated with a single HTTP method, so you can install different operations on `POST /foo` and `GET /foo`.

### Changed

- The frontend names, used as a prefix on all URIs, have been changed. Calls to `/members/...` or `/users/...` should be replaced with `/gov/...` and `/app/...` respectively. The old paths will return HTTP redirects in this release, but may return 404 in a future release (#1325).
- App-handler installation API has changed. `install(URI, FN, READWRITE)` should be replaced with `make_endpoint(URI, VERB, FN).install()`. Existing apps should compile with deprecation warnings in this release, but the old API will be removed in a future release. See [this diff](https://github.com/microsoft/CCF/commit/7f131074027e3aeb5d469cf42e94acad5bf3e70a#diff-18609f46fab38755458a063d1079edaa) of logging.cpp for an example of the required changes.
- Improved quickstart documentation (#1298, #1316).
- Member ACKs are required, even when the service is opening (#1318).
- The naming scheme for releases has changed to be more consistent. The tags will now be in the form `ccf-X.Y.Z`.

## [0.11]

### Changed

- KV reorganisation to enable app-defined serialisation (#1179, #1216, #1234)

`kv.h` has been split into multiple headers so apps may need to add includes for `kv/store.h` and `kv/tx.h`. The typedefs `ccf::Store` and `ccf::Tx` have been removed; apps should now use `kv::Store` and `kv::Tx`.

CCF now deals internally only with serialised data in its tables, mapping byte-vectors to byte-vectors. By default all tables will convert their keys and values to msgpack, using the existing macros for user-defined types. Apps may define custom serialisers for their own types - see `kv/serialise_entry_json.h` for an example.

- Fixed issues that affected the accuracy of tx status reporting (#1157, #1150)
- All RPCs and external APIs now use `view` and `seqno` to describe the components of a transaction ID, regardless of the specific consensus implementation selected (#1187, #1227)
- Improved resiliency of recovery process (#1051)
- `foreach` early-exit semantics are now consistent (#1222)
- Third party dependency updates (#1144, #1148, #1149, #1151, #1155, #1255)
- All logging output now goes to stdout, and can be configured to be either JSON or plain text (#1258) [doc](https://microsoft.github.io/CCF/main/operators/node_output.html#json-formatting)
- Initial support for historical query handlers (#1207) [sample](https://github.com/microsoft/CCF/blob/main/src/apps/logging/logging.cpp#L262)
- Implement the equivalent of "log rolling" for the ledger (#1135) [doc](https://microsoft.github.io/CCF/main/operators/ledger.html)
- Internal RPCs renamed to follow more traditional REST conventions (#968) [doc](https://microsoft.github.io/CCF/main/operators/operator_rpc_api.html)

### Added

- Support for floating point types in default KV serialiser (#1174)
- The `start_test_network.sh` script now supports recovering an old network with the `--recover` flag (#1095) [doc](https://microsoft.github.io/CCF/main/users/deploy_app.html#recovering-a-service)
- Application CI and runtime containers are now available (#1178)
  1. `ccfciteam/ccf-app-ci:0.11` is recommended to build CCF applications
  2. `ccfciteam/ccf-app-run:0.11` is recommended to run CCF nodes, for example in k8s
- Initial websockets support (#629) [sample](https://github.com/microsoft/CCF/blob/main/tests/ws_scaffold.py#L21)

### Removed

- `ccf::Store` and `ccf::Tx` typdefs, in favour of `kv::Store` and `kv::Tx`.

## [0.10]

### Added

- Brand new versioned documentation: https://microsoft.github.io/CCF.
- New `/tx` endpoint to check that a transaction is committed (#1111). See [docs](https://microsoft.github.io/CCF/main/users/issue_commands.html#checking-for-commit).
- Disaster recovery is now performed with members key shares (#1101). See [docs](https://microsoft.github.io/CCF/main/members/accept_recovery.html).
- Open Enclave install is included in CCF install (#1125).
- New `sgxinfo.sh` script (#1081).
- New `--transaction-rate` flag to performance client (#1071).

### Changed

- CCF now uses Open Enclave 0.9 (#1098).
- `cchost`'s `--enclave-type` is `release` by default (#1083).
- `keygenerator.sh`'s `--gen-key-share` option renamed to `--gen-enc-key` to generate member encryption key (#1101).
- Enhanced view change support for PBFT (#1085, #1087, #1092).
- JavaScript demo logging app is now more generic (#1110).
- Updated method to retrieve time in enclave from host (#1100).
- Correct use of Everycrypt hashing (#1098).
- Maximum number of active members is 255 (#1107).
- Python infra: handle proposals correctly with single member (#1079).
- Dependencies updates (#1080, #1082).

### Removed

- `cchost` no longer outputs a sealed secrets file to be used for recovery (#1101).

## [0.9.3]

### Added

1. Install artifacts include `virtual` build (#1072)
2. `add_enclave_library_c` is exposed in `ccp_app.cmake` (#1073)

## [0.9.2]

### Added

- Handlers can decide if transaction writes are applied independently from error status (#1054)
- Scenario Perf Client is now part of the CCF install to facilitate performance tests (#1058)

### Changed

- Handle writes when host is reconnecting (#1038)
- Member tables are no longer whitelisted for raw_puts (#1041)
- Projects including CCF's CMake files now use the same build type default (#1057)

## [0.9.1]

### Added

- `cchost` now supports [file-based configuration](https://microsoft.github.io/CCF/operators/start_network.html#using-a-configuration-file), as well as command-line switches (#1013, #1019)

## [0.9]

This pre-release improves support for handling HTTP requests.

### Added

- Key shares will be accepted after multiple disaster recovery operations (#992).
- HTTP response headers and status can be set directly from handler (#921, #977).
- Handlers can be restricted to accept only specific HTTP verbs (#966).
- Handlers can accept requests without a matching client cert (#962).
- PBFT messages are authenticated by each receiving node (#947).
- snmalloc can be used as allocator (#943, #990).
- Performance optimisations (#946, #971).
- Install improvements (#983, #986).

### Changed

- HTTP request and responses no longer need to contain JSON-RPC objects (#930, #977).
- Files and binaries have been renamed to use a consistent `lower_snake_case` (#989). Most app includes should be unaffected, but users of the `luageneric` app should now look for `lua_generic`.
- Threading support relies on fixes from a recent build of OE (#990). Existing machines should re-run the ansible playbooks to install the current dependencies.
- Consensus is chosen at run-time, rather than build-time (#922).
- API for installing handlers has changed (#960). See the logging app or [documentation](https://microsoft.github.io/CCF/developers/logging_cpp.html#rpc-handler) for the current style.
- Several standard endpoints are now GET-only, and must be passed a URL query (ie `GET /users/getCommit?id=42`).

## [0.8.2]

### Changed

- CCF install can now be installed anywhere (#950).
- PBFT messages are now authenticated (#947).
- Miscellaneous performance improvements (#946).

## [0.8.1]

### Added

- PBFT timers can be set from`cchost` CLI (#929). See [docs](https://microsoft.github.io/CCF/developers/consensus.html#consensus-protocols).
- Nodes output their PID in a `cchost.pid` file on start-up (#927).
- (Experimental) Members can retrieve their decrypted recovery shares via `getEncryptedRecoveryShare` and submit the decrypted share via `submitRecoveryShare` (#932).

### Changed

- App handlers should set HTTP response fields instead of custom error codes (#921). See [docs](https://microsoft.github.io/CCF/developers/logging_cpp.html#rpc-handler).
- Single build for Raft and PBFT consensuses (#922, #929, #935).
- Members' proposals are forever rejected if they fail to execute (#930).
- Original consortium members can ACK (#933).
- PBFT performance improvements (#940, #942).
- PBFT ledger private tables are now encrypted (#939).

## [0.8]

This pre-release enables experimental support for running CCF with the PBFT consensus protocol. In providing an experimental release of CCF with PBFT we hope to get feedback from early adopters.

### Added

- Experimental PBFT support [docs](https://microsoft.github.io/CCF/developers/consensus.html)
- Increased threading support [docs](https://microsoft.github.io/CCF/developers/threading.html) (#831, #838)
- Governance proposals can now be rejected, which allows constitutions to implement veto power (#854)
- Support for non JSON-RPC payloads (#852)
- RPC to get the OE report (containing the SGX quote) of a specific node (#907)

### Changed

- Compatibility with msgpack 1.0.0
- Members now need to provide two public keys, an identity to sign their proposals and votes as before, and public key with which their recovery key share will be encrypted. `--member_cert` cli argument replaced with `--member-info` when starting up a network to allow this [docs](https://microsoft.github.io/CCF/operators/start_network.html)
- Member status is now a string, eg. `"ACTIVE"` rather than an integer (#827)
- User apps have access to standard user-cert lookup (#906)
- `get_rpc_handler()` now returns `UserRpcFrontend` instead of `RpcHandler` [docs](https://microsoft.github.io/CCF/developers/logging_cpp.html#rpc-handler) (#908)
- All governance RPC's must now be signed (#911)
- Test infra stores keys and certificates (e.g. `networkcert.pem`, `user0_privk.pem`) in new `workspace/<test_label>_common/` folder (#892)

### Removed

- FramedTCP support

## [0.7.1]

### Added

- Installed Python infrastructure can now be used to launch test networks of external builds (#809)
- Initial threading support, Raft nodes now execute transactions on multiple worker threads (#773, #822)

## [0.7]

This pre-release enables experimental support for Javascript as a CCF runtime, and switches the default transport to HTTP. FramedTCP is still supported in this release (`-DFTCP=ON`) but is deprecated and will be dropped in the next release.

### Changed

- Fixed node deadlock that could occur under heavy load (#628)
- Fixed vulnerability to possible replay attack (#419)
- CCF has an installable bundle (#742)
- HTTP is the default frame format (#744)

### Added

- Added support for re-keying the ledger (#50)
- Added QuickJS runtime and sample Javascript app (#668)

### Deprecated

- FramedTCP support. Please use the ccf_FTCP.tar.gz release bundle or build CCF with `-DFTCP=ON` if you require FTCP support.

## [0.6]

This pre-release enables support for HTTP in CCF

### Changed

- Quote format in `getQuotes` changed from string to vector of bytes (https://github.com/microsoft/CCF/pull/566)
- Improved error reporting and logging (https://github.com/microsoft/CCF/pull/572, https://github.com/microsoft/CCF/pull/577, https://github.com/microsoft/CCF/pull/620)
- Node certificates endorsed by the network (https://github.com/microsoft/CCF/pull/581)
- The [`keygenerator.sh`](https://github.com/microsoft/CCF/blob/v0.6/tests/keygenerator.sh) scripts replaces the `keygenerator` CLI utility to generate member and user identities.

### Added

- HTTP endpoint support when built with `-DHTTP=ON`, see https://microsoft.github.io/CCF/users/client.html for details.
- [Only when building with `-DHTTP=ON`] The new [`scurl.sh`](https://github.com/microsoft/CCF/blob/v0.6/tests/scurl.sh) script can be used to issue signed HTTP requests to CCF (e.g. for member votes). The script takes the same arguments as `curl`.
- `listMethods` RPC for luageneric app (https://github.com/microsoft/CCF/pull/570)
- `getReceipt`/`verifyReceipt` RPCs (https://github.com/microsoft/CCF/pull/567)
- Support for app-defined ACLs (https://github.com/microsoft/CCF/pull/590)

Binaries for `cchost` and `libluagenericenc.so` are attached to this release. Note that libluagenericenc.so should be signed before being deployed by CCF (see https://microsoft.github.io/CCF/developers/build_app.html#standalone-signing).

## [0.5]

This pre-release fixes minor issues and clarifies some of `cchost` command line options.

### Removed

- The `new_user` function in constitution scripts (e.g. `gov.lua`) should be deleted as it is now directly implemented inside CCF (https://github.com/microsoft/CCF/pull/550).
- `cmake -DTARGET=all` replaced with `cmake -DTARGET=sgx;virtual`. See https://microsoft.github.io/CCF/quickstart/build.html#build-switches for new values (https://github.com/microsoft/CCF/pull/513).

### Changed

- The members and users certificates can now be registered by the consortium using clients that are not the `memberclient` CLI (e.g. using the `tests/infra/jsonrpc.py` module) (https://github.com/microsoft/CCF/pull/550).
- Fix for Raft consensus to truncate the ledger whenever a rollback occurs and use `commit_idx` instead of `last_idx` in many places because of signatures (https://github.com/microsoft/CCF/pull/503).
- Join protocol over HTTP fix (https://github.com/microsoft/CCF/pull/550).
- Clearer error messages for when untrusted users/members issue transactions to CCF (https://github.com/microsoft/CCF/pull/530).
- `devcontainer.json` now points to right Dockerfile (https://github.com/microsoft/CCF/pull/543).
- `cchost --raft-election-timeout` CLI option default now set to 5000 ms (https://github.com/microsoft/CCF/pull/559).
- Better descriptions for `cchost` command line options (e.g. `--raft-election-timeout`) (https://github.com/microsoft/CCF/pull/559).

The `cchost`, `libluagenericenc.so`, `keygenerator` and `memberclient` are also attached to this release to start a CCF network with lua application.
Note that `libluagenericenc.so` should be signed before being deployed by CCF (see https://microsoft.github.io/CCF/developers/build_app.html#standalone-signing).

## [0.4]

In this preview release, it is possible to run CCF with the PBFT consensus algorithm, albeit with significant limitations.

The evercrypt submodule has been removed, the code is instead imported, to make release tarballs easier to use.

## [0.3]

This pre-release implements the genesis model described in the TR, with a distinct service opening phase. See https://microsoft.github.io/CCF/start_network.html for details.

Some discrepancies with the TR remain, and are being tracked under https://github.com/microsoft/CCF/milestone/2

## 0.2

Initial pre-release

[3.0.0-dev6]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev6
[3.0.0-dev5]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev5
[3.0.0-dev4]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev4
[3.0.0-dev3]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev3
[3.0.0-dev2]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev2
[3.0.0-dev1]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev1
[3.0.0-dev0]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev0
[2.0.0]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0
[2.0.0-rc9]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc9
[2.0.0-rc8]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc8
[2.0.0-rc7]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc7
[2.0.0-rc6]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc6
[2.0.0-rc5]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc5
[2.0.0-rc4]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc4
[2.0.0-rc3]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc3
[2.0.0-rc2]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc2
[2.0.0-rc1]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc1
[2.0.0-rc0]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc0
[2.0.0-dev8]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev8
[2.0.0-dev7]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev7
[2.0.0-dev6]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev6
[2.0.0-dev5]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev5
[2.0.0-dev4]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev4
[2.0.0-dev3]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev3
[2.0.0-dev2]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev2
[2.0.0-dev1]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev1
[2.0.0-dev0]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-dev0
[1.0.4]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.4
[1.0.3]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.3
[1.0.2]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.2
[1.0.1]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.1
[1.0.0]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.0
[1.0.0-rc3]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.0-rc3
[1.0.0-rc2]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.0-rc2
[1.0.0-rc1]: https://github.com/microsoft/CCF/releases/tag/ccf-1.0.0-rc1
[0.99.4]: https://github.com/microsoft/CCF/releases/tag/ccf-0.99.4
[0.99.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.99.3
[0.99.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.99.2
[0.99.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.99.1
[0.99.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.99.0
[0.19.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.19.3
[0.19.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.19.2
[0.19.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.19.1
[0.19.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.19.0
[0.18.5]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.5
[0.18.4]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.4
[0.18.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.3
[0.18.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.2
[0.18.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.1
[0.18.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.18.0
[0.17.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.17.2
[0.17.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.17.1
[0.17.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.17.0
[0.16.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.16.3
[0.16.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.16.2
[0.16.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.16.1
[0.16.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.16.0
[0.15.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.15.2
[0.15.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.15.1
[0.15.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.15.0
[0.14.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.14.3
[0.14.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.14.2
[0.14.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.14.1
[0.14.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.14.0
[0.13.4]: https://github.com/microsoft/CCF/releases/tag/ccf-0.13.4
[0.13.3]: https://github.com/microsoft/CCF/releases/tag/ccf-0.13.3
[0.13.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.13.2
[0.13.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.13.1
[0.13.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.13.0
[0.12.2]: https://github.com/microsoft/CCF/releases/tag/ccf-0.12.2
[0.12.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.12.1
[0.12.0]: https://github.com/microsoft/CCF/releases/tag/ccf-0.12.0
[0.11.7]: https://github.com/microsoft/CCF/releases/tag/ccf-0.11.7
[0.11.4]: https://github.com/microsoft/CCF/releases/tag/ccf-0.11.4
[0.11.1]: https://github.com/microsoft/CCF/releases/tag/ccf-0.11.1
[0.11]: https://github.com/microsoft/CCF/releases/tag/0.11
[0.10]: https://github.com/microsoft/CCF/releases/tag/v0.10
[0.9.3]: https://github.com/microsoft/CCF/releases/tag/v0.9.3
[0.9.2]: https://github.com/microsoft/CCF/releases/tag/v0.9.2
[0.9.1]: https://github.com/microsoft/CCF/releases/tag/v0.9.1
[0.9]: https://github.com/microsoft/CCF/releases/tag/v0.9
[0.8.2]: https://github.com/microsoft/CCF/releases/tag/v0.8.2
[0.8.1]: https://github.com/microsoft/CCF/releases/tag/v0.8.1
[0.8]: https://github.com/microsoft/CCF/releases/tag/v0.8
[0.7.1]: https://github.com/microsoft/CCF/releases/tag/v0.7.1
[0.7]: https://github.com/microsoft/CCF/releases/tag/v0.7
[0.6]: https://github.com/microsoft/CCF/releases/tag/v0.6
[0.5]: https://github.com/microsoft/CCF/releases/tag/v0.5
[0.4]: https://github.com/microsoft/CCF/releases/tag/v0.4
[0.3]: https://github.com/microsoft/CCF/releases/tag/v0.3
[2.0.0-rc8]: https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc8
[unreleased]: https://github.com/microsoft/CCF/releases/tag/ccf-Unreleased
[3.0.0-dev4]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev4
[3.0.0-dev6]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev6
[3.0.0-dev7]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-dev7
[3.0.0-rc0]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-rc0
[3.0.0-rc2]: https://github.com/microsoft/CCF/releases/tag/ccf-3.0.0-rc2
