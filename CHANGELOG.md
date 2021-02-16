# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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
- Governance proposals can now be rejected, which allows consitutions to implement veto power (#854)
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
