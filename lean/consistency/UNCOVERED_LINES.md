# Consistency (`lean/consistency`) Uncovered Lines Analysis

This document inventories every uncovered line in the core implementation files mapped to `lean/consistency` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #988 (ID `45850573035`, artifacts `coverage-history-main` and `coverage-report-html` on `main`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage.

## Summary

| File                                                                                             | Missed Lines | Total Lines |   Line Cov | Notes                                                                                            |
| ------------------------------------------------------------------------------------------------ | -----------: | ----------: | ---------: | ------------------------------------------------------------------------------------------------ |
| [`include/ccf/tx_status.h`](../../include/ccf/tx_status.h)                                       |            5 |          54 |     90.74% | All 5 lines are LLVM closing-brace artifacts in `tx_status_to_str`; `evaluate_tx_status` is 100% |
| [`src/endpoints/base_endpoint_registry.cpp`](../../src/endpoints/base_endpoint_registry.cpp)     |           58 |         251 |     76.89% | Mostly `catch (const std::exception&)` blocks (36 lines), null-consensus paths, and `NotFound`   |
| [`include/ccf/base_endpoint_registry.h`](../../include/ccf/base_endpoint_registry.h)             |           31 |          54 |     42.59% | 6 LLVM closing-brace artifacts in `api_result_to_str` + unused `invalid_args_reason_to_str`      |
| [`src/endpoints/common_endpoint_registry.cpp`](../../src/endpoints/common_endpoint_registry.cpp) |           69 |         292 |     76.37% | Bad query-parameter paths on `/receipt`, `/tx`, `/commit`, `view_history=false`, and 500 paths   |
| [`src/node/rpc/frontend.h`](../../src/node/rpc/frontend.h)                                       |          146 |         891 |     83.61% | Forwarding error paths (daisy-chain, view change, unknown primary), redirection, exception paths |
| [`src/endpoints/endpoint_registry.cpp`](../../src/endpoints/endpoint_registry.cpp)               |           49 |         424 |     88.44% | Unused `set_default`, OpenAPI edge cases, templated-path errors, defensive `dynamic_cast` checks |
| [`include/ccf/endpoint_registry.h`](../../include/ccf/endpoint_registry.h)                       |            7 |          28 |     75.00% | Missing path-parameter error and unused `get_history()` accessor                                 |
| [`include/ccf/common_endpoint_registry.h`](../../include/ccf/common_endpoint_registry.h)         |            0 |           0 |          - | Declarations only (0 instrumented lines)                                                         |
| **Total**                                                                                        |      **365** |   **1,994** | **81.70%** |                                                                                                  |

Crucially, the core consistency evaluation function `ccf::evaluate_tx_status` (`include/ccf/tx_status.h`) has **100% line and 100% branch coverage**.
Most of the 365 uncovered lines are in surrounding RPC/endpoint plumbing: forwarding failure paths in `frontend.h` (some of which are directly consistency-relevant, such as session-consistency checks before forwarding and preventing forwarding daisy chains), query-parameter validation on `/tx`, `/commit`, and `/receipt`, generic `catch (const std::exception&)` wrappers in `base_endpoint_registry.cpp`, and unused helper functions.

## `include/ccf/tx_status.h` (5 uncovered lines)

### `tx_status_to_str()` closing braces (L51, L55, L59, L63, L67)

- **Uncovered lines**: `51, 55, 59, 63, 67` (5 lines).
- **What it does**: Closing braces `}` immediately after unconditional `return "...";` statements in each `case` / `default` block of `tx_status_to_str`.
- **Why not covered**: Pure LLVM source-based coverage artifact; every `return` statement in `tx_status_to_str` and every line and branch of `evaluate_tx_status` is covered.
- **Suggested test**: None needed.

## `src/endpoints/base_endpoint_registry.cpp` (58 uncovered lines)

### Uninitialised consensus paths (`current_consensus == nullptr`) (L77-80, L110-113, L217)

- **Uncovered lines**: `77, 78, 79, 80, 110, 111, 112, 113, 217` (9 lines).
- **What it does**:
  - `L77-80`: `get_status_for_txid_v1` sets `tx_status = TxStatus::Unknown` when `get_consensus() == nullptr`.
  - `L110-113`: `get_last_committed_txid_v1` returns `ApiResult::Uninitialised` when `get_consensus() == nullptr`.
  - `L217`: `get_view_for_seqno_v1` returns `ApiResult::Uninitialised` when `get_consensus() == nullptr`.
- **Why not covered**: E2E tests only query `/tx` and `/commit` after consensus is initialized, and unit tests in `src/node/rpc/test/frontend_test.cpp` usually attach a stub consensus.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` calling `get_status_for_txid_v1`, `get_last_committed_txid_v1`, and `get_view_for_seqno_v1` (and HTTP `GET /app/tx` and `GET /app/commit`) on a `BaseEndpointRegistry` / `CommonEndpointRegistry` whose consensus pointer is `nullptr`.
  This also covers the `result != ApiResult::OK` error paths in `common_endpoint_registry.cpp` (`L113-118`).

### `NotFound` paths for unknown node/member lookups (L147-150, L258-260, L306-308)

- **Uncovered lines**: `147, 148, 149, 150, 258, 259, 260, 306, 307, 308` (10 lines).
- **What it does**: Returns `ApiResult::NotFound` in `get_quote_for_this_node_v1` (`L147-150`), `get_member_data_v1` (`L258-260`), and `get_member_cert_v1` (`L306-308`) when the requested node or member is absent from the KV table.
- **Why not covered**: Unrelated to consistency semantics; existing tests only query registered nodes and members.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` calling those three methods with an absent `NodeId` / `MemberId` on an empty store.

### `catch (const std::exception&)` exception-to-`InternalError` wrappers (L55-57, L86-88, L106-108, L132-134, L157-159, L171-173, L196-198, L221-223, L243-245, L267-269, L291-293, L315-317)

- **Uncovered lines**: `55, 56, 57, 86, 87, 88, 106, 107, 108, 132, 133, 134, 157, 158, 159, 171, 172, 173, 196, 197, 198, 221, 222, 223, 243, 244, 245, 267, 268, 269, 291, 292, 293, 315, 316, 317` (36 lines).
- **What it does**: Twelve identical `catch (const std::exception&)` handlers across `BaseEndpointRegistry` API methods that log at `TRACE` level and return `ApiResult::InternalError`.
- **Why not covered**: Normal consensus and KV table lookups do not throw exceptions during happy-path or standard negative tests.
- **Suggested test**: Add a unit test in `src/node/rpc/test/frontend_test.cpp` with a throwing `StubConsensus` (throwing `std::runtime_error` from `get_view_history_since`, `evaluate_tx_status`, `get_committed_txid`, `get_view`) to cover the consistency-relevant exception wrappers (`L55-57`, `L86-88`, `L106-108`, `L221-223`) and their callers in `common_endpoint_registry.cpp`.

### `get_untrusted_host_time_v1()` `timespec_get` failure (L324-326)

- **Uncovered lines**: `324, 325, 326` (3 lines).
- **What it does**: Returns `ApiResult::InternalError` if `::timespec_get(&time, TIME_UTC) == -1`.
- **Why not covered**: `timespec_get` with `TIME_UTC` does not fail on Linux (and note that the C11 standard actually defines failure as returning `0`, not `-1`, so `base == -1` is effectively dead code!).
- **Suggested test**: Worth fixing the bug (`base == 0` per C11 `timespec_get` specification) rather than trying to test an unreachable `-1` return.

## `include/ccf/base_endpoint_registry.h` (31 uncovered lines)

### `api_result_to_str()` closing braces (L42, L46, L50, L54, L58, L62)

- **Uncovered lines**: `42, 46, 50, 54, 58, 62` (6 lines).
- **What it does**: Closing braces `}` after `return "...";` in `api_result_to_str`.
- **Why not covered**: LLVM source-based coverage artifact; all `return` statements are covered.
- **Suggested test**: None needed.

### `invalid_args_reason_to_str()` (L81-105)

- **Uncovered lines**: `81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105` (25 lines).
- **What it does**: Public helper converting `InvalidArgsReason` enum values to strings.
- **Why not covered**: Never called anywhere in CCF or its tests (public API helper).
- **Suggested test**: Add a unit test in `src/ds/test/public_header_helpers.cpp` (which already tests `tx_status_to_str` and `api_result_to_str`) covering every `InvalidArgsReason` enumerator and the `default` branch.

## `src/endpoints/common_endpoint_registry.cpp` (69 uncovered lines)

### `txid_from_query_string()` missing or malformed `transaction_id` on `/receipt` (L70-77, L83-93)

- **Uncovered lines**: `70, 71, 72, 73, 74, 75, 76, 77, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93` (19 lines).
- **What it does**: Returns `400 InvalidQueryParameterValue` when `/receipt` or `/cose_receipt` is called without a `transaction_id` query parameter (`L70-77`) or with an unparseable value (`L83-93`).
- **Why not covered**: Receipt tests always supply a valid `transaction_id`.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` (or e2e checks) calling `GET /app/receipt` with no query string and with `?transaction_id=invalid`.

### `/commit` error paths and `view_history=false` (L113-118, L137-142, L167-172, L184-189, L195-200, L204-206)

- **Uncovered lines**: `113, 114, 115, 116, 117, 118, 137, 138, 139, 140, 141, 142, 167, 168, 169, 170, 171, 172, 184, 185, 186, 187, 188, 189, 195, 196, 197, 198, 199, 200, 204, 205, 206` (33 lines).
- **What it does**:
  - `L113-118`, `L167-172`, `L195-200`: returns `500 InternalError` if `get_last_committed_txid_v1` or `get_view_history_v1` returns an unexpected non-`OK` `ApiResult`.
  - `L137-142`, `L184-189`: returns `400 InvalidQueryParameterValue` when `view_history_since` or `view_history` fails query parsing with a non-empty `error_reason` while still returning a value (defensive: `get_query_value_opt` normally returns `std::nullopt` on parse error).
  - `L204-206`: clears `out.view_history` when `view_history=false`.
- **Why not covered**: Tests pass `view_history=true` or invalid values, never `view_history=false`, and do not inject consensus errors into `/commit`.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` calling `GET /app/commit?view_history=false` (covering `L204-206`), `GET /app/commit` with `consensus == nullptr` (covering `L113-118`), and `GET /app/commit?view_history=true` / `?view_history_since=1` with a throwing `StubConsensus` (covering `L167-172`, `L195-200`).

### `/tx` missing `transaction_id` and `InternalError` paths (L242-247, L270-273)

- **Uncovered lines**: `242, 243, 244, 245, 246, 247, 270, 271, 272, 273` (10 lines).
- **What it does**:
  - `L242-247`: returns `400 InvalidQueryParameterValue` when `GET /tx` omits `transaction_id`.
  - `L270-273`: returns `500 InternalError` if `get_status_for_txid_v1` returns a non-`OK` `ApiResult`.
- **Why not covered**: Tests always pass `transaction_id` to `/tx` and never force `get_status_for_txid_v1` to fail.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` sending `GET /app/tx` with no query parameter and sending `GET /app/tx?transaction_id=2.1` against a throwing `StubConsensus`.

### `api_endpoint()` OpenAPI generation failure (L390-396)

- **Uncovered lines**: `390, 391, 392, 393, 394, 395, 396` (7 lines).
- **What it does**: Returns `500 InternalError` if `generate_openapi_document_v1` fails.
- **Why not covered**: OpenAPI generation succeeds for all valid endpoint registries in tests.
- **Suggested test**: Low priority (unrelated to consistency); testable only via a stub endpoint schema builder that throws.

## `src/node/rpc/frontend.h` (146 uncovered lines)

### `check_uri_allowed()` subsystem, interface-lookup, and unsecured-interface guards (L134-137, L149-153, L204, L206-212)

- **Uncovered lines**: `134, 135, 136, 137, 149, 150, 151, 152, 153, 204, 206, 207, 208, 209, 210, 211, 212` (17 lines).
- **What it does**:
  - `L134-137`: returns `500` if `NodeConfigurationSubsystem` is absent.
  - `L149-153`: throws `std::runtime_error` if `interface_id` is missing from startup config when checking `required_operator_features`.
  - `L204, L206-212`: rejects requests with `503 ServiceUnavailable` on an `Authority::UNSECURED` RPC interface that has no `accepted_endpoints` regex configured.
- **Why not covered**: Unrelated to consistency; tests configuring unsecured interfaces always supply `accepted_endpoints` (or don't send requests to an unsecured interface without one).
- **Suggested test**: Add a unit test in `src/node/rpc/test/frontend_test.cpp` configuring an `UNSECURED` interface with no `accepted_endpoints` and verifying a request receives `503` (`L204-212`), plus a test with a missing `NodeConfigurationSubsystem` (`L134-137`).

### Redirection resolution and error paths (`resolve_redirect_location`, `check_redirect`, `get_redirections_config`) (L243-245, L251-253, L304-308, L314, L318, L335, L397-402, L407-411, L421-424, L431-435)

- **Uncovered lines**: `243, 244, 245, 251, 252, 253, 304, 305, 306, 307, 308, 314, 318, 335, 397, 398, 399, 400, 401, 402, 407, 408, 409, 410, 411, 421, 422, 423, 424, 431, 432, 433, 434, 435` (34 lines).
- **What it does**:
  - `L243-245`, `L251-253`, `L304-308`, `L318`: invalid/unmatched `NodeByRole` resolver config (`role` not a string, unknown role, missing node in `nodes` table).
  - `L314`, `L335`: unreachable `break;` after `return` (`L314`) and LLVM closing-brace artifact (`L335`).
  - `L397-402`: returns `503 BackupNotFound` when `RedirectionStrategy::ToBackup` cannot resolve any backup address.
  - `L407-411`: `default:` unknown `RedirectionStrategy`.
  - `L421-424`, `L431-435`: missing `NodeConfigurationSubsystem` or unknown `incoming_interface` in `get_redirections_config`.
- **Why not covered**: Redirection is outside `lean/consistency`, and existing redirection tests only use valid configs with available backups.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` for `RedirectionStrategy::ToBackup` on a single-node network (covering `L397-402`) and malformed `NodeByRole` targets (`L243-245`, `L251-253`); remove unreachable `break;` at `L314`.

### `forward()` error and consistency-guard paths (L559-563, L565-566, L569, L572-575, L577-578, L583-585, L589-593, L595-596, L603-607, L609-610)

- **Uncovered lines**: `559, 560, 561, 562, 563, 565, 566, 569, 572, 573, 574, 575, 577, 578, 583, 584, 585, 589, 590, 591, 592, 593, 595, 596, 603, 604, 605, 606, 607, 609, 610` (31 lines).
- **What it does**:
  - `L559-566`: returns `500 InternalError` if `!cmd_forwarder || current_consensus == nullptr`.
  - `L569-578`: returns `503 RequestAlreadyForwarded` if `is_forwarded` is already true (prevents forwarding daisy chains).
  - `L583-585`: aborts forwarding and closes the session if `check_session_consistency` detects a view change on the backup session.
  - `L589-596`: returns `503 InternalError` if `current_consensus->primary()` is `std::nullopt`.
  - `L603-610`: returns `503 InternalError` if `cmd_forwarder->forward_command(...)` returns `false`.
- **Why not covered**: These are **directly consistency-relevant** forwarding safety paths!
  Existing forwarding tests run on healthy networks with a known primary, stable view, and connected node-to-node channels, so none of the 5 error guards trigger.
- **Suggested test**: Add focused unit tests in `src/node/rpc/test/frontend_test.cpp` (using `StubConsensus` and a mock `AbstractForwarder`) testing all five cases: (1) forwarding with no forwarder registered; (2) calling `process_forwarded` on a backup that would otherwise forward again (`RequestAlreadyForwarded`); (3) advancing `StubConsensus` view between two requests on a forwarding session (`SessionConsistencyLost`); (4) `primary() == std::nullopt`; and (5) `forward_command()` returning `false`.

### `process_command_without_kv()` exception handlers (L693-695, L698-701, L704-707, L710-715)

- **Uncovered lines**: `693, 694, 695, 698, 699, 700, 701, 704, 705, 706, 707, 710, 711, 712, 713, 714, 715` (17 lines).
- **What it does**: Catches `RpcException`, `ccf::JsonParseError`, `nlohmann::json::exception`, and `std::exception` when executing a command endpoint while the KV store is not ready (`!tables.is_ready()`).
- **Why not covered**: Only lightweight readiness/state command endpoints run while `!tables.is_ready()`, and no test triggers exceptions from them.
- **Suggested test**: Add a unit test in `src/node/rpc/test/frontend_test.cpp` with `tables.set_readiness(StoreReadiness::Unavailable)` and a command endpoint throwing each of `RpcException`, `JsonParseError`, `nlohmann::json::parse_error`, and `std::runtime_error`.

### `redirect_or_forward()` `ForwardingRequired::Never` closing brace (L778)

- **Uncovered lines**: `778` (1 line).
- **What it does**: Closing brace `}` after `break;` in `case ForwardingRequired::Never:`.
- **Why not covered**: LLVM source-based coverage artifact.
- **Suggested test**: None needed.

### `process_command_inner()` closed frontend, pending response, stolen Tx, JSON/serialisation errors (L933-939, L1024-1026, L1029-1034, L1036-1042, L1068-1070, L1072-1073, L1076-1078, L1080-1081, L1099-1104)

- **Uncovered lines**: `933, 934, 935, 936, 937, 938, 939, 1024, 1025, 1026, 1029, 1030, 1031, 1032, 1033, 1034, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1068, 1069, 1070, 1072, 1073, 1076, 1077, 1078, 1080, 1081, 1099, 1100, 1101, 1102, 1103, 1104` (39 lines).
- **What it does**:
  - `L933-939`: returns `404 FrontendNotOpen` if `!is_open()` when `process_command_inner` starts.
  - `L1024-1026`: returns early if an endpoint handler sets `ctx->response_is_pending = true` while `should_apply_writes()` is still true.
  - `L1029-1042`: returns `500 InternalError` if an endpoint handler steals/nullifies `args.owned_tx` without marking `response_is_pending`.
  - `L1068-1073`, `L1076-1081`: catches `ccf::JsonParseError` and `nlohmann::json::exception` escaping an endpoint handler, returning `400 InvalidInput`.
  - `L1099-1104`: catches `ccf::kv::KvSerialiserException` after local commit and calls `abort()` (unrecoverable post-commit serialisation failure).
- **Why not covered**: Endpoints wrapped in `json_adapter` catch JSON errors themselves rather than letting them escape to `RpcFrontend`; no test calls a closed `RpcFrontend`, steals `args.owned_tx`, or triggers a fatal `abort()` in `KvSerialiserException`.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` covering: (1) sending a request before calling `frontend.open()` (`L933-939`); (2) an endpoint setting `response_is_pending = true` (`L1024-1026`); (3) an endpoint resetting `args.owned_tx` (`L1029-1042`); and (4) raw endpoints throwing `ccf::JsonParseError` and `nlohmann::json::type_error` (`L1068-1081`).
  Leave `L1099-1104` (`abort()`) uncovered or test only in a death test.

### `process_forwarded()` defensive invariants (L1214-1217, L1221, L1224-1225)

- **Uncovered lines**: `1214, 1215, 1216, 1217, 1221, 1224, 1225` (7 lines).
- **What it does**: Throws `std::logic_error` if `process_forwarded` is called with `!is_forwarded` (`L1214-1217`) or if `process_command` leaves `ctx->response_is_pending == true` on an already-forwarded request (`L1221-1225`).
- **Why not covered**: `Forwarder` always sets `is_forwarded = true`, and `forward()` rejects re-forwarding at `L568-578` before `response_is_pending` can be set.
- **Suggested test**: Add a unit test in `src/node/rpc/test/frontend_test.cpp` calling `process_forwarded` with an unforwarded `RpcContextImpl` (`CHECK_THROWS_AS(..., std::logic_error)`).

## `src/endpoints/endpoint_registry.cpp` (49 uncovered lines)

### OpenAPI schema edge cases (L26-28, L85-87, L384-386)

- **Uncovered lines**: `26, 27, 28, 85, 86, 87, 384, 385, 386` (9 lines).
- **What it does**:
  - `L26-28`: skips non-HTTP verbs (`!get_http_method().has_value()`) when building OpenAPI schemas.
  - `L85-87`: emits `"deprecated": true/false` in OpenAPI when `endpoint->openapi_deprecated` is set.
  - `L384-386`: skips `openapi_hidden` endpoints in `build_api()`'s templated-endpoint loop.
- **Why not covered**: Unrelated to consistency; no test generates `/api` over a registry containing a deprecated endpoint, a non-HTTP verb, or a hidden templated endpoint.
- **Suggested test**: Add unit tests in `src/endpoints/test/endpoint_registry.cpp` registering a deprecated endpoint and a hidden templated endpoint, calling `build_api`, and checking the generated OpenAPI JSON.

### `PathTemplateSpec::parse()` unclosed brace (L154-157)

- **Uncovered lines**: `154, 155, 156, 157` (4 lines).
- **What it does**: Throws `std::logic_error` for a templated path missing `}` (e.g., `/items/{id`).
- **Why not covered**: `src/endpoints/test/endpoint_registry.cpp` only passes well-formed path templates.
- **Suggested test**: Add `CHECK_THROWS_AS(PathTemplateSpec::parse("/items/{id"), std::logic_error)` in `src/endpoints/test/endpoint_registry.cpp`.

### `install()` stripping sole `empty_auth_policy` (L283-285)

- **Uncovered lines**: `283, 284, 285` (3 lines).
- **What it does**: Pops `empty_auth_policy` when it is the only authentication policy on an endpoint.
- **Why not covered**: Unauthenticated endpoints pass `no_auth_required` (an empty vector) rather than `{empty_auth_policy}`.
- **Suggested test**: Add a unit test in `src/endpoints/test/endpoint_registry.cpp` installing an endpoint with `{empty_auth_policy}` and checking `authn_policies.empty()`.

### `set_default()` and fallback dispatch (L307-310, L312-313, L477-479)

- **Uncovered lines**: `307, 308, 309, 310, 312, 313, 477, 478, 479` (9 lines).
- **What it does**: Registers and returns a fallback `default_endpoint` when no exact or templated route matches.
- **Why not covered**: No CCF app or test registers a default fallback endpoint.
- **Suggested test**: Add a unit test in `src/endpoints/test/endpoint_registry.cpp` calling `set_default(...)` and verifying `find_endpoint` returns it for unmatched paths.

### Ambiguous templated path and `get_allowed_verbs()` on templated paths (L467-469, L556-558)

- **Uncovered lines**: `467, 468, 469, 556, 557, 558` (6 lines).
- **What it does**:
  - `L467-469`: calls `report_ambiguous_templated_path` when two templated routes match the same URI.
  - `L556-558`: collects allowed HTTP verbs matching a templated path when returning `405 Method Not Allowed` or `OPTIONS`.
- **Why not covered**: Tests do not install overlapping templates or send unsupported HTTP verbs to templated paths.
- **Suggested test**: Add unit tests in `src/endpoints/test/endpoint_registry.cpp` registering two ambiguous templates (e.g., `/{a}/x` and `/y/{b}` matched by `/y/x`) and calling `get_allowed_verbs` for a templated endpoint path.

### Defensive `dynamic_cast` type-mismatch guards (L443-445, L496-499, L509-513, L523-528)

- **Uncovered lines**: `443, 444, 445, 496, 497, 498, 499, 509, 510, 511, 512, 513, 523, 524, 525, 526, 527, 528` (18 lines).
- **What it does**: Throws `std::logic_error` if `RpcContext` is not `RpcContextImpl` (`L443-445`) or if `execute_command_endpoint`, `execute_endpoint`, or `execute_endpoint_locally_committed` receives an `EndpointDefinition` that is not an `Endpoint` (`L496-499`, `L509-513`, `L523-528`).
- **Why not covered**: Standard CCF dispatch always passes `RpcContextImpl` and `Endpoint` instances (derived JS registries override the execute hooks).
- **Suggested test**: Defensive type checks; testable only with stub subclasses of `RpcContext` / `EndpointDefinition` in `src/endpoints/test/endpoint_registry.cpp`.

## `include/ccf/endpoint_registry.h` (7 uncovered lines)

### `get_path_param()` missing parameter (L112-115)

- **Uncovered lines**: `112, 113, 114, 115` (4 lines).
- **What it does**: Sets `error` and returns `false` when `param_name` is not found in `params`.
- **Why not covered**: Endpoint handlers always ask for path parameter names that match their own registered URI template.
- **Suggested test**: Add a unit test in `src/endpoints/test/endpoint_registry.cpp` calling `get_path_param({}, "missing", value, error)` and verifying it returns `false` with the expected error string.

### `EndpointRegistry::get_history()` (L186-188)

- **Uncovered lines**: `186, 187, 188` (3 lines).
- **What it does**: Protected getter returning `history.load(std::memory_order_acquire)`.
- **Why not covered**: No derived endpoint registry currently calls `get_history()`.
- **Suggested test**: Low priority; either test via a derived test registry in `src/endpoints/test/endpoint_registry.cpp` or remove if unused.
