# Consistency (`lean/consistency`) Uncovered Lines Analysis

This document inventories every uncovered line in the masked in-scope implementation files mapped to `lean/consistency` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md) and [`lean/consistency/coverage_mask.json`](coverage_mask.json), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #997 (ID `45962731034`, `main` commit `6a9d9d870`, artifact `coverage-export-json`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage and deduplicates branches per source location.

## Summary

| File                                                                                             | Missed Lines | Total Lines |   Line Cov | Missed Branches | Total Branches | Branch Cov | Notes                                                                                   |
| ------------------------------------------------------------------------------------------------ | -----------: | ----------: | ---------: | --------------: | -------------: | ---------: | --------------------------------------------------------------------------------------- |
| [`include/ccf/tx_status.h`](../../include/ccf/tx_status.h)                                       |            0 |          49 |    100.00% |               0 |             22 |    100.00% | Fully covered                                                                           |
| [`src/endpoints/base_endpoint_registry.cpp`](../../src/endpoints/base_endpoint_registry.cpp)     |            6 |          19 |     68.42% |               1 |              2 |     50.00% | `get_status_for_txid_v1` null-consensus and exception paths                             |
| [`src/endpoints/common_endpoint_registry.cpp`](../../src/endpoints/common_endpoint_registry.cpp) |           10 |          47 |     78.72% |               2 |              6 |     66.67% | `GET /tx` missing `transaction_id` parameter and `InternalError` path                   |
| [`src/endpoints/endpoint_registry.cpp`](../../src/endpoints/endpoint_registry.cpp)               |           15 |          79 |     81.01% |               4 |             10 |     60.00% | Defensive `dynamic_cast` `std::logic_error` guards in `execute_*_endpoint`              |
| [`src/node/rpc/frontend.h`](../../src/node/rpc/frontend.h)                                       |           70 |         377 |     81.43% |              12 |             98 |     87.76% | `forward()` guards (daisy-chain, view change, unknown primary), error paths, invariants |
| **Total (in-scope masked)**                                                                      |      **101** |     **571** | **82.31%** |          **19** |        **138** | **86.23%** |                                                                                         |

Crucially, `include/ccf/tx_status.h` (`ccf::evaluate_tx_status` and `tx_status_to_str`) has **100% line and 100% branch coverage**.
Almost all remaining actionable gaps live in `RpcFrontend::forward()` and `process_command_inner()` (`src/node/rpc/frontend.h`) plus `/tx` error handling, and can be covered with fast virtual unit tests in `src/node/rpc/test/frontend_test.cpp`.

## `src/endpoints/base_endpoint_registry.cpp` (6 uncovered lines, 1 missed branch outcome)

### `get_status_for_txid_v1()` null-consensus and exception paths (L78-80, L86-88)

- **Uncovered lines**: `78, 79, 80, 86, 87, 88` (6 lines).
- **What it does**:
  - `L78-80`: sets `tx_status = TxStatus::Unknown` when `get_consensus() == nullptr`.
  - `L86-88`: catches `const std::exception&` from `evaluate_tx_status` and returns `ApiResult::InternalError`.
- **Why not covered**: E2E tests only query `/tx` after consensus is initialized, and unit tests in `src/node/rpc/test/frontend_test.cpp` attach a non-throwing `StubConsensus`.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` calling `get_status_for_txid_v1` (and `GET /app/tx`) with `consensus == nullptr` and with a `StubConsensus` that throws `std::runtime_error` from `evaluate_tx_status`.

## `src/endpoints/common_endpoint_registry.cpp` (10 uncovered lines, 2 missed branch outcomes)

### `/tx` missing `transaction_id` and `InternalError` paths (L242-247, L270-273)

- **Uncovered lines**: `242, 243, 244, 245, 246, 247, 270, 271, 272, 273` (10 lines).
- **What it does**:
  - `L242-247`: returns `400 InvalidQueryParameterValue` when `GET /tx` omits `transaction_id`.
  - `L270-273`: returns `500 InternalError` if `get_status_for_txid_v1` returns a non-`OK` `ApiResult`.
- **Why not covered**: Tests always pass `transaction_id` to `/tx` and never force `get_status_for_txid_v1` to fail.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` sending `GET /app/tx` with no query parameter and sending `GET /app/tx?transaction_id=2.1` against a throwing `StubConsensus`.

## `src/endpoints/endpoint_registry.cpp` (15 uncovered lines, 4 missed branch outcomes)

### Defensive `dynamic_cast` type-mismatch guards (L496-499, L509-513, L523-528)

- **Uncovered lines**: `496, 497, 498, 499, 509, 510, 511, 512, 513, 523, 524, 525, 526, 527, 528` (15 lines).
- **What it does**: Throws `std::logic_error` if `execute_command_endpoint`, `execute_endpoint`, or `execute_endpoint_locally_committed` receives an `EndpointDefinition` that is not an `Endpoint` (or lacks `command_func`).
- **Why not covered**: Standard CCF dispatch always passes `Endpoint` instances (derived JS registries override the execute hooks).
- **Suggested test**: Defensive type checks; testable only with stub subclasses of `EndpointDefinition` in `src/endpoints/test/endpoint_registry.cpp`.

## `src/node/rpc/frontend.h` (70 uncovered lines, 12 missed branch outcomes)

### `forward()` error and consistency-guard paths (L559-566, L569, L572-578, L583-585, L589-596, L603-610)

- **Uncovered lines**: `559, 560, 561, 562, 563, 565, 566, 569, 572, 573, 574, 575, 577, 578, 583, 584, 585, 589, 590, 591, 592, 593, 595, 596, 603, 604, 605, 606, 607, 609, 610` (31 lines).
- **What it does**:
  - `L559-566`: returns `500 InternalError` if `!cmd_forwarder || current_consensus == nullptr`.
  - `L569-578`: returns `503 RequestAlreadyForwarded` if `is_forwarded` is already true (prevents forwarding daisy chains).
  - `L583-585`: aborts forwarding and closes the session if `check_session_consistency` detects a view change on the backup session.
  - `L589-596`: returns `503 InternalError` if `current_consensus->primary()` is `std::nullopt`.
  - `L603-610`: returns `503 InternalError` if `cmd_forwarder->forward_command(...)` returns `false`.
- **Why not covered**: These are **directly consistency-relevant** forwarding safety paths.
  Existing forwarding tests run on healthy networks with a known primary, stable view, and connected node-to-node channels, so none of the five error guards trigger.
- **Suggested test**: Add focused unit tests in `src/node/rpc/test/frontend_test.cpp` (using `StubConsensus` and a mock `AbstractForwarder`) testing all five cases: (1) forwarding with no forwarder registered; (2) calling `process_forwarded` on a backup that would otherwise forward again (`RequestAlreadyForwarded`); (3) advancing `StubConsensus` view between two requests on a forwarding session (`SessionConsistencyLost`); (4) `primary() == std::nullopt`; and (5) `forward_command()` returning `false`.

### `process_command_inner()` pending response, stolen Tx, JSON/serialisation errors (L1024-1026, L1029-1042, L1068-1073, L1076-1081, L1099-1104)

- **Uncovered lines**: `1024, 1025, 1026, 1029, 1030, 1031, 1032, 1033, 1034, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1068, 1069, 1070, 1072, 1073, 1076, 1077, 1078, 1080, 1081, 1099, 1100, 1101, 1102, 1103, 1104` (32 lines).
- **What it does**:
  - `L1024-1026`: returns early if an endpoint handler sets `ctx->response_is_pending = true` while `should_apply_writes()` is still true.
  - `L1029-1042`: returns `500 InternalError` if an endpoint handler steals/nullifies `args.owned_tx` without marking `response_is_pending`.
  - `L1068-1073`, `L1076-1081`: catches `ccf::JsonParseError` and `nlohmann::json::exception` escaping an endpoint handler, clearing headers and returning `400 InvalidInput`.
  - `L1099-1104`: catches `ccf::kv::KvSerialiserException` after local commit and calls `abort()` (unrecoverable post-commit serialisation failure).
- **Why not covered**: Endpoints wrapped in `json_adapter` catch JSON errors themselves rather than letting them escape to `RpcFrontend`; no test steals `args.owned_tx`, sets `response_is_pending` on an endpoint, or triggers a fatal `abort()` in `KvSerialiserException`.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` covering: (1) an endpoint setting `response_is_pending = true` (`L1024-1026`); (2) an endpoint resetting `args.owned_tx` (`L1029-1042`); and (3) raw endpoints throwing `ccf::JsonParseError` and `nlohmann::json::type_error` (`L1068-1081`).
  Leave `L1099-1104` (`abort()`) uncovered or test only in a death test.

### `process_forwarded()` defensive invariants (L1214-1217, L1221, L1224-1225)

- **Uncovered lines**: `1214, 1215, 1216, 1217, 1221, 1224, 1225` (7 lines).
- **What it does**: Throws `std::logic_error` if `process_forwarded` is called with `!is_forwarded` (`L1214-1217`) or if `process_command` leaves `ctx->response_is_pending == true` on an already-forwarded request (`L1221-1225`).
- **Why not covered**: `Forwarder` always sets `is_forwarded = true`, and `forward()` rejects re-forwarding at `L568-578` before `response_is_pending` can be set.
- **Suggested test**: Add unit tests in `src/node/rpc/test/frontend_test.cpp` calling `process_forwarded` with an unforwarded `RpcContextImpl` and with an endpoint that sets `response_is_pending = true` (`CHECK_THROWS_AS(..., std::logic_error)`).
