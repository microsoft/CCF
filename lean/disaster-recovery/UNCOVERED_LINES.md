# Disaster Recovery (`lean/disaster-recovery`) Uncovered Lines Analysis

This document inventories every uncovered line in the masked in-scope implementation files mapped to `lean/disaster-recovery` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md) and [`lean/disaster-recovery/coverage_mask.json`](coverage_mask.json), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #997 (ID `45962731034`, `main` commit `6a9d9d870`, artifact `coverage-export-json`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage and deduplicates branches per source location.

## Summary

| File                                                                                                     | Missed Lines | Total Lines |   Line Cov | Missed Branches | Total Branches | Branch Cov | Notes                                                                                 |
| -------------------------------------------------------------------------------------------------------- | -----------: | ----------: | ---------: | --------------: | -------------: | ---------: | ------------------------------------------------------------------------------------- |
| [`src/node/recovery_decision_protocol.cpp`](../../src/node/recovery_decision_protocol.cpp)               |           95 |         499 |     80.96% |              31 |            130 |     76.15% | 0-vote voting timeout, `OPEN`/`JOINING` handling, and defensive missing-state guards  |
| [`src/node/rpc/self_healing_open_handlers.h`](../../src/node/rpc/self_healing_open_handlers.h)           |           82 |         309 |     73.46% |              13 |             38 |     65.79% | Security/auth error paths (bad quote, cert change, non-primary timeout, unconfigured) |
| [`include/ccf/service/tables/self_healing_open.h`](../../include/ccf/service/tables/self_healing_open.h) |            1 |           6 |     83.33% |               0 |              0 |          - | Unused `Location::operator==`                                                         |
| [`src/node/recovery_decision_protocol.h`](../../src/node/recovery_decision_protocol.h)                   |            0 |           0 |          - |               0 |              0 |          - | Declarations/types only (0 instrumented lines)                                        |
| **Total (in-scope masked)**                                                                              |      **178** |     **814** | **78.13%** |          **44** |        **168** | **73.81%** |                                                                                       |

Note: the 72 disabled `RDP_TRACE` lines (`CCF_RECOVERY_TRACE` is unset in `.github/workflows/coverage.yml`) and `start_failover_timers` are excluded by [`lean/disaster-recovery/coverage_mask.json`](coverage_mask.json) as trace instrumentation and wall-clock/cURL transport.
Two high-value in-scope takeaways stand out:

1. **Security and error-handling gaps (82 lines in `self_healing_open_handlers.h`)**: none of the invalid-quote, changed-certificate-key, non-primary `/timeout`, unconfigured-node, or `advance()` `std::logic_error` rejection paths are exercised by tests.
   All of these can be covered cheaply with virtual C++ unit tests against `NodeFrontend` / `self_healing_open_handlers.h` without needing SNP hardware.
2. **Protocol state-machine gaps (~22 lines in `recovery_decision_protocol.cpp`)**: existing SNP e2e scenarios (`tests/e2e_operations.py`) do not exercise the voting-timeout-with-zero-votes safety branch (`valid_timeout && votes->size() == 0`), reaching `StateMachine::OPEN` in `advance()`, stopping retry timers on `JOINING`/`OPEN`, or `GOSSIPING` timeout with empty gossips.

## `src/node/recovery_decision_protocol.cpp` (95 uncovered lines, 31 missed branch outcomes)

### `advance()` voting timeout with zero votes for self (L335, L339-344)

- **Uncovered lines**: `335, 339, 340, 341, 342, 343, 344` (7 lines).
- **What it does**: In `StateMachine::VOTING`, when `valid_timeout && votes->size() == 0`, logs a failure and returns early without opening the service (and without advancing `timeout_state`).
- **Why not covered**: This is a key protocol safety branch (a node that voted for a more up-to-date peer must not failover-open with 0 votes).
  In existing SNP tests (`tests/e2e_operations.py`), either the quorum or failover opener receives votes and broadcasts `IAmOpen` (moving peers to `JOINING`) before a non-chosen peer's voting timeout fires.
- **Suggested test**: Add a virtual C++ unit test driving `RecoveryDecisionProtocolSubsystem::advance` (or a test scenario in `tests/e2e_operations.py`) where a node in `VOTING` has received 0 votes for itself and receives a `timeout`, asserting it remains in `VOTING`, does not open, and does not advance `timeout_state`.

### `advance()` and retry timer reaching `StateMachine::OPEN` / stopping on `JOINING` or `OPEN` (L423-426, L550-555)

- **Uncovered lines**: `423, 424, 426, 550, 551, 552, 553, 554, 555` (9 lines).
- **What it does**:
  - `L423-426`: `StateMachine::OPEN` case in `advance()` (no-op once open).
  - `L550-555`: `JOINING` and `OPEN` cases inside `retry_task`, calling `stop_timers()` and returning.
- **Why not covered**: As noted in `lean/disaster-recovery/replayer/README.md`, existing e2e scenarios stop checking as soon as the chosen node enters `OPENING` and joining nodes request restart, without waiting for the `OPENING -> OPEN` failover timeout or subsequent retry ticks.
  Note that inside `retry_task`, line 504 already returns early when `sm_state == OPEN`, making the `OPEN` label at `L551` redundant with the earlier `if (sm_state == OPEN)` check.
- **Suggested test**: Cover `advance()` in `StateMachine::OPEN` and a `JOINING` retry tick calling `stop_timers()` in a virtual C++ unit test (or extend one SNP scenario in `tests/e2e_operations.py`), and consider removing the unreachable `case StateMachine::OPEN:` at `L551`.

### Defensive state/configuration `std::logic_error` guards in `advance()`, retry timer, and helpers (L251-254, L299-301, L316-318, L363-367, L387-390, L395-399, L428-432, L473-477, L481-483, L491-494, L528-531, L535-539, L556-561, L754-757, L831-835, L883-885, L889-891, L898-900, L911-915)

- **Uncovered lines**: `251, 252, 253, 254, 299, 300, 301, 316, 317, 318, 363, 364, 365, 366, 367, 387, 388, 389, 390, 395, 396, 397, 398, 399, 428, 429, 430, 431, 432, 473, 474, 475, 476, 477, 481, 482, 483, 491, 492, 493, 494, 528, 529, 530, 531, 535, 536, 537, 538, 539, 556, 557, 558, 559, 560, 561, 754, 755, 756, 757, 831, 832, 833, 834, 835, 883, 884, 885, 889, 890, 891, 898, 899, 900, 911, 912, 913, 914, 915` (79 lines).
- **What it does**:
  - `L251-254`, `L491-494`: throws if `SMState` or `TimeoutSMState` table entry is missing.
  - `L299-301`, `L316-318`: throws in `GOSSIPING` if `valid_timeout` fires before any gossip (even self-gossip) has arrived (`L316-318` is strictly redundant with `L299-301`).
  - `L363-367`: throws if `Tables::SERVICE` is missing when opening.
  - `L387-390`, `L395-399`, `L528-531`, `L535-539`: throws if `ChosenNode` or its `NodeInfoMap` entry is missing in `JOINING` or `VOTING`.
  - `L428-432`, `L556-561`: `default:` throws for an invalid `StateMachine` enum value.
  - `L473-477`, `L481-483`, `L883-885`, `L889-891`, `L898-900`: throws/returns if `sealing_recovery` or `recovery_decision_protocol` config is missing after timers were already started.
  - `L754-757`, `L831-835`, `L911-915`: throws if self is missing from `Tables::NODES`, `PREVIOUS_SERVICE_IDENTITY` is missing during recovery, or `get_view(last_recovered_signed_idx)` returns `VIEW_UNKNOWN`.
- **Why not covered**: Almost all are defensive internal consistency checks against corrupted KV tables or miswired configuration, except `L299-301` (`GOSSIPING` timeout with 0 gossips), which is reachable in real life if a node's self-gossip has not committed before `failover_timeout` fires.
- **Suggested test**: Add a C++ unit test (e.g., a new `src/node/test/recovery_decision_protocol.cpp`) driving `RecoveryDecisionProtocolSubsystem::advance` directly on an in-memory KV store to cover `L299-301` (gossiping timeout with empty gossips, which also exercises the `catch (const std::logic_error&)` handler in `self_healing_open_handlers.h`), plus key missing-state error checks (`L251-254`, `L387-390`, `L395-399`).
  Consider removing the unreachable duplicate check at `L316-318`.

## `src/node/rpc/self_healing_open_handlers.h` (82 uncovered lines, 13 missed branch outcomes)

### Missing subsystems or unconfigured node rejections (L40-45, L52-57, L335-340, L347-352)

- **Uncovered lines**: `40, 41, 42, 43, 44, 45, 52, 53, 54, 55, 56, 57, 335, 336, 337, 338, 339, 340, 347, 348, 349, 350, 351, 352` (24 lines).
- **What it does**: Returns `400 InvalidNodeState` from `/recovery_decision_protocol/{gossip,vote,iamopen,timeout}` when `NodeConfigurationSubsystem`/`AbstractNodeOperation` are unavailable (`L40-45`, `L335-340`) or when `sealing_recovery.recovery_decision_protocol` is not configured (`L52-57`, `L347-352`).
- **Why not covered**: The recovery endpoints are only ever called during SNP recovery tests where the protocol is configured and subsystems are registered.
- **Suggested test**: Add virtual C++ unit tests in `src/node/rpc/test/node_frontend_test.cpp` (no SNP hardware required) sending `PUT /node/recovery_decision_protocol/gossip` and `PUT /node/recovery_decision_protocol/timeout` to a `NodeFrontend` without `recovery_decision_protocol` configured (and with a stub context missing subsystems), asserting `400 InvalidNodeState`.

### Invalid quote rejection (L71-80)

- **Uncovered lines**: `71, 72, 73, 74, 75, 76, 77, 78, 79, 80` (10 lines).
- **What it does**: Rejects an incoming `gossip`, `vote`, or `iamopen` request when `node_operation->verify_quote(...) != QuoteVerificationResult::Verified`, returning `InvalidQuote`.
- **Why not covered**: Security-critical validation path (`Validation.rejected` in `DisasterRecovery/Model/Local.lean`) that is never triggered by the happy-path SNP recovery tests.
- **Suggested test**: Add a C++ unit test in `src/node/rpc/test/node_frontend_test.cpp` with a stub `NodeOperation` returning a non-`Verified` `QuoteVerificationResult` (e.g., `FailedInvalidQuotedPublicKey`) on `/recovery_decision_protocol/gossip`, asserting the request fails with `InvalidQuote` and leaves protocol KV tables unmodified.

### Changed certificate public key rejection (L100-109)

- **Uncovered lines**: `100, 101, 102, 103, 104, 105, 106, 107, 108, 109` (10 lines).
- **What it does**: Rejects a message from a previously seen `info.location.name` if the TLS caller certificate's public key differs from `existing_node_info->node_cert_der` (`400 NodeAlreadyExists`).
- **Why not covered**: Security-critical equivocation/spoofing check (`Validation.rejected`) never triggered because honest recovery peers keep a single keypair in SNP tests.
- **Suggested test**: Add a C++ unit test in `src/node/rpc/test/node_frontend_test.cpp` sending two messages for the same `location.name` signed with two different client certificates (both passing stubbed quote verification), asserting the second is rejected with `400 NodeAlreadyExists` and does not overwrite `NodeInfoMap` or advance state.

### `advance()` `std::logic_error` catch blocks and unset `SMState` in `iamopen` (L139-147, L261-264, L387-395)

- **Uncovered lines**: `139, 140, 141, 142, 143, 144, 145, 146, 147, 261, 262, 263, 264, 387, 388, 389, 390, 391, 392, 393, 394, 395` (22 lines).
- **What it does**:
  - `L139-147`, `L387-395`: catches `std::logic_error` thrown by `advance()` in `wrap_recovery_decision_protocol` and `recovery_decision_protocol_timeout`, returning `500 InternalError`.
  - `L261-264`: throws `std::logic_error` in `recovery_decision_protocol_iamopen` if `RECOVERY_DECISION_PROTOCOL_SM_STATE` is not set.
- **Why not covered**: No test sends protocol requests before `try_start()` initializes `SMState` or fires a timeout when `Gossips` is empty.
- **Suggested test**: Add unit tests in `src/node/rpc/test/node_frontend_test.cpp` sending `gossip`, `iamopen`, and `timeout` before `SMState` is initialized (or sending `timeout` with `SMState == GOSSIPING` and empty `Gossips`), asserting `500 InternalError`.

### Timeout primary-origin authorization checks (L359-365, L369-377)

- **Uncovered lines**: `359, 360, 361, 362, 363, 364, 365, 369, 370, 371, 372, 373, 374, 375, 376, 377` (16 lines).
- **What it does**: Rejects `PUT /recovery_decision_protocol/timeout` with `500 InternalError` if `node_operation->get_primary()` is `std::nullopt` (`L359-365`) or does not match the authenticated caller's `NodeCertAuthnIdentity::node_id` (`L369-377`).
- **Why not covered**: In single-node recovery clusters during SNP tests, every timeout request is self-sent by the sole primary node.
- **Suggested test**: Add unit tests in `src/node/rpc/test/node_frontend_test.cpp` calling `/recovery_decision_protocol/timeout` (1) when `get_primary()` returns `std::nullopt`, and (2) when the caller node certificate belongs to a non-primary node ID, verifying both are rejected without advancing state.

## `include/ccf/service/tables/self_healing_open.h` (1 uncovered line, 0 missed branch outcomes)

### `Location::operator==` (L26)

- **Uncovered lines**: `26` (1 line).
- **What it does**: Defaulted equality operator `bool operator==(const Location&) const = default`.
- **Why not covered**: `RecoveryDecisionProtocolConfig::operator==` is never called in tests (nor is `Location` compared directly with `==`).
- **Suggested test**: Add a round-trip JSON + equality check for `sealing_recovery::Location` / `RecoveryDecisionProtocolConfig` in a node config unit test, or omit if `operator==` is only for config comparison boilerplate.
