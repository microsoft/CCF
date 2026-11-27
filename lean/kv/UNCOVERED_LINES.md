# Key-Value Store (`lean/kv`) Uncovered Lines Analysis

This document inventories every uncovered line in the masked in-scope implementation files mapped to `lean/kv` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md) and [`lean/kv/coverage_mask.json`](coverage_mask.json), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #997 (ID `45962731034`, `main` commit `6a9d9d870`, artifact `coverage-export-json`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage and deduplicates branches per source location.

## Summary

| File                                                                                   | Missed Lines | Total Lines |   Line Cov | Missed Branches | Total Branches | Branch Cov | Notes                                                                   |
| -------------------------------------------------------------------------------------- | -----------: | ----------: | ---------: | --------------: | -------------: | ---------: | ----------------------------------------------------------------------- |
| [`src/kv/store.h`](../../src/kv/store.h)                                               |           11 |         321 |     96.57% |               7 |             62 |     88.71% | 64-bit wraparound guard and unexpected `PendingTx` failure log          |
| [`src/kv/untyped_map.h`](../../src/kv/untyped_map.h)                                   |            3 |         198 |     98.48% |               1 |             46 |     97.83% | Defensive `dynamic_cast` type-confusion throw in `create_committer`     |
| [`src/kv/tx.cpp`](../../src/kv/tx.cpp)                                                 |           15 |          85 |     82.35% |               4 |             16 |     75.00% | All 15 lines are defensive `std::logic_error` internal invariant checks |
| [`src/kv/committable_tx.h`](../../src/kv/committable_tx.h)                             |           13 |         175 |     92.57% |               0 |             30 |    100.00% | Unused `CommittableTx::commit_term()`                                   |
| [`src/kv/apply_changes.h`](../../src/kv/apply_changes.h)                               |            0 |          82 |    100.00% |               1 |             40 |     97.50% | 100% lines; 1 missed branch outcome on `L134`                           |
| [`src/kv/untyped_change_set.h`](../../src/kv/untyped_change_set.h)                     |            0 |          10 |    100.00% |               0 |              0 |          - | Fully covered                                                           |
| [`src/kv/untyped_map_handle.cpp`](../../src/kv/untyped_map_handle.cpp)                 |            0 |         202 |    100.00% |               0 |             44 |    100.00% | Fully covered                                                           |
| [`include/ccf/kv/tx.h`](../../include/ccf/kv/tx.h)                                     |            0 |          50 |    100.00% |               0 |              8 |    100.00% | Fully covered                                                           |
| [`src/kv/compacted_version_conflict.h`](../../src/kv/compacted_version_conflict.h)     |            0 |           4 |    100.00% |               0 |              0 |          - | Fully covered                                                           |
| [`src/kv/version_v.h`](../../src/kv/version_v.h)                                       |            0 |           2 |    100.00% |               0 |              0 |          - | Fully covered                                                           |
| `include/ccf/kv/untyped_map_handle.h`, `src/kv/tx_pimpl.h`, `include/ccf/kv/version.h` |            0 |           0 |          - |               0 |              0 |          - | Declarations/types only (0 instrumented lines)                          |
| **Total (in-scope masked)**                                                            |       **42** |   **1,129** | **96.28%** |          **13** |        **246** | **94.72%** |                                                                         |

Every line inside the core transactional operations modeled by `lean/kv` (`untyped_map_handle.cpp`, `apply_changes.h`, `untyped_change_set.h`, `tx.h`, `compacted_version_conflict.h`, `version_v.h`) is at **100% line coverage**.
The 42 remaining uncovered lines consist of one unused public getter (`CommittableTx::commit_term()`, 13 lines) and 29 lines of defensive internal invariant checks.

## `src/kv/store.h` (11 uncovered lines, 7 missed branch outcomes)

### `next_version_unsafe()` 64-bit signed-max wraparound guard (L210-213)

- **Uncovered lines**: `210, 211, 212, 213` (4 lines).
- **What it does**: Wraps `version` back to `0` if it exceeds `std::numeric_limits<int64_t>::max()`.
- **Why not covered**: Unreachable in practice without executing 2^63 transactions (or injecting a near-max snapshot version).
- **Suggested test**: Optional unit test in `src/kv/test/kv_snapshot.cpp` installing a snapshot at version `INT64_MAX` and committing one transaction to observe the wraparound behavior (or replacing wrap-to-0 with a fatal error, since wrapping to `0` would violate version monotonicity).

### `commit()` unexpected non-`SUCCESS` result from `PendingTx` (L1278-1284)

- **Uncovered lines**: `1278, 1279, 1280, 1281, 1282, 1283, 1284` (7 lines).
- **What it does**: Logs an unexpected failure reason when `pending_tx->call()` returns neither `SUCCESS` nor `FAIL_NO_REPLICATE` (the latter handled just above).
- **Why not covered**: As the comment states, normal transactions have already passed conflict detection (`MovePendingTx` always returns `SUCCESS`) and reserved transactions only return `SUCCESS` or `FAIL_NO_REPLICATE`.
- **Suggested test**: Add a unit test in `src/kv/test/kv_test.cpp` with a custom `PendingTx` returning `CommitResult::FAIL_CONFLICT` to exercise the diagnostic log, or keep as a defensive check.

## `src/kv/untyped_map.h` (3 uncovered lines, 1 missed branch outcome)

### `create_committer()` type-confusion guard (L526-528)

- **Uncovered lines**: `526, 527, 528` (3 lines).
- **What it does**: Throws `std::logic_error("Type confusion error")` if `dynamic_cast<ChangeSet*>(changes)` is `nullptr`.
- **Why not covered**: Only `untyped::ChangeSet` (and its subclass `SnapshotChangeSet`) is ever passed.
- **Suggested test**: Defensive check; testable only by passing a mock `AbstractChangeSet` in `src/kv/test/kv_test.cpp`.

## `src/kv/tx.cpp` (15 uncovered lines, 4 missed branch outcomes)

### Internal invariant `std::logic_error` guards (L34-37, L78-80, L95-98, L125-128)

- **Uncovered lines**: `34, 35, 36, 37, 78, 79, 80, 95, 96, 97, 98, 125, 126, 127, 128` (15 lines).
- **What it does**:
  - `L34-37`: `BaseTx::retain_change_set` throws if `map_name` already exists in `all_changes`.
  - `L78-80`: `BaseTx::get_map_and_change_set_by_name` throws if a dynamically created map is already in `created_maps` without an entry in `all_changes`.
  - `L95-98`: throws if `store->get_map(...)` returns a non-`untyped::Map` implementation.
  - `L125-128`: `BaseTx::compacted_version_conflict` throws if `read_txid` was not set before reporting a compacted-version conflict.
- **Why not covered**: All four are `protected` helper methods only invoked by `BaseTx::get_handle_by_name`, which always checks `all_changes` first, sets `read_txid` on first access, and only uses `untyped::Map` in `Store`.
- **Suggested test**: Defensive internal invariants; none are reachable via the public `BaseTx`/`Tx` API without subclassing `BaseTx` or injecting a custom `AbstractStore`/`AbstractMap`.

## `src/kv/committable_tx.h` (13 uncovered lines, 0 missed branch outcomes)

### `CommittableTx::commit_term()` (L438-450)

- **Uncovered lines**: `438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450` (13 lines).
- **What it does**: Public accessor returning `pimpl->commit_view` after verifying `committed` and `success`.
- **Why not covered**: Callers use `get_txid()` (which returns both view and seqno) rather than `commit_term()`, so `commit_term()` is never called in CCF or its tests.
- **Suggested test**: Add unit tests in `src/kv/test/kv_test.cpp` covering `commit_term()` before commit (throws), after conflict (throws), and after successful commit (returns expected view), or remove `commit_term()` if unused.
