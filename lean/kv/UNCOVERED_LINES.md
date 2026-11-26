# Key-Value Store (`lean/kv`) Uncovered Lines Analysis

This document inventories every uncovered line in the core implementation files mapped to `lean/kv` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #988 (ID `45850573035`, artifacts `coverage-history-main` and `coverage-report-html` on `main`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage.

## Summary

| File                                                                                   | Missed Lines | Total Lines |   Line Cov | Notes                                                                                       |
| -------------------------------------------------------------------------------------- | -----------: | ----------: | ---------: | ------------------------------------------------------------------------------------------- |
| [`src/kv/store.h`](../../src/kv/store.h)                                               |           23 |       1,038 |     97.78% | Unmodeled snapshot/deserialise error paths, wrap-around guard, 1 LLVM range-for quirk       |
| [`src/kv/untyped_map.h`](../../src/kv/untyped_map.h)                                   |           27 |         470 |     94.26% | Unmodeled legacy read-set deserialisation, `Map::clear()`, type-mismatch guards             |
| [`src/kv/tx.cpp`](../../src/kv/tx.cpp)                                                 |           15 |          85 |     82.35% | All 15 lines are defensive `std::logic_error` internal invariant checks                     |
| [`src/kv/committable_tx.h`](../../src/kv/committable_tx.h)                             |           47 |         380 |     87.63% | Unused `commit_term()`, redundant `serialise()` preconditions, unmodeled `ReservedTx` races |
| [`src/kv/untyped_change_set.h`](../../src/kv/untyped_change_set.h)                     |            0 |          69 |    100.00% | Fully covered                                                                               |
| [`src/kv/untyped_map_handle.cpp`](../../src/kv/untyped_map_handle.cpp)                 |            0 |         202 |    100.00% | Fully covered                                                                               |
| [`src/kv/apply_changes.h`](../../src/kv/apply_changes.h)                               |            0 |         100 |    100.00% | Fully covered                                                                               |
| [`include/ccf/kv/tx.h`](../../include/ccf/kv/tx.h)                                     |            0 |          59 |    100.00% | Fully covered                                                                               |
| [`src/kv/compacted_version_conflict.h`](../../src/kv/compacted_version_conflict.h)     |            0 |           4 |    100.00% | Fully covered                                                                               |
| [`src/kv/version_v.h`](../../src/kv/version_v.h)                                       |            0 |           2 |    100.00% | Fully covered                                                                               |
| `include/ccf/kv/untyped_map_handle.h`, `src/kv/tx_pimpl.h`, `include/ccf/kv/version.h` |            0 |           0 |          - | Declarations/types only (0 instrumented lines)                                              |
| **Total**                                                                              |      **112** |   **2,409** | **95.35%** |                                                                                             |

Notably, every line inside the core transactional operations modeled by `lean/kv` (`untyped_map_handle.cpp`, `apply_changes.h`, `untyped_change_set.h`, `tx.h`, and the modeled paths of `store.h` and `untyped_map.h`) is already at or near 100% line coverage.
The 112 uncovered lines fall into unmodeled serialization/snapshot/reserved-tx paths, unused methods (`commit_term()`, `Map::clear()`, `SnapshotPublicMaps::operator=`), defensive `std::logic_error` checks, and one LLVM range-for coverage artifact.

## `src/kv/store.h` (23 uncovered lines)

### `commit_deserialised()` apply failure (L176-179)

- **Uncovered lines**: `176, 177, 178, 179` (4 lines).
- **What it does**: Logs failure and returns `false` if `apply_changes` fails while committing a deserialised transaction.
- **Why not covered**: Unmodeled path (`commit deserialised`).
  Deserialised entries do not carry read-set dependencies in modern CCF ledgers and are applied sequentially during replication/recovery, so `apply_changes` does not fail in normal runs.
- **Suggested test**: Add a unit test in `src/kv/test/kv_serialisation.cpp` that deserialises a transaction carrying a legacy conflicting read set (or races a map creation) to verify `commit_deserialised` returns `false`.

### `next_version_unsafe()` 64-bit signed-max wraparound guard (L210-213)

- **Uncovered lines**: `210, 211, 212, 213` (4 lines).
- **What it does**: Wraps `version` back to `0` if it exceeds `std::numeric_limits<int64_t>::max()`.
- **Why not covered**: Unreachable in practice without executing 2^63 transactions (or injecting a near-max snapshot version).
- **Suggested test**: Optional unit test in `src/kv/test/kv_snapshot.cpp` installing a snapshot at version `INT64_MAX` and committing one transaction to observe the wraparound behavior (or replacing wrap-to-0 with a fatal error, since wrapping to `0` would violate version monotonicity).

### `SnapshotPublicMaps` move-assignment operator (L533)

- **Uncovered lines**: `533` (1 line).
- **What it does**: Defaulted move-assignment operator `SnapshotPublicMaps& operator=(SnapshotPublicMaps&&) noexcept = default`.
- **Why not covered**: Unmodeled snapshot optimization path; callers only move-construct or emplace `std::optional<SnapshotPublicMaps>`, never move-assign directly.
- **Suggested test**: Add a trivial move-assignment assertion in `src/kv/test/kv_snapshot.cpp`, or omit if move-assignment is unused.

### `deserialise_snapshot_internal()` `apply_changes` failure (L784-788)

- **Uncovered lines**: `784, 785, 786, 787, 788` (5 lines).
- **What it does**: Logs failure and returns `ApplyResult::FAIL` if `apply_changes` returns `std::nullopt` during snapshot installation.
- **Why not covered**: Unmodeled snapshot path.
  `SnapshotHandleCommitter::prepare()` unconditionally returns `true` and `maps_lock` is held so no concurrent dynamic map creation can collide with `new_maps`, making `apply_changes` failure unreachable.
- **Suggested test**: Defensive guard; unreachable under the current locking protocol.

### `rollback()` range-for header (L983)

- **Uncovered lines**: `983` (1 line).
- **What it does**: `for (auto& it : maps)` locking every map during `Store::rollback`.
- **Why not covered**: LLVM source-based coverage artifact: lines 984-987 inside the loop body executed 1,190 times and line 981 before it executed 88 times, yet `llvm-cov` assigns count `0` to the range-for header line.
- **Suggested test**: None needed; the loop is already heavily exercised.

### `commit()` unexpected non-`SUCCESS` result from `PendingTx` (L1278-1284)

- **Uncovered lines**: `1278, 1279, 1280, 1281, 1282, 1283, 1284` (7 lines).
- **What it does**: Logs an unexpected failure reason when `pending_tx->call()` returns neither `SUCCESS` nor `FAIL_NO_REPLICATE` (the latter handled just above).
- **Why not covered**: As the comment states, normal transactions have already passed conflict detection (`MovePendingTx` always returns `SUCCESS`) and reserved transactions only return `SUCCESS` or `FAIL_NO_REPLICATE`.
- **Suggested test**: Add a unit test in `src/kv/test/kv_test.cpp` with a custom `PendingTx` returning `CommitResult::FAIL_CONFLICT` to exercise the diagnostic log, or keep as a defensive check.

### `should_schedule_snapshot()` without a snapshotter (L1349)

- **Uncovered lines**: `1349` (1 line).
- **What it does**: Returns `false` when `snapshotter == nullptr`.
- **Why not covered**: Unmodeled snapshotter helper; every node calling `should_schedule_snapshot()` has a snapshotter attached.
- **Suggested test**: Add a unit test in `src/kv/test/kv_snapshot.cpp` calling `store.should_schedule_snapshot()` on a fresh `Store` with no snapshotter attached and checking it returns `false`.

## `src/kv/untyped_map.h` (27 uncovered lines)

### `serialise_changes()` `ChangeSet` type-mismatch guard (L323-326)

- **Uncovered lines**: `323, 324, 325, 326` (4 lines).
- **What it does**: Logs an error and returns if `dynamic_cast<const untyped::ChangeSet*>(changes)` fails.
- **Why not covered**: `untyped::ChangeSet` is the only `AbstractChangeSet` implementation used with `untyped::Map`.
- **Suggested test**: Defensive runtime type check; could be covered in `src/kv/test/kv_test.cpp` with a dummy `AbstractChangeSet` subclass if desired.

### `deserialise_internal()` unavailable change set and legacy read-set deserialisation (L479-485, L493-495, L499-502)

- **Uncovered lines**: `479, 480, 481, 482, 483, 484, 485, 493, 494, 495, 499, 500, 501, 502` (14 lines).
- **What it does**:
  - `L479-485`: throws `std::logic_error("Can't create change set")` if `create_change_set(version, false)` returns `nullptr` during ledger deserialisation (e.g., `version` already compacted).
  - `L493-495`, `L499-502`: populates `change_set.read_version` and `change_set.reads` from legacy ledger entries that serialized read sets.
- **Why not covered**: Unmodeled path (`map deserialisation`).
  Modern `serialise_changes` always writes `NoVersion` and `0` reads for wire compatibility, so non-empty read sets never appear in newly serialized entries, and deserialisation tests do not target compacted versions.
- **Suggested test**: Add two unit tests in `src/kv/test/kv_serialisation.cpp`: (1) feed a crafted legacy serialized entry with non-zero `read_version` and at least one read-set entry to verify backward-compatible parsing; (2) call `deserialise` at a version older than `compacted` to verify the `std::logic_error` throw.

### `create_committer()` type-confusion guard (L526-528)

- **Uncovered lines**: `526, 527, 528` (3 lines).
- **What it does**: Throws `std::logic_error("Type confusion error")` if `dynamic_cast<ChangeSet*>(changes)` is `nullptr`.
- **Why not covered**: Only `untyped::ChangeSet` (and its subclass `SnapshotChangeSet`) is ever passed.
- **Suggested test**: Defensive check; testable only by passing a mock `AbstractChangeSet` in `src/kv/test/kv_test.cpp`.

### `Map::clear()` outside a transaction (L706-708, L711-713)

- **Uncovered lines**: `706, 707, 708, 711, 712, 713` (6 lines).
- **What it does**: Resets `roll` commits and `rollback_counter` directly on a `Map` (explicitly marked `unsupported: "map clear outside transaction"` in `KV_TRACE`).
- **Why not covered**: No production code or unit test calls `AbstractMap::clear()` directly; callers clear the whole store or use transactional `MapHandle::clear()`.
- **Suggested test**: Either remove `AbstractMap::clear()` if it is dead code, or add a unit test in `src/kv/test/kv_test.cpp` verifying `roll` reset behavior.

## `src/kv/tx.cpp` (15 uncovered lines)

### Internal invariant `std::logic_error` guards (L34-37, L78-80, L95-98, L125-128)

- **Uncovered lines**: `34, 35, 36, 37, 78, 79, 80, 95, 96, 97, 98, 125, 126, 127, 128` (15 lines).
- **What it does**:
  - `L34-37`: `BaseTx::retain_change_set` throws if `map_name` already exists in `all_changes`.
  - `L78-80`: `BaseTx::get_map_and_change_set_by_name` throws if a dynamically created map is already in `created_maps` without an entry in `all_changes`.
  - `L95-98`: throws if `store->get_map(...)` returns a non-`untyped::Map` implementation.
  - `L125-128`: `BaseTx::compacted_version_conflict` throws if `read_txid` was not set before reporting a compacted-version conflict.
- **Why not covered**: All four are `protected` helper methods only invoked by `BaseTx::get_handle_by_name`, which always checks `all_changes` first, sets `read_txid` on first access, and only uses `untyped::Map` in `Store`.
- **Suggested test**: Defensive internal invariants; none are reachable via the public `BaseTx`/`Tx` API without subclassing `BaseTx` or injecting a custom `AbstractStore`/`AbstractMap`.

## `src/kv/committable_tx.h` (47 uncovered lines)

### `CommittableTx::serialise()` defensive preconditions (L127-129, L132-134, L137-139, L142-144, L148-150)

- **Uncovered lines**: `127, 128, 129, 132, 133, 134, 137, 138, 139, 142, 143, 144, 148, 149, 150` (15 lines).
- **What it does**: Checks `!committed`, `!success`, `claims_digest_.empty()`, `!has_writes()`, and `encryptor == nullptr` inside `protected` `CommittableTx::serialise()`.
- **Why not covered**: `serialise()` is only called from `commit()` and `commit_reserved()`, both of which already verify `committed`, `success`, `has_writes()`, `claims` (via `projected_serialised_size`), and `encryptor` before calling `serialise()`.
- **Suggested test**: Redundant defensive guards inside a `protected` helper; only reachable via a test subclass calling `serialise()` directly.

### `CommittableTx::commit()` `apply_tx_flags` rollback-count guard and concurrent rollback race (L335-338, L346-349)

- **Uncovered lines**: `335, 336, 337, 338, 346, 347, 348, 349` (8 lines).
- **What it does**:
  - `L335-338`: throws `std::logic_error` if `expected_rollback_count` was not populated when a write version was allocated.
  - `L346-349`: returns `CommitResult::FAIL_NO_REPLICATE` if `store->apply_tx_flags(...)` rejects `LEDGER_CHUNK_AT_NEXT_SIGNATURE` or `SNAPSHOT_AT_NEXT_SIGNATURE` because a concurrent rollback occurred between `apply_changes` and `apply_tx_flags`.
- **Why not covered**: Unmodeled `TxFlag` path.
  `L335-338` is an unreachable defensive check (`next_version` always sets `expected_rollback_count`); `L346-349` requires a concurrent rollback to land in the narrow window after `apply_changes` releases map locks and before `apply_tx_flags` runs.
- **Suggested test**: Add a unit test in `src/kv/test/kv_test.cpp` (using a custom `AbstractStore` or concurrent hook/barrier) that triggers a rollback between `next_version` and `apply_tx_flags` on a transaction with `SNAPSHOT_AT_NEXT_SIGNATURE` set, verifying `FAIL_NO_REPLICATE` and that the flag is not armed.

### `CommittableTx::commit_term()` (L438-450)

- **Uncovered lines**: `438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450` (13 lines).
- **What it does**: Public accessor returning `pimpl->commit_view` after verifying `committed` and `success`.
- **Why not covered**: Callers use `get_txid()` (which returns both view and seqno) rather than `commit_term()`, so `commit_term()` is never called in CCF or its tests.
- **Suggested test**: Add unit tests in `src/kv/test/kv_test.cpp` covering `commit_term()` before commit (throws), after conflict (throws), and after successful commit (returns expected view), or remove `commit_term()` if unused.

### `CommittableTx::set_read_txid()` double-set guard (L482-484)

- **Uncovered lines**: `482, 483, 484` (3 lines).
- **What it does**: Throws `std::logic_error("Read TxID already set")` if `set_read_txid()` is called after `read_txid` is already populated.
- **Why not covered**: Unmodeled helper (`explicit read transaction ID`); tests only call `set_read_txid()` once on a fresh transaction.
- **Suggested test**: Add a `CHECK_THROWS_AS(tx.set_read_txid(...), std::logic_error)` test in `src/kv/test/kv_test.cpp` calling `set_read_txid()` twice (or after acquiring a handle).

### `ReservedTx::commit_reserved()` failure and concurrent-rollback chunk check (L580-582, L601-605)

- **Uncovered lines**: `580, 581, 582, 601, 602, 603, 604, 605` (8 lines).
- **What it does**:
  - `L580-582`: throws `std::logic_error("Failed to commit reserved transaction")` if `apply_changes` fails even though `check_rollback_count(rollback_count)` still matches (should be impossible because reserved signature transactions perform no reads).
  - `L601-605`: returns `CommitResult::FAIL_NO_REPLICATE` if `should_create_ledger_chunk_for_reserved_tx` returns `std::nullopt` because a concurrent rollback occurred between `apply_changes` and the chunk check.
- **Why not covered**: Unmodeled `ReservedTx` path.
  `L580-582` is a defensive invariant check; `L601-605` requires a rollback to interleave right between `apply_changes` and `should_create_ledger_chunk_for_reserved_tx`.
- **Suggested test**: Add a unit test in `src/kv/test/kv_test.cpp` where a `MapHook` on the signature table triggers a store rollback during `apply_changes`'s `post_commit()` so `should_create_ledger_chunk_for_reserved_tx` observes a changed rollback count and returns `FAIL_NO_REPLICATE`.
