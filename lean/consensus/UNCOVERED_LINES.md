# Consensus (`lean/consensus`) Uncovered Lines Analysis

This document inventories every uncovered line in the masked in-scope implementation files mapped to `lean/consensus` in [`lean/COVERAGE_MAPPING.md`](../COVERAGE_MAPPING.md) and [`lean/consensus/coverage_mask.json`](coverage_mask.json), explains why each block is not executed in CI, and recommends tests where coverage is actionable.

Coverage data comes from `microsoft/CCF` Coverage run #997 (ID `45962731034`, `main` commit `6a9d9d870`, artifact `coverage-export-json`), which merges virtual unit/e2e/partition tests with SNP Genoa coverage and deduplicates branches per source location.

## Summary

| File                                                                     | Missed Lines | Total Lines |   Line Cov | Missed Branches | Total Branches | Branch Cov | Notes                                                                                       |
| ------------------------------------------------------------------------ | -----------: | ----------: | ---------: | --------------: | -------------: | ---------: | ------------------------------------------------------------------------------------------- |
| [`src/consensus/aft/cft.h`](../../src/consensus/aft/cft.h)               |           67 |       1,807 |     96.29% |              35 |            460 |     92.39% | Mix of retirement edge cases, `find_successor` config scan, and defensive/canary guards     |
| [`src/consensus/aft/impl/state.h`](../../src/consensus/aft/impl/state.h) |            8 |          81 |     90.12% |               1 |             24 |     95.83% | Unused copy/assignment on `AtomicLeadershipState` and `end_of_view` `InvalidView` branch    |
| [`src/consensus/aft/cft_types.h`](../../src/consensus/aft/cft_types.h)   |            0 |           0 |          - |               0 |              0 |          - | Type declarations only once unmodeled `Store`/`Adaptor` and `std::formatter` are masked out |
| [`src/node/hooks.h`](../../src/node/hooks.h)                             |            6 |          58 |     89.66% |               1 |             20 |     95.00% | Defensive `default:` unknown `NodeStatus` throw                                             |
| **Total (in-scope masked)**                                              |       **81** |   **1,946** | **95.84%** |          **37** |        **504** | **92.66%** |                                                                                             |

Roughly 21 of the 81 uncovered lines represent genuinely testable protocol behavior (primarily retirement edge cases, `find_successor` tie-breaking across active configurations, and stale `commit()` early return).
The remaining ~60 lines are defensive `std::logic_error` / canary guards, unused copy boilerplate, or legacy wire fallbacks.

## `src/consensus/aft/cft.h` (67 uncovered lines, 35 missed branch outcomes)

### `replicate()` after `is_retired_committed()` (L684-690)

- **Uncovered lines**: `684, 685, 686, 687, 688, 689, 690` (7 lines).
- **What it does**: Rejects `replicate()` with `rollback(state->last_idx); return false;` when the primary has already committed its own retirement (`is_retired_committed()`).
- **Why not covered**: Once `set_retired_committed` commits, `become_retired` clears leadership (`LeadershipState::None`), so `can_replicate()` returns false before callers reach `replicate()`, and the preceding `!is_primary()` check normally triggers first.
  Reaching this branch requires `is_primary()` to still hold while `is_retired_committed()` is true (or calling `replicate()` directly in a test harness after retirement completes before stepping down).
- **Suggested test**: Add a unit test in `src/consensus/aft/test/main.cpp` or a CFT scenario in `tests/cft_scenarios/Scenarios/` that drives a primary through `retired_committed` and verifies `replicate()` rejects new entries; if `!is_primary()` always subsumes `is_retired_committed()` at entry, document or assert that invariant instead of keeping a dead rollback branch.

### `send_append_entries_range()` heartbeat suppression when retired-committed (L1074, L1077-1078)

- **Uncovered lines**: `1074, 1077, 1078` (3 lines).
- **What it does**: Skips sending empty heartbeats (`start_idx >= end_idx`) once `is_retired_committed()` is true while still allowing replication of remaining entries.
- **Why not covered**: After a primary commits its own retirement, it steps down and stops periodic heartbeats, so `send_append_entries_range()` is rarely invoked with `start_idx >= end_idx` while `is_retired_committed()` holds.
- **Suggested test**: Add a Lean CFT scenario in `tests/cft_scenarios/Scenarios/` (similar to `retire_one.lean` or `retired_committed_delayed_nomination.lean`) that forces a `periodic_one` / flush tick on a retired-committed node when peers are already caught up, verifying no heartbeat is sent.

### `recv_append_entries()` retaining conflicting suffix when `!is_new_follower` (L1305, L1312-1319)

- **Uncovered lines**: `1305, 1312, 1313, 1314, 1315, 1316, 1317, 1318, 1319` (9 lines).
- **What it does**: Emits a canary `LOG_ROLLBACK_INFO_FMT` and returns without rolling back when a follower receives a conflicting `AppendEntries` after `is_new_follower` has already been cleared.
- **Why not covered**: As the source comment notes, this is an intentionally unreachable canary branch under normal CFT safety: a single primary in a term never contradicts an earlier entry it already sent in the same term, and a new term resets `is_new_follower = true`.
- **Suggested test**: Add a unit test in `src/consensus/aft/test/main.cpp` crafting a synthetic Byzantine/corrupted same-term `AppendEntries` with a conflicting term after an initial rollback in the same term to verify the node refuses to roll back a second time and logs the canary.

### `execute_append_entries_sync()` non-`std::exception` catch-all (L1425-1429)

- **Uncovered lines**: `1425, 1426, 1427, 1428, 1429` (5 lines).
- **What it does**: `catch (...)` around running consensus hooks during follower entry execution, rolling back to `max(initial_last_idx, last_committable_index())` and sending a NACK.
- **Why not covered**: All CCF consensus hooks throw `std::exception` subclasses (handled by the preceding `catch (const std::exception&)` block), never non-`std::exception` objects.
- **Suggested test**: Add a unit test in `src/consensus/aft/test/main.cpp` using a stub hook that throws a non-`std::exception` value (e.g., `int`) to verify rollback and NACK behavior.

### `execute_append_entries_sync()` legacy `InvalidView` fallback on signature (L1462-1464)

- **Uncovered lines**: `1462, 1463, 1464` (3 lines).
- **What it does**: When a signature entry arrives with `r.term_of_idx == aft::ViewHistory::InvalidView` (0), records `state->view_history.update(1, r.term)`.
- **Why not covered**: Modern primaries always populate `r.term_of_idx` with the entry's actual term on every `AppendEntries` packet; `InvalidView` only arises from malformed or legacy packets.
- **Suggested test**: Add a unit test in `src/consensus/aft/test/main.cpp` delivering a crafted `AppendEntries` containing a signature with `term_of_idx == VIEW_UNKNOWN` (or remove if wire compatibility with pre-`term_of_idx` primaries is no longer needed).

### `become_candidate()` with empty configurations (L2100, L2104-2108)

- **Uncovered lines**: `2100, 2104, 2105, 2106, 2107, 2108` (6 lines).
- **What it does**: Aborts `become_candidate()` if `configurations.empty()`.
- **Why not covered**: Callers (`become_pre_vote_candidate`, `recv_propose_request_vote`, election timeout) require membership in an active configuration before starting an election, so `configurations` is non-empty whenever `become_candidate()` is reached in normal operation.
- **Suggested test**: Add a unit test in `src/consensus/aft/test/main.cpp` exercising an election proposal or candidate transition on a freshly initialized backup that has not yet received any configuration entry.

### `become_leader()` refusing leadership when `is_retired_committed()` (L2140-2142)

- **Uncovered lines**: `2140, 2141, 2142` (3 lines).
- **What it does**: Returns `false` from `become_leader()` if `is_retired_committed()` is true.
- **Why not covered**: `is_retired_committed()` already gates election start and clears `LeadershipState`, so a retired-committed node normally never collects a quorum and reaches `become_leader()`.
- **Suggested test**: Add a CFT scenario in `tests/cft_scenarios/Scenarios/` where a candidate's retirement confirmation commits (or is triggered) right before the deciding `RequestVoteResponse` arrives, verifying `become_leader()` refuses leadership.

### `find_successor()` configuration tie-breaker loop continuation (L2264-2265)

- **Uncovered lines**: `2264, 2265` (2 lines).
- **What it does**: Advances the reverse iterator `conf++` in `configurations` when a candidate peer is not in the newest configuration (searching earlier active configurations for its latest membership index).
- **Why not covered**: Existing `nominate_successor` scenarios only test peers that are already members of the newest configuration, so `conf->nodes.find(node)` succeeds on the first iteration (`break`) and never increments `conf`.
- **Suggested test**: Add a CFT scenario in `tests/cft_scenarios/Scenarios/` with two overlapping active configurations (where a retiring peer in the older configuration is absent from the newer uncommitted configuration) and invoke `nominate_successor`, exercising the reverse scan across `configurations` and verifying the peer in the newer configuration wins the tie-break.

### `add_vote_for_me()` empty configuration and invalid-state guards (L2334-2339, L2395-2402)

- **Uncovered lines**: `2334, 2335, 2336, 2337, 2338, 2339, 2395, 2396, 2397, 2398, 2399, 2400, 2401, 2402` (14 lines).
- **What it does**:
  - `L2334-2339`: early return when `configurations.empty()`.
  - `L2395-2402`: throws `std::logic_error` if `add_vote_for_me()` is called while in `None`, `Leader`, or `Follower` state.
- **Why not covered**: `add_vote_for_me()` is a private helper only called from `become_pre_vote_candidate`, `become_candidate`, `recv_request_vote_response`, and `recv_request_pre_vote_response` after checking role and configurations.
- **Suggested test**: Defensive invariant check; unreachable through the public API.

### `update_commit()` non-leader guard (L2416-2419)

- **Uncovered lines**: `2416, 2417, 2418, 2419` (4 lines).
- **What it does**: Defensive `std::logic_error` if `update_commit()` is invoked when not `Leader`.
- **Why not covered**: `update_commit()` is private and all call sites are guarded by `is_primary()`.
- **Suggested test**: Defensive invariant check; not reachable through the public API.

### `commit()` bounds and monotonicity guards (L2561-2564, L2571-2573)

- **Uncovered lines**: `2561, 2562, 2563, 2564, 2571, 2572, 2573` (7 lines).
- **What it does**:
  - `L2561-2564`: throws `std::logic_error` if `idx > state->last_idx`.
  - `L2571-2573`: returns early if `idx <= state->commit_idx`.
- **Why not covered**: Callers clamp `commit(idx)` to `last_idx` and usually check `idx > state->commit_idx` before calling `commit()`.
- **Suggested test**: `L2561-2564` is a defensive invariant check; for `L2571-2573`, add a CFT scenario in `tests/cft_scenarios/Scenarios/` where a follower receives an `AppendEntries` carrying a stale `leader_commit_idx <= commit_idx` (or where a newly elected primary with an already-committed prefix triggers `commit()` on a lower index).

### `rollback()` downgrading `RetirementPhase::Signed` back to `Ordered` (L2703-2706)

- **Uncovered lines**: `2703, 2704, 2705, 2706` (4 lines).
- **What it does**: When rolling back past `retirement_committable_idx` while keeping `retirement_idx` in the log, clears `retirement_committable_idx` and resets `retirement_phase` from `Signed` back to `Ordered`.
- **Why not covered**: Existing retirement rollback tests (`tests/cft_scenarios/Scenarios/retirement_rollback.lean`) roll back past `retirement_idx` itself (reverting all the way to `Active`), rather than rolling back strictly between `retirement_idx` and `retirement_committable_idx`.
- **Suggested test**: Add a CFT scenario in `tests/cft_scenarios/Scenarios/` (e.g., `retirement_signature_rollback.lean`) where a follower appends a retirement configuration at index `r` and a signature at index `s > r` (reaching `RetirementPhase::Signed`), then rolls back to an index `k` with `r <= k < s` from a new primary, asserting `retirement_phase == Ordered` and `retirement_committable_idx == nullopt`.

## `src/consensus/aft/impl/state.h` (8 uncovered lines, 1 missed branch outcome)

### `AtomicLeadershipState` copy constructor and copy assignment (L149, L152-158)

- **Uncovered lines**: `149, 152, 153, 154, 155, 156, 157, 158` (8 lines).
- **What it does**: Implements copy construction and copy assignment for `AtomicLeadershipState` (so `aft::State` remains copyable).
- **Why not covered**: `aft::State` is held by pointer/reference in `Aft` and never copied or copy-assigned during tests.
- **Suggested test**: Add a small unit test in `src/consensus/aft/test/main.cpp` copying and copy-assigning `AtomicLeadershipState` (including self-assignment), or delete copy operations on `AtomicLeadershipState` if copying `aft::State` is unused.
  Note that `ViewHistory::end_of_view()` (`L100`) also has one missed branch outcome on `view == InvalidView` because `start_of_view(InvalidView)` already returns `NoVersion` on the preceding line.

## `src/node/hooks.h` (6 uncovered lines, 1 missed branch outcome)

### `ConfigurationChangeHook` unknown `NodeStatus` guard (L74-79)

- **Uncovered lines**: `74, 75, 76, 77, 78, 79` (6 lines).
- **What it does**: Throws `std::logic_error` in the `default:` arm of `switch (ni.status)` if a `Nodes::Write` carries a `NodeStatus` other than `PENDING`, `TRUSTED`, or `RETIRED`.
- **Why not covered**: All valid `NodeStatus` enumerators are handled by explicit `case` arms.
- **Suggested test**: Defensive enum guard; coverable in a unit test only by casting an invalid underlying integer to `NodeStatus`.
