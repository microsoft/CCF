# Recorded failure: whole-map dependency at revision zero

## Conclusion

The rejection at event **168** is a **whole-map read-dependency mismatch for
`fuzz.4`**, not a term, rollback-lineage, snapshot-availability, or write-set
mismatch.

The model records an empty map in this transaction's current-state snapshot,
before overlaying its own writes. At application time, another transaction has
added an entry to that map, so the dependency no longer holds.

The C++ implementation uses **zero both as a valid initial map revision and as
`NoVersion`**, the marker for an absent whole-map read dependency. Iteration
records revision zero, but the commit validator interprets it as "no whole-map
read", and skips the comparison with the now-current map revision.

This analysis uses the existing saved execution and an offline walk through the
model's actual transition and dependency functions. No C++ workload was rerun,
and no implementation, model, or fuzzer behavior was changed.

## Evidence identity

| Item                       | Recorded value                                                            |
| -------------------------- | ------------------------------------------------------------------------- |
| Campaign                   | `build-kv-trace/kv-fuzz/campaign-pjwoyln0`                                |
| Fuzzer configuration       | Seed 1; 4 workers; 24 transaction slots per worker; 8 operations per slot |
| Rejected event             | `apply`, sequence 168, store 1, transaction 4, proposed local version 5   |
| Accepted model prefix      | 167 events                                                                |
| Actual C++ result          | `success`, version 5, at event 336; the C++ testcase exited zero          |
| Complete captured file     | 3,688 events, ending with a `trace_end` count of 3,687                    |
| Source revision in sidecar | `e9cb2af6bb7a777898158e84af1757da3cd3d0e9`                                |
| Compiler/build             | Ubuntu Clang 21.1.8; `CCF_KV_TRACING`; schema 1                           |
| KV binary SHA-256          | `1490f0d1e39ab2e99783881324857ebb8f956b3059b2dd79e8f2ded23281e7fe`        |
| Checker SHA-256            | `88791c1e147406f8beb18688b2e9a11a74c5ca3bf1bea56059be7ac6c691232f`        |
| Full trace SHA-256         | `0a156c3541f950336c290dcf9bae27b851c415d0a63952bac7a0c53e69f54a70`        |
| Rejected prefix SHA-256    | `3cf48fa4df92452962d0475ca94ab9079a12ea3e2ff1f57444dbaca1b1a038cd`        |

The sidecar revision is the committed base of a workspace containing the new
fuzzer. The binary hashes identify the actual execution artifacts; this is not a
claim about an independently built release.

The seed identifies generated program choices, not a deterministic OS schedule.
This report concerns this saved execution, not a different earlier seed-1
capture whose first rejection had a different event number.

The full trace, rejected prefix, checker output, and metadata sidecar are in the
campaign's `seed-0001` directory. The offline predicate result is saved there as
`model-diagnosis.json`. These are generated local artifacts, not checked-in
reproduction programs.

## Exact model condition

Walking the unchanged model through the prefix gives the following state
immediately before event 168:

| Condition                                        | Result                                                   |
| ------------------------------------------------ | -------------------------------------------------------- |
| Transaction phase                                | `committing`                                             |
| Captured current cut                             | 1                                                        |
| Local head / global cut                          | 4 / 3                                                    |
| Store term / captured commit term                | 0 / 0                                                    |
| Snapshot marked unavailable                      | No                                                       |
| Lineage of both acquired maps                    | Valid                                                    |
| Nonempty staged writes                           | Yes                                                      |
| Logged writes unique and equal to pending writes | Yes                                                      |
| Proposed version and term                        | Valid: next local version 5, term 0                      |
| Individual key dependency                        | Holds                                                    |
| Whole-map dependencies                           | **Two copies of the `fuzz.4` empty-map dependency fail** |

`canApply` (now in `Kv/Protocol/Model.lean`) combines availability, lineage, and dependency
validation. Here `validLineage` is true and `unavailable` is false, but
`validates` is false.

The only individual key dependency is an earlier absence read of `k3` in
`fuzz.4` (key bytes `6b33`). That key is still absent from the stored local state
before transaction 4 applies, so this dependency passes. Transaction 4 has its
own pending write at that key; reads of that pending write introduce no new
dependency on the stored snapshot.

The two map dependencies come from the iterations beginning at events 82 and 115. `needs` records the underlying snapshot's map image, not the overlay of
pending writes. That image is empty in both cases. At the rejected application,
the current image contains one different key, with bytes `006b`, written by
transaction 5 at local version 4 (event 138). Both map-dependency comparisons
therefore fail.

The other acquired map, `fuzz.1`, has also changed since capture, but transaction
4 did not record a dependency on its stored snapshot. Its operations there
are pending writes/deletions and reads of its own deletions. That map is not the
reason for rejection.

## Why C++ accepts the application

The relevant implementation behavior is:

1. **Map creation need not advance its effective revision.** The initial
   transaction's missing-key deletion causes `fuzz.4` to be registered at store
   version 1. Normal commits do not track missing-key deletions as effective
   changes, so its map history still contains the initial empty revision zero.
   This is an existing empty map, not a map transaction 4 is trying to create.
2. **Acquisition retains that map revision.** `create_change_set` passes the
   selected map-history entry's version to `ChangeSet::start_version`.
   Transaction 4's acquisition at event 41 consequently reports map revision
   zero, although its transaction-wide current cut is 1.
3. **Iteration records zero.** `foreach_state_and_writes` assigns
   `read_version = start_version`. The transaction's own pending entries make
   its iterations nonempty, but do not change `start_version`.
4. **Validation skips the map dependency.** `HandleCommitter::prepare` compares
   the recorded map-read version with the current map version only when
   `read_version != NoVersion`. Both values are zero here, so it never compares
   the recorded zero with current revision 4.
5. **The remaining checks pass.** No rollback occurred in this prefix; the
   individual absence dependency still holds; the maps already exist; and the
   commit term remains valid. C++ allocates local version 5 and later reports
   success.

The logged `apply` is not merely a commit request. `apply_changes` validates the
map committers while holding their locks before resolving the new version.
Transaction 5 and transaction 4 access the same maps, so the prior application
cannot be reordered past transaction 4's map validation merely because commit
return messages are delayed.

Relevant source locations at the time of analysis:

| Source                                | Relevant behavior                                                     |
| ------------------------------------- | --------------------------------------------------------------------- |
| `include/ccf/kv/version.h:11`         | `NoVersion` is zero                                                   |
| `src/kv/untyped_change_set.h:46-62`   | Initial read marker and captured `start_version`                      |
| `src/kv/untyped_map_handle.cpp:11-49` | Own-write reads and recording the whole-map dependency                |
| `src/kv/untyped_map.h:147-197`        | Rollback, map-wide, and per-key validation                            |
| `src/kv/untyped_map.h:202-250`        | Missing-key deletion and conditional history insertion                |
| `src/kv/untyped_map.h:797-830`        | Map revision selected when creating a change set                      |
| `src/kv/apply_changes.h:78-151`       | Validation, dynamic-map registration, version resolution, application |
| `src/kv/committable_tx.h:245`         | Normal commits disable tracking of missing-key deletions              |
| `lean/kv/Types.lean:63-85`            | Map dependencies and their equality test                              |
| `lean/kv/Model.lean:111-120,288-296`  | Application guard and iteration dependency capture                    |

## Scope and follow-up

This establishes a concrete difference in **whole-map conflict tracking**.
It is separate from the earlier transaction-wide versus per-map global-snapshot
interpretation: neither global reads nor a changed term caused this rejection.

The model deliberately validates the whole map for iteration, including an
early-terminated iteration. Its application-order serializability proof relies
on that dependency. This report does not independently prove that no alternative
serial ordering could explain every externally visible observation in the
complete C++ execution, nor assess network or deployment impact.

A corrective change should distinguish "no whole-map read" from "read at revision
zero". That distinction belongs in whole-map dependency tracking; changing the
shared `NoVersion` constant indiscriminately would also affect unrelated
absence/version semantics. Follow-up should preserve individual-key absence
dependencies and read-your-writes behavior, and cover the zero-revision and
ordinary nonzero-revision cases consistently.

## Upstream correction

The diagnosis and source locations above describe the original, pre-fix
execution. [microsoft/CCF#8320](https://github.com/microsoft/CCF/pull/8320)
corrected the in-memory whole-map dependency to `std::optional<Version>`:
`nullopt` means no observation, while a present zero is checked against the
current map revision. The first transaction is still numbered 1 and ordinary
ledger encoding is unchanged. The obsolete read-inclusive emission path was
separately removed by
[microsoft/CCF#8303](https://github.com/microsoft/CCF/pull/8303).

The model branch now inherits these changes from upstream rather than applying
the earlier local fix again. The original trace must remain rejected because it
records an application that the corrected implementation prevents. Fresh
executions are checked against the unchanged Lean model.

The upstream conflict regression now includes `range`, which remains outside the
current trace schema. It runs in the ordinary KV unit suite and is explicitly
excluded from trace conformance; the separate non-conflict regression is
selected. No unsupported range event is silently skipped.
