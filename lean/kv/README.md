# Lean KV implementation model

This package contains an executable Lean model of the observable semantics of CCF's KV store (`src/kv/`), its properties, machine-checked proofs of those properties, and a replayer that checks traces recorded by the C++ KV unit tests against the model.
It does not change CCF behavior or introduce a normal-build dependency.
The user-facing contract, trace capture and fuzzing campaigns are described in [`doc/build_apps/kv/semantics.rst`](../../doc/build_apps/kv/semantics.rst).
This profile follows the implementation's **per-map globally committed views**.
[The Lean module guide](../AGENT.md) describes the module layout, which this package shares with the [disaster-recovery model](../disaster-recovery/README.md).

## Contents

| Purpose                                                     | Location                          |
| ----------------------------------------------------------- | --------------------------------- |
| Proved theorems and their witnesses                         | `Kv/Properties.lean`              |
| State, observations, and dependencies                       | `Kv/Model/Types.lean`             |
| Executable transitions and replay                           | `Kv/Model/Transitions.lean`       |
| Transition-system assembly and shared execution definitions | `Kv/Model.lean`, `../common/CCF/` |
| Sequential reference, trace projections, and invariants     | `Kv/Properties/`                  |
| Proof implementations                                       | `Kv/Proofs/`                      |
| Replay self-tests                                           | `Kv/Tests/`                       |
| Valid and invalid trace fixtures                            | `replayer/fixtures/`              |
| Replay of recorded C++ traces                               | `Kv/TraceValidation.lean`         |
| Strict decoding of those traces                             | `Kv/TraceValidation/`             |
| Replayer executable                                         | `replayer/`                       |

Human review covers the model, the full theorem statements in `Properties.lean`, the definitions they use, and their one-line references to proof implementations.
The proof implementations under `Proofs/` are verified by the build and `lake check` and are marked `linguist-generated` in `.gitattributes`.

`Model.transitionSystem` presents `step` as a [`CCF.TransitionSystem`](../common/CCF/TransitionSystem.lean) from the empty world.
Properties of executions use the shared `CCF.Execution.Run` and `TransitionSystem.Reachable`, and `Proofs/Execution.lean` shows that they coincide with successful `replay`.

## Model

`Kv/Model/Types.lean` defines finite association lists over arbitrary equality-bearing map/key/value types.
The executable instance uses opaque map-name strings and lossless serialized bytes encoded as lowercase hex.
There are no fixed bounds on map/key/transaction counts.
`Unique` (in `Properties/Programs.lean`), `publish_unique` and `publish_lookup` describe the finite-map representation.
Empty bytes and absence are distinct: `""` denotes a present zero-byte value, `null` denotes absence, and a missing required `value` field is an invalid trace.

`Kv/Model/Transitions.lean` implements the **one transition used by replay**.
`Kv/Model.lean` assembles it as `Model.transitionSystem`.
The [observation contract](../../doc/build_apps/kv/semantics.rst#observation-contract), [snapshot and global-view semantics](../../doc/build_apps/kv/semantics.rst#current-and-globally-committed-views), and [application, compaction and rollback rules](../../doc/build_apps/kv/semantics.rst#local-application-commitment-and-rollback) are documented in the KV guide.
Model states are plain data and carry no proofs; a step checks only the conditions that C++ must satisfy, never a sequential oracle.

A `Store` keeps its branch of committed frames newest first, its global (compacted) version, and its term.
`Snapshot` retains the captured head frame and commit term.
The initial global frontier is checked at capture, not retained as transaction state.
Schema 1 omits the initial term from `store_create`; the first snapshot or rollback establishes it without changing data, versions or the global cut.
Subsequent snapshots must match the tracked term; later untraced term changes are not inferred.
Store and transaction terms drive stale-term rejection.
Per-map revision and birth stamps carry application identities, so reuse of a rolled-back version cannot restore discarded lineage, including for empty maps.

Maps are acquired lazily, as in C++.
The first acquisition of a map selects the newest surviving frame at or below the snapshot's read version, or an empty placeholder if the map is absent there, so it may observe a rollback that occurred after the snapshot.
`Tx.globalViews` stores one `GlobalView` per acquired map: the pinned local frame and the globally committed frame.
Once acquired, neither frame changes for the rest of the attempt, and `Tx.data` combines the pinned local data used by normal observations.

The invariants used by the proofs are stated separately, in `Proofs/Invariants.lean`, and proved for every state reachable from the empty world.
Store histories start with the empty version-zero frame, contain every descending version through the current head, and each successor frame results from publishing a finite write set over its predecessor; the head is the first history frame and the global cut never exceeds it.
Each live attempt's operation log, replayed against its pinned data, reproduces its normal view.
Each snapshot comes from a store head, and each global view is either an empty placeholder or a store's frame at its global cut.
None of these is a replay acceptance condition.
The normal-view reconstruction function `normalRun` and the per-step head-effect relation `HeadEffect` are proof machinery under `Proofs/`, not definitions needed to understand the public claims.

## Properties

`Kv/Properties.lean` states each claim as a proved theorem in `Kv.Properties`, whose one-line proof refers to an implementation in `Kv/Proofs/`.
No `sorry`, custom axioms, unsafe declarations, or external solver are used; `lake check` accepts only Lean's standard `propext`, `Quot.sound` and `Classical.choice`.
Claims that depend on the model's state invariants assume `Model.transitionSystem.Reachable`; `Proofs/Invariants.lean` proves those invariants hold initially and are preserved by every step.

Each claim is followed by a `_witness` lemma, so no claim is vacuous.
For a claim with premises, the witness asserts that some concrete state, trace or program satisfies them.
The five claims without premises (`read_your_write`, `read_your_deletion`, `previous_ignores_pending`, `publish_lookup` and `apply_atomic`) cannot be vacuous; their witnesses instead show that the conclusion has an effect: a staged write or removal changes the read, a key can have both a committed version and a staged write, one write set can leave, remove and write addresses, and one applied write set can span two maps.
`Kv/Proofs/Witnesses.lean` proves these witnesses, mostly from prefixes and segments of one accepted trace that the kernel evaluates with `decide +kernel`.

| Theorems                                                                                                                | Established scope                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `read_your_write`, `read_your_deletion`, `absent_read`, `staged_noninterference`, `previous_ignores_pending`            | Point-read and overlay semantics                                                                                                                                               |
| `publish_lookup`, `publication_noninterference`, `publish_unique`, `apply_atomic`                                       | Entire finite multi-map publication and unrelated-key preservation                                                                                                             |
| `transaction_snapshot_serial`                                                                                           | Every live attempt's normal log runs serially on its pinned local data, including read-only completions                                                                        |
| `transaction_application_serial`                                                                                        | The same executable application primitive used by replay has an independent sequential transaction witness                                                                     |
| `executable_branch_serializability`                                                                                     | Every finite branch of executable applications, with compaction interleavings, admits application order as a serial witness, including locally applied `no_replicate` attempts |
| `replay_segment_serializability`                                                                                        | Actual successful replay projects to a selected live store's application-order serial witness; the attempts come from pre-event `txOf`                                         |
| `reachable_store_invariants`, `reachable_store_data_invariants`                                                         | Starting from empty World, live stores have complete publication histories, matching heads, bounded global cuts, unique data keys and bounded previous-write versions          |
| `step_capture_metadata`, `step_capture_cut_values`, `capture_replay_preserves_metadata`, `replay_snapshot_fixed`        | Current snapshot and commit term capture/preservation; initial global metadata must match the store at capture but is not stored                                               |
| `step_map_capture`, `captureGlobal_committed`, `captureGlobal_placeholder`                                              | Actual map acquisitions derive the current committed map revision, or an explicit empty placeholder for a map absent at R                                                      |
| `replay_map_global_fixed`, `replay_map_local_fixed`, `capture_replay_preserves_map`                                     | A map's pinned local and global views remain unchanged through a live attempt, across all keys, aliases, compaction and rollback                                               |
| `step_global_read_from_captured_map`, `step_global_has_from_captured_map`                                               | Actual global observations use that map's frozen frame, ignore pending writes, and have committed-prefix or explicit empty-placeholder provenance                              |
| `compact_above_head_noop`                                                                                               | Above-head compaction leaves the store unchanged                                                                                                                               |
| `rollback_keeps_prefix`, `rollback_discards_suffix`, `durable_cut_survives_rollback`                                    | Durable-prefix frames and contents survive; suffix frames disappear                                                                                                            |
| `stale_term_cannot_apply`, `discarded_handle_cannot_apply`, `discarded_birth_cannot_apply`, `compacted_map_unavailable` | Stale-term/removed-lineage rejection, including recreated empty maps, and retained-base gating for existing maps                                                               |
| `absent_map_available`, `absent_placeholder_has_no_values`                                                              | Truly absent map cuts permit empty placeholders independently of retention; this path cannot expose old map values                                                             |

The sequential reference (`serialStep`, `serialRun`, `serialTransactions`) has no dependency validation and is not consulted by the checker.
Serializability is derived from the OCC check.
It applies to **normal** observations on a local branch, not a single global serial read view combining normal and historical reads, and not one permanent serial order across rollback.
Per-map global observations need not agree with either the current snapshot or each other across maps.

Read-only completions use `transaction_snapshot_serial`: they are placed at their captured snapshot in the history they observed, not at completion time, and do not appear as new applications in `executable_branch_serializability`.
An already pinned snapshot may belong to a subsequently discarded branch.
Conversely, every local application belongs to its application-order witness even if its later `commit_result` is `no_replicate`.
A pre-application `no_replicate` contributes no application.
Only an explicit rollback changes the local branch; a failed replication reply does not erase an application.

`replay_segment_serializability` assumes a reachable starting world, a successful typed replay, a selected store live at the segment's start, and no `store_create`, `store_end` or `rollback` for that selected store within the segment.
It does **not** assume `AppliedBranch` or a sequential result.
`projectApplications` runs the same steps and extracts only that store's actual `apply` attempts via pre-event `txOf`.
Compaction, initial-term establishment, read-only/failed returns and all other-store operations stutter on the selected head data/version.
Other stores may even roll back or end within the segment.
Selected-store rollback partitions branches; the durable-prefix theorems cover that boundary.
Snapshot preservation requires no creation/end of the selected attempt during its segment, but permits store rollback: the current snapshot and each acquired map's local and committed views remain pinned.
Their replay-preservation proofs reuse `replay_attempt_invariant`, which lifts an already-proved single-step property through a successful replay while retaining the live attempt.

The principal guarantees are proved directly from successful executable `step` and `replay` results, without optional graph-wrapper relations.
They cover typed replay, not the JSON parser.
The trace-to-property theorems cover normal-view serial projection, history safety, current-snapshot consistency, and per-map global provenance/immutability.
They do not prove that arbitrary C++ executions refine this model or that the instrumentation is complete; iteration protocol and acquisition-availability checks are not claimed as independently verified C++ algorithms.

## Trace validation

`Kv/TraceValidation.lean` checks traces recorded by the instrumented C++ KV unit tests against the model, decoding them with `Kv/TraceValidation/Records.lean`.
The replayer is run as `.lake/build/bin/kv-replay [--json] <trace.ndjson>`.
Its exit codes are 0 for an accepted trace, 1 for a contract rejection, 2 for an invalid or incomplete trace or an IO error, and 3 for an explicitly unsupported operation.
`--json` writes exactly one object to stdout, with `status`, `events`, `message`, and, when decoded, `seq`, `store`, `tx`.
`events` counts accepted records (including `trace_end` on success).
Without `--json`, diagnostics go to stderr.
Diagnostics identify the event index/type, case and available IDs.

The replayer reads one NDJSON line at a time and returns immediately at the first diagnostic; it does not load the entire input before checking.
It still reads through EOF after a valid `trace_end` to reject trailing records.
Accepted prefixes retain model history and lifecycle metadata, so total model memory is not constant even though whole-file input buffering is avoided.

### Strict schema 1

Every NDJSON record is an object with `type` and strictly increasing run-wide uint64 `seq`.
Numeric fields must be lexical nonnegative JSON integers, not floats, exponents, signed values or strings.
Duplicate keys (including escaped aliases), unknown fields/events, malformed hex, missing fields, blank records, truncation, open lifecycles and empty coverage are rejected.
One terminal newline is allowed.
Failed test cases cannot establish conformance.
Numbers are parsed using arbitrary-precision integers and then bounded by 18446744073709551615; no floating-point conversion occurs.

Common fields: `store` is a stable incarnation, `tx` a run-unique attempt, `map` an exact opaque string.
Stores and transactions have explicit create/end events; an active `tx_end` abandons writes.
Retries need new attempt IDs.

| Type                                         | Additional fields                                                                                   |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `trace_start`                                | `schema:1`                                                                                          |
| `case_begin`, `subcase_begin`, `subcase_end` | `name:string`                                                                                       |
| `case_end`                                   | `name:string`, `failed:bool`                                                                        |
| `store_create`, `store_end`                  | `store`                                                                                             |
| `tx_create`, `tx_end`, `commit_begin`        | `store`, `tx`                                                                                       |
| `snapshot`                                   | `store`, `tx`, `version`, `global`, `term`                                                          |
| `map_acquire`                                | `store`, `tx`, `map`, `version`, `global` (effective map revisions, possibly older than store cuts) |
| `map_unavailable`, `clear`                   | `store`, `tx`, `map`                                                                                |
| `get`, `get_global`                          | `store`, `tx`, `map`, `key:hex`, `value:hex or null`                                                |
| `has`, `has_global`                          | `store`, `tx`, `map`, `key:hex`, `value:bool`                                                       |
| `previous_write`                             | `store`, `tx`, `map`, `key:hex`, `value:uint64 or null`                                             |
| `put`                                        | `store`, `tx`, `map`, `key:hex`, `value:hex`                                                        |
| `remove`                                     | `store`, `tx`, `map`, `key:hex`                                                                     |
| `size`                                       | `store`, `tx`, `map`, `value:uint64`                                                                |
| `range`                                      | `store`, `tx`, `map`, `from:hex or null`, `to:hex or null`, `entries:[{key:hex,value:hex}]`         |
| `foreach_begin`, `foreach_end`               | `store`, `tx`, `map`, `iteration:uint64`                                                            |
| `foreach_entry`                              | `store`, `tx`, `map`, `iteration`, `key:hex`, `value:hex`                                           |
| `foreach_continue`                           | `store`, `tx`, `map`, `iteration`, `value:bool`                                                     |
| `apply`                                      | `store`, `tx`, `version`, `term`, `writes:[{map,key,value:hex or null}]`                            |
| `commit_result`                              | `store`, `tx`, `result:success or conflict or no_replicate`, `version` (0 when unassigned)          |
| `compact`                                    | `store`, `version` (effective), `requested`                                                         |
| `rollback`                                   | `store`, `version` (effective), `requested`, `term`                                                 |
| `rollback_rejected`                          | `store`, `requested`, `term`                                                                        |
| `unsupported`                                | optional `store`, `operation:string`                                                                |
| `trace_end`                                  | `events:uint64` counting all prior records                                                          |

### Fixtures

Each directory under `replayer/fixtures/` holds a valid schema 1 `trace.ndjson`, whose cases cover acceptance relationships not guaranteed by generated-trace event coverage, and diffs against it in `invalid/`, in the same layout as the [disaster-recovery fixtures](../disaster-recovery/README.md#validation).
Most diffs change one record, so each shows exactly the deviation being tested.
An invalid diff's name starts with the status it must produce: `rejected.`, `invalid-trace.` or `unsupported.`.
They cover forbidden map-view refreshes, wrong global values/presence/revisions, partial applications, absent/phantom/write-skew conflicts, stale lineage, compaction and rollback boundaries, iteration lifecycle errors, and damaged streams.

`replayer/check-fixtures.sh` replays each base trace, which must be accepted, and each diff applied with `git apply --unidiff-zero`, which must produce its named status.
It also requires replay to be deterministic, every failure to carry a diagnostic, and every rejection to identify the failing record.
`Tests/Replay.lean` keeps only the checks that are not traces: agreement between the projected serial history and actual replay, and exact uint64 decoding; they run with `#eval` when the module is built.
Other positive implementation schedules come from the focused C++ tests and concurrent fuzzer.

## Recorded finding

The concurrent fuzzer found a whole-map conflict that C++ failed to detect.
An iteration over a map at revision zero recorded its map-read version as zero, which was also `NoVersion`, the marker for "no whole-map read".
Commit validation therefore skipped the check, and C++ applied a transaction whose iterated map had since gained an entry, while the model rejected the `apply`.
[#8320](https://github.com/microsoft/CCF/pull/8320) fixed this by tracking the map-read version as `std::optional<Version>`.
The model's whole-map dependency check, which caught it, is exercised by `replayer/fixtures/dependencies/invalid/rejected.map-wide-phantom-dependency.diff`.

## Trust and exclusions

The [proof and trust boundaries](../../doc/build_apps/kv/semantics.rst#proof-and-trust-boundaries) describe the consensus assumptions and excluded mechanisms.
The remaining trust boundary includes the trace emitter's completeness and linearization order, accurate typed-result/byte capture, UTF-8/JSON decoding, Lean's kernel/compiler/runtime, filesystem IO and the correspondence of emitted events to actual C++ actions.
Rejections remain diagnostic evidence and must not be hidden by reseeding state or accepting arbitrary global revisions.

## Validation

Run the following commands from this directory:

```console
lake exe cache get
lake build --wfail --fail-fast
lake exe check-imports
lake build CCF
lake lint
lake exe runLinter --no-build CCF Kv replayer.Main
lake check --inadvisably-no-sandbox
./replayer/check-fixtures.sh
```

These are the same checks as the [disaster-recovery validation](../disaster-recovery/README.md#validation), which describes each of them and the package's linter options.
The build runs the self-tests in `Tests/Replay.lean`, and `check-fixtures.sh` replays the [fixtures](#fixtures) with the built `kv-replay`.
The shared `lake exe check-imports` checks import coverage and layering, as described in the [common package](../common/README.md#architecture-checks).

To check C++ traces against the model, build the replayer and pass it to CMake as described in [Reproducing a run](../../doc/build_apps/kv/semantics.rst).
In the Lean CI workflow, the `KV trace captures` job builds the instrumented C++ tests and captures traces in Azure Linux 3, while the model job runs these checks and the fixtures in parallel and then replays the captured traces.
See the disaster-recovery [Formatting](../disaster-recovery/README.md#formatting) section for the formatting check, and pass `lean/kv` to restrict it to this package.
