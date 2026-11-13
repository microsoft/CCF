# Lean KV implementation model

This package contains an executable Lean model of the observable semantics of CCF's KV store (`src/kv/`), its properties, machine-checked proofs of those properties, and a replayer that checks traces recorded by the C++ KV unit tests against the model.
It does not change CCF behavior or introduce a normal-build dependency.
The user-facing contract, trace capture and fuzzing campaigns are described in [`doc/build_apps/kv/semantics.rst`](../../doc/build_apps/kv/semantics.rst).
This profile follows the implementation's **per-map globally committed views**.
[The Lean module guide](../AGENT.md) describes the module layout, which this package shares with the [disaster-recovery model](../disaster-recovery/README.md).

## Contents

| Purpose                                                     | Location                                                               |
| ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| Proved theorems and their witnesses                         | `Kv/Properties.lean`                                                   |
| State, observations, and dependencies                       | `Kv/Model/Types.lean`                                                  |
| Semantic inputs, computed outputs, and transitions          | `Kv/Model/Transitions.lean`                                            |
| Transition-system assembly and shared execution definitions | `Kv/Model.lean`, `../common/CCF/`                                      |
| Semantic sequential reference and execution predicates      | `Kv/Properties/`                                                       |
| Trace/model correspondence and replay projections           | `Kv/Proofs/Correspondence.lean`, `Kv/TraceValidation/Projections.lean` |
| Proof implementations                                       | `Kv/Proofs/`                                                           |
| Replay self-tests                                           | `Kv/Tests/`                                                            |
| Valid and invalid trace fixtures                            | `replayer/fixtures/`                                                   |
| Replay of recorded C++ traces                               | `Kv/TraceValidation.lean`                                              |
| Strict decoding, lifecycle validation, and semantic adapter | `Kv/TraceValidation/`                                                  |
| Replayer executable                                         | `replayer/`                                                            |

Human review covers the model, the full theorem statements in `Properties.lean`, the definitions they use, and their one-line references to proof implementations.
The proof implementations under `Proofs/` are verified by the build and `lake check` and are marked `linguist-generated` in `.gitattributes`.
Semantic invariant and retention proofs depend only on the semantic model and semantic property helpers.
Adapter proofs reuse these guarantees and the correspondence/capture foundations, rather than maintaining a second transition implementation.

`Model.transitionSystem` presents semantic `State` and `Action` through a [`CCF.TransitionSystem`](../common/CCF/TransitionSystem.lean), starting with no live stores or attempts.
`Model.execute` computes both the next state and an `Output`; its state projection is `Model.step`.
Neither semantic state nor actions contain records, schemas, reported observations, test scopes, sequence numbers, diagnostics, or run-wide identity bookkeeping.
`TraceValidation.transitionSystem` separately presents typed record validation.
The `step_projects`, `replay_projects`, and `reachable_projects` theorems connect accepted typed replay to executions and reachability of the actual semantic system.
An event translates to semantic inputs through `TraceValidation.actions`; trace-only bookkeeping and individual callback reports stutter.

## Model

`Kv/Model/Types.lean` defines finite association lists over arbitrary equality-bearing map/key/value types.
The semantic instance uses opaque strings for map names, keys, and values.
The trace adapter represents serialized key/value bytes losslessly as lowercase hex.
There are no fixed bounds on map/key/transaction counts.
`Unique` (in `Properties/Semantics.lean`), `publish_unique` and `publish_lookup` describe the finite-map representation.
Empty bytes and absence are distinct: `""` denotes a present zero-byte value, `null` denotes absence, and a missing required `value` field is an invalid trace.

`Kv/Model/Transitions.lean` implements semantic operations and environment inputs, without a trace envelope.
`Kv/Model.lean` assembles it as `Model.transitionSystem`.
The [observation contract](../../doc/build_apps/kv/semantics.rst#observation-contract), [snapshot and global-view semantics](../../doc/build_apps/kv/semantics.rst#current-and-globally-committed-views), and [application, compaction and rollback rules](../../doc/build_apps/kv/semantics.rst#local-application-commitment-and-rollback) are documented in the KV guide.
Model states are plain data and carry no proofs; execution computes observations and effects, never consulting a sequential oracle.
Live store and attempt references may be reused after destruction in the semantic system.
The adapter separately requires run-unique recorded IDs and complete instrumentation lifecycles.
`TraceValidation.Store` and `TraceValidation.Tx` decorate semantic stores and attempts with omitted-term and callback-protocol bookkeeping.
All publication, retention, lineage, dependency, and write effects use the semantic helpers, not a separate KV implementation.
The adapter checks trace protocol and detailed report guards, executes the translated inputs exactly once, compares the computed outputs with the reports, and installs the returned semantic state as authoritative.
It updates only schema/lifecycle bookkeeping, sequence/count metadata, and frozen callback-entry bookkeeping around that result; it does not construct a separate semantic candidate.
`Proofs/Correspondence.lean` proves that lifting and projecting the returned state is the identity and that accepted records yield actual runs of `Model.transitionSystem`.

A `Store` keeps its branch of committed frames newest first, its current head, global (compacted) version, term, and next application identity.
`Snapshot` retains the captured head frame and commit term.
The initial global frontier is checked at capture, not retained as transaction state.
Semantic store creation takes an explicit initial term.
Schema 1 omits that term from `store_create`; the trace adapter establishes it at the first snapshot or rollback without changing data, versions or the global cut.
Subsequent snapshots must match the tracked term; later untraced term changes are not inferred.
Store and transaction terms drive stale-term rejection.
Per-map revision and birth stamps carry application identities, so reuse of a rolled-back version cannot restore discarded lineage, including for empty maps.

Maps are acquired lazily, as in C++.
The first acquisition of a map selects the newest surviving frame at or below the snapshot's read version, or an empty placeholder if the map is absent there, so it may observe a rollback that occurred after the snapshot.
`Tx.globalViews` stores one `GlobalView` per acquired map: the pinned local frame and the globally committed frame.
Once acquired, neither frame changes for the rest of the attempt, and `Tx.data` combines the pinned local data used by normal observations.

The invariants used by the proofs are stated separately in `Proofs/SemanticInvariant.lean` and proved initially and preserved by every successful `Model.execute` action.
They therefore hold for every `Model.transitionSystem.Reachable` state, independently of trace validation or its extra instrumentation guards.
Store histories start with the empty version-zero frame, contain every descending version through the current head, and each successor frame results from publishing a finite write set over its predecessor; the head is the first history frame and the global cut never exceeds it.
Each live attempt's operation log, replayed against its pinned data, reproduces its normal view.
Each snapshot comes from a store head, and each global view is either an empty placeholder or a store's frame at its global cut.
None of these is a replay acceptance condition.
The normal-view reconstruction function `normalRun` and the per-step head-effect relation `HeadEffect` are proof machinery under `Proofs/`, not definitions needed to understand the public claims.

## Properties

`Kv/Properties.lean` states each claim as a proved theorem in `Kv.Properties`, whose one-line proof refers to an implementation in `Kv/Proofs/`.
No `sorry`, custom axioms, unsafe declarations, or external solver are used; `lake check` accepts only Lean's standard `propext`, `Quot.sound` and `Classical.choice`.
The `reachable_store_invariants`, `reachable_store_data_invariants`, `transaction_snapshot_serial`, and `transaction_application_serial` claims quantify over arbitrary `Model.transitionSystem.Reachable` states.
`executable_branch_serializability` proves application-order seriality for programs drawn from such states, using the shared semantic application primitive and allowing compaction interleavings.
All safety statements concern semantic state, computed outputs, or executions of `Model.transitionSystem`, without trace reachability premises.
Neither the entrypoint, its property helpers, nor its transitive proof imports depend on trace validation or correspondence.
Trace/model correspondence proofs remain in `Kv/Proofs/Correspondence.lean`, without a separate theorem entrypoint.
`application_atomic` states publication directly over `Model.execute`, with no trace assumptions.
Generic finite-map, dependency, and sequential reference helpers in `Properties/Semantics.lean` depend only on the semantic model.
Semantic segment projections are defined in `Properties/Executions.lean`; replay projections live in `TraceValidation/Projections.lean`, and reference programs used only by correspondence proofs live in `Proofs/ReplayPrograms.lean`.

Each claim is followed by a `_witness` lemma, so no claim is vacuous.
For a claim with premises, the witness asserts that some concrete semantic state, execution or program satisfies them.
The five claims without premises (`read_your_write`, `read_your_deletion`, `previous_ignores_pending`, `publish_lookup` and `apply_atomic`) cannot be vacuous; their witnesses instead show that the conclusion has an effect: a staged write or removal changes the read, a key can have both a committed version and a staged write, one write set can leave, remove and write addresses, and one applied write set can span two maps.
`Kv/Proofs/CoreWitnesses.lean` proves the capture, retention, global-observation and segment witnesses from actual model-action prefixes and executions, without trace metadata.
The semantic-execution, semantic-reachability, and correspondence witnesses are adjacent to their implementations in `Proofs/Semantics.lean`, `Proofs/SemanticInvariant.lean`, and `Proofs/Correspondence.lean`.

| Theorems                                                                                                                | Established scope                                                                                                                                                                 |
| ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `reachable_store_invariants`, `reachable_store_data_invariants`                                                         | Every live store in every semantic-reachable state has complete publication history, a matching head, a bounded global cut, unique data keys, and bounded previous-write versions |
| `transaction_snapshot_serial`, `transaction_application_serial`                                                         | Every semantic-reachable attempt's normal log reproduces its writes on pinned data, and on the application head when OCC permits publication                                      |
| `executable_branch_serializability`                                                                                     | Application-order branches of arbitrary semantic-reachable programs serialize through the actual semantic application primitive, with compaction interleavings                    |
| `application_atomic`                                                                                                    | Actual `Model.execute` publication computes the complete staged write set, next version, term, and store effect without trace assumptions                                         |
| `read_your_write`, `read_your_deletion`, `absent_read`, `staged_noninterference`, `previous_ignores_pending`            | Point-read and overlay semantics                                                                                                                                                  |
| `publish_lookup`, `publication_noninterference`, `publish_unique`, `apply_atomic`                                       | Entire finite multi-map publication and unrelated-key preservation                                                                                                                |
| `execution_segment_serializability`                                                                                     | Actual semantic execution projects to a selected live store's application-order serial witness; the attempts come from pre-application `Model.lookupTx`                           |
| `step_capture_metadata`, `step_capture_cut_values`, `capture_execution_preserves_metadata`, `execution_snapshot_fixed`  | Current snapshot and commit term capture/preservation; initial global metadata must match the store at capture but is not stored                                                  |
| `step_map_capture`, `captureGlobal_committed`, `captureGlobal_placeholder`                                              | Actual map acquisitions derive the current committed map revision, or an explicit empty placeholder for a map absent at R                                                         |
| `execution_map_global_fixed`, `execution_map_local_fixed`, `capture_execution_preserves_map`                            | A map's pinned local and global views remain unchanged through a live attempt, across all keys, aliases, compaction and rollback                                                  |
| `step_global_read_from_captured_map`, `step_global_has_from_captured_map`                                               | Actual global observations use that map's frozen frame, ignore pending writes, and have committed-prefix or explicit empty-placeholder provenance                                 |
| `compact_above_head_noop`                                                                                               | Above-head compaction leaves the store unchanged                                                                                                                                  |
| `rollback_keeps_prefix`, `rollback_discards_suffix`, `durable_cut_survives_rollback`                                    | Durable-prefix frames and contents survive; suffix frames disappear                                                                                                               |
| `stale_term_cannot_apply`, `discarded_handle_cannot_apply`, `discarded_birth_cannot_apply`, `compacted_map_unavailable` | Stale-term/removed-lineage rejection, including recreated empty maps, and retained-base gating for existing maps                                                                  |
| `absent_map_available`, `absent_placeholder_has_no_values`                                                              | Truly absent map cuts permit empty placeholders independently of retention; this path cannot expose old map values                                                                |

The semantic sequential reference (`serialStep`, `serialRun`, `semanticSerialTransactions`) has no dependency validation and is not consulted by the checker.
Serializability is derived from the OCC check.
It applies to **normal** observations on a local branch, not a single global serial read view combining normal and historical reads, and not one permanent serial order across rollback.
Per-map global observations need not agree with either the current snapshot or each other across maps.

Read-only completions use `transaction_snapshot_serial`, which interprets their normal log against the combined pinned local data, and do not appear as new applications in `executable_branch_serializability`.
Without intervening rollback, these pinned views come from the frozen read version.
An already acquired map can retain a removed branch's frame while a later lazy acquisition selects a surviving frame after rollback.
The checker preserves this mixed-view read-only behavior, including successful completion without publication.
The theorem does not assert that such combined pinned data occurred at one store-wide historical cut, nor that all successful read-only attempts across rollback have one serial placement.
Writing attempts still require valid acquired-map lineage, term, and dependencies before publication.
An already pinned snapshot may belong to a subsequently discarded branch.
Conversely, every local application belongs to its application-order witness even if its later `commit_result` is `no_replicate`.
A pre-application `no_replicate` contributes no application.
Only an explicit rollback changes the local branch; a failed replication reply does not erase an application.

`execution_segment_serializability` assumes a reachable semantic starting state, a `Model.transitionSystem` execution, a selected live store, and `SegmentInputs` excluding creation, destruction, or successful rollback of that store.
It does **not** assume `SemanticAppliedBranch` or a sequential result.
`applicationInputs` executes the same semantic steps and extracts only that store's actual application attempts via pre-application `Model.lookupTx`.
Rejected rollback of the selected store is permitted because it does not change the branch.
Compaction, initial-term establishment, read-only/failed returns and all other-store operations stutter on the selected head data/version.
Other stores may even roll back or end within the segment.
Selected-store rollback partitions branches; the durable-prefix theorems cover that boundary.
Snapshot preservation requires no creation/end of the selected attempt during its segment, but permits store rollback: the current snapshot and each acquired map's local and committed views remain pinned.
`Proofs/Retention.lean` proves captured-view preservation for every semantic action and finite attempt-preserving run.
`Proofs/AdapterRetention.lean` lifts it through accepted trace replay using correspondence, including callback and scope records that stutter.

The semantic guarantees are proved for actual `Model.execute` transitions and arbitrary reachable semantic runs, without trace preconditions or a sequential acceptance oracle.
The separate correspondence guarantees cover successful typed trace `step` and `replay` results, not the JSON parser.
The canonical model theorems cover normal-view serial projection, history safety, frozen read metadata, and per-map local/global provenance and immutability.
They do not establish cross-map snapshot consistency for the mixed lazy-acquisition rollback schedule described above.
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
`Tests/Replay.lean` checks serial projection, interleaved adapter/model correspondence, reported-observation rejection, trace ID reuse, and exact uint64 decoding.
`Tests/Semantics.lean` imports only the semantic model and executes overlapping transactions, multiple stores, nonreplicating publication, conflict dependencies, reusable live references, rollback identities, lazy acquisition across rollback, and per-map global frames without any trace records.
Both run with `#eval` when their modules are built.
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
lake build --wfail --fail-fast
lake exe check-imports
lake build CCF
lake lint
lake exe runLinter --no-build CCF Kv replayer.Main
lake check --inadvisably-no-sandbox
./replayer/check-fixtures.sh
```

These are the same checks as the [disaster-recovery validation](../disaster-recovery/README.md#validation), which describes each of them and the package's linter options.
The build runs the self-tests in `Tests/Replay.lean` and `Tests/Semantics.lean`, and `check-fixtures.sh` replays the [fixtures](#fixtures) with the built `kv-replay`.
The shared `lake exe check-imports` checks import coverage and layering, as described in the [common package](../common/README.md#architecture-checks).

To check C++ traces against the model, build the replayer and pass it to CMake as described in [Reproducing a run](../../doc/build_apps/kv/semantics.rst).
In the Lean CI workflow, the `KV trace captures` job builds the instrumented C++ tests and captures traces in Azure Linux 3, while the model job runs these checks and the fixtures in parallel and then replays the captured traces.
See the disaster-recovery [Formatting](../disaster-recovery/README.md#formatting) section for the formatting check, and pass `lean/kv` to restrict it to this package.
