# Executable KV specification

Standalone Lean 4.28.0 project, using only Lean core/Std and the bundled JSON
parser. It does not change CCF behavior or introduce a normal-build dependency.
The fuller contract and provenance belong in
`doc/build_apps/kv/semantics.rst`.

## Commands

Run under Linux, from `lean/kv`:

```bash
lake build
lake exe kv_trace_tests
lake exe kv_trace_check fixtures/basic.ndjson
lake exe kv_trace_check --json fixtures/global_cut_mismatch.ndjson
```

Elan is optional: putting the official Lean 4.28.0 distribution's `bin`
directory on `PATH` is sufficient. The project invokes no elan commands and
has no Lake package dependencies.

The last command intentionally exits 1: event 29 refreshes map B's global
revision to 2, although the transaction captured global cut 1. This is a
contract discrepancy, not an accepted exception. The original file is not
modified. `.lake/build/bin/kv_trace_check` accepts the same arguments without
Lake's build messages.

Exit codes: 0 accepted, 1 contract rejection, 2 invalid/incomplete trace or IO
error, 3 explicitly unsupported operation. `--json` writes exactly one object
to stdout, with `status`, `events`, `message`, and, when decoded, `seq`, `store`,
`tx`. `events` counts accepted records (including `trace_end` on success).
Without `--json`, diagnostics go to stderr. Diagnostics identify the event
index/type, case and available IDs.
The CLI reads one NDJSON line at a time and returns immediately at the first
diagnostic; it does not load the entire input before checking. It still reads
through EOF after a valid `trace_end` to reject trailing records. Accepted
prefixes retain model history and lifecycle metadata, so total model memory
is not constant even though whole-file input buffering is avoided.

## Model

`Types.lean` defines finite association lists over arbitrary equality-bearing
map/key/value types. The executable instance uses opaque map-name strings and
lossless serialized bytes encoded as lowercase hex. There are no fixed bounds
on map/key/transaction counts. `Unique`, `set_unique`, `publish_unique` and
`publish_lookup` describe the finite-map representation. Empty bytes and
absence are distinct: `""` denotes a present zero-byte value, `null` denotes
absence, and a missing required `value` field is an invalid trace.

`Model.lean` implements the **one transition used by replay**:

- First access captures both current and irrevocable cuts. All acquired handles
  share staged writes. Normal reads overlay writes; previous-write observations
  ignore them. Global reads always ignore writes and use the fixed global cut.
- Schema 1 omits the store's initial term from `store_create`, so the initially
  unobserved term is established once by the first snapshot or rollback. This
  does not initialize or replace any database contents, version or global cut.
  Subsequent snapshots must match the tracked term; later untraced term changes
  are not inferred. This permits initial `initialise_term(1)` before first use
  without manufacturing a rollback event.
- Normal key reads (including absence) and whole-map reads create OCC
  dependencies. Reading an own write creates no dependency. Global reads create
  no normal dependency. Blind concurrent writes may both apply.
- Iteration freezes visible entries at begin, checks membership/value/uniqueness,
  permits arbitrary order, supports nested callbacks and explicit early stop.
  Iteration identity is `(store, tx, map, iteration)`; different maps may use
  the same numeric iteration ID.
  `size` and `clear` take the same whole-map dependency.
- Application validates dependencies/lineage/term and publishes the entire
  reconstructed staged write set, not the logged `writes` array. The array is
  only an exact, order-independent cross-check. Even an absent-key deletion may
  allocate a version without changing a map revision.
- `apply` and the eventual `commit_result` are separate. `no_replicate` after
  application retains local effects. Read-only success allocates no version.
  Pre-application conflict is permitted conservatively; the checker does not
  claim that all admissible attempts must succeed.
- Compaction advances the irrevocable cut, preserving current data and pinned
  handles. Full frames are ghost history: late acquisition of an existing map
  view is gated by that map's retained base revision for **both** cuts. Unchanged sparse maps may
  remain available even below the store-wide cut. If a fixed global map view
  has been discarded, the permitted outcome is `map_unavailable`, not a refresh.
  Map birth is tracked separately from its effective revision, from the first
  applied write to that map, including remove-missing. A map not yet created
  at a captured cut has a fresh empty placeholder at that cut, even if another
  transaction subsequently creates and compacts it. This does not recover
  discarded contents from ghost history. An already-existing empty map with
  revision zero remains subject to retention checks; zero revision alone is
  not evidence that the map was absent.
  A request above the current head is an observed no-op: its effective boundary
  must equal the previous global cut. A backward request also leaves the
  effective cut unchanged. Neither request permits a fabricated global advance.
- Rollback keeps the irrevocable prefix and discards the provisional suffix.
  Pinned handles remain readable. Per-map application identities prevent reuse
  of a rolled-back version from restoring lineage. Map-birth identities also
  distinguish removed/recreated empty maps whose effective revision stayed zero.
  A changed commit term also
  invalidates writing attempts. Unrelated same-term rollback does not
  automatically invalidate all handles.

`Tx.certificate` is a kernel-checked, runtime-erased invariant that the exact
normal-operation log was executed against its captured snapshot. It is
constructed by ordinary execution and maintained by `normalRun_extend`; it
is not a serializability assumption or an extra acceptance test.

`Store.historyShape`, `headFirst` and `globalBound` are also erased certificates.
They are constructed at store creation and maintained by application,
compaction and rollback. History starts with the empty version-zero frame,
contains every descending version through the current head, and each successor
frame results from publishing a finite write set over its predecessor.
The head is the first history frame and the global cut never exceeds it.
`Snapshot.origin` records paired-cut provenance; actual capture and subsequent
trace preservation are additionally proved below. None of these certificates
is obtained by checking serial execution as an acceptance condition.

## Proof scope

Proofs are in `Types.lean`, `Properties.lean` and `TraceProperties.lean`.
No `sorry`, custom axioms,
unsafe declarations, Mathlib, or external solver are used. Lean's intentional
Unicode mathematical notation is used in source.
The audited trace projection and history theorems use Lean's standard
`propext` and `Quot.sound`; the snapshot/global-observation proofs additionally
use standard `Classical.choice`.
The normal Lake build treats every Lean warning as an error, including
admission warnings. `AxiomAudit.lean` checks the transitive dependencies of the
35 exported main guarantees listed in `mainGuarantees`, using Lean's
`collectAxioms` over the kernel-checked environment. Only the three standard
dependencies above are permitted; `sorryAx`, custom assumptions and native
evaluation assumptions are rejected. Both executables import this audit, so
building either target also enforces it. Add new main guarantees to this list.

| Theorems                                                                                                                  | Established scope                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `read_your_write`, `read_your_deletion`, `absent_read`, `staged_noninterference`, `previous_ignores_pending`              | Point-read and overlay semantics                                                                                                                                                |
| `publish_lookup`, `publication_noninterference`, `publish_unique`, `apply_atomic`                                         | Entire finite multi-map publication and unrelated-key preservation                                                                                                              |
| `dependency_rebase`, `normalRun_serial_witness`                                                                           | Actual read/previous/whole-map observations replay identically at a dependency-valid current state                                                                              |
| `transaction_snapshot_witness`, `runOp_preserves_snapshot`                                                                | Every certified attempt's normal log has its captured snapshot witness, including read-only completions; operations preserve both captured cuts                                 |
| `transaction_application_serial_witness`, `tryApply_serial_witness`                                                       | The same executable application primitive used by replay has an independent sequential transaction witness                                                                      |
| `executable_branch_serializability`                                                                                       | Every finite branch of executable applications, with compaction interleavings, admits application order as a serial witness, including locally applied `no_replicate` attempts  |
| `branch_normal_serializability`                                                                                           | Type-parameterized version for arbitrary finite OCC programs                                                                                                                    |
| `step_store_effect`, `replay_segment_serializability`                                                                     | Actual successful steps/replays project to a selected live store's application-order serial witness; the attempts come from pre-event `txOf`                                    |
| `reachable_store_invariants`, `reachable_store_data_invariants`                                                           | Starting from empty World, live stores have certified complete publication histories, matching heads, bounded global cuts, unique data keys and bounded previous-write versions |
| `step_capture_paired`, `capture_replay_preserves_pair`, `replay_snapshot_fixed`                                           | Capture uses the actual pre-event store's paired cuts; both cuts remain fixed throughout a live attempt segment, including compaction and rollback                              |
| `reachable_snapshot_global_safety`, `step_global_read_from_irrevocable_prefix`, `step_global_has_from_irrevocable_prefix` | Captured global frames and actual accepted global observations originate in the captured irrevocable prefix; present cells have write versions no later than that prefix        |
| `withTx_preserves_stores`, `compact_preserves_head`, `compact_preserves_history`                                          | Nonpublishing transaction updates and compaction preserve store contents/history                                                                                                |
| `compact_above_head_noop`, `rollbackCut_exact`, `rollback_effective_version`                                              | Above-head compaction leaves the store unchanged; legal rollback boundaries are preserved exactly by the total internal constructor                                             |
| `rollback_keeps_prefix`, `rollback_discards_suffix`, `durable_cut_survives_rollback`                                      | Durable-prefix frames and contents survive; suffix frames disappear                                                                                                             |
| `stale_term_cannot_apply`, `discarded_handle_cannot_apply`, `discarded_birth_cannot_apply`, `compacted_map_unavailable`   | Stale-term/removed-lineage rejection, including recreated empty maps, and retained-base gating for existing maps                                                                |
| `absent_map_available`, `absent_placeholder_has_no_values`                                                                | Truly absent map cuts permit empty placeholders independently of retention; this path cannot expose old map values                                                              |
| `step_correspondence`, `replay_correspondence`                                                                            | Accepted typed steps/replays correspond to the operational transition/execution relation                                                                                        |

The sequential reference (`serialStep`, `serialRun`, `serialTransactions`) has
no dependency validation and is not consulted by the checker. Serializability
is derived from the OCC check. It applies to **normal** observations on a local
branch, not a single global serial read view combining normal and historical
reads, and not one permanent serial order across rollback.

Read-only completions use `transaction_snapshot_witness`: they are placed at
their captured snapshot in the history they observed, not at completion time,
and do not appear as new applications in `executable_branch_serializability`.
An already pinned snapshot may belong to a subsequently discarded branch.
Conversely, every local application belongs to its application-order witness
even if its later `commit_result` is `no_replicate`. A pre-application
`no_replicate` contributes no application. Only an explicit rollback changes
the local branch; a failed replication reply does not erase an application.

`replay_segment_serializability` assumes a successful typed replay, a selected
store live at the segment's start, and no `store_create`, `store_end` or
`rollback` for that selected store within the segment. It does **not** assume
`AppliedBranch` or a sequential result. `projectApplications` runs the same
steps and extracts only that store's actual `apply` attempts via pre-event
`txOf`. Compaction, initial-term establishment, read-only/failed returns and
all other-store operations stutter on the selected head data/version.
Other stores may even roll back or end within the segment. Selected-store
rollback partitions branches; the durable-prefix theorems cover that boundary.
Snapshot preservation requires no creation/end of the selected attempt during
its segment, but permits store rollback: already captured views remain pinned.

The correspondence relation is explicitly the graph of the common executable
transition, not a second independent CCF specification. The theorem covers
typed replay, not the JSON parser. The listed trace-to-property theorems cover
serial projection, history safety, snapshot provenance and immutability.
They do not prove that arbitrary C++ executions refine this model or that the
instrumentation is complete; iteration protocol and acquisition-availability
checks are not claimed as independently verified C++ algorithms.

## Strict schema 1

Every NDJSON record is an object with `type` and strictly increasing run-wide
uint64 `seq`. Numeric fields must be lexical nonnegative JSON integers, not
floats, exponents, signed values or strings. Duplicate keys (including escaped
aliases), unknown fields/events, malformed hex, missing fields, blank records,
truncation, open lifecycles and empty coverage are rejected. One terminal
newline is allowed. Failed test cases cannot establish conformance.
Numbers are parsed using arbitrary-precision integers and then bounded by
18446744073709551615; no floating-point conversion occurs.

Common fields: `store` is a stable incarnation, `tx` a run-unique attempt,
`map` an exact opaque string. Stores and transactions have explicit create/end
events; an active `tx_end` abandons writes. Retries need new attempt IDs.

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

`Tests.lean` exercises positive schedules and expected rejections, including
the selected cross-map global-cut discrepancy, no-op deletion, same-value
writes, absent/phantom/write-skew conflicts, nested iteration, compaction,
rollback, branch identity, exact uint64 decoding and damaged streams.

## Trust and exclusions

Consensus supplies valid irrevocability decisions. Liveness, successful retry,
quorums, crash recovery, encryption, serialization formats, imported snapshots,
cross-store swaps, ledger/signature metadata, permission/domain policy and
external hook side effects are not modeled. Such traced operations must be
reported as `unsupported`, not skipped.

The remaining trust boundary includes the trace emitter's completeness and
linearization order, accurate typed-result/byte capture, UTF-8/JSON decoding,
Lean's kernel/compiler/runtime, filesystem IO and the correspondence of emitted
events to actual C++ actions. Positive finite traces are conformance evidence,
not a proof of C++ refinement. Rejections remain diagnostic evidence and must
not be hidden by reseeding state or weakening the fixed-cut contract.
