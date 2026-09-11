KV Implementation Model
=======================

The Lean project in ``lean/kv`` gives an executable model of KV
observations and a checker for traces from the C++ KV unit tests. It complements
the :doc:`kv_how_to` and :doc:`api`: it makes the observed implementation
semantics, their assumptions, and differences from documentation explicit.

The model covers one node, with arbitrarily many finite maps, keys, values, and
transaction attempts. Transactions may span several maps. Consensus is abstracted
as commitment/compaction and rollback events. Public/private domains, encryption,
and governance/application access restrictions are not modelled. Map names are
opaque identities.

.. important::

   A theorem about this model is not a theorem about the C++ implementation.
   Replaying a complete trace establishes conformance of the recorded execution,
   subject to the instrumentation and decoding assumptions described below.
   A rejected trace can reveal an implementation discrepancy, a documentation
   ambiguity, a model error, or an instrumentation error.

Observation contract
--------------------

The :ref:`transaction semantics <build_apps/kv/kv_how_to:Transaction Semantics>`
promise atomic interaction across maps and a consistent, opaque view. Current
reads use one transaction-wide snapshot. Global reads follow the implementation's
per-map capture described below, not a transaction-wide global snapshot:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Operation
     - Model interpretation
   * - First map access
     - Capture the current-state cut used by all maps in this transaction.
       Constructing a transaction without accessing the KV does not capture it.
   * - First handle for each map
     - Capture that map's globally committed view at acquisition. Reused handles
       and different handle facets for this map share the captured view; later
       acquisitions of other maps may capture a newer global prefix.
   * - ``get`` / ``has``
     - Read the current snapshot overlaid with the transaction's pending writes.
       Missing and deleted keys are absent. Handles in one transaction share
       pending writes.
   * - ``put`` / ``remove``
     - Stage a value or deletion. Other transactions cannot see these changes
       until local application. An absent map behaves like an empty map.
   * - ``get_version_of_previous_write``
     - Observe the previous write in the captured current snapshot, not a pending
       write in this transaction. Equal value bytes do not imply equal versions.
   * - ``get_globally_committed``
     - Read the global view captured for this map, ignoring pending writes and
       subsequent consensus progress. Reading another key does not refresh it.
   * - ``foreach``
     - Capture the map's entries at iteration start. Visit them in unspecified
       order, with optional early termination. Callback mutations affect
       ordinary reads but do not change the entries already captured for this
       iteration.
   * - ``size`` / ``clear``
     - Observe or modify the whole transaction-visible map, using the same
       visibility rules as iteration.
   * - Local application
     - Validate dependencies across all touched maps, then publish all writes
       atomically. Blind writes need not conflict; absent reads and map-wide
       reads introduce dependencies too.
   * - Abandonment or pre-application conflict
     - Publish none of the attempt's pending writes. A retry is a fresh attempt.

The C++ ``Value`` and ``Set`` wrappers use the same map operations. JavaScript
``set`` and ``delete`` correspond to KV ``put`` and ``remove``. The model does not
verify serializers or the JavaScript binding implementation.

Normal application code receives a transaction from the framework; it does not
need to call the internal ``CommittableTx::commit`` used by the unit tests.
The decision to apply or discard an endpoint's writes and automatic endpoint
re-execution are outside this model.

Current and globally committed views
------------------------------------

The store has one history, not separate current and global databases. Local
application extends that history. Its irrevocable prefix determines globally
committed observations.

``get`` and ``get_globally_committed`` may intentionally return different values
for the same key. The serializability claim about normal current-state reads
must therefore be distinguished from the per-map global observation contract.
Historical global reads are not silently converted into current-state reads
or current-state conflict dependencies.

.. important::

   The implementation captures committed state when each map's change set is
   acquired. A transaction can therefore observe different global prefixes
   through different maps, while each acquired map retains one fixed view.
   Even the first map can be acquired after commitment advances beyond the
   global frontier observed alongside the transaction's initial current cut.

   The how-to's global-commit example also appears to refresh a read through an
   existing handle, whereas the API reference describes a transaction-wide
   fixed view. This model explicitly follows the implementation's per-map
   behavior. It does not establish the stronger documentation claim or change
   C++ KV behavior.

A regression schedule uses two maps with two locally applied versions. Compact
only version one, then begin a transaction and acquire map A. Its current cut is
version two, while A's global view is from version one. Compact version two
before acquiring map B. A keeps its version-one global view, including for keys
not previously read, while B captures version two. Ordinary reads through both
maps still use the transaction's version-two current snapshot.

Local application, commitment, and rollback
-------------------------------------------

An application's local result is not itself a durability guarantee; see
:doc:`/use_apps/verify_tx`. The model distinguishes the point at which writes
are applied from the later outcome of replication submission. A
``FAIL_NO_REPLICATE`` result must not be interpreted as proof that local
application never happened. Conversely, a trace must not invent a rollback to
explain a failed submission.

Read-only completion does not append a new write version. Local application order
is the candidate serial order for writing transactions within a local branch;
read-only transactions have witnesses at the snapshot positions they observed.
Not every locally acknowledged transaction belongs to one permanent history
across rollbacks.

``Compact(v)`` abstracts the environment's declaration that a prefix is
irrevocable and the removal of obsolete history. Current contents and already
materialized snapshots remain observable, but some old snapshots can no longer
be acquired. Unchanged maps can retain an older effective revision, so
availability cannot be decided solely by comparing a transaction's version with
one store-wide number.

Map birth and effective revision are distinct. A map that did not exist at a
captured cut can still have a fresh empty view at that cut after another
transaction creates and compacts it. This placeholder's global view is empty
too; it must not expose the newer map merely because that map is now globally
committed. A map already persisted by a deletion of an absent key is an existing
empty map, even though its effective revision is zero; its old local view remains
subject to retention checks. This metadata does not introduce a public
map-existence query.

An attempt must not silently switch to a newer current cut if a required local
snapshot is unavailable. The corresponding conflict requires a fresh attempt.
Discarding an earlier global prefix does not itself prevent acquiring another
map's current committed view. Already acquired global views remain fixed.
Retaining old states for proofs or diagnostics does not make unavailable local
snapshots operationally accessible again.

Rollback truncates only a provisional suffix. It cannot cross the irrevocable
prefix. The model accounts for removed maps, retained handles, invalidated writing
attempts, sequence-number reuse, and term changes that do not truncate the local
history. A retained handle may still read its captured state after rollback;
that does not authorize it to republish an invalidated write set.

Proof and trust boundaries
--------------------------

The model's statements separate read semantics, cross-map current-snapshot
consistency, per-map global-view stability, atomic application, normal-view
serializability, compaction, rollback, and executable replay. The
:ccf_repo:`proof catalogue <lean/kv/README.md>` records their precise scope and
the corresponding Lean declarations.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Main declaration
     - Established scope
   * - ``replay_segment_serializability``
     - An accepted typed trace segment for a live store has a serial witness
       obtained from its actual application events and pre-event transactions.
       The segment excludes creation, destruction, or rollback of that store;
       operations on other stores may interleave.
   * - ``reachable_store_invariants``
     - Store constructors preserve complete publication histories, matching
       heads, and globally committed cuts no later than the local head.
   * - ``replay_snapshot_fixed``
     - The current snapshot comes from the initial capture and remains fixed
       across all maps during the attempt.
   * - ``capture_replay_preserves_map``
     - An acquired map's global view remains fixed, including for other keys,
       aliases, compaction, and rollback. This is not cross-map global consistency.
   * - ``step_global_read_from_captured_map``
     - Accepted global reads originate in that map's captured irrevocable view,
       with the explicit empty-placeholder case for a map absent at the local cut.
   * - ``durable_cut_survives_rollback``
     - Legal rollback preserves observations from the irrevocable prefix.

Serializability is derived from dependency validation, not from an assumption
that an accepted transaction is already serializable. Runtime-erased
certificates carry snapshot execution and store-history invariants through the
constructors; they are not extra sequential-oracle acceptance checks.

The Lake build treats warnings as errors and checks the transitive axiom
dependencies of the main guarantees. Only Lean's standard trusted axioms are
allowed; admitted proofs and custom assumptions fail the build.

The consensus abstraction assumes a valid irrevocable prefix and permitted
environment transitions. It does not prove quorum agreement, eventual
commitment, successful retries, fairness, or network/crash-recovery behavior.
The documentation's term "opaque" is interpreted as snapshot consistency; it is
not an assertion of unrestricted network-wide strict serializability.

Replay relies on complete observations of actual C++ operations, correct byte
encoding/decoding and event ordering, and execution of the Lean checker.
Incomplete instrumentation cannot be repaired by a theorem about an otherwise
correct state machine. Unknown or unsupported state-changing operations are
reported, rather than skipped.

Trace format and diagnostics
----------------------------

Tracing is opt-in through ``CCF_KV_TRACING`` and a dedicated ``kv_trace`` doctest
reporter. It is disabled in normal builds. Traces contain test data and are not a
production logging facility.

Versioned NDJSON records include stable store and transaction-attempt identities,
current-snapshot and per-map acquisition, operation inputs and actual outputs,
iteration callbacks, local application, commit results, compaction, rollback,
and explicit lifecycle boundaries. The attempt identity is distinct from CCF's
transaction ID: read-only attempts can share a transaction ID, and rollback
can reuse sequence numbers.

The initial ``snapshot.global`` field is checked as an observation of the
frontier at current-snapshot capture. It does not set the global view for every
subsequent map. ``map_acquire.global`` records the effective revision captured
for that map; it can be older than the store's global frontier for an unchanged
map.

Keys and values are represented losslessly, including the difference between
empty bytes and absence. The checker reconstructs pending writes and dependencies
from operations. Logged effects are evidence to check, not replacement model
state.

Event order must reflect logical transition boundaries, not wall-clock timestamps
or the order buffered log lines reach disk. Concurrent workload recording must
not add a global lock around KV operations. Iteration order remains unspecified,
and callback operations remain visible in the trace.

The checker distinguishes accepted executions, contract rejections, invalid
traces, and unsupported operations. The runner also distinguishes C++ test or
capture failure. Missing events, incomplete lifecycles, unknown operations, and
empty claimed coverage are not successes. Rejected traces retain the first
failing event and its expected and observed state.

Reproducing a run
-----------------

Use Linux or WSL. Lean is pinned by ``lean/kv/lean-toolchain`` and is independent
of normal CCF builds:

.. code-block:: bash

   cd lean/kv
   lake build
   lake exe kv_trace_tests
   cd ../..
   cmake -S . -B build-kv-trace -GNinja \
     -DCMAKE_BUILD_TYPE=Debug -DCCF_KV_TRACING=ON \
     -DCCF_KV_TRACE_CHECKER="$PWD/lean/kv/.lake/build/bin/kv_trace_check"
   cmake --build build-kv-trace --target kv_test
   cd build-kv-trace
   ./tests.sh -R '^kv_test$' -L unit --no-tests=error
   ./tests.sh -R '^kv_trace_validation$' -L kv_trace --no-tests=error

The conformance command returns a failure for rejected, invalid, or unsupported
traces and for capture/test failures. It does not turn unsupported mechanisms
into accepted observations. This is separate from whether the Lean proofs/checker
regressions and C++ unit tests succeed.

The runner captures the purpose-built ``KV trace *`` cases once, then captures
the concurrent fuzzer for each seed. It checks every generated trace with Lean
and verifies that the expected cases, event families, and important outcomes
were actually observed. Each run retains its trace and test/checker output in a
unique directory.

``CCF_KV_TRACE_TIMEOUT`` configures each capture and replay timeout. The checker
streams records and stops at the first diagnostic; accepted model history is not
constant-memory.

The ``Lean`` workflow builds the model and instrumented tests, then uploads
diagnostics even if conformance fails. Selected tests can exercise explicitly
unsupported mechanisms, which remain non-passing outcomes. It uses a standard
Linux runner; these single-node KV tests do not require an enclave or a
multi-node network.

Seeded concurrent campaigns
---------------------------

``KV trace concurrent operation fuzzer`` generates bounded KV operation programs
on multiple worker threads. It exercises the KV interface and transaction
lifetimes, not binary parsers or a running network. Each worker has its own
deterministically seeded operation choices and transaction objects.

Concurrent workers mix current/global reads, version observations, writes,
deletions, map-wide operations, callback mutations, read-only completion and
abandonment. A maintenance thread can compact while ordinary transactions run.
Coordinated phases retain transactions and handles across global advancement,
compaction and rollback, covering less frequent lifetime and conflict cases.
Rollback occurs between KV calls rather than overlapping its internal
multi-step implementation: an overlap which the existing tracer cannot order
must not be mistaken for a valid atomic transition.

Campaigns use the same Lean checker as ordinary trace validation. A seed fixes
program choices, not the operating system's scheduling. The captured trace is
the exact observed execution to replay. Every seed retains its console output,
trace, and diagnostics under a unique directory. C++ writes recipe and coverage
metadata to console records, separately from the strict NDJSON event schema.

The campaign checks both completed-operation counters and actual emitted event
families and outcomes, including successful/conflicting/nonreplicating commits,
absent/present reads and early iteration termination. Empty coverage, unsupported
operations, timeout, rejection and malformed capture remain non-passing
outcomes. A campaign stops at the first non-passing seed. Coverage of these
families is not an exhaustive exploration of every program or thread schedule.

After configuring a tracing build as above:

.. code-block:: bash

   cd build-kv-trace
   ./tests.sh -R '^kv_trace_validation$' -L kv_fuzz --no-tests=error

The CMake options below configure the campaign, without modifying the test
program or its trace schema:

.. list-table::
   :header-rows: 1
   :widths: 45 15 40

   * - Option
     - Default
     - Meaning
   * - ``CCF_KV_FUZZ_SEED_START``
     - ``0``
     - First unsigned 64-bit seed.
   * - ``CCF_KV_FUZZ_SEEDS``
     - ``8``
     - Number of consecutive seeds, from 1 to 256 without overflow.

The C++ workload bounds its worker count, transaction and operation budgets,
iteration depth, callback visits, and key/map universes.
``CCF_KV_TRACE_TIMEOUT`` bounds each capture/replay process. For example, to
explore a different seed range:

.. code-block:: bash

   cmake -S .. -B . -DCCF_KV_FUZZ_SEED_START=100 -DCCF_KV_FUZZ_SEEDS=16
   ./tests.sh -R '^kv_trace_validation$' -L kv_fuzz --no-tests=error

The workflow uploads each generated trace and its test and checker output as
diagnostic artifacts.
