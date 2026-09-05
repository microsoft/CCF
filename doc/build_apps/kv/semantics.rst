KV Contract Model
=================

The Lean project in ``lean/kv`` gives an executable specification of KV
observations and a checker for traces from the C++ KV unit tests. It complements
the :doc:`kv_how_to` and :doc:`api`: it makes the interpretation of the contract,
its assumptions, and implementation discrepancies explicit.

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
promise atomic interaction across maps and a consistent, opaque view. The model
makes the following interpretation explicit:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Operation
     - Model interpretation
   * - First map access
     - Capture a current-state cut and a globally committed cut together. Both
       cuts remain fixed for this transaction, across all its maps. Constructing
       a transaction without accessing the KV does not capture either cut.
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
     - Read the captured globally committed snapshot, ignoring pending writes
       and subsequent consensus progress.
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
must therefore be distinguished from the full two-snapshot observation
contract. Historical global reads are not silently converted into current-state
reads or current-state conflict dependencies.

.. important::

   The selected model contract fixes the global snapshot once per transaction.
   The current C++ implementation captures committed state separately when
   each map's change set is acquired. If commitment advances between acquisitions,
   while the transaction's local snapshot remains available, those captures can
   differ from the model.

   The how-to's global-commit example also appears to refresh a read through an
   existing handle, whereas the API reference describes a fixed view. The trace
   tooling reports disagreements with the transaction-wide fixed contract; it
   does not change KV behavior or silently weaken the specification.

A diagnostic schedule uses two maps with two locally applied versions. Compact
only version one, then begin a transaction and acquire map A. Its current cut is
version two and its global cut is version one. Compact version two before
acquiring map B. The model still requires global observations from version one.
This separates global-cut drift from failure to acquire an already discarded
local snapshot.

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
transaction creates and compacts it. A map already persisted by a deletion of
an absent key is an existing empty map, even though its effective revision is
zero; its old view remains subject to retention checks. This metadata does not
introduce a public map-existence query.

An attempt must not silently switch to a newer cut if its snapshot is unavailable.
The corresponding conflict requires a fresh attempt. Retaining old states for
proofs or diagnostic history does not make them operationally available again.

Rollback truncates only a provisional suffix. It cannot cross the irrevocable
prefix. The model accounts for removed maps, retained handles, invalidated writing
attempts, sequence-number reuse, and term changes that do not truncate the local
history. A retained handle may still read its captured state after rollback;
that does not authorize it to republish an invalidated write set.

Proof and trust boundaries
--------------------------

The model's statements separate read semantics, cross-map snapshot consistency,
atomic application, normal-view serializability, compaction, rollback, and
executable replay. The :ccf_repo:`proof catalogue <lean/kv/README.md>` records
their precise scope and the corresponding Lean declarations.

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
   * - ``capture_replay_preserves_pair``
     - Both snapshots come from the actual capture event and remain fixed
       during the attempt, including across compaction and rollback.
   * - ``step_global_read_from_irrevocable_prefix``
     - Accepted global reads originate in the captured irrevocable prefix.
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
snapshot acquisition, operation inputs and actual outputs, iteration callbacks,
local application, commit results, compaction, rollback, and explicit lifecycle
boundaries. The attempt identity is distinct from CCF's transaction ID:
read-only attempts can share a transaction ID, and rollback can reuse sequence
numbers.

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
failing event, its expected and observed state, and a failing prefix.

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
   ./tests.sh -R '^(kv_test|kv_trace_runner_test)$' -L unit --no-tests=error
   ./tests.sh -R '^kv_trace_validation$' -L kv_trace --no-tests=error

The conformance command returns a failure for a rejected trace, including a known
contract discrepancy. This is separate from whether the Lean proofs/checker
regressions and C++ unit tests succeed.

``tests/kv_trace_cases.json`` records selected test cases and explicit exclusions.
The runner inventories the actual binary: a missing selected case or an
unclassified/stale coverage entry prevents an all-covered success. Its report
records the selection, per-case results, binary/checker digests, and trace/log
locations. Explicit ``--case`` selection produces a subset report, not a claim
about the complete unit-test suite.

``CCF_KV_TRACE_TIMEOUT`` configures the per-case timeout passed to the runner.
The full contention case produces a large trace, unlike the small focused
schedules. The checker streams records and stops at the first diagnostic;
accepted model history is not constant-memory.

The manually dispatched ``KV Contract Verification`` workflow builds the
specification and instrumented tests, then uploads diagnostics even if strict
conformance fails. It is not a required conformance gate while separately
approved behavior fixes remain outstanding. It uses a standard Linux runner:
these single-node KV tests do not require an enclave or a multi-node network.
