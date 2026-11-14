Formal Verification and Trace Validation
========================================

CCF's formal models are written in `Lean <https://lean-lang.org/>`__ and live under :ccf_repo:`lean/ <lean>`.
Apart from the shared ``common`` package, each package contains an executable model of part of CCF, safety properties stated as theorems about that model, machine-checked proofs of those properties, and a replayer that checks traces recorded from the C++ implementation against the model.

The models and the implementation are connected in two different ways, which provide different guarantees:

* **Proofs** establish properties of the model for every execution the model allows.
  Lean's kernel checks proof terms but accepts proofs that depend on declared axioms.
  The package CI ``lake check`` command also checks axiom dependencies, rejecting unfinished proofs and any axioms other than Lean's standard ``propext``, ``Classical.choice`` and ``Quot.sound``.
  Each safety theorem is accompanied by a witness lemma showing that its premises can be satisfied, so that no property holds vacuously.
* **Trace validation** replays executions recorded from the C++ implementation, step by step, through the model's transition function.
  A successful replay shows that the model can explain that particular recorded execution.
  A rejected trace is reported with a diagnostic identifying the record that the model cannot explain, which may reveal an implementation bug, a model error, or an instrumentation error.

.. important::

   A theorem about a model is not a theorem about the C++ implementation.
   Trace validation checks only the executions that were recorded, and relies on the instrumentation recording them completely and accurately.
   None of the models cover liveness.

Lean packages
-------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Package
     - What it models
     - Trace validation
   * - :ccf_repo:`common <lean/common/README.md>`
     - Protocol-independent infrastructure shared by the other packages: transition systems, multi-node message-passing composition, finite and infinite execution traces, a trace event parser, and import coverage and architecture checks.
     - Not applicable.
   * - :ccf_repo:`consensus <lean/consensus/README.md>`
     - The :doc:`CCF consensus protocol </architecture/consensus/index>`, as implemented in :ccf_repo:`src/consensus/aft/cft.h`.
       Proved properties include election safety (no two primaries in the same term), prefix-comparability of committed logs, and that every positive commit index points to a signature entry.
       A joining node may initialize from another node's committed ledger prefix, as when installing a snapshot; the join protocol is not modelled.
     - :ccf_repo:`consensus-replay <lean/consensus/replay/README.md>` replays traces of the consensus scenarios run by the native ``cft_driver``.
   * - :ccf_repo:`consistency <lean/consistency/README.md>`
     - CCF's externally visible consistency semantics, including :ref:`transaction status <use_apps/verify_tx:Checking for Commit>`, for a simple append-and-read application with forwarded reads, elections and invalidation.
       The primary guarantee is that committed writes serialize in transaction ID order, and that this order respects the real-time order of requests and their initial responses.
       There is no refinement proof connecting this model to the consensus model.
     - ``consistency-replay`` replays client-observed request, response and transaction status traces from a multi-node e2e test.
   * - :ccf_repo:`disaster-recovery <lean/disaster-recovery/README.md>`
     - The :doc:`recovery decision protocol </operations/recovery>` (:ccf_repo:`src/node/recovery_decision_protocol.cpp`).
       Proved properties include that all quorum openings in a trace originate from one node and, under stated premises, that the opening node passes the consensus vote freshness check against a strict majority of the recovered ledgers.
     - :ccf_repo:`disaster-recovery-replay <lean/disaster-recovery/replayer/README.md>` replays node logs from e2e recovery scenarios.
   * - :ccf_repo:`kv <lean/kv/README.md>`
     - The observable semantics of CCF's single-node key-value store (:ccf_repo:`src/kv/`), including snapshots, globally committed views, atomic application, compaction and rollback.
       Proved properties include serializability of normal observations and preservation of the committed prefix across rollback.
       See :doc:`/build_apps/kv/semantics` for the full contract and its proof and trust boundaries.
     - ``kv-replay`` replays traces recorded by the instrumented C++ KV unit tests, including a seeded concurrent fuzzer.

The README of each package lists the precise theorem statements, the scope of the model, and what a successful replay does and does not show.

Trace sources
-------------

Each replayer consumes traces produced by existing C++ tests:

* **Consensus**: the ``cft_scenario_test`` test runs :ccf_repo:`tests/cft_scenarios_runner.py`, which executes each scenario in :ccf_repo:`tests/cft_scenarios/Scenarios/` with the ``cft_driver`` binary.
  The scenarios are Lean programs, which drive the implementation through the bindings in :ccf_repo:`tests/cft_scenarios/CftDriver.lean` and :ccf_repo:`src/consensus/aft/test/driver.cpp`; see :ccf_repo:`tests/cft_scenarios/README.md`.
  The driver exports consensus events as Fluentd records with the ``ccf.cft`` tag, which the runner collects and writes as NDJSON traces to ``consensus/raw/`` in the build directory.
  The ``cft_model_test`` test, built with ``-DCFT_MODEL_DRIVER=ON``, runs the same scenarios with ``cft_model_driver``, which links the driver with the replayer and replays each trace in the process which records it; see :ccf_repo:`tests/cft_model/README.md`.
  ``cft_model_driver --explore`` also changes the scenarios at random, and replays each changed run, to find runs in which the implementation and the model disagree, or which show an outcome that no scenario does.
* **KV**: building with ``-DCCF_KV_TRACING=ON`` enables test-only trace capture in ``kv_test``.
  :ccf_repo:`tests/kv_trace_validation.py` captures the purpose-built ``KV trace *`` test cases and a seeded concurrent fuzzer, then checks every trace with ``kv-replay`` unless ``--capture-only`` is passed.
  Tracing is disabled in normal builds.
* **Consistency**: the ``consistency_trace_validation`` e2e test (:ccf_repo:`tests/consistency_trace_validation.py`) starts a three-node network running the :ccf_repo:`basic_tv <samples/apps/basic_tv/>` JavaScript application, and runs :ccf_repo:`tests/tvc.py` against it to record client requests, responses and transaction statuses to ``consistency/trace.ndjson``.
  The test suspends the primary to cause an election during the recording.
* **Disaster recovery**: nodes started with the ``CCF_RECOVERY_TRACE`` environment variable set log each step of the recovery decision protocol as an ``RDP_TRACE`` record.
  These scenarios only run in the SNP Genoa CI job, where :ccf_repo:`tests/infra/recovery_trace.py` replays the node logs of the quorum, failover and multiple-timeout scenarios in :ccf_repo:`tests/e2e_operations.py` through ``disaster-recovery-replay``.

Every replayer is also checked against committed fixtures: valid traces that it must accept and invalid traces that it must reject.

Continuous integration
----------------------

The :ccf_repo:`Lean workflow <.github/workflows/lean.yml>` runs on pull requests that change the Lean packages, the consensus or KV implementation, or the trace tests.

* A package job for each of ``common``, ``consensus``, ``consistency``, ``disaster-recovery`` and ``kv`` runs the kernel and axiom check (``lake check``), import coverage and architecture checks, formatting and linting, and, where applicable, the package's replay fixtures.
* Separate capture jobs build CCF and record consensus, KV and consistency traces from the tests described above.
  The consensus capture job also runs ``cft_model_test``.
* Replay jobs build each replayer and validate every captured trace.
  The consensus replay job also reports which outcomes of the model's handlers the captured traces show, and which none shows; see :ccf_repo:`lean/consensus/replay/README.md`.
* A final ``Lean models and proofs`` job succeeds only if all of the above succeed.

The disaster recovery traces are replayed by the SNP Genoa job in the main CI workflow instead, since that is where the recovery scenarios run.

A separate ``Lean Mathlib equivalence`` workflow proves that the replacements for Mathlib definitions in ``lean/common`` are equivalent to the Mathlib originals, and runs only when those definitions change; see :ccf_repo:`lean/mathlib-equivalence/README.md`.

Running locally
---------------

Install Lean with `elan <https://lean-lang.org/install/>`__.
The Lean toolchain is pinned by :ccf_repo:`lean/lean-toolchain`, and the models are independent of normal CCF builds.
The only part of a default CCF build which needs Lean is ``cft_driver``; without Lean, it is not built and ``cft_scenario_test`` is disabled.
``cft_model_driver`` also needs Lean, and is built only with ``-DCFT_MODEL_DRIVER=ON``.
From a package directory under ``lean/``, the common checks are:

.. code-block:: bash

    lake build --wfail --fail-fast
    lake check --inadvisably-no-sandbox
    lake exe check-imports
    lake lint

To check formatting of all tracked Lean files, run ``scripts/lean-format-checks.sh`` from the repository root, optionally passing a package name.

``lake check --inadvisably-no-sandbox`` performs the kernel and axiom checks.
The flag disables build isolation so the package can use the shared ``common`` modules; only run this command on code you trust.
The consensus package recommends running it only in CI.
Each package README lists its complete validation commands, including how to build its replayer, replay its fixtures, and generate and replay traces from a local CCF build.
For the KV model, see also :ref:`build_apps/kv/semantics:Reproducing a run`.

The :ref:`trace viewer <operations/recovery:Trace viewer>` steps through recovery decision protocol traces as the Lean model replays them.

Background
----------

The approach of validating the implementation against formal specifications in CI is described in the 2025 paper `Smart Casual Verification of the Confidential Consortium Framework <https://github.com/microsoft/CCF/blob/main/CCF-VERIFICATION-NSDI-2025.pdf>`__ (see :doc:`/research/index`).
The specifications described in that paper were written in TLA+; they have since been removed from the repository and replaced by the Lean models described on this page.
