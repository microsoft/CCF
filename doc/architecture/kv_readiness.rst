KV Readiness Gate
=================

`Issue #5141 <https://github.com/microsoft/CCF/issues/5141>`_ identifies a startup window where RPC dispatch can observe snapshot maps and the Store version before the corresponding history is initialised. The required invariant is that no KV-backed RPC transaction starts until maps, version, history, consensus, and snapshot hooks form a coherent startup state.

Each network Store will expose a shared atomic lifecycle state with four values: ``Unavailable``, ``InstallingSnapshot``, ``Ready``, and ``Failed``. The node state machine owns transitions, while every frontend reads the same state. Generic Stores remain ready by default, and node construction explicitly marks the network Store unavailable before accepting RPC work.

Frontend dispatch will check logical frontend openness and Store readiness before constructing a ``CommittableTx``. When the Store is not ready, route lookup may select only a statically registered command endpoint, explicitly identified by endpoint metadata; unauthenticated, non-forwarded commands execute with ``CommandEndpointContext`` and no transaction. All other requests receive ``503 FrontendNotOpen``.

Fresh nodes move directly from unavailable to ready after history, encryption, and consensus setup. Join and recovery nodes remain unavailable while waiting for network state, enter snapshot installation before deserialisation, and publish ready only after history initialisation, hooks, consensus setup, and snapshotter restoration complete.

.. mermaid::

    stateDiagram-v2
        [*] --> Unavailable: node construction
        Unavailable --> Ready: fresh Store setup
        Unavailable --> InstallingSnapshot: startup snapshot selected
        InstallingSnapshot --> Ready: coherent state published
        InstallingSnapshot --> Failed: installation error
        Unavailable --> Failed: startup error

The initial implementation permits only startup transitions, so no transaction can be admitted in ``Ready`` before installation begins. Supporting snapshot installation after a Store has become ready would additionally require draining in-flight transactions or validating a captured generation before access and commit. An installation failure leaves the Store inaccessible rather than exposing partially published state; the private-recovery map swap remains outside this snapshot-specific gate.

Coverage will combine focused frontend tests with lifecycle coverage. Unit tests will prove that transactionless commands remain available without creating a transaction, KV-backed endpoints receive ``503`` until readiness, and normal dispatch resumes after publication; join or recovery coverage will exercise the unavailable-to-installing-to-ready transition around snapshot restoration.

Implementation steps
--------------------

* Add the atomic Store lifecycle state and node-owned transition helpers.
* Mark command endpoints explicitly and support static route lookup without a KV transaction.
* Add the transaction-free command dispatch path and reject other requests before transaction construction.
* Move initial node frontend opening after basic Store/history setup and publish readiness at the correct start, join, and recovery boundaries.
* Add frontend unit tests and join/recovery lifecycle coverage.
* Make startup polling treat the temporary ``503`` response as retryable.
* Run the relevant formatting, build, and test targets under normal and TSAN configurations.
