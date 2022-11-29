Disaster Recovery
=================

For unexpected reasons, a significant number [#crash]_ of CCF nodes may become unavailable. In this catastrophic scenario, operators and members can recover transactions that were committed on the crashed service by starting a new network.

The disaster recovery procedure is costly (e.g. the service identity certificate will need to be re-distributed to clients) and should only be staged once operators are confident that the service will not heal by itself. In other words, the recovery procedure should only be staged once a majority of nodes do not consistently report one of them as their primary node. 

.. tip:: See :ccf_repo:`tests/infra/health_watcher.py` for an example of how a network can be monitored to detect a disaster recovery scenario.

Overview
--------

The recovery procedure consists of two phases:

1. Operators should retrieve one of the ledgers of the previous service and re-start one or several nodes in ``recover`` mode. The public transactions of the previous network are restored and the new network established.

2. After agreeing that the configuration of the new network is suitable, members should vote to accept to recover the network and once this is done, submit their recovery shares to initiate the end of the recovery procedure. See :ref:`here <governance/accept_recovery:Accepting Recovery and Submitting Shares>` for more details.

.. note:: Before attempting to recover a network, it is recommended to make a copy of all available ledger and snapshot files.

.. tip:: See :ref:`build_apps/run_app:Sandbox recovery` for an example of the recovery procedure using the CCF sandbox.

Establishing a Recovered Public Network
---------------------------------------

To initiate the first phase of the recovery procedure, one or several nodes should be started with the ``Recover`` command in the ``cchost`` config file (see also the sample recovery configuration file :ccf_repo:`recover_config.json </samples/config/recover_config.json>`):

.. code-block:: bash

    $ cat /path/to/config/file
      ...
      "command": {
        "type": "Recover",
        ...
        "recover": {
          "initial_service_certificate_validity_days": 1
        }
      ...
    $ cchost --config /path/to/config/file

Each node will then immediately restore the public entries of its ledger ("ledger.directory`` and ``ledger.read_only_ledger_dir`` configuration entries). Because deserialising the public entries present in the ledger may take some time, operators can query the progress of the public recovery by calling :http:GET:`/node/state` which returns the version of the last signed recovered ledger entry. Once the public ledger is fully recovered, the recovered node automatically becomes part of the public network, allowing other nodes to join the network.

The recovery procedure can be accelerated by specifying a valid snapshot file created by the previous service in the directory specified via the ``snapshots.directory`` configuration entry. If specified, the ``recover`` node will automatically recover the snapshot and the ledger entries following that snapshot, which in practice should be a fraction of the total time required to recover the entire historical ledger.`

The state machine for the ``recover`` node is as follows:

.. mermaid::

    graph LR;
        Uninitialized-- config -->Initialized;
        Initialized-- recovery -->ReadingPublicLedger;
        ReadingPublicLedger-->PartOfPublicNetwork;
        PartOfPublicNetwork-- member shares reassembly -->ReadingPrivateLedger;
        ReadingPrivateLedger-->PartOfNetwork;

.. note:: It is possible that the length of the ledgers of each node may differ slightly since some transactions may not have yet been fully replicated. It is preferable to use the ledger of the primary node before the service crashed. If the latest primary node of the defunct service is not known, it is recommended to `concurrently` start as many nodes as previous existed in ``recover`` mode, each recovering one ledger of each defunct node. Once all nodes have completed the public recovery procedure, operators can query the highest recovered signed seqno (as per the response to the :http:GET:`/node/state` endpoint) and select this ledger to recover the service. Other nodes should be shutdown and new nodes restarted with the ``join`` option.

Similarly to the normal join protocol (see :ref:`operations/start_network:Adding a New Node to the Network`), other nodes are then able to join the network.

.. warning:: After recovery, the identity of the network has changed. The new service certificate ``service_cert.pem`` must be distributed to all existing and new users.

The state machine for the ``join`` node is as follows:

.. mermaid::

    graph LR;
        Uninitialized-- config -->Initialized;
        Initialized-- join -->Pending;
        Pending-- poll status -->Pending;
        Pending-- trusted -->PartOfPublicNetwork;

Summary Diagram
---------------

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Node 0
        participant Node 1
        participant Node 2

        Operators->>+Node 0: cchost recover
        Node 0-->>Operators: Service Certificate 0
        Note over Node 0: Reading Public Ledger...

        Operators->>+Node 1: cchost recover
        Node 1-->>Operators: Service Certificate 1
        Note over Node 1: Reading Public Ledger...

        Operators->>+Node 0: GET /node/state
        Node 0-->>Operators: {"last_signed_seqno": 50, "state": "readingPublicLedger"}
        Note over Node 0: Finished Reading Public Ledger, now Part of Public Network
        Operators->>Node 0: GET /node/state
        Node 0-->>Operators: {"last_signed_seqno": 243, "state": "partOfPublicNetwork"}

        Operators->>+Node 1: GET /node/state
        Node 1-->>Operators: {"last_signed_seqno": 36, "state": "readingPublicLedger"}
        Note over Node 1: Finished Reading Public Ledger, now Part of Public Network
        Operators->>Node 1: GET /node/state
        Node 1-->>Operators: {"last_signed_seqno": 203, "state": "partOfPublicNetwork"}

        Note over Operators, Node 1: Operators select Node 0 to start the new network (243 > 203)

        Operators->>+Node 1: cchost shutdown

        Operators->>+Node 2: cchost join
        Node 2->>+Node 0: Join network (over TLS)
        Node 0-->>Node 2: Join network response
        Note over Node 2: Part of Public Network

Once operators have established a recovered crash-fault tolerant public network, the existing members of the consortium :ref:`must vote to accept the recovery of the network and submit their recovery shares <governance/accept_recovery:Accepting Recovery and Submitting Shares>`.

Notes
-----

- Operators can track the number of times a given service has undergone the disaster recovery procedure via the :http:GET:`/node/network` endpoint (``recovery_count`` field).

.. rubric:: Footnotes

.. [#crash] When using CFT as consensus algorithm, CCF tolerates up to `(N-1)/2` crashed nodes (where `N` is the number of trusted nodes constituting the network) before having to perform a recovery procedure. For example, in a 5-node network, no more than 2 nodes are allowed to fail for the service to be able to commit new transactions.
