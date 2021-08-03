Consensus Protocols
===================

CCF supports multiple consensus protocols.

The default consensus protocol for CCF is Crash Fault Tolerance (:term:`CFT`) and there is an experimental option of enabling Byzantine Fault Tolerance (:term:`BFT`).

Below, we give an overview over the nodes state machine in both settings and the retirement mechanics that apply across the two protocols. 

CFT Consensus Protocol
-----------------------

The crash fault tolerant implementation in CCF is based on Raft. You can find more information on the Raft implementation in CCF :doc:`here <cft>`.

CFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CLI are:

- ``raft-timeout-ms`` is the Raft heartbeat timeout in milliseconds. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``--raft-election-timeout-ms``.
- ``raft-election-timeout-ms`` is the Raft election timeout in milliseconds. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

BFT Consensus Protocol
----------------------
.. warning:: CCF with BFT is currently still in development and should not be used in a production environment.

More details on this mode is given :doc:`here <bft>`. There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

By default CCF runs with CFT **and BFT is disabled on release versions**. To run CCF with BFT, CCF first needs to be :doc:`built from source </contribute/build_ccf>`. Then, the ``--consensus bft`` CLI argument must be provided when starting up the nodes (see :doc:`/operations/start_network` for starting up a network and nodes).

BFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CLI are:

- ``bft-view-change-timeout-ms`` is the BFT view change timeout in milliseconds. If a backup does not receive the pre-prepare message for a request forwarded to the primary after this timeout, the backup triggers a view change.
- ``bft-status-interval-ms`` is the BFT status timer interval in milliseconds. All BFT nodes send messages containing their status to all other known nodes at regular intervals defined by this timer interval.


Replica State Machine
---------------------

Simplified
~~~~~~~~~~

Main states and transitions in CCF consensus. Note that while the implementation of the transitions differs between CFT and BFT, the states themselves do not.

.. mermaid::

    graph LR;
        Init-->Leader;
        Init-->Follower;
        Follower-->Candidate;
        Candidate-->Follower;
        Candidate-->Leader;
        Leader-->Retired;
        Follower-->Retired;

Retirement details
~~~~~~~~~~~~~~~~~~

The transition towards retirement involves two additional elements of state:

- Retirement index (RI): Index at which node is set to ``Retired`` in ``public:ccf.gov.nodes.info``
- Retirement Committable Index (RCI): Index at which the retirement transaction first becomes committable, ie. the first signature following the transaction.

A node permanently transitions to ``Retired`` once it has observed commit reaching its Retirement Committable Index.

.. mermaid::

    graph LR;
        Follower-->FRI[Follower w/ RI];
        FRI-->Follower;
        FRI-->FRCI[Follower w/ RCI];
        FRCI-->Follower;
        FRCI-->Retired;

.. mermaid::

    graph LR;
        Leader-->LRI[Leader w/ RI];
        LRI-->Follower;
        LRI-->LRCI[Leader w/ RCI: reject new entries];
        LRCI-->Follower;
        LRCI-->Retired;

Note that because the rollback triggered when a node becomes aware of a new term never preserves unsigned transactions,
and because RCI is always the first signature after RI, RI and RCI are always both rolled back if RCI itself is rolled back.

.. toctree::
    cft
    bft