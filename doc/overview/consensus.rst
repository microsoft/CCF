Consensus Protocols
===================

CCF supports multiple consensus protocols.

The default consensus protocol for CCF is CFT.

There is an option of enabling BFT for the consensus protocol.

.. warning:: Currently CCF with BFT is in development and should not be used in a production environment.

CFT Consensus Protocol
-----------------------

The CFT implementation in CCF is based on Raft and provides Crash Fault Tolerance.

For more information on the Raft protocol please see the original `Raft paper <https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf>`_.

CFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CLI are:

- ``raft-timeout-ms`` is the Raft heartbeat timeout in milliseconds. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``--raft-election-timeout-ms``.
- ``raft-election-timeout-ms`` is the Raft election timeout in milliseconds. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

BFT Consensus Protocol
----------------------

.. warning:: BFT consensus protocol is experimental in CCF

BFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CLI are:

- ``bft-view-change-timeout-ms`` is the BFT view change timeout in milliseconds. If a backup does not receive the pre-prepare message for a request forwarded to the primary after this timeout, the backup triggers a view change.
- ``bft-status-interval-ms`` is the BFT status timer interval in milliseconds. All BFT nodes send messages containing their status to all other known nodes at regular intervals defined by this timer interval.

BFT is still under development and should not be enabled in a production environment. There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

By default CCF runs with CFT. To run CCF with BFT the ``--consensus bft`` CLI argument must be provided when starting up the nodes (see :doc:`/operations/start_network` for starting up a network and nodes).

Reconfiguration
---------------

One-transaction Reconfiguration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This describes the reconfiguration as implemented currently, this is only valid for CFT.

From a ledger an KV store perspective, reconfiguration is a single **reconfiguration transaction**.
Any transaction whose write-set contains at least one write to ``public:ccf.gov.nodes.info`` setting a node's status to ``TRUSTED`` or ``RETIRED`` is a **reconfiguration transaction**.

From a consensus perspective (ie. replication and primary election), the transaction takes effect immediately.
In particular, the **reconfiguration transaction** will only commit when the necessary quorum of acknowledgements is reached in **both** the previous and the new configuration it defines.

This sample illustrates the addition of a single node to a one-node network:

.. mermaid::

    sequenceDiagram
        participant Members
        participant Node 0
        participant Node 1

        Note over Node 0: State in KV: TRUSTED
        Note over Node 1: State in KV: PENDING

        Note right of Node 0: Cfg 0: [Node 0]
        Note right of Node 0: Active configs: [Cfg 0]

        Members->>+Node 0: Vote for Node 1 to become TRUSTED

        Note right of Node 0: Reconfiguration Tx ID := 3.42
        Note right of Node 0: Cfg 1 := [Node 0, Node 1]
        Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
        Node 0-->>-Members: Success

        Node 1->>+Node 0: Poll join
        Node 0-->>-Node 1: Trusted

        Node 0->>Node 1: Replicate 3.42
        Note over Node 1: State in KV := TRUSTED
        Node 1->>Node 0: Acknowledge 3.42

        Note right of Node 0: 3.42 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]


Two-transaction Reconfiguration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~