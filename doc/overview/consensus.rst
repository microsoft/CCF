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

This describes the reconfiguration as implemented currently. Note, that the one-transaction reconfiguration is only valid for CFT.

From a ledger and KV store perspective, reconfiguration is a single **reconfiguration transaction**. Any transaction that contains at least one write to ``public:ccf.gov.nodes.info`` setting a node's status to ``TRUSTED`` or ``RETIRED`` is such a reconfiguration transaction.

In contrast to normal transactions, reconfiguration transactions will only commit when the necessary quorum of acknowledgements is reached in **both** the previous and the new configuration it defines. From a consensus perspective (ie. replication and primary election), the transaction takes effect immediately.

The following sample illustrates the addition of a single node to a one-node network:

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
        Note right of Node 1: Active configs := [Cfg 0, Cfg 1]
        Node 1->>Node 0: Acknowledge 3.42

        Note right of Node 0: 3.42 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]

        Node 0->>Node 1: Notify commit 3.42
        Note right of Node 1: Active configs := [Cfg 1]

.. note:: This diagram assumes the reconfiguration transaction itself is committable which is a simplification. In reality it is not committable since in CCF only signatures can be committed. This means that in reality, reconfiguration transactions only commit when the next signature does. For the sake of simplicity, we omit signatures from the diagrams on this page.

The following sample illustrates replacing the node in a one-node network:

.. mermaid::

    sequenceDiagram
        participant Members
        participant Node 0
        participant Node 1

        Note over Node 0: State in KV: TRUSTED
        Note over Node 1: State in KV: PENDING

        Note right of Node 0: Cfg 0: [Node 0]
        Note right of Node 0: Active configs: [Cfg 0]

        Members->>+Node 0: Vote for Node 1 to become TRUSTED and Node 0 to become RETIRED

        Note right of Node 0: Reconfiguration Tx ID := 3.42
        Note right of Node 0: Cfg 1 := [Node 1]
        Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
        Node 0-->>-Members: Success

        Note over Node 0: State in KV := RETIRED

        Node 1->>+Node 0: Poll join
        Node 0-->>-Node 1: Trusted

        Node 0->>Node 1: Replicate 3.42
        Note over Node 1: State in KV := TRUSTED
        Note right of Node 1: Active configs := [Cfg 0, Cfg 1]
        Node 1->>Node 0: Acknowledge 3.42

        Note right of Node 0: 3.42 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]

        Node 0->>Node 1: Notify commit 3.42
        Note right of Node 1: Active configs := [Cfg 1]

At this point, Node 0 is aware that its retirement has been committed. It therefore stops replicating and issuing heartbeats. **However**, it does not immediately stop responding to voting requests and also does not stop propagating its own view of the global commit index. In the single node example above, the old leader Node 0 could remove itself from the network without consequences upon realizing that its retirement has been committed. For larger networks however, the leader could not do that as it would lead to situations where other nodes would not know of the global commit of the reconfiguration as the leader immediately left the network upon observing this change. In that case, followers of the old configuration may trigger timeouts that are unnecessary and potentially dangerous for the liveness of the system if they each leave the network upon noticing that the new configuration is globally committed.

Instead, upon retiring from a network, retired leaders still respond to requests from followers in a way that helps to propagate the current global commit index to all other nodes and will also vote in the next election to help one of the nodes in the new configuration become elected. The leader in the old configuration will not however accept any new entries into the log or send any more heartbeats. It effectively stepped down as leader and will not replicate new messages but will stay available for queries of the latest state that it was responsible for. The old leader can leave the network or be taken offline from the network once the new configuration makes progress in its global commit (i.e., once the newly elected leader sees its global commit index increase beyond the index that included the reconfiguration itself).

For crash fault tolerance, this means the following: Before the reconfiguration the network could suffer f_C0 failures. After the reconfiguration, the network can suffer f_C1 failures. During the reconfiguration, the network can only suffer a maximum of f_C0 failures in the old **and** f_C1 failures in the new configuration as a failure in either configuration is unacceptable. This transitive period where the system relies on both configurations ends once the new configuration's leader's global commit index surpasses the commit that included the reconfiguration as described above.

In our example above, the election timeout on Node 1 simply expires and causes Node 1 to call for an election, which it wins immediately.

Two-transaction Reconfiguration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A two-transaction reconfiguration is triggered by the same mechanism as in one-transaction reconfiguration, i.e. a change to ``public:ccf.gov.nodes.info``. It does however not become active immediately. Joining nodes are held in a ``LEARNER`` state in which they receive copies of the ledger, but they are not taken into account in commit-level decisions or leader selection until they are caught up sufficiently with the rest of the network. They recognize this fact by observing the commit of the reconfiguration transaction that includes its own addition to ``public:ccf.gov.nodes.info`` while replaying the reconfiguration transaction. This means that they have seen all preceding transactions up until their addition to the network.

Once a node reaches this point, they submit an RPC call for promotion to the current leader, which changes the ``ready_for_promotion`` flag in their entry in ``public:ccf.gov.nodes.info``. When the number of nodes in the next scheduled configuration reaches the required quorum of acknowledgements, the new configuration becomes fully active and the leader confirms this by promoting all of the new nodes of the configuration (some of which may still be catching up) to ``TRUSTED``. It is also at this point that nodes scheduled for retirement can safely begin to retire.

This sample illustrates the addition of a single node to a one-node network with two-transaction reconfiguration:

.. mermaid::

    sequenceDiagram
        participant Members
        participant Node 0
        participant Node 1

        Note over Node 0: State in KV: TRUSTED
        Note over Node 1: State in KV: PENDING

        Note right of Node 0: Cfg 0: [Node 0]
        Note right of Node 0: Active configs: [Cfg 0]

        Members->>+Node 0: Vote for Node 1 to become LEARNER

        Note right of Node 0: Reconfiguration Tx ID := 3.42
        Note right of Node 0: Cfg 1 := [Node 0, Node 1]
        Note right of Node 0: Active configs := [Cfg 0]
        Node 0-->>-Members: Success


        Node 0->>Node 1: Replicate Tx ID 3.42
        Note over Node 1: State in KV := LEARNER
        Node 1->>Node 0: Acknowledge Tx ID 3.42

        Node 0->>Node 1: Notify commit 3.42
        
        Node 1->>+Node 0: Ready-for-promotion RPC for Node 1
        Note over Node 0: Node 1 in KV := UP_TO_DATE_LEARNER
        Note over Node 0: All nodes in Cfg 1 in KV := TRUSTED
        Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
        Node 0-->>-Node 1: Success @ Tx ID 3.43

        Node 0->>Node 1: Replicate Tx ID 3.43
        Note over Node 1: State in KV := TRUSTED
        Node 1->>Node 0: Acknowledge Tx ID 3.43


        Note right of Node 0: Tx ID 3.43 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]

Joining a small number of nodes to a large, existing network will lead to almost-instant promotion of the joining node if both the existing and the new configuration have a sufficient number of nodes for quorums. Learners also help to improve the liveness of the system, because they do not necessarily have to receive the entire ledger from the leader immediately. Further, the two transactions on the ledger make it clear that the configuration change was not instant and it allows for other mechanisms to gate the switch to a new configuration on the committment to a number of other transactions on the ledger, for instance those required for the successful establishment of a Byzantine network identity.


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
