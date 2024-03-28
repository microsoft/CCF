One-transaction Reconfiguration
===============================

This describes the default reconfiguration scheme as currently implemented. When using CFT, CCF also supports :doc:`two-transaction reconfiguration <2tx-reconfig>`.

Below, we only discuss changes to the original Raft implementation that are not trivial. For more information on Raft please see the original `Raft paper <https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf>`_.

From a ledger and KV store perspective, reconfiguration is a single **reconfiguration transaction**. Any transaction that contains at least one write to :ref:`audit/builtin_maps:``nodes.info``` setting a node's status to ``TRUSTED`` or ``RETIRED`` is such a reconfiguration transaction.

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

At this point, Node 0 is aware that its retirement has been committed. It therefore stops replicating and issuing heartbeats. **However**, it does not immediately stop responding to voting requests and also does not stop propagating its own view of the commit index. In the single node example above, the old leader Node 0 could remove itself from the network without consequences upon realizing that its retirement has been committed. For larger networks however, the leader could not do that as it would lead to situations where other nodes would not know of the commit of the reconfiguration as the leader immediately left the network upon observing this change. In that case, followers of the old configuration may trigger timeouts that are unnecessary and potentially dangerous for the liveness of the system if they each leave the network upon noticing that the new configuration is committed.

Instead, upon retiring from a network, retired leaders still respond to requests from followers in a way that helps to propagate the current commit index to all other nodes and will also vote in the next election to help one of the nodes in the new configuration become elected. The leader in the old configuration will not however accept any new entries into the log or send any more heartbeats. It effectively stepped down as leader and will not replicate new messages but will stay available for queries of the latest state that it was responsible for.

The old leader can leave the network or be taken offline from the network once the new configuration makes progress in its commit (i.e., once the newly elected leader sees its commit index increase beyond the index that included the reconfiguration itself). As a convenience to the operator, the :http:GET:`/node/network/removable_nodes` exposes a list of nodes whose retirement is complete and who are no longer useful to consensus.

For crash fault tolerance, this means the following: Before the reconfiguration the network could suffer f_C0 failures. After the reconfiguration, the network can suffer f_C1 failures. During the reconfiguration, the network can only suffer a maximum of f_C0 failures in the old **and** f_C1 failures in the new configuration as a failure in either configuration is unacceptable. This transitive period where the system relies on both configurations ends once the new configuration's leader's commit index surpasses the commit that included the reconfiguration as described above.

In our example above, the election timeout on Node 1 simply expires and causes Node 1 to call for an election, which it wins immediately.

Retirement details
~~~~~~~~~~~~~~~~~~

Retirement of a node runs through four phases, as indicated by the following diagram. It starts with a reconfiguration transaction (RTX) and it involves 
two additional elements of state:

- Retirement index (RI): Index at which node is set to ``Retired`` in ``public:ccf.gov.nodes.info``
- Retirement Committable Index (RCI): Index at which the retirement transaction first becomes committable, ie. the first signature following the transaction.

A node permanently transitions to the ``Completed`` phase once it has observed commit reaching its Retirement Committable Index.

.. mermaid::

    graph TB;
        Active-- RTX executes -->Started

        subgraph Retired
            Started-- RTX commits -->Ordered;
            Ordered[Ordered: RI set]
            Ordered-- Signature -->Signed;
            Signed[Signed: RCI set]
            Signed-- RCI commits -->Completed;            
            Ordered-.->Started
            Signed-.->Ordered
        end

Until the very last phase (``Completed``) is reached, a retiring leader will continue to act as leader, although it will not execute new transactions once it observes RCI. 

Note that because the rollback triggered when a node becomes aware of a new term never preserves unsigned transactions,
and because RCI is always the first signature after RI, RI and RCI are always both rolled back if RCI itself is rolled back.