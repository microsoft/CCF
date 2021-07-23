Byzantine Fault Tolerance
=========================

Below we discuss the reconfiguration as implemented for the BFT setting. Technically the two-transaction scheme is not specific to BFT. In fact, Ongardie and Ousterhout also described a two-transaction reconfiguration mechanism for Raft. As such, the two-transaction scheme as described below could also be used in CFT. However in BFT, the following properties are desirable: 

1. A reconfiguration only starts when the reconfiguration transaction is committed, so a reconfiguration attempt can never roll back.
2. Reconfigurations are atomic. This creates room for additional conditions, such as checking that the byzantine reconfiguration (a multiple transaction protocol) is complete before proceeding to the new configuration.

BFT is still under development and should not be enabled in a production environment. There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

Two-transaction Reconfiguration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A two-transaction reconfiguration is triggered by the same mechanism as in one-transaction reconfiguration, i.e. a change to ``public:ccf.gov.nodes.info``. It does however not become active immediately. Joining nodes are held in a ``LEARNER`` state in which they receive copies of the ledger, but they are not taken into account in commit-level decisions or leader selection until a quorum of them has caught up. Nodes recognize that they are added to the network by observing the commit of the transaction that includes their own addition to ``public:ccf.gov.nodes.info``. This means that they have seen all preceding transactions up until their addition to the network. Similary, nodes that are to be retired recognize that their state is changed to ``RETIRING`` in ``public:ccf.gov.nodes.info``.

All nodes in the new configuration (including learners) submit an Observed Reconfiguration Commit (ORC) RPC call to the current leader once they observe a reconfiguration that changes their state. This allows the leader to track how many of the nodes in the new configuration are aware of that configuration. Once the number of nodes in the next scheduled configuration reaches the required quorum of acknowledgements, the leader changes the state of all
nodes of the new configuration that are in the ``LEARNER`` and ``RETIRING`` states to ``TRUSTED`` and ``RETIRED`` respectively, in ``public:ccf.gov.nodes.info``.

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

        Note right of Node 0: Tx ID := 3.42
        Note right of Node 0: Cfg 1 := [Node 0, Node 1]
        Note right of Node 0: Active configs := [Cfg 0]
        Node 0-->>-Members: Success

        Node 1->>+Node 0: Poll join
        Node 0-->>-Node 1: Learner

        Node 0->>Node 1: Replicate Tx ID 3.42
        Note over Node 1: State in KV := LEARNER
        Node 1->>Node 0: Acknowledge Tx ID 3.42

        Node 0->>Node 1: Notify commit 3.42

        Node 1->>+Node 0: ORC for Node 1
        Note over Node 0: Quorum reached. All nodes in Cfg 1: State in KV := TRUSTED
        Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
        Node 0-->>-Node 1: Success @ Tx ID 3.43

        Node 0->>Node 1: Replicate Tx ID 3.43
        Note over Node 1: State in KV := TRUSTED
        Node 1->>Node 0: Acknowledge Tx ID 3.43

        Note right of Node 0: Tx ID 3.43 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]


The following example illustrates one possible execution of an addition of two nodes to a one-node network.

.. mermaid::

    sequenceDiagram
        participant Members
        participant Node 0
        participant Node 1
        participant Node 2

        Note over Node 0: State in KV: TRUSTED
        Note over Node 1: State in KV: PENDING
        Note over Node 2: State in KV: PENDING

        Note right of Node 0: Cfg 0: [Node 0]
        Note right of Node 0: Active configs: [Cfg 0]

        Members->>+Node 0: Vote for Nodes 1 and 2 to become LEARNER

        Note right of Node 0: Tx ID := 3.42
        Note right of Node 0: Cfg 1 := [Node 0, Node 1, Node 2]
        Note right of Node 0: Active configs := [Cfg 0]
        Node 0-->>-Members: Success

        Node 1->>+Node 0: Poll join
        Node 0-->>-Node 1: Learner

        Node 2->>+Node 0: Poll join
        Node 0-->>-Node 2: Learner

        Node 0->>Node 1: Replicate Tx ID 3.42
        Note over Node 1: State in KV := LEARNER
        Node 1->>Node 0: Acknowledge Tx ID 3.42

        Node 0->>Node 2: Replicate Tx ID 3.42
        Note over Node 2: State in KV := LEARNER
        Node 2->>Node 0: Acknowledge Tx ID 3.42

        Node 0->>Node 1: Notify commit 3.42

        Node 1->>+Node 0: ORC for Node 1
        Note right of Node 0: Active configs := [Cfg 0]

        Node 0->>Node 2: Notify commit 3.42

        Node 2->>+Node 0: ORC for Node 2
        Note over Node 0: Quorum reached. All nodes in Cfg 1: State in KV := TRUSTED
        Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
        Node 0-->>-Node 2: Success @ Tx ID 3.43

        Node 0->>Node 1: Replicate Tx ID 3.43
        Note over Node 1: State in KV := TRUSTED
        Node 1->>Node 0: Acknowledge Tx ID 3.43
        Node 0->>Node 2: Replicate Tx ID 3.43
        Note over Node 2: State in KV := TRUSTED
        Node 2->>Node 0: Acknowledge Tx ID 3.43

        Note right of Node 0: Tx ID 3.43 commits (meets quorum in Cfg 0 and 1)
        Note right of Node 0: Active configs := [Cfg 1]

Joining a small number of nodes to a large network will lead to almost-instant promotion of the joining node if both the existing and the new configuration have a sufficient number of nodes for quorums. Learners also help to improve the liveness of the system, because they do not necessarily have to receive the entire ledger from the leader immediately. Further, the two transactions on the ledger make it clear that the configuration change was not instant and it allows for other mechanisms to gate the switch to a new configuration on the committment to a number of other transactions on the ledger, for instance those required for the successful establishment of a Byzantine network identity.


The following diagram illustrates retirement of the leader:

.. mermaid::

  sequenceDiagram
      participant Members
      participant Node 0
      participant Node 1

      Note over Node 0: State in KV: TRUSTED
      Note over Node 0: Leader
      Note over Node 1: State in KV: TRUSTED

      Note right of Node 0: Cfg 0: [Node 0, Node 1]
      Note right of Node 0: Active configs: [Cfg 0]

      Members->>+Node 0: Vote for Node 0 to become RETIRED

      Note right of Node 0: Tx ID := 3.42
      Note right of Node 0: Cfg 1 := [Node 1]
      Note right of Node 0: Active configs := [Cfg 0]
      Node 0-->>-Members: Success @ Tx ID 3.42

      Note over Node 0: State in KV := RETIRING

      Node 0->>Node 1: Replicate Tx ID 3.42
      Node 1->>Node 0: Acknowledge Tx ID 3.42

      Node 1->>+Node 0: ORC for Node 1
      Note left of Node 0: Tx ID := 3.43
      Note left of Node 0: (Quorum reached, all nodes in Cfg 1 are already TRUSTED)
      Note left of Node 0: All RETIRING nodes in Cfg 1: state in KV := RETIRED
      Note left of Node 0: Active configs := [Cfg 0, Cfg 1]
      Node 0-->>-Node 1: Success @ Tx ID 3.43

      Note over Node 0: State in KV := RETIRED

      Node 0->>Node 1: Replicate Tx ID 3.43
      Node 1->>Node 0: Acknowledge Tx ID 3.43
      Note right of Node 0: Active configs := [Cfg 0, Cfg 1]
      Note right of Node 0: Tx ID 3.43 commits (meets quorum in Cfg 0 and 1)

      Node 0->>Node 1: Notify commit 3.43
      Note right of Node 1: Active configs := [Cfg 1]
      Note over Node 1: Leader
