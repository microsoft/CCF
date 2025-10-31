Consensus Protocol
==================

The consensus protocol for CCF implements Crash Fault Tolerance (:term:`CFT`) and is based on `Raft <https://raft.github.io/>`_. The key differences between the original Raft protocol (as described in the `Raft paper <https://raft.github.io/raft.pdf>`_), and CCF Raft are as follows:

* Transactions in CCF Raft are not considered to be committed until a subsequent signed transaction has been committed. More information can be found :doc:`here </architecture/merkle_tree>`. Transactions in the ledger before the last signed transactions are discarded during leader election.
* CCF Raft does not support node restart as the unique identity of each node is tied to the node process launch. If a node fails and is replaced, it must rejoin Raft via reconfiguration.
* In CCF Raft, clients receive an early response with a :term:`Transaction ID` (view and sequence number) before the transaction has been replicated to Raft's ledger. The client can later use this transaction ID to verify that the transaction has been committed by Raft.
* CCF Raft uses an additional mechanism so a newly elected leader can more efficiently determine the current state of a follower's ledger when the two ledgers have diverged. This enables the leader to bring the follower up to date more quickly. CCF Raft also batches appendEntries messages.

CFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CCF node JSON configuration:

- ``consensus.message_timeout`` is the Raft heartbeat timeout. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``consensus.election_timeout``.
- ``consensus.election_timeout`` is the Raft election timeout. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

Extensions for Omission Faults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning:: Support for these extensions is work-in-progress. See https://github.com/microsoft/CCF/issues/2577. 

The CFT consensus implementation in CCF also supports some extensions for :term:`omission fault`.
This may happen when the network is unreliable and may lead to one or more nodes being isolated from the rest of the network.

Supported extensions include:

- "CheckQuorum": the primary node automatically steps down, in the same view, if it does not hear back (via ``AppendEntriesResponse`` messages) from a majority of backups within a ``consensus.election_timeout`` period. This prevents an isolated primary node from still processing client write requests without being able to commit them.
- "NoTimeoutRetirement": a primary node that completes its retirement sends a ProposeRequestVote message to the most up-to-date node in the new configuration, causing that node to run for election without waiting for time out.
- "PreVote": followers must first request a pre-vote before starting a new election. This prevents followers from starting elections (and increasing the term) when they are isolated from the rest of the network.

Replica State Machine
---------------------

Membership
~~~~~~~~~~

Any node of the network is always in one of two membership states. The dotted arrows in the
state diagram indicate a transition on rollback:

.. mermaid::

    graph LR;
        Active-->Retired
        Retired-.->Active

The membership state a node is currently is provided in the output of the :http:GET:`/node/consensus` endpoint.

Simplified Leadership
~~~~~~~~~~~~~~~~~~~~~

Main consensus states and transitions. Nodes are not in any consensus state if they are not in the ``Active`` membership state yet,
but once they are, they transition between all the consensus states as the network evolves:

.. mermaid::

    graph LR;
        Follower-->Candidate;
        Candidate-->Follower;
        Candidate-->Leader;
        Candidate-->Candidate;
        Leader-->Follower;

The leadership state a node is currently is provided in the output of the :http:GET:`/node/consensus` endpoint.

Key-Value Store
~~~~~~~~~~~~~~~

Reconfiguration of the network is controlled via updates to the :ref:`audit/builtin_maps:``nodes.info``` built-in map, which assigns a :cpp:enum:`ccf::NodeStatus` to each node. Nodes with status :cpp:enumerator:`ccf::NodeStatus::PENDING` in this map do not have membership or leadership states yet. Nodes with status :cpp:enumerator:`ccf::NodeStatus::TRUSTED` are in the ``Active`` membership state and may be in any leadership state.

Reconfiguration
~~~~~~~~~~~~~~~

This discusses changes to the original Raft implementation that are not trivial. For more information on Raft please see the original `paper <https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf>`_.

From a ledger and KV store perspective, reconfiguration is materialised in two separate transactions:

  - Any transaction that contains at least one write to :ref:`audit/builtin_maps:``nodes.info``` setting a node's status to ``TRUSTED`` or ``RETIRED`` is a *reconfiguration transaction*.
  - Any transaction that contains at least one write to :ref:`audit/builtin_maps:``nodes.info``` setting a node's retired_committed to ``TRUE`` is a *retirement committed transaction*.

In contrast to normal transactions, reconfiguration transactions will only commit when the necessary quorum of acknowledgements is reached in **both** the previous and the new configuration it defines.

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

        Note over Node 0: State in KV := retired_committed = true
        Node 0->>Node 1: Replicate 3.43
        Node 1->>Node 0: Acknowledge 3.43

        Note right of Node 0: 3.43 commits (meets quorum in Cfg 1)
        Node 0->>Node 1: Notify commit 3.43

        Note over Node 0: Step down as leader

In the single node example above, it may be tempting to think that Node 0 can remove itself from the network upon realizing that its retirement has been committed.
However, this will lead to a situation where other nodes would not know the reconfiguration has been committed, and would be trying to establish commit on the reconfiguration transaction that necessitates a quorum of the old nodes.
Until every future primary is aware of the commit of the reconfiguration transaction, shutting down a quorum of the old configuration puts liveness at risk.

To avoid this problem, upon retiring from a network, retired nodes will continue to vote in elections, and retired leaders will continue to advance commit. They will not however accept any new entries into the log. 

Retired nodes can leave the network or be taken offline from the network once any node in the new configuration is elected and makes progress. As a convenience to the operator, the :http:GET:`/node/network/removable_nodes` exposes a list of nodes who are no longer useful to consensus, and whose KV entry can be deleted.

For crash fault tolerance, this means the following: Before the reconfiguration the network could suffer f_C0 failures. After the reconfiguration, the network can suffer f_C1 failures. During the reconfiguration, the network can only suffer a maximum of f_C0 failures in the old **and** f_C1 failures in the new configuration as a failure in either configuration is unacceptable. This transitive period where the system relies on both configurations ends once the new configuration's leader's commit index surpasses the commit that included the reconfiguration as described above.

In our example above, the election timeout on Node 1 simply expires and causes Node 1 to call for an election, which it wins immediately.

Retirement details
~~~~~~~~~~~~~~~~~~

Retirement of a node runs through five phases, as indicated by the following diagram. It starts with a reconfiguration transaction (RTX), involves 
two additional elements of state and ends with a retirement committed transaction (RTCX), whose commitment indicates that all future primaries are aware RTX is committed,
and no longer require nodes in the old configuration to make progress.

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
            Completed-- RTCX executes and commits -->RetiredCommitted
        end

Until the very last phase (``RetiredCommitted``) is reached, a retiring leader will continue to act as leader, although it will not execute new transactions once it observes RCI. 

Note that because the rollback triggered when a node becomes aware of a new term never preserves unsigned transactions,
and because RCI is always the first signature after RI, RI and RCI are always both rolled back if RCI itself is rolled back.

PreVote Extensions
~~~~~~~~~~~~~~~~~~

If a node's `RequestVote` requests are able to reach the cluster, but it is unable to hear the `AppendEntries` messages from the current leader (for example, due to network partitioning), it may start new elections, incrementing its term, which deposes the leader and disrupts the cluster.

To mitigate this, the PreVote extension requires that followers first become `PreVoteCandidates` and receive a quorum of speculative pre-votes to prove that they could be elected, using the standard Raft election conditions, before becoming `Candidates` and potentially disrupting the cluster.

More specifically, when a follower's election timeout elapses, it becomes a `PreVoteCandidate` for the current term  and sends out `RequestVote` messages with an additional `is_pre_vote` flag set to true.
If the `PreVoteCandidate` hears from a current leader, or a new leader, it reverts back to being a `Follower`.
Nodes receive this pre-vote request, and respond positively if node would have voted for the `PreVoteCandidate`'s ledger during an election, (ie. if the `PreVoteCandidate`'s ledger is at least as up to date as the receiver's ledger).
If the `PreVoteCandidate` receives a quorum of positive pre-vote responses, it then becomes a `Candidate`, increments its term, and the election proceeds as normal from here.

.. mermaid::

    sequenceDiagram
        participant Node 0
        participant Node 1
        participant Node 2

        Note over Node 0: Leader for term 2

        Note over Node 1: PreVoteCandidate in term 2
        Node 1 ->> Node 2: RequestVote(is_pre_vote=true, term=2)

        Note right of Node 2: No changes to Node 2's state
        Node 2 ->> Node 1: RequestVoteResponse(granted=true, is_pre_vote=true, term=2)

        Note over Node 1: Candidate in term 3
        Node 1 ->> Node 2: RequestVote(is_pre_vote=false, term=3) 

        Note right of Node 2: Updates term to 3 and votes for Node 1
        Node 2 ->> Node 1: RequestVoteResponse(granted=true, is_pre_vote=false, term=3)

        Note over Node 1: Leader for term 3

The only state update in response to a pre-vote message is that if the node's term is older than the pre-vote messages's it will update it.
This allows the pre-vote request to inform lagging nodes that a more recent term had a node succeed in its pre-vote, becomming a Candidate or a Leader.
This can be viewed as a piggybacking the term information from that previous Candidate or Leader, with the pre-vote request to the lagging node.

.. mermaid::

    sequenceDiagram
        participant Node 0
        participant Node 1
        participant Node 2

        Note over Node 0: Leader for term 2
        Note over Node 1: Follower in term 2
        Note over Node 2: Lagging Follower in term 1

        Note over Node 1: PreVoteCandidate in term 2
        Node 1 ->> Node 2: RequestVote(is_pre_vote=true, term=2)

        Note right of Node 2: Updates term to 2
        Node 2 ->> Node 1: RequestVoteResponse(granted=true, is_pre_vote=true, term=2)

        Note over Node 1: Candidate in term 3
        Node 1 ->> Node 2: RequestVote(is_pre_vote=false, term=3) 

        Note right of Node 2: Updates to term 3 and votes for Node 1
        Node 2 ->> Node 1: RequestVoteResponse(granted=true, is_pre_vote=false, term=3)

        Note over Node 1: Leader for term 3

Migration to PreVote
~~~~~~~~~~~~~~~~~~~~

Supposing we have a cluster of nodes which currently do not support PreVote, we must first migrate the cluster to support PreVote before we can enable it, as the nodes that do not support PreVote will respond incorrectly to PreVote requests.

To enable PreVote safely, we must first migrate the cluster to support PreVote messages, and then enable PreVote.
During the migration to enable PreVote, the pre-vote candidates will be less likely to be elected leader, as the other followers may preempt the pre-vote candidate and become candidates themselves.

We plan to enable PreVote in 6.X, and then enable PreVote in 7.X.