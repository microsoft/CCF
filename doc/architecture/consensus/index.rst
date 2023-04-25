Consensus Protocol
==================

The consensus protocol for CCF is Crash Fault Tolerance (:term:`CFT`) and is based on `Raft <https://raft.github.io/>`_. The key differences between the original Raft protocol (as described in the `Raft paper <https://raft.github.io/raft.pdf>`_), and CCF Raft are as follows:

* Transactions in CCF Raft are not considered to be committed until a subsequent signed transaction has been committed. More information can be found :doc:`here </architecture/merkle_tree>`. Transactions in the ledger before the last signed transactions are discarded during leader election.
* By default, CCF supports one-phase reconfiguration and you can find more information :doc:`here <1tx-reconfig>`. Note that CCF Raft does not support node restart as the unique identity of each node is tied to the node process launch. If a node fails and is replaced, it must rejoin Raft via reconfiguration.
* In CCF Raft, clients receive an early response with a :term:`Transaction ID` (view and sequence number) before the transaction has been replicated to Raft's ledger. The client can later use this transaction ID to verify that the transaction has been committed by Raft.
* CCF Raft uses an additional mechanism so a newly elected leader can more efficiently determine the current state of a follower's ledger when the two ledgers have diverged. This enables the leader to bring the follower up to date more quickly. CCF Raft also batches appendEntries messages.

CFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CCF node JSON configuration:

- ``consensus.message_timeout`` is the Raft heartbeat timeout. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``consensus.election_timeout``.
- ``consensus.election_timeout`` is the Raft election timeout. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

Extensions for Omission Faults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning:: Support for these extensions is work-in-progress. See https://github.com/microsoft/CCF/issues/2577. 

The CFT consensus variant also supports some extensions for :term:`omission fault`.
This may happen when the network is unreliable and may lead to one or more nodes being isolated from the rest of the network.

Supported extensions include:

- "CheckQuorum": the primary node automatically steps down, in the same view, if it does not hear back (via ``AppendEntriesResponse`` messages) from a majority of backups within a ``consensus.election_timeout`` period. This prevents an isolated primary node from still processing client write requests without being able to commit them.

Replica State Machine
---------------------

Membership
~~~~~~~~~~

Any node of the network is always in one of four membership states. The dotted arrows in the
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


Further information about reconfiguration:

.. toctree::
    1tx-reconfig
