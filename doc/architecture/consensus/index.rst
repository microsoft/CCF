Consensus Protocols
===================

The default consensus protocol for CCF is Crash Fault Tolerance (:term:`CFT`) and there is an experimental option of enabling Byzantine Fault Tolerance (:term:`BFT`).

Below, we give an overview over the nodes state machine in both settings and the retirement mechanics that apply across the two protocols.

CFT Consensus Protocol
----------------------

The crash fault tolerant implementation in CCF is based on `Raft <https://raft.github.io/>`_. The key differences between the original Raft protocol (as described in the `Raft paper <https://raft.github.io/raft.pdf>`_), and CCF Raft are as follows:

* Transactions in CCF Raft are not considered to be committed until a subsequent signed transaction has been committed. More information can be found :doc:`here </consensus/merkle_tree>`. Transactions in the ledger before the last signed transactions are discarded during leader election.
* By default, CCF supports one-phase reconfiguration and you can find more information :doc:`here <1tx-reconfig>`. CCF also supports Raft's two-phase reconfiguration protocol, as described :doc:`here <2tx-reconfig>`. Note that CCF Raft does not support node restart as the unique identity of each node is tied to the node process launch. If a node fails and is replaced, it must rejoin Raft via reconfiguration.
* In CCF Raft, clients receive an early response with a :term:`Transaction ID` (view and sequence number) before the transaction has been replicated to Raft's ledger. The client can later use this transaction ID to verify that the transaction has been committed by Raft.
* CCF Raft uses an additional mechanism so a newly elected leader can more efficiently determine the current state of a follower's ledger when the two ledgers have diverged. This enables the leader to bring the follower up to date more quickly. CCF Raft also batches appendEntries messages.

CFT parameters can be configured when starting up a network (see :doc:`here </operations/start_network>`). The parameters that can be set via the CCF node JSON configuration:

- ``consensus.message_timeout`` is the Raft heartbeat timeout. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``consensus.election_timeout``.
- ``consensus.election_timeout`` is the Raft election timeout. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

BFT Consensus Protocol
----------------------

.. warning:: CCF with BFT is currently in development and should not be used in a production environment.

More details on this mode is given :doc:`here <2tx-reconfig>`. There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

By default CCF runs with CFT **and BFT is disabled on release versions**. To run CCF with BFT, CCF first needs to be :doc:`built from source </contribute/build_ccf>`. Then, the ``--consensus bft`` CLI argument must be provided when starting up the nodes (see :doc:`/operations/start_network` for starting up a network and nodes).

Replica State Machine
---------------------

Membership
~~~~~~~~~~

Any node of the network is always in one of four membership states. When using one-transaction reconfiguration, the ``Learner`` and
``RetirementInitiated`` states are not used and each node is either in the ``Active`` or ``Retired`` states. The dotted arrows in the
state diagram indicate a transition on rollback:

.. mermaid::

    graph LR;
        Learner-->Active
        Active-->RetirementInitiated
        Active-->Retired
        RetirementInitiated-.->Active
        RetirementInitiated-->Retired
        Retired-.->RetirementInitiated
        Retired-.->Active

The membership state a node is currently is provided in the output of the :http:GET:`/node/consensus` endpoint.

Simplified Leadership
~~~~~~~~~~~~~~~~~~~~~

Main consensus states and transitions. Note that while the implementation of the transitions differs between CFT and BFT, the states themselves do not.
Nodes are not in any consensus state if they are not in the ``Active`` membership state yet, but once they are, they transition between all the
consensus states as the network evolves:

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


Further information about the reconfiguration schemes:

.. toctree::
    1tx-reconfig
    2tx-reconfig
