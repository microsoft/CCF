Consensus Protocols
===================

In order to guarantee system reliability changes to the key-value store must be agreed by a number of nodes before being applied. The number of nodes that need to agree on a change before it is applied depends on the consensus protocol being run.

The default consensus protocol for CCF is a version of Raft which provides Crash Fault Tolerance.

There is an option of enabling PBFT for the consensus protocol. PBFT provides Byzantine Fault Tolerance.

.. warning:: Currently CCF with PBFT is in development and should not be used in a production environment.

Raft Consensus Protocol
-----------------------

CCF runs with a version of Raft that provides Crash Fault Tolerance. This means that if the network can tolerate up to ``f`` nodes crashing (or being un-responsive) then there need to be ``2*f + 1`` nodes participating in the network in total to guarantee liveness. Raft will only commit to a change once it has been shared with ``f + 1`` nodes.
If any nodes are faulty or compromised then integrity may be lost.

When running CCF with Raft any requests that require the key-value store to be altered go via the Primary node. The Primary node executes the request and then serialises and encrypts the write set resulting from that execution.
The resulting write set will be persisted to the ledger and replicated to the other (Backup) nodes. Backup nodes will in turn persist the change to their ledger, decrypt and deserialise the write set, and apply it to their key-value store. This results in a consistent state across nodes and ledgers.

When ``f + 1`` nodes have applied the change the Primary will then consider it to be committed. If there is a disagreement and changes can not be committed (e.g. Primary is un-responsive), nodes will roll back to the latest valid state and issue an election for a new node to become Primary.

To provide verifiability and auditability the Primary node periodically signs the current state of the ledger. When the signature is replicated successfully across nodes then all changes up to that point are considered globally committed and any key-value changes will not be rolled back beyond that point.

PBFT Consensus Protocol
-----------------------

There is an option of enabling CCF with PBFT as a consensus providing Byzantine Fault Tolerance. This means that if the network can tolerate up to ``f`` nodes acting in a non benign way (either non-responsive or compromised nodes) then there need to be ``3*f + 1`` nodes participating in the network in total to guarantee liveness and integrity. PBFT will only commit to a change once ``2*f + 1`` nodes have confirmed the same execution result.

When running CCF with PBFT any requests that require they key-value store to be altered will be broadcasted to all nodes. The Primary node will provide execution ordering of incoming requests but requests will be executed on each Backup node, serialised, encrypted, and persisted on each nodes' ledger. This results in a consistent state across nodes and ledgers.
The nodes then communicate with each other and when ``2*f + 1`` nodes have confirmed the same execution result it will be considered as committed. If there is a disagreement and changes can not be committed, nodes will roll back to the latest valid state and an election (view change in PBFT terminology) will be triggered to elect a new Primary.

To provide verifiability and auditability the Primary node periodically signs the current state of the ledger. When the signature is replicated successfully across nodes then all changes up to that point are considered globally committed and any key-value changes will not be rolled back beyond that point.

As mentioned above PBFT is still under development and should not be enabled in a production environment. Listed below are the high level current PBFT limitations.

- The ledger and network keys are currently held in each node. As a result a single byzantine node may allow extraction of node and network secrets.
- There is no support yet for node configuration changes, meaning no support for adding/removing nodes after the network has been opened
- There is no guarantee that primary elections will be successful at this point
- There is no support yet for catastrophic recovery

By default CCF runs with Raft. To enable PBFT CCF must be built with the the build switch **PBFT** set to ON. The ``--consensus pbft`` CLI argument must also be provided when starting up the nodes (see :ref:`here <operators/start_network:Starting a New Network>` for starting up a newtork and nodes).