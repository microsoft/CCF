Consensus Protocols
===================

In order to guarantee system reliability changes to the key-value store must be agreed by a number of nodes before being applied. The number of nodes that need to agree on a change before it is applied depends on the consensus protocol being run.

The default consensus protocol for CCF is Raft.

There is an option of enabling PBFT for the consensus protocol.

.. warning:: Currently CCF with PBFT is in development and should not be used in a production environment.

Raft Consensus Protocol
-----------------------

The Raft implementation in CCF provides Crash Fault Tolerance.

For more information on the Raft protocol please see the orignial `Raft paper <https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf>`_.


PBFT Consensus Protocol
-----------------------

There is an option of enabling CCF with PBFT as a consensus protocol providing Byzantine Fault Tolerance.

For more information on the PBFT protocol plase see the original `PBFT paper <http://pmg.csail.mit.edu/papers/osdi99.pdf>`_.

As mentioned above PBFT is still under development and should not be enabled in a production environment. Features to be completed and bugs are tracked under the `Complete ePBFT support in CCF <https://github.com/microsoft/CCF/milestone/4>`_ milestone.

There is also the open research question of node identity with Byzantine nodes. The ledger and network keys are currently held in each node. As a result a single byzantine node may allow extraction of node and network secrets.

By default CCF runs with Raft. To enable PBFT CCF must be built with the the build switch **PBFT** set to ON. The ``--consensus pbft`` CLI argument must also be provided when starting up the nodes (see :ref:`here <operators/start_network:Starting a New Network>` for starting up a newtork and nodes).