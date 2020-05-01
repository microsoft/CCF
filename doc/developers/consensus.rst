Consensus Protocols
===================

CCF supports multiple consensus protocols.

The default consensus protocol for CCF is Raft.

There is an option of enabling PBFT for the consensus protocol.

.. warning:: Currently CCF with PBFT is in development and should not be used in a production environment.

Raft Consensus Protocol
-----------------------

The Raft implementation in CCF provides Crash Fault Tolerance.

For more information on the Raft protocol please see the orignial `Raft paper <https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf>`_.

Raft parameters can be configured when starting up a network (see :ref:`here <operators/start_network:Starting a New Network>`). The paramters that can be set via the CLI are:

- ``raft-timeout-ms`` is the Raft heartbeat timeout in millisecons. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``--raft-election-timeout-ms``.
- ``raft-election-timeout-ms`` is the Raft election timeout in milliseconds. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

PBFT Consensus Protocol
-----------------------

There is an option of enabling CCF with PBFT as a consensus protocol providing Byzantine Fault Tolerance.

For more information on the PBFT protocol please see the original `PBFT paper <http://pmg.csail.mit.edu/papers/osdi99.pdf>`_.

PBFT parameters can be configured when starting up a network (see :ref:`here <operators/start_network:Starting a New Network>`). The paramters that can be set via the CLI are:

- ``pbft-view-change-timeout-ms`` is the PBFT view change timeout in milliseconds. If a backup does not receive the pre-prepare message for a request forwarded to the primary after this timeout, the backup triggers a view change.
- ``pbft-status-interval-ms`` is the PBFT status timer interval in milliseconds. All PBFT nodes send messages containing their status to all other known nodes at regular intervals defined by this timer interval.


PBFT is still under development and should not be enabled in a production environment. Features to be completed and bugs are tracked under the `Complete ePBFT support in CCF <https://github.com/microsoft/CCF/milestone/4>`_ milestone.

There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

By default CCF runs with Raft. To run CCF with PBFT the ``--consensus pbft`` CLI argument must be provided when starting up the nodes (see :ref:`here <operators/start_network:Starting a New Network>` for starting up a newtork and nodes).