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

CFT parameters can be configured when starting up a network (see :doc:`here </operators/start_network>`). The parameters that can be set via the CLI are:

- ``raft-timeout-ms`` is the Raft heartbeat timeout in milliseconds. The Raft leader sends heartbeats to its followers at regular intervals defined by this timeout. This should be set to a significantly lower value than ``--raft-election-timeout-ms``.
- ``raft-election-timeout-ms`` is the Raft election timeout in milliseconds. If a follower does not receive any heartbeat from the leader after this timeout, the follower triggers a new election.

BFT Consensus Protocol
----------------------

.. warning:: BFT consensus protocol is experimental in CCF

There is an option of enabling CCF with BFT as a consensus protocol providing Byzantine Fault Tolerance.

PBFT parameters can be configured when starting up a network (see :doc:`here </operators/start_network>`). The parameters that can be set via the CLI are:

- ``pbft-view-change-timeout-ms`` is the PBFT view change timeout in milliseconds. If a backup does not receive the pre-prepare message for a request forwarded to the primary after this timeout, the backup triggers a view change.
- ``pbft-status-interval-ms`` is the PBFT status timer interval in milliseconds. All PBFT nodes send messages containing their status to all other known nodes at regular intervals defined by this timer interval.

BFT is still under development and should not be enabled in a production environment.

There is an open research question of `node identity with Byzantine nodes <https://github.com/microsoft/CCF/issues/893>`_.

By default CCF runs with CFT. To run CCF with BFT the ``--consensus bft`` CLI argument must be provided when starting up the nodes (see :doc:`/operators/start_network` for starting up a network and nodes).
