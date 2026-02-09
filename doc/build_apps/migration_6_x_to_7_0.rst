6.x to 7.0 Migration Guide
==========================

This page outlines the major changes introduced in 7.0 and how developers and operators should update their applications and deployments when migrating from 6.x to 7.0.

A full feature list is available in the `7.0 release notes <https://github.com/microsoft/CCF/releases/tag/ccf-7.0.0-rc0>`_.


Snapshot Requirements for Upgrades
-----------------------------------

When upgrading a CCF service from 6.x to 7.0, operators must ensure that all nodes create a new snapshot from the 6.x service before starting 7.0 nodes.

Snapshot Generation Before Upgrade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before upgrading any nodes to 7.0:

1. Ensure all nodes in the network are running 6.0.21 or later (practically, the latest 6.x release).
2. Generate a new snapshot from the 6.x service. This can be done by triggering the ``trigger_snapshot`` governance action or waiting for an automatic snapshot based on the configured ``snapshots.tx_count``.
3. Verify that the snapshot has been committed (file name ends with ``.committed``).

The reason for this requirement is to ensure consistent ledger chunk sizes across the network. Changes in 7.0 may affect how ledger chunks are sized, and starting 7.0 nodes from a 6.x snapshot ensures that all nodes in the upgraded service use consistent chunk boundaries.

.. warning:: 7.0 nodes joining the network must start from a snapshot created by a 6.0.21 (or later) node. Attempting to join with an older snapshot or no snapshot may result in inconsistent chunk sizes and potential ledger integrity issues.

Upgrade Procedure
~~~~~~~~~~~~~~~~~

The recommended upgrade procedure is:

1. Ensure all nodes are at version 6.0.21 or later (preferably 6.latest).
2. Trigger a new snapshot generation on the primary node using the ``trigger_snapshot`` governance action, or wait for the next automatic snapshot.
3. Verify the snapshot is committed by checking the ``snapshots.directory`` for files ending in ``.committed``.
4. Make the committed snapshot available to new 7.0 nodes (either via shared read-only directory or using the ``fetch_recent_snapshot`` feature).
5. Start upgrading nodes to 7.0 one at a time, ensuring each new 7.0 node joins from the recent 6.x snapshot.
6. Once all nodes are upgraded to 7.0, the service will operate normally with consistent chunk sizes.

For more information on snapshots and ledger management, see :doc:`/operations/ledger_snapshot`.


Version Live Compatibility
--------------------------

When upgrading CCF services from one major version to the next, our usual recommendation is to upgrade first to the initial release in the new major version before attempting upgrade to later versions; ``N.latest`` transitions to ``N+1.0.0``. Interoperation between other versions is not guaranteed.

.. note:: For upgrades from 6.x to 7.0, ensure all nodes are at 6.0.21 or later before beginning the upgrade process. Starting 7.0 nodes from snapshots created by earlier 6.x versions is not supported.
