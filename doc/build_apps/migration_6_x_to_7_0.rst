6.x to 7.0 Migration Guide
==========================

This page outlines the major changes introduced in 7.0 and how developers and operators should update their applications and deployments when migrating from 6.x to 7.0.

A full feature list is available in the `7.0 release notes <https://github.com/microsoft/CCF/releases/tag/ccf-7.0.0-rc0>`_.


Snapshot Requirements for Upgrades
-----------------------------------

When upgrading a CCF service from 6.x to 7.0, operators must ensure that 7.0 nodes start from a snapshot created by a 6.x service at version 6.0.21 or later. This requirement ensures consistent ledger chunk sizes across the network, as changes in 7.0 affect how ledger chunks are sized.

.. warning:: 7.0 nodes joining the network must start from a snapshot created by a 6.0.21 (or later) node. Attempting to join with an older snapshot or no snapshot may result in inconsistent chunk sizes and potential ledger integrity issues.

Upgrade Procedure
~~~~~~~~~~~~~~~~~

The recommended upgrade procedure is:

1. Ensure all nodes in the network are running version 6.0.21 or later (preferably the latest 6.x release).
2. Generate a fresh snapshot from the 6.x service:
   
   - Trigger snapshot generation on the primary node using the ``trigger_snapshot`` governance action, or
   - Wait for the next automatic snapshot based on the configured ``snapshots.tx_count``.

3. Verify the snapshot is committed by checking the ``snapshots.directory`` for files ending in ``.committed``.
4. Make the committed snapshot available to new 7.0 nodes (either via shared read-only directory or using the ``fetch_recent_snapshot`` feature).
5. Start upgrading nodes to 7.0 one at a time, ensuring each new 7.0 node joins from the recent 6.x snapshot.
6. Once all nodes are upgraded to 7.0, the service will operate normally with consistent chunk sizes.

For more information on snapshots and ledger management, see :doc:`/operations/ledger_snapshot`.


Version Live Compatibility
--------------------------

When upgrading CCF services from one major version to the next, our usual recommendation is to upgrade from ``N.latest`` to ``N+1.0.0``. Interoperation between other versions is not guaranteed.

.. note:: For upgrades from 6.x to 7.0 specifically, a minimum version of 6.0.21 is required before upgrading. While upgrading from the latest 6.x release is recommended for the best experience, 6.0.21 is the minimum supported version that ensures proper snapshot compatibility and consistent chunk sizes in 7.0.
