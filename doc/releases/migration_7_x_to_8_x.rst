7.x to 8.x Migration Guide
========================================

This page describes how application developers and operators can prepare for the transition from CCF 7.x to 8.x.

.. note::

    This guide is being developed ahead of 8.0. The removals described below are planned for 8.0; deprecated features remain available in 7.x.

Request Forwarding
------------------

Removal of request forwarding between nodes is planned for 8.0. Migrate applications and deployments to HTTP redirection while still running 7.x.

This requires changes to RPC interface configuration, endpoint definitions, and client redirect handling. See :doc:`fwd_to_redirect` for configuration examples, endpoint strategy mappings, and authentication considerations.

Ringbuffer-Era Configuration
----------------------------------------

The ringbuffer has been removed. Replace its legacy configuration names with settings for the remaining ledger and node-to-node limits:

.. list-table::
   :header-rows: 1

   * - Legacy setting
     - Replacement
   * - ``memory.circuit_size``
     - ``ledger.max_pending_append_bytes``
   * - ``memory.max_msg_size``
     - ``ledger.max_read_size`` and ``node_to_node.max_message_size``
   * - ``memory.max_fragment_size``
     - None; this setting is ignored and should be removed.

The defaults remain 16MB for pending ledger appends and 64MB for each size limit. Configure the ledger read and node-to-node message limits independently.
See :doc:`/operations/configuration` for the setting descriptions and :doc:`/operations/resource_usage` for backlog threshold behavior.

Legacy fields remain accepted in 7.x and produce INFO deprecation notices at startup and with ``--check``. For each limit, an explicitly supplied new setting takes precedence over its legacy alias; otherwise the alias supplies the value, falling back to the default when neither is supplied.
Removal of the entire ``memory`` section is planned for 8.0. Migrate to the new settings on a 7.x release that supports them, then remove the ``memory`` section before upgrading to 8.x.

``ledger.max_read_size`` limits ledger-entry data bytes, including entry framing. No ringbuffer response metadata allowance is subtracted, even when using the legacy alias.
This increases the effective read budget by 2048 bytes compared with previous releases at the same configured size.
``ledger.max_transaction_size`` must not exceed this budget. The independent node-to-node limit includes message headers but excludes the 4-byte length prefix.

Snapshot Receipts
-----------------

Snapshots carry a COSE receipt of their evidence transaction since 7.0, and 8.x nodes accept only those receipts.
Snapshots written by 6.x and earlier releases carry a JSON receipt, which 8.x nodes reject like any snapshot that fails verification (see :ref:`operations/ledger_snapshot:Join or Recover From Snapshot`): a joining node marks the file as ignored in its ``snapshots.directory`` and moves on to an older snapshot or fetches one from the service, and a recovering node moves on to an older snapshot or to the ledger.
A service whose newest snapshot predates 7.0 therefore recovers from its ledger on 8.x.
An 8.x node joining a service whose newest snapshot predates 7.0 fetches and rejects that snapshot; its later join requests are then held to the sequence number its target node started from, so it is admitted and replays the ledger when the target itself started from the ledger, or from a snapshot no newer than the joiner's own.
When the target started from a newer snapshot, the joiner keeps fetching and rejecting until the service has a usable snapshot.
Create a snapshot on the service before adding 8.x nodes (:http:POST:`/node/snapshot:create`), so that they join from a snapshot with a COSE receipt.
``ccf.ledger.Snapshot`` and ``read_ledger.py --snapshot`` in the 8.x Python package reject these snapshots as well.

ML-DSA Service Identity
-----------------------

A service started or recovered by a node built with ML-DSA support (OpenSSL 3.5 or newer, the Azure Linux 4 builds of 8.x) gets an ML-DSA service identity in addition to its classical one: an ML-DSA service certificate, stored as ``pq_cert`` in ``public:ccf.gov.service.info`` and returned by :http:GET:`/node/network`, with the parameter set chosen by ``command.start.service_mldsa_parameter_set`` or ``command.recover.service_mldsa_parameter_set`` (default ``ML-DSA-65``).
Its public key is published in the same transaction as the ``PQ`` entry of :ref:`audit/builtin_maps:``service.signing_identities```.
Nodes that join a service never create one.

- A live code upgrade does not create it. Joining nodes only receive the identity the service already has, so a 7.x service upgraded to 8.x nodes keeps its classical identity only.
- Starting a new service or recovering an existing one on such a node always creates it. Recovery of a classical-only ledger is the way to give an existing service an ML-DSA identity.
- 7.x runs on Azure Linux 3 with OpenSSL 3.3 and never creates an ML-DSA identity; Azure Linux 4 with OpenSSL 3.5 is 8.x only, and running 7.x on OpenSSL 3.5 is unsupported.
- Once a service has an ML-DSA identity, every node must be able to hold it.
  Join requests from nodes built without ML-DSA support, including all 7.x nodes, are rejected with ``400 Bad Request`` before the node is recorded, and an 8.x node built without ML-DSA support aborts the recovery of a ledger whose service has one at the end of the public ledger.
  Rolling such a service back to 7.x nodes is therefore impossible by joining and unsupported by disaster recovery: 7.x nodes recover the ledger, and the recovered service silently loses its ML-DSA identity.
  Plan the recovery that introduces the identity for after the live upgrade has completed and been validated.
- The ML-DSA service certificate is renewed by the ``set_pq_service_certificate_validity`` proposal of the 8.x default constitution (see :ref:`governance/common_member_operations:Renewing ML-DSA Service Certificate`).
  A recovery keeps the constitution stored in the ledger, so under a 7.x or custom constitution the ML-DSA certificate expires after ``initial_service_certificate_validity_days``.
  After the recovery that introduces the identity and before the first renewal, install the 8.x default constitution with ``set_constitution``, or port its ``set_pq_service_certificate_validity`` action into the custom constitution.
