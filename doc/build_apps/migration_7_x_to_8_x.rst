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
