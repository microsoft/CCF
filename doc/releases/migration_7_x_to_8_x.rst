7.x to 8.x Migration Guide
========================================

This page describes how application developers and operators can prepare for the transition from CCF 7.x to 8.x.

.. note::

    This guide is being developed ahead of 8.0. The removals described below are planned for 8.0; deprecated features remain available in 7.x.

Request Forwarding
------------------

Removal of request forwarding between nodes is planned for 8.0. Migrate applications and deployments to HTTP redirection while still running 7.x.

This requires changes to RPC interface configuration, endpoint definitions, and client redirect handling. See :doc:`fwd_to_redirect` for configuration examples, endpoint strategy mappings, and authentication considerations.

Node-to-Node TLS
----------------

The 7.x bridge supports opt-in TLS alongside legacy channels.
TLS-only configuration and removal of the legacy endpoint are deferred to 8.0.
First upgrade every node to a TLS-capable bridge release.
Only TLS-capable nodes should advertise TLS endpoints: do not configure ``node_to_node_tls_interface`` on pre-bridge releases, which preserve the field but do not open a TLS listener.
Then replace nodes with the TLS-capable bridge release, explicitly configuring both endpoints and permitting network access to both.
TLS is exercised between dual-enabled nodes while pairs involving legacy-only nodes continue using legacy channels.

Before any later TLS-only upgrade, inspect each trusted node's recorded network information through ``GET /node/network/nodes`` and verify its TLS published endpoint is present and reachable.
An older primary may have dropped the TLS field from a joining node's metadata.
Upgrading that primary or changing local configuration alone does not repair previously recorded metadata: replace the affected node through a metadata-aware primary.
Do not introduce TLS-only nodes until all required peers advertise usable TLS endpoints.
See :doc:`/operations/configuration` for the opt-in configuration.

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

Public C++ Headers
------------------

Public header components (top-level directories and standalone headers under ``include/ccf/``) no longer depend on each other cyclically.
Several headers and functions moved to the component that owns them, without forwarding headers or aliases, so C++ applications must update their includes:

.. list-table::
   :header-rows: 1

   * - 7.x
     - 8.x
   * - ``ccf/tx.h``
     - ``ccf/kv/tx.h``
   * - ``ccf/endpoint.h``
     - ``ccf/endpoints/endpoint.h``
   * - ``ccf/endpoint_context.h``
     - ``ccf/endpoints/endpoint_context.h``
   * - ``ccf/common_auth_policies.h``
     - ``ccf/endpoints/common_auth_policies.h``
   * - ``ccf/crypto/base64.h``
     - ``ccf/ds/base64.h``
   * - ``ccf::crypto::b64_from_raw``, ``ccf::crypto::b64url_from_raw``, ``ccf::crypto::raw_from_b64`` and ``ccf::crypto::raw_from_b64url``
     - The same functions in ``ccf::ds``

Class and function names are otherwise unchanged.
``ccf/app_interface.h`` still provides the endpoint registry, authentication policies and transaction types.

Some headers no longer provide declarations that they did not use themselves.
Include the header that declares them instead:

.. list-table::
   :header-rows: 1

   * - Declarations
     - No longer provided by
     - Include
   * - ``ccf::kv::Map``, ``ccf::kv::Set``, ``ccf::kv::Value`` and their ``ccf::Service*`` aliases
     - ``ccf/kv/tx.h`` and ``ccf/crypto/sha256_hash.h``, and headers which obtained them from these, such as ``ccf/claims_digest.h``
     - ``ccf/service/map.h`` or the matching ``ccf/kv/`` header
   * - ``ccf::AbstractNodeContext``
     - ``ccf/indexing/strategies/seqnos_by_key_bucketed.h``
     - ``ccf/node_context.h``
   * - ``ccf::DID``, ``ccf::Feed`` and the UVM endorsements tables
     - ``ccf/pal/uvm_endorsements.h``
     - ``ccf/service/tables/uvm_endorsements.h``

The ``BlitSerialiser<ccf::crypto::Sha256Hash>`` specialisation now lives with its primary template in ``ccf/kv/serialisers/blit_serialiser.h``.
Applications that use it should include that header directly.

Applications can now include ``ccf/research/create_tx_claims_digest.h`` using only the installed SDK.

CCF's private headers are no longer installed under ``include/ccf/_private``, and the ``ccf`` CMake target no longer adds ``include/ccf`` to the include path.
Includes such as ``"ccf/_private/kv/kv_types.h"`` and ``"_private/kv/kv_types.h"`` therefore no longer resolve.
Replace ``ccf/_private/js/checks.h`` (or ``_private/js/checks.h``) with ``ccf/js/checks.h``.
Rename ``JS_CHECK_EXC``, ``JS_CHECK_SET`` and ``JS_CHECK_OR_THROW`` to ``CCF_JS_CHECK_EXC``, ``CCF_JS_CHECK_SET`` and ``CCF_JS_CHECK_OR_THROW`` respectively.

Public headers do not depend on private headers.
If your application or its tests still need a declaration that is only available in a private header, migrate to a public API or open an issue to request a supported replacement.

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
- When a service with an ML-DSA identity opens, it endorses the ML-DSA identity of the previous service with its own, as it does for the classical identity (see :ref:`audit/builtin_maps:``previous_service_identity_endorsement```).
  A service whose previous service had no ML-DSA identity, such as the one that introduces it, endorses its own ML-DSA identity, which starts the chain.
