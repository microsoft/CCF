Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the executable via the ``--config /path/to/config/file`` argument.

.. tip::

    JSON configuration samples:

    - Minimal configuration: :ccf_repo:`minimal_config.json </samples/config/minimal_config.json>`
    - Complete ``start`` configuration: :ccf_repo:`start_config.json </samples/config/start_config.json>`
    - Complete ``join`` configuration: :ccf_repo:`join_config.json </samples/config/join_config.json>`
    - Complete ``recover`` configuration: :ccf_repo:`recover_config.json </samples/config/recover_config.json>`

    A single configuration file can be verified using the executable, but without launching a node, using the ``--check`` option:

    .. code-block:: bash

        $ /opt/ccf/bin/js_generic --config /path/to/config/file --check

.. include:: generated_config.rst


For migration from deprecated ringbuffer-era configuration, see :doc:`/build_apps/migration_7_x_to_8_x`.

.. _observability_export:

Observability Export
--------------------

To export consensus protocol traces (not ordinary console logs), add the experimental ``observability.fluentd`` array to your node configuration and restart the node.
Use trusted Fluentd ``in_forward`` TCP listeners: connections are unauthenticated and unencrypted.

.. code-block:: json

    {
      "observability": {
        "fluentd": [
          { "host": "127.0.0.1", "port": "24224", "delivery": "buffered-best-effort" },
          { "host": "127.0.0.1", "port": "24225", "delivery": "unbuffered-non-blocking" }
        ]
      }
    }

Each collector receives the same traces.
For a single collector, use one array entry; to migrate an existing single-object configuration, wrap it in an array.
Omit the array or leave it empty to disable export.

Choose a ``delivery`` policy per collector:

- ``buffered-best-effort`` (default): retain queued records while the collector is unavailable or cannot accept data.
- ``unbuffered-non-blocking``: drop queued records when the collector is unavailable or cannot accept data.

Optional ``queue_capacity`` on each array entry defaults to 4096 records per node thread.
Full queues drop new records under either policy; larger queues use more memory.

Both policies retain one in-flight record for retry, but delivery is not guaranteed and retries can produce duplicates.
Shutdown attempts to drain all collectors for up to two seconds, then drops remaining records; blocked console output can delay shutdown.


IPv6 Addresses
--------------

.. note:: IPv6 support is currently **experimental**.

Every address field accepts an IPv4 address, an IPv6 address, or a fully qualified domain name. IPv6 literals must be written in bracketed form, ``[host]:port``, so that the colons in the address are not mistaken for the host/port separator. This applies to all address fields, including:

- ``network.node_to_node_interface.bind_address`` and ``published_address``
- ``network.rpc_interfaces.[name].bind_address`` and ``published_address``
- ``command.join.target_rpc_address``

For example, to bind a node's interfaces to the IPv6 loopback address ``::1`` and publish an address on a different IPv6 host:

.. code-block:: json

    {
      "network": {
        "node_to_node_interface": { "bind_address": "[::1]:8081" },
        "rpc_interfaces": {
          "primary_rpc_interface": {
            "bind_address": "[::1]:8080",
            "published_address": "[2001:db8::1]:12345"
          }
        }
      }
    }

A node joining over IPv6 sets ``command.join.target_rpc_address`` to the bracketed address of an existing node:

.. code-block:: json

    {
      "command": {
        "join": { "target_rpc_address": "[2001:db8::1]:12345" }
      }
    }

When a node is identified by an IPv6 literal, the matching ``node_certificate.subject_alt_names`` entry uses the ``iPAddress:`` prefix with the **unbracketed** address, for example ``"iPAddress:2001:db8::1"``.

.. note:: ``published_address`` defaults to ``bind_address`` when omitted, and is the address embedded in redirect URLs returned to clients. Brackets are added automatically where required, so a published IPv6 address appears in a redirect as ``https://[2001:db8::1]:12345/...``.


Operator Features
-----------------

The `enabled_operator_features` configuration field allows enabling or disabling specific operator features on a per-interface basis.

Currently supported features are:

1. 'SnapshotRead': gates access to endpoints used to fetch snapshots directly from nodes (:http:GET:`/node/snapshot`, :http:HEAD:`/node/snapshot`, :http:GET:`/node/snapshot/{snapshot_name}` and :http:HEAD:`/node/snapshot/{snapshot_name}`).
2. 'LedgerChunkRead': gates access to endpoints used to retrieve ledger chunks (:http:GET:`/node/ledger_chunk`, :http:HEAD:`/node/ledger_chunk`, :http:GET:`/node/ledger_chunk/{chunk_name}`, :http:HEAD:`/node/ledger_chunk/{chunk_name}`, :http:GET:`/node/ledger_chunk/committed_prefix/{chunk_name}` and :http:HEAD:`/node/ledger_chunk/committed_prefix/{chunk_name}`).
3. 'SnapshotCreate': gates access to the operator endpoint used to create a snapshot on the next signature transaction (:http:POST:`/node/snapshot:create`).

Since these operations may require disk IO and produce large responses, these features should not be enabled on interfaces with public access, and instead restricted to interfaces with local connectivity for node-to-node and operator access.


.. note::

    - Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

    - Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.


Upgrading to COSE-Only Ledger Signatures
-----------------------------------------

By default, CCF nodes emit **dual** ledger signatures: a traditional node signature and a COSE Sign1 signature. Applications control this via the ``ccf::get_ledger_sign_mode()`` weak-symbol callback declared in ``ccf/node/ledger_sign_mode.h``, which returns one of three modes:

- ``Dual`` (default) — emit both signature types, accept all joiners.
- ``CoseAllowDualJoin`` — emit only COSE signatures, but still accept join requests from ``Dual``-mode nodes. Use during rolling upgrades.
- ``CoseOnly`` — emit only COSE signatures, reject ``Dual``-mode joiners. Final state after upgrade.

The mode is set at link time by providing a strong definition in the application binary. Joining nodes advertise their signing mode in the join request.

A rolling upgrade from ``Dual`` to ``CoseOnly`` is a two-step process:

1. **CoseAllowDualJoin.** Deploy a binary that returns ``CoseAllowDualJoin``. Replace nodes one at a time. During this phase, new nodes running the old ``Dual`` binary can still join as replacements.

2. **CoseOnly.** Once all nodes are upgraded, deploy a binary that returns ``CoseOnly``. Replace nodes again. After this, ``Dual`` joiners are rejected.
