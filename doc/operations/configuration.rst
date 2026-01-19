Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the ``cchost`` executable via the ``--config /path/to/config/file`` argument.

.. tip::

    JSON configuration samples:

    - Minimal configuration: :ccf_repo:`minimal_config.json </samples/config/minimal_config.json>`
    - Complete ``start`` configuration: :ccf_repo:`start_config.json </samples/config/start_config.json>`
    - Complete ``join`` configuration: :ccf_repo:`join_config.json </samples/config/join_config.json>`
    - Complete ``recover`` configuration: :ccf_repo:`recover_config.json </samples/config/recover_config.json>`

    A single configuration file can be verified using the ``cchost`` executable, but without launching the enclave application, using the ``--check`` option:

    .. code-block:: bash

        $ cchost --config /path/to/config/file --check

.. include:: generated_config.rst


Operator Features
-----------------

The `enabled_operator_features` configuration field allows enabling or disabling specific operator features on a per-interface basis.

Currently supported features are:

1. 'SnapshotRead': gates access to endpoints used to fetch snapshots directly from nodes (:http:GET:`/node/snapshot`, :http:HEAD:`/node/snapshot`, :http:GET:`/node/snapshot/{snapshot_name}` and :http:HEAD:`/node/snapshot/{snapshot_name}`).
2. 'LedgerChunkRead': gates access to endpoints used to retrieve ledger chunks, to be added in a future release.

Since these operations may require disk IO and produce large responses, these features should not be enabled on interfaces with public access, and instead restricted to interfaces with local connectivity for node-to-node and operator access.


.. note::

    - Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

    - Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.