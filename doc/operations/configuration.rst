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


Operator Features
-----------------

The `enabled_operator_features` configuration field allows enabling or disabling specific operator features on a per-interface basis.

Currently supported features are:

1. 'SnapshotRead': gates access to endpoints used to fetch snapshots directly from nodes (:http:GET:`/node/snapshot`, :http:HEAD:`/node/snapshot`, :http:GET:`/node/snapshot/{snapshot_name}` and :http:HEAD:`/node/snapshot/{snapshot_name}`).
2. 'LedgerChunkRead': gates access to endpoints used to retrieve ledger chunks (:http:GET:`/node/ledger_chunk`, :http:HEAD:`/node/ledger_chunk`, :http:GET:`/node/ledger_chunk/{chunk_name}` and :http:HEAD:`/node/ledger_chunk/{chunk_name}`).
3. 'SnapshotCreate': gates access to the operator endpoint used to create a snapshot on the next signature transaction (:http:POST:`/node/snapshot:create`).

Since these operations may require disk IO and produce large responses, these features should not be enabled on interfaces with public access, and instead restricted to interfaces with local connectivity for node-to-node and operator access.


.. note::

    - Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

    - Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.


COSE-Only Ledger Signatures
----------------------------

By default, CCF nodes emit **dual** ledger signatures: a traditional node signature (stored in ``ccf.internal.signatures``) and a COSE Sign1 signature (stored in ``ccf.internal.cose_signatures``).

Applications can switch to **COSE-only** mode by providing an implementation of ``ccf::get_ledger_signing_mode()`` (declared in ``ccf/research/get_ledger_signing_mode.h``) that returns ``ccf::LedgerSignMode::COSE``. This follows the same weak-symbol override pattern as ``ccf::get_create_tx_claims_digest()``.

When the signing mode is ``COSE``:

- The node signs ledger entries using only COSE Sign1 with the service key. Traditional node signatures (``ccf.internal.signatures``) are not emitted.
- The signing mode is determined at link time and applies from the very first signature.

The default (weak) implementation returns ``Dual``, which retains backward-compatible behaviour by emitting both signature types.

