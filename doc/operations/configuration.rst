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

.. note::

    - Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

    - Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.

Environment variables
---------------------

In addition to the configuration file, cchost behaviour can be modified with the following environment variables:

CCF_IGNORE_FIRST_SIGTERM
~~~~~~~~~~~~~~~~~~~~~~~~

When set, will cause a node to ignore the first `SIGTERM` it receives, but the ``/node/process`` endpoint will return `{"stop_notice": true}`.

A second `SIGTERM` will cause the process to shut down as normal. This can be useful in orchestration settings where nodes receive unsollicited signals that the operator wishes to react to.