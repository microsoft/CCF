Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the ``cchost`` executable via the ``--config /path/to/config/file`` argument.

.. tip::

    JSON configuration samples:

    - Minimal configuration: https://github.com/microsoft/CCF/blob/main/samples/config/minimal_config.json
    - Complete ``start`` configuration: https://github.com/microsoft/CCF/blob/main/samples/config/start_config.json
    - Complete ``join`` configuration: https://github.com/microsoft/CCF/blob/main/samples/config/join_config.json
    - Complete ``recover`` configuration: https://github.com/microsoft/CCF/blob/main/samples/config/recover_config.json

    A single configuration file can be verified using the ``cchost`` executable, but without launching the enclave application, using the ``--check`` option:

    .. code-block:: bash

        $ cchost --config /path/to/config/file --check

.. include:: generated_config.rst

.. note::

    - Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

    - Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.
