Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the ``cchost`` executable via the ``--config /path/to/config/file`` argument.

.. tip::

    JSON configuration samples:

    - Minimal configuration: https://github.com/microsoft/CCF/blob/main/samples/config/minimal_config.json
    - Full configuration: https://github.com/microsoft/CCF/blob/main/samples/config/config.json

    A single configuration file can be verified using the ``cchost`` executable, but without launching the enclave application, using the ``--check`` option:

    .. code-block:: bash

        $ cchost --config /path/to/config/file --check

Configuration Options
---------------------

``enclave``
~~~~~~~~~~~

- ``file``: Path to enclave application.
- ``type``: Type of enclave application (either ``"release"``, ``"debug"`` or ``"virtual"``). Default value: ``"release"``.

``network``
~~~~~~~~~~~

The ``network`` section includes configuration for the interfaces a node listens on (both node-to-node and RPC).

- ``node_to_node_interface``: Address (hostname and port) to listen on for incoming node-to-node connections.

Each node-to-node interface must contain the local RPC address (``bind_address``) the node binds to and listens on.

- ``rpc_interfaces``: Addresses (hostname and port) to listen on for incoming client TLS connections.

Each RPC interface must contain:

- The local RPC address (``bind_address``) the node binds to and listens on.
- The published RPC address (``published_address``) advertised to clients. Default value: value of ``bind_address``.
- The maximum number of active client sessions (``max_open_sessions_soft``) on that interface after which clients will receive an HTTP 503 error. Default value: ``1000``.
- The maximum number of active client sessions (``max_open_sessions_hard``) on that interface after which clients sessions will be terminated, before the TLS handshake is complete. Note that its value must be greater than the value of ``max_open_sessions_soft``. Default value: ``1010``.

Example:

.. code-block:: json

    "network": {
        "node_to_node_interface": {"bind_address": "127.0.0.1:0"},
        "rpc_interfaces": [
            {
                "bind_address": "127.0.0.1:0",
                "published_address": "foo.dummy.com:12345",
            },
            {
                "bind_address": "127.0.0.2:8080",
                "max_open_sessions_soft": 200,
                "max_open_sessions_hard": 210
            }
        ]
    }

``node_certificate``
~~~~~~~~~~~~~~~~~~~~

Optional. The ``node_certificate`` section includes configuration for the node x509 certificate.

- ``subject_name``: Subject name to include in node certificate. Default value: ``CN=CCF Node``.
- ``subject_alt_names``: List of ``iPAddress:`` or ``dNSName:`` strings to include as Subject Alternative Names (SAN) in node certificates. If none is set, the node certificate will automatically include the value of the main RPC interface ``published_address``. Default value: ``[]``.
- ``curve_id``: Elliptic curve to use for node identity key (``secp384r1`` or ``secp256r1``). Default value: ``"secp384r1"``.
- ``initial_validity_days``: Initial validity period (days) for node certificate. Default value: ``1`` day.

``command``
~~~~~~~~~~~

The ``command`` section includes configuration for the type of node (start, join or recover) and associated information.

- ``type``: Type of CCF node (either ``start``, ``join`` or ``recover``). Default value: ``"start"``.
- ``network_certificate_file``: For ``start`` and ``recover`` nodes, path to which network certificate will be written to on startup. For ``join`` nodes, path to the certificate of the existing network to join. Default value: ``"networkcert.pem"``.

.. _start configuration:

``start``
+++++++++

Only set when ``type`` is ``start``.

- ``constitution_files``: List of constitution files. These typically include ``actions.js``, ``validate.js``, ``resolve.js`` and ``apply.js``.

- ``members``: List of initial consortium members files, including identity certificates, public encryption keys and member data files.

.. note:: Common examples:

    - A recovery member with member data: ``{"certificate_file": "member_cert.pem", "encryption_public_key_file": "member_enc_pubk.pem", "data_json_file": "member_data.json"}``
    - A recovery member with no member data: ``{"certificate_file": "member_cert.pem", "encryption_public_key_file": "member_enc_pubk.pem"}``
    - A non-recovery member with member data: ``{"certificate_file": "member_cert.pem", "data_json_file": "member_data.json"}``
    - A non-recovery member with no member data: ``{"certificate_file": "member_cert.pem"}``

- ``service_configuration``: Initial service configuration, including:

    - ``maximum_node_certificate_validity_days``: The maximum number of days allowed for node certificate validity period. Default value: ``365`` days.
    - ``recovery_threshold``. Note that if the recovery threshold is set to ``0``, it is automatically set to the number of recovery members specified in ``members``.
    - ``reconfiguration_type``. The type of reconfiguration for new nodes. Default value: ``"OneTransaction"``.

Example:

.. code-block:: json

    "start": {
        "constitution_files": ["actions.js", "validate.js", "resolve.js", "apply.js"],
        "members": [
            {"certificate_file": "member0_cert.pem", "encryption_public_key_file": "member0_enc_pubk.pem"},
            {"certificate_file": "member1_cert.pem", "data_json_file": "member1_data.json"},
            {"certificate_file": "member2_cert.pem", "encryption_public_key_file": "member2_enc_pubk.pem"}
        ],
        "service_configuration":
        {
            "recovery_threshold": 0,
            "maximum_node_certificate_validity_days": 365,
            "reconfiguration_type": "OneTransaction"
        }
    }

.. _join configuration:

``join``
++++++++

Only set when ``type`` is ``join``.

- ``target_rpc_address``: Address (hostname and port) of a node of the existing service to join.
- ``retry_timeout``: Interval at which the node sends join requests to the existing network. Default value: ``"1000ms"`` [#time_string]_.

Example:

.. code-block:: json

    "join": {
        "retry_timeout": "1000ms",
        "target_rpc_address": {"hostname": "127.0.0.1", "port": "8080"}
    }

``ledger``
~~~~~~~~~~

- ``directory``: Path to main ledger directory. Default value: ``"ledger"``.
- ``read_only_directories``: Optional. Paths to read-only ledger directories. Note that only ``.committed`` files will be read from these directories. Default value: ``[]``.
- ``chunk_size``: Minimum size of the current ledger file after which a new ledger file (chunk) is created. Default value: ``"5MB"``  [#size_string]_.

``snapshots``
~~~~~~~~~~~~~

- ``directory``: Path to snapshot directory. Default value: ``"snapshots"``.
- ``tx_count``: Minimum number of transactions between two snapshots. Default value: ``10000``.

``logging``
~~~~~~~~~~~

- ``host_level``: Logging level for the `untrusted host`. Default value: ``"info"``.

.. note:: While it is possible to set the host log level at startup, it is deliberately not possible to change the log level of the enclave without rebuilding it and changing its code identity.

- ``format``: If ``"json"``, node logs will be formatted as JSON. Default value: ``"text"``.

``consensus``
~~~~~~~~~~~~~

- ``type``: Type of consensus protocol. Only ``CFT`` (Crash-Fault Tolerant) is currently supported. Default value: ``"CFT"``.
- ``message_timeout``: Interval at which the primary node sends messages to backup nodes to maintain its primary-ship. This should be set to a significantly lower value than ``election_timeout``. Default value: ``"100ms"``.
- ``election_timeout``: Timeout value after which backup node that have not received any message from the primary node will trigger a new election. This should be set to a significantly lower value than ``message_timeout``. Default timeout: ``"5000ms"``.

``ledger_signatures``
~~~~~~~~~~~~~~~~~~~~~

- ``tx_count``: Number of transactions after which a signature transaction is automatically generated. Default value: ``5000``.
- ``delay``: Maximum duration after which a signature transaction is automatically generated. Default value: ``"1000ms"``[#time_string]_.

.. note::
    Transaction commit latency in a CCF network is primarily a function of signature frequency. A network emitting signatures more frequently will be able to commit transactions faster, but will spend a larger proportion of its execution resources creating and verifying signatures. Setting signature frequency is a trade-off between transaction latency and throughput.

    The ledger signature interval options specify the intervals at which the generation of signature transactions is `triggered`. However, because of the parallel execution and queuing of transactions, the intervals between signature transactions may be slightly larger in practice.

``jwt``
~~~~~~~

- ``key_refresh_interval``: Interval at which JWT keys for issuers registered with auto-refresh are automatically refreshed. Default value: ``"30min"`` [#time_string]_.

``output_files``
~~~~~~~~~~~~~~~~

- ``node_certificate_file``: Path to self-signed node certificate output by node on startup. Default value: ``"nodecert.pem"``.
- ``node_pid_file``: Path to file in which ``cchost`` process identifier (PID) will be written to on startup. Default value: ``"cchost.pid"``.
- ``node_to_node_address_file``: Path to file in which node address (hostname and port) will be written to on startup. This option is particularly useful when binding to port ``0`` and getting auto-assigned a port by the OS. No file is created if this entry is not specified.
- ``rpc_addresses_file``: Path to file in which all RPC addresses (hostnames and ports) will be written to on startup. This option is particularly useful when binding to port ``0`` and getting auto-assigned a port by the OS. No file is created if this entry is not specified.

Advanced Configuration Options
------------------------------

.. warning:: The following configuration options have sensible default values and should be modified with care.

``tick_period``
~~~~~~~~~~~~~~~

Interval at which the enclave time will be updated by the host. Default value: ``"10ms"`` [#time_string]_.

``slow_io_logging_threshold``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration of I/O operations (ledger and snapshots) after which slow operations will be logged to node's log. Default value: ``"10000us"`` [#time_string]_.

``node_client_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~

Address to bind to for node-to-node client connections. If unspecified, this is automatically assigned by the OS.
This option is particularly useful for testing purposes (e.g. establishing network partitions between nodes).

``client_connection_timeout``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration after which unestablished client connections will be marked as timed out and either re-established or discarded. Default value: ``"2000ms"`` [#time_string]_.

``worker_threads``
~~~~~~~~~~~~~~~~~~

Experimental. Number of additional threads processing incoming client requests in the enclave. Default value: ``0``.

``memory``
~~~~~~~~~~

- ``circuit_size``: Size of the internal host-enclave ringbuffers, as a power of 2. Default value: ``"4MB"`` [#size_string]_.
- ``max_msg_size``: Maximum size for a message sent over the ringbuffer, as a power of 2. Messages may be split into multiple fragments, but this limits the total size of the sum of those fragments. Default value: ``"16MB"`` [#size_string]_.
- ``max_fragment_size``: Maximum size of individual ringbuffer message fragments, as a power of 2. Messages larger than this will be split into multiple fragments Default value: ``"64KB"`` [#size_string]_.

.. rubric:: Footnotes

.. [#size_string] Size strings are expressed as the value suffixed with the size in bytes (``B``, ``KB``, ``MB``, ``GB``, ``TB``, as factors of 1024), e.g. ``"20MB"``, ``"100KB"`` or ``"2048"`` (bytes).

.. [#time_string] Time strings are expressed as the value suffixed with the duration (``us``, ``ms``, ``s``, ``min``, ``h``), e.g. ``"1000ms"``, ``"10s"`` or ``"30min"``.
