Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the ``cchost`` executable via the ``--config </path/to/configuration/file>`` argument.

.. tip:: JSON configuration samples:

    - Minimal configuration: https://github.com/microsoft/CCF/blob/main/samples/config/minimal_config.json
    - Full configuration: https://github.com/microsoft/CCF/blob/main/samples/config/config.json

Configuration Options
---------------------

``enclave``
~~~~~~~~~~~

- ``file``: Path to enclave application.
- ``type``: Type of enclave application (either ``release``, ``debug`` or ``virtual``). Default value: ``release``.

``network``
~~~~~~~~~~~

The ``network`` section includes configuration for the interfaces a node listens on (both node-to-node and RPC).

- ``node_address``: Address (hostname and port) to listen on for incoming node-to-node connections.

- ``rpc_interfaces``: Addresses (hostname and port) to listen on for incoming client TLS connections.

Each RPC address must contain:

- The local RPC address (``bind_address``) the node binds to and listens on.
- The published RPC address (``published_address``) advertised to clients. Default value: value of ``rpc_address``.
- The maximum number of active client sessions (``max_open_sessions_soft``) on that interface after which clients will receive a HTTP 503 error. Default value: ``1000``.
- The maximum number of active client sessions (``max_open_sessions_hard``) on that interface after which clients sessions will be terminated, before the TLS handshake is complete. Note that its value must be greater than the value of ``max_open_sessions_soft``. Default value: ``1010``.

Example:

.. code-block:: json

    "network": {
        "node_address": {"hostname": "127.0.0.1", "port": "0"},
        "rpc_interfaces": [
            {
                "bind_address":{"hostname": "127.0.0.1", "port": "0"},
                "published_address":{"hostname":"foo.dummy.com","port": "12345"},
            },
            {
                "bind_address":{"hostname": "127.0.0.2", "port": "8080"},
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
- ``curve_id``: Elliptic curve to use for node identity key (``secp384r1`` or ``secp256r1``). Default value: ``secp384r1``.
- ``initial_validity_days``: Initial validity period (days) for node certificate. Default value: ``1`` day.

.. _start configuration:

``start``
~~~~~~~~~

.. note:: This only needs to be set when the node started in ``start`` mode.

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
    - ``reconfiguration_type``. The type of reconfiguration for new nodes. Default value: ``OneTransaction``.

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
~~~~~~~~

.. note:: This only needs to be set when the node is started in ``join`` mode.

- ``target_rpc_address``: Address (hostname and port) of a node of the existing service to join.
- ``timer_ms``: Interval (ms) at which the node sends join requests to the existing network. Default value: ``1000`` ms.

Example:

.. code-block:: json

    "join": {
        "timer_ms": 1000,
        "target_rpc_address": {"hostname": "127.0.0.1", "port": "8080"}
    }

``ledger``
~~~~~~~~~~

- ``directory``: Path to main ledger directory. Default value: ``ledger``.
- ``read_only_directories``: Optional. Paths to read-only ledger directories. Note that only ``.committed`` files will be read from these directories. Default value: ``[]``.
- ``chunk_size``: Minimum size (bytes) of the current ledger file after which a new ledger file (chunk) is created. Default value: ``5000000`` bytes.

``snapshots``
~~~~~~~~~~~~~

- ``directory``: Path to snapshot directory. Default value: ``snapshots``.
- ``interval_size``: Minimum number of transactions between two snapshots. Default value: ``10000``.

``logging``
~~~~~~~~~~~

- ``host_level``: Logging level for the `untrusted host`. Default value: ``INFO``.

.. note:: While it is possible to set the host log level at startup, it is deliberately not possible to change the log level of the enclave without rebuilding it and changing its code identity.

- ``format``: If ``"json"``, node logs will be formatted as JSON. Default value: ``"text"``.

``consensus``
~~~~~~~~~~~~~

- ``type``: Type of consensus protocol. Only ``CFT`` (Crash-Fault Tolerant) is currently supported. Default value: ``CFT``.
- ``timeout_ms``: Interval (ms) at which the primary node sends messages to backup nodes to maintain its primary-ship. This should be set to a significantly lower value than ``election_timeout_ms``. Default value: ``100`` ms.
- ``election_timeout_ms``: Timeout value (ms) after which backup node that have not received any message from the primary node will trigger a new election. This should be set to a significantly lower value than ``timeout_ms``. Default timeout: ``4000`` ms.

``intervals``
~~~~~~~~~~~~~

- ``signature_interval_size``: Number of transactions after which a signature transaction is automatically generated. Default value: ``5000``.
- ``signature_interval_duration_ms``: Maximum duration (milliseconds) after which a signature transaction is automatically triggered. Default value: ``1000`` ms.

.. note::
    Transaction commit latency in a CCF network is primarily a function of signature frequency. A network emitting signatures more frequently will be able to commit transactions faster, but will spend a larger proportion of its execution resources creating and verifying signatures. Setting signature frequency is a trade-off between transaction latency and throughput.

    The signature interval options specify the intervals at which the generation of signature transactions is `triggered`. However, because of the parallel execution and queuing of transactions, the intervals between signature transactions may be slightly larger in practice.

``jwt``
~~~~~~~

- ``key_refresh_interval_s``: Interval (seconds) at which JWT keys for issuers registered with auto-refresh are automatically refreshed. Default value: ``1800`` s.

``network_certificate_file``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ``start`` and ``recover`` nodes, path to which network/service certificate will be written to on startup. For ``join`` nodes, path to the certificate of the existing network/service to join. Default value: ``networkcert.pem``.

``node_certificate_file``
~~~~~~~~~~~~~~~~~~~~~~~~~

Path to self-signed node certificate output by node on startup. Default value: ``nodecert.pem``.

``node_pid_file``
~~~~~~~~~~~~~~~~~

Path to file in which ``cchost`` process identifier (PID) will be written to on startup. Default value: ``cchost.pid``.

``node_address_file``
~~~~~~~~~~~~~~~~~~~~~

Optional. Path to file in which node address (hostname and port) will be written to on startup.
This option is particularly useful when binding to port ``0`` and getting auto-assigned a port by the OS.

``rpc_addresses_file``
~~~~~~~~~~~~~~~~~~~~~~

Optional. Path to file in which all RPC addresses (hostnames and ports) will be written to on startup.
This option is particularly useful when binding to port ``0`` and getting auto-assigned a port by the OS.

Advanced Configuration Options
------------------------------

.. warning:: The following configuration options have sensible default values and should be modified with care.

``tick_period_ms``
~~~~~~~~~~~~~~~~~~

Interval (milliseconds) at which the enclave time will be updated by the host. Default value: ``10`` ms.

``io_logging_threshold_ns``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration (nanoseconds) of I/O operations (ledger and snapshots) after which slow operations will be logged to node's log. Default value: ``10000000`` ns.

``node_client_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~

Address to bind to for node-to-node client connections. If unspecified, this is automatically assigned by the OS.
This option is particularly useful for testing purposes (e.g. establishing network partitions between nodes).

``client_connection_timeout_ms``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration (milliseconds) after which unestablished client connections will be marked as timed out and either re-established or discarded. Default value: ``2000`` ms.

``worker_threads``
~~~~~~~~~~~~~~~~~~

Experimental. Number of additional threads processing incoming client requests in the enclave. Default value: ``0``.

``memory``
~~~~~~~~~~

- ``circuit_size_shift``: Size of the internal host-enclave ringbuffers, as a power of 2. Default value: ``22`` (``4,194,304`` bytes).
- ``max_msg_size_shift``: Maximum size for a message sent over the ringbuffer, as a power of 2. Messages may be split into multiple fragments, but this limits the total size of the sum of those fragments. Default value: ``24`` (``16,777,216`` bytes).
- ``max_fragment_size_shift``: Maximum size of individual ringbuffer message fragments, as a power of 2. Messages larger than this will be split into multiple fragments Default value: ``16`` (``65,536`` bytes).