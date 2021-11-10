Configuration
=============

The configuration for each CCF node must be contained in a single JSON configuration file specified to the ``cchost`` executable via the ``--config </path/to/configuration/file>`` argument.

.. tip:: Link to sample configurations:

    - Minimal sample configuration
    - Full sample configuration


TODO:

- Update `start_network` and `recovery` pages
- Link to sample JSON configuration file
- Which options are optional?
- Minimal config on startup (move some options to misc or bottom of page?)
- Enclave vs. host
- Remove BFT timeouts
- IP/DNS.
- Remove reserved memory.
- raft_timeout -> cft_timeout
- Default RPC and node-to-node values?
- Description for each section.


Configuration Options
---------------------

``enclave_file``
~~~~~~~~~~~~~~~~

Path to CCF enclave application.

``enclave_type``
~~~~~~~~~~~~~~~~

Type of enclave application. Default value: ``release``.

.. doxygenenum:: EnclaveType
   :project: CCF

``network``
~~~~~~~~~~~

- ``node_address``: Address (hostname and port) to listen on for incoming node-to-node connections.

- ``rpc_interfaces``: Addresses (hostname and port) to listen on for incoming client TLS connections.
Each RPC address must contain:

- The local RPC address (``rpc_address``) the node listens on.
- The public RPC address (``public_rpc_address``) advertised to clients.
- The maximum number of active client sessions (``max_open_sessions_soft``) on that interface after which clients will receive a HTTP 503 error.
- The maximum number of active client sessions (``max_open_sessions_hard``) on that interface after which clients sessions will be terminated, before the TLS handshake is complete. Note that its value must be greater than the value of ``max_open_sessions_soft``.

Example:

.. code-block:: json

    "network": {
        "node_address": {"hostname": "127.0.0.1", "port": "0"},
        "rpc_interfaces": [
            {
                "rpc_address":{"hostname": "127.0.0.1", "port": "0"},
                "public_rpc_address":{"hostname":"127.0.0.1","port": "0"},
                "max_open_sessions_soft": 1000,
                "max_open_sessions_hard": 1010
            },
            {
                "rpc_address":{"hostname": "127.0.0.2", "port": "8080"},
                "public_rpc_address":{"hostname":"<public_address>","port": "80"},
                "max_open_sessions_soft": 200,
                "max_open_sessions_hard": 210
            }
        ]
    }

``node_certificate``
~~~~~~~~~~~~~~~~~~~~

- ``subject_name``: Subject name to include in node certificate. Default value: ``CN=CCF Node``.
- ``subject_alt_names``: List of ``iPAddress:`` or ``dNSName:`` strings to include as Subject Alternative Names (SAN) in node certificates. If none is set, the node certificate will automatically include the value of the main RPC interface ``public_rpc_address``. Default value: ``[]``.
- ``curve_id``: Elliptic curve to use for node identity key (``secp384r1`` or ``secp256r1``). Default value: ``secp384r1``.
- ``initial_validity_period_days``: Initial validity period (days) for node certificate. Default value: ``1``day.

``start``
~~~~~~~~~

.. note:: This only needs to be set when the node started in ``start`` mode.

- ``constitution_files``: List of constitution files. These typically include ``actions.js``, ``validate.js``, ``resolve.js`` and ``apply.js``.
- ``members``: Information of members
- ``service_configuration``: Initial service configuration.

TODO: What if recovery_threshold is 0?

Example:

.. code-block:: json

    "start":
    {
        "constitution_files": ["actions.js", "validate.js", "resolve.js", "apply.js"],
        "members": [
            {"certificate_file": "member0_cert.pem", "data_json_file": null, "encryption_public_key_file": "member0_enc_pubk.pem"},
            {"certificate_file": "member1_cert.pem", "data_json_file": "member1_data.json", "encryption_public_key_file": null},
            {"certificate_file": "member2_cert.pem", "data_json_file": null, "encryption_public_key_file": "member2_enc_pubk.pem"}
        ],
        "service_configuration":
        {
            "recovery_threshold": 0,
            "max_allowed_node_cert_validity_days": 365
        }
    }

``join``
~~~~~~~~

.. note:: This only needs to be set when the node is started in ``join`` mode.

- ``target_rpc_address``: Address (hostname and port) of a node of the existing service to join.
- ``join_timer_ms``: Interval (ms) at which the node sends join requests to the existing network. Default value: ``1,000``ms.

``ledger``
~~~~~~~~~~

- ``ledger_dir``: Path to main ledger directory. Default value: ``ledger``.
- ``read_only_ledger_dirs``: Optional. Paths to read-only ledger directories. Note that only ``.committed`` files will be read from these directories. Default value: ``[]``.
- ``ledger_chunk_bytes``: Minimum size (bytes) of the current ledger file after which a new ledger file (chunk) is created. Default value: ``5,000,000`` bytes.

``snapshots``
~~~~~~~~~~~~~

- ``snapshots_dir``: Path to snapshot directory. Default value: ``snapshots``.
- ``snapshot_tx_interval``: Minimum number of transactions between snapshots. Default value: ``10,000``.

``logging``
~~~~~~~~~~~

- ``host_log_level``: Logging level for the untrusted `host`. Note that it is not possible to change the log level of the enclave at runtime. Default value: ``INFO``.
- ``log_format_json``: If ``true``, node logs will be formatted as JSON. Default value: ``false``.

``consensus``
~~~~~~~~~~~~~

- ``type``: Type of consensus protocol. Only ``CFT`` (crash-fault tolerant) is currently supported in production. Default value: ``CFT``.
- ``raft_timeout_ms``: Hearbeat interval (ms) at which primary node sends messages to backup nodes to maintain primary-ship. This should be set to a significantly lower value than ``raft_election_timeout_ms``. Default value: ``100``ms.
- ``raft_election_timeout_ms``: Timeout value (ms) after which backup node that have not received primary heartbeats will trigger a new election. Default timeout: ``4,000``ms.

``intervals``
~~~~~~~~~~~~~

- ``sig_tx_interval``: Number of transactions after which a signature transaction is automatically generated. Default value: ``5,000``.
- ``sig_ms_interval``: Maximum duration (milliseconds) after which a signature transaction is automatically triggered. Default value: ``1,000``ms.
- ``jwt_key_refresh_interval_s``: Interval (seconds) after which JWT keys for issuers registered with auto-refresh are automatically refreshed. Default value: ``1,800``s.

``network_certificate_file``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ``start`` and ``recover`` nodes, path to which network/service certificate will be written to on startup.
For ``join`` nodes, path to the certificate of the existing network/service to join.

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

TODO: These options aren't as required and have sensible defaults.

``tick_period_ms``
~~~~~~~~~~~~~~~~~~

Interval (milliseconds) at which the enclave time will be updated by the host. Default value: ``10``ms.

``io_logging_threshold_ns``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration (nanoseconds) of I/O operations (ledger and snapshots) after which slow operations will be logged to node's log. Default value: ``10,000,000``ns.

``node_client_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~

Optional. Address to bind to for node-to-node client connections. If unspecified, this is automatically assigned by the OS.
This option is particularly useful for testing purposes (e.g. establishing network partitions between nodes).

``client_connection_timeout_ms``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration (milliseconds) after which unestablished client connections will be marked as timed out and either re-established or discarded. Default value: ``2000``ms.

``worker_threads``
~~~~~~~~~~~~~~~~~~

Experimental. Number of threads processing incoming client requests in the enclave.

``memory``
~~~~~~~~~~

- ``circuit_size_shift``: Size of the internal host-enclave ringbuffers, as a power of 2. Default value: ``22`` (``4,194,304`` bytes).
- ``max_msg_size_shift``: Maximum size for a message sent over the ringbuffer, as a power of 2. Messages may be split into multiple fragments, but this limits the total size of the sum of those fragments. Default value: ``24`` (``16,777,216`` bytes).
- ``max_fragment_size_shift``: Maximum size of individual ringbuffer message fragments, as a power of 2. Messages larger than this will be split into multiple fragments Default value: ``16`` (``65,536`` bytes).