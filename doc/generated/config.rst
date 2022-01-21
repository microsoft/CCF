Configuration Options
---------------------

``enclave``
~~~~~~~~~~~

- ``file``: Path to enclave application.

- ``type``: Type of enclave application (values: ``"release"``, ``"debug"``, ``"virtual"``). Default: ``"release"``.

``network``
~~~~~~~~~~~

- ``node_to_node_interface``: Address (host:port) to listen on for incoming node-to-node connections (e.g. internal consensus messages).

- ``rpc_interfaces``: Interfaces to listen on for incoming client TLS connections, as a dictionnary from unique interface name to RPC interface information.

``command``
~~~~~~~~~~~

- ``type``: Type of CCF node (values: ``"start"``, ``"join"``, ``"recover"``). Default: ``"start"``.

- ``service_certificate_file``: For start and recover nodes, path to which service certificate will be written to on startup. For join nodes, path to the certificate of the existing network to join. Default: ``"service_cert.pem"``.

``node_certificate``
~~~~~~~~~~~~~~~~~~~~

- ``subject_name``: Subject name to include in node certificate. Default: ``"CN=CCF Node"``.

- ``subject_alt_names``: List of 'iPAddress:' or 'dNSName:' strings to include as Subject Alternative Names (SAN) in node certificates. If none is set, the node certificate will automatically include the value of the main RPC interface 'published_rpc_address'.

- ``curve_id``: Elliptic curve to use for node identity key (values: ``"secp384r1"``, ``"secp256r1"``). Default: ``"secp384r1"``.

- ``initial_validity_days``: Initial validity period (days) for node certificate. Default: ``1``.

``ledger``
~~~~~~~~~~

- ``directory``: Path to main ledger directory. Default: ``"ledger"``.

- ``read_only_directories``: Paths to read-only ledger directories. Note that only '.committed' files will be read from these directories.

- ``chunk_size``: Minimum size (size string) of the current ledger file after which a new ledger file (chunk) is created. Default: ``"5MB"``.

``snapshots``
~~~~~~~~~~~~~

- ``directory``: Path to snapshot directory. Default: ``"snapshots"``.

- ``tx_count``: Number of transactions after which a snapshot is automatically generated. Default: ``10000``.

``logging``
~~~~~~~~~~~

- ``host_level``: Logging level for the untrusted host (values: ``"info"``, ``"fail"``, ``"fatal"``). Default: ``"info"``.

- ``format``: If 'json', node logs will be formatted as JSON (values: ``"text"``, ``"json"``). Default: ``"text"``.

``consensus``
~~~~~~~~~~~~~

- ``type``: Type of consensus protocol. Only CFT (Crash-Fault Tolerant) is currently supported (values: ``"CFT"``). Default: ``"CFT"``.

- ``message_timeout``: Maximum interval (time string) at which the primary node sends messages to backup nodes to maintain its primary-ship. This should be set to a significantly lower value than 'election_timeout'. Default: ``"100ms"``.

- ``election_timeout``: Timeout value after which backup nodes that have not received any message from the primary node will trigger a new election. This should be set to a significantly greater value than 'message_timeout'. Default: ``"5000ms"``.

``ledger_signatures``
~~~~~~~~~~~~~~~~~~~~~

- ``tx_count``: Number of transactions after which a signature transaction is automatically generated. Default: ``5000``.

- ``delay``: Maximum duration after which a signature transaction is automatically generated. Default: ``"1000ms"``.

``jwt``
~~~~~~~

- ``key_refresh_interval``: Interval at which JWT keys for issuers registered with auto-refresh are automatically refreshed. Default: ``"30min"``.

``output_files``
~~~~~~~~~~~~~~~~

- ``node_certificate_file``: Path to self-signed node certificate output by node on startup. Default: ``"nodecert.pem"``.

- ``pid_file``: Path to file in which 'cchost' process identifier (PID) will be written to on startup. Default: ``"cchost.pid"``.

- ``node_to_node_address_file``: Path to file in which node address (hostname and port) will be written to on startup. This option is particularly useful when binding to port 0 and getting auto-assigned a port by the OS. No file is created if this entry is not specified.

- ``rpc_addresses_file``: Path to file in which all RPC addresses (hostnames and ports) will be written to on startup. This option is particularly useful when binding to port 0 and getting auto-assigned a port by the OS. No file is created if this entry is not specified.

``tick_interval``
~~~~~~~~~~~~~~~~~

Interval at which the enclave time will be updated by the host. Default: ``"10ms"``.

``slow_io_logging_threshold``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration of I/O operations (ledger and snapshots) after which slow operations will be logged to node log. Default: ``"10000us"``.

``node_client_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~

Address to bind to for node-to-node client connections. If unspecified, this is automatically assigned by the OS. This option is particularly useful for testing purposes (e.g. establishing network partitions between nodes).

``client_connection_timeout``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration after which unestablished client connections will be marked as timed out and either re-established or discarded. Default: ``"2000ms"``.

``worker_threads``
~~~~~~~~~~~~~~~~~~

Experimental. Number of additional threads processing incoming client requests in the enclave. Default: ``0``.

``memory``
~~~~~~~~~~

- ``circuit_size``: Size (size string) of the internal host-enclave ringbuffers, as a power of 2. Default: ``"4MB"``.

- ``max_msg_size``: Maximum size (size string) for a message sent over the ringbuffer, as a power of 2. Messages may be split into multiple fragments, but this limits the total size of the sum of those fragments. Default: ``"16MB"``.

- ``max_fragment_size``: Maximum size (size string) of individual ringbuffer message fragments, as a power of 2. Messages larger than this will be split into multiple fragments. Default: ``"64KB"``.

