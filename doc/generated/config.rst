Configuration Options
---------------------

``enclave``
-----------

- ``file``: Path to enclave application.

- ``type``: Type of enclave application (values: ``"release"``, ``"debug"``, ``"virtual"``). Default: ``"release"``.

``network``
-----------

``node_to_node_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``bind_address``: Local address the node binds to and listens on.

``rpc_interfaces``
~~~~~~~~~~~~~~~~~~

- ``bind_address``: Local address the node binds to and listens on.

- ``published_rpc_address``: The published RPC address advertised to clients. Default: ``"Value of 'bind_address'"``.

- ``max_open_sessions_soft``: The maximum number of active client sessions on that interface after which clients will receive an HTTP 503 error. Default: ``1000``.

- ``max_open_sessions_hard``: The maximum number of active client sessions on that interface after which clients sessions will be terminated, before the TLS handshake is complete. Note that its value must be greater than the value of 'max_open_sessions_soft'. Default: ``1010``.

``command``
-----------

- ``type``: Type of CCF node (values: ``"start"``, ``"join"``, ``"recover"``). Default: ``"start"``.

- ``service_certificate_file``: For ``start`` and ``recover`` nodes, path to which service certificate will be written to on startup. For ``join`` nodes, path to the certificate of the existing network to join. Default: ``"service_cert.pem"``.

``start``
~~~~~~~~~

- ``type``: .

- ``type``: .

- ``properties``: .

- ``data_json_file``: Path to member data file (JSON).

- ``required``: .

``service_configuration``
+++++++++++++++++++++++++

- ``recovery_threshold``: Number of recovery members required to recover the service. Note that if the recovery threshold is set to 0, it is automatically set to the number of recovery members specified in 'members'. Default: ``0``.

- ``maximum_node_certificate_validity_days``: The maximum number of days allowed for node certificate validity period. Default: ``365``.

- ``reconfiguration_type``:  (values: ``"OneTransaction"``, ``"TwoTransaction"``). Default: ``"OneTransaction"``.

- ``initial_service_certificate_validity_days``: Initial validity period (days) for service certificate. Default: ``1``.

``join``
~~~~~~~~

- ``target_rpc_address``: Address (host:port) of a node of the existing service to join.

- ``retry_timeout``: Interval (time string) at which the node sends join requests to the existing network. Default: ``"1000ms"``.

``recover``
~~~~~~~~~~~

- ``initial_service_certificate_validity_days``: Initial validity period (days) for service certificate. Default: ``1``.

``node_certificate``
--------------------

- ``subject_name``: Subject name to include in node certificate. Default: ``"CN=CCF Node"``.

- ``type``: .

- ``curve_id``: Elliptic curve to use for node identity key (values: ``"secp384r1"``, ``"secp256r1"``). Default: ``"secp384r1"``.

- ``initial_validity_days``: Initial validity period (days) for node certificate. Default: ``1``.

``ledger``
----------

- ``directory``: Path to main ledger directory. Default: ``"ledger"``.

- ``type``: .

- ``chunk_size``: Minimum size (size string) of the current ledger file after which a new ledger file (chunk) is created. Default: ``"5MB"``.

``snapshots``
-------------

- ``directory``: Path to snapshot directory. Default: ``"snapshots"``.

- ``tx_count``: Number of transactions after which a snapshot is automatically generated. Default: ``10000``.

``logging``
-----------

- ``host_level``: Logging level for the untrusted host (values: ``"info"``, ``"fail"``, ``"fatal"``). Default: ``"info"``.

- ``format``: If 'json', node logs will be formatted as JSON (values: ``"text"``, ``"json"``). Default: ``"text"``.

``consensus``
-------------

- ``type``: Type of consensus protocol. Only CFT (Crash-Fault Tolerant) is currently supported (values: ``"CFT"``). Default: ``"CFT"``.

- ``message_timeout``: Maximum interval (time string) at which the primary node sends messages to backup nodes to maintain its primary-ship. This should be set to a significantly lower value than 'election_timeout'. Default: ``"100ms"``.

- ``election_timeout``: Timeout value after which backup nodes that have not received any message from the primary node will trigger a new election. This should be set to a significantly greater value than 'message_timeout'. Default: ``"5000ms"``.

``ledger_signatures``
---------------------

- ``tx_count``: Number of transactions after which a signature transaction is automatically generated. Default: ``5000``.

- ``delay``: Maximum duration after which a signature transaction is automatically generated. Default: ``"1000ms"``.

``jwt``
-------

- ``key_refresh_interval``: Interval at which JWT keys for issuers registered with auto-refresh are automatically refreshed. Default: ``"30min"``.

``output_files``
----------------

- ``node_certificate_file``: Path to self-signed node certificate output by node on startup. Default: ``"nodecert.pem"``.

- ``pid_file``: Path to file in which 'cchost' process identifier (PID) will be written to on startup. Default: ``"cchost.pid"``.

- ``node_to_node_address_file``: Path to file in which node address (hostname and port) will be written to on startup. This option is particularly useful when binding to port 0 and getting auto-assigned a port by the OS. No file is created if this entry is not specified.

- ``rpc_addresses_file``: Path to file in which all RPC addresses (hostnames and ports) will be written to on startup. This option is particularly useful when binding to port 0 and getting auto-assigned a port by the OS. No file is created if this entry is not specified.

- ``tick_interval``: Interval at which the enclave time will be updated by the host. Default: ``"10ms"``.

- ``slow_io_logging_threshold``: Maximum duration of I/O operations (ledger and snapshots) after which slow operations will be logged to node log. Default: ``"10000us"``.

- ``node_client_interface``: Address to bind to for node-to-node client connections. If unspecified, this is automatically assigned by the OS. This option is particularly useful for testing purposes (e.g. establishing network partitions between nodes).

- ``client_connection_timeout``: Maximum duration after which unestablished client connections will be marked as timed out and either re-established or discarded. Default: ``"2000ms"``.

- ``worker_threads``: Experimental. Number of additional threads processing incoming client requests in the enclave. Default: ``0``.

``memory``
----------

- ``circuit_size``: Size (size string) of the internal host-enclave ringbuffers, as a power of 2. Default: ``"4MB"``.

- ``max_msg_size``: Maximum size (size string) for a message sent over the ringbuffer, as a power of 2. Messages may be split into multiple fragments, but this limits the total size of the sum of those fragments. Default: ``"16MB"``.

- ``max_fragment_size``: Maximum size (size string) of individual ringbuffer message fragments, as a power of 2. Messages larger than this will be split into multiple fragments. Default: ``"64KB"``.

