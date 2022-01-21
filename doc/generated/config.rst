Configuration Options
---------------------

``enclave``
~~~~~~~~~~~

``network``
~~~~~~~~~~~

``command``
~~~~~~~~~~~

``node_certificate``
~~~~~~~~~~~~~~~~~~~~

``ledger``
~~~~~~~~~~

``snapshots``
~~~~~~~~~~~~~

``logging``
~~~~~~~~~~~

``consensus``
~~~~~~~~~~~~~

``ledger_signatures``
~~~~~~~~~~~~~~~~~~~~~

``jwt``
~~~~~~~

``output_files``
~~~~~~~~~~~~~~~~

``tick_interval``
~~~~~~~~~~~~~~~~~

Interval at which the enclave time will be updated by the host (default:
"10ms").

``slow_io_logging_threshold``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration of I/O operations (ledger and snapshots) after which
slow operations will be logged to node log (default: "10000us").

``node_client_interface``
~~~~~~~~~~~~~~~~~~~~~~~~~

Address to bind to for node-to-node client connections. If unspecified,
this is automatically assigned by the OS. This option is particularly
useful for testing purposes (e.g. establishing network partitions
between nodes).

``client_connection_timeout``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Maximum duration after which unestablished client connections will be
marked as timed out and either re-established or discarded (default:
"2000ms").

``worker_threads``
~~~~~~~~~~~~~~~~~~

Experimental. Number of additional threads processing incoming client
requests in the enclave (default: 0).

``memory``
~~~~~~~~~~

