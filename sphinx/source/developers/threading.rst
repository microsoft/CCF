Threading
=========

Consistency
-----------

If all commands are executed on the primary CCF guarantees session consistency from the perspective of a :term:`TLS` client connection.
This means that within a single client connection a client is guaranteed to read its own writes.
For example, if a client sends command (A) to the primary of a CCF service and then sends command (B), CCF guarantees that command (A) will be executed before command (B).

Implementation
--------------

Configuration
~~~~~~~~~~~~~

To enable multiple worker threads pass the ```--worker_threads=``` flag along with the number of desired threads to cchost when starting a CCF node.
It is strongly recommended that all CCF nodes run the same number of worker threads.
The number of worker threads must be at least 1 less than the value of ```NumTCS``` in the oe_sign.conf file.

Programming Model
~~~~~~~~~~~~~~~~~

To ensure session consistency all commands that originate from the same connection are executed on the same thread.
It is strongly advised that during the execution of a command the applications does not mutate any global state outside of the key-value store.
Any inter-command communication should be performed via they key-value store.
This ensures that CCF can rollback commands or change primaries as required.

If an application has global state that exists outside the key-value store CCF offers several concurrency control primitives (via OpenEnclave) to protect memory that could be accessed concurrently by multiple threads.
It is recommended that these primitives are used rather than other primitives, such as mutexes, which many result in an OCALL.