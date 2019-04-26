Logging (C++)
-------------

Overview
```````````

A C++ transaction engine exposes itself to CCF by implementing:

.. literalinclude:: ../../src/enclave/appinterface.h
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

The Logging application simply has:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

.. note::

    :cpp:class:`kv::Store` tables are essentially the only interface between CCF
    and the application, and the sole mechanism for it to have state.

    The Logging application keeps its state in a single table, defined as:

    .. literalinclude:: ../../src/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: table_definition
        :lines: 1
        :dedent: 2

    Table creation happens in the Handler's constructor, described below.

RPC Handler
```````````

The handler returned by :cpp:func:`ccfapp::getRpcHandler()` needs to subclass :cpp:class:`ccf::UserRpcFrontend`:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp

The constructor then needs to create a handler for the single transaction type supported here:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: record
    :end-before: SNIPPET_END: record
    :dedent: 6

Before being installed:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: install_record
    :lines: 1
    :dedent: 6

A handle can either be installed as:

- ``Write``: this handler can only be executed on the leader of the Raft network.
- ``Read``: this handler can be executed on any node of the network.
- ``MayWrite``: the execution of this handler on a specific node depends on the value of the ``"readonly"`` paramater in the JSON-RPC command.

Build
`````

Once an application is complete, it needs be built into a shared object, and signed:

.. literalinclude:: ../../CMakeLists.txt
    :language: cmake
    :start-after: SNIPPET: Logging application
    :lines: 1

For signing to work, a configuration is necessary. The configuration should be called `oe_sign.conf`, and
be placed under the same directory as the source files for the application.

.. literalinclude:: ../../src/apps/logging/oe_sign.conf

Running
```````

This produces the enclave library ``libloggingenc.so.signed`` which can be loaded by the cchost application:

.. code-block:: bash

    ./cchost --enclave-file libloggingenc.so.signed [args]
