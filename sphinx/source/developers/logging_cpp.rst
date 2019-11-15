Logging (C++)
=============

A C++ transaction engine exposes itself to CCF by implementing:

.. literalinclude:: ../../../src/enclave/appinterface.h
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

The Logging application simply has:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

.. note::

    :cpp:class:`kv::Store` tables are essentially the only interface between CCF
    and the application, and the sole mechanism for it to have state.

    The Logging application keeps its state in a pair of tables, one containing private encrypted logs and the other containing public unencrypted logs. Their type is defined as:

    .. literalinclude:: ../../../src/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: table_definition
        :lines: 1
        :dedent: 2

    Table creation happens in the app's constructor:

    .. literalinclude:: ../../../src/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET_START: constructor
        :end-before: SNIPPET_END: constructor
        :dedent: 4

RPC Handler
-----------

The handler returned by :cpp:func:`ccfapp::getRpcHandler()` needs to subclass :cpp:class:`ccf::UserRpcFrontend`:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: inherit_frontend
    :lines: 1
    :dedent: 2

The constructor then needs to create a handler function or lambda for each transaction type. This takes a transaction object and the request's ``params``, interacts with the KV tables, and returns a result:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: get
    :end-before: SNIPPET_END: get
    :dedent: 6

Each function is installed as the handler for a specific RPC ``method``, optionally with schema included:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: install_get
    :lines: 1
    :dedent: 6

A handler can either be installed as:

- ``Write``: this handler can only be executed on the primary of the consensus network.
- ``Read``: this handler can be executed on any node of the network.
- ``MayWrite``: the execution of this handler on a specific node depends on the value of the ``"readonly"`` parameter in the JSON-RPC command.

App-defined errors
~~~~~~~~~~~~~~~~~~

Applications can define their own error codes. These should be between ``-32050`` and ``-32099`` to avoid conflicting with CCF's error codes. The Logging application returns errors if the user tries to get an id which has not been logged, or tries to log an empty message. These error codes should be given their own ``enum class``, and a ``get_error_prefix`` function should be defined in the same namespace to help users distinguish error messages:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: errors
    :end-before: SNIPPET_END: errors
    :dedent: 2

API Schema
~~~~~~~~~~

These handlers also demonstrate two different ways of defining schema for RPCs, and validating incoming requests against them. The record/get methods operating on public tables have manually defined schema and use [#valijson]_ for validation, returning an error if the input is not compliant with the schema:

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: valijson_record_public
    :end-before: SNIPPET_END: valijson_record_public
    :dedent: 6

This provides robust, extensible validation using the full JSON schema spec.

The methods operating on private tables use an alternative approach, with a macro-generated schema and parser converting compliant requests into a PoD C++ object:

.. literalinclude:: ../../../src/apps/logging/logging_schema.h
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_macros
    :end-before: SNIPPET_END: macro_validation_macros
    :dedent: 2

.. literalinclude:: ../../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_record
    :end-before: SNIPPET_END: macro_validation_record
    :dedent: 6

This produces validation error messages with a lower performance overhead, and ensures the schema and parsing logic stay in sync, but is only suitable for simple schema with required and optional fields of supported types.

Both approaches register their RPC's params and result schema, allowing them to be retrieved at runtime with calls to the getSchema RPC.

.. rubric:: Footnotes

.. [#valijson] `Valijson is a header-only JSON Schema Validation library for C++11 <https://github.com/tristanpenman/valijson>`_.
