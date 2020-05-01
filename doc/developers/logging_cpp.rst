Logging (C++)
=============

A C++ transaction engine exposes itself to CCF by implementing:

.. literalinclude:: ../../src/enclave/app_interface.h
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

    The Logging application keeps its state in a pair of tables, one containing private encrypted logs and the other containing public unencrypted logs. Their type is defined as:

    .. literalinclude:: ../../src/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: table_definition
        :lines: 1
        :dedent: 2

    Table creation happens in the app's constructor:

    .. literalinclude:: ../../src/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET_START: constructor
        :end-before: SNIPPET_END: constructor
        :dedent: 4

RPC Handler
-----------

The handler returned by :cpp:func:`ccfapp::get_rpc_handler()` should subclass :cpp:class:`ccf::UserRpcFrontend`, providing an implementation of :cpp:class:`ccf::HandlerRegistry`:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: inherit_frontend
    :lines: 1
    :dedent: 2

The logging app defines :cpp:class:`ccfapp::LoggerHandlers`, which creates and installs handler functions or lambdas for each transaction type. These take a transaction object and the request's ``params``, interact with the KV tables, and return a result:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: get
    :end-before: SNIPPET_END: get
    :dedent: 6

This handler uses the simple signatures provided by the ``json_adapter`` wrapper function, which handles parsing of a JSON params object from the HTTP request body.

Each function is installed as the handler for a specific RPC ``method``, the name of the HTTP resource at which your handler will be invoked:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_get
    :end-before: SNIPPET_END: install_get
    :dedent: 6

The return value from ``install`` is a ``Handler&`` object which can be used to alter how the handler is executed. For example, the handler for ``LOG_get`` shown above sets a `schema` for the handler, which will be used in calls to the ``/getSchema`` endpoint. It also marks the handler as `GET-only`, so the framework will return a ``405 Method Not Allowed`` for any requests which are not HTTP ``GET``.

To process the raw body directly, a handler should use the general lambda signature which takes a single ``RequestArgs&`` parameter. Examples of this are also included in the logging sample app. For instance the ``log_record_text`` handler takes a raw string as the request body:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_text
    :end-before: SNIPPET_END: log_record_text
    :dedent: 6

Rather than parsing the request body as JSON and extracting the message from it, in this case `the entire body` is the message to be logged, and the ID to associate it with is passed as a request header.

This general form of handler (taking a single ``RequestArgs&`` parameter) also allows a handler to see additional caller context. An example of this is the ``log_record_prefix_cert`` handler:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_prefix_cert
    :end-before: SNIPPET_END: log_record_prefix_cert
    :dedent: 6

This uses mbedtls to parse the caller's TLS certificate, and prefixes the logged message with the Subject field extracted from this certificate.

A handler can either be installed as:

- ``Write``: this handler can only be executed on the primary of the consensus network.
- ``Read``: this handler can be executed on any node of the network.
- ``MayWrite``: the execution of this handler on a specific node depends on the value of the ``x-ccf-readonly`` header in the HTTP request.

API Schema
~~~~~~~~~~

These handlers also demonstrate two different ways of defining schema for RPCs, and validating incoming requests against them. The record/get methods operating on public tables have manually defined schema and use [#valijson]_ for validation, returning an error if the input is not compliant with the schema:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: valijson_record_public
    :end-before: SNIPPET_END: valijson_record_public
    :dedent: 6

This provides robust, extensible validation using the full JSON schema spec.

The methods operating on private tables use an alternative approach, with a macro-generated schema and parser converting compliant requests into a PoD C++ object:

.. literalinclude:: ../../src/apps/logging/logging_schema.h
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_macros
    :end-before: SNIPPET_END: macro_validation_macros
    :dedent: 2

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_record
    :end-before: SNIPPET_END: macro_validation_record
    :dedent: 6

This produces validation error messages with a lower performance overhead, and ensures the schema and parsing logic stay in sync, but is only suitable for simple schema with required and optional fields of supported types.

Both approaches register their RPC's params and result schema, allowing them to be retrieved at runtime with calls to the getSchema RPC.

.. rubric:: Footnotes

.. [#valijson] `Valijson is a header-only JSON Schema Validation library for C++11 <https://github.com/tristanpenman/valijson>`_.
