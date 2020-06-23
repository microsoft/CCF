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

The type returned by :cpp:func:`ccfapp::get_rpc_handler()` should subclass :cpp:class:`ccf::UserRpcFrontend`, passing the base constructor a reference to an implementation of :cpp:class:`ccf::EndpointRegistry`:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: inherit_frontend
    :lines: 1
    :dedent: 2

The logging app defines :cpp:class:`ccfapp::LoggerHandlers`, which creates and installs handler functions or lambdas for several different HTTP endpoints. Each of these functions takes as input the details of the current request (such as the URI which was called, the query string, the request body), interacts with the KV tables using the given :cpp:class:`kv::Tx` object, and returns a result:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: record
    :end-before: SNIPPET_END: record
    :dedent: 6

This example uses the ``json_adapter`` wrapper function, which handles parsing of a JSON params object from the HTTP request body.

Each function is installed as the handler for a specific HTTP resource, defined by a verb and URI:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_record
    :end-before: SNIPPET_END: install_record
    :dedent: 6

This example installs at ``"LOG_record", HTTP_POST``, so will be invoked for requests beginning ``POST /app/LOG_record``.

The return value from ``make_endpoint`` is an ``Endpoint&`` object which can be used to alter how the handler is executed. For example, the handler for ``LOG_record`` shown above sets a `schema` for the handler, declaring the types of its request and response bodies. These will be used in calls to the ``/api/schema`` endpoint to generate JSON documents describing the API. Since this is the only handler installed for ``"LOG_record"`` only HTTP ``POST``s will be accepted for this URI - the framework will return a ``405 Method Not Allowed`` for requests with any other verb.

To process the raw body directly, a handler should use the general lambda signature which takes a single ``EndpointContext&`` parameter. Examples of this are also included in the logging sample app. For instance the ``log_record_text`` handler takes a raw string as the request body:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_text
    :end-before: SNIPPET_END: log_record_text
    :dedent: 6

Rather than parsing the request body as JSON and extracting the message from it, in this case `the entire body` is the message to be logged, and the ID to associate it with is passed as a request header. This requires some additional code in the handler, but provides complete control of the request and response formats.

This general signature also allows a handler to see additional caller context. An example of this is the ``log_record_prefix_cert`` handler:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_prefix_cert
    :end-before: SNIPPET_END: log_record_prefix_cert
    :dedent: 6

This uses mbedtls to parse the caller's TLS certificate, and prefixes the logged message with the ``Subject`` field extracted from this certificate.

If a handler makes no writes to the KV, it may be installed as read-only:

.. literalinclude:: ../../src/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_get
    :end-before: SNIPPET_END: install_get
    :dedent: 6

This offers some additional type safety (accidental `put`s or `remove`s will be caught at compile-time) and also enables performance scaling since read-only operations can be executed on any receiving node, whereas writes must always be executed on the primary node.

API Schema
~~~~~~~~~~

These handlers also demonstrate two different ways of defining the type schema for each endpoint, and validating incoming requests against them. The record/get methods operating on public tables have manually defined schema and use [#valijson]_ for validation, returning an error if the input is not compliant with the schema:

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

This produces validation error messages with a lower performance overhead, and ensures the schema and parsing logic stay in sync, but is only suitable for simple schema - an object with some required and some optional fields, each of a supported type.

Both approaches register their endpoint's request and response schema, allowing them to be retrieved at runtime with calls to the ``/api/schema`` endpoint.

.. rubric:: Footnotes

.. [#valijson] `Valijson is a header-only JSON Schema Validation library for C++11 <https://github.com/tristanpenman/valijson>`_.
