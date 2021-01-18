Logging (C++)
=============

A C++ application exposes itself to CCF by implementing:

.. literalinclude:: ../../src/enclave/app_interface.h
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

The Logging application simply has:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: rpc_handler
    :end-before: SNIPPET_END: rpc_handler
    :dedent: 2

.. note::

    :cpp:class:`kv::Store` tables are essentially the only interface between CCF
    and the application, and the sole mechanism for it to have state.

    The Logging application keeps its state in a pair of tables, one containing private encrypted logs and the other containing public unencrypted logs. Their type is defined as:

    .. literalinclude:: ../../samples/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: table_definition
        :lines: 1
        :dedent: 2

    Table creation happens in the app's constructor:

    .. literalinclude:: ../../samples/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET_START: constructor
        :end-before: SNIPPET_END: constructor
        :dedent: 4

RPC Handler
-----------

The type returned by :cpp:func:`ccfapp::get_rpc_handler()` should subclass :cpp:class:`ccf::UserRpcFrontend`, passing the base constructor a reference to an implementation of :cpp:class:`ccf::EndpointRegistry`:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: inherit_frontend
    :lines: 1
    :dedent: 2

The logging app defines :cpp:class:`ccfapp::LoggerHandlers`, which creates and installs handler functions or lambdas for several different HTTP endpoints. Each of these functions takes as input the details of the current request (such as the URI which was called, the query string, the request body), interacts with the KV tables using the given :cpp:class:`kv::Tx` object, and returns a result:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: record
    :end-before: SNIPPET_END: record
    :dedent: 6

This example uses the ``json_adapter`` wrapper function, which handles parsing of a JSON params object from the HTTP request body.

Each function is installed as the handler for a specific HTTP resource, defined by a verb and URI:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_record
    :end-before: SNIPPET_END: install_record
    :dedent: 6

This example installs at ``"log/private", HTTP_POST``, so will be invoked for HTTP requests beginning ``POST /app/log/private``.

The return value from ``make_endpoint`` is an ``Endpoint&`` object which can be used to alter how the handler is executed. For example, the handler for ``/log/private`` shown above sets a `schema` declaring the types of its request and response bodies. These will be used in calls to the ``/api`` endpoint to populate the relevant parts of the OpenAPI document. There are other endpoints installed for the URI path ``/log/private`` with different verbs, to handle ``GET`` and ``DELETE`` requests. Any other verbs, without an installed endpoint, will not be accepted - the framework will return a ``405 Method Not Allowed`` response.

To process the raw body directly, a handler should use the general lambda signature which takes a single ``EndpointContext&`` parameter. Examples of this are also included in the logging sample app. For instance the ``log_record_text`` handler takes a raw string as the request body:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_text
    :end-before: SNIPPET_END: log_record_text
    :dedent: 6

Rather than parsing the request body as JSON and extracting the message from it, in this case `the entire body` is the message to be logged, and the ID to associate it with is passed as a request header. This requires some additional code in the handler, but provides complete control of the request and response formats.

This general signature also allows a handler to see additional caller context. An example of this is the ``log_record_prefix_cert`` handler:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_prefix_cert
    :end-before: SNIPPET_END: log_record_prefix_cert
    :dedent: 6

This uses mbedtls to parse the caller's TLS certificate, and prefixes the logged message with the ``Subject`` field extracted from this certificate.

If a handler makes no writes to the KV, it may be installed as read-only:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_get
    :end-before: SNIPPET_END: install_get
    :dedent: 6

This offers some additional type safety (accidental `put`\s or `remove`\s will be caught at compile-time) and also enables performance scaling since read-only operations can be executed on any receiving node, whereas writes must always be executed on the primary node.

API Schema
~~~~~~~~~~

Instead of taking and returning `nlohmann::json` objects directly, the endpoint handlers use a macro-generated schema and parser converting compliant requests into a PoD C++ object:

.. literalinclude:: ../../samples/apps/logging/logging_schema.h
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_macros
    :end-before: SNIPPET_END: macro_validation_macros
    :dedent: 2

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_record
    :end-before: SNIPPET_END: macro_validation_record
    :dedent: 6

This produces validation error messages with a low performance overhead, and ensures the schema and parsing logic stay in sync, but is only suitable for simple schema - an object with some required and some optional fields, each of a supported type.

Authentication
~~~~~~~~~~~~~~

Each endpoint must provide a list of associated authentication policies in the call to ``make_endpoint``. Each request to this endpoint will first be checked by these policies in the order they are specified, and the handler will only be invoked if at least one of these policies accepts the request. Inside the handler, the caller identity that was constructed by the accepting policy check can be retrieved with ``get_caller`` or ``try_get_caller`` - the latter should be used when multiple policies are present, to detect which policy accepted the request. This caller identity can then be used to make authorization decisions during execution of the endpoint.

For example in the ``/log/private`` endpoint above there is a single policy stating that requests must come from a known user cert, over mutually authenticated TLS. This is one of several built-in policies provided by CCF. These built-in policies will check that the caller's TLS cert is a known user or member identity, or that the request is HTTP signed by a known user or member identity, or that the request contains a JWT signed by a known issuer. Additionally, there is an empty policy which accepts all requests, which should be used as the final policy to declare that the endpoint is optionally authenticated (either an earlier-listed policy passes providing a real caller identity, or the empty policy passes and the endpoint is invoked with no caller identity). To declare that an endpoint has no authentication requirements and should be accessible by any caller, use the special value ``no_auth_required``.

Applications can extend this system by writing their own authentication policies. There is an example of this in the C++ logging app. First it defines a type describing the identity details it aims to find in an acceptable request:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_identity
    :end-before: SNIPPET_END: custom_identity
    :dedent: 2

Next it defines the policy itself. The core functionality is the implementation of the ``authenticate()`` method, which looks at each request and returns either a valid new identity if it accepts the request, or ``nullptr`` if it doesn't. In this demo case it is looking for a pair of headers and doing some validation of their values:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_auth_policy
    :end-before: SNIPPET_END: custom_auth_policy
    :dedent: 2

Note that ``authenticate()`` is also passed a ``ReadOnlyTx`` object, so more complex authentication decisions can depend on the current state of the KV. For instance the built-in TLS cert auth policies are looking up the currently known user/member certs stored in the KV, which will change over the life of the service.

The final piece is the definition of the endpoint itself, which uses an instance of this new policy when it is constructed and then retrieves the custom identity inside the handler:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_auth_endpoint
    :end-before: SNIPPET_END: custom_auth_endpoint
    :dedent: 6

Default Endpoints
~~~~~~~~~~~~~~~~~

The logging app sample exposes several built-in endpoints which are provided by the framework for convenience, such as ``/app/tx``, ``/app/commit``, and ``/app/user_id``. It is also possible to write an app which does not expose these endpoints, either to build a minimal user-facing API or to re-wrap this common functionality in your own format or authentication. A sample of this is provided in ``samples/apps/nobuiltins``. Whereas the logging app declares a registry inheriting from :cpp:class:`ccf::CommonEndpointRegistry`, this app inherits from :cpp:class:`ccf::BaseEndpointRegistry` which does not install any default endpoints:

.. literalinclude:: ../../samples/apps/nobuiltins/nobuiltins.cpp
    :language: cpp
    :start-after: SNIPPET: registry_inheritance
    :lines: 1
    :dedent: 2

This app can then define its own endpoints from a blank slate. If it wants to provide similar functionality to the default endpoints, it does so using the APIs provided by :cpp:class:`ccf::BaseEndpointRegistry`. For instance to retrieve the hardware quote of the executing node:

.. literalinclude:: ../../samples/apps/nobuiltins/nobuiltins.cpp
    :language: cpp
    :start-after: SNIPPET_START: get_quote_api_v1
    :end-before: SNIPPET_END: get_quote_api_v1
    :dedent: 10