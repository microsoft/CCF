Example app (C++)
=================

A C++ application exposes itself to CCF by implementing:

.. literalinclude:: ../../include/ccf/app_interface.h
    :language: cpp
    :start-after: SNIPPET_START: app_interface
    :end-before: SNIPPET_END: app_interface
    :dedent:

The Logging example application simply has:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: app_interface
    :end-before: SNIPPET_END: app_interface
    :dedent:

.. note::

    :cpp:type:`kv::Map` tables are the only interface between CCF and the replicated application, and the sole mechanism for it to have distributed state.

    The Logging application keeps its state in a pair of tables, one containing private encrypted logs and the other containing public unencrypted logs. Their type is defined as:

    .. literalinclude:: ../../samples/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: table_definition
        :lines: 1
        :dedent:

    These tables are then accessed by type and name:

    .. literalinclude:: ../../samples/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: public_table_access
        :lines: 1
        :dedent:

    .. literalinclude:: ../../samples/apps/logging/logging.cpp
        :language: cpp
        :start-after: SNIPPET: private_table_access
        :lines: 1
        :dedent:

Application Endpoints
---------------------

The implementation of :cpp:func:`ccfapp::make_user_endpoints()` should return a subclass of :cpp:class:`ccf::endpoints::EndpointRegistry`, containing the endpoints that constitute the app.

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET: inherit_frontend
    :lines: 1
    :dedent:

The logging app defines :cpp:class:`ccfapp::LoggerHandlers`, which creates and installs handler functions or lambdas for several different HTTP endpoints. Each of these functions takes as input the details of the current request (such as the URI which was called, the query string, the request body), interacts with the KV tables using the given :cpp:class:`kv::Tx` object, and returns a result:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: record
    :end-before: SNIPPET_END: record
    :dedent:

This example uses the ``json_adapter`` wrapper function, which handles parsing of a JSON params object from the HTTP request body.

Each function is installed as the handler for a specific HTTP resource, defined by a verb and URI:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_record
    :end-before: SNIPPET_END: install_record
    :dedent:

This example installs at ``"log/private", HTTP_POST``, so will be invoked for HTTP requests beginning :http:POST:`/app/log/private`.

The return value from ``make_endpoint`` is an ``Endpoint&`` object which can be used to alter how the handler is executed. For example, the handler for :http:POST:`/app/log/private` shown above sets a `schema` declaring the types of its request and response bodies. These will be used in calls to the :http:GET:`/app/api` endpoint to populate the relevant parts of the OpenAPI document. That OpenAPI document in turn is used to generate the entries in this documentation describing :http:POST:`/app/log/private`.

There are other endpoints installed for the URI path ``/app/log/private`` with different verbs, to handle :http:GET:`GET </app/log/private>` and :http:DELETE:`DELETE </app/log/private>` requests. Requests with those verbs will be executed by the appropriate handler. Any other verbs, without an installed endpoint, will not be accepted - the framework will return a ``405 Method Not Allowed`` response.

To process the raw body directly, a handler should use the general lambda signature which takes a single ``EndpointContext&`` parameter. Examples of this are also included in the logging sample app. For instance the ``log_record_text`` handler takes a raw string as the request body:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_text
    :end-before: SNIPPET_END: log_record_text
    :dedent:

Rather than parsing the request body as JSON and extracting the message from it, in this case `the entire body` is the message to be logged, and the ID to associate it with is passed as a request header. This requires some additional code in the handler, but provides complete control of the request and response formats.

This general signature also allows a handler to see additional caller context. An example of this is the ``log_record_prefix_cert`` handler:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: log_record_prefix_cert
    :end-before: SNIPPET_END: log_record_prefix_cert
    :dedent:

This parses the caller's TLS certificate, and prefixes the logged message with the ``Subject`` field extracted from this certificate.

If a handler makes no writes to the KV, it may be installed as read-only:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_get
    :end-before: SNIPPET_END: install_get
    :dedent:

This offers some additional type safety (accidental `put`\s or `remove`\s will be caught at compile-time) and also enables performance scaling since read-only operations can be executed on any receiving node, whereas writes must always be executed on the primary node.

API Schema
~~~~~~~~~~

Instead of taking and returning `nlohmann::json` objects directly, the endpoint handlers use a macro-generated schema and parser converting compliant requests into a PoD C++ object:

.. literalinclude:: ../../samples/apps/logging/logging_schema.h
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_macros
    :end-before: SNIPPET_END: macro_validation_macros
    :dedent:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: macro_validation_record
    :end-before: SNIPPET_END: macro_validation_record
    :dedent:

This produces validation error messages with a low performance overhead, and ensures the schema and parsing logic stay in sync, but is only suitable for simple schema - an object with some required and some optional fields, each of a supported type.

Authentication
~~~~~~~~~~~~~~

Each endpoint must provide a list of associated authentication policies in the call to ``make_endpoint``. Inside the handler, the caller identity that was constructed by the accepting policy check can be retrieved with ``get_caller`` or ``try_get_caller`` - the latter should be used when multiple policies are present, to detect which policy accepted the request.

For example in the ``/log/private`` endpoint above there is a single policy stating that requests must come from a known user cert, over mutually authenticated TLS. This is one of several built-in policies provided by CCF. These built-in policies will check that the caller's TLS cert is a known user or member identity, or that the request is HTTP signed by a known user or member identity, or that the request contains a JWT signed by a known issuer. Additionally, there is an empty policy which accepts all requests, which should be used as the final policy to declare that the endpoint is optionally authenticated (either an earlier-listed policy passes providing a real caller identity, or the empty policy passes and the endpoint is invoked with no caller identity). To declare that an endpoint has no authentication requirements and should be accessible by any caller, use the special value ``no_auth_required``.

Applications can extend this system by writing their own authentication policies. There is an example of this in the C++ logging app. First it defines a type describing the identity details it aims to find in an acceptable request:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_identity
    :end-before: SNIPPET_END: custom_identity
    :dedent:

Next it defines the policy itself. The core functionality is the implementation of the ``authenticate()`` method, which looks at each request and returns either a valid new identity if it accepts the request, or ``nullptr`` if it does not. In this demo case it is looking for a pair of headers and doing some validation of their values:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_auth_policy
    :end-before: SNIPPET_END: custom_auth_policy
    :dedent:

Note that ``authenticate()`` is also passed a ``ReadOnlyTx`` object, so more complex authentication decisions can depend on the current state of the KV. For instance the built-in TLS cert auth policies are looking up the currently known user/member certs stored in the KV, which will change over the life of the service.

The final piece is the definition of the endpoint itself, which uses an instance of this new policy when it is constructed and then retrieves the custom identity inside the handler:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: custom_auth_endpoint
    :end-before: SNIPPET_END: custom_auth_endpoint
    :dedent:

Default Endpoints
~~~~~~~~~~~~~~~~~

The logging app sample exposes several built-in endpoints which are provided by the framework for convenience, such as :http:GET:`/app/tx`, :http:GET:`/app/commit`, and :http:GET:`/app/receipt`. It is also possible to write an app which does not expose these endpoints, either to build a minimal user-facing API or to re-wrap this common functionality in your own format or authentication. A sample of this is provided in ``samples/apps/nobuiltins``. Whereas the logging app declares a registry inheriting from :cpp:class:`ccf::CommonEndpointRegistry`, this app inherits from :cpp:class:`ccf::BaseEndpointRegistry` which does not install any default endpoints:

.. literalinclude:: ../../samples/apps/nobuiltins/nobuiltins.cpp
    :language: cpp
    :start-after: SNIPPET: registry_inheritance
    :lines: 1
    :dedent:

This app can then define its own endpoints from a blank slate. If it wants to provide similar functionality to the default endpoints, it does so using the APIs provided by :cpp:class:`ccf::BaseEndpointRegistry`. For instance to retrieve the hardware quote of the executing node:

.. literalinclude:: ../../samples/apps/nobuiltins/nobuiltins.cpp
    :language: cpp
    :start-after: SNIPPET_START: get_quote_api_v1
    :end-before: SNIPPET_END: get_quote_api_v1
    :dedent:

Historical Queries
~~~~~~~~~~~~~~~~~~

This sample demonstrates how to define a historical query endpoint with the help of :cpp:func:`ccf::historical::adapter_v2`.

The handler passed to the adapter is very similar to a read-only endpoint definition, but receives a read-only :cpp:struct:`ccf::historical::State` rather than a transaction.

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: get_historical
    :end-before: SNIPPET_END: get_historical
    :dedent:

Receipts
~~~~~~~~

Historical state always contains a receipt. Users wishing to implement a receipt endpoint may return it directly, or include it along with other historical state in the response.

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: get_historical_with_receipt
    :end-before: SNIPPET_END: get_historical_with_receipt
    :dedent:

User-Defined Claims in Receipts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A user wanting to tie transaction-specific values to a receipt can do so by attaching a claims digest to their transaction.
This is conceptually equivalent to getting a signature from the service for claims made by the application logic.

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: set_claims_digest
    :end-before: SNIPPET_END: set_claims_digest
    :dedent:

CCF will record this transaction as a leaf in the Merkle tree constructed from the combined digest of the write set, this ``claims_digest``, and the :term:`Commit Evidence`.

This ``claims_digest`` will be exposed in receipts under ``leaf_components``. It can then be revealed externally,
or by the endpoint directly if it has been stored in the ledger. The receipt object deliberately makes the ``claims_digest`` optional,
to allow the endpoint to remove it when the claims themselves are revealed.

Receipt verification can then only succeed if the revealed claims are digested and their digest combined into a
``leaf`` that correctly combines with the ``proof`` to form the ``root`` that the signature covers. Receipt verification
therefore establishes the authenticity of the claims.

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: claims_digest_in_receipt
    :end-before: SNIPPET_END: claims_digest_in_receipt
    :dedent:

A client consuming the output of this endpoint must digest the claims themselves, combine the digest with the other leaf components
(``write_set_digest`` and ``hash(commit_evidence)``) to obtain the equivalent ``leaf``. See :ref:`use_apps/verify_tx:Receipt Verification` for the full set of steps.

As an example, a logging application may register the contents being logged as a claim:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: record_public
    :end-before: SNIPPET_END: record_public
    :dedent:

And expose an endpoint returning receipts, with that claim expanded:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: get_historical_with_receipt
    :end-before: SNIPPET_END: get_historical_with_receipt
    :dedent:

Receipts from this endpoint will then look like:

.. code-block:: python

    {'msg': 'Public message at idx 5 [0]',
     'receipt': {'cert': '-----BEGIN CERTIFICATE-----\n'
                         'MIIBzzCCAVWgAwIBAgIRANKoegKBViucMxSPzftnDB4wCgYIKoZIzj0EAwMwFjEU\n'
                         'MBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwMzE1MjExODIwWhcNMjIwMzE2MjEx\n'
                         'ODE5WjATMREwDwYDVQQDDAhDQ0YgTm9kZTB2MBAGByqGSM49AgEGBSuBBAAiA2IA\n'
                         'BG+RJ5qNPOga8shCF3w64yija/ShW46JxrE0n9kDybyRf+L3810GjCvjxSpzTQhX\n'
                         '5WEF2dou1dG2ppI/KSNQsSfk081lbaB50NADWw+jDCtrq/fKuZ+w9wQSaoSvE5+0\n'
                         '1qNqMGgwCQYDVR0TBAIwADAdBgNVHQ4EFgQU7tFQR91U1EDhup1XPS3u0w5+R2Yw\n'
                         'HwYDVR0jBBgwFoAU3aI0vfJMBdWckvv9dKK2UzNCLU0wGwYDVR0RBBQwEocEfwAA\n'
                         'AYcEfxoNCocEfwAAAjAKBggqhkjOPQQDAwNoADBlAjAiOmvGpatg4Uq8phQkwj/p\n'
                         'Wj33fih6SUtRHOpdsIKvbV8TDNHRdSo1RKPArDd1w1wCMQDnw9zziS5G8qwvucP3\n'
                         'gn3htz+2ZPBJRr98AqmRNmgflhgqLQp+jAVPrJaWtD3fDpw=\n'
                         '-----END CERTIFICATE-----\n',
                 'leaf_components': {'commit_evidence': 'ce:2.25:54571ec6d0540b364d8343b74dff055932981fd72a24c1399c39ca9c74d2f713',
                                     'write_set_digest': '08b044fc5b0e9cd03c68d77c949bb815e3d70bd24ad339519df48758430ac0f7'},
                 'node_id': '95baf92969b4c9e52b4f8fcde830dea9fa0286a8c3a92cda4cffcf8251c06b39',
                 'proof': [{'left': '50a1a35a50bd2c5a4725907e77f3b1f96f1f9f37482aa18f8e7292e0542d9d23'},
                           {'left': 'e2184154ac72b304639b923b3c7a0bc04cecbd305de4f103a174a90210cae0dc'},
                           {'left': 'abc9bcbeff670930c34ebdab0f2d57b56e9d393e4dccdccf2db59b5e34507422'}],
                 'signature': 'MGUCMHYBgZ3gySdkJ+STUL13EURVBd8354ULC11l/kjx20IwpXrg/aDYLWYf7tsGwqUxPwIxAMH2wJDd9wpwbQrULpaAx5XEifpUfOriKtYo7XiFr05J+BV10U39xa9GBS49OK47QA=='}}
                 
Note that the ``claims_digest`` is deliberately omitted from ``leaf_components``, and must be re-computed by digesting the ``msg``.