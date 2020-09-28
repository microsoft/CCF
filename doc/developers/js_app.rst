JavaScript Application
======================

CCF includes a native ``js_generic`` application which can execute JavaScript applications proposed through governance.

CCF's JavaScript environment is similar to that in browsers, with the following differences:

- only `JavaScript modules <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules>`_ are supported,
- no `Web APIs <https://developer.mozilla.org/en-US/docs/Web/API>`_ are available,
- module imports cannot be URLs and must be relative paths.

Typical web applications running in browsers have a top-level module that does not
export functions but rather modifies the global browser state.
In CCF, top-level modules define the application endpoints and instead export
one or more functions that are called by CCF from C++.

The most basic CCF JavaScript app has the following folder structure:

.. code-block:: bash

    $ tree my-app/
    my-app/
    ├── app.json
    └── src
        └── app.js

We also call this a `JavaScript app bundle` since it is the format used for deployment.
It consists of metadata (``app.json``) and one or more JavaScript modules (``src/``)
-- more details in later sections.

You can find an example app bundle in the ``tests/js-app-bundle`` folder of the CCF git repository.

An app bundle can be turned into a proposal with the Python client:

.. code-block:: bash

    $ python -m ccf.proposal_generator deploy_js_app my-app/
    SUCCESS | Writing proposal to ./deploy_js_app_proposal.json
    SUCCESS | Wrote vote to ./deploy_js_app_vote_for.json

Once accepted, a ``deploy_js_app`` proposal atomically (re-)deploys the complete JavaScript application.
Any existing application endpoints and JavaScript modules are removed.

In the following sections we go into details of the metadata file and
how JavaScript modules can export endpoint handlers.

Modern JavaScript app development typically makes use of
`Node.js <https://nodejs.org/>`_,
`npm <https://www.npmjs.com/>`_, and
`TypeScript <https://www.typescriptlang.org/>`_.
CCF provides multiple example apps built with these tools.
They involve a `build` step that generates an app bundle suitable for CCF.
See the following pages for more details:

.. toctree::
   :maxdepth: 1

   js_app_ts_npm
   js_app_tsoa_npm

Metadata
--------

The ``app.json`` file has the following structure:

.. code-block:: json

    {
      "endpoints": {
        "/foo": {
          "post": {
            "js_module": "app.js",
            "js_function": "foo_post",
            "forwarding_required": "never",    
            "execute_locally": true,           
            "require_client_signature": false, 
            "require_client_identity": true,
            "readonly": true,
            "openapi": {
              ...
            }
          },
          ...
        },
        ...
      }
    }

``"endpoints"`` contains endpoint descriptions nested by REST API URL and HTTP method.
Each endpoint object contains the following information:

- ``"js_module"``: The path to the module containing the endpoint handler, relative to the ``src/`` folder.
- ``"js_function"``: The name of the endpoint handler function.
- ``"forwarding_required"``, ``"execute_locally"``,
  ``"require_client_signature"``, ``"require_client_identity"```,
  ``"readonly"``: Request execution policies, see **TODO**.
- ``"openapi"``:  An `OpenAPI Operation Object <https://swagger.io/specification/#operation-object>`_ 
  without `references <https://swagger.io/specification/#reference-object>`_.

.. note::
    See the :ref:`tsoa-based app example <tsoa-app>` on how to generate OpenAPI definitions with TypeScript.

JavaScript modules
------------------

An endpoint handler is an exported function that receives a ``request`` object
and returns a ``response`` object.

A request object has the following fields:

- ``headers``: An object mapping lower-case HTTP header names to their values.
- ``params``: An object mapping URL path parameter names to their values.
- ``query``: The query string of the requested URL.
- ``body``: An object with ``text()``/``json()``/``arrayBuffer()`` functions to access the
  request body in various ways.

A response object can contain the following fields (all optional):

- ``statusCode``: The HTTP status code to return (default ``200``, or ``500`` if an exception is raised).
- ``headers``: An object mapping lower-case HTTP header names to their values.
  Depending on the type of ``body`` a default content type is used, see below.
- ``body``: Either
  a `string <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String>`_ (``text/plain``),
  an `ArrayBuffer <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer>`_ (``application/octet-stream``),
  a `TypedArray <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray>`_ (``application/octet-stream``),
  or as fall-back any `JSON-serializable <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify>`_ value (``application/json``).
  The content type in parentheses is the default and can be overridden in ``headers``.

See the following handler from the example app bundle in the ``tests/js-app-bundle`` folder of the CCF git repository.
It validates the request input and returns the result of a mathematical operation:

.. literalinclude:: ../../tests/js-app-bundle/src/math.js
   :language: js
