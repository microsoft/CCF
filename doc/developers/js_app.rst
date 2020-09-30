JavaScript Application
======================

CCF includes a native ``js_generic`` application which can execute JavaScript applications proposed through governance.

CCF's JavaScript environment is similar to that in browsers, with the following differences:

- only `JavaScript modules <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules>`_ are supported,
- no `Web APIs <https://developer.mozilla.org/en-US/docs/Web/API>`_ are available,
- module imports cannot be URLs and must be relative paths.

.. _js-app-bundle:

App bundle
----------

The most basic CCF JavaScript app has the following folder structure:

.. code-block:: bash

    $ tree --dirsfirst my-app
    my-app
    ├── src
    │   └── app.js
    └── app.json

We also call this a `JavaScript app bundle` since it is the format used for deployment.
It consists of metadata (``app.json``) and one or more JavaScript modules (``src/``)
-- more details in later sections.

You can find an example app bundle in the
`tests/js-app-bundle <https://github.com/microsoft/CCF/tree/master/tests/js-app-bundle>`_
folder of the CCF git repository.

An app bundle can be wrapped into a governance proposal with the Python client for deployment:

.. code-block:: bash

    $ python -m ccf.proposal_generator deploy_js_app my-app/
    SUCCESS | Writing proposal to ./deploy_js_app_proposal.json
    SUCCESS | Wrote vote to ./deploy_js_app_vote_for.json

Once accepted, a ``deploy_js_app`` proposal atomically (re-)deploys the complete JavaScript application.
Any existing application endpoints and JavaScript modules are removed.

In the following sections we go into details of the metadata file and
how JavaScript modules can export application endpoint handlers.

.. note::
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

.. _js-app-bundle-metadata:

Metadata
--------

The ``app.json`` file of an app bundle has the following structure:

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

You can find an example metadata file at
`tests/js-app-bundle/app.json <https://github.com/microsoft/CCF/tree/master/tests/js-app-bundle/app.json>`_
in the CCF git repository.

.. note::
    See the :ref:`tsoa-based app example <tsoa-app>` on how to generate OpenAPI definitions with TypeScript.

JavaScript modules
------------------

Globals
~~~~~~~

JavaScript provides a set of built-in
`global functions, objects, and values <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects>`_.

CCF provides the following additional globals:

- ``tables``:
  Provides access to the Key-Value Store of the network.
  ``tables`` is an object that maps table names to ``Table`` objects.
  A ``Table`` object has ``get(k)``/``put(k,v)``/``remove(k)`` functions.
  Keys and values currently have to be strings, although this will change in the near future.

  Example: ``tables['msg'].put('123', 'Hello world!')``

Endpoint handlers
~~~~~~~~~~~~~~~~~

An endpoint handler is an exported function that receives a ``Request`` object, returns a ``Response`` object,
and is referenced in the ``app.json`` file of the app bundle (see above).

A ``Request`` object has the following fields:

- ``headers``: An object mapping lower-case HTTP header names to their values.
- ``params``: An object mapping URL path parameter names to their values.
- ``query``: The query string of the requested URL.
- ``body``: An object with ``text()``/``json()``/``arrayBuffer()`` functions to access the
  request body in various ways.

A ``Response`` object can contain the following fields (all optional):

- ``statusCode``: The HTTP status code to return (default ``200``, or ``500`` if an exception is raised).
- ``headers``: An object mapping lower-case HTTP header names to their values.
  The type of ``body`` determines the default value of the ``content-type`` header, see below.
- ``body``: Either
  a `string <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String>`_ (``text/plain``),
  an `ArrayBuffer <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer>`_ (``application/octet-stream``),
  a `TypedArray <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray>`_ (``application/octet-stream``),
  or as fall-back any `JSON-serializable <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify>`_ value (``application/json``).
  The content type in parentheses is the default and can be overridden in ``headers``.

See the following handler from the example app bundle in the
`tests/js-app-bundle <https://github.com/microsoft/CCF/tree/master/tests/js-app-bundle>`_
folder of the CCF git repository.
It validates the request body and returns the result of a mathematical operation:

.. literalinclude:: ../../tests/js-app-bundle/src/math.js
   :language: js

.. note::
    See the :ref:`tsoa-based app example <tsoa-app>` on how to automatically validate
    JSON request data using TypeScript types.
