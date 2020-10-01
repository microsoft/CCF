JavaScript Application Bundle
=============================

The native format for JavaScript applications in CCF is a JavaScript application bundle, or short app bundle.
A bundle can be wrapped directly into a governance proposal for deployment.

This page documents the components of a bundle and the JavaScript API available for developing endpoints.

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

      js_app_ts
      js_app_tsoa

Folder Layout
-------------

A bundle has the following folder structure:

.. code-block:: bash

    $ tree --dirsfirst my-app
    my-app
    ├── src
    │   └── app.js
    └── app.json

It consists of :ref:`metadata <developers/js_app_bundle:Metadata>` (``app.json``) and one or more :ref:`JavaScript modules <developers/js_app_bundle:JavaScript API>` (``src/``).
JavaScript modules can `import <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import>`_ other modules using relative path names.

You can find an example app bundle in the
`tests/js-app-bundle <https://github.com/microsoft/CCF/tree/master/tests/js-app-bundle>`_
folder of the CCF git repository.

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
    See the :ref:`tsoa-based app example <developers/js_app_tsoa:TypeScript Application using tsoa>` on how to generate OpenAPI definitions with TypeScript.

.. warning::
    CCF currently ignores all fields except ``"js_module"`` and ``"js_function"``.
    This will be addressed in the near future, see
    `#1460 <https://github.com/microsoft/CCF/issues/1460>`_ and `#1565 <https://github.com/microsoft/CCF/issues/1565>`_.

JavaScript API
--------------

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

.. note::
  `Web APIs <https://developer.mozilla.org/en-US/docs/Web/API>`_ are not available.

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
    See the :ref:`tsoa-based app example <developers/js_app_tsoa:TypeScript Application using tsoa>` on how to automatically validate
    JSON request data using TypeScript types.

Deployment
----------

An app bundle can be wrapped into a governance proposal with the Python client for deployment:

.. code-block:: bash

    $ python -m ccf.proposal_generator deploy_js_app my-app/
    SUCCESS | Writing proposal to ./deploy_js_app_proposal.json
    SUCCESS | Wrote vote to ./deploy_js_app_vote_for.json

Once :ref:`submitted and accepted <members/proposals:Submitting a New Proposal>`, a ``deploy_js_app`` proposal atomically (re-)deploys the complete JavaScript application.
Any existing application endpoints and JavaScript modules are removed.
