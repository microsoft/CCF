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
    CCF provides an example app built with these tools.
    They involve a `build` step that generates an app bundle suitable for CCF.
    See the following for more details:

    .. toctree::
      :maxdepth: 1

      js_app_ts

Folder Layout
-------------

A bundle has the following folder structure:

.. code-block:: bash

    $ tree --dirsfirst my-app
    my-app
    ├── src
    │   └── app.js
    └── app.json

It consists of :ref:`metadata <build_apps/js_app_bundle:Metadata>` (``app.json``) and one or more :ref:`JavaScript modules <build_apps/js_app_bundle:JavaScript API>` (``src/``).
JavaScript modules can `import <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import>`_ other modules using relative path names.

You can find an example app bundle in the :ccf_repo:`tests/js-app-bundle/` folder of the CCF git repository.

Metadata
--------

The ``app.json`` file of an app bundle has the following structure:

.. code-block:: js

    {
      "endpoints": {
        "/foo": {
          "post": {
            "js_module": "app.js",
            "js_function": "foo_post",
            "forwarding_required": "never",
            "authn_policies": ["user_cert"],
            "mode": "readonly",
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
- ``"js_function"``: The name of the endpoint handler function. This must be the name of a function exported by
  the ``js_module``.
- ``"authn_policies"``: A list of :ref:`authentication policies <build_apps/auth/index:User Authentication>` to be applied before the endpoint
  is executed. An empty list indicates an unauthenticated endpoint which can be called by anyone. Possible entries are:

  - ``"user_cert"``
  - ``"user_signature"``
  - ``"member_cert"``
  - ``"member_signature"``
  - ``"jwt"``
  - ``"no_auth"``

- ``"forwarding_required"``: A string indicating whether the endpoint is always forwarded, or whether it is safe to sometimes execute on followers. Possible values are:

  - ``"always"``
  - ``"sometimes"``
  - ``"never"``

- ``"mode"``: A string indicating whether the endpoint requires read/write or read-only access to the Key-Value Store, or whether it is a historical endpoint that sees the state written in a specific transaction. Possible values are:

  - ``"readwrite"``
  - ``"readonly"``
  - ``"historical"``

- ``"openapi"``:  An `OpenAPI Operation Object <https://swagger.io/specification/#operation-object>`_
  without `references <https://swagger.io/specification/#reference-object>`_. This is descriptive but not
  enforced - it will be inserted into the generated OpenAPI document for this service, but will not restrict the
  types of the endpoint's requests or responses.

You can find an example metadata file at :ccf_repo:`tests/js-app-bundle/app.json` in the CCF git repository.

JavaScript API
--------------

Globals
~~~~~~~

JavaScript provides a set of built-in
`global functions, objects, and values <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects>`_.

CCF provides the additional global variable ``ccf`` to access native CCF functionality.
It is an object implementing the :typedoc:interface:`CCF <ccf-app/global/CCF>` interface.

.. note::
  `Web APIs <https://developer.mozilla.org/en-US/docs/Web/API>`_ are not available.

Endpoint handlers
~~~~~~~~~~~~~~~~~

An endpoint handler is an exported function that receives a :typedoc:interface:`Request <ccf-app/endpoints/Request>` object, returns a :typedoc:interface:`Response <ccf-app/endpoints/Response>` object, and is referenced in the ``app.json`` file of the app bundle (see above).

See the following handler from the example app bundle in the :ccf_repo:`tests/js-app-bundle/` folder of the CCF git repository. It validates the request body and returns the result of a mathematical operation:

.. literalinclude:: ../../tests/js-app-bundle/src/math.js
   :language: js

Deployment
----------

An app bundle can be wrapped into a governance proposal with the Python client for deployment:

.. code-block:: bash

    $ python -m ccf.proposal_generator set_js_app my-app/
    SUCCESS | Writing proposal to ./set_js_app_proposal.json
    SUCCESS | Wrote vote to ./set_js_app_vote_for.json

Once :ref:`submitted and accepted <governance/proposals:Submitting a New Proposal>`, a ``set_js_app`` proposal atomically (re-)deploys the complete JavaScript application.
Any existing application endpoints and JavaScript modules are removed.
