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
    See the :ref:`TypeScript Application <build_apps/js_app_ts:TypeScript Application>` section for more details

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

.. note:: "sometimes" is a good default value for most endpoints. The node that receives the request will forward only to preserve session consistency (a previous transaction was already forwarded), or because the transaction cannot be executed locally (it involves a write, and the node is a backup). "always" is a good setting for endpoints that always write to the KV, because it saves attempting the transaction on a backup before forwarding.
   
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

Accessing the current date and time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Code executing inside the enclave does not have access to a trusted time source. To prevent accidental errors (eg - relying on an in-enclave timestamp for tamper-proof ordering), the standard ``Date`` API is stubbed out by default - ``Date.now()`` will always return ``0``.

In many places where timestamps are desired, they should come from the outside with user requests - the accuracy of this timestamp is then considered a claim by a specific user, and the application logic is a purely functional transformation of those external inputs which does not generate unique claims of its own.

To ease porting of existing apps, and for logging scenarios, there is an option to retrieve the current time from the host. When the executing CCF node is run by an honest operator this will be kept up-to-date, but the accuracy of this is not covered by any attestation and as such these times should not be relied upon. To enable use of this untrusted time, call ``ccf.enableUntrustedDateTime(true)`` at any point in your application code, including at the global scope. After this is enabled, calls to ``Date.now()`` will retrieve the current time as specified by the untrusted host. This behaviour can also be revoked by a call to ``ccf.enableUntrustedDateTime(false)``, allowing the untrusted behaviour to be tightly scoped, and explicitly opted in to at each call point.

Deployment
----------

An app bundle must be wrapped into a JSON object for submission as a ``set_js_app`` proposal to deploy the application code onto a CCF service.
For instance a proposal which deploys the example app above would look like:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_js_app",
          "args": {
            "bundle": {
              "metadata": {
                "endpoints": {
                  "/compute": {
                    "post": {
                      "js_module": "math.js",
                      "js_function": "compute",
                      "forwarding_required": "never",
                      "authn_policies": [
                        "user_cert"
                      ],
                      "mode": "readonly",
                      "openapi": {
                        "requestBody": {
                          "required": true,
                          "content": {
                            "application/json": {
                              "schema": {
                                "properties": {
                                  "op": {
                                    "type": "string",
                                    "enum": [
                                      "add",
                                      "sub",
                                      "mul"
                                    ]
                                  },
                                  "left": {
                                    "type": "number"
                                  },
                                  "right": {
                                    "type": "number"
                                  }
                                },
                                "required": [
                                  "op",
                                  "left",
                                  "right"
                                ],
                                "type": "object",
                                "additionalProperties": false
                              }
                            }
                          }
                        },
                        "responses": {
                          "200": {
                            "description": "Compute result",
                            "content": {
                              "application/json": {
                                "schema": {
                                  "properties": {
                                    "result": {
                                      "type": "number"
                                    }
                                  },
                                  "required": [
                                    "result"
                                  ],
                                  "type": "object",
                                  "additionalProperties": false
                                }
                              }
                            }
                          },
                          "400": {
                            "description": "Client-side error",
                            "content": {
                              "application/json": {
                                "schema": {
                                  "properties": {
                                    "error": {
                                      "description": "Error message",
                                      "type": "string"
                                    }
                                  },
                                  "required": [
                                    "error"
                                  ],
                                  "type": "object",
                                  "additionalProperties": false
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  },
                  "/compute2/{op}/{left}/{right}": {
                    "get": {
                      "js_module": "math.js",
                      "js_function": "compute2",
                      "forwarding_required": "never",
                      "authn_policies": [
                        "user_cert"
                      ],
                      "mode": "readonly",
                      "openapi": {
                        "parameters": [
                          {
                            "name": "op",
                            "in": "path",
                            "required": true,
                            "schema": {
                              "type": "string",
                              "enum": [
                                "add",
                                "sub",
                                "mul"
                              ]
                            }
                          },
                          {
                            "name": "left",
                            "in": "path",
                            "required": true,
                            "schema": {
                              "type": "number"
                            }
                          },
                          {
                            "name": "right",
                            "in": "path",
                            "required": true,
                            "schema": {
                              "type": "number"
                            }
                          }
                        ],
                        "responses": {
                          "default": {
                            "description": "Default response"
                          }
                        }
                      }
                    }
                  }
                }
              },
              "modules": [
                {
                  "name": "math.js",
                  "module": "function compute_impl(op, left, right) {\n  let result;\n  if (op == \"add\") result = left + right;\n  else if (op == \"sub\") result = left - right;\n  else if (op == \"mul\") result = left * right;\n  else {\n    return {\n      statusCode: 400,\n      body: {\n        error: \"unknown op\",\n      },\n    };\n  }\n\n  return {\n    body: {\n      result: result,\n    },\n  };\n}\n\nexport function compute(request) {\n  const body = request.body.json();\n\n  if (typeof body.left != \"number\" || typeof body.right != \"number\") {\n    return {\n      statusCode: 400,\n      body: {\n        error: \"invalid operand type\",\n      },\n    };\n  }\n\n  return compute_impl(body.op, body.left, body.right);\n}\n\nexport function compute2(request) {\n  const params = request.params;\n\n  // Type of params is always string. Try to parse as float\n  let left = parseFloat(params.left);\n  if (isNaN(left)) {\n    return {\n      statusCode: 400,\n      body: {\n        error: \"left operand is not a parseable number\",\n      },\n    };\n  }\n\n  let right = parseFloat(params.right);\n  if (isNaN(right)) {\n    return {\n      statusCode: 400,\n      body: {\n        error: \"right operand is not a parseable number\",\n      },\n    };\n  }\n\n  return compute_impl(params.op, left, right);\n}\n"
                }
              ]
            },
            "disable_bytecode_cache": false
          }
        }
      ]
    }

The key fields are:

- ``args.bundle.metadata``: The object contained in ``app.json``, defining the HTTP endpoints that access the app.
- ``args.bundle.modules``: The contents of all JS files (including scripts and any modules they depend on) which define the app's functionality.
- ``args.disable_bytecode_cache``: Whether the bytecode cache should be enabled for this app. See below for more detail.

Once :ref:`submitted and accepted <governance/proposals:Submitting a New Proposal>`, a ``set_js_app`` proposal atomically (re-)deploys the complete JavaScript application.
Any existing application endpoints and JavaScript modules are removed.

If you are using ``npm`` or similar to build your app it may make sense to convert your app into a proposal-ready JSON bundle during packaging.
For an example of how this could be done, see :ccf_repo:`tests/npm-app/build_bundle.js` from one of CCF's test applications, called by ``npm build`` from the corresponding :ccf_repo:`tests/npm-app/package.json`.

Bytecode cache
~~~~~~~~~~~~~~

By default, the source code is pre-compiled into bytecode and both the source code and the bytecode are stored in the Key Value store. To disable precompilation and remove any existing cached bytecode, set ``"args.disable_bytecode_cache": true`` in the above proposal. See :ref:`Resource Usage <operations/resource_usage:Memory>` for a discussion on latency vs. memory usage.

If CCF is updated and introduces a newer JavaScript engine version, then any pre-compiled bytecode is not used anymore and must be re-compiled by either re-deploying the JavaScript application or issuing a proposal for re-compilation:

.. code-block:: json

    {
      "actions": [
        {
          "name": "refresh_js_app_bytecode_cache"
        }
      ]
    }

.. note:: The operator RPC :http:GET:`/node/js_metrics` returns the size of the bytecode and whether it is used. If it is not used, then either no bytecode is stored or it needs to be re-compiled due to a CCF update.
