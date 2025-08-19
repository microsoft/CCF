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
  - ``"member_cert"``
  - ``"any_cert"``
  - ``"jwt"``
  - ``"user_cose_sign1"``
  - ``"no_auth"``

.. _allofauthnpolicy:
.. note::
    This tests each policy in the list in-order, and passes if any single policy passes (returning the corresponding identity).
    To combine policies so that they must `all` pass, you may instead pass an object with an ``allOf`` key as an element of this list.
    For example, this endpoint will test (in order of preference) for `a member cert`, then `a user cert AND a JWT`, then `a JWT`:

    .. code-block:: json

        {
          "authn_policies": [
            "member_cert",
            {
              "all_of": ["user_cert", "jwt"]
            },
            "jwt"
          ]
        }

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
It is an object implementing the :typedoc-interface:`CCF <ccf-app/global/CCF>` interface.

.. note::
  `Web APIs <https://developer.mozilla.org/en-US/docs/Web/API>`_ are not available.

Endpoint handlers
~~~~~~~~~~~~~~~~~

An endpoint handler is an exported function that receives a :typedoc-interface:`Request <ccf-app/endpoints/Request>` object, returns a :typedoc-interface:`Response <ccf-app/endpoints/Response>` object, and is referenced in the ``app.json`` file of the app bundle (see above).

See the following handler from the example app bundle in the :ccf_repo:`tests/js-app-bundle/` folder of the CCF git repository. It validates the request body and returns the result of a mathematical operation:

.. literalinclude:: ../../tests/js-app-bundle/src/math.js
   :language: js

Accessing the current date and time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Code executing inside the enclave does not have access to a trusted time source. To prevent accidental errors (eg - relying on an in-enclave timestamp for tamper-proof ordering), the standard ``Date`` API is stubbed out by default - ``Date.now()`` will always return ``0``.

In many places where timestamps are desired, they should come from the outside with user requests - the accuracy of this timestamp is then considered a claim by a specific user, and the application logic is a purely functional transformation of those external inputs which does not generate unique claims of its own.

To ease porting of existing apps, and for logging scenarios, there is an option to retrieve the current time from the host. When the executing CCF node is run by an honest operator this will be kept up-to-date, but the accuracy of this is not covered by any attestation and as such these times should not be relied upon. To enable use of this untrusted time, call ``ccf.enableUntrustedDateTime(true)`` at any point in your application code, including at the global scope. After this is enabled, calls to ``Date.now()`` will retrieve the current time as specified by the untrusted host. This behaviour can also be revoked by a call to ``ccf.enableUntrustedDateTime(false)``, allowing the untrusted behaviour to be tightly scoped, and explicitly opted in to at each call point.

Execution metrics
~~~~~~~~~~~~~~~~~

By default the CCF JS runtime will print a log line for each completed JS request. This lists the request path and response status as well as how long the request took to execute. Each line also includes a ``[js]`` tag so that they can easily be filtered and sent to an automated monitoring system. These lines have the following format:

.. code-block::

    <timestamp> [info ][js] <...> | JS execution complete: Method=GET, Path=/app/make_randoms, Status=200, ExecMilliseconds=30

These are designed to aid debugging, as a starting point for building operational metrics graphs.

.. note:: The execution time is only precise within a few milliseconds, and relies on the time provided by the untrusted host. It should be used for comparing the execution time between different requests, and as an approximation of real execution time, but will not help distinguish requests which complete in under 1ms.

Some applications may not wish to log this information to the untrusted host (for example, if the frequency of each request type is considered confidential). This logging can be disabled by a call to ``ccf.enableMetricsLogging(false)`` at any point in the application code. This could be at the global scope to disable this logging for all calls, or within a single request handler to selectively mute that request.

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

If you are using ``npm`` to build your app, we package a `ccf-build-bundle` script alongside `ccf-app`. This can be run using `npx --package @microsoft/ccf-app ccf-build-bundle path/to/root/of/app` to package the `app.json` and all javascript modules under `src` into a proposal-ready JSON bundle.

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

Reusing interpreters
~~~~~~~~~~~~~~~~~~~~

By default, every request executes in a freshly-constructed JS interpreter. This provides extremely strict sandboxing - the only interaction with other requests is transactionally via the KV - and so forbids the sharing of any global state. For some applications, this may lead to unnecessarily duplicated work.

For instance, if your application needs to construct a large, immutable singleton object to process a request, that construction cost will be paid in each and every request. Requests could execute significantly faster if they were able to access and reuse a previously-constructed object, rather than constructing their own. JS libraries designed for other runtimes (such as Node) may benefit from this, as they expect to have a persistent global state.

CCF supports this pattern with `interpreter reuse`. Applications may opt-in to persisting an interpreter, and all of its global state, to be reused by multiple requests. This means that expensive initialisation work can be done once, and the resulting objects stashed in the global state where future requests will reuse them.

Note that this removes the sandboxing protections described above. If the contents of the global state change the result of a request's execution, then the execution will no longer be reproducible from the state recorded in the ledger, since the state of the interpreter cache will not be recorded. This should be avoided - reuse should only be used to make a handler `faster`, not to `change its behaviour`.

This behaviour is controlled in ``app.json``, with the ``"interpreter_reuse"`` property on each endpoint. The default behaviour, taken when the field is omitted, is to avoid any interpreter reuse, providing strict sandboxing safety. To reuse an interpreter, set ``"interpreter_reuse"`` to an object of the form ``{"key": "foo"}``, where ``foo`` is an arbitrary, app-defined string. Interpreters will be shared between endpoints where this string matches. For instance:

.. code-block:: yaml

    {
      "endpoints": {
        "/admin/modify": {
          "post": {
            "js_module": ...,
            "interpreter_reuse": {"key": "admin_interp"}
          }
        },
        "/admin/admins": {
          "get": {
            "js_module": ...,
            "interpreter_reuse": {"key": "admin_interp"}
          },
          "post": {
            "js_module": ...,
            "interpreter_reuse": {"key": "admin_interp"}
          }
        },
        "/sum/{a}/{b}": {
          "get": {
            "js_module": ...,
            "interpreter_reuse": {"key": "sum"}
          }
        },
        "/fast/and/small": {
          "get": {
            "js_module": ...
            // No "interpreter_reuse" field
          }
        }
      }
    }

In this example, each CCF node will store up-to 2 interpreters, and divides the endpoints into 3 classes:

- Requests to ``POST /admin/modify``, ``GET /admin/admins``, and ``POST /admin/admins`` will reuse the same interpreter (keyed by the string ``"admin_interp"``).
- Requests to ``GET /sum/{a}/{b}`` will use a separate interpreter (keyed by the string ``"sum"``).
- Requests to ``GET /fast/and/small`` will `not reuse any interpreters`, instead getting a fresh interpreter for each incoming request.

Note that ``"interpreter_reuse"`` describes when interpreters `may` be reused, but does not ensure that an interpreter `is` reused. A CCF node may decide to evict interpreters to limit memory use, or for parallelisation. Additionally, interpreters are node-local, are evicted for semantic safety whenever the JS application is modified, and only constructed on-demand for an incoming request (so the first request will see no performance benefit, since it includes the initialisation cost that later requests can skip). In short, this reuse should be seen as a best-effort optimisation - when it takes effect it will make many request patterns significantly faster, but it should not be relied upon for correctness.
