TypeScript Application using tsoa
=================================

This guide shows how to build a TypeScript application using Node.js, npm, and tsoa.
It is recommended to read through the :ref:`build_apps/js_app_ts:TypeScript Application` page first.

Using `tsoa <https://github.com/lukeautry/tsoa>`_ as framework provides the following advantages over not using a framework:

- TypeScript types and JSDoc annotations are used to generate OpenAPI definitions and validate request data.
- App metadata (``app.json``) is auto-generated as much as possible.

The source code for the example app can be found in the
`samples/apps/forum <https://github.com/microsoft/CCF/tree/master/samples/apps/forum>`_
folder of the CCF git repository.

.. note::
   tsoa currently focuses on JSON as content type.
   Using other content types is possible but requires to :ref:`manually specify the OpenAPI definition <build_apps/js_app_tsoa>`.

Prerequisites
-------------

The following tools are assumed to be installed on the development machine:

- Node.js
- npm

Folder Layout
-------------

The sample app has the following folder layout:

.. code-block:: bash

    $ tree --dirsfirst forum
    forum
    ├── src
    │   ├── controllers
    │   │   ├── csv.ts
    │   │   ├── poll.ts
    │   │   └── site.ts
    │   ├── models
    │   │   └── poll.ts
    │   ├── types
    │   │   └── ccf.ts
    │   ├── authentication.ts
    │   └── error_handler.ts
    ├── tsoa-support
    │   ├── entry.ts
    │   ├── postprocess.js
    │   └── routes.ts.tmpl
    ├── app.tmpl.json
    ├── package.json
    ├── rollup.config.js
    ├── tsconfig.json
    └── tsoa.json

It contains these files:

- ``src/controllers/*.ts``: :ref:`build_apps/js_app_tsoa:Controllers`.
- ``src/models/*.ts``: Data models shared between endpoint handlers.
- ``src/types/ccf.ts``: :ref:`build_apps/js_app_tsoa:Type definitions` for CCF objects.
- ``src/authentication.ts``: `authentication module <https://tsoa-community.github.io/docs/authentication.html>`_. 
  See also :ref:`build_apps/auth/jwt_ms_example:JWT Authentication example using Microsoft Identity Platform`.
- ``src/error_handler.ts``: global error handler.
- ``tsoa-support/*``: Supporting scripts used during :ref:`build_apps/js_app_tsoa:Conversion to an app bundle`.
- ``app.tmpl.json``: :ref:`App metadata <build_apps/js_app_tsoa:Metadata>`.
- ``package.json``: Dependencies and build command.
- ``rollup.config.js``: Rollup configuration, see :ref:`build_apps/js_app_tsoa:Conversion to an app bundle` for more details.
- ``tsconfig.json``: TypeScript compiler configuration.
- ``tsoa.json``: tsoa configuration.

.. note::
    Rollup requires exactly one entry-point module.
    The :ref:`auto-generated <build_apps/js_app_tsoa:Conversion to an app bundle>` ``build/endpoints.ts`` module
    serves that purpose and re-exports all endpoint handlers from the other files in the same folder.
    Keeping endpoint handlers in separate modules and referencing those directly in ``app.tmpl.json``
    allows for fine-grained control over which other modules are loaded, per endpoint.
    This in turn may improve load time and/or memory consumption, for example if not all endpoints
    share the same npm package dependencies.

Controllers
-----------

In tsoa, a controller represents a URL path, or route, together with handlers for each supported HTTP method.
Typically, each controller is defined in its own module.
tsoa discovers controllers through a list of search locations specified in ``tsoa.json``:

.. code-block:: json

    {
        "controllerPathGlobs": [
            "src/controllers/*.ts"
        ]
    }

As an example, the ``/polls`` route of the sample app is implemented as in `src/controllers/poll.ts <https://github.com/microsoft/CCF/tree/master/samples/apps/forum/src/controllers/poll.ts>`_.

For more information on how to write controllers,
see the `tsoa documentation <https://tsoa-community.github.io/docs/getting-started.html#defining-a-simple-controller>`_.

.. note::
   :ref:`Endpoint handler functions <build_apps/js_app_bundle:Endpoint handlers>`, as required by CCF's JavaScript app bundles,
   are auto-generated from controllers during the :ref:`conversion to an app bundle <build_apps/js_app_tsoa:Conversion to an app bundle>`.

Type Definitions
----------------

CCF currently does not provide an npm package with TypeScript definitions
for :ref:`CCF's JavaScript API <build_apps/js_app_bundle:JavaScript API>`.

Instead, the definitions are part of the sample app in
`src/types/ccf.ts <https://github.com/microsoft/CCF/tree/samples/apps/forum/src/types/ccf.ts>`_.

Using CCF's ``Response`` object is not needed when using tsoa because the return value always has to be the body itself.
Headers and the status code can be set using `Controller methods <https://tsoa-community.github.io/reference/classes/_tsoa_runtime.controller-1.html>`_.

Sometimes though it is necessary to access CCF's ``Request`` object, for example when the request body is not JSON.
In this case, instead of using ``@Body() body: MyType`` as function argument, ``@Request() request: ccf.Request`` can be used.
See `src/controllers/csv.ts <https://github.com/microsoft/CCF/tree/master/samples/apps/forum/src/controllers/csv.ts>`_
for a concrete example.

.. warning::
    Requesting CCF's ``Request`` object via ``@Request()`` instead of using ``@Body()`` disables automatic schema validation.

Metadata
--------

App metadata is stored in an ``app.tmpl.json`` file in the root of the app project.
The file follows the :ref:`metadata format <build_apps/js_app_bundle:Metadata>` used by app bundles,
except that the ``"openapi"`` field is optional.

During :ref:`conversion to an app bundle <build_apps/js_app_tsoa:Conversion to an app bundle>` the following happens:

#. ``app.tmpl.json`` is created (if it doesn't exist yet) and from then on kept up-to-date.
   URL paths or HTTP methods that don't exist anymore are removed, new ones are added with default metadata.

#. The final ``dist/app.json`` file is generated by auto-populating ``"openapi"`` fields, if missing.

Conversion to an App Bundle
---------------------------

Preparing the app for deployment means converting it to CCF's native JavaScript application format, an :ref:`app bundle <build_apps/js_app_bundle:JavaScript Application Bundle>`.
This involves the following steps:

- transform TypeScript into JavaScript,
- transform bare imports (``lodash``) into relative imports (``./node_modules/lodash/lodash.js``),
- transform old-style CommonJS modules into native JavaScript modules,
- transform request/response TypeScript types into OpenAPI definitions,
- generate a module with CCF endpoint handlers for each tsoa controller (``build/*Proxy.ts``),
- generate a single entry-point module for Rollup (``build/endpoints.ts``),
- generate the final ``app.json`` metadata file with OpenAPI definitions (``dist/app.json``),
- store all files according to the app bundle folder structure (``dist/``).

For this, the sample app relies on the `TypeScript compiler <https://www.npmjs.com/package/typescript>`_,
`rollup <https://rollupjs.org>`_, `tsoa-cli <https://www.npmjs.com/package/@tsoa/cli>`_,
and custom scripts.
See ``package.json``, ``rollup.config.js``, ``tsoa.json``, and ``tsoa-support/`` for details.

The conversion command is invoked with

.. code-block:: bash

    $ npm run build

The app bundle can now be found in the ``dist/`` folder and is ready to be deployed.

Deployment
----------

After the app was converted to an app bundle, it can be wrapped into a proposal and deployed.
See the :ref:`Deployment section of the app bundle page <build_apps/js_app_bundle:Deployment>` for further details.
