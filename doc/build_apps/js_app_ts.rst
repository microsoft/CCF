TypeScript Application
======================

This guide shows how to build a TypeScript application using Node.js and npm.

The source code for the example app can be found in the :ccf_repo:`tests/npm-app/` folder of the CCF git repository.

Prerequisites
-------------

The following tools are assumed to be installed on the development machine:

- Node.js
- npm

Folder layout
-------------

The sample app has the following folder layout:

.. code-block:: bash

    $ tree --dirsfirst npm-app
    npm-app
    ├── src
    │   └── endpoints
    │       ├── all.ts
    │       ├── crypto.ts
    │       ├── partition.ts
    │       └── proto.ts
    ├── app.json
    ├── package.json
    ├── rollup.config.js
    └── tsconfig.json

It contains these files:

- ``src/endpoints/*.ts``: :ref:`build_apps/js_app_ts:Endpoint handlers`.
- ``app.json``: :ref:`App metadata <build_apps/js_app_ts:Metadata>`.
- ``package.json``: Dependencies and build command.
- ``rollup.config.js``: Rollup configuration, see :ref:`build_apps/js_app_ts:Conversion to an app bundle` for more details.
- ``tsconfig.json``: TypeScript compiler configuration.

.. note::
    Rollup requires exactly one entry-point module.
    The ``src/endpoints/all.ts`` module serves that purpose and re-exports all endpoint handlers
    from the other files in the same folder.
    Keeping endpoint handlers in separate modules and referencing those directly in ``app.json``
    allows for fine-grained control over which other modules are loaded, per endpoint.
    This in turn may improve load time and/or memory consumption, for example if not all endpoints
    share the same npm package dependencies.

Dependencies
------------

The sample uses several runtime and development packages (see ``package.json``).
One of them is the :typedoc:package:`ccf-app` package.
This package references the current branch's version of the ``ccf-app`` package using ``file:``.
To test against a published version you should adjust the version number accordingly:

.. code-block:: js

    "@microsoft/ccf-app": "~1.0.0",

Now you can continue with installing all dependencies:

.. code-block:: bash

    $ npm install

Endpoint handlers
-----------------

An endpoint handler, here named ``abc``, has the following structure:

.. code-block:: ts

    import * as ccfapp from 'ccf-app';

    interface AbcRequest {
        ...
    }

    interface AbcResponse {
        ...
    }

    export function abc(request: ccfapp.Request<AbcRequest>): ccfapp.Response<AbcResponse> {
        // access request details
        const data = request.body.json();

        // process request
        // ...

        // return response
        return {
            body: ...,
            headers: ...,
            statusCode: ...
        }
    }

``AbcRequest`` and ``AbcResponse`` define the JSON schema of the request and response body, respectively.
If an endpoint has no request or response body, the type parameters of :typedoc:interface:`ccfapp.Request <ccf-app/endpoints/Request>`/:typedoc:interface:`ccfapp.Response <ccf-app/endpoints/Response>` can be omitted.

As an example, the ``/partition`` endpoint of the sample app is implemented as:

.. literalinclude:: ../../tests/npm-app/src/endpoints/partition.ts
   :language: ts

Here, the request body is a JSON array with elements of arbitrary type,
and the response body is an even/odd partitioning of those elements as nested JSON array.
The example also shows how an external library, here ``lodash``, is imported and used.

.. warning::
    Even though request body schemas can be defined as part of the OpenAPI :ref:`metadata <build_apps/js_app_ts:Metadata>`,
    CCF does not validate incoming request data against those schemas.
    It is up to the application to perform any necessary validation.

.. tip::
    See the :typedoc:package:`ccf-app` package API documentation for how to access the Key-Value Store and other CCF functionality.
    Although not recommended, instead of using the :typedoc:package:`ccf-app` package, all native CCF functionality can also be directly accessed through the :typedoc:interface:`ccf <ccf-app/global/CCF>` global variable.


Metadata
--------

App metadata is stored in an ``app.json`` file in the root of the app project.
It is copied as-is to the ``dist/`` folder during the :ref:`build step <build_apps/js_app_ts:Conversion to an app bundle>`.
The file follows the :ref:`metadata format <build_apps/js_app_bundle:Metadata>` used by app bundles.

Note that module paths must be relative to the ``dist/src/`` folder and end with ``.js`` instead of ``.ts``.

Conversion to an app bundle
---------------------------

Preparing the app for deployment means converting it to CCF's native JavaScript application format, an :ref:`app bundle <build_apps/js_app_bundle:JavaScript Application Bundle>`.
This involves the following steps:

- transform TypeScript into JavaScript,
- transform bare imports (``lodash``) into relative imports (``./node_modules/lodash/lodash.js``),
- transform old-style CommonJS modules into native JavaScript modules, and
- store all files according to the app bundle folder structure.

For this, the sample app relies on the `TypeScript compiler <https://www.npmjs.com/package/typescript>`_ and
`rollup <https://rollupjs.org>`_. Rollup also offers tree shaking support
to avoid deploying unused modules. See ``package.json`` and ``rollup.config.js`` for details.

The conversion command is invoked with

.. code-block:: bash

    $ npm run build

The app bundle can now be found in the ``dist/`` folder and is ready to be deployed.

Deployment
----------

After the app was converted to an app bundle, it can be wrapped into a proposal and deployed.
See the :ref:`Deployment section of the app bundle page <build_apps/js_app_bundle:Deployment>` for further details.

A note on CommonJS modules
--------------------------

The sample project uses the
`@rollup/plugin-commonjs <https://github.com/rollup/plugins/tree/master/packages/commonjs>`_
package to automatically convert npm packages with CommonJS modules to native JavaScript modules
so that they can be used in CCF.

For some packages this conversion may fail, for example when the package has circular module dependencies.
If that is the case, try one of the following suggestions:

1. Check if there is a JavaScript module variant of the package and use that instead.
   These are also named ES or ECMAScript modules/packages.

2. Check if there is a known work-around to fix the conversion issue.
   Chances are you are not the only one experiencing it.

3. Check if the npm package contains a browser bundle and try to import that instead.
   For example, this works for protobuf.js: ``import protobuf from 'protobufjs/dist/protobuf.js'``.

4. Manually wrap a browser bundle of the package without using npm.
   This may be needed if the browser bundle is not part of the npm package, although this is uncommon.

Manually wrapping a browser bundle (step 4) means copying the bundle source code in a module
file and surrounding it with module boiler-plate. This may look something like:

.. code-block:: js

    let exports = {}, module = {exports};

    // REPLACE this comment with the content of the bundle.

    export default module.exports;

If the bundle uses only global exports instead of CommonJS/Node.js exports,
then the module should look something like:

.. code-block:: js

    // REPLACE this comment with the content of the bundle.

    // Adjust this to match the globals of the package.
    export {ExportA, ExportB};
