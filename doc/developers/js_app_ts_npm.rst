TypeScript Application using Node.js and npm
============================================

CCF's native JavaScript application format is an :ref:`app bundle <js-app-bundle>`.
However, this does not prevent us from using standard app development tools.
In the following we show how to build a CCF JavaScript app using TypeScript, Node.js, and npm.

You can find the example TypeScript app in the
`tests/npm-app <https://github.com/microsoft/CCF/tree/master/tests/npm-app>`_
folder of the CCF git repository.

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
    │   ├── endpoints
    │   │   ├── all.ts
    │   │   ├── crypto.ts
    │   │   ├── partition.ts
    │   │   └── proto.ts
    │   └── types
    │       └── ccf.ts
    ├── app.json
    ├── package.json
    ├── rollup.config.js
    └── tsconfig.json

Compared to a CCF app bundle, there are a few additional files:

- ``package.json``: Dependencies and build command.
- ``rollup.config.js``: Rollup configuration, see :ref:`ts-app-bundle-conversion` for more details.
- ``tsconfig.json``: TypeScript compiler configuration.
- ``src/types/ccf.ts``: Types for CCF objects, see :ref:`ts-ccf-types` for more details.

.. note::
    Rollup requires exactly one entry-point module.
    The ``src/endpoints/all.ts`` module serves that purpose and re-exports all endpoint handlers
    from the other files in the same folder.
    Keeping endpoint handlers in separate modules and referencing those directly in ``app.json``
    allows for fine-grained control over which other modules are loaded, per endpoint.
    This in turn may improve load time and/or memory consumption, for example if not all endpoints
    share the same npm package dependencies.

.. _ts-ccf-types:

Metadata
--------

:ref:`App metadata <js-app-bundle-metadata>` is stored in an ``app.json`` file in the root of the app project.
This file is copied as-is to the ``dist/`` folder during the :ref:`build step <ts-app-bundle-conversion>`.
Note that paths must be relative to the ``dist/src/`` folder and end with ``.js`` instead of ``.ts``.

Type definitions
----------------

CCF currently does not provide an npm package with TypeScript definitions
for the ``Request`` and ``Response`` objects and the globals.

Instead, the definitions are part of the sample app in
`src/types/ccf.ts <https://github.com/microsoft/CCF/tree/master/tests/npm-app/src/types/ccf.ts>`_.
See `src/endpoints <https://github.com/microsoft/CCF/tree/master/tests/npm-app/src/endpoints>`_
on how the types can be imported and used.

.. _ts-app-bundle-conversion:

Conversion to an app bundle
---------------------------

Preparing the app for deployment relies on a build step that

- transforms TypeScript into JavaScript,
- transforms bare imports (``lodash``) into relative imports (``./node_modules/lodash/lodash.js``),
- transforms old-style CommonJS modules into native JavaScript modules, and
- stores all files according to the CCF app bundle folder structure.

For this, the sample app relies on the `TypeScript compiler <https://www.npmjs.com/package/typescript>`_ and
`rollup <https://rollupjs.org>`_. Rollup also offers tree shaking support
to avoid deploying unused modules. See ``package.json`` and ``rollup.config.js`` for details.

The build step is invoked with

.. code-block:: bash

    $ npm run build

The app bundle can now be found in the ``dist/`` folder and is ready to be deployed.

A note on CommonJS modules
--------------------------

The sample project uses the
`@rollup/plugin-commonjs <https://github.com/rollup/plugins/tree/master/packages/commonjs>`_
package to automatically convert packages with CommonJS modules to native JavaScript modules
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
