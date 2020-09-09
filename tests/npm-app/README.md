# Node.js/npm CCF app

This folder contains a sample CCF app written in JavaScript and uses Node.js/npm as tooling
and package manager.

CCF's JavaScript environment is similar to that in browsers, with the following differences:
- only [JavaScript modules](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules) are supported,
- no [Web APIs](https://developer.mozilla.org/en-US/docs/Web/API) are available,
- module imports cannot be URLs and must be relative paths.

Typical web applications running in browsers have a top-level/entry-point module that does not
export functions but rather modifies the global browser state.
In CCF, the entry-point module defines the application endpoints and instead exports
one or more functions that are called by CCF from C++.

Preparing an app for deployment requires a build step that
- transforms bare imports (`lodash`) into relative imports (`./node_modules/lodash/lodash.js`),
- transforms old-style CommonJS modules into native JavaScript modules.

For this, the sample app relies on [rollup](https://rollupjs.org), which also offers tree shaking support
to avoid deploying unused modules. See `package.json` and `rollup.config.js` for details.

See the `modules.py` test for how this app is built and deployed to CCF.

## A note on CommonJS modules

The sample project uses the [@rollup/plugin-commonjs](https://github.com/rollup/plugins/tree/master/packages/commonjs) package to automatically convert packages with CommonJS modules to native JavaScript modules
so that they can be used in CCF.

For some packages this conversion may fail, for example when the package has circular module dependencies.
If that is the case, try one of the following suggestions:

1. Check if there is a JavaScript module variant of the package and use that instead.
   These are also named ES or ECMAScript modules/packages.

2. Check if there is a known work-around to fix the conversion issue.
   Chances are you are not the only one experiencing it.

3. Check if the npm package contains a browser bundle and try to import that instead.
   For example, this works for protobuf.js: `import protobuf from 'protobufjs/dist/protobuf.js'`.

4. Manually wrap a browser bundle of the package without using npm.
   This may be needed if the browser bundle is not part of the npm package, although this is uncommon.

Manually wrapping a browser bundle (step 4) means copying the bundle source code in a module
file and surrounding it with module boiler-plate. This may look something like:

```js
let exports = {}, module = {exports};

// REPLACE this comment with the content of the bundle.

export default module.exports;
```

If the bundle uses only global exports instead of CommonJS/Node.js exports,
then the module should look something like:

```js
// REPLACE this comment with the content of the bundle.

// Adjust this to match the globals of the package.
export {ExportA, ExportB};
```
