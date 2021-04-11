# Development notes

NOTE: Before contributing to this package, please read this document in full.

## Getting started

```sh
npm install
```

## Code

**Relative imports**:
Every relative import of another TypeScript module **must** end with `.js` (yes, not `.ts`).
The extension is the **target** extension and all TypeScript-related tooling understands this.
Omitting extensions will lead to omitted extensions in the transpiled `.js` files
which may cause import issues depending on the module loader used in the consuming environment.

## Tests

```sh
npm test
```

Tests make use of the `src/polyfill.ts` module and run in Node.js, not in CCF.
This allows to iterate quickly and allows to test most functions.

End-to-end tests running inside CCF are located in `/tests/npm-app` and are run as part of CCF's regular CI.

## Debugging

Tests executed via `npm test` run in Node.js and can be debugged easily.
The simplest workflow is using the [JavaScript Debug Terminal](https://code.visualstudio.com/docs/nodejs/nodejs-debugging#_javascript-debug-terminal) in VS Code. Set a break point and run `npm test` inside the JavaScript Debug Terminal. The debugger will attach and stop automatically.

Debugging problems that only happen in CCF is harder.

If the problem occurs in native functions/properties exposed from C++ (see `src/global.ts`) then VS Code's C++ debugger can be used when running a CCF end-to-end test in virtual mode (not SGX).

Debugging of JavaScript code running in CCF is currently not possible.
A compromise is to run a debug build of CCF with verbose logging enabled.
When running JavaScript code, uncaught exceptions and output from `console.log()` is dumped to the node's log files.

## Docs

```sh
npm run docs
# or in watch mode with web server:
npm run docs:serve
```

typedoc's default theme is extended in `doc/theme` to add a backlink to CCF's main docs and add a version selector.

When this package's docs are built within CCF's multi-version Sphinx-based documentation then additional environment variables are set to enable the version selector.

A dummy CCF version configuration can be simulated as follows to show the version selector without running Sphinx:

```sh
export SMV_CURRENT_VERSION=ccf-0.19.1
export SMV_METADATA_PATH=$(pwd)/doc/theme/helpers/versions.sample.json
npm run docs:serve
```

## Packaging

`tsconfig.json` is configured such that the transpiled JavaScript files are output in the root folder. This allows to consume modules without subfolder like `import .. from '@microsoft/ccf-app/crypto.js`. A side-effect of this is that the root folder becomes messy during development.

A look into the future:

- Node.js gained support for [export maps](https://nodejs.org/dist/latest-v15.x/docs/api/packages.html#packages_exports) which give library authors control over how other packages can import modules, essentially allowing to redirect imports to different folders and/or names, including omitting file extensions.
- TypeScript still [lacks support](https://github.com/microsoft/TypeScript/issues/33079) for export maps. Once TypeScript gains support, this package should make use of it and generate files in `lib/` instead of the root, while also simplifying imports by removing `.js`.
- Another benefit of export maps is that test code can [self-reference the package](https://nodejs.org/dist/latest-v15.x/docs/api/packages.html#packages_self_referencing_a_package_using_its_name). This avoids long relative paths and serves as additional copy-pastable sample code.

## Releases

Releases of this package are automated in CI together with CCF releases.
Even if nothing in this package changes, a new release is published.

The version number in `package.json` is fixed to `0.0.0` and is automatically set during release using `npm version`.
