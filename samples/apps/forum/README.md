# Confidential Forum sample app

See also the [TypeScript Application using tsoa](https://microsoft.github.io/CCF/main/build_apps/js_app_tsoa.html) documentation page for further details on how this sample is built using the tsoa framework.

## Getting started

When running this sample against a CCF release, open `package.json` and replace the `file:` reference of `ccf-app` with a reference to a published version (adjust the version number accordingly):

```
"@microsoft/ccf-app": "~1.0.0",
```

Now you can continue with installing all dependencies:

```sh
npm install
```

To run the demo and end-to-end tests, define the following environment variable:

```sh
export CCF_BINARY_DIR=/opt/ccf-x.y.z/bin
```

If not defined, it assumes you built CCF from source and defaults to `CCF_BINARY_DIR=<repo_root>/build`.

## Demo

Start the sandbox:

```sh
npm start
```

(Use `VERBOSE=1 npm start` for verbose output)

Open your browser at https://127.0.0.1:8000/app/site and create the sample polls and opinions.
The statistics will still be empty since the opinion threshold has not been reached yet.

Now, generate more opinions, user identities and submit:

```sh
mkdir demo/data
python3.8 demo/generate-opinions.py demo/data demo/polls.csv 9
npm run ts demo/generate-jwts.ts demo/data 9
npm run ts demo/submit-opinions.ts demo/data
```

Return to the website and view the statistics which should be visible now.

## Tests & debugging

Run tests:

```sh
npm test
# or:
npm run test:unit # unit tests
npm run test:e2e # end-to-end tests
```

Unit tests run outside CCF and end-to-end tests run against a single CCF sandbox node.

The unit tests make use of the [`ccf-app` polyfill](https://microsoft.github.io/CCF/main/js/ccf-app/modules/polyfill.html) and can be easily debugged in VS Code.
The simplest workflow is using the [JavaScript Debug Terminal](https://code.visualstudio.com/docs/nodejs/nodejs-debugging#_javascript-debug-terminal) in VS Code. Set a break point and run `npm run test:unit` inside the JavaScript Debug Terminal. The debugger will attach and stop automatically.

Debugging of JavaScript code running in CCF is currently not possible.
However, all uncaught exceptions and output from `console.log()` are dumped to the node's log files.
