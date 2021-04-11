# Confidential Forum sample app

Install dependencies:

```sh
npm install
```

Start the sandbox:

```sh
npm start
```

(Use `VERBOSE=1 npm start` for verbose output)

Open your browser at https://127.0.0.1:8000/app/site and create the sample polls and opinions.
The statistics will still be empty since the opinion threshold has not been reached yet.

Now, generate more opinions, user identities and submit:

```sh
python3.8 demo/generate-opinions.py demo/polls.csv 9
npm run ts demo/generate-jwts.ts . 9
npm run ts demo/submit-opinions.ts .
```

Return to the website and view the statistics which should be visible now.

Run tests:

```sh
npm test
# or:
npm run test:unit #  unit tests
npm run test:e2e # end-to-end tests
```

Unit tests run outside CCF and end-to-end tests run against a single CCF sandbox node.

The unit tests make use of the [`ccf-app` polyfill](https://microsoft.github.io/CCF/main/js/ccf-app/modules/polyfill.html) and can be easily debugged in VS Code.
The simplest workflow is using the [JavaScript Debug Terminal](https://code.visualstudio.com/docs/nodejs/nodejs-debugging#_javascript-debug-terminal) in VS Code. Set a break point and run `npm run test:unit` inside the JavaScript Debug Terminal. The debugger will attach and stop automatically.
