# Confidential Forum sample app

NOTE: This sample is a work-in-progress.

Install dependencies:

```sh
npm install
```

Start the sandbox:

```sh
npm start
```

(Use `VERBOSE=1 npm start` for verbose output)

Open your browser at https://127.0.0.1:8000/app/site

Generate opinions, user identities and submit:

```sh
python3.8 demo/generate-opinions.py demo/polls.csv 9
npm run ts demo/generate-jwts.ts . 9
npm run ts demo/submit-opinions.ts .
```

Run tests:

```sh
npm test
```
