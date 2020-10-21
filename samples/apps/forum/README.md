# Confidential Forum sample app

Install dependencies:
```sh
npm install
```

Start the sandbox:
```sh
npm start
```

Open your browser at https://127.0.0.1:8000/app/site

Create polls by copy-pasting test/demo/polls.csv.

Generate opinions and submit:
```sh
python test/demo/generate-opinions.py test/demo/polls.csv 9
npm run ts test/demo/submit-opinions.ts .
```

Run tests:
```sh
npm test
```
