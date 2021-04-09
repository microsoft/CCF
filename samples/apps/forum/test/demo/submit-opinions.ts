// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as fs from "fs";
import * as path from "path";
import glob from "glob";
import bent from "bent";
import papa from "papaparse";
import { NODE_ADDR } from "../util";
import { SubmitOpinionsRequest } from "../../src/controllers/poll";

const ENDPOINT_URL = `${NODE_ADDR}/app/polls`;

function getAuth(jwt: string) {
  // See src/util.ts.
  return {
    authorization: `Bearer ${jwt}`,
  };
}

interface CSVRow {
  Topic: string;
  Opinion: string;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    console.error("Usage: npm run ts submit-opinions.ts folder");
    process.exit(1);
  }
  const folder = args[0];
  const csvPaths = glob.sync(folder + "/*_opinions.csv");
  for (const csvPath of csvPaths) {
    const user = path.basename(csvPath).replace("_opinions.csv", "");
    const jwtPath = path.join(folder, user + ".jwt");
    const jwt = fs.readFileSync(jwtPath, "utf8");
    const csv = fs.readFileSync(csvPath, "utf8");
    const rows = papa.parse(csv, { header: true }).data as CSVRow[];

    const req: SubmitOpinionsRequest = { opinions: {} };
    for (const row of rows) {
      req.opinions[row.Topic] = {
        opinion: isNumber(row.Opinion) ? parseFloat(row.Opinion) : row.Opinion,
      };
    }
    console.log("Submitting opinions for user " + user);
    try {
      await bent("PUT", 204)(`${ENDPOINT_URL}`, req, getAuth(jwt));
    } catch (e) {
      console.error("Error: " + (await e.text()));
      process.exit(1);
    }
  }
}

function isNumber(s: string) {
  return !Number.isNaN(Number(s));
}

main();
