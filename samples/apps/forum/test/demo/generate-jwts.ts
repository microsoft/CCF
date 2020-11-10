// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as fs from "fs";
import * as path from "path";
import jwt from "jsonwebtoken";

const hmac_secret = "secret";

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2) {
    console.error("Usage: npm run ts generate-jwts.ts folder count");
    process.exit(1);
  }
  const folder = args[0];
  const count = parseInt(args[1]);
  console.log(`Generating ${count} JWTs in ${folder}`);
  for (let i = 0; i < count; i++) {
    const payload = {
      sub: "user" + i,
    };
    const token = jwt.sign(payload, hmac_secret);
    const jwtPath = path.join(folder, "user" + i + ".jwt");
    console.log(`Writing ${jwtPath}`);
    fs.writeFileSync(jwtPath, token);
  }
}

main();
