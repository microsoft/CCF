// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import jwt_decode from "jwt-decode";
import * as ccf from "./types/ccf";
import { UnauthorizedError } from "./error_handler";

export interface User {
  claims: { [name: string]: any };
  userId: string;
}

export function authentication(
  request: ccf.Request,
  securityName: string,
  scopes?: string[]
): void {
  if (securityName === "jwt") {
    const authHeader = request.headers["authorization"];
    if (!authHeader) {
      throw new UnauthorizedError("authorization header missing");
    }
    const parts = authHeader.split(" ", 2);
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      throw new UnauthorizedError("unexpected authentication type");
    }
    const token = parts[1];
    let claims: any;
    try {
      claims = jwt_decode(token);
    } catch (e) {
      throw new UnauthorizedError(`malformed jwt: ${e.message}`);
    }
    request.user = {
      claims: claims,
      userId: claims.sub,
    } as User;
  } else {
    throw new Error(`BUG: unknown securityName: ${securityName}`);
  }
}
