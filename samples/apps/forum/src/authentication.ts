// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as ccfapp from "@microsoft/ccf-app";
import { UnauthorizedError } from "./error_handler";

export interface User extends ccfapp.JwtAuthnIdentity {
  userId: string;
}

interface BodyClaims {
  sub: string;
  iss: string;
}

interface MSAccessTokenClaims extends BodyClaims {
  aud: string;
  appid: string; // 1.0 only
  ver: string; // 1.0 or 2.0
}

// Replace the below string with your own app id by registering an app in Azure:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
export const MS_APP_ID = "1773214f-72b8-48f9-ae18-81e30fab04db";
export const MS_APP_ID_URI = "api://1773214f-72b8-48f9-ae18-81e30fab04db";

export function authentication(
  request: ccfapp.Request,
  securityName: string,
  scopes?: string[]
): void {
  if (securityName === "jwt") {
    const caller = request.caller as User;
    if (!caller || caller.policy != "jwt") {
      throw new Error("unexpected policy");
    }

    if (caller.jwt.key_issuer === "https://demo") {
      // no further validation
    } else if (
      caller.jwt.key_issuer === "https://login.microsoftonline.com/common/v2.0"
    ) {
      // Microsoft identity platform access tokens
      const msClaims = caller.jwt.payload as MSAccessTokenClaims;
      if (msClaims.ver !== "1.0") {
        throw new UnauthorizedError(
          "unsupported access token version, must be 1.0"
        );
      }
      if (msClaims.appid !== MS_APP_ID) {
        throw new UnauthorizedError("jwt validation failed: appid mismatch");
      }
      if (msClaims.aud !== MS_APP_ID_URI) {
        throw new UnauthorizedError(
          "jwt validation failed: aud mismatch (incorrect scope requested?)"
        );
      }
    } else {
      throw new Error(`BUG: unknown key issuer: ${caller.jwt.key_issuer}`);
    }

    caller.userId = caller.jwt.payload.sub;
  } else {
    throw new Error(`BUG: unknown securityName: ${securityName}`);
  }
}
