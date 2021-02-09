// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { KJUR, KEYUTIL } from "jsrsasign";
import jwt_decode from "jwt-decode";
import { Base64 } from "js-base64";
import * as ccf from "./types/ccf";
import { UnauthorizedError } from "./error_handler";

export interface User {
  claims: { [name: string]: any };
  userId: string;
}

interface HeaderClaims {
  kid: string;
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
  request: ccf.Request,
  securityName: string,
  scopes?: string[]
): void {
  if (securityName === "jwt") {
    // Extract the token from the header.
    const authHeader = request.headers["authorization"];
    if (!authHeader) {
      throw new UnauthorizedError("authorization header missing");
    }
    const parts = authHeader.split(" ", 2);
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      throw new UnauthorizedError(
        `unexpected authentication type ${parts[0]}, expected Bearer`
      );
    }
    const token = parts[1];

    // Extract header claims to select the correct signing key.
    // We use jwt_decode() instead of jsrsasign's parse() as the latter does unnecessary work.
    let headerClaims: HeaderClaims;
    try {
      headerClaims = jwt_decode(token, { header: true }) as HeaderClaims;
    } catch (e) {
      throw new UnauthorizedError(`malformed jwt: ${e.message}`);
    }
    const signingKeyId = headerClaims.kid;
    if (!signingKeyId) {
      throw new UnauthorizedError("kid missing in header claims");
    }

    // Get the stored signing key to validate the token.
    const keysMap = new ccf.TypedKVMap(
      ccf.kv["public:ccf.gov.jwt.public_signing_keys"],
      ccf.string,
      ccf.typedArray(Uint8Array)
    );
    const publicKeyDer = keysMap.get(signingKeyId);
    if (publicKeyDer === undefined) {
      throw new UnauthorizedError("token signing key not found");
    }
    // jsrsasign can only load X.509 certs from PEM strings
    const publicKeyB64 = Base64.fromUint8Array(publicKeyDer);
    const publicKeyPem =
      "-----BEGIN CERTIFICATE-----\n" +
      publicKeyB64 +
      "\n-----END CERTIFICATE-----";
    const publicKey = KEYUTIL.getKey(publicKeyPem);

    // Validate the token signature.
    const valid = KJUR.jws.JWS.verifyJWT(
      token,
      <any>publicKey,
      <any>{
        alg: ["RS256"],
        // No trusted time, disable time validation.
        verifyAt: Date.parse("2020-01-01T00:00:00") / 1000,
        gracePeriod: 10 * 365 * 24 * 60 * 60,
      }
    );
    if (!valid) {
      throw new UnauthorizedError("jwt validation failed");
    }

    // Get the issuer associated to the signing key.
    const keyIssuerMap = new ccf.TypedKVMap(
      ccf.kv["public:ccf.gov.jwt.public_signing_key_issuer"],
      ccf.string,
      ccf.string
    );
    const keyIssuer = keyIssuerMap.get(signingKeyId);

    // Validate token body claims.
    let claims: BodyClaims;
    try {
      claims = jwt_decode(token) as BodyClaims;
    } catch (e) {
      // Shouldn't happen given earlier validation by jsrsasign.
      throw new UnauthorizedError(`malformed jwt: ${e.message}`);
    }

    if (keyIssuer === "https://demo") {
      // no further validation
    } else if (keyIssuer === "https://login.microsoftonline.com/common/v2.0") {
      // Microsoft identity platform access tokens
      const msClaims = claims as MSAccessTokenClaims;
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
      throw new Error(`BUG: unknown key issuer: ${keyIssuer}`);
    }

    request.user = {
      claims: claims,
      userId: claims.sub,
    } as User;
  } else {
    throw new Error(`BUG: unknown securityName: ${securityName}`);
  }
}
