import { KJUR, KEYUTIL, ArrayBuffertohex } from "jsrsasign";
import jwt_decode from "jwt-decode";
import { Base64 } from "js-base64";

import * as ccf from "../types/ccf";

interface JwtResponse {
  userId: string;
}

interface ErrorResponse {
  msg: string;
}

interface HeaderClaims {
  kid: string;
}

interface BodyClaims {
  sub: string;
}

// Rather than using the built-in JWT authenticator provided by the framework,
// this is an unauthenticated endpoint which extracts, parses, and validates
// the JWT itself directly in TS.
export function jwt(
  request: ccf.Request
): ccf.Response<JwtResponse | ErrorResponse> {
  const authHeader = request.headers["authorization"];
  if (!authHeader) {
    return unauthorized("authorization header missing");
  }
  const parts = authHeader.split(" ", 2);
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return unauthorized("unexpected authentication type");
  }
  const token = parts[1];

  // Extract header claims to select the correct signing key.
  // We use jwt_decode() instead of jsrsasign's parse() as the latter does unnecessary work.
  let headerClaims: HeaderClaims;
  try {
    headerClaims = jwt_decode(token, { header: true }) as HeaderClaims;
  } catch (e) {
    return unauthorized(`malformed jwt: ${e.message}`);
  }
  const signingKeyId = headerClaims.kid;
  if (!signingKeyId) {
    return unauthorized("kid missing in header claims");
  }

  // Get the stored signing key to validate the token.
  const keysMap = new ccf.TypedKVMap(
    ccf.kv["public:ccf.gov.jwt.public_signing_keys"],
    ccf.string,
    ccf.typedArray(Uint8Array)
  );
  const publicKeyDer = keysMap.get(signingKeyId);
  if (publicKeyDer === undefined) {
    return unauthorized(`token signing key not found: ${signingKeyId}`);
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
    return unauthorized("jwt validation failed");
  }

  // Custom body claims validation, app-specific.
  const claims = jwt_decode(token) as BodyClaims;
  if (!claims.sub) {
    return unauthorized("jwt invalid, sub claim missing");
  }
  return {
    body: {
      userId: claims.sub,
    },
  };
}

function unauthorized(msg: string): ccf.Response<ErrorResponse> {
  return {
    statusCode: 401,
    body: {
      msg: msg,
    },
  };
}
