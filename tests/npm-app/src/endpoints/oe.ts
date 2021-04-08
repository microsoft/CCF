import { Base64 } from "js-base64";

import * as ccfapp from "@microsoft/ccf-app";
import * as ccfoe from "@microsoft/ccf-app/openenclave";

interface Evidence {
  format?: string;
  evidence: string;
  endorsements?: string;
}

interface Claims {
  claims: { [key: string]: string };
  customClaims: { [key: string]: string };
}

interface ErrorResponse {
  error: {
    message: string;
  };
}

export function verifyOpenEnclaveEvidence(
  request: ccfapp.Request<Evidence>
): ccfapp.Response<Claims | ErrorResponse> {
  const body = request.body.json();
  const evidence = ccfapp
    .typedArray(Uint8Array)
    .encode(Base64.toUint8Array(body.evidence));
  const endorsements = body.endorsements
    ? ccfapp
        .typedArray(Uint8Array)
        .encode(Base64.toUint8Array(body.endorsements))
    : undefined;
  let r: ccfoe.EvidenceClaims;
  try {
    r = ccfoe.verifyOpenEnclaveEvidence(body.format, evidence, endorsements);
  } catch (e) {
    return {
      statusCode: 400,
      body: {
        error: {
          message: e.message,
        },
      },
    };
  }
  const claimsHex = {};
  for (const [name, value] of Object.entries(r.claims)) {
    claimsHex[name] = hex(value);
  }
  const customClaimsHex = {};
  for (const [name, value] of Object.entries(r.customClaims)) {
    customClaimsHex[name] = hex(value);
  }
  return {
    body: {
      claims: claimsHex,
      customClaims: customClaimsHex,
    },
  };
}

function hex(buf: ArrayBuffer) {
  return Array.from(new Uint8Array(buf))
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
