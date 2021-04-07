import { Base64 } from "js-base64";

import * as ccfapp from "@microsoft/ccf-app";
import * as ccfoe from "@microsoft/ccf-app/openenclave";

interface Evidence {
  evidence: string
  endorsements?: string
}

interface Claims {
  claims: { [key: string]: string }
}

export function verifyOpenEnclaveEvidence(request: ccfapp.Request<Evidence>): ccfapp.Response<Claims> {
  const body = request.body.json();
  const evidence = typedArrToArrBuf(Base64.toUint8Array(body.evidence));
  const endorsements = body.endorsements ? typedArrToArrBuf(Base64.toUint8Array(body.endorsements)) : undefined;
  const claims = ccfoe.verifyOpenEnclaveEvidence(evidence, endorsements);
  const claimsHex = {};
  for (const [name, value] of Object.entries(claims)) {
    claimsHex[name] = hex(value);
  }
  return {
    body: {
      claims: claimsHex
    }
  };
}

function typedArrToArrBuf(ta: ArrayBufferView) {
  return ta.buffer.slice(ta.byteOffset, ta.byteOffset + ta.byteLength);
}

function hex(buf: ArrayBuffer) {
  return Array.from(new Uint8Array(buf))
    .map(n => n.toString(16).padStart(2, "0"))
    .join("");
}
