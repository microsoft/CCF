import { Base64 } from "js-base64";

import * as ccfapp from "@microsoft/ccf-app";
import * as ccfsnp from "@microsoft/ccf-app/snp_attestation";

interface ErrorResponse {
  error: {
    message: string;
  };
}

interface SnpEvidence {
  evidence: string;
  endorsements: string;
  endorsed_tcb?: string;
}

interface SnpAttestationResult {
  measurement: string;
  report_data: string;
}

export function verifySnpAttestation(
  request: ccfapp.Request<SnpEvidence>,
): ccfapp.Response<SnpAttestationResult | ErrorResponse> {
  const body = request.body.json();
  const evidence = ccfapp
    .typedArray(Uint8Array)
    .encode(Base64.toUint8Array(body.evidence));
  const endorsements = ccfapp
    .typedArray(Uint8Array)
    .encode(Base64.toUint8Array(body.endorsements));
  try {
    const r =
      body.endorsed_tcb !== undefined
        ? ccfsnp.verifySnpAttestation(evidence, endorsements, body.endorsed_tcb)
        : ccfsnp.verifySnpAttestation(evidence, endorsements);
    return {
      body: {
        measurement: r.measurement,
        report_data: r.report_data,
      },
    };
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
}
