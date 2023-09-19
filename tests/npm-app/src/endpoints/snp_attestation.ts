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

export interface TcbVersion {
    boot_loader: number;
    tee: number;
    snp: number;
    microcode: number;
}

interface SnpAttestationResult {
  version: number;
  guest_svn: number;
  policy: {
      abi_minor: number,
      abi_major: number,
      smt: number,
      migrate_ma: number,
      debug: number,
      single_socket: number,
  };
  family_id: string;
  image_id: string;
  vmpl: number;
  signature_algo: number;
  platform_version: TcbVersion;
  platform_info: {
      smt_en: number;
      tsme_en: number;
  };
  flags: {
      author_key_en: number;
      mask_chip_key: number;
      signing_key: number;
  };
  report_data: string;
  measurement: string;
  host_data: string;
  id_key_digest: string;
  author_key_digest: string;
  report_id: string;
  report_id_ma: string;
  reported_tcb: TcbVersion;
  chip_id: string;
  committed_tcb: TcbVersion;
  current_minor: number;
  current_build: number;
  current_major: number;
  committed_build: number;
  committed_minor: number;
  committed_major: number;
  launch_tcb: TcbVersion;
  signature: {
      r: string;
      s: string;
  };
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
        ...r,
        family_id: hex(r.family_id),
        image_id: hex(r.image_id),
        report_data: hex(r.report_data),
        measurement: hex(r.measurement),
        host_data: hex(r.host_data),
        id_key_digest: hex(r.id_key_digest),
        author_key_digest: hex(r.author_key_digest),
        report_id: hex(r.report_id),
        report_id_ma: hex(r.report_id_ma),
        chip_id: hex(r.chip_id),
        signature: {
          r: hex(r.signature.r),
          s: hex(r.signature.s),
        }
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

function hex(buf: ArrayBuffer) {
  return Array.from(new Uint8Array(buf))
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
