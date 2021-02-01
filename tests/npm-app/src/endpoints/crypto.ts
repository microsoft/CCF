import * as rs from "jsrsasign";
import { Base64 } from "js-base64";

import * as ccf from "../types/ccf";

interface CryptoResponse {
  available: boolean;
}

export function crypto(request: ccf.Request): ccf.Response<CryptoResponse> {
  // Most functionality of jsrsasign requires keys.
  // Generating a key here is too slow, so we'll just check if the
  // JS API got exported correctly.
  let available = rs.KEYUTIL.generateKeypair ? true : false;
  return { body: { available: available } };
}

interface GenerateAesKeyRequest {
  size: number;
}

export function generateAesKey(
  request: ccf.Request<GenerateAesKeyRequest>
): ccf.Response<ArrayBuffer> {
  return { body: ccf.ccf.generateAesKey(request.body.json().size) };
}

type Base64 = string;

interface WrapKeyRsaOaepRequest {
  key: Base64; // typically an AES key
  wrappingKey: string; // PEM-encoded RSA public key
  label?: string;
}

export function wrapKeyRsaOaep(
  request: ccf.Request<WrapKeyRsaOaepRequest>
): ccf.Response<ArrayBuffer> {
  const r = request.body.json();
  const key = b64ToBuf(r.key);
  const wrappingKey = publicPemToDer(r.wrappingKey);
  const label = r.label ? ccf.ccf.strToBuf(r.label) : undefined;
  const wrappedKey = ccf.ccf.wrapKey(key, wrappingKey, {
    name: "RSA-OAEP",
    label: label,
  });
  return { body: wrappedKey };
}

function b64ToBuf(b64: string): ArrayBuffer {
  return Base64.toUint8Array(b64).buffer;
}

function publicPemToDer(pem: string): ArrayBuffer {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.indexOf(pemFooter));
  return b64ToBuf(pemContents);
}
