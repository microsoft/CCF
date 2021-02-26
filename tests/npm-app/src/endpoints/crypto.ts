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

interface WrapAlgoParams {
  name: string;
}

interface RsaOaepParams extends WrapAlgoParams {
  label?: Base64;
}

interface RsaOaepAesParams extends WrapAlgoParams {
  aes_key_size: number; // in bits
  label?: Base64;
}

interface WrapKeyRequest {
  key: Base64; // typically an AES key
  wrappingKey: Base64; // base64 encoding of PEM-encoded RSA public key or AES key bytes
  parameters: WrapAlgoParams; // Wrapping algorithm parameters
}

export function wrapKey(
  request: ccf.Request<WrapKeyRequest>
): ccf.Response<ArrayBuffer> {
  const r = request.body.json();
  const key = b64ToBuf(r.key);
  const wrappingKey = b64ToBuf(r.wrappingKey);
  if (r.parameters.name == "RSA-OAEP") {
    const p = r.parameters as RsaOaepParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, label: l };
    const wrappedKey = ccf.ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else if (r.parameters.name == "RSA-OAEP-AES-KWP") {
    const p = r.parameters as RsaOaepAesParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, aes_key_size: p.aes_key_size, label: l };
    const wrappedKey = ccf.ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else {
    const wrappedKey = ccf.ccf.wrapKey(key, wrappingKey, r.parameters);
    return { body: wrappedKey };
  }
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
