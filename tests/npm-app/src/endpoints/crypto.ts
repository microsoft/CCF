import * as rs from "jsrsasign";
import { Base64 } from "js-base64";

import * as ccfapp from "ccf-app";

interface CryptoResponse {
  available: boolean;
}

export function crypto(
  request: ccfapp.Request
): ccfapp.Response<CryptoResponse> {
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
  request: ccfapp.Request<GenerateAesKeyRequest>
): ccfapp.Response<ArrayBuffer> {
  return { body: ccfapp.ccf.generateAesKey(request.body.json().size) };
}

interface GenerateRsaKeyPairRequest {
  size: number;
  exponent?: number;
}

export interface CryptoKeyPair {
  privateKey: string;
  publicKey: string;
}

export function generateRsaKeyPair(
  request: ccfapp.Request<GenerateRsaKeyPairRequest>
): ccfapp.Response<CryptoKeyPair> {
  const req = request.body.json();
  const res = req.exponent
    ? ccfapp.ccf.generateRsaKeyPair(req.size, req.exponent)
    : ccfapp.ccf.generateRsaKeyPair(req.size);
  return { body: res };
}

type Base64 = string;

interface WrapAlgoParams {
  name: string;
}

interface RsaOaepParams extends WrapAlgoParams {
  label?: Base64;
}

interface RsaOaepAesKwpParams extends WrapAlgoParams {
  aesKeySize: number; // in bits
  label?: Base64;
}

interface WrapKeyRequest {
  key: Base64; // typically an AES key
  wrappingKey: Base64; // base64 encoding of PEM-encoded RSA public key or AES key bytes
  wrapAlgo: WrapAlgoParams; // Wrapping algorithm parameters
}

export function wrapKey(
  request: ccfapp.Request<WrapKeyRequest>
): ccfapp.Response<ArrayBuffer> {
  const r = request.body.json();
  const key = b64ToBuf(r.key);
  const wrappingKey = b64ToBuf(r.wrappingKey);
  if (r.wrapAlgo.name == "RSA-OAEP") {
    const p = r.wrapAlgo as RsaOaepParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, label: l };
    const wrappedKey = ccfapp.ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else if (r.wrapAlgo.name == "RSA-OAEP-AES-KWP") {
    const p = r.wrapAlgo as RsaOaepAesKwpParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, aesKeySize: p.aesKeySize, label: l };
    const wrappedKey = ccfapp.ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else {
    const wrappedKey = ccfapp.ccf.wrapKey(key, wrappingKey, r.wrapAlgo);
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
