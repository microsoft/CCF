import * as rs from "jsrsasign";
import { Base64 } from "js-base64";

import { ccf, CCF } from '../ccf/builtin'

interface CryptoResponse {
  available: boolean;
}

export function crypto(request: CCF.Request): CCF.Response<CryptoResponse> {
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
  request: CCF.Request<GenerateAesKeyRequest>
): CCF.Response<ArrayBuffer> {
  return { body: ccf.generateAesKey(request.body.json().size) };
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
  request: CCF.Request<GenerateRsaKeyPairRequest>
): CCF.Response<CryptoKeyPair> {
  const req = request.body.json();
  const res = req.exponent
    ? ccf.generateRsaKeyPair(req.size, req.exponent)
    : ccf.generateRsaKeyPair(req.size);
  return { body: res };
}

type Base64 = string;

interface WrapAlgoParams {
  name: string;
}

interface RsaOaepParams extends WrapAlgoParams {
  label?: Base64;
}

interface RsaOaepAesParams extends WrapAlgoParams {
  aesKeySize: number; // in bits
  label?: Base64;
}

interface WrapKeyRequest {
  key: Base64; // typically an AES key
  wrappingKey: Base64; // base64 encoding of PEM-encoded RSA public key or AES key bytes
  wrapAlgo: WrapAlgoParams; // Wrapping algorithm parameters
}

export function wrapKey(
  request: CCF.Request<WrapKeyRequest>
): CCF.Response<ArrayBuffer> {
  const r = request.body.json();
  const key = b64ToBuf(r.key);
  const wrappingKey = b64ToBuf(r.wrappingKey);
  if (r.wrapAlgo.name == "RSA-OAEP") {
    const p = r.wrapAlgo as RsaOaepParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, label: l };
    const wrappedKey = ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else if (r.wrapAlgo.name == "RSA-OAEP-AES-KWP") {
    const p = r.wrapAlgo as RsaOaepAesParams;
    const l = p.label ? b64ToBuf(p.label) : undefined;
    const new_p = { name: p.name, aesKeySize: p.aesKeySize, label: l };
    const wrappedKey = ccf.wrapKey(key, wrappingKey, new_p);
    return { body: wrappedKey };
  } else {
    const wrappedKey = ccf.wrapKey(key, wrappingKey, r.wrapAlgo);
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
