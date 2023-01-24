import * as rs from "jsrsasign";
import { Base64 } from "js-base64";

import * as ccfapp from "@microsoft/ccf-app";
import * as ccfcrypto from "@microsoft/ccf-app/crypto";

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
  return { body: ccfcrypto.generateAesKey(request.body.json().size) };
}

interface GenerateRsaKeyPairRequest {
  size: number;
  exponent?: number;
}

export interface GenerateRsaKeyPairResponse {
  privateKey: string;
  publicKey: string;
}

export function generateRsaKeyPair(
  request: ccfapp.Request<GenerateRsaKeyPairRequest>
): ccfapp.Response<GenerateRsaKeyPairResponse> {
  const req = request.body.json();
  const res = req.exponent
    ? ccfcrypto.generateRsaKeyPair(req.size, req.exponent)
    : ccfcrypto.generateRsaKeyPair(req.size);
  return { body: res };
}

interface GenerateEcdsaKeyPairRequest {
  curve: string;
}

export interface GenerateEcdsaKeyPairResponse {
  privateKey: string;
  publicKey: string;
}

export function generateEcdsaKeyPair(
  request: ccfapp.Request<GenerateEcdsaKeyPairRequest>
): ccfapp.Response<GenerateEcdsaKeyPairResponse> {
  const req = request.body.json();
  const res = ccfcrypto.generateEcdsaKeyPair(req.curve);
  return { body: res };
}

interface GenerateEddsaKeyPairRequest {
  curve: string;
}

export interface GenerateEddsaKeyPairResponse {
  privateKey: string;
  publicKey: string;
}

export function generateEddsaKeyPair(
  request: ccfapp.Request<GenerateEddsaKeyPairRequest>
): ccfapp.Response<GenerateEddsaKeyPairResponse> {
  const req = request.body.json();
  const res = ccfcrypto.generateEddsaKeyPair(req.curve);
  return { body: res };
}

type Base64 = string;

interface RsaOaepParams {
  name: "RSA-OAEP";
  label?: Base64;
}

interface RsaOaepAesKwpParams {
  name: "RSA-OAEP-AES-KWP";
  aesKeySize: number; // in bits
  label?: Base64;
}

type WrapAlgoParams =
  | RsaOaepParams
  | RsaOaepAesKwpParams
  | ccfcrypto.AesKwpParams;

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
  let wrappedKey: ArrayBuffer;
  if (r.wrapAlgo.name == "RSA-OAEP") {
    const label = r.wrapAlgo.label ? b64ToBuf(r.wrapAlgo.label) : undefined;
    wrappedKey = ccfcrypto.wrapKey(key, wrappingKey, {
      name: r.wrapAlgo.name,
      label: label,
    });
  } else if (r.wrapAlgo.name == "RSA-OAEP-AES-KWP") {
    const label = r.wrapAlgo.label ? b64ToBuf(r.wrapAlgo.label) : undefined;
    wrappedKey = ccfcrypto.wrapKey(key, wrappingKey, {
      name: r.wrapAlgo.name,
      aesKeySize: r.wrapAlgo.aesKeySize,
      label: label,
    });
  } else {
    wrappedKey = ccfcrypto.wrapKey(key, wrappingKey, r.wrapAlgo);
  }
  return { body: wrappedKey };
}

interface SignRequest {
  algorithm: ccfcrypto.SigningAlgorithm;
  key: string;
  data: Base64;
}

export function sign(
  request: ccfapp.Request<SignRequest>
): ccfapp.Response<ArrayBuffer> {
  const body = request.body.json();
  const result = ccfcrypto.sign(body.algorithm, body.key, b64ToBuf(body.data));
  return {
    body: result,
  };
}

interface VerifySignatureRequest {
  algorithm: ccfcrypto.SigningAlgorithm;
  key: string;
  signature: Base64;
  data: Base64;
}

export function verifySignature(
  request: ccfapp.Request<VerifySignatureRequest>
): ccfapp.Response<boolean> {
  const body = request.body.json();
  const result = ccfcrypto.verifySignature(
    body.algorithm,
    body.key,
    b64ToBuf(body.signature),
    b64ToBuf(body.data)
  );
  return {
    body: result,
  };
}

interface DigestRequest {
  algorithm: ccfcrypto.DigestAlgorithm;
  data: Base64;
}

export function digest(
  request: ccfapp.Request<DigestRequest>
): ccfapp.Response {
  const body = request.body.json();
  const data = b64ToBuf(body.data);
  return {
    body: hex(ccfcrypto.digest(body.algorithm, data)),
  };
}

export function isValidX509CertBundle(
  request: ccfapp.Request
): ccfapp.Response<boolean> {
  const pem = request.body.text();
  return { body: ccfcrypto.isValidX509CertBundle(pem) };
}

interface IsValidX509CertChainRequest {
  chain: string;
  trusted: string;
}

export function isValidX509CertChain(
  request: ccfapp.Request<IsValidX509CertChainRequest>
): ccfapp.Response<boolean> {
  const { chain, trusted } = request.body.json();
  return { body: ccfcrypto.isValidX509CertChain(chain, trusted) };
}

interface pemToJWKRequest {
  pem: string;
  kid: string;
}

export function pubPemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubPemToJwk(req.pem, req.kid);
  return { body: res };
}

export function pemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pemToJwk(req.pem, req.kid);
  return { body: res };
}

export function pubRsaPemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubRsaPemToJwk(req.pem, req.kid);
  return { body: res };
}

export function rsaPemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.rsaPemToJwk(req.pem, req.kid);
  return { body: res };
}

export function pubEddsaPemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubEddsaPemToJwk(req.pem, req.kid);
  return { body: res };
}

export function eddsaPemToJwk(
  request: ccfapp.Request<pemToJWKRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.eddsaPemToJwk(req.pem, req.kid);
  return { body: res };
}

interface JwkToPemRequest {
  jwk: any;
}

export function pubJwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubJwkToPem(req.jwk);
  return { body: { pem: res } };
}

export function jwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.jwkToPem(req.jwk);
  return { body: { pem: res } };
}

export function pubRsaJwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubRsaJwkToPem(req.jwk);
  return { body: { pem: res } };
}

export function rsaJwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.rsaJwkToPem(req.jwk);
  return { body: { pem: res } };
}

export function pubEddsaJwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.pubEddsaJwkToPem(req.jwk);
  return { body: { pem: res } };
}

export function eddsaJwkToPem(
  request: ccfapp.Request<JwkToPemRequest>
): ccfapp.Response {
  const req = request.body.json();
  const res = ccfcrypto.eddsaJwkToPem(req.jwk);
  return { body: { pem: res } };
}

function b64ToBuf(b64: string): ArrayBuffer {
  return Base64.toUint8Array(b64).buffer;
}

function hex(buf: ArrayBuffer) {
  return Array.from(new Uint8Array(buf))
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
