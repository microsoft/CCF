// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module polyfills CCF's native functions for use in
 * unit tests that run in Node.js instead of CCF.
 * It must be imported before all other imports like so:
 *
 * ```
 * import '@microsoft/ccf-app/polyfill.js';
 * ```
 *
 * Note that some functionality is not polyfilled,
 * for example historic state (for historical endpoints).
 *
 * @module
 */

import * as jscrypto from "crypto";
import { TextEncoder, TextDecoder } from "util";
import * as rs from "jsrsasign";

// Note: It is important that only types are imported here to prevent executing
// the module at this point (which would query the ccf global before we polyfilled it).
import {
  CCF,
  KvMaps,
  KvMap,
  JsonCompatible,
  CryptoKeyPair,
  WrapAlgoParams,
  DigestAlgorithm,
  EvidenceClaims,
  OpenEnclave,
  SigningAlgorithm,
  JsonWebKeyECPublic,
  JsonWebKeyECPrivate,
  JsonWebKeyRSAPublic,
  JsonWebKeyRSAPrivate,
} from "./global.js";

// JavaScript's Map uses reference equality for non-primitive types,
// whereas CCF compares the content of the ArrayBuffer.
// To achieve CCF's semantics, all keys are base64-encoded.
class KvMapPolyfill implements KvMap {
  map = new Map<string, ArrayBuffer>();

  has(key: ArrayBuffer): boolean {
    return this.map.has(base64(key));
  }
  get(key: ArrayBuffer): ArrayBuffer | undefined {
    return this.map.get(base64(key));
  }
  getVersionOfPreviousWrite(key: ArrayBuffer): number | undefined {
    throw new Error("Not implemented");
  }
  set(key: ArrayBuffer, value: ArrayBuffer): KvMap {
    this.map.set(base64(key), value);
    return this;
  }
  delete(key: ArrayBuffer): void {
    this.map.delete(base64(key));
  }
  clear(): void {
    this.map.clear();
  }
  forEach(
    callback: (value: ArrayBuffer, key: ArrayBuffer, kvmap: KvMap) => void
  ): void {
    this.map.forEach((value, key, _) => {
      callback(value, unbase64(key), this);
    });
  }
  get size(): number {
    return this.map.size;
  }
}

class CCFPolyfill implements CCF {
  kv = new Proxy(<KvMaps>{}, {
    get: (target, name, receiver) => {
      if (typeof name === "string") {
        return name in target
          ? target[name]
          : (target[name] = new KvMapPolyfill());
      }
      return Reflect.get(target, name, receiver);
    },
  });

  consensus = {
    getLastCommittedTxId() {
      throw new Error("Not implemented");
    },
    getStatusForTxId(view: number, seqno: number) {
      throw new Error("Not implemented");
    },
    getViewForSeqno(seqno: number) {
      throw new Error("Not implemented");
    },
  };

  historical = {
    getStateRange(
      handle: number,
      startSeqno: number,
      endSeqno: number,
      secondsUntilExpiry: number
    ) {
      throw new Error("Not implemented");
    },

    dropCachedStates(handle: number) {
      throw new Error("Not implemented");
    },
  };

  rpc = {
    setApplyWrites(force: boolean) {
      throw new Error("Not implemented");
    },
    setClaimsDigest(digest: ArrayBuffer) {
      throw new Error("Not implemented");
    },
  };

  crypto = {
    verifySignature(
      algorithm: SigningAlgorithm,
      key: string,
      signature: ArrayBuffer,
      data: ArrayBuffer
    ): boolean {
      let padding = undefined;
      const pubKey = jscrypto.createPublicKey(key);
      if (pubKey.asymmetricKeyType == "rsa") {
        if (algorithm.name === "RSASSA-PKCS1-v1_5") {
          padding = jscrypto.constants.RSA_PKCS1_PADDING;
        } else {
          throw new Error("incompatible signing algorithm for given key type");
        }
      } else if (pubKey.asymmetricKeyType == "ec") {
        if (algorithm.name !== "ECDSA") {
          throw new Error("incompatible signing algorithm for given key type");
        }
      } else {
        throw new Error("unrecognized signing algorithm");
      }
      const hashAlg = algorithm.hash.replace("-", "").toLowerCase();
      const verifier = jscrypto.createVerify(hashAlg);
      verifier.update(new Uint8Array(data));
      return verifier.verify(
        {
          key: pubKey,
          dsaEncoding: "ieee-p1363",
          padding: padding,
        },
        new Uint8Array(signature)
      );
    },
    generateAesKey(size: number): ArrayBuffer {
      return nodeBufToArrBuf(jscrypto.randomBytes(size / 8));
    },
    generateRsaKeyPair(size: number, exponent?: number): CryptoKeyPair {
      const rsaKeyPair = jscrypto.generateKeyPairSync("rsa", {
        modulusLength: size,
        publicExponent: exponent,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      return rsaKeyPair;
    },
    generateEcdsaKeyPair(curve: string): CryptoKeyPair {
      var curve_name = curve;
      if (curve == "secp256r1") curve_name = "prime256v1";
      const ecdsaKeyPair = jscrypto.generateKeyPairSync("ec", {
        namedCurve: curve_name,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      return ecdsaKeyPair;
    },
    generateEddsaKeyPair(curve: string): CryptoKeyPair {
      // `type` is always "ed25519" because currently only "curve25519" is supported for `curve`.
      const type = "ed25519";
      const ecdsaKeyPair = jscrypto.generateKeyPairSync(type, {
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      return ecdsaKeyPair;
    },
    wrapKey(
      key: ArrayBuffer,
      wrappingKey: ArrayBuffer,
      parameters: WrapAlgoParams
    ): ArrayBuffer {
      if (parameters.name === "RSA-OAEP") {
        return nodeBufToArrBuf(
          jscrypto.publicEncrypt(
            {
              key: Buffer.from(wrappingKey),
              oaepHash: "sha256",
              oaepLabel: parameters.label
                ? new Uint8Array(parameters.label)
                : undefined,
              padding: jscrypto.constants.RSA_PKCS1_OAEP_PADDING,
            },
            new Uint8Array(key)
          )
        );
      } else if (parameters.name === "AES-KWP") {
        const iv = Buffer.from("A65959A6", "hex"); // defined in RFC 5649
        const cipher = jscrypto.createCipheriv(
          "id-aes256-wrap-pad",
          new Uint8Array(wrappingKey),
          iv
        );
        return nodeBufToArrBuf(
          Buffer.concat([cipher.update(new Uint8Array(key)), cipher.final()])
        );
      } else if (parameters.name === "RSA-OAEP-AES-KWP") {
        const randomAesKey = this.generateAesKey(parameters.aesKeySize);
        const wrap1 = this.wrapKey(randomAesKey, wrappingKey, {
          name: "RSA-OAEP",
          label: parameters.label,
        });
        const wrap2 = this.wrapKey(key, randomAesKey, {
          name: "AES-KWP",
        });
        return nodeBufToArrBuf(
          Buffer.concat([Buffer.from(wrap1), Buffer.from(wrap2)])
        );
      } else {
        throw new Error("unsupported wrapAlgo.name");
      }
    },
    digest(algorithm: DigestAlgorithm, data: ArrayBuffer): ArrayBuffer {
      if (algorithm === "SHA-256") {
        return nodeBufToArrBuf(
          jscrypto.createHash("sha256").update(new Uint8Array(data)).digest()
        );
      } else {
        throw new Error("unsupported algorithm");
      }
    },
    isValidX509CertBundle(pem: string): boolean {
      if ("X509Certificate" in jscrypto) {
        const sep = "-----END CERTIFICATE-----";
        const items = pem.split(sep);
        if (items.length === 1) {
          return false;
        }
        const pems = items.slice(0, -1).map((p) => p + sep);
        for (const [i, p] of pems.entries()) {
          try {
            new (<any>jscrypto).X509Certificate(p);
          } catch (e: any) {
            console.error(`cert ${i} is not valid: ${e.message}`);
            console.error(p);
            return false;
          }
        }
        return true;
      } else {
        throw new Error(
          "X509 validation unsupported, Node.js version too old (< 15.6.0)"
        );
      }
    },
    isValidX509CertChain(chain: string, trusted: string): boolean {
      if (!("X509Certificate" in jscrypto)) {
        throw new Error(
          "X509 validation unsupported, Node.js version too old (< 15.6.0)"
        );
      }
      try {
        const toX509Array = (pem: string) => {
          const sep = "-----END CERTIFICATE-----";
          const items = pem.split(sep);
          if (items.length === 1) {
            return [];
          }
          const pems = items.slice(0, -1).map((p) => p + sep);
          const arr = pems.map(
            (pem) => new (<any>jscrypto).X509Certificate(pem)
          );
          return arr;
        };
        const certsChain = toX509Array(chain);
        const certsTrusted = toX509Array(trusted);
        if (certsChain.length === 0) {
          throw new Error("chain cannot be empty");
        }
        for (let i = 0; i < certsChain.length - 1; i++) {
          if (!certsChain[i].checkIssued(certsChain[i + 1])) {
            throw new Error(`chain[${i}] is not issued by chain[${i + 1}]`);
          }
        }
        for (const certChain of certsChain) {
          for (const certTrusted of certsTrusted) {
            if (certChain.fingerprint === certTrusted.fingerprint) {
              return true;
            }
            if (certChain.verify(certTrusted.publicKey)) {
              return true;
            }
          }
        }
        throw new Error(
          "none of the chain certificates are identical to or issued by a trusted certificate"
        );
      } catch (e: any) {
        console.error(`certificate chain validation failed: ${e.message}`);
        return false;
      }
    },
    pubPemToJwk(pem: string, kid?: string): JsonWebKeyECPublic {
      let jwk = rs.KEYUTIL.getJWK(
        rs.KEYUTIL.getKey(pem) as rs.KJUR.crypto.ECDSA
      ) as JsonWebKeyECPublic;
      if (kid !== undefined) {
        jwk.kid = kid;
      }
      return jwk;
    },
    pemToJwk(pem: string, kid?: string): JsonWebKeyECPrivate {
      let jwk = rs.KEYUTIL.getJWK(
        rs.KEYUTIL.getKey(pem) as rs.KJUR.crypto.ECDSA
      ) as JsonWebKeyECPrivate;
      if (kid !== undefined) {
        jwk.kid = kid;
      }
      return jwk;
    },
    pubRsaPemToJwk(pem: string, kid?: string): JsonWebKeyRSAPublic {
      let jwk = rs.KEYUTIL.getJWK(
        rs.KEYUTIL.getKey(pem) as rs.RSAKey
      ) as JsonWebKeyRSAPublic;
      if (kid !== undefined) {
        jwk.kid = kid;
      }
      return jwk;
    },
    rsaPemToJwk(pem: string, kid?: string): JsonWebKeyRSAPrivate {
      let jwk = rs.KEYUTIL.getJWK(
        rs.KEYUTIL.getKey(pem) as rs.RSAKey
      ) as JsonWebKeyRSAPrivate;
      if (kid !== undefined) {
        jwk.kid = kid;
      }
      return jwk;
    },
  };

  strToBuf(s: string): ArrayBuffer {
    return typedArrToArrBuf(new TextEncoder().encode(s));
  }

  bufToStr(v: ArrayBuffer): string {
    return new TextDecoder().decode(v);
  }

  jsonCompatibleToBuf<T extends JsonCompatible<T>>(v: T): ArrayBuffer {
    return this.strToBuf(JSON.stringify(v));
  }

  bufToJsonCompatible<T extends JsonCompatible<T>>(v: ArrayBuffer): T {
    return JSON.parse(this.bufToStr(v));
  }

  generateAesKey(size: number): ArrayBuffer {
    return this.crypto.generateAesKey(size);
  }

  generateRsaKeyPair(size: number, exponent?: number): CryptoKeyPair {
    return this.crypto.generateRsaKeyPair(size, exponent);
  }

  generateEcdsaKeyPair(curve: string): CryptoKeyPair {
    return this.crypto.generateEcdsaKeyPair(curve);
  }

  wrapKey(
    key: ArrayBuffer,
    wrappingKey: ArrayBuffer,
    parameters: WrapAlgoParams
  ): ArrayBuffer {
    return this.crypto.wrapKey(key, wrappingKey, parameters);
  }

  digest(algorithm: DigestAlgorithm, data: ArrayBuffer): ArrayBuffer {
    return this.crypto.digest(algorithm, data);
  }

  isValidX509CertBundle(pem: string): boolean {
    return this.crypto.isValidX509CertBundle(pem);
  }

  isValidX509CertChain(chain: string, trusted: string): boolean {
    return this.crypto.isValidX509CertChain(chain, trusted);
  }
}

(<any>globalThis).ccf = new CCFPolyfill();

class OpenEnclavePolyfill implements OpenEnclave {
  verifyOpenEnclaveEvidence(
    format: string | undefined,
    evidence: ArrayBuffer,
    endorsements?: ArrayBuffer
  ): EvidenceClaims {
    throw new Error("Method not implemented.");
  }
}

(<any>globalThis).openenclave = new OpenEnclavePolyfill();

function nodeBufToArrBuf(buf: Buffer): ArrayBuffer {
  // Note: buf.buffer is not safe, see docs.
  const arrBuf = new ArrayBuffer(buf.byteLength);
  buf.copy(new Uint8Array(arrBuf));
  return arrBuf;
}

function typedArrToArrBuf(ta: ArrayBufferView) {
  return ta.buffer.slice(ta.byteOffset, ta.byteOffset + ta.byteLength);
}

function base64(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString("base64");
}

function unbase64(s: string): ArrayBuffer {
  return nodeBufToArrBuf(Buffer.from(s, "base64"));
}
