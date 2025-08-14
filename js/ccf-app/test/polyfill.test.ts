import { assert } from "chai";
import * as crypto from "crypto";
import "../src/polyfill.js";
import {
  AesKwpParams,
  ccf,
  DigestAlgorithm,
  RsaOaepAesKwpParams,
  RsaOaepParams,
} from "../src/global.js";
import * as textcodec from "../src/textcodec.js";
import { generateSelfSignedCert, generateCertChain } from "./crypto.js";
import { toArrayBuffer } from "../src/utils.js";

beforeEach(function () {
  // clear KV before each test
  for (const prop of Object.getOwnPropertyNames(ccf.kv)) {
    delete ccf.kv[prop];
  }
});

describe("polyfill", function () {
  describe("strToBuf/bufToStr", function () {
    it("converts string <--> ArrayBuffer", function () {
      const s = "foo";
      assert.equal(ccf.bufToStr(ccf.strToBuf(s)), s);
    });
  });
  describe("TextEncoder", function () {
    it("returns utf-8 for encoding field", function () {
      const encoder = new textcodec.TextEncoder();
      assert.equal(encoder.encoding, "utf-8");
      const s = encoder.encode("foo");
    });
    it("returns an empty array for default empty input", function () {
      assert.deepEqual(
        new textcodec.TextEncoder().encode(""),
        new Uint8Array(),
      );
    });
    it("encodes ascii strings correctly", function () {
      const sample = "foo";
      assert.deepEqual(
        new textcodec.TextEncoder().encode(sample),
        new Uint8Array([0x66, 0x6f, 0x6f]),
      );
    });
    it("encodes UTF-8 strings correctly", function () {
      // a (U+0061, 0x61 in UTF-8), pound sign (U+00A3, 0xC2 0xA3 in UTF-8)
      const sample = "\u0061\u00A3";
      assert.deepEqual(
        new textcodec.TextEncoder().encode(sample),
        new Uint8Array([0x61, 0xc2, 0xa3]),
      );
    });
    it("throws when unsupported method is called", function () {
      assert.throws(() =>
        new textcodec.TextEncoder().encodeInto("test", new Uint8Array([])),
      );
    });
  });
  describe("jsonCompatibleToBuf/bufToJsonCompatible", function () {
    it("converts JSON-compatible <--> ArrayBuffer", function () {
      const s = { foo: "bar" };
      assert.deepEqual(ccf.bufToJsonCompatible(ccf.jsonCompatibleToBuf(s)), s);
    });
  });
  describe("generateAesKey", function () {
    it("generates a random AES key", function () {
      assert.equal(ccf.crypto.generateAesKey(128).byteLength, 16);
      assert.equal(ccf.crypto.generateAesKey(192).byteLength, 24);
      assert.equal(ccf.crypto.generateAesKey(256).byteLength, 32);
      assert.notDeepEqual(
        ccf.crypto.generateAesKey(256),
        ccf.crypto.generateAesKey(256),
      );
    });
  });
  describe("generateRsaKeyPair", function () {
    it("generates a random RSA key pair", function () {
      const pair = ccf.crypto.generateRsaKeyPair(2048);
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("generateEcdsaKeyPair/secp256r1", function () {
    it("generates a random ECDSA P256R1 key pair", function () {
      const pair = ccf.crypto.generateEcdsaKeyPair("secp256r1");
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("generateEcdsaKeyPair/secp384r1", function () {
    it("generates a random ECDSA P384R1 key pair", function () {
      const pair = ccf.crypto.generateEcdsaKeyPair("secp384r1");
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("generateEddsaKeyPair/Curve25519", function () {
    it("generates a random EdDSA Curve25519 key pair", function () {
      const pair = ccf.crypto.generateEddsaKeyPair("curve25519");
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("generateEddsaKeyPair/X25519", function () {
    it("generates a random EdDSA X25519 key pair", function () {
      const pair = ccf.crypto.generateEddsaKeyPair("x25519");
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("wrapKey", function () {
    it("performs RSA-OAEP wrapping correctly", function () {
      const key = ccf.crypto.generateAesKey(128);
      const wrappingKey = ccf.crypto.generateRsaKeyPair(2048);
      const wrapAlgo: RsaOaepParams = {
        name: "RSA-OAEP",
      };
      const wrapped = ccf.crypto.wrapKey(
        key,
        ccf.strToBuf(wrappingKey.publicKey),
        wrapAlgo,
      );
      const unwrapped = ccf.crypto.unwrapKey(
        wrapped,
        ccf.strToBuf(wrappingKey.privateKey),
        wrapAlgo,
      );
      assert.deepEqual(unwrapped, key);
    });
    it("performs AES-KWP wrapping correctly", function () {
      const key = ccf.crypto.generateAesKey(128);
      const wrappingKey = ccf.crypto.generateAesKey(256);
      const wrapAlgo: AesKwpParams = {
        name: "AES-KWP",
      };
      const wrapped = ccf.crypto.wrapKey(key, wrappingKey, wrapAlgo);
      const unwrapped = ccf.crypto.unwrapKey(wrapped, wrappingKey, wrapAlgo);
      assert.deepEqual(unwrapped, key);
    });
    it("performs RSA-OAEP-AES-KWP wrapping correctly", function () {
      const key = ccf.crypto.generateAesKey(128);
      const wrappingKey = ccf.crypto.generateRsaKeyPair(2048);
      const wrapAlgo: RsaOaepAesKwpParams = {
        name: "RSA-OAEP-AES-KWP",
        aesKeySize: 256,
      };
      const wrapped = ccf.crypto.wrapKey(
        key,
        ccf.strToBuf(wrappingKey.publicKey),
        wrapAlgo,
      );
      const unwrapped = ccf.crypto.unwrapKey(
        wrapped,
        ccf.strToBuf(wrappingKey.privateKey),
        wrapAlgo,
      );
      assert.deepEqual(unwrapped, key);
    });
  });
  describe("sign", function () {
    it("performs RSA-PSS sign correctly", function () {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "RSA-PSS",
          hash: "SHA-256",
        },
        privateKey,
        data,
      );

      {
        const verifier = crypto.createVerify("SHA256");
        verifier.update(new Uint8Array(data));
        verifier.end();
        assert.isTrue(
          verifier.verify(
            {
              key: publicKey,
              dsaEncoding: "ieee-p1363",
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            new Uint8Array(signature),
          ),
        );
      }

      // Also `signature` should be verified successfully with the JS API
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );

      {
        const verifier = crypto.createVerify("SHA256");
        verifier.update("bar");
        verifier.end();
        assert.isFalse(
          verifier.verify(
            {
              key: publicKey,
              dsaEncoding: "ieee-p1363",
            },
            new Uint8Array(signature),
          ),
        );
      }
    });
    it("performs ECDSA sign correctly", function () {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        privateKey,
        data,
      );

      {
        const verifier = crypto.createVerify("SHA256");
        verifier.update(new Uint8Array(data));
        verifier.end();
        assert.isTrue(
          verifier.verify(
            {
              key: publicKey,
              dsaEncoding: "ieee-p1363",
            },
            new Uint8Array(signature),
          ),
        );
      }

      // Also `signature` should be verified successfully with the JS API
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );

      {
        const verifier = crypto.createVerify("SHA256");
        verifier.update("bar");
        verifier.end();
        assert.isFalse(
          verifier.verify(
            {
              key: publicKey,
              dsaEncoding: "ieee-p1363",
            },
            new Uint8Array(signature),
          ),
        );
      }
    });
    it("performs EdDSA with Curve25519 sign correctly", function () {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "EdDSA",
        },
        privateKey,
        data,
      );

      assert.isTrue(
        crypto.verify(
          null,
          new Uint8Array(data),
          publicKey,
          new Uint8Array(signature),
        ),
      );

      // Also `signature` should be verified successfully with the JS API
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "EdDSA",
          },
          publicKey,
          signature,
          data,
        ),
      );

      assert.isFalse(
        crypto.verify(
          null,
          new Uint8Array(ccf.strToBuf("bar")),
          publicKey,
          new Uint8Array(signature),
        ),
      );
    });
    it("performs HMAC sign correctly", function () {
      [
        { ccfHash: "SHA-256", nodeHash: "sha256" },
        { ccfHash: "SHA-384", nodeHash: "sha384" },
        { ccfHash: "SHA-512", nodeHash: "sha512" },
      ].forEach(({ ccfHash, nodeHash }) => {
        it(`for ${ccfHash}`, function () {
          let cryptoKey = crypto.generateKeySync("hmac", {
            length: 256,
          });
          const key = cryptoKey.export().toString();

          const data = ccf.strToBuf("foo");
          const signature = ccf.crypto.sign(
            {
              name: "HMAC",
              hash: ccfHash as DigestAlgorithm,
            },
            key,
            data,
          );

          {
            // Re-calculate directly, check for match
            let node_hmac = toArrayBuffer(
              crypto
                .createHmac(nodeHash, key)
                .update(new Uint8Array(data))
                .digest(),
            );
            assert.deepEqual(signature, node_hmac);
          }
          assert.deepEqual(5, 6);

          {
            // Check for mismatch
            let node_hmac = toArrayBuffer(
              crypto
                .createHmac(nodeHash, key)
                .update(new Uint8Array(ccf.strToBuf("bar")))
                .digest(),
            );
            assert.notDeepEqual(signature, node_hmac);
          }
        });
      });
    });
  });
  describe("verifySignature", function () {
    it("performs RSA-PSS validation correctly", function () {
      const { cert, publicKey, privateKey } = generateSelfSignedCert();
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "RSA-PSS",
          hash: "SHA-256",
        },
        privateKey,
        data,
      );
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          cert,
          signature,
          data,
        ),
      );
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );
      assert.isNotTrue(
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          cert,
          signature,
          ccf.strToBuf("bar"),
        ),
      );
      assert.throws(() =>
        ccf.crypto.verifySignature(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );
    });
    it("performs ECDSA validation correctly", function () {
      // Not validating EC with certs here as node-forge used in
      // generateSelfSignedCert() does not support EC keys.
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        privateKey,
        data,
      );

      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );
      assert.isNotTrue(
        ccf.crypto.verifySignature(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          ccf.strToBuf("bar"),
        ),
      );
      assert.throws(() =>
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );
    });
    it("performs EdDSA validation correctly", function () {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });
      const data = ccf.strToBuf("foo");
      const signature = ccf.crypto.sign(
        {
          name: "EdDSA",
        },
        privateKey,
        data,
      );
      assert.isTrue(
        ccf.crypto.verifySignature(
          {
            name: "EdDSA",
          },
          publicKey,
          signature,
          data,
        ),
      );
      assert.isNotTrue(
        ccf.crypto.verifySignature(
          {
            name: "EdDSA",
          },
          publicKey,
          signature,
          ccf.strToBuf("bar"),
        ),
      );
      assert.throws(() =>
        ccf.crypto.verifySignature(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        ),
      );
    });
  });
  describe("digest", function () {
    it("generates a valid SHA-256 hash", function () {
      const data = "Hello world!";
      const expected =
        "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a";
      const digest = ccf.crypto.digest("SHA-256", ccf.strToBuf(data));
      const actual = Buffer.from(digest).toString("hex");
      assert.equal(actual, expected);
    });
  });
  describe("isValidX509CertBundle", function (this) {
    const supported = "X509Certificate" in crypto;
    it("returns true for valid certs", function () {
      if (!supported) {
        this.skip();
      }
      const pem1 = generateSelfSignedCert().cert;
      const pem2 = generateSelfSignedCert().cert;
      assert.isTrue(ccf.crypto.isValidX509CertBundle(pem1));
      assert.isTrue(ccf.crypto.isValidX509CertBundle(pem1 + "\n" + pem2));
    });
    it("returns false for invalid certs", function () {
      if (!supported) {
        this.skip();
      }
      assert.isFalse(ccf.crypto.isValidX509CertBundle("garbage"));
    });
  });
  describe("pemToJwk and jwkToPem", function () {
    it("EC", function () {
      const my_kid = "my_kid";
      const curves = ["secp256r1", "secp384r1"];
      for (const curve of curves) {
        const pair = ccf.crypto.generateEcdsaKeyPair(curve);
        {
          const jwk = ccf.crypto.pubPemToJwk(pair.publicKey);
          assert.equal(jwk.kty, "EC");
          assert.notEqual(jwk.kid, my_kid);
          const pem = ccf.crypto.pubJwkToPem(jwk);
          assert.equal(pem, pair.publicKey);
        }
        {
          const jwk = ccf.crypto.pubPemToJwk(pair.publicKey, my_kid);
          assert.equal(jwk.kty, "EC");
          assert.equal(jwk.kid, my_kid);
          const pem = ccf.crypto.pubJwkToPem(jwk);
          assert.equal(pem, pair.publicKey);
        }
        {
          const jwk = ccf.crypto.pemToJwk(pair.privateKey);
          assert.equal(jwk.kty, "EC");
          assert.notExists(jwk.kid);
          const pem = ccf.crypto.jwkToPem(jwk);
          assert.equal(pem, pair.privateKey);
        }
        {
          const jwk = ccf.crypto.pemToJwk(pair.privateKey, my_kid);
          assert.equal(jwk.kty, "EC");
          assert.equal(jwk.kid, my_kid);
          const pem = ccf.crypto.jwkToPem(jwk);
          assert.equal(pem, pair.privateKey);
        }
      }
    });
    it("RSA", function () {
      const my_kid = "my_kid";
      const pair = ccf.crypto.generateRsaKeyPair(1024);
      {
        const jwk = ccf.crypto.pubRsaPemToJwk(pair.publicKey);
        assert.equal(jwk.kty, "RSA");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.pubRsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.pubRsaPemToJwk(pair.publicKey, my_kid);
        assert.equal(jwk.kty, "RSA");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.pubRsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.rsaPemToJwk(pair.privateKey);
        assert.equal(jwk.kty, "RSA");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.rsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
      {
        const jwk = ccf.crypto.rsaPemToJwk(pair.privateKey, my_kid);
        assert.equal(jwk.kty, "RSA");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.rsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
    });
    it("Ed25119", function () {
      const my_kid = "my_kid";
      const pair = ccf.crypto.generateEddsaKeyPair("curve25519");
      {
        const jwk = ccf.crypto.pubEddsaPemToJwk(pair.publicKey);
        assert.equal(jwk.kty, "OKP");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.pubEddsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.pubEddsaPemToJwk(pair.publicKey, my_kid);
        assert.equal(jwk.kty, "OKP");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.pubEddsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.eddsaPemToJwk(pair.privateKey);
        assert.equal(jwk.kty, "OKP");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.eddsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
      {
        const jwk = ccf.crypto.eddsaPemToJwk(pair.privateKey, my_kid);
        assert.equal(jwk.kty, "OKP");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.eddsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
    });
    it("X25119", function () {
      const my_kid = "my_kid";
      const pair = ccf.crypto.generateEddsaKeyPair("x25519");
      {
        const jwk = ccf.crypto.pubEddsaPemToJwk(pair.publicKey);
        assert.equal(jwk.kty, "OKP");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.pubEddsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.pubEddsaPemToJwk(pair.publicKey, my_kid);
        assert.equal(jwk.kty, "OKP");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.pubEddsaJwkToPem(jwk);
        assert.equal(pem, pair.publicKey);
      }
      {
        const jwk = ccf.crypto.eddsaPemToJwk(pair.privateKey);
        assert.equal(jwk.kty, "OKP");
        assert.notEqual(jwk.kid, my_kid);
        const pem = ccf.crypto.eddsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
      {
        const jwk = ccf.crypto.eddsaPemToJwk(pair.privateKey, my_kid);
        assert.equal(jwk.kty, "OKP");
        assert.equal(jwk.kid, my_kid);
        const pem = ccf.crypto.eddsaJwkToPem(jwk);
        assert.equal(pem, pair.privateKey);
      }
    });
  });
  describe("kv", function () {
    it("basic", function () {
      const foo = ccf.kv["foo"];

      const key = "bar";
      const val = 65535;
      const key_buf = ccf.strToBuf(key);
      const val_buf = ccf.jsonCompatibleToBuf(val);

      assert.equal(foo.get(key_buf), undefined);

      foo.set(key_buf, val_buf);
      assert.deepEqual(foo.get(key_buf), val_buf);
      assert.isTrue(foo.has(key_buf));

      const foo2 = ccf.kv["foo"];
      assert.deepEqual(foo2.get(key_buf), val_buf);
      assert.isTrue(foo2.has(key_buf));

      let found = false;
      foo.forEach((v, k) => {
        if (ccf.bufToStr(k) == key && ccf.bufToJsonCompatible(v) == val) {
          found = true;
        }
      });
      assert.isTrue(found);

      foo.delete(key_buf);
      assert.isNotTrue(foo.has(key_buf));
      assert.equal(foo.get(key_buf), undefined);
    });
  });
  // This test case should be the last until https://github.com/nodejs/node/pull/45377 is addressed.
  describe("isValidX509CertChain", function (this) {
    const supported = "X509Certificate" in crypto;
    it("returns true for valid cert chains", function () {
      if (!supported) {
        this.skip();
      }
      const pems = generateCertChain(3);
      const chain = [pems[0], pems[1]].join("\n");
      const trusted = pems[2];
      assert.isTrue(ccf.crypto.isValidX509CertChain(chain, trusted));
    });
    it("returns false for invalid cert chains", function () {
      if (!supported) {
        this.skip();
      }
      const pems = generateCertChain(3);
      const chain = pems[0];
      const trusted = pems[2];
      assert.isFalse(ccf.crypto.isValidX509CertChain(chain, trusted));
    });
  });
});
