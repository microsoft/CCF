import { assert } from "chai";
import "../src/polyfill";
import { ccf } from "../src/global";

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
  describe("jsonCompatibleToBuf/bufToJsonCompatible", function () {
    it("converts JSON-compatible <--> ArrayBuffer", function () {
      const s = { foo: "bar" };
      assert.deepEqual(ccf.bufToJsonCompatible(ccf.jsonCompatibleToBuf(s)), s);
    });
  });
  describe("generateAesKey", function () {
    it("generates a random AES key", function () {
      assert.equal(ccf.generateAesKey(128).byteLength, 16);
      assert.equal(ccf.generateAesKey(192).byteLength, 24);
      assert.equal(ccf.generateAesKey(256).byteLength, 32);
      assert.notDeepEqual(ccf.generateAesKey(256), ccf.generateAesKey(256));
    });
  });
  describe("generateRsaKeyPair", function () {
    it("generates a random RSA key pair", function () {
      const pair = ccf.generateRsaKeyPair(2048);
      assert.isTrue(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.isTrue(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });
  });
  describe("wrapKey", function () {
    it("performs RSA-OAEP wrapping correctly", function () {
      const key = ccf.generateAesKey(128);
      const wrappingKey = ccf.generateRsaKeyPair(2048);
      const wrapped = ccf.wrapKey(key, ccf.strToBuf(wrappingKey.privateKey), {
        name: "RSA-OAEP",
      });
      assert.isAbove(wrapped.byteLength, 0);
    });
    it("performs AES-KWP wrapping correctly", function () {
      const key = ccf.generateAesKey(128);
      const wrappingKey = ccf.generateAesKey(256);
      const wrapped = ccf.wrapKey(key, wrappingKey, {
        name: "AES-KWP",
      });
      assert.isAbove(wrapped.byteLength, 0);
    });
    it("performs RSA-OAEP-AES-KWP wrapping correctly", function () {
      const key = ccf.generateAesKey(128);
      const wrappingKey = ccf.generateRsaKeyPair(2048);
      const wrapped = ccf.wrapKey(key, ccf.strToBuf(wrappingKey.privateKey), {
        name: "RSA-OAEP-AES-KWP",
        aesKeySize: 256,
      });
      assert.isAbove(wrapped.byteLength, 0);
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
});
