import { assert } from "chai";
import "../src/polyfill.js";
import * as kv from "../src/kv.js";
import * as conv from "../src/converters.js";

beforeEach(function () {
  // clear KV before each test
  for (const prop of Object.getOwnPropertyNames(kv.rawKv)) {
    delete kv.rawKv[prop];
  }
});

describe("typedKv", function () {
  it("basic", function () {
    const foo = kv.typedKv("foo", conv.string, conv.uint16);
    const key = "bar";
    const val = 65535;
    assert.equal(foo.get(key), undefined);
    foo.set(key, val);
    assert.equal(foo.get(key), val);
    assert.isTrue(foo.has(key));
    let found = false;
    foo.forEach((v, k) => {
      if (k == key && v == val) {
        found = true;
      }
    });
    assert.isTrue(found);
    foo.delete(key);
    assert.isNotTrue(foo.has(key));
    assert.equal(foo.get(key), undefined);

    const key2 = "baz";
    foo.set(key, val);
    foo.set(key2, val);
    assert.isTrue(foo.has(key));
    assert.isTrue(foo.has(key2));
    foo.clear();
    assert.isNotTrue(foo.has(key));
    assert.isNotTrue(foo.has(key2));
  });
});
