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
  const foo = kv.typedKv("foo", conv.string, conv.uint16);
  const key = "bar";
  const key2 = "baz";
  const val = 65535;

  it("basic", function () {
    assert.isFalse(foo.has(key));
    assert.isFalse(foo.has(key2));
    assert.equal(foo.get(key), undefined);
    foo.set(key, val);
    assert.equal(foo.get(key), val);
    assert.isTrue(foo.has(key));
    assert.isFalse(foo.has(key2));
    let found = false;
    foo.forEach((v, k) => {
      if (k == key && v == val) {
        found = true;
      }
    });
    assert.isTrue(found);
    foo.delete(key);
    assert.isFalse(foo.has(key));
    assert.isFalse(foo.has(key2));
    assert.equal(foo.get(key), undefined);
  });

  it("clear", function () {
    foo.set(key, val);
    foo.set(key2, val);
    assert.isTrue(foo.has(key));
    assert.isTrue(foo.has(key2));
    foo.clear();
    assert.isNotTrue(foo.has(key));
    assert.isNotTrue(foo.has(key2));
  });

  it("size", function () {
    assert.equal(foo.size, 0);
    foo.set(key, val);
    assert.equal(foo.size, 1);
    foo.set(key2, val);
    assert.equal(foo.size, 2);
    foo.set(key2, val);
    assert.equal(foo.size, 2);
    foo.delete(key);
    assert.equal(foo.size, 1);
    foo.set(key, val);
    assert.equal(foo.size, 2);
    foo.clear();
    assert.equal(foo.size, 0);
  });
});

class TypeErasedKvMap<K, V> {
  constructor(private map: kv.TypedKvMap<K, V>) {}

  has(key: any): boolean {
    return this.map.has(key);
  }
  get(key: any): V | undefined {
    return this.map.get(key);
  }
  set(key: any, value: V) {
    this.map.set(key, value);
  }
}

describe("erased types", function () {
  const bar = new TypeErasedKvMap(kv.typedKv("bar", conv.int32, conv.uint16));
  const key = "baz";
  const val = 65535;

  it("basic", function () {
    assert.throws(() => bar.has(key), `${key} is not a number`);
    assert.throws(() => bar.get(key), `${key} is not a number`);
    assert.throws(() => bar.set(key, val), `${key} is not a number`);
  });
});
