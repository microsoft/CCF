import { assert } from "chai";
import * as util from "../src/utils.js";

function uint8ArrayBufferEquality(
  a: Uint8Array,
  b: Uint8Array,
): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

describe("utils", function () {
  it("toUint8ArrayBuffer(Uint8Array<ArrayBuffer>", function () {
    const buffer = new Uint8Array([1, 2, 3]).buffer;
    const uint8Array = new Uint8Array(buffer);
    const result = util.toUint8ArrayBuffer(uint8Array);
    assert.instanceOf(result, Uint8Array);
    assert.strictEqual(result.buffer, buffer);
  });
  it("toUint8ArrayBuffer(Uint8Array<SharedArrayBuffer>)", function () {
    const sharedBuffer = new SharedArrayBuffer(3);
    const view = new Uint8Array(sharedBuffer);
    view.set([1, 2, 3]);
    const uint8Array = new Uint8Array(sharedBuffer);
    const result = util.toUint8ArrayBuffer(uint8Array);
    assert.instanceOf(result, Uint8Array);
    assert.notStrictEqual((result.buffer as any), (sharedBuffer as any));
    assert.isTrue(uint8ArrayBufferEquality(result, new Uint8Array([1, 2, 3])));
  });

  it("toArrayBuffer(ArrayBuffer)", function () {
    const buffer = new Uint8Array([1, 2, 3]).buffer;
    const result = util.toArrayBuffer(buffer);
    assert.instanceOf(result, ArrayBuffer);
    assert.strictEqual(result, buffer);
  });
  it("toArrayBuffer(SharedArrayBuffer)", function () {
    const buffer = new SharedArrayBuffer(3);
    const view = new Uint8Array(buffer);
    view.set([1, 2, 3]);
    const result = util.toArrayBuffer(buffer);
    assert.instanceOf(result, ArrayBuffer);
    assert.notStrictEqual(result as any, buffer as any);
    assert.isTrue(uint8ArrayBufferEquality(new Uint8Array(result), new Uint8Array([1, 2, 3])));
  });
  it("toArrayBuffer(Uint8Array<ArrayBuffer>)", function () {
    const buffer = new Uint8Array([1, 2, 3]);
    const result = util.toArrayBuffer(buffer);
    assert.instanceOf(result, ArrayBuffer);
    assert.deepEqual(new Uint8Array(result), buffer);
  });
  it("toArrayBuffer(Uint8Array<SharedArrayBuffer>)", function () {
    const sharedBuffer = new SharedArrayBuffer(3);
    const view = new Uint8Array(sharedBuffer);
    view.set([1, 2, 3]);
    const buffer = new Uint8Array(sharedBuffer);
    const result = util.toArrayBuffer(buffer);
    assert.instanceOf(result, ArrayBuffer);
    assert.notStrictEqual((result as any), (sharedBuffer as any));
    assert.isTrue(uint8ArrayBufferEquality(new Uint8Array(result), new Uint8Array([1, 2, 3])));
  });
  it("toArrayBuffer(Buffer)", function () {
    const buffer = Buffer.from([1, 2, 3]);
    const result = util.toArrayBuffer(buffer);
    assert.instanceOf(result, ArrayBuffer);
    assert.isTrue(uint8ArrayBufferEquality(new Uint8Array(result), new Uint8Array([1, 2, 3])));
  });
  it("toArrayBuffer(unsupported type)", function () {
    assert.throws(() => util.toArrayBuffer("string" as any), /Unsupported buffer type/);
  });
});