import { assert } from "chai";
import "../src/polyfill";
import * as conv from "../src/converters";

describe("converters", function () {
  it("bool", function () {
    const val = true;
    assert.equal(conv.bool.decode(conv.bool.encode(val)), val);
  });
  it("int8", function () {
    const val = 127;
    assert.equal(conv.int8.decode(conv.int8.encode(val)), val);
  });
  it("uint8", function () {
    const val = 255;
    assert.equal(conv.uint8.decode(conv.uint8.encode(val)), val);
  });
  it("int16", function () {
    const val = 32767;
    assert.equal(conv.int16.decode(conv.int16.encode(val)), val);
  });
  it("uint16", function () {
    const val = 65535;
    assert.equal(conv.uint16.decode(conv.uint16.encode(val)), val);
  });
  it("int32", function () {
    const val = 2147483647;
    assert.equal(conv.int32.decode(conv.int32.encode(val)), val);
  });
  it("uint32", function () {
    const val = 4294967295;
    assert.equal(conv.uint32.decode(conv.uint32.encode(val)), val);
  });
  it("int64", function () {
    const val = 9223372036854775807n;
    assert.equal(conv.int64.decode(conv.int64.encode(val)), val);
  });
  it("uint64", function () {
    const val = 18446744073709551615n;
    assert.equal(conv.uint64.decode(conv.uint64.encode(val)), val);
  });
  it("json", function () {
    const json = conv.json<{ foo: string }>();
    const val = { foo: "bar" };
    assert.deepEqual(json.decode(json.encode(val)), val);
  });
  it("typedArray", function () {
    const uint8Array = conv.typedArray(Uint8Array);
    const val = new Uint8Array([42]);
    assert.deepEqual(uint8Array.decode(uint8Array.encode(val)), val);
  });
  it("arrayBuffer", function () {
    const val = new Uint8Array([42]).buffer;
    assert.deepEqual(
      conv.arrayBuffer.decode(conv.arrayBuffer.encode(val)),
      val
    );
  });
});
