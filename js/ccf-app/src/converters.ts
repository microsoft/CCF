// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module provides converters to and from `ArrayBuffer` objects.
 *
 * Converters are commonly used as {@linkcode kv.typedKv} arguments.
 * Another use case is {@linkcode crypto.wrapKey} to convert
 * PEM-encoded keys to `ArrayBuffer`.
 *
 * Example:
 * ```
 * import * as ccfapp from '@microsoft/ccf-app';
 *
 * const val = 'my-string';
 * const buf = ccfapp.string.encode(val);  // ArrayBuffer
 * const val2 = ccfapp.string.decode(buf); // string, val == val2
 * ```
 *
 * @module
 */

import { ccf } from "./global.js";

// This should eventually cover all JSON-compatible values.
// There are attempts at https://github.com/microsoft/TypeScript/issues/1897
// to create such a type but it needs further refinement.
export type JsonCompatible<T> = any;

export interface DataConverter<T> {
  encode(val: T): ArrayBuffer;
  decode(arr: ArrayBuffer): T;
}

function checkBoolean(val: any) {
  if (typeof val !== "boolean") {
    throw new TypeError(`Value ${val} is not a boolean`);
  }
}

function checkNumber(val: any) {
  if (typeof val !== "number") {
    throw new TypeError(`Value ${val} is not a number`);
  }
}

function checkBigInt(val: any) {
  if (typeof val !== "bigint") {
    throw new TypeError(`Value ${val} is not a bigint`);
  }
}

function checkString(val: any) {
  if (typeof val !== "string") {
    throw new TypeError(`Value ${val} is not a string`);
  }
}

class BoolConverter implements DataConverter<boolean> {
  encode(val: boolean): ArrayBuffer {
    checkBoolean(val);
    const buf = new ArrayBuffer(1);
    new DataView(buf).setUint8(0, val ? 1 : 0);
    return buf;
  }
  decode(buf: ArrayBuffer): boolean {
    return new DataView(buf).getUint8(0) === 1 ? true : false;
  }
}
class Int8Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < -128 || val > 127) {
      throw new RangeError("value is not within int8 range");
    }
    const buf = new ArrayBuffer(1);
    new DataView(buf).setInt8(0, val);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt8(0);
  }
}
class Uint8Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < 0 || val > 255) {
      throw new RangeError("value is not within uint8 range");
    }
    const buf = new ArrayBuffer(2);
    new DataView(buf).setUint8(0, val);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint8(0);
  }
}
class Int16Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < -32768 || val > 32767) {
      throw new RangeError("value is not within int16 range");
    }
    const buf = new ArrayBuffer(2);
    new DataView(buf).setInt16(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt16(0, true);
  }
}
class Uint16Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < 0 || val > 65535) {
      throw new RangeError("value is not within uint16 range");
    }
    const buf = new ArrayBuffer(2);
    new DataView(buf).setUint16(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint16(0, true);
  }
}
class Int32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < -2147483648 || val > 2147483647) {
      throw new RangeError("value is not within int32 range");
    }
    const buf = new ArrayBuffer(4);
    new DataView(buf).setInt32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt32(0, true);
  }
}
class Uint32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    if (val < 0 || val > 4294967295) {
      throw new RangeError("value is not within uint32 range");
    }
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint32(0, true);
  }
}
class Int64Converter implements DataConverter<bigint> {
  encode(val: bigint): ArrayBuffer {
    checkBigInt(val);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigInt64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): bigint {
    return new DataView(buf).getBigInt64(0, true);
  }
}
class Uint64Converter implements DataConverter<bigint> {
  encode(val: bigint): ArrayBuffer {
    checkBigInt(val);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): bigint {
    return new DataView(buf).getBigUint64(0, true);
  }
}
class Float32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    const buf = new ArrayBuffer(4);
    new DataView(buf).setFloat32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getFloat32(0, true);
  }
}
class Float64Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    checkNumber(val);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setFloat64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getFloat64(0, true);
  }
}
class StringConverter implements DataConverter<string> {
  encode(val: string): ArrayBuffer {
    checkString(val);
    return ccf.strToBuf(val);
  }
  decode(buf: ArrayBuffer): string {
    return ccf.bufToStr(buf);
  }
}
class JSONConverter<T extends JsonCompatible<T>> implements DataConverter<T> {
  encode(val: T): ArrayBuffer {
    return ccf.jsonCompatibleToBuf(val);
  }
  decode(buf: ArrayBuffer): T {
    return ccf.bufToJsonCompatible(buf);
  }
}

export type TypedArray = ArrayBufferView;

export interface TypedArrayConstructor<T extends TypedArray> {
  new (buffer: ArrayBuffer, byteOffset?: number, length?: number): T;
}

class TypedArrayConverter<T extends TypedArray> implements DataConverter<T> {
  constructor(private clazz: TypedArrayConstructor<T>) {}
  encode(val: T): ArrayBuffer {
    return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
  }
  decode(buf: ArrayBuffer): T {
    return new this.clazz(buf);
  }
}

class IdentityConverter implements DataConverter<ArrayBuffer> {
  encode(val: ArrayBuffer): ArrayBuffer {
    return val;
  }
  decode(buf: ArrayBuffer): ArrayBuffer {
    return buf;
  }
}

/**
 * Converter for `boolean` values.
 *
 * A `boolean` is represented as `uint8` where `true` is `1`
 * and `false` is `0`.
 *
 * Example:
 * ```
 * const buf = ccfapp.bool.encode(true); // ArrayBuffer of size 1
 * const val = ccfapp.bool.decode(buf);  // boolean
 * ```
 */
export const bool: DataConverter<boolean> = new BoolConverter();

/**
 * Converter for `number` values, encoded as `int8`.
 *
 * Example:
 * ```
 * const buf = ccfapp.int8.encode(-50); // ArrayBuffer of size 1
 * const val = ccfapp.int8.decode(buf); // number
 * ```
 */
export const int8: DataConverter<number> = new Int8Converter();

/**
 * Converter for `number` values, encoded as `uint8`.
 *
 * Example:
 * ```
 * const buf = ccfapp.uint8.encode(255); // ArrayBuffer of size 1
 * const val = ccfapp.uint8.decode(buf); // number
 * ```
 */
export const uint8: DataConverter<number> = new Uint8Converter();

/**
 * Converter for `number` values, encoded as `int16`.
 *
 * Example:
 * ```
 * const buf = ccfapp.int16.encode(-1000); // ArrayBuffer of size 2
 * const val = ccfapp.int16.decode(buf);   // number
 * ```
 */
export const int16: DataConverter<number> = new Int16Converter();

/**
 * Converter for `number` values, encoded as `uint16`.
 *
 * Example:
 * ```
 * const buf = ccfapp.uint16.encode(50000); // ArrayBuffer of size 2
 * const val = ccfapp.uint16.decode(buf);   // number
 * ```
 */
export const uint16: DataConverter<number> = new Uint16Converter();

/**
 * Converter for `number` values, encoded as `int32`.
 *
 * Example:
 * ```
 * const buf = ccfapp.int32.encode(-50000); // ArrayBuffer of size 4
 * const val = ccfapp.int32.decode(buf);    // number
 * ```
 */
export const int32: DataConverter<number> = new Int32Converter();

/**
 * Converter for `number` values, encoded as `uint32`.
 *
 * Example:
 * ```
 * const buf = ccfapp.uint32.encode(50000); // ArrayBuffer of size 4
 * const val = ccfapp.uint32.decode(buf);   // number
 * ```
 */
export const uint32: DataConverter<number> = new Uint32Converter();

/**
 * Converter for `bigint` values, encoded as `int64`.
 *
 * Example:
 * ```
 * const n = 2n ** 53n + 1n; // larger than Number.MAX_SAFE_INTEGER
 * const buf = ccfapp.int64.encode(n);   // ArrayBuffer of size 8
 * const val = ccfapp.int64.decode(buf); // bigint
 * ```
 */
export const int64: DataConverter<bigint> = new Int64Converter();

/**
 * Converter for `bigint` values, encoded as `uint64`.
 *
 * Example:
 * ```
 * const n = 2n ** 53n + 1n; // larger than Number.MAX_SAFE_INTEGER
 * const buf = ccfapp.uint64.encode(n);   // ArrayBuffer of size 8
 * const val = ccfapp.uint64.decode(buf); // bigint
 * ```
 */
export const uint64: DataConverter<bigint> = new Uint64Converter();

/**
 * Converter for `number` values, encoded as `float32`.
 *
 * Example:
 * ```
 * const buf = ccfapp.float32.encode(3.141); // ArrayBuffer of size 4
 * const val = ccfapp.float32.decode(buf);   // number
 * ```
 */
export const float32: DataConverter<number> = new Float32Converter();

/**
 * Converter for `number` values, encoded as `float64`.
 *
 * Example:
 * ```
 * const buf = ccfapp.float64.encode(3.141); // ArrayBuffer of size 8
 * const val = ccfapp.float64.decode(buf);   // number
 * ```
 */
export const float64: DataConverter<number> = new Float64Converter();

/**
 * Converter for `string` values, encoded as UTF-8.
 *
 * Example:
 * ```
 * const buf = ccfapp.string.encode('my-string'); // ArrayBuffer
 * const val = ccfapp.string.decode(buf);         // string
 * ```
 */
export const string: DataConverter<string> = new StringConverter();

/**
 * Returns a converter for JSON-compatible objects or values.
 *
 * {@linkcode DataConverter.encode | encode} first serializes the object
 * or value to JSON and then converts the resulting string to an `ArrayBuffer`.
 * JSON serialization uses `JSON.stringify()` without `replacer` or
 * `space` parameters.
 *
 * {@linkcode DataConverter.decode | decode} converts the `ArrayBuffer`
 * to a string and parses it using `JSON.parse()` without `reviver`
 * parameter.
 *
 * Example:
 * ```
 * interface Person {
 *   name: string
 *   age: number
 * }
 * const person: Person = { name: "John", age: 42 };
 * const conv = ccfapp.json<Person>();
 * const buffer = conv.encode(person); // ArrayBuffer
 * const person2 = conv.decode(buffer); // Person
 * ```
 */
export const json: <T extends JsonCompatible<T>>() => DataConverter<T> = <
  T extends JsonCompatible<T>
>() => new JSONConverter<T>();

/**
 * Returns a converter for [TypedArray](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray) objects.
 *
 * Note that a `TypedArray` is a view into an underlying `ArrayBuffer`.
 * This view allows to cover a subset of the `ArrayBuffer`, for example
 * when using `TypedArray.prototype.subarray()`.
 * For views which are subsets, a roundtrip from `TypedArray` to `ArrayBuffer`
 * and back will yield a `TypedArray` that is not a subset anymore.
 *
 * Example:
 * ```
 * const arr = new Uint8Array([42]);
 * const conv = ccfapp.typedArray(Uint8Array);
 * const buffer = conv.encode(arr); // ArrayBuffer of size arr.byteLength
 * const arr2 = conv.decode(buffer); // Uint8Array
 * ```
 *
 * @param clazz The TypedArray class, for example `Uint8Array`.
 */
export const typedArray: <T extends TypedArray>(
  clazz: TypedArrayConstructor<T>
) => DataConverter<T> = <T extends TypedArray>(
  clazz: TypedArrayConstructor<T>
) => new TypedArrayConverter(clazz);

/**
 * Identity converter.
 * {@linkcode DataConverter.encode | encode} / {@linkcode DataConverter.decode | decode}
 * return the input `ArrayBuffer` unchanged. No copy is made.
 *
 * This converter can be used with {@linkcode kv.typedKv} when the key or value
 * type is `ArrayBuffer`, in which case no conversion is applied.
 */
export const arrayBuffer: DataConverter<ArrayBuffer> = new IdentityConverter();
