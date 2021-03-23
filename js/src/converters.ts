// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ccf } from "./global";

// This should eventually cover all JSON-compatible values.
// There are attempts at https://github.com/microsoft/TypeScript/issues/1897
// to create such a type but it needs further refinement.
export type JsonCompatible<T> = any;

export interface DataConverter<T> {
  encode(val: T): ArrayBuffer;
  decode(arr: ArrayBuffer): T;
}

class BoolConverter implements DataConverter<boolean> {
  encode(val: boolean): ArrayBuffer {
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
    if (val < 0 || val > 4294967295) {
      throw new RangeError("value is not within int32 range");
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

type TypedArray = ArrayBufferView;

interface TypedArrayConstructor<T extends TypedArray> {
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

export const bool = new BoolConverter();
export const int8 = new Int8Converter();
export const uint8 = new Uint8Converter();
export const int16 = new Int16Converter();
export const uint16 = new Uint16Converter();
export const int32 = new Int32Converter();
export const uint32 = new Uint32Converter();
export const int64 = new Int64Converter();
export const uint64 = new Uint64Converter();
export const float32 = new Float32Converter();
export const float64 = new Float64Converter();
export const string = new StringConverter();
export const json = <T extends JsonCompatible<T>>() => new JSONConverter<T>();
export const typedArray = <T extends TypedArray>(
  clazz: TypedArrayConstructor<T>
) => new TypedArrayConverter(clazz);
export const arrayBuffer = new IdentityConverter();
