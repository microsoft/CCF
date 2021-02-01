// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Types/objects exposed from C++:

// This should eventually cover all JSON-compatible values.
// There are attempts at https://github.com/microsoft/TypeScript/issues/1897
// to create such a type but it needs further refinement.
type JsonCompatible<T> = any;

export interface Body<T extends JsonCompatible<T>> {
  text: () => string;
  json: () => T;
  arrayBuffer: () => ArrayBuffer;
}

export interface Request<T extends JsonCompatible<T> = any> {
  headers: { [key: string]: string };
  params: { [key: string]: string };
  query: string;
  body: Body<T>;
  caller: any;
  user?: any;
}

type ResponseBodyType<T> = string | ArrayBuffer | JsonCompatible<T>;

export interface Response<T extends ResponseBodyType<T> = any> {
  statusCode?: number;
  headers?: { [key: string]: string };
  body?: T;
}

export type EndpointFn<
  A extends JsonCompatible<A> = any,
  B extends ResponseBodyType<B> = any
> = (request: Request<A>) => Response<B>;

export interface KVMap {
  has: (key: ArrayBuffer) => boolean;
  get: (key: ArrayBuffer) => ArrayBuffer | undefined;
  set: (key: ArrayBuffer, value: ArrayBuffer) => KVMap;
  delete: (key: ArrayBuffer) => boolean;
  forEach: (
    callback: (value: ArrayBuffer, key: ArrayBuffer, table: KVMap) => void
  ) => void;
}

export type KVMaps = { [key: string]: KVMap };

interface WrapAlgoBase {
  name: string;
}

export interface RsaOaepParams extends WrapAlgoBase {
  // name == 'RSA-OAEP'
  label?: ArrayBuffer;
}

export type WrapAlgo = RsaOaepParams;

export interface CCF {
  strToBuf(v: string): ArrayBuffer;
  bufToStr(v: ArrayBuffer): string;
  jsonCompatibleToBuf<T extends JsonCompatible<T>>(v: T): ArrayBuffer;
  bufToJsonCompatible<T extends JsonCompatible<T>>(v: ArrayBuffer): T;
  generateAesKey(size: number): ArrayBuffer;
  wrapKey(
    key: ArrayBuffer,
    wrappingKey: ArrayBuffer,
    wrapAlgo: WrapAlgo
  ): ArrayBuffer;

  kv: KVMaps;
}

export const ccf = globalThis.ccf as CCF;

// Additional functionality on top of C++:

// Optional, so that this module can be (indirectly) imported outside CCF.
export const kv = ccf ? ccf.kv : undefined;

export interface DataConverter<T> {
  encode(val: T): ArrayBuffer;
  decode(arr: ArrayBuffer): T;
}

export class BoolConverter implements DataConverter<boolean> {
  encode(val: boolean): ArrayBuffer {
    const buf = new ArrayBuffer(1);
    new DataView(buf).setUint8(0, val ? 1 : 0);
    return buf;
  }
  decode(buf: ArrayBuffer): boolean {
    return new DataView(buf).getUint8(0) === 1 ? true : false;
  }
}
export class Int8Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(1);
    new DataView(buf).setInt8(0, val);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt8(0);
  }
}
export class Uint8Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(2);
    new DataView(buf).setUint8(0, val);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint8(0);
  }
}
export class Int16Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(2);
    new DataView(buf).setInt16(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt16(0, true);
  }
}
export class Uint16Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(2);
    new DataView(buf).setUint16(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint16(0, true);
  }
}
export class Int32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setInt32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getInt32(0, true);
  }
}
export class Uint32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getUint32(0, true);
  }
}
export class Int64Converter implements DataConverter<bigint> {
  encode(val: bigint): ArrayBuffer {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigInt64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): bigint {
    return new DataView(buf).getBigInt64(0, true);
  }
}
export class Uint64Converter implements DataConverter<bigint> {
  encode(val: bigint): ArrayBuffer {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): bigint {
    return new DataView(buf).getBigUint64(0, true);
  }
}
export class Float32Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setFloat32(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getFloat32(0, true);
  }
}
export class Float64Converter implements DataConverter<number> {
  encode(val: number): ArrayBuffer {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setFloat64(0, val, true);
    return buf;
  }
  decode(buf: ArrayBuffer): number {
    return new DataView(buf).getFloat64(0, true);
  }
}
export class StringConverter implements DataConverter<string> {
  encode(val: string): ArrayBuffer {
    return ccf.strToBuf(val);
  }
  decode(buf: ArrayBuffer): string {
    return ccf.bufToStr(buf);
  }
}
export class JSONConverter<T extends JsonCompatible<T>>
  implements DataConverter<T> {
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

export class TypedArrayConverter<T extends TypedArray>
  implements DataConverter<T> {
  constructor(private clazz: TypedArrayConstructor<T>) {}
  encode(val: T): ArrayBuffer {
    return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
  }
  decode(buf: ArrayBuffer): T {
    return new this.clazz(buf);
  }
}
export class IdentityConverter implements DataConverter<ArrayBuffer> {
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

export class TypedKVMap<K, V> {
  constructor(
    private kv: KVMap,
    private kt: DataConverter<K>,
    private vt: DataConverter<V>
  ) {}
  has(key: K): boolean {
    return this.kv.has(this.kt.encode(key));
  }
  get(key: K): V | undefined {
    const v = this.kv.get(this.kt.encode(key));
    return v === undefined ? undefined : this.vt.decode(v);
  }
  set(key: K, value: V): TypedKVMap<K, V> {
    this.kv.set(this.kt.encode(key), this.vt.encode(value));
    return this;
  }
  delete(key: K): boolean {
    return this.kv.delete(this.kt.encode(key));
  }
  forEach(callback: (value: V, key: K, table: TypedKVMap<K, V>) => void): void {
    let kt = this.kt;
    let vt = this.vt;
    let typedMap = this;
    this.kv.forEach(function (
      raw_v: ArrayBuffer,
      raw_k: ArrayBuffer,
      table: KVMap
    ) {
      callback(vt.decode(raw_v), kt.decode(raw_k), typedMap);
    });
  }
}
