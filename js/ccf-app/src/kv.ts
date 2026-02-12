// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module provides access to the Key-Value Store of CCF.
 *
 * Example of using raw access:
 * ```
 * import * as ccfapp from '@microsoft/ccf-app';
 *
 * const foo = ccfapp.rawKv['foo'];
 * foo.set(
 *  ccfapp.string.encode("key-1"),
 *  ccfapp.json.encode({"prop1": 42})
 * );
 * ```
 *
 * Example of using typed access:
 * ```
 * import * as ccfapp from '@microsoft/ccf-app';
 *
 * const foo = ccfapp.typedKv('foo', ccfapp.string, ccfapp.json);
 * foo.set("key-1", {"prop1": 42});
 * ```
 *
 * Example of using typed access with historical state:
 * ```
 * import * as ccfapp from '@microsoft/ccf-app';
 *
 * const states = ccfapp.getStateRange(handle, begin, end, expiry);
 * // ... error handling ...
 * const firstKv = states[0].kv;
 * const foo = ccfapp.typedKv(firstKv['foo'], ccfapp.string, ccfapp.json);
 * const val = foo.get("key-1");
 * ```
 *
 * @module
 */

import { KvMap, KvSet, ccf } from "./global.js";
import { DataConverter } from "./converters.js";

export class TypedKvMap<K, V> {
  constructor(
    private kv: KvMap,
    private kt: DataConverter<K>,
    private vt: DataConverter<V>,
  ) {}

  has(key: K): boolean {
    return this.kv.has(this.kt.encode(key));
  }

  get(key: K): V | undefined {
    const v = this.kv.get(this.kt.encode(key));
    return v === undefined ? undefined : this.vt.decode(v);
  }

  getVersionOfPreviousWrite(key: K): number | undefined {
    return this.kv.getVersionOfPreviousWrite(this.kt.encode(key));
  }

  set(key: K, value: V): TypedKvMap<K, V> {
    this.kv.set(this.kt.encode(key), this.vt.encode(value));
    return this;
  }

  delete(key: K): void {
    this.kv.delete(this.kt.encode(key));
  }

  clear(): void {
    this.kv.clear();
  }

  forEach(callback: (value: V, key: K, table: TypedKvMap<K, V>) => void): void {
    let kt = this.kt;
    let vt = this.vt;
    let typedMap = this;
    this.kv.forEach(function (
      raw_v: ArrayBuffer,
      raw_k: ArrayBuffer,
      table: KvMap,
    ) {
      callback(vt.decode(raw_v), kt.decode(raw_k), typedMap);
    });
  }

  get size(): number {
    return this.kv.size;
  }
}

export class TypedKvSet<K> {
  constructor(
    private kv: KvMap,
    private kt: DataConverter<K>,
  ) {}

  has(key: K): boolean {
    return this.kv.has(this.kt.encode(key));
  }

  getVersionOfPreviousWrite(key: K): number | undefined {
    return this.kv.getVersionOfPreviousWrite(this.kt.encode(key));
  }

  add(key: K): TypedKvSet<K> {
    this.kv.set(this.kt.encode(key), new ArrayBuffer(8));
    return this;
  }

  delete(key: K): void {
    this.kv.delete(this.kt.encode(key));
  }

  clear(): void {
    this.kv.clear();
  }

  forEach(callback: (key: K, table: TypedKvSet<K>) => void): void {
    let kt = this.kt;
    let typedSet = this;
    this.kv.forEach(function (
      raw_v: ArrayBuffer,
      raw_k: ArrayBuffer,
      table: KvMap,
    ) {
      callback(kt.decode(raw_k), typedSet);
    });
  }

  get size(): number {
    return this.kv.size;
  }
}

/**
 * Returns a typed view of a map in the Key-Value Store,
 * where keys and values are automatically converted
 * to and from ``ArrayBuffer`` based on the given key
 * and value converters.
 *
 * See the {@linkcode converters} module for available converters.
 *
 * @param nameOrMap Either the map name in the Key-Value Store,
 *    or a ``KvMap`` object.
 * @param kt The converter to use for map keys.
 * @param vt The converter to use for map values.
 */
export function typedKv<K, V>(
  nameOrMap: string | KvMap,
  kt: DataConverter<K>,
  vt: DataConverter<V>,
) {
  const kvMap = typeof nameOrMap === "string" ? ccf.kv[nameOrMap] : nameOrMap;
  return new TypedKvMap(kvMap, kt, vt);
}

/**
 * Returns a typed view of a set in the Key-Value Store,
 * where keys are automatically converted
 * to and from ``ArrayBuffer`` based on the given key
 * converter.
 *
 * See the {@linkcode converters} module for available converters.
 *
 * @param nameOrMap Either the map name in the Key-Value Store,
 *    or a ``KvMap`` object.
 * @param kt The converter to use for map keys.
 */
export function typedKvSet<K, V>(
  nameOrMap: string | KvMap,
  kt: DataConverter<K>,
) {
  const kvMap = typeof nameOrMap === "string" ? ccf.kv[nameOrMap] : nameOrMap;
  return new TypedKvSet(kvMap, kt);
}

/**
 * @inheritDoc global!CCF.kv
 */
export const rawKv = ccf.kv;

export type { KvMap, KvSet, KvMaps } from "./global";
