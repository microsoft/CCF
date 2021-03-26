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
 * @module
 */

import { KvMap, ccf } from "./global";
import { DataConverter } from "./converters";

export class TypedKvMap<K, V> {
  constructor(
    private kv: KvMap,
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

  set(key: K, value: V): TypedKvMap<K, V> {
    this.kv.set(this.kt.encode(key), this.vt.encode(value));
    return this;
  }

  delete(key: K): boolean {
    return this.kv.delete(this.kt.encode(key));
  }

  forEach(callback: (value: V, key: K, table: TypedKvMap<K, V>) => void): void {
    let kt = this.kt;
    let vt = this.vt;
    let typedMap = this;
    this.kv.forEach(function (
      raw_v: ArrayBuffer,
      raw_k: ArrayBuffer,
      table: KvMap
    ) {
      callback(vt.decode(raw_v), kt.decode(raw_k), typedMap);
    });
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
 * @param name The map name in the Key-Value Store.
 * @param kt The converter to use for map keys.
 * @param vt The converter to use for map values.
 */
export function typedKv<K, V>(
  name: string,
  kt: DataConverter<K>,
  vt: DataConverter<V>
) {
  return new TypedKvMap(ccf.kv[name], kt, vt);
}

/**
 * @inheritDoc CCF.kv
 */
export const rawKv = ccf.kv;

export { KvMap, KvMaps } from "./global";
