import * as ccfapp from "@microsoft/ccf-app";

import { isEqual } from "lodash-es";

class MyStruct {
  x: number;
  y: string;
  z: {
    za: boolean;
    zb: Array<string>;
  };
}

class MapStruct {
  a: {
    b: {
      m: Map<string, number>;
    };
  };
}

const v_bool = "v_bool";
const v_uint32 = "v_uint32";
const v_uint64 = "v_uint64";
const v_int32 = "v_int32";
const v_int64 = "v_int64";
const v_string = "v_string";
const v_string_empty = "v_string_empty";
const v_bigint = "v_bigint";
const v_float = "v_float";
const v_struct = "v_struct";
const v_map = "v_map";

let map = new Map<string, number>();
map.set("aaa", 1);
map.set("bcd", 123);

const vals = {
  v_bool: true,
  v_uint32: 0,
  v_uint64: 2 ** 32 + 1,
  v_int32: -1,
  v_int64: -(2 ** 32) - 1,
  v_string: "hello world",
  v_string_empty: "",
  v_bigint: 2n ** 53n + 1n,
  v_float: 0.5,
  v_struct: {
    x: 42,
    y: "goodbye",
    z: {
      za: false,
      zb: ["saluton", "mondo"],
    },
  },
  v_map: {
    a: {
      b: { m: map },
    },
  },
};

const to_u32 = ccfapp.typedKv("to_u32", ccfapp.string, ccfapp.uint32);
const to_i32 = ccfapp.typedKv("to_i32", ccfapp.string, ccfapp.int32);
const to_string = ccfapp.typedKv("to_string", ccfapp.string, ccfapp.string);
const to_json = ccfapp.typedKv("to_json", ccfapp.string, ccfapp.json<any>());
const to_struct = ccfapp.typedKv(
  "to_struct",
  ccfapp.string,
  ccfapp.json<MyStruct>(),
);
const to_map = ccfapp.typedKv(
  "to_map",
  ccfapp.string,
  ccfapp.json<MapStruct>(),
);
const to_map_checked = ccfapp.typedKv(
  "to_map",
  ccfapp.string,
  ccfapp.checkedJson<MapStruct>(),
);

function expectError(fn, errType) {
  var threw = false;
  try {
    fn();
  } catch (e) {
    if (!(e instanceof errType)) {
      throw e;
    }
    threw = true;
  }

  if (!threw) {
    throw new Error(`Expected error was not thrown!`);
  }
}

// Confirm that expected values can be written to KV tables, while others are prevented with errors.
// All of the lines decorated with ts-ignore are compilation errors.
export function testConvertersSet() {
  // Uint32Converter
  {
    // Fine
    to_u32.set(v_uint32, vals[v_uint32]);

    // NB: Accepts all values of type `number` at compilation!
    // Some numbers will become runtime errors:
    // - negative values
    expectError(() => to_u32.set(v_int32, vals[v_int32]), RangeError);
    // - too-large values
    expectError(() => to_u32.set(v_uint64, vals[v_uint64]), RangeError);
    // - non-ints
    expectError(() => to_u32.set(v_float, vals[v_float]), TypeError);

    // Some values will produce compile errors (_and_ later runtime errors):
    // @ts-ignore
    expectError(() => to_u32.set(v_bool, vals[v_bool]), TypeError);
    // @ts-ignore
    expectError(() => to_u32.set(v_bigint, vals[v_bigint]), TypeError);
    // @ts-ignore
    expectError(() => to_u32.set(v_string, vals[v_string]), TypeError);
  }

  // Int32Converter
  {
    // Fine
    to_i32.set(v_uint32, vals[v_uint32]);
    to_i32.set(v_int32, vals[v_int32]);

    // NB: Accepts all values of type `number` at compilation!
    // Some numbers will become runtime errors:
    // - too-large values
    expectError(() => to_i32.set(v_uint64, vals[v_uint64]), RangeError);
    // - too-low values
    expectError(() => to_i32.set(v_int64, vals[v_int64]), RangeError);
    // - non-ints
    expectError(() => to_i32.set(v_float, vals[v_float]), TypeError);

    // Some values will produce compile errors (_and_ later runtime errors):
    // @ts-ignore
    expectError(() => to_i32.set(v_bool, vals[v_bool]), TypeError);
    // @ts-ignore
    expectError(() => to_i32.set(v_bigint, vals[v_bigint]), TypeError);
    // @ts-ignore
    expectError(() => to_i32.set(v_string, vals[v_string]), TypeError);
  }

  // StringConverter
  {
    // Fine
    to_string.set(v_string, vals[v_string]);
    to_string.set(v_string_empty, vals[v_string_empty]);

    // Other values produce compile errors (_and_ later runtime errors):
    // @ts-ignore
    expectError(() => to_string.set(v_bool, vals[v_bool]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_uint32, vals[v_uint32]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_int32, vals[v_int32]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_uint64, vals[v_uint64]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_int64, vals[v_int64]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_float, vals[v_float]), TypeError);
    // @ts-ignore
    expectError(() => to_string.set(v_bigint, vals[v_bigint]), TypeError);
  }

  // JsonConverter
  {
    // Fine
    to_json.set(v_bool, vals[v_bool]);
    to_json.set(v_uint32, vals[v_uint32]);
    to_json.set(v_uint64, vals[v_uint64]);
    to_json.set(v_int32, vals[v_int32]);
    to_json.set(v_int64, vals[v_int64]);
    to_json.set(v_string, vals[v_string]);
    to_json.set(v_string_empty, vals[v_string_empty]);
    to_json.set(v_float, vals[v_float]);
    to_json.set(v_struct, vals[v_struct]);

    // Some values are runtime errors only:
    expectError(() => to_json.set(v_bigint, vals[v_bigint]), TypeError);
  }

  // StructConverter
  {
    // Fine
    to_struct.set(v_struct, vals[v_struct]);

    // Other values produce compile errors _but mostly not runtime errors_:
    // @ts-ignore
    to_struct.set(v_bool, vals[v_bool]);
    // @ts-ignore
    to_struct.set(v_uint32, vals[v_uint32]);
    // @ts-ignore
    to_struct.set(v_int64, vals[v_int64]);

    // Some are runtime errors too:
    // @ts-ignore
    expectError(() => to_struct.set(v_bigint, vals[v_bigint]), TypeError);
  }

  // MapConverter
  {
    // Bad behaviour. No error, but wrote empty object!
    to_map.set(v_map, vals[v_map]);
  }

  // CheckedMapConverter
  {
    // This variant (by using checkedJson) produces a runtime error
    expectError(() => to_map_checked.set(v_map, vals[v_map]), TypeError);
  }

  return { body: "Passed\n" };
}

function expectReadable(map, key) {
  const v = map.get(key);
  if (!isEqual(v, vals[key])) {
    throw Error(
      `Failed roundtrip. Expected ${JSON.stringify(vals[key])}}, read ${JSON.stringify(v)}`,
    );
  }
}

// Confirm that previously written values can be successfully roundtripped by reading from KV
export function testConvertersGet() {
  // Uint32Converter
  {
    expectReadable(to_u32, v_uint32);
  }

  // Int32Converter
  {
    expectReadable(to_i32, v_uint32);
    expectReadable(to_i32, v_int32);
  }

  // StringConverter
  {
    expectReadable(to_string, v_string);
    expectReadable(to_string, v_string_empty);
  }

  // JsonConverter
  {
    expectReadable(to_json, v_bool);
    expectReadable(to_json, v_uint32);
    expectReadable(to_json, v_uint64);
    expectReadable(to_json, v_int32);
    expectReadable(to_json, v_int64);
    expectReadable(to_json, v_string);
    expectReadable(to_json, v_string_empty);
    expectReadable(to_json, v_float);
    expectReadable(to_json, v_struct);
  }

  // StructConverter
  {
    expectReadable(to_struct, v_struct);
  }

  // MapConverter
  {
    // Bad write results in mismatch on read
    expectError(() => expectReadable(to_map, v_map), Error);
  }

  // CheckedMapConverter
  {
    // Failed write means nothing to read
    expectError(() => expectReadable(to_map_checked, v_map), Error);
  }

  return { body: "Passed\n" };
}
