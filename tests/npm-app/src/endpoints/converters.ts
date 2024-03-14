import * as ccfapp from "@microsoft/ccf-app";

// TODO: Hook this up to call, assert that the expected runtime errors are runtime errors
const v_bool = "v_bool";
const v_uint32 = "v_uint32";
const v_uint64 = "v_uint64";
const v_int32 = "v_int32";
const v_int64 = "v_int64";
const v_string = "v_string";
const v_string_empty = "v_string_empty";
const v_bigint = "v_bigint";
const v_float = "v_float";

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
};

const to_u32 = ccfapp.typedKv("to_u32", ccfapp.string, ccfapp.uint32);
const to_i32 = ccfapp.typedKv("to_i32", ccfapp.string, ccfapp.int32);
const to_str = ccfapp.typedKv("to_str", ccfapp.string, ccfapp.string);

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
    to_str.set(v_string, vals[v_string]);
    to_str.set(v_string_empty, vals[v_string_empty]);

    // Other values produce compile errors:
    // @ts-ignore
    expectError(() => to_str.set(v_bool, vals[v_bool]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_uint32, vals[v_uint32]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_int32, vals[v_int32]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_uint64, vals[v_uint64]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_int64, vals[v_int64]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_float, vals[v_float]), TypeError);
    // @ts-ignore
    expectError(() => to_str.set(v_bigint, vals[v_bigint]), TypeError);
  }

  // {
  //   class POD extends ccfapp.JsonCompatible {
  //     x: number;
  //     y: string;
  //     z: {
  //       za: boolean;
  //       zb: List<string>;
  //     };
  //   }

  //   const str_to_pod = ccfapp.typedKv(
  //     "str_to_pod",
  //     ccfapp.string,
  //     ccfapp.json<POD>()
  //   );
  // }

  // {
  //   type M = Map<number, string>;
  //   const str_to_m = ccfapp.typedKv(
  //     "str_to_m",
  //     ccfapp.string,
  //     ccfapp.json<M>()
  //   );

  //   str_to_m.set(v_string, new Map<number, string>());

  //   // class Foo extends ccfapp.JsonCompatible<Foo> {

  //   // }
  // }

  return { body: "Passed\n" };
}

function expectReadable(map, key) {
  const v = map.get(key);
  if (v !== vals[key]) {
    throw Error(`Failed roundtrip. Expected ${vals[key]}, read ${v}`);
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
    expectReadable(to_str, v_string);
    expectReadable(to_str, v_string_empty);
  }

  return { body: "Passed\n" };
}
