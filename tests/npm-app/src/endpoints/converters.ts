import * as ccfapp from "@microsoft/ccf-app";

// TODO: Hook this up to call, assert that the expected runtime errors are runtime errors
const v_bool = "v_bool";
const v_uint32 = "v_uint32";
const v_uint64 = "v_uint64";
const v_int32 = "v_int32";
const v_int64 = "v_int64";
const v_string = "v_string";
const v_bigint = "v_bigint";
const v_float = "v_float";

const vals = {
  v_bool: true,
  v_uint32: 0,
  v_uint64: 2 ** 32 + 1,
  v_int32: -1,
  v_int64: -(2 ** 32) - 1,
  v_string: "hello world",
  v_bigint: 2n ** 53n + 1n,
  v_float: 0.5,
};

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

// NB: Not hooked up to a callable path, just testing compile-time converter type restrictions.
// All of the lines decorated with ts-ignore are compilation errors.
export function testConvertersSet() {
  {
    const to_u32 = ccfapp.typedKv("to_u32", ccfapp.string, ccfapp.uint32);

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

    // Correctly blocks bools at compile time
    // @ts-ignore
    expectError(() => to_u32.set(v_bool, vals[v_bool]), TypeError);

    // Correctly blocks bignums at compile time
    // @ts-ignore
    expectError(() => to_u32.set(v_bigint, vals[v_bigint]), TypeError);

    // Correctly blocks strings at compile time
    // @ts-ignore
    expectError(() => to_u32.set(v_string, vals[v_string]), TypeError);
  }

  {
    const to_i32 = ccfapp.typedKv("to_i32", ccfapp.string, ccfapp.int32);

    // Fine
    to_i32.set(v_uint32, vals[v_uint32]);
    to_i32.set(v_int32, vals[v_int32]);

    // NB: Accepts all values of type `number` at compilation!
    // Some numbers will become runtime errors:
    // - too-large values
    to_i32.set(v_uint64, vals[v_uint64]);
    // - too-low values
    to_i32.set(v_int64, vals[v_int64]);
    // - non-ints
    to_i32.set(v_float, vals[v_float]);

    // Correctly blocks bools at compile time
    // @ts-ignore
    to_i32.set(v_bool, vals[v_bool]);

    // Correctly blocks bignums at compile time
    // @ts-ignore
    to_i32.set(v_bigint, vals[v_bigint]);

    // Correctly blocks strings at compile time
    // @ts-ignore
    to_i32.set(v_string, vals[v_string]);
  }

  {
    const to_str = ccfapp.typedKv("to_str", ccfapp.string, ccfapp.string);

    // Fine
    to_str.set(v_string, vals[v_string]);
    to_str.set("", "");

    // Correctly blocks other types at compile time
    // @ts-ignore
    to_str.set(v_bool, vals[v_bool]);
    // @ts-ignore
    to_str.set(v_uint32, vals[v_uint32]);
    // @ts-ignore
    to_str.set(v_int32, vals[v_int32]);
    // @ts-ignore
    to_str.set(v_uint64, vals[v_uint64]);
    // @ts-ignore
    to_str.set(v_int64, vals[v_int64]);
    // @ts-ignore
    to_str.set(v_float, vals[v_float]);
    // @ts-ignore
    to_str.set(v_bigint, vals[v_bigint]);
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
}
