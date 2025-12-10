#include <stdint.h>
#include <stdio.h>
#include "CBORNondet.h"
#include "qcbortests.h"
#include "assert.h"

/* These test cases are taken from Laurence Lundblade's QCBOR. */

#define print_assert(X) do { assert(X); printf(#X " succeeded\n"); } while(false)

// From qcbor_decode_tests.c

bool check_equal_gen(cbor_nondet_t expected, uint8_t *input, size_t len) {
  cbor_nondet_t parsed;
  print_assert (cbor_nondet_parse(false, 0, &input, &len, &parsed));

  print_assert (cbor_nondet_equal(expected, parsed));

  return true;
}

#define check_equal(expected, input) check_equal_gen((expected), (input), sizeof(input))

// IntegerValuesParseTestInternal
static int64_t IntegerValues[]  = {
      -9223372036854775807LL - 1,
      -4294967297,
      -4294967296,
      -4294967295,
      -4294967294,
      -2147483648,
      -2147483647,
      -65538,
      -65537,
      -65536,
      -65535,
      -65534,
      -257,
      -256,
      -255,
      -254,
      -25,
      -24,
      -23,
      -1,
      0,
      0,
      1,
      22,
      23,
      24,
      25,
      26,
      254,
      255,
      256,
      257,
      65534,
      65535,
      65536,
      65537,
      65538,
      2147483647,
      2147483647,
      2147483648,
      2147483649,
      4294967294,
      4294967295,
      4294967296,
      4294967297,
      9223372036854775807,
//      18446744073709551615 // this is a non-Int64 UInt64
};

#define INTEGER_VALUES_COUNT (sizeof(IntegerValues) / sizeof(int64_t))

static uint8_t spExpectedEncodedInts[] = {
   0x98, 0x2f, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x3a, 0xff, 0xff, 0xff,
   0xff, 0x3a, 0xff, 0xff, 0xff, 0xfe, 0x3a, 0xff,
   0xff, 0xff, 0xfd, 0x3a, 0x7f, 0xff, 0xff, 0xff,
   0x3a, 0x7f, 0xff, 0xff, 0xfe, 0x3a, 0x00, 0x01,
   0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x39,
   0xff, 0xff, 0x39, 0xff, 0xfe, 0x39, 0xff, 0xfd,
   0x39, 0x01, 0x00, 0x38, 0xff, 0x38, 0xfe, 0x38,
   0xfd, 0x38, 0x18, 0x37, 0x36, 0x20, 0x00, 0x00,
   0x01, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19, 0x18,
   0x1a, 0x18, 0xfe, 0x18, 0xff, 0x19, 0x01, 0x00,
   0x19, 0x01, 0x01, 0x19, 0xff, 0xfe, 0x19, 0xff,
   0xff, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x00,
   0x01, 0x00, 0x01, 0x1a, 0x00, 0x01, 0x00, 0x02,
   0x1a, 0x7f, 0xff, 0xff, 0xff, 0x1a, 0x7f, 0xff,
   0xff, 0xff, 0x1a, 0x80, 0x00, 0x00, 0x00, 0x1a,
   0x80, 0x00, 0x00, 0x01, 0x1a, 0xff, 0xff, 0xff,
   0xfe, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x1b, 0x00,
   0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1b,
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
   0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff};

static void IntegerValuesParseTestInternal(void) {
  cbor_nondet_t IntegerObjects[INTEGER_VALUES_COUNT + 1];
  
  for (size_t i = 0; i < INTEGER_VALUES_COUNT; ++i) {
    int64_t value = IntegerValues[i];
    if (value < 0) {
      IntegerObjects[i] = cbor_nondet_mk_neg_int64(-1 - value);
    } else {
      IntegerObjects[i] = cbor_nondet_mk_uint64(value);
    }
  }
  IntegerObjects[INTEGER_VALUES_COUNT] = cbor_nondet_mk_uint64(18446744073709551615ULL);

  cbor_nondet_t expected;
  print_assert (cbor_nondet_mk_array(IntegerObjects, INTEGER_VALUES_COUNT + 1, &expected));

  print_assert(check_equal(expected, spExpectedEncodedInts));
}

/*
 Some basic CBOR with map and array used in a lot of tests.
 The map labels are all strings

   {
      "first integer": 42,
      "an array of two strings": [
         "string1", "string2"
      ],
      "map in a map": {
         "bytes 1": h'78787878',
         "bytes 2": h'79797979',
         "another int": 98,
         "text 2": "lies, damn lies and statistics"
      }
   }
*/

static uint8_t pValidMapEncoded[] = {
   0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
   0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x18,
   0x2a, 0x77, 0x61, 0x6e, 0x20, 0x61, 0x72, 0x72,
   0x61, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x77,
   0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x31, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x32, 0x6c, 0x6d, 0x61, 0x70, 0x20, 0x69,
   0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61, 0x70, 0xa4,
   0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31,
   0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62, 0x79,
   0x74, 0x65, 0x73, 0x20, 0x32, 0x44, 0x79, 0x79,
   0x79, 0x79, 0x6b, 0x61, 0x6e, 0x6f, 0x74, 0x68,
   0x65, 0x72, 0x20, 0x69, 0x6e, 0x74, 0x18, 0x62,
   0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32, 0x78,
   0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64,
   0x61, 0x6d, 0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73,
   0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x74, 0x61,
   0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73 };

#define cbor_nondet_mk_text_string_from_literal(X, Y) cbor_nondet_mk_text_string((uint8_t *)(X), sizeof(X) - 1, (Y))

void ValidMapEncoded(void) {
  cbor_nondet_map_entry_t outer_map[3];

  print_assert(cbor_nondet_mk_text_string_from_literal("first integer", &outer_map[0].cbor_map_entry_key));
  outer_map[0].cbor_map_entry_value = cbor_nondet_mk_uint64(42);

  print_assert(cbor_nondet_mk_text_string_from_literal("an array of two strings", &outer_map[1].cbor_map_entry_key));
  cbor_nondet_t outer_map_1_value_array[2];
  print_assert(cbor_nondet_mk_text_string_from_literal("string1", &outer_map_1_value_array[0]));
  print_assert(cbor_nondet_mk_text_string_from_literal("string2", &outer_map_1_value_array[1]));
  print_assert(cbor_nondet_mk_array(outer_map_1_value_array, 2, &outer_map[1].cbor_map_entry_value));

  print_assert(cbor_nondet_mk_text_string_from_literal("map in a map", &outer_map[2].cbor_map_entry_key));
  cbor_nondet_map_entry_t inner_map[4];
  print_assert(cbor_nondet_mk_text_string_from_literal("bytes 1", &inner_map[0].cbor_map_entry_key));
  uint8_t bytes1[] = {0x78, 0x78, 0x78, 0x78};
  print_assert(cbor_nondet_mk_byte_string(bytes1, sizeof(bytes1), &inner_map[0].cbor_map_entry_value));
  print_assert(cbor_nondet_mk_text_string_from_literal("bytes 2", &inner_map[1].cbor_map_entry_key));
  uint8_t bytes2[] = {0x79, 0x79, 0x79, 0x79};
  print_assert(cbor_nondet_mk_byte_string(bytes2, sizeof(bytes2), &inner_map[1].cbor_map_entry_value));
  print_assert(cbor_nondet_mk_text_string_from_literal("another int", &inner_map[2].cbor_map_entry_key));
  inner_map[2].cbor_map_entry_value = cbor_nondet_mk_uint64(98);
  print_assert(cbor_nondet_mk_text_string_from_literal("text 2", &inner_map[3].cbor_map_entry_key));
  print_assert(cbor_nondet_mk_text_string_from_literal("lies, damn lies and statistics", &inner_map[3].cbor_map_entry_value));
  print_assert(cbor_nondet_mk_map(inner_map, 4, &outer_map[2].cbor_map_entry_value));

  cbor_nondet_t expected;
  print_assert(cbor_nondet_mk_map(outer_map, 3, &expected));

  print_assert(check_equal(expected, pValidMapEncoded));
}

/*
 [
    0,
    [],
    [
       [],
       [
          0
       ],
       {},
       {
          1: {},
          2: {},
          3: []
       }
    ]
 ]
 */
static uint8_t sEmpties[] = {
   0x83, 0x00, 0x80, 0x84, 0x80, 0x81, 0x00, 0xa0,
   0xa3, 0x01, 0xa0, 0x02, 0xa0, 0x03, 0x80};

static void CheckEmpties(void) {
  cbor_nondet_t z[3];

  z[0] = cbor_nondet_mk_uint64(0);

  cbor_nondet_t empty_array[1]; // dummy
  print_assert (cbor_nondet_mk_array(empty_array, 0, &z[1]));

  cbor_nondet_t y[4];
  print_assert (cbor_nondet_mk_array(empty_array, 0, &y[0]));
  cbor_nondet_t x[1];
  x[0] = cbor_nondet_mk_uint64(0);
  print_assert (cbor_nondet_mk_array(x, 1, &y[1]));
  cbor_nondet_map_entry_t empty_map[1]; // dummy
  print_assert (cbor_nondet_mk_map(empty_map, 0, &y[2]));
  cbor_nondet_map_entry_t w[3];
  w[0].cbor_map_entry_key = cbor_nondet_mk_uint64(1);
  print_assert (cbor_nondet_mk_map(empty_map, 0, &w[0].cbor_map_entry_value));
  w[1].cbor_map_entry_key = cbor_nondet_mk_uint64(2);
  print_assert (cbor_nondet_mk_map(empty_map, 0, &w[1].cbor_map_entry_value));
  w[2].cbor_map_entry_key = cbor_nondet_mk_uint64(3);
  print_assert (cbor_nondet_mk_array(empty_array, 0, &w[2].cbor_map_entry_value));
  print_assert (cbor_nondet_mk_map(w, 3, &y[3]));
  print_assert (cbor_nondet_mk_array(y, 4, &z[2]));

  cbor_nondet_t expected;
  print_assert (cbor_nondet_mk_array(z, 3, &expected));

  print_assert (check_equal(expected, sEmpties));
}

static bool ParseDeepArrayGen(const size_t nesting, uint8_t *input, uint8_t len) {
  cbor_nondet_t arrays[nesting];
  print_assert (cbor_nondet_mk_array(&arrays[0], 0, &arrays[1]));
  for (size_t i = 2; i < nesting; ++i) {
    print_assert (cbor_nondet_mk_array(&arrays[i-1], 1, &arrays[i]));
  }
  cbor_nondet_t expected;
  print_assert (cbor_nondet_mk_array(&arrays[nesting - 1], 1, &expected));

  return check_equal_gen(expected, input, len);
}

/* [[[[[[[[[[]]]]]]]]]] */

static uint8_t spDeepArrays[] = {
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x80};

static void ParseDeepArrayTest(void) {
  print_assert (ParseDeepArrayGen(10, spDeepArrays, sizeof(spDeepArrays)));
}

/* Big enough to test nesting to the depth of 24
 [[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]
 */
static uint8_t spTooDeepArrays[] = {
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x80};

static void ParseTooDeepArrayTest(void) {
  print_assert (ParseDeepArrayGen(25, spTooDeepArrays, sizeof(spTooDeepArrays)));
}

#define RUN_TEST(X) do { printf(#X "\n"); X; printf(#X " succeeded\n"); } while(false)

int qcbortests(void) {
  RUN_TEST(IntegerValuesParseTestInternal());
  RUN_TEST(ValidMapEncoded());
  RUN_TEST(CheckEmpties());
  RUN_TEST(ParseDeepArrayTest());
  RUN_TEST(ParseTooDeepArrayTest());
  return 0;
}
