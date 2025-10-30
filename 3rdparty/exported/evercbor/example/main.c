/* This file is a documented example of how to use the CBORNondet C API */

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

/* CBORNondet.h defines the CBORNondet C API */
#include "CBORNondet.h"

int main(void) {

  /* 1. Creating CBOR objects */

  /* Stack-allocate an unsigned integer object (major type 0) of value x */
  uint64_t x = 1729;
  cbor_nondet_t cbor0 = cbor_nondet_mk_uint64(x);

  /* Stack-allocate an unsigned integer object (major type 1) of value -1-x */
  cbor_nondet_t cbor1 = cbor_nondet_mk_neg_int64(x);

  /* Stack-allocate a byte string object (major type 2) */
  #define my_bytes_len 4
  uint8_t my_bytes[my_bytes_len] = { 18, 42, 17, 29 };
  cbor_nondet_t cbor2;
  assert (cbor_nondet_mk_byte_string(my_bytes, my_bytes_len, &cbor2));

  /* Stack-allocate a text string object (major type 3) */
  uint8_t * my_string = "Hello world!";
  assert (sizeof(my_string) > 0);
  uint64_t my_string_len = sizeof(my_string) - 1; // we don't want the null terminator
  cbor_nondet_t cbor3;
  assert (cbor_nondet_mk_text_string(my_string, my_string_len, &cbor3));

  /* Stack-allocate an array object (major type 4) with array elements cbor0 and cbor1 */
  #define my_array_len 2
  cbor_nondet_t my_array[my_array_len] = { cbor0, cbor1 };
  cbor_nondet_t cbor4;
  assert (cbor_nondet_mk_array(my_array, my_array_len, &cbor4));

  /* Stack-allocate a map object (major type 5) with map entries (cbor0, cbor1) and (cbor2, cbor3) */
  #define my_map_len 2
  cbor_map_entry my_entry0 = cbor_nondet_mk_map_entry(cbor0, cbor1);
  cbor_map_entry my_entry1 = cbor_nondet_mk_map_entry(cbor2, cbor3);
  cbor_map_entry my_map[my_map_len] = { my_entry0, my_entry1 };
  cbor_nondet_t cbor5;
  assert (cbor_nondet_mk_map(my_map, my_map_len, &cbor5));

  /* Tries to stack-allocate a map object with map entries (cbor0,
     cbor1) and (cbor0, cbor3) (notice the duplicate keys.) Then,
     cbor_nondet_mk_map will gracefully fail
  */
  cbor_map_entry my_entry1_fail = cbor_nondet_mk_map_entry(cbor0, cbor3);
  cbor_map_entry my_map_fail[my_map_len] = { my_entry0, my_entry1_fail };
  cbor_nondet_t cbor5_fail;
  assert (! cbor_nondet_mk_map(my_map_fail, my_map_len, &cbor5_fail));
  
  /* Stack-allocate a tagged object (major type 6) with payload cbor0
     Note that cbor_nondet_mk_tagged takes a pointer to the payload
  */
  uint64_t my_tag = 42;
  cbor_nondet_t cbor6;
  assert (cbor_nondet_mk_tagged(my_tag, &cbor0, &cbor6));

  /* Stack-allocate a simple value object (major type 7).
     TODO: add support for floats.
  */
  uint8_t my_simple = 18;
  cbor_nondet_t cbor7;
  assert (cbor_nondet_mk_simple_value(my_simple, &cbor7));

  /* Tries to stack-allocate a simple value object with an invalid value.
     Then, cbor_nondet_mk_simple_value will gracefully fail. */
  cbor_nondet_t cbor7_fail;
  uint8_t my_simple_fail = 26;
  assert (! cbor_nondet_mk_simple_value(my_simple_fail, &cbor7_fail));


  /* 2. Reading values from CBOR objects */

  /* Determine the major type of a CBOR object */
  uint8_t major_type0 = cbor_nondet_major_type(cbor0);
  assert (major_type0 == CBOR_MAJOR_TYPE_UINT64);
  
  /* Read the value of an integer object (major type 0 or 1). Requires
     cbor_nondet_major_type to return CBOR_MAJOR_TYPE_UINT64 or
     CBOR_MAJOR_TYPE_NEG_INT64. In the case of a negative integer, the
     value returned is its one's complement (-1-x).
  */
  uint64_t read0;
  assert (cbor_nondet_read_uint64(cbor0, &read0));
  assert (read0 == x);
  assert (cbor_nondet_major_type(cbor1) == CBOR_MAJOR_TYPE_NEG_INT64);
  uint64_t read1;
  assert (cbor_nondet_read_uint64(cbor1, &read1));
  assert (read1 == x);

  /* Get the byte payload of a byte or text string
     (major type 2 or 3). Requires cbor_nondet_major_type to return
     CBOR_MAJOR_TYPE_BYTE_STRING or CBOR_MAJOR_TYPE_TEXT_STRING. */

  /* Byte strings */
  assert (cbor_nondet_major_type(cbor2) == CBOR_MAJOR_TYPE_BYTE_STRING);
  uint64_t payload_size2;
  uint8_t *cbor2_payload;
  assert (cbor_nondet_get_string(cbor2, &cbor2_payload, &payload_size2));
  assert (payload_size2 == my_bytes_len);
  assert (memcmp(my_bytes, cbor2_payload, my_bytes_len) == 0);

  /* Text strings */
  assert (cbor_nondet_major_type(cbor3) == CBOR_MAJOR_TYPE_TEXT_STRING);
  uint64_t payload_size3;
  uint8_t *cbor3_payload;
  assert (cbor_nondet_get_string(cbor3, &cbor3_payload, &payload_size3));
  assert (payload_size3 == my_string_len);
  assert (memcmp(my_string, cbor3_payload, my_string_len) == 0);

  /* Get the length of a CBOR array object (major type 4.) Requires
     cbor_nondet_major_type to return CBOR_MAJOR_TYPE_ARRAY */
  assert (cbor_nondet_major_type(cbor4) == CBOR_MAJOR_TYPE_ARRAY);
  uint64_t array_len4;
  assert (cbor_nondet_get_array_length(cbor4, &array_len4));
  assert (array_len4 == my_array_len);

  /* Get the nth item of a CBOR array object (major type 4.) Requires
     cbor_nondet_major_type to return CBOR_MAJOR_TYPE_ARRAY */
  uint64_t array_index = 1;
  cbor_nondet_t array_item;
  assert (cbor_nondet_get_array_item(cbor4, array_index, &array_item));
  assert (cbor_nondet_major_type(array_item) == CBOR_MAJOR_TYPE_NEG_INT64);
  uint64_t array_item_value;
  assert (cbor_nondet_read_uint64(array_item, &array_item_value));
  assert (array_item_value == x);

  /* Stack-allocate an iterator over the items of a CBOR array object
     (major type 4.) Requires cbor_nondet_major_type to return
     CBOR_MAJOR_TYPE_ARRAY */
  cbor_nondet_array_iterator_t array_iter;
  assert (cbor_nondet_array_iterator_start(cbor4, &array_iter));
  {
    cbor_nondet_t item;
    while (cbor_nondet_array_iterator_next(&array_iter, &item)) {
      uint8_t item_type = cbor_nondet_major_type(item);
      assert (item_type == CBOR_MAJOR_TYPE_UINT64 || item_type == CBOR_MAJOR_TYPE_NEG_INT64);
    }
  }

  /* Get the number of entries of a CBOR map object (major type 5.) Requires
     cbor_nondet_major_type to return CBOR_MAJOR_TYPE_MAP */
  assert (cbor_nondet_major_type(cbor5) == CBOR_MAJOR_TYPE_MAP);
  uint64_t map_len5;
  assert (cbor_nondet_get_map_length(cbor5, &map_len5));
  assert (map_len5 == my_map_len);

  /* Lookup an entry in a map by its key. Requires cbor_nondet_major_type
     to return CBOR_MAJOR_TYPE_MAP. cbor_nondet_map_get returns true if
     and only if there is an entry for the key, and if so, updates the
     outparameter with the value part of the entry. */
  // success
  cbor_nondet_t key = cbor_nondet_mk_uint64(x);
  cbor_nondet_t value;
  bool lookup = cbor_nondet_map_get(cbor5, key, &value);
  assert (lookup);
  assert (cbor_nondet_major_type(value) == CBOR_MAJOR_TYPE_NEG_INT64);
  uint64_t value_v;
  assert (cbor_nondet_read_uint64(value, &value_v));
  assert (value_v == x);
  // failure
  assert (! cbor_nondet_map_get(cbor5, cbor1, &value));

  /* Stack-allocate an iterator over the items of a CBOR map object
     (major type 5.) Requires cbor_nondet_major_type to return
     CBOR_MAJOR_TYPE_MAP */
  cbor_nondet_map_iterator_t map_iter;
  assert (cbor_nondet_map_iterator_start(cbor5, &map_iter));
  {
    cbor_nondet_t entry_key;
    cbor_nondet_t entry_value;
    uint64_t count = 2;
    while (cbor_nondet_map_iterator_next(&map_iter, &entry_key, &entry_value)) {
      /* TODO: perform some tests on the key and the value */
      assert (count > 0);
      count--;
    }
    assert (count == 0);
  }

  /* Get the tag and payload of a CBOR tag object (major type 6.) Requires
     cbor_nondet_major_type to return CBOR_MAJOR_TYPE_TAGGED */
  assert (cbor_nondet_major_type(cbor6) == CBOR_MAJOR_TYPE_TAGGED);
  uint64_t tag;
  cbor_nondet_t cbor6_payload;
  assert (cbor_nondet_get_tagged(cbor6, &cbor6_payload, &tag));
  assert (tag == my_tag);
  assert (cbor_nondet_major_type(cbor6_payload) == CBOR_MAJOR_TYPE_UINT64);
  uint64_t cbor6_payload_value;
  assert (cbor_nondet_read_uint64(cbor6_payload, &cbor6_payload_value));
  assert (cbor6_payload_value == x);

  /* Get the value of a CBOR simple value object (major type 7.)
     Requires cbor_nondet_major_type to return CBOR_MAJOR_TYPE_SIMPLE_VALUE */
  assert (cbor_nondet_major_type(cbor7) == CBOR_MAJOR_TYPE_SIMPLE_VALUE);
  uint8_t value7;
  assert (cbor_nondet_read_simple_value(cbor7, &value7));
  assert (value7 == my_simple);

  /* Compare two CBOR objects for equality. */
  // success
  bool compare = cbor_nondet_equal(cbor0, cbor6_payload);
  assert (compare);
  // failure
  assert (! (cbor_nondet_equal(cbor0, cbor1)));
  
  
  /* 3. Serialization */
  #define output_size 42

  /* Serialize a CBOR object at offset 0 of the output
     buffer. cbor_nondet_serialize takes as argument the byte size
     of the output buffer, and returns either 0 if the output buffer
     is too small, or the byte size of the CBOR object written, which
     is a positive integer.
  */
  // success
  uint8_t output[output_size];
  size_t cbor5_serialized_size = cbor_nondet_serialize(cbor5, output, output_size);
  assert (cbor5_serialized_size > 0);
  // failure
  #define output_fail_size 2
  uint8_t output_fail[output_fail_size];
  assert (cbor_nondet_serialize(cbor5, output_fail, output_fail_size) == 0);


  /* 4. Validation and parsing */

  /* Check that an input buffer contains a valid deterministic byte
     encoding of a CBOR object. cbor_nondet_parse takes:

     * a Boolean, true if one wants to check for the map nesting in
       map keys. This is meant as a security measure to control
       call recursion.

     * the expected maximum `depth` of map nesting in map keys. If the
       previous argument is true, then cbor_nondet_parse will use
       O(depth) levels of call recursion. Ignored if the previous
       Boolean argument is false.

       For instance, a user can request to reject all maps in map keys
       by passing `true, 0` to cbor_nondet_parse.

     * a _pointer to_ the input buffer

     * a pointer to the input buffer length

     If cbor_nondet_parse returns true, then the bytes are valid. If,
     moreover, the preceding Boolean argument is true, then the map
     nesting in map keys is within the `depth` argument.

     If cbor_nondet_parse returns false and the first Boolean argument
     is false, then the bytes are invalid. If cbor_nondet_parse
     returns false and the first Boolean argument is true, then the
     bytes are invalid or the map nesting in map keys exceeds the
     `depth` argument.

     If the bytes are valid, then cbor_nondet_parse advances the input
     buffer pointer, and adjusts the value pointed to by `length` to
     the remaining input length past those bytes.

     cbor_nondet_parse copies only an integer, a simple value, the tag of
     a tagged object, or the length of an array or map.  Otherwise,
     the resulting CBOR object internally contains pointers to the
     input bytes. Access operations can be used on the resulting CBOR
     object.
  */
  // validation success
  uint8_t *input = output;
  size_t len = output_size;
  cbor_nondet_t parsed;
  assert (cbor_nondet_parse(true, 0, &input, &len, &parsed));
  assert (output_size > len);
  assert (output_size - len == cbor5_serialized_size);
  assert (cbor_nondet_major_type(parsed) == CBOR_MAJOR_TYPE_MAP);
  assert (cbor_nondet_equal(parsed, cbor5));
  uint64_t map_len;
  assert (cbor_nondet_get_map_length(parsed, &map_len));
  assert (map_len == 2);
  assert (cbor_nondet_map_get(parsed, cbor0, &value));
  assert (cbor_nondet_equal(value, cbor1));
  assert (cbor_nondet_map_get(parsed, cbor2, &value));
  assert (cbor_nondet_equal(value, cbor3));

  // validation failure: see RFC 8949, Section 3.3
  output_fail[0] = 0xf8u;
  output_fail[1] = 0;
  input = output_fail;
  len = output_fail_size;
  assert (! cbor_nondet_parse(false, 0, &input, &len, &parsed));

  return 0;
}
