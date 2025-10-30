
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include "CBORNondet.h"
#include "CBORNondetTest.h"

static char * hex_digits[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

static void dump_encoding_test_failure (uint8_t *bytes, size_t len) {
  size_t pos = 0;
  printf("Encoded bytes: ");
  while (pos < len) {
    uint8_t x = bytes[pos];
    printf("%s%s", hex_digits[x / 16], hex_digits[x % 16]);
    pos += 1;
  };
  printf("\n");
}

int gentest(void) {
  {
    printf("Test 1 out of 29\n");
    printf("Testing: ""0""\n");
    uint8_t source_bytes[1] = {0x00};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(0);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 2 out of 29\n");
    printf("Testing: ""1""\n");
    uint8_t source_bytes[1] = {0x01};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(1);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 3 out of 29\n");
    printf("Testing: ""10""\n");
    uint8_t source_bytes[1] = {0x0a};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(10);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 4 out of 29\n");
    printf("Testing: ""23""\n");
    uint8_t source_bytes[1] = {0x17};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(23);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 5 out of 29\n");
    printf("Testing: ""24""\n");
    uint8_t source_bytes[2] = {0x18, 0x18};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(24);
    uint8_t target_bytes[2];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 2);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 2 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 2;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 2;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 6 out of 29\n");
    printf("Testing: ""25""\n");
    uint8_t source_bytes[2] = {0x18, 0x19};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(25);
    uint8_t target_bytes[2];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 2);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 2 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 2;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 2;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 7 out of 29\n");
    printf("Testing: ""100""\n");
    uint8_t source_bytes[2] = {0x18, 0x64};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(100);
    uint8_t target_bytes[2];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 2);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 2 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 2;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 2;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 8 out of 29\n");
    printf("Testing: ""1000""\n");
    uint8_t source_bytes[3] = {0x19, 0x03, 0xe8};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(1000);
    uint8_t target_bytes[3];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 3);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 3 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 3;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 3;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 9 out of 29\n");
    printf("Testing: ""1000000""\n");
    uint8_t source_bytes[5] = {0x1a, 0x00, 0x0f, 0x42, 0x40};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(1000000);
    uint8_t target_bytes[5];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 5);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 5 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 5;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 5;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 10 out of 29\n");
    printf("Testing: ""1000000000000""\n");
    uint8_t source_bytes[9] = {0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00};
    cbor_nondet_t source_cbor = cbor_nondet_mk_uint64(1000000000000);
    uint8_t target_bytes[9];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 9);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 9 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 9;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (9 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 9 bytes, got %ld\n", 9 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 9;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (9 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 9 bytes, got %ld\n", 9 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 11 out of 29\n");
    printf("Testing: ""-1""\n");
    uint8_t source_bytes[1] = {0x20};
    cbor_nondet_t source_cbor = cbor_nondet_mk_neg_int64(0);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 12 out of 29\n");
    printf("Testing: ""-10""\n");
    uint8_t source_bytes[1] = {0x29};
    cbor_nondet_t source_cbor = cbor_nondet_mk_neg_int64(9);
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 13 out of 29\n");
    printf("Testing: ""-100""\n");
    uint8_t source_bytes[2] = {0x38, 0x63};
    cbor_nondet_t source_cbor = cbor_nondet_mk_neg_int64(99);
    uint8_t target_bytes[2];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 2);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 2 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 2;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 2;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 14 out of 29\n");
    printf("Testing: ""-1000""\n");
    uint8_t source_bytes[3] = {0x39, 0x03, 0xe7};
    cbor_nondet_t source_cbor = cbor_nondet_mk_neg_int64(999);
    uint8_t target_bytes[3];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 3);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 3 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 3;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 3;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 15 out of 29\n");
    printf("Testing: ""\"\"""\n");
    uint8_t source_bytes[1] = {0x60};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"", 0, &source_cbor));
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 16 out of 29\n");
    printf("Testing: ""\"a\"""\n");
    uint8_t source_bytes[2] = {0x61, 0x61};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"a", 1, &source_cbor));
    uint8_t target_bytes[2];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 2);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 2 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 2;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 2;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (2 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 2 bytes, got %ld\n", 2 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 17 out of 29\n");
    printf("Testing: ""\"IETF\"""\n");
    uint8_t source_bytes[5] = {0x64, 0x49, 0x45, 0x54, 0x46};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"IETF", 4, &source_cbor));
    uint8_t target_bytes[5];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 5);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 5 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 5;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 5;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 18 out of 29\n");
    printf("Testing: ""\"\\\"\\\\\"""\n");
    uint8_t source_bytes[3] = {0x62, 0x22, 0x5c};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"\"\\", 2, &source_cbor));
    uint8_t target_bytes[3];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 3);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 3 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 3;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 3;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 19 out of 29\n");
    printf("Testing: ""\"ü\"""\n");
    uint8_t source_bytes[3] = {0x62, 0xc3, 0xbc};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"ü", 2, &source_cbor));
    uint8_t target_bytes[3];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 3);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 3 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 3;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 3;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (3 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 3 bytes, got %ld\n", 3 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 20 out of 29\n");
    printf("Testing: ""\"水\"""\n");
    uint8_t source_bytes[4] = {0x63, 0xe6, 0xb0, 0xb4};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"水", 3, &source_cbor));
    uint8_t target_bytes[4];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 4);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 4 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 4;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (4 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 4 bytes, got %ld\n", 4 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 4;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (4 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 4 bytes, got %ld\n", 4 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 21 out of 29\n");
    printf("Testing: ""\"𐅑\"""\n");
    uint8_t source_bytes[5] = {0x64, 0xf0, 0x90, 0x85, 0x91};
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_text_string((uint8_t *)"𐅑", 4, &source_cbor));
    uint8_t target_bytes[5];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 5);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 5 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 5;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 5;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (5 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 5 bytes, got %ld\n", 5 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 22 out of 29\n");
    printf("Testing: ""[]""\n");
    uint8_t source_bytes[1] = {0x80};
    cbor_nondet_t source_cbor_array[0];
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_array(source_cbor_array, 0, &source_cbor));
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 23 out of 29\n");
    printf("Testing: ""[1,2,3]""\n");
    uint8_t source_bytes[4] = {0x83, 0x01, 0x02, 0x03};
    cbor_nondet_t source_cbor_array[3];
    cbor_nondet_t source_cbor_array_2 = cbor_nondet_mk_uint64(3);
    source_cbor_array[2] = source_cbor_array_2;
    cbor_nondet_t source_cbor_array_1 = cbor_nondet_mk_uint64(2);
    source_cbor_array[1] = source_cbor_array_1;
    cbor_nondet_t source_cbor_array_0 = cbor_nondet_mk_uint64(1);
    source_cbor_array[0] = source_cbor_array_0;
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_array(source_cbor_array, 3, &source_cbor));
    uint8_t target_bytes[4];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 4);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 4 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 4;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (4 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 4 bytes, got %ld\n", 4 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 4;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (4 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 4 bytes, got %ld\n", 4 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 24 out of 29\n");
    printf("Testing: ""[1,[2,3],[4,5]]""\n");
    uint8_t source_bytes[8] = {0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05};
    cbor_nondet_t source_cbor_array[3];
    cbor_nondet_t source_cbor_array_2_array[2];
    cbor_nondet_t source_cbor_array_2_array_1 = cbor_nondet_mk_uint64(5);
    source_cbor_array_2_array[1] = source_cbor_array_2_array_1;
    cbor_nondet_t source_cbor_array_2_array_0 = cbor_nondet_mk_uint64(4);
    source_cbor_array_2_array[0] = source_cbor_array_2_array_0;
    cbor_nondet_t source_cbor_array_2;
    assert (cbor_nondet_mk_array(source_cbor_array_2_array, 2, &source_cbor_array_2));
    source_cbor_array[2] = source_cbor_array_2;
    cbor_nondet_t source_cbor_array_1_array[2];
    cbor_nondet_t source_cbor_array_1_array_1 = cbor_nondet_mk_uint64(3);
    source_cbor_array_1_array[1] = source_cbor_array_1_array_1;
    cbor_nondet_t source_cbor_array_1_array_0 = cbor_nondet_mk_uint64(2);
    source_cbor_array_1_array[0] = source_cbor_array_1_array_0;
    cbor_nondet_t source_cbor_array_1;
    assert (cbor_nondet_mk_array(source_cbor_array_1_array, 2, &source_cbor_array_1));
    source_cbor_array[1] = source_cbor_array_1;
    cbor_nondet_t source_cbor_array_0 = cbor_nondet_mk_uint64(1);
    source_cbor_array[0] = source_cbor_array_0;
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_array(source_cbor_array, 3, &source_cbor));
    uint8_t target_bytes[8];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 8);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 8 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 8;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (8 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 8 bytes, got %ld\n", 8 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 8;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (8 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 8 bytes, got %ld\n", 8 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 25 out of 29\n");
    printf("Testing: ""[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]""\n");
    uint8_t source_bytes[29] = {0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19};
    cbor_nondet_t source_cbor_array[25];
    cbor_nondet_t source_cbor_array_24 = cbor_nondet_mk_uint64(25);
    source_cbor_array[24] = source_cbor_array_24;
    cbor_nondet_t source_cbor_array_23 = cbor_nondet_mk_uint64(24);
    source_cbor_array[23] = source_cbor_array_23;
    cbor_nondet_t source_cbor_array_22 = cbor_nondet_mk_uint64(23);
    source_cbor_array[22] = source_cbor_array_22;
    cbor_nondet_t source_cbor_array_21 = cbor_nondet_mk_uint64(22);
    source_cbor_array[21] = source_cbor_array_21;
    cbor_nondet_t source_cbor_array_20 = cbor_nondet_mk_uint64(21);
    source_cbor_array[20] = source_cbor_array_20;
    cbor_nondet_t source_cbor_array_19 = cbor_nondet_mk_uint64(20);
    source_cbor_array[19] = source_cbor_array_19;
    cbor_nondet_t source_cbor_array_18 = cbor_nondet_mk_uint64(19);
    source_cbor_array[18] = source_cbor_array_18;
    cbor_nondet_t source_cbor_array_17 = cbor_nondet_mk_uint64(18);
    source_cbor_array[17] = source_cbor_array_17;
    cbor_nondet_t source_cbor_array_16 = cbor_nondet_mk_uint64(17);
    source_cbor_array[16] = source_cbor_array_16;
    cbor_nondet_t source_cbor_array_15 = cbor_nondet_mk_uint64(16);
    source_cbor_array[15] = source_cbor_array_15;
    cbor_nondet_t source_cbor_array_14 = cbor_nondet_mk_uint64(15);
    source_cbor_array[14] = source_cbor_array_14;
    cbor_nondet_t source_cbor_array_13 = cbor_nondet_mk_uint64(14);
    source_cbor_array[13] = source_cbor_array_13;
    cbor_nondet_t source_cbor_array_12 = cbor_nondet_mk_uint64(13);
    source_cbor_array[12] = source_cbor_array_12;
    cbor_nondet_t source_cbor_array_11 = cbor_nondet_mk_uint64(12);
    source_cbor_array[11] = source_cbor_array_11;
    cbor_nondet_t source_cbor_array_10 = cbor_nondet_mk_uint64(11);
    source_cbor_array[10] = source_cbor_array_10;
    cbor_nondet_t source_cbor_array_9 = cbor_nondet_mk_uint64(10);
    source_cbor_array[9] = source_cbor_array_9;
    cbor_nondet_t source_cbor_array_8 = cbor_nondet_mk_uint64(9);
    source_cbor_array[8] = source_cbor_array_8;
    cbor_nondet_t source_cbor_array_7 = cbor_nondet_mk_uint64(8);
    source_cbor_array[7] = source_cbor_array_7;
    cbor_nondet_t source_cbor_array_6 = cbor_nondet_mk_uint64(7);
    source_cbor_array[6] = source_cbor_array_6;
    cbor_nondet_t source_cbor_array_5 = cbor_nondet_mk_uint64(6);
    source_cbor_array[5] = source_cbor_array_5;
    cbor_nondet_t source_cbor_array_4 = cbor_nondet_mk_uint64(5);
    source_cbor_array[4] = source_cbor_array_4;
    cbor_nondet_t source_cbor_array_3 = cbor_nondet_mk_uint64(4);
    source_cbor_array[3] = source_cbor_array_3;
    cbor_nondet_t source_cbor_array_2 = cbor_nondet_mk_uint64(3);
    source_cbor_array[2] = source_cbor_array_2;
    cbor_nondet_t source_cbor_array_1 = cbor_nondet_mk_uint64(2);
    source_cbor_array[1] = source_cbor_array_1;
    cbor_nondet_t source_cbor_array_0 = cbor_nondet_mk_uint64(1);
    source_cbor_array[0] = source_cbor_array_0;
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_array(source_cbor_array, 25, &source_cbor));
    uint8_t target_bytes[29];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 29);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 29 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 29;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (29 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 29 bytes, got %ld\n", 29 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 29;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (29 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 29 bytes, got %ld\n", 29 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 26 out of 29\n");
    printf("Testing: ""{}""\n");
    uint8_t source_bytes[1] = {0xa0};
    cbor_map_entry source_cbor_map[0];
    cbor_nondet_t source_cbor;;
    if (! cbor_nondet_mk_map(source_cbor_map, 0, &source_cbor))
    {
      printf("Map build failed for source_cbor\n");
      return 1;
    }
    uint8_t target_bytes[1];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 1);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 1 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 1;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 1;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (1 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 1 bytes, got %ld\n", 1 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 27 out of 29\n");
    printf("Testing: ""{\"a\":1,\"b\":[2,3]}""\n");
    uint8_t source_bytes[9] = {0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03};
    cbor_map_entry source_cbor_map[2];
    cbor_nondet_t source_cbor_map_1_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"b", 1, &source_cbor_map_1_key));
    cbor_nondet_t source_cbor_map_1_value_array[2];
    cbor_nondet_t source_cbor_map_1_value_array_1 = cbor_nondet_mk_uint64(3);
    source_cbor_map_1_value_array[1] = source_cbor_map_1_value_array_1;
    cbor_nondet_t source_cbor_map_1_value_array_0 = cbor_nondet_mk_uint64(2);
    source_cbor_map_1_value_array[0] = source_cbor_map_1_value_array_0;
    cbor_nondet_t source_cbor_map_1_value;
    assert (cbor_nondet_mk_array(source_cbor_map_1_value_array, 2, &source_cbor_map_1_value));
    source_cbor_map[1] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_1_key, .cbor_map_entry_value = source_cbor_map_1_value};
    cbor_nondet_t source_cbor_map_0_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"a", 1, &source_cbor_map_0_key));
    cbor_nondet_t source_cbor_map_0_value = cbor_nondet_mk_uint64(1);
    source_cbor_map[0] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_0_key, .cbor_map_entry_value = source_cbor_map_0_value};
    cbor_nondet_t source_cbor;;
    if (! cbor_nondet_mk_map(source_cbor_map, 2, &source_cbor))
    {
      printf("Map build failed for source_cbor\n");
      return 1;
    }
    uint8_t target_bytes[9];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 9);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 9 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 9;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (9 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 9 bytes, got %ld\n", 9 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 9;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (9 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 9 bytes, got %ld\n", 9 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 28 out of 29\n");
    printf("Testing: ""[\"a\",{\"b\":\"c\"}]""\n");
    uint8_t source_bytes[8] = {0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63};
    cbor_nondet_t source_cbor_array[2];
    cbor_map_entry source_cbor_array_1_map[1];
    cbor_nondet_t source_cbor_array_1_map_0_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"b", 1, &source_cbor_array_1_map_0_key));
    cbor_nondet_t source_cbor_array_1_map_0_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"c", 1, &source_cbor_array_1_map_0_value));
    source_cbor_array_1_map[0] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_array_1_map_0_key, .cbor_map_entry_value = source_cbor_array_1_map_0_value};
    cbor_nondet_t source_cbor_array_1;;
    if (! cbor_nondet_mk_map(source_cbor_array_1_map, 1, &source_cbor_array_1))
    {
      printf("Map build failed for source_cbor_array_1\n");
      return 1;
    }
    source_cbor_array[1] = source_cbor_array_1;
    cbor_nondet_t source_cbor_array_0;
    assert (cbor_nondet_mk_text_string((uint8_t *)"a", 1, &source_cbor_array_0));
    source_cbor_array[0] = source_cbor_array_0;
    cbor_nondet_t source_cbor;
    assert (cbor_nondet_mk_array(source_cbor_array, 2, &source_cbor));
    uint8_t target_bytes[8];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 8);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 8 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 8;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (8 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 8 bytes, got %ld\n", 8 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 8;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (8 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 8 bytes, got %ld\n", 8 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("Test 29 out of 29\n");
    printf("Testing: ""{\"a\":\"A\",\"b\":\"B\",\"c\":\"C\",\"d\":\"D\",\"e\":\"E\"}""\n");
    uint8_t source_bytes[21] = {0xa5, 0x61, 0x61, 0x61, 0x41, 0x61, 0x62, 0x61, 0x42, 0x61, 0x63, 0x61, 0x43, 0x61, 0x64, 0x61, 0x44, 0x61, 0x65, 0x61, 0x45};
    cbor_map_entry source_cbor_map[5];
    cbor_nondet_t source_cbor_map_4_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"e", 1, &source_cbor_map_4_key));
    cbor_nondet_t source_cbor_map_4_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"E", 1, &source_cbor_map_4_value));
    source_cbor_map[4] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_4_key, .cbor_map_entry_value = source_cbor_map_4_value};
    cbor_nondet_t source_cbor_map_3_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"d", 1, &source_cbor_map_3_key));
    cbor_nondet_t source_cbor_map_3_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"D", 1, &source_cbor_map_3_value));
    source_cbor_map[3] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_3_key, .cbor_map_entry_value = source_cbor_map_3_value};
    cbor_nondet_t source_cbor_map_2_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"c", 1, &source_cbor_map_2_key));
    cbor_nondet_t source_cbor_map_2_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"C", 1, &source_cbor_map_2_value));
    source_cbor_map[2] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_2_key, .cbor_map_entry_value = source_cbor_map_2_value};
    cbor_nondet_t source_cbor_map_1_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"b", 1, &source_cbor_map_1_key));
    cbor_nondet_t source_cbor_map_1_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"B", 1, &source_cbor_map_1_value));
    source_cbor_map[1] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_1_key, .cbor_map_entry_value = source_cbor_map_1_value};
    cbor_nondet_t source_cbor_map_0_key;
    assert (cbor_nondet_mk_text_string((uint8_t *)"a", 1, &source_cbor_map_0_key));
    cbor_nondet_t source_cbor_map_0_value;
    assert (cbor_nondet_mk_text_string((uint8_t *)"A", 1, &source_cbor_map_0_value));
    source_cbor_map[0] = (cbor_map_entry) {.cbor_map_entry_key = source_cbor_map_0_key, .cbor_map_entry_value = source_cbor_map_0_value};
    cbor_nondet_t source_cbor;;
    if (! cbor_nondet_mk_map(source_cbor_map, 5, &source_cbor))
    {
      printf("Map build failed for source_cbor\n");
      return 1;
    }
    uint8_t target_bytes[21];
    size_t target_byte_size = cbor_nondet_serialize (source_cbor, target_bytes, 21);
    if (target_byte_size == 0)
    {
      printf("Encoding failed: expected 21 bytes, wrote %ld\n", target_byte_size);
      dump_encoding_test_failure(target_bytes, target_byte_size);
      return 1;
    }
    printf("Encoding succeeded!\n");
    size_t remaining_size = 21;
    uint8_t *target_bytes2 = target_bytes;
    cbor_nondet_t target_cbor;
    bool valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (21 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 21 bytes, got %ld\n", 21 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
    remaining_size = 21;
    target_bytes2 = source_bytes;
    valid = cbor_nondet_parse(false, 0, &target_bytes2, &remaining_size, &target_cbor);
    if (21 - remaining_size != target_byte_size || ! valid)
    {
      printf("Validation failed: expected 21 bytes, got %ld\n", 21 - remaining_size);
      return 1;
    }
    printf("Validation and parsing succeeded!\n");
    if (! (cbor_nondet_equal(source_cbor, target_cbor)))
    {
      printf("Decoding mismatch!\n");
      return 1;
    }
    printf("Decoding succeeded!\n");
  }
  {
    printf("UTF-8 Test 37.4. Testing text string encoding and UTF-8 validation for: 20 00\n");
    uint8_t mystr[2] = {0x20, 0x00};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 37.3. Testing text string encoding and UTF-8 validation for: 20 00 20 ff\n");
    uint8_t mystr[4] = {0x20, 0x00, 0x20, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 37.2.1. Testing text string encoding and UTF-8 validation for: 20 00 35\n");
    uint8_t mystr[3] = {0x20, 0x00, 0x35};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 37.2. Testing text string encoding and UTF-8 validation for: F0 80 80 80\n");
    uint8_t mystr[4] = {0xF0, 0x80, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 37.1. Testing text string encoding and UTF-8 validation for: E0 80 80\n");
    uint8_t mystr[3] = {0xE0, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 37.0. Testing text string encoding and UTF-8 validation for: c0 80\n");
    uint8_t mystr[2] = {0xc0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 35.0. Testing text string encoding and UTF-8 validation for: f4 80 80 00\n");
    uint8_t mystr[4] = {0xf4, 0x80, 0x80, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 34.0. Testing text string encoding and UTF-8 validation for: f1 80 80 00\n");
    uint8_t mystr[4] = {0xf1, 0x80, 0x80, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 33.0. Testing text string encoding and UTF-8 validation for: f0 90 80 00\n");
    uint8_t mystr[4] = {0xf0, 0x90, 0x80, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 32.0. Testing text string encoding and UTF-8 validation for: ed 80 00\n");
    uint8_t mystr[3] = {0xed, 0x80, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 31.0. Testing text string encoding and UTF-8 validation for: e0 80 00\n");
    uint8_t mystr[3] = {0xe0, 0x80, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.4. Testing text string encoding and UTF-8 validation for: df 00\n");
    uint8_t mystr[2] = {0xdf, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.0. Testing text string encoding and UTF-8 validation for: c2 00\n");
    uint8_t mystr[2] = {0xc2, 0x00};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 5.0. Testing text string encoding and UTF-8 validation for: 00\n");
    uint8_t mystr[1] = {0x00};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[10];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 10);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 10;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (10 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 36.9.1. Testing text string encoding and UTF-8 validation for: EF BF BE 3d EF BF BE 2e\n");
    uint8_t mystr[8] = {0xEF, 0xBF, 0xBE, 0x3d, 0xEF, 0xBF, 0xBE, 0x2e};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[17];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 17);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 17;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (17 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 36.9. Testing text string encoding and UTF-8 validation for: EF BF BF 3d EF BF BF 2e\n");
    uint8_t mystr[8] = {0xEF, 0xBF, 0xBF, 0x3d, 0xEF, 0xBF, 0xBF, 0x2e};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[17];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 17);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 17;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (17 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 36.10. Testing text string encoding and UTF-8 validation for: EFBFBD EFBFBD EFBFBD 3d e0 80 af 2e \n");
    uint8_t mystr[14] = {0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0x3d, 0xe0, 0x80, 0xaf, 0x2e};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 14, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 36.8. Testing text string encoding and UTF-8 validation for: EFBFBD EFBFBD EFBFBD 3d ed a0 80 2e \n");
    uint8_t mystr[14] = {0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0x3d, 0xed, 0xa0, 0x80, 0x2e};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 14, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 36.7. Testing text string encoding and UTF-8 validation for: EFBFBD EFBFBD EFBFBD EFBFBD 3d F7 BF BF BF 2e \n");
    uint8_t mystr[18] = {0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0x3d, 0xF7, 0xBF, 0xBF, 0xBF, 0x2e};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 18, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 9.1. Testing text string encoding and UTF-8 validation for: C2 41 42\n");
    uint8_t mystr[3] = {0xC2, 0x41, 0x42};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 35.3. Testing text string encoding and UTF-8 validation for: f4 80 80 ff\n");
    uint8_t mystr[4] = {0xf4, 0x80, 0x80, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 35.2. Testing text string encoding and UTF-8 validation for: f4 80 80 c0\n");
    uint8_t mystr[4] = {0xf4, 0x80, 0x80, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 35.1. Testing text string encoding and UTF-8 validation for: f4 80 80 7f\n");
    uint8_t mystr[4] = {0xf4, 0x80, 0x80, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 34.3. Testing text string encoding and UTF-8 validation for: f1 80 80 ff\n");
    uint8_t mystr[4] = {0xf1, 0x80, 0x80, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 34.2. Testing text string encoding and UTF-8 validation for: f1 80 80 c0\n");
    uint8_t mystr[4] = {0xf1, 0x80, 0x80, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 34.1. Testing text string encoding and UTF-8 validation for: f1 80 80 7f\n");
    uint8_t mystr[4] = {0xf1, 0x80, 0x80, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 33.3. Testing text string encoding and UTF-8 validation for: f0 90 80 ff\n");
    uint8_t mystr[4] = {0xf0, 0x90, 0x80, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 33.2. Testing text string encoding and UTF-8 validation for: f0 90 80 c0\n");
    uint8_t mystr[4] = {0xf0, 0x90, 0x80, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 33.1. Testing text string encoding and UTF-8 validation for: f0 90 80 7f\n");
    uint8_t mystr[4] = {0xf0, 0x90, 0x80, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 32.3. Testing text string encoding and UTF-8 validation for: ed 80 ff\n");
    uint8_t mystr[3] = {0xed, 0x80, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 32.2. Testing text string encoding and UTF-8 validation for: ed 80 c0\n");
    uint8_t mystr[3] = {0xed, 0x80, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 32.1. Testing text string encoding and UTF-8 validation for: ed 80 7f\n");
    uint8_t mystr[3] = {0xed, 0x80, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 31.3. Testing text string encoding and UTF-8 validation for: e0 80 ff\n");
    uint8_t mystr[3] = {0xe0, 0x80, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 31.2. Testing text string encoding and UTF-8 validation for: e0 80 c0\n");
    uint8_t mystr[3] = {0xe0, 0x80, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 31.1. Testing text string encoding and UTF-8 validation for: e0 80 7f\n");
    uint8_t mystr[3] = {0xe0, 0x80, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.7. Testing text string encoding and UTF-8 validation for: df ff\n");
    uint8_t mystr[2] = {0xdf, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.6. Testing text string encoding and UTF-8 validation for: df c0\n");
    uint8_t mystr[2] = {0xdf, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.5. Testing text string encoding and UTF-8 validation for: df 7f\n");
    uint8_t mystr[2] = {0xdf, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.3. Testing text string encoding and UTF-8 validation for: c2 ff\n");
    uint8_t mystr[2] = {0xc2, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.2. Testing text string encoding and UTF-8 validation for: c2 c0\n");
    uint8_t mystr[2] = {0xc2, 0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 30.1. Testing text string encoding and UTF-8 validation for: c2 7f\n");
    uint8_t mystr[2] = {0xc2, 0x7f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.9. Testing text string encoding and UTF-8 validation for: ff 20\n");
    uint8_t mystr[2] = {0xff, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.8. Testing text string encoding and UTF-8 validation for: f5 20\n");
    uint8_t mystr[2] = {0xf5, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.7. Testing text string encoding and UTF-8 validation for: c1 20\n");
    uint8_t mystr[2] = {0xc1, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.6. Testing text string encoding and UTF-8 validation for: 81 20\n");
    uint8_t mystr[2] = {0x81, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.5. Testing text string encoding and UTF-8 validation for: 20 80 20\n");
    uint8_t mystr[3] = {0x20, 0x80, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.4. Testing text string encoding and UTF-8 validation for: 80 20\n");
    uint8_t mystr[2] = {0x80, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.3. Testing text string encoding and UTF-8 validation for: 20 21 21 23 24 fe\n");
    uint8_t mystr[6] = {0x20, 0x21, 0x21, 0x23, 0x24, 0xfe};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.2. Testing text string encoding and UTF-8 validation for: 20 21 21 23 fe 20\n");
    uint8_t mystr[6] = {0x20, 0x21, 0x21, 0x23, 0xfe, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.1. Testing text string encoding and UTF-8 validation for: 20 80\n");
    uint8_t mystr[2] = {0x20, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 29.0. Testing text string encoding and UTF-8 validation for: 80\n");
    uint8_t mystr[1] = {0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 28.15. Testing text string encoding and UTF-8 validation for: F4 8F BF BF\n");
    uint8_t mystr[4] = {0xF4, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.14. Testing text string encoding and UTF-8 validation for: F3 BF BF BF\n");
    uint8_t mystr[4] = {0xF3, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.13. Testing text string encoding and UTF-8 validation for: F3 AF BF BF\n");
    uint8_t mystr[4] = {0xF3, 0xAF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.12. Testing text string encoding and UTF-8 validation for: F3 9F BF BF\n");
    uint8_t mystr[4] = {0xF3, 0x9F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.11. Testing text string encoding and UTF-8 validation for: F3 8F BF BF\n");
    uint8_t mystr[4] = {0xF3, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.10. Testing text string encoding and UTF-8 validation for: F2 BF BF BF\n");
    uint8_t mystr[4] = {0xF2, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.9. Testing text string encoding and UTF-8 validation for: F2 AF BF BF\n");
    uint8_t mystr[4] = {0xF2, 0xAF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.8. Testing text string encoding and UTF-8 validation for: F2 9F BF BF\n");
    uint8_t mystr[4] = {0xF2, 0x9F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.7. Testing text string encoding and UTF-8 validation for: F2 8F BF BF\n");
    uint8_t mystr[4] = {0xF2, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.6. Testing text string encoding and UTF-8 validation for: F1 BF BF BF\n");
    uint8_t mystr[4] = {0xF1, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.5. Testing text string encoding and UTF-8 validation for: F1 AF BF BF\n");
    uint8_t mystr[4] = {0xF1, 0xAF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.4. Testing text string encoding and UTF-8 validation for: F1 9F BF BF\n");
    uint8_t mystr[4] = {0xF1, 0x9F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.3. Testing text string encoding and UTF-8 validation for: F1 8F BF BF\n");
    uint8_t mystr[4] = {0xF1, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.2. Testing text string encoding and UTF-8 validation for: F0 BF BF BF\n");
    uint8_t mystr[4] = {0xF0, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.1. Testing text string encoding and UTF-8 validation for: F0 AF BF BF\n");
    uint8_t mystr[4] = {0xF0, 0xAF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 28.0. Testing text string encoding and UTF-8 validation for: F0 9F BF BF\n");
    uint8_t mystr[4] = {0xF0, 0x9F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.15. Testing text string encoding and UTF-8 validation for: F4 8F BF BE\n");
    uint8_t mystr[4] = {0xF4, 0x8F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.14. Testing text string encoding and UTF-8 validation for: F3 BF BF BE\n");
    uint8_t mystr[4] = {0xF3, 0xBF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.13. Testing text string encoding and UTF-8 validation for: F3 AF BF BE\n");
    uint8_t mystr[4] = {0xF3, 0xAF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.12. Testing text string encoding and UTF-8 validation for: F3 9F BF BE\n");
    uint8_t mystr[4] = {0xF3, 0x9F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.11. Testing text string encoding and UTF-8 validation for: F3 8F BF BE\n");
    uint8_t mystr[4] = {0xF3, 0x8F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.10. Testing text string encoding and UTF-8 validation for: F2 BF BF BE\n");
    uint8_t mystr[4] = {0xF2, 0xBF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.9. Testing text string encoding and UTF-8 validation for: F2 AF BF BE\n");
    uint8_t mystr[4] = {0xF2, 0xAF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.8. Testing text string encoding and UTF-8 validation for: F2 9F BF BE\n");
    uint8_t mystr[4] = {0xF2, 0x9F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.7. Testing text string encoding and UTF-8 validation for: F2 8F BF BE\n");
    uint8_t mystr[4] = {0xF2, 0x8F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.6. Testing text string encoding and UTF-8 validation for: F1 BF BF BE\n");
    uint8_t mystr[4] = {0xF1, 0xBF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.5. Testing text string encoding and UTF-8 validation for: F1 AF BF BE\n");
    uint8_t mystr[4] = {0xF1, 0xAF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.4. Testing text string encoding and UTF-8 validation for: F1 9F BF BE\n");
    uint8_t mystr[4] = {0xF1, 0x9F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.3. Testing text string encoding and UTF-8 validation for: F1 8F BF BE\n");
    uint8_t mystr[4] = {0xF1, 0x8F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.2. Testing text string encoding and UTF-8 validation for: F0 BF BF BE\n");
    uint8_t mystr[4] = {0xF0, 0xBF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.1. Testing text string encoding and UTF-8 validation for: F0 AF BF BE\n");
    uint8_t mystr[4] = {0xF0, 0xAF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 27.0. Testing text string encoding and UTF-8 validation for: F0 9F BF BE\n");
    uint8_t mystr[4] = {0xF0, 0x9F, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.17. Testing text string encoding and UTF-8 validation for: EF B7 9f\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9f};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.16. Testing text string encoding and UTF-8 validation for: EF B7 9e\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9e};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.15. Testing text string encoding and UTF-8 validation for: EF B7 9d\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9d};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.14. Testing text string encoding and UTF-8 validation for: EF B7 9c\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9c};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.13. Testing text string encoding and UTF-8 validation for: EF B7 9b\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9b};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.12. Testing text string encoding and UTF-8 validation for: EF B7 9a\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x9a};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.11. Testing text string encoding and UTF-8 validation for: EF B7 99\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x99};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.10. Testing text string encoding and UTF-8 validation for: EF B7 98\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x98};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.9. Testing text string encoding and UTF-8 validation for: EF B7 97\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x97};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.8. Testing text string encoding and UTF-8 validation for: EF B7 96\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x96};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.7. Testing text string encoding and UTF-8 validation for: EF B7 95\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x95};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.6. Testing text string encoding and UTF-8 validation for: EF B7 94\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x94};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.5. Testing text string encoding and UTF-8 validation for: EF B7 93\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x93};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.4. Testing text string encoding and UTF-8 validation for: EF B7 92\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x92};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.3. Testing text string encoding and UTF-8 validation for: EF B7 91\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x91};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.2. Testing text string encoding and UTF-8 validation for: EF B7 90\n");
    uint8_t mystr[3] = {0xEF, 0xB7, 0x90};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.1. Testing text string encoding and UTF-8 validation for: EF BF BF\n");
    uint8_t mystr[3] = {0xEF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 26.0. Testing text string encoding and UTF-8 validation for: EF BF BE\n");
    uint8_t mystr[3] = {0xEF, 0xBF, 0xBE};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 25.7. Testing text string encoding and UTF-8 validation for: ed af bf ed bf bf\n");
    uint8_t mystr[6] = {0xed, 0xaf, 0xbf, 0xed, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.6. Testing text string encoding and UTF-8 validation for: ed af bf ed b0 80\n");
    uint8_t mystr[6] = {0xed, 0xaf, 0xbf, 0xed, 0xb0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.5. Testing text string encoding and UTF-8 validation for: ed ae 80 ed bf bf\n");
    uint8_t mystr[6] = {0xed, 0xae, 0x80, 0xed, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.4. Testing text string encoding and UTF-8 validation for: ed ae 80 ed b0 80\n");
    uint8_t mystr[6] = {0xed, 0xae, 0x80, 0xed, 0xb0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.3. Testing text string encoding and UTF-8 validation for: ed ad bf ed bf bf\n");
    uint8_t mystr[6] = {0xed, 0xad, 0xbf, 0xed, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.2. Testing text string encoding and UTF-8 validation for: ed ad bf ed b0 80\n");
    uint8_t mystr[6] = {0xed, 0xad, 0xbf, 0xed, 0xb0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.1. Testing text string encoding and UTF-8 validation for: ed a0 80 ed bf bf\n");
    uint8_t mystr[6] = {0xed, 0xa0, 0x80, 0xed, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 25.0. Testing text string encoding and UTF-8 validation for: ed a0 80 ed b0 80\n");
    uint8_t mystr[6] = {0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.7. Testing text string encoding and UTF-8 validation for: ed bf bf\n");
    uint8_t mystr[3] = {0xed, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.6. Testing text string encoding and UTF-8 validation for: ed be 80\n");
    uint8_t mystr[3] = {0xed, 0xbe, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.5. Testing text string encoding and UTF-8 validation for: ed b0 80\n");
    uint8_t mystr[3] = {0xed, 0xb0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.4. Testing text string encoding and UTF-8 validation for: ed af bf\n");
    uint8_t mystr[3] = {0xed, 0xaf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.3. Testing text string encoding and UTF-8 validation for: ed ae 80\n");
    uint8_t mystr[3] = {0xed, 0xae, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.2. Testing text string encoding and UTF-8 validation for: ed ad bf\n");
    uint8_t mystr[3] = {0xed, 0xad, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.0.2. Testing text string encoding and UTF-8 validation for: 31 32 33 ed a0 80 31\n");
    uint8_t mystr[7] = {0x31, 0x32, 0x33, 0xed, 0xa0, 0x80, 0x31};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 7, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.0.1. Testing text string encoding and UTF-8 validation for: ed a0 80 35\n");
    uint8_t mystr[4] = {0xed, 0xa0, 0x80, 0x35};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 24.0. Testing text string encoding and UTF-8 validation for: ed a0 80\n");
    uint8_t mystr[3] = {0xed, 0xa0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 23.3. Testing text string encoding and UTF-8 validation for: f8 87 bf bf bf\n");
    uint8_t mystr[5] = {0xf8, 0x87, 0xbf, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 23.2. Testing text string encoding and UTF-8 validation for: f0 8f bf bf\n");
    uint8_t mystr[4] = {0xf0, 0x8f, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 23.1. Testing text string encoding and UTF-8 validation for: e0 9f bf\n");
    uint8_t mystr[3] = {0xe0, 0x9f, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 23.0. Testing text string encoding and UTF-8 validation for: c1 bf\n");
    uint8_t mystr[2] = {0xc1, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.6. Testing text string encoding and UTF-8 validation for: fc 80 80 80 80 af\n");
    uint8_t mystr[6] = {0xfc, 0x80, 0x80, 0x80, 0x80, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.5. Testing text string encoding and UTF-8 validation for: f8 80 80 80 af\n");
    uint8_t mystr[5] = {0xf8, 0x80, 0x80, 0x80, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.4. Testing text string encoding and UTF-8 validation for: f0 80 80 af\n");
    uint8_t mystr[4] = {0xf0, 0x80, 0x80, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.3. Testing text string encoding and UTF-8 validation for: e0 80 af\n");
    uint8_t mystr[3] = {0xe0, 0x80, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.2. Testing text string encoding and UTF-8 validation for: c0 af\n");
    uint8_t mystr[2] = {0xc0, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.6. Testing text string encoding and UTF-8 validation for: 37 38 39 fe\n");
    uint8_t mystr[4] = {0x37, 0x38, 0x39, 0xfe};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.5. Testing text string encoding and UTF-8 validation for: 37 38 fe\n");
    uint8_t mystr[3] = {0x37, 0x38, 0xfe};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.4. Testing text string encoding and UTF-8 validation for: 37 ff\n");
    uint8_t mystr[2] = {0x37, 0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.3. Testing text string encoding and UTF-8 validation for: ff\n");
    uint8_t mystr[1] = {0xff};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.2. Testing text string encoding and UTF-8 validation for: fe\n");
    uint8_t mystr[1] = {0xfe};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.1. Testing text string encoding and UTF-8 validation for: 81\n");
    uint8_t mystr[1] = {0x81};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 21.0. Testing text string encoding and UTF-8 validation for: 80\n");
    uint8_t mystr[1] = {0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.6. Testing text string encoding and UTF-8 validation for: 31 32 33 ef 80 f0\n");
    uint8_t mystr[6] = {0x31, 0x32, 0x33, 0xef, 0x80, 0xf0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.5. Testing text string encoding and UTF-8 validation for: 31 32 33 ef 80\n");
    uint8_t mystr[5] = {0x31, 0x32, 0x33, 0xef, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.4. Testing text string encoding and UTF-8 validation for: fd bf bf bf bf\n");
    uint8_t mystr[5] = {0xfd, 0xbf, 0xbf, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.3. Testing text string encoding and UTF-8 validation for: fb bf bf bf\n");
    uint8_t mystr[4] = {0xfb, 0xbf, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.2. Testing text string encoding and UTF-8 validation for: f7 bf bf\n");
    uint8_t mystr[3] = {0xf7, 0xbf, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.1. Testing text string encoding and UTF-8 validation for: ef bf\n");
    uint8_t mystr[2] = {0xef, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 19.0. Testing text string encoding and UTF-8 validation for: df\n");
    uint8_t mystr[1] = {0xdf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 18.4. Testing text string encoding and UTF-8 validation for: fc 80 80 80 80\n");
    uint8_t mystr[5] = {0xfc, 0x80, 0x80, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 18.3. Testing text string encoding and UTF-8 validation for: f8 80 80 80\n");
    uint8_t mystr[4] = {0xf8, 0x80, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 18.2. Testing text string encoding and UTF-8 validation for: f0 80 80\n");
    uint8_t mystr[3] = {0xf0, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 18.1. Testing text string encoding and UTF-8 validation for: e0 80\n");
    uint8_t mystr[2] = {0xe0, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 18.0. Testing text string encoding and UTF-8 validation for: c0\n");
    uint8_t mystr[1] = {0xc0};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 17.1. Testing text string encoding and UTF-8 validation for: fd20\n");
    uint8_t mystr[2] = {0xfd, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 17.0. Testing text string encoding and UTF-8 validation for: fc20\n");
    uint8_t mystr[2] = {0xfc, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 16.3. Testing text string encoding and UTF-8 validation for: fb20\n");
    uint8_t mystr[2] = {0xfb, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 16.2. Testing text string encoding and UTF-8 validation for: fa20\n");
    uint8_t mystr[2] = {0xfa, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 16.1. Testing text string encoding and UTF-8 validation for: f920\n");
    uint8_t mystr[2] = {0xf9, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 16.0. Testing text string encoding and UTF-8 validation for: f820\n");
    uint8_t mystr[2] = {0xf8, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 15.3. Testing text string encoding and UTF-8 validation for: f620 f720\n");
    uint8_t mystr[4] = {0xf6, 0x20, 0xf7, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 15.2. Testing text string encoding and UTF-8 validation for: f420 f520\n");
    uint8_t mystr[4] = {0xf4, 0x20, 0xf5, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 15.1. Testing text string encoding and UTF-8 validation for: f220 f320\n");
    uint8_t mystr[4] = {0xf2, 0x20, 0xf3, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 15.0. Testing text string encoding and UTF-8 validation for: f020 f120\n");
    uint8_t mystr[4] = {0xf0, 0x20, 0xf1, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.5.1. Testing text string encoding and UTF-8 validation for: E1 80 E2 F0 91 92 F1 BF 41\n");
    uint8_t mystr[9] = {0xE1, 0x80, 0xE2, 0xF0, 0x91, 0x92, 0xF1, 0xBF, 0x41};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 9, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.4.2. Testing text string encoding and UTF-8 validation for: F4 91 92 93 FF 41 80 BF 42\n");
    uint8_t mystr[9] = {0xF4, 0x91, 0x92, 0x93, 0xFF, 0x41, 0x80, 0xBF, 0x42};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 9, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.4.1. Testing text string encoding and UTF-8 validation for: ED A0 80 ED BF BF ED AF 41\n");
    uint8_t mystr[9] = {0xED, 0xA0, 0x80, 0xED, 0xBF, 0xBF, 0xED, 0xAF, 0x41};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 9, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.4.0. Testing text string encoding and UTF-8 validation for: C0 AF E0 80 BF F0 81 82 41\n");
    uint8_t mystr[9] = {0xC0, 0xAF, 0xE0, 0x80, 0xBF, 0xF0, 0x81, 0x82, 0x41};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 9, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.3. Testing text string encoding and UTF-8 validation for: ec20 ed20 ee20 ef20\n");
    uint8_t mystr[8] = {0xec, 0x20, 0xed, 0x20, 0xee, 0x20, 0xef, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.2. Testing text string encoding and UTF-8 validation for: e820 e920 ea20 eb20\n");
    uint8_t mystr[8] = {0xe8, 0x20, 0xe9, 0x20, 0xea, 0x20, 0xeb, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.1. Testing text string encoding and UTF-8 validation for: e420 e520 e620 e720\n");
    uint8_t mystr[8] = {0xe4, 0x20, 0xe5, 0x20, 0xe6, 0x20, 0xe7, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 14.0. Testing text string encoding and UTF-8 validation for: e020 e120 e220 e320\n");
    uint8_t mystr[8] = {0xe0, 0x20, 0xe1, 0x20, 0xe2, 0x20, 0xe3, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.7. Testing text string encoding and UTF-8 validation for: dc20 dd20 de20 df20\n");
    uint8_t mystr[8] = {0xdc, 0x20, 0xdd, 0x20, 0xde, 0x20, 0xdf, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.6. Testing text string encoding and UTF-8 validation for: d820 d920 da20 db20\n");
    uint8_t mystr[8] = {0xd8, 0x20, 0xd9, 0x20, 0xda, 0x20, 0xdb, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.5. Testing text string encoding and UTF-8 validation for: d420 d520 d620 d720\n");
    uint8_t mystr[8] = {0xd4, 0x20, 0xd5, 0x20, 0xd6, 0x20, 0xd7, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.4. Testing text string encoding and UTF-8 validation for: d020 d120 d220 d320\n");
    uint8_t mystr[8] = {0xd0, 0x20, 0xd1, 0x20, 0xd2, 0x20, 0xd3, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.3. Testing text string encoding and UTF-8 validation for: cc20 cd20 ce20 cf20\n");
    uint8_t mystr[8] = {0xcc, 0x20, 0xcd, 0x20, 0xce, 0x20, 0xcf, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.2. Testing text string encoding and UTF-8 validation for: c820 c920 ca20 cb20\n");
    uint8_t mystr[8] = {0xc8, 0x20, 0xc9, 0x20, 0xca, 0x20, 0xcb, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.1. Testing text string encoding and UTF-8 validation for: c420 c520 c620 c720\n");
    uint8_t mystr[8] = {0xc4, 0x20, 0xc5, 0x20, 0xc6, 0x20, 0xc7, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 13.0. Testing text string encoding and UTF-8 validation for: c020 c120 c220 c320\n");
    uint8_t mystr[8] = {0xc0, 0x20, 0xc1, 0x20, 0xc2, 0x20, 0xc3, 0x20};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.7. Testing text string encoding and UTF-8 validation for: b8b9 babb bcbd bebf\n");
    uint8_t mystr[8] = {0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.6. Testing text string encoding and UTF-8 validation for: b0b1 b2b3 b4b5 b6b7\n");
    uint8_t mystr[8] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.5. Testing text string encoding and UTF-8 validation for: a8a9 aaab acad aeaf\n");
    uint8_t mystr[8] = {0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.4. Testing text string encoding and UTF-8 validation for: a0a1 a2a3 a4a5 a6a7\n");
    uint8_t mystr[8] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.3. Testing text string encoding and UTF-8 validation for: 9899 9a9b 9c9d 9e9f\n");
    uint8_t mystr[8] = {0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.2. Testing text string encoding and UTF-8 validation for: 9091 9293 9495 9697\n");
    uint8_t mystr[8] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.1. Testing text string encoding and UTF-8 validation for: 8889 8a8b 8c8d 8e8f\n");
    uint8_t mystr[8] = {0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 12.0. Testing text string encoding and UTF-8 validation for: 8081 8283 8485 8687\n");
    uint8_t mystr[8] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 8, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.6. Testing text string encoding and UTF-8 validation for: 80 bf 80 bf 80 bf\n");
    uint8_t mystr[6] = {0x80, 0xbf, 0x80, 0xbf, 0x80, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.5. Testing text string encoding and UTF-8 validation for: 80 bf 80 bf 80\n");
    uint8_t mystr[5] = {0x80, 0xbf, 0x80, 0xbf, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.4. Testing text string encoding and UTF-8 validation for: 80 bf 80 bf\n");
    uint8_t mystr[4] = {0x80, 0xbf, 0x80, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.3. Testing text string encoding and UTF-8 validation for: 80 bf 80\n");
    uint8_t mystr[3] = {0x80, 0xbf, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.2. Testing text string encoding and UTF-8 validation for: 80 bf\n");
    uint8_t mystr[2] = {0x80, 0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.1. Testing text string encoding and UTF-8 validation for: bf\n");
    uint8_t mystr[1] = {0xbf};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 11.0. Testing text string encoding and UTF-8 validation for: 80\n");
    uint8_t mystr[1] = {0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 9.0. Testing text string encoding and UTF-8 validation for: F7 BF BF\n");
    uint8_t mystr[3] = {0xF7, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.5. Testing text string encoding and UTF-8 validation for: F7 BF BF BF BF BF BF\n");
    uint8_t mystr[7] = {0xF7, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 7, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.4. Testing text string encoding and UTF-8 validation for: F7 BF BF BF BF BF\n");
    uint8_t mystr[6] = {0xF7, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.3. Testing text string encoding and UTF-8 validation for: fc 84 80 80 80 80\n");
    uint8_t mystr[6] = {0xfc, 0x84, 0x80, 0x80, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 6, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.2. Testing text string encoding and UTF-8 validation for: F7 BF BF BF BF\n");
    uint8_t mystr[5] = {0xF7, 0xBF, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.1. Testing text string encoding and UTF-8 validation for: f8 88 80 80 80\n");
    uint8_t mystr[5] = {0xf8, 0x88, 0x80, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 5, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.0.1. Testing text string encoding and UTF-8 validation for: F4 90 80 80\n");
    uint8_t mystr[4] = {0xF4, 0x90, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 6.0. Testing text string encoding and UTF-8 validation for: F7 BF BF BF\n");
    uint8_t mystr[4] = {0xF7, 0xBF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt succeeded but it was expected to have failed\n");
      return 1;
    }
    printf("CBOR object construction attempt failed as expected\n");
  }
  {
    printf("UTF-8 Test 22.7. Testing text string encoding and UTF-8 validation for: e0 a0 80\n");
    uint8_t mystr[3] = {0xe0, 0xa0, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 22.1. Testing text string encoding and UTF-8 validation for: 2F\n");
    uint8_t mystr[1] = {0x2F};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[10];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 10);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 10;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (10 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 10.3. Testing text string encoding and UTF-8 validation for: F4 8F BF BF\n");
    uint8_t mystr[4] = {0xF4, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 10.2. Testing text string encoding and UTF-8 validation for: EFBFBD\n");
    uint8_t mystr[3] = {0xEF, 0xBF, 0xBD};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 10.1. Testing text string encoding and UTF-8 validation for: EE 80 80\n");
    uint8_t mystr[3] = {0xEE, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 8.3. Testing text string encoding and UTF-8 validation for: F4 8F BF BF\n");
    uint8_t mystr[4] = {0xF4, 0x8F, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 8.2. Testing text string encoding and UTF-8 validation for: EF BF BF\n");
    uint8_t mystr[3] = {0xEF, 0xBF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 8.1. Testing text string encoding and UTF-8 validation for: DF BF\n");
    uint8_t mystr[2] = {0xDF, 0xBF};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 8.0. Testing text string encoding and UTF-8 validation for: 7F\n");
    uint8_t mystr[1] = {0x7F};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[10];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 10);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 10;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (10 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 7.3. Testing text string encoding and UTF-8 validation for: c2 82\n");
    uint8_t mystr[2] = {0xc2, 0x82};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 7.2. Testing text string encoding and UTF-8 validation for: c2 81\n");
    uint8_t mystr[2] = {0xc2, 0x81};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 7.1. Testing text string encoding and UTF-8 validation for: c2 80\n");
    uint8_t mystr[2] = {0xc2, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 5.3. Testing text string encoding and UTF-8 validation for: f0 90 80 80\n");
    uint8_t mystr[4] = {0xf0, 0x90, 0x80, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 5.2. Testing text string encoding and UTF-8 validation for: e0 a0 80\n");
    uint8_t mystr[3] = {0xe0, 0xa0, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 5.1. Testing text string encoding and UTF-8 validation for: c2 80\n");
    uint8_t mystr[2] = {0xc2, 0x80};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 4.0. Testing text string encoding and UTF-8 validation for: F0 9D 92 9C\n");
    uint8_t mystr[4] = {0xF0, 0x9D, 0x92, 0x9C};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 4, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[13];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 13);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 13;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (13 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 3.0. Testing text string encoding and UTF-8 validation for: E2 80 90\n");
    uint8_t mystr[3] = {0xE2, 0x80, 0x90};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 3, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[12];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 12);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 12;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (12 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 2.1.0. Testing text string encoding and UTF-8 validation for: C2 A9\n");
    uint8_t mystr[2] = {0xC2, 0xA9};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 2, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[11];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 11);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 11;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (11 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }
  {
    printf("UTF-8 Test 1.0.1. Testing text string encoding and UTF-8 validation for: 31\n");
    uint8_t mystr[1] = {0x31};
    cbor_nondet_t mycbor;
    if (!cbor_nondet_mk_text_string(mystr, 1, &mycbor))
    {
      printf("CBOR object construction attempt failed but it was expected to have succeeded\n");
      return 1;
    }
    printf("CBOR object construction attempt succeeded as expected\n");
    uint8_t output[10];
    size_t serialized_size = cbor_nondet_serialize(mycbor, output, 10);
    if (serialized_size == 0)
    {
      printf("Serialization failed");
      return 1;
    }
    printf("Serialization succeeded!\n");
    size_t test = 10;
    uint8_t *output2 = output;
    cbor_nondet_t outcbor;
    bool valid = cbor_nondet_parse(false, 0, &output2, &test, &outcbor);
    if (10 - test != serialized_size || ! valid)
    {
      printf("Validation failed, but it was expected to succeed\n");
      return 1;
    }
    printf("Validation succeeded!\n");
    if (! cbor_nondet_equal(mycbor, outcbor))
    {
      printf("Round-trip failed\n");
      return 1;
    }
    printf("Round-trip succeeded!\n");
  }

  return 0;
}

